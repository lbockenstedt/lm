"""LM Hub message delivery — pending-ack tracking and offline queuing.

``Mailbox`` owns the Hub-side outbound queue: every message sent via ``push``
is recorded in ``pending_ack`` until the spoke acknowledges it, retried on an
exponential backoff schedule, and — if the spoke is offline — moved to a
per-spoke offline queue (``spoke_queues``) that is flushed on reconnect. This
is the retry/durability layer for non-heartbeat traffic; heartbeats themselves
are not ack-tracked here (their liveness signal flows through
``heartbeat.py``). The envelope shape for both messages and acks is defined in
``protocol.py``.

Persisted to ``<state_dir>/mailbox.json`` (same dir + encryption as
StateManager's system/tenant state — queued payloads can carry secrets, e.g.
SPOKE_UPDATE_SESSION_KEY's plaintext session key) so a hub restart doesn't
drop in-flight or offline-queued messages: they were sitting in memory only
before, so a restart silently lost anything a temporarily-disconnected spoke
hadn't acked yet. Loaded on construction; saved after every mutation that
actually changes pending_ack/spoke_queues.
"""

import asyncio
import json
import os
import time
import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from .protocol import Message, MessageHeader, MessagePayload, Acknowledgement, MessagePriority

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("Mailbox")

class Mailbox:
    def __init__(self, state_dir: Optional[str] = None):
        # Messages sent by the Hub that are awaiting an Ack
        # { message_id: (message, first_sent_time, retry_count) }
        self.pending_ack: Dict[str, tuple[Message, float, int]] = {}

        # Mailboxes for spokes (messages queued while spoke is offline)
        # { spoke_id: [Message, ...] }
        self.spoke_queues: Dict[str, List[Message]] = {}

        self.retry_intervals = [5, 15, 60, 300, 900]  # Exponential backoff intervals in seconds

        # Same directory StateManager resolves (prod /var/lib/lm/state, dev
        # home-dir fallback) so the two files sit side by side.
        if state_dir is None:
            state_dir = "/var/lib/lm/state"
            try:
                os.makedirs(state_dir, exist_ok=True)
                test_file = os.path.join(state_dir, ".write_test")
                with open(test_file, "w") as f:
                    f.write("test")
                os.remove(test_file)
            except Exception:
                state_dir = os.path.expanduser("~/.local/share/lm/state")
                os.makedirs(state_dir, exist_ok=True)
        self._path = os.path.join(state_dir, "mailbox.json")
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    @staticmethod
    def _message_to_dict(message: Message) -> Dict[str, Any]:
        return asdict(message)

    @staticmethod
    def _message_from_dict(d: Dict[str, Any]) -> Message:
        h = dict(d.get("header") or {})
        if "priority" in h:
            try:
                h["priority"] = MessagePriority(h["priority"])
            except Exception:
                h["priority"] = MessagePriority.NORMAL
        p = dict(d.get("payload") or {})
        return Message(header=MessageHeader(**h), payload=MessagePayload(**p),
                       signature=d.get("signature"))

    def _save(self) -> None:
        """Best-effort atomic + encrypted write — mirrors StateManager._save_file.
        Never raises: a failed mailbox persist must not break message delivery."""
        try:
            from security.encryption import hub_encryption
            data = {
                "pending_ack": {
                    mid: {"message": self._message_to_dict(msg),
                          "first_sent": ts, "retries": retries}
                    for mid, (msg, ts, retries) in self.pending_ack.items()
                },
                "spoke_queues": {
                    sid: [self._message_to_dict(m) for m in msgs]
                    for sid, msgs in self.spoke_queues.items()
                },
            }
            json_data = json.dumps(data, indent=2, default=str)
            encrypted = hub_encryption.encrypt(json_data)
            tmp_path = self._path + ".tmp"
            with open(tmp_path, "wb") as f:
                f.write(encrypted)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self._path)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Mailbox persist failed ({self._path}): {e}")

    def _load(self) -> None:
        """Restore pending_ack/spoke_queues from disk (warm start after a hub
        restart). Best-effort: any failure just starts empty — never fatal."""
        if not os.path.exists(self._path):
            return
        try:
            from security.encryption import hub_encryption
            with open(self._path, "rb") as f:
                encrypted = f.read()
            if not encrypted:
                return
            json_data = hub_encryption.decrypt(encrypted)
            data = json.loads(json_data) or {}
            for mid, entry in (data.get("pending_ack") or {}).items():
                try:
                    msg = self._message_from_dict(entry["message"])
                    self.pending_ack[mid] = (msg, float(entry["first_sent"]), int(entry["retries"]))
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Mailbox load: dropping unreadable pending_ack entry {mid}: {e}")
            for sid, msgs in (data.get("spoke_queues") or {}).items():
                restored = []
                for m in msgs:
                    try:
                        restored.append(self._message_from_dict(m))
                    except Exception as e:  # noqa: BLE001
                        logger.warning(f"Mailbox load: dropping unreadable queued message for {sid}: {e}")
                if restored:
                    self.spoke_queues[sid] = restored
            total = len(self.pending_ack) + sum(len(v) for v in self.spoke_queues.values())
            if total:
                logger.info(f"Mailbox: restored {total} message(s) from {self._path} (warm start).")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Mailbox load failed ({self._path}): {e} — starting empty.")

    async def push(self, message: Message, send_func):
        """
        Pushes a message via the provided send_func and adds it to the pending queue.
        """
        logger.info(f"Pushing message {message.header.message_id} to {message.header.destination_id}")

        # Try to send immediately
        try:
            await send_func(message)
        except Exception as e:
            logger.warning(f"Immediate push failed for {message.header.message_id}: {e}")
            # If it fails here, it's already in the queue for the retry loop to handle if we add it

        self.pending_ack[message.header.message_id] = (message, time.time(), 0)
        self._save()

    async def acknowledge(self, ack: Acknowledgement):
        """
        Processes an acknowledgement and removes the corresponding message from the pending queue.
        """
        if ack.correlation_id in self.pending_ack:
            logger.info(f"Message {ack.correlation_id} acknowledged with status: {ack.status}")
            del self.pending_ack[ack.correlation_id]
            self._save()
        else:
            # Unknown ack: the original message is no longer in pending_ack
            # (already acked, expired, or never sent by this Hub), so we cannot
            # recover spoke_id/type from the queue. Log what the ack envelope
            # carries — including spoke_id/message_type when the receive path
            # populated them (see protocol.Acknowledgement) — so triage can
            # identify which spoke/type produced the stray ack.
            logger.warning(
                f"Received acknowledgement for unknown message ID: {ack.correlation_id} "
                f"(spoke_id={getattr(ack, 'spoke_id', None)}, "
                f"message_type={getattr(ack, 'message_type', None)}, "
                f"source_ip={getattr(ack, 'source_ip', None)}, "
                f"status={ack.status})"
            )

    def queue_for_spoke(self, spoke_id: str, message: Message):
        """
        Queues a message for a spoke that is currently offline.
        """
        if spoke_id not in self.spoke_queues:
            self.spoke_queues[spoke_id] = []

        # Filter out expired messages before adding
        now = time.time()
        self.spoke_queues[spoke_id] = [
            m for m in self.spoke_queues[spoke_id]
            if (now - m.header.timestamp) < m.header.ttl
        ]

        self.spoke_queues[spoke_id].append(message)
        logger.info(f"Queued message {message.header.message_id} for offline spoke {spoke_id}")
        self._save()

    async def flush_mailbox(self, spoke_id: str, send_func):
        """
        Sends all queued messages for a newly connected spoke.
        """
        if spoke_id in self.spoke_queues and self.spoke_queues[spoke_id]:
            messages = self.spoke_queues[spoke_id][:]
            logger.info(f"Flushing mailbox for spoke {spoke_id} ({len(messages)} messages)")

            for msg in messages:
                await self.push(msg, send_func)

            self.spoke_queues[spoke_id] = []
            self._save()

    async def retry_loop(self, send_func_map):
        """
        Periodically checks for messages that haven't been acknowledged and retries them.
        send_func_map: { spoke_id: send_func }
        """
        while True:
            now = time.time()
            to_retry = []

            changed = False
            for msg_id, (msg, last_sent, retries) in list(self.pending_ack.items()):
                if retries >= len(self.retry_intervals):
                    # Include spoke_id (destination) + message type so triage
                    # can tell which spoke and which command type got stranded
                    # — the bare message_id is a UUID and unhelpful on its own.
                    logger.error(
                        f"Message {msg_id} failed after max retries. Giving up. "
                        f"(spoke_id={msg.header.destination_id}, "
                        f"message_type={msg.payload.type})"
                    )
                    del self.pending_ack[msg_id]
                    changed = True
                    continue

                wait_time = self.retry_intervals[retries]
                if now - last_sent >= wait_time:
                    to_retry.append((msg_id, msg, retries))

            for msg_id, msg, retries in to_retry:
                spoke_id = msg.header.destination_id
                send_func = send_func_map.get(spoke_id)
                changed = True

                if send_func:
                    logger.info(f"Retrying message {msg_id} (Attempt {retries + 1})")
                    try:
                        await send_func(msg)
                        self.pending_ack[msg_id] = (msg, now, retries + 1)
                    except Exception as e:
                        # Advance the backoff schedule even on failure. Without
                        # this, a permanently-failing send (e.g. sign_message
                        # raising "No key found" for an unapproved/keyless spoke)
                        # retries EVERY 1s loop at the SAME attempt number
                        # forever — flooding the log and never reaching the
                        # max-retries give-up branch below. Bumping retries +
                        # last_sent lets the exponential intervals progress and
                        # the message drop after retry_intervals is exhausted.
                        logger.warning(f"Retry failed for {msg_id}: {e}")
                        self.pending_ack[msg_id] = (msg, now, retries + 1)
                else:
                    # Spoke is offline, move to offline queue if not already there
                    logger.info(f"Spoke {spoke_id} offline. Moving message {msg_id} to offline queue.")
                    self.queue_for_spoke(spoke_id, msg)  # saves its own change
                    del self.pending_ack[msg_id]

            if changed:
                self._save()

            await asyncio.sleep(1)

    def clear_spoke(self, spoke_id: str) -> int:
        """Drop ALL queued/pending messages destined for ``spoke_id``.

        Called when an admin deletes a spoke, resets its secret, or un-approves
        it (api.delete_spoke / reset_spoke_secret / approve_spoke unapprove).
        Those paths wipe the spoke's session key, so any message still in
        ``pending_ack`` for it can no longer be signed — without this clear it
        would retry forever (the retry loop's backoff advances, but a keyless
        spoke never becomes signable, so the messages would still churn through
        the full backoff schedule per stranded message). Returns the number of
        messages dropped (best-effort, non-raising).
        """
        dropped = 0
        for msg_id in [mid for mid, (msg, _, _) in self.pending_ack.items()
                       if msg.header.destination_id == spoke_id]:
            del self.pending_ack[msg_id]
            dropped += 1
        if spoke_id in self.spoke_queues:
            dropped += len(self.spoke_queues[spoke_id])
            del self.spoke_queues[spoke_id]
        if dropped:
            logger.info(f"Cleared {dropped} queued message(s) for spoke {spoke_id}.")
            self._save()
        return dropped

    def get_all_pending(self) -> list:
        """
        Returns a list of all messages currently awaiting acknowledgement
        or queued for offline spokes.
        """
        all_pending = []
        for msg, _, _ in self.pending_ack.values():
            all_pending.append(msg)
        for q in self.spoke_queues.values():
            all_pending.extend(q)
        return all_pending
