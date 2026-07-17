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

# A SPOKE_UPDATE tells a spoke to git-pull its repo + restart. It carries only
# {repo_url, branch} (NOT a target commit), so a spoke that flaps mid-update
# never acks it → the durable queue re-flushes the SAME message on EVERY
# reconnect, and the fan-out can queue several before one lands. Both produce a
# storm of redundant pull/restart nudges at a device that may already be
# current. Two guards below tame this:
#   1. De-dup (coalesce): queue_for_spoke keeps at most ONE pending SPOKE_UPDATE
#      per (repo_url, branch) per spoke — a newer one supersedes the older.
#   2. Delivery cooldown: flush_mailbox will not re-deliver a SPOKE_UPDATE for
#      the same (repo_url, branch) within this window; it DEFERS it (leaves it
#      queued) so a genuinely-new tip still lands on a later reconnect but a
#      stuck one cannot re-fire every reconnect.
SPOKE_UPDATE_DELIVERY_COOLDOWN_S = 600

# Default absolute backlog expiry (seconds): a queued/unacked message older than
# this is dropped even if its own 24h ttl hasn't elapsed. Overridable live via
# global_config["backlog_expiry"]["max_age_seconds"]; 0 disables the cap.
BACKLOG_MAX_AGE_DEFAULT_S = 3600
# How often retry_loop runs the expiry sweep (cheap, but no need every 1s).
BACKLOG_EXPIRY_SWEEP_INTERVAL_S = 30
# Grace before the "supersession" fast-expiry can fire: a message must have been
# pending at least this long, and the spoke must have acked NEWER traffic, before
# we treat it as passed-over. Keeps a just-queued message from being dropped in a
# normal interleave.
BACKLOG_SUPERSEDE_GRACE_S = 45


def _is_spoke_update(message: Message) -> bool:
    try:
        return getattr(message.payload, "type", None) == "SPOKE_UPDATE"
    except Exception:
        return False


def _spoke_update_key(spoke_id: str, message: Message) -> str:
    """Coalesce/cooldown key: spoke + repo + branch (NOT message_id — a re-push
    of the same repo tip must collide with the prior one)."""
    data = getattr(message.payload, "data", None) or {}
    repo = data.get("repo_url", "") if isinstance(data, dict) else ""
    branch = data.get("branch", "") if isinstance(data, dict) else ""
    return f"{spoke_id}|{repo}|{branch}"

class Mailbox:
    def __init__(self, state_dir: Optional[str] = None):
        # Messages sent by the Hub that are awaiting an Ack
        # { message_id: (message, first_sent_time, retry_count) }
        self.pending_ack: Dict[str, tuple[Message, float, int]] = {}

        # Mailboxes for spokes (messages queued while spoke is offline)
        # { spoke_id: [Message, ...] }
        self.spoke_queues: Dict[str, List[Message]] = {}

        # Last time a SPOKE_UPDATE was actually delivered for a given
        # (spoke|repo|branch) key — drives the delivery cooldown so a durable
        # SPOKE_UPDATE that never gets acked cannot re-flush every reconnect.
        # In-memory only (not persisted): a hub restart legitimately clears the
        # cooldown so a pending update flushes promptly after the restart.
        self._spoke_update_delivered: Dict[str, float] = {}

        # Proactive backlog expiry: drop any queued/unacked message older than
        # min(its own ttl, backlog_max_age_s) so a stale entry (e.g. an
        # undeliverable SPOKE_UPDATE to a spoke that never takes it) can't sit
        # forever. The hub refreshes backlog_max_age_s from
        # global_config["backlog_expiry"]["max_age_seconds"] (default 1h);
        # set to 0 to disable the absolute cap and fall back to each message's
        # 24h ttl. Swept on a throttle from retry_loop.
        self.backlog_max_age_s: float = float(BACKLOG_MAX_AGE_DEFAULT_S)
        self._last_expiry_sweep = 0.0

        # Per-spoke time of the last successful ack — "the spoke is alive and
        # draining". A message still pending to a spoke whose last ack is NEWER
        # than that message's send time was passed over → drop it fast (see
        # _expire_stale supersession rule), instead of waiting out the age cap.
        self._last_ack_ts: Dict[str, float] = {}

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
            try:
                os.chmod(tmp_path, 0o600)  # encrypted mailbox state: not world-readable
            except OSError:
                pass
            os.replace(tmp_path, self._path)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Mailbox persist failed ({self._path}): {e}")

    async def _asave(self) -> None:
        """Async wrapper around the synchronous encrypted JSON write.

        ``_save`` does a ``json.dumps`` of every pending/offline message + an
        fsync'd atomic file replace on every ``acknowledge``/``push``/
        ``retry_loop``/``flush_mailbox`` — the hub-side COMMAND_RESULT /
        command-dispatch fan-in. Doing that inline on the hub's asyncio loop
        is the same I/O-starvation pattern that stalled cs-svr-02's WS link
        (sync disk writes on the shared loop → 5s Request Timeout). Offload it
        to a thread so heartbeats / ``request_response`` keep flowing while the
        mailbox persists."""
        await asyncio.to_thread(self._save)

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
        logger.debug(f"Pushing message {message.header.message_id} to {message.header.destination_id}")

        # Try to send immediately
        try:
            await send_func(message)
            # Record SPOKE_UPDATE delivery so flush_mailbox's cooldown sees this
            # direct (online) push too — a spoke that just got nudged online must
            # not be re-nudged again by a reconnect flush moments later.
            if _is_spoke_update(message):
                self._spoke_update_delivered[
                    _spoke_update_key(message.header.destination_id, message)] = time.time()
        except Exception as e:
            logger.warning(f"Immediate push failed for {message.header.message_id}: {e}")
            # If it fails here, it's already in the queue for the retry loop to handle if we add it

        self.pending_ack[message.header.message_id] = (message, time.time(), 0)
        await self._asave()

    async def acknowledge(self, ack: Acknowledgement):
        """
        Processes an acknowledgement and removes the corresponding message from the pending queue.
        """
        if ack.correlation_id in self.pending_ack:
            logger.debug(f"Message {ack.correlation_id} acknowledged with status: {ack.status}")
            # Record per-spoke last-ack time (authoritative dest from the pending
            # message) — proof the spoke is alive AND draining traffic. Drives
            # the "supersession" expiry: an OLDER message still pending to a
            # spoke that has since acked NEWER traffic was passed over and won't
            # be acked, so it can be dropped fast (no 1h wait).
            _dest = getattr(self.pending_ack[ack.correlation_id][0].header, "destination_id", None)
            if _dest:
                self._last_ack_ts[_dest] = time.time()
            del self.pending_ack[ack.correlation_id]
            await self._asave()
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

    async def queue_for_spoke(self, spoke_id: str, message: Message):
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

        # De-dup (coalesce) SPOKE_UPDATE: keep at most ONE pending update per
        # (repo_url, branch) for this spoke. A newer SPOKE_UPDATE supersedes the
        # older queued one, so a flapping spoke can't accumulate a backlog of
        # identical pull-and-restart nudges that all re-flush on reconnect.
        if _is_spoke_update(message):
            new_key = _spoke_update_key(spoke_id, message)
            before = len(self.spoke_queues[spoke_id])
            self.spoke_queues[spoke_id] = [
                m for m in self.spoke_queues[spoke_id]
                if not (_is_spoke_update(m) and _spoke_update_key(spoke_id, m) == new_key)
            ]
            dropped = before - len(self.spoke_queues[spoke_id])
            if dropped:
                logger.info(f"Coalesced {dropped} superseded SPOKE_UPDATE(s) for {spoke_id} ({new_key})")

        self.spoke_queues[spoke_id].append(message)
        logger.info(f"Queued message {message.header.message_id} for offline spoke {spoke_id}")
        await self._asave()

    async def flush_mailbox(self, spoke_id: str, send_func):
        """
        Sends all queued messages for a newly connected spoke.
        """
        if spoke_id in self.spoke_queues and self.spoke_queues[spoke_id]:
            messages = self.spoke_queues[spoke_id][:]
            logger.info(f"Flushing mailbox for spoke {spoke_id} ({len(messages)} messages)")

            now = time.time()
            deferred: List[Message] = []
            for msg in messages:
                # Delivery cooldown: don't re-deliver a SPOKE_UPDATE for the same
                # (repo|branch) within the window. DEFER it (keep it queued) so a
                # stuck/never-acked update can't re-fire a pull+restart on every
                # reconnect, while a genuinely-new tip still lands after the
                # window. A hub restart clears _spoke_update_delivered, so a real
                # pending update flushes promptly post-restart.
                if _is_spoke_update(msg):
                    key = _spoke_update_key(spoke_id, msg)
                    last = self._spoke_update_delivered.get(key, 0.0)
                    if (now - last) < SPOKE_UPDATE_DELIVERY_COOLDOWN_S:
                        left = int(SPOKE_UPDATE_DELIVERY_COOLDOWN_S - (now - last))
                        logger.info(f"Deferring SPOKE_UPDATE for {spoke_id} ({key}) — "
                                    f"delivery cooldown {left}s remaining")
                        deferred.append(msg)
                        continue
                await self.push(msg, send_func)

            # Retain only the cooldown-deferred messages; everything else was
            # pushed into pending_ack.
            self.spoke_queues[spoke_id] = deferred
            await self._asave()

    def _expire_stale(self, now: float, connected: Optional[set] = None) -> int:
        """Drop backlog messages from BOTH pending_ack and the per-spoke offline
        queues when either:

          • AGE: older than min(their ttl, backlog_max_age_s) — the absolute
            catch-all so nothing lingers to the 24h ttl; or
          • SUPERSEDED: the destination spoke is CONNECTED and has acked NEWER
            traffic (``_last_ack_ts[spoke] > msg.send_time + grace``) — proof
            the spoke is alive and draining, so this older still-pending message
            was passed over and won't be acked. Drops in ~45s instead of 1h.

        Returns the count expired. Non-raising; caller persists if non-zero."""
        cap = self.backlog_max_age_s if self.backlog_max_age_s and self.backlog_max_age_s > 0 else None
        connected = connected or set()

        def _superseded(msg: Message, stamp: float) -> bool:
            sid = getattr(msg.header, "destination_id", None)
            if not sid or sid not in connected:
                return False
            stamp = float(stamp or now)
            if (now - stamp) < BACKLOG_SUPERSEDE_GRACE_S:
                return False  # give a fresh message a fair chance first
            last_ack = self._last_ack_ts.get(sid, 0.0)
            return last_ack > (stamp + BACKLOG_SUPERSEDE_GRACE_S)

        def _expired(msg: Message, stamp: float) -> bool:
            if _superseded(msg, stamp):
                return True
            age = now - float(stamp or now)
            limit = float(getattr(msg.header, "ttl", 86400) or 86400)
            if cap is not None:
                limit = min(limit, cap)
            return age >= limit

        dropped = 0
        by_type: Dict[str, int] = {}
        for mid in [m for m, (msg, first_sent, _r) in self.pending_ack.items()
                    if _expired(msg, first_sent)]:
            msg = self.pending_ack[mid][0]
            by_type[getattr(msg.payload, "type", "?") or "?"] = \
                by_type.get(getattr(msg.payload, "type", "?") or "?", 0) + 1
            del self.pending_ack[mid]
            dropped += 1
        for sid in list(self.spoke_queues.keys()):
            keep: List[Message] = []
            for msg in self.spoke_queues[sid]:
                if _expired(msg, getattr(msg.header, "timestamp", now)):
                    t = getattr(msg.payload, "type", "?") or "?"
                    by_type[t] = by_type.get(t, 0) + 1
                    dropped += 1
                else:
                    keep.append(msg)
            self.spoke_queues[sid] = keep
        if dropped:
            logger.warning("[backlog-expiry] dropped %d stale backlog message(s) "
                           "(older than %ss): %s", dropped,
                           int(cap) if cap else "ttl", by_type)
        return dropped

    async def retry_loop(self, send_func_map):
        """
        Periodically checks for messages that haven't been acknowledged and retries them.
        send_func_map: { spoke_id: send_func }
        """
        while True:
            now = time.time()
            to_retry = []

            changed = False
            # Proactive stale-backlog expiry (throttled) — drop entries past
            # their age cap so a stuck message can't linger to its 24h ttl.
            if (now - self._last_expiry_sweep) >= BACKLOG_EXPIRY_SWEEP_INTERVAL_S:
                self._last_expiry_sweep = now
                if self._expire_stale(now, connected=set(send_func_map or {})):
                    changed = True
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
                    logger.debug(f"Retrying message {msg_id} (Attempt {retries + 1})")
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
                    logger.debug(f"Spoke {spoke_id} offline. Moving message {msg_id} to offline queue.")
                    await self.queue_for_spoke(spoke_id, msg)  # saves its own change
                    del self.pending_ack[msg_id]

            if changed:
                await self._asave()

            await asyncio.sleep(1)

    async def clear_spoke(self, spoke_id: str) -> int:
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
            await self._asave()
        return dropped

    async def rename_spoke(self, old_id: str, new_id: str) -> None:
        """Re-key a spoke's mailbox state from ``old_id`` → ``new_id``.

        The guid-primary migration counterpart to
        KeyManager.rename_spoke_keys / StateManager.rename_module: when a
        spoke is lazily re-keyed to its guid, its queued + pending-ack
        messages + per-spoke cooldown / last-ack tracking must move with it
        so delivery survives the rename. Idempotent (no-op if
        ``old_id == new_id`` or ``old_id`` has no state). Best-effort,
        non-raising."""
        if old_id == new_id:
            return
        moved = False
        # Offline queue. Re-point each queued message's destination_id too so
        # a later flush delivers to the new id even before send_to_spoke
        # resolves the destination via _primary_key.
        if old_id in self.spoke_queues:
            queued = self.spoke_queues.pop(old_id)
            for _q in queued:
                if getattr(_q.header, "destination_id", None) == old_id:
                    _q.header.destination_id = new_id
            self.spoke_queues[new_id] = queued
            moved = True
        # Per-spoke last-ack time (drives the supersession expiry).
        if old_id in self._last_ack_ts:
            self._last_ack_ts[new_id] = self._last_ack_ts.pop(old_id)
            moved = True
        # SPOKE_UPDATE delivery-cooldown keys are "{spoke}|{repo}|{branch}".
        old_prefix = f"{old_id}|"
        for key in list(self._spoke_update_delivered.keys()):
            if key.startswith(old_prefix):
                self._spoke_update_delivered[f"{new_id}|{key[len(old_prefix):]}"] = \
                    self._spoke_update_delivered.pop(key)
                moved = True
        # pending_ack: re-point each pending message's destination_id so the
        # retry loop + send_to_spoke route to the new id (mirrors clear_spoke's
        # iteration). MessageHeader is a mutable dataclass → in-place setattr.
        # message_id keys are global (not per-spoke), so only the embedded
        # header destination moves.
        for _mid, (msg, _ts, _retries) in list(self.pending_ack.items()):
            if getattr(msg.header, "destination_id", None) == old_id:
                msg.header.destination_id = new_id
                moved = True
        if moved:
            logger.info(f"Re-keyed mailbox for spoke {old_id} → {new_id}")
            await self._asave()

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

    def backlog_stats(self) -> Dict[str, Any]:
        """Snapshot of the outbound backlog for the Hub Status UI. Splits the
        two kinds (``pending_ack`` = sent-but-unacked; ``queued`` = waiting for
        an offline/flapping spoke to reconnect) and breaks the total down by
        message type and destination spoke, plus the oldest entry's age. A
        backlog that won't drain shows up here: e.g. a pile of SPOKE_UPDATE to
        one flapping spoke, or many entries all destined for the same spoke.
        Non-raising (best-effort)."""
        now = time.time()
        by_type: Dict[str, int] = {}
        by_spoke: Dict[str, int] = {}
        oldest = 0.0

        def _tally(m: Message) -> None:
            t = getattr(m.payload, "type", None) or "?"
            by_type[t] = by_type.get(t, 0) + 1
            sid = getattr(m.header, "destination_id", None) or "?"
            by_spoke[sid] = by_spoke.get(sid, 0) + 1

        for msg, first_sent, _retries in self.pending_ack.values():
            _tally(msg)
            oldest = max(oldest, now - float(first_sent or now))
        queued = 0
        for q in self.spoke_queues.values():
            for msg in q:
                queued += 1
                _tally(msg)
                oldest = max(oldest, now - float(getattr(msg.header, "timestamp", now) or now))
        pending = len(self.pending_ack)
        return {
            "total": pending + queued,
            "pending_ack": pending,
            "queued": queued,
            "by_type": by_type,
            "by_spoke": by_spoke,
            "oldest_age_s": int(oldest),
        }

    async def purge_all(self, msg_type: Optional[str] = None) -> int:
        """Diag: drop backlog messages — all, or only those of ``msg_type`` —
        from BOTH ``pending_ack`` and the per-spoke offline queues. Returns the
        count dropped. Backs the Hub Status 'Drop Backlog' button so an operator
        can clear a stuck backlog (e.g. undeliverable SPOKE_UPDATE to a flapping
        spoke) without deleting the spoke. Non-raising."""
        dropped = 0
        for mid in [m for m, (msg, _, _) in self.pending_ack.items()
                    if msg_type is None or getattr(msg.payload, "type", None) == msg_type]:
            del self.pending_ack[mid]
            dropped += 1
        for sid in list(self.spoke_queues.keys()):
            keep: List[Message] = []
            for msg in self.spoke_queues[sid]:
                if msg_type is None or getattr(msg.payload, "type", None) == msg_type:
                    dropped += 1
                else:
                    keep.append(msg)
            self.spoke_queues[sid] = keep
        if dropped:
            logger.info("Purged %d backlog message(s)%s (diag).", dropped,
                        f" of type {msg_type}" if msg_type else "")
            await self._asave()
        return dropped
