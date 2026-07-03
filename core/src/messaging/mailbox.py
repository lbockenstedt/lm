"""LM Hub message delivery — pending-ack tracking and offline queuing.

``Mailbox`` owns the Hub-side outbound queue: every message sent via ``push``
is recorded in ``pending_ack`` until the spoke acknowledges it, retried on an
exponential backoff schedule, and — if the spoke is offline — moved to a
per-spoke offline queue (``spoke_queues``) that is flushed on reconnect. This
is the retry/durability layer for non-heartbeat traffic; heartbeats themselves
are not ack-tracked here (their liveness signal flows through
``heartbeat.py``). The envelope shape for both messages and acks is defined in
``protocol.py``.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional
from .protocol import Message, Acknowledgement, MessagePriority

# Logging configured by the process entrypoint (hub main.py); see base_spoke.py.
logger = logging.getLogger("Mailbox")

class Mailbox:
    def __init__(self):
        # Messages sent by the Hub that are awaiting an Ack
        # { message_id: (message, first_sent_time, retry_count) }
        self.pending_ack: Dict[str, tuple[Message, float, int]] = {}

        # Mailboxes for spokes (messages queued while spoke is offline)
        # { spoke_id: [Message, ...] }
        self.spoke_queues: Dict[str, List[Message]] = {}

        self.retry_intervals = [5, 15, 60, 300, 900]  # Exponential backoff intervals in seconds

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

    async def acknowledge(self, ack: Acknowledgement):
        """
        Processes an acknowledgement and removes the corresponding message from the pending queue.
        """
        if ack.correlation_id in self.pending_ack:
            logger.info(f"Message {ack.correlation_id} acknowledged with status: {ack.status}")
            del self.pending_ack[ack.correlation_id]
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

    async def retry_loop(self, send_func_map):
        """
        Periodically checks for messages that haven't been acknowledged and retries them.
        send_func_map: { spoke_id: send_func }
        """
        while True:
            now = time.time()
            to_retry = []

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
                    continue

                wait_time = self.retry_intervals[retries]
                if now - last_sent >= wait_time:
                    to_retry.append((msg_id, msg, retries))

            for msg_id, msg, retries in to_retry:
                spoke_id = msg.header.destination_id
                send_func = send_func_map.get(spoke_id)

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
                    self.queue_for_spoke(spoke_id, msg)
                    del self.pending_ack[msg_id]

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
