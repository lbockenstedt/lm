"""Mailbox unknown-ack warning must name the source (sender spoke_id + frame
type + peer IP) so a stray/late acknowledgement can be triaged. The ack
envelope's own spoke_id is often None for these, so the receive path threads
the sender's identity + remote IP into the Acknowledgement (see main.py
handle_client) and mailbox.acknowledge() includes them in its WARNING.
"""
import asyncio
import logging

from messaging.mailbox import Mailbox
from messaging.protocol import (
    Acknowledgement, Message, MessageHeader, MessagePayload, MessagePriority,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_unknown_ack_warning_names_source_spoke_type_and_ip(caplog, tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    with caplog.at_level(logging.WARNING, logger="Mailbox"):
        asyncio.run(mb.acknowledge(Acknowledgement(
            correlation_id="838a423e-cf9b-4849-94ef-2684f880329f",
            status="FAILED",
            spoke_id="netbox-spoke-1",
            message_type="COMMAND_RESULT",
            source_ip="10.0.0.5",
        )))
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warns, "expected a WARNING for an unknown ack"
    msg = warns[0].getMessage()
    assert "unknown message ID" in msg
    assert "838a423e" in msg
    assert "spoke_id=netbox-spoke-1" in msg
    assert "message_type=COMMAND_RESULT" in msg
    assert "source_ip=10.0.0.5" in msg
    assert "status=FAILED" in msg


def test_known_ack_retires_no_unknown_warning(caplog, tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    m = Message(
        header=MessageHeader(message_id="m1", destination_id="s1",
                             priority=MessagePriority.NORMAL),
        payload=MessagePayload(type="COMMAND", data={}),
    )
    mb.pending_ack["m1"] = (m, 0.0, 0)
    with caplog.at_level(logging.WARNING, logger="Mailbox"):
        asyncio.run(mb.acknowledge(Acknowledgement(
            correlation_id="m1", status="SUCCESS",
            spoke_id="s1", source_ip="10.0.0.9",
        )))
    # Retired from pending_ack, no unknown-ack WARNING emitted.
    assert "m1" not in mb.pending_ack
    assert not [r for r in caplog.records if r.levelno == logging.WARNING
                and "unknown message ID" in r.getMessage()]


# ── retry_loop: a permanently-failing send must advance backoff + give up ──────
#
# Regression: the except branch only logged and did NOT bump retries or
# last_sent, so a send that always raises (e.g. sign_message "No key found" for
# an unapproved/keyless spoke) retried EVERY 1s loop at the SAME attempt number
# forever — flooding the log and never reaching the max-retries give-up branch.
# Now a failed retry advances retries + last_sent so the exponential schedule
# progresses and the message is dropped after len(retry_intervals) attempts.

def _msg(mid, dest="s1"):
    return Message(
        header=MessageHeader(message_id=mid, destination_id=dest,
                             priority=MessagePriority.NORMAL),
        payload=MessagePayload(type="COMMAND", data={}),
    )


def test_retry_advances_backoff_on_failure_then_drops(caplog, tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    # A message whose send always raises. Seed pending_ack with an old
    # last_sent so the first retry tick fires immediately.
    mb.pending_ack["m1"] = (_msg("m1"), 0.0, 0)

    async def always_fails(_msg):
        raise ValueError("No key found for spoke s1")

    send_map = {"s1": always_fails}

    # Drive the loop manually so the test is deterministic + fast: each tick,
    # set last_sent far in the past so the message is always "due", and run the
    # retry body once. After len(retry_intervals) failed attempts the message
    # must be gone (give-up branch), not stuck retrying at attempt 0/1.
    async def drive(n_ticks):
        for _ in range(n_ticks):
            # Force every pending message to be "due" this tick.
            for mid in list(mb.pending_ack.keys()):
                m, _ls, retries = mb.pending_ack[mid]
                mb.pending_ack[mid] = (m, 0.0, retries)
            # Re-run one iteration of retry_loop by invoking it and cancelling
            # after it processes due messages then sleeps.
            task = asyncio.create_task(mb.retry_loop(send_map))
            await asyncio.sleep(0)  # let it enter + process due messages
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    # 5 failed attempts (retries 0..4) then the 6th tick sees retries >=
    # len(intervals)=5 and drops it. Give a few extra ticks of slack.
    asyncio.run(drive(len(mb.retry_intervals) + 2))
    assert "m1" not in mb.pending_ack, (
        "permanently-failing message must be dropped after max retries, "
        "not retried forever at the same attempt number"
    )


def test_retry_succeeding_advances_retries_stays_pending(tmp_path):
    # A successful send does NOT retire the message — it stays in pending_ack
    # (still awaiting the spoke's ack) with retries bumped, so the backoff
    # schedule progresses between acks. Only acknowledge() retires it.
    mb = Mailbox(state_dir=str(tmp_path))
    mb.pending_ack["m1"] = (_msg("m1"), 0.0, 0)

    async def succeeds(_msg):
        return None

    send_map = {"s1": succeeds}

    async def drive():
        task = asyncio.create_task(mb.retry_loop(send_map))
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(drive())
    assert "m1" in mb.pending_ack  # still awaiting ack
    _, _, retries = mb.pending_ack["m1"]
    assert retries == 1  # bumped by the success branch


# ── clear_spoke: delete/reset/unapprove must purge stranded messages ──────────

def test_clear_spoke_drops_pending_ack_and_offline_queue(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    a = _msg("a", dest="s1")
    b = _msg("b", dest="s2")
    mb.pending_ack["a"] = (a, 0.0, 0)
    mb.pending_ack["b"] = (b, 0.0, 0)
    mb.queue_for_spoke("s1", _msg("q1", dest="s1"))
    mb.queue_for_spoke("s3", _msg("q3", dest="s3"))

    dropped = mb.clear_spoke("s1")

    assert dropped == 2  # 1 pending_ack + 1 queued
    assert "a" not in mb.pending_ack  # s1's pending entry gone
    assert "b" in mb.pending_ack  # other spokes untouched
    assert "s1" not in mb.spoke_queues
    assert "s3" in mb.spoke_queues  # other spokes' queues untouched


def test_clear_spoke_missing_spoke_is_noop(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    assert mb.clear_spoke("never-seen") == 0
    assert mb.pending_ack == {}
    assert mb.spoke_queues == {}