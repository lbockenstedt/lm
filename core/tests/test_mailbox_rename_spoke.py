"""Phase 2a: Mailbox.rename_spoke re-keys every spoke_id-keyed store.

Defined here ahead of the Phase 2b migration trigger (which calls it). Verifies
the queue, per-spoke last-ack, SPOKE_UPDATE delivery-cooldown keys, and
pending-ack destinations all move old→new; that unrelated spokes are untouched;
that it persists; and that it is idempotent / a safe no-op.
"""
import asyncio
from messaging.mailbox import Mailbox
from messaging.protocol import Message, MessageHeader, MessagePayload


def _msg(dest: str, mid: str) -> Message:
    return Message(header=MessageHeader(message_id=mid, destination_id=dest),
                   payload=MessagePayload(type="COMMAND", data={}))


def test_rename_spoke_moves_queue_and_persists(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.queue_for_spoke("old", _msg("old", "m1")))
    assert "old" in mb.spoke_queues and len(mb.spoke_queues["old"]) == 1

    asyncio.run(mb.rename_spoke("old", "new"))

    assert "old" not in mb.spoke_queues
    assert "new" in mb.spoke_queues
    assert mb.spoke_queues["new"][0].header.destination_id == "new"
    # Persisted: a fresh Mailbox on the same dir auto-loads the queue under "new".
    mb2 = Mailbox(state_dir=str(tmp_path))
    assert "new" in mb2.spoke_queues and "old" not in mb2.spoke_queues


def test_rename_spoke_rekeys_cooldown_last_ack_and_pending(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    mb._last_ack_ts["old"] = 1234.0
    mb._spoke_update_delivered["old|repo-x|main"] = 999.0
    mb._spoke_update_delivered["other|repo-y|dev"] = 888.0  # must NOT move
    mb.pending_ack["m1"] = (_msg("old", "m1"), 100.0, 0)
    mb.pending_ack["m2"] = (_msg("other", "m2"), 100.0, 0)  # must NOT move

    asyncio.run(mb.rename_spoke("old", "new"))

    assert "old" not in mb._last_ack_ts and mb._last_ack_ts["new"] == 1234.0
    assert "old|repo-x|main" not in mb._spoke_update_delivered
    assert mb._spoke_update_delivered["new|repo-x|main"] == 999.0
    assert mb._spoke_update_delivered["other|repo-y|dev"] == 888.0
    assert mb.pending_ack["m1"][0].header.destination_id == "new"
    assert mb.pending_ack["m2"][0].header.destination_id == "other"


def test_rename_spoke_idempotent_and_noop(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.rename_spoke("x", "x"))        # old == new → no-op
    asyncio.run(mb.rename_spoke("ghost", "g2"))   # no state → no-op
    assert mb.spoke_queues == {}
    assert mb._last_ack_ts == {}
