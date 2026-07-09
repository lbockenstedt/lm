"""Mailbox.pending_ack / spoke_queues were purely in-memory — a hub restart
silently dropped anything a temporarily-disconnected spoke hadn't acked yet,
including e.g. an in-flight SPOKE_UPDATE_SESSION_KEY. Persisted to
<state_dir>/mailbox.json (encrypted, same convention as StateManager) so a
fresh Mailbox() pointed at the same directory picks the queue back up —
a warm start across a hub restart/service reset.
"""
import asyncio

from messaging.mailbox import Mailbox
from messaging.protocol import Message, MessageHeader, MessagePayload, MessagePriority


def _msg(mid, dest="s1", mtype="COMMAND", data=None):
    return Message(
        header=MessageHeader(message_id=mid, destination_id=dest,
                             priority=MessagePriority.NORMAL),
        payload=MessagePayload(type=mtype, data=data or {}),
    )


def test_pending_ack_survives_a_fresh_mailbox_instance(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    mb.pending_ack["m1"] = (_msg("m1", dest="cs-svr-02-spoke",
                                mtype="CS_CONFIG_UPDATE",
                                data={"usb_auto_provision": "on"}), 12345.0, 2)
    mb._save()

    mb2 = Mailbox(state_dir=str(tmp_path))
    assert "m1" in mb2.pending_ack
    msg, first_sent, retries = mb2.pending_ack["m1"]
    assert msg.header.destination_id == "cs-svr-02-spoke"
    assert msg.payload.type == "CS_CONFIG_UPDATE"
    assert msg.payload.data == {"usb_auto_provision": "on"}
    assert first_sent == 12345.0
    assert retries == 2


def test_spoke_offline_queue_survives_a_fresh_mailbox_instance(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    # queue_for_spoke is async (awaits _asave to persist) — must be awaited, else
    # the coroutine never runs and nothing is queued/persisted.
    asyncio.run(mb.queue_for_spoke("cs-svr-02-spoke", _msg("q1", dest="cs-svr-02-spoke")))
    asyncio.run(mb.queue_for_spoke("cs-svr-02-spoke", _msg("q2", dest="cs-svr-02-spoke")))

    mb2 = Mailbox(state_dir=str(tmp_path))
    assert "cs-svr-02-spoke" in mb2.spoke_queues
    ids = [m.header.message_id for m in mb2.spoke_queues["cs-svr-02-spoke"]]
    assert ids == ["q1", "q2"]


def test_push_persists_and_ack_removes_from_disk(tmp_path):
    async def ok_send(_msg):
        return None

    mb = Mailbox(state_dir=str(tmp_path))
    asyncio.run(mb.push(_msg("m1"), ok_send))

    mb2 = Mailbox(state_dir=str(tmp_path))
    assert "m1" in mb2.pending_ack

    from messaging.protocol import Acknowledgement
    asyncio.run(mb2.acknowledge(Acknowledgement(correlation_id="m1", status="SUCCESS")))

    mb3 = Mailbox(state_dir=str(tmp_path))
    assert "m1" not in mb3.pending_ack


def test_fresh_mailbox_with_no_file_starts_empty(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    assert mb.pending_ack == {}
    assert mb.spoke_queues == {}


def test_corrupt_mailbox_file_degrades_to_empty(tmp_path):
    bad_path = tmp_path / "mailbox.json"
    bad_path.write_bytes(b"not encrypted json garbage")
    mb = Mailbox(state_dir=str(tmp_path))
    assert mb.pending_ack == {}
    assert mb.spoke_queues == {}
