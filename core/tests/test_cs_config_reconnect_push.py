"""Hub-side cs reconnect / CS_CONFIG_REQUEST handling and the mailbox merge.

* push_config_to_spoke's cs branch DEFERS while handle_connection has marked
  the spoke (the push then runs as a task after the mailbox flush), and pushes
  directly otherwise.
* _handle_cs_config_request skips a matching hash and a just-pushed spoke.
* Mailbox.queue_for_spoke folds queued CS_CONFIG_UPDATE patches (newer wins).
"""

import asyncio
import time

import main
from messaging.mailbox import Mailbox, merge_cs_config_updates
from messaging.protocol import Message, MessageHeader, MessagePayload


class _Hub:
    _CS_FULL_PUSH_DEDUP_S = main.LabManagerHub._CS_FULL_PUSH_DEDUP_S

    def __init__(self, expected="h1", full_result=1):
        self._cs_full_push_ts = {}
        self._cs_connect_defer = {}
        self.calls = []
        self.legacy = []
        self._expected = expected
        self._full_result = full_result

    def _primary_key(self, sid):
        return sid

    async def _cs_full_config_push(self, sid, reason=""):
        self.calls.append((sid, reason))
        return self._full_result

    async def _cs_expected_config_hash(self, sid):
        return self._expected

    async def push_cs_hub_config(self, sid):
        self.legacy.append(sid)

    async def push_cs_full_config(self, sid, reason="reconnect"):
        return await main.LabManagerHub.push_cs_full_config(self, sid, reason)


def test_full_push_records_timestamp_and_skips_legacy():
    hub = _Hub()
    asyncio.run(main.LabManagerHub.push_cs_full_config(hub, "s1", "reconnect"))
    assert hub.calls == [("s1", "reconnect")]
    assert hub.legacy == []
    assert time.time() - hub._cs_full_push_ts["s1"] < 5


def test_full_push_falls_back_to_legacy_when_nothing_reached():
    hub = _Hub(full_result=0)
    asyncio.run(main.LabManagerHub.push_cs_full_config(hub, "s1"))
    assert hub.legacy == ["s1"]


def test_config_request_with_matching_hash_is_noop():
    hub = _Hub(expected="abc")
    asyncio.run(main.LabManagerHub._handle_cs_config_request(hub, "s1", "abc"))
    assert hub.calls == []


def test_config_request_mismatch_or_empty_hash_pushes():
    hub = _Hub(expected="abc")
    asyncio.run(main.LabManagerHub._handle_cs_config_request(hub, "s1", "old"))
    hub._cs_full_push_ts.clear()
    asyncio.run(main.LabManagerHub._handle_cs_config_request(hub, "s2", ""))
    assert hub.calls == [("s1", "request"), ("s2", "request")]


def test_config_request_deduped_after_recent_reconnect_push():
    hub = _Hub(expected="abc")
    hub._cs_full_push_ts["s1"] = time.time()
    asyncio.run(main.LabManagerHub._handle_cs_config_request(hub, "s1", "old"))
    assert hub.calls == []


def _cfg_msg(mid, data, dest="s1"):
    return Message(header=MessageHeader(message_id=mid, destination_id=dest),
                   payload=MessagePayload(type="CS_CONFIG_UPDATE", data=data))


def test_merge_helper_newer_wins_and_drops_stale_full_meta():
    out = merge_cs_config_updates(
        {"a": 1, "b": 1, "config_hash": "x", "full_config": True}, {"b": 2})
    assert out == {"a": 1, "b": 2}
    out = merge_cs_config_updates({"a": 1}, {"full_config": True, "config_hash": "y"})
    assert out == {"a": 1, "full_config": True, "config_hash": "y"}
    assert merge_cs_config_updates(None, None) == {}


def test_mailbox_merges_queued_cs_config_updates(tmp_path):
    mb = Mailbox(state_dir=str(tmp_path))
    other = Message(header=MessageHeader(message_id="c1", destination_id="s1"),
                    payload=MessagePayload(type="COMMAND", data={}))
    asyncio.run(mb.queue_for_spoke("s1", _cfg_msg("m1", {"central_config": {"v": 1}, "x": 1})))
    asyncio.run(mb.queue_for_spoke("s1", other))
    asyncio.run(mb.queue_for_spoke("s1", _cfg_msg("m2", {"central_config": {"v": 2}})))
    q = mb.spoke_queues["s1"]
    cfgs = [m for m in q if m.payload.type == "CS_CONFIG_UPDATE"]
    assert len(cfgs) == 1
    assert cfgs[0].header.message_id == "m2"
    assert cfgs[0].payload.data == {"central_config": {"v": 2}, "x": 1}
    assert any(m.payload.type == "COMMAND" for m in q)
