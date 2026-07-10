"""Regression: the agent-hosting message loop must decode the ``<sig>.<body>``
wire form the agent actually sends (encode_frame), not do a bare
``json.loads(raw)``.

The bug (observed on cs-svr-03): an APPROVED pxmx agent completed the plain-JSON
auth handshake, then sent its first AGENT_HEARTBEAT/AGENT_TELEMETRY as
``<hex-hmac>.<compact-json>``. The stale spoke loop did ``json.loads(raw)`` on
that whole string and raised ``JSONDecodeError`` ("Expecting value: line 1
column 1" when the HMAC began a-f; "Extra data: line 1 column N" when it began
with N digits). The exception propagated out of ``async for``, tore the whole
connection down on the FIRST frame, and the agent reconnected in a tight,
no-backoff flap (~1/s, spamming tracebacks).

These tests drive the inherited ``_agent_handler`` through a fake websocket and
assert: a valid ``<sig>.<body>`` frame is processed, the legacy ``{...}``
dict-envelope still works, and a forged/garbage frame is dropped per-frame
(continue) WITHOUT tearing down the connection.
"""
import asyncio
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner, encode_frame       # noqa: E402

SECRET = "test-agent-secret-1234567890"


class _Host(AgentHostingControlPlane):
    """Minimal harness — bypass the heavy BaseControlPlane.__init__ and set only
    the attributes ``_agent_handler`` touches."""

    def __init__(self, secret):
        self.agent_secret = secret
        self.agent_signer = MessageSigner(secret)
        self.connected_agents = {}
        self.pending_agents = {}
        self.pending_responses = {}
        self.relayed = []
        self.telemetry = []

    async def _on_agent_registered(self, agent_id):
        pass

    async def _on_agent_telemetry(self, agent_id, rec, data):
        self.telemetry.append((agent_id, data))

    async def _relay_agent_msg_up(self, agent_id, msg_type, data):
        self.relayed.append((agent_id, msg_type, data))


class _FakeAgentWS:
    """recv() feeds the auth handshake (plain JSON, as the real agent sends via
    json.dumps); iterating the socket yields the post-auth frames under test."""

    def __init__(self, frames, agent_id="pxmx-test-agent"):
        self._recv = [
            json.dumps({"agent_id": agent_id, "secret": SECRET,
                        "install_uuid": "uuid-1", "hostname": "test-host"}),
            json.dumps({"status": "HUB_OK"}),
        ]
        self._frames = list(frames)
        self.sent = []
        self.closed = None

    async def recv(self):
        return self._recv.pop(0)

    async def send(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._frames:
            return self._frames.pop(0)
        raise StopAsyncIteration


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _heartbeat_body(corr="c1"):
    return {"header": {"correlation_id": corr},
            "payload": {"type": "AGENT_HEARTBEAT", "data": {"ok": 1}}}


def test_valid_sig_body_frame_is_decoded_and_relayed():
    signer = MessageSigner(SECRET)
    good = encode_frame(signer, _heartbeat_body())
    # Sanity: this is the exact shape the old json.loads(raw) choked on.
    assert "." in good and good[:1] != "{"

    host = _Host(SECRET)
    ws = _FakeAgentWS([good])
    _run(host._agent_handler(ws, path="/ws/agent"))

    assert ("pxmx-test-agent", "AGENT_HEARTBEAT", {"ok": 1}) in host.relayed
    assert ws.closed is None  # completed cleanly, no forced 1008 teardown


def test_legacy_dict_envelope_still_accepted():
    signer = MessageSigner(SECRET)
    env = _heartbeat_body("legacy")
    env["signature"] = signer.sign(env)
    wire = json.dumps(env, separators=(",", ":"))
    assert wire[:1] == "{"

    host = _Host(SECRET)
    _run(host._agent_handler(_FakeAgentWS([wire]), path="/ws/agent"))

    assert host.relayed and host.relayed[0][1] == "AGENT_HEARTBEAT"


def test_forged_and_garbage_frames_are_dropped_not_fatal():
    signer = MessageSigner(SECRET)
    good = encode_frame(signer, _heartbeat_body("after"))

    body = json.dumps(_heartbeat_body("forged"), separators=(",", ":"))
    forged = "0" * 64 + "." + body          # well-formed frame, bad HMAC
    garbage = "5garbage-not-a-frame"        # no '.', unsigned → dropped
    empty = ""                              # what "Expecting value col 1" was

    host = _Host(SECRET)
    # A bad frame BEFORE a good one must not prevent the good one from being
    # processed — i.e. the loop survives the bad frame instead of tearing down.
    ws = _FakeAgentWS([forged, garbage, empty, good])
    _run(host._agent_handler(ws, path="/ws/agent"))

    # Exactly the trailing valid frame got through; none of the bad ones did.
    assert host.relayed == [("pxmx-test-agent", "AGENT_HEARTBEAT", {"ok": 1})]
    assert ws.closed is None


def test_unexpected_path_is_rejected():
    host = _Host(SECRET)
    ws = _FakeAgentWS([])
    _run(host._agent_handler(ws, path="/ws/wrong"))
    assert ws.closed and ws.closed[0] == 1008


# ── spoke → hub relay wire form ──────────────────────────────────────────────

class _FakeHubWS:
    def __init__(self):
        self.sent = []

    async def send(self, wire):
        self.sent.append(wire)


def test_relay_up_uses_sig_body_wire_the_hub_can_decode():
    """_relay_agent_msg_up must emit ``<sig>.<body>`` (what the hub's
    split_frame + json.loads(body) + verify_signature expects), NOT the legacy
    dict-envelope. The dict-envelope's header ``timestamp`` is a float, so the
    hub's split_frame split on that '.' and json.loads(body) failed → every
    relayed agent frame (heartbeat/telemetry/CS_*/log) was dropped → hosted
    agents stuck 'offline' despite a healthy agent↔spoke link."""
    from core.src.security.signer import split_frame  # noqa: E402

    host = _Host(SECRET)
    host.spoke_id = "cs-svr-02-spoke"
    host.signer = MessageSigner(SECRET)  # spoke↔hub session signer
    host.connected_agents = {
        "pxmx-cs-svr-02-agent": {"install_uuid": "u1", "hostname": "pxmx-cs-svr-02"}}
    host._hub_ws = _FakeHubWS()

    # _Host stubs _relay_agent_msg_up for the handler tests above; exercise the
    # REAL inherited implementation here.
    _run(AgentHostingControlPlane._relay_agent_msg_up(
        host, "pxmx-cs-svr-02-agent", "AGENT_HEARTBEAT", {"x": 1}))

    assert len(host._hub_ws.sent) == 1
    wire = host._hub_ws.sent[0]

    # Wire is <sig>.<body>: sig is a 64-char hex HMAC (no '.'), body is the FULL
    # relay JSON — exactly what the hub decodes.
    sig, body = split_frame(wire)
    assert len(sig) == 64 and "." not in sig
    parsed = json.loads(body)  # the hub's json.loads(body_str) must succeed
    assert parsed["payload"]["type"] == "AGENT_RELAY_UP"
    inner = parsed["payload"]["data"]["original_payload"]["payload"]
    assert inner["type"] == "AGENT_HEARTBEAT" and inner["data"] == {"x": 1}
    # The hub verifies the RECEIVED body bytes against sig — that must pass.
    assert MessageSigner(SECRET).verify_bytes(body.encode(), sig)


def test_legacy_dict_envelope_would_have_been_dropped_by_hub():
    """Documents the bug: a dict-envelope with a float timestamp is mis-split by
    the hub's split_frame (first '.' is inside the timestamp), so json.loads(body)
    raises — the frame the hub silently dropped."""
    from core.src.security.signer import split_frame  # noqa: E402
    import pytest  # noqa: E402

    legacy = {"header": {"message_id": "no-dots-uuid", "timestamp": 1783658368.1234},
              "payload": {"type": "AGENT_RELAY_UP", "data": {}}}
    legacy["signature"] = MessageSigner(SECRET).sign(legacy)
    legacy_wire = json.dumps(legacy, separators=(",", ":"))

    _sig, body = split_frame(legacy_wire)
    assert body.startswith("1234")  # split landed inside the timestamp float
    with pytest.raises(Exception):
        json.loads(body)
