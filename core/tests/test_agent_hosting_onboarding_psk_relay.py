"""A zero-touch agent presenting an onboarding PSK + tenant hint on its
initial ``/ws/agent`` connect must have that credential relayed UP to the hub
(as ``AGENT_ONBOARDING_PSK``) immediately, fire-and-forget — the hub validates
it and, on a match, auto-approves the agent without an admin click (see
main.py's ``_handle_agent_onboarding_psk`` / ``_try_psk_agent_auto_approve``).

Mirrors test_agent_hosting_frame_decode.py's harness: drive the inherited
``_agent_handler`` through a fake websocket whose recv() feeds the auth
handshake, then raises (empty queue) to unwind the pending-keepalive loop
promptly instead of hanging.
"""
import asyncio
import json
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402
from core.src.security.signer import MessageSigner                     # noqa: E402

SECRET = "test-agent-secret-1234567890"


class _Host(AgentHostingControlPlane):
    """Minimal harness — bypass the heavy BaseControlPlane.__init__ and set
    only the attributes ``_agent_handler``/``send_to_hub`` touch."""

    def __init__(self):
        self.agent_secret = SECRET
        self.agent_signer = MessageSigner(SECRET)
        self.connected_agents = {}
        self.pending_agents = {}
        self.relayed_to_hub = []  # (payload_type, data)

    async def send_to_hub(self, payload_type, data):
        self.relayed_to_hub.append((payload_type, data))
        return True


class _FakeAgentWS:
    """recv() feeds the zero-touch auth handshake (no secret), then raises
    (empty queue) so the pending-keepalive loop unwinds immediately instead of
    blocking on asyncio.wait_for — the outer ``except Exception: pass``
    already tolerates this, matching a genuine disconnect-while-pending."""

    def __init__(self, auth):
        self._recv = [json.dumps(auth)]
        self.sent = []
        self.closed = None

    async def recv(self):
        return self._recv.pop(0)  # IndexError once exhausted → unwinds the loop

    async def send(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_psk_and_tenant_hint_are_relayed_to_hub():
    host = _Host()
    ws = _FakeAgentWS({"agent_id": "pxmx-node-1", "onboarding_psk": "the-psk",
                       "tenant_hint": "lrb", "hostname": "pxmx-node-1",
                       "install_uuid": "uuid-1"})
    _run(host._agent_handler(ws, path="/ws/agent"))

    assert len(host.relayed_to_hub) == 1
    ptype, data = host.relayed_to_hub[0]
    assert ptype == "AGENT_ONBOARDING_PSK"
    assert data == {"agent_id": "pxmx-node-1", "psk": "the-psk",
                     "tenant_hint": "lrb", "hostname": "pxmx-node-1",
                     "install_uuid": "uuid-1"}
    # Still enters pending approval normally (APPROVAL_REQUIRED sent).
    assert json.loads(ws.sent[0])["status"] == "APPROVAL_REQUIRED"


def test_missing_psk_or_tenant_hint_relays_nothing():
    for auth in (
        {"agent_id": "a1"},
        {"agent_id": "a1", "onboarding_psk": "x"},
        {"agent_id": "a1", "tenant_hint": "lrb"},
    ):
        host = _Host()
        _run(host._agent_handler(_FakeAgentWS(auth), path="/ws/agent"))
        assert host.relayed_to_hub == [], f"unexpected relay for auth={auth!r}"


def test_authenticated_connect_never_relays_onboarding_psk():
    """A normal (secret-bearing) connect skips the zero-touch branch entirely
    — no AGENT_ONBOARDING_PSK relay, even if onboarding_psk/tenant_hint were
    (nonsensically) also present."""
    host = _Host()
    ws = _FakeAgentWS({"agent_id": "pxmx-node-1", "secret": SECRET,
                       "onboarding_psk": "the-psk", "tenant_hint": "lrb"})
    ws._recv.append(json.dumps({"status": "HUB_OK"}))

    class _NoFrames:
        def __aiter__(self):
            return self

        async def __anext__(self):
            raise StopAsyncIteration

    ws.__aiter__ = _NoFrames().__aiter__
    ws.__anext__ = _NoFrames().__anext__
    _run(host._agent_handler(ws, path="/ws/agent"))
    assert host.relayed_to_hub == []


def test_send_to_hub_failure_does_not_break_the_pending_loop():
    """A relay failure (e.g. not yet connected to the hub) must not prevent
    the agent from still landing in pending_agents / getting APPROVAL_REQUIRED
    — best-effort, matches the docstring."""
    class _FailHost(_Host):
        async def send_to_hub(self, payload_type, data):
            raise RuntimeError("hub not connected")

    host = _FailHost()
    ws = _FakeAgentWS({"agent_id": "pxmx-node-1", "onboarding_psk": "the-psk",
                       "tenant_hint": "lrb"})
    _run(host._agent_handler(ws, path="/ws/agent"))
    assert json.loads(ws.sent[0])["status"] == "APPROVAL_REQUIRED"
    assert ws.closed is None
