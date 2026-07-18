"""``/ws/agent`` route — the unified :443 agent-WebSocket byte-proxy.

Under the unified-443 merge a pxmx agent dials ``wss://<hub>:443/ws/agent``; the
hub terminates TLS at :443 and dumb-pipes bytes to the co-located pxmx spoke's
loopback agent listener (``ws://127.0.0.1:<LM_PXMX_AGENT_PORT>/ws/agent``,
plaintext). The hub does NOT parse the agent protocol — auth/approval/telemetry/
signing all stay in the spoke's ``_agent_handler``.

These tests pin the proxy wiring (dial loopback → two-task byte pipe → close)
with a fake upstream swapped in for ``websockets.connect`` and a minimal fake
hub exposing ``pxmx_agent_port``. The loopback URI, both-direction byte flow,
and the unreachable-loopback → 1011 close are covered.
"""

import asyncio
import tempfile

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import api as api_mod


# ── Fakes ────────────────────────────────────────────────────────────────────
# Mirror test_spoke_ws_route's _FakeHub build-time surface (create_app +
# register_simulations_routes read state / simulations_store / simulations_cache
# / active_connections at app-build) and add ``pxmx_agent_port`` for the proxy.

class _FakeState:
    def __init__(self, data_dir):
        self.data_dir = data_dir

    def ensure_admin_lockout(self):
        return False

    def save_state(self):
        pass

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()


class _FakeHub:
    def __init__(self, data_dir, pxmx_agent_port=8443):
        self.state = _FakeState(data_dir)
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = {}
        self.pxmx_agent_port = pxmx_agent_port


class _FakeUpstream:
    """A websockets-lib client-connection stand-in: ``send`` records, async-iter
    yields pre-seeded replies then stops, ``close`` records."""

    def __init__(self, replies=None):
        self.sent = []
        self.closed = False
        self._replies = list(replies or [])

    async def send(self, msg):
        self.sent.append(msg)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._replies:
            return self._replies.pop(0)
        raise StopAsyncIteration

    async def close(self):
        self.closed = True


def _build_client(pxmx_agent_port=8443):
    tmp = tempfile.mkdtemp()
    hub = _FakeHub(tmp, pxmx_agent_port=pxmx_agent_port)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


def _ensure_loop():
    # Python 3.9: asyncio.Queue() (used inside create_app's routes) binds to the
    # current event loop at construction; ensure one exists for the TestClient
    # portal to share.
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


# ── Tests ────────────────────────────────────────────────────────────────────

def test_agent_proxy_pipes_both_ways_and_dials_loopback(monkeypatch):
    """An agent connects to /ws/agent; bytes flow agent→loopback (recorded) and
    loopback→agent (received by the client). Confirms the loopback URI is
    ``ws://127.0.0.1:<pxmx_agent_port>/ws/agent``."""
    _ensure_loop()
    upstream = _FakeUpstream(replies=["hello-from-spoke"])
    dialed = {}

    async def _connect(uri, **kwargs):
        dialed["uri"] = uri
        return upstream

    monkeypatch.setattr(api_mod.websockets, "connect", _connect)
    client, _hub = _build_client(pxmx_agent_port=8443)

    with client.websocket_connect("/ws/agent") as ws:
        ws.send_text("agent-hello")
        reply = ws.receive_text()

    assert reply == "hello-from-spoke"
    assert upstream.sent == ["agent-hello"]            # agent→loopback piped
    assert dialed["uri"] == "ws://127.0.0.1:8443/ws/agent"
    assert upstream.closed                              # proxy closed the loopback


def test_agent_proxy_pipes_binary_frames(monkeypatch):
    """Binary frames round-trip agent→loopback unchanged (the proxy is
    frame-type-agnostic, not text-only)."""
    _ensure_loop()
    upstream = _FakeUpstream(replies=[b"\x01\x02\x03"])

    async def _connect(uri, **kwargs):
        return upstream

    monkeypatch.setattr(api_mod.websockets, "connect", _connect)
    client, _hub = _build_client()

    with client.websocket_connect("/ws/agent") as ws:
        ws.send_bytes(b"\xaa\xbb")
        reply = ws.receive_bytes()

    assert reply == b"\x01\x02\x03"
    assert upstream.sent == [b"\xaa\xbb"]


def test_agent_proxy_closes_1011_when_loopback_unreachable(monkeypatch):
    """If the loopback dial fails (pxmx spoke not running / not co-located), the
    agent WS closes 1011 with a clear reason instead of hanging."""
    _ensure_loop()

    async def _connect(uri, **kwargs):
        raise ConnectionRefusedError("loopback down")

    monkeypatch.setattr(api_mod.websockets, "connect", _connect)
    client, _hub = _build_client()

    with client.websocket_connect("/ws/agent") as ws:
        try:
            ws.receive_text()
            closed = False
            code = None
        except WebSocketDisconnect as exc:
            closed = True
            code = exc.code

    assert closed
    assert code == 1011