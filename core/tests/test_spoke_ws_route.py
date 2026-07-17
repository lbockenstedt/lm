"""``/ws/spoke`` route — the unified :443 spoke-WebSocket endpoint.

Replaces the former bare ``websockets.serve`` listener (8765 loopback / 443
wss) that lived in the hub's main asyncio loop. The route ``accept()``s the
Starlette ``WebSocket``, wraps it in ``StarletteWSAdapter``, and hands it to
``hub.handle_connection`` — which owns the full mutual-auth + signed-frame
dispatch loop and expects a websockets-lib-style socket.

These tests pin the wiring (accept → adapter → handle_connection) with a
minimal fake hub whose ``handle_connection`` exercises the adapter's
recv/send/close surface end-to-end through a Starlette ``TestClient``. The
real 411-line ``handle_connection`` is covered by the existing spoke-protocol
suite; here we only lock in that the route plumbs the I/O boundary correctly.
"""

import asyncio
import tempfile

from fastapi.testclient import TestClient

import api as api_mod


# ── Fakes ────────────────────────────────────────────────────────────────────
# Mirror test_pxmx_console_ws._FakeHub's build-time surface (create_app +
# register_simulations_routes capture these at app-build time) and add the
# handle_connection the /ws/spoke route calls.

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
    """Minimal hub whose ``handle_connection`` echoes one frame then closes.

    Records the adapter's ``remote_address`` so the test can confirm the
    Starlette client tuple flowed through to the handler.
    """

    def __init__(self, data_dir):
        self.state = _FakeState(data_dir)
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = {}
        self.seen_remote = None
        self.received = []

    async def handle_connection(self, ws):
        # The real handler does mutual auth + a dispatch loop; here we just
        # prove the adapter's recv/send/close work through the route.
        self.seen_remote = ws.remote_address
        msg = await ws.recv()
        self.received.append(msg)
        await ws.send(f"echo:{msg}")
        await ws.close(1000, "done")


def _build_client():
    tmp = tempfile.mkdtemp()
    hub = _FakeHub(tmp)
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

def test_spoke_ws_route_echoes_through_adapter():
    """A spoke connects to /ws/spoke, sends one frame, and receives the hub's
    reply — proving accept → StarletteWSAdapter → handle_connection recv/send."""
    _ensure_loop()
    client, hub = _build_client()

    with client.websocket_connect("/ws/spoke") as ws:
        ws.send_text("hello")
        reply = ws.receive_text()

    assert reply == "echo:hello"
    assert hub.received == ["hello"]


def test_spoke_ws_route_sees_remote_address():
    """The adapter's ``remote_address`` (from the Starlette client tuple)
    reaches ``handle_connection`` so the real handler can telemetry the peer."""
    _ensure_loop()
    client, hub = _build_client()

    with client.websocket_connect("/ws/spoke") as ws:
        ws.send_text("ping")
        ws.receive_text()

    # TestClient connects from a synthetic client → a (host, port) tuple
    # (Starlette uses "testclient" as the host). What matters is that the
    # adapter's remote_address flowed through to the handler as a 2-tuple.
    assert hub.seen_remote is not None
    assert isinstance(hub.seen_remote, tuple) and len(hub.seen_remote) == 2


def test_spoke_ws_route_clean_close_after_handler_returns():
    """When ``handle_connection`` returns (after close), the WS is closed
    cleanly — the client sees a disconnect, not a hang."""
    _ensure_loop()
    client, hub = _build_client()

    with client.websocket_connect("/ws/spoke") as ws:
        ws.send_text("bye")
        ws.receive_text()
        # The handler called ws.close(1000) → the next receive disconnects.
        try:
            ws.receive_text()
            disconnected = False
        except Exception:
            # WebSocketDisconnect (starlette) — the exact code varies by
            # TestClient/Starlette version; what matters is that it DID close.
            disconnected = True

    assert disconnected