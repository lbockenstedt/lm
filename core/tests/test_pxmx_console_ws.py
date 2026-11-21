"""Regression tests for the pxmx VNC console WebSocket relay
(``/ws/console/{session_id}`` → ``pxmx_console_ws`` in ``api.create_app``).

The browser side (noVNC/RFB) treats the WS as a raw RFB byte stream, so the
hub's ``spoke_to_browser`` task is a transparent queue→WS byte pump that also
honors control tuples enqueued by ``_handle_agent_relay_up``:

* ``("ready",)``      — the agent opened the Proxmox vncwebsocket; RFB frames
  are about to flow. Must be a **no-op that keeps the relay loop running**.
* ``("disconnect",)`` — Proxmox side closed; close the browser WS cleanly.
* ``("error", msg)``  — vncproxy/WSS failed; close the browser WS with 1011.

This locks in the fix for the "console button pops the screen but nothing
loads / Disconnected: closed" bug: ``spoke_to_browser`` used to ``return`` on
``("ready",)``, killing the only queue consumer the instant VNC_READY arrived,
so the RFB handshake bytes piled up unread and noVNC's connect timer fired →
"Disconnected: closed". The ``("ready",)`` case must ``continue``.
"""

import asyncio
import base64
import tempfile
import time

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import api as api_mod


# ── Fakes ────────────────────────────────────────────────────────────────────
# Only the surface ``create_app`` touches at build time + the WS route touches
# at request time. The console WS path bypasses the HTTP access-control
# middleware (not a gated prefix; HTTP middleware doesn't wrap websockets), so
# no login session/cookie is required.


class _FakeState:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def ensure_admin_lockout(self) -> bool:
        return False

    def save_state(self) -> None:
        pass

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()


class _FakeHub:
    """Minimal hub: serves a pre-seeded VNC session + records down-commands."""

    def __init__(self, sessions: dict, data_dir: str):
        self.state = _FakeState(data_dir)
        self._vnc = sessions          # {session_id: {queue, ws_token, spoke_id, ...}}
        self.sent = []                # recorded (spoke_id, cmd, data) down-commands
        self.writer_checks = []       # recorded vnc_is_writer (unique_id, session_id, agent_id)
        # ``register_simulations_routes`` reads these at app-build time (closures
        # capture them; they're never exercised by the console WS tests).
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = set()

    def get_vnc_session(self, sid):
        return self._vnc.get(sid)

    def vnc_is_writer(self, unique_id, session_id, agent_id=""):
        """Record the relay's write-lock check. The lock is held on
        "agent-b" only: the session tests open their VM through that agent,
        and a unique_id names no agent, so the relay must ask with it."""
        self.writer_checks.append((unique_id, session_id, agent_id))
        return agent_id == "agent-b"

    def register_vnc_session(self, sid, meta):
        # Tests pre-seed the queue directly; mirror the real shape if called.
        self._vnc.setdefault(sid, {"queue": asyncio.Queue(), **meta})

    def unregister_vnc_session(self, sid):
        self._vnc.pop(sid, None)

    async def send_to_spoke_command(self, spoke_id, cmd, data):
        self.sent.append((spoke_id, cmd, data))

    def get_spoke_by_type(self, _t):
        return "pxmx-spoke-1"


def _build_client(sessions):
    tmp = tempfile.mkdtemp()
    hub = _FakeHub(sessions, tmp)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


def _session(sid="s1", token="tok", spoke="pxmx-spoke-1", items=()):
    # Python 3.9: asyncio.Queue() binds to get_event_loop() at construction.
    # Some tests in the suite leave the main thread with no current loop, so
    # ensure one exists before building the queue (the Starlette TestClient
    # portal shares it for the server-side relay task).
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    q = asyncio.Queue()
    for it in items:
        q.put_nowait(it)
    return {"queue": q, "ws_token": token, "spoke_id": spoke,
            "tenant_id": "10", "vmid": 101, "node": "pve1",
            "unique_id": "c1/pve1/101", "expires": 9_999_999_999}


# ── Tests ────────────────────────────────────────────────────────────────────


def test_vnc_ready_then_frames_reach_browser():
    """VNC_READY must NOT terminate the relay — subsequent RFB frame bytes must
    be delivered to the browser. This is the regression: a bare ``return`` on
    ``("ready",)`` killed the queue consumer so noVNC got zero RFB bytes and
    timed out with 'Disconnected: closed'."""
    rfb_banner = b"RFB 003.008\n"
    sess = _session(items=[("ready",), rfb_banner])
    client, hub = _build_client({"s1": sess})

    with client.websocket_connect("/ws/console/s1?token=tok") as ws:
        # The server dequeues ("ready",) → continue, then the RFB bytes → send_bytes.
        received = ws.receive_bytes()
    assert received == rfb_banner


def test_vnc_disconnect_closes_browser_ws_cleanly():
    """``("disconnect",)`` must close the browser WS (code 1000) so noVNC
    surfaces 'Disconnected' instead of hanging on a dead socket."""
    sess = _session(items=[("disconnect",)])
    client, hub = _build_client({"s1": sess})

    with client.websocket_connect("/ws/console/s1?token=tok") as ws:
        try:
            ws.receive_bytes()
            closed = False
            code = None
        except WebSocketDisconnect as exc:
            closed = True
            code = exc.code
    assert closed, "expected the browser WS to be closed on VNC_DISCONNECT"
    assert code == 1000


def test_vnc_error_closes_browser_ws_with_reason():
    """``("error", msg)`` must close the browser WS with code 1011 so noVNC
    surfaces the agent-side failure reason rather than a blank screen."""
    sess = _session(items=[("error", "vncproxy 401")])
    client, hub = _build_client({"s1": sess})

    with client.websocket_connect("/ws/console/s1?token=tok") as ws:
        try:
            ws.receive_bytes()
            closed = False
            code = None
        except WebSocketDisconnect as exc:
            closed = True
            code = exc.code
    assert closed, "expected the browser WS to be closed on VNC_ERROR"
    assert code == 1011


def test_invalid_ws_token_rejected():
    """A mismatched/missing ws_token is rejected before the relay starts."""
    sess = _session(token="tok")
    client, hub = _build_client({"s1": sess})

    with client.websocket_connect("/ws/console/s1?token=wrong") as ws:
        try:
            ws.receive_bytes()
            closed = False
            code = None
        except WebSocketDisconnect as exc:
            closed = True
            code = exc.code
    assert closed
    assert code == 4401  # invalid/expired console session


def test_ws_connect_marks_session_connected():
    """On accept, the relay marks the session ``connected`` (+ ``connected_at``)
    so the 60s TTL no longer reaps it mid-view and the presence roster can list
    the viewer. Regression: a VNC session with no ``connected`` flag froze the
    screen after 60s when a live frame re-read the reaped session."""
    sess = _session(items=[("ready",), b"RFB 003.008\n"])
    assert not sess.get("connected")
    client, hub = _build_client({"s1": sess})
    with client.websocket_connect("/ws/console/s1?token=tok") as ws:
        ws.receive_bytes()
        assert sess.get("connected") is True
        assert isinstance(sess.get("connected_at"), (int, float))


def test_vnc_input_asks_for_the_lock_of_the_sessions_own_agent():
    """Browser input reaches the VM only while the session holds the write
    lock of its VM on the agent it was opened through. A unique_id names no
    agent, so two tenants' VMs can share one and the hub keys the lock by
    both (HubVncConsoleMixin._vnc_lock_key); the relay must ask with the
    agent stored in the session. Asked without it, it would read the lock
    of another VM, and this session's keystrokes would be dropped."""
    sess = _session(items=[("ready",)])
    sess["agent_id"] = "agent-b"
    client, hub = _build_client({"s1": sess})
    with client.websocket_connect("/ws/console/s1?token=tok") as ws:
        ws.send_bytes(b"key")
        # The relay runs on the test client's own thread: wait until it has
        # checked the lock and forwarded the bytes (or 2 s), before the close
        # on leaving this block cancels it.
        for _ in range(200):
            if any(cmd == "VNC_FRAME_DOWN" for _, cmd, _ in hub.sent):
                break
            time.sleep(0.01)
    assert hub.writer_checks == [("c1/pve1/101", "s1", "agent-b")]
    frames = [data for _, cmd, data in hub.sent if cmd == "VNC_FRAME_DOWN"]
    assert [base64.b64decode(f["data"]) for f in frames] == [b"key"]
