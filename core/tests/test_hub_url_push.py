"""Hub-URL repoint feature (Setup → Spokes & Agents → Hub Connection URL).

Pins the four pieces of the "change the hub's DNS name and push the new address
to every agent/spoke" flow:

1. ``SPOKE_SET_HUB_URL`` spoke-side handler (``control_plane.handle_system_command``)
   — guards (loopback / auto / already-current → no-op) + apply path (persist
   ``HUB_URL`` to ``.env`` + deferred ``os._exit(3)`` so systemd relaunches
   dialed to the new URL).
2. ``_deferred_repoint_exit`` — the 0.5s-deferred flush + exit task the apply
   path schedules (so the SUCCESS ack clears the mailbox BEFORE the restart).
3. Hub-side push: ``push_config_to_spoke`` re-sends ``SPOKE_SET_HUB_URL`` on
   every connect (reconcile) when ``global_config["hub"]["url"]`` is set, and
   ``push_hub_url_to_all_spokes`` fans it out (durable) on save.
4. ``POST /api/setup/hub-url`` — admin-gated, validates the URL against a tight
   charset (``_HUB_URL_RE``), writes ``global_config["hub"]["url"]``, fans out.

The spoke handler is exercised via ``_BareSpoke`` (skips the heavy
BaseControlPlane ``__init__`` but keeps the REAL ``handle_system_command``);
the hub methods are exercised unbound (``LabManagerHub.method(fakehub, ...)``)
like ``test_push_or_queue_to_spoke``; the route via FastAPI ``TestClient`` like
``test_push_config_multi_spoke``.
"""
import asyncio
import os
import sys

import pytest

# core/src on sys.path (for `import main`, `import api`) via conftest; the lm
# repo root (parent of core/) for `from core.src.messaging import control_plane`.
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)
# core/src/routes for `import setup_misc`. APPEND (not insert(0)) so core/src
# stays first on the path — main.py does `import self_backup` and there is a
# routes/self_backup.py that does NOT define SelfBackupMixin; inserting routes
# at the front would shadow the real core/src/self_backup.py and break
# `import main`.
_ROUTES = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "routes"))
if _ROUTES not in sys.path:
    sys.path.append(_ROUTES)

import main as main_module  # noqa: E402
from main import LabManagerHub  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402
import setup_misc  # noqa: E402
from setup_misc import _HUB_URL_RE  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


# ── _HUB_URL_RE validation ───────────────────────────────────────────────────

def test_hub_url_re_accepts_full_wss_url():
    assert _HUB_URL_RE.match("wss://hub.example.com:443/ws/spoke")
    assert _HUB_URL_RE.match("ws://127.0.0.1:8765/ws/spoke")


def test_hub_url_re_accepts_bare_host_and_ip():
    assert _HUB_URL_RE.match("hub.example.com")
    assert _HUB_URL_RE.match("172.16.1.31")
    assert _HUB_URL_RE.match("hub.example.com:8443")
    assert _HUB_URL_RE.match("[fd00::1]")


def test_hub_url_re_rejects_shell_meta_and_spaces():
    assert not _HUB_URL_RE.match("wss://evil.ex/x; rm -rf /")
    assert not _HUB_URL_RE.match("hub example.com")
    assert not _HUB_URL_RE.match("$(curl evil)")
    assert not _HUB_URL_RE.match("hub|cat /etc/passwd")


# ── SPOKE_SET_HUB_URL handler ────────────────────────────────────────────────

class _BareSpoke(cp.BaseControlPlane):
    """BaseControlPlane that skips the heavy __init__ (WS / log-relay /
    install-uuid setup) but keeps the REAL handle_system_command + the real
    ``_normalize_hub_url`` / ``_hub_url_is_loopback`` staticmethods — so the
    SPOKE_SET_HUB_URL branch runs the production code path, not a stub."""

    def __init__(self, hub_url="wss://old.example.com:443/ws/spoke"):
        self.spoke_id = "test-spoke"
        self.hub_url = hub_url
        self._draining = False
        self.persisted = []  # (key, value) per _persist_secret_to_env call

    def _persist_secret_to_env(self, key, value):
        self.persisted.append((key, value))


@pytest.mark.asyncio
async def test_set_hub_url_idempotent_no_restart():
    """Already on the requested URL → SUCCESS 'already current', no persist,
    no deferred-exit task scheduled (no restart). This is what makes the
    reconcile-on-every-connect path loop-safe."""
    spoke = _BareSpoke(hub_url="wss://hub.example.com:443/ws/spoke")
    created = []
    monkeypatch_target = cp.asyncio
    orig = monkeypatch_target.create_task
    monkeypatch_target.create_task = lambda coro: created.append(coro) or None
    try:
        res = await spoke.handle_system_command(
            "SPOKE_SET_HUB_URL", {"hub_url": "wss://hub.example.com:443"})
    finally:
        monkeypatch_target.create_task = orig
    # Close the coroutine (never scheduled) to avoid a "never awaited" warning.
    for c in created:
        c.close()
    assert res["status"] == "SUCCESS"
    assert "already current" in res["message"]
    assert spoke.persisted == []          # no .env write
    assert spoke._draining is False       # no restart scheduled


@pytest.mark.asyncio
async def test_set_hub_url_loopback_current_skips():
    """A co-located spoke dialing loopback is NOT repointed to the public URL
    (loopback is still correct after a DNS-name move; a public URL may not
    route from the same box)."""
    spoke = _BareSpoke(hub_url="wss://localhost:443/ws/spoke")
    res = await spoke.handle_system_command(
        "SPOKE_SET_HUB_URL", {"hub_url": "wss://hub.example.com:443"})
    assert res["status"] == "SUCCESS"
    assert "loopback" in res["message"]
    assert spoke.persisted == []
    assert spoke._draining is False


@pytest.mark.asyncio
async def test_set_hub_url_auto_current_skips():
    """An auto-discovering spoke (hub_url == 'auto') keeps self-healing —
    pinning it would remove the reconnect-time re-resolution."""
    spoke = _BareSpoke(hub_url="auto")
    res = await spoke.handle_system_command(
        "SPOKE_SET_HUB_URL", {"hub_url": "wss://hub.example.com:443"})
    assert res["status"] == "SUCCESS"
    assert "auto" in res["message"]
    assert spoke.persisted == []
    assert spoke._draining is False


@pytest.mark.asyncio
async def test_set_hub_url_apply_persists_and_schedules_restart():
    """A pinned remote spoke on a DIFFERENT URL: persist HUB_URL to .env, set
    _draining, schedule the deferred-exit task, return SUCCESS (the ack clears
    the mailbox before the 0.5s-deferred os._exit fires)."""
    spoke = _BareSpoke(hub_url="wss://old.example.com:443/ws/spoke")
    created = []
    monkeypatch_target = cp.asyncio
    orig = monkeypatch_target.create_task
    monkeypatch_target.create_task = lambda coro: created.append(coro) or None
    try:
        res = await spoke.handle_system_command(
            "SPOKE_SET_HUB_URL", {"hub_url": "wss://new.example.com:443"})
    finally:
        monkeypatch_target.create_task = orig
    assert res["status"] == "SUCCESS"
    assert "repointing" in res["message"]
    # Persisted the NORMALIZED new URL (bare/443 → wss://new.example.com:443/ws/spoke).
    assert spoke.persisted == [("HUB_URL", "wss://new.example.com:443/ws/spoke")]
    # The in-memory hub_url was updated (so a non-restart path still dials new).
    assert spoke.hub_url == "wss://new.example.com:443/ws/spoke"
    assert spoke._draining is True
    # Exactly one deferred-exit task was scheduled.
    assert len(created) == 1
    created[0].close()  # don't actually run the exit


@pytest.mark.asyncio
async def test_set_hub_url_missing_or_invalid_errors():
    spoke = _BareSpoke()
    assert (await spoke.handle_system_command("SPOKE_SET_HUB_URL", {}))["status"] == "ERROR"
    # The 'auto' sentinel is not a valid push target.
    assert (await spoke.handle_system_command(
        "SPOKE_SET_HUB_URL", {"hub_url": "auto"}))["status"] == "ERROR"


@pytest.mark.asyncio
async def test_deferred_repoint_exit_flushes_then_exits_nonzero(monkeypatch):
    """_deferred_repoint_exit sleeps briefly, flushes the log relay, then
    os._exit(3) so systemd Restart=always/on-failure relaunches dialed to the
    new URL. Patch sleep (no-op) + flush (no-op) + os._exit (record) so the
    test doesn't actually die or wait."""
    spoke = _BareSpoke()
    exited = []
    async def _noop_sleep(delay): return None
    async def _noop_flush(timeout=2.0): return None
    monkeypatch.setattr(cp.asyncio, "sleep", _noop_sleep)
    monkeypatch.setattr(spoke, "_flush_log_relay_async", _noop_flush)
    monkeypatch.setattr(cp.os, "_exit", lambda code: exited.append(code))
    await spoke._deferred_repoint_exit()
    assert exited == [3]


# ── Hub-side reconcile-on-connect + fan-out ──────────────────────────────────

class _FakeHub:
    """Minimal hub stand-in for push_config_to_spoke: a hub secret, a
    global_config dict, an empty module-type map (so module_key is None → the
    agent path, which is exactly where the hub-URL push is inserted), and a
    recording send_to_spoke. ``state.get_global_config()`` returns the gc dict
    passed to the constructor (bound per-instance in ``_make_fake_hub``)."""

    def __init__(self, gc):
        self.key_manager = type("KM", (), {"hub_secrets": ["hubsecret"]})()
        self._gc = gc
        self.spoke_module_types = {}  # agent-1 has no module_key → early return AFTER hub-url push
        self.sent = []
        self.state = type("S", (), {
            "get_global_config": lambda self, _g=gc: _g,
        })()

    async def send_to_spoke(self, msg):
        self.sent.append(msg)


def _make_fake_hub(gc):
    return _FakeHub(gc)


@pytest.mark.asyncio
async def test_push_config_re_pushes_hub_url_when_set():
    """push_config_to_spoke sends SPOKE_SET_HUB_URL on connect when
    global_config['hub']['url'] is set (the reconcile-on-connect path)."""
    hub = _make_fake_hub({"hub": {"url": "wss://hub.example.com:443"}})
    await LabManagerHub.push_config_to_spoke(hub, "agent-1")
    types = [m.payload.type for m in hub.sent]
    assert "SPOKE_SET_HUB_SECRET" in types  # always pushed first
    url_msgs = [m for m in hub.sent if m.payload.type == "SPOKE_SET_HUB_URL"]
    assert len(url_msgs) == 1
    assert url_msgs[0].payload.data == {"hub_url": "wss://hub.example.com:443"}


@pytest.mark.asyncio
async def test_push_config_omits_hub_url_when_unset():
    """No global_config['hub']['url'] → no SPOKE_SET_HUB_URL (spokes keep their
    install-time pin / auto-discovery). Hub secret still pushed."""
    hub = _make_fake_hub({})
    await LabManagerHub.push_config_to_spoke(hub, "agent-1")
    types = [m.payload.type for m in hub.sent]
    assert "SPOKE_SET_HUB_URL" not in types
    assert "SPOKE_SET_HUB_SECRET" in types


class _FakeFanHub:
    """Minimal hub for push_hub_url_to_all_spokes: an approved_modules map and
    a recording push_or_queue_to_spoke that returns queued/pushed/raises per
    configured spoke."""

    def __init__(self, approved, queued=(), fail=()):
        self.approved_modules = {sid: True for sid in approved}
        self._queued = set(queued)
        self._fail = set(fail)
        self.calls = []

    async def push_or_queue_to_spoke(self, sid, cmd, data, timeout=5.0):
        self.calls.append((sid, cmd, data))
        if sid in self._fail:
            raise RuntimeError("boom")
        if sid in self._queued:
            return {"status": "ok", "queued": True, "message": "queued"}
        return {"status": "ok", "queued": False, "result": {"status": "SUCCESS"}}


@pytest.mark.asyncio
async def test_push_hub_url_fan_out_categorizes_pushed_queued_failed():
    """Fan-out reaches every approved spoke; results are categorized into
    pushed / queued / failed."""
    hub = _FakeFanHub(["a-1", "a-2", "a-3", "a-4"],
                      queued=("a-2",), fail=("a-4",))
    res = await LabManagerHub.push_hub_url_to_all_spokes(hub, "wss://new:443")
    assert res["status"] == "SUCCESS"
    assert sorted(res["pushed"]) == ["a-1", "a-3"]
    assert res["queued"] == ["a-2"]
    assert res["failed"] == ["a-4"]
    # Every spoke got the SPOKE_SET_HUB_URL command with the URL payload.
    for sid, cmd, data in hub.calls:
        assert cmd == "SPOKE_SET_HUB_URL"
        assert data == {"hub_url": "wss://new:443"}


@pytest.mark.asyncio
async def test_push_hub_url_fan_out_no_targets():
    """No approved spokes → empty result, no calls."""
    hub = _FakeFanHub([])
    res = await LabManagerHub.push_hub_url_to_all_spokes(hub, "wss://new:443")
    assert res == {"status": "SUCCESS", "pushed": [], "queued": [], "failed": []}
    assert hub.calls == []


# ── POST /api/setup/hub-url route ────────────────────────────────────────────

class _FakeCtx:
    """Admin ctx for the route — _session_user returns a truthy sess, _is_admin
    True. Pass admin=False for a non-admin variant."""
    def __init__(self, admin=True):
        self._admin = admin

    def _session_user(self, request):
        return {"user": "admin"} if self._admin else {"user": "ops"}

    def _is_admin(self, sess):
        return self._admin


class _FakeRouteHub:
    """Hub stand-in for the route: system_state dict + save_state + a recording
    push_hub_url_to_all_spokes."""
    def __init__(self, fan_result=None):
        self.state = type("S", (), {
            "system_state": {},
            "save_state": lambda self: None,
        })()
        self.fanned = []
        self._fan_result = fan_result or {
            "status": "SUCCESS", "pushed": ["a-1", "a-2"], "queued": ["a-3"],
            "failed": []}

    async def push_hub_url_to_all_spokes(self, url):
        self.fanned.append(url)
        return self._fan_result


def _build_route(admin=True, fan_result=None):
    app = FastAPI()
    hub = _FakeRouteHub(fan_result=fan_result)
    app.state.hub = hub
    setup_misc.register(app, hub, _FakeCtx(admin=admin))
    return TestClient(app), hub


def test_route_set_hub_url_validates_writes_and_fans_out():
    c, hub = _build_route()
    r = c.post("/api/setup/hub-url", json={"url": "wss://hub.example.com:443"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["pushed"] == ["a-1", "a-2"]
    assert body["queued"] == ["a-3"]
    # global_config["hub"]["url"] persisted.
    assert hub.state.system_state["global_config"]["hub"]["url"] == "wss://hub.example.com:443"
    # Fan-out invoked once with the URL.
    assert hub.fanned == ["wss://hub.example.com:443"]


def test_route_accepts_bare_host():
    c, hub = _build_route()
    r = c.post("/api/setup/hub-url", json={"url": "172.16.1.31"})
    assert r.status_code == 200, r.text
    assert hub.state.system_state["global_config"]["hub"]["url"] == "172.16.1.31"


def test_route_empty_url_clears_override_no_fanout():
    c, hub = _build_route()
    # Seed an existing override first.
    c.post("/api/setup/hub-url", json={"url": "wss://hub.example.com:443"})
    hub.fanned.clear()
    r = c.post("/api/setup/hub-url", json={"url": ""})
    assert r.status_code == 200, r.text
    assert hub.state.system_state["global_config"]["hub"]["url"] == ""
    assert hub.fanned == []  # clearing does not fan out


def test_route_rejects_bad_url():
    c, _ = _build_route()
    r = c.post("/api/setup/hub-url", json={"url": "wss://evil.ex/x; rm -rf /"})
    assert r.status_code == 400


def test_route_admin_gate_403_for_non_admin():
    c, _ = _build_route(admin=False)
    r = c.post("/api/setup/hub-url", json={"url": "wss://hub.example.com:443"})
    assert r.status_code == 403