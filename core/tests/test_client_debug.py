"""Remote Client Debug Mode — hub ingest (``_handle_cs_debug_log``) + the
``/api/cs/clients/{hostname}/debug`` control routes (routes/client_debug.py).

Covers:
  * CS_DEBUG_LOG ingest appends into the per-(tenant,hostname) ring buffer and
    tenant-scopes by the spoke's binding (a foreign tenant's host can't be read
    by another tenant).
  * Hub-side auto-off: frames past the 30-min ``enabled_at`` window are dropped.
  * POST relays a ``CS_QUEUE_COMMAND`` (debug_mode) to the cs spoke + records
    the session; DELETE stops it; both honor the write tier (403 on deny).
  * GET returns the buffered logs + the active/window state; 403 on a foreign
    tenant.

Avoids the WIPE-HAZARD suite (test_update_recovery / stale_restart /
test_spoke_update_*) that git-resets the real lm repo — this file imports no
update-pipeline code and runs fully in-memory.
"""

import time
from types import SimpleNamespace

import main  # noqa: E402  (core/src on sys.path via conftest)
import access
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import client_debug as client_debug_routes

_TENANT = "10"
_WINDOW = 30 * 60


class _FakeState:
    def __init__(self, tenant=_TENANT):
        self._tenant = tenant

    def get_spoke_tenant(self, spoke_id):
        return self._tenant


class FakeHub:
    """Minimal hub: per-(tenant,host) debug buffers + records forwarded commands."""

    def __init__(self, replies=None, connected=True, tenant=_TENANT):
        self.client_debug_logs = {}
        self.client_debug_sessions = {}
        self.client_debug_size = 2000
        self.state = _FakeState(tenant)
        self.forwarded = []
        self._connected = connected
        self.replies = replies or {}

    def _primary_key(self, spoke_id):
        return spoke_id

    def get_client_sim_spoke(self, tenant_id):
        return "cs-spoke-1" if self._connected else None

    async def request_response(self, sid, cmd_type, payload, timeout=15.0):
        self.forwarded.append((cmd_type, payload))
        return {"payload": {"data": self.replies.get(cmd_type, {"status": "SUCCESS"})}}


def _sess(admin=False, tenants=None, edit=False):
    """Build a session dict shaped for access.read_scope/write_scope.

    access.is_admin / is_tenant_admin / has_edit_access all read
    ``sess["user"]["permissions"]`` ({"admin":True}, {"role":"tenant_admin"},
    {"edit":True}) — NOT a user-level role/is_admin flag — so this builds the
    permissions dict those helpers actually inspect. ``user.tenants`` is what
    ``check_tenant_access`` / ``read_scope`` / ``write_scope`` scope on."""
    if admin:
        perms = {"admin": True}
    elif edit:
        perms = {"edit": True}  # write-user tier (has_edit_access, not admin)
    else:
        perms = {}  # viewer: no edit, no admin — write_scope → "deny"
    return {
        "user_id": "u1",
        "username": "tester",
        "user": {
            "tenants": tenants if tenants is not None else [_TENANT],
            "permissions": perms,
        },
    }


def _build(sess=None, hub=None):
    """Build a TestClient with the client_debug routes + a ctx wired to ``sess``.

    ``_session_user`` returns ``sess`` for every request so the access gates see
    a stable identity; ``_resolve_tenant`` honors ?tenant= (the route's path) or
    falls back to the session tenant."""
    sess = sess if sess is not None else _sess(admin=True)
    hub = hub or FakeHub()

    def _session_user(request):
        return sess

    def _resolve_tenant(request, explicit=None):
        return explicit or request.query_params.get("tenant") or _TENANT

    def _check_tenant_access(sess, tid):
        return access.check_tenant_access(sess, tid)

    ctx = SimpleNamespace(
        _session_user=_session_user,
        _resolve_tenant=_resolve_tenant,
        _check_tenant_access=_check_tenant_access,
    )
    app = FastAPI()
    client_debug_routes.register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app), hub


# ── _handle_cs_debug_log ingest ──────────────────────────────────────────────

def test_ingest_appends_lines_to_per_host_buffer():
    hub = FakeHub()
    payload = {"type": "CS_DEBUG_LOG",
               "data": {"hostname": "host-a", "level": "basic",
                        "lines": ["line1", "line2"]}}
    # The ingest runs unbound against the fake hub (self=hub), exactly the way
    # test_push_cs_hub_config calls LabManagerHub.push_cs_hub_config(hub, ...).
    import asyncio
    asyncio.run(main.LabManagerHub._handle_cs_debug_log(hub, "cs-spoke-1", payload))
    ring = hub.client_debug_logs[(_TENANT, "host-a")]
    assert [e["line"] for e in ring] == ["line1", "line2"]
    assert all(e["level"] == "basic" for e in ring)


def test_ingest_tenant_scopes_by_spoke_binding():
    """A cs spoke bound to tenant '10' stamps its frames '10' — a host streaming
    through a different tenant's spoke lands under THAT tenant, not '10'."""
    hub = FakeHub(tenant="other")
    payload = {"type": "CS_DEBUG_LOG",
               "data": {"hostname": "host-a", "level": "basic", "lines": ["x"]}}
    import asyncio
    asyncio.run(main.LabManagerHub._handle_cs_debug_log(hub, "cs-spoke-1", payload))
    assert ("other", "host-a") in hub.client_debug_logs
    assert (_TENANT, "host-a") not in hub.client_debug_logs


def test_ingest_drops_frames_past_auto_off_window():
    hub = FakeHub()
    key = (_TENANT, "host-a")
    # Session started 31 min ago — past the 30-min window.
    hub.client_debug_sessions[key] = {"enabled_at": time.time() - _WINDOW - 60,
                                      "level": "basic"}
    payload = {"type": "CS_DEBUG_LOG",
               "data": {"hostname": "host-a", "level": "basic",
                        "lines": ["late"]}}
    import asyncio
    asyncio.run(main.LabManagerHub._handle_cs_debug_log(hub, "cs-spoke-1", payload))
    assert key not in hub.client_debug_logs  # dropped, not buffered


def test_ingest_no_hostname_is_noop():
    hub = FakeHub()
    import asyncio
    asyncio.run(main.LabManagerHub._handle_cs_debug_log(
        hub, "cs-spoke-1", {"type": "CS_DEBUG_LOG", "data": {"lines": ["x"]}}))
    assert hub.client_debug_logs == {}


# ── POST /api/cs/clients/{host}/debug ─────────────────────────────────────────

def test_post_enables_relays_queue_command_and_records_session():
    c, hub = _build()
    r = c.post(f"/api/cs/clients/host-a/debug?tenant={_TENANT}",
               json={"enabled": True, "level": "advanced"})
    assert r.status_code == 200
    assert r.json()["enabled"] is True
    assert r.json()["level"] == "advanced"
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_QUEUE_COMMAND"
    assert payload["target"] == "host-a"
    assert payload["action"] == "debug_mode"
    assert payload["args"] == {"enabled": True, "level": "advanced"}
    sess = hub.client_debug_sessions[(_TENANT, "host-a")]
    assert sess["level"] == "advanced"
    assert "enabled_at" in sess


def test_post_disables_clears_session():
    c, hub = _build()
    hub.client_debug_sessions[(_TENANT, "host-a")] = {"enabled_at": 1, "level": "basic"}
    r = c.post(f"/api/cs/clients/host-a/debug?tenant={_TENANT}",
               json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    assert (_TENANT, "host-a") not in hub.client_debug_sessions


def test_post_503_when_spoke_disconnected():
    c, _ = _build(hub=FakeHub(connected=False))
    r = c.post(f"/api/cs/clients/host-a/debug?tenant={_TENANT}",
               json={"enabled": True})
    assert r.status_code == 503


def test_post_rejects_foreign_tenant_for_non_admin():
    """A tenant-bound write user of '10' cannot debug a host on tenant 'other'."""
    c, _ = _build(sess=_sess(edit=True, tenants=[_TENANT]))
    r = c.post(f"/api/cs/clients/host-a/debug?tenant=other",
               json={"enabled": True})
    assert r.status_code == 403


def test_post_viewer_of_own_tenant_denied_write():
    """A view-tier user (no edit) cannot toggle debug mode on their own tenant."""
    c, _ = _build(sess=_sess(tenants=[_TENANT]))  # default role=viewer, no edit
    r = c.post(f"/api/cs/clients/host-a/debug?tenant={_TENANT}",
               json={"enabled": True})
    assert r.status_code == 403


# ── GET /api/cs/clients/{host}/debug-logs ─────────────────────────────────────

def test_get_returns_buffered_logs_and_active_state():
    c, hub = _build()
    key = (_TENANT, "host-a")
    hub.client_debug_logs[key] = __import__("collections").deque(
        [{"ts": 1, "level": "basic", "line": "hello"}], maxlen=2000)
    hub.client_debug_sessions[key] = {"enabled_at": time.time(), "level": "basic"}
    r = c.get(f"/api/cs/clients/host-a/debug-logs?tenant={_TENANT}")
    assert r.status_code == 200
    body = r.json()
    assert body["active"] is True
    assert body["level"] == "basic"
    assert body["logs"][0]["line"] == "hello"


def test_get_window_elapsed_marks_inactive_and_clears_session():
    c, hub = _build()
    key = (_TENANT, "host-a")
    hub.client_debug_sessions[key] = {"enabled_at": time.time() - _WINDOW - 1,
                                      "level": "basic"}
    r = c.get(f"/api/cs/clients/host-a/debug-logs?tenant={_TENANT}")
    assert r.status_code == 200
    assert r.json()["active"] is False
    assert key not in hub.client_debug_sessions  # stale record reaped


def test_get_foreign_tenant_denied():
    c, _ = _build(sess=_sess(edit=True, tenants=[_TENANT]))
    r = c.get(f"/api/cs/clients/host-a/debug-logs?tenant=other")
    assert r.status_code == 403


# ── DELETE /api/cs/clients/{host}/debug ───────────────────────────────────────

def test_delete_relays_stop_and_clears_session():
    c, hub = _build()
    hub.client_debug_sessions[(_TENANT, "host-a")] = {"enabled_at": 1, "level": "basic"}
    r = c.delete(f"/api/cs/clients/host-a/debug?tenant={_TENANT}")
    assert r.status_code == 200
    assert r.json()["enabled"] is False
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_QUEUE_COMMAND"
    assert payload["args"]["enabled"] is False
    assert (_TENANT, "host-a") not in hub.client_debug_sessions