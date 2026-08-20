"""Ownership gate for the tenant-scoped role-management routes
(``routes/agents.py``: ``/tenant/agent/{spoke_id}/load-role``,
``/unload-role``, ``/roles``).

These let a tenant-admin load/unload roles on their OWN spokes without the
Global-Admin-only ``/api/agent/*`` arbitrary-command surface. The security
contract, enforced by ``access.can_bind_spoke``:

* a Global Admin may manage any spoke;
* a tenant-admin may manage ONLY a spoke bound to one of their OWN tenants;
* a tenant-admin may NOT manage another tenant's spoke, a shared-tenant spoke,
  or an unbound spoke → 403, and the hub relay is never reached;
* the unload/roles routes relay ONLY UNLOAD_ROLE / GET_AVAILABLE_ROLES — never
  an arbitrary command.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import agents


class _State:
    def __init__(self, spoke_tenant):
        self._spoke_tenant = spoke_tenant
        self.system_state = {"module_metadata": {}, "module_names": {},
                             "known_modules": []}

    def get_spoke_tenant(self, module_id):
        return self._spoke_tenant


class _Hub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self, spoke_tenant):
        self.state = _State(spoke_tenant)
        self.active_connections = {"spoke-1"}
        self.spoke_module_types = {"spoke-1": "agent"}
        self.relayed = []

    def _primary_key(self, sid):
        return sid

    def spoke_can_accept_commands(self, sid):
        return True, "ok"

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.relayed.append((cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            return {"payload": {"data": {"available": ["dns"], "active": []}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _client(hub, sess):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: (s or {}).get("user", {}).get("permissions", {}).get("role") == "admin",
    )
    agents.register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


def _sess(role, tenants):
    return {"user": {"permissions": {"role": role}, "tenants": tenants}}


# ── ownership gate ───────────────────────────────────────────────────────────
def test_tenant_admin_owns_spoke_can_load():
    hub = _Hub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/load-role", json={"role": "proxy"})
    assert r.status_code == 200
    assert ("LOAD_ROLE", {"role": "proxy", "config": {}}) in hub.relayed


def test_tenant_admin_other_tenant_spoke_forbidden():
    hub = _Hub(spoke_tenant="other")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/load-role", json={"role": "proxy"})
    assert r.status_code == 403
    assert hub.relayed == []  # never reached the relay


def test_tenant_admin_shared_spoke_forbidden():
    # Shared infra is Global-Admin managed — a tenant-admin owning "acme" may
    # NOT manage a spoke bound to the shared tenant even though it is visible.
    hub = _Hub(spoke_tenant="shared")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/unload-role", json={"role": "proxy"})
    assert r.status_code == 403
    assert hub.relayed == []


def test_global_admin_any_spoke_allowed():
    hub = _Hub(spoke_tenant="")  # unbound
    c = _client(hub, _sess("admin", []))
    r = c.get("/tenant/agent/spoke-1/roles")
    assert r.status_code == 200
    assert r.json().get("available") == ["dns"]
    assert ("GET_AVAILABLE_ROLES", {}) in hub.relayed


def test_plain_user_forbidden():
    hub = _Hub(spoke_tenant="acme")
    c = _client(hub, _sess("user", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/load-role", json={"role": "proxy"})
    assert r.status_code == 403
    assert hub.relayed == []


# ── only role commands are relayed (no arbitrary-command surface) ────────────
def test_unload_route_relays_only_unload():
    hub = _Hub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/unload-role", json={"role": "dns"})
    assert r.status_code == 200
    assert hub.relayed == [("UNLOAD_ROLE", {"role": "dns"})]


def test_load_requires_role():
    hub = _Hub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/load-role", json={})
    assert r.status_code == 400
