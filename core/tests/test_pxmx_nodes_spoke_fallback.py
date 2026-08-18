"""Regression tests for ``/api/pxmx/nodes`` spoke resolution (``routes/pxmx.py``).

Pre-fix, the Hypervisors → Overview (node list) resolved its spoke ONLY via
``get_hypervisor_spoke_for_tenant(tid)``, which returns ``None`` when the
connected Proxmox hypervisor spoke isn't explicitly BOUND to the selected
tenant. ``/api/pxmx/vms``, however, uses the GLOBAL ``get_hypervisor_spoke()``
and scopes per-tenant via proxmox_tag + subnet filter — so a connected but
unbound host showed its VMs on the Virtual Machines tab while the Overview went
empty (the reported bug: "I can see the VMs but nothing shows in the overview").

The route now falls back to the global hypervisor spoke when no tenant-bound
spoke exists, matching the VM list. These lock in:

* a tenant with a BOUND spoke still uses that bound spoke (isolation preserved);
* a tenant whose host is connected but UNBOUND falls back to the global spoke
  and returns its nodes instead of an empty list (the fix);
* an admin with no tenant selected uses the global spoke (unchanged).
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx


class _State:
    def __init__(self):
        self.system_state = {}

    def _mark_dirty(self):
        pass


class _Hub:
    """Minimal hub: records which spoke GET_NODE_STATS was relayed to."""

    def __init__(self, bound_spoke=None, global_spoke="pxmx-global",
                 nodes=None, raise_on_relay=False):
        self.state = _State()
        self._bound = bound_spoke
        self._global = global_spoke
        self._nodes = nodes if nodes is not None else [
            {"node": "pve1", "status": "online", "cluster": "lab"}]
        self.relayed_to = None
        self.raise_on_relay = raise_on_relay
        self.warm_cache = {}

    def get_hypervisor_spoke_for_tenant(self, tid=None):
        return self._bound

    def get_hypervisor_spoke(self):
        return self._global

    def warm_get(self, ns, key):
        return (self.warm_cache.get(ns) or {}).get(key)

    async def warm_set(self, ns, key, data):
        self.warm_cache.setdefault(ns, {})[key] = data

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
        self.relayed_to = sid
        if self.raise_on_relay:
            raise RuntimeError("spoke timeout")
        return {"payload": {"data": {"nodes": self._nodes}}}


def _ctx(admin=True, tenant=None):
    async def _filter_tenant(request, data, module, ip_fields, explicit=None):
        return data
    return SimpleNamespace(
        _session_user=lambda request: {"user": {}},
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: tenant or explicit,
        _filter_tenant=_filter_tenant,
    )


def _build(hub, admin=True, tenant=None):
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, _ctx(admin=admin, tenant=tenant))
    return TestClient(app)


def test_bound_spoke_is_used_when_present():
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    c = _build(hub, admin=False, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    assert len(r.json()["nodes"]) == 1
    # Isolation: the tenant's OWN bound spoke answered, not the global one.
    assert hub.relayed_to == "pxmx-acme"


def test_unbound_tenant_falls_back_to_global_spoke():
    """The reported bug: host connected but not bound to the tenant → Overview
    must still list nodes (VM list already does), not go empty."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    assert len(r.json()["nodes"]) == 1
    assert hub.relayed_to == "pxmx-global"


def test_admin_no_tenant_uses_global_spoke():
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/nodes")
    assert r.status_code == 200
    assert hub.relayed_to == "pxmx-global"


def test_no_spoke_at_all_returns_empty_not_error():
    hub = _Hub(bound_spoke=None, global_spoke=None)
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []
    assert body["spoke_connected"] is False


def test_live_nodes_populate_warm_cache():
    """A successful live fetch seeds the warm cache keyed by tenant scope."""
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200 and len(r.json()["nodes"]) == 1
    assert hub.warm_cache.get("pxmx_nodes", {}).get("acme")  # cached raw


def test_spoke_down_serves_stale_warm_cache():
    """Overview warm-starts after a hub restart: with the spoke unresolved,
    last-known nodes are served (stale) instead of an empty list — mirroring the
    VM tab so the Overview doesn't blank while VMs render from their cache."""
    hub = _Hub(bound_spoke=None, global_spoke=None)
    hub.warm_cache["pxmx_nodes"] = {"acme": {"nodes": [{"node": "pve1", "status": "online"}]}}
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1
    assert body["stale"] is True
    assert body["spoke_connected"] is False


def test_live_fetch_failure_falls_back_to_warm_cache():
    """A live GET_NODE_STATS timeout serves stale nodes rather than a 500."""
    hub = _Hub(bound_spoke="pxmx-acme", raise_on_relay=True)
    hub.warm_cache["pxmx_nodes"] = {"acme": {"nodes": [{"node": "pve1", "status": "online"}]}}
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1 and body["stale"] is True
