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

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx


@pytest.fixture(autouse=True)
def _reset_nodes_ttl_cache():
    """The route's fresh-TTL memo (``_NODES_CACHE``) is module-level and keyed
    by tenant scope — several tests here reuse the same scope (e.g. "acme")
    with different hub fakes, so a stale entry from an earlier test would be
    served instead of hitting the fake spoke this test set up."""
    pxmx._NODES_CACHE.clear()
    yield
    pxmx._NODES_CACHE.clear()


class _State:
    def __init__(self):
        self.system_state = {}

    def _mark_dirty(self):
        pass

    def is_agent_decommissioned(self, apk):
        return False


class _Hub:
    """Minimal hub: records which spoke GET_NODE_STATS was relayed to."""

    def __init__(self, bound_spoke=None, global_spoke="pxmx-global",
                 nodes=None, raise_on_relay=False, global_spoke_tenant=None,
                 offline_hosts=None):
        self.state = _State()
        self._bound = bound_spoke
        self._global = global_spoke
        self._nodes = nodes if nodes is not None else [
            {"node": "pve1", "status": "online", "cluster": "lab"}]
        self.relayed_to = None
        self.raise_on_relay = raise_on_relay
        self.warm_cache = {}
        # Persisted offline relay-agent roster (reconstructed by
        # _offline_relay_agents): a host whose parent spoke is DOWN. Seed the
        # exact side-data that helper reads (agent_config + composite heartbeat
        # keys) so the Overview merge can surface it as an offline node.
        self.heartbeat = SimpleNamespace(last_seen={})
        for oh in (offline_hosts or []):
            aid = oh["agent_id"]
            self.state.system_state.setdefault("agent_config", {})[aid] = {
                "agent_id": aid,
                "hostname": oh["hostname"],
                "client_simulation": {"tenant_id": oh.get("tenant", "")},
            }
            self.heartbeat.last_seen[f"{oh.get('spoke', 'sp-' + aid)}:{aid}"] = \
                oh.get("last_seen", 100.0)
        # A global hypervisor spoke BOUND to a specific tenant — used to prove
        # the Overview fallback never leaks a bound host into another tenant.
        if global_spoke and global_spoke_tenant is not None:
            self.state.system_state["module_metadata"] = {
                global_spoke: {"tenant_id": global_spoke_tenant}}

    def get_hypervisor_spoke_for_tenant(self, tid=None):
        return self._bound

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        # Plural tenant-scoped resolver: the single bound spoke (if any),
        # mirroring the pre-fix bound_spoke semantics for these tests.
        return [self._bound] if self._bound else []

    def get_all_spokes_by_type(self, module_type):
        if module_type == "hypervisor":
            return [self._global] if self._global else []
        return []

    def get_hypervisor_spoke(self):
        return self._global

    def is_spoke_in_contact(self, spoke_pk):
        # Seeded offline hosts are treated as parent-spoke-down so
        # _offline_relay_agents surfaces them.
        return False

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


def test_foreign_bound_global_spoke_does_not_leak_into_other_tenant():
    """CROSS-TENANT ISOLATION (reported leak): the global hypervisor spoke is
    BOUND to tenant 'lrb'. Tenant 'ra' has no hypervisor of its own, so the
    fallback must NOT surface lrb's host in ra's Overview — it returns an empty
    envelope and never relays GET_NODE_STATS to the foreign spoke."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-lrb", global_spoke_tenant="lrb")
    c = _build(hub, admin=True, tenant="ra")
    r = c.get("/api/pxmx/nodes?tenant=ra")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []
    assert body["spoke_connected"] is False
    assert hub.relayed_to is None  # never queried the foreign-bound host


def test_foreign_bound_global_spoke_ignores_poisoned_warm_cache():
    """Even if a pre-fix leaky fetch poisoned ra's per-tenant warm cache with
    lrb's nodes, the isolation path returns a CLEAN empty envelope rather than
    re-serving the stale cross-tenant data."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-lrb", global_spoke_tenant="lrb")
    hub.warm_cache["pxmx_nodes"] = {"ra": {"nodes": [{"node": "lrb-pve", "status": "online"}]}}
    c = _build(hub, admin=True, tenant="ra")
    r = c.get("/api/pxmx/nodes?tenant=ra")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []  # poisoned cache NOT served
    assert hub.relayed_to is None


def test_unbound_global_spoke_still_falls_back():
    """A genuinely UNBOUND connected host (no tenant binding) still falls back
    to the global spoke so its Overview matches its subnet-filtered VM list —
    the isolation guard only excludes hosts bound to a DIFFERENT tenant."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global", global_spoke_tenant="")
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    assert len(r.json()["nodes"]) == 1
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


# ── Offline-host merge (reported gap: '05 is offline; shows in CS module but ──
# not the Hypervisor module') ─────────────────────────────────────────────────
# A host whose agent (and co-located parent spoke) is down is reported by no
# live cluster peer, so GET_NODE_STATS from the online spokes drops it — yet it
# stays visible (offline) in the Agents/Simulations roster. get_pxmx_nodes now
# folds that persisted offline roster back into the node list, marked offline.

def test_offline_host_merged_into_live_nodes():
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global",
               offline_hosts=[{"hostname": "svr-05", "agent_id": "agent-05",
                               "tenant": "acme", "spoke": "pxmx-05"}])
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    nodes = r.json()["nodes"]
    by_name = {str(n["node"]).lower(): n for n in nodes}
    assert "pve1" in by_name              # the live node still present
    assert "svr-05" in by_name            # the offline host now surfaced
    off = by_name["svr-05"]
    assert off["status"] == "offline" and off["offline"] is True
    assert off["agent_id"] == "agent-05"


def test_offline_host_not_leaked_across_tenants():
    """An offline host pinned to 'acme' must not appear in tenant 'ra' — the
    same effective-tenant filter the Agents roster applies."""
    hub = _Hub(bound_spoke="pxmx-ra", global_spoke="pxmx-global",
               offline_hosts=[{"hostname": "svr-05", "agent_id": "agent-05",
                               "tenant": "acme", "spoke": "pxmx-05"}])
    c = _build(hub, admin=True, tenant="ra")
    r = c.get("/api/pxmx/nodes?tenant=ra")
    assert r.status_code == 200
    names = {str(n["node"]).lower() for n in r.json()["nodes"]}
    assert "svr-05" not in names


def test_offline_host_deduped_against_live_node():
    """If a live cluster peer already reports the (now-offline) node by
    hostname, the merge must NOT add a duplicate row."""
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global",
               nodes=[{"node": "svr-05", "status": "offline", "cluster": "lab"}],
               offline_hosts=[{"hostname": "svr-05", "agent_id": "agent-05",
                               "tenant": "acme", "spoke": "pxmx-05"}])
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    names = [str(n["node"]).lower() for n in r.json()["nodes"]]
    assert names.count("svr-05") == 1


def test_offline_host_hidden_when_operator_deleted():
    """A host the operator explicitly removed (pxmx_hidden_nodes) stays gone
    even though its offline roster entry survives."""
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global",
               offline_hosts=[{"hostname": "svr-05", "agent_id": "agent-05",
                               "tenant": "acme", "spoke": "pxmx-05"}])
    hub.state.system_state["pxmx_hidden_nodes"] = ["svr-05"]
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    names = {str(n["node"]).lower() for n in r.json()["nodes"]}
    assert "svr-05" not in names


def test_offline_host_surfaced_when_no_spoke_and_no_cache():
    """No connected spoke and no warm cache used to yield an empty Overview;
    the offline host is now surfaced from persisted state (marked stale)."""
    hub = _Hub(bound_spoke=None, global_spoke=None,
               offline_hosts=[{"hostname": "svr-05", "agent_id": "agent-05",
                               "tenant": "acme", "spoke": "pxmx-05"}])
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    names = {str(n["node"]).lower() for n in body["nodes"]}
    assert "svr-05" in names
