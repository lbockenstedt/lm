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

The node list is served from the hub data cache (ns ``pxmx_nodes``, key =
tenant id or ``_all_``); the fakes below use the real ``WarmCacheMixin``.
"""

import tempfile
import time
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx
from warm_cache import STALE_AFTER_S, WarmCacheMixin


class _State:
    def __init__(self):
        self.system_state = {}

    def _mark_dirty(self):
        pass

    def is_agent_decommissioned(self, apk):
        return False


class _Hub(WarmCacheMixin):
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
        self.cache_dir = tempfile.mkdtemp(prefix="pxmx-nodes-")
        self.warm_cache_init()
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

    def seed_warm(self, ns, key, data, age=0.0, tenants=None):
        """Seed a cached entry the way a past successful fetch would have."""
        entry = {"data": data, "fetched_at": time.time() - age}
        if tenants is not None:
            entry["tenants"] = list(tenants)
        self.warm_cache.setdefault(ns, {})[key] = entry

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


def test_admin_default_tenant_sees_its_own_unbound_global_spoke():
    """The ADMIN (``default``) tenant is scoped exactly like any other tenant:
    an UNBOUND (truly unassigned) global hypervisor spoke is visible to it —
    same fallback a real tenant with no dedicated spoke gets (see
    ``test_unbound_tenant_falls_back_to_global_spoke``). Only a spoke bound to
    a DIFFERENT real tenant must stay excluded (see the companion
    ``..._does_not_leak_a_foreign_bound_spoke`` test below) — that was the
    originally-reported cross-tenant accumulation. Previously ADMIN/default
    was blanked unconditionally here, which also hid a Proxmox host the admin
    had deliberately assigned to the ADMIN tenant (the reported "servers I
    just added don't show up" bug)."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant=None)  # ctx resolves ?tenant= explicitly
    r = c.get("/api/pxmx/nodes?tenant=default")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1
    assert body.get("select_tenant") is not True
    assert hub.relayed_to == "pxmx-global"


def test_admin_default_tenant_sees_a_spoke_explicitly_bound_to_it():
    """The reported bug: a Proxmox hypervisor spoke the admin explicitly
    assigned to the ADMIN (``default``) tenant must show up on the ADMIN
    tenant's own Overview — it is a REAL binding, not "unassigned", and
    ``default`` is scoped like any other tenant id."""
    hub = _Hub(bound_spoke="pxmx-admin-host", global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/nodes?tenant=default")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1
    assert body.get("select_tenant") is not True
    assert hub.relayed_to == "pxmx-admin-host"


def test_admin_default_tenant_does_not_leak_a_foreign_bound_spoke():
    """ADMIN (``default``) must still never accumulate a spoke BOUND to some
    OTHER real tenant — the originally-reported cross-tenant leak. Mirrors
    ``test_foreign_bound_global_spoke_does_not_leak_into_other_tenant`` but for
    the ADMIN tenant itself."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-lrb", global_spoke_tenant="lrb")
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/nodes?tenant=default")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []
    assert hub.relayed_to is None  # no spoke was queried


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
    hub.seed_warm("pxmx_nodes", "ra", {"nodes": [{"node": "lrb-pve", "status": "online"}]})
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
    """A successful live fetch seeds the hub cache keyed by tenant scope."""
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200 and len(r.json()["nodes"]) == 1
    assert r.json()["cached_at"] is not None
    entry = hub.warm_cache.get("pxmx_nodes", {}).get("acme")
    assert entry and entry["data"]["nodes"]  # cached raw
    assert entry["tenants"] == ["acme"]


def test_admin_unscoped_nodes_cached_under_all_key():
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant=None)
    assert c.get("/api/pxmx/nodes").status_code == 200
    assert set(hub.warm_cache["pxmx_nodes"]) == {"_all_"}


def test_fresh_cached_nodes_served_without_relay():
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    hub.seed_warm("pxmx_nodes", "acme", {"nodes": [{"node": "cached-pve", "status": "online"}]})
    c = _build(hub, admin=True, tenant="acme")
    body = c.get("/api/pxmx/nodes?tenant=acme").json()
    assert [n["node"] for n in body["nodes"]] == ["cached-pve"]
    assert hub.relayed_to is None
    assert "stale" not in body


def test_spoke_down_serves_stale_warm_cache():
    """Overview warm-starts after a hub restart: with the spoke unresolved,
    last-known nodes are served (stale) instead of an empty list — mirroring the
    VM tab so the Overview doesn't blank while VMs render from their cache."""
    hub = _Hub(bound_spoke=None, global_spoke=None)
    hub.seed_warm("pxmx_nodes", "acme", {"nodes": [{"node": "pve1", "status": "online"}]},
                  age=STALE_AFTER_S + 60)
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    assert len(body["nodes"]) == 1
    assert body["stale"] is True
    assert body["cached_at"] is not None


def test_live_fetch_failure_falls_back_to_warm_cache():
    """A live GET_NODE_STATS timeout serves stale nodes rather than a 500."""
    hub = _Hub(bound_spoke="pxmx-acme", raise_on_relay=True)
    hub.seed_warm("pxmx_nodes", "acme", {"nodes": [{"node": "pve1", "status": "online"}]}, age=300)
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    assert len(r.json()["nodes"]) == 1
    # The background refresh the read kicked off failed → the entry is now
    # flagged as failing and the next read is badged stale (still served).
    deadline = time.time() + 2
    while time.time() < deadline and not hub.warm_cache["pxmx_nodes"]["acme"].get("error_at"):
        time.sleep(0.01)
    body = c.get("/api/pxmx/nodes?tenant=acme").json()
    assert len(body["nodes"]) == 1 and body["stale"] is True


def test_live_fetch_failure_no_cache_returns_empty_envelope():
    hub = _Hub(bound_spoke="pxmx-acme", raise_on_relay=True)
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/nodes?tenant=acme")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == [] and body["spoke_connected"] is False
    assert not hub.warm_cache.get("pxmx_nodes")  # a failure is never cached


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


# ── /api/pxmx/drive-health: same ADMIN(default) rule, behaviourally ──────────
# These replace source-text assertions in test_pxmx_admin_default_scope.py that
# grepped the route body for `if tid == "default":\n            spokes = []`
# with exact indentation. That guarded the letter of the fix, not its effect:
# it would pass on a route that had been reindented into something broken and
# fail on a correct one that was merely reformatted. Flagged on lm#1026.

def test_drive_health_admin_default_queries_no_spoke():
    """ADMIN(default) must not borrow the global hypervisor spoke, which may be
    bound to ANOTHER tenant — that leaked that tenant's drive diagnostics into
    the ADMIN view."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-lrb", global_spoke_tenant="lrb")
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/drive-health?tenant=default")
    assert r.status_code == 200
    body = r.json()
    assert body["nodes"] == []
    assert body.get("select_tenant") is not True
    assert hub.relayed_to is None, "queried a spoke for the ADMIN scope"


def test_drive_health_admin_default_reports_no_spoke_connected():
    """``spoke_connected`` answers "is a hypervisor spoke attached?". It was
    forced True here purely to suppress the UI's offline banner, so every other
    reader saw a spoke that does not exist. The UI now branches on
    ``select_tenant`` first, so the field stays honest."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-lrb", global_spoke_tenant="lrb")
    c = _build(hub, admin=True, tenant=None)
    body = c.get("/api/pxmx/drive-health?tenant=default").json()
    assert body["spoke_connected"] is False
    assert body["summary"]["total_drives"] == 0



def test_drive_health_unscoped_admin_still_uses_global_spoke():
    """A programmatic call with no ``?tenant=`` at all keeps the fleet view."""
    hub = _Hub(bound_spoke=None, global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/drive-health")
    assert r.status_code == 200
    assert r.json().get("select_tenant") is None
    assert hub.relayed_to == "pxmx-global"


def test_drive_health_specific_tenant_uses_its_bound_spoke():
    hub = _Hub(bound_spoke="pxmx-acme", global_spoke="pxmx-global")
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/drive-health?tenant=acme")
    assert r.status_code == 200
    assert hub.relayed_to == "pxmx-acme"
