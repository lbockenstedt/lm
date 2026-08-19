"""Regression tests for ``/api/pxmx/vms`` SPOKE-level tenant isolation
(``routes/pxmx.py``).

Reported bug: Hypervisors -> Overview (``get_pxmx_nodes``) was hardened to
never leak a foreign-tenant-bound spoke's nodes into another tenant's view,
but Hypervisors -> Virtual Machines (``get_pxmx_vms``) still fanned
PXMX_LIST_VMS out to EVERY connected agent-hosting spoke on the fleet,
regardless of tenant, relying entirely on the post-fetch subnet/tag filter
(``access.filter_tenant``) for isolation. That filter's ``hypervisor`` branch
explicitly FAILS OPEN (returns the unfiltered list) when the tenant has no
NetBox prefixes configured, or when the "hypervisor" subnet-filter module is
toggled off -- unlike every other module, which fails closed. A tenant in
either state saw every OTHER tenant's Proxmox VMs.

The fix mirrors get_pxmx_nodes' spoke resolution exactly: restrict the spoke
set to those bound to (or shared with) the resolved tenant BEFORE the fetch,
so isolation no longer depends on subnet prefixes being configured at all.
These lock in:

* a tenant sees only its own bound spoke's VMs, even with zero NetBox
  prefixes configured (the actual reported gap);
* a spoke bound to a DIFFERENT tenant is never queried for this tenant;
* a genuinely unbound (unassigned) spoke still falls back for an unbound
  tenant, matching get_pxmx_nodes and the pre-existing VM-list behavior;
* an admin with no tenant selected ("All") still sees every spoke;
* a non-admin with no resolvable tenant is refused (403), not silently
  shown the whole fleet;
* ``?agent_id=`` can't be used to reach another tenant's spoke by guessing
  an agent id.
"""

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx


@pytest.fixture(autouse=True)
def _reset_vms_ttl_cache():
    pxmx._VMS_CACHE.clear()
    yield
    pxmx._VMS_CACHE.clear()


class _State:
    def __init__(self, system_state=None):
        self.system_state = system_state or {}


class _Store:
    def get_all_protected_vms(self):
        return set()


class _Hub:
    """Two spokes: one bound to tenant 'lrb', one bound to tenant 'ra'.
    Records which spokes were actually queried."""

    def __init__(self, lrb_spoke="pxmx-lrb", ra_spoke="pxmx-ra",
                 lrb_vms=None, ra_vms=None, lrb_tenant="lrb", ra_tenant="ra"):
        module_metadata = {}
        if lrb_spoke and lrb_tenant is not None:
            module_metadata[lrb_spoke] = {"tenant_id": lrb_tenant}
        if ra_spoke and ra_tenant is not None:
            module_metadata[ra_spoke] = {"tenant_id": ra_tenant}
        self.state = _State(system_state={"module_metadata": module_metadata})
        self.simulations_store = _Store()
        self._lrb_spoke, self._ra_spoke = lrb_spoke, ra_spoke
        # unique_id/node/vmid populated -- the cross-spoke aggregator dedups by
        # unique_id (falling back to (node, vmid)); minimal {"name": ...}-only
        # fixtures from two different spokes would collide on that fallback
        # key and silently merge into one, masking the isolation this file
        # tests.
        self._vms = {lrb_spoke: lrb_vms if lrb_vms is not None else
                      [{"name": "lrb-vm", "node": lrb_spoke, "vmid": 100,
                        "unique_id": f"{lrb_spoke}/{lrb_spoke}/100"}],
                     ra_spoke: ra_vms if ra_vms is not None else
                      [{"name": "ra-vm", "node": ra_spoke, "vmid": 200,
                        "unique_id": f"{ra_spoke}/{ra_spoke}/200"}]}
        self._bindings = {lrb_spoke: lrb_tenant, ra_spoke: ra_tenant}
        self.warm = {}
        self.queried = []

    def warm_get(self, ns, key):
        return self.warm.get((ns, key))

    async def warm_set(self, ns, key, data):
        self.warm[(ns, key)] = data

    def get_hypervisor_spoke(self):
        return self._lrb_spoke  # arbitrary "global" pick, matches nodes' single-fallback shape

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        return [s for s, t in self._bindings.items() if s and t == tid]

    def get_all_spokes_by_type(self, module_type):
        if module_type == "hypervisor":
            return [s for s in (self._lrb_spoke, self._ra_spoke) if s]
        return []

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        # Pretend agent ids are just "<spoke>-agent".
        for s in (self._lrb_spoke, self._ra_spoke):
            if s and agent_id == f"{s}-agent":
                return s
        return None

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
        self.queried.append(sid)
        return {"payload": {"data": {"vms": self._vms.get(sid, []),
                                     "spoke_connected": True}}}


def _ctx(admin=True, tenant=None, sess=None):
    async def _filter_tenant(request, data, module, ip_fields, explicit=None):
        return data  # isolate the SPOKE-level gate from the subnet filter
    return SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: admin,
        _resolve_tenant=lambda request, explicit=None: tenant or explicit,
        _filter_tenant=_filter_tenant,
    )


def _build(hub, admin=True, tenant=None, sess=None):
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, _ctx(admin=admin, tenant=tenant, sess=sess))
    return TestClient(app)


def test_tenant_sees_only_its_own_bound_spoke_with_zero_netbox_prefixes():
    """The actual reported gap: no NetBox prefixes configured for this tenant
    (access.filter_tenant's hypervisor branch would fail OPEN here) -- the
    SPOKE-level gate must be what keeps ra's VM out, not the subnet filter."""
    hub = _Hub()
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get("/api/pxmx/vms?tenant=lrb")
    assert r.status_code == 200
    names = [v["name"] for v in r.json()["vms"]]
    assert names == ["lrb-vm"]
    assert hub.queried == ["pxmx-lrb"]  # ra's spoke was never even queried


def test_foreign_tenant_spoke_never_queried():
    hub = _Hub()
    c = _build(hub, admin=True, tenant="ra")
    r = c.get("/api/pxmx/vms?tenant=ra")
    assert r.status_code == 200
    names = [v["name"] for v in r.json()["vms"]]
    assert names == ["ra-vm"]
    assert "pxmx-lrb" not in hub.queried


def test_unbound_spoke_still_falls_back_for_unbound_tenant():
    hub = _Hub(lrb_tenant=None, ra_tenant="ra")  # lrb spoke genuinely unassigned
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get("/api/pxmx/vms?tenant=lrb")
    assert r.status_code == 200
    assert hub.queried == ["pxmx-lrb"]


def test_admin_no_tenant_selected_sees_every_spoke():
    hub = _Hub()
    c = _build(hub, admin=True, tenant=None)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    names = sorted(v["name"] for v in r.json()["vms"])
    assert names == ["lrb-vm", "ra-vm"]
    assert set(hub.queried) == {"pxmx-lrb", "pxmx-ra"}


def test_non_admin_no_resolvable_tenant_is_refused_not_shown_everything():
    hub = _Hub()
    c = _build(hub, admin=False, tenant=None, sess={"user": {}})
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 403
    assert hub.queried == []


def test_agent_id_cannot_reach_a_foreign_tenants_spoke():
    """A tenant scoped to 'lrb' passing ?agent_id=pxmx-ra-agent (guessing/
    probing another tenant's agent id) must not reach ra's spoke."""
    hub = _Hub()
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get("/api/pxmx/vms?tenant=lrb&agent_id=pxmx-ra-agent")
    assert r.status_code == 200
    assert r.json()["vms"] == []
    assert hub.queried == []


def test_agent_id_for_own_tenants_spoke_still_works():
    hub = _Hub()
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get("/api/pxmx/vms?tenant=lrb&agent_id=pxmx-lrb-agent")
    assert r.status_code == 200
    assert [v["name"] for v in r.json()["vms"]] == ["lrb-vm"]
    assert hub.queried == ["pxmx-lrb"]
