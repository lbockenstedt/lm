"""Regression tests for ``_merge_pinned_agent_vms`` (``routes/pxmx.py``),
closing three defects the skeptical review panel found in lm#1131/#1132:

* STATE COVERAGE — a pinned ``agent_config[...].client_simulation.tenant_id``
  was compared to the scope tenant with a raw ``!=``, so a pin recorded as
  ``"Default"`` never matched a scope of ``"default"`` -- exactly the
  case-mismatch class of bug the surrounding feature claims to fix.
* REACHABILITY — the merge call was wired into only 3 of ``get_pxmx_vms``'s 5
  return paths. The fast non-admin session-cache hit and the no-visible-spoke
  cached-entry fallback both skipped it, so a pinned host's off-subnet/
  untagged VMs depended on which branch served the response.
* Single-agent scope — ``?agent_id=`` must restrict the merge to that ONE
  pinned agent, not union every agent pinned to the same tenant.
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
    """One SHARED spoke (bound to no tenant) hosting two agents: one pinned
    to tenant 'lrb' (as 'Lrb' -- deliberately mismatched case), one unpinned.
    """

    def __init__(self, pin="Lrb", pinned_agent="shared-agent-1",
                 other_agent="shared-agent-2", shared_spoke="pxmx-shared"):
        agent_config = {}
        if pinned_agent:
            agent_config[pinned_agent] = {"client_simulation": {"tenant_id": pin}}
        if other_agent:
            agent_config[other_agent] = {"client_simulation": {"tenant_id": ""}}
        self.state = _State(system_state={
            "module_metadata": {},  # shared spoke: unbound to any tenant
            "agent_config": agent_config,
        })
        self.simulations_store = _Store()
        self._shared_spoke = shared_spoke
        self._pinned_agent, self._other_agent = pinned_agent, other_agent
        # Live PXMX_LIST_VMS fanout returns nothing for the shared spoke itself
        # (no VMs reachable via subnet/tag) -- the merge is the only way the
        # pinned host's VM shows up at all.
        self._live_vms = []
        self._pinned_vms = [{"name": "pinned-vm", "node": "pinned-host", "vmid": 1,
                              "unique_id": "pinned-host/1"}]
        self.warm = {}
        self.queried_merge = []  # agent ids queried via the merge's request_response

    def warm_get(self, ns, key):
        return self.warm.get((ns, key))

    async def warm_set(self, ns, key, data):
        self.warm[(ns, key)] = data

    def get_hypervisor_spoke(self):
        return self._shared_spoke

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        return []  # nothing explicitly bound -- only the unbound shared spoke

    def get_all_spokes_by_type(self, module_type):
        return [self._shared_spoke] if module_type == "hypervisor" else []

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        if agent_id in (self._pinned_agent, self._other_agent):
            return self._shared_spoke
        return None

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
        if cmd == "PXMX_LIST_VMS" and "agent_id" in payload:
            self.queried_merge.append(payload["agent_id"])
            if payload["agent_id"] == self._pinned_agent:
                return {"payload": {"data": {"vms": self._pinned_vms}}}
            return {"payload": {"data": {"vms": []}}}
        return {"payload": {"data": {"vms": self._live_vms, "spoke_connected": True}}}


def _ctx(admin=True, tenant=None, sess=None):
    async def _filter_tenant(request, data, module, ip_fields, explicit=None):
        return data
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


def test_pinned_agent_merge_is_case_insensitive():
    """Pin recorded as 'Lrb' must still be merged into a request for tenant
    'lrb' -- pre-fix this raw-string comparison silently dropped the host."""
    hub = _Hub(pin="Lrb")
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get("/api/pxmx/vms?tenant=lrb")
    assert r.status_code == 200
    names = sorted(v["name"] for v in r.json()["vms"])
    assert "pinned-vm" in names
    assert hub._pinned_agent in hub.queried_merge


def test_pinned_agent_merge_scoped_to_requested_agent_id():
    """?agent_id=<other> must NOT pull in a different agent pinned to the
    same tenant -- pre-fix the merge unioned every pinned agent regardless of
    the requested single-agent scope."""
    hub = _Hub(pin="lrb")
    c = _build(hub, admin=True, tenant="lrb")
    r = c.get(f"/api/pxmx/vms?tenant=lrb&agent_id={hub._other_agent}")
    assert r.status_code == 200
    assert hub._pinned_agent not in hub.queried_merge


def test_pinned_agent_merge_reachable_on_non_admin_session_cache_path():
    """The fast non-admin session-cache-hit path (no ?agent_id, no ?tenant,
    session already scoped) must also apply the pinned-host merge. Pre-fix
    this early return skipped ``_merge_pinned_agent_vms`` entirely."""
    import time
    import api as api_mod

    hub = _Hub(pin="lrb")
    tid = "lrb"
    try:
        api_mod._tenant_cache[tid] = {
            "pxmx_vms": {"data": {"vms": []}, "fetched_at": time.time()},
        }
        c = _build(hub, admin=False, tenant=None, sess={"user": {"tenant_id": tid}})
        r = c.get("/api/pxmx/vms")  # fast session-cache path: no agent_id/tenant
        assert r.status_code == 200
        names = sorted(v["name"] for v in r.json()["vms"])
        assert "pinned-vm" in names
    finally:
        api_mod._tenant_cache.pop(tid, None)
