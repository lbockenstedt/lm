"""Hub-cache regression tests for ``/api/pxmx/vms`` (``routes/pxmx.py``).

The VM list is served from the unified hub data cache
(``WarmCacheMixin.cache_read``, ns ``pxmx_vms``): every successful fetch stores
the RAW aggregate (persisted to disk), a read with a cached entry returns it
immediately (refreshing in the background when it is older than the refresh
interval), and only a read with NOTHING cached waits on the live fetch. These
lock in:

* a live fetch stores the raw envelope in the hub cache (keyed by tenant+agent);
* a spoke-down with a cached entry still serves it — the reboot warm-load
  path — badged ``stale`` once it is old or the refresh is failing;
* a spoke-down with NOTHING cached falls back to the empty spoke-down envelope;
* a live-fetch failure with a cached entry serves the cached entry instead of
  500; with nothing cached it surfaces 500;
* the cache key isolates tenants by TENANT ID (an admin unscoped read caches
  under ``_all_``) — two tenants sharing a proxmox_tag never share an entry;
* an ``?agent_id=`` read is a separate entry from the all-agents read.
"""

import tempfile
import time
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx
from warm_cache import STALE_AFTER_S, WarmCacheMixin


# ── Fakes ────────────────────────────────────────────────────────────────────

class _State:
    """Minimal hub.state: per-tenant proxmox_tag + system_state for
    access._template_pools / get_tenant_scoping."""

    def __init__(self, tenants=None, system_state=None):
        self._tenants = tenants or {}
        self.system_state = system_state or {}

    def get_tenant(self, tid):
        return self._tenants.get(tid)


class _Store:
    """Minimal simulations_store: just the delete-protection union surface."""

    def __init__(self, protected=None):
        self._protected = set(protected or [])

    def get_all_protected_vms(self):
        return set(self._protected)


class _Hub(WarmCacheMixin):
    """Minimal hub: the real hub data cache + canned PXMX_LIST_VMS replies."""

    def __init__(self, vms=None, spoke_connected=True, tenants=None,
                 system_state=None, protected=None, spoke_tenant=None):
        self.state = _State(tenants=tenants, system_state=system_state)
        self.simulations_store = _Store(protected=protected)
        self._spoke = "pxmx-1" if spoke_connected else None
        self._vms = vms if vms is not None else []
        self.fail_live = False  # make request_response raise
        self.live_calls = []    # payloads sent to PXMX_LIST_VMS
        self.cache_dir = tempfile.mkdtemp(prefix="pxmx-vms-cache-")
        self.warm_cache_init()
        # The single spoke's tenant binding, for the spoke-visibility gate in
        # get_pxmx_vms (mirrors get_pxmx_nodes' global_spoke_tenant fixture
        # pattern) — None = unbound (visible to any tenant as the fallback).
        self._spoke_tenant = spoke_tenant
        if self._spoke and spoke_tenant is not None:
            self.state.system_state.setdefault("module_metadata", {})[self._spoke] = \
                {"tenant_id": spoke_tenant}

    def seed_warm(self, namespace, key, data, age=0.0, tenants=None):
        """Seed a cached entry the way a past successful fetch would have."""
        entry = {"data": data, "fetched_at": time.time() - age}
        if tenants is not None:
            entry["tenants"] = list(tenants)
        self.warm_cache.setdefault(namespace, {})[key] = entry
        return entry["fetched_at"]

    def get_hypervisor_spoke(self):
        return self._spoke

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        if self._spoke and tid and self._spoke_tenant == tid:
            return [self._spoke]
        return []

    def get_all_spokes_by_type(self, module_type):
        # Only a hypervisor spoke in these warm-cache fakes; simulation empty.
        if module_type == "hypervisor":
            return [self._spoke] if self._spoke else []
        return []

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return self._spoke

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
        self.live_calls.append(dict(payload))
        if self.fail_live:
            raise RuntimeError("live fetch failed")
        return {"payload": {"data": {"vms": self._vms,
                                     "spoke_connected": True}}}


def _ctx(admin=True, tenant=None):
    """Route ctx with stubbed auth + a passthrough tenant filter (these tests
    exercise the warm-cache wiring, not subnet filtering)."""
    async def _filter_tenant(request, data, module, ip_fields, explicit=None):
        return data
    return SimpleNamespace(
        _session_user=lambda request: None,
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: tenant or explicit,
        _filter_tenant=_filter_tenant,
    )


def _build(hub, admin=True, tenant=None):
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, _ctx(admin=admin, tenant=tenant))
    return TestClient(app)


# ── Tests ────────────────────────────────────────────────────────────────────

def test_live_fetch_persists_to_warm_cache():
    hub = _Hub(vms=[{"name": "vm-1", "vmid": 100, "ips": []}])
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert len(body["vms"]) == 1
    assert body["cached_at"] is not None
    # raw envelope stored under the admin / unscoped key
    assert list(hub.warm_cache["pxmx_vms"]) == ["_all_|agent="]
    entry = hub.warm_cache["pxmx_vms"]["_all_|agent="]
    assert [v["name"] for v in entry["data"]["vms"]] == ["vm-1"]


def test_second_read_served_from_cache_without_live_fetch():
    hub = _Hub(vms=[{"name": "vm-1", "vmid": 100, "ips": []}])
    c = _build(hub, admin=True)
    assert c.get("/api/pxmx/vms").status_code == 200
    assert len(hub.live_calls) == 1
    hub._vms = [{"name": "changed", "vmid": 101, "ips": []}]
    r = c.get("/api/pxmx/vms")
    assert [v["name"] for v in r.json()["vms"]] == ["vm-1"]
    assert len(hub.live_calls) == 1  # fresh entry: no refresh fired


def test_spoke_down_serves_warm_snapshot_stale():
    """The reboot warm-load path: spoke disconnected, but a prior live fetch
    left an (old) entry in the hub cache → serve it, badged stale, instead of
    going empty."""
    hub = _Hub(spoke_connected=False)
    seeded = hub.seed_warm("pxmx_vms", "_all_|agent=",
                           {"vms": [{"name": "carried-over"}], "spoke_connected": True},
                           age=STALE_AFTER_S + 60)
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert body["stale"] is True
    assert abs(body["cached_at"] - seeded) < 1
    assert [v["name"] for v in body["vms"]] == ["carried-over"]


def test_spoke_down_failed_refresh_marks_cached_entry_stale():
    """A recent entry whose background refresh then FAILS (spoke went away)
    keeps being served, now badged stale."""
    hub = _Hub(spoke_connected=False)
    hub.seed_warm("pxmx_vms", "_all_|agent=", {"vms": [{"name": "carried-over"}]}, age=300)
    c = _build(hub, admin=True)
    first = c.get("/api/pxmx/vms").json()
    assert [v["name"] for v in first["vms"]] == ["carried-over"]
    # The background refresh spawned by the first read failed and was recorded.
    deadline = time.time() + 2
    while time.time() < deadline and not hub.warm_cache["pxmx_vms"]["_all_|agent="].get("error_at"):
        time.sleep(0.01)
    second = c.get("/api/pxmx/vms").json()
    assert second["stale"] is True
    assert [v["name"] for v in second["vms"]] == ["carried-over"]


def test_spoke_down_no_snapshot_returns_empty_envelope():
    hub = _Hub(spoke_connected=False)
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert body["vms"] == []
    assert body["spoke_connected"] is False
    assert "stale" not in body     # not stale — genuinely nothing
    assert not hub.warm_cache.get("pxmx_vms")  # an error is never cached


def test_live_fetch_failure_serves_warm_snapshot_stale():
    """A live-fetch error (timeout / spoke RPC failure) never replaces a cached
    entry: the cached list is served instead of 500."""
    hub = _Hub(vms=[{"name": "fresh"}], spoke_connected=True)
    hub.fail_live = True
    hub.seed_warm("pxmx_vms", "_all_|agent=", {"vms": [{"name": "carried-over"}]},
                  age=STALE_AFTER_S + 60)
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert body["stale"] is True
    assert [v["name"] for v in body["vms"]] == ["carried-over"]


def test_live_fetch_failure_no_snapshot_surfaces_500():
    hub = _Hub(spoke_connected=True)
    hub.fail_live = True
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 500


def test_warm_key_is_scoped_by_tenant_id():
    """A tenant caches under its own TENANT id (the proxmox_tag is sent to the
    spoke as ``tag_filter`` but is not the key); an admin unscoped read caches
    under ``_all_`` — so the raw envelopes never collide."""
    hub = _Hub(vms=[{"name": "tagged-vm"}],
               tenants={"acme": {"proxmox_tag": "acme-tag"}})
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/vms?tenant=acme")
    assert r.status_code == 200
    keys = set(hub.warm_cache["pxmx_vms"])
    assert keys == {"acme|agent="}
    assert hub.warm_cache["pxmx_vms"]["acme|agent="]["tenants"] == ["acme"]
    assert hub.live_calls[-1].get("tag_filter") == "acme-tag"


def test_two_tagless_tenants_never_share_an_entry():
    """Two tenants with the SAME (empty) proxmox_tag must get separate keys."""
    hub = _Hub(vms=[{"name": "vm"}], tenants={"t1": {}, "t2": {}})
    _build(hub, admin=True, tenant="t1").get("/api/pxmx/vms?tenant=t1")
    _build(hub, admin=True, tenant="t2").get("/api/pxmx/vms?tenant=t2")
    assert set(hub.warm_cache["pxmx_vms"]) == {"t1|agent=", "t2|agent="}
    assert len(hub.live_calls) == 2


def test_warm_key_agent_scope_partition():
    """An agent-scoped read (``?agent_id=``) caches under a distinct key so it
    isn't served back to an all-agents read (different raw envelope)."""
    hub = _Hub(vms=[{"name": "one-agent"}])
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms?agent_id=pxmx-2")
    assert r.status_code == 200
    keys = set(hub.warm_cache["pxmx_vms"])
    assert keys == {"_all_|agent=pxmx-2"}
    assert hub.warm_cache["pxmx_vms"]["_all_|agent=pxmx-2"].get("detail") is True


def test_protected_vm_annotated_in_list():
    """A VM whose unique_id is in the global protected set is stamped
    ``protected: True`` on the way out (so the UI can lock its Delete button);
    a non-protected VM is ``protected: False``."""
    hub = _Hub(vms=[
        {"name": "guarded", "vmid": 100, "ips": [], "unique_id": "px/px/100"},
        {"name": "free",    "vmid": 101, "ips": [], "unique_id": "px/px/101"},
    ], protected={"px/px/100"})
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    by = {v["unique_id"]: v for v in r.json()["vms"]}
    assert by["px/px/100"]["protected"] is True
    assert by["px/px/101"]["protected"] is False



def test_per_read_protected_flag_never_written_into_the_cache_rows():
    """``protected`` is stamped on a copy of each VM; the cached rows (which
    are also persisted to disk) stay exactly as the spoke returned them."""
    hub = _Hub(vms=[{"name": "vm-1", "unique_id": "u1"}], protected={"u1"})
    r = _build(hub, admin=True).get("/api/pxmx/vms")
    assert r.json()["vms"][0]["protected"] is True
    cached = hub.warm_cache["pxmx_vms"]["_all_|agent="]["data"]["vms"][0]
    assert "protected" not in cached


def test_spoke_timeout_envelope_never_replaces_cached_vms():
    """A spoke timeout / self-update comes back as a RETURNED
    ``{"status": "ERROR"}`` envelope (not an exception). It must count as a
    failed refresh: the last-known VMs stay cached and are badged stale."""
    import asyncio
    hub = _Hub(vms=[{"name": "vm-1", "unique_id": "u1"}])
    c = _build(hub, admin=True)
    assert len(c.get("/api/pxmx/vms").json()["vms"]) == 1

    async def timed_out(*a, **k):
        return {"status": "ERROR", "message": "Timed out waiting for spoke response"}
    hub.request_response = timed_out

    async def go():
        hub.cache_refresh("pxmx_vms")
        await hub.cache_wait_idle(2)
    asyncio.run(go())
    body = c.get("/api/pxmx/vms").json()
    assert [v["name"] for v in body["vms"]] == ["vm-1"]
    assert body.get("stale") is True
    assert "Timed out" in hub.cache_meta("pxmx_vms", "_all_|agent=")["error"]
