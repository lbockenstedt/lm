"""Warm-cache regression tests for ``/api/pxmx/vms`` (``routes/pxmx.py``).

Pre-fix, the Hypervisor VM list relied ONLY on the in-memory ``_tenant_cache``
(populated by the background refresh loop) — nothing was persisted to disk, so
after a hub service restart the page went empty (or 503) until the live
``PXMX_LIST_VMS`` round-trip returned. The route now mirrors the netbox/cppm
warm cache: every successful live fetch writes the raw envelope to
``warm_cache.json`` via ``hub.warm_set``; a spoke-down / failed fetch serves the
last-known snapshot marked ``stale`` instead of going empty. These lock in:

* a live fetch persists the raw envelope to the warm cache (keyed by tag+agent);
* a spoke-down with a warm snapshot serves it stale (``stale=True``,
  ``spoke_connected=False``) — the reboot warm-load path;
* a spoke-down with NO snapshot falls back to the empty spoke-down envelope;
* a live-fetch failure with a warm snapshot serves it stale instead of 500;
* the warm-cache scope key isolates tenants by their ``proxmox_tag`` (an
  admin / tagless read caches under ``_all_``; a tagged tenant under its tag)
  so one tenant's raw envelope is never served to another.
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx


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


class _Hub:
    """Minimal hub: in-memory warm cache + canned PXMX_LIST_VMS replies."""

    def __init__(self, vms=None, spoke_connected=True, tenants=None,
                 system_state=None, protected=None):
        self.state = _State(tenants=tenants, system_state=system_state)
        self.simulations_store = _Store(protected=protected)
        self._spoke = "pxmx-1" if spoke_connected else None
        self._vms = vms if vms is not None else []
        self.warm = {}          # {(namespace, key): raw envelope}
        self.warm_sets = []     # log of (namespace, key) writes
        self.fail_live = False  # make request_response raise

    # warm cache surface (WarmCacheMixin)
    def warm_get(self, namespace, key="_"):
        return self.warm.get((namespace, key))

    async def warm_set(self, namespace, key, data):
        self.warm[(namespace, key)] = data
        self.warm_sets.append((namespace, key))

    def get_hypervisor_spoke(self):
        return self._spoke

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
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
    assert len(r.json()["vms"]) == 1
    # raw envelope persisted under the admin / tagless scope key
    assert ("pxmx_vms", "_all_|agent=") in hub.warm
    assert hub.warm_sets == [("pxmx_vms", "_all_|agent=")]


def test_spoke_down_serves_warm_snapshot_stale():
    """The reboot warm-load path: spoke disconnected, but a prior live fetch
    left a snapshot in the warm cache → serve it stale instead of going empty."""
    hub = _Hub(spoke_connected=False)
    # simulate a snapshot persisted before the restart
    hub.warm[("pxmx_vms", "_all_|agent=")] = {"vms": [{"name": "carried-over"}],
                                              "spoke_connected": True}
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert body["stale"] is True
    assert body["spoke_connected"] is False
    assert [v["name"] for v in body["vms"]] == ["carried-over"]


def test_spoke_down_no_snapshot_returns_empty_envelope():
    hub = _Hub(spoke_connected=False)
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms")
    assert r.status_code == 200
    body = r.json()
    assert body["vms"] == []
    assert body["spoke_connected"] is False
    assert "stale" not in body     # not stale — genuinely nothing


def test_live_fetch_failure_serves_warm_snapshot_stale():
    """A live-fetch error (timeout / spoke RPC failure) falls back to the warm
    snapshot instead of 500 when one exists."""
    hub = _Hub(vms=[{"name": "fresh"}], spoke_connected=True)
    hub.fail_live = True
    hub.warm[("pxmx_vms", "_all_|agent=")] = {"vms": [{"name": "carried-over"}]}
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


def test_warm_key_is_scoped_by_proxmox_tag():
    """A tenant with a proxmox_tag caches under its own key; an admin / tagless
    read caches under ``_all_`` — so the two raw envelopes never collide and a
    tenant can't be served another scope's snapshot."""
    hub = _Hub(vms=[{"name": "tagged-vm"}],
               tenants={"acme": {"proxmox_tag": "acme"}})
    c = _build(hub, admin=True, tenant="acme")
    r = c.get("/api/pxmx/vms?tenant=acme")
    assert r.status_code == 200
    assert ("pxmx_vms", "acme|agent=") in hub.warm
    assert ("pxmx_vms", "_all_|agent=") not in hub.warm


def test_warm_key_agent_scope_partition():
    """An agent-scoped read (``?agent_id=``) caches under a distinct key so it
    isn't served back to an all-agents read (different raw envelope)."""
    hub = _Hub(vms=[{"name": "one-agent"}])
    c = _build(hub, admin=True)
    r = c.get("/api/pxmx/vms?agent_id=pxmx-2")
    assert r.status_code == 200
    assert ("pxmx_vms", "_all_|agent=pxmx-2") in hub.warm
    assert ("pxmx_vms", "_all_|agent=") not in hub.warm


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