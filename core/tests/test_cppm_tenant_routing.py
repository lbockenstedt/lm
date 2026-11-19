"""cppm.py routes resolve the NAC spoke PER TENANT, not the first-connected
spoke of type "nac". Two tenants can each run their own ClearPass appliance;
a request from tenant A must never be answered by tenant B's spoke. The
unselected admin device view can fan out, but Access Tracker requires a
selected tenant because it contains authentication identities.
"""
import asyncio
import tempfile

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from types import MethodType, SimpleNamespace

from hub_spoke_registry import SpokeRegistryMixin
from routes.cppm import (ACCESS_TRACKER_FETCH_PAGE_SIZE, ACCESS_TRACKER_LOOKBACK_HOURS,
                         ACCESS_TRACKER_MAX_PAGES, ACCESS_TRACKER_MIN_INTERVAL_S,
                         NAC_FEED_READS, register)
import routes.cppm as cppm_routes
from warm_cache import WarmCacheMixin
from simulations.tenant_filter import filter_items_by_prefixes


class FakeState:
    def __init__(self, nac_instances=None, module_metadata=None):
        self.system_state = {
            "global_config": {"nac_instances": nac_instances or []},
            "module_metadata": module_metadata or {},
        }
        self._tenants = dict(module_metadata or {})
        tenant_ids = {row.get("tenant_id") for row in (module_metadata or {}).values()
                      if isinstance(row, dict) and row.get("tenant_id")
                      and row.get("tenant_id") != "shared-tenant"}
        self.tenant_state = {"tenants": {tid: {} for tid in tenant_ids}}

    def get_spoke_tenant(self, sid):
        return (self._tenants.get(sid) or {}).get("tenant_id", "")

    def get_global_config(self):
        return self.system_state["global_config"]


class FakeHub(WarmCacheMixin):
    def __init__(self, spokes, replies=None, nac_instances=None,
                module_metadata=None, global_nac=None, approved=None):
        # Real hub data cache (the NAC routes read through hub.cache_read).
        self.cache_dir = tempfile.mkdtemp(prefix="lm-cppm-test-")
        self.warm_cache_init()
        # spokes: set of connected+approved nac spoke ids
        self.active_connections = set(spokes)
        self.approved_modules = approved or {sid: True for sid in spokes}
        self.state = FakeState(nac_instances, module_metadata)
        self.replies = replies or {}   # {spoke_id: {cmd: payload_data}}
        self.forwarded = []
        self._nac_spokes = set(spokes)
        self._global_nac = global_nac

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return self._global_nac if module_type == "nac" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._nac_spokes) if module_type == "nac" else []

    def get_nac_live_spokes(self):
        """Delegate to the production live-spoke list (connected, approved, not stale)."""
        return SpokeRegistryMixin.get_nac_live_spokes(self)

    def get_nac_usable_spokes(self):
        """Delegate to the production usable-spoke list (live and configured)."""
        return SpokeRegistryMixin.get_nac_usable_spokes(self)

    def get_nac_spoke_owner(self, sid):
        """Delegate to the production owner of a NAC spoke's ClearPass."""
        return SpokeRegistryMixin.get_nac_spoke_owner(self, sid)

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        if not tenant_id:
            return self._global_nac
        for sid in self._nac_spokes:
            if self.state.get_spoke_tenant(sid) == tenant_id:
                return sid
        return None

    def get_cppm_spoke_for_global(self):
        """Choose the shared or unassigned spoke used by route tests."""
        shared_tid = cppm_routes.access.shared_tenant_id()
        if shared_tid and shared_tid != "default":
            spoke = self.get_cppm_spoke_for_tenant(shared_tid)
            if (spoke in self.active_connections
                    and self.approved_modules.get(spoke, False)):
                return spoke
        for spoke in self.get_all_spokes_by_type("nac"):
            if (spoke in self.active_connections
                    and self.approved_modules.get(spoke, False)
                    and not self.state.get_spoke_tenant(spoke)):
                return spoke
        return None

    def get_cppm_spoke_for_shared(self):
        return None

    def get_cppm_spokes_for_tenant(self, tenant_id=None):
        if not tenant_id or tenant_id == "default":
            return []
        own = self.get_cppm_spoke_for_tenant(tenant_id)
        shared = self.get_cppm_spoke_for_shared()
        return list(dict.fromkeys(sid for sid in (own, shared) if sid))

    def get_cppm_spoke_for_scope(self, tenant_id=None):
        """Delegate to the production one-spoke resolver (own, else shared)."""
        return SpokeRegistryMixin.get_cppm_spoke_for_scope(self, tenant_id)

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        data = (self.replies.get(sid) or {}).get(cmd, {"status": "SUCCESS"})
        return {"payload": {"data": data}}


def _passthrough_filter(request, data, module, ip_fields, explicit_tenant=None):
    return data


async def _apassthrough(*a, **k):
    # last positional/keyword arg conventions vary per helper; just return
    # whichever "data"/"record" arg was passed (2nd positional after request).
    return a[1] if len(a) > 1 else None


def _build(sess, hub, filter_tenant=_apassthrough, filter_session=_apassthrough):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _effective_tenant=lambda request, explicit=None: (
            explicit if (sess and sess.get("user", {}).get("is_admin"))
            else (sess or {}).get("user", {}).get("tenant_id")
        ),
        _effective_tenant_slug=lambda request, explicit=None: None,
        _filter_session=filter_session,
        _filter_tenant=filter_tenant,
        _gate_record_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


def _admin():
    return {"user": {"is_admin": True}}


def _tenant_user(tid):
    return {"user": {"is_admin": False, "tenant_id": tid}}


# ── per-tenant spoke resolution ──────────────────────────────────────────────

def test_tenant_user_routes_to_their_own_bound_spoke():
    hub = FakeHub(
        {"cppm-a", "cppm-b"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "A"}},
                "cppm-b": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.status_code == 200
    assert r.json()["server"] == "A"
    assert hub.forwarded[-1][0] == "cppm-a"


def test_tenant_b_never_reaches_tenant_a_spoke():
    """The exact bug this PR fixes: with 2 nac spokes connected, tenant B's
    request must never hit tenant A's ClearPass appliance."""
    hub = FakeHub(
        {"cppm-a", "cppm-b"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "A"}},
                "cppm-b": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantB"), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.json()["server"] == "B"
    assert hub.forwarded[-1][0] == "cppm-b"


def test_tenant_with_no_bound_spoke_gets_503_not_another_tenants_spoke():
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantC"), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.status_code == 503
    assert hub.forwarded == []


def test_nac_instance_record_spoke_wins_over_module_type_fallback():
    """A tenant-admin's self-configured NAC connection (nac_instances,
    via /tenant/devices/nac-instances) pins the exact spoke — checked BEFORE
    the module_type tenant-binding fallback. The route asks the hub's real
    resolver, which reads the records; "cppm-a" sorts first, so the binding
    fallback alone would answer from it."""
    hub = FakeHub(
        {"cppm-a", "cppm-pinned"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "fallback"}},
                "cppm-pinned": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "pinned"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-pinned": {"tenant_id": "tenantA"}},
        nac_instances=[{"id": "rec-p", "tenant_id": "tenantA", "spoke_id": "cppm-pinned",
                        "host": "cp-p"}],
    )
    # The hub sent cppm-pinned that record, so it is not stale.
    hub.state.system_state["nac_config_pushed"] = {"cppm-pinned": "rec-p@cp-p"}
    hub.get_cppm_spoke_for_tenant = MethodType(SpokeRegistryMixin.get_cppm_spoke_for_tenant, hub)
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.json()["server"] == "pinned"
    assert hub.forwarded[-1][0] == "cppm-pinned"


def test_admin_no_tenant_selected_uses_unassigned_global_spoke_for_single_lookups():
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "A"}}},
        global_nac="cppm-a",
    )
    c = _build(_admin(), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.status_code == 200
    assert hub.forwarded[-1][0] == "cppm-a"


# ── admin combined (merge-fanout) view ───────────────────────────────────────

def test_admin_devices_view_combines_every_tenants_spoke_tagged():
    hub = FakeHub(
        {"cppm-a", "cppm-b"},
        replies={
            "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                          "devices": [{"mac": "aa:aa:aa:aa:aa:aa"}]}},
            "cppm-b": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                          "devices": [{"mac": "bb:bb:bb:bb:bb:bb"}]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    devices = r.json()["devices"]
    assert {d["mac"] for d in devices} == {"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}
    tags = {d["mac"]: d["_tenant"] for d in devices}
    assert tags["aa:aa:aa:aa:aa:aa"] == "tenantA"
    assert tags["bb:bb:bb:bb:bb:bb"] == "tenantB"


def test_admin_merge_fanout_survives_one_spoke_erroring():
    hub = FakeHub(
        {"cppm-a", "cppm-down"},
        replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                               "devices": [{"mac": "aa:aa:aa:aa:aa:aa"}]}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-down": {"tenant_id": "tenantB"}},
    )
    async def _boom(sid, cmd, payload=None, timeout=None):
        if sid == "cppm-down":
            raise RuntimeError("spoke unreachable")
        hub.forwarded.append((sid, cmd, payload))
        return {"payload": {"data": hub.replies[sid][cmd]}}
    hub.request_response = _boom

    c = _build(_admin(), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    devices = r.json()["devices"]
    assert [d["mac"] for d in devices] == ["aa:aa:aa:aa:aa:aa"]


def test_admin_devices_view_skips_spoke_still_holding_a_moved_record():
    """tenantA's record moved from cppm-old to cppm-a. cppm-old was sent that
    record and keeps answering from tenantA's ClearPass, which the merge
    would label with cppm-old's own binding (tenantB), so the admin view
    leaves it out until it is sent a config again."""
    hub = FakeHub(
        {"cppm-a", "cppm-old"},
        replies={
            "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                          "devices": [{"mac": "aa:aa:aa:aa:aa:aa"}]}},
            "cppm-old": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                            "devices": [{"mac": "bb:bb:bb:bb:bb:bb"}]}},
        },
        nac_instances=[{"id": "rec-a", "tenant_id": "tenantA", "spoke_id": "cppm-a",
                        "host": "cp-a"}],
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-old": {"tenant_id": "tenantB"}},
    )
    hub.state.system_state["nac_config_pushed"] = {
        "cppm-old": "rec-a@cp-a", "cppm-a": "rec-a@cp-a"}
    c = _build(_admin(), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert [(d["mac"], d["_tenant"]) for d in r.json()["devices"]] == [
        ("aa:aa:aa:aa:aa:aa", "tenantA")]
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a"}


def test_no_nac_spokes_connected_returns_503_for_admin_merge_view():
    hub = FakeHub(set())
    c = _build(_admin(), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 503


def test_tenant_scoped_devices_view_does_not_fan_out():
    """A tenant-scoped caller only talks to spokes in their OWN combined view
    (own + shared, if configured) — never every tenant's spoke like the
    admin merge fanout. No shared instance is configured here, so this
    tenant's view is just their own spoke."""
    hub = FakeHub(
        {"cppm-a", "cppm-b"},
        replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                               "devices": [{"mac": "aa:aa:aa:aa:aa:aa"}]}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a"}


# ── combined view: tenant's own CPPM + shared CPPM merged ───────────────────

def test_tenant_devices_view_combines_own_and_shared_spoke():
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        replies={
            "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                          "devices": [{"mac": "own-1"}]}},
            "cppm-shared": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                               "devices": [{"mac": "shared-1"}]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    macs = {d["mac"] for d in r.json()["devices"]}
    assert macs == {"own-1", "shared-1"}
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a", "cppm-shared"}


def test_tenant_sessions_view_combines_own_and_shared_spoke():
    async def filter_tenant(request, data, module, fields, tenant=None):
        """Apply the production IP-prefix filter for tenantA."""
        return filter_items_by_prefixes(data, ["10.1.0.0/24"], fields)

    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        replies={
            "cppm-a": {"CPPM_GET_ACCESS_TRACKER": {"status": "SUCCESS",
                                                    "window_start": "2026-11-16T00:00:00Z",
                                                    "sessions": [{"mac": "own-1", "ip": "192.0.2.5"}]}},
            "cppm-shared": {"CPPM_GET_ACCESS_TRACKER": {"status": "SUCCESS",
                                                        "window_start": "2026-11-16T00:00:00Z",
                                                        "sessions": [
                                                            {"mac": "shared-in", "ip": "10.1.0.5"},
                                                            {"mac": "shared-out", "ip": "198.51.100.5"},
                                                        ]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    legacy_key = (
        "_all_:tenantA|limit=1000,lookback_hours=24,offset=1000,"
        "snapshot=2,window_end=2026-11-16T00:00:00Z"
    )
    hub.warm_cache.setdefault("cppm_get_access_tracker", {})[legacy_key] = {
        "data": {"sessions": []}, "detail": True, "tenants": ["tenantA"],
        "fetched_at": 1,
    }
    c = _build(_tenant_user("tenantA"), hub, filter_tenant=filter_tenant)
    r = c.get("/api/cppm/sessions")
    assert r.status_code == 200
    macs = {s["mac"] for s in r.json()["sessions"]}
    assert macs == {"own-1", "shared-in"}
    assert r.json()["recent_window_complete"] is True
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a", "cppm-shared"}
    assert all(payload["lookback_hours"] == ACCESS_TRACKER_LOOKBACK_HOURS
               for _, _, payload in hub.forwarded)
    assert NAC_FEED_READS[1][2]["lookback_hours"] == ACCESS_TRACKER_LOOKBACK_HOURS
    feed_jobs = list(hub._cache_feeds["nac"](hub))
    session_jobs = [job for job in feed_jobs if job.ns == "cppm_get_access_tracker"]
    assert len(session_jobs) == 1
    assert (session_jobs[0].ns, session_jobs[0].key) in hub._cache_read_jobs
    access_jobs = [job for (ns, _), job in hub._cache_read_jobs.items()
                   if ns == "cppm_get_access_tracker"]
    assert len(access_jobs) == 1
    assert access_jobs[0].min_interval_s == ACCESS_TRACKER_MIN_INTERVAL_S
    assert session_jobs[0].min_interval_s == ACCESS_TRACKER_MIN_INTERVAL_S
    assert legacy_key not in hub.warm_cache["cppm_get_access_tracker"]
    assert not any(job.key.startswith("_fanout_") for job in session_jobs)
    calls = len(hub.forwarded)
    again = c.get("/api/cppm/sessions")
    assert again.status_code == 200
    assert len(hub.forwarded) == calls


def test_older_cppm_spoke_marks_recent_history_as_unavailable():
    """A pre-update spoke stays active-only and is identified as incomplete."""
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_ACCESS_TRACKER": {
            "status": "SUCCESS", "sessions": [{"mac": "active-only"}],
        }}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantA"), hub)

    r = c.get("/api/cppm/sessions")

    assert r.status_code == 200
    assert r.json()["recent_window_complete"] is False


def test_partial_access_tracker_failure_is_not_reported_as_an_old_spoke():
    """A failed shared source warns and marks the returned count as a lower bound."""
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"

    async def request_response(sid, cmd, payload=None, timeout=None):
        """Return one tenant source and simulate an offline shared source."""
        hub.forwarded.append((sid, cmd, payload))
        if sid == "cppm-shared":
            raise RuntimeError("shared CPPM unavailable")
        return {"payload": {"data": {
            "status": "SUCCESS",
            "window_start": "2026-11-16T00:00:00Z",
            "sessions": [{"mac": "own-1", "ip": "10.1.0.5"}],
            "total": 1,
        }}}

    hub.request_response = request_response
    c = _build(_tenant_user("tenantA"), hub)

    response = c.get("/api/cppm/sessions")

    assert response.status_code == 200
    assert [row["mac"] for row in response.json()["sessions"]] == ["own-1"]
    assert response.json()["source_error"] is True
    assert response.json()["recent_window_complete"] is False
    assert response.json()["total_is_lower_bound"] is True


def test_unscoped_access_tracker_requires_tenant_selection():
    """Authentication identities are never returned without tenant context."""
    hub = FakeHub(
        {"cppm-global"},
        global_nac="cppm-global",
    )
    c = _build(_tenant_user(None), hub)
    response = c.get("/api/cppm/sessions")
    assert response.status_code == 400
    assert response.json()["detail"] == "Select a tenant to view Access Tracker."


def test_cppm_refresh_invalidates_tenant_access_tracker_snapshots():
    """A spoke refresh requests refresh of only its tenant's history key."""
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_REFRESH_CACHE": {"status": "SUCCESS"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    refreshed = []
    hub.cache_refresh = lambda ns, keys, exact=False: refreshed.append(
        (ns, keys, exact))
    c = _build(_tenant_user("tenantA"), hub)

    response = c.get("/cppm/refresh?tenant=tenantA")

    assert response.status_code == 200
    history_refresh = next(call for call in refreshed
                           if call[0] == "cppm_get_access_tracker")
    assert history_refresh[1][0].startswith("_all_:tenantA|")
    assert history_refresh[2] is True


def test_admin_selected_tenant_is_used_for_access_tracker_filtering():
    """An admin's explicit tenant selection is passed to the history filter."""
    filtered = []

    async def filter_tenant(request, data, module, fields, tenant=None):
        """Record the effective tenant passed to the production filter."""
        filtered.append(tenant)
        return data

    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_ACCESS_TRACKER": {
            "status": "SUCCESS",
            "window_start": "2026-11-16T00:00:00Z",
            "sessions": [{"mac": "tenantA-session", "ip": "10.1.0.5"}],
        }}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_admin(), hub,
               filter_tenant=filter_tenant)

    response = c.get("/api/cppm/sessions?tenant=tenantA")

    assert response.status_code == 200
    assert [row["mac"] for row in response.json()["sessions"]] == ["tenantA-session"]
    assert filtered == ["tenantA"]


def test_access_tracker_sort_does_not_mutate_cached_sessions():
    """Sorting a response leaves the shared cache's source order unchanged."""
    sessions = [
        {"mac": "older", "ip": "10.1.0.5", "start_time": "2026-11-16T00:00:00Z"},
        {"mac": "newer", "ip": "10.1.0.6", "start_time": "2026-11-17T00:00:00Z"},
    ]
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_ACCESS_TRACKER": {
            "status": "SUCCESS",
            "window_start": "2026-11-16T00:00:00Z",
            "sessions": sessions,
            "total": len(sessions),
        }}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantA"), hub)

    response = c.get("/api/cppm/sessions?tenant=tenantA")

    assert response.status_code == 200
    assert [row["mac"] for row in response.json()["sessions"]] == ["newer", "older"]
    cached_sessions = next(iter(hub.warm_cache["cppm_get_access_tracker"].values()))[
        "data"]["sessions"]
    assert [row["mac"] for row in cached_sessions] == ["older", "newer"]


def test_tenant_access_tracker_reads_later_shared_pages_before_filtering():
    """A tenant's rows beyond the shared source's first page are still returned."""
    async def filter_tenant(request, data, module, fields, tenant=None):
        """Apply the production prefix filter used for shared CPPM rows."""
        return filter_items_by_prefixes(data, ["10.1.0.0/24"], fields)

    other_sessions = [{"mac": f"other-{index}", "ip": "198.51.100.5"}
                      for index in range(ACCESS_TRACKER_FETCH_PAGE_SIZE)]
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"

    async def page_response(sid, cmd, payload=None, timeout=None):
        """Return a full first page and a tenant match on the following page."""
        hub.forwarded.append((sid, cmd, payload))
        if sid == "cppm-a":
            sessions, total = [], 0
        elif payload["offset"] == 0:
            sessions, total = other_sessions, ACCESS_TRACKER_FETCH_PAGE_SIZE + 1
        else:
            sessions, total = [{"mac": "tenant-a", "ip": "10.1.0.5"}], 1001
        return {"payload": {"data": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": sessions, "total": total,
        }}}

    hub.request_response = page_response
    c = _build(_tenant_user("tenantA"), hub, filter_tenant=filter_tenant)

    response = c.get("/api/cppm/sessions")

    assert response.status_code == 200
    assert [row["mac"] for row in response.json()["sessions"]] == ["tenant-a"]
    assert response.json()["recent_window_complete"] is True
    shared_offsets = [payload["offset"] for sid, _, payload in hub.forwarded
                      if sid == "cppm-shared"]
    assert shared_offsets == [0, ACCESS_TRACKER_FETCH_PAGE_SIZE]
    snapshot_ends = {payload["window_end"] for _, _, payload in hub.forwarded}
    assert len(snapshot_ends) == 1


def test_access_tracker_scans_later_source_pages_before_slicing_newest_rows():
    """A full first source page cannot hide newer tenant rows from later pages."""
    async def filter_tenant(request, data, module, fields, tenant=None):
        """Apply the production prefix filter used for shared CPPM rows."""
        return filter_items_by_prefixes(data, ["10.1.0.0/24"], fields)

    own_sessions = [
        {"mac": f"own-{index}", "ip": "10.1.0.5",
         "start_time": "2026-11-16T00:00:00Z"}
        for index in range(ACCESS_TRACKER_FETCH_PAGE_SIZE)
    ]
    other_sessions = [{"mac": f"shared-other-{index}", "ip": "198.51.100.5"}
                      for index in range(ACCESS_TRACKER_FETCH_PAGE_SIZE)]
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"

    async def page_response(sid, cmd, payload=None, timeout=None):
        """Return enough own rows to fill page one and a newer shared row later."""
        hub.forwarded.append((sid, cmd, payload))
        if payload["offset"] == 0:
            sessions = own_sessions if sid == "cppm-a" else other_sessions
            total = ACCESS_TRACKER_FETCH_PAGE_SIZE + 1
        elif sid == "cppm-shared":
            sessions, total = [{
                "mac": "newer-shared", "ip": "10.1.0.6",
                "start_time": "2026-11-17T00:00:00Z",
            }], ACCESS_TRACKER_FETCH_PAGE_SIZE + 1
        else:
            sessions, total = [{
                "mac": "older-own-last", "ip": "10.1.0.5",
                "start_time": "2026-11-15T00:00:00Z",
            }], ACCESS_TRACKER_FETCH_PAGE_SIZE + 1
        return {"payload": {"data": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": sessions, "total": total,
        }}}

    hub.request_response = page_response
    c = _build(_tenant_user("tenantA"), hub, filter_tenant=filter_tenant)

    response = c.get("/api/cppm/sessions?limit=200")

    assert response.status_code == 200
    assert response.json()["sessions"][0]["mac"] == "newer-shared"
    shared_offsets = [payload["offset"] for sid, _, payload in hub.forwarded
                      if sid == "cppm-shared"]
    assert shared_offsets == [0, ACCESS_TRACKER_FETCH_PAGE_SIZE]


def test_tenant_access_tracker_stops_at_the_page_safety_cap():
    """A very busy shared source is bounded and explicitly marked as truncated."""
    async def filter_tenant(request, data, module, fields, tenant=None):
        """Exclude all shared records so the route must continue scanning."""
        return filter_items_by_prefixes(data, ["10.1.0.0/24"], fields)

    other_sessions = [{"mac": f"other-{index}", "ip": "198.51.100.5"}
                      for index in range(ACCESS_TRACKER_FETCH_PAGE_SIZE)]
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"

    async def page_response(sid, cmd, payload=None, timeout=None):
        """Keep reporting more shared sessions until the hub's fixed cap."""
        hub.forwarded.append((sid, cmd, payload))
        if sid == "cppm-a":
            sessions, total = [], 0
        else:
            sessions, total = other_sessions, ACCESS_TRACKER_FETCH_PAGE_SIZE * 20
        return {"payload": {"data": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": sessions, "total": total,
        }}}

    hub.request_response = page_response
    c = _build(_tenant_user("tenantA"), hub, filter_tenant=filter_tenant)

    response = c.get("/api/cppm/sessions")

    assert response.status_code == 200
    assert response.json()["sessions"] == []
    assert response.json()["recent_window_truncated"] is True
    assert response.json()["total_is_lower_bound"] is True
    shared_offsets = [payload["offset"] for sid, _, payload in hub.forwarded
                      if sid == "cppm-shared"]
    assert shared_offsets == [
        page * ACCESS_TRACKER_FETCH_PAGE_SIZE for page in range(ACCESS_TRACKER_MAX_PAGES)
    ]
    snapshot_ends = {payload["window_end"] for _, _, payload in hub.forwarded}
    assert len(snapshot_ends) == 1


def test_unselected_admin_must_switch_tenant_before_access_tracker():
    """The all-tenant admin fan-out must not expose authentication identities."""
    hub = FakeHub({"cppm-a"})
    c = _build(_admin(), hub)

    r = c.get("/api/cppm/sessions")

    assert r.status_code == 400
    assert "Select a tenant" in r.json()["detail"]
    assert hub.forwarded == []


def test_admin_can_view_access_tracker_after_switching_into_tenant():
    """Tenant switching routes the admin to that tenant's ClearPass source."""
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_ACCESS_TRACKER": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": [{"mac": "tenant-a"}],
        }}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_admin(), hub)

    r = c.get("/api/cppm/sessions?tenant=tenantA")

    assert r.status_code == 200
    assert [s["mac"] for s in r.json()["sessions"]] == ["tenant-a"]
    assert [sid for sid, _, _ in hub.forwarded] == ["cppm-a"]


def test_tenant_devices_view_survives_shared_spoke_erroring():
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                               "devices": [{"mac": "own-1"}]}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"

    async def _boom(sid, cmd, payload=None, timeout=None):
        if sid == "cppm-shared":
            raise RuntimeError("shared clearpass unreachable")
        hub.forwarded.append((sid, cmd, payload))
        return {"payload": {"data": hub.replies[sid][cmd]}}
    hub.request_response = _boom

    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert [d["mac"] for d in r.json()["devices"]] == ["own-1"]


def test_shared_tenant_itself_does_not_double_query_its_own_spoke():
    """The shared tenant's OWN users must not see their spoke queried twice —
    own == shared for them, so the combined list dedupes to one entry."""
    hub = FakeHub(
        {"cppm-shared"},
        replies={"cppm-shared": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                                     "devices": [{"mac": "shared-1"}]}}},
        module_metadata={"cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    c = _build(_tenant_user("shared-tenant"), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert [d["mac"] for d in r.json()["devices"]] == ["shared-1"]
    assert len(hub.forwarded) == 1


# ── a tenant that only uses the shared ClearPass ─────────────────────────────

def _shared_only_hub(replies):
    """tenantA has no ClearPass of its own; cppm-shared is the shared one."""
    hub = FakeHub({"cppm-shared"}, replies={"cppm-shared": replies},
                  module_metadata={"cppm-shared": {"tenant_id": "shared-tenant"}})
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    return hub


def test_shared_only_tenant_reads_its_rows_from_the_shared_spoke():
    """A device's sessions and the ClearPass logs are rows the route
    subnet-filters, so a tenant on the shared ClearPass reads them there (it
    got a 503 before), narrowed to its own prefixes as the Access Tracker is."""
    seen = []

    async def filter_tenant(request, data, module, fields, tenant=None, spoke_id=None):
        """Record the source spoke and apply tenantA's prefix filter."""
        seen.append(spoke_id)
        return filter_items_by_prefixes(data, ["10.1.0.0/24"], fields)

    rows = [{"mac": "aa", "ip": "10.1.0.5"}, {"mac": "bb", "ip": "198.51.100.5"}]
    hub = _shared_only_hub({"GET_DEVICE_SESSIONS": rows, "GET_LOGS": rows})
    c = _build(_tenant_user("tenantA"), hub, filter_tenant=filter_tenant)
    sessions = c.get("/api/cppm/device-sessions", params={"mac": "aa"})
    logs = c.get("/api/cppm/logs", params={"start": "s", "end": "e"})
    assert sessions.status_code == logs.status_code == 200
    assert sessions.json() == logs.json() == [rows[0]]
    assert [(sid, cmd) for sid, cmd, _ in hub.forwarded] == [
        ("cppm-shared", "GET_DEVICE_SESSIONS"), ("cppm-shared", "GET_LOGS")]
    assert seen == ["cppm-shared", "cppm-shared"]


def test_appliance_wide_reads_refuse_a_shared_only_tenant():
    """The NAC totals and the role list cover every tenant on the appliance
    and have no rows to filter, so a tenant on the shared ClearPass gets a
    403 that says why (not "no spoke"), and nothing is sent to the spoke."""
    hub = _shared_only_hub({"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "active_sessions": 9},
                            "LIST_ROLES": {"status": "SUCCESS", "roles": []}})
    c = _build(_tenant_user("tenantA"), hub)
    for path in ("/api/cppm/nac-status", "/api/cppm/roles"):
        r = c.get(path)
        assert r.status_code == 403, path
        assert "shared ClearPass" in r.json()["detail"]
    assert hub.forwarded == []


# ── hub data cache ───────────────────────────────────────────────────────────

def _own_and_shared_hub():
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        replies={
            "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                          "devices": [{"mac": "own-1"}]}},
            "cppm-shared": {"LIST_ENDPOINTS": {"status": "SUCCESS",
                                               "devices": [{"mac": "shared-1"}]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    return hub


def test_tenant_merge_skips_a_spoke_with_no_clearpass_configured():
    # The hub knows cppm-shared has no ClearPass configured: it is not queried
    # and the tenant still gets its own CPPM's data.
    hub = _own_and_shared_hub()
    hub._nac_unconfigured_spokes = {"cppm-shared"}
    r = _build(_tenant_user("tenantA"), hub).get("/api/cppm/devices")
    assert r.status_code == 200
    assert {d["mac"] for d in r.json()["devices"]} == {"own-1"}
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a"}


def test_tenant_merge_with_every_spoke_unconfigured_is_503():
    hub = _own_and_shared_hub()
    hub._nac_unconfigured_spokes = {"cppm-a", "cppm-shared"}
    r = _build(_tenant_user("tenantA"), hub).get("/api/cppm/devices")
    assert r.status_code == 503
    assert hub.forwarded == []


def test_second_read_is_served_from_cache_without_a_spoke_call():
    hub = _own_and_shared_hub()
    c = _build(_tenant_user("tenantA"), hub)
    first = c.get("/api/cppm/devices").json()
    calls = len(hub.forwarded)
    second = c.get("/api/cppm/devices").json()
    assert len(hub.forwarded) == calls          # no new spoke round-trip
    assert second["devices"] == first["devices"]
    assert second.get("cached_at")              # cache badge info


def test_spoke_down_after_first_read_still_serves_last_known_data():
    hub = _own_and_shared_hub()
    c = _build(_tenant_user("tenantA"), hub)
    assert c.get("/api/cppm/devices").status_code == 200
    hub.active_connections.clear()
    hub._nac_spokes.clear()
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert {d["mac"] for d in r.json()["devices"]} == {"own-1", "shared-1"}


def test_tenants_never_share_a_cache_entry():
    hub = FakeHub(
        {"cppm-a", "cppm-b"},
        replies={
            "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": "a-1"}]}},
            "cppm-b": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": "b-1"}]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-b": {"tenant_id": "tenantB"}},
    )
    ra = _build(_tenant_user("tenantA"), hub).get("/api/cppm/devices").json()
    rb = _build(_tenant_user("tenantB"), hub).get("/api/cppm/devices").json()
    assert {d["mac"] for d in ra["devices"]} == {"a-1"}
    assert {d["mac"] for d in rb["devices"]} == {"b-1"}
    fp = cppm_routes.nac_cache_fingerprint(hub)
    entries = hub.warm_cache["list_endpoints"]
    assert entries[f"_all_:tenantA|src={fp}"]["tenants"] == ["tenantA"]
    assert entries[f"_all_:tenantB|src={fp}"]["tenants"] == ["tenantB"]


def _swap_spoke_tenants(hub):
    """Bind cppm-a to tenantB and cppm-b to tenantA in the saved state,
    without the cache drop the routes run after such a change."""
    meta = hub.state.system_state["module_metadata"]
    meta["cppm-a"]["tenant_id"], meta["cppm-b"]["tenant_id"] = "tenantB", "tenantA"


def _two_tenant_nac_hub(**kwargs):
    """cppm-a serves tenantA and cppm-b tenantB, both saved as NAC spokes."""
    return FakeHub({"cppm-a", "cppm-b"},
                   module_metadata={"cppm-a": {"tenant_id": "tenantA", "module_type": "nac"},
                                    "cppm-b": {"tenant_id": "tenantB", "module_type": "nac"}},
                   **kwargs)


def test_data_cached_before_an_ownership_change_is_not_served_after_it():
    """The keys carry the ownership fingerprint, so a cached read is never
    served after an ownership change, even when the drop that should follow
    the change was lost (the hub crashed or restarted first)."""
    hub = _two_tenant_nac_hub(replies={
        "cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": "a-1"}]}},
        "cppm-b": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": "b-1"}]}},
    })
    c = _build(_tenant_user("tenantA"), hub)
    assert [d["mac"] for d in c.get("/api/cppm/devices").json()["devices"]] == ["a-1"]

    _swap_spoke_tenants(hub)
    r = c.get("/api/cppm/devices")

    assert [d["mac"] for d in r.json()["devices"]] == ["b-1"]
    assert hub.forwarded[-1][:2] == ("cppm-b", "LIST_ENDPOINTS")


def _fingerprint_hub():
    """tenantA's NAC record on cppm-a, a NAC spoke bound to tenantA, plus a
    non-NAC spoke bound to tenantA."""
    return FakeHub(
        {"cppm-a"},
        nac_instances=[{"id": "rec-a", "tenant_id": "tenantA", "spoke_id": "cppm-a",
                        "host": "cp-a"}],
        module_metadata={"cppm-a": {"tenant_id": "tenantA", "module_type": "nac"},
                         "nw-1": {"tenant_id": "tenantA", "module_type": "nw"}},
    )


def test_nac_cache_fingerprint_follows_only_who_reads_which_clearpass():
    """The fingerprint changes with what decides which ClearPass answers for
    whom, and not with what leaves that alone: moving a record to another
    spoke keeps its cache warm (instance_relocate), and connection state
    is left out so the cache stays warm across a restart."""
    def record(hub):
        """The fixture's one NAC record."""
        return hub.state.get_global_config()["nac_instances"][0]

    def tenants(hub):
        """The saved tenant records."""
        return hub.state.tenant_state["tenants"]

    def meta(hub, sid):
        """The saved metadata of spoke ``sid``."""
        return hub.state.system_state["module_metadata"][sid]

    changes = {
        "record tenant": lambda h: record(h).update(tenant_id="tenantB"),
        "record host": lambda h: record(h).update(host="cp-b"),
        "NAC spoke binding": lambda h: meta(h, "cppm-a").update(tenant_id="tenantB"),
        "new shared tenant": lambda h: tenants(h).update(tenantS={"shared": True}),
        "shared-access mode": lambda h: tenants(h)["tenantA"].update(shared_access="deny"),
    }
    same = {
        "record spoke": lambda h: record(h).update(spoke_id="cppm-b"),
        "record id": lambda h: record(h).update(id="rec-z"),
        "new plain tenant": lambda h: tenants(h).update(tenantZ={}),
        "non-NAC spoke binding": lambda h: meta(h, "nw-1").update(tenant_id="tenantB"),
        "connections": lambda h: h.active_connections.clear(),
    }
    for name, change in {**changes, **same}.items():
        hub = _fingerprint_hub()
        before = cppm_routes.nac_cache_fingerprint(hub)
        change(hub)
        assert (cppm_routes.nac_cache_fingerprint(hub) != before) == (name in changes), name

    # With no NAC record, the legacy single ClearPass's host counts.
    hub = FakeHub({"cppm-a"})
    hub.state.get_global_config()["cppm"] = {"host": "cp-1"}
    before = cppm_routes.nac_cache_fingerprint(hub)
    hub.state.get_global_config()["cppm"]["host"] = "cp-2"
    assert cppm_routes.nac_cache_fingerprint(hub) != before


def test_nac_status_is_read_again_when_its_spoke_gets_another_clearpass():
    """Two of tenantA's records swap spokes. Each keeps its tenant and host,
    so the fingerprint stays the same, but cppm-a now holds the other
    ClearPass: its cached totals must not be served."""
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "cp-1"}}},
        nac_instances=[
            {"id": "rec-1", "tenant_id": "tenantA", "spoke_id": "cppm-a", "host": "cp-1"},
            {"id": "rec-2", "tenant_id": "tenantA", "spoke_id": "cppm-b", "host": "cp-2"}],
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": "rec-1@cp-1"}
    c = _build(_tenant_user("tenantA"), hub)
    assert c.get("/api/cppm/nac-status").json()["server"] == "cp-1"
    fp = cppm_routes.nac_cache_fingerprint(hub)

    # Swap the records' spokes; the push then confirms cppm-a holds cp-2.
    first, second = hub.state.get_global_config()["nac_instances"]
    first["spoke_id"], second["spoke_id"] = "cppm-b", "cppm-a"
    hub.state.system_state["nac_config_pushed"] = {"cppm-a": "rec-2@cp-2"}
    hub.replies["cppm-a"]["CPPM_GET_NAC_STATUS"] = {"status": "SUCCESS", "server": "cp-2"}
    r = c.get("/api/cppm/nac-status")

    assert cppm_routes.nac_cache_fingerprint(hub) == fp
    assert r.json()["server"] == "cp-2"
    assert len(hub.forwarded) == 2


def test_a_nac_fetch_keyed_under_other_settings_is_refused():
    """A feed job made under one fingerprint refuses to fetch once the
    settings change. Otherwise tenantA's key would be filled from tenantA's
    new spoke, and if the change were reverted, tenantA would be served the
    data of a ClearPass that is then tenantB's."""
    hub = _two_tenant_nac_hub()
    _build(_tenant_user("tenantA"), hub)
    job = next(j for j in hub._cache_feeds["nac"](hub)
               if j.ns == "list_endpoints" and j.key.startswith("_all_:tenantA|"))

    _swap_spoke_tenants(hub)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(job.fetch())

    assert refused.value.status_code == 503
    assert hub.forwarded == []


def test_an_access_tracker_scan_stops_when_nac_settings_change_between_pages():
    """The check runs before every page, so one history scan never merges
    pages read under two different settings: tenantA's spoke moves to
    tenantB after page one, page two is never asked for, and nothing is
    cached."""
    hub = _two_tenant_nac_hub()

    async def page_response(sid, cmd, payload=None, timeout=None):
        """Answer one page with more to come, then swap the spokes' tenants."""
        hub.forwarded.append((sid, cmd, payload))
        _swap_spoke_tenants(hub)
        return {"payload": {"data": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": [{"mac": f"{sid}-1"}], "total": ACCESS_TRACKER_FETCH_PAGE_SIZE * 2}}}

    hub.request_response = page_response
    r = _build(_tenant_user("tenantA"), hub).get("/api/cppm/sessions")

    assert r.status_code == 503
    assert [(sid, payload["offset"]) for sid, _, payload in hub.forwarded] == [("cppm-a", 0)]
    assert not hub.warm_cache.get("cppm_get_access_tracker")


def test_admin_fanout_labels_rows_with_the_owner_of_the_clearpass(monkeypatch):
    """The admin view labels each spoke's rows with the tenant whose
    ClearPass the spoke serves, not with the spoke's own binding: tenantA's
    record on a spoke bound to tenantB is tenantA's, a shared record is the
    shared tenant's, and a spoke holding two tenants' records gets none."""
    monkeypatch.setattr(cppm_routes.access, "_SHARED_TENANT_ID", "shared-tenant")
    spokes = ("cppm-b", "cppm-s", "cppm-x")
    hub = FakeHub(
        set(spokes),
        replies={sid: {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": sid}]}}
                 for sid in spokes},
        nac_instances=[
            {"id": "rec-a", "tenant_id": "tenantA", "spoke_id": "cppm-b", "host": "cp-a"},
            {"id": "rec-s", "tenant_id": "shared-tenant", "spoke_id": "cppm-s", "host": "cp-s"},
            {"id": "rec-c", "tenant_id": "tenantC", "spoke_id": "cppm-x", "host": "cp-c"},
            {"id": "rec-d", "tenant_id": "tenantD", "spoke_id": "cppm-x", "host": "cp-d"}],
        module_metadata={"cppm-b": {"tenant_id": "tenantB"},
                         "cppm-x": {"tenant_id": "tenantC"}},
    )
    hub.state.system_state["nac_config_pushed"] = {
        "cppm-b": "rec-a@cp-a", "cppm-s": "rec-s@cp-s", "cppm-x": "rec-c@cp-c"}

    r = _build(_admin(), hub).get("/api/cppm/devices")

    assert r.status_code == 200
    assert {d["mac"]: d["_tenant"] for d in r.json()["devices"]} == {
        "cppm-b": "tenantA", "cppm-s": "shared-tenant", "cppm-x": ""}


def test_nac_status_second_read_served_from_cache():
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "active_sessions": 7}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    assert c.get("/api/cppm/nac-status").json()["active_sessions"] == 7
    second = c.get("/api/cppm/nac-status").json()
    assert len(hub.forwarded) == 1               # no new spoke round-trip
    assert second["active_sessions"] == 7
    assert second.get("cached_at")


def test_a_nac_ownership_change_drops_every_cached_nac_read():
    """drop_nac_caches covers every namespace the NAC routes cache under
    (device list, Access Tracker, status, role list) and lifts the Access
    Tracker floor, so after an ownership change the next page view asks the
    spoke now answering for the tenant instead of serving the old snapshot."""
    hub = FakeHub(
        {"cppm-a", "cppm-g"},
        replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": [{"mac": "a-1"}]},
                            "CPPM_GET_ACCESS_TRACKER": {"status": "SUCCESS", "sessions": []}},
                 "cppm-g": {"LIST_ROLES": {"status": "SUCCESS", "roles": []}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    for path in ("/api/cppm/devices", "/api/cppm/sessions", "/api/cppm/nac-status",
                 "/api/cppm/role-overrides"):
        assert c.get(path).status_code == 200, path
    assert {ns for ns, entries in hub.warm_cache.items() if entries} == set(
        cppm_routes.NAC_CACHE_NAMESPACES)
    calls = len(hub.forwarded)
    assert c.get("/api/cppm/sessions").status_code == 200
    assert len(hub.forwarded) == calls
    assert cppm_routes.drop_nac_caches(hub) == 4
    assert not any(hub.warm_cache.get(ns) for ns in cppm_routes.NAC_CACHE_NAMESPACES)
    assert c.get("/api/cppm/sessions").status_code == 200
    assert hub.forwarded[calls][:2] == ("cppm-a", "CPPM_GET_ACCESS_TRACKER")


# ── role-override list (one global SSPLM- list, cached) ──────────────────────

def test_role_overrides_lists_prefixed_roles_from_global_spoke():
    hub = FakeHub({"cppm-g"}, global_nac="cppm-g", replies={"cppm-g": {"LIST_ROLES": {
        "status": "SUCCESS",
        "roles": [{"name": "SSPLM-ROUTED"}, {"name": "[Guest]"}, {"name": "SSPLM-DMZ"}]}}})
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/role-overrides")
    assert r.status_code == 200
    # Older spokes ignore the prefix, so the hub filters too.
    assert r.json()["roles"] == ["SSPLM-DMZ", "SSPLM-ROUTED"]
    assert hub.forwarded[-1] == ("cppm-g", "LIST_ROLES", {"prefix": "SSPLM-"})
    # Second read is served from the cache.
    c.get("/api/cppm/role-overrides")
    assert len(hub.forwarded) == 1


def test_role_overrides_never_selects_another_tenants_spoke(monkeypatch):
    """A tenant-specific NAC spoke cannot become the global role-list source."""
    monkeypatch.setattr(cppm_routes.access, "shared_tenant_id", lambda: None)
    hub = FakeHub(
        {"cppm-tenant", "cppm-global"},
        global_nac="cppm-tenant",
        module_metadata={"cppm-tenant": {"tenant_id": "tenantB"}},
        replies={
            "cppm-tenant": {"LIST_ROLES": {"status": "SUCCESS",
                                           "roles": [{"name": "SSPLM-WRONG"}]}},
            "cppm-global": {"LIST_ROLES": {"status": "SUCCESS",
                                           "roles": [{"name": "SSPLM-GLOBAL"}]}},
        },
    )
    client = _build(_tenant_user("tenantA"), hub)

    response = client.get("/api/cppm/role-overrides")

    assert response.status_code == 200
    assert response.json()["roles"] == ["SSPLM-GLOBAL"]
    assert hub.forwarded == [("cppm-global", "LIST_ROLES", {"prefix": "SSPLM-"})]


def test_role_overrides_503_when_only_tenant_bound_nac_spokes_exist(monkeypatch):
    """A tenant-bound source is not a fallback for the global role list."""
    monkeypatch.setattr(cppm_routes.access, "shared_tenant_id", lambda: None)
    hub = FakeHub({"cppm-tenant"}, module_metadata={"cppm-tenant": {"tenant_id": "tenantB"}})
    client = _build(_tenant_user("tenantA"), hub)

    response = client.get("/api/cppm/role-overrides")

    assert response.status_code == 503
    assert hub.forwarded == []


def test_role_overrides_503_without_nac_spoke():
    c = _build(_admin(), FakeHub(set()))
    assert c.get("/api/cppm/role-overrides").status_code == 503


def test_tenant_devices_filtered_by_netbox_tenant_id(monkeypatch):
    # Ownership is the NetBox_Tenant_ID attribute; slug attributes are ignored.
    import routes.cppm as cppm_routes
    monkeypatch.setattr(cppm_routes, "get_tenant_scoping",
                        lambda hub, tid: {"netbox_tenant_slug": "a-slug"})
    devices = [
        {"mac": "aa:aa:aa:aa:aa:aa", "attributes": {"NetBox_Tenant_ID": "tenantA"}},
        {"mac": "bb:bb:bb:bb:bb:bb", "attributes": {"NetBox_Tenant_ID": "tenantB"}},
        {"mac": "cc:cc:cc:cc:cc:cc", "attributes": {"NetBox_Tenant_Slug": "tenantA"}},
    ]
    hub = FakeHub({"cppm-a"},
                  replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": devices}}},
                  module_metadata={"cppm-a": {"tenant_id": "tenantA"}})
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/devices")
    assert r.status_code == 200
    assert [d["mac"] for d in r.json()["devices"]] == ["aa:aa:aa:aa:aa:aa"]

    r = c.get("/api/cppm/unknown-devices")
    assert [d["mac"] for d in r.json()["devices"]] == ["cc:cc:cc:cc:cc:cc"]


def test_feed_drops_nac_cache_keys_no_current_read_uses():
    """Every feed pass, the first one at startup included, drops the NAC
    cache keys no current read uses: earlier Access Tracker shapes (admin
    fan-out, global scope, per-page, older-snapshot keys), the keys from
    before the ownership fingerprint, keys made under another fingerprint,
    and a failure floor left with no entry. Each current key stays, though
    every one starts with an older key."""
    hub = FakeHub({"cppm-a"}, module_metadata={"cppm-a": {"tenant_id": "tenantA"}})
    _build(_tenant_user("tenantA"), hub)
    fp = cppm_routes.nac_cache_fingerprint(hub)
    tracker = "_all_:tenantA|limit=1000,lookback_hours=24,offset=0,snapshot=3"
    current = {
        "cppm_get_access_tracker": [f"{tracker},src={fp}"],
        "list_endpoints": [f"_fanout_|src={fp}", f"_all_:tenantA|src={fp}"],
        "cppm_get_nac_status": [f"cppm-a||src={fp}"],
        "nac_role_overrides": [f"_|src={fp}"],
    }
    orphans = {
        "cppm_get_access_tracker": [
            "_fanout_|limit=200,offset=0",
            "_all_:tenantA|limit=200,offset=0",
            "_all_:_global_|limit=200,offset=0",
            "_all_:tenantA|limit=1000,lookback_hours=24,offset=0",
            "_all_:tenantA|limit=1000,lookback_hours=24,offset=0,snapshot=2,"
            "window_end=2026-11-16T00:00:00Z",
            f"_all_:_global_|limit=1000,lookback_hours=24,offset=0,snapshot=3,src={fp}",
            tracker,
            f"{tracker},src=0123456789ab"],
        "list_endpoints": ["_fanout_", "_all_:tenantA", "_all_:tenantA|src=0123456789ab"],
        "cppm_get_nac_status": ["cppm-a", "cppm-a||src=0123456789ab"],
        "nac_role_overrides": ["_", "_|src=0123456789ab"],
    }
    for ns in current:
        hub.warm_cache[ns] = {key: {"data": {}, "fetched_at": 1}
                              for key in current[ns] + orphans[ns]}
    floor = ("cppm_get_access_tracker", "_all_:tenantB|src=0123456789ab")
    hub._cache_failed[floor] = (1.0, "ClearPass unreachable", ("tenantB",))

    feed = list(hub._cache_feeds["nac"](hub))

    assert {ns: sorted(hub.warm_cache[ns]) for ns in current} == {
        ns: sorted(keys) for ns, keys in current.items()}
    assert floor not in hub._cache_failed
    assert sorted(job.key for job in feed) == sorted(
        current["cppm_get_access_tracker"] + current["list_endpoints"]
        + current["nac_role_overrides"])


def test_failed_access_tracker_query_is_not_retried_inside_the_floor():
    """After the first 24-hour query fails, another page view inside the
    floor sends ClearPass nothing and answers 503 with Retry-After."""
    hub = FakeHub({"cppm-a"}, module_metadata={"cppm-a": {"tenant_id": "tenantA"}})

    async def request_response(sid, cmd, payload=None, timeout=None):
        """Simulate a ClearPass that does not answer the tenant's spoke."""
        hub.forwarded.append((sid, cmd, payload))
        raise RuntimeError("ClearPass unreachable")

    hub.request_response = request_response
    c = _build(_tenant_user("tenantA"), hub)

    first = c.get("/api/cppm/sessions")
    calls = len(hub.forwarded)
    second = c.get("/api/cppm/sessions")

    assert first.status_code == 503 and calls == 1
    assert second.status_code == 503 and len(hub.forwarded) == calls
    assert 0 < int(second.headers["Retry-After"]) <= ACCESS_TRACKER_MIN_INTERVAL_S
    assert "No spoke connected" in second.json()["detail"]


def test_access_tracker_hides_shared_rows_a_nested_tenant_owns():
    """Tenant a's 10.0.0.0/8 holds tenant b's 10.1.0.0/16 on the shared
    ClearPass: each sees only the authentications it owns most specifically."""
    from access import filter_tenant as production_filter
    from test_subnet_filter import _admin_session, _FakeRequest, _nested_hub

    prefix_hub = _nested_hub()

    async def filter_tenant(request, data, module, fields, tenant=None):
        """Run the production tenant filter, as api.py's shim does."""
        return await production_filter(prefix_hub, {"x": _admin_session()}, _FakeRequest("x"),
                                       data, module, fields, explicit_tenant=tenant)

    hub = FakeHub(
        {"cppm-shared"},
        replies={"cppm-shared": {"CPPM_GET_ACCESS_TRACKER": {
            "status": "SUCCESS", "window_start": "2026-11-16T00:00:00Z",
            "sessions": [{"mac": "b-host", "ip": "10.1.0.5"},
                         {"mac": "a-host", "ip": "10.2.0.5"}]}}},
        module_metadata={"cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    c = _build(_admin(), hub, filter_tenant=filter_tenant)

    for tenant, want in (("a", ["a-host"]), ("b", ["b-host"])):
        r = c.get(f"/api/cppm/sessions?tenant={tenant}")
        assert r.status_code == 200
        assert [s["mac"] for s in r.json()["sessions"]] == want
def test_tenant_devices_tag_matches_in_any_case(monkeypatch):
    # Tenant ids are not case-sensitive: a device tagged "TENANTA" is tenantA's,
    # as the spoke binding is matched; another tenant's tag is still dropped.
    import routes.cppm as cppm_routes
    monkeypatch.setattr(cppm_routes, "get_tenant_scoping",
                        lambda hub, tid: {"netbox_tenant_slug": "a-slug"})
    devices = [
        {"mac": "aa:aa:aa:aa:aa:aa", "attributes": {"NetBox_Tenant_ID": "TENANTA"}},
        {"mac": "bb:bb:bb:bb:bb:bb", "attributes": {"NetBox_Tenant_ID": "tenantB"}},
    ]
    hub = FakeHub({"cppm-a"},
                  replies={"cppm-a": {"LIST_ENDPOINTS": {"status": "SUCCESS", "devices": devices}}},
                  module_metadata={"cppm-a": {"tenant_id": "tenantA"}})
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/devices")
    assert [d["mac"] for d in r.json()["devices"]] == ["aa:aa:aa:aa:aa:aa"]
