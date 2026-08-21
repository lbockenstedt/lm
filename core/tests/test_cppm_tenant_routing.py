"""cppm.py routes resolve the NAC spoke PER TENANT, not the first-connected
spoke of type "nac". Two tenants can each run their own ClearPass appliance;
a request from tenant A must never be answered by tenant B's spoke, and an
admin with no tenant selected should see every tenant's data combined
(_nac_merge_fanout), not just whichever spoke happened to connect first.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.cppm import register


class FakeState:
    def __init__(self, nac_instances=None, module_metadata=None):
        self.system_state = {
            "global_config": {"nac_instances": nac_instances or []},
            "module_metadata": module_metadata or {},
        }
        self._tenants = dict(module_metadata or {})

    def get_spoke_tenant(self, sid):
        return (self._tenants.get(sid) or {}).get("tenant_id", "")


class FakeHub:
    def __init__(self, spokes, replies=None, nac_instances=None,
                module_metadata=None, global_nac=None, approved=None):
        # spokes: set of connected+approved nac spoke ids
        self.active_connections = set(spokes)
        self.approved_modules = approved or {sid: True for sid in spokes}
        self.state = FakeState(nac_instances, module_metadata)
        self.replies = replies or {}   # {spoke_id: {cmd: payload_data}}
        self.forwarded = []
        self._nac_spokes = set(spokes)
        self._global_nac = global_nac
        self.warm_cache = {}

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return self._global_nac if module_type == "nac" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._nac_spokes) if module_type == "nac" else []

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        if not tenant_id:
            return self._global_nac
        for sid in self._nac_spokes:
            if self.state.get_spoke_tenant(sid) == tenant_id:
                return sid
        return None

    def get_cppm_spoke_for_shared(self):
        return None

    def get_cppm_spokes_for_tenant(self, tenant_id=None):
        if not tenant_id or tenant_id == "default":
            return []
        own = self.get_cppm_spoke_for_tenant(tenant_id)
        shared = self.get_cppm_spoke_for_shared()
        return list(dict.fromkeys(sid for sid in (own, shared) if sid))

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        data = (self.replies.get(sid) or {}).get(cmd, {"status": "SUCCESS"})
        return {"payload": {"data": data}}

    def warm_get(self, cmd, key):
        return self.warm_cache.get((cmd, key))

    async def warm_set(self, cmd, key, data):
        self.warm_cache[(cmd, key)] = data


def _passthrough_filter(request, data, module, ip_fields, explicit_tenant=None):
    return data


async def _apassthrough(*a, **k):
    # last positional/keyword arg conventions vary per helper; just return
    # whichever "data"/"record" arg was passed (2nd positional after request).
    return a[1] if len(a) > 1 else None


def _build(sess, hub):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _effective_tenant=lambda request, explicit=None: (
            explicit if (sess and sess.get("user", {}).get("is_admin"))
            else (sess or {}).get("user", {}).get("tenant_id")
        ),
        _effective_tenant_slug=lambda request, explicit=None: None,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
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
    the module_type tenant-binding fallback."""
    hub = FakeHub(
        {"cppm-a", "cppm-pinned"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "fallback"}},
                "cppm-pinned": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "pinned"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-pinned": {"tenant_id": "tenantA"}},
        nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-pinned"}],
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/nac-status")
    assert r.json()["server"] == "pinned"
    assert hub.forwarded[-1][0] == "cppm-pinned"


def test_admin_no_tenant_selected_keeps_legacy_global_spoke_for_single_lookups():
    hub = FakeHub(
        {"cppm-a"},
        replies={"cppm-a": {"CPPM_GET_NAC_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"cppm-a": {"tenant_id": "tenantA"}},
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
    hub = FakeHub(
        {"cppm-a", "cppm-shared"},
        replies={
            "cppm-a": {"CPPM_GET_ACCESS_TRACKER": {"status": "SUCCESS",
                                                    "sessions": [{"mac": "own-1"}]}},
            "cppm-shared": {"CPPM_GET_ACCESS_TRACKER": {"status": "SUCCESS",
                                                        "sessions": [{"mac": "shared-1"}]}},
        },
        module_metadata={"cppm-a": {"tenant_id": "tenantA"},
                         "cppm-shared": {"tenant_id": "shared-tenant"}},
    )
    hub.get_cppm_spoke_for_shared = lambda: "cppm-shared"
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/cppm/sessions")
    assert r.status_code == 200
    macs = {s["mac"] for s in r.json()["sessions"]}
    assert macs == {"own-1", "shared-1"}
    assert {sid for sid, _, _ in hub.forwarded} == {"cppm-a", "cppm-shared"}


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
