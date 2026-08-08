"""net_services.py DHCP routes resolve the Kea spoke PER TENANT, not the
first-connected spoke of type "dhcp". Two tenants can each run their own
DHCP server; a request from tenant A must never be answered by tenant B's
spoke, and an admin with no tenant selected and 2+ dhcp spokes connected
should see every tenant's subnets/leases/reservations combined
(_dhcp_merge_fanout), not just whichever spoke happened to connect first.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.net_services import register


class FakeState:
    def __init__(self, dhcp_instances=None, module_metadata=None):
        self.system_state = {
            "global_config": {"dhcp_instances": dhcp_instances or []},
            "module_metadata": module_metadata or {},
        }
        self._tenants = dict(module_metadata or {})

    def get_spoke_tenant(self, sid):
        return (self._tenants.get(sid) or {}).get("tenant_id", "")


class FakeHub:
    def __init__(self, spokes, replies=None, dhcp_instances=None,
                module_metadata=None, global_dhcp=None, approved=None):
        self.active_connections = set(spokes)
        self.approved_modules = approved or {sid: True for sid in spokes}
        self.state = FakeState(dhcp_instances, module_metadata)
        self.replies = replies or {}
        self.forwarded = []
        self._dhcp_spokes = set(spokes)
        self._global_dhcp = global_dhcp

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return self._global_dhcp if module_type == "dhcp" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._dhcp_spokes) if module_type == "dhcp" else []

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        if not tenant_id:
            return self._global_dhcp
        for sid in self._dhcp_spokes:
            if self.state.get_spoke_tenant(sid) == tenant_id:
                return sid
        return None

    def get_dhcp_spoke_for_shared(self):
        return None

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        data = (self.replies.get(sid) or {}).get(cmd, {"status": "SUCCESS"})
        return {"payload": {"data": data}}


async def _apassthrough(*a, **k):
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
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
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
        {"dhcp-a", "dhcp-b"},
        replies={"dhcp-a": {"DHCP_STATUS": {"status": "SUCCESS", "server": "A"}},
                "dhcp-b": {"DHCP_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dhcp/status")
    assert r.status_code == 200
    assert r.json()["server"] == "A"
    assert hub.forwarded[-1][0] == "dhcp-a"


def test_tenant_b_never_reaches_tenant_a_spoke():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={"dhcp-a": {"DHCP_STATUS": {"status": "SUCCESS", "server": "A"}},
                "dhcp-b": {"DHCP_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantB"), hub)
    r = c.get("/api/dhcp/status")
    assert r.json()["server"] == "B"
    assert hub.forwarded[-1][0] == "dhcp-b"


def test_tenant_with_no_bound_spoke_gets_503():
    hub = FakeHub(
        {"dhcp-a"},
        replies={"dhcp-a": {"DHCP_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantC"), hub)
    r = c.get("/api/dhcp/status")
    assert r.status_code == 503
    assert hub.forwarded == []


def test_dhcp_instance_record_spoke_wins_over_module_type_fallback():
    hub = FakeHub(
        {"dhcp-a", "dhcp-pinned"},
        replies={"dhcp-a": {"DHCP_STATUS": {"status": "SUCCESS", "server": "fallback"}},
                "dhcp-pinned": {"DHCP_STATUS": {"status": "SUCCESS", "server": "pinned"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-pinned": {"tenant_id": "tenantA"}},
        dhcp_instances=[{"tenant_id": "tenantA", "spoke_id": "dhcp-pinned"}],
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dhcp/status")
    assert r.json()["server"] == "pinned"
    assert hub.forwarded[-1][0] == "dhcp-pinned"


def test_admin_no_tenant_single_spoke_keeps_legacy_global_behavior():
    hub = FakeHub(
        {"dhcp-a"},
        replies={"dhcp-a": {"DHCP_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"}},
        global_dhcp="dhcp-a",
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/status")
    assert r.status_code == 200
    assert hub.forwarded[-1][0] == "dhcp-a"


def test_reservation_add_routes_to_tenants_own_spoke():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={"dhcp-a": {"DHCP_ADD_RES": {"status": "SUCCESS"}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.post("/api/dhcp/reservation?tenant=tenantA", json={"ip": "10.0.0.5", "mac": "aa:bb"})
    assert r.status_code == 200
    assert hub.forwarded[-1][0] == "dhcp-a"


# ── admin combined (merge-fanout) view, per list endpoint ───────────────────

def test_admin_subnets_view_combines_every_tenants_spoke_when_multiple_connected():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={
            "dhcp-a": {"DHCP_LIST_SUBNETS": {"status": "SUCCESS",
                                             "subnets": [{"subnet": "10.0.1.0/24"}]}},
            "dhcp-b": {"DHCP_LIST_SUBNETS": {"status": "SUCCESS",
                                             "subnets": [{"subnet": "10.0.2.0/24"}]}},
        },
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/subnets")
    assert r.status_code == 200
    subnets = r.json()["subnets"]
    assert {s["subnet"] for s in subnets} == {"10.0.1.0/24", "10.0.2.0/24"}
    tags = {s["subnet"]: s["_tenant"] for s in subnets}
    assert tags["10.0.1.0/24"] == "tenantA"
    assert tags["10.0.2.0/24"] == "tenantB"


def test_admin_leases_view_combines_every_tenants_spoke_when_multiple_connected():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={
            "dhcp-a": {"DHCP_LIST_LEASES": {"status": "SUCCESS",
                                            "leases": [{"ip": "10.0.1.5"}]}},
            "dhcp-b": {"DHCP_LIST_LEASES": {"status": "SUCCESS",
                                            "leases": [{"ip": "10.0.2.5"}]}},
        },
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/leases")
    assert r.status_code == 200
    leases = r.json()["leases"]
    assert {l["ip"] for l in leases} == {"10.0.1.5", "10.0.2.5"}


def test_admin_reservations_view_combines_every_tenants_spoke_when_multiple_connected():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={
            "dhcp-a": {"DHCP_LIST_RES": {"status": "SUCCESS",
                                         "reservations": [{"ip": "10.0.1.9"}]}},
            "dhcp-b": {"DHCP_LIST_RES": {"status": "SUCCESS",
                                         "reservations": [{"ip": "10.0.2.9"}]}},
        },
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/reservations")
    assert r.status_code == 200
    reservations = r.json()["reservations"]
    assert {res["ip"] for res in reservations} == {"10.0.1.9", "10.0.2.9"}


def test_admin_single_spoke_does_not_fan_out():
    hub = FakeHub(
        {"dhcp-a"},
        replies={"dhcp-a": {"DHCP_LIST_SUBNETS": {"status": "SUCCESS",
                                                  "subnets": [{"subnet": "10.0.1.0/24"}]}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"}},
        global_dhcp="dhcp-a",
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/subnets")
    assert r.status_code == 200
    assert r.json()["subnets"][0]["subnet"] == "10.0.1.0/24"


def test_tenant_scoped_subnets_view_does_not_fan_out():
    hub = FakeHub(
        {"dhcp-a", "dhcp-b"},
        replies={"dhcp-a": {"DHCP_LIST_SUBNETS": {"status": "SUCCESS",
                                                  "subnets": [{"subnet": "10.0.1.0/24"}]}}},
        module_metadata={"dhcp-a": {"tenant_id": "tenantA"},
                         "dhcp-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dhcp/subnets")
    assert r.status_code == 200
    assert {sid for sid, _, _ in hub.forwarded} == {"dhcp-a"}


def test_no_dhcp_spokes_connected_returns_503():
    hub = FakeHub(set())
    c = _build(_admin(), hub)
    r = c.get("/api/dhcp/subnets")
    assert r.status_code == 503
