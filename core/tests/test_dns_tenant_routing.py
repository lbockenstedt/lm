"""net_services.py DNS routes resolve the Unbound spoke PER TENANT, not the
first-connected spoke of type "dns". Two tenants can each run their own DNS
server; a request from tenant A must never be answered by tenant B's spoke,
and an admin with no tenant selected and 2+ dns spokes connected should see
every tenant's records combined (_dns_merge_fanout), not just whichever
spoke happened to connect first.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.net_services import register


class FakeState:
    def __init__(self, dns_instances=None, module_metadata=None):
        self.system_state = {
            "global_config": {"dns_instances": dns_instances or []},
            "module_metadata": module_metadata or {},
        }
        self._tenants = dict(module_metadata or {})

    def get_spoke_tenant(self, sid):
        return (self._tenants.get(sid) or {}).get("tenant_id", "")


class FakeHub:
    def __init__(self, spokes, replies=None, dns_instances=None,
                module_metadata=None, global_dns=None, approved=None):
        self.active_connections = set(spokes)
        self.approved_modules = approved or {sid: True for sid in spokes}
        self.state = FakeState(dns_instances, module_metadata)
        self.replies = replies or {}   # {spoke_id: {cmd: payload_data}}
        self.forwarded = []
        self._dns_spokes = set(spokes)
        self._global_dns = global_dns

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return self._global_dns if module_type == "dns" else None

    def get_all_spokes_by_type(self, module_type):
        return list(self._dns_spokes) if module_type == "dns" else []

    def get_dns_spoke_for_tenant(self, tenant_id=None):
        if not tenant_id:
            return self._global_dns
        for sid in self._dns_spokes:
            if self.state.get_spoke_tenant(sid) == tenant_id:
                return sid
        return None

    def get_dns_spoke_for_shared(self):
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
        {"dns-a", "dns-b"},
        replies={"dns-a": {"DNS_STATUS": {"status": "SUCCESS", "server": "A"}},
                "dns-b": {"DNS_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dns/status")
    assert r.status_code == 200
    assert r.json()["server"] == "A"
    assert hub.forwarded[-1][0] == "dns-a"


def test_tenant_b_never_reaches_tenant_a_spoke():
    hub = FakeHub(
        {"dns-a", "dns-b"},
        replies={"dns-a": {"DNS_STATUS": {"status": "SUCCESS", "server": "A"}},
                "dns-b": {"DNS_STATUS": {"status": "SUCCESS", "server": "B"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantB"), hub)
    r = c.get("/api/dns/status")
    assert r.json()["server"] == "B"
    assert hub.forwarded[-1][0] == "dns-b"


def test_tenant_with_no_bound_spoke_gets_503():
    hub = FakeHub(
        {"dns-a"},
        replies={"dns-a": {"DNS_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"}},
    )
    c = _build(_tenant_user("tenantC"), hub)
    r = c.get("/api/dns/status")
    assert r.status_code == 503
    assert hub.forwarded == []


def test_dns_instance_record_spoke_wins_over_module_type_fallback():
    hub = FakeHub(
        {"dns-a", "dns-pinned"},
        replies={"dns-a": {"DNS_STATUS": {"status": "SUCCESS", "server": "fallback"}},
                "dns-pinned": {"DNS_STATUS": {"status": "SUCCESS", "server": "pinned"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-pinned": {"tenant_id": "tenantA"}},
        dns_instances=[{"tenant_id": "tenantA", "spoke_id": "dns-pinned"}],
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dns/status")
    assert r.json()["server"] == "pinned"
    assert hub.forwarded[-1][0] == "dns-pinned"


def test_admin_no_tenant_single_spoke_keeps_legacy_global_behavior():
    hub = FakeHub(
        {"dns-a"},
        replies={"dns-a": {"DNS_STATUS": {"status": "SUCCESS", "server": "A"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"}},
        global_dns="dns-a",
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dns/status")
    assert r.status_code == 200
    assert hub.forwarded[-1][0] == "dns-a"


# ── mutations route to the right spoke too ───────────────────────────────────

def test_add_record_routes_to_tenants_own_spoke():
    hub = FakeHub(
        {"dns-a", "dns-b"},
        replies={"dns-a": {"DNS_ADD": {"status": "SUCCESS"}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.post("/api/dns/record?tenant=tenantA", json={"name": "x", "value": "10.0.0.1"})
    assert r.status_code == 200
    assert hub.forwarded[-1][0] == "dns-a"


# ── admin combined (merge-fanout) view ───────────────────────────────────────

def test_admin_records_view_combines_every_tenants_spoke_when_multiple_connected():
    hub = FakeHub(
        {"dns-a", "dns-b"},
        replies={
            "dns-a": {"DNS_LIST": {"status": "SUCCESS",
                                   "records": [{"name": "a.local", "value": "10.0.0.1"}]}},
            "dns-b": {"DNS_LIST": {"status": "SUCCESS",
                                   "records": [{"name": "b.local", "value": "10.0.0.2"}]}},
        },
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dns/records")
    assert r.status_code == 200
    records = r.json()["records"]
    assert {rec["name"] for rec in records} == {"a.local", "b.local"}
    tags = {rec["name"]: rec["_tenant"] for rec in records}
    assert tags["a.local"] == "tenantA"
    assert tags["b.local"] == "tenantB"


def test_admin_records_view_single_spoke_does_not_fan_out():
    """Only one dns spoke connected — no reason to merge-fanout, keep the
    simple legacy relay path (still correctly resolved)."""
    hub = FakeHub(
        {"dns-a"},
        replies={"dns-a": {"DNS_LIST": {"status": "SUCCESS",
                                        "records": [{"name": "a.local", "value": "10.0.0.1"}]}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"}},
        global_dns="dns-a",
    )
    c = _build(_admin(), hub)
    r = c.get("/api/dns/records")
    assert r.status_code == 200
    assert r.json()["records"][0]["name"] == "a.local"


def test_tenant_scoped_records_view_does_not_fan_out():
    hub = FakeHub(
        {"dns-a", "dns-b"},
        replies={"dns-a": {"DNS_LIST": {"status": "SUCCESS",
                                        "records": [{"name": "a.local", "value": "10.0.0.1"}]}}},
        module_metadata={"dns-a": {"tenant_id": "tenantA"},
                         "dns-b": {"tenant_id": "tenantB"}},
    )
    c = _build(_tenant_user("tenantA"), hub)
    r = c.get("/api/dns/records")
    assert r.status_code == 200
    assert {sid for sid, _, _ in hub.forwarded} == {"dns-a"}


def test_no_dns_spokes_connected_returns_503_for_admin_merge_view():
    hub = FakeHub(set())
    c = _build(_admin(), hub)
    r = c.get("/api/dns/records")
    assert r.status_code == 503
