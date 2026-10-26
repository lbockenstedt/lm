"""Hub routes for per-client DNS override profiles.

* Profiles (the answers themselves) are Global-Admin only.
* Assigning/removing a profile is allowed to a tenant Admin, but only for a
  host IP or a subnet that lies entirely inside their own subnets.
* The listing shows every profile (so a tenant can pick one) but only the
  assignments inside the caller's tenant prefixes.
"""
import copy
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.net_services as ns
from routes.net_services import register

TENANT_PREFIXES = {"t-a": ["10.1.0.0/24"]}

SNAPSHOT = {
    "status": "SUCCESS",
    "profiles": [{"name": "PAVO-DEVICE", "description": "", "records": [], "block": ["x.com"]}],
    "assignments": [
        {"target": "10.1.0.5/32", "profile": "PAVO-DEVICE", "label": "mine"},
        {"target": "10.1.0.0/25", "profile": "PAVO-DEVICE", "label": "my half"},
        {"target": "10.2.0.9/32", "profile": "PAVO-DEVICE", "label": "theirs"},
        {"target": "10.0.0.0/8", "profile": "PAVO-DEVICE", "label": "covers me"},
    ],
    "members": [],
}


class FakeState:
    system_state = {"global_config": {}}

    def get_spoke_tenant(self, sid):
        return "shared"

    def _mark_dirty(self):
        pass


class FakeHub:
    def __init__(self):
        self.active_connections = {"dns-1"}
        self.approved_modules = {"dns-1": True}
        self.state = FakeState()
        self.forwarded = []
        self.spoke_module_types = {}
        self.spoke_parent_map = {}
        self.spoke_telemetry = {}

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return "dns-1" if module_type == "dns" else None

    def get_all_spokes_by_type(self, module_type):
        return [self.get_spoke_by_type(module_type)]

    def get_dns_spoke_for_tenant(self, tenant_id=None):
        return "dns-1"

    def get_dns_spoke_for_shared(self):
        return "dns-1"

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        reply = SNAPSHOT if cmd == "DNS_OVERRIDES" else {"status": "SUCCESS"}
        return {"payload": {"data": copy.deepcopy(reply)}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


@pytest.fixture(autouse=True)
def _scope(monkeypatch):
    async def by_tenant(hub, tid):
        return TENANT_PREFIXES.get(tid, [])

    async def by_session_tenant(hub, sess, tid):
        return TENANT_PREFIXES.get(tid, [])

    async def in_scope(hub, sess, record, fields):
        return str(record.get("ip", "")).startswith("10.1.0.")

    async def by_session(hub, sess):
        return TENANT_PREFIXES.get(sess["user"]["tenant_id"], [])

    monkeypatch.setattr(ns.access, "resolve_prefixes", by_session)
    monkeypatch.setattr(ns.access, "resolve_prefixes_for_tenant", by_tenant)
    monkeypatch.setattr(ns.access, "resolve_prefixes_for_session_tenant", by_session_tenant)
    monkeypatch.setattr(ns.access, "record_in_tenant_scope", in_scope)


def _client(admin):
    hub = FakeHub()
    sess = {"user": {"is_admin": admin, "tenant_id": None if admin else "t-a"}}
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s["user"]["is_admin"]),
        _effective_tenant=lambda request, explicit=None: explicit if admin else "t-a",
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app), hub


def test_admin_sees_every_assignment():
    client, hub = _client(admin=True)
    r = client.get("/api/dns/overrides")
    assert r.status_code == 200
    assert len(r.json()["assignments"]) == 4
    assert hub.forwarded[-1][1] == "DNS_OVERRIDES"


def test_tenant_sees_only_assignments_inside_its_prefixes():
    client, _ = _client(admin=False)
    body = client.get("/api/dns/overrides").json()
    assert [a["target"] for a in body["assignments"]] == ["10.1.0.5/32", "10.1.0.0/25"]
    assert body["profiles"][0]["name"] == "PAVO-DEVICE"
    assert body["tenant_scoped"] is True


def test_profile_writes_are_admin_only():
    client, hub = _client(admin=False)
    assert client.put("/api/dns/overrides/profile",
                      json={"profile": {"name": "X"}}).status_code == 403
    assert client.request("DELETE", "/api/dns/overrides/profile",
                          json={"name": "X"}).status_code == 403
    assert hub.forwarded == []


def test_admin_profile_set_and_delete_relay():
    client, hub = _client(admin=True)
    prof = {"name": "PAVO-DEVICE", "records": [], "block": ["x.com"]}
    assert client.put("/api/dns/overrides/profile",
                      json={"profile": prof, "old_name": "OLD"}).status_code == 200
    assert hub.forwarded[-1] == ("dns-1", "DNS_OVERRIDE_PROFILE_SET",
                                 {"profile": prof, "old_name": "OLD"})
    client.request("DELETE", "/api/dns/overrides/profile", json={"name": "PAVO-DEVICE", "force": True})
    assert hub.forwarded[-1] == ("dns-1", "DNS_OVERRIDE_PROFILE_DELETE",
                                 {"name": "PAVO-DEVICE", "force": True})


def test_admin_may_assign_a_subnet():
    client, hub = _client(admin=True)
    r = client.post("/api/dns/override-assignment",
                    json={"target": "10.9.0.0/16", "profile": "PAVO-DEVICE", "label": "lab"})
    assert r.status_code == 200
    assert hub.forwarded[-1] == ("dns-1", "DNS_OVERRIDE_ASSIGN",
                                 {"target": "10.9.0.0/16", "profile": "PAVO-DEVICE", "label": "lab"})


def test_tenant_may_assign_and_remove_its_own_device():
    client, hub = _client(admin=False)
    assert client.post("/api/dns/override-assignment",
                       json={"target": "10.1.0.5", "profile": "PAVO-DEVICE"}).status_code == 200
    assert client.request("DELETE", "/api/dns/override-assignment",
                          json={"target": "10.1.0.5/32"}).status_code == 200
    assert [c[1] for c in hub.forwarded] == ["DNS_OVERRIDE_ASSIGN", "DNS_OVERRIDE_UNASSIGN"]


@pytest.mark.parametrize("target", ["10.1.0.0/24", "10.1.0.128/25"])
def test_tenant_may_assign_and_remove_a_subnet_inside_its_prefixes(target):
    client, hub = _client(admin=False)
    assert client.post("/api/dns/override-assignment",
                       json={"target": target, "profile": "PAVO-DEVICE"}).status_code == 200
    assert client.request("DELETE", "/api/dns/override-assignment",
                          json={"target": target}).status_code == 200
    assert [c[1] for c in hub.forwarded] == ["DNS_OVERRIDE_ASSIGN", "DNS_OVERRIDE_UNASSIGN"]


@pytest.mark.parametrize("target", ["10.2.0.9", "10.1.0.0/23", "10.2.0.0/24", "garbage"])
def test_tenant_cannot_touch_other_devices_or_subnets(target):
    client, hub = _client(admin=False)
    r = client.post("/api/dns/override-assignment",
                    json={"target": target, "profile": "PAVO-DEVICE"})
    assert r.status_code in (400, 403)
    r = client.request("DELETE", "/api/dns/override-assignment", json={"target": target})
    assert r.status_code in (400, 403)
    assert hub.forwarded == []
