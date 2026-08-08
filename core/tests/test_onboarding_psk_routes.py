"""routes/onboarding.py — generic tenant self-service spoke onboarding PSK
(the "Add Server" button's backend). A tenant-admin generates/lists/revokes
a PSK for their OWN tenant only; a Global Admin may act on any tenant.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.onboarding import register


class _FakeSimStore:
    def __init__(self):
        self._psks = {}

    async def get_psks(self, tenant_id):
        return list(self._psks.get(tenant_id, []))

    async def add_psk(self, tenant_id, psk):
        self._psks.setdefault(tenant_id, []).append(psk)

    async def remove_psk(self, tenant_id, psk):
        lst = self._psks.get(tenant_id, [])
        if psk in lst:
            lst.remove(psk)
            return True
        return False


class FakeHub:
    def __init__(self):
        self.simulations_store = _FakeSimStore()


def _build(sess):
    app = FastAPI()
    hub = FakeHub()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _is_tenant_admin=lambda s: bool(s and s.get("user", {}).get("is_tenant_admin")),
    )
    register(app, hub, ctx)
    return TestClient(app), hub


def _admin():
    return {"user": {"is_admin": True}}


def _tenant_admin(tenants):
    return {"user": {"is_admin": False, "is_tenant_admin": True, "tenants": tenants}}


def test_tenant_admin_generates_a_psk_for_their_own_tenant():
    c, hub = _build(_tenant_admin(["tenantA"]))
    r = c.post("/tenant/tenantA/onboarding-psk")
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "tenantA"
    assert body["psk"]
    assert body["psk"] in hub.simulations_store._psks["tenantA"]


def test_tenant_admin_cannot_generate_a_psk_for_another_tenant():
    c, _ = _build(_tenant_admin(["tenantA"]))
    r = c.post("/tenant/tenantB/onboarding-psk")
    assert r.status_code == 403


def test_admin_may_generate_a_psk_for_any_tenant():
    c, hub = _build(_admin())
    r = c.post("/tenant/tenantZ/onboarding-psk")
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "tenantZ"


def test_list_returns_only_that_tenants_psks():
    c, hub = _build(_admin())
    c.post("/tenant/tenantA/onboarding-psk")
    c.post("/tenant/tenantB/onboarding-psk")
    r = c.get("/tenant/tenantA/onboarding-psk")
    assert r.status_code == 200
    assert r.json()["psks"] == hub.simulations_store._psks["tenantA"]
    assert len(r.json()["psks"]) == 1


def test_tenant_admin_cannot_list_another_tenants_psks():
    c, _ = _build(_tenant_admin(["tenantA"]))
    r = c.get("/tenant/tenantB/onboarding-psk")
    assert r.status_code == 403


def test_revoke_removes_the_psk():
    c, hub = _build(_tenant_admin(["tenantA"]))
    gen = c.post("/tenant/tenantA/onboarding-psk").json()
    r = c.request("DELETE", "/tenant/tenantA/onboarding-psk", json={"psk": gen["psk"]})
    assert r.status_code == 200
    assert r.json()["removed"] is True
    assert gen["psk"] not in hub.simulations_store._psks["tenantA"]


def test_tenant_admin_cannot_revoke_another_tenants_psk():
    c_admin, hub = _build(_admin())
    gen = c_admin.post("/tenant/tenantB/onboarding-psk").json()
    c_other, _ = _build(_tenant_admin(["tenantA"]))
    r = c_other.request("DELETE", "/tenant/tenantB/onboarding-psk", json={"psk": gen["psk"]})
    assert r.status_code == 403
    assert gen["psk"] in hub.simulations_store._psks["tenantB"]


def test_revoke_unknown_psk_returns_removed_false():
    c, _ = _build(_tenant_admin(["tenantA"]))
    r = c.request("DELETE", "/tenant/tenantA/onboarding-psk", json={"psk": "nope"})
    assert r.status_code == 200
    assert r.json()["removed"] is False


def test_plain_user_is_rejected():
    """No admin/tenant-admin flag at all."""
    c, _ = _build({"user": {"is_admin": False, "tenants": []}})
    r = c.post("/tenant/tenantA/onboarding-psk")
    assert r.status_code == 403
