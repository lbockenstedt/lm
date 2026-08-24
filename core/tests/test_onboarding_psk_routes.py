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
        self.active_connections = {}
        self.approved_modules = {}
        self.spoke_module_types = {}
        self.spoke_telemetry = {}
        self.state = SimpleNamespace(
            system_state={"known_modules": [], "module_names": {}, "module_metadata": {}},
            get_spoke_tenant=lambda sid: self._tenants.get(sid, ""),
            remove_module=self._remove_module,
        )
        self._tenants = {}
        self.evicted = []
        self.cleared_mail = []
        self.deleted_keys = []
        self.key_manager = SimpleNamespace(delete_spoke_key=lambda pk: self.deleted_keys.append(pk))
        self.mailbox = SimpleNamespace(clear_spoke=self._clear_spoke)

    def _primary_key(self, sid):
        return sid

    async def _clear_spoke(self, pk):
        self.cleared_mail.append(pk)

    def _evict_spoke(self, sid):
        self.evicted.append(sid)

    def _remove_module(self, sid):
        self.state.system_state["known_modules"] = [
            m for m in self.state.system_state["known_modules"] if m != sid]
        self.state.system_state["module_names"].pop(sid, None)
        self.state.system_state["module_metadata"].pop(sid, None)
        self._tenants.pop(sid, None)

    def add_spoke(self, sid, tenant, *, module_type="nac", approved=True, connected=True, name=None, ip=None):
        self.state.system_state["known_modules"].append(sid)
        if name:
            self.state.system_state["module_names"][sid] = name
        self.state.system_state["module_metadata"][sid] = {"module_type": module_type, "hostname": name or sid}
        self._tenants[sid] = tenant
        self.approved_modules[sid] = approved
        if connected:
            self.active_connections[sid] = object()
        if ip:
            self.spoke_telemetry[sid] = {"remote_ip": ip}


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


def test_list_spokes_returns_only_that_tenants_fleet():
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-a1", "tenantA", module_type="nac", approved=True, connected=True, name="box-a1")
    hub.add_spoke("s-a2", "tenantA", module_type="dns", approved=False, connected=True, name="box-a2")
    hub.add_spoke("s-b1", "tenantB", module_type="nac", approved=True, connected=True, name="box-b1")
    r = c.get("/tenant/tenantA/spokes")
    assert r.status_code == 200
    body = r.json()
    assert body["tenant_id"] == "tenantA"
    ids = {s["spoke_id"] for s in body["spokes"]}
    assert ids == {"s-a1", "s-a2"}  # tenantB's box is never leaked


def test_list_spokes_includes_pending_and_offline():
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-pending", "tenantA", approved=False, connected=True, name="new-box")
    hub.add_spoke("s-offline", "tenantA", approved=True, connected=False, name="old-box")
    r = c.get("/tenant/tenantA/spokes")
    by_id = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert by_id["s-pending"]["approved"] is False
    assert by_id["s-pending"]["connected"] is True
    assert by_id["s-offline"]["approved"] is True
    assert by_id["s-offline"]["connected"] is False


def test_list_spokes_includes_remote_ip_from_telemetry():
    """The Proxmox Host Agent install-command spoke picker needs each
    hypervisor spoke's remote_ip so it can pin --spoke-ip; sourced from
    hub.spoke_telemetry, keyed by primary key — same data the WS connect
    handler in main.py captures."""
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-hv1", "tenantA", module_type="hypervisor", approved=True,
                   connected=True, name="pve1", ip="10.1.2.3")
    hub.add_spoke("s-hv2", "tenantA", module_type="hypervisor", approved=True,
                   connected=False, name="pve2")  # no telemetry captured
    r = c.get("/tenant/tenantA/spokes")
    by_id = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert by_id["s-hv1"]["ip"] == "10.1.2.3"
    assert by_id["s-hv2"]["ip"] == ""


def test_tenant_admin_cannot_list_another_tenants_spokes():
    c, _ = _build(_tenant_admin(["tenantA"]))
    r = c.get("/tenant/tenantB/spokes")
    assert r.status_code == 403


# ── DELETE /tenant/{tenant}/spokes/{spoke_id} ───────────────────────────────
def test_tenant_admin_deletes_their_own_spoke():
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-a1", "tenantA", approved=True, connected=True, name="box-a1")
    r = c.request("DELETE", "/tenant/tenantA/spokes/s-a1")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    # Full teardown ran: registration gone, key wiped, mail cleared, evicted.
    assert "s-a1" not in hub.state.system_state["known_modules"]
    assert "s-a1" in hub.deleted_keys
    assert "s-a1" in hub.cleared_mail
    assert "s-a1" in hub.evicted
    assert hub.approved_modules.get("s-a1") is None


def test_tenant_admin_cannot_delete_another_tenants_spoke():
    """Anti-IDOR: a spoke bound to another tenant is 404 (existence not leaked)
    and is NOT torn down."""
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-b1", "tenantB", approved=True, connected=True, name="box-b1")
    r = c.request("DELETE", "/tenant/tenantA/spokes/s-b1")
    assert r.status_code == 404
    # Untouched.
    assert "s-b1" in hub.state.system_state["known_modules"]
    assert "s-b1" not in hub.deleted_keys


def test_tenant_admin_cannot_delete_via_another_tenant_path():
    """The tenant path must be owned by the caller (middleware+route gate)."""
    c, hub = _build(_tenant_admin(["tenantA"]))
    hub.add_spoke("s-b1", "tenantB", approved=True, connected=True)
    r = c.request("DELETE", "/tenant/tenantB/spokes/s-b1")
    assert r.status_code == 403
    assert "s-b1" in hub.state.system_state["known_modules"]


def test_delete_unknown_spoke_is_404_for_tenant_admin():
    c, hub = _build(_tenant_admin(["tenantA"]))
    r = c.request("DELETE", "/tenant/tenantA/spokes/ghost")
    assert r.status_code == 404


def test_admin_may_delete_any_tenants_spoke():
    c, hub = _build(_admin())
    hub.add_spoke("s-b1", "tenantB", approved=True, connected=True, name="box-b1")
    r = c.request("DELETE", "/tenant/tenantB/spokes/s-b1")
    assert r.status_code == 200
    assert "s-b1" not in hub.state.system_state["known_modules"]
    assert "s-b1" in hub.evicted
