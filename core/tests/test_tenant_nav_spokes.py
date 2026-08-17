"""``/tenant/spokes`` — the tenant-admin left-nav spoke source.

A tenant-admin cannot reach the Global-Admin-only ``/setup/pending_spokes`` (it
403s), so the WebUI ``updateStatus`` builds their left nav from this mirror
instead. Unlike ``/tenant/devices/spokes`` (``can_bind_spoke`` — OWN tenant
only, for the Add-device dropdown), the NAV must ALSO surface SHARED-tenant
modules, so this endpoint uses ``access.spoke_visible_to_session`` (own +
shared), mirroring the frontend ``_spokeVisibleToTenant``.

These tests pin: own-tenant included, shared-tenant included, other-tenant
excluded, unapproved excluded, and the ``tenant_shared`` flag the nav filter
reads.
"""
import access
import routes.tenant_devices as tenant_devices

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _sess(*, role=None, admin=False, tenants=None, tenant_id=None, user_id="caller"):
    perms = {}
    if admin:
        perms["admin"] = True
    if role:
        perms["role"] = role
    return {"user": {
        "user_id": user_id,
        "tenants": tenants or [],
        "tenant_id": tenant_id,
        "permissions": perms,
    }}


def _tenant_admin(tenant="acme"):
    return _sess(role="tenant_admin", tenants=[tenant], tenant_id=tenant,
                 user_id=f"tadm-{tenant}")


class _State:
    def __init__(self):
        self.system_state = {
            "known_modules": [],
            "module_names": {},
            "module_metadata": {},
        }
        # Consumed by access.refresh_shared_tenant to resolve the shared tenant.
        self.tenant_state = {"tenants": {}}

    def get_spoke_tenant(self, sid):
        return self.system_state.get("module_metadata", {}).get(sid, {}).get("tenant_id")


class _Hub:
    def __init__(self):
        self.state = _State()
        self.approved_modules = {}
        self.spoke_module_types = {}

    def _primary_key(self, sid):
        return sid


class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current


class _Holder:
    def __init__(self):
        self.current = None


def _build(shared_tenant=None):
    hub = _Hub()
    if shared_tenant:
        hub.state.tenant_state["tenants"][shared_tenant] = {"shared": True}
    access.refresh_shared_tenant(hub)
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub
    tenant_devices.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


def _seed(hub, sid, *, tenant_id=None, module_type="firewall", approved=True):
    hub.state.system_state["known_modules"].append(sid)
    hub.state.system_state["module_names"][sid] = sid
    meta = {"module_type": module_type}
    if tenant_id:
        meta["tenant_id"] = tenant_id
    hub.state.system_state["module_metadata"][sid] = meta
    hub.approved_modules[sid] = approved
    hub.spoke_module_types[sid] = module_type


def test_own_tenant_spoke_visible():
    c, hub, holder = _build()
    _seed(hub, "fw-acme", tenant_id="acme")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    assert r.status_code == 200
    spokes = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert set(spokes) == {"fw-acme"}
    assert spokes["fw-acme"]["approved"] is True
    assert spokes["fw-acme"]["tenant_shared"] is False
    # Row shape mirrors /setup/pending_spokes so _rebuildMainNav consumes it.
    assert "display_name" in spokes["fw-acme"]
    assert "module_type" in spokes["fw-acme"]


def test_shared_tenant_spoke_visible():
    """The nav must show SHARED modules — the key difference from
    /tenant/devices/spokes, which excludes them (can_bind_spoke)."""
    c, hub, holder = _build(shared_tenant="shared")
    _seed(hub, "fw-shared", tenant_id="shared")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    spokes = {s["spoke_id"]: s for s in r.json()["spokes"]}
    assert set(spokes) == {"fw-shared"}
    assert spokes["fw-shared"]["tenant_shared"] is True


def test_other_tenant_spoke_excluded():
    c, hub, holder = _build()
    _seed(hub, "fw-acme", tenant_id="acme")
    _seed(hub, "fw-other", tenant_id="other")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    spokes = {s["spoke_id"] for s in r.json()["spokes"]}
    assert spokes == {"fw-acme"}


def test_unassigned_spoke_excluded_for_tenant_admin():
    """Unassigned (no tenant_id) → admin-only holding state; a tenant-admin must
    NOT see it (matches spoke_visible_to_session / _spokeVisibleToTenant)."""
    c, hub, holder = _build()
    _seed(hub, "fw-limbo", tenant_id=None)
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    assert r.json()["spokes"] == []


def test_unapproved_excluded():
    c, hub, holder = _build()
    _seed(hub, "fw-acme", tenant_id="acme", approved=True)
    _seed(hub, "fw-pending", tenant_id="acme", approved=False)
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    spokes = {s["spoke_id"] for s in r.json()["spokes"]}
    assert spokes == {"fw-acme"}


def test_admin_sees_all_including_unassigned():
    c, hub, holder = _build()
    _seed(hub, "fw-acme", tenant_id="acme")
    _seed(hub, "fw-other", tenant_id="other")
    _seed(hub, "fw-limbo", tenant_id=None)
    holder.current = _sess(admin=True, user_id="root")

    r = c.get("/tenant/spokes")
    spokes = {s["spoke_id"] for s in r.json()["spokes"]}
    assert spokes == {"fw-acme", "fw-other", "fw-limbo"}
