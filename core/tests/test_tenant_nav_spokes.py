"""``/tenant/spokes`` — the tenant-admin left-nav spoke source.

A tenant-admin cannot reach the Global-Admin-only ``/setup/pending_spokes`` (it
403s), so the WebUI ``updateStatus`` builds their left nav from this mirror
instead. It reuses the CANONICAL ``_aggregate_spokes`` payload (identical
``module_type`` derivation + orphan-approved inclusion as the admin nav) and
only applies a per-row VISIBILITY filter: unlike ``/tenant/devices/spokes``
(``can_bind_spoke`` — own-tenant ONLY, for the Add-device dropdown), the NAV
must ALSO surface SHARED-tenant modules, so it uses
``access.spoke_visible_to_session`` (own + shared), mirroring the frontend
``_spokeVisibleToTenant``.

These tests pin the filter: approved own-tenant included, shared included,
other-tenant / unassigned / unapproved excluded, and admin sees every approved
spoke. The aggregation itself is covered by the setup.py spoke tests; here it is
stubbed so the filter is tested in isolation.
"""
import access
import routes.setup as setup_routes
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


def _row(spoke_id, *, tenant_id="", approved=True, tenant_shared=False,
         module_type="firewall"):
    """A /setup/pending_spokes-shaped row (the subset the filter reads)."""
    return {
        "spoke_id": spoke_id,
        "display_name": spoke_id,
        "approved": approved,
        "module_type": module_type,
        "tenant_id": tenant_id,
        "tenant_shared": tenant_shared,
    }


class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current


class _Holder:
    def __init__(self):
        self.current = None


def _build(monkeypatch, rows, shared_tenant=None):
    # Stub the canonical aggregation the endpoint reuses; the filter is the unit
    # under test. Patch the SOURCE (routes.setup) since the handler lazy-imports
    # _aggregate_spokes at call time.
    async def _fake_aggregate(hub):
        return {"spokes": rows}
    monkeypatch.setattr(setup_routes, "_aggregate_spokes", _fake_aggregate)

    # Resolve the shared tenant so access.tenant_is_shared /
    # spoke_visible_to_session treat the shared row as everyone-visible.
    access._SHARED_TENANT_ID = shared_tenant

    holder = _Holder()
    app = FastAPI()
    app.state.hub = object()  # unused — aggregation is stubbed
    tenant_devices.register(app, app.state.hub, _Ctx(holder))
    return TestClient(app), holder


def test_own_tenant_spoke_visible(monkeypatch):
    c, holder = _build(monkeypatch, [_row("fw-acme", tenant_id="acme")])
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    assert r.status_code == 200
    ids = {s["spoke_id"] for s in r.json()["spokes"]}
    assert ids == {"fw-acme"}


def test_shared_tenant_spoke_visible(monkeypatch):
    """The nav must show SHARED modules — the key difference from
    /tenant/devices/spokes, which excludes them (can_bind_spoke)."""
    c, holder = _build(
        monkeypatch,
        [_row("fw-shared", tenant_id="shared", tenant_shared=True)],
        shared_tenant="shared")
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    ids = {s["spoke_id"] for s in r.json()["spokes"]}
    assert ids == {"fw-shared"}


def test_other_tenant_spoke_excluded(monkeypatch):
    c, holder = _build(monkeypatch, [
        _row("fw-acme", tenant_id="acme"),
        _row("fw-other", tenant_id="other"),
    ])
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    ids = {s["spoke_id"] for s in r.json()["spokes"]}
    assert ids == {"fw-acme"}


def test_unassigned_spoke_excluded_for_tenant_admin(monkeypatch):
    """Unassigned (blank tenant_id) -> admin-only holding state; a tenant-admin
    must NOT see it (matches spoke_visible_to_session / _spokeVisibleToTenant)."""
    c, holder = _build(monkeypatch, [_row("fw-limbo", tenant_id="")])
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    assert r.json()["spokes"] == []


def test_unapproved_excluded(monkeypatch):
    c, holder = _build(monkeypatch, [
        _row("fw-acme", tenant_id="acme", approved=True),
        _row("fw-pending", tenant_id="acme", approved=False),
    ])
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    ids = {s["spoke_id"] for s in r.json()["spokes"]}
    assert ids == {"fw-acme"}


def test_admin_sees_all_approved_including_unassigned(monkeypatch):
    c, holder = _build(monkeypatch, [
        _row("fw-acme", tenant_id="acme"),
        _row("fw-other", tenant_id="other"),
        _row("fw-limbo", tenant_id=""),
        _row("fw-pending", tenant_id="acme", approved=False),
    ])
    holder.current = _sess(admin=True, user_id="root")

    r = c.get("/tenant/spokes")
    ids = {s["spoke_id"] for s in r.json()["spokes"]}
    assert ids == {"fw-acme", "fw-other", "fw-limbo"}  # approved only


def test_module_type_preserved_from_aggregation(monkeypatch):
    """The row shape (incl. module_type that drives MODULE_TYPE_PRODUCT -> the
    left-nav class) passes through untouched, so the tenant-admin nav lights the
    exact same classes the admin nav would for the same spoke."""
    c, holder = _build(monkeypatch, [_row("cppm-1", tenant_id="acme", module_type="nac")])
    holder.current = _tenant_admin("acme")

    r = c.get("/tenant/spokes")
    spokes = r.json()["spokes"]
    assert spokes[0]["module_type"] == "nac"
