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
import types

import access
import routes.setup as setup_routes
import routes.tenant_devices as tenant_devices
from hub_spoke_registry import SpokeRegistryMixin, nac_push_key

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


def _build(monkeypatch, rows, shared_tenant=None, hub=None):
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
    app.state.hub = hub or object()  # aggregation is stubbed; a hub only for NAC owners
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


class _NacHub:
    """Enough hub for NAC rows: each spoke's binding, the ``nac_instances``
    records, and the real record-based owner (``get_nac_spoke_owner``)."""

    get_nac_spoke_owner = SpokeRegistryMixin.get_nac_spoke_owner

    def __init__(self, bindings, records):
        self.spoke_module_types = {sid: "nac" for sid in bindings}
        md = {sid: {"tenant_id": t, "module_type": "nac"} for sid, t in bindings.items()}
        gc = {"nac_instances": records}
        # Each record has a host and each spoke was sent the first record
        # bound to it, so none is stale (hub_spoke_registry.nac_spoke_stale).
        pushed = {}
        for rec in records:
            rec.setdefault("host", "cp.example")
            pushed.setdefault(rec["spoke_id"], nac_push_key(rec))
        self.state = types.SimpleNamespace(
            system_state={"module_metadata": md, "global_config": gc,
                          "nac_config_pushed": pushed},
            get_global_config=lambda: gc,
            get_spoke_tenant=lambda sid: (md.get(sid) or {}).get("tenant_id") or "")

    def _primary_key(self, sid):
        return sid


def test_nac_spoke_follows_the_clearpass_record_it_serves(monkeypatch):
    """A NAC spoke shows to the tenant whose ClearPass record the hub pushes
    it, whatever its own binding (a record keeps its tenant when Setup → NAC
    moves it). A spoke serving two tenants' records shows to neither, and the
    shared ClearPass is hidden from a tenant with a record of its own."""
    hub = _NacHub({"nac-acme": "", "nac-both": "acme", "nac-shared": "shared"}, [
        {"id": "a", "spoke_id": "nac-acme", "tenant_id": "acme"},
        {"id": "b", "spoke_id": "nac-both", "tenant_id": "acme"},
        {"id": "c", "spoke_id": "nac-both", "tenant_id": "other"}])
    rows = [_row("nac-acme", module_type="nac"),
            _row("nac-both", tenant_id="acme", module_type="nac"),
            _row("nac-shared", tenant_id="shared", module_type="nac")]
    c, holder = _build(monkeypatch, rows, shared_tenant="shared", hub=hub)

    def ids():
        return {s["spoke_id"] for s in c.get("/tenant/spokes").json()["spokes"]}

    holder.current = _tenant_admin("acme")
    assert ids() == {"nac-acme"}
    holder.current = _tenant_admin("other")
    assert ids() == set()
    holder.current = _tenant_admin("beta")
    assert ids() == {"nac-shared"}
    holder.current = _sess(admin=True, user_id="root")
    assert ids() == {"nac-acme", "nac-both", "nac-shared"}
