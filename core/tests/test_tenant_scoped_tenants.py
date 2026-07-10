"""Regression tests for tenant-scoped tenant editing (Phase 4).

A tenant Admin may EDIT a tenant in its own ``user.tenants`` list — display
name, description, quotas — via ``/api/tenant/{tenant}`` (GET details + POST
edit). Creating a tenant, deleting a tenant, and editing a tenant the admin
does NOT own stay Global-Admin-only (``/setup/tenants*`` untouched). Safety
rules under test:

* the path {tenant} must be in the caller's user.tenants — a tenant_admin for
  "acme" cannot GET or POST ``/api/tenant/other`` (403);
* a tenant_admin may only merge the editable allowlist (name/description/
  quotas) — scoping fields (netbox_tenant_slug, proxmox_tag, ldap_base_dn,
  netbox_id) and `active` are silently dropped, so a tenant_admin cannot
  re-scope its tenant to another tenant's NetBox/Proxmox/LDAP data
  (cross-tenant escalation prevention);
* a Global admin using the same route is unconstrained (full merge, mirrors
  ``/setup/tenant``) and may set scoping/active;
* a plain (non-admin) user is blocked (403) — tenant edit is an admin op;
* a 404 is returned for an unknown tenant.
"""
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import access
from access import resolve_effective_permissions  # noqa: F401  (import side-effect parity)
import routes.tenants_users as tenants_users


# ── session builders ───────────────────────────────────────────────────────
def _sess(*, role=None, admin=False, tenants=None, tenant_id=None, rights=None,
          user_id="caller"):
    perms = dict(rights or {})
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


def _global_admin():
    return _sess(role="admin", admin=True, user_id="root")


def _tenant_admin(tenant="acme"):
    return _sess(role="tenant_admin", tenants=[tenant], tenant_id=tenant,
                 user_id=f"tadm-{tenant}")


def _plain_cs_user(tenant="acme"):
    return _sess(tenants=[tenant], tenant_id=tenant, rights={"cs": True},
                 user_id=f"cs-{tenant}")


# ── fake hub/state with a real tenant store ─────────────────────────────────
class _State:
    def __init__(self, tenants=None):
        self.system_state = {"users": {}, "permission_groups": {}}
        # tenant_state mirrors StateManager: a dict of tenant_id -> record.
        self.tenant_state = {"tenants": dict(tenants or {})}

    def get_tenant(self, tid):
        return self.tenant_state.get("tenants", {}).get(tid)

    def update_tenant(self, tid, data):
        rec = self.tenant_state.setdefault("tenants", {}).setdefault(tid, {})
        rec.update(dict(data))
        return rec

    def save_state(self):
        return None


class _Hub:
    def __init__(self, tenants=None):
        self.state = _State(tenants=tenants)


# ── app builder ──────────────────────────────────────────────────────────────
class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current
        self._is_admin = access.is_admin
        self._is_tenant_admin = access.is_tenant_admin
        self._check_tenant_access = access.check_tenant_access


class _Holder:
    def __init__(self):
        self.current = None


def _build(tenants=None):
    hub = _Hub(tenants=tenants)
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub
    tenants_users.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


def _acme_record():
    return {"acme": {
        "name": "Acme Corp", "netbox_tenant_slug": "acme",
        "netbox_id": 11, "proxmox_tag": "tenant-acme",
        "ldap_base_dn": "ou=acme,dc=corp,dc=com",
        "description": "original", "quotas": {"vm": 5},
    }}


# ── GET details ──────────────────────────────────────────────────────────────
def test_get_own_tenant_as_tenant_admin():
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.get("/api/tenant/acme")
    assert r.status_code == 200
    cfg = r.json()["config"]
    # editable + scoping-for-display only; system fields (netbox_id) excluded.
    assert cfg["name"] == "Acme Corp"
    assert cfg["description"] == "original"
    assert cfg["quotas"] == {"vm": 5}
    assert "netbox_tenant_slug" in cfg  # read-only display
    assert "netbox_id" not in cfg       # system field withheld


def test_get_403_for_other_tenant_as_tenant_admin():
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.get("/api/tenant/other")
    assert r.status_code == 403


def test_get_403_for_plain_cs_user():
    c, hub, holder = _build(_acme_record())
    holder.current = _plain_cs_user("acme")
    r = c.get("/api/tenant/acme")
    assert r.status_code == 403


def test_get_401_no_session():
    c, hub, holder = _build(_acme_record())
    holder.current = None
    r = c.get("/api/tenant/acme")
    assert r.status_code == 401


def test_get_404_unknown_tenant():
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.get("/api/tenant/ghost")
    # 'ghost' isn't in the admin's tenants → 403 (ownership gate fires first).
    assert r.status_code == 403


def test_get_any_tenant_as_global_admin_returns_full_record():
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    r = c.get("/api/tenant/acme")
    assert r.status_code == 200
    cfg = r.json()["config"]
    # Global sees everything, including system fields.
    assert cfg["netbox_id"] == 11
    assert cfg["proxmox_tag"] == "tenant-acme"


# ── POST edit ───────────────────────────────────────────────────────────────
def test_edit_own_tenant_name_description_quotas_as_tenant_admin():
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme", json={"config": {
        "name": "Acme Renamed", "description": "updated",
        "quotas": {"vm": 9, "cppm": 2}}})
    assert r.status_code == 200
    rec = hub.state.tenant_state["tenants"]["acme"]
    assert rec["name"] == "Acme Renamed"
    assert rec["description"] == "updated"
    assert rec["quotas"] == {"vm": 9, "cppm": 2}


def test_edit_drops_scoping_fields_as_tenant_admin():
    """The whole point: a tenant_admin cannot re-scope to another tenant's
    NetBox/Proxmox/LDAP data. Sent scoping fields are silently dropped."""
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme", json={"config": {
        "name": "Acme",
        "netbox_tenant_slug": "other-tenant",  # attempted cross-tenant re-scope
        "proxmox_tag": "tenant-other",
        "ldap_base_dn": "ou=other,dc=corp,dc=com",
        "netbox_id": 999,
        "active": True}})
    assert r.status_code == 200
    rec = hub.state.tenant_state["tenants"]["acme"]
    # Scoping fields UNCHANGED — the attempted re-scope was dropped.
    assert rec["netbox_tenant_slug"] == "acme"
    assert rec["proxmox_tag"] == "tenant-acme"
    assert rec["ldap_base_dn"] == "ou=acme,dc=corp,dc=com"
    assert rec["netbox_id"] == 11
    assert "active" not in rec
    # The cosmetic edit DID land.
    assert rec["name"] == "Acme"
    # The response lists only what was actually applied.
    assert "netbox_tenant_slug" not in r.json()["updated"]


def test_edit_400_when_only_scoping_fields_supplied_as_tenant_admin():
    """If a tenant_admin sends ONLY scoping fields (no editable ones), nothing
    is applicable → 400 (not a silent no-op that looks like success)."""
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme", json={"config": {
        "netbox_tenant_slug": "other", "proxmox_tag": "tenant-other"}})
    assert r.status_code == 400
    rec = hub.state.tenant_state["tenants"]["acme"]
    assert rec["netbox_tenant_slug"] == "acme"  # unchanged


def test_edit_403_for_other_tenant_as_tenant_admin():
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/other", json={"config": {"name": "x"}})
    assert r.status_code == 403


def test_edit_403_for_plain_cs_user():
    c, hub, holder = _build(_acme_record())
    holder.current = _plain_cs_user("acme")
    r = c.post("/api/tenant/acme", json={"config": {"name": "x"}})
    assert r.status_code == 403


def test_edit_401_no_session():
    c, hub, holder = _build(_acme_record())
    holder.current = None
    r = c.post("/api/tenant/acme", json={"config": {"name": "x"}})
    assert r.status_code == 401


def test_edit_404_unknown_owned_tenant():
    """Admin owns 'ghost' (in user.tenants) but no record exists → 404."""
    c, hub, holder = _build(_acme_record())
    holder.current = _sess(role="tenant_admin", tenants=["ghost"],
                           tenant_id="ghost", user_id="tadm-ghost")
    r = c.post("/api/tenant/ghost", json={"config": {"name": "x"}})
    assert r.status_code == 404


def test_edit_as_global_admin_can_set_scoping_and_active():
    """A Global admin via the same route is unconstrained — full merge,
    mirrors /setup/tenant (can re-scope, set active)."""
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    r = c.post("/api/tenant/acme", json={"config": {
        "name": "Acme", "netbox_tenant_slug": "other-tenant", "active": True}})
    assert r.status_code == 200
    rec = hub.state.tenant_state["tenants"]["acme"]
    assert rec["netbox_tenant_slug"] == "other-tenant"
    assert rec.get("active") is True


def test_edit_does_not_create_tenant_as_tenant_admin():
    """A tenant_admin editing a tenant it owns but that has no record yet is
    NOT silently created — edit is for an existing record (404). Creating a
    tenant stays Global-only (/setup/tenants)."""
    c, hub, holder = _build({})  # no tenants seeded
    holder.current = _sess(role="tenant_admin", tenants=["acme"],
                           tenant_id="acme", user_id="tadm-acme")
    r = c.post("/api/tenant/acme", json={"config": {"name": "Acme"}})
    assert r.status_code == 404
    assert "acme" not in hub.state.tenant_state.get("tenants", {})


def test_edit_merge_preserves_existing_fields_as_tenant_admin():
    """update_tenant merges; a tenant_admin editing `name` must not wipe
    scoping/quotas it didn't send."""
    c, hub, holder = _build(_acme_record())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme", json={"config": {"name": "Just Rename"}})
    assert r.status_code == 200
    rec = hub.state.tenant_state["tenants"]["acme"]
    assert rec["name"] == "Just Rename"
    # Untouched fields preserved.
    assert rec["netbox_tenant_slug"] == "acme"
    assert rec["quotas"] == {"vm": 5}
    assert rec["description"] == "original"