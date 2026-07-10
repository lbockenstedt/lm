"""Regression tests for tenant-scoped user management (Phase 2).

A tenant Admin may manage the operators of its own tenant(s) via
``/api/tenant/{tenant}/users*`` — create/edit/set-password/remove — without any
system-wide power. The /setup/users* routes stay Global-Admin-only; these
routes are the tenant-scoped path. Safety rules under test:

* the path {tenant} must be in the caller's user.tenants (a tenant Admin for
  "acme" cannot manage "other");
* a tenant Admin may only MODIFY a user whose tenants ⊆ the admin's tenants
  (a change can't bleed into a tenant the admin doesn't own) and who is not an
  admin-tier / protected user;
* a tenant Admin may NEVER grant the admin or tenant_admin role (no
  escalation) — only module rights;
* a tenant Admin may only assign tenants it owns;
* "delete" is remove-from-my-tenant (non-destructive); the record survives,
  minus this tenant. A user left with no tenants is inert.
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


# ── fake hub/state ──────────────────────────────────────────────────────────
class _State:
    def __init__(self):
        self.system_state = {"users": {}, "permission_groups": {}}

    def get_tenant(self, tid):
        return {"id": tid, "name": tid} if tid else None

    def save_state(self):
        return None

    def remove_user_from_tenant(self, user_id, tenant_id):
        u = self.system_state.get("users", {}).get(user_id)
        if u and tenant_id in (u.get("tenants") or []):
            u["tenants"].remove(tenant_id)
            return True
        return False

    def assign_user_to_tenant(self, user_id, tenant_id):
        u = self.system_state.setdefault("users", {}).setdefault(
            user_id, {"tenants": []})
        if tenant_id not in (u.get("tenants") or []):
            u.setdefault("tenants", []).append(tenant_id)
        return True


class _Hub:
    def __init__(self):
        self.state = _State()


# ── app builder ──────────────────────────────────────────────────────────────
class _Ctx:
    """Minimal ctx mirroring the keys tenants_users.register uses for the
    tenant-scoped routes (the /setup/* routes it registers don't read ctx)."""
    def __init__(self, holder):
        self._session_user = lambda req: holder.current
        self._is_admin = access.is_admin
        self._is_tenant_admin = access.is_tenant_admin
        self._check_tenant_access = access.check_tenant_access


class _Holder:
    def __init__(self):
        self.current = None


def _build(seed_users=None):
    hub = _Hub()
    hub.state.system_state["users"] = dict(seed_users or {})
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub  # the routes read app.state.hub, not the closed-over hub
    tenants_users.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


def _seed_regular(acme_only=True):
    """A regular operator user 'op1' in acme (and optionally also 'other')."""
    tenants = ["acme"] if acme_only else ["acme", "other"]
    return {
        "op1": {
            "permissions": {"cs": True},
            "auth_type": "local",
            "tenants": tenants,
            "password_hash": "x",
        }
    }


def _seed_admin_user(uid="bigadmin"):
    return {uid: {
        "permissions": {"admin": True, "role": "admin"},
        "auth_type": "local", "tenants": [], "password_hash": "x",
    }}


def _seed_tenant_admin_user(uid="tadm2", tenants=("acme",)):
    return {uid: {
        "permissions": {"role": "tenant_admin"},
        "auth_type": "local", "tenants": list(tenants), "password_hash": "x",
    }}


def _seed_protected():
    return {"bootstrap": {
        "permissions": {"admin": True, "role": "admin"},
        "auth_type": "local", "tenants": [], "password_hash": "x",
        "protected": True,
    }}


# ── list ─────────────────────────────────────────────────────────────────────
def test_list_own_tenant_users_as_tenant_admin():
    seed = {**_seed_regular(), **{"op2": {
        "permissions": {}, "tenants": ["other"], "password_hash": "x"}}}
    c, hub, holder = _build(seed)
    holder.current = _tenant_admin("acme")
    r = c.get("/api/tenant/acme/users")
    assert r.status_code == 200
    users = r.json()["users"]
    assert "op1" in users and "op2" not in users
    # password hash stripped
    assert "password_hash" not in users["op1"]


def test_list_403_for_plain_cs_user():
    c, hub, holder = _build(_seed_regular())
    holder.current = _plain_cs_user("acme")
    r = c.get("/api/tenant/acme/users")
    assert r.status_code == 403


def test_list_403_for_tenant_admin_other_tenant():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.get("/api/tenant/other/users")
    assert r.status_code == 403


def test_list_any_tenant_as_global_admin():
    seed = {**_seed_regular(), **{"op2": {
        "permissions": {}, "tenants": ["other"], "password_hash": "x"}}}
    c, hub, holder = _build(seed)
    holder.current = _global_admin()
    r = c.get("/api/tenant/other/users")
    assert r.status_code == 200
    assert "op2" in r.json()["users"]


def test_list_401_no_session():
    c, hub, holder = _build(_seed_regular())
    holder.current = None
    r = c.get("/api/tenant/acme/users")
    assert r.status_code == 401


# ── create ───────────────────────────────────────────────────────────────────
def test_create_user_as_tenant_admin():
    c, hub, holder = _build({})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users", json={
        "user_id": "newop", "permissions": {"cs": True, "nw": True},
        "password": "secret123"})
    assert r.status_code == 200
    u = hub.state.system_state["users"]["newop"]
    assert u["tenants"] == ["acme"]
    assert u["permissions"] == {"cs": True, "nw": True}
    assert "password_hash" in u and u["password_hash"] != "secret123"
    assert "admin" not in u["permissions"] and "role" not in u["permissions"]


def test_create_rejects_global_admin_role_escalation():
    c, hub, holder = _build({})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users", json={
        "user_id": "bad", "permissions": {"admin": True}})
    assert r.status_code == 400
    assert "bad" not in hub.state.system_state["users"]


def test_create_rejects_tenant_admin_role_escalation():
    c, hub, holder = _build({})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users", json={
        "user_id": "bad", "permissions": {"tenant_admin": True}})
    assert r.status_code == 400
    assert "bad" not in hub.state.system_state["users"]


def test_create_rejects_duplicate():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users", json={
        "user_id": "op1", "permissions": {"cs": True}})
    assert r.status_code == 409


def test_create_403_for_other_tenant():
    c, hub, holder = _build({})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/other/users", json={
        "user_id": "newop", "permissions": {"cs": True}})
    assert r.status_code == 403


def test_create_strips_non_enforced_keys():
    c, hub, holder = _build({})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users", json={
        "user_id": "newop",
        "permissions": {"cs": True, "bogus_right": True, "admin": False}})
    assert r.status_code == 200
    perms = hub.state.system_state["users"]["newop"]["permissions"]
    assert perms == {"cs": True}  # bogus_right dropped, admin/role absent


# ── edit ─────────────────────────────────────────────────────────────────────
def test_edit_regular_user_as_tenant_admin():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1", json={
        "permissions": {"cs": True, "nw": True}, "password": "newpw"})
    assert r.status_code == 200
    u = hub.state.system_state["users"]["op1"]
    assert u["permissions"] == {"cs": True, "nw": True}
    assert u["tenants"] == ["acme"]  # path tenant retained


def test_edit_user_extending_beyond_owned_tenants_403():
    """A user in acme AND other cannot be edited by an acme-only tenant admin."""
    c, hub, holder = _build(_seed_regular(acme_only=False))
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1", json={"permissions": {"cs": True}})
    assert r.status_code == 403


def test_edit_admin_tier_user_403_for_tenant_admin():
    c, hub, holder = _build(_seed_admin_user("bigadmin"))
    holder.current = _tenant_admin("acme")
    # Put bigadmin in acme so the subset check would pass, then the admin-tier
    # check must still block.
    hub.state.system_state["users"]["bigadmin"]["tenants"] = ["acme"]
    r = c.post("/api/tenant/acme/users/bigadmin", json={"permissions": {"cs": True}})
    assert r.status_code == 403


def test_edit_cannot_grant_admin_role():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1", json={"permissions": {"admin": True}})
    assert r.status_code == 400


def test_edit_protected_user_403():
    c, hub, holder = _build(_seed_protected())
    holder.current = _tenant_admin("acme")
    hub.state.system_state["users"]["bootstrap"]["tenants"] = ["acme"]
    r = c.post("/api/tenant/acme/users/bootstrap", json={"permissions": {"cs": True}})
    assert r.status_code == 403


def test_edit_add_owned_tenant():
    """A tenant admin for acme+beta may add beta to a user who is in acme only."""
    c, hub, holder = _build(_seed_regular())
    holder.current = _sess(role="tenant_admin", tenants=["acme", "beta"],
                           tenant_id="acme", user_id="tadm-ab")
    r = c.post("/api/tenant/acme/users/op1", json={"tenants": ["acme", "beta"]})
    assert r.status_code == 200
    assert set(hub.state.system_state["users"]["op1"]["tenants"]) == {"acme", "beta"}


def test_edit_cannot_add_non_owned_tenant():
    """A tenant admin for acme only: adding 'other' is dropped (intersection)."""
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1", json={"tenants": ["acme", "other"]})
    assert r.status_code == 200
    # 'other' dropped — only owned tenants (acme) retained.
    assert hub.state.system_state["users"]["op1"]["tenants"] == ["acme"]


def test_edit_404_unknown_user():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/nobody", json={"permissions": {"cs": True}})
    assert r.status_code == 404


def test_edit_as_global_admin_can_grant_admin():
    """A Global admin editing via the tenant-scoped route may grant admin
    (it's unconstrained and reuses the /setup normalization)."""
    c, hub, holder = _build(_seed_regular())
    holder.current = _global_admin()
    r = c.post("/api/tenant/acme/users/op1", json={"permissions": {"admin": True}})
    assert r.status_code == 200
    u = hub.state.system_state["users"]["op1"]
    assert u["permissions"].get("admin") is True
    assert u["permissions"].get("role") == "admin"


# ── set-password ─────────────────────────────────────────────────────────────
def test_set_password_as_tenant_admin():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1/set-password", json={"password": "pw1"})
    assert r.status_code == 200
    assert hub.state.system_state["users"]["op1"]["password_hash"] != "x"


def test_set_password_non_member_403():
    """The user is in 'other' only — not a member of acme → 403."""
    c, hub, holder = _build({
        "op1": {"permissions": {}, "tenants": ["other"], "password_hash": "x"}})
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1/set-password", json={"password": "pw1"})
    assert r.status_code == 403


def test_set_password_admin_tier_target_403():
    c, hub, holder = _build(_seed_admin_user("bigadmin"))
    holder.current = _tenant_admin("acme")
    hub.state.system_state["users"]["bigadmin"]["tenants"] = ["acme"]
    r = c.post("/api/tenant/acme/users/bigadmin/set-password", json={"password": "pw1"})
    assert r.status_code == 403


def test_set_password_protected_403():
    c, hub, holder = _build(_seed_protected())
    holder.current = _tenant_admin("acme")
    hub.state.system_state["users"]["bootstrap"]["tenants"] = ["acme"]
    r = c.post("/api/tenant/acme/users/bootstrap/set-password", json={"password": "pw1"})
    assert r.status_code == 403


def test_set_password_empty_400():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.post("/api/tenant/acme/users/op1/set-password", json={"password": ""})
    assert r.status_code == 400


# ── delete (remove from tenant) ───────────────────────────────────────────────
def test_remove_user_from_tenant():
    c, hub, holder = _build(_seed_regular(acme_only=False))
    holder.current = _tenant_admin("acme")
    r = c.request("DELETE", "/api/tenant/acme/users/op1")
    assert r.status_code == 200
    # User survives, minus acme; retains other.
    u = hub.state.system_state["users"]["op1"]
    assert u["tenants"] == ["other"]


def test_remove_user_left_inert_when_no_tenants_remain():
    c, hub, holder = _build(_seed_regular(acme_only=True))
    holder.current = _tenant_admin("acme")
    r = c.request("DELETE", "/api/tenant/acme/users/op1")
    assert r.status_code == 200
    assert hub.state.system_state["users"]["op1"]["tenants"] == []
    assert r.json()["remaining_tenants"] == []


def test_remove_admin_tier_user_403():
    c, hub, holder = _build(_seed_admin_user("bigadmin"))
    holder.current = _tenant_admin("acme")
    hub.state.system_state["users"]["bigadmin"]["tenants"] = ["acme"]
    r = c.request("DELETE", "/api/tenant/acme/users/bigadmin")
    assert r.status_code == 403


def test_remove_protected_403():
    c, hub, holder = _build(_seed_protected())
    holder.current = _tenant_admin("acme")
    hub.state.system_state["users"]["bootstrap"]["tenants"] = ["acme"]
    r = c.request("DELETE", "/api/tenant/acme/users/bootstrap")
    assert r.status_code == 403


def test_remove_404_unknown_user():
    c, hub, holder = _build(_seed_regular())
    holder.current = _tenant_admin("acme")
    r = c.request("DELETE", "/api/tenant/acme/users/nobody")
    assert r.status_code == 404


def test_remove_other_tenant_403():
    """A tenant admin for acme cannot remove a user from 'other'."""
    c, hub, holder = _build({
        "op1": {"permissions": {}, "tenants": ["other"], "password_hash": "x"}})
    holder.current = _tenant_admin("acme")
    r = c.request("DELETE", "/api/tenant/other/users/op1")
    assert r.status_code == 403
    # User untouched.
    assert hub.state.system_state["users"]["op1"]["tenants"] == ["other"]