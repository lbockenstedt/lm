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
from state.manager import StateManager


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
        self.system_state = {"users": {}, "permission_groups": {},
                             "module_metadata": {}, "active_tenant": "default"}
        # tenant_state mirrors StateManager: a dict of tenant_id -> record.
        self.tenant_state = {"tenants": dict(tenants or {})}

    def get_tenant(self, tid):
        return self.tenant_state.get("tenants", {}).get(tid)

    # The real lookup, merge and delete, so another spelling of a stored
    # tenant id names that tenant here as it does on the hub.
    tenant_key = StateManager.tenant_key
    update_tenant = StateManager.update_tenant
    delete_tenant = StateManager.delete_tenant

    def save_state(self):
        return None

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()


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


# ── GET /setup/tenants display-name rename (default → ADMIN) ────────────────
# The built-in 'default' tenant is the global-admin scope and must ALWAYS
# render as 'ADMIN' in the header picker / tenant lists — even when a real
# 'default' record is persisted (which shadows the fallback injection and,
# with name=None, would otherwise fall back to the raw 'default' id).
def test_setup_tenants_persisted_default_renders_as_admin():
    # Persisted 'default' record with a null name (the live-hub condition).
    c, hub, holder = _build({
        "default": {"name": None},
        "acme": {"name": "Acme Corp"},
    })
    holder.current = _global_admin()
    r = c.get("/setup/tenants")
    assert r.status_code == 200
    by_id = {t["id"]: t["name"] for t in r.json()["tenants"]}
    assert by_id["default"] == "ADMIN"
    assert by_id["acme"] == "Acme Corp"


def test_setup_tenants_default_named_default_still_renders_as_admin():
    # Even a stored name of "Default" is overridden to "ADMIN".
    c, hub, holder = _build({"default": {"name": "Default"}})
    holder.current = _global_admin()
    r = c.get("/setup/tenants")
    assert r.status_code == 200
    by_id = {t["id"]: t["name"] for t in r.json()["tenants"]}
    assert by_id["default"] == "ADMIN"


def test_setup_tenants_injects_admin_when_default_absent():
    # Fallback path (no persisted default) still injects the ADMIN label.
    c, hub, holder = _build({"acme": {"name": "Acme Corp"}})
    holder.current = _global_admin()
    r = c.get("/setup/tenants")
    assert r.status_code == 200
    by_id = {t["id"]: t["name"] for t in r.json()["tenants"]}
    assert by_id["default"] == "ADMIN"


def test_setup_tenants_carry_the_hub_tenant_key():
    # Managed Devices matches a tenant record to its spoke bindings by the
    # hub's key, not a JS case fold ("Straße" and "STRASSE" are one tenant).
    c, hub, holder = _build({"Straße": {"name": "Straße GmbH"}})
    holder.current = _global_admin()
    keys = {t["id"]: t["tenant_key"] for t in c.get("/setup/tenants").json()["tenants"]}
    assert keys == {"Straße": "strasse", "default": "default"}


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

# ── DELETE /setup/tenants/{id} ──────────────────────────────────────────────
# The /setup prefix is Global-Admin-gated by the app middleware (not present in
# this route-level harness), so these exercise the route's own guardrails.
def test_delete_tenant_removes_record_and_detaches_users():
    c, hub, holder = _build(_acme_record())
    hub.state.system_state["users"] = {
        "u1": {"tenants": ["acme", "other"]},
        "u2": {"tenants": ["other"]},
    }
    hub.state.system_state["active_tenant"] = "acme"
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/acme")
    assert r.status_code == 200
    assert "acme" not in hub.state.tenant_state["tenants"]
    # User assignments detached; unrelated tenants untouched.
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["other"]
    assert hub.state.system_state["users"]["u2"]["tenants"] == ["other"]
    # Active pointer falls back to default.
    assert hub.state.system_state["active_tenant"] == "default"


def test_delete_default_tenant_rejected():
    c, hub, holder = _build({"default": {"name": "Default"}})
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/default")
    assert r.status_code == 400
    assert "default" in hub.state.tenant_state["tenants"]


def test_delete_unknown_tenant_404():
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/ghost")
    assert r.status_code == 404


def test_delete_tenant_with_bound_spoke_rejected_409():
    c, hub, holder = _build(_acme_record())
    hub.state.system_state["module_metadata"] = {
        "spoke-1": {"tenant_id": "acme", "display_name": "acme-fw"},
    }
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/acme")
    assert r.status_code == 409
    assert "acme-fw" in r.json()["detail"]
    # Tenant NOT removed while a spoke is still bound.
    assert "acme" in hub.state.tenant_state["tenants"]


# ── tenant sharing changes drop the NAC caches ──────────────────────────────
# A cached NAC entry is served without re-resolving its ClearPass, so a write
# that changes which tenant is shared, or a tenant's shared access, must drop
# the NAC caches; a write that changes neither keeps them.
@pytest.fixture
def nac_drops(monkeypatch):
    """Record drop_nac_caches calls and restore the shared-tenant cache after."""
    drops = []
    monkeypatch.setattr(tenants_users, "drop_nac_caches", drops.append)
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", access._SHARED_TENANT_ID)
    monkeypatch.setattr(access, "_GROUP_MEMBERS", access._GROUP_MEMBERS)
    return drops


def test_setup_tenant_drops_nac_caches_only_when_sharing_changes(nac_drops):
    c, hub, holder = _build({**_acme_record(), "beta": {"name": "Beta"}})
    holder.current = _global_admin()
    assert c.post("/setup/tenant", json={"tenant_id": "acme",
                                         "config": {"description": "x"}}).status_code == 200
    assert nac_drops == []
    assert c.post("/setup/tenant", json={"tenant_id": "acme",
                                         "config": {"shared_access": "deny"}}).status_code == 200
    assert nac_drops == [hub]
    assert c.post("/setup/tenant", json={"tenant_id": "beta",
                                         "config": {"shared": True}}).status_code == 200
    assert nac_drops == [hub, hub]


def test_tenant_edit_route_drops_nac_caches_for_a_global_sharing_change(nac_drops):
    c, hub, holder = _build({"beta": {"name": "Beta", "shared": True}, **_acme_record()})
    access.refresh_shared_tenant(hub)
    holder.current = _tenant_admin("acme")
    assert c.post("/api/tenant/acme", json={"config": {"name": "Acme 2"}}).status_code == 200
    assert nac_drops == []
    holder.current = _global_admin()
    assert c.post("/api/tenant/acme", json={"config": {"shared": True}}).status_code == 200
    assert nac_drops == [hub]
    # One shared tenant, as /setup/tenant keeps it: beta's flag is cleared.
    assert hub.state.get_tenant("beta")["shared"] is False
    assert access.shared_tenant_id() == "acme"


def test_delete_tenant_drops_nac_caches(nac_drops):
    c, hub, holder = _build({**_acme_record(), "beta": {"name": "Beta", "shared": True}})
    access.refresh_shared_tenant(hub)
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/beta").status_code == 200
    assert nac_drops == [hub]
    assert access.shared_tenant_id() is None


def test_tenant_group_prune_drops_nac_caches(monkeypatch, nac_drops):
    """The NetBox group sync deletes a group that left NetBox, which may be
    the shared tenant, so it drops the NAC caches; a sync that prunes nothing
    keeps them."""
    import asyncio
    import main
    import routes.cppm as cppm
    monkeypatch.setattr(cppm, "drop_nac_caches", nac_drops.append)
    hub = _Hub({**_acme_record(),
                "group:emea": {"name": "EMEA", "is_tenant_group": True, "shared": True}})
    access.refresh_shared_tenant(hub)
    groups = [{"slug": "emea", "name": "EMEA", "tenant_slugs": ["acme"]}]

    async def _rr(spoke_id, cmd, payload, timeout=None):
        """The NetBox spoke's NETBOX_GET_TENANT_GROUPS reply."""
        return {"payload": {"data": {"status": "SUCCESS", "groups": list(groups)}}}
    hub.request_response = _rr

    asyncio.run(main.LabManagerHub._sync_tenant_groups(hub, "nb-1"))
    assert nac_drops == [] and access.shared_tenant_id() == "group:emea"
    groups.clear()
    asyncio.run(main.LabManagerHub._sync_tenant_groups(hub, "nb-1"))
    assert nac_drops == [hub] and access.shared_tenant_id() is None
    assert "group:emea" not in hub.state.tenant_state["tenants"]
def test_delete_tenant_with_spoke_bound_in_another_case_rejected_409():
    # The access checks match a spoke tag in any case, so "ACME" binds the
    # spoke to "acme" and deleting it would orphan that binding.
    c, hub, holder = _build(_acme_record())
    hub.state.system_state["module_metadata"] = {
        "spoke-1": {"tenant_id": "ACME", "display_name": "acme-fw"},
    }
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/acme")
    assert r.status_code == 409
    assert "acme" in hub.state.tenant_state["tenants"]


def test_delete_tenant_detaches_every_spelling_of_the_grant():
    # Another spelling of the id is the same grant; left behind, it would grant
    # a tenant later re-created under the id.
    c, hub, holder = _build(_acme_record())
    hub.state.system_state["users"] = {"u1": {"tenants": ["ACME", "other"]}}
    hub.state.system_state["active_tenant"] = "Acme"
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/acme").status_code == 200
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["other"]
    assert hub.state.system_state["active_tenant"] == "default"
    # Without a twin left, nothing is kept as retired.
    assert "retired_twin_ids" not in hub.state.tenant_state


def test_delete_tenant_ends_the_sessions_of_users_who_lose_it(monkeypatch, keep_tenant_cache):
    # Each session and API token holds a snapshot of the user's tenants. One
    # still naming "ACME" would reach the per-module records left tagged
    # "ACME", so whoever lost "ACME" is logged out.
    ended = []
    monkeypatch.setattr(tenants_users, "_invalidate_user_sessions",
                        lambda hub, user_id: ended.append(user_id))
    c, hub, holder = _build({"ACME": {"name": "Acme"}, "acme": {"name": "acme"}})
    hub.state.system_state["users"] = {
        "u-upper": {"tenants": ["ACME"]},
        "u-lower": {"tenants": ["acme"], "default_tenant": "acme"},
        "u-other": {"tenants": ["beta"]},
        "admin": {"tenants": [], "default_tenant": "ACME"},
    }
    hub.state.system_state["permission_groups"] = {
        "g1": {"ldap_group": "grp-1", "tenants": ["ACME", "beta"]},
        "g2": {"ldap_group": "grp-2", "tenants": ["acme"]},
    }
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/ACME").status_code == 200
    assert ended == ["u-upper"]
    users = hub.state.system_state["users"]
    assert users["u-upper"]["tenants"] == [] and users["u-lower"]["tenants"] == ["acme"]
    # A saved default that named it is cleared, so it never opens the twin.
    assert "default_tenant" not in users["admin"] and users["u-lower"]["default_tenant"] == "acme"
    # A group drops the grant too, so an Entra login through it can't grant
    # the deleted id again; the twin's grant stays.
    groups = hub.state.system_state["permission_groups"]
    assert groups["g1"]["tenants"] == ["beta"] and groups["g2"]["tenants"] == ["acme"]
    assert access.groups_and_tenants_for_membership(hub, ["grp-1"]) == (["g1"], ["beta"])


def test_tenant_group_prune_ends_the_sessions_of_users_who_lose_it(monkeypatch, keep_tenant_cache):
    """Pruning a tenant group that left NetBox logs out its members, as
    deleting a tenant in Setup does."""
    import asyncio
    import main
    import routes.cppm as cppm
    monkeypatch.setattr(cppm, "drop_nac_caches", lambda hub: None)
    ended = []
    monkeypatch.setattr(main, "_invalidate_user_sessions",
                        lambda hub, user_id: ended.append(user_id))
    hub = _Hub({**_acme_record(), "group:emea": {"name": "EMEA", "is_tenant_group": True}})
    hub.state.system_state["users"] = {"u1": {"tenants": ["group:emea"]},
                                       "u2": {"tenants": ["acme"]}}

    async def _rr(spoke_id, cmd, payload, timeout=None):
        """A NetBox spoke reporting no tenant groups."""
        return {"payload": {"data": {"status": "SUCCESS", "groups": []}}}
    hub.request_response = _rr

    asyncio.run(main.LabManagerHub._sync_tenant_groups(hub, "nb-1"))
    assert "group:emea" not in hub.state.tenant_state["tenants"]
    assert ended == ["u1"]


# ── tenant ids are unique ignoring case ─────────────────────────────────────
# The access checks compare tenant ids in any case, so two stored tenants that
# differ only by case would be one tenant to them: a member of "acme" would
# pass the gates for "ACME".
@pytest.fixture
def keep_tenant_cache(monkeypatch):
    """Restore access's cached tenant data after a route reloads it."""
    for name in ("_SHARED_TENANT_ID", "_GROUP_MEMBERS", "_AMBIGUOUS_TENANT_IDS"):
        monkeypatch.setattr(access, name, getattr(access, name, None), raising=False)


def test_create_refuses_another_spelling_of_a_stored_tenant(keep_tenant_cache):
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    r = c.post("/setup/tenants", json={"tenant_id": "ACME"})
    assert r.status_code == 409
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    # A missing id is the caller's error, not a server error.
    assert c.post("/setup/tenants", json={}).status_code == 400
    # A new tenant is still created.
    assert c.post("/setup/tenants", json={"tenant_id": "beta"}).status_code == 200
    assert set(hub.state.tenant_state["tenants"]) == {"acme", "beta"}


@pytest.mark.parametrize("spelling", ["ACME", "Acme"])
def test_create_names_the_tenant_and_the_deleted_twin_it_clashes_with(keep_tenant_cache,
                                                                      spelling):
    """Before, this clash was reported as "Tenant 'ACME' already exists",
    naming the id the caller typed, which no stored tenant has."""
    c, hub, holder = _build(_acme_record())
    hub.state.tenant_state["retired_twin_ids"] = ["ACME"]
    holder.current = _global_admin()
    r = c.post("/setup/tenants", json={"tenant_id": spelling})
    detail = r.json()["detail"]
    assert r.status_code == 409
    assert "'acme'" in detail and "deleted" in detail and "already exists" not in detail
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}


@pytest.mark.parametrize("spelling", [" acme ", "acme ", " ACME"])
def test_create_refuses_a_padded_spelling_of_a_stored_tenant(keep_tenant_cache, spelling):
    """Surrounding spaces make another spelling too. Before, " acme " passed
    the check (compared stripped), changed nothing and replied "created"."""
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    before = dict(hub.state.tenant_state["tenants"])
    r = c.post("/setup/tenants", json={"tenant_id": spelling})
    assert r.status_code == 409 and "'acme'" in r.json()["detail"]
    assert hub.state.tenant_state["tenants"] == before


def test_create_refuses_another_spelling_of_the_built_in_default(keep_tenant_cache):
    """With no "default" record stored, "Default" is still the built-in Admin
    tenant: create refuses it, and the editor saves into "default"."""
    c, hub, holder = _build({})
    holder.current = _global_admin()
    assert c.post("/setup/tenants", json={"tenant_id": "Default"}).status_code == 409
    assert hub.state.tenant_state["tenants"] == {}
    r = c.post("/setup/tenant", json={"tenant_id": "DEFAULT", "config": {"name": "Admin"}})
    assert r.status_code == 200
    assert hub.state.tenant_state["tenants"] == {"default": {"name": "Admin"}}


def test_netbox_sync_merges_case_variants_and_skips_ambiguous_slugs(keep_tenant_cache):
    c, hub, holder = _build({"ACME": {"name": "A1"}, "acme": {"name": "A2"},
                             "beta": {"name": "B", "quotas": {"vm": 1}}})
    holder.current = _global_admin()
    hub.get_spoke_by_type = lambda module_type: "nb-1" if module_type == "ipam" else None

    async def _reply(spoke_id, command, payload, **kw):
        """NetBox's tenants: one slug matching two stored tenants, one matching one."""
        return {"payload": {"data": {"status": "SUCCESS", "tenants": [
            {"slug": "Acme", "name": "Acme", "id": 1},
            {"slug": "BETA", "name": "Beta", "id": 2}]}}}

    hub.request_response = _reply
    r = c.post("/setup/sync-tenants")
    assert r.status_code == 200, r.text
    assert (r.json()["skipped"], r.json()["updated"], r.json()["added"]) == (["Acme"], ["BETA"], [])
    tenants = hub.state.tenant_state["tenants"]
    # Neither stored acme was touched, and no third spelling was created.
    assert set(tenants) == {"ACME", "acme", "beta"}
    assert tenants["ACME"] == {"name": "A1"} and tenants["acme"] == {"name": "A2"}
    # "BETA" updated the stored "beta" and kept its local quotas.
    assert tenants["beta"]["netbox_id"] == 2 and tenants["beta"]["quotas"] == {"vm": 1}


# ── blank tenant ids ─────────────────────────────────────────────────────────
# A blank id names no tenant, and as a picker selection it would read as no
# selection (access.tenant_scope_ids), so no route stores one as a tenant or a
# grant.
def test_routes_refuse_a_blank_tenant_id(keep_tenant_cache):
    c, hub, holder = _build(_acme_record())
    hub.state.system_state["users"] = {"u1": {"tenants": ["acme"]}}
    holder.current = _global_admin()
    assert c.post("/setup/tenants", json={"tenant_id": "  "}).status_code == 400
    for tid in ("  ", None):
        r = c.post("/setup/tenant", json={"tenant_id": tid, "config": {"name": "X"}})
        assert r.status_code == 400 and r.json()["detail"] == "Missing tenant_id"
    assert c.post("/setup/users/assign-tenant",
                  json={"user_id": "u1", "tenant_id": " "}).status_code == 400
    r = c.post("/setup/users/set-tenants", json={"user_id": "u1", "add": [" ", ""]})
    assert r.status_code == 200 and r.json()["errors"] == ["blank tenant id"] * 2
    # A Global Admin naming a blank path tenant on the tenant-scoped routes.
    assert c.get("/api/tenant/%20/users").status_code == 400
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["acme"]


def test_user_edits_drop_blank_tenant_grants(keep_tenant_cache, monkeypatch):
    monkeypatch.setattr(tenants_users, "_invalidate_user_sessions", lambda hub, uid: 0)
    c, hub, holder = _build(_acme_record())
    holder.current = _global_admin()
    r = c.post("/setup/users", json={"user_id": "u2", "tenants": ["acme", " ", ""],
                                     "tenant_id": "  "})
    assert r.status_code == 200, r.text
    assert hub.state.system_state["users"]["u2"]["tenants"] == ["acme"]
    r = c.post("/api/tenant/acme/users/u2", json={"tenants": ["acme", "  "]})
    assert r.status_code == 200, r.text
    assert hub.state.system_state["users"]["u2"]["tenants"] == ["acme"]


# ── a legacy "Default" record beside the built-in default ───────────────────
# The built-in Admin tenant "default" exists without a record and can never be
# deleted. A record spelt "Default" saved beside it is a tenant of its own
# (access._case_collisions), so it can be, by its exact id.
def test_delete_a_legacy_Default_record_but_never_the_built_in(keep_tenant_cache):
    c, hub, holder = _build({"Default": {"name": "Old"}, "acme": {}})
    hub.state.system_state["users"] = {
        "u1": {"tenants": ["default", "Default", "DEFAULT", "acme"]}}
    hub.state.system_state["module_metadata"] = {
        "spoke-1": {"tenant_id": "default", "display_name": "admin-fw"}}
    access.refresh_shared_tenant(hub)
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/default").status_code == 400
    # A third spelling cannot pick between them.
    assert c.delete("/setup/tenants/DEFAULT").status_code == 409
    # The built-in tenant's spoke does not block deleting the record ...
    assert c.delete("/setup/tenants/Default").status_code == 200
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    # ... and the built-in tenant's own grant stays, while "DEFAULT" (which
    # named neither while both existed) does not come to name it.
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["default", "acme"]
    # Records left tagged "Default" never come to name the built-in tenant.
    assert hub.state.tenant_state["retired_twin_ids"] == ["Default"]
    assert not access.same_tenant("Default", "default")


def test_delete_a_legacy_blank_tenant_record_by_its_exact_id(keep_tenant_cache):
    # Saved before blank ids were refused. An unassigned spoke is not bound to it.
    c, hub, holder = _build({" ": {"name": "Blank"}, "acme": {}})
    hub.state.system_state["users"] = {"u1": {"tenants": [" ", "acme"]}}
    hub.state.system_state["module_metadata"] = {
        "s-1": {"tenant_id": "", "display_name": "unassigned-fw"}}
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/%20%20").status_code == 404
    assert c.delete("/setup/tenants/%20").status_code == 200
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["acme"]


def test_deleting_one_twin_keeps_the_other_and_refuses_unplaceable_tags(keep_tenant_cache):
    # "ACME" and "acme" were both saved before ids were kept unique. A spoke
    # tagged "Acme" names neither; deleting one twin would move it into the
    # other, so it must be re-bound first.
    c, hub, holder = _build({"ACME": {}, "acme": {}})
    hub.state.system_state["users"] = {"u1": {"tenants": ["ACME", "acme", "Acme"]}}
    hub.state.system_state["module_metadata"] = {
        "s-1": {"tenant_id": "acme", "display_name": "twin-fw"},
        "s-2": {"tenant_id": "Acme", "display_name": "loose-fw"}}
    access.refresh_shared_tenant(hub)
    holder.current = _global_admin()
    r = c.delete("/setup/tenants/ACME")
    assert r.status_code == 409 and "loose-fw" in r.json()["detail"]
    assert "twin-fw" not in r.json()["detail"]
    del hub.state.system_state["module_metadata"]["s-2"]
    assert c.delete("/setup/tenants/ACME").status_code == 200
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    assert hub.state.system_state["users"]["u1"]["tenants"] == ["acme"]


def test_a_deleted_twins_id_stays_retired(keep_tenant_cache):
    """Per-module records tagged "ACME" stay in place when the twin "ACME" is
    deleted, so its id is kept as retired and still told apart from the
    surviving "acme": those records never come to name "acme", and no other
    spelling names "acme" either. A repeated delete is refused rather than
    deleting the survivor, a sync push for "ACME" goes nowhere, and a group
    grant spelt "ACME" grants neither."""
    c, hub, holder = _build({"ACME": {}, "acme": {}})
    holder.current = _global_admin()
    assert c.delete("/setup/tenants/ACME").status_code == 200
    assert hub.state.tenant_state["retired_twin_ids"] == ["ACME"]
    assert not access.tenant_among("ACME", ["acme"])
    assert access.tenant_among("acme", ["acme"])
    for spelling in ("ACME", "Acme"):
        assert c.delete(f"/setup/tenants/{spelling}").status_code == 409
    assert set(hub.state.tenant_state["tenants"]) == {"acme"}
    assert access.push_tenant_key(hub, "ACME") == ""
    r = c.post("/setup/groups", json={"name": "Ops", "tenants": ["ACME", "acme"]})
    assert r.status_code == 200
    assert hub.state.system_state["permission_groups"][r.json()["group_id"]]["tenants"] == ["acme"]
    # Recomputed from the saved tenant state alone, as after a restart.
    access._AMBIGUOUS_TENANT_IDS = frozenset()
    access.refresh_shared_tenant(hub)
    assert not access.tenant_among("ACME", ["acme"])


def test_group_grants_each_tenant_by_its_stored_id(monkeypatch):
    """A group's tenant list stores each tenant's own id: " ACME " is the
    legacy twin itself (not stripped into "ACME"), "acme" names both twins
    and so grants neither, "other" names "Other", and an unknown id is
    dropped."""
    monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS", frozenset({"acme"}))
    c, hub, holder = _build({"ACME": {}, " ACME ": {}, "Other": {}})
    holder.current = _global_admin()
    r = c.post("/setup/groups", json={"name": "Ops",
                                      "tenants": [" ACME ", "acme", "other", "ghost", " ACME "]})
    assert r.status_code == 200
    gid = r.json()["group_id"]
    assert hub.state.system_state["permission_groups"][gid]["tenants"] == [" ACME ", "Other"]
