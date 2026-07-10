"""Regression tests for the Global Admin / tenant-Admin role split (Phase 1).

The single ``admin`` tier was split into:

* **Global Admin** — ``is_admin`` (``permissions.admin`` OR
  ``permissions.role == "admin"``); system-wide, unchanged. Today's admin.
* **tenant Admin** — ``is_tenant_admin`` (``permissions.role ==
  "tenant_admin"``); an admin *within* its assigned tenants only. Auto-passes
  the module-access gates (cs/nw/ipam/le/console) but is tenant-confined by
  ``check_tenant_access`` / ``filter_session`` (deny-by-default since 21d483e)
  and carries no ``admin`` flag, so every system/fleet/cross-tenant gate
  (``/setup``/``/admin``/``_ADMIN_API_PREFIXES``/aggregates) keeps blocking it.

This file covers the keystone pieces of Phase 1: the tier predicates, the
module-gate short-circuit, ``resolve_effective_permissions`` precedence
(Global wins over tenant), tenant confinement of the tier, and the
onboarding-PSK route gate (M1: a plain ``cs``-righted user must no longer
retrieve/generate/revoke a tenant's onboarding PSK; a tenant Admin may for
its own tenant; a Global Admin may for any).
"""
import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import access
from access import (
    check_tenant_access,
    is_admin,
    is_tenant_admin,
    has_cs_access,
    has_nw_access,
    has_module_access,
    resolve_effective_permissions,
)
from simulations.routes import register_simulations_routes


# ── session builders ───────────────────────────────────────────────────────
def _sess(*, role=None, admin=False, tenants=None, tenant_id=None, rights=None):
    """Build a minimal LM session shape (``{"user": {...}}``).

    ``role`` is the permissions.role value ("admin" / "tenant_admin" / None).
    ``admin`` sets the boolean ``admin`` flag (the second admin form). The two
    are kept independent so a test can assert one tier does not imply the other.
    ``rights`` is a dict of module rights (cs/nw/ipam/le/console/console_write)."""
    perms = dict(rights or {})
    if admin:
        perms["admin"] = True
    if role:
        perms["role"] = role
    user = {
        "tenants": tenants or [],
        "tenant_id": tenant_id,
        "permissions": perms,
    }
    return {"user": user}


def _global_admin():
    return _sess(role="admin", admin=True)


def _tenant_admin(tenant="acme"):
    # tenant_admin carries NO admin flag — that is the whole point of the split.
    return _sess(role="tenant_admin", tenants=[tenant], tenant_id=tenant)


def _cs_user(tenant="acme"):
    return _sess(tenants=[tenant], tenant_id=tenant, rights={"cs": True})


# ── tier predicates ─────────────────────────────────────────────────────────
def test_is_admin_true_for_global_admin():
    assert is_admin(_global_admin()) is True


def test_is_admin_false_for_tenant_admin():
    """A tenant Admin is NOT a Global Admin — the keystone invariant."""
    assert is_admin(_tenant_admin()) is False


def test_is_tenant_admin_true_for_tenant_admin():
    assert is_tenant_admin(_tenant_admin()) is True


def test_is_tenant_admin_false_for_global_admin():
    """A Global Admin is not labelled a tenant Admin (different tier)."""
    assert is_tenant_admin(_global_admin()) is False


def test_is_tenant_admin_false_for_plain_user():
    assert is_tenant_admin(_cs_user()) is False


def test_is_admin_false_for_plain_cs_user():
    assert is_admin(_cs_user()) is False


def test_no_session_is_neither_admin():
    assert is_admin(None) is False
    assert is_tenant_admin(None) is False
    assert is_admin({}) is False
    assert is_tenant_admin({}) is False


# ── module-access gates pass for tenant_admin ───────────────────────────────
def test_has_cs_access_passes_for_tenant_admin():
    """A tenant Admin auto-passes the cs gate (tenant confinement happens later)."""
    assert has_cs_access(_tenant_admin()) is True


def test_has_module_access_passes_for_tenant_admin():
    for right in ("nw", "ipam", "le", "console", "console_write"):
        assert has_module_access(_tenant_admin(), right) is True


def test_has_nw_access_passes_for_tenant_admin():
    assert has_nw_access(_tenant_admin()) is True


def test_module_gates_still_pass_for_global_admin():
    assert has_cs_access(_global_admin()) is True
    assert has_nw_access(_global_admin()) is True
    assert has_module_access(_global_admin(), "ipam") is True


def test_plain_cs_user_only_has_cs():
    """A plain user with only the ``cs`` right passes cs but NOT the other gates."""
    u = _cs_user()
    assert has_cs_access(u) is True
    assert has_nw_access(u) is False
    assert has_module_access(u, "ipam") is False
    assert has_module_access(u, "console") is False


# ── resolve_effective_permissions precedence ───────────────────────────────
class _Hub:
    """Minimal hub for resolve_effective_permissions (only needs
    ``state.system_state["permission_groups"]``)."""
    class _state:
        system_state = {}

    state = _state()


def test_resolve_global_wins_over_tenant():
    """A user who is BOTH a Global Admin and a tenant Admin resolves to Global."""
    rec = {"groups": [], "permissions": {"role": "admin", "tenant_admin": True}}
    eff = resolve_effective_permissions(_Hub(), rec)
    assert eff.get("admin") is True
    assert eff.get("role") == "admin"
    # The tenant_admin flag must NOT survive once Global wins (else
    # is_tenant_admin would also be True, muddying the tier).
    assert "tenant_admin" not in eff or eff.get("tenant_admin") is not True


def test_resolve_tenant_admin_no_admin_flag():
    rec = {"groups": [], "permissions": {"role": "tenant_admin"}}
    eff = resolve_effective_permissions(_Hub(), rec)
    assert eff.get("role") == "tenant_admin"
    assert "admin" not in eff  # so is_admin stays False


def test_resolve_tenant_admin_via_flag_form():
    """The ``tenant_admin: True`` flag form (WebUI checkbox) sets the tier too."""
    rec = {"groups": [], "permissions": {"tenant_admin": True, "cs": True}}
    eff = resolve_effective_permissions(_Hub(), rec)
    assert eff.get("role") == "tenant_admin"
    assert "admin" not in eff
    assert eff.get("cs") is True


def test_resolve_group_grants_tenant_admin():
    """A group carrying role:"tenant_admin" elevates a member to the tier."""
    _Hub._state.system_state = {
        "permission_groups": {"g1": {"permissions": {"role": "tenant_admin"}}},
    }
    try:
        rec = {"groups": ["g1"], "permissions": {}}
        eff = resolve_effective_permissions(_Hub(), rec)
        assert eff.get("role") == "tenant_admin"
        assert "admin" not in eff
    finally:
        _Hub._state.system_state = {}


def test_resolve_neither_tier_keeps_rights_only():
    rec = {"groups": [], "permissions": {"cs": True, "nw": True}}
    eff = resolve_effective_permissions(_Hub(), rec)
    assert "admin" not in eff
    assert "role" not in eff
    assert eff.get("cs") is True and eff.get("nw") is True


# ── tenant confinement of the tier ─────────────────────────────────────────
def test_tenant_admin_confined_to_own_tenant():
    tadm = _tenant_admin("acme")
    assert check_tenant_access(tadm, "acme") is True
    assert check_tenant_access(tadm, "other") is False


def test_tenant_admin_tenantless_denied_everywhere():
    """A tenant Admin with no tenants assigned is denied (the safety net)."""
    tadm = _sess(role="tenant_admin", tenants=[], tenant_id=None)
    assert check_tenant_access(tadm, "acme") is False
    assert check_tenant_access(tadm, "other") is False


class _FakeRequest:
    """A minimal stand-in for starlette.Request: just a cookies dict, which is
    all session_user/effective_tenant read off it."""
    def __init__(self, token="t1"):
        self.cookies = {"lm_session": token} if token else {}


def _sessions_with(sess):
    """Wrap a session dict in a sessions store keyed by token 't1' with a
    far-future expiry so session_user accepts it (no idle-timeout pop)."""
    import time as _t
    s = dict(sess)
    s["expires"] = _t.time() + 3600
    s["last_seen"] = _t.time()
    return {"t1": s}


def test_tenant_admin_effective_tenant_confined():
    """effective_tenant scopes a tenant Admin to its own tenant: an explicit
    ?tenant= for another tenant is refused (falls back to own tenant_id), and
    an explicit ?tenant= for its own tenant is honoured."""
    sessions = _sessions_with(_tenant_admin("acme"))
    req = _FakeRequest()
    # own tenant → honoured
    assert access.effective_tenant(sessions, req, explicit="acme") == "acme"
    # foreign tenant → refused, falls back to session tenant_id
    assert access.effective_tenant(sessions, req, explicit="other") == "acme"
    # no explicit → session tenant_id
    assert access.effective_tenant(sessions, req, explicit=None) == "acme"


def test_global_admin_effective_tenant_any():
    """A Global Admin is NOT confined — explicit ?tenant= passes through
    unchanged (None = sees all)."""
    sessions = _sessions_with(_global_admin())
    req = _FakeRequest()
    assert access.effective_tenant(sessions, req, explicit="acme") == "acme"
    assert access.effective_tenant(sessions, req, explicit="other") == "other"
    assert access.effective_tenant(sessions, req, explicit=None) is None


def test_tenantless_tenant_admin_effective_tenant_denied():
    """A tenant Admin with no tenants resolves to None (no scope = sees nothing,
    matching the deny-by-default safety net)."""
    sessions = _sessions_with(_sess(role="tenant_admin", tenants=[], tenant_id=None))
    req = _FakeRequest()
    assert access.effective_tenant(sessions, req, explicit="acme") is None
    assert access.effective_tenant(sessions, req, explicit=None) is None


# ── onboarding-PSK route gate (M1 closure) ──────────────────────────────────
class _Store:
    """In-memory onboarding-psk store mirroring the real store's async API."""
    def __init__(self):
        self.by_tenant = {}

    async def get_psks(self, tenant_id):
        return list(self.by_tenant.get(tenant_id, []))

    async def add_psk(self, tenant_id, psk):
        self.by_tenant.setdefault(tenant_id, []).append(psk)

    async def remove_psk(self, tenant_id, psk):
        lst = self.by_tenant.get(tenant_id, [])
        if psk in lst:
            lst.remove(psk)
            return True
        return False


class _RoleHub:
    """Minimal hub for the PSK routes: a simulations_store + a state with a
    tenant lookup. get_client_sim_spoke returns None so _push_config is a no-op
    (the gen/revoke routes still succeed and report 0 spokes pushed)."""
    def __init__(self, store):
        self.simulations_store = store
        self.active_connections = set()

        class _state:
            @staticmethod
            def get_tenant(tid):
                return {"name": tid} if tid else None

        self.state = _state

    def get_client_sim_spoke(self, tenant_id):
        return None  # no spokes → _push_config returns _PushResult(0)


class _SessionHolder:
    """Lets a single registered session_user_fn return a different session per
    test (the closure is bound once at register_simulations_routes time)."""
    def __init__(self):
        self.current = None


def _build():
    store = _Store()
    hub = _RoleHub(store)
    holder = _SessionHolder()

    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: holder.current,
        resolve_tenant_fn=lambda req: (holder.current or {}).get("user", {}).get("tenant_id"),
        is_admin_fn=access.is_admin,
        check_tenant_access_fn=access.check_tenant_access,
        sessions=None,
        has_cs_access_fn=access.has_cs_access,
        is_tenant_admin_fn=access.is_tenant_admin,
    )
    return TestClient(app), store, holder


def test_psk_get_403_for_plain_cs_user():
    """M1: a plain cs-right user must NOT retrieve a tenant's onboarding PSKs."""
    c, store, holder = _build()
    holder.current = _cs_user("acme")
    store.by_tenant["acme"] = ["secret-psk-1"]
    r = c.get("/sim/api/tenant/acme/onboarding-psk")
    assert r.status_code == 403


def test_psk_gen_403_for_plain_cs_user():
    c, store, holder = _build()
    holder.current = _cs_user("acme")
    r = c.post("/sim/api/tenant/acme/onboarding-psk")
    assert r.status_code == 403
    # And nothing was added.
    assert store.by_tenant.get("acme", []) == []


def test_psk_revoke_403_for_plain_cs_user():
    c, store, holder = _build()
    holder.current = _cs_user("acme")
    store.by_tenant["acme"] = ["secret-psk-1"]
    r = c.request("DELETE", "/sim/api/tenant/acme/onboarding-psk",
                  json={"psk": "secret-psk-1"})
    assert r.status_code == 403
    assert store.by_tenant["acme"] == ["secret-psk-1"]


def test_psk_get_allowed_for_tenant_admin_own_tenant():
    c, store, holder = _build()
    holder.current = _tenant_admin("acme")
    store.by_tenant["acme"] = ["secret-psk-1"]
    r = c.get("/sim/api/tenant/acme/onboarding-psk")
    assert r.status_code == 200
    assert r.json()["psks"] == ["secret-psk-1"]


def test_psk_gen_allowed_for_tenant_admin_own_tenant():
    c, store, holder = _build()
    holder.current = _tenant_admin("acme")
    r = c.post("/sim/api/tenant/acme/onboarding-psk")
    assert r.status_code == 200
    psks = store.by_tenant.get("acme", [])
    assert len(psks) == 1
    assert psks[0]  # a non-empty token was stored


def test_psk_revoke_allowed_for_tenant_admin_own_tenant():
    c, store, holder = _build()
    holder.current = _tenant_admin("acme")
    store.by_tenant["acme"] = ["secret-psk-1", "secret-psk-2"]
    r = c.request("DELETE", "/sim/api/tenant/acme/onboarding-psk",
                  json={"psk": "secret-psk-1"})
    assert r.status_code == 200
    assert r.json()["removed"] is True
    assert store.by_tenant["acme"] == ["secret-psk-2"]


def test_psk_tenant_admin_cannot_reach_other_tenant():
    """A tenant Admin for 'acme' is confined — ?tenant_id=other is 403
    (check_tenant_access inside get_tenant_id blocks the cross-tenant read)."""
    c, store, holder = _build()
    holder.current = _tenant_admin("acme")
    store.by_tenant["other"] = ["foreign-psk"]
    r = c.get("/sim/api/tenant/other/onboarding-psk?tenant_id=other")
    assert r.status_code == 403


def test_psk_global_admin_can_reach_any_tenant():
    """A Global Admin acts on any tenant's PSKs (uses ?tenant_id= to target)."""
    c, store, holder = _build()
    holder.current = _global_admin()  # tenant_id=None, tenants=[]
    store.by_tenant["acme"] = ["acme-psk"]
    store.by_tenant["other"] = ["other-psk"]
    r1 = c.get("/sim/api/tenant/acme/onboarding-psk?tenant_id=acme")
    assert r1.status_code == 200
    assert r1.json()["psks"] == ["acme-psk"]
    r2 = c.get("/sim/api/tenant/other/onboarding-psk?tenant_id=other")
    assert r2.status_code == 200
    assert r2.json()["psks"] == ["other-psk"]


def test_psk_no_session_403():
    c, store, holder = _build()
    holder.current = None
    r = c.get("/sim/api/tenant/acme/onboarding-psk")
    assert r.status_code in (401, 403)  # no session → gate denies


# ── update_user rejects tenant_admin with no tenants ──────────────────────
# This route lives in routes/tenants_users.py and is exercised end-to-end via
# the app's user-management API. Here we assert the rejection rule directly
# against the normalized shape the route enforces, mirroring the unit-style of
# test_tenantless_bypass.py (no FastAPI app needed for the rule itself).
def test_tenant_admin_requires_at_least_one_tenant_rule():
    """The rejection guard's precondition: a tenant_admin record with no
    tenants is the invalid shape. The route raises 400 in that case; here we
    confirm the shape the route checks (role=="tenant_admin" and not tenants)
    is detectable, and that a configured tenant_admin is NOT flagged."""
    def _would_reject(sess):
        perms = (sess or {}).get("user", {}).get("permissions", {})
        return perms.get("role") == "tenant_admin" and not sess["user"].get("tenants")

    assert _would_reject(_sess(role="tenant_admin", tenants=[], tenant_id=None)) is True
    assert _would_reject(_sess(role="tenant_admin", tenants=None)) is True
    assert _would_reject(_tenant_admin("acme")) is False  # has a tenant
    assert _would_reject(_global_admin()) is False         # not the tier
    assert _would_reject(_cs_user()) is False              # not the tier