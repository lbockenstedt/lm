"""A user can pick the tenant LM opens on (``PUT /auth/default-tenant``).

The choice is saved on the user's record, returned by ``/auth/me`` and login,
and only honoured while the tenant exists and the user may still view it.
"""
import api as api_mod
from test_auth_session_security import (  # noqa: F401 — _isolate is an autouse fixture
    _admin_user, _build, _isolate, _mint_session,
)


def _client(tmp_path, users):
    c, hub = _build(users, tmp_path)
    hub.state.tenant_state = {"tenants": {"acme": {"name": "Acme"}, "globex": {"name": "Globex"}}}
    return c, hub


def _tenant_user(tenants):
    return {"auth_type": "local", "permissions": {"ipam": True}, "tenants": tenants}


def _mint_tenant_session(hub, uid, tenants):
    return api_mod._record_session(hub, {
        "user_id": uid, "auth_type": "local", "permissions": {"ipam": True},
        "tenants": tenants, "tenant_id": tenants[0], "protected": False})


def test_user_sets_and_clears_their_default_tenant(tmp_path):
    c, hub = _client(tmp_path, {"bob": _tenant_user(["acme", "globex"])})
    tok = _mint_tenant_session(hub, "bob", hub.state.system_state["users"]["bob"]["tenants"])
    r = c.put("/auth/default-tenant", json={"tenant_id": "globex"}, cookies={"lm_session": tok})
    assert r.status_code == 200 and r.json()["default_tenant"] == "globex"
    assert hub.state.system_state["users"]["bob"]["default_tenant"] == "globex"
    assert c.get("/auth/me", cookies={"lm_session": tok}).json()["default_tenant"] == "globex"

    r = c.put("/auth/default-tenant", json={"tenant_id": None}, cookies={"lm_session": tok})
    assert r.json()["default_tenant"] is None
    assert "default_tenant" not in hub.state.system_state["users"]["bob"]
    assert c.get("/auth/me", cookies={"lm_session": tok}).json()["default_tenant"] is None


def test_user_cannot_default_to_a_tenant_they_cannot_view(tmp_path):
    c, hub = _client(tmp_path, {"bob": _tenant_user(["acme"])})
    tok = _mint_tenant_session(hub, "bob", hub.state.system_state["users"]["bob"]["tenants"])
    r = c.put("/auth/default-tenant", json={"tenant_id": "globex"}, cookies={"lm_session": tok})
    assert r.status_code == 403
    assert "default_tenant" not in hub.state.system_state["users"]["bob"]


def test_unknown_tenant_is_refused(tmp_path):
    c, hub = _client(tmp_path, {"admin": _admin_user()})
    tok = _mint_session(hub, "admin")
    r = c.put("/auth/default-tenant", json={"tenant_id": "nope"}, cookies={"lm_session": tok})
    assert r.status_code == 404


def test_admin_may_default_to_any_tenant_or_the_admin_scope(tmp_path):
    c, hub = _client(tmp_path, {"admin": _admin_user()})
    tok = _mint_session(hub, "admin")
    for tenant in ("acme", "default"):
        r = c.put("/auth/default-tenant", json={"tenant_id": tenant}, cookies={"lm_session": tok})
        assert r.status_code == 200 and r.json()["default_tenant"] == tenant


def test_requires_sign_in(tmp_path):
    c, _ = _client(tmp_path, {})
    assert c.put("/auth/default-tenant", json={"tenant_id": "acme"}).status_code == 401


def test_stale_default_is_not_returned(tmp_path):
    user = {**_tenant_user(["acme"]), "default_tenant": "globex"}   # access since removed
    c, hub = _client(tmp_path, {"bob": user})
    tok = _mint_tenant_session(hub, "bob", hub.state.system_state["users"]["bob"]["tenants"])
    assert c.get("/auth/me", cookies={"lm_session": tok}).json()["default_tenant"] is None

    hub.state.system_state["users"]["bob"]["default_tenant"] = "acme"
    assert c.get("/auth/me", cookies={"lm_session": tok}).json()["default_tenant"] == "acme"
    del hub.state.tenant_state["tenants"]["acme"]                    # tenant deleted
    assert c.get("/auth/me", cookies={"lm_session": tok}).json()["default_tenant"] is None


def test_login_returns_the_default_tenant(tmp_path):
    c, hub = _client(tmp_path, {"admin": {**_admin_user(), "default_tenant": "acme"}})
    r = c.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200 and r.json()["default_tenant"] == "acme"
