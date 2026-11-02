"""Global Admins can impersonate another registered user and switch back."""
import api as api_mod
from test_auth_session_security import (  # noqa: F401 — _isolate is an autouse fixture
    _admin_user, _build, _isolate, _mint_session,
)


def _bob(**perms):
    return {"auth_type": "local", "permissions": {"ipam": True, **perms},
            "tenants": ["acme"], "name": "Bob Builder"}


def _client(tmp_path, bob=None):
    c, hub = _build({"admin": _admin_user(), "bob": bob or _bob()}, tmp_path)
    hub.state.tenant_state = {"tenants": {"acme": {"name": "Acme"}}}
    return c, hub


def test_admin_impersonates_a_user_and_stops(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "admin"))

    r = c.post("/auth/impersonate", json={"user_id": "bob"})
    assert r.status_code == 200
    me = c.get("/auth/me").json()
    assert me["user_id"] == "bob" and me["tenants"] == ["acme"]
    assert not me["permissions"].get("admin")
    assert me["impersonator"]["user_id"] == "admin"
    assert c.get("/setup/users").status_code == 403

    assert c.post("/auth/impersonate/stop").status_code == 200
    me = c.get("/auth/me").json()
    assert me["user_id"] == "admin" and "impersonator" not in me
    assert c.get("/setup/users").status_code == 200


def test_non_admin_cannot_impersonate(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "bob", perms={"ipam": True}))
    assert c.post("/auth/impersonate", json={"user_id": "admin"}).status_code == 403


def test_unknown_or_self_target_is_refused(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "admin"))
    assert c.post("/auth/impersonate", json={"user_id": "nobody"}).status_code == 404
    assert c.post("/auth/impersonate", json={"user_id": "admin"}).status_code == 400


def test_no_api_tokens_or_nesting_while_impersonating(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "admin"))
    c.post("/auth/impersonate", json={"user_id": "bob"})
    assert c.post("/auth/token", json={}).status_code == 403
    assert c.post("/auth/impersonate", json={"user_id": "bob"}).status_code == 409


def test_read_only_target_can_still_stop(tmp_path):
    c, hub = _client(tmp_path, bob=_bob(read_only=True))
    c.cookies.set("lm_session", _mint_session(hub, "admin"))
    c.post("/auth/impersonate", json={"user_id": "bob"})
    assert c.post("/auth/impersonate/stop").status_code == 200


def test_target_session_revocation_returns_admin_to_own_identity(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "admin"))
    c.post("/auth/impersonate", json={"user_id": "bob"})
    api_mod._invalidate_user_sessions(hub, "bob")
    me = c.get("/auth/me").json()
    assert me["user_id"] == "admin" and "impersonator" not in me


def test_admin_revocation_ends_the_impersonating_session(tmp_path):
    c, hub = _client(tmp_path)
    c.cookies.set("lm_session", _mint_session(hub, "admin"))
    c.post("/auth/impersonate", json={"user_id": "bob"})
    api_mod._invalidate_user_sessions(hub, "admin")
    assert c.get("/auth/me").status_code == 401
