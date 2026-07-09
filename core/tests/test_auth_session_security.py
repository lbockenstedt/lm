"""WebUI auth/session security regressions (item 12).

Covers the seven fixes through the real ``create_app`` stack (FastAPI
``TestClient``) plus targeted unit tests for the pure helpers:

  1. Login rate limiting — failed-attempt lockout (429 + Retry-After) + the
     per-IP spray window; a successful login clears the username's counters.
  2. First-run setup token (install flag) — ``LM_SETUP_TOKEN`` gates
     ``POST /auth/setup`` via ``X-Setup-Token``; absent env = open first run.
  3. Secure cookie flag + HSTS — ``lm_session`` carries ``Secure`` and responses
     carry ``Strict-Transport-Security`` when the hub serves TLS; both off on
     plaintext.
  4. ``LM_CORS_ORIGINS`` — credentialed cross-origin is opt-in only; default
     (unset) reflects no Origin (no wildcard+credentials).
  5. Session invalidation on privilege/password/tenant/user change.
  6. Idle timeout (``LM_SESSION_IDLE_TIMEOUT_S``) + per-user session cap
     (``LM_MAX_SESSIONS_PER_USER``).
  7. ``/admin/sessions`` exposes a non-secret ``sid`` (not the cookie prefix)
     and revocation matches by ``sid``.
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import api as api_mod
import access as access_mod
from access import session_user  # noqa: E402


# ── Fakes ────────────────────────────────────────────────────────────────────

class _FakeState:
    def __init__(self, data_dir, system_state=None):
        self.data_dir = data_dir
        self.system_state = system_state or {}

    def ensure_admin_lockout(self):
        return False

    def save_state(self):
        pass

    def get_tenant(self, tid):
        return None


class _FakeHub:
    def __init__(self, data_dir, system_state=None):
        self.state = _FakeState(data_dir, system_state)
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = set()


def _ensure_loop():
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Per-test clean slate for the module-global session/lockout stores and
    the env knobs the security code reads."""
    api_mod._sessions.clear()
    api_mod._login_attempts.clear()
    api_mod._login_ip_attempts.clear()
    for v in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_CORS_ORIGINS", "LM_SETUP_TOKEN",
              "LM_COOKIE_SECURE", "LM_MAX_SESSIONS_PER_USER",
              "LM_SESSION_IDLE_TIMEOUT_S", "LM_LOGIN_MAX_FAILS",
              "LM_LOGIN_IP_MAX", "LM_LOGIN_IP_WINDOW_S"):
        monkeypatch.delenv(v, raising=False)


def _build(users=None, tmp_path=None, extra_state=None):
    import tempfile
    tmp = tmp_path or tempfile.mkdtemp()
    _ensure_loop()
    sys_state = {"users": users or {}}
    if extra_state:
        sys_state.update(extra_state)
    hub = _FakeHub(tmp, sys_state)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


def _admin_user(uid="admin", password="pass1234"):
    return {
        "auth_type": "local",
        "password_hash": api_mod._hash_password(password),
        "permissions": {"role": "admin", "admin": True},
        "tenants": [],
        "protected": False,
    }


def _mint_session(hub, uid="admin", perms=None, last_seen=None):
    """Drop a live admin session straight into the store (bypass login)."""
    user_data = {"user_id": uid, "auth_type": "local",
                 "permissions": perms or {"role": "admin", "admin": True},
                 "tenants": [], "tenant_id": None, "protected": False}
    token = api_mod._record_session(hub, user_data)
    if last_seen is not None:
        api_mod._sessions[token]["last_seen"] = last_seen
    return token


class _Req:
    """Minimal stand-in for Starlette Request with a cookie jar."""
    def __init__(self, cookie=None):
        self._cookie = cookie
        self.cookies = {"lm_session": cookie} if cookie else {}

    def cookies_get(self, key):
        return self.cookies.get(key)


# ── 1. Login rate limiting ───────────────────────────────────────────────────

def test_login_lockout_after_max_failures(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_LOGIN_MAX_FAILS", "5")
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    for i in range(5):
        r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
        assert r.status_code == 401, f"attempt {i+1} should be 401, got {r.status_code}"
    # 6th attempt is locked out before the password check.
    r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 429
    assert "Retry-After" in r.headers


def test_login_success_clears_lockout(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_LOGIN_MAX_FAILS", "5")
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    for _ in range(3):
        c.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert "admin" in api_mod._login_attempts
    # Correct password logs in and clears the lockout record.
    r = c.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200
    assert "admin" not in api_mod._login_attempts


def test_login_does_not_leak_username_existence(tmp_path):
    """No-such-user and wrong-password both return the same 401 message."""
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    r1 = c.post("/auth/login", json={"username": "ghost", "password": "x"})
    r2 = c.post("/auth/login", json={"username": "admin", "password": "x"})
    assert r1.status_code == 401 and r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"] == "Invalid credentials"


# ── 2. First-run setup token (install flag) ──────────────────────────────────

def test_setup_requires_token_when_env_set(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_SETUP_TOKEN", "install-secret")
    c, hub = _build({}, tmp_path)  # no users → first run
    r = c.post("/auth/setup", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 403
    # Matching header succeeds.
    r = c.post("/auth/setup", json={"username": "admin", "password": "pass1234"},
               headers={"X-Setup-Token": "install-secret"})
    assert r.status_code == 200


def test_setup_open_when_env_unset(tmp_path):
    c, hub = _build({}, tmp_path)
    r = c.post("/auth/setup", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200


def test_setup_403_once_users_exist(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_SETUP_TOKEN", "install-secret")
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    r = c.post("/auth/setup", json={"username": "other", "password": "pass1234"},
               headers={"X-Setup-Token": "install-secret"})
    assert r.status_code == 403  # "Setup already complete"


# ── 3. Secure cookie + HSTS ──────────────────────────────────────────────────

def test_secure_cookie_and_hsts_when_tls(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_TLS_CERT", "/etc/ssl/hub.crt")
    monkeypatch.setenv("LM_TLS_KEY", "/etc/ssl/hub.key")
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    r = c.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200
    sc = r.headers.get("set-cookie", "")
    assert "Secure" in sc
    # HSTS on a public response.
    s = c.get("/status")
    assert "strict-transport-security" in {k.lower() for k in s.headers}


def test_no_secure_cookie_no_hsts_on_plaintext(tmp_path):
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    r = c.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    sc = r.headers.get("set-cookie", "")
    assert "Secure" not in sc
    s = c.get("/status")
    assert "strict-transport-security" not in {k.lower() for k in s.headers}


def test_cookie_secure_env_override(monkeypatch, tmp_path):
    """LM_COOKIE_SECURE=1 forces Secure even without LM_TLS_CERT (Azure front-end
    that terminates TLS without forwarding X-Forwarded-Proto)."""
    monkeypatch.setenv("LM_COOKIE_SECURE", "1")
    users = {"admin": _admin_user()}
    c, hub = _build(users, tmp_path)
    r = c.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert "Secure" in r.headers.get("set-cookie", "")


# ── 4. LM_CORS_ORIGINS (no wildcard+credentials) ─────────────────────────────

def test_cors_default_reflects_no_origin(tmp_path):
    c, hub = _build({}, tmp_path)
    r = c.get("/status", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_cors_explicit_origin_reflected(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_CORS_ORIGINS", "https://app.example")
    c, hub = _build({}, tmp_path)
    r = c.get("/status", headers={"Origin": "https://app.example"})
    assert r.headers.get("access-control-allow-origin") == "https://app.example"


def test_cors_unlisted_origin_not_reflected(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_CORS_ORIGINS", "https://app.example")
    c, hub = _build({}, tmp_path)
    r = c.get("/status", headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"


# ── 5. Session invalidation on privilege/password/tenant change ──────────────

def test_invalidate_user_sessions_drops_all(tmp_path):
    c, hub = _build({}, tmp_path)
    t1 = _mint_session(hub, "alice")
    t2 = _mint_session(hub, "alice")
    _mint_session(hub, "bob")
    n = api_mod._invalidate_user_sessions(hub, "alice")
    assert n == 2
    assert t1 not in api_mod._sessions and t2 not in api_mod._sessions
    assert any(s.get("user_id") == "bob" for s in api_mod._sessions.values())


def test_update_user_invalidates_sessions(tmp_path):
    users = {"alice": {"auth_type": "local",
                       "password_hash": api_mod._hash_password("pass1234"),
                       "permissions": {}, "tenants": []}}
    c, hub = _build(users, tmp_path)
    token = _mint_session(hub, "alice",
                          perms={"role": "user"})  # non-admin session for alice
    # An admin edits alice (e.g. grants admin). The admin needs a session too.
    admin_token = _mint_session(hub, "admin")
    r = c.post("/setup/users", json={"user_id": "alice",
                                     "permissions": {"admin": True, "role": "admin"}},
               cookies={"lm_session": admin_token})
    assert r.status_code == 200
    # alice's prior session is revoked.
    assert token not in api_mod._sessions


def test_set_password_invalidates_sessions(tmp_path):
    users = {"alice": {"auth_type": "local",
                       "password_hash": api_mod._hash_password("old1234"),
                       "permissions": {}, "tenants": []}}
    c, hub = _build(users, tmp_path)
    token = _mint_session(hub, "alice", perms={})
    admin_token = _mint_session(hub, "admin")
    r = c.post("/setup/users/alice/set-password", json={"password": "new1234"},
               cookies={"lm_session": admin_token})
    assert r.status_code == 200
    assert token not in api_mod._sessions


def test_delete_user_invalidates_sessions(tmp_path):
    users = {"alice": {"auth_type": "local",
                       "password_hash": api_mod._hash_password("pass1234"),
                       "permissions": {}, "tenants": []}}
    c, hub = _build(users, tmp_path)
    token = _mint_session(hub, "alice", perms={})
    admin_token = _mint_session(hub, "admin")
    r = c.delete("/setup/users/alice", cookies={"lm_session": admin_token})
    assert r.status_code == 200
    assert token not in api_mod._sessions


# ── 6. Idle timeout + per-user session cap ───────────────────────────────────

def test_idle_timeout_expires_inactive_session(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_SESSION_IDLE_TIMEOUT_S", "1800")
    access_mod._SESSION_IDLE_TIMEOUT_S = 1800.0  # env read at import; force live
    try:
        c, hub = _build({}, tmp_path)
        token = _mint_session(hub, "alice", last_seen=time.time() - 3600)
        # /auth/me sees the idle-expired session as no session → 401.
        r = c.get("/auth/me", cookies={"lm_session": token})
        assert r.status_code == 401
        assert token not in api_mod._sessions  # popped on read
    finally:
        access_mod._SESSION_IDLE_TIMEOUT_S = float(
            __import__("os").environ.get("LM_SESSION_IDLE_TIMEOUT_S", "1800"))


def test_idle_timeout_zero_disables(tmp_path):
    access_mod._SESSION_IDLE_TIMEOUT_S = 0.0
    try:
        c, hub = _build({}, tmp_path)
        token = _mint_session(hub, "alice", last_seen=time.time() - 999999)
        r = c.get("/auth/me", cookies={"lm_session": token})
        assert r.status_code == 200  # absolute TTL still honored; idle disabled
    finally:
        access_mod._SESSION_IDLE_TIMEOUT_S = float(
            __import__("os").environ.get("LM_SESSION_IDLE_TIMEOUT_S", "1800"))


def test_session_cap_evicts_oldest(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_MAX_SESSIONS_PER_USER", "3")
    api_mod._MAX_SESSIONS_PER_USER = 3
    try:
        c, hub = _build({}, tmp_path)
        tokens = [_mint_session(hub, "alice") for _ in range(5)]
        live = [t for t, s in api_mod._sessions.items()
                if s.get("user_id") == "alice"]
        assert len(live) == 3
        # The oldest (first two minted) were evicted; the newest three survive.
        assert tokens[0] not in api_mod._sessions
        assert tokens[1] not in api_mod._sessions
        assert tokens[2] in api_mod._sessions
        assert tokens[4] in api_mod._sessions
    finally:
        api_mod._MAX_SESSIONS_PER_USER = int(
            __import__("os").environ.get("LM_MAX_SESSIONS_PER_USER", "5"))


# ── 7. /admin/sessions uses sid, not the cookie prefix ───────────────────────

def test_admin_sessions_lists_sid_not_token_prefix(tmp_path):
    c, hub = _build({}, tmp_path)
    token = _mint_session(hub, "alice")
    admin_token = _mint_session(hub, "admin")
    r = c.get("/admin/sessions", cookies={"lm_session": admin_token})
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    alice = next(s for s in sessions if s["user_id"] == "alice")
    assert "sid" in alice and alice["sid"]
    assert "token_hint" not in alice
    # The sid must NOT be a prefix of the actual session token.
    assert not token.startswith(alice["sid"])


def test_admin_revoke_by_sid(tmp_path):
    c, hub = _build({}, tmp_path)
    token = _mint_session(hub, "alice")
    admin_token = _mint_session(hub, "admin")
    r = c.get("/admin/sessions", cookies={"lm_session": admin_token})
    sid = next(s for s in r.json()["sessions"] if s["user_id"] == "alice")["sid"]
    r = c.delete(f"/admin/sessions/{sid}", cookies={"lm_session": admin_token})
    assert r.status_code == 200
    assert token not in api_mod._sessions


def test_admin_revoke_unknown_sid_404(tmp_path):
    c, hub = _build({}, tmp_path)
    admin_token = _mint_session(hub, "admin")
    r = c.delete("/admin/sessions/nope", cookies={"lm_session": admin_token})
    assert r.status_code == 404