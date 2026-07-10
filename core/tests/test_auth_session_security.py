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
from fastapi import HTTPException
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
        # NetBox cross-tenant-ownership tests need a connected ipam spoke + a
        # benign request_response so _verify_owns / _fetch_module can run.
        self.approved_modules = {}
        self.spoke_module_types = {}
        self._spokes_by_type = {"ipam": "ipam-spoke"}

    def get_spoke_by_type(self, t):
        return self._spokes_by_type.get(t)

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        # A NETBOX_GET_* round-trip (used by _fetch_module on cache miss) returns
        # an empty list so a not-owned object is fail-closed; any other command
        # (delete/update) returns a SUCCESS body so the handler proceeds past
        # the ownership gate.
        if cmd and cmd.startswith("NETBOX_GET"):
            return {"payload": {"data": []}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


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
    api_mod._tenant_cache.clear()
    for v in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_CORS_ORIGINS", "LM_SETUP_TOKEN",
              "LM_COOKIE_SECURE", "LM_MAX_SESSIONS_PER_USER",
              "LM_SESSION_IDLE_TIMEOUT_S", "LM_LOGIN_MAX_FAILS",
              "LM_LOGIN_IP_MAX", "LM_LOGIN_IP_WINDOW_S", "LM_TRUSTED_PROXIES"):
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


def _mint_tenant_session(hub, uid, tenant_id, rights=("ipam",)):
    """Drop a live NON-admin session scoped to ``tenant_id`` with the given
    module rights. Used by the cross-tenant / shared-infra write-gate tests."""
    user_data = {"user_id": uid, "auth_type": "local",
                 "permissions": {r: True for r in rights},
                 "tenants": [tenant_id], "tenant_id": tenant_id, "protected": False}
    return api_mod._record_session(hub, user_data)


def _mint_tenant_admin_session(hub, uid, tenants):
    """Drop a live tenant-Admin session (role:"tenant_admin", NO admin flag)
    scoped to ``tenants`` (a list — a tenant Admin may own several). Used by
    the Phase-3 shared-infra write-gate tests."""
    user_data = {"user_id": uid, "auth_type": "local",
                 "permissions": {"role": "tenant_admin"},
                 "tenants": list(tenants), "tenant_id": tenants[0],
                 "protected": False}
    return api_mod._record_session(hub, user_data)


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


def test_cors_wildcard_rejected(monkeypatch, tmp_path):
    # LM_CORS_ORIGINS="*" is spec-invalid with credentials and unsafe (would
    # reflect arbitrary Origin). It's rejected → falls back to the no-
    # credentialed default (no Origin reflected), NOT a wildcard+creds policy.
    monkeypatch.setenv("LM_CORS_ORIGINS", "*")
    c, hub = _build({}, tmp_path)
    r = c.get("/status", headers={"Origin": "https://evil.example"})
    assert r.headers.get("access-control-allow-origin") != "https://evil.example"
    assert r.headers.get("access-control-allow-credentials") != "true"


# ── 4b. Trusted-proxy XFF parsing (LM_TRUSTED_PROXIES) ───────────────────────

class _FakeReq:
    """Minimal stand-in for a Starlette Request for _client_ip unit tests."""
    def __init__(self, peer, xff=""):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_client_ip_no_trusted_proxies_ignores_xff(monkeypatch):
    # Fail-safe: with no trusted-proxy config, XFF is spoofable so it's IGNORED
    # — the per-IP limiter uses the TCP peer (a misconfigured Azure deploy
    # self-DoSes rather than trusting spoofable XFF).
    monkeypatch.setattr(api_mod, "_TRUSTED_PROXY_NETS", ())
    r = _FakeReq("203.0.113.9", xff="198.51.100.7")  # client-set (spoofed) XFF
    assert api_mod._client_ip(r) == "203.0.113.9"


def test_client_ip_trusted_peer_walks_xff_to_real_client(monkeypatch):
    import ipaddress
    monkeypatch.setattr(api_mod, "_TRUSTED_PROXY_NETS",
                        (ipaddress.ip_network("10.0.0.0/8"),))
    # Peer is the Azure proxy; XFF chain is [real-client, proxy]. Walk right-to-
    # left past the trusted proxy hop to the real client.
    r = _FakeReq("10.0.0.5", xff="203.0.113.9, 10.0.0.5")
    assert api_mod._client_ip(r) == "203.0.113.9"


def test_client_ip_untrusted_peer_ignores_xff(monkeypatch):
    import ipaddress
    monkeypatch.setattr(api_mod, "_TRUSTED_PROXY_NETS",
                        (ipaddress.ip_network("10.0.0.0/8"),))
    # Peer is NOT a trusted proxy → XFF is untrusted → return the peer.
    r = _FakeReq("198.51.100.7", xff="203.0.113.9")
    assert api_mod._client_ip(r) == "198.51.100.7"


def test_client_ip_multi_hop_skips_all_trusted(monkeypatch):
    import ipaddress
    monkeypatch.setattr(api_mod, "_TRUSTED_PROXY_NETS",
                        (ipaddress.ip_network("10.0.0.0/8"),))
    # Two trusted proxy hops, then the real client at the left.
    r = _FakeReq("10.0.0.9", xff="203.0.113.99, 10.0.0.5, 10.0.0.9")
    assert api_mod._client_ip(r) == "203.0.113.99"


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


# ── 8. Shared-infrastructure writes gated to admin (firewall / DNS / DHCP) ───

def test_firewall_write_requires_admin(tmp_path):
    # /api/firewall/* has no module-right gate; writes (POST/PUT/DELETE) now
    # require admin. A non-admin (even with ipam) is 403'd at the middleware.
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    r = c.post("/api/firewall/fw1/rules", json={"rule": {}},
               cookies={"lm_session": tok})
    assert r.status_code == 403
    # Admin passes the gate (the handler then runs against the fake hub — not 403).
    admin_tok = _mint_session(hub, "admin")
    r = c.post("/api/firewall/fw1/rules", json={"rule": {}},
               cookies={"lm_session": admin_tok})
    assert r.status_code != 403


def test_firewall_read_stays_authed_not_admin(tmp_path):
    # GET is method-gated OUT of the admin requirement — a non-admin can still
    # view (filtered) firewall data; only writes are admin-gated.
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    r = c.get("/api/firewall/fw1/rules", cookies={"lm_session": tok})
    assert r.status_code != 403


def test_dns_dhcp_write_requires_admin(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    assert c.post("/api/dns/record", json={},
                  cookies={"lm_session": tok}).status_code == 403
    assert c.post("/api/dhcp/reservation", json={},
                  cookies={"lm_session": tok}).status_code == 403
    assert c.post("/api/dns/sync", cookies={"lm_session": tok}).status_code == 403
    # Admin passes the gate (handler then runs — not 403).
    admin_tok = _mint_session(hub, "admin")
    assert c.post("/api/dns/record", json={},
                  cookies={"lm_session": admin_tok}).status_code != 403


# ── 8b. Shared-infrastructure writes: tenant-Admin tier (Phase 3) ─────────────
# A tenant Admin may write firewall/DNS/DHCP ONLY for an explicit ?tenant= it
# owns. Without ?tenant= the write is ambiguous and rejected; a ?tenant= for a
# tenant it doesn't own is rejected; a plain (non-tier) user is still blocked.

def test_firewall_write_tenant_admin_requires_explicit_tenant(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA"])
    # No ?tenant= → ambiguous → 403.
    r = c.post("/api/firewall/fw1/rules", json={"rule": {}},
               cookies={"lm_session": tok})
    assert r.status_code == 403
    assert "explicit owned tenant" in r.json().get("detail", "")


def test_firewall_write_tenant_admin_owned_tenant_passes(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA"])
    # ?tenant=tA (owned) → middleware passes; the handler then runs (not 403).
    r = c.post("/api/firewall/fw1/rules?tenant=tA", json={"rule": {}},
               cookies={"lm_session": tok})
    assert r.status_code != 403


def test_firewall_write_tenant_admin_other_tenant_403(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA"])
    # ?tenant=other (not owned) → 403 (check_tenant_access fails).
    r = c.post("/api/firewall/fw1/rules?tenant=other", json={"rule": {}},
               cookies={"lm_session": tok})
    assert r.status_code == 403


def test_dns_write_tenant_admin_owned_tenant_passes(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA"])
    r = c.post("/api/dns/record?tenant=tA", json={},
               cookies={"lm_session": tok})
    assert r.status_code != 403


def test_dhcp_write_tenant_admin_requires_explicit_tenant(tmp_path):
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA"])
    # No ?tenant= → 403.
    r = c.post("/api/dhcp/reservation", json={},
               cookies={"lm_session": tok})
    assert r.status_code == 403
    # ?tenant=tA (owned) → passes the gate.
    r = c.post("/api/dhcp/reservation?tenant=tA", json={},
               cookies={"lm_session": tok})
    assert r.status_code != 403


def test_firewall_write_global_admin_any_tenant(tmp_path):
    """A Global Admin writes for any tenant — no ?tenant= required (it may
    scope the push, but the tier gate doesn't demand it)."""
    c, hub = _build({}, tmp_path)
    admin_tok = _mint_session(hub, "admin")
    # No ?tenant= → still passes (Global admin is unconstrained at the tier gate).
    r = c.post("/api/firewall/fw1/rules", json={"rule": {}},
               cookies={"lm_session": admin_tok})
    assert r.status_code != 403
    # ?tenant=anything → the end-of-middleware check_tenant_access(admin, x) is
    # True for admins, so it passes too.
    r = c.post("/api/firewall/fw1/rules?tenant=zzz", json={"rule": {}},
               cookies={"lm_session": admin_tok})
    assert r.status_code != 403


def test_firewall_write_tenant_admin_multi_tenant_owned(tmp_path):
    """A tenant Admin owning several tenants may write for any of them."""
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["tA", "tB"])
    assert c.post("/api/firewall/fw1/rules?tenant=tA", json={"rule": {}},
                  cookies={"lm_session": tok}).status_code != 403
    assert c.post("/api/firewall/fw1/rules?tenant=tB", json={"rule": {}},
                  cookies={"lm_session": tok}).status_code != 403
    # But not a third tenant.
    assert c.post("/api/firewall/fw1/rules?tenant=tC", json={"rule": {}},
                  cookies={"lm_session": tok}).status_code == 403


# ── 9. Help assistant admin-gate (cross-tenant LLM tools) ─────────────────────

def test_help_ask_requires_admin(tmp_path):
    # /api/help/ask runs hub-wide (cross-tenant) LLM tools — admin-only. A
    # non-admin is 403'd; /api/help/available stays authed-read.
    c, hub = _build({}, tmp_path)
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    r = c.post("/api/help/ask", json={"question": "list all spokes"},
               cookies={"lm_session": tok})
    assert r.status_code == 403
    # available is NOT admin-gated — any authed user may read it.
    assert c.get("/api/help/available",
                 cookies={"lm_session": tok}).status_code == 200
    # Admin passes the gate; with no bugfixer agent connected the handler 409s.
    admin_tok = _mint_session(hub, "admin")
    r = c.post("/api/help/ask", json={"question": "list all spokes"},
               cookies={"lm_session": admin_tok})
    assert r.status_code == 409


# ── 10. NetBox cross-tenant mutation ownership check ──────────────────────────

def test_netbox_delete_not_owned_by_tenant_denied(tmp_path):
    # Seed tenant tA's device cache with device 5 only. A non-admin ipam user
    # scoped to tA may NOT delete device 999 (another tenant's, by ID enum) —
    # fail-closed 403.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_devices": {"data": [{"id": 5}]}}
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    r = c.delete("/api/netbox/devices/999", cookies={"lm_session": tok})
    assert r.status_code == 403


def test_netbox_delete_owned_by_tenant_passes_gate(tmp_path):
    # Device 5 IS in alice's tenant cache → ownership passes; the handler then
    # proceeds (fake request_response returns SUCCESS) → 200, not the 403 gate.
    c, hub = _build({}, tmp_path)
    api_mod._tenant_cache["tA"] = {"netbox_devices": {"data": [{"id": 5}]}}
    tok = _mint_tenant_session(hub, "alice", "tA", rights=("ipam",))
    r = c.delete("/api/netbox/devices/5", cookies={"lm_session": tok})
    assert r.status_code == 200


def test_netbox_delete_admin_bypasses_ownership(tmp_path):
    # Admin may delete any device regardless of cache; ownership check returns
    # None for admin. The handler proceeds (fake SUCCESS) → 200, not 403.
    c, hub = _build({}, tmp_path)
    admin_tok = _mint_session(hub, "admin")
    r = c.delete("/api/netbox/devices/999", cookies={"lm_session": admin_tok})
    assert r.status_code == 200

# ── 9. H1: 5xx internal-exception detail scrubbing ───────────────────────────
# Routes raise HTTPException(500, detail=str(e)) in their except-Exception
# blocks. A non-Global caller must NOT see the raw internal exception text
# (paths, SQL/spoke error strings, stack fingerprints) — they get a generic
# "Internal server error" + a ref id; a Global admin retains the real detail
# for ops debugging. Authored 4xx messages pass through unscrubbed.

_INTERNAL_SECRET = "internal leak: /opt/lm/.env Fernet key path (psycopg2 OperationalError)"

def _build_with_error_routes(users=None, tmp_path=None):
    """Real create_app stack + two public test routes: one that 500s with an
    internal-looking detail, one that 400s with an authored message. Both are
    outside the gated prefixes so any session (or none) can reach them. They
    are inserted at the FRONT of the router so the ``/{full_path:path}``
    catch-all (serve_ui) does not shadow them."""
    c, hub = _build(users, tmp_path)
    app = c.app

    @app.get("/__test_500__")
    async def _boom():
        raise HTTPException(status_code=500, detail=_INTERNAL_SECRET)

    @app.get("/__test_400__")
    async def _bad():
        raise HTTPException(status_code=400, detail="Missing tenant_id")

    # Move the two just-added routes to the front so they match before the
    # /{full_path:path} UI catch-all registered inside create_app.
    routes = app.router.routes
    for _ in range(2):
        routes.insert(0, routes.pop())

    return c, hub


def test_5xx_detail_scrubbed_for_plain_user(tmp_path):
    c, hub = _build_with_error_routes({}, tmp_path)
    tok = _mint_tenant_session(hub, "op", "acme", rights=("ipam",))
    r = c.get("/__test_500__", cookies={"lm_session": tok})
    assert r.status_code == 500
    body = r.json()
    assert body["detail"] == "Internal server error"
    assert "ref" in body and body["ref"]
    # The raw internal text must not reach the client.
    assert _INTERNAL_SECRET not in r.text
    assert "Fernet" not in r.text


def test_5xx_detail_scrubbed_for_tenant_admin(tmp_path):
    c, hub = _build_with_error_routes({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["acme"])
    r = c.get("/__test_500__", cookies={"lm_session": tok})
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error"
    assert _INTERNAL_SECRET not in r.text


def test_5xx_detail_preserved_for_global_admin(tmp_path):
    c, hub = _build_with_error_routes({}, tmp_path)
    tok = _mint_session(hub, "root")  # Global admin
    r = c.get("/__test_500__", cookies={"lm_session": tok})
    assert r.status_code == 500
    # Global admin sees the real detail (ops debugging), no ref substitution.
    assert r.json()["detail"] == _INTERNAL_SECRET


def test_5xx_detail_scrubbed_for_anonymous(tmp_path):
    # An anonymous caller (no session) is non-admin → scrubbed.
    c, hub = _build_with_error_routes({}, tmp_path)
    r = c.get("/__test_500__")
    assert r.status_code == 500
    assert r.json()["detail"] == "Internal server error"
    assert _INTERNAL_SECRET not in r.text


def test_4xx_authored_detail_preserved_for_non_admin(tmp_path):
    # A 400 with an authored validation message is NOT scrubbed — only 5xx is.
    c, hub = _build_with_error_routes({}, tmp_path)
    tok = _mint_tenant_session(hub, "op", "acme", rights=("ipam",))
    r = c.get("/__test_400__", cookies={"lm_session": tok})
    assert r.status_code == 400
    assert r.json()["detail"] == "Missing tenant_id"


def test_4xx_authored_detail_preserved_for_anonymous(tmp_path):
    c, hub = _build_with_error_routes({}, tmp_path)
    r = c.get("/__test_400__")
    assert r.status_code == 400
    assert r.json()["detail"] == "Missing tenant_id"


def test_5xx_scrub_ref_unique_and_logged(tmp_path, caplog):
    import logging
    c, hub = _build_with_error_routes({}, tmp_path)
    tok = _mint_tenant_admin_session(hub, "tadm", ["acme"])
    with caplog.at_level(logging.WARNING, logger="uvicorn.error"):
        r1 = c.get("/__test_500__", cookies={"lm_session": tok})
        r2 = c.get("/__test_500__", cookies={"lm_session": tok})
    assert r1.status_code == r2.status_code == 500
    ref1, ref2 = r1.json()["ref"], r2.json()["ref"]
    # Each 5xx gets a fresh ref id for operator correlation.
    assert ref1 and ref2 and ref1 != ref2
    # The real detail is logged server-side (with the ref) but not returned.
    log_text = caplog.text
    assert ref1 in log_text
    assert _INTERNAL_SECRET in log_text
