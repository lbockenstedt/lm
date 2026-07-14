"""OIDC (Azure Entra ID) login regressions.

Covers the pure helpers in ``security.oidc`` (cert client-assertion signing,
id-token verification + MFA hard-enforcement, state-cookie HMAC, provisioning +
re-sync with session invalidation, group→tenant mapping) and the callback flow
end-to-end through the real ``create_app`` stack with the Entra token endpoint
+ JWKS stubbed via ``httpx.MockTransport``.

Models the token-exchange stubbing on ``test_central_aruba_hub.py`` and the
auth-flow stand-in on ``test_auth_session_security.py``.
"""
import asyncio
import base64
import json
import os
import sys
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api as api_mod
from access import groups_and_tenants_for_membership
import security.oidc as oidc


# ── test fixtures: RSA key pair + JWKS + signed id_token ────────────────────

@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rsa_cert(rsa_key):
    """Self-signed cert PEM for rsa_key — build_client_assertion needs it to set
    the Entra x5t header."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    import datetime as _dt
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lm-hub-oidc-test")])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(rsa_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=365))
            .sign(rsa_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _write_keypair(tmp_path, rsa_key, rsa_cert):
    """Write key + cert to tmp_path, return (key_path, cert_path) as strings."""
    key_path = tmp_path / "client.key"
    key_path.write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    cert_path = tmp_path / "client.crt"
    cert_path.write_bytes(rsa_cert)
    return str(key_path), str(cert_path)


@pytest.fixture(scope="module")
def jwks(rsa_key):
    pub = rsa_key.public_key().public_numbers()
    def _b64u(n):
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    return [{
        "kty": "RSA", "kid": "test-kid", "use": "sig", "alg": "RS256",
        "n": _b64u(pub.n), "e": _b64u(pub.e),
    }]


def _make_id_token(rsa_key, *, aud="cid", iss="https://login.microsoftonline.com/tid/v2.0",
                   nonce="nonce-xyz", amr=("mfa", "pwd"), groups=("g-noc",),
                   oid="user-oid-1", email="alice@example.com", name="Alice",
                   tid="tid", exp_delta=300, extra=None):
    now = int(time.time())
    payload = {
        "iss": iss, "aud": aud, "sub": oid, "oid": oid, "tid": tid,
        "nonce": nonce, "email": email, "name": name,
        "amr": list(amr), "groups": list(groups),
        "iat": now, "exp": now + exp_delta,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, rsa_key, algorithm="RS256", headers={"kid": "test-kid"})


# ── fakes ────────────────────────────────────────────────────────────────────

class _KM:
    """Minimal key_manager stand-in (hub_secrets for the state-cookie HMAC)."""
    def __init__(self):
        self.hub_secrets = ["hub-secret-test"]


class _FakeState:
    def __init__(self, system_state=None):
        self.system_state = system_state or {}
        self.tenant_state = {"tenants": {"t-tenant-a": {"id": "t-tenant-a"},
                                          "t-tenant-b": {"id": "t-tenant-b"}}}
        self.data_dir = None

    def save_state(self):
        pass

    def ensure_admin_lockout(self):
        return False

    def get_tenant(self, tid):
        return self.tenant_state.get("tenants", {}).get(tid)


class _FakeHub:
    def __init__(self, system_state=None):
        self.state = _FakeState(system_state)
        self.key_manager = _KM()
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = set()
        self.approved_modules = {}
        self.spoke_module_types = {}
        self._spokes_by_type = {}

    def get_spoke_by_type(self, t):
        return self._spokes_by_type.get(t)

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        return {"payload": {"data": []}}


def _groups_state():
    """permission_groups: noc → tenant-a, certs → tenant-b + tenant-a."""
    return {
        "noc":   {"name": "NOC", "permissions": {"nw": True, "ipam": True},
                  "ldap_group": "g-noc", "tenants": ["t-tenant-a"]},
        "certs": {"name": "Certs", "permissions": {"le": True},
                  "ldap_group": "g-certs", "tenants": ["t-tenant-b", "t-tenant-a"]},
    }


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    api_mod._sessions.clear()
    oidc._discovery_cache.clear()
    for v in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_CORS_ORIGINS", "LM_OIDC_STATE_SECRET",
              "LM_OIDC_TENANT_ID", "LM_OIDC_CLIENT_ID", "LM_OIDC_CLIENT_KEY",
              "LM_OIDC_ENABLED", "LM_FERNET_KEY"):
        monkeypatch.delenv(v, raising=False)
    # _FakeHub.key_manager provides the state secret; no Fernet key needed.
    monkeypatch.setenv("LM_FERNET_KEY", "z" * 44)  # placeholder so encryption import OK


def _build(system_state):
    hub = _FakeHub(system_state)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


# ── pure helper unit tests ──────────────────────────────────────────────────

def test_state_cookie_round_trips(hub_none=None):
    hub = _FakeHub({"permission_groups": _groups_state()})
    cookie = oidc.sign_state_cookie(hub, "st", "nc", "cv")
    assert oidc.verify_state_cookie(hub, cookie) == ("st", "nc", "cv")


def test_state_cookie_rejects_tamper():
    hub = _FakeHub({})
    cookie = oidc.sign_state_cookie(hub, "st", "nc", "cv")
    bad = cookie[:-2] + "00"  # flip the HMAC tail
    assert oidc.verify_state_cookie(hub, bad) is None


def test_state_cookie_rejects_expired(monkeypatch):
    hub = _FakeHub({})
    cookie = oidc.sign_state_cookie(hub, "st", "nc", "cv")
    # Warp time past the TTL: re-sign with an old timestamp via direct build.
    old = int(time.time()) - (oidc._STATE_TTL_S + 60)
    payload = f"st:nc:cv:{old}"
    sig = __import__("hmac").new(
        oidc._state_secret(hub), payload.encode(), __import__("hashlib").sha256).hexdigest()
    assert oidc.verify_state_cookie(hub, f"{payload}.{sig}") is None


def test_state_cookie_accepts_rotation_history(monkeypatch):
    # A state cookie signed with the OLD secret verifies against the hub_secrets
    # history (rotation mid-round-trip).
    hub = _FakeHub({})
    hub.key_manager.hub_secrets = ["new-secret", "old-secret"]
    old_payload = f"st:nc:cv:{int(time.time())}"
    import hmac, hashlib
    sig = hmac.new(b"old-secret", old_payload.encode(), hashlib.sha256).hexdigest()
    assert oidc.verify_state_cookie(hub, f"{old_payload}.{sig}") == ("st", "nc", "cv")


def test_client_assertion_is_valid_rs256_jwt(rsa_key, rsa_cert, tmp_path):
    key_path, cert_path = _write_keypair(tmp_path, rsa_key, rsa_cert)
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid",
                           "key_path": key_path, "cert_path": cert_path})
    tok_endpoint = "https://login.microsoftonline.com/tid/oauth2/v2.0/token"
    assertion = oidc.build_client_assertion(cfg, tok_endpoint)
    # Entra requires the cert thumbprint in the header.
    assert jwt.get_unverified_header(assertion).get("x5t") == \
        oidc.cert_thumbprint_x5t(rsa_cert)
    decoded = jwt.decode(assertion, rsa_key.public_key(), algorithms=["RS256"],
                          audience=tok_endpoint)
    assert decoded["iss"] == "cid" and decoded["sub"] == "cid"
    assert decoded["aud"] == tok_endpoint
    assert "exp" in decoded and "jti" in decoded


def test_verify_id_token_mfa_enforced_passes_with_mfa(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid",
                          "key_path": "/k", "require_mfa": True})
    tok = _make_id_token(rsa_key, aud="cid", nonce="n1", amr=["mfa", "pwd"])
    claims = oidc.verify_id_token(cfg, tok, "n1", jwks)
    assert claims["oid"] == "user-oid-1"


def test_verify_id_token_refuses_without_mfa(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid",
                           "key_path": "/k", "require_mfa": True})
    tok = _make_id_token(rsa_key, aud="cid", nonce="n1", amr=["pwd"])  # no mfa
    with pytest.raises(oidc.OidcError, match="MFA required"):
        oidc.verify_id_token(cfg, tok, "n1", jwks)


def test_verify_id_token_mfa_off_allows_no_mfa(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid",
                           "key_path": "/k", "require_mfa": False})
    tok = _make_id_token(rsa_key, aud="cid", nonce="n1", amr=["pwd"])
    assert oidc.verify_id_token(cfg, tok, "n1", jwks)["oid"] == "user-oid-1"


def test_verify_id_token_rejects_nonce_mismatch(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid", "key_path": "/k"})
    tok = _make_id_token(rsa_key, aud="cid", nonce="n1")
    with pytest.raises(oidc.OidcError, match="nonce"):
        oidc.verify_id_token(cfg, tok, "WRONG", jwks)


def test_verify_id_token_rejects_wrong_audience(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid", "key_path": "/k"})
    tok = _make_id_token(rsa_key, aud="someone-else", nonce="n1")
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(cfg, tok, "n1", jwks)


def test_verify_id_token_rejects_wrong_issuer(rsa_key, jwks):
    cfg = oidc.OidcConfig({"tenant_id": "tid", "client_id": "cid", "key_path": "/k"})
    tok = _make_id_token(rsa_key, iss="https://login.microsoftonline.com/other/v2.0",
                        nonce="n1")
    with pytest.raises(oidc.OidcError):
        oidc.verify_id_token(cfg, tok, "n1", jwks)


def test_provision_auto_provisions_and_maps_tenants():
    hub = _FakeHub({"permission_groups": _groups_state()})
    rec = oidc.provision_or_sync_entra_user(
        hub, "user-oid-1", "alice@example.com", "Alice", ["g-noc"], "")
    assert rec["auth_type"] == "entra"
    assert rec["groups"] == ["noc"]
    assert rec["tenants"] == ["t-tenant-a"]
    assert "password_hash" not in rec
    assert hub.state.system_state["users"]["user-oid-1"] is rec


def test_provision_allowed_group_gate_refuses():
    hub = _FakeHub({"permission_groups": _groups_state()})
    with pytest.raises(oidc.OidcError, match="allowed group"):
        oidc.provision_or_sync_entra_user(
            hub, "user-oid-1", "a@x", "A", ["g-noc"], allowed_group="g-admins")


def test_provision_resync_invalidates_on_change():
    hub = _FakeHub({"permission_groups": _groups_state(), "users": {
        "user-oid-1": {"auth_type": "entra", "groups": ["noc"],
                       "tenants": ["t-tenant-a"], "permissions": {}}}})
    # Mint a live session for the user so invalidation has something to drop.
    api_mod._record_session(hub, {"user_id": "user-oid-1", "auth_type": "entra",
                                   "permissions": {}, "tenants": ["t-tenant-a"],
                                   "tenant_id": "t-tenant-a", "protected": False})
    assert any(s.get("user_id") == "user-oid-1" for s in api_mod._sessions.values())
    # Re-sync with a NEW group → tenant set changes → sessions invalidated.
    oidc.provision_or_sync_entra_user(
        hub, "user-oid-1", "alice@example.com", "Alice", ["g-noc", "g-certs"], "")
    rec = hub.state.system_state["users"]["user-oid-1"]
    assert set(rec["groups"]) == {"noc", "certs"}
    assert set(rec["tenants"]) == {"t-tenant-a", "t-tenant-b"}
    assert not any(s.get("user_id") == "user-oid-1" for s in api_mod._sessions.values())


def test_provision_resync_no_change_keeps_sessions():
    hub = _FakeHub({"permission_groups": _groups_state(), "users": {
        "user-oid-1": {"auth_type": "entra", "groups": ["noc"],
                       "tenants": ["t-tenant-a"], "permissions": {}}}})
    api_mod._record_session(hub, {"user_id": "user-oid-1", "auth_type": "entra",
                                   "permissions": {}, "tenants": ["t-tenant-a"],
                                   "tenant_id": "t-tenant-a", "protected": False})
    # Same groups/tenants → no change → sessions survive.
    oidc.provision_or_sync_entra_user(
        hub, "user-oid-1", "a@x", "A", ["g-noc"], "")
    assert any(s.get("user_id") == "user-oid-1" for s in api_mod._sessions.values())


def test_build_user_data_carries_perms_and_tenants():
    hub = _FakeHub({"permission_groups": _groups_state(), "users": {
        "user-oid-1": {"auth_type": "entra", "groups": ["noc", "certs"],
                       "tenants": ["t-tenant-a", "t-tenant-b"], "permissions": {}}}})
    rec = hub.state.system_state["users"]["user-oid-1"]
    ud = oidc.build_user_data(hub, rec, "user-oid-1")
    assert ud["auth_type"] == "entra"
    assert ud["protected"] is False
    assert ud["user_id"] == "user-oid-1"
    assert ud["tenant_id"] == "t-tenant-a"  # first tenant
    assert ud["permissions"].get("nw") and ud["permissions"].get("le")
    assert set(ud["tenants"]) == {"t-tenant-a", "t-tenant-b"}


# ── callback flow end-to-end (MockTransport for Entra) ──────────────────────

def _mount_oidc_config(hub, **kw):
    hub.state.system_state.setdefault("global_config", {})["oidc"] = {
        "enabled": True, "tenant_id": "tid", "client_id": "cid",
        "redirect_uri": "https://hub.example/auth/oidc/callback",
        "key_path": kw["key_path"], "cert_path": kw.get("cert_path", ""),
        "allowed_group": kw.get("allowed_group", ""),
        "require_mfa": kw.get("require_mfa", True),
    }


def _mock_transport(rsa_key, jwks, *, id_token_factory, access_token="at",
                    token_status=200):
    """MockTransport handling discovery + token endpoint + JWKS.

    ``id_token_factory`` is a callable returning the id_token string, invoked
    at token-endpoint time so the test can bake in the nonce captured from the
    login redirect (the route generates a random nonce). A mutable holder lets
    the test set the factory AFTER the login request."""
    disc = {
        "issuer": "https://login.microsoftonline.com/tid/v2.0",
        "authorization_endpoint": "https://login.microsoftonline.com/tid/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/tid/oauth2/v2.0/token",
        "jwks_uri": "https://login.microsoftonline.com/tid/discovery/v2.0/keys",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        u = str(request.url)
        if u.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=disc)
        if u.endswith("/discovery/v2.0/keys"):
            return httpx.Response(200, json={"keys": jwks})
        if u.endswith("/oauth2/v2.0/token"):
            return httpx.Response(token_status, json={"id_token": id_token_factory(),
                                                       "access_token": access_token})
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def _parse_nonce_from_redirect(location: str) -> str:
    from urllib.parse import urlparse, parse_qs
    return parse_qs(urlparse(location).query)["nonce"][0]


def test_callback_happy_path_provisions_and_sets_cookie(rsa_key, rsa_cert, jwks, tmp_path, monkeypatch):
    key_path, cert_path = _write_keypair(tmp_path, rsa_key, rsa_cert)
    system_state = {"permission_groups": _groups_state()}
    client, hub = _build(system_state)
    _mount_oidc_config(hub, key_path=key_path, cert_path=cert_path)

    # Stub the module-level httpx clients the routes use to hit the MockTransport.
    holder = {"nonce": None}
    transport = _mock_transport(rsa_key, jwks,
        id_token_factory=lambda: _make_id_token(
            rsa_key, nonce=holder["nonce"], amr=["mfa"], groups=["g-noc"]))

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **k):
            k["transport"] = transport
            super().__init__(*a, **k)

    monkeypatch.setattr(oidc.httpx, "AsyncClient", _PatchedClient)

    # Simulate the browser round-trip: GET /auth/oidc/login captures the state
    # cookie + nonce, then GET /auth/oidc/callback replays it with ?code&state.
    r1 = client.get("/auth/oidc/login", follow_redirects=False)
    assert r1.status_code == 302
    assert "login.microsoftonline.com" in r1.headers["location"]
    state_cookie = r1.cookies.get("lm_oidc_state")
    assert state_cookie
    # Extract the state + nonce we signed so the callback query + id_token match.
    st, nonce, _cv = oidc.verify_state_cookie(hub, state_cookie)
    holder["nonce"] = _parse_nonce_from_redirect(r1.headers["location"])
    assert holder["nonce"] == nonce

    r2 = client.get("/auth/oidc/callback", params={"code": "ac", "state": st},
                    cookies={"lm_oidc_state": state_cookie}, follow_redirects=False)
    assert r2.status_code == 302, r2.text
    assert r2.headers["location"] == "/"
    sess_cookie = r2.cookies.get("lm_session")
    assert sess_cookie, "callback must set the lm_session cookie"
    # The user was auto-provisioned with the group-derived tenant.
    rec = hub.state.system_state["users"]["user-oid-1"]
    assert rec["auth_type"] == "entra" and rec["tenants"] == ["t-tenant-a"]
    # The session cookie authenticates.
    me = client.get("/auth/me", cookies={"lm_session": sess_cookie})
    assert me.status_code == 200
    body = me.json()
    assert body["user_id"] == "user-oid-1"
    assert body["auth_type"] == "entra"
    assert set(body["tenants"]) == {"t-tenant-a"}
    assert body["permissions"].get("nw")


def test_callback_refuses_when_mfa_missing(rsa_key, rsa_cert, jwks, tmp_path, monkeypatch):
    key_path, cert_path = _write_keypair(tmp_path, rsa_key, rsa_cert)
    client, hub = _build({"permission_groups": _groups_state()})
    _mount_oidc_config(hub, key_path=key_path, cert_path=cert_path)
    holder = {"nonce": None}
    transport = _mock_transport(rsa_key, jwks,
        id_token_factory=lambda: _make_id_token(
            rsa_key, nonce=holder["nonce"], amr=["pwd"], groups=["g-noc"]))

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, *a, **k):
            k["transport"] = transport
            super().__init__(*a, **k)
    monkeypatch.setattr(oidc.httpx, "AsyncClient", _PatchedClient)

    r1 = client.get("/auth/oidc/login", follow_redirects=False)
    state_cookie = r1.cookies.get("lm_oidc_state")
    st, nonce, _cv = oidc.verify_state_cookie(hub, state_cookie)
    holder["nonce"] = nonce
    r2 = client.get("/auth/oidc/callback", params={"code": "ac", "state": st},
                    cookies={"lm_oidc_state": state_cookie}, follow_redirects=False)
    assert r2.status_code == 401
    assert "MFA" in r2.text


def test_callback_rejects_state_mismatch(rsa_key, jwks, tmp_path, monkeypatch):
    key_path = tmp_path / "client.key"
    key_path.write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    client, hub = _build({"permission_groups": _groups_state()})
    _mount_oidc_config(hub, key_path=str(key_path))
    # No transport needed — state check fires before token exchange.
    r1 = client.get("/auth/oidc/login", follow_redirects=False)
    state_cookie = r1.cookies.get("lm_oidc_state")
    r2 = client.get("/auth/oidc/callback", params={"code": "ac", "state": "WRONG"},
                    cookies={"lm_oidc_state": state_cookie}, follow_redirects=False)
    assert r2.status_code == 400


def test_callback_rejects_missing_state_cookie(rsa_key, jwks, tmp_path):
    key_path = tmp_path / "client.key"
    key_path.write_bytes(rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    client, hub = _build({"permission_groups": _groups_state()})
    _mount_oidc_config(hub, key_path=str(key_path))
    r2 = client.get("/auth/oidc/callback", params={"code": "ac", "state": "x"},
                    follow_redirects=False)
    assert r2.status_code == 400


def test_oidc_enabled_endpoint_reports_enabled(tmp_path):
    client, hub = _build({"permission_groups": _groups_state()})
    # Not configured → disabled.
    assert client.get("/auth/oidc/enabled").json() == {"enabled": False}
    _mount_oidc_config(hub, key_path="/nonexistent.key")
    assert client.get("/auth/oidc/enabled").json() == {"enabled": True}


def test_setup_oidc_config_admin_only_and_persists(tmp_path):
    admin = {"admin": {"auth_type": "local",
                       "password_hash": api_mod._hash_password("pass1234"),
                       "permissions": {"role": "admin", "admin": True},
                       "tenants": [], "protected": False}}
    client, hub = _build({"users": admin})
    # Unauthenticated → 401 (middleware gate, not the route body).
    assert client.get("/setup/oidc-config").status_code == 401
    # Log in as admin, then read/write the config.
    r = client.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200
    ck = r.cookies.get("lm_session")
    got = client.get("/setup/oidc-config", cookies={"lm_session": ck})
    assert got.status_code == 200
    gj = got.json()
    assert gj["config"] == {}
    # New: the GET also reports cert/key presence so the form can prompt to
    # generate. Nothing on disk here → both absent.
    assert gj["cert_status"]["key_present"] is False
    assert gj["cert_status"]["cert_present"] is False
    r2 = client.post("/setup/oidc-config", cookies={"lm_session": ck},
                     json={"config": {"enabled": True, "tenant_id": "tid",
                                      "client_id": "cid", "redirect_uri": "u",
                                      "key_path": "/k", "require_mfa": True}})
    assert r2.status_code == 200
    assert hub.state.system_state["global_config"]["oidc"]["tenant_id"] == "tid"
    assert hub.state.system_state["global_config"]["oidc"]["enabled"] is True
    # The key material itself is never stored (only the path ref — and not echoed
    # as a secret): confirm no surprise secret fields appear.
    assert "client_secret" not in hub.state.system_state["global_config"]["oidc"]

def test_default_oidc_dir_uses_hub_data_dir(monkeypatch, tmp_path):
    """Default cert dir derives from the hub's WRITABLE state data_dir (not the
    non-writable /etc/lm), with LM_OIDC_DIR overriding."""
    monkeypatch.delenv("LM_OIDC_DIR", raising=False)

    class _S:
        data_dir = str(tmp_path / "state")

    class _H:
        state = _S()

    assert oidc.default_oidc_dir(_H()) == str(tmp_path / "state" / "oidc")
    monkeypatch.setenv("LM_OIDC_DIR", "/custom/oidc")
    assert oidc.default_oidc_dir(_H()) == "/custom/oidc"


def test_generate_client_cert_writes_and_refuses_overwrite(tmp_path, monkeypatch):
    monkeypatch.delenv("LM_OIDC_DIR", raising=False)
    kp = tmp_path / "d" / "key.pem"
    cp = tmp_path / "d" / "cert.pem"
    res = oidc.generate_client_cert(key_path=str(kp), cert_path=str(cp))
    assert kp.exists() and cp.exists()
    assert res["key_path"] == str(kp) and res["cert_path"] == str(cp)
    assert res["thumbprint"] == oidc.cert_thumbprint_x5t(cp.read_bytes())
    # 0600 on the key.
    assert (kp.stat().st_mode & 0o777) == 0o600
    # Refuses to clobber an existing key without force.
    with pytest.raises(oidc.OidcError):
        oidc.generate_client_cert(key_path=str(kp), cert_path=str(cp))
    # force overwrites.
    oidc.generate_client_cert(key_path=str(kp), cert_path=str(cp), force=True)
