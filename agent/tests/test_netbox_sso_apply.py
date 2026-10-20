"""NETBOX_APPLY_SSO on a netbox-server host + the agent-shipped NetBox backend.

* ``GenericAgent._apply_netbox_sso`` installs ``lm_sso_backend.py`` + the hub's
  Entra cert/key (0600, NetBox user), writes the LM SSO block (Microsoft login
  button, cert auth, SOCIAL_AUTH_* group settings), replaces an installer-written
  block in place, is idempotent, and removes block + key on disable.
* ``netbox_sso_backend.EntraCertOIDCAuth`` swaps the client secret for a
  cert-signed ``client_assertion`` (x5t header) Entra accepts.
* ``netbox_sso_backend.sync_entra_groups`` gates on the allowed group, maps
  groups, and grants/revokes superuser.
"""
import asyncio
import base64
import hashlib
import importlib
import os
import stat
import sys
import types

import jwt
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

import agent_spoke
from agent_spoke import GenericAgent


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lm-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem, cert


class _Base:
    """Stand-in for social_core's OpenIdConnectAuth (not installed in CI)."""

    def __init__(self, settings):
        self._settings = settings

    def setting(self, name, default=None):
        return self._settings.get(name, default)

    def get_key_and_secret(self):
        return self._settings.get("KEY"), self._settings.get("SECRET")

    def access_token_url(self):
        return "https://login.microsoftonline.com/tid/oauth2/v2.0/token"

    def use_basic_auth(self):
        return True

    def auth_complete_credentials(self):
        return self.get_key_and_secret()

    def auth_complete_params(self, state=None):
        p = {"grant_type": "authorization_code", "code": "c", "redirect_uri": "r"}
        if not self.use_basic_auth():
            k, s = self.get_key_and_secret()
            p.update(client_id=k, client_secret=s)
        return p


@pytest.fixture
def backend_mod(monkeypatch):
    mod = types.ModuleType("social_core.backends.open_id_connect")
    mod.OpenIdConnectAuth = _Base
    for name in ("social_core", "social_core.backends"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "social_core.backends.open_id_connect", mod)
    sys.modules.pop("netbox_sso_backend", None)
    m = importlib.import_module("netbox_sso_backend")
    yield m
    sys.modules.pop("netbox_sso_backend", None)


@pytest.fixture
def nb_host(tmp_path, monkeypatch):
    app = tmp_path / "netbox"
    (app / "netbox").mkdir(parents=True)
    cfg = app / "netbox" / "configuration.py"
    cfg.write_text("ALLOWED_HOSTS = ['*']\n\n"
                   + agent_spoke._NB_SSO_BEGIN + "\nREMOTE_AUTH_ENABLED = True\n"
                   + agent_spoke._NB_SSO_END + "\nTRAILER = 1\n")
    monkeypatch.setattr(agent_spoke, "_NETBOX_CONFIG_PY", str(cfg))
    monkeypatch.setattr(agent_spoke, "_NETBOX_SSO_BACKEND", str(app / "lm_sso_backend.py"))
    monkeypatch.setattr(agent_spoke, "_NETBOX_SSO_CERT_DIR", str(tmp_path / "etc-sso"))
    calls = []

    class _Proc:
        returncode = 0

        async def wait(self):
            return 0

        async def communicate(self):
            return b"", b""

    async def _exec(*args, **kw):
        calls.append(args)
        return _Proc()

    monkeypatch.setattr(agent_spoke.asyncio, "create_subprocess_exec", _exec)
    return {"cfg": cfg, "app": app, "calls": calls, "certdir": tmp_path / "etc-sso"}


def _payload(cert_pem, key_pem, **kw):
    p = {"enabled": True, "tenant": "tid-1", "client_id": "cid-1", "client_secret": "",
         "redirect_uri": "https://netbox.example/oauth/complete/oidc/",
         "group_map": {"g-admin": "Global Admins"}, "allowed_group": "g-allowed",
         "superuser_groups": ["g-admin"],
         "client_cert_pem": cert_pem.decode(), "client_key_pem": key_pem.decode()}
    p.update(kw)
    return p


# ── agent: render + apply ────────────────────────────────────────────────────

def test_render_block_is_valid_python_with_microsoft_button():
    agent = GenericAgent.__new__(GenericAgent)
    block = agent._render_netbox_sso_block(
        {"tenant": "t", "client_id": "c", "group_map": {"a": "B"},
         "allowed_group": "a", "superuser_groups": ["a"],
         "redirect_uri": "https://nb/oauth/complete/oidc/"},
        cert_files=("/x/c.pem", "/x/k.pem"))
    ns = {}
    exec(block, ns)  # noqa: S102 — our own generated config
    assert ns["SOCIAL_AUTH_BACKEND_ATTRS"] == {"oidc": ("Sign in with Microsoft", "microsoft")}
    assert ns["REMOTE_AUTH_BACKEND"] == ["lm_sso_backend.EntraCertOIDCAuth"]
    assert ns["SOCIAL_AUTH_OIDC_SECRET"] == ""
    assert ns["SOCIAL_AUTH_OIDC_CLIENT_KEY_FILE"] == "/x/k.pem"
    assert ns["SOCIAL_AUTH_LM_GROUP_MAP"] == {"a": "B"}
    assert ns["SOCIAL_AUTH_LM_SUPERUSER_GROUPS"] == ["a"]
    assert ns["SOCIAL_AUTH_REDIRECT_IS_HTTPS"] is True
    assert "social_core.pipeline.user.user_details" in ns["SOCIAL_AUTH_PIPELINE"]
    assert ns["SOCIAL_AUTH_PIPELINE"][-1] == "lm_sso_backend.sync_entra_groups"
    # Every custom setting must be SOCIAL_AUTH_* — NetBox forwards nothing else.
    custom = [k for k in ns if k.isupper() and not k.startswith(("SOCIAL_AUTH_", "REMOTE_AUTH_"))]
    assert custom == []


def test_render_block_secret_mode():
    agent = GenericAgent.__new__(GenericAgent)
    ns = {}
    exec(agent._render_netbox_sso_block({"tenant": "t", "client_id": "c",  # noqa: S102
                                         "client_secret": "s"}), ns)
    assert ns["SOCIAL_AUTH_OIDC_SECRET"] == "s"
    assert "SOCIAL_AUTH_OIDC_CLIENT_KEY_FILE" not in ns
    assert "SOCIAL_AUTH_REDIRECT_IS_HTTPS" not in ns


def test_apply_installs_backend_cert_and_block(nb_host):
    cert_pem, key_pem, _ = _make_cert()
    agent = GenericAgent.__new__(GenericAgent)
    res = asyncio.run(agent._apply_netbox_sso(_payload(cert_pem, key_pem)))
    assert res["status"] == "SUCCESS", res
    assert res["auth_mode"] == "certificate" and res["changed"] is True

    backend = nb_host["app"] / "lm_sso_backend.py"
    with open(agent_spoke._NETBOX_SSO_BACKEND_SRC) as f:
        assert backend.read_text() == f.read()
    key_file = nb_host["certdir"] / "client-key.pem"
    assert key_file.read_bytes().strip() == key_pem.strip()
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(nb_host["certdir"].stat().st_mode) == 0o700

    text = nb_host["cfg"].read_text()
    assert text.count(agent_spoke._NB_SSO_BEGIN) == 1  # installer block replaced
    assert "TRAILER = 1" in text and "ALLOWED_HOSTS" in text
    assert "SOCIAL_AUTH_BACKEND_ATTRS = {'oidc': ('Sign in with Microsoft', 'microsoft')}" in text
    assert "SOCIAL_AUTH_OIDC_CLIENT_KEY_FILE = %r" % str(key_file) in text
    assert ("systemctl", "restart", "netbox", "netbox-rq") in nb_host["calls"]

    # Idempotent: a re-push with identical values leaves the config alone.
    nb_host["calls"].clear()
    res2 = asyncio.run(agent._apply_netbox_sso(_payload(cert_pem, key_pem)))
    assert res2["changed"] is False
    assert ("systemctl", "restart", "netbox", "netbox-rq") not in nb_host["calls"]


def test_apply_disable_removes_block_and_key(nb_host):
    cert_pem, key_pem, _ = _make_cert()
    agent = GenericAgent.__new__(GenericAgent)
    asyncio.run(agent._apply_netbox_sso(_payload(cert_pem, key_pem)))
    res = asyncio.run(agent._apply_netbox_sso({"enabled": False}))
    assert res["status"] == "SUCCESS" and res["changed"] is True
    text = nb_host["cfg"].read_text()
    assert agent_spoke._NB_SSO_BEGIN not in text and "TRAILER = 1" in text
    assert not (nb_host["certdir"] / "client-key.pem").exists()


def test_apply_requires_cert_or_secret(nb_host):
    agent = GenericAgent.__new__(GenericAgent)
    res = asyncio.run(agent._apply_netbox_sso(
        {"enabled": True, "tenant": "t", "client_id": "c"}))
    assert res["status"] == "ERROR" and "credentials" in res["message"]


def test_apply_secret_fallback_from_older_hub(nb_host):
    agent = GenericAgent.__new__(GenericAgent)
    res = asyncio.run(agent._apply_netbox_sso(
        {"enabled": True, "tenant": "t", "client_id": "c", "client_secret": "s"}))
    assert res["status"] == "SUCCESS" and res["auth_mode"] == "secret"
    assert "SOCIAL_AUTH_OIDC_SECRET = 's'" in nb_host["cfg"].read_text()


# ── NetBox backend module ────────────────────────────────────────────────────

def test_backend_cert_mode_sends_signed_client_assertion(backend_mod, tmp_path):
    cert_pem, key_pem, cert = _make_cert()
    (tmp_path / "c.pem").write_bytes(cert_pem)
    (tmp_path / "k.pem").write_bytes(key_pem)
    b = backend_mod.EntraCertOIDCAuth({"KEY": "cid-1", "SECRET": "",
                                       "CLIENT_CERT_FILE": str(tmp_path / "c.pem"),
                                       "CLIENT_KEY_FILE": str(tmp_path / "k.pem")})
    assert b.name == "oidc"
    assert b.use_basic_auth() is False and b.auth_complete_credentials() is None
    p = b.auth_complete_params()
    assert "client_secret" not in p and p["client_id"] == "cid-1"
    assert p["client_assertion_type"].endswith("jwt-bearer")
    claims = jwt.decode(p["client_assertion"], cert.public_key(), algorithms=["RS256"],
                        audience=b.access_token_url())
    assert claims["iss"] == claims["sub"] == "cid-1"
    der = cert.public_bytes(serialization.Encoding.DER)
    want_x5t = base64.urlsafe_b64encode(hashlib.sha1(der).digest()).rstrip(b"=").decode()
    assert jwt.get_unverified_header(p["client_assertion"])["x5t"] == want_x5t


def test_backend_secret_mode_is_stock(backend_mod):
    b = backend_mod.EntraCertOIDCAuth({"KEY": "cid", "SECRET": "s"})
    assert b.use_basic_auth() is True
    assert b.auth_complete_credentials() == ("cid", "s")
    assert "client_assertion" not in b.auth_complete_params()


class _Groups:
    def __init__(self):
        self.current = []
        store = {}

        class _Mgr:
            def filter(self, name):
                return types.SimpleNamespace(first=lambda: store.get(name))

            def get_or_create(self, name):
                store.setdefault(name, types.SimpleNamespace(name=name))
                return store[name], True

        self.model = types.SimpleNamespace(objects=_Mgr())

    def set(self, groups):
        self.current = list(groups)


class _User:
    def __init__(self, superuser=False):
        self.username = "alice"
        self.groups = _Groups()
        self.is_superuser = superuser
        self.saved = []

    def save(self, update_fields=None):
        self.saved.append(update_fields)


def _id_token(claims):
    enc = lambda d: base64.urlsafe_b64encode(  # noqa: E731
        __import__("json").dumps(d).encode()).rstrip(b"=").decode()
    return enc({"alg": "none"}) + "." + enc(claims) + ".sig"


@pytest.fixture
def dj_settings(monkeypatch):
    s = types.SimpleNamespace(SOCIAL_AUTH_LM_GROUP_MAP={"g-admin": "Global Admins",
                                                        "g-ops": "Operators"},
                              SOCIAL_AUTH_LM_ALLOWED_GROUP="g-ops, g-admin",
                              SOCIAL_AUTH_LM_SUPERUSER_GROUPS=["g-admin"],
                              REMOTE_AUTH_AUTO_CREATE_GROUPS=True)
    conf = types.ModuleType("django.conf")
    conf.settings = s
    monkeypatch.setitem(sys.modules, "django", types.ModuleType("django"))
    monkeypatch.setitem(sys.modules, "django.conf", conf)
    return s


def test_sync_maps_groups_and_grants_superuser(backend_mod, dj_settings):
    u = _User()
    backend_mod.sync_entra_groups(backend_mod.EntraCertOIDCAuth({}), u,
                                  {"id_token": _id_token({"groups": ["g-admin", "x"]})})
    assert [g.name for g in u.groups.current] == ["Global Admins"]
    assert u.is_superuser is True and u.saved == [["is_superuser"]]


def test_sync_revokes_superuser_when_admin_group_dropped(backend_mod, dj_settings):
    u = _User(superuser=True)
    backend_mod.sync_entra_groups(backend_mod.EntraCertOIDCAuth({}), u,
                                  {"id_token": _id_token({"groups": ["g-ops"]})})
    assert [g.name for g in u.groups.current] == ["Operators"]
    assert u.is_superuser is False


def test_sync_refuses_user_outside_allowed_groups(backend_mod, dj_settings):
    with pytest.raises(Exception):
        backend_mod.sync_entra_groups(backend_mod.EntraCertOIDCAuth({}), _User(),
                                      {"id_token": _id_token({"groups": ["other"]})})


def test_sync_uses_app_token_graph_lookup_without_groups_claim(backend_mod, dj_settings,
                                                               monkeypatch):
    seen = {}
    monkeypatch.setattr(backend_mod, "_app_graph_token", lambda b: "app-tok")

    def _ids(url, tok):
        seen["url"], seen["tok"] = url, tok
        return ["g-ops"]
    monkeypatch.setattr(backend_mod, "_graph_ids", _ids)
    b = backend_mod.EntraCertOIDCAuth({"CLIENT_KEY_FILE": "k", "CLIENT_CERT_FILE": "c"})
    u = _User()
    backend_mod.sync_entra_groups(b, u, {"id_token": _id_token({"oid": "user-oid"})})
    assert "/users/user-oid/transitiveMemberOf" in seen["url"] and seen["tok"] == "app-tok"
    assert [g.name for g in u.groups.current] == ["Operators"]
