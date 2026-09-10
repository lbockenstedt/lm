"""Tests for LE issue-time resolution of a *vaulted* DNS-01 credential
(``_le_resolve_vault_dns_cred`` in ``routes/net_services.py``).

When a cert is issued with a ``dns_vault_credential`` {bucket,name} reference,
the hub resolves the secret VALUE unattended (``cred_vault.automation_get``) and
rewrites the request body into the inline spoke DNS-cred shape
(``dns_provider`` + ``dns_creds`` INI, or HE-login user/pass) before relaying to
the le spoke — the plaintext is never returned to the browser. Reach is
enforced: a tenant-admin may only reference buckets for their own tenants.

The helper is a closure inside ``register``; we lift it with ``ast`` (stripping
nothing — it has no decorator) and exec it in a namespace wired with fakes.
"""
import ast
import asyncio
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cred_vault  # noqa: E402

_NS = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "net_services.py")


class _HTTPError(Exception):
    def __init__(self, status_code=400, detail=""):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _load(is_admin, tenants, hub):
    src = open(_NS).read()
    tree = ast.parse(src)
    ns = {
        "Request": object, "HTTPException": _HTTPError,
        "logger": types.SimpleNamespace(warning=lambda *a, **k: None, info=lambda *a, **k: None),
        "app": types.SimpleNamespace(state=types.SimpleNamespace(hub=hub)),
        "_session_user": lambda request: {"user": {"tenants": tenants}},
        "_is_admin": lambda sess: is_admin,
        "_LE_DNS_PLUGIN_ALIAS": {"he": "rfc2136"},
    }
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and \
                node.name == "_le_resolve_vault_dns_cred":
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns["_le_resolve_vault_dns_cred"]


def _patch_get(monkeypatch, value):
    async def _fake(hub, bucket, name):
        return value
    monkeypatch.setattr(cred_vault, "automation_get", _fake)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_no_ref_is_noop():
    fn = _load(True, [], object())
    body = {"domain": "x.example", "dns_credential": "keep"}
    _run(fn(object(), body))
    assert body == {"domain": "x.example", "dns_credential": "keep"}


def test_global_admin_resolves_cloudflare(monkeypatch):
    _patch_get(monkeypatch, {"provider": "cloudflare",
                             "dns_creds": "dns_cloudflare_api_token = TKN"})
    fn = _load(True, [], object())
    body = {"dns_vault_credential": {"bucket": "t-acme", "name": "cf"},
            "dns_credential": "should-be-dropped"}
    _run(fn(object(), body))
    # The secret-free reference is now KEPT (normalized to {bucket,name}) so it
    # round-trips to the spoke ledger + is re-resolvable on renew/reinstall.
    assert body["dns_vault_credential"] == {"bucket": "t-acme", "name": "cf"}
    assert "dns_credential" not in body            # vault ref supersedes named cred
    assert body["dns_provider"] == "cloudflare"
    assert body["dns_creds"] == "dns_cloudflare_api_token = TKN"


def test_provider_alias_he_maps_to_rfc2136(monkeypatch):
    _patch_get(monkeypatch, {"provider": "he", "dns_creds": "dns_rfc2136_server = 1.2.3.4"})
    fn = _load(True, [], object())
    body = {"dns_vault_credential": {"bucket": "__admin__", "name": "he"}}
    _run(fn(object(), body))
    assert body["dns_provider"] == "rfc2136"
    assert body["dns_creds"] == "dns_rfc2136_server = 1.2.3.4"


def test_he_login_sets_user_pass(monkeypatch):
    _patch_get(monkeypatch, {"provider": "he-login",
                             "he_username": "u@e", "he_password": "pw"})
    fn = _load(True, [], object())
    body = {"dns_vault_credential": {"bucket": "t-acme", "name": "he-acct"}}
    _run(fn(object(), body))
    assert body["dns_provider"] == "he-login"
    assert body["he_username"] == "u@e" and body["he_password"] == "pw"
    assert "dns_creds" not in body


def test_tenant_admin_without_reach_is_404(monkeypatch):
    _patch_get(monkeypatch, {"provider": "cloudflare", "dns_creds": "x = y"})
    fn = _load(False, ["t-mine"], object())
    body = {"dns_vault_credential": {"bucket": "t-other", "name": "cf"}}
    with pytest.raises(_HTTPError) as ei:
        _run(fn(object(), body))
    assert ei.value.status_code == 404


def test_tenant_admin_with_reach_resolves(monkeypatch):
    _patch_get(monkeypatch, {"provider": "cloudflare", "dns_creds": "x = y"})
    fn = _load(False, ["t-mine"], object())
    body = {"dns_vault_credential": {"bucket": "t-mine", "name": "cf"}}
    _run(fn(object(), body))
    assert body["dns_provider"] == "cloudflare" and body["dns_creds"] == "x = y"


def test_missing_provider_is_400(monkeypatch):
    _patch_get(monkeypatch, {"dns_creds": "x = y"})  # no provider
    fn = _load(True, [], object())
    body = {"dns_vault_credential": {"bucket": "t-acme", "name": "cf"}}
    with pytest.raises(_HTTPError) as ei:
        _run(fn(object(), body))
    assert ei.value.status_code == 400


def _load_post_route(name="le_set_dns_cred", *, vault_enabled=True, relay=None,
                     tenant="t-acme"):
    """Lift a vault-gated POST route with the ``@app.post`` decorator stripped
    and exec it in a minimal namespace.

    The route's closure over ``_le_vault_enabled`` / ``_le_tenant`` /
    ``_le_request`` is supplied here, so a single helper can drive BOTH the
    vault-ON (raw creation refused) and vault-OFF (spoke-local store is the
    supported path) branches."""
    calls = []

    async def _relay(command, body=None, **kw):
        calls.append((command, body))
        return (object(), "le-1", (relay if relay is not None else {"status": "ok"}))

    src = open(_NS).read()
    tree = ast.parse(src)
    ns = {
        "Request": object,
        "HTTPException": _HTTPError,
        "_le_vault_enabled": lambda: vault_enabled,
        "_le_tenant": lambda _req: tenant,
        "_le_request": _relay,
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == name:
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _NS, "exec"), ns)
    return ns[name], calls


class _Req:
    """Minimal Request stand-in exposing the awaited ``.json()`` the routes use."""

    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


# ── vault ON: raw credential creation is refused, steer to the vault ────────

def test_set_dns_cred_post_disabled_when_vault_enabled():
    fn, _ = _load_post_route(vault_enabled=True)
    with pytest.raises(_HTTPError) as ei:
        _run(fn(_Req({"name": "cf", "dns_provider": "cloudflare"})))
    assert ei.value.status_code == 409
    assert "Credential Vault" in ei.value.detail


def test_set_he_login_post_disabled_when_vault_enabled():
    fn, _ = _load_post_route("le_set_he_login", vault_enabled=True)
    with pytest.raises(_HTTPError) as ei:
        _run(fn(_Req({"username": "u@e", "password": "pw"})))
    assert ei.value.status_code == 409
    assert "Credential Vault" in ei.value.detail


# ── vault OFF: the spoke-local store is the supported path and stays open ───
#
# Pins the user-reported bug: with NO vault configured the DNS-01 modal said
# "New DNS-01 credentials are now managed in the Credential Vault ... Creating
# raw credentials here is disabled", leaving nowhere at all to store a DNS-01
# credential. Creation must work when there is no vault to steer to.

def test_set_dns_cred_post_allowed_when_no_vault():
    fn, calls = _load_post_route(vault_enabled=False)
    out = _run(fn(_Req({"name": "cf", "dns_provider": "cloudflare",
                        "dns_creds": "dns_cloudflare_api_token = x"})))
    assert out == {"status": "ok"}
    assert len(calls) == 1
    command, body = calls[0]
    assert command == "LE_SET_DNS_CRED"
    assert body["name"] == "cf" and body["dns_provider"] == "cloudflare"


def test_set_dns_cred_tenant_is_server_derived_not_client_supplied():
    """A client must not be able to write into another tenant's cred store."""
    fn, calls = _load_post_route(vault_enabled=False, tenant="t-mine")
    _run(fn(_Req({"name": "cf", "tenant_id": "t-someone-else"})))
    assert calls[0][1]["tenant_id"] == "t-mine"


def test_set_dns_cred_non_dict_body_does_not_explode():
    fn, calls = _load_post_route(vault_enabled=False)
    _run(fn(_Req(["not", "a", "dict"])))
    assert calls[0][1] == {"tenant_id": "t-acme"}


def test_set_he_login_post_allowed_when_no_vault():
    fn, calls = _load_post_route("le_set_he_login", vault_enabled=False)
    out = _run(fn(_Req({"username": "u@e", "password": "pw"})))
    assert out == {"status": "ok"}
    assert calls[0][0] == "LE_SET_HE_LOGIN"
    assert calls[0][1]["username"] == "u@e"
