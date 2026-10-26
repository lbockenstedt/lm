"""R5: Entra app tokens are cached and shared instead of minted per call.

The Entra token endpoint and Key Vault are stubbed with ``httpx.MockTransport``;
``build_client_assertion`` is stubbed so no real cert/key is needed.
"""
import asyncio
import os
import time

import httpx
import pytest

import key_vault
import security.oidc as oidc

VAULT = "https://lm-vault.vault.azure.net"
GRAPH = "https://graph.microsoft.com/.default"


class _Cfg:
    def __init__(self, cert_path):
        self.tenant_id = "tid"
        self.client_id = "cid"
        self.key_path = "/nonexistent/key.pem"
        self.cert_path = cert_path


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setattr(oidc, "build_client_assertion", lambda cfg, ep: "assertion")
    cert = tmp_path / "client-cert.pem"
    cert.write_text("cert")
    return _Cfg(str(cert))


class _Entra:
    """Token endpoint stub that counts mints and hands out tok-1, tok-2, ..."""

    def __init__(self, expires_in=3600, vault_statuses=()):
        self.mints = 0
        self.expires_in = expires_in
        self.vault_statuses = list(vault_statuses)
        self.vault_auth = []

    async def handler(self, request):
        if request.url.path.endswith("/oauth2/v2.0/token"):
            self.mints += 1
            await asyncio.sleep(0.01)  # let concurrent callers pile up
            body = {"access_token": f"tok-{self.mints}"}
            if self.expires_in is not None:
                body["expires_in"] = self.expires_in
            return httpx.Response(200, json=body)
        self.vault_auth.append(request.headers.get("Authorization"))
        status = self.vault_statuses.pop(0) if self.vault_statuses else 200
        return httpx.Response(status, json={"value": "secret-value"})

    def client(self):
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_token_is_reused_until_near_expiry(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            return [await oidc.fetch_app_token(cfg, GRAPH, http=c) for _ in range(5)]

    assert _run(go()) == ["tok-1"] * 5
    assert entra.mints == 1


def test_concurrent_callers_share_one_mint(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            return await asyncio.gather(
                *[oidc.fetch_app_token(cfg, GRAPH, http=c) for _ in range(30)])

    assert set(_run(go())) == {"tok-1"}
    assert entra.mints == 1


def test_short_lived_or_unknown_lifetime_token_is_not_cached(cfg):
    for expires_in in (60, None):  # 60s is inside the 60s safety margin
        oidc.clear_app_token_cache()
        entra = _Entra(expires_in=expires_in)

        async def go():
            async with entra.client() as c:
                await oidc.fetch_app_token(cfg, GRAPH, http=c)
                await oidc.fetch_app_token(cfg, GRAPH, http=c)

        _run(go())
        assert entra.mints == 2, expires_in


def test_max_age_forces_a_fresh_mint(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            await oidc.fetch_app_token(cfg, GRAPH, http=c)
            assert await oidc.fetch_app_token(cfg, GRAPH, http=c, max_age=300) == "tok-1"
            time.sleep(0.01)
            return await oidc.fetch_app_token(cfg, GRAPH, http=c, max_age=0.001)

    assert _run(go()) == "tok-2"


def test_new_cert_file_or_config_save_drops_cached_token(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            await oidc.fetch_app_token(cfg, GRAPH, http=c)
            # "Generate certificate" rewrites the file in place → new mtime.
            later = time.time() + 10
            os.utime(cfg.cert_path, (later, later))
            assert await oidc.fetch_app_token(cfg, GRAPH, http=c) == "tok-2"
            oidc.clear_app_token_cache()
            return await oidc.fetch_app_token(cfg, GRAPH, http=c)

    assert _run(go()) == "tok-3"


def test_each_scope_gets_its_own_token(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            a = await oidc.fetch_app_token(cfg, GRAPH, http=c)
            b = await oidc.fetch_app_token(cfg, "https://vault.azure.net/.default", http=c)
            return a, b

    assert _run(go()) == ("tok-1", "tok-2")


def test_key_vault_reads_share_one_token(cfg):
    entra = _Entra()

    async def go():
        async with entra.client() as c:
            return await asyncio.gather(
                *[key_vault.get_secret(cfg, VAULT, f"cred-{i}", http=c) for i in range(20)])

    assert _run(go()) == ["secret-value"] * 20
    assert entra.mints == 1


def test_key_vault_401_retries_once_with_a_fresh_token(cfg):
    entra = _Entra(vault_statuses=[200, 401, 200])

    async def go():
        async with entra.client() as c:
            await key_vault.get_secret(cfg, VAULT, "a", http=c)   # mints tok-1
            return await key_vault.get_secret(cfg, VAULT, "b", http=c)  # 401 → tok-2

    assert _run(go()) == "secret-value"
    assert entra.mints == 2
    assert entra.vault_auth[-2:] == ["Bearer tok-1", "Bearer tok-2"]


def test_key_vault_persistent_401_is_not_retried_forever(cfg):
    entra = _Entra(vault_statuses=[401, 401, 401])

    async def go():
        async with entra.client() as c:
            await key_vault.get_secret(cfg, VAULT, "a", http=c)

    with pytest.raises(key_vault.KeyVaultError):
        _run(go())
    assert len(entra.vault_auth) == 2
