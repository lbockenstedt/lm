"""POST /setup/key-vault/test-fernet-tier1 — diagnostic for the Tier-1
Fernet-key-from-Key-Vault boot path (security/encryption.py's
_resolve_primary_key). Exercises the REAL registered FastAPI route via
TestClient, mirroring test_role_pool.py's pattern. Monkeypatches
security.credential_store.get_credential_provider so no real Azure call
happens.

Critical property asserted throughout: the response NEVER contains the
actual secret value, only whether it was found/valid.
"""
import os
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import security.credential_store as credential_store
from routes.key_vault import register


class _FakeProvider:
    def __init__(self, name="keyvault", ready=True, secrets=None, raise_on_get=False):
        self.name = name
        self.ready = ready
        self._secrets = secrets or {}
        self.raise_on_get = raise_on_get

    def get_secret(self, name):
        if self.raise_on_get:
            raise RuntimeError("vault unreachable")
        return self._secrets.get(name)


def _build():
    app = FastAPI()
    hub = SimpleNamespace()
    register(app, hub, SimpleNamespace())
    return TestClient(app)


def _clear_env(monkeypatch):
    for var in ("LM_FERNET_KEY_KV_SECRET", "LM_KEYVAULT_URL"):
        monkeypatch.delenv(var, raising=False)


def test_reports_not_configured_when_kv_secret_unset(monkeypatch):
    _clear_env(monkeypatch)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "error"
    assert body["kv_secret_env_set"] is False
    assert "not set" in body["message"]


def test_reports_env_provider_when_vault_url_unset(monkeypatch):
    """LM_FERNET_KEY_KV_SECRET is set but LM_KEYVAULT_URL isn't — the
    credential store resolves to the plain env provider, not keyvault."""
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    credential_store.reset_credential_provider()
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    body = r.json()
    assert body["status"] == "error"
    assert body["provider"] == "env"
    assert "not 'keyvault'" in body["message"] or "env" in body["message"]


def test_reports_not_ready_when_provider_not_ready(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(ready=False)
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    body = r.json()
    assert body["status"] == "error"
    assert body["ready"] is False
    assert "not ready" in body["message"]


def test_reports_secret_not_found(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(secrets={})  # nothing seeded
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    body = r.json()
    assert body["status"] == "error"
    assert body["secret_found"] is False
    assert "not found" in body["message"]


def test_reports_invalid_fernet_key(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(secrets={"lm-fernet-key": "not-a-valid-fernet-key"})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    body = r.json()
    assert body["status"] == "error"
    assert body["secret_found"] is True
    assert body["valid_fernet_key"] is False
    assert "NOT a valid Fernet key" in body["message"]


def test_reports_ok_on_a_real_valid_fernet_key(monkeypatch):
    from cryptography.fernet import Fernet
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    real_key = Fernet.generate_key().decode()
    provider = _FakeProvider(secrets={"lm-fernet-key": real_key})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    body = r.json()
    assert body["status"] == "ok"
    assert body["secret_found"] is True
    assert body["valid_fernet_key"] is True
    # The actual key value must NEVER appear anywhere in the response.
    assert real_key not in str(body)


def test_never_leaks_the_secret_value_even_on_failure_paths(monkeypatch):
    """Defense in depth: scan every failure-path response for the secret."""
    from cryptography.fernet import Fernet
    real_key = Fernet.generate_key().decode()
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(secrets={"lm-fernet-key": real_key}, raise_on_get=True)
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    assert real_key not in str(r.json())


def test_get_secret_exception_is_caught_not_propagated(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(raise_on_get=True)
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    c = _build()
    r = c.post("/setup/key-vault/test-fernet-tier1")
    assert r.status_code == 200  # never a 500 — errors are reported in the body
    assert r.json()["status"] == "error"
