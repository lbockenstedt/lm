"""Tier-1 off-disk Fernet key sourcing: LM_FERNET_KEY_KV_SECRET lets the
primary at-rest key come from Azure Key Vault instead of LM_FERNET_KEY,
via the shared security.credential_store provider abstraction.

Asserts:
  * no LM_FERNET_KEY_KV_SECRET set -> pure env path, unchanged from before
    this feature existed (source == "env").
  * LM_FERNET_KEY_KV_SECRET set + a ready keyvault provider that resolves
    the secret -> the vault value wins (source == "keyvault:<name>"), and
    HubEncryption() actually boots on it end-to-end (encrypt/decrypt works,
    primary_key() returns the vault value).
  * a KV fetch failure (wrong/not-ready provider, or get_secret raising)
    falls back to LM_FERNET_KEY when present, with a warning logged.
  * KV fetch failure + no LM_FERNET_KEY at all -> resolves to nothing, and
    HubEncryption() raises (fail-closed), matching the pre-Tier-1 behavior
    for "no key available at all".
  * _fetch_key_from_vault never raises regardless of what the provider does.
"""
import os
import sys

import pytest
from cryptography.fernet import Fernet

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import security.encryption as enc
import security.credential_store as credential_store


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


def _clear_env(monkeypatch):
    for var in ("LM_FERNET_KEY", "LM_FERNET_KEY_PREVIOUS", "LM_FERNET_KEY_KV_SECRET",
               "LM_DROP_FERNET_KEY_ENV", "LM_KEEP_FERNET_KEY_ENV"):
        monkeypatch.delenv(var, raising=False)


# ── _resolve_primary_key ─────────────────────────────────────────────────────

def test_resolve_env_only_when_kv_secret_unset(monkeypatch):
    _clear_env(monkeypatch)
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", key)
    h = enc.HubEncryption.__new__(enc.HubEncryption)
    assert h._resolve_primary_key() == (key, "env")


def test_resolve_prefers_vault_when_kv_secret_set_and_reachable(monkeypatch):
    _clear_env(monkeypatch)
    vault_key = Fernet.generate_key().decode()
    env_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", env_key)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(secrets={"lm-fernet-key": vault_key})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)

    h = enc.HubEncryption.__new__(enc.HubEncryption)
    key_str, source = h._resolve_primary_key()
    assert key_str == vault_key
    assert source == "keyvault:lm-fernet-key"


def test_resolve_falls_back_to_env_when_vault_unreachable(monkeypatch, caplog):
    _clear_env(monkeypatch)
    env_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", env_key)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(ready=False)  # vault configured but not reachable
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)

    h = enc.HubEncryption.__new__(enc.HubEncryption)
    with caplog.at_level("WARNING"):
        key_str, source = h._resolve_primary_key()
    assert key_str == env_key
    assert source == "env"
    assert "Falling back to LM_FERNET_KEY" in caplog.text


def test_resolve_returns_nothing_when_vault_fails_and_no_env(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(ready=False)
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)

    h = enc.HubEncryption.__new__(enc.HubEncryption)
    assert h._resolve_primary_key() == ("", "")


# ── _fetch_key_from_vault ────────────────────────────────────────────────────

def test_fetch_returns_none_when_provider_is_not_keyvault(monkeypatch):
    provider = _FakeProvider(name="env", secrets={"x": "y"})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    assert enc.HubEncryption._fetch_key_from_vault("x") is None


def test_fetch_returns_none_when_provider_not_ready(monkeypatch):
    provider = _FakeProvider(ready=False, secrets={"x": "y"})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    assert enc.HubEncryption._fetch_key_from_vault("x") is None


def test_fetch_never_raises_when_get_secret_raises(monkeypatch, caplog):
    provider = _FakeProvider(raise_on_get=True)
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    with caplog.at_level("WARNING"):
        result = enc.HubEncryption._fetch_key_from_vault("x")
    assert result is None
    assert "Key Vault fetch" in caplog.text


def test_fetch_returns_the_secret_value_on_success(monkeypatch):
    provider = _FakeProvider(secrets={"lm-fernet-key": "the-value"})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)
    assert enc.HubEncryption._fetch_key_from_vault("lm-fernet-key") == "the-value"


# ── end-to-end HubEncryption() construction ─────────────────────────────────

def test_hub_encryption_boots_on_vault_key_end_to_end(monkeypatch):
    _clear_env(monkeypatch)
    vault_key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(secrets={"lm-fernet-key": vault_key})
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)

    h = enc.HubEncryption()
    assert h.primary_key() == vault_key
    token = h.encrypt("secret-payload")
    assert h.decrypt(token) == "secret-payload"


def test_hub_encryption_fails_closed_when_nothing_resolves(monkeypatch):
    _clear_env(monkeypatch)
    monkeypatch.setenv("LM_FERNET_KEY_KV_SECRET", "lm-fernet-key")
    provider = _FakeProvider(ready=False)  # vault unreachable, and no LM_FERNET_KEY set
    monkeypatch.setattr(credential_store, "get_credential_provider", lambda: provider)

    with pytest.raises(RuntimeError, match="No Fernet key available"):
        enc.HubEncryption()


def test_plain_env_path_is_unaffected_by_this_feature(monkeypatch):
    """No LM_FERNET_KEY_KV_SECRET at all — must behave identically to the
    pre-Tier-1 code (this is the existing/default deployment shape)."""
    _clear_env(monkeypatch)
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("LM_FERNET_KEY", key)
    h = enc.HubEncryption()
    assert h.primary_key() == key
    token = h.encrypt("secret-payload")
    assert h.decrypt(token) == "secret-payload"
