"""Tests for the pluggable credential store (env + Key Vault stub) and the
OIDC / break-glass resolution helpers.

The Key Vault provider is exercised with a stubbed Azure SDK (the real SDK is
an optional dep not installed in the test env): we monkeypatch
``credential_store._AZURE_AVAILABLE`` + ``SecretClient`` +
``DefaultAzureCredential`` so the provider's ``ready``/``get_secret`` path runs
without Azure. The graceful-degrade path (no SDK / no vault URL) is also
covered, as are the ``resolve_private_key_material`` (cert key from path vs
``kv:`` ref vs bare secret) and ``resolve_password_hash`` (break-glass)
helpers used by ``security/oidc.py`` and ``routes/auth.py``.
"""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import security.credential_store as cs  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate():
    """Reset the cached provider + clear per-test env between tests."""
    cs.reset_credential_provider()
    saved = {k: os.environ.pop(k, None) for k in (
        "LM_KEYVAULT_URL", "LM_KEYVAULT_CLIENT_ID", "LM_TEST_SECRET",
        "LM_TEST_HASH", "LM_OIDC_CLIENT_KEY")}
    yield
    cs.reset_credential_provider()
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v


# ── EnvCredentialProvider ────────────────────────────────────────────────────

def test_env_provider_always_ready():
    assert cs.EnvCredentialProvider().ready is True
    assert cs.EnvCredentialProvider().name == "env"


def test_env_provider_reads_environment():
    os.environ["LM_TEST_SECRET"] = "vault-me"
    assert cs.EnvCredentialProvider().get_secret("LM_TEST_SECRET") == "vault-me"


def test_env_provider_missing_returns_none():
    assert cs.EnvCredentialProvider().get_secret("LM_NOPE_MISSING") is None
    assert cs.EnvCredentialProvider().get_secret("") is None


# ── KeyVaultCredentialProvider (stubbed SDK) ─────────────────────────────────

class _FakeSecret:
    def __init__(self, value):
        self.value = value


class _FakeSecretClient:
    """Records construction + serves get_secret(name) from a dict."""
    instances = []

    def __init__(self, vault_url, credential):
        self.vault_url = vault_url
        self.credential = credential
        self.store = {}
        _FakeSecretClient.instances.append(self)

    def set(self, name, value):
        self.store[name] = value

    def get_secret(self, name):
        return _FakeSecret(self.store.get(name))


def _enable_fake_kv(monkeypatch, store):
    """Wire a fake SecretClient into the module so the KV provider is 'ready'."""
    _FakeSecretClient.instances.clear()
    monkeypatch.setattr(cs, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(cs, "SecretClient",
                        lambda vault_url, credential: store.attach(vault_url, credential))
    monkeypatch.setattr(cs, "DefaultAzureCredential", lambda **kw: "fake-cred")


def test_kv_provider_not_ready_without_sdk_or_url():
    p = cs.KeyVaultCredentialProvider("")
    assert p.ready is False
    assert p.get_secret("x") is None
    # vault URL set but SDK unavailable (the test env) -> still not ready
    p = cs.KeyVaultCredentialProvider("https://kv.vault.azure.net")
    assert p.ready is False
    assert p.get_secret("x") is None


def test_kv_provider_ready_and_fetches(monkeypatch):
    bag = type("B", (), {"attach": lambda self, u, c: (client := _FakeSecretClient(u, c))})()
    # Simpler: build the client up front and have the lambda return it.
    client = _FakeSecretClient("https://kv.vault.azure.net", "fake-cred")
    monkeypatch.setattr(cs, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(cs, "SecretClient",
                        lambda vault_url, credential: client)
    monkeypatch.setattr(cs, "DefaultAzureCredential", lambda **kw: "fake-cred")
    client.set("oidc-client-key", "PEM-PEM-PEM")

    p = cs.KeyVaultCredentialProvider("https://kv.vault.azure.net")
    assert p.ready is True
    assert p.get_secret("oidc-client-key") == "PEM-PEM-PEM"
    # Cached: a second fetch with the client mutated still returns the cached
    # value within the TTL (proves the cache, not a re-fetch).
    client.store["oidc-client-key"] = "CHANGED"
    assert p.get_secret("oidc-client-key") == "PEM-PEM-PEM"


def test_kv_provider_swallows_fetch_errors(monkeypatch):
    class _BrokenClient:
        def get_secret(self, name):
            raise RuntimeError("vault down")
    monkeypatch.setattr(cs, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(cs, "SecretClient",
                        lambda vault_url, credential: _BrokenClient())
    monkeypatch.setattr(cs, "DefaultAzureCredential", lambda **kw: "fake-cred")
    p = cs.KeyVaultCredentialProvider("https://kv.vault.azure.net")
    assert p.get_secret("oidc-client-key") is None  # never raises


# ── Factory ──────────────────────────────────────────────────────────────────

def test_factory_defaults_to_env():
    p = cs.get_credential_provider()
    assert p.name == "env"
    assert p is cs.get_credential_provider()  # cached singleton


def test_factory_selects_keyvault_when_configured(monkeypatch):
    client = _FakeSecretClient("https://kv.vault.azure.net", "fake-cred")
    monkeypatch.setattr(cs, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(cs, "SecretClient",
                        lambda vault_url, credential: client)
    monkeypatch.setattr(cs, "DefaultAzureCredential", lambda **kw: "fake-cred")
    os.environ["LM_KEYVAULT_URL"] = "https://kv.vault.azure.net"
    cs.reset_credential_provider()
    p = cs.get_credential_provider()
    assert p.name == "keyvault"
    assert p.ready is True


def test_factory_falls_back_to_env_when_sdk_missing():
    # SDK unavailable (real test env) even though a vault URL is set.
    os.environ["LM_KEYVAULT_URL"] = "https://kv.vault.azure.net"
    cs.reset_credential_provider()
    p = cs.get_credential_provider()
    assert p.name == "env"


# ── resolve_private_key_material ─────────────────────────────────────────────

def test_resolve_key_from_kv_ref(monkeypatch):
    client = _FakeSecretClient("https://kv.vault.azure.net", "fake-cred")
    monkeypatch.setattr(cs, "_AZURE_AVAILABLE", True)
    monkeypatch.setattr(cs, "SecretClient",
                        lambda vault_url, credential: client)
    monkeypatch.setattr(cs, "DefaultAzureCredential", lambda **kw: "fake-cred")
    client.set("oidc-key", "PEM-BYTES")
    os.environ["LM_KEYVAULT_URL"] = "https://kv.vault.azure.net"
    cs.reset_credential_provider()
    assert cs.resolve_private_key_material("kv:oidc-key") == b"PEM-BYTES"


def test_resolve_key_from_existing_file_absolute_and_relative():
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        f.write(b"FILE-PEM")
        abs_path = f.name
    try:
        assert cs.resolve_private_key_material(abs_path) == b"FILE-PEM"
    finally:
        os.unlink(abs_path)
    # A relative bare filename that exists in the cwd reads the file
    # (backward compat with the historical key_path).
    cwd = os.getcwd()
    d = tempfile.mkdtemp()
    try:
        os.chdir(d)
        with open("key.pem", "wb") as f:
            f.write(b"REL-PEM")
        assert cs.resolve_private_key_material("key.pem") == b"REL-PEM"
    finally:
        os.chdir(cwd)
        import shutil
        shutil.rmtree(d)


def test_resolve_key_path_shaped_but_missing_returns_none():
    # Path-shaped ref that doesn't exist -> None (not misread as a secret).
    assert cs.resolve_private_key_material("/no/such/key.pem") is None
    assert cs.resolve_private_key_material("./missing.pem") is None


def test_resolve_key_bare_secret_name_uses_env():
    os.environ["LM_TEST_SECRET"] = "ENV-PEM"
    assert cs.resolve_private_key_material("LM_TEST_SECRET") == b"ENV-PEM"


def test_resolve_key_empty_and_missing_returns_none():
    assert cs.resolve_private_key_material("") is None
    assert cs.resolve_private_key_material("kv:missing") is None
    assert cs.resolve_private_key_material("no-such-secret") is None


# ── resolve_password_hash (break-glass) ──────────────────────────────────────

def test_password_hash_stored_wins():
    assert cs.resolve_password_hash({"password_hash": "H"}) == "H"


def test_password_hash_ref_falls_back_to_store():
    os.environ["LM_TEST_HASH"] = "HASH-FROM-ENV"
    assert cs.resolve_password_hash({"password_hash_ref": "LM_TEST_HASH"}) == "HASH-FROM-ENV"


def test_password_hash_ref_missing_returns_none():
    assert cs.resolve_password_hash({"password_hash_ref": "LM_NOPE"}) is None


def test_password_hash_none_when_nothing_set():
    assert cs.resolve_password_hash({}) is None
    assert cs.resolve_password_hash(None) is None


def test_password_hash_store_error_returns_none(monkeypatch):
    class _Boom(cs.CredentialProvider):
        @property
        def ready(self):
            return True
        def get_secret(self, name):
            raise RuntimeError("store exploded")
    # Stored hash still wins even if a ref would blow up (ref isn't reached).
    assert cs.resolve_password_hash({"password_hash": "H"}) == "H"
    # A ref whose store raises -> None (never propagates).
    assert cs.resolve_password_hash({"password_hash_ref": "x"},
                                    provider=_Boom()) is None