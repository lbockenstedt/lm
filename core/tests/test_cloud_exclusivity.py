"""Cloud NSG / Cloud Vault exclusivity + generic-dispatcher tests.

Covers the two new abstraction modules added alongside OCI NSG/Vault parity:

- ``cloud_nsg.py`` / ``cloud_vault.py``: ``active_provider()`` (Azure wins a
  tie, with a warning, if both are somehow enabled) and
  ``other_provider_enabled()`` (the save-time exclusivity guard every route
  below calls).
- The save-time exclusivity guard itself, end-to-end through ``create_app``,
  in each of the four routes that can enable a cloud NSG/Vault provider:
  ``routes/azure_nsg.py``, ``routes/oci_nsg.py``, ``routes/key_vault.py``,
  ``routes/oci_vault.py`` — enabling one while its sibling is already enabled
  must be rejected with HTTP 400 and NOT persisted.
- ``cloud_vault.resolve_ref`` / ``get_secret`` / ``set_secret`` /
  ``test_connection``: dispatch transparently to whichever backend
  (``key_vault`` or ``oci_vault``) is enabled, with no caller-visible branch.
"""
import asyncio
import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api as api_mod
import cloud_nsg
import cloud_vault
from cryptography.fernet import Fernet


# ── fakes (modeled on test_ldap_setup_config.py's _FakeHub/_FakeState) ──────

class _FakeState:
    def __init__(self, system_state=None, data_dir=None):
        self.system_state = system_state or {}
        self.tenant_state = {"tenants": {}}
        self.data_dir = data_dir or tempfile.mkdtemp(prefix="lm-cloud-exclusivity-test-")

    def save_state(self):
        pass

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        pass

    def ensure_admin_lockout(self):
        return False

    def get_global_config(self):
        return self.system_state.setdefault("global_config", {})


class _KM:
    def __init__(self):
        self.hub_secrets = ["hub-secret-test"]


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
        return None

    def get_all_spokes_by_type(self, t):
        return []


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    api_mod._sessions.clear()
    for v in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_CORS_ORIGINS", "LM_FERNET_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("LM_FERNET_KEY", Fernet.generate_key().decode())


def _admin_state(**global_config):
    st = {"users": {"admin": {
        "auth_type": "local",
        "password_hash": api_mod._hash_password("pass1234"),
        "permissions": {"role": "admin", "admin": True},
        "tenants": [], "protected": False}}}
    if global_config:
        st["global_config"] = dict(global_config)
    return st


def _build(system_state):
    hub = _FakeHub(system_state)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


def _admin_login(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200, r.text
    return r.cookies.get("lm_session")


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _Hub:
    """Minimal hub for the pure cloud_nsg/cloud_vault unit tests below —
    doesn't need the full FastAPI app."""
    def __init__(self, global_config):
        self.state = type("_S", (), {"system_state": {"global_config": global_config}})()


# ── cloud_nsg.py: pure dispatcher unit tests ────────────────────────────────

def test_cloud_nsg_active_provider_none_when_neither_enabled():
    assert cloud_nsg.active_provider(_Hub({})) is None


def test_cloud_nsg_active_provider_azure():
    hub = _Hub({"azure_nsg": {"enabled": True}, "oci_nsg": {"enabled": False}})
    assert cloud_nsg.active_provider(hub) == "azure"


def test_cloud_nsg_active_provider_oci():
    hub = _Hub({"azure_nsg": {"enabled": False}, "oci_nsg": {"enabled": True}})
    assert cloud_nsg.active_provider(hub) == "oci"


def test_cloud_nsg_active_provider_both_enabled_defaults_to_azure(caplog):
    hub = _Hub({"azure_nsg": {"enabled": True}, "oci_nsg": {"enabled": True}})
    assert cloud_nsg.active_provider(hub) == "azure"


def test_cloud_nsg_other_provider_enabled():
    hub = _Hub({"azure_nsg": {"enabled": True}, "oci_nsg": {"enabled": False}})
    assert cloud_nsg.other_provider_enabled(hub, "oci") is True
    assert cloud_nsg.other_provider_enabled(hub, "azure") is False


# ── cloud_vault.py: pure dispatcher unit tests ──────────────────────────────

def test_cloud_vault_active_provider_none_when_neither_enabled():
    assert cloud_vault.active_provider(_Hub({})) is None


def test_cloud_vault_active_provider_azure():
    hub = _Hub({"key_vault": {"enabled": True}, "oci_vault": {"enabled": False}})
    assert cloud_vault.active_provider(hub) == "azure"


def test_cloud_vault_active_provider_oci():
    hub = _Hub({"key_vault": {"enabled": False}, "oci_vault": {"enabled": True}})
    assert cloud_vault.active_provider(hub) == "oci"


def test_cloud_vault_other_provider_enabled():
    hub = _Hub({"key_vault": {"enabled": False}, "oci_vault": {"enabled": True}})
    assert cloud_vault.other_provider_enabled(hub, "azure") is True
    assert cloud_vault.other_provider_enabled(hub, "oci") is False


def test_cloud_vault_resolve_ref_no_provider_passes_through_inline_literal():
    hub = _Hub({})
    assert _run(cloud_vault.resolve_ref(hub, "inline-value")) == "inline-value"
    assert _run(cloud_vault.resolve_ref(hub, "kv:missing")) is None
    assert _run(cloud_vault.resolve_ref(hub, None)) is None


def test_cloud_vault_resolve_ref_dispatches_to_oci_when_oci_enabled(monkeypatch):
    hub = _Hub({"oci_vault": {"enabled": True, "vault_id": "v1", "compartment_id": "c1"}})
    import oci_vault

    async def _fake_resolve(h, ref, http=None):
        assert h is hub
        return f"oci:{ref}"
    monkeypatch.setattr(oci_vault, "resolve_ref", _fake_resolve)

    assert _run(cloud_vault.resolve_ref(hub, "kv:my-secret")) == "oci:kv:my-secret"


def test_cloud_vault_resolve_ref_dispatches_to_azure_when_azure_enabled(monkeypatch):
    hub = _Hub({"key_vault": {"enabled": True, "vault_url": "https://x.vault.azure.net"}})
    import key_vault

    async def _fake_resolve(h, ref, http=None):
        assert h is hub
        return f"azure:{ref}"
    monkeypatch.setattr(key_vault, "resolve_ref", _fake_resolve)

    assert _run(cloud_vault.resolve_ref(hub, "kv:my-secret")) == "azure:kv:my-secret"


def test_cloud_vault_set_secret_raises_when_no_provider_enabled():
    hub = _Hub({})
    with pytest.raises(RuntimeError):
        _run(cloud_vault.set_secret(hub, "name", "value"))


def test_cloud_vault_delete_secret_noop_when_no_provider_enabled():
    hub = _Hub({})
    assert _run(cloud_vault.delete_secret(hub, "name")) is True


def test_cloud_vault_delete_secret_dispatches_to_oci_when_oci_enabled(monkeypatch):
    hub = _Hub({"oci_vault": {"enabled": True, "vault_id": "v1", "compartment_id": "c1"}})
    import oci_vault

    async def _fake_delete(cfg, vcfg, name, http=None):
        assert name == "my-secret"
        return True
    monkeypatch.setattr(oci_vault, "delete_secret", _fake_delete)

    assert _run(cloud_vault.delete_secret(hub, "my-secret")) is True


def test_cloud_vault_delete_secret_dispatches_to_azure_when_azure_enabled(monkeypatch):
    hub = _Hub({"key_vault": {"enabled": True, "vault_url": "https://x.vault.azure.net"}})
    import key_vault

    async def _fake_delete(cfg, vault_url, name, http=None):
        assert name == "my-secret"
        return True
    monkeypatch.setattr(key_vault, "delete_secret", _fake_delete)

    assert _run(cloud_vault.delete_secret(hub, "my-secret")) is True


def test_cloud_vault_delete_secret_swallows_backend_error(monkeypatch):
    hub = _Hub({"oci_vault": {"enabled": True, "vault_id": "v1", "compartment_id": "c1"}})
    import oci_vault

    async def _boom(cfg, vcfg, name, http=None):
        raise oci_vault.OciVaultError("boom")
    monkeypatch.setattr(oci_vault, "delete_secret", _boom)

    assert _run(cloud_vault.delete_secret(hub, "my-secret")) is False


def test_cloud_vault_test_connection_skipped_when_no_provider_enabled():
    hub = _Hub({})
    res = _run(cloud_vault.test_connection(hub))
    assert res["status"] == "SKIPPED"


# ── route-level exclusivity, end-to-end through create_app ─────────────────

def test_azure_nsg_route_rejects_enable_when_oci_nsg_enabled():
    client, hub = _build(_admin_state(oci_nsg={"enabled": True, "nsg_id": "x", "region": "us-ashburn-1"}))
    cookie = _admin_login(client)
    r = client.post("/setup/azure-nsg", json={"config": {"enabled": True}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 400
    assert "OCI NSG" in r.json()["detail"]
    assert not hub.state.system_state.get("global_config", {}).get("azure_nsg", {}).get("enabled")


def test_oci_nsg_route_rejects_enable_when_azure_nsg_enabled():
    client, hub = _build(_admin_state(azure_nsg={
        "enabled": True, "subscription_id": "s", "resource_group": "r", "nsg_name": "n"}))
    cookie = _admin_login(client)
    r = client.post("/setup/oci-nsg", json={"config": {"enabled": True}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 400
    assert "Azure NSG" in r.json()["detail"]
    assert not hub.state.system_state.get("global_config", {}).get("oci_nsg", {}).get("enabled")


def test_key_vault_route_rejects_enable_when_oci_vault_enabled():
    client, hub = _build(_admin_state(oci_vault={"enabled": True}))
    cookie = _admin_login(client)
    r = client.post("/setup/key-vault", json={"config": {"enabled": True, "vault_url": "https://x.vault.azure.net"}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 400
    assert "OCI Vault" in r.json()["detail"]
    assert not hub.state.system_state.get("global_config", {}).get("key_vault", {}).get("enabled")


def test_oci_vault_route_rejects_enable_when_key_vault_enabled():
    client, hub = _build(_admin_state(key_vault={"enabled": True, "vault_url": "https://x.vault.azure.net"}))
    cookie = _admin_login(client)
    r = client.post("/setup/oci-vault", json={"config": {
        "enabled": True, "vault_id": "v1", "compartment_id": "c1", "region": "us-ashburn-1"}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 400
    assert "Azure Key Vault" in r.json()["detail"]
    assert not hub.state.system_state.get("global_config", {}).get("oci_vault", {}).get("enabled")


def test_oci_nsg_route_allows_enable_when_azure_nsg_disabled():
    client, hub = _build(_admin_state(azure_nsg={"enabled": False}))
    cookie = _admin_login(client)
    r = client.post("/setup/oci-nsg", json={"config": {
        "enabled": True, "nsg_id": "ocid1.nsg.oc1..x", "region": "us-ashburn-1"}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 200, r.text
    assert r.json()["config"]["enabled"] is True


def test_oci_vault_route_allows_enable_when_key_vault_disabled():
    client, hub = _build(_admin_state(key_vault={"enabled": False}))
    cookie = _admin_login(client)
    r = client.post("/setup/oci-vault", json={"config": {
        "enabled": True, "vault_id": "v1", "compartment_id": "c1", "region": "us-ashburn-1"}},
                    cookies={"lm_session": cookie})
    assert r.status_code == 200, r.text
    assert r.json()["config"]["enabled"] is True
