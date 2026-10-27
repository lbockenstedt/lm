"""Central API secrets go to the vault when one is configured, else stay inline."""
import asyncio
from types import SimpleNamespace

import cloud_vault
from simulations import central_secrets


def _hub(vault_enabled):
    gc = {"key_vault": {"enabled": vault_enabled, "vault_url": "https://v.example"}}
    return SimpleNamespace(state=SimpleNamespace(system_state={"global_config": gc}))


class FakeVault:
    def __init__(self):
        self.secrets = {}

    async def set_secret(self, hub, name, value):
        self.secrets[name] = value

    async def resolve_ref(self, hub, ref):
        return self.secrets.get(ref[len("kv:"):])


class FakeStore:
    def __init__(self, data):
        self.data = data

    def tenant_ids(self):
        return list(self.data)

    async def get_central_config(self, t):
        return self.data[t].get("central_config", {})

    async def set_central_config(self, t, cfg):
        self.data[t]["central_config"] = cfg

    async def get_central_on_prem_config(self, t):
        return self.data[t].get("central_on_prem_config", {})

    async def set_central_on_prem_config(self, t, cfg):
        self.data[t]["central_on_prem_config"] = cfg


def _patch_vault(monkeypatch):
    vault = FakeVault()
    monkeypatch.setattr(cloud_vault, "set_secret", vault.set_secret)
    monkeypatch.setattr(cloud_vault, "resolve_ref", vault.resolve_ref)
    central_secrets._resolved.clear()
    return vault


def test_secrets_stored_as_vault_refs_and_resolved(monkeypatch):
    vault = _patch_vault(monkeypatch)
    cfg = {"mode": "central", "client_id": "cid", "client_secret": "s3cret", "access_token": ""}
    stored = asyncio.run(central_secrets.to_vault(_hub(True), "central_config", "t1", cfg))
    assert stored["client_secret"] == "kv:sim-central-t1-client-secret"
    assert stored["client_id"] == "cid" and stored["access_token"] == ""
    assert vault.secrets == {"sim-central-t1-client-secret": "s3cret"}

    central_secrets._resolved.clear()
    resolved = asyncio.run(central_secrets.resolve(_hub(True), stored))
    assert resolved["client_secret"] == "s3cret"


def test_no_vault_keeps_secrets_inline(monkeypatch):
    vault = _patch_vault(monkeypatch)
    cfg = {"client_id": "cid", "client_secret": "s3cret"}
    stored = asyncio.run(central_secrets.to_vault(_hub(False), "central_config", "t1", cfg))
    assert stored == cfg
    assert vault.secrets == {}


def test_existing_ref_from_form_is_kept(monkeypatch):
    vault = _patch_vault(monkeypatch)
    cfg = {"client_secret": "kv:sim-central-t1-client-secret"}
    stored = asyncio.run(central_secrets.to_vault(_hub(True), "central_config", "t1", cfg))
    assert stored == cfg
    assert vault.secrets == {}


def test_migrate_moves_inline_secrets(monkeypatch):
    vault = _patch_vault(monkeypatch)
    store = FakeStore({
        "t1": {"central_config": {"client_id": "cid", "client_secret": "a"},
               "central_on_prem_config": {"access_token": "b"}},
        "t2": {},
    })
    moved = asyncio.run(central_secrets.migrate_to_vault(_hub(True), store))
    assert moved == 2
    assert store.data["t1"]["central_config"]["client_secret"] == "kv:sim-central-t1-client-secret"
    assert store.data["t1"]["central_on_prem_config"]["access_token"] == \
        "kv:sim-central-on-prem-t1-access-token"
    assert vault.secrets == {"sim-central-t1-client-secret": "a",
                             "sim-central-on-prem-t1-access-token": "b"}
