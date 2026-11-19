"""Central API secrets go to the vault when one is configured, else stay inline."""
import asyncio
from types import SimpleNamespace

import cloud_vault
import pytest
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

    async def delete_secret(self, hub, name):
        self.secrets.pop(name, None)
        return True


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
    monkeypatch.setattr(cloud_vault, "delete_secret", vault.delete_secret)
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


def test_public_status_config_returns_presence_flags_not_secrets():
    cfg = {
        "client_id": "id",
        "client_secret": "inline-secret",
        "access_token": "kv:tenant-token",
        "refresh_token": "",
        "cluster_url": "https://central.example",
        "cc_thresholds": {"warn_pct": 20, "error_pct": 50, "unexpected": "secret"},
        "unexpected": "secret",
    }
    public = central_secrets.public_status_config(cfg)
    assert public["client_id"] == "id"
    assert public["client_secret_set"] is True
    assert public["access_token_set"] is True
    assert public["refresh_token_set"] is False
    assert public["cc_thresholds"] == {"warn_pct": 20, "error_pct": 50}
    assert "client_secret" not in public
    assert "access_token" not in public
    assert "refresh_token" not in public
    assert "unexpected" not in public
    assert "inline-secret" not in repr(public)
    assert "kv:tenant-token" not in repr(public)


@pytest.mark.parametrize("field", central_secrets.SECRET_FIELDS)
def test_merge_secret_updates_preserves_rotates_and_clears(field):
    existing = {field: "stored-secret"}
    for update in ({}, {field: ""}, {field: "  "}):
        merged, cleared = central_secrets.merge_secret_updates(update, existing)
        assert merged[field] == "stored-secret"
        assert cleared == []

    merged, cleared = central_secrets.merge_secret_updates(
        {field: "rotated-secret"}, existing)
    assert merged[field] == "rotated-secret"
    assert cleared == []

    merged, cleared = central_secrets.merge_secret_updates(
        {f"{field}_clear": True}, existing)
    assert field not in merged
    assert cleared == [field]


def test_merge_secret_updates_rejects_conflicting_or_malformed_clear():
    with pytest.raises(ValueError):
        central_secrets.merge_secret_updates(
            {"client_secret": "new-secret", "client_secret_clear": True}, {})
    with pytest.raises(ValueError):
        central_secrets.merge_secret_updates(
            {"client_secret_clear": "true"}, {})


def test_merge_secret_updates_preserves_vault_reference_when_blank():
    ref = "kv:sim-central-t1-client-secret"
    merged, cleared = central_secrets.merge_secret_updates(
        {"client_secret": ""}, {"client_secret": ref})
    assert merged["client_secret"] == ref
    assert cleared == []


def test_existing_ref_from_form_is_kept(monkeypatch):
    vault = _patch_vault(monkeypatch)
    cfg = {"client_secret": "kv:sim-central-t1-client-secret"}
    stored = asyncio.run(central_secrets.to_vault(_hub(True), "central_config", "t1", cfg))
    assert stored == cfg
    assert vault.secrets == {}


def test_clear_deletes_only_managed_vault_secret(monkeypatch):
    vault = _patch_vault(monkeypatch)
    hub = _hub(True)
    stored = asyncio.run(central_secrets.to_vault(
        hub, "central_config", "t1", {"client_secret": "secret"}))
    ref = stored["client_secret"]
    asyncio.run(central_secrets.delete_cleared_secrets(
        hub, "central_config", "t1", stored, ["client_secret"]))
    assert vault.secrets == {}
    assert ref not in central_secrets._resolved


def test_clear_requires_active_vault_for_managed_reference(monkeypatch):
    _patch_vault(monkeypatch)
    ref = "kv:" + central_secrets.secret_name(
        "central_config", "t1", "client_secret")
    with pytest.raises(RuntimeError, match="vault must be configured"):
        asyncio.run(central_secrets.delete_cleared_secrets(
            _hub(False), "central_config", "t1",
            {"client_secret": ref}, ["client_secret"]))


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


def test_resolve_reuses_a_recent_vault_read(monkeypatch):
    """Each Central poll resolved its secrets from Key Vault (~110 reads/hour);
    a value read in the last 15 minutes is reused instead."""
    vault = _patch_vault(monkeypatch)
    vault.secrets["sim-central-t1-client-secret"] = "s3cret"
    reads = []
    orig = vault.resolve_ref

    async def counting(hub, ref):
        reads.append(ref)
        return await orig(hub, ref)
    monkeypatch.setattr(cloud_vault, "resolve_ref", counting)
    cfg = {"client_secret": "kv:sim-central-t1-client-secret"}
    for _ in range(3):
        assert asyncio.run(central_secrets.resolve(_hub(True), cfg))["client_secret"] == "s3cret"
    assert len(reads) == 1
    monkeypatch.setattr(central_secrets, "_CACHE_S", 0)
    asyncio.run(central_secrets.resolve(_hub(True), cfg))
    assert len(reads) == 2


def test_cache_age_ignores_wall_clock_changes(monkeypatch):
    """A wall clock stepped back an hour must not keep a cached secret past 15 minutes."""
    vault = _patch_vault(monkeypatch)
    vault.secrets["sim-central-t1-client-secret"] = "s3cret"
    clock = SimpleNamespace(wall=10_000.0, mono=0.0)
    monkeypatch.setattr(central_secrets, "time",
                        SimpleNamespace(time=lambda: clock.wall, monotonic=lambda: clock.mono))
    cfg = {"client_secret": "kv:sim-central-t1-client-secret"}
    asyncio.run(central_secrets.resolve(_hub(True), cfg))
    vault.secrets["sim-central-t1-client-secret"] = "rotated"
    clock.wall -= 3600
    clock.mono += 16 * 60
    assert asyncio.run(central_secrets.resolve(_hub(True), cfg))["client_secret"] == "rotated"
