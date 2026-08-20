"""Unit tests for the proxied-tenant disk-backed hub cache (``api.py``).

A tenant assigned a (non-shared) edge proxy does NOT keep its module cache
resident in the hub's RAM (``_tenant_cache``). Instead the hub keeps that
tenant's encrypted ``api_cache`` shard fresh on disk and reads it on demand on a
cache miss, evicting the RAM entries after each persist. Non-proxied tenants are
unchanged (RAM-first, no disk fallback). These lock in:

* a proxied tenant with an empty RAM cache is served from its on-disk shard;
* a NON-proxied tenant with an empty RAM cache still returns None (no disk read);
* ``set_proxied_tenants`` evicts a newly-proxied tenant's resident RAM at once;
* the shard micro-cache decrypts once for a read-burst (RAM-free at rest);
* the ``LM_PROXIED_TENANT_DISK_CACHE=0`` kill-switch forces legacy RAM behaviour.
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# A real Fernet key so hub_encryption.encrypt/decrypt round-trips deterministically.
os.environ.setdefault(
    "LM_FERNET_KEY",
    __import__("cryptography.fernet", fromlist=["Fernet"]).Fernet.generate_key().decode(),
)

import api  # noqa: E402
from security.encryption import hub_encryption  # noqa: E402


class _State:
    def __init__(self, data_dir):
        self.data_dir = data_dir


class _Hub:
    def __init__(self, data_dir):
        self.state = _State(data_dir)


def _write_shard(data_dir, tenant, modules):
    """Persist a tenant's ``{module: entry}`` slice exactly as
    ``_persist_tenant_cache_sync`` does (file content is ``{tenant: modules}``,
    Fernet-encrypted)."""
    d = os.path.join(data_dir, "tenants", str(tenant), api._TENANT_CACHE_MODULE)
    os.makedirs(d, exist_ok=True)
    blob = hub_encryption.encrypt(json.dumps({str(tenant): modules}, default=str))
    with open(os.path.join(d, api._TENANT_CACHE_NAME), "wb") as f:
        f.write(blob)


@pytest.fixture(autouse=True)
def _reset_module_state(tmp_path):
    """Isolate the module-level cache state between tests."""
    api._tenant_cache.clear()
    api._shard_micro.clear()
    api.set_proxied_tenants(set())
    os.environ.pop("LM_PROXIED_TENANT_DISK_CACHE", None)
    api.set_module_hub(_Hub(str(tmp_path)))
    yield
    api._tenant_cache.clear()
    api._shard_micro.clear()
    api.set_proxied_tenants(set())
    os.environ.pop("LM_PROXIED_TENANT_DISK_CACHE", None)
    api.set_module_hub(None)


def test_proxied_tenant_served_from_disk(tmp_path):
    _write_shard(str(tmp_path), "acme",
                 {"pxmx_vms": {"data": {"vms": [1, 2]}, "fetched_at": 111.0}})
    api.set_proxied_tenants({"acme"})
    # RAM is empty for acme, but it's proxied → disk fallback serves it.
    entry = api._cache_entry("acme", "pxmx_vms")
    assert entry is not None
    assert entry["data"] == {"vms": [1, 2]}
    assert entry["fetched_at"] == 111.0


def test_non_proxied_tenant_no_disk_fallback(tmp_path):
    _write_shard(str(tmp_path), "beta",
                 {"pxmx_vms": {"data": {"vms": [9]}, "fetched_at": 5.0}})
    # NOT proxied → RAM-only; disk is never consulted even though a shard exists.
    assert api._cache_entry("beta", "pxmx_vms") is None


def test_proxied_ram_hit_takes_precedence(tmp_path):
    _write_shard(str(tmp_path), "acme",
                 {"pxmx_vms": {"data": "disk", "fetched_at": 1.0}})
    api.set_proxied_tenants({"acme"})
    api._tenant_cache["acme"] = {"pxmx_vms": {"data": "ram", "fetched_at": 2.0}}
    # A resident RAM entry (mid fetch cycle) is preferred over the disk shard.
    assert api._cache_entry("acme", "pxmx_vms")["data"] == "ram"


def test_set_proxied_evicts_resident_ram(tmp_path):
    api._tenant_cache["acme"] = {"pxmx_vms": {"data": "x", "fetched_at": 1.0}}
    api.set_proxied_tenants({"acme"})
    # Becoming proxied evicts the warm-loaded RAM copy immediately.
    assert "acme" not in api._tenant_cache


def test_micro_cache_decrypts_once(tmp_path):
    _write_shard(str(tmp_path), "acme",
                 {"pxmx_vms": {"data": 1, "fetched_at": 1.0}})
    api.set_proxied_tenants({"acme"})
    calls = {"n": 0}
    real_decrypt = hub_encryption.decrypt

    def _counting(blob):
        calls["n"] += 1
        return real_decrypt(blob)

    hub_encryption.decrypt = _counting
    try:
        for _ in range(5):
            api._cache_entry("acme", "pxmx_vms")
    finally:
        hub_encryption.decrypt = real_decrypt
    # 5 reads within the TTL window → a single decrypt.
    assert calls["n"] == 1


def test_kill_switch_forces_ram_only(tmp_path):
    _write_shard(str(tmp_path), "acme",
                 {"pxmx_vms": {"data": {"vms": [1]}, "fetched_at": 1.0}})
    os.environ["LM_PROXIED_TENANT_DISK_CACHE"] = "0"
    api.set_proxied_tenants({"acme"})
    # Kill-switch on: proxied tenants behave like legacy RAM-only tenants.
    assert api._cache_entry("acme", "pxmx_vms") is None


def test_evict_tenant_ram_clears_ram_and_micro(tmp_path):
    api._tenant_cache["acme"] = {"pxmx_vms": {"data": 1, "fetched_at": 1.0}}
    api._shard_micro["acme"] = (time.time(), {"pxmx_vms": {"data": 2}})
    api._evict_tenant_ram("acme")
    assert "acme" not in api._tenant_cache
    assert "acme" not in api._shard_micro


def test_shared_proxy_disk_backs_all_tenants(tmp_path):
    """A SHARED proxy fronts the whole fleet → EVERY tenant is disk-backed, even
    one never listed explicitly (it caches all tenants locally)."""
    _write_shard(str(tmp_path), "gamma",
                 {"pxmx_vms": {"data": {"vms": [7]}, "fetched_at": 3.0}})
    api.set_proxied_tenants(set(), all_tenants=True)
    entry = api._cache_entry("gamma", "pxmx_vms")
    assert entry is not None and entry["data"] == {"vms": [7]}


def test_shared_proxy_evicts_all_resident_ram(tmp_path):
    api._tenant_cache["a"] = {"m": {"data": 1, "fetched_at": 1.0}}
    api._tenant_cache["b"] = {"m": {"data": 2, "fetched_at": 1.0}}
    api.set_proxied_tenants(set(), all_tenants=True)
    # Becoming fleet-wide disk-backed drops every resident tenant at once.
    assert api._tenant_cache == {}


def test_shared_proxy_kill_switch_forces_ram(tmp_path):
    _write_shard(str(tmp_path), "gamma",
                 {"pxmx_vms": {"data": {"vms": [7]}, "fetched_at": 3.0}})
    os.environ["LM_PROXIED_TENANT_DISK_CACHE"] = "0"
    api.set_proxied_tenants(set(), all_tenants=True)
    assert api._cache_entry("gamma", "pxmx_vms") is None
