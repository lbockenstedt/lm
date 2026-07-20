"""Mist API config store plumbing — the per-tenant ``mist_config`` +
``mist_sites_config`` getters/setters and the ``mist_api_is_centralized``
processing-mode helper (defaults to centralized, mirroring
``central_api_is_centralized``)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from simulations.store import SimulationsStore


async def test_mist_config_roundtrip(tmp_path):
    s = SimulationsStore(str(tmp_path))
    assert await s.get_mist_config("t1") == {}  # default: nothing stored
    await s.set_mist_config("t1", {"api_token": "tok", "org_id": "org-1", "host": "api.mist.com"})
    cfg = await s.get_mist_config("t1")
    assert cfg["api_token"] == "tok"
    assert cfg["org_id"] == "org-1"
    # Tenant isolation: a second tenant sees its own (empty) config.
    assert await s.get_mist_config("t2") == {}


async def test_mist_sites_config_roundtrip(tmp_path):
    s = SimulationsStore(str(tmp_path))
    assert await s.get_mist_sites_config("t1") == {}
    await s.set_mist_sites_config("t1", {"site_mappings": {"MIA": "MIA"},
                                       "monitored_checks": [{"id": "ap_offline"}]})
    csc = await s.get_mist_sites_config("t1")
    assert csc["site_mappings"] == {"MIA": "MIA"}
    assert csc["monitored_checks"] == [{"id": "ap_offline"}]


async def test_mist_config_set_replaces_not_merges(tmp_path):
    s = SimulationsStore(str(tmp_path))
    await s.set_mist_config("t1", {"api_token": "tok", "org_id": "org-1"})
    # A second set REPLACES (sentinel-merge happens at the handler layer, not here).
    await s.set_mist_config("t1", {"api_token": "tok2"})
    cfg = await s.get_mist_config("t1")
    assert cfg == {"api_token": "tok2"}


def test_mist_api_is_centralized_defaults_true():
    # Unset / blank / unknown → centralized (only explicit "distributed" opts out).
    assert SimulationsStore.mist_api_is_centralized(None) is True
    assert SimulationsStore.mist_api_is_centralized({}) is True
    assert SimulationsStore.mist_api_is_centralized({"mist_api": ""}) is True
    assert SimulationsStore.mist_api_is_centralized({"mist_api": "centralized"}) is True
    assert SimulationsStore.mist_api_is_centralized({"mist_api": "bogus"}) is True


def test_mist_api_is_centralized_distributed_opts_out():
    assert SimulationsStore.mist_api_is_centralized({"mist_api": "distributed"}) is False
    assert SimulationsStore.mist_api_is_centralized({"mist_api": "DISTRIBUTED"}) is False