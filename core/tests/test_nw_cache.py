"""Network Devices (nw) in-memory + JSON-persisted cache — ``NwCacheMixin``.

The nw module's per-device live data (fleet list + info/macs/arp/interfaces +
poll results) used to be fetched live from the nw spoke on every request with
no cache and no persistence, so a hub restart / spoke outage 503-ed the
Network Devices UI until the spoke reconnected. ``NwCacheMixin`` mirrors the
firewall tenant-cache pattern (cache the raw spoke envelope, serve from cache
when the spoke is offline) AND adds atomic JSON persistence + load-on-startup
so the UI seeds from last-known data on a restart.

These lock in: set/get fleet + per-device endpoints, poll folds its
sub-resources into the endpoint slots, atomic persist to ``cache/nw_data.json``
survives a fresh instance (the UI-seed-on-restart contract), and a
missing/corrupt file degrades to a cold-start empty cache.
"""

import asyncio
import json
import os

from nw_cache import NwCacheMixin


class _CacheHub(NwCacheMixin):
    """Minimal stand-in: only ``cache_dir`` is needed (the mixin reads it for
    the JSON path). ``nw_cache_init`` seeds the in-memory slots."""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.nw_cache_init()


def _envelope(data):
    return {"status": "SUCCESS", "data": data}


async def _flush(hub):
    """Wait for any fire-and-forget persist tasks to finish."""
    if hub._nw_cache_save_tasks:
        await asyncio.gather(*hub._nw_cache_save_tasks)


async def test_set_fleet_then_get_and_persist(tmp_path):
    hub = _CacheHub(str(tmp_path))
    assert hub.nw_cache_get_fleet() is None  # cold start
    envelope = _envelope([{"id": "sw1", "name": "core-sw"}])
    await hub.nw_cache_set_fleet(envelope)
    got = hub.nw_cache_get_fleet()
    assert got is not None
    assert got["devices"] == envelope
    assert got["fetched_at"] > 0
    await _flush(hub)
    # Persisted to disk.
    path = os.path.join(str(tmp_path), "nw_data.json")
    assert os.path.exists(path)
    with open(path) as f:
        on_disk = json.load(f)
    assert on_disk["fleet"]["devices"] == envelope


async def test_persisted_cache_seeds_a_fresh_instance_on_restart(tmp_path):
    """The UI-seed-on-restart contract: a new hub instance loads the file."""
    hub = _CacheHub(str(tmp_path))
    await hub.nw_cache_set_fleet(_envelope([{"id": "sw1"}]))
    await hub.nw_cache_set_device("sw1", "arp", _envelope([{"ip": "10.0.0.5"}]))
    await hub.nw_cache_set_device("sw1", "info", _envelope({"model": "CX"}))
    await _flush(hub)

    # Simulate a hub restart: brand-new instance pointing at the same dir.
    restarted = _CacheHub(str(tmp_path))
    restarted.nw_cache_load()
    fleet = restarted.nw_cache_get_fleet()
    assert fleet is not None
    assert fleet["devices"]["data"] == [{"id": "sw1"}]
    assert restarted.nw_cache_get_device("sw1", "arp")["data"] == [{"ip": "10.0.0.5"}]
    assert restarted.nw_cache_get_device("sw1", "info")["data"] == {"model": "CX"}
    # A device/endpoint never cached is None (no spurious data).
    assert restarted.nw_cache_get_device("sw1", "macs") is None
    assert restarted.nw_cache_get_device("never-seen", "arp") is None


async def test_poll_folds_subresources_into_endpoint_slots(tmp_path):
    """POLL NOW returns device_info/interfaces/arp/mac_table in one result;
    the cache mirrors them into the per-endpoint slots so the device sub-views
    also serve the last poll when the spoke is down."""
    hub = _CacheHub(str(tmp_path))
    poll = {
        "status": "SUCCESS", "reachable": True, "latency_ms": 7,
        "device_info": {"model": "GW-100", "serial": "S1"},
        "interfaces": [{"name": "1", "ip": "10.20.0.1"}],
        "arp": [{"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:ff"}],
        "mac_table": [{"mac": "aa:bb:cc:dd:ee:ff", "vlan": "10"}],
        "netbox_push": {"status": "SUCCESS", "pushed": 1},
    }
    await hub.nw_cache_set_poll("gw1", poll)
    assert hub.nw_cache_get_device("gw1", "poll") == poll
    # Sub-resources mirrored into endpoint slots, wrapped in the SUCCESS
    # envelope the routes expect to unwrap/filter.
    assert hub.nw_cache_get_device("gw1", "info")["data"] == poll["device_info"]
    assert hub.nw_cache_get_device("gw1", "arp")["data"] == poll["arp"]
    assert hub.nw_cache_get_device("gw1", "macs")["data"] == poll["mac_table"]
    assert hub.nw_cache_get_device("gw1", "interfaces")["data"] == poll["interfaces"]
    await _flush(hub)
    # Survives restart.
    restarted = _CacheHub(str(tmp_path))
    restarted.nw_cache_load()
    assert restarted.nw_cache_get_device("gw1", "poll")["reachable"] is True


async def test_missing_file_is_cold_start(tmp_path):
    hub = _CacheHub(str(tmp_path))
    hub.nw_cache_load()  # no file yet
    assert hub.nw_cache_get_fleet() is None
    assert hub.nw_cache_get_device("sw1", "arp") is None


async def test_corrupt_file_degrades_to_empty(tmp_path):
    path = os.path.join(str(tmp_path), "nw_data.json")
    with open(path, "w") as f:
        f.write("{not valid json")
    hub = _CacheHub(str(tmp_path))
    hub.nw_cache_load()  # must not raise
    assert hub.nw_cache_get_fleet() is None
    assert hub.nw_device_cache == {}


async def test_atomic_write_uses_tmp_then_replace(tmp_path):
    hub = _CacheHub(str(tmp_path))
    await hub.nw_cache_set_fleet(_envelope([]))
    await _flush(hub)
    assert os.path.exists(os.path.join(str(tmp_path), "nw_data.json"))
    # No leftover .tmp once the replace completes.
    assert not os.path.exists(os.path.join(str(tmp_path), "nw_data.json.tmp"))