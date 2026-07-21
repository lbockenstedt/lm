"""TrueNAS (storage) in-memory + JSON-persisted cache — ``TruenasCacheMixin``.

Mirrors test_nw_cache.py: set/get fleet + per-appliance endpoints, poll folds
its sub-resources into the endpoint slots, atomic persist to
``cache/truenas_data.json`` survives a fresh instance (the UI-seed-on-restart
contract), a missing/corrupt file degrades to a cold-start empty cache, and the
tenant-filtered offline path does not leak another tenant's appliances.
"""

import asyncio
import json
import os

from truenas_cache import TruenasCacheMixin


class _CacheHub(TruenasCacheMixin):
    """Minimal stand-in: only ``cache_dir`` is needed (the mixin reads it for
    the JSON path). ``truenas_cache_init`` seeds the in-memory slots."""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.truenas_cache_init()


def _envelope(data):
    return {"status": "SUCCESS", "data": data}


async def _flush(hub):
    """Force the debounced persist NOW (tests must not wait out the ~5s
    coalescing window): cancel any pending delayed flusher and write."""
    for t in list(hub._truenas_cache_save_tasks):
        t.cancel()
    await hub.truenas_cache_flush_now()


async def test_set_fleet_then_get_and_persist(tmp_path):
    hub = _CacheHub(str(tmp_path))
    assert hub.truenas_cache_get_fleet() is None  # cold start
    envelope = _envelope([{"id": "nas1", "name": "truenas-1"}])
    await hub.truenas_cache_set_fleet(envelope)
    got = hub.truenas_cache_get_fleet()
    assert got is not None
    assert got["appliances"] == envelope
    assert got["fetched_at"] > 0
    await _flush(hub)
    path = os.path.join(str(tmp_path), "truenas_data.json")
    assert os.path.exists(path)
    with open(path) as f:
        on_disk = json.load(f)
    assert on_disk["fleet"]["appliances"] == envelope


async def test_persisted_cache_seeds_a_fresh_instance_on_restart(tmp_path):
    hub = _CacheHub(str(tmp_path))
    await hub.truenas_cache_set_fleet(_envelope([{"id": "nas1"}]))
    await hub.truenas_cache_set_appliance("nas1", "pools", _envelope([{"name": "tank"}]))
    await hub.truenas_cache_set_appliance("nas1", "info", _envelope({"product": "TrueNAS"}))
    await _flush(hub)

    restarted = _CacheHub(str(tmp_path))
    restarted.truenas_cache_load()
    fleet = restarted.truenas_cache_get_fleet()
    assert fleet is not None
    assert fleet["appliances"]["data"] == [{"id": "nas1"}]
    assert restarted.truenas_cache_get_appliance("nas1", "pools")["data"] == [{"name": "tank"}]
    assert restarted.truenas_cache_get_appliance("nas1", "info")["data"] == {"product": "TrueNAS"}
    assert restarted.truenas_cache_get_appliance("nas1", "disks") is None
    assert restarted.truenas_cache_get_appliance("never-seen", "pools") is None


async def test_poll_folds_subresources_into_endpoint_slots(tmp_path):
    """POLL NOW returns system_info/pools/datasets/disks/shares/alerts/
    services/capacity in one result; the cache mirrors them into the
    per-endpoint slots so the appliance sub-views also serve the last poll
    when the spoke is down."""
    hub = _CacheHub(str(tmp_path))
    poll = {
        "status": "SUCCESS",
        "data": {
            "system_info": {"product_name": "TrueNAS SCALE", "_is_scale": True},
            "pools": [{"name": "tank", "status": "ONLINE"}],
            "datasets": [{"id": "tank/test"}],
            "disks": [{"name": "da1"}],
            "shares": {"smb": [{"name": "share1"}], "nfs": [], "iscsi": []},
            "alerts": [{"id": 1}],
            "services": [{"service": "smb"}],
            "capacity": [{"pool": "tank", "used": 100, "avail": 900}],
        },
        "errors": [],
    }
    await hub.truenas_cache_set_poll("nas1", poll)
    assert hub.truenas_cache_get_appliance("nas1", "poll") == poll
    # Sub-resources mirrored into endpoint slots (system_info → info).
    assert hub.truenas_cache_get_appliance("nas1", "info")["data"] == poll["data"]["system_info"]
    assert hub.truenas_cache_get_appliance("nas1", "pools")["data"] == poll["data"]["pools"]
    assert hub.truenas_cache_get_appliance("nas1", "datasets")["data"] == poll["data"]["datasets"]
    assert hub.truenas_cache_get_appliance("nas1", "disks")["data"] == poll["data"]["disks"]
    await _flush(hub)
    restarted = _CacheHub(str(tmp_path))
    restarted.truenas_cache_load()
    assert restarted.truenas_cache_get_appliance("nas1", "pools")["data"][0]["name"] == "tank"


async def test_missing_file_is_cold_start(tmp_path):
    hub = _CacheHub(str(tmp_path))
    hub.truenas_cache_load()  # no file yet
    assert hub.truenas_cache_get_fleet() is None
    assert hub.truenas_cache_get_appliance("nas1", "pools") is None


async def test_corrupt_file_degrades_to_empty(tmp_path):
    path = os.path.join(str(tmp_path), "truenas_data.json")
    with open(path, "w") as f:
        f.write("{not valid json")
    hub = _CacheHub(str(tmp_path))
    hub.truenas_cache_load()  # must not raise
    assert hub.truenas_cache_get_fleet() is None
    assert hub.truenas_appliance_cache == {}


async def test_atomic_write_uses_tmp_then_replace(tmp_path):
    hub = _CacheHub(str(tmp_path))
    await hub.truenas_cache_set_fleet(_envelope([]))
    await _flush(hub)
    assert os.path.exists(os.path.join(str(tmp_path), "truenas_data.json"))
    assert not os.path.exists(os.path.join(str(tmp_path), "truenas_data.json.tmp"))


async def test_write_burst_coalesces_to_one_pending_flusher(tmp_path):
    hub = _CacheHub(str(tmp_path))
    for i in range(10):
        await hub.truenas_cache_set_appliance(f"nas{i}", "pools", _envelope([{"n": i}]))
    assert len(hub._truenas_cache_save_tasks) == 1
    assert hub._truenas_cache_dirty is True
    await _flush(hub)
    with open(os.path.join(str(tmp_path), "truenas_data.json")) as f:
        on_disk = json.load(f)
    assert len(on_disk["appliances"]) == 10


async def test_fleet_filtered_returns_none_when_never_cached(tmp_path):
    hub = _CacheHub(str(tmp_path))
    assert hub.truenas_cache_get_fleet_filtered(lambda r: True) is None


async def test_fleet_filtered_keeps_only_predicate_visible_rows(tmp_path):
    hub = _CacheHub(str(tmp_path))
    rows = [
        {"id": "acme-nas", "tenant_id": "acme"},
        {"id": "other-nas", "tenant_id": "othercorp"},
        {"id": "shared-nas", "tenant_id": "shared"},
    ]
    await hub.truenas_cache_set_fleet(_envelope(rows))
    got = hub.truenas_cache_get_fleet_filtered(
        lambda r: r.get("tenant_id") in ("acme", "shared"))
    assert got is not None
    ids = [r["id"] for r in got["appliances"]["data"]]
    assert ids == ["acme-nas", "shared-nas"]
    assert got["fetched_at"] > 0


async def test_fleet_filtered_does_not_mutate_underlying_cache(tmp_path):
    hub = _CacheHub(str(tmp_path))
    rows = [{"id": "acme-nas", "tenant_id": "acme"},
            {"id": "other-nas", "tenant_id": "othercorp"}]
    await hub.truenas_cache_set_fleet(_envelope(rows))
    hub.truenas_cache_get_fleet_filtered(lambda r: r.get("tenant_id") == "acme")
    full = hub.truenas_cache_get_fleet()
    assert [r["id"] for r in full["appliances"]["data"]] == ["acme-nas", "other-nas"]


async def test_fleet_filtered_preserves_envelope_shape_and_message(tmp_path):
    hub = _CacheHub(str(tmp_path))
    env = {"status": "SUCCESS", "message": "3 appliance(s)", "data": [
        {"id": "a", "tenant_id": "acme"}, {"id": "b", "tenant_id": "other"}]}
    await hub.truenas_cache_set_fleet(env)
    got = hub.truenas_cache_get_fleet_filtered(lambda r: r.get("tenant_id") == "acme")
    assert got["appliances"]["status"] == "SUCCESS"
    assert got["appliances"]["message"] == "3 appliance(s)"
    assert [r["id"] for r in got["appliances"]["data"]] == ["a"]