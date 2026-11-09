"""5-minute storage performance averages pushed by spokes (StoragePerfStore +
the hub's STORAGE_PERF_SAMPLE handler)."""
import asyncio
import types

import main
from storage_perf import StoragePerfStore

NOW = 1_800_000_000


def _sample(device, ts, write_ops):
    return {"device_id": device, "ts": ts, "samples": 10, "metrics": {"write_ops": write_ops}}


async def test_store_merges_repeats_drops_old_and_persists(tmp_path):
    store = StoragePerfStore(lambda: str(tmp_path))
    kept = store.add("truenas", [
        _sample("a1", NOW - 600, 100), _sample("a1", NOW - 300, 200),
        _sample("a1", NOW - 8 * 86400, 1),            # older than 7 days
        {"device_id": "a1", "ts": "bad", "metrics": {}}], now=NOW)
    assert kept == 2
    # A re-sent bucket replaces the old one rather than duplicating it.
    store.add("truenas", [_sample("a1", NOW - 300, 250)], now=NOW)
    rows = store.get("truenas", "a1", now=NOW)
    assert [(r["ts"], r["metrics"]["write_ops"]) for r in rows] == [(NOW - 600, 100), (NOW - 300, 250)]
    assert store.get("truenas", "a1", days=0.005, now=NOW) == rows[1:]
    for t in list(store._file._tasks):
        t.cancel()
    await store.flush_now()
    again = StoragePerfStore(lambda: str(tmp_path))
    again.load()
    assert again.get("truenas", "a1", now=NOW) == rows


def test_handler_keeps_only_known_appliances_of_this_spoke(tmp_path):
    hub = types.SimpleNamespace(
        storage_perf=StoragePerfStore(lambda: str(tmp_path)),
        state=types.SimpleNamespace(system_state={"global_config": {"truenas_appliances": [
            {"id": "mine"}, {"id": "bound", "spoke_id": "truenas-1"},
            {"id": "other", "spoke_id": "truenas-2"}]}}),
        _primary_key=lambda s: s)
    conn = types.SimpleNamespace(spoke_id="truenas-1")
    ts = (int(__import__("time").time()) // 300) * 300
    payload = {"data": {"module": "truenas", "samples": [
        _sample("mine", ts, 1), _sample("bound", ts, 2),
        _sample("other", ts, 3), _sample("ghost", ts, 4)]}}

    async def _go():
        await main.LabManagerHub._spoke_msg_storage_perf_sample(hub, conn, {}, payload, None)
        for t in list(hub.storage_perf._file._tasks):
            t.cancel()
    asyncio.new_event_loop().run_until_complete(_go())
    assert sorted(hub.storage_perf.series) == ["truenas:bound", "truenas:mine"]
