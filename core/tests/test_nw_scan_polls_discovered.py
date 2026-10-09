"""A scan that auto-adds devices must poll them as part of discovery.

Without this, a freshly discovered device sat with its IP as its name and no
MAC/ARP/LLDP data until the spoke's first scheduled poll (0.5-1.5 x the 6h
default). ``_nw_poll_discovered`` runs the POLL NOW path (hostname rename +
NetBox push) for every added device and warms the cache.
"""
import asyncio
from pathlib import Path

import routes.nw as nw_routes
from routes.nw import _nw_poll_discovered

NW_ROUTES = Path(__file__).resolve().parents[1] / "src" / "routes" / "nw.py"


class _Hub:
    def __init__(self, results):
        self.results = results          # did -> list of results (one per call)
        self.polled = []
        self.cached = {}

    async def poll_nw_device(self, did):
        self.polled.append(did)
        seq = self.results[did]
        return seq.pop(0) if len(seq) > 1 else seq[0]

    async def nw_cache_set_poll(self, did, res):
        self.cached[did] = res


def test_every_added_device_is_polled_and_cached():
    ok = {"status": "SUCCESS", "errors": [], "message": "reachable=True"}
    hub = _Hub({"a": [ok], "b": [ok]})
    asyncio.run(_nw_poll_discovered(hub, ["a", "b"]))
    assert sorted(hub.polled) == ["a", "b"]
    assert hub.cached == {"a": ok, "b": ok}


def test_retries_until_spoke_has_the_new_device(monkeypatch):
    monkeypatch.setattr(nw_routes, "_NW_DISCOVERY_POLL_RETRY_S", 0)
    miss = {"status": "ERROR", "errors": ["poll: Device a not found"]}
    ok = {"status": "SUCCESS", "errors": [], "message": "reachable=True"}
    hub = _Hub({"a": [miss, ok]})
    asyncio.run(_nw_poll_discovered(hub, ["a"]))
    assert hub.polled == ["a", "a"]
    assert hub.cached["a"] is ok


def test_one_failing_device_does_not_block_the_rest():
    class _Boom(_Hub):
        async def poll_nw_device(self, did):
            if did == "bad":
                raise RuntimeError("spoke gone")
            return await super().poll_nw_device(did)

    ok = {"status": "SUCCESS", "errors": []}
    hub = _Boom({"good": [ok]})
    asyncio.run(_nw_poll_discovered(hub, ["bad", "good"]))
    assert hub.cached == {"good": ok}


def test_auto_add_branch_spawns_the_discovery_poll():
    src = NW_ROUTES.read_text(encoding="utf-8")
    block = src[src.index("        if added:"):src.index('            "discovery_only": discovery_only,')]
    assert "_nw_push_fleet(hub, spoke_id)" in block
    assert "_nw_poll_discovered(hub, new_ids)" in block
    assert block.index("_nw_push_fleet") < block.index("_nw_poll_discovered")
