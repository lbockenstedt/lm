"""Regression coverage for the bounded pxmx TTL caches.

``_NODES_CACHE`` / ``_VMS_CACHE`` / ``_DRIVE_HEALTH_CACHE`` are keyed per
warm_key (tenant/agent scope) and ``_ttl_locks`` is keyed per
``(id(loop), cache_name, key)``. Before ``_prune`` none of them were ever
evicted, so a long-lived hub serving many tenants grew one entry per scope
forever. ``_ttl_locks`` was the worse case: CPython recycles ``id()`` once a
loop is collected, so a never-pruned table can alias a stale lock onto an
unrelated loop.

These tests pin that the tables stay bounded, that pruning terminates even
when every remaining entry is protected, and that an in-flight lock is never
evicted out from under its holder.
"""
import asyncio
import time

from routes import pxmx


def setup_function(_):
    pxmx._NODES_CACHE.clear()
    pxmx._ttl_locks.clear()


def teardown_function(_):
    pxmx._NODES_CACHE.clear()
    pxmx._ttl_locks.clear()


def test_prune_evicts_oldest_first():
    d = {f"k{i}": {"ts": float(i)} for i in range(1, 6)}
    pxmx._prune(d, 3, lambda v: v["ts"])
    assert len(d) == 3
    assert "k1" not in d and "k2" not in d
    assert {"k3", "k4", "k5"} == set(d)


def test_prune_noop_under_limit():
    d = {f"k{i}": {"ts": float(i)} for i in range(1, 3)}
    pxmx._prune(d, 5, lambda v: v["ts"])
    assert len(d) == 2


def test_prune_respects_keep_and_terminates():
    """Every entry protected -> must return, not spin forever."""
    d = {f"k{i}": {"ts": float(i)} for i in range(1, 6)}
    started = time.time()
    pxmx._prune(d, 1, lambda v: v["ts"], keep=lambda v: True)
    assert time.time() - started < 1.0
    assert len(d) == 5


def test_prune_never_raises():
    d = {f"k{i}": {"ts": float(i)} for i in range(1, 6)}

    def _bad(_v):
        raise TypeError("boom")

    pxmx._prune(d, 3, _bad)
    assert len(d) == 5


def test_ttl_cached_bounds_cache():
    async def _run():
        async def _fetch():
            return "data"

        for i in range(pxmx._TTL_CACHE_MAX + 10):
            await pxmx._ttl_cached(pxmx._NODES_CACHE, "nodes", f"k{i}", _fetch)
        assert len(pxmx._NODES_CACHE) <= pxmx._TTL_CACHE_MAX

    asyncio.run(_run())


def test_ttl_locks_bounded():
    async def _run():
        for i in range(pxmx._TTL_CACHE_MAX + 10):
            pxmx._ttl_lock("nodes", str(i))
        assert len(pxmx._ttl_locks) <= pxmx._TTL_CACHE_MAX

    asyncio.run(_run())


def test_ttl_lock_returns_same_lock_for_same_key():
    async def _run():
        first = pxmx._ttl_lock("nodes", "k1")
        second = pxmx._ttl_lock("nodes", "k1")
        assert first is second
        assert isinstance(first, asyncio.Lock)

    asyncio.run(_run())


def test_ttl_lock_never_evicts_a_held_lock():
    async def _run():
        held = pxmx._ttl_lock("nodes", "held")
        await held.acquire()
        try:
            for i in range(pxmx._TTL_CACHE_MAX + 20):
                pxmx._ttl_lock("nodes", f"other{i}")
            assert pxmx._ttl_lock("nodes", "held") is held
            assert held.locked()
        finally:
            held.release()

    asyncio.run(_run())
