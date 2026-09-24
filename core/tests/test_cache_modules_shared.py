"""Cross-module guarantees for the four caches that sit on ``cache_core``.

The point of the shared module is that "this data is cached" means the SAME
thing everywhere: the same debounce, the same atomic 0600 write, the same
survive-a-restart behaviour and the same staleness vocabulary. Per-module tests
can't prove that — each one only ever sees its own mixin — so the uniformity
itself is asserted here, once, over all four.

``le_cache`` and ``warm_cache`` additionally had NO debounce before the
migration (every set re-serialized the whole file); these are the regression
guards for the behaviour they gained.
"""
import json
import os

import pytest

from cache_core import StalenessPolicy
from le_cache import LeCacheMixin
from nw_cache import NwCacheMixin
from truenas_cache import TruenasCacheMixin
from warm_cache import WarmCacheMixin

pytestmark = pytest.mark.asyncio


class _Hub(NwCacheMixin, TruenasCacheMixin, LeCacheMixin, WarmCacheMixin):
    """Every cache mixin on one object, exactly as ``LabManagerHub`` composes
    them — this also proves the four don't collide on any attribute name."""

    def __init__(self, cache_dir: str):
        self.cache_dir = cache_dir
        self.nw_cache_init()
        self.truenas_cache_init()
        self.le_cache_init()
        self.warm_cache_init()


# Per module: the write, the flush, the reload, and the value that must survive.
_CASES = {
    "nw": (
        lambda h: h.nw_cache_set_fleet({"status": "SUCCESS", "data": [{"id": "sw1"}]}),
        lambda h: h.nw_cache_flush_now(),
        lambda h: h.nw_cache_load(),
        lambda h: h.nw_cache_get_fleet()["devices"]["data"][0]["id"],
        "sw1",
    ),
    "truenas": (
        lambda h: h.truenas_cache_set_fleet({"status": "SUCCESS", "data": [{"id": "n1"}]}),
        lambda h: h.truenas_cache_flush_now(),
        lambda h: h.truenas_cache_load(),
        lambda h: h.truenas_cache_get_fleet()["appliances"]["data"][0]["id"],
        "n1",
    ),
    "le": (
        lambda h: h.le_cache_set("certs", {"domain": "lab.example"}),
        lambda h: h.le_cache_flush_now(),
        lambda h: h.le_cache_load(),
        lambda h: h.le_cache_get("certs")["domain"],
        "lab.example",
    ),
    "warm": (
        lambda h: h.warm_set("console_ports", "spoke1", [{"port": 1}]),
        lambda h: h.warm_cache_flush_now(),
        lambda h: h.warm_cache_load(),
        lambda h: h.warm_get("console_ports", "spoke1")[0]["port"],
        1,
    ),
}


@pytest.mark.parametrize("name", sorted(_CASES))
async def test_value_survives_a_restart(tmp_path, name):
    """The whole reason the data is on disk: a hub restart must not lose it.

    A second ``_Hub`` over the same cache_dir IS the restart — nothing is
    carried over in memory.
    """
    write, flush, _, read, expected = _CASES[name]
    hub = _Hub(str(tmp_path))
    await write(hub)
    await flush(hub)

    revived = _Hub(str(tmp_path))
    _CASES[name][2](revived)
    assert read(revived) == expected


@pytest.mark.parametrize("name", sorted(_CASES))
async def test_write_is_debounced_into_a_single_file_write(tmp_path, name):
    """A burst must coalesce: N sets schedule ONE delayed flusher, not N dumps.

    ``le`` and ``warm`` re-serialized the entire file on every single set before
    the migration, so this is the behaviour they gained, not merely kept.
    """
    write, flush, _, _, _ = _CASES[name]
    hub = _Hub(str(tmp_path))
    files = {
        "nw": hub._nw_cache_file, "truenas": hub._truenas_cache_file,
        "le": hub._le_cache_file, "warm": hub._warm_cache_file,
    }
    cf = files[name]

    for _ in range(12):
        await write(hub)
    assert len([t for t in cf._tasks if not t.done()]) == 1
    assert cf._dirty is True

    # Nothing has hit the disk yet — the coalescing window is still open.
    for t in list(cf._tasks):
        t.cancel()
    await flush(hub)
    assert cf._dirty is False


@pytest.mark.parametrize("name", sorted(_CASES))
async def test_file_is_owner_only_and_valid_json(tmp_path, name):
    """Caches can hold fleet topology and cert metadata, so 0600 is not
    optional; and a half-written file must never be what readers see."""
    write, flush, _, _, _ = _CASES[name]
    hub = _Hub(str(tmp_path))
    await write(hub)
    await flush(hub)

    written = [f for f in os.listdir(str(tmp_path)) if f.endswith(".json")]
    assert written, "flush_now produced no file"
    for fname in written:
        p = os.path.join(str(tmp_path), fname)
        assert oct(os.stat(p).st_mode)[-3:] == "600"
        with open(p) as f:
            json.load(f)  # raises if the atomic replace exposed a partial write
        assert not os.path.exists(p + ".tmp")


@pytest.mark.parametrize("name", sorted(_CASES))
async def test_all_modules_share_one_staleness_policy(tmp_path, name):
    """Same thresholds everywhere: a page has no business deciding on its own
    when "cached" becomes "stale"."""
    hub = _Hub(str(tmp_path))
    policies = {
        "nw": hub.nw_policy, "truenas": hub.truenas_policy,
        "le": hub.le_policy, "warm": hub.warm_policy,
    }
    p = policies[name]
    ref = StalenessPolicy()
    assert (p.refresh_after_s, p.stale_after_s, p.expire_after_s) == (
        ref.refresh_after_s, ref.stale_after_s, ref.expire_after_s)


async def test_never_cached_reports_missing_not_fresh(tmp_path):
    """A cold start must not masquerade as fresh data — epoch 0.0 is the trap
    that would make an empty cache look a moment old."""
    hub = _Hub(str(tmp_path))
    assert hub.nw_cache_fleet_state() == "missing"
    assert hub.truenas_cache_fleet_state() == "missing"
    assert hub.le_cache_state("certs") == "missing"
    assert hub.warm_state("console_ports", "spoke1") == "missing"


async def test_flush_now_is_safe_with_nothing_to_write(tmp_path):
    """Shutdown calls flush_now unconditionally (api.py), including on a hub
    that never cached anything — it must not raise there."""
    hub = _Hub(str(tmp_path))
    await hub.nw_cache_flush_now()
    await hub.truenas_cache_flush_now()
    await hub.le_cache_flush_now()
    await hub.warm_cache_flush_now()
