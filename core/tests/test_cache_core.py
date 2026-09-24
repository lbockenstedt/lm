"""Pins cache_core — the one shared cache implementation.

WHY THIS FILE EXISTS: four modules (nw/truenas/le/warm) each carried their own
copy of this logic and drifted. The point of cache_core is that "cached" means
ONE behaviour, so the behaviour has to be nailed down here rather than
re-asserted per module.

Two things get the most attention:

  * The debounce. A poll burst of N devices must produce ONE file write, not N.
    This is the property that made nw_cache's writer worth copying, and the one
    warm_cache/le_cache were missing.
  * The three-threshold ladder. The whole reason it is three timers and not one
    is that a spoke restarting during an update must NOT surface an error. A
    regression that collapses STALE into EXPIRED would look harmless and would
    re-break exactly the bug this was written for.
"""
import asyncio
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cache_core  # noqa: E402
from cache_core import (  # noqa: E402
    EXPIRED,
    FRESH,
    MISSING,
    REFRESH,
    STALE,
    JsonCacheFile,
    StalenessPolicy,
)


# ---------------------------------------------------------------------------
# StalenessPolicy — pure, no I/O
# ---------------------------------------------------------------------------

@pytest.fixture
def pol():
    return StalenessPolicy(refresh_after_s=30.0, stale_after_s=120.0,
                           expire_after_s=86400.0)


def test_defaults_are_the_documented_ladder():
    """The constants are load-bearing: routes read them to decide badge vs error.
    They must stay ordered refresh < stale < expire or the ladder is nonsense."""
    assert cache_core.DEFAULT_REFRESH_AFTER_S < cache_core.DEFAULT_STALE_AFTER_S
    assert cache_core.DEFAULT_STALE_AFTER_S < cache_core.DEFAULT_EXPIRE_AFTER_S
    assert cache_core.DEFAULT_FLUSH_DELAY_S > 0


@pytest.mark.parametrize("age,want", [
    (0, FRESH), (29, FRESH), (30, FRESH),          # boundary is exclusive (>)
    (31, REFRESH), (119, REFRESH), (120, REFRESH),
    (121, STALE), (86399, STALE), (86400, STALE),
    (86401, EXPIRED), (10 ** 7, EXPIRED),
])
def test_classify_ladder(pol, age, want):
    now = 1_000_000.0
    assert pol.classify(now - age, now=now) == want


@pytest.mark.parametrize("bad", [None, 0, 0.0, "", "abc", [], {}])
def test_no_timestamp_is_missing_not_fresh(pol, bad):
    """A never-cached entry must read MISSING. If it fell through to FRESH the
    caller would serve None as if it were good data."""
    assert pol.classify(bad, now=1_000_000.0) == MISSING
    assert pol.age(bad, now=1_000_000.0) is None


def test_future_timestamp_clamps_to_zero(pol):
    """Clock skew (or an NTP step) must not make a just-written entry look
    ancient — or, worse, wrap into EXPIRED and start erroring."""
    now = 1_000_000.0
    assert pol.age(now + 5_000, now=now) == 0.0
    assert pol.classify(now + 5_000, now=now) == FRESH


def test_the_restarting_spoke_window_is_badged_not_errored(pol):
    """THE bug this module exists for: an agent/hub update takes a spoke offline
    for tens of seconds. Throughout that window the data must stay usable and
    merely badged — never expired, never an error."""
    now = 1_000_000.0
    for secs in (5, 20, 60, 119, 300, 3600):
        fetched = now - secs
        assert pol.is_expired(fetched, now=now) is False, secs
        assert pol.is_usable(fetched, now=now) is True, secs


def test_only_expired_may_error(pol):
    now = 1_000_000.0
    assert pol.is_expired(now - 86401, now=now) is True
    assert pol.is_usable(now - 86401, now=now) is False
    # ...and MISSING is the other non-usable state, but it is not "expired":
    # there is nothing to serve, which is a different message to the user.
    assert pol.is_usable(None, now=now) is False
    assert pol.is_expired(None, now=now) is False


def test_is_stale_covers_stale_and_expired_only(pol):
    now = 1_000_000.0
    assert pol.is_stale(now - 10, now=now) is False       # FRESH
    assert pol.is_stale(now - 60, now=now) is False       # REFRESH: badge-free
    assert pol.is_stale(now - 200, now=now) is True       # STALE
    assert pol.is_stale(now - 90000, now=now) is True     # EXPIRED


def test_refresh_state_is_not_badged(pol):
    """REFRESH exists so we can revalidate in the background WITHOUT telling the
    user anything is wrong. If it badged, every page would flash 'cached' 30s
    after load, which is just noise."""
    now = 1_000_000.0
    assert pol.classify(now - 45, now=now) == REFRESH
    assert pol.is_stale(now - 45, now=now) is False
    assert pol.should_refresh(now - 45, now=now) is True


def test_should_refresh_is_everything_but_fresh(pol):
    now = 1_000_000.0
    assert pol.should_refresh(now - 5, now=now) is False
    for secs in (45, 200, 90000):
        assert pol.should_refresh(now - secs, now=now) is True
    assert pol.should_refresh(None, now=now) is True      # never fetched


def test_now_defaults_to_wall_clock(pol):
    assert pol.classify(time.time()) == FRESH


def test_thresholds_are_overridable():
    """A module with a slow upstream must be able to widen the ladder without
    forking the implementation — that was the whole failure mode before."""
    p = StalenessPolicy(refresh_after_s=1, stale_after_s=2, expire_after_s=3)
    now = 1_000.0
    assert p.classify(now - 0.5, now=now) == FRESH
    assert p.classify(now - 1.5, now=now) == REFRESH
    assert p.classify(now - 2.5, now=now) == STALE
    assert p.classify(now - 3.5, now=now) == EXPIRED


# ---------------------------------------------------------------------------
# JsonCacheFile — persistence
# ---------------------------------------------------------------------------

def _mk(tmp_path, data, **kw):
    path = tmp_path / "sub" / "c.json"
    return JsonCacheFile("test cache", lambda: str(path), lambda: data, **kw), path


def test_write_is_atomic_and_0600(tmp_path):
    store = {"a": 1}
    jf, path = _mk(tmp_path, store)
    asyncio.run(jf.flush_now())
    assert json.loads(path.read_text()) == {"a": 1}
    assert oct(os.stat(path).st_mode)[-3:] == "600", "at-rest policy for id-bearing caches"
    assert not os.path.exists(str(path) + ".tmp"), "tmp must be renamed away, not left behind"


def test_write_creates_missing_parent_dir(tmp_path):
    jf, path = _mk(tmp_path, {"a": 1})
    assert not path.parent.exists()
    asyncio.run(jf.flush_now())
    assert path.exists()


def test_snapshot_is_taken_at_write_time_not_schedule_time(tmp_path):
    """A mutation landing during the debounce window must be captured by the
    pending write. Snapshotting at schedule time would silently drop it."""
    store = {"n": 1}
    jf, path = _mk(tmp_path, store, flush_delay_s=0.02)

    async def go():
        jf.schedule_save()
        store["n"] = 2          # mutate mid-window
        await asyncio.sleep(0.2)
    asyncio.run(go())
    assert json.loads(path.read_text()) == {"n": 2}


def test_burst_of_sets_produces_one_write(tmp_path):
    """The debounce is the reason this module exists rather than le_cache's
    persist-on-every-write. N marks must collapse to one file write."""
    writes = []
    jf, path = _mk(tmp_path, {"a": 1}, flush_delay_s=0.05)
    real = jf._write
    jf._write = lambda snap: (writes.append(snap), real(snap))[1]

    async def go():
        for _ in range(25):
            jf.schedule_save()
        await asyncio.sleep(0.3)
    asyncio.run(go())
    assert len(writes) == 1, f"expected coalesced single write, got {len(writes)}"


def test_mutation_after_the_flush_still_gets_written(tmp_path):
    """The flusher loops while dirty: a set arriving just after a write must not
    be stranded unpersisted until the next unrelated set."""
    store = {"n": 1}
    jf, path = _mk(tmp_path, store, flush_delay_s=0.05)

    async def go():
        jf.schedule_save()
        await asyncio.sleep(0.15)       # let the first write land
        store["n"] = 99
        jf.schedule_save()
        await asyncio.sleep(0.25)
    asyncio.run(go())
    assert json.loads(path.read_text()) == {"n": 99}


def test_schedule_save_without_a_loop_is_not_fatal(tmp_path):
    """Called from sync __init__/startup there is no running loop. That must
    degrade to 'persist later', not crash the hub at boot."""
    jf, path = _mk(tmp_path, {"a": 1})
    jf.schedule_save()              # no asyncio.run wrapper — must not raise
    assert not path.exists()


def test_flush_now_skips_the_debounce(tmp_path):
    jf, path = _mk(tmp_path, {"a": 1}, flush_delay_s=999.0)
    asyncio.run(jf.flush_now())
    assert path.exists(), "shutdown path must not wait out the coalescing window"


def test_load_roundtrips(tmp_path):
    jf, path = _mk(tmp_path, {"a": 1, "b": [1, 2]})
    asyncio.run(jf.flush_now())
    assert jf.load() == {"a": 1, "b": [1, 2]}


@pytest.mark.parametrize("body", ["", "   ", "not json", "[1,2,3]", '"str"', "null"])
def test_load_of_junk_is_none_not_an_exception(tmp_path, body):
    """A corrupt/truncated cache file (killed mid-write on an older build, or a
    half-written file from a full disk) must degrade to a cold start, never
    prevent the hub from booting."""
    path = tmp_path / "c.json"
    path.write_text(body)
    jf = JsonCacheFile("test cache", lambda: str(path), lambda: {})
    assert jf.load() is None


def test_load_of_missing_file_is_none(tmp_path):
    jf = JsonCacheFile("t", lambda: str(tmp_path / "nope.json"), lambda: {})
    assert jf.load() is None


def test_load_never_raises_even_if_path_fn_explodes():
    """path_fn is supplied by the owner and reads cache_dir, which may not be set
    yet. load() is documented as never raising, so a bad path_fn must be caught
    too — and the error path must not itself blow up on an unbound `path`."""
    def boom():
        raise OSError("no cache_dir")
    jf = JsonCacheFile("t", boom, lambda: {})
    assert jf.load() is None


def test_persist_swallows_a_failing_snapshot_fn(tmp_path):
    """_persist runs inside a fire-and-forget task. If snapshot_fn raises there
    is no one to catch it, so it must be swallowed and logged rather than
    surfacing as an unhandled task exception."""
    def boom():
        raise RuntimeError("snapshot exploded")
    jf = JsonCacheFile("t", lambda: str(tmp_path / "c.json"), boom)
    asyncio.run(jf.flush_now())          # must not raise
    assert not (tmp_path / "c.json").exists()


def test_persist_swallows_an_unserializable_snapshot(tmp_path):
    """default=str covers most objects, but a write failure of any kind is
    best-effort: the cache is an optimisation, never a correctness dependency."""
    class Boom:
        def __str__(self):
            raise ValueError("nope")
    jf = JsonCacheFile("t", lambda: str(tmp_path / "c.json"), lambda: {"x": Boom()})
    asyncio.run(jf.flush_now())          # must not raise


def test_non_serializable_falls_back_to_str(tmp_path):
    jf, path = _mk(tmp_path, {"when": object()})
    asyncio.run(jf.flush_now())
    assert isinstance(json.loads(path.read_text())["when"], str)


def test_concurrent_flushes_do_not_interleave(tmp_path):
    """The lock exists so two writers can't both be mid-rename on the same path."""
    jf, path = _mk(tmp_path, {"a": 1})

    async def go():
        await asyncio.gather(*(jf.flush_now() for _ in range(8)))
    asyncio.run(go())
    assert json.loads(path.read_text()) == {"a": 1}


def test_is_a_stdlib_leaf():
    """cache_core must not import project modules: main imports it, not the other
    way round. A cycle here would break hub startup in a hard-to-read way."""
    import ast
    src = os.path.join(os.path.dirname(__file__), "..", "src", "cache_core.py")
    tree = ast.parse(open(src).read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])
    assert imported <= {"asyncio", "json", "logging", "os", "time", "typing",
                        "__future__"}, f"non-stdlib import: {imported}"
