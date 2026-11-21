"""Unit tests for the unified hub data cache.

Covers the three layers every module page now relies on:

1. ``cache_core.ShardedCacheFile`` — the on-disk format (one file per
   namespace: ``LMC1`` + mode byte + zlib, Fernet-encrypted in production),
   atomic 0600 writes, unchanged-content skip, empty-namespace delete.
2. ``WarmCacheMixin`` read path — ``cache_read`` present / missing /
   invalidated, single-flight, failures never cached, badge metadata,
   restart warm-load and the legacy ``warm_cache.json`` migration.
3. The refresher + admin actions — active vs idle intervals, login kicks,
   read-only (non-feed) entries, eviction, ``cache_refresh``,
   ``cache_wait_idle``, ``cache_purge``, ``cache_status`` and the
   ``/admin/cache/*`` + ``/auth/cache/*`` routes.
"""
import asyncio
import json
import os
import stat
import sys
import tempfile
import time
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.fernet import Fernet  # noqa: E402

import warm_cache as wc  # noqa: E402
from cache_core import (  # noqa: E402
    CACHE_FILE_MAGIC, CACHE_MODE_ENCRYPTED, CACHE_MODE_PLAIN, ShardedCacheFile,
    _ns_filename,
)
from warm_cache import ALL_SCOPE, CacheJob, WarmCacheMixin  # noqa: E402

_KEY = Fernet.generate_key()


def _enc(b):
    return Fernet(_KEY).encrypt(b)


def _dec(b):
    return Fernet(_KEY).decrypt(b)


class _Hub(WarmCacheMixin):
    def __init__(self, cache_dir=None, encrypted=True, active=None):
        self.cache_dir = cache_dir or tempfile.mkdtemp(prefix="hubcache-")
        if encrypted:
            self.warm_cache_init(encrypt=_enc, decrypt=_dec)
        else:
            self.warm_cache_init()
        self._active = set(active or ())
        self.cache_active_scopes_fn = lambda: set(self._active)


def run(coro):
    return asyncio.run(coro)


class _Fetch:
    """Counting fetch closure; raises ``self.fail`` when set."""

    def __init__(self, data=None, delay=0.0):
        self.data = data if data is not None else {"rows": [1]}
        self.calls = 0
        self.fail = None
        self.delay = delay

    async def __call__(self):
        self.calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            raise self.fail
        return self.data


# ═════════════════════════ 1. on-disk format ═════════════════════════════════

def _file(d, encrypted=True, store=None):
    store = store if store is not None else {}
    return ShardedCacheFile("t", lambda: d, lambda ns: store.get(ns, {}),
                            encrypt=_enc if encrypted else None,
                            decrypt=_dec if encrypted else None), store


def test_encrypted_round_trip_and_no_plaintext_on_disk(tmp_path):
    f, store = _file(str(tmp_path))
    store["nb_devices"] = {"tA": {"data": {"secret-hostname": 1}, "fetched_at": 1.0}}
    f._write_ns("nb_devices", store["nb_devices"])
    blob = (tmp_path / "nb_devices.bin").read_bytes()
    assert blob[:4] == CACHE_FILE_MAGIC and blob[4:5] == CACHE_MODE_ENCRYPTED
    assert b"secret-hostname" not in blob
    assert f.load_all() == {"nb_devices": store["nb_devices"]}


def test_plain_mode_is_compressed_only(tmp_path):
    f, store = _file(str(tmp_path), encrypted=False)
    store["x"] = {"k": {"data": [1, 2], "fetched_at": 2.0}}
    f._write_ns("x", store["x"])
    blob = (tmp_path / "x.bin").read_bytes()
    assert blob[4:5] == CACHE_MODE_PLAIN
    assert f.load_all() == {"x": store["x"]}


def test_file_is_owner_only(tmp_path):
    f, store = _file(str(tmp_path))
    store["x"] = {"k": {"data": 1, "fetched_at": 1.0}}
    f._write_ns("x", store["x"])
    mode = stat.S_IMODE(os.stat(tmp_path / "x.bin").st_mode)
    assert mode == 0o600
    assert not os.path.exists(tmp_path / "x.bin.tmp")


def test_unchanged_content_is_not_rewritten(tmp_path):
    f, store = _file(str(tmp_path))
    store["x"] = {"k": {"data": 1, "fetched_at": 1.0}}
    f._write_ns("x", store["x"])
    first = f.last_write_at["x"]
    os.utime(tmp_path / "x.bin", (0, 0))
    f._write_ns("x", store["x"])
    assert f.last_write_at["x"] == first
    assert os.stat(tmp_path / "x.bin").st_mtime == 0     # file untouched
    store["x"]["k"]["data"] = 2
    f._write_ns("x", store["x"])
    assert os.stat(tmp_path / "x.bin").st_mtime > 0


def test_empty_namespace_deletes_its_file(tmp_path):
    f, store = _file(str(tmp_path))
    store["x"] = {"k": {"data": 1}}
    f._write_ns("x", store["x"])
    f._write_ns("x", {})
    assert not os.path.exists(tmp_path / "x.bin")


@pytest.mark.parametrize("blob", [b"", b"JUNK", b"LMC1", b"LMC1Q" + b"x" * 10,
                                  b"LMC1Z" + b"not-zlib"])
def test_bad_files_are_rejected(blob):
    f, _ = _file("/nonexistent")
    with pytest.raises(Exception):
        f.decode(blob)


def test_wrong_key_or_missing_key_cannot_read(tmp_path):
    f, store = _file(str(tmp_path))
    store["x"] = {"k": {"data": 1}}
    f._write_ns("x", store["x"])
    other = Fernet(Fernet.generate_key())
    g = ShardedCacheFile("t", lambda: str(tmp_path), dict,
                         encrypt=other.encrypt, decrypt=other.decrypt)
    assert g.load_all() == {}            # unreadable file skipped, not fatal
    h = ShardedCacheFile("t", lambda: str(tmp_path), dict)
    with pytest.raises(ValueError):
        h.decode((tmp_path / "x.bin").read_bytes())


def test_one_bad_file_does_not_stop_the_rest(tmp_path):
    f, store = _file(str(tmp_path))
    store["good"] = {"k": {"data": 1}}
    f._write_ns("good", store["good"])
    (tmp_path / "bad.bin").write_bytes(b"garbage")
    (tmp_path / "notes.txt").write_text("ignored")
    assert f.load_all() == {"good": store["good"]}


def test_odd_namespace_names_are_hashed_but_round_trip(tmp_path):
    assert _ns_filename("nb_devices") == "nb_devices.bin"
    weird = "../etc/passwd"
    name = _ns_filename(weird)
    assert "/" not in name and name.startswith("ns-")
    f, store = _file(str(tmp_path))
    store[weird] = {"k": {"data": 1}}
    f._write_ns(weird, store[weird])
    assert f.load_all() == {weird: store[weird]}


# ═════════════════════════ 2. read path ══════════════════════════════════════

def test_missing_entry_waits_for_fetch_then_serves_from_cache():
    hub, fetch = _Hub(), _Fetch({"rows": [1]})

    async def go():
        a = await hub.cache_read("ns", "k", fetch, tenants=("tA",))
        b = await hub.cache_read("ns", "k", fetch, tenants=("tA",))
        return a, b
    a, b = run(go())
    assert a == b == {"rows": [1]}
    assert fetch.calls == 1
    assert hub.warm_cache["ns"]["k"]["tenants"] == ["tA"]


def test_concurrent_first_reads_share_one_fetch():
    hub, fetch = _Hub(), _Fetch(delay=0.05)

    async def go():
        return await asyncio.gather(*[hub.cache_read("ns", "k", fetch) for _ in range(5)])
    out = run(go())
    assert fetch.calls == 1 and all(o == fetch.data for o in out)


def test_old_entry_is_served_immediately_and_refreshed_in_background():
    hub, fetch = _Hub(), _Fetch({"new": 1})
    hub.warm_cache["ns"] = {"k": {"data": {"old": 1},
                                  "fetched_at": time.time() - wc.IDLE_INTERVAL_S - 1}}

    async def go():
        first = await hub.cache_read("ns", "k", fetch)
        await hub.cache_wait_idle(2)
        return first, await hub.cache_read("ns", "k", fetch)
    first, second = run(go())
    assert first == {"old": 1}
    assert second == {"new": 1}
    assert fetch.calls == 1


def test_fresh_entry_does_not_refetch():
    hub, fetch = _Hub(), _Fetch()
    hub.warm_cache["ns"] = {"k": {"data": "x", "fetched_at": time.time()}}
    assert run(hub.cache_read("ns", "k", fetch)) == "x"
    assert fetch.calls == 0


def test_invalidated_entry_waits_for_the_refresh():
    hub, fetch = _Hub(), _Fetch("after-write")
    hub.warm_cache["ns"] = {"k": {"data": "before", "fetched_at": time.time()}}
    hub.warm_invalidate("ns", ("k",))
    assert run(hub.cache_read("ns", "k", fetch)) == "after-write"


def test_invalidated_entry_serves_old_data_if_refresh_fails():
    hub, fetch = _Hub(), _Fetch()
    fetch.fail = RuntimeError("spoke down")
    t0 = time.time() - 30
    hub.warm_cache["ns"] = {"k": {"data": "before", "fetched_at": t0}}
    hub.warm_invalidate("ns", ("k",))
    assert run(hub.cache_read("ns", "k", fetch)) == "before"
    meta = hub.cache_meta("ns", "k")
    assert meta["cached_at"] == t0 and meta["stale"] and "spoke down" in meta["error"]


def test_failure_is_never_cached_and_first_failure_is_forgotten():
    hub, fetch = _Hub(), _Fetch()
    fetch.fail = RuntimeError("nope")
    with pytest.raises(RuntimeError):
        run(hub.cache_read("ns", "bad-id", fetch))
    assert "bad-id" not in hub.warm_cache.get("ns", {})
    assert ("ns", "bad-id") not in hub._cache_read_jobs   # not retried forever


def test_failed_background_refresh_keeps_data_and_badges_stale():
    hub, fetch = _Hub(), _Fetch()
    hub.warm_cache["ns"] = {"k": {"data": "keep", "fetched_at": time.time() - 1000}}
    fetch.fail = RuntimeError("timeout")

    async def go():
        await hub.cache_read("ns", "k", fetch)
        await hub.cache_wait_idle(2)
    run(go())
    assert hub.warm_get("ns", "k") == "keep"
    out = hub.cache_annotate({"rows": []}, "ns", "k")
    assert out["stale"] is True and out["cached_at"]


def test_annotate_never_mutates_cached_object():
    hub = _Hub()
    data = {"rows": [1]}
    hub.warm_cache["ns"] = {"k": {"data": data, "fetched_at": time.time()}}
    out = hub.cache_annotate(data, "ns", "k")
    assert "cached_at" in out and "cached_at" not in data
    assert hub.cache_annotate([1], "ns", "k") == [1]


def test_fetch_later_queues_behind_the_lane_limit():
    """cache_fetch_later registers a read job and fetches in the background
    through the lane limit, so rebuilding many entries at once runs at most
    LANE_CONCURRENCY of them together, and each one is stored."""
    hub = _Hub()
    live = {"now": 0, "peak": 0}

    def fetch_for(k):
        async def fetch():
            live["now"] += 1
            live["peak"] = max(live["peak"], live["now"])
            await asyncio.sleep(0.02)
            live["now"] -= 1
            return {"k": k}
        return fetch

    async def go():
        for i in range(6):
            assert hub.cache_fetch_later("m", f"k{i}", fetch_for(i), lane="m")
        await hub.cache_wait_idle()

    run(go())
    assert live["peak"] == wc.LANE_CONCURRENCY
    assert sorted(hub.cache_keys("m")) == [f"k{i}" for i in range(6)]
    assert not hub.cache_fetch_later("m", "k9", fetch_for(9), lane="m")  # no loop


def test_fresh_read_waits_for_a_due_refresh_but_never_inside_the_floor():
    """cache_read_fresh (a background build feeding another entry) waits for
    a due refresh instead of returning the copy it replaces; inside the floor
    it fetches nothing, and a failed refresh serves the cached copy."""
    kw = {"min_interval_s": 300.0, "refresh_s": 300.0}
    hub, fetch = _Hub(), _Fetch("new")
    hub.warm_cache["ns"] = {"k": {"data": "old", "fetched_at": time.time() - 400}}
    assert run(hub.cache_read_fresh("ns", "k", fetch, **kw)) == "new"
    assert run(hub.cache_read_fresh("ns", "k", fetch, **kw)) == "new"
    assert fetch.calls == 1
    hub, fetch = _Hub(), _Fetch()
    fetch.fail = RuntimeError("spoke down")
    hub.warm_cache["ns"] = {"k": {"data": "old", "fetched_at": time.time() - 400}}
    assert run(hub.cache_read_fresh("ns", "k", fetch, **kw)) == "old"
    assert run(hub.cache_read_fresh("ns", "k", fetch, **kw)) == "old"
    assert fetch.calls == 1


def test_fetch_now_bypasses_a_fresh_entry():
    hub, fetch = _Hub(), _Fetch("live")
    hub.warm_cache["ns"] = {"k": {"data": "cached", "fetched_at": time.time()}}
    assert run(hub.cache_fetch_now("ns", "k", fetch)) == "live"
    assert hub.warm_get("ns", "k") == "live"


def test_restart_warm_loads_encrypted_files(tmp_path):
    hub = _Hub(cache_dir=str(tmp_path))
    run(hub.cache_read("ns", "k", _Fetch({"v": 1}), tenants=("tA",)))
    run(hub.warm_cache_flush_now())
    assert os.path.exists(tmp_path / "warm" / "ns.bin")
    hub2 = _Hub(cache_dir=str(tmp_path))
    hub2.warm_cache_load()
    assert hub2.warm_get("ns", "k") == {"v": 1}
    assert hub2.warm_cache["ns"]["k"]["tenants"] == ["tA"]
    # Served from disk without any spoke call.
    fetch = _Fetch()
    assert run(hub2.cache_read("ns", "k", fetch)) == {"v": 1}
    assert fetch.calls == 0


def test_runtime_bookkeeping_is_not_persisted():
    hub = _Hub()
    hub.warm_cache["ns"] = {"k": {"data": 1, "fetched_at": 1.0, "error": "x",
                                  "error_at": 2.0, "read_at": 3.0}}
    assert hub._warm_ns_snapshot("ns") == {"k": {"data": 1, "fetched_at": 1.0, "read_at": 3.0}}


def test_legacy_plaintext_json_is_migrated_and_deleted(tmp_path):
    legacy = tmp_path / "warm_cache.json"
    legacy.write_text(json.dumps({"old_ns": {"k": {"data": [1], "fetched_at": 5.0}}}))
    hub = _Hub(cache_dir=str(tmp_path))
    hub.warm_cache_load()
    assert hub.warm_get("old_ns", "k") == [1]
    assert not legacy.exists()
    blob = (tmp_path / "warm" / "old_ns.bin").read_bytes()
    assert blob[4:5] == CACHE_MODE_ENCRYPTED


# ═════════════════════════ 3. refresher + admin actions ══════════════════════

def _feed(hub, jobs):
    hub.cache_register_feed("t", lambda h: [CacheJob(**j) for j in jobs])


def test_feed_entries_are_fetched_on_first_tick_with_no_one_logged_in():
    hub, fetch = _Hub(), _Fetch()
    _feed(hub, [dict(ns="ns", key="k", fetch=fetch, tenants=("tA",))])

    async def go():
        n = await hub.cache_refresh_tick()
        await hub.cache_wait_idle(2)
        return n
    assert run(go()) == 1
    assert hub.warm_get("ns", "k") == fetch.data


def test_interval_is_fast_while_active_and_slow_while_idle():
    hub = _Hub()
    job = CacheJob("ns", "k", _Fetch(), ("tA",))
    assert hub._cache_interval(job, set()) == wc.IDLE_INTERVAL_S
    assert hub._cache_interval(job, {"tA"}) == wc.ACTIVE_INTERVAL_S
    assert hub._cache_interval(job, {"tB"}) == wc.IDLE_INTERVAL_S
    shared = CacheJob("ns", "k", _Fetch(), None)
    assert hub._cache_interval(shared, {"tB"}) == wc.ACTIVE_INTERVAL_S
    admin_only = CacheJob("ns", "k", _Fetch(), (ALL_SCOPE,))
    assert hub._cache_interval(admin_only, {"tB"}) == wc.IDLE_INTERVAL_S
    assert hub._cache_interval(admin_only, {ALL_SCOPE}) == wc.ACTIVE_INTERVAL_S


def test_interval_is_fast_for_active_tenant_in_any_capitalisation():
    """A logged-in user assigned "TA" keeps "tA"'s data on the fast cycle
    (tenant ids compare canonically, fleet rule 6.1)."""
    job = CacheJob("ns", "k", _Fetch(), ("tA",))
    assert _Hub()._cache_interval(job, {"TA"}) == wc.ACTIVE_INTERVAL_S


def test_due_respects_active_and_idle_age():
    hub = _Hub()
    job = CacheJob("ns", "k", _Fetch(), ("tA",), from_feed=True)
    now = time.time()
    age = wc.ACTIVE_INTERVAL_S + wc.JITTER_S + 1
    hub.warm_cache["ns"] = {"k": {"data": 1, "fetched_at": now - age}}
    assert hub._cache_job_due(job, now, {"tA"}) is True     # active: due
    assert hub._cache_job_due(job, now, set()) is False     # idle: not yet


def test_login_kick_refreshes_that_tenant_only():
    hub = _Hub()
    now = time.time()
    a = CacheJob("ns", "a", _Fetch(), ("tA",), from_feed=True)
    b = CacheJob("ns", "b", _Fetch(), ("tB",), from_feed=True)
    hub.warm_cache["ns"] = {"a": {"data": 1, "fetched_at": now - 5},
                            "b": {"data": 1, "fetched_at": now - 5}}
    hub.cache_kick_tenant("tA")
    assert hub._cache_job_due(a, time.time(), set()) is True
    assert hub._cache_job_due(b, time.time(), set()) is False


def test_admin_kick_refreshes_admin_and_shared_data_not_tenants():
    hub = _Hub()
    now = time.time()
    adm = CacheJob("ns", "adm", _Fetch(), (ALL_SCOPE,), from_feed=True)
    shared = CacheJob("ns", "sh", _Fetch(), None, from_feed=True)
    ten = CacheJob("ns", "t", _Fetch(), ("tA",), from_feed=True)
    hub.warm_cache["ns"] = {k: {"data": 1, "fetched_at": now - 5} for k in ("adm", "sh", "t")}
    hub.cache_kick_tenant(None)
    t = time.time()
    assert hub._cache_job_due(adm, t, set()) is True
    assert hub._cache_job_due(shared, t, set()) is True
    assert hub._cache_job_due(ten, t, set()) is False


def test_read_only_entries_refresh_only_while_someone_is_looking():
    hub = _Hub()
    job = CacheJob("ns", "k", _Fetch(), ("tA",), from_feed=False)
    old = time.time() - 10_000
    hub.warm_cache["ns"] = {"k": {"data": 1, "fetched_at": old}}
    assert hub._cache_job_due(job, time.time(), set()) is False
    assert hub._cache_job_due(job, time.time(), {"tA"}) is True


def test_a_recent_read_makes_the_tenant_active():
    hub = _Hub()
    run(hub.cache_read("ns", "k", _Fetch(), tenants=("tA",)))
    assert "tA" in hub._cache_active_scopes()


def test_eviction_drops_unread_detail_entries_only():
    hub = _Hub()
    old = time.time() - wc.DETAIL_EVICT_S - 10
    hub.warm_cache["ns"] = {
        "detail-old": {"data": 1, "fetched_at": old, "detail": True},
        "detail-read": {"data": 1, "fetched_at": old, "detail": True, "read_at": time.time()},
        "list-old": {"data": 1, "fetched_at": old},
    }
    assert hub.cache_evict_idle() == 1
    assert set(hub.warm_cache["ns"]) == {"detail-read", "list-old"}


def test_cache_refresh_exact_vs_prefix():
    hub = _Hub()
    f = _Fetch("new")
    now = time.time()

    async def go():
        for k in ("fw-1", "fw-10"):
            hub.warm_cache.setdefault("fw_rules", {})[k] = {"data": "old", "fetched_at": now}
            hub._cache_remember("fw_rules", k, f, None, "", False)
        n_exact = hub.cache_refresh("fw_rules", ("fw-1",), exact=True)
        await hub.cache_wait_idle(2)
        return n_exact
    assert run(go()) == 1
    assert hub.warm_get("fw_rules", "fw-1") == "new"
    assert hub.warm_get("fw_rules", "fw-10") == "old"


def test_cache_refresh_recovers_from_malformed_entry():
    """A corrupt cache entry is treated as missing and refreshed."""
    hub = _Hub()
    fetch = _Fetch("recovered")

    async def go():
        hub.warm_cache["ns"] = {"k": "corrupt"}
        hub._cache_remember("ns", "k", fetch, None, "", False)
        count = hub.cache_refresh("ns", ("k",), exact=True)
        await hub.cache_wait_idle(2)
        return count

    assert run(go()) == 1
    assert hub.warm_get("ns", "k") == "recovered"


def test_cache_wait_idle_times_out_on_a_slow_fetch():
    hub = _Hub()

    async def go():
        hub._cache_spawn(CacheJob("ns", "k", _Fetch(delay=1.0)))
        return await hub.cache_wait_idle(timeout=0.05)
    assert run(go()) is False


def test_purge_one_tenant_keeps_others_and_kicks_a_refresh():
    hub = _Hub()
    hub.warm_cache["ns"] = {"a": {"data": 1, "tenants": ["tA"]},
                            "b": {"data": 1, "tenants": ["tB"]}}
    assert hub.cache_purge("tA") == 1
    assert set(hub.warm_cache["ns"]) == {"b"}
    assert "tA" in hub._cache_kicked
    assert hub.cache_purge() == 1 and hub.warm_cache["ns"] == {}


def test_status_reports_entries_and_activity():
    hub = _Hub(active={"tA"})
    _feed(hub, [dict(ns="ns", key="k", fetch=_Fetch(), tenants=("tA",))])
    hub.warm_cache["ns"] = {"k": {"data": 1, "fetched_at": time.time()}}
    st = hub.cache_status()
    assert st["encrypted"] is True and st["feeds"] == ["t"]
    row = st["namespaces"][0]["entries"][0]
    assert row["feed"] and row["active"] and row["cached"] and not row["stale"]


def test_one_broken_feed_does_not_stop_the_others():
    hub = _Hub()

    def boom(h):
        raise RuntimeError("bad feed")
    hub.cache_register_feed("boom", boom)
    _feed(hub, [dict(ns="ns", key="k", fetch=_Fetch())])
    assert [(j.ns, j.key) for j in hub._cache_collect_jobs()] == [("ns", "k")]


# ═════════════════════════ admin/auth cache routes ═══════════════════════════

def _client(hub, sess):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import api  # noqa: F401 — admin_cache imports from api
    from routes import admin_cache
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("permissions", {}).get("admin")),
    )
    admin_cache.register(app, hub, ctx)
    return TestClient(app)


_ADMIN = {"user": {"permissions": {"admin": True}}}
_TENANT_A = {"user": {"tenant_id": "tA"}}


def test_admin_routes_reject_non_admins():
    hub = _Hub()
    c = _client(hub, _TENANT_A)
    assert c.get("/admin/cache/status").status_code == 403
    assert c.post("/admin/cache/refresh").status_code == 403
    assert c.post("/admin/cache/purge").status_code == 403
    assert _client(hub, None).get("/auth/cache-status").status_code == 401


def test_admin_status_and_purge():
    hub = _Hub()
    hub.warm_cache["nb_devices"] = {"x": {"data": 1, "fetched_at": time.time(), "tenants": ["tA"]}}
    c = _client(hub, _ADMIN)
    assert c.get("/admin/cache/status").json()["namespaces"][0]["namespace"] == "nb_devices"
    r = c.post("/admin/cache/purge?tenant=tA").json()
    assert r == {"status": "ok", "tenant": "tA", "dropped": 1}


def test_tenant_refresh_button_only_refreshes_entries_it_can_see():
    hub = _Hub()
    fa, fb = _Fetch("A2"), _Fetch("B2")
    now = time.time()
    for key, tid, f in (("ka", "tA", fa), ("kb", "tB", fb)):
        hub.warm_cache.setdefault("nb_devices", {})[key] = {
            "data": "old", "fetched_at": now, "tenants": [tid]}
        hub._cache_remember("nb_devices", key, f, (tid,), "", False)
    r = _client(hub, _TENANT_A).post("/auth/cache/refresh?module=netbox_devices")
    assert r.json()["refreshed"] == 1
    assert fa.calls == 1 and fb.calls == 0
    assert hub.warm_get("nb_devices", "ka") == "A2"
    assert hub.warm_get("nb_devices", "kb") == "old"


def test_tenant_refresh_button_matches_tenant_in_any_capitalisation():
    """A session assigned "TA" refreshes the entries stamped "tA" (tenant ids
    compare canonically, fleet rule 6.1), never tB's."""
    hub = _Hub()
    fa, fb = _Fetch("A2"), _Fetch("B2")
    now = time.time()
    for key, tid, f in (("ka", "tA", fa), ("kb", "tB", fb)):
        hub.warm_cache.setdefault("nb_devices", {})[key] = {
            "data": "old", "fetched_at": now, "tenants": [tid]}
        hub._cache_remember("nb_devices", key, f, (tid,), "", False)
    r = _client(hub, {"user": {"tenant_id": "TA"}}).post("/auth/cache/refresh?module=netbox_devices")
    assert r.json()["refreshed"] == 1
    assert fa.calls == 1 and fb.calls == 0


def test_footer_status_is_ready_when_everything_is_cached():
    hub = _Hub()
    r = _client(hub, _TENANT_A).get("/auth/cache-status").json()
    assert r == {"loading": [], "all_ready": True, "tenant_id": "tA"}


# ═════════════════════════ cached objects are never narrowed in place ════════

def test_tenant_filters_return_copies_and_never_modify_the_input():
    from simulations import tenant_filter as tf
    env = {"sessions": [{"ip": "10.0.0.1"}, {"ip": "192.168.1.1"}], "total": 2}
    out = tf.filter_items_by_prefixes(env, ["10.0.0.0/8"], ["ip"])
    assert [r["ip"] for r in out["sessions"]] == ["10.0.0.1"]
    assert len(env["sessions"]) == 2

    nested = {"payload": {"data": [{"ip": "10.0.0.1"}, {"ip": "172.16.0.1"}]}}
    out = tf.filter_items_by_prefixes(nested, ["10.0.0.0/8"], ["ip"])
    assert len(out["payload"]["data"]) == 1
    assert len(nested["payload"]["data"]) == 2

    vms = {"vms": [{"name": "a", "ips": ["10.0.0.5"]}, {"name": "b", "ips": ["8.8.8.8"]}]}
    out = tf.filter_hypervisor_vms(vms, ["10.0.0.0/8"])
    assert [v["name"] for v in out["vms"]] == ["a"]
    assert len(vms["vms"]) == 2

    rules = {"rows": [{"source_net": "10.0.0.0/24"}, {"source_net": "8.8.8.0/24"}]}
    tf.filter_firewall_rules(rules, ["10.0.0.0/8"])
    assert len(rules["rows"]) == 2


def test_job_refresh_floor_slows_active_refresh():
    hub = _Hub()
    job = CacheJob("ns", "k", _Fetch(), ("tA",), refresh_s=300.0)
    assert hub._cache_interval(job, {"tA"}) == 300.0
    assert hub._cache_interval(job, set()) == wc.IDLE_INTERVAL_S
    floor = CacheJob("ns", "k", _Fetch(), ("tA",), min_interval_s=300.0)
    assert hub._cache_interval(floor, {"tA"}) == 300.0


def test_login_kick_obeys_min_interval_floor():
    hub = _Hub(active={"tA"})
    job = CacheJob("ns", "k", _Fetch(), ("tA",), min_interval_s=300.0)
    now = time.time()
    hub.warm_cache["ns"] = {
        "k": {"data": {"rows": []}, "fetched_at": now - 60, "tenants": ["tA"]},
    }
    hub._cache_read_jobs[("ns", "k")] = job
    hub.cache_kick_tenant("tA")

    assert not hub._cache_job_due(job, now, {"tA"})
    assert hub._cache_job_due(job, now + 301, {"tA"})


def test_refresh_cadence_does_not_delay_login_kick():
    """``refresh_s`` is only the background cadence (Entra): a kick is due now."""
    hub = _Hub(active={"tA"})
    job = CacheJob("ns", "k", _Fetch(), ("tA",), refresh_s=900.0)
    now = time.time()
    hub.warm_cache["ns"] = {
        "k": {"data": {"rows": []}, "fetched_at": now - 60, "tenants": ["tA"]},
    }
    hub._cache_read_jobs[("ns", "k")] = job
    assert not hub._cache_job_due(job, now, {"tA"})
    hub.cache_kick_tenant("tA")
    assert hub._cache_job_due(job, now, {"tA"})


def test_cache_refresh_obeys_min_interval_floor():
    """Manual invalidation cannot bypass a slow source's minimum interval."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("new")
    job = CacheJob("ns", "k", fetch, ("tA",), min_interval_s=300.0)
    hub.cache_register_feed("slow", lambda _hub: [job])
    entry = {"data": "old", "fetched_at": time.time() - 10, "tenants": ["tA"]}
    hub.warm_cache["ns"] = {"k": entry}

    async def refresh_twice():
        """Skip a recent cache, then refresh it once its floor has elapsed."""
        assert hub.cache_refresh("ns", ("k",), exact=True) == 0
        assert entry["fetched_at"] > 0
        entry["fetched_at"] = 0
        entry["error_at"] = time.time() - 10
        assert hub.cache_refresh("ns", ("k",), exact=True) == 0
        entry["error_at"] = time.time() - 301
        assert hub.cache_refresh("ns", ("k",), exact=True) == 1
        await hub.cache_wait_idle()

    run(refresh_twice())
    assert fetch.calls == 1
    assert hub.warm_get("ns", "k") == "new"


def test_cache_refresh_after_write_ignores_refresh_cadence():
    """A write's ``cache_refresh`` refreshes a ``refresh_s``-only job at once
    (Entra group/user writes), and floor-free siblings in the same namespace
    still refresh when a floored entry is held back."""
    hub = _Hub(active={"tA"})
    cadence, floored = _Fetch("cadence-new"), _Fetch("floored-new")
    jobs = [CacheJob("ns", "a", cadence, ("tA",), refresh_s=900.0),
            CacheJob("ns", "b", floored, ("tA",), min_interval_s=300.0)]
    hub.cache_register_feed("mixed", lambda _hub: jobs)
    recent = time.time() - 10
    hub.warm_cache["ns"] = {
        "a": {"data": "cadence-old", "fetched_at": recent, "tenants": ["tA"]},
        "b": {"data": "floored-old", "fetched_at": recent, "tenants": ["tA"]},
    }

    async def refresh():
        """Refresh the whole namespace and wait for the fetches."""
        assert hub.cache_refresh("ns") == 1
        await hub.cache_wait_idle()

    run(refresh())
    assert (cadence.calls, floored.calls) == (1, 0)
    assert hub.warm_get("ns", "a") == "cadence-new"
    assert hub.warm_cache["ns"]["b"]["fetched_at"] == recent


def test_floor_holds_after_a_first_fetch_fails():
    """A floored job whose first fetch failed has no entry to record it on:
    neither the refresher nor a page read retries it inside the floor, the
    read raises ``CacheFloorError``, and the first success clears the record."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("rows")
    fetch.fail = RuntimeError("clearpass down")
    job = CacheJob("ns", "k", fetch, ("tA",), min_interval_s=300.0)
    hub.cache_register_feed("slow", lambda _hub: [job])

    async def scenario():
        """Fail once, then tick and read inside the floor, then succeed after it."""
        assert await hub.cache_refresh_tick() == 1
        await hub.cache_wait_idle()
        assert await hub.cache_refresh_tick() == 0
        with pytest.raises(wc.CacheFloorError) as held:
            await hub.cache_read("ns", "k", fetch, tenants=("tA",), min_interval_s=300.0)
        assert hub._cache_job_due(hub._cache_collect_jobs()[0], time.time() + 301, {"tA"})
        # Once the floor has passed, the next read fetches and clears the failure.
        hub._cache_failed[("ns", "k")] = (time.time() - 301, "clearpass down", ("tA",))
        fetch.fail = None
        return held.value, await hub.cache_read("ns", "k", fetch, tenants=("tA",),
                                                min_interval_s=300.0)

    held, data = run(scenario())
    assert "clearpass down" in str(held) and 0 < held.retry_after <= 300
    assert data == "rows" and fetch.calls == 2 and not hub._cache_failed


def test_floor_holds_page_reads_after_a_failed_refresh():
    """Old floored data whose background refresh failed: later reads inside
    the floor serve the cached data and start no other fetch."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("new")
    fetch.fail = RuntimeError("clearpass down")
    hub.warm_cache["ns"] = {"k": {"data": "old", "fetched_at": time.time() - 400,
                                  "tenants": ["tA"]}}

    async def read_twice():
        """Read, let the refresh fail, then read again."""
        reads = []
        for _ in range(2):
            reads.append(await hub.cache_read("ns", "k", fetch, tenants=("tA",),
                                              min_interval_s=300.0))
            await hub.cache_wait_idle()
        return reads

    assert run(read_twice()) == ["old", "old"]
    assert fetch.calls == 1


def test_floor_holds_reads_of_an_invalidated_entry():
    """An invalidated floored entry is not refetched within the floor of its
    last fetch (kept in ``stale_from``) or of a failed refresh."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("new")
    fetch.fail = RuntimeError("clearpass down")
    entry = {"data": "old", "fetched_at": 0, "stale_from": time.time() - 10,
             "tenants": ["tA"]}
    hub.warm_cache["ns"] = {"k": entry}

    async def read(n):
        """Read the entry n times; return the last answer."""
        for _ in range(n):
            data = await hub.cache_read("ns", "k", fetch, tenants=("tA",),
                                        min_interval_s=300.0)
        return data

    assert run(read(1)) == "old" and fetch.calls == 0
    entry["stale_from"] = time.time() - 400
    assert run(read(2)) == "old" and fetch.calls == 1


def test_warm_drop_exact_keeps_keys_that_extend_a_dropped_key():
    """``exact`` drops only the named keys, not keys that start with them."""
    hub = _Hub()
    hub.warm_cache["ns"] = {"a|x": {"data": 1}, "a|x,y": {"data": 2}}
    assert hub.warm_drop("ns", ("a|x",), exact=True) == 1
    assert list(hub.warm_cache["ns"]) == ["a|x,y"]


async def _turns(cond):
    """Yield to the loop until ``cond()`` holds, for at most 20 turns."""
    for _ in range(20):
        if cond():
            return True
        await asyncio.sleep(0)
    return cond()


def test_warm_drop_detaches_a_running_fetch():
    """A fetch still running when its key is dropped (for example from a NAC
    spoke that has just moved to another tenant) stores nothing when it
    finishes. The read already waiting on it still gets its answer, and the
    next read starts a fresh fetch instead of joining it."""
    hub = _Hub(active={"tA"})
    calls = []

    async def scenario():
        """Drop the key while the first fetch runs; the second fetch ends first."""
        gates = [asyncio.Event(), asyncio.Event()]
        answers = ["before the drop", "after the drop"]

        async def fetch():
            """The n-th call waits for its gate, then answers."""
            n = len(calls)
            calls.append(n)
            await gates[n].wait()
            return answers[n]

        def read():
            """Start a read of the key."""
            return asyncio.ensure_future(hub.cache_read("ns", "k", fetch, tenants=("tA",)))

        first = read()
        assert await _turns(lambda: len(calls) == 1)
        hub.warm_drop("ns", ("k",))
        second = read()
        assert await _turns(lambda: len(calls) == 2)
        gates[1].set()
        assert await second == "after the drop"
        gates[0].set()
        assert await first == "before the drop"
        await hub.cache_wait_idle()

    run(scenario())
    assert hub.warm_get("ns", "k") == "after the drop"
    assert not hub._cache_dropped


def test_warm_drop_lifts_the_failure_floor():
    """A dropped key starts over: neither a failure recorded before the drop
    nor a fetch that fails after it holds back the next read."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("rows")
    hub._cache_failed[("ns", "k")] = (time.time(), "clearpass down", ("tA",))

    async def scenario():
        """Drop a floored key, then drop it again while its fetch fails."""
        hub.warm_drop("ns", ("k",))
        assert await hub.cache_read("ns", "k", fetch, tenants=("tA",),
                                    min_interval_s=300.0) == "rows"
        hub.warm_drop("ns", ("k",))
        gate = asyncio.Event()

        async def failing():
            """Fail once the gate opens."""
            await gate.wait()
            raise RuntimeError("old spoke gone")

        first = asyncio.ensure_future(hub.cache_read("ns", "k", failing, tenants=("tA",),
                                                     min_interval_s=300.0))
        assert await _turns(lambda: ("ns", "k") in hub._cache_inflight)
        hub.warm_drop("ns", ("k",))
        gate.set()
        with pytest.raises(RuntimeError):
            await first
        return await hub.cache_read("ns", "k", fetch, tenants=("tA",), min_interval_s=300.0)

    assert run(scenario()) == "rows"
    assert fetch.calls == 2 and not hub._cache_failed


def test_cache_purge_lets_a_failed_first_fetch_retry():
    """A purge starts over for a floored job whose first fetch failed, as it
    does for a cached entry; another tenant's purge leaves the floor alone."""
    hub = _Hub(active={"tA"})
    fetch = _Fetch("rows")
    fetch.fail = RuntimeError("clearpass down")

    async def read():
        """Read the floored entry for tenant tA."""
        return await hub.cache_read("ns", "k", fetch, tenants=("tA",), min_interval_s=300.0)

    async def scenario():
        """Fail, purge another tenant (still held), purge tA, then read."""
        with pytest.raises(RuntimeError):
            await read()
        hub.cache_purge("tB")
        with pytest.raises(wc.CacheFloorError):
            await read()
        hub.cache_purge("tA")
        fetch.fail = None
        return await read()

    assert run(scenario()) == "rows" and fetch.calls == 2
