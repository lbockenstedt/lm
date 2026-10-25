"""The hub data cache: every page is served from here, never fetched live.

WHAT IT IS
    One in-memory store, keyed ``(namespace, key)``:
      * ``namespace`` — the kind of data, e.g. ``"nb_netbox_devices"``,
        ``"list_endpoints"`` (NAC), ``"fw_rules"``, ``"pxmx_vms"``.
      * ``key``       — the scope inside it: a tenant (``"acme"``), the admin
        all-tenants view (``"_all_"``), or a shared device (a firewall id).
    Each entry holds the RAW spoke answer plus when it was fetched. Readers
    re-apply their own tenant/RBAC filter on every read — the cache never
    holds a filtered view, so one tenant can never see what another warmed.

HOW A PAGE READ WORKS  (``cache_read``)
    1. Entry present  → returned immediately. If it is older than the refresh
       interval a background refresh starts (the page is NOT blocked).
    2. Entry missing  → the very first read for that scope fetches live and
       waits for it (there is nothing to show yet). Errors propagate.
    3. Entry invalidated by a write (``warm_invalidate``) → wait up to
       ``INVALIDATED_WAIT_S`` for the refresh so the user sees their own
       change; if the spoke is slow, serve the old data badged stale.
    Concurrent reads of the same entry share ONE fetch (single-flight).

WHO KEEPS IT FRESH  (``run_cache_refresher_loop``)
    A background loop ticks every ``TICK_S``. It refreshes:
      * FEED jobs   — registered by each module (``cache_register_feed``): the
        full list of scopes that should always be warm (every tenant's NetBox
        devices, every firewall's rules, …). Refreshed every
        ``ACTIVE_INTERVAL_S`` (60s) while someone who can see the data is
        logged in, else every ``IDLE_INTERVAL_S`` (5 min).
      * READ jobs   — any other scope a page has read (e.g. one VM's detail).
        Remembered in memory, refreshed only while its tenant is active,
        evicted after ``DETAIL_EVICT_S`` (7 days) unread.
    Login calls ``cache_kick_tenant`` so that tenant's data refreshes now.
    Spoke protection: at most ``LANE_CONCURRENCY`` refreshes per lane (one
    lane per spoke/module) and ``GLOBAL_CONCURRENCY`` overall; a failed
    refresh retries on the normal interval (no hammering a down spoke).

WHEN IS IT "STALE"  (``cache_meta``)
    Data is ALWAYS shown. It is badged stale when older than ``STALE_AFTER_S``
    (10 min) or when the most recent refresh failed (spoke offline).

DISK  (``cache_core.ShardedCacheFile``)
    Every namespace is persisted to ``<cache_dir>/warm/<namespace>.bin`` —
    JSON → zlib → Fernet (hub key). Restored on startup so a restart serves
    warm data immediately while the refresher catches up. The old plaintext
    ``warm_cache.json`` is migrated once and deleted.

A leaf: stdlib + ``cache_core`` only. MUST NOT import ``main``/``api``; the
hub injects the encryption functions and the "who is logged in" function.
Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple

from cache_core import JsonCacheFile, ShardedCacheFile, StalenessPolicy

logger = logging.getLogger("Hub")

# ── tuning (fixed by design; the admin page shows them, it does not edit them) ──
ACTIVE_INTERVAL_S = 60.0       # refresh period while a viewer is logged in
IDLE_INTERVAL_S = 300.0        # refresh period while nobody who can see it is
STALE_AFTER_S = 600.0          # badge "stale" after this age
INVALIDATED_WAIT_S = 10.0      # how long a read waits for a post-write refresh
TICK_S = 10.0                  # refresher loop period
JITTER_S = 10.0                # spreads refreshes so keys don't fire in lockstep
LANE_CONCURRENCY = 2           # parallel refreshes per spoke/module
GLOBAL_CONCURRENCY = 8         # parallel refreshes overall
RECENT_READ_ACTIVE_S = 600.0   # a tenant read this recently counts as active
DETAIL_EVICT_S = 7 * 86400.0   # drop read-only (non-feed) entries unread this long
EVICT_EVERY_S = 3600.0

ALL_SCOPE = "*"                # "any logged-in user" marker for shared data

Fetch = Callable[[], Awaitable[Any]]


@dataclass
class CacheJob:
    """One thing the refresher can refresh.

    ``tenants`` — who can see this data: a tuple of tenant ids, or None for
    admin/shared data (active whenever ANYONE is logged in).
    ``lane``    — concurrency bucket (usually the spoke id or module name).
    """
    ns: str
    key: str
    fetch: Fetch
    tenants: Optional[Tuple[str, ...]] = None
    lane: str = ""
    from_feed: bool = False
    detail: bool = False
    _jitter: float = field(default=0.0, repr=False)


def _norm_tenants(tenants) -> Optional[Tuple[str, ...]]:
    if tenants is None:
        return None
    if isinstance(tenants, str):
        return (tenants,) if tenants else None
    t = tuple(str(x) for x in tenants if x)
    return t or None


def _jitter_for(ns: str, key: str) -> float:
    """Stable per-entry offset in [0, JITTER_S) so a fleet of keys that were
    all fetched at startup don't all come due in the same tick forever."""
    return (zlib.crc32(("%s|%s" % (ns, key)).encode()) % 1000) / 1000.0 * JITTER_S


class WarmCacheMixin:
    """Unified hub data cache (store + reads + refresher + disk)."""

    WARM_CACHE_FILE = "warm_cache.json"     # legacy single plaintext file (migrated)
    WARM_CACHE_DIR = "warm"                 # per-namespace encrypted files

    # ── lifecycle ────────────────────────────────────────────────────────────

    def warm_cache_init(self, *, encrypt: Optional[Callable[[bytes], bytes]] = None,
                        decrypt: Optional[Callable[[bytes], bytes]] = None) -> None:
        """Initialize the store. Call once from ``__init__``.

        ``encrypt``/``decrypt`` are the hub's Fernet byte functions; without
        them files are compressed but NOT encrypted (tests only)."""
        self.warm_cache: Dict[str, Dict[str, Any]] = {}
        self.warm_policy = StalenessPolicy()
        self._warm_cache_file = ShardedCacheFile(
            "hub cache", self._warm_cache_dir, self._warm_ns_snapshot,
            encrypt=encrypt, decrypt=decrypt)
        self._cache_feeds: Dict[str, Callable[[Any], Iterable[CacheJob]]] = {}
        self._cache_read_jobs: Dict[Tuple[str, str], CacheJob] = {}
        self._cache_inflight: Dict[Tuple[str, str], asyncio.Task] = {}
        self._cache_lane_sems: Dict[str, asyncio.Semaphore] = {}
        self._cache_global_sem: Optional[asyncio.Semaphore] = None
        self._cache_recent_tenant: Dict[str, float] = {}
        self._cache_kicked: Dict[str, float] = {}     # tenant (or ALL_SCOPE) → kick time
        self._cache_wake: Optional[asyncio.Event] = None
        self._cache_last_evict = 0.0
        self._cache_last_tick = 0.0
        # Injected by the API layer: () -> set of tenant ids with a live,
        # recently-used session, plus ALL_SCOPE if an admin is logged in.
        if not hasattr(self, "cache_active_scopes_fn"):
            self.cache_active_scopes_fn: Optional[Callable[[], set]] = None

    def _warm_cache_dir(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.WARM_CACHE_DIR)

    def _warm_cache_path(self) -> str:
        """Legacy single-file path (only read once, for migration)."""
        return os.path.join(getattr(self, "cache_dir", "."), self.WARM_CACHE_FILE)

    def _warm_ns_snapshot(self, ns: str) -> Dict[str, Any]:
        """What gets written for one namespace: data + timestamps only (the
        in-memory error/read bookkeeping is rebuilt at runtime)."""
        out = {}
        for k, e in list((self.warm_cache.get(ns) or {}).items()):
            if not isinstance(e, dict) or "data" not in e:
                continue
            out[k] = {f: e[f] for f in ("data", "fetched_at", "stale_from",
                                         "tenants", "detail", "read_at") if f in e}
        return out

    def warm_cache_load(self) -> None:
        """Rehydrate from disk on startup (best-effort; unreadable → empty).

        Also performs the one-time migration from the legacy plaintext
        ``warm_cache.json``: its namespaces are loaded, written out as
        encrypted per-namespace files, and the plaintext file is deleted."""
        loaded = self._warm_cache_file.load_all()
        self.warm_cache = {str(ns): {str(k): v for k, v in (entries or {}).items()
                                     if isinstance(v, dict)}
                           for ns, entries in loaded.items()}
        legacy = self._warm_cache_path()
        if os.path.exists(legacy):
            data = JsonCacheFile("legacy warm cache", lambda: legacy, dict).load() or {}
            migrated = []
            for ns, entries in data.items():
                if isinstance(entries, dict) and str(ns) not in self.warm_cache:
                    self.warm_cache[str(ns)] = {str(k): v for k, v in entries.items()
                                                if isinstance(v, dict)}
                    migrated.append(str(ns))
            self._warm_cache_file.write_all_sync(migrated)
            try:
                os.remove(legacy)
                logger.info("hub cache: migrated %d namespace(s) from %s (deleted)",
                            len(migrated), legacy)
            except OSError as exc:
                logger.warning("hub cache: could not delete legacy %s: %s", legacy, exc)
        total = sum(len(e) for e in self.warm_cache.values())
        logger.info("hub cache: restored %d namespace(s) / %d key(s) from %s",
                    len(self.warm_cache), total, self._warm_cache_dir())

    # ── low-level read/write (unchanged API; used by every module) ───────────

    def warm_get(self, namespace: str, key: str = "_") -> Optional[Any]:
        """Last-known raw envelope for ``(namespace, key)``, or None."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) and "data" in entry else None

    def warm_fetched_at(self, namespace: str, key: str = "_") -> Optional[float]:
        """Epoch seconds when ``(namespace, key)`` was last stored, or None
        (also None/0 right after ``warm_invalidate``)."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        ts = entry.get("fetched_at") if isinstance(entry, dict) else None
        return ts if isinstance(ts, (int, float)) else None

    def warm_state(self, namespace: str, key: str = "_",
                   policy: Optional[StalenessPolicy] = None) -> str:
        """``cache_core`` staleness verdict for one entry."""
        return (policy or self.warm_policy).classify(
            self.warm_fetched_at(namespace, key))

    async def warm_set(self, namespace: str, key: str, data: Any, *,
                       tenants=None, detail: bool = False) -> None:
        """Store a fresh envelope for ``(namespace, key)`` and schedule a
        (debounced) write of that namespace's file."""
        key = str(key)
        old = self.warm_cache.get(namespace, {}).get(key)
        entry = {"data": data, "fetched_at": time.time()}
        t = _norm_tenants(tenants)
        if t is None and isinstance(old, dict) and old.get("tenants"):
            t = tuple(old["tenants"])
        if t is not None:
            entry["tenants"] = list(t)
        if detail or (isinstance(old, dict) and old.get("detail")):
            entry["detail"] = True
        if isinstance(old, dict) and old.get("read_at"):
            entry["read_at"] = old["read_at"]
        self.warm_cache.setdefault(namespace, {})[key] = entry
        self._warm_cache_file.schedule_save(namespace)

    def warm_drop(self, ns_prefix: str, key_prefixes: tuple) -> int:
        """Delete entries (namespace starts ``ns_prefix``, key starts with any of
        ``key_prefixes``). Returns the count dropped."""
        n = 0
        for ns, entries in self.warm_cache.items():
            if not ns.startswith(ns_prefix):
                continue
            dropped = [k for k in entries if k.startswith(key_prefixes)]
            for k in dropped:
                del entries[k]
                self._cache_read_jobs.pop((ns, k), None)
            if dropped:
                n += len(dropped)
                self._warm_cache_file.schedule_save(ns)
        return n

    def warm_invalidate(self, ns_prefix: str, key_prefixes: tuple) -> int:
        """Mark matching entries as needing a refresh but KEEP their data:
        ``fetched_at`` becomes 0 (the next read waits briefly for a refresh)
        and the original time moves to ``stale_from`` so the badge stays
        honest if that refresh fails."""
        n = 0
        for ns, entries in self.warm_cache.items():
            if not ns.startswith(ns_prefix):
                continue
            hit = False
            for k, e in entries.items():
                if k.startswith(key_prefixes) and isinstance(e, dict) and e.get("fetched_at"):
                    e["stale_from"] = e["fetched_at"]
                    e["fetched_at"] = 0
                    n += 1
                    hit = True
            if hit:
                self._warm_cache_file.schedule_save(ns)
        return n

    def warm_last_fetched_at(self, namespace: str, key: str = "_") -> Optional[float]:
        """Epoch of the data actually held, even if the entry was invalidated."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        if not isinstance(entry, dict):
            return None
        ts = entry.get("fetched_at") or entry.get("stale_from")
        return ts if isinstance(ts, (int, float)) else None

    async def warm_cache_flush_now(self) -> None:
        """Write every dirty namespace now (shutdown path)."""
        await self._warm_cache_file.flush_now()

    # ── the page read ────────────────────────────────────────────────────────

    async def cache_read(self, ns: str, key: str, fetch: Fetch, *, tenants=None,
                         lane: str = "", detail: bool = False) -> Any:
        """Serve ``(ns, key)`` from cache; see the module docstring for the
        three cases (present / missing / invalidated).

        ``fetch`` is an async callable returning the RAW data to cache; it
        must RAISE on failure (an error envelope must never be cached).
        ``tenants`` — who can see this data (see ``CacheJob``).
        ``detail``  — True for drill-down data (one VM, one device): it is
        refreshed only while its tenant is active and evicted after a week
        unread."""
        key = str(key)
        job = self._cache_remember(ns, key, fetch, tenants, lane, detail)
        entry = self.warm_cache.get(ns, {}).get(key)
        now = time.time()
        if isinstance(entry, dict):
            entry["read_at"] = now
        if not isinstance(entry, dict) or "data" not in entry:
            # Nothing to show yet — this one read must wait.
            return await asyncio.shield(self._cache_spawn(job, foreground=True))
        fetched = entry.get("fetched_at") or 0
        if not fetched:
            # Invalidated by a write: give the refresh a moment so the user
            # sees their own change, else fall through to the old data.
            task = self._cache_spawn(job, foreground=True)
            try:
                return await asyncio.wait_for(asyncio.shield(task), INVALIDATED_WAIT_S)
            except Exception:  # noqa: BLE001 - timeout or spoke error → serve old data
                return self.warm_get(ns, key)
        if now - fetched >= self._cache_interval(job):
            self._cache_spawn(job)
        return entry["data"]

    async def cache_fetch_now(self, ns: str, key: str, fetch: Fetch, *, tenants=None,
                              lane: str = "", detail: bool = False) -> Any:
        """Fetch live NOW (joining any in-flight fetch), store, and return it.
        For security checks that must not trust a possibly-old copy (e.g. a
        write's ownership guard after a cache miss). Errors propagate."""
        job = self._cache_remember(ns, str(key), fetch, tenants, lane, detail)
        return await asyncio.shield(self._cache_spawn(job, foreground=True))

    def cache_meta(self, ns: str, key: str) -> Dict[str, Any]:
        """Badge info for a response: ``cached_at`` (epoch of the data shown),
        ``age`` (s), ``stale`` (bool) and ``error`` (last refresh failure)."""
        entry = self.warm_cache.get(ns, {}).get(str(key))
        if not isinstance(entry, dict):
            return {"cached_at": None, "age": None, "stale": False, "error": None}
        held = entry.get("fetched_at") or entry.get("stale_from") or 0
        age = max(0.0, time.time() - held) if held else None
        err_at = entry.get("error_at") or 0
        failing = bool(err_at and err_at >= (entry.get("fetched_at") or 0))
        stale = bool((age is not None and age > STALE_AFTER_S) or failing)
        return {"cached_at": held or None, "age": age, "stale": stale,
                "error": entry.get("error") if failing else None}

    def cache_annotate(self, resp: Any, ns: str, key: str) -> Any:
        """Add ``stale``/``cached_at`` to a dict response (the WebUI's existing
        "cached data" badge reads these). Non-dicts are returned unchanged.
        Returns a shallow copy — the cached object itself is never mutated."""
        if not isinstance(resp, dict):
            return resp
        m = self.cache_meta(ns, key)
        out = dict(resp)
        out["cached_at"] = m["cached_at"]
        if m["stale"]:
            out["stale"] = True
        return out

    # ── single-flight fetch ──────────────────────────────────────────────────

    def _cache_remember(self, ns, key, fetch, tenants, lane, detail) -> CacheJob:
        t = _norm_tenants(tenants)
        for tid in t or ():
            self._cache_recent_tenant[tid] = time.time()
        job = self._cache_read_jobs.get((ns, key))
        if job is None:
            job = CacheJob(ns, key, fetch, t, lane or ns, False, detail, _jitter_for(ns, key))
            self._cache_read_jobs[(ns, key)] = job
        else:
            # Latest closure wins (it captures the latest request context).
            job.fetch, job.tenants, job.lane = fetch, t, (lane or ns)
            job.detail = job.detail or detail
        return job

    def _cache_spawn(self, job: CacheJob, *, foreground: bool = False) -> asyncio.Task:
        """Start (or join) the one fetch for ``(job.ns, job.key)``.

        Foreground fetches (a user is waiting on a missing entry) skip the
        lane limits; background refreshes queue behind them."""
        k = (job.ns, job.key)
        task = self._cache_inflight.get(k)
        if task is not None and not task.done():
            return task
        task = asyncio.ensure_future(self._cache_run(job, foreground))
        self._cache_inflight[k] = task

        def _done(t, k=k):
            if self._cache_inflight.get(k) is t:
                self._cache_inflight.pop(k, None)
            if not t.cancelled():
                t.exception()  # mark retrieved: background failures are recorded, not raised
        task.add_done_callback(_done)
        return task

    def _cache_sems(self, lane: str):
        if self._cache_global_sem is None:
            self._cache_global_sem = asyncio.Semaphore(GLOBAL_CONCURRENCY)
        sem = self._cache_lane_sems.get(lane)
        if sem is None:
            sem = self._cache_lane_sems[lane] = asyncio.Semaphore(LANE_CONCURRENCY)
        return self._cache_global_sem, sem

    async def _cache_run(self, job: CacheJob, foreground: bool) -> Any:
        if foreground:
            return await self._cache_fetch_store(job)
        g, lane = self._cache_sems(job.lane or job.ns)
        async with g, lane:
            return await self._cache_fetch_store(job)

    async def _cache_fetch_store(self, job: CacheJob) -> Any:
        try:
            data = await job.fetch()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            entry = self.warm_cache.get(job.ns, {}).get(job.key)
            if isinstance(entry, dict):
                entry["error"] = str(exc)[:300] or exc.__class__.__name__
                entry["error_at"] = time.time()
            elif not job.from_feed:
                # Never fetched successfully (bad id, unsupported endpoint,
                # spoke down on first open): don't keep retrying it forever.
                self._cache_read_jobs.pop((job.ns, job.key), None)
            logger.debug("hub cache: refresh %s/%s failed: %s", job.ns, job.key, exc)
            raise
        await self.warm_set(job.ns, job.key, data, tenants=job.tenants, detail=job.detail)
        return data

    # ── activity (who is logged in) ──────────────────────────────────────────

    def _cache_active_scopes(self) -> set:
        scopes = set()
        fn = getattr(self, "cache_active_scopes_fn", None)
        if fn is not None:
            try:
                scopes |= set(fn() or ())
            except Exception as exc:  # noqa: BLE001
                logger.debug("hub cache: active-scopes fn failed: %s", exc)
        cutoff = time.time() - RECENT_READ_ACTIVE_S
        scopes |= {t for t, at in self._cache_recent_tenant.items() if at >= cutoff}
        return scopes

    def _cache_is_active(self, tenants, scopes: Optional[set] = None) -> bool:
        """Is someone who can see this data logged in? Shared/admin data
        (``tenants`` None) is active whenever anyone is."""
        scopes = self._cache_active_scopes() if scopes is None else scopes
        if not scopes:
            return False
        if tenants is None:
            return True
        return any(t in scopes for t in tenants)

    def _cache_interval(self, job: CacheJob, scopes: Optional[set] = None) -> float:
        return ACTIVE_INTERVAL_S if self._cache_is_active(job.tenants, scopes) else IDLE_INTERVAL_S

    def cache_kick_tenant(self, tenant_id: Optional[str]) -> None:
        """Login hook: refresh everything this tenant (None → admin) can see on
        the next refresher tick, so the pages they open are current."""
        now = time.time()
        scope = tenant_id or ALL_SCOPE
        self._cache_kicked[scope] = now
        if tenant_id:
            self._cache_recent_tenant[tenant_id] = now
        if self._cache_wake is not None:
            self._cache_wake.set()

    # ── feeds + refresher ────────────────────────────────────────────────────

    def cache_register_feed(self, name: str, fn: Callable[[Any], Iterable[CacheJob]]) -> None:
        """Register a feed: ``fn(hub)`` yields the ``CacheJob``s that must
        always be warm (called every tick — keep it cheap, no I/O)."""
        self._cache_feeds[name] = fn

    def _cache_collect_jobs(self) -> List[CacheJob]:
        jobs: Dict[Tuple[str, str], CacheJob] = {}
        for name, fn in list(self._cache_feeds.items()):
            try:
                for j in fn(self) or ():
                    j.key = str(j.key)
                    j.tenants = _norm_tenants(j.tenants)
                    j.from_feed = True
                    j.lane = j.lane or j.ns
                    j._jitter = _jitter_for(j.ns, j.key)
                    jobs[(j.ns, j.key)] = j
            except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the rest
                logger.warning("hub cache: feed %s failed: %s", name, exc)
        for k, j in self._cache_read_jobs.items():
            jobs.setdefault(k, j)
        return list(jobs.values())

    def _cache_kicked_at(self, job: CacheJob) -> float:
        """Latest login kick relevant to this job. Shared data (tenants None)
        is kicked by any login; tenant data only by a login of one of its
        tenants (an admin login kicks ``ALL_SCOPE`` + the admin tenant — it
        does NOT force-refresh every tenant in the fleet)."""
        if job.tenants is None:
            return max(self._cache_kicked.values(), default=0.0)
        return max((self._cache_kicked.get(t, 0.0) for t in job.tenants), default=0.0)

    def _cache_job_due(self, job: CacheJob, now: float, scopes: set) -> bool:
        k = (job.ns, job.key)
        task = self._cache_inflight.get(k)
        if task is not None and not task.done():
            return False
        active = self._cache_is_active(job.tenants, scopes)
        if not job.from_feed and not active:
            return False   # read-only scopes refresh only while someone is looking
        entry = self.warm_cache.get(job.ns, {}).get(job.key)
        fetched = (entry or {}).get("fetched_at") or 0
        kicked = self._cache_kicked_at(job)
        if kicked > fetched and kicked > ((entry or {}).get("error_at") or 0):
            return True
        if not fetched and not (entry or {}).get("error_at"):
            return True
        interval = ACTIVE_INTERVAL_S if active else IDLE_INTERVAL_S
        last_try = max(fetched, (entry or {}).get("error_at") or 0)
        return now - last_try >= interval + job._jitter

    async def cache_refresh_tick(self) -> int:
        """One refresher pass. Returns the number of refreshes started."""
        now = time.time()
        self._cache_last_tick = now
        scopes = self._cache_active_scopes()
        started = 0
        for job in self._cache_collect_jobs():
            if self._cache_job_due(job, now, scopes):
                self._cache_spawn(job)
                started += 1
        if now - self._cache_last_evict >= EVICT_EVERY_S:
            self._cache_last_evict = now
            self.cache_evict_idle(now)
        return started

    def cache_evict_idle(self, now: Optional[float] = None) -> int:
        """Drop non-feed entries nobody has read for ``DETAIL_EVICT_S``."""
        now = now or time.time()
        feed_keys = {(j.ns, j.key) for j in self._cache_collect_jobs() if j.from_feed}
        n = 0
        for ns, entries in self.warm_cache.items():
            for k in list(entries):
                e = entries[k]
                if (ns, k) in feed_keys or not isinstance(e, dict) or not e.get("detail"):
                    continue
                last = e.get("read_at") or e.get("fetched_at") or e.get("stale_from") or 0
                if now - last >= DETAIL_EVICT_S:
                    del entries[k]
                    self._cache_read_jobs.pop((ns, k), None)
                    self._warm_cache_file.schedule_save(ns)
                    n += 1
        return n

    async def run_cache_refresher_loop(self) -> None:
        """Background loop: refresh due entries every ``TICK_S`` (or right away
        after a login kick)."""
        self._cache_wake = asyncio.Event()
        logger.info("hub cache: refresher started (%d feed(s))", len(self._cache_feeds))
        while True:
            try:
                await self.cache_refresh_tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                logger.warning("hub cache: refresher tick failed: %s", exc)
            try:
                await asyncio.wait_for(self._cache_wake.wait(), TICK_S)
            except asyncio.TimeoutError:
                pass
            self._cache_wake.clear()

    # ── write path / admin actions ───────────────────────────────────────────

    def cache_refresh(self, ns: str, key_prefixes: tuple = ("",), *,
                      exact: bool = False) -> int:
        """After a write: invalidate ``ns`` entries (exact namespace) whose key
        starts with any of ``key_prefixes`` (or equals one, with ``exact``)
        and refresh them NOW. Readers in the next few seconds wait for the new
        data. Returns refreshes started."""
        def match(k: str) -> bool:
            return k in key_prefixes if exact else k.startswith(tuple(key_prefixes))

        entries = self.warm_cache.get(ns) or {}
        for k, e in entries.items():
            if match(k) and isinstance(e, dict) and e.get("fetched_at"):
                e["stale_from"] = e["fetched_at"]
                e["fetched_at"] = 0
        n = 0
        for job in self._cache_collect_jobs():
            if job.ns == ns and match(job.key):
                try:
                    self._cache_spawn(job)
                    n += 1
                except RuntimeError:  # no running loop (sync caller at startup)
                    break
        return n

    async def cache_wait_idle(self, timeout: float = 15.0) -> bool:
        """Wait (up to ``timeout``) for the fetches running right now to finish
        — e.g. a "refresh" button that reloads the page afterwards. Returns
        True when everything finished in time."""
        tasks = [t for t in self._cache_inflight.values() if not t.done()]
        if not tasks:
            return True
        _done, pending = await asyncio.wait(tasks, timeout=timeout)
        return not pending

    def cache_purge(self, tenant_id: Optional[str] = None) -> int:
        """Drop cached data (all of it, or everything visible to one tenant)
        and refresh it. Returns entries dropped."""
        n = 0
        for ns, entries in self.warm_cache.items():
            hit = False
            for k in list(entries):
                e = entries[k]
                if tenant_id is None or tenant_id in ((e or {}).get("tenants") or ()):
                    del entries[k]
                    n += 1
                    hit = True
            if hit:
                self._warm_cache_file.schedule_save(ns)
        self.cache_kick_tenant(tenant_id)
        return n

    def cache_status(self) -> Dict[str, Any]:
        """Read-only snapshot for the admin Cache page."""
        now = time.time()
        scopes = self._cache_active_scopes()
        jobs = {(j.ns, j.key): j for j in self._cache_collect_jobs()}
        f = self._warm_cache_file
        namespaces = []
        for ns in sorted(set(self.warm_cache) | {k[0] for k in jobs}):
            rows = []
            for key in sorted(set(self.warm_cache.get(ns, {})) | {k[1] for k in jobs if k[0] == ns}):
                j = jobs.get((ns, key))
                m = self.cache_meta(ns, key)
                task = self._cache_inflight.get((ns, key))
                rows.append({
                    "key": key,
                    "age": round(m["age"], 1) if m["age"] is not None else None,
                    "stale": m["stale"],
                    "error": m["error"],
                    "cached": key in self.warm_cache.get(ns, {}),
                    "refreshing": bool(task is not None and not task.done()),
                    "feed": bool(j and j.from_feed),
                    "active": bool(j and self._cache_is_active(j.tenants, scopes)),
                    "tenants": list(j.tenants) if j and j.tenants else None,
                })
            namespaces.append({
                "namespace": ns, "entries": rows,
                "file_bytes": f.last_size.get(ns),
                "written_at": f.last_write_at.get(ns),
            })
        return {
            "now": now,
            "intervals": {"active_s": ACTIVE_INTERVAL_S, "idle_s": IDLE_INTERVAL_S,
                          "stale_after_s": STALE_AFTER_S, "tick_s": TICK_S},
            "active_scopes": sorted(scopes),
            "last_tick": self._cache_last_tick or None,
            "encrypted": f.encrypt is not None,
            "feeds": sorted(self._cache_feeds),
            "namespaces": namespaces,
        }
