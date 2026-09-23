"""The ONE shared cache implementation: atomic JSON persistence + staleness timers.

``nw_cache``, ``truenas_cache``, ``le_cache`` and ``warm_cache`` each grew their
own copy of the same "keep the last spoke answer, serve it when the spoke is
down, persist it so a hub restart isn't a cold start" logic. Four copies drifted:
two debounce their writes and two re-serialize the whole file on every single
set; only the console page ever aged its entries out. This module is the single
implementation they delegate to, so "this needs to be cached" means one
behaviour everywhere instead of whichever copy was pasted.

THE THREE THRESHOLDS ARE SEPARATE ON PURPOSE. One timer cannot express the rule
we actually want, which is "a brief outage must not become a user-visible
error":

  * ``refresh_after_s`` (30s)  — old enough to revalidate in the BACKGROUND. The
    reader still gets the cached value immediately; nothing is blocked.
  * ``stale_after_s`` (120s)   — old enough to admit it. Still served, now with
    the "cached data" badge. This is the window that covers a spoke restarting
    during a hub/agent update: it is offline for far less than this, so the
    Hypervisor/Diagnostics pages keep rendering last-known data instead of
    replacing the page with "Timed out waiting for spoke response".
  * ``expire_after_s`` (24h)   — old enough that serving it would be a lie. This
    is the ONLY state permitted to surface an error, because only now is the
    error the honest answer rather than an artifact of a 20-second restart.

CACHE THE RAW ENVELOPE, NEVER THE FILTERED VIEW. Every value stored here must be
the raw pre-tenant-filter spoke envelope, so each reader's tenant/subnet filter
is re-applied from that raw on every read. Caching a filtered result would let
whoever warmed the entry decide what the NEXT reader sees — i.e. hand one
tenant another tenant's rows.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction is
``main → cache_core`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional, Set

logger = logging.getLogger("Hub")

DEFAULT_FLUSH_DELAY_S = 5.0
DEFAULT_REFRESH_AFTER_S = 30.0
DEFAULT_STALE_AFTER_S = 120.0
DEFAULT_EXPIRE_AFTER_S = 86400.0


FRESH = "fresh"
REFRESH = "refresh"
STALE = "stale"
EXPIRED = "expired"
MISSING = "missing"


class JsonCacheFile:
    """
    Manages atomic JSON persistence of cache data.

    Owns NO cache data; it only persists whatever the owner hands it.
    """

    def __init__(
        self,
        label: str,
        path_fn: Callable[[], str],
        snapshot_fn: Callable[[], Dict[str, Any]],
        *,
        flush_delay_s: float = DEFAULT_FLUSH_DELAY_S
    ) -> None:
        """
        Initialize a JsonCacheFile.

        :param label: Used in log messages (e.g. "nw cache")
        :param path_fn: Callable returning the absolute file path (deferred)
        :param snapshot_fn: Callable returning dict to serialize at write time
        :param flush_delay_s: Debounce delay for writes
        """
        self._label = label
        self._path_fn = path_fn
        self._snapshot_fn = snapshot_fn
        self._flush_delay_s = flush_delay_s

        self._lock: Optional[asyncio.Lock] = None
        self._lock_loop: Any = None
        self._tasks: Set[asyncio.Task] = set()
        self._dirty = False

    def _get_lock(self) -> asyncio.Lock:
        """A lock bound to the RUNNING loop, created on first use.

        These cache objects are constructed in a synchronous ``__init__`` during
        hub startup — before any event loop exists. On Python < 3.10
        ``asyncio.Lock()`` captures a loop at construction time, and a lock
        captured from the wrong loop raises "got Future attached to a different
        loop" the first time two writers genuinely contend. That is exactly the
        poll-burst case this class exists to serialize, so it would fail only
        under load. Binding lazily keeps the behaviour identical across
        interpreter versions.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._lock is None or self._lock_loop is not loop:
            self._lock = asyncio.Lock()
            self._lock_loop = loop
        return self._lock

    def load(self) -> Optional[Dict[str, Any]]:
        """
        Load cache from disk.

        Returns parsed dict or None if file is missing/empty/not a dict.
        Catches all expected exceptions and logs at WARNING.
        Never raises.
        """
        path = ""
        try:
            path = self._path_fn()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return None
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return None
            return data
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("%s load failed (%s): %s — starting empty", self._label, path, exc)
            return None

    def schedule_save(self) -> None:
        """
        Schedule a save with debounce.

        Ensures exactly one flusher is pending. If one already exists,
        it will pick up the change.
        """
        self._dirty = True
        if any(not t.done() for t in self._tasks):
            return  # a flusher is already pending — it will pick this up

        coro = self._flush_after_delay()
        try:
            task = asyncio.create_task(coro)
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (startup path)
            # Close the coroutine we just built, or Python warns "coroutine was
            # never awaited" on every startup-path set.
            coro.close()
            logger.debug("%s: skipping async persist (no running loop)", self._label)

    async def flush_now(self) -> None:
        """
        Immediately persist, skipping debounce.

        Used during shutdown or forced sync.
        """
        self._dirty = False
        await self._persist()

    async def _flush_after_delay(self) -> None:
        while self._dirty:
            self._dirty = False
            await asyncio.sleep(self._flush_delay_s)
            await self._persist()

    async def _persist(self) -> None:
        """
        Persist the current snapshot to disk.

        Locks, calls snapshot_fn(), writes via asyncio.to_thread.
        Logs WARNING on failure (best-effort).
        """
        async with self._get_lock():
            try:
                snapshot = self._snapshot_fn()
                await asyncio.to_thread(self._write, snapshot)
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("%s persist failed: %s", self._label, exc)

    def _write(self, snapshot: Dict[str, Any]) -> None:
        """
        Write snapshot atomically to disk.

        Creates parent dir, writes to tmp file with json.dump(..., default=str),
        chmod 0o600, then os.replace(tmp, path).
        """
        path = self._path_fn()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)


class StalenessPolicy:
    """
    Pure staleness classifier for cached data.

    Fully synchronous and testable. No I/O.
    """

    def __init__(
        self,
        *,
        refresh_after_s: float = DEFAULT_REFRESH_AFTER_S,
        stale_after_s: float = DEFAULT_STALE_AFTER_S,
        expire_after_s: float = DEFAULT_EXPIRE_AFTER_S
    ) -> None:
        """
        Initialize a staleness policy.

        :param refresh_after_s: Age after which data should be refreshed in background
        :param stale_after_s: Age after which data is "cached" but still usable
        :param expire_after_s: Age after which data is no longer trustworthy
        """
        self.refresh_after_s = refresh_after_s
        self.stale_after_s = stale_after_s
        self.expire_after_s = expire_after_s

    def age(self, fetched_at: Optional[float], now: Optional[float] = None) -> Optional[float]:
        """
        Compute the age of data in seconds.

        Returns None if fetched_at is invalid.
        Clamps at 0.0 to prevent negative ages from clock skew.
        """
        if not fetched_at or not isinstance(fetched_at, (int, float)):
            return None
        if now is None:
            now = time.time()
        return max(0.0, now - fetched_at)

    def classify(self, fetched_at: Optional[float], now: Optional[float] = None) -> str:
        """
        Classify the staleness of data.

        Returns one of FRESH, REFRESH, STALE, EXPIRED, MISSING.
        Checked in order of severity.
        """
        a = self.age(fetched_at, now)
        if a is None:
            return MISSING
        if a > self.expire_after_s:
            return EXPIRED
        if a > self.stale_after_s:
            return STALE
        if a > self.refresh_after_s:
            return REFRESH
        return FRESH

    def should_refresh(self, fetched_at, now=None) -> bool:
        """
        Should data be refreshed in background?

        True for MISSING, REFRESH, STALE and EXPIRED.
        """
        return self.classify(fetched_at, now) != FRESH

    def is_stale(self, fetched_at, now=None) -> bool:
        """
        Is data stale (should be shown with badge)?

        True for STALE and EXPIRED.
        """
        c = self.classify(fetched_at, now)
        return c in (STALE, EXPIRED)

    def is_expired(self, fetched_at, now=None) -> bool:
        """
        Is data expired (should surface an error)?

        True only for EXPIRED.
        """
        return self.classify(fetched_at, now) == EXPIRED

    def is_usable(self, fetched_at, now=None) -> bool:
        """
        Is data still usable?

        True for anything except MISSING and EXPIRED.
        """
        c = self.classify(fetched_at, now)
        return c not in (MISSING, EXPIRED)
