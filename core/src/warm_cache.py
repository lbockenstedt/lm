"""Generic in-memory + JSON-persisted warm cache for read-heavy spoke pages.

Same pattern as ``nw_cache`` / ``le_cache`` but namespaced so several modules
(NetBox/IPAM, NAC/CPPM, Directory/LDAP) can share one store: the last-known raw
spoke envelope is kept in memory, persisted atomically to
``<cache_dir>/warm_cache.json``, and warm-loaded on startup. A read handler
caches every successful live fetch and serves the last-known value (marked
``stale``) when the spoke is offline or a live fetch overruns — so the page
renders instantly instead of blocking/503-ing, and survives a hub restart.

Values are the *raw unwrapped spoke envelopes* so any per-reader tenant/subnet
filter is re-applied from the cached raw (never cache post-filter data).

Keys: ``(namespace, key)`` — ``namespace`` is the logical dataset
(e.g. ``"netbox_devices"``), ``key`` is the scope within it (tenant slug, or
``"_all_"`` for an admin all-tenants read) so tenant isolation is preserved.

Persistence and the staleness timers are NOT implemented here: they come from
``cache_core`` so every cache in the hub ages out and writes identically. This
module used to re-serialize the whole file on every single ``warm_set`` — a
poll burst of N spokes meant N full-file dumps — while ``nw_cache`` coalesced
them. Delegating to ``cache_core.JsonCacheFile`` removes that difference.

A leaf: stdlib only. MUST NOT import ``main``/``api``. Audience: Hub developers.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, Optional

from cache_core import JsonCacheFile, StalenessPolicy

logger = logging.getLogger("Hub")


class WarmCacheMixin:
    """Namespaced last-known-data cache with atomic JSON persistence."""

    WARM_CACHE_FILE = "warm_cache.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def warm_cache_init(self) -> None:
        """Initialize the in-memory store. Call once from ``__init__``."""
        self.warm_cache: Dict[str, Dict[str, Any]] = {}
        self.warm_policy = StalenessPolicy()
        self._warm_cache_file = JsonCacheFile(
            "warm cache", self._warm_cache_path,
            lambda: {ns: dict(e) for ns, e in self.warm_cache.items()})

    def _warm_cache_path(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.WARM_CACHE_FILE)

    def warm_cache_load(self) -> None:
        """Rehydrate from disk on startup (best-effort; missing/corrupt → empty)."""
        data = self._warm_cache_file.load()
        if not isinstance(data, dict):
            return
        self.warm_cache = {
            str(ns): {str(k): v for k, v in (entries or {}).items()}
            for ns, entries in data.items() if isinstance(entries, dict)
        }
        total = sum(len(e) for e in self.warm_cache.values())
        logger.info("warm cache: restored %d namespace(s) / %d key(s) from %s",
                    len(self.warm_cache), total, self._warm_cache_path())

    # ── read/write ─────────────────────────────────────────────────────────────

    def warm_get(self, namespace: str, key: str = "_") -> Optional[Any]:
        """Last-known raw envelope for ``(namespace, key)``, or None."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) and "data" in entry else None

    def warm_fetched_at(self, namespace: str, key: str = "_") -> Optional[float]:
        """Epoch seconds when ``(namespace, key)`` was last stored, or None.

        Lets a read handler decide a cache entry is aging and schedule a
        background refresh instead of re-polling the spoke on every request."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        ts = entry.get("fetched_at") if isinstance(entry, dict) else None
        return ts if isinstance(ts, (int, float)) else None

    def warm_state(self, namespace: str, key: str = "_",
                   policy: Optional[StalenessPolicy] = None) -> str:
        """Shared staleness verdict for one entry — ``cache_core`` vocabulary
        (``fresh``/``refresh``/``stale``/``expired``/``missing``).

        Route handlers use this instead of open-coding an age comparison, so
        "when do we badge it" and "when may we finally error" are one rule for
        every module rather than per-page guesswork."""
        return (policy or self.warm_policy).classify(
            self.warm_fetched_at(namespace, key))

    async def warm_set(self, namespace: str, key: str, data: Any) -> None:
        """Store a fresh envelope for ``(namespace, key)`` + persist (best-effort)."""
        self.warm_cache.setdefault(namespace, {})[str(key)] = {
            "data": data, "fetched_at": time.time()}
        self._warm_cache_file.schedule_save()

    async def warm_cache_flush_now(self) -> None:
        """Immediate persist (shutdown path) — skips the coalescing delay."""
        await self._warm_cache_file.flush_now()
