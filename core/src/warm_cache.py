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

A leaf: stdlib only. MUST NOT import ``main``/``api``. Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


class WarmCacheMixin:
    """Namespaced last-known-data cache with atomic JSON persistence."""

    WARM_CACHE_FILE = "warm_cache.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def warm_cache_init(self) -> None:
        """Initialize the in-memory store. Call once from ``__init__``."""
        self.warm_cache: Dict[str, Dict[str, Any]] = {}
        self._warm_cache_lock = asyncio.Lock()
        self._warm_cache_tasks: set = set()

    def _warm_cache_path(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.WARM_CACHE_FILE)

    def warm_cache_load(self) -> None:
        """Rehydrate from disk on startup (best-effort; missing/corrupt → empty)."""
        try:
            path = self._warm_cache_path()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.warm_cache = {
                    str(ns): {str(k): v for k, v in (entries or {}).items()}
                    for ns, entries in data.items() if isinstance(entries, dict)
                }
                total = sum(len(e) for e in self.warm_cache.values())
                logger.info("warm cache: restored %d namespace(s) / %d key(s) from %s",
                            len(self.warm_cache), total, path)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("warm cache load failed (%s): %s — starting empty",
                           self._warm_cache_path(), exc)

    # ── read/write ─────────────────────────────────────────────────────────────

    def warm_get(self, namespace: str, key: str = "_") -> Optional[Any]:
        """Last-known raw envelope for ``(namespace, key)``, or None."""
        entry = self.warm_cache.get(namespace, {}).get(str(key))
        return entry.get("data") if isinstance(entry, dict) and "data" in entry else None

    async def warm_set(self, namespace: str, key: str, data: Any) -> None:
        """Store a fresh envelope for ``(namespace, key)`` + persist (best-effort)."""
        self.warm_cache.setdefault(namespace, {})[str(key)] = {
            "data": data, "fetched_at": time.time()}
        self._warm_cache_schedule_save()

    # ── persist (mirrors nw_cache) ──────────────────────────────────────────────

    def _warm_cache_schedule_save(self) -> None:
        try:
            task = asyncio.create_task(self._warm_cache_persist())
            self._warm_cache_tasks.add(task)
            task.add_done_callback(self._warm_cache_tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (sync init)
            logger.debug("warm cache: skipping async persist (no running loop)")

    async def _warm_cache_persist(self) -> None:
        async with self._warm_cache_lock:
            try:
                snapshot = {ns: dict(e) for ns, e in self.warm_cache.items()}
                await asyncio.to_thread(self._warm_cache_write, snapshot)
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("warm cache persist failed: %s", exc)

    def _warm_cache_write(self, snapshot: Dict[str, Any]) -> None:
        path = self._warm_cache_path()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.chmod(tmp, 0o600)  # can hold device/user identifiers — 0600 at-rest policy
        os.replace(tmp, path)
