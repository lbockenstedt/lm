"""In-memory + JSON-persisted cache for the Certificates (le) module.

Mirrors ``nw_cache.NwCacheMixin`` exactly (cache the raw spoke envelope, serve
it — marked stale — when the le spoke is offline or a live fetch overruns,
refresh on every live fetch) so the Certificates page renders instantly from
last-known data instead of blocking on a live LE_LIST_CERTS round-trip or
503-ing until the le spoke reconnects.

Warm start: persisted to ``<cache_dir>/le_certs.json`` (atomic tmp +
``os.replace``, ``asyncio.Lock``-guarded, written off the event loop) and
reloaded on startup via ``le_cache_load``. The cert-distribution loop refreshes
it every cycle, so the on-disk snapshot is superseded by the next poll.

A leaf: stdlib only. MUST NOT import ``main``/``api`` (direction is
``main → le_cache`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


class LeCacheMixin:
    """Last-known Certificates data (cert list + status) for warm serve."""

    LE_CACHE_FILE = "le_certs.json"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def le_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        self.le_cache: Dict[str, Any] = {}
        self._le_cache_lock = asyncio.Lock()
        self._le_cache_save_tasks: set = set()

    def _le_cache_path(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.LE_CACHE_FILE)

    def le_cache_load(self) -> None:
        """Rehydrate the cache from disk on startup (best-effort). Missing/corrupt
        file → cache stays empty (the first live fetch repopulates)."""
        try:
            path = self._le_cache_path()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return
            with open(path) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self.le_cache = {str(k): v for k, v in data.items()}
                logger.info("le cache: restored %d key(s) from %s",
                            len(self.le_cache), path)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("le cache load failed (%s): %s — starting empty",
                           self._le_cache_path(), exc)

    # ── read/write ─────────────────────────────────────────────────────────────

    def le_cache_get(self, key: str) -> Optional[Any]:
        """Last-known raw envelope for ``key`` (e.g. 'certs'/'status'), or None."""
        v = self.le_cache.get(key)
        return v.get("data") if isinstance(v, dict) and "data" in v else None

    async def le_cache_set(self, key: str, data: Any) -> None:
        """Store a fresh envelope for ``key`` + persist (best-effort)."""
        self.le_cache[key] = {"data": data, "fetched_at": time.time()}
        self._le_cache_schedule_save()

    # ── persist (mirrors nw_cache) ──────────────────────────────────────────────

    def _le_cache_schedule_save(self) -> None:
        try:
            task = asyncio.create_task(self._le_cache_persist())
            self._le_cache_save_tasks.add(task)
            task.add_done_callback(self._le_cache_save_tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (sync init)
            logger.debug("le cache: skipping async persist (no running loop)")

    async def _le_cache_persist(self) -> None:
        async with self._le_cache_lock:
            try:
                await asyncio.to_thread(self._le_cache_write, dict(self.le_cache))
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("le cache persist failed: %s", exc)

    def _le_cache_write(self, snapshot: Dict[str, Any]) -> None:
        path = self._le_cache_path()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.chmod(tmp, 0o600)  # cert domains/targets — match the 0600 at-rest policy
        os.replace(tmp, path)
