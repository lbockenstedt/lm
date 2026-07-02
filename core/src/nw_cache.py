"""In-memory + JSON-persisted cache for the Network Devices (nw) module.

Mirrors the firewall tenant-cache pattern (cache the raw spoke result, serve
from cache when the spoke is offline, refresh on live fetch) AND adds atomic
JSON persistence so a hub restart seeds the Network Devices UI from the
last-known data instead of 503-ing until the nw spoke reconnects.

Cache shape (all values are the *raw unwrapped spoke envelopes*
``{"status":"SUCCESS","data":...}`` so the tenant subnet filter
``access.filter_nw`` can be re-applied per-reader from the same cached raw,
exactly like ``_filter_fw`` over the firewall cache)::

  fleet   -> {"devices": <NW_LIST_DEVICES envelope>, "fetched_at": epoch}
  devices -> {device_id: {
      "info":       <NW_GET_DEVICE_INFO envelope>,
      "macs":       <NW_GET_MAC_TABLE envelope>,
      "arp":        <NW_GET_ARP envelope>,
      "interfaces": <NW_GET_INTERFACES envelope>,
      "poll":       <last POLL NOW result>,        # rich probe+interfaces+arp+mac
      "fetched_at": epoch,                          # most recent per-device write
  }}

Persisted to ``<data_dir>/cache/nw_data.json`` (atomic tmp + ``os.replace``,
best-effort, ``asyncio.Lock``-guarded, written off the event loop via
``asyncio.to_thread``). Loaded on startup via ``nw_cache_load`` so the UI is
seeded immediately; subsequent live fetches refresh + re-persist.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction
is ``main → nw_cache`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("Hub")


class NwCacheMixin:
    """In-memory + JSON-persisted cache for the Network Devices (nw) module.

    The cache holds the last-known fleet list + per-device endpoint data so the
    WebUI Network Devices page can render last-known data when the nw spoke is
    offline (or before it reconnects after a hub restart) instead of 503-ing.
    Live fetches refresh the cache; the cache is persisted atomically to
    ``cache/nw_data.json`` and reloaded on startup to seed the UI.
    """

    NW_CACHE_FILE = "nw_data.json"
    _NW_CACHE_ENDPOINTS = ("info", "macs", "arp", "interfaces")

    # ── lifecycle ────────────────────────────────────────────────────────────

    def nw_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        self.nw_fleet_cache: Dict[str, Any] = {}
        self.nw_device_cache: Dict[str, Dict[str, Any]] = {}
        self._nw_cache_lock = asyncio.Lock()
        self._nw_cache_save_tasks: set = set()

    def _nw_cache_path(self) -> str:
        return os.path.join(getattr(self, "cache_dir", "."), self.NW_CACHE_FILE)

    def nw_cache_load(self) -> None:
        """Rehydrate the in-memory cache from disk on startup (best-effort).

        Missing/corrupt file → leaves the cache empty (cold-start behavior):
        the UI 503s once, then the first live fetch populates + persists.
        """
        try:
            path = self._nw_cache_path()
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                return
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return
            fleet = data.get("fleet")
            if isinstance(fleet, dict):
                self.nw_fleet_cache = {
                    "devices": fleet.get("devices"),
                    "fetched_at": float(fleet.get("fetched_at", 0.0) or 0.0),
                }
            devices = data.get("devices")
            if isinstance(devices, dict):
                self.nw_device_cache = {
                    str(did): dict(v) for did, v in devices.items()
                    if isinstance(v, dict)
                }
            if self.nw_fleet_cache or self.nw_device_cache:
                logger.info("nw cache: restored %d device(s) + fleet snapshot from %s",
                            len(self.nw_device_cache), path)
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("nw cache load failed (%s): %s — starting empty",
                           self._nw_cache_path(), exc)

    # ── read ──────────────────────────────────────────────────────────────────

    def nw_cache_get_fleet(self) -> Optional[Dict[str, Any]]:
        """Last-known fleet envelope + ``fetched_at``, or None if never cached."""
        f = self.nw_fleet_cache
        if not f or f.get("devices") is None:
            return None
        return f

    def nw_cache_get_device(self, device_id: str, endpoint: str) -> Optional[Any]:
        """Last-known raw envelope for one device endpoint, or None."""
        entry = self.nw_device_cache.get(device_id)
        if not entry:
            return None
        val = entry.get(endpoint)
        return val if val is not None else None

    # ── write ─────────────────────────────────────────────────────────────────

    async def nw_cache_set_fleet(self, data: Any) -> None:
        """Store a fresh NW_LIST_DEVICES envelope + persist (best-effort)."""
        self.nw_fleet_cache = {"devices": data, "fetched_at": time.time()}
        self._nw_cache_schedule_save()

    async def nw_cache_set_device(self, device_id: str, endpoint: str,
                                  data: Any) -> None:
        """Store a fresh per-device endpoint envelope + persist (best-effort)."""
        if endpoint not in self._NW_CACHE_ENDPOINTS and endpoint != "poll":
            return
        entry = self.nw_device_cache.setdefault(device_id, {})
        entry[endpoint] = data
        entry["fetched_at"] = time.time()
        self._nw_cache_schedule_save()

    async def nw_cache_set_poll(self, device_id: str, poll_result: Dict[str, Any]
                                ) -> None:
        """Fold a POLL NOW result into the per-device cache + persist.

        The poll carries device_info / interfaces / arp / mac_table alongside
        the reachability + NetBox-push summary; threading it into the cache
        means a later page load (spoke offline) still reflects the last poll.
        """
        if not isinstance(poll_result, dict):
            return
        entry = self.nw_device_cache.setdefault(device_id, {})
        entry["poll"] = poll_result
        # Best-effort: mirror the poll's sub-resources into the endpoint slots
        # so /api/nw/{id}/{info|arp|macs|interfaces} also serves the poll data
        # when the spoke is down. Wrapped in the standard SUCCESS envelope so
        # the unwrapping/contract the routes expect is preserved.
        info = poll_result.get("device_info")
        if isinstance(info, dict) and info:
            entry["info"] = {"status": "SUCCESS", "data": info}
        arp = poll_result.get("arp")
        if isinstance(arp, list):
            entry["arp"] = {"status": "SUCCESS", "data": arp}
        macs = poll_result.get("mac_table")
        if isinstance(macs, list):
            entry["macs"] = {"status": "SUCCESS", "data": macs}
        ifaces = poll_result.get("interfaces")
        if isinstance(ifaces, list):
            entry["interfaces"] = {"status": "SUCCESS", "data": ifaces}
        entry["fetched_at"] = time.time()
        self._nw_cache_schedule_save()

    # ── persist ───────────────────────────────────────────────────────────────

    def _nw_cache_schedule_save(self) -> None:
        """Fire-and-forget an atomic persist (coalesced under the lock)."""
        try:
            task = asyncio.create_task(self._nw_cache_persist())
            self._nw_cache_save_tasks.add(task)
            task.add_done_callback(self._nw_cache_save_tasks.discard)
        except RuntimeError:  # pragma: no cover - no running loop (startup path)
            # Called outside an event loop (e.g. a sync init test) — skip the
            # async persist; the next live fetch under a loop will persist.
            logger.debug("nw cache: skipping async persist (no running loop)")

    async def _nw_cache_persist(self) -> None:
        """Serialize the cache off the event loop + atomically replace the file."""
        async with self._nw_cache_lock:
            snapshot = {
                "fleet": self.nw_fleet_cache,
                "devices": self.nw_device_cache,
            }
            try:
                await asyncio.to_thread(self._nw_cache_write, snapshot)
            except Exception as exc:  # noqa: BLE001 - best-effort persist
                logger.warning("nw cache persist failed: %s", exc)

    def _nw_cache_write(self, snapshot: Dict[str, Any]) -> None:
        """Synchronous atomic write (runs in a worker thread)."""
        path = self._nw_cache_path()
        d = os.path.dirname(path)
        if d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snapshot, f, default=str)
        os.replace(tmp, path)