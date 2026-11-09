"""In-memory + JSON-persisted cache for the TrueNAS (storage) module.

Mirrors the nw cache twin (cache the raw spoke result, serve from cache when
the spoke is offline, refresh on live fetch) + atomic JSON persistence so a
hub restart seeds the Storage UI from last-known data instead of 503-ing
until the truenas spoke reconnects.

Cache shape (all values are the *raw unwrapped spoke envelopes*
``{"status":"SUCCESS","data":...}`` so the tenant filter can be re-applied
per-reader from the same cached raw, exactly like ``nw_cache``)::

  fleet       -> {"appliances": <TRUENAS_LIST_APPLIANCES envelope>, "fetched_at": epoch}
  appliances  -> {appliance_id: {
      "info":       <TRUENAS_PROBE envelope>,
      "pools":      <TRUENAS_GET_POOLS envelope>,
      "datasets":   <TRUENAS_GET_DATASETS envelope>,
      "disks":      <TRUENAS_GET_DISKS envelope>,
      "shares":     <TRUENAS_GET_SHARES envelope>,
      "alerts":     <TRUENAS_GET_ALERTS envelope>,
      "services":   <TRUENAS_GET_SERVICES envelope>,
      "capacity":   <TRUENAS_GET_CAPACITY envelope>,
      "performance": <TRUENAS_GET_PERFORMANCE envelope>,
      "poll":       <last TRUENAS_POLL result>,        # rich envelope
      "fetched_at": epoch,                              # most recent per-appliance write
  }}

Persisted to ``<data_dir>/cache/truenas_data.json`` (atomic tmp + ``os.replace``,
best-effort, ``asyncio.Lock``-guarded, written off the event loop via
``asyncio.to_thread``). Loaded on startup via ``truenas_cache_load`` so the UI
is seeded immediately; subsequent live fetches refresh + re-persist.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction
is ``main → truenas_cache`` only). Audience: Hub developers. Mirrors nw_cache.py.
"""

from __future__ import annotations

# logging; os for paths; time for fetched_at stamps; type hints.
import logging
import os
import time
from typing import Any, Dict, Optional

# Shared JSON cache-file persistence and staleness policy.
from cache_core import JsonCacheFile, StalenessPolicy

# Log to the hub's logger.
logger = logging.getLogger("Hub")


class TruenasCacheMixin:
    """In-memory + JSON-persisted cache for the TrueNAS (storage) module.

    The cache holds the last-known fleet list + per-appliance data so the
    WebUI Storage page renders last-known data when the truenas spoke is
    offline (or before it reconnects after a hub restart) instead of 503-ing.
    Live fetches refresh the cache; the cache is persisted atomically to
    ``cache/truenas_data.json`` and reloaded on startup to seed the UI.
    """

    # Cache file name and the per-appliance endpoints that may be cached.
    TRUENAS_CACHE_FILE = "truenas_data.json"
    _TRUENAS_CACHE_ENDPOINTS = ("info", "pools", "datasets", "disks", "shares",
                                "alerts", "services", "capacity", "performance")

    # ── lifecycle ────────────────────────────────────────────────────────────

    def truenas_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        # Empty fleet and per-appliance caches, plus a staleness policy.
        self.truenas_fleet_cache: Dict[str, Any] = {}
        self.truenas_appliance_cache: Dict[str, Dict[str, Any]] = {}
        self.truenas_policy = StalenessPolicy()
        # Persistence: snapshot both caches, coalescing writes.
        self._truenas_cache_file = JsonCacheFile(
            "truenas cache", self._truenas_cache_path,
            lambda: {"fleet": self.truenas_fleet_cache,
                     "appliances": self.truenas_appliance_cache})

    def _truenas_cache_path(self) -> str:
        """Return the path of the TrueNAS cache file under cache_dir."""
        # cache_dir/truenas_data.json.
        return os.path.join(getattr(self, "cache_dir", "."), self.TRUENAS_CACHE_FILE)

    def truenas_cache_load(self) -> None:
        """Rehydrate the in-memory cache from disk on startup (best-effort).

        Missing/corrupt file → leaves the cache empty (cold-start behavior):
        the UI 503s once, then the first live fetch populates + persists.
        The read itself is ``cache_core``'s, so a truncated or non-JSON file
        degrades identically here and in every other module.
        """
        # Read the file; anything but a dict leaves the cache empty.
        data = self._truenas_cache_file.load()
        if not isinstance(data, dict):
            return
        # Restore the fleet snapshot.
        fleet = data.get("fleet")
        if isinstance(fleet, dict):
            self.truenas_fleet_cache = {
                "appliances": fleet.get("appliances"),
                "fetched_at": float(fleet.get("fetched_at", 0.0) or 0.0),
            }
        # Restore the per-appliance entries that are dicts.
        appliances = data.get("appliances")
        if isinstance(appliances, dict):
            self.truenas_appliance_cache = {
                str(aid): dict(v) for aid, v in appliances.items()
                if isinstance(v, dict)
            }
        # Log what was restored.
        if self.truenas_fleet_cache or self.truenas_appliance_cache:
            logger.info("truenas cache: restored %d appliance(s) + fleet snapshot from %s",
                        len(self.truenas_appliance_cache), self._truenas_cache_path())

    # ── read ──────────────────────────────────────────────────────────────────

    def truenas_cache_get_fleet(self) -> Optional[Dict[str, Any]]:
        """Last-known fleet envelope + ``fetched_at``, or None if never cached."""
        # Return the fleet entry only if it holds data.
        f = self.truenas_fleet_cache
        if not f or f.get("appliances") is None:
            return None
        return f

    def truenas_cache_get_fleet_filtered(self, predicate) -> Optional[Dict[str, Any]]:
        """Last-known fleet envelope with the appliance rows filtered by
        ``predicate(row)``, or None if never cached. Serves the offline-cache
        path of ``GET /api/truenas/appliances`` tenant-scoped: a non-admin
        reader must NOT see another tenant's appliances from the single global
        cache. Same shape as ``truenas_cache_get_fleet`` so the route serves the
        filtered snapshot exactly as the full one. Requires the cached rows to
        carry ``tenant_id`` so the predicate can decide visibility per row."""
        # Nothing cached: None.
        f = self.truenas_fleet_cache
        if not f or f.get("appliances") is None:
            return None
        # Filter the cached list down to rows the predicate allows.
        env = f["appliances"]
        data = env.get("data") if isinstance(env, dict) else None
        if isinstance(data, list):
            env = {**env, "data": [r for r in data
                                   if isinstance(r, dict) and predicate(r)]}
        # Same shape as the unfiltered fleet entry.
        return {"appliances": env, "fetched_at": f["fetched_at"]}

    def truenas_cache_get_appliance(self, appliance_id: str,
                                    endpoint: str) -> Optional[Any]:
        """Last-known raw envelope for one appliance endpoint, or None."""
        # Unknown appliance: None.
        entry = self.truenas_appliance_cache.get(appliance_id)
        if not entry:
            return None
        # The cached envelope for the endpoint, if any.
        val = entry.get(endpoint)
        return val if val is not None else None

    # ── write ─────────────────────────────────────────────────────────────────

    async def truenas_cache_set_fleet(self, data: Any) -> None:
        """Store a fresh TRUENAS_LIST_APPLIANCES envelope + persist."""
        # Replace the fleet entry and schedule a save.
        self.truenas_fleet_cache = {"appliances": data, "fetched_at": time.time()}
        self._truenas_cache_file.schedule_save()

    async def truenas_cache_set_appliance(self, appliance_id: str, endpoint: str,
                                          data: Any) -> None:
        """Store a fresh per-appliance endpoint envelope + persist."""
        # Ignore endpoints that are not cached.
        if endpoint not in self._TRUENAS_CACHE_ENDPOINTS and endpoint != "poll":
            return
        # Store the envelope, stamp it, and schedule a save.
        entry = self.truenas_appliance_cache.setdefault(appliance_id, {})
        entry[endpoint] = data
        entry["fetched_at"] = time.time()
        self._truenas_cache_file.schedule_save()

    async def truenas_cache_set_poll(self, appliance_id: str,
                                     poll_result: Dict[str, Any]) -> None:
        """Fold a TRUENAS_POLL result into the per-appliance cache + persist.

        The poll carries system_info/pools/datasets/disks/shares/alerts/
        services/capacity; threading it into the cache means a later page load
        (spoke offline) still reflects the last poll. Each sub-resource is
        mirrored into its endpoint slot, wrapped in a SUCCESS envelope so the
        routes' unwrapping contract is preserved."""
        # Ignore malformed results.
        if not isinstance(poll_result, dict):
            return
        # Keep the raw poll result.
        entry = self.truenas_appliance_cache.setdefault(appliance_id, {})
        entry["poll"] = poll_result
        # Accept the full envelope ({status, data, errors}) or the bare data dict.
        data = poll_result.get("data") if isinstance(poll_result.get("data"), dict) else poll_result
        # Parts that failed ("pools: ..." / "shares.smb: ...") keep their last good value.
        failed = {str(e).split(":", 1)[0].split(".", 1)[0]
                  for e in (poll_result.get("errors") or [])}
        for key in ("system_info", "pools", "datasets", "disks", "shares",
                    "alerts", "services", "capacity", "performance"):
            val = data.get(key)
            if val is None or key in failed:
                continue
            slot = "info" if key == "system_info" else key
            entry[slot] = {"status": "SUCCESS", "data": val}
        # Reachable = the appliance answered system.info on this poll.
        entry["reachable"] = bool(data.get("system_info")) and "system_info" not in failed
        entry["polled_at"] = time.time()
        # Stamp and schedule a save.
        entry["fetched_at"] = time.time()
        self._truenas_cache_file.schedule_save()
        # The appliance's hardware serial may now match a management controller's.
        if getattr(self, "state", None) is not None:
            import hw_serial_links
            hw_serial_links.refresh_hw_serial_links(self, min_interval_s=30.0)

    # ── persist ───────────────────────────────────────────────────────────────
    # Persistence itself lives in cache_core.JsonCacheFile — see nw_cache for
    # the same delegation; this module used to carry a verbatim copy of it.

    async def truenas_cache_flush_now(self) -> None:
        """Immediate persist (shutdown path) — skips the coalescing delay."""
        # Write now, skipping the delay.
        await self._truenas_cache_file.flush_now()

    # ── staleness ─────────────────────────────────────────────────────────────

    def truenas_cache_fleet_fetched_at(self) -> float:
        """Epoch of the last fleet-cache write (0.0 if never cached)."""
        # 0.0 when nothing is cached, else the stored timestamp.
        f = self.truenas_fleet_cache
        if not f or f.get("appliances") is None:
            return 0.0
        return float(f.get("fetched_at", 0.0) or 0.0)

    def truenas_cache_appliance_fetched_at(self, appliance_id: str) -> float:
        """Epoch of the most recent write to one appliance's cache entry."""
        # 0.0 for an unknown appliance, else its timestamp.
        entry = self.truenas_appliance_cache.get(appliance_id)
        if not entry:
            return 0.0
        return float(entry.get("fetched_at", 0.0) or 0.0)
