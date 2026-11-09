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

Persisted per tenant (``cache_core.TenantShardCache``) as
``<data_dir>/tenants/<tenant>/nw/nw_fleet.json`` (that tenant's fleet rows) and
``.../nw/nw_devices.json`` (that tenant's per-device data): a poll rewrites only
its tenant's file, atomically, off the event loop. Loaded on startup via
``nw_cache_load`` so the UI is seeded immediately; subsequent live fetches
refresh + re-persist. A legacy ``cache/nw_data.json`` is split once on load.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction
is ``main → nw_cache`` only). Audience: Hub developers.
"""

from __future__ import annotations

# logging for restore/refresh messages; os builds the cache file path; time stamps writes.
import logging
import os
import time
# Type hints only; they document the shapes of values passed around.
from typing import Any, Dict, Optional

# Shared cache helpers: JsonCacheFile does debounced atomic JSON persistence and
# StalenessPolicy decides when cached data is old.
from cache_core import JsonCacheFile, StalenessPolicy, TenantShardCache

# Logs under the shared "Hub" logger so cache messages appear with other hub output.
logger = logging.getLogger("Hub")


class NwCacheMixin:
    """In-memory + JSON-persisted cache for the Network Devices (nw) module.

    The cache holds the last-known fleet list + per-device endpoint data so the
    WebUI Network Devices page can render last-known data when the nw spoke is
    offline (or before it reconnects after a hub restart) instead of 503-ing.
    Live fetches refresh the cache; the cache is persisted atomically to
    ``cache/nw_data.json`` and reloaded on startup to seed the UI.
    """

    # Legacy single-file cache (split into per-tenant files on first load).
    NW_CACHE_FILE = "nw_data.json"
    # Per-tenant shard files under tenants/<tenant>/nw/.
    NW_SHARD_MODULE = "nw"
    NW_FLEET_SHARD = "nw_fleet.json"
    NW_DEVICES_SHARD = "nw_devices.json"
    # Bucket for devices whose tenant is not (yet) known from the fleet list.
    NW_UNASSIGNED = "_unassigned"
    _NW_KEYSEP = "\x1f"
    # Per-device endpoint slots that may be cached ("poll" is handled separately).
    _NW_CACHE_ENDPOINTS = ("info", "macs", "arp", "interfaces",
                           "endpoints", "vlans", "lldp")

    # ── lifecycle ────────────────────────────────────────────────────────────

    def nw_cache_init(self) -> None:
        """Initialize the in-memory cache slots. Call once from ``__init__``."""
        # Fleet snapshot and per-device endpoint data, both empty until first fetch or load.
        self.nw_fleet_cache: Dict[str, Any] = {}
        self.nw_device_cache: Dict[str, Dict[str, Any]] = {}
        # Staleness rules used by the read path to decide when to revalidate.
        self.nw_policy = StalenessPolicy()
        # Persistence: one small file per tenant for the fleet rows and one for
        # the per-device data, each rewritten only when its tenant changed.
        self._nw_fleet_file = TenantShardCache(
            "nw fleet cache", self._nw_data_dir, self.NW_SHARD_MODULE,
            self.NW_FLEET_SHARD, self._nw_fleet_resident)
        self._nw_cache_file = TenantShardCache(
            "nw device cache", self._nw_data_dir, self.NW_SHARD_MODULE,
            self.NW_DEVICES_SHARD, self._nw_devices_resident)

    def _nw_data_dir(self) -> str:
        """Root holding ``tenants/``: the hub's data dir, else the cache dir (tests)."""
        state = getattr(self, "state", None)
        return getattr(state, "data_dir", None) or getattr(self, "cache_dir", ".")

    def _nw_tenant_of_device(self, device_id: str) -> str:
        """Tenant owning a device, from the cached fleet rows."""
        env = (self.nw_fleet_cache or {}).get("devices")
        rows = env.get("data") if isinstance(env, dict) else None
        for r in rows if isinstance(rows, list) else ():
            if isinstance(r, dict) and r.get("id") == device_id:
                return str(r.get("tenant_id") or "") or self.NW_UNASSIGNED
        return self.NW_UNASSIGNED

    def _nw_fleet_resident(self) -> Dict[str, Any]:
        """``{tenant\\x1f_fleet: {rows, envelope, fetched_at}}`` for the fleet store."""
        f = self.nw_fleet_cache or {}
        env = f.get("devices")
        rows = env.get("data") if isinstance(env, dict) else None
        if not isinstance(rows, list):
            return {}
        meta = {k: v for k, v in env.items() if k != "data"}
        by_tenant: Dict[str, list] = {}
        for r in rows:
            if isinstance(r, dict):
                by_tenant.setdefault(str(r.get("tenant_id") or "") or self.NW_UNASSIGNED, []).append(r)
        return {t + self._NW_KEYSEP + "_fleet":
                {"rows": rs, "envelope": meta, "fetched_at": f.get("fetched_at", 0.0)}
                for t, rs in by_tenant.items()}

    def _nw_devices_resident(self) -> Dict[str, Any]:
        """``{tenant\\x1fdevice_id: entry}`` for the per-device store."""
        owner = {}
        env = (self.nw_fleet_cache or {}).get("devices")
        rows = env.get("data") if isinstance(env, dict) else None
        for r in rows if isinstance(rows, list) else ():
            if isinstance(r, dict) and r.get("id") is not None:
                owner[r["id"]] = str(r.get("tenant_id") or "") or self.NW_UNASSIGNED
        return {owner.get(did, self.NW_UNASSIGNED) + self._NW_KEYSEP + str(did): entry
                for did, entry in list(self.nw_device_cache.items())}

    def _nw_cache_path(self) -> str:
        """Return the full path of the persisted nw cache file."""
        # Use the hub's cache_dir when set, else the current directory.
        return os.path.join(getattr(self, "cache_dir", "."), self.NW_CACHE_FILE)

    def nw_cache_load(self) -> None:
        """Rehydrate the in-memory cache from disk on startup (best-effort).

        Missing/corrupt file → leaves the cache empty (cold-start behavior):
        the UI 503s once, then the first live fetch populates + persists.
        The read itself is ``cache_core``'s, so a truncated or non-JSON file
        degrades identically here and in every other module.
        """
        # Split a legacy single-file cache into per-tenant files, once.
        self._nw_migrate_legacy()
        # Per-tenant fleet rows → one merged fleet envelope.
        fleet_rows, meta, fetched = [], {}, 0.0
        for key, v in sorted(self._nw_fleet_file.load().items()):
            if isinstance(v, dict) and isinstance(v.get("rows"), list):
                fleet_rows.extend(r for r in v["rows"] if isinstance(r, dict))
                meta = v.get("envelope") if isinstance(v.get("envelope"), dict) else meta
                fetched = max(fetched, float(v.get("fetched_at", 0.0) or 0.0))
        if fleet_rows or meta:
            self.nw_fleet_cache = {"devices": {**meta, "data": fleet_rows}, "fetched_at": fetched}
        # Per-tenant device entries; drop failed envelopes persisted before
        # set_device refused them, so a restart serves a cold miss (live fetch)
        # rather than a cached ERROR.
        self.nw_device_cache = {
            key.split(self._NW_KEYSEP, 1)[-1]: {k: e for k, e in v.items()
                                                 if not self._nw_failed_envelope(e)}
            for key, v in self._nw_cache_file.load().items()
            if isinstance(v, dict)
        }
        # Log what was restored so operators can see the warm start happened.
        if self.nw_fleet_cache or self.nw_device_cache:
            logger.info("nw cache: restored %d device(s) + fleet snapshot from per-tenant files under %s",
                        len(self.nw_device_cache), self._nw_data_dir())

    def _nw_migrate_legacy(self) -> None:
        """One-time split of ``cache/nw_data.json`` into per-tenant files
        (the old file is kept as ``.migrated``). Best-effort; never raises."""
        legacy = self._nw_cache_path()
        try:
            if not os.path.exists(legacy):
                return
            data = JsonCacheFile("legacy nw cache", lambda: legacy, dict).load()
            if isinstance(data, dict):
                fleet, devices = data.get("fleet"), data.get("devices")
                if isinstance(fleet, dict):
                    self.nw_fleet_cache = {"devices": fleet.get("devices"),
                                           "fetched_at": float(fleet.get("fetched_at", 0.0) or 0.0)}
                if isinstance(devices, dict):
                    self.nw_device_cache = {str(k): v for k, v in devices.items() if isinstance(v, dict)}
                # Write every tenant's files now (no event loop is needed).
                self._nw_fleet_file._write(self._nw_fleet_resident(), {TenantShardCache.ALL})
                self._nw_cache_file._write(self._nw_devices_resident(), {TenantShardCache.ALL})
            os.replace(legacy, legacy + ".migrated")
            logger.info("nw cache: split %s into per-tenant files", legacy)
        except Exception as exc:  # noqa: BLE001
            logger.warning("nw cache: legacy migration failed (left in place): %s", exc)

    # ── read ──────────────────────────────────────────────────────────────────

    def nw_cache_get_fleet(self) -> Optional[Dict[str, Any]]:
        """Last-known fleet envelope + ``fetched_at``, or None if never cached."""
        # Return the fleet snapshot only if a device list was actually cached.
        f = self.nw_fleet_cache
        if not f or f.get("devices") is None:
            return None
        return f

    def nw_cache_get_fleet_filtered(self, predicate) -> Optional[Dict[str, Any]]:
        """Last-known fleet envelope with the device rows filtered by
        ``predicate(row)``, or None if never cached. Serves the offline-cache
        path of ``GET /api/nw/devices`` tenant-scoped: a non-admin reader must
        NOT see another tenant's devices from the single global cache (the
        cross-tenant leak the nw tenant-scoping closes).

        Returns the SAME shape as ``nw_cache_get_fleet`` (``{"devices": env,
        "fetched_at": epoch}``) so the route serves the filtered snapshot
        exactly as it serves the full one. Requires the cached rows to carry
        ``tenant_id`` (Stage 1 stamps every list_devices row), so the route's
        predicate — ``access.spoke_visible_to_session(sess, row.tenant_id)``
        — can decide visibility per row. No storage-shape change: the filter
        builds a shallow-copied envelope; the underlying cache is untouched.
        A missing/empty ``data`` list is returned as-is (None cache or a
        zero-row fleet both short-circuit to the caller's empty handling)."""
        # No cached fleet list means nothing to filter.
        f = self.nw_fleet_cache
        if not f or f.get("devices") is None:
            return None
        # Filter the envelope's data rows through the caller's visibility predicate.
        env = f["devices"]
        data = env.get("data") if isinstance(env, dict) else None
        if isinstance(data, list):
            env = {**env, "data": [r for r in data
                                   if isinstance(r, dict) and predicate(r)]}
        # Same shape as nw_cache_get_fleet, with the filtered envelope.
        return {"devices": env, "fetched_at": f["fetched_at"]}

    def nw_cache_get_device(self, device_id: str, endpoint: str) -> Optional[Any]:
        """Last-known raw envelope for one device endpoint, or None."""
        # Look up the device entry; unknown devices have no cached data.
        entry = self.nw_device_cache.get(device_id)
        if not entry:
            return None
        # Return the cached envelope for this endpoint (None when absent).
        val = entry.get(endpoint)
        return val if val is not None else None

    def nw_cache_fleet_fetched_at(self) -> float:
        """Epoch of the last fleet-cache write (0.0 if never cached). Drives the
        cache-first read path's staleness/revalidate decision in ``routes/nw``."""
        # Return the fleet write time, or 0.0 if there is no cached fleet list.
        f = self.nw_fleet_cache
        if not f or f.get("devices") is None:
            return 0.0
        return float(f.get("fetched_at", 0.0) or 0.0)

    def nw_cache_device_fetched_at(self, device_id: str) -> float:
        """Epoch of the most recent write to one device's cache entry (0.0 if
        the device was never cached). Drives the cache-first read path's
        staleness/revalidate decision in ``routes/nw``."""
        # Return the device's last write time, or 0.0 if it was never cached.
        entry = self.nw_device_cache.get(device_id)
        if not entry:
            return 0.0
        return float(entry.get("fetched_at", 0.0) or 0.0)

    # ── write ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _nw_failed_envelope(data: Any) -> bool:
        """Return True when data is a dict whose 'status' value, converted with str(...).strip().upper(), is one of 'ERROR', 'FAILED', 'FAILURE'. Otherwise False."""
        # Only dict envelopes can carry a status.
        if not isinstance(data, dict):
            return False
        # Normalize the status text and treat any of the failure words as failed.
        status = str(data.get("status", "")).strip().upper()
        return status in ("ERROR", "FAILED", "FAILURE")

    async def nw_cache_set_fleet(self, data: Any) -> None:
        """Store a fresh NW_LIST_DEVICES envelope + persist (best-effort). Failed envelopes never overwrite last-known-good data."""
        # Never overwrite good cached data with a failed refresh.
        if self._nw_failed_envelope(data):
            logger.info("nw cache: keeping last-known fleet snapshot (refresh failed: %s)", data.get("message"))
            return
        # Store the new envelope with the current time and schedule a debounced save.
        self.nw_fleet_cache = {"devices": data, "fetched_at": time.time()}
        self._nw_fleet_file.schedule_save()
        # Rows may have changed tenant: re-evaluate device ownership too.
        self._nw_cache_file.schedule_save()

    async def nw_cache_set_reachability(self, device_id: str,
                                        reachable: Optional[bool],
                                        latency_ms: Optional[float] = None
                                        ) -> None:
        """Fold a lightweight ICMP-reachability result (spoke ``NW_REACHABILITY``
        sweep) into the cached fleet row for ``device_id`` so the up/down badge
        stays fresh between the hours-apart data polls WITHOUT a full
        NW_LIST_DEVICES round-trip. Updates the row's ``reachable`` +
        ``latency_ms`` in place (no-op if the fleet snapshot or the row is not
        cached yet — the first fleet list seeds it). ``reachable`` may be
        ``None`` (UNKNOWN) which surfaces as the yellow 'unknown' badge."""
        # Need a cached fleet envelope to update.
        f = self.nw_fleet_cache
        if not f or not isinstance(f.get("devices"), dict):
            return
        # The rows live under the envelope's "data" list.
        rows = f["devices"].get("data")
        if not isinstance(rows, list):
            return
        # Find this device's row and update its reachability fields in place.
        touched = False
        for r in rows:
            if isinstance(r, dict) and r.get("id") == device_id:
                # Latency jitters every sweep; only an up/down flip is worth a disk write.
                touched = r.get("reachable") != reachable
                r["reachable"] = reachable
                r["latency_ms"] = latency_ms
                break
        # Persist only on a reachability flip (that tenant's fleet file only).
        if touched:
            self._nw_fleet_file.schedule_save(self._nw_tenant_of_device(device_id))

    async def nw_cache_set_device(self, device_id: str, endpoint: str,
                                  data: Any) -> None:
        """Store a fresh per-device endpoint envelope + persist (best-effort). Failed envelopes never overwrite last-known-good data."""
        # Ignore endpoints that are not cacheable.
        if endpoint not in self._NW_CACHE_ENDPOINTS and endpoint != "poll":
            return
        # Keep last-known data rather than caching an error envelope.
        if self._nw_failed_envelope(data):
            logger.info("nw cache: keeping last-known %s for %s (refresh failed: %s)", endpoint, device_id, data.get("message"))
            return
        # Create the device entry if needed, store the envelope and stamp the time.
        entry = self.nw_device_cache.setdefault(device_id, {})
        entry[endpoint] = data
        entry["fetched_at"] = time.time()
        # Schedule a debounced write of this device's tenant file.
        self._nw_cache_file.schedule_save(self._nw_tenant_of_device(device_id))

    async def nw_cache_set_poll(self, device_id: str, poll_result: Dict[str, Any]
                                ) -> None:
        """Fold a POLL NOW result into the per-device cache + persist.

        The poll carries device_info / interfaces / arp / mac_table alongside
        the reachability + NetBox-push summary; threading it into the cache
        means a later page load (spoke offline) still reflects the last poll.
        """
        # Ignore malformed poll results.
        if not isinstance(poll_result, dict):
            return
        # Keep the full poll result in its own slot.
        entry = self.nw_device_cache.setdefault(device_id, {})
        entry["poll"] = poll_result
        # Best-effort: mirror the poll's sub-resources into the endpoint slots
        # so /api/nw/{id}/{info|arp|macs|interfaces} also serves the poll data
        # when the spoke is down. Wrapped in the standard SUCCESS envelope so
        # the unwrapping/contract the routes expect is preserved.
        #
        # ONLY when the poll actually reached the device: an UNREACHABLE poll
        # returns empty datum lists (probe/creds/transport failed), and mirroring
        # those would CLOBBER good last-known-good per-datum caches with empties
        # stamped SUCCESS — blanking the UI tabs even though the individual
        # fetches still work. A poll we couldn't complete must preserve, not
        # destroy, the cached data.
        if poll_result.get("reachable"):
            # Copy each sub-resource present in the poll into its endpoint slot.
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
            endpoints = poll_result.get("endpoints")
            if isinstance(endpoints, list):
                entry["endpoints"] = {"status": "SUCCESS", "data": endpoints}
            vlans = poll_result.get("vlans")
            if isinstance(vlans, list):
                entry["vlans"] = {"status": "SUCCESS", "data": vlans}
        # Stamp the write time and schedule a debounced save.
        entry["fetched_at"] = time.time()
        self._nw_cache_file.schedule_save(self._nw_tenant_of_device(device_id))

    # ── persist ───────────────────────────────────────────────────────────────
    # Persistence itself lives in cache_core.JsonCacheFile: the debounced
    # writer, the atomic 0600 replace and the best-effort error handling are
    # shared with every other cache instead of being a fourth copy here.

    async def nw_cache_flush_now(self) -> None:
        """Immediate persist (shutdown path) — skips the coalescing delay."""
        # Write the cache to disk now, bypassing the debounce timer.
        await self._nw_fleet_file.flush_now()
        await self._nw_cache_file.flush_now()

    # ── staleness ─────────────────────────────────────────────────────────────
