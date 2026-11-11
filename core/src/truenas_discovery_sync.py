"""TrueNAS → NetBox inventory-discovery sync subsystem for the Hub.

A deliberately minimal counterpart to ``nw_discovery_sync.py``. Where nw sync
pulls the ARP table from every switch/gateway and attributes IP↔MAC neighbors
to tenants by prefix containment, TrueNAS has **no neighbor topology** — the
appliances themselves are the inventory. So each cycle the hub pulls the
appliance fleet + a light pool summary from every connected ``storage`` spoke,
maps each appliance to a NetBox ``dcim.device`` record (tenant-tagged, the
appliance's own ``tenant_id`` from its config record — no prefix attribution
needed), and pushes per-tenant to the netbox (IPAM) spoke via
``NETBOX_SYNC_DEVICES`` with ``source="TrueNAS"`` so the netbox sink tags the
records truenas-owned (and replace-deletes only truenas-owned records, never
touching nw/opnsense-discovered ones). The appliance is the source of truth:
each sync is authoritative for the tenant (``replace=True`` → the sink
overwrites that tenant's truenas-discovered-device set to match, deleting
stale records).

Datasets/shares are NOT mirrored (they aren't devices; surfacing them in
NetBox would require custom-field-stamped inventory records beyond this
sync's scope — a later expansion). This first cut registers the appliances
themselves into DCIM so the storage fleet shows up in NetBox inventory,
tenant-tagged, with product/version/health/pool-count custom fields.

``api.py`` routes call ``hub.TRUENAS_DISCOVERY_SOURCES``,
``hub.run_truenas_discovery_sync_all()``, ``hub.sync_tenant_truenas_devices()``,
``hub._truenas_discovery_cfg()`` — all resolve via inheritance once
``TruenasDiscoverySyncMixin`` is added to ``LabManagerHub`` bases.

This module is a **leaf**: it imports only stdlib + ``access.unwrap_spoke``
+ ``sync_loop`` helpers (sibling leaves that import neither ``main`` nor
``api``). It MUST NOT import ``main`` or ``api`` (dependency direction is
``main → truenas_discovery_sync`` only).

Audience: Hub developers.
"""

from __future__ import annotations

# asyncio for concurrent pulls; datetime for timestamps; logging; type hints.
import asyncio
import datetime as _dt
import logging
from typing import Any, Dict, List, Tuple

# Unwrap spoke replies; shared schedule and loop helpers.
from access import unwrap_spoke  # sibling leaf (no main/api back-import)
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

# Log to the hub's logger.
logger = logging.getLogger("Hub")


class TruenasDiscoverySyncMixin:
    """Pulls the appliance fleet + a light pool summary from every connected
    ``storage`` spoke, maps each appliance to a NetBox ``dcim.device`` record
    (tenant-tagged by the appliance's own ``tenant_id``), and pushes the
    per-tenant appliance set to the netbox (IPAM) spoke via
    ``NETBOX_SYNC_DEVICES`` so NetBox DCIM devices mirror the TrueNAS fleet —
    tenant-tagged, with product/version/health/pool-count custom fields. The
    truenas source is selectable via ``source`` (default "truenas"); the
    appliances are the source of truth: each sync is authoritative for the
    tenant (``replace=True`` → the sink overwrites that tenant's
    truenas-discovered-device set to match, deleting stale records). The netbox
    write handler lives in the external netbox spoke repo. Best-effort: never
    raises."""

    # TRUENAS_DISCOVERY_SOURCES maps a source name → how the hub talks to that
    # product:
    #   module_type        : spoke module type to resolve (get_all_spokes_by_type)
    #   appliances_command : command to list the appliance fleet (no request
    #                        body; response {"status":"SUCCESS",
    #                        "data":[{id, name, host, tenant_id, ...}, ...]})
    #   pools_command      : command to fetch one appliance's pool summary
    #                        (request {"appliance_id": <id>}; response
    #                        {"status":"SUCCESS","data":[{name, status, ...}]})
    #   label              : human label for the WebUI source selector + the
    #                        push payload's ``source`` field (the netbox sink
    #                        uses it as the discovered_from ownership tag).
    TRUENAS_DISCOVERY_SOURCES: Dict[str, Dict[str, str]] = {
        "truenas": {
            "module_type": "storage",
            "appliances_command": "TRUENAS_LIST_APPLIANCES",
            "pools_command": "TRUENAS_GET_POOLS",
            "label": "TrueNAS",
        },
    }

    # Push target module, push command, and config key.
    _TRUENAS_DISCOVERY_TARGET_MODULE = "ipam"
    _TRUENAS_DISCOVERY_PUSH_COMMAND = "NETBOX_SYNC_DEVICES"
    _TRUENAS_DISCOVERY_CFG_KEY = "truenas_discovery_sync"

    # ── config helpers ──────────────────────────────────────────────────────

    def _truenas_discovery_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/mode/interval/daily_time/
        defaults)."""
        # The config block from global_config, or {}.
        return (self.state.system_state.get("global_config", {})
                .get(self._TRUENAS_DISCOVERY_CFG_KEY, {})) or {}

    def _truenas_discovery_source(self) -> Dict[str, str]:
        """Resolve the configured truenas source registry entry (falls back to
        "truenas")."""
        # Configured source name, falling back to truenas.
        name = str(self._truenas_discovery_cfg().get("source", "truenas")).strip().lower()
        return (self.TRUENAS_DISCOVERY_SOURCES.get(name)
                or self.TRUENAS_DISCOVERY_SOURCES["truenas"])

    def _truenas_spokes(self) -> List[str]:
        """Connected storage spoke ids to pull from this cycle."""
        # All connected storage spokes.
        return list(self.get_all_spokes_by_type("storage") or [])

    def _truenas_discovery_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        # Configured concurrency, default 4 when invalid.
        try:
            n = int(self._truenas_discovery_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        # Clamp to 1..8.
        return max(1, min(8, n))

    # ── pull + map ───────────────────────────────────────────────────────────

    async def _truenas_pull_appliances(self) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Pull the appliance fleet + a per-appliance pool summary from every
        connected storage spoke. Returns ``(records, errors)`` where each
        record is the appliance config dict enriched with ``_pools`` (a list
        of pool summary dicts) and ``_n_pools``. Best-effort: a spoke or
        appliance that fails is recorded as an error string and skipped, never
        raised."""
        # Source entry, spokes, and result lists.
        se = self._truenas_discovery_source()
        spokes = self._truenas_spokes()
        records: List[Dict[str, Any]] = []
        errors: List[str] = []
        # No spokes: nothing to pull.
        if not spokes:
            return records, errors
        # Commands for listing appliances and pools.
        list_cmd = se.get("appliances_command", "TRUENAS_LIST_APPLIANCES")
        pools_cmd = se.get("pools_command", "TRUENAS_GET_POOLS")
        # Pull the fleet from each spoke (a spoke returns the appliances bound
        # to it). Cap concurrent spoke round-trips so a slow box doesn't stall
        # the cycle.
        fetch_sem = asyncio.Semaphore(self._truenas_discovery_concurrency())

        async def _fetch(sid: str) -> None:
            """List the appliances on spoke sid, add each one's pool summary, and record any errors."""
            # Any failure for this spoke becomes an error string.
            try:
                # List the appliances, within the concurrency limit.
                async with fetch_sem:
                    r = await self.request_response(sid, list_cmd, {}, timeout=30.0)
                # Spoke error: record it and stop.
                d = unwrap_spoke(r) if isinstance(r, dict) else {}
                if isinstance(d, dict) and d.get("status") == "ERROR":
                    errors.append(f"{list_cmd}({sid}): {d.get('message', 'error')}")
                    return
                # Process each appliance dict.
                apps = (d.get("data") if isinstance(d, dict) else None) or []
                for app in apps or []:
                    if not isinstance(app, dict):
                        continue
                    # Copy it and tag it with its spoke.
                    app = dict(app)
                    app["_spoke_id"] = sid
                    # Light pool summary for the custom-field stamp + count.
                    pools: List[Dict[str, Any]] = []
                    # Fetch its pools; a failure is recorded but the appliance is kept.
                    try:
                        async with fetch_sem:
                            pr = await self.request_response(
                                sid, pools_cmd, {"appliance_id": app.get("id")},
                                timeout=30.0)
                        pd = unwrap_spoke(pr) if isinstance(pr, dict) else {}
                        if isinstance(pd, dict) and pd.get("status") != "ERROR":
                            pp = pd.get("data")
                            if isinstance(pp, list):
                                pools = pp
                    except Exception as e:  # noqa: BLE001 — one appliance's pool fetch must not sink the fleet
                        errors.append(f"{pools_cmd}({app.get('name') or app.get('id')}@{sid}): {e}")
                    # Pool list and count, then add the record.
                    app["_pools"] = pools
                    app["_n_pools"] = len(pools) if isinstance(pools, list) else 0
                    records.append(app)
            # Spoke-level failure.
            except Exception as e:  # noqa: BLE001
                errors.append(f"{list_cmd}({sid}): {e}")

        # Fetch from all spokes in parallel.
        await asyncio.gather(*(_fetch(sid) for sid in spokes), return_exceptions=True)
        return records, errors

    def _truenas_device_record(self, app: Dict[str, Any]) -> Dict[str, Any]:
        """Map one TrueNAS appliance to a NETBOX_SYNC_DEVICES record. The
        appliance's ``tenant_id`` attributes it (no prefix containment — TrueNAS
        appliances carry an explicit tenant bind). The host is the management
        IP; product/version/health/pool-count ride as custom fields."""
        # Appliance info and pool list.
        info = app.get("info") if isinstance(app.get("info"), dict) else {}
        pools = app.get("_pools") or []
        # Healthy only if every pool is ONLINE.
        healthy = True
        if isinstance(pools, list):
            healthy = all(str(p.get("status", "ONLINE")).upper() == "ONLINE"
                          for p in pools if isinstance(p, dict)) if pools else True
        # The management controller (iLO) stitched to this box by hardware serial.
        linked = ""
        try:
            for a in (self.state.get_global_config().get("truenas_appliances") or []):
                if isinstance(a, dict) and str(a.get("id")) == str(app.get("id")):
                    linked = str((a.get("linked_controller") or {}).get("name") or "")
        except Exception:  # noqa: BLE001
            linked = ""
        # NetBox device record.
        return {
            "hostname": str(app.get("name") or app.get("id") or ""),
            "ip": str(app.get("host") or "").strip(),
            "mac": "",
            "serial": str(info.get("system_serial") or info.get("serial")
                        or info.get("system_serial_number") or "").strip(),
            "model": str(info.get("system_product") or info.get("model") or "").strip(),
            "manufacturer": "TrueNAS",
            "tenant_id": str(app.get("tenant_id") or ""),
            "role": "storage",
            "custom_fields": {
                "product": str(info.get("product_name") or info.get("product") or "TrueNAS"),
                "version": str(info.get("version") or ""),
                "healthy": "true" if healthy else "false",
                "pool_count": str(app.get("_n_pools", 0)),
                "discovered_from": "TrueNAS",
                **({"linked_device": linked} if linked else {}),
            },
        }

    # ── push ────────────────────────────────────────────────────────────────

    async def _truenas_push_tenant(self, tenant_id: str,
                                   devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Push one tenant's truenas-discovered appliances to NetBox via
        NETBOX_SYNC_DEVICES. Records per-tenant last-sync status. Payload
        carries ``replace=True`` + ``source="TrueNAS"`` (the netbox sink tags
        records truenas-owned and replace-deletes only truenas-owned records).
        Best-effort: never raises."""
        # Timestamp plus the tenant's name and NetBox slug.
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        # Fields shared by every status record.
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "discovered_total": len(devices)}
        # No NetBox spoke: record an error and stop.
        netbox = self.get_spoke_by_type(self._TRUENAS_DISCOVERY_TARGET_MODULE)
        if not netbox:
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
            await self.simulations_store.set_truenas_discovery_sync_status(tenant_id, status)
            return status
        # Tenant not bound to NetBox: record skipped and stop.
        if not netbox_slug:
            status = {**base, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0,
                      "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
            await self.simulations_store.set_truenas_discovery_sync_status(tenant_id, status)
            return status
        # Authoritative payload: replace this tenant's TrueNAS-owned devices.
        defaults = self._truenas_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name,
                   "source": self._truenas_discovery_source().get("label", "TrueNAS"),
                   "replace": True, "devices": devices, "defaults": defaults}
        # Push it; any exception becomes an error status.
        try:
            rr = await self.request_response(netbox, self._TRUENAS_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=600.0)
            # Unwrap the reply and read its counters.
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(devices)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            # Errors go to the error-log feed; a clean run logs at info.
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] truenas-discovery tenant=%s(%s) status=%s "
                               "sent=%d pushed=%d skipped=%d deleted=%d errors=%d — %s",
                               tenant_id, tenant_name, rstate, len(devices),
                               pushed, skipped, deleted, errors, message or "NetBox error")
            else:
                logger.info("truenas discovery sync tenant=%s(%s) result status=%s sent=%d "
                            "pushed=%d skipped=%d deleted=%d errors=%d",
                            tenant_id, tenant_name, rstate,
                            len(devices), pushed, skipped, deleted, errors)
            # Status record for the WebUI.
            status = {**base, "status": rstate,
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(devices)} device(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        # Exception: log it and record an error.
        except Exception as e:
            logger.warning("[sync-error] truenas-discovery tenant=%s push failed: %s",
                           tenant_id, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        # Persist the tenant status and return it.
        await self.simulations_store.set_truenas_discovery_sync_status(tenant_id, status)
        return status

    # ── entry points ─────────────────────────────────────────────────────────

    async def sync_tenant_truenas_devices(self, tenant_id: str) -> Dict[str, Any]:
        """Sync one tenant's TrueNAS appliances to NetBox. Named
        ``sync_tenant_truenas_devices`` (not ``sync_tenant_devices``) to avoid
        an MRO clash with ``FwDiscoverySyncMixin.sync_tenant_devices`` /
        ``NwDiscoverySyncMixin.sync_tenant_nw_devices``. Best-effort."""
        # Pull everything, keep this tenant's devices, and push them.
        records, _errors = await self._truenas_pull_appliances()
        devices = [self._truenas_device_record(a)
                   for a in records if str(a.get("tenant_id") or "") == tenant_id]
        return await self._truenas_push_tenant(tenant_id, devices)

    async def run_truenas_discovery_sync_all(self) -> Dict[str, Any]:
        """One full cycle: pull the appliance fleet from every storage spoke,
        group by tenant, and push each tenant's set to NetBox in parallel
        (capped). Appliances with no tenant_id are dropped (NetBox stays
        tenant-authoritative). Best-effort: never raises."""
        # Pull all appliances.
        records, pull_errors = await self._truenas_pull_appliances()
        # Group by tenant; drop unattributed appliances.
        buckets: Dict[str, List[Dict[str, Any]]] = {}
        for app in records:
            tid = str(app.get("tenant_id") or "").strip()
            if not tid:
                continue
            buckets.setdefault(tid, []).append(self._truenas_device_record(app))
        # Limit how many tenants are pushed at once.
        sem = asyncio.Semaphore(self._truenas_discovery_concurrency())

        async def _one(tid: str):
            """Push tenant tid's devices, within the concurrency limit."""
            # Hold a semaphore slot during the push.
            async with sem:
                return await self._truenas_push_tenant(tid, buckets[tid])

        # Push every tenant in parallel.
        results = await asyncio.gather(*(_one(tid) for tid in buckets),
                                       return_exceptions=True)
        # Per-tenant results; exceptions become error entries.
        per_tenant: Dict[str, Any] = {}
        for tid, res in zip(buckets.keys(), results):
            per_tenant[tid] = res if isinstance(res, dict) else {"status": "error",
                                                                 "message": str(res)}
        # Cycle summary.
        return {"tenants": list(buckets.keys()),
                "discovered_total": len(records),
                "pushed_tenants": sum(1 for r in per_tenant.values()
                                      if r.get("status") == "success"),
                "per_tenant": per_tenant,
                "pull_errors": pull_errors}

    async def run_truenas_discovery_sync_loop(self):
        """Background loop: per schedule (or on-demand "Sync now") pull the
        TrueNAS appliance fleet from every connected storage spoke and push
        per-tenant to the netbox spoke via NETBOX_SYNC_DEVICES
        (source="TrueNAS"). Gated by the sync config's enable flag + a
        connected storage spoke + a connected netbox spoke; disabled → sleeps
        the short re-check interval."""
        def _guard() -> bool:
            """Return True when enabled and both storage and NetBox spokes are connected."""
            # Each condition must hold.
            cfg = self._truenas_discovery_cfg()
            if not cfg.get("enabled"):
                return False
            if not self._truenas_spokes():
                return False
            return bool(self.get_spoke_by_type(self._TRUENAS_DISCOVERY_TARGET_MODULE))

        def _delay() -> float:
            """Return seconds until the next cycle: 300 while disabled, else per the schedule."""
            # Disabled: re-check in 5 minutes.
            cfg = self._truenas_discovery_cfg()
            if not cfg.get("enabled"):
                return 300.0  # disabled → re-check every 5 min
            # Enabled: daily or interval schedule.
            return next_schedule_delay(cfg, default_daily_time="02:45",
                                       default_interval=3600,
                                       log_name="truenas-discovery")

        # Start 90 s after boot, then loop.
        await run_sync_loop(stagger=90, guard=_guard,
                            body=self.run_truenas_discovery_sync_all, delay=_delay,
                            error_label="truenas-discovery loop failed")