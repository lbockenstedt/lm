"""IPAM → ClearPass endpoint-sync subsystem for the Hub.

Previously lived inline in ``core/src/main.py`` on ``LabManagerHub``. It is a
self-contained, already-named subsystem (recently made source-pluggable via the
``IPAM_SOURCES`` registry) and is gathered here as a **mixin** so the Hub class
body shrinks without any call-site change: ``api.py`` routes call
``hub.IPAM_SOURCES``, ``hub.sync_tenant_endpoints()``, ``hub.trigger_endpoint_sync()``,
``hub._endpoint_sync_tenants()``, ``hub._endpoint_sync_source()``,
``hub.tenant_id_for_ipam_scope()`` — all of which now resolve via inheritance
once ``EndpointSyncMixin`` is added to ``LabManagerHub`` bases. The method
bodies are moved verbatim, still taking ``self``, so there is zero rename and
zero churn.

This module is a **leaf**: it imports only stdlib and must NOT import ``main``
or ``api`` (no back-import — that would create a cycle, since ``main`` imports
this module to pull in the mixin). Dependency direction is
``main → endpoint_sync`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Hub")


class EndpointSyncMixin:
    """Pulls each tenant's endpoints (IP/MAC) from an IPAM source spoke and
    pushes them to the CPPM (ClearPass) spoke via CPPM_SYNC_ENDPOINTS so
    ClearPass Device Inventory is populated with tenant-tagged endpoints
    ahead of auth. The IPAM source is selectable via the ``source`` config
    field (default "netbox"); adding a product is a one-entry addition to
    IPAM_SOURCES below + a spoke that implements the get-ips command. The
    IPAM source is the source of truth: each sync is authoritative for the
    tenant (payload carries replace=True → the spoke overwrites that
    tenant's CPPM endpoint set to match). The ClearPass write handler lives
    in the external CPPM spoke repo (not in this tree); the hub only
    schedules + relays + records per-tenant last-sync status. See
    docs/modules/cppm.md for the CPPM_SYNC_ENDPOINTS + IPAM-source contract.
    #
    # IPAM_SOURCES maps a source name → how the hub talks to that product:
    #   module_type        : spoke module type to resolve (get_spoke_by_type)
    #   get_ips_command    : command the hub sends to fetch the tenant's IPs
    #   tenant_scope_field : tenant-config key holding the per-tenant scope id
    #                        (NetBox → netbox_tenant_slug)
    #   response_key       : key in the spoke response holding the IP list
    #   label              : human label for the WebUI source selector
    # The spoke contract for <get_ips_command>: request {"tenant": <scope>};
    # response {"status": "SUCCESS", <response_key>: [{address, custom_fields
    # .mac_address, dns_name}, ...]} — each product's spoke normalizes its own
    # fields into that shape, so the hub extraction is source-agnostic.
    #
    # The sync is modular: to swap in / add another IPAM product later, add one
    # entry here + a spoke that implements the get-ips command with the response
    # shape above. The hub logic, the loop, the edit-trigger, the WebUI source
    # dropdown (driven by /setup/endpoint-sync/sources), and the per-tenant
    # scoping all key off this registry, so no other change is needed.
    """

    IPAM_SOURCES: Dict[str, Dict[str, str]] = {
        "netbox": {
            "module_type": "ipam",
            "get_ips_command": "NETBOX_GET_IPS",
            "tenant_scope_field": "netbox_tenant_slug",
            "response_key": "ip_addresses",
            "label": "NetBox",
        },
    }

    _ENDPOINT_SYNC_CFG_KEY = "netbox_cppm_sync"  # legacy key; ``source`` selects the IPAM product

    def _endpoint_sync_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/mode/interval/daily_time)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._ENDPOINT_SYNC_CFG_KEY, {})) or {}

    def _endpoint_sync_source(self) -> Dict[str, str]:
        """Resolve the configured IPAM source registry entry (falls back to NetBox)."""
        name = str(self._endpoint_sync_cfg().get("source", "netbox")).strip().lower()
        return self.IPAM_SOURCES.get(name) or self.IPAM_SOURCES["netbox"]

    def _ipam_scope_for_tenant(self, source_entry: Dict[str, str],
                               tenant_id: str) -> str:
        """The per-tenant IPAM scope value for the active source ('' if unbound).

        e.g. NetBox → the tenant's netbox_tenant_slug. Which field is read is
        driven by the source entry's ``tenant_scope_field`` so the hub stays
        source-agnostic and a future IPAM product only needs its own scope field.
        """
        cfg = self.state.get_tenant(tenant_id) or {}
        return str(cfg.get(source_entry.get("tenant_scope_field", "")) or "").strip()

    def _endpoint_sync_tenants(self) -> List[str]:
        """Tenant ids bound to the configured IPAM source (have its scope field set)."""
        out: List[str] = []
        se = self._endpoint_sync_source()
        field = se.get("tenant_scope_field", "")
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        for tid, cfg in tenants.items():
            if str((cfg or {}).get(field) or "").strip():
                out.append(str(tid))
        return out

    def tenant_id_for_ipam_scope(self, scope_value: str) -> Optional[str]:
        """Reverse-map an IPAM scope value (for the configured source) → LM tenant id.

        Used by the IPAM edit-trigger to find which tenant a mutated IPAM object
        belongs to when the request body carries the per-tenant scope value.
        """
        se = self._endpoint_sync_source()
        field = se.get("tenant_scope_field", "")
        val = str(scope_value or "").strip()
        if not val or not field:
            return None
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        for tid, cfg in tenants.items():
            if str((cfg or {}).get(field) or "").strip() == val:
                return str(tid)
        return None

    def _endpoint_sync_concurrency(self) -> int:
        """Max tenants synced in parallel per cycle. Bounded so hundreds of
        tenants don't stampede the IPAM/CPPM spoke, but enough that a full cycle
        finishes well within the schedule. Clamp 1..16; default 8."""
        try:
            n = int(self._endpoint_sync_cfg().get("concurrency", 8))
        except (TypeError, ValueError):
            n = 8
        return max(1, min(16, n))

    def _endpoint_sync_next_delay(self, cfg: Dict[str, Any]) -> float:
        """Seconds to sleep before the next scheduled sync, per the config mode.

        ``mode`` is ``"daily"`` (run once a day at ``daily_time`` "HH:MM", 24h
        local) or anything else (interval mode → every ``interval_seconds``).
        Always clamped to >= 60 s so a bad config can't hot-loop the hub.
        """
        mode = str(cfg.get("mode", "interval")).strip().lower()
        if mode == "daily":
            hhmm = str(cfg.get("daily_time", "02:00")).strip()
            try:
                hh, mm = (int(p) for p in hhmm.split(":")[:2])
                now = _dt.datetime.now()
                target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if target <= now:
                    target += _dt.timedelta(days=1)
                return max(60.0, (target - now).total_seconds())
            except Exception:
                logger.debug("endpoint sync: bad daily_time %r — falling back to interval", hhmm)
        interval = 3600
        try:
            interval = int(cfg.get("interval_seconds", 3600))
        except (TypeError, ValueError):
            interval = 3600
        return max(60.0, float(interval))

    async def sync_tenant_endpoints(self, tenant_id: str) -> Dict[str, Any]:
        """Pull this tenant's endpoints from the configured IPAM source, push to CPPM.

        Returns a status dict {tenant_id, status, pushed, errors, message,
        last_sync_ts, endpoints_total}. Idempotent + best-effort: an IPAM/CPPM
        outage or a missing scoping yields a per-tenant error/skipped status,
        never an unhandled exception (the background loop depends on this).
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tenant_name = (self.state.get_tenant(tenant_id) or {}).get("name") or tenant_id
        se = self._endpoint_sync_source()
        ipam = self.get_spoke_by_type(se.get("module_type", "ipam"))
        nac = self.get_spoke_by_type("nac")
        if not ipam or not nac or nac in self._nac_unconfigured_spokes:
            logger.info("endpoint sync tenant=%s(%s) SKIP tenant: %s or CPPM spoke not connected "
                        "(ipam=%r nac=%r)", tenant_id, tenant_name, se.get('label', 'IPAM'),
                        bool(ipam), bool(nac))
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "error", "pushed": 0, "errors": 0,
                      "message": f"{se.get('label', 'IPAM')} or CPPM spoke not connected",
                      "last_sync_ts": now, "endpoints_total": 0}
            await self.simulations_store.set_endpoint_sync_status(tenant_id, status)
            return status
        scope = self._ipam_scope_for_tenant(se, tenant_id)
        if not scope:
            logger.info("endpoint sync tenant=%s(%s) SKIP tenant: not bound to %s "
                        "(no netbox_tenant_slug)", tenant_id, tenant_name, se.get('label', 'IPAM'))
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "skipped", "pushed": 0, "errors": 0,
                      "message": f"tenant not bound to {se.get('label', 'IPAM')}",
                      "last_sync_ts": now, "endpoints_total": 0}
            await self.simulations_store.set_endpoint_sync_status(tenant_id, status)
            return status
        try:
            r = await self.request_response(ipam, se.get("get_ips_command", "NETBOX_GET_IPS"),
                                             {"tenant": scope}, timeout=30.0)
            data = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            if isinstance(data, dict) and data.get("status") == "ERROR":
                logger.info("endpoint sync tenant=%s(%s) SKIP tenant: %s returned ERROR: %s",
                            tenant_id, tenant_name, se.get('label', 'IPAM'),
                            data.get('message', 'error'))
                status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                          "status": "error", "pushed": 0, "errors": 0,
                          "message": f"{se.get('label', 'IPAM')}: {data.get('message', 'error')}",
                          "last_sync_ts": now, "endpoints_total": 0}
                await self.simulations_store.set_endpoint_sync_status(tenant_id, status)
                return status
            resp_key = se.get("response_key", "ip_addresses")
            endpoints: List[Dict[str, Any]] = []
            hub_skipped = 0  # records dropped hub-side before reaching CPPM
            for ip in (data.get(resp_key, []) if isinstance(data, dict) else []):
                address = str((ip or {}).get("address") or "").split("/")[0].strip()
                mac = str(((ip or {}).get("custom_fields") or {}).get("mac_address") or "").strip()
                hostname = str((ip or {}).get("dns_name") or "").strip()
                if not address and not mac:
                    hub_skipped += 1
                    logger.info("endpoint sync tenant=%s(%s) SKIP record: no address and no mac; "
                                "hostname=%s (record has neither an IP nor a mac_address custom field)",
                                tenant_id, tenant_name, hostname or "<empty>")
                    continue  # nothing to sync
                ep = {"ip": address, "mac": mac, "hostname": hostname}
                endpoints.append(ep)
            payload = {"tenant_id": tenant_id, "tenant_slug": scope,
                       "tenant_name": tenant_name, "source": se.get("label", "IPAM"),
                       "replace": True, "endpoints": endpoints}
            # 185+ sequential endpoint PUTs to ClearPass can exceed the old 60s
            # ceiling → "Timed out waiting for spoke response" (the sync had
            # sent=185 pushed=185 but reported status=error). 180s matches the
            # vm-sync push budget (vm_sync.py) so a full tenant batch completes.
            rr = await self.request_response(nac, "CPPM_SYNC_ENDPOINTS", payload, timeout=180.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(endpoints)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            skipped_details = (rd or {}).get("skipped_details") or []
            message = (rd or {}).get("message", "")
            if skipped_details:
                logger.info(
                    "endpoint sync tenant=%s(%s) skipped %d: %s",
                    tenant_id, tenant_name, skipped,
                    "; ".join(f"ip={s.get('ip') or '<empty>'} mac={s.get('mac') or '<empty>'} "
                              f"hostname={s.get('hostname') or '<empty>'} ({s.get('reason')})"
                              for s in skipped_details))
            rstate = "success" if rstatus != "ERROR" else "error"
            # Hub-authoritative sync log: clean → INFO; errors/failure →
            # [sync-error] WARNING carrying the sink's message (first-error text)
            # so the cause lands in the hub log + GET_ERROR_LOGS (bugfixer).
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] endpoint-sync tenant=%s(%s) status=%s "
                               "sent=%d pushed=%d skipped=%d hub_skipped=%d errors=%d — %s",
                               tenant_id, tenant_name, rstate, len(endpoints),
                               pushed, skipped, hub_skipped, errors,
                               message or "CPPM error")
            else:
                logger.info("endpoint sync tenant=%s(%s) result status=%s sent=%d pushed=%d "
                            "skipped=%d hub_skipped=%d errors=%d",
                            tenant_id, tenant_name, rstate,
                            len(endpoints), pushed, skipped, hub_skipped, errors)
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "success" if rstatus != "ERROR" else "error",
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "message": message or (f"{len(endpoints)} endpoint(s) sent" if rstatus != "ERROR" else "CPPM error"),
                      "last_sync_ts": now, "endpoints_total": len(endpoints),
                      "hub_skipped": hub_skipped,
                      "skipped_details": skipped_details}
        except Exception as e:
            logger.warning("[sync-error] endpoint-sync tenant=%s failed: %s",
                           tenant_id, e)
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                      "status": "error", "pushed": 0, "errors": 0,
                      "message": str(e),
                      "last_sync_ts": now, "endpoints_total": 0}
        await self.simulations_store.set_endpoint_sync_status(tenant_id, status)
        return status

    def trigger_endpoint_sync(self, tenant_id: str) -> None:
        """Fire-and-forget an endpoint sync for one tenant after an IPAM edit.

        Called from the LM/IPAM mutation routes (e.g. add/update/delete a
        NetBox device or IP) so a change made through the hub propagates to
        ClearPass immediately instead of waiting for the next scheduled cycle.
        No-op when the sync is disabled or no CPPM spoke is connected — the one
        ``enabled`` toggle controls all automatic sync behavior. Safe to call
        from an async route (spawns a task on the running loop); silently does
        nothing if there is no running loop.
        """
        if not self._endpoint_sync_cfg().get("enabled", False):
            return
        nac = self.get_spoke_by_type("nac")
        if not nac or nac in self._nac_unconfigured_spokes:
            return
        try:
            asyncio.create_task(self.sync_tenant_endpoints(tenant_id))
        except RuntimeError:
            pass  # no running event loop — nothing to do

    async def run_endpoint_sync_loop(self):
        """Periodically sync IPAM endpoints → CPPM per the configured schedule.

        Reads the config fresh each cycle (enabled / source / mode / interval /
        daily time) so a WebUI change takes effect without a restart. Disabled
        → short sleep + re-check. Skips a cycle entirely if the configured
        IPAM source or CPPM is offline (the per-tenant sync records an 'error'
        status for it).
        """
        await asyncio.sleep(30)  # let spokes connect first (parity with tenant_sync)
        while True:
            try:
                cfg = self._endpoint_sync_cfg()
                se = self._endpoint_sync_source()
                nac = self.get_spoke_by_type("nac")
                if cfg.get("enabled", False) and \
                        self.get_spoke_by_type(se.get("module_type", "ipam")) and \
                        nac and nac not in self._nac_unconfigured_spokes:
                    # Fan tenants out concurrently with a bounded semaphore.
                    # Sequential await at hundreds of tenants × (30s IPAM + 60s
                    # CPPM) per tenant made a full cycle take longer than the
                    # schedule, so late tenants were perpetually stale. Bounded
                    # (not unbounded gather) so we don't stampede the IPAM/CPPM
                    # spokes with hundreds of simultaneous requests.
                    tenants = self._endpoint_sync_tenants()
                    sem = asyncio.Semaphore(self._endpoint_sync_concurrency())

                    async def _one(tid: str):
                        async with sem:
                            try:
                                await self.sync_tenant_endpoints(tid)
                            except Exception as e:  # defense in depth — sync_tenant_endpoints already swallows, but never let one task kill the gather
                                logger.debug("endpoint sync gather tenant=%s: %s", tid, e)

                    await asyncio.gather(*(_one(tid) for tid in tenants))
                delay = self._endpoint_sync_next_delay(cfg) if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] endpoint-sync loop failed: %s", e)
                await asyncio.sleep(60)