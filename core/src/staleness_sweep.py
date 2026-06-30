"""NetBox staleness-sweep subsystem for the Hub.

Mirrors ``realtime_ipam_nac_sync.py``: a self-contained, named subsystem gathered
here as a **mixin** so the Hub class body shrinks with zero call-site change.
``api.py`` routes call ``hub.run_staleness_sweep_all()`` /
``hub.run_staleness_sweep_loop()`` — all of which resolve via inheritance once
``StalenessSweepMixin`` is added to ``LabManagerHub`` bases. The method bodies
take ``self`` and use the same state/spoke helpers as the other syncs.

The sweep is **cluster-wide** (not per-tenant): it asks the netbox (IPAM) spoke
to run ``NETBOX_STALENESS_SWEEP``, which ages out sync-owned NetBox objects —
devices/VMs not seen for ``stale_days`` → status offline + ``decommissioned_at``;
offline + ``decommissioned_at`` older than ``delete_days`` → deleted (IPs free
automatically); unassigned stale IPs → freed. Objects with no ``last_seen``
custom field are never swept (protects hand-managed inventory). The sweep logic
itself lives in the external netbox spoke repo (not in this tree); the hub only
schedules + relays + records the cluster-wide last-sweep status.

This module is a **leaf**: it imports only stdlib and must NOT import ``main``
or ``api`` (no back-import — that would create a cycle, since ``main`` imports
this module to pull in the mixin). Dependency direction is ``main →
staleness_sweep`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import datetime as _dt
import asyncio
import logging
from typing import Any, Dict

logger = logging.getLogger("Hub")


class StalenessSweepMixin:
    """Periodically runs the NetBox staleness sweep (cluster-wide age-out of
    sync-owned devices/VMs/IPs) and records the last-run status for the WebUI.

    Config (``global_config["staleness_sweep"]``): ``enabled`` (bool),
    ``interval_seconds`` (default 3600 — hourly), ``stale_days`` (default 7),
    ``delete_days`` (default 30). Read fresh each cycle so a WebUI change takes
    effect without a restart. The thresholds are forwarded to the netbox spoke,
    which owns the actual sweep decision logic.
    #
    # The sweep is the lifecycle counterpart to the ``last_seen`` custom field
    # every sync stamps on each detection (sync_vms / sync_devices /
    # sync_access_tracker): an object the syncs keep seeing keeps its last_seen
    # refreshed and is never swept; an object that stops appearing ages out.
    """

    _STALENESS_CFG_KEY = "staleness_sweep"
    _STALENESS_PUSH_COMMAND = "NETBOX_STALENESS_SWEEP"

    def _staleness_cfg(self) -> Dict[str, Any]:
        """Read the sweep config fresh (enabled/interval/stale_days/delete_days)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._STALENESS_CFG_KEY, {})) or {}

    def _staleness_interval(self) -> float:
        """Seconds between scheduled sweeps. Clamp >= 60 so a bad config can't
        hot-loop the hub. Default 3600 (hourly)."""
        try:
            n = int(self._staleness_cfg().get("interval_seconds", 3600))
        except (TypeError, ValueError):
            n = 3600
        return max(60.0, float(n))

    def _staleness_thresholds(self) -> Dict[str, int]:
        """Forwarded to the spoke: {stale_days, delete_days}. Clamp each to
        >= 1; defaults 7 / 30."""
        cfg = self._staleness_cfg()
        def _pos(key: str, default: int) -> int:
            try:
                v = int(cfg.get(key, default))
            except (TypeError, ValueError):
                v = default
            return max(1, v)
        return {"stale_days": _pos("stale_days", 7),
                "delete_days": _pos("delete_days", 30)}

    async def run_staleness_sweep_all(self) -> Dict[str, Any]:
        """Run one cluster-wide NetBox staleness sweep and record its status.

        Returns ``{status, scanned, decommissioned, deleted, ip_freed, errors,
        message, per_tenant, last_sync_ts}``. Idempotent + best-effort: an IPAM
        outage yields an 'error' status, never an unhandled exception (the
        background loop depends on this).
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        ipam = self.get_spoke_by_type("ipam")
        if not ipam:
            logger.info("staleness sweep SKIP: NetBox (IPAM) spoke not connected")
            status = {"status": "error", "scanned": 0, "decommissioned": 0,
                      "deleted": 0, "ip_freed": 0, "errors": 0,
                      "message": "NetBox spoke not connected",
                      "per_tenant": {}, "last_sync_ts": now}
            await self.simulations_store.set_staleness_sweep_status(status)
            return status
        thresholds = self._staleness_thresholds()
        try:
            rr = await self.request_response(
                ipam, self._STALENESS_PUSH_COMMAND, thresholds, timeout=180.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            scanned = int((rd or {}).get("scanned", 0) or 0)
            decommissioned = int((rd or {}).get("decommissioned", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            ip_freed = int((rd or {}).get("ip_freed", 0) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            message = (rd or {}).get("message", "")
            per_tenant = (rd or {}).get("per_tenant", {}) or {}
            rstate = "success" if rstatus != "ERROR" else "error"
            # Hub-authoritative sync log: clean → INFO; errors/failure →
            # [sync-error] WARNING carrying the spoke's message so the cause
            # lands in the hub log + GET_ERROR_LOGS (bugfixer).
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] staleness-sweep status=%s scanned=%d "
                               "decommissioned=%d deleted=%d ip_freed=%d errors=%d — %s",
                               rstate, scanned, decommissioned, deleted, ip_freed,
                               errors, message or "NetBox error")
            else:
                logger.info("staleness sweep: scanned=%d decommissioned=%d deleted=%d "
                            "ip_freed=%d", scanned, decommissioned, deleted, ip_freed)
            status = {"status": rstate, "scanned": scanned,
                      "decommissioned": decommissioned, "deleted": deleted,
                      "ip_freed": ip_freed, "errors": errors,
                      "message": message or ("sweep complete" if rstatus != "ERROR"
                                              else "NetBox error"),
                      "per_tenant": per_tenant, "last_sync_ts": now}
        except Exception as e:
            logger.warning("[sync-error] staleness-sweep failed: %s", e)
            status = {"status": "error", "scanned": 0, "decommissioned": 0,
                      "deleted": 0, "ip_freed": 0, "errors": 0,
                      "message": str(e), "per_tenant": {}, "last_sync_ts": now}
        await self.simulations_store.set_staleness_sweep_status(status)
        return status

    async def run_staleness_sweep_loop(self):
        """Periodically run the NetBox staleness sweep per the configured
        interval (default hourly).

        Reads the config fresh each cycle (enabled / interval / stale_days /
        delete_days) so a WebUI change takes effect without a restart. Disabled
        → short sleep + re-check. Skips a cycle entirely if the IPAM (netbox)
        spoke is offline. Staggered ~90s after startup so it doesn't
        simultaneous-fire with the other heavy syncs.
        """
        await asyncio.sleep(90)  # let spokes connect; stagger after the other syncs
        while True:
            try:
                cfg = self._staleness_cfg()
                ipam_up = bool(self.get_spoke_by_type("ipam"))
                if cfg.get("enabled", False) and ipam_up:
                    await self.run_staleness_sweep_all()
                delay = self._staleness_interval() if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] staleness-sweep loop cycle failed: %s", e)
                await asyncio.sleep(60)