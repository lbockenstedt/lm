"""Realtime NAC → IPAM reverse-sync subsystem for the Hub (the bidirectional
counterpart to ``endpoint_sync.py``).

``endpoint_sync`` is the forward direction: NetBox (IPAM, source of truth) →
ClearPass endpoints. This module is the **reverse**: pull ClearPass **Access
Tracker / session** data (MAC, IP, switch IP, switch port, timestamp) and add
the entries NetBox is missing, so the NetBox DB reflects what is actually
authenticating on the network right now. NetBox stays source of truth → the
reverse is **only-add-missing** (it never overwrites or deletes hand-managed
NetBox records); the netbox spoke's ``NETBOX_SYNC_ACCESS_TRACKER`` /
``sync_access_tracker`` does the MAC-first matching + create.

The user asked for a **1-minute background loop** that pulls sessions from the
**last 2 minutes** and adds entries not already in NetBox. Both directions live
in one Setup→Sync card ("IPAM ↔ NAC Sync"): the forward sync's card label +
description are updated in the WebUI, and a "Realtime NAC → IPAM" sub-block
(enable / interval / lookback / Sync-now / status) is added inside it.

Architecture mirrors ``fw_discovery_sync.py`` (the closest analog: pull once per
cycle → attribute by prefix containment → push per-tenant to the netbox spoke),
but the source is the NAC (CPPM) spoke and the sink is the IPAM (netbox) spoke
— the opposite of the forward endpoint sync. Tenant attribution reuses the
shared ``access.attribute_by_prefix`` helper (extracted from
``FwDiscoverySyncMixin._fw_attribute``).

This module is a **leaf**: it imports only stdlib + ``access.attribute_by_prefix``
(a sibling leaf that itself imports neither ``main`` nor ``api``). It MUST NOT
import ``main`` or ``api`` (no back-import — that would create a cycle, since
``main`` imports this module to pull in the mixin). Dependency direction is
``main → realtime_ipam_nac_sync`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import re
import datetime as _dt
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

try:
    from access import attribute_by_prefix  # sibling leaf (no main/api back-import)
except Exception:  # pragma: no cover - access always importable in-app
    attribute_by_prefix = None  # type: ignore

logger = logging.getLogger("Hub")


class RealtimeIpamNacSyncMixin:
    """Pulls recent ClearPass Access Tracker sessions from the NAC (CPPM) spoke,
    attributes each to a tenant by IP prefix containment, and pushes the
    per-tenant session set to the IPAM (netbox) spoke via
    ``NETBOX_SYNC_ACCESS_TRACKER`` so NetBox DCIM gains a device (with a NIC
    interface carrying the native MAC + framed IP + a cable to a switch device's
    port interface) for every MAC not already present — only-add-missing, never
    overwriting or deleting. CPPM is the source for *what just authenticated*;
    NetBox stays the source of truth for the tenant-scoped device inventory.

    Config (``global_config["realtime_ipam_nac_sync"]``): ``enabled``,
    ``interval_seconds`` (default 60), ``lookback_minutes`` (default 2),
    ``defaults`` (role/device_type/site/switch_role/switch_device_type slugs),
    ``concurrency`` (tenants pushed in parallel; clamp 1..8; default 4). Read
    fresh each cycle so a WebUI change takes effect without a restart.

    The CPPM read (``CPPM_GET_RECENT_SESSIONS``) + the netbox write
    (``NETBOX_SYNC_ACCESS_TRACKER`` / ``sync_access_tracker``) live in the
    external spoke repos (not in this tree); the hub only schedules + relays +
    records per-tenant last-sync status. See those spokes for the contracts.
    """

    _REALTIME_NAC_CFG_KEY = "realtime_ipam_nac_sync"
    _RT_NAC_SOURCE_MODULE = "nac"        # CPPM spoke (pull side)
    _RT_NAC_SINK_MODULE = "ipam"         # netbox spoke (push side)
    _RT_NAC_PULL_COMMAND = "CPPM_GET_RECENT_SESSIONS"
    _RT_NAC_PUSH_COMMAND = "NETBOX_SYNC_ACCESS_TRACKER"

    # ── config helpers ──────────────────────────────────────────────────────

    def _rt_nac_cfg(self) -> Dict[str, Any]:
        """Read the realtime reverse-sync config fresh (enabled/interval/lookback/
        defaults/concurrency)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._REALTIME_NAC_CFG_KEY, {})) or {}

    def _rt_nac_spoke(self) -> Optional[str]:
        """Connected NAC (CPPM) spoke id to pull from (first of type). None if down."""
        return self.get_spoke_by_type(self._RT_NAC_SOURCE_MODULE)

    def _rt_ipam_spoke(self) -> Optional[str]:
        """Connected IPAM (netbox) spoke id to push to (first of type). None if down."""
        return self.get_spoke_by_type(self._RT_NAC_SINK_MODULE)

    def _rt_nac_lookback(self) -> int:
        """Sessions started in the last N minutes. Clamp 1..60; default 2."""
        try:
            n = int(self._rt_nac_cfg().get("lookback_minutes", 2))
        except (TypeError, ValueError):
            n = 2
        return max(1, min(60, n))

    def _rt_nac_interval(self) -> float:
        """Seconds between cycles. Clamp >= 60 so a bad config can't hot-loop the
        hub (the user asked for ~1 minute; default 60)."""
        try:
            n = float(int(self._rt_nac_cfg().get("interval_seconds", 60)))
        except (TypeError, ValueError):
            n = 60.0
        return max(60.0, n)

    def _rt_nac_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        try:
            n = int(self._rt_nac_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        return max(1, min(8, n))

    # ── pull / attribute / push ─────────────────────────────────────────────

    @staticmethod
    def _rt_norm_mac(m: Any) -> str:
        """Canonical lower-colon MAC (``aa:bb:cc:dd:ee:ff``) for dedup. '' for an
        absent/unknown MAC — the netbox sink tolerates a blank mac but the hub
        drops MAC-less sessions before the push (nothing to match/create by)."""
        s = str(m or "").strip().lower()
        if not s or s == "unknown":
            return ""
        hexd = re.sub(r"[^0-9a-f]", "", s)
        if len(hexd) == 12:
            return ":".join(hexd[i:i + 2] for i in range(0, 12, 2))
        return s

    async def _rt_pull_sessions(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """Pull recent Access Tracker sessions from the CPPM spoke.

        Returns ``(sessions, pull_info)`` where each session is normalized to
        ``{mac, ip, nas_ip, nas_name, nas_port, nas_port_type, username,
        start_time}`` (MAC normalized; MAC-less rows dropped hub-side — there's
        nothing to match/create by) and ``pull_info`` is
        ``{"errors": [<per-spoke errors>], "window_start": iso, "window_end":
        iso, "total": N}``. Empty list + an error when no NAC spoke is connected.
        """
        nac = self._rt_nac_spoke()
        if not nac:
            return [], {"errors": ["no NAC spoke connected"], "total": 0}
        lookback = self._rt_nac_lookback()
        errors: List[str] = []
        try:
            r = await self.request_response(nac, self._RT_NAC_PULL_COMMAND,
                                            {"lookback_minutes": lookback},
                                            timeout=30.0)
            d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            if isinstance(d, dict) and d.get("status") == "ERROR":
                errors.append(f"CPPM({nac}): {d.get('message', 'error')}")
                return [], {"errors": errors, "total": 0}
            rows = (d.get("sessions") if isinstance(d, dict) else None) or []
            out: List[Dict[str, Any]] = []
            for row in rows or []:
                if not isinstance(row, dict):
                    continue
                mac = self._rt_norm_mac(row.get("mac"))
                if not mac:
                    continue  # MAC-less → nothing to match/create by
                ip = str(row.get("ip") or "").strip().split("/")[0].strip()
                out.append({
                    "mac": mac,
                    "ip": ip,
                    "nas_ip": str(row.get("nas_ip") or "").strip().split("/")[0].strip(),
                    "nas_name": str(row.get("nas_name") or "").strip(),
                    "nas_port": str(row.get("nas_port") or "").strip(),
                    "nas_port_type": str(row.get("nas_port_type") or "").strip(),
                    "username": str(row.get("username") or "").strip(),
                    "start_time": str(row.get("start_time") or "").strip(),
                })
            info = {"errors": errors, "total": int(d.get("total", len(out)) or 0) if isinstance(d, dict) else len(out),
                    "window_start": (d.get("window_start") if isinstance(d, dict) else "") or "",
                    "window_end": (d.get("window_end") if isinstance(d, dict) else "") or ""}
            return out, info
        except Exception as e:
            errors.append(f"CPPM({nac}): {e}")
            return [], {"errors": errors, "total": 0}

    async def _rt_push_tenant(self, tenant_id: str,
                              sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Push one tenant's attributed sessions to NetBox via
        ``NETBOX_SYNC_ACCESS_TRACKER`` (only-add-missing).

        Records the per-tenant last-sync status (success/error/skipped). The
        payload carries ``replace=False`` (only-add-missing by design — never
        delete hand-managed NetBox records) and ``defaults`` for creation.
        Idempotent + best-effort: a netbox outage or an unbound tenant yields an
        error/skipped status, never an unhandled exception (the loop depends on this).
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "sessions_total": len(sessions)}
        netbox = self._rt_ipam_spoke()
        if not netbox:
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
            await self.simulations_store.set_realtime_nac_sync_status(tenant_id, status)
            return status
        if not netbox_slug:
            status = {**base, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0,
                      "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
            await self.simulations_store.set_realtime_nac_sync_status(tenant_id, status)
            return status
        defaults = self._rt_nac_cfg().get("defaults", {}) or {}
        # access_tracker is only-add-missing by design (NetBox is source of
        # truth). source_of_truth is relayed for parity; "netbox" is the only
        # mode exposed in v1 (an "external" overwrite mode isn't wired up). An
        # unknown/blank value falls back to netbox.
        sot_raw = str((self.state.system_state.get("global_config", {}) or {})
                     .get("source_of_truth", {}).get("access_tracker", "netbox")
                     ).strip().lower()
        sot = sot_raw if sot_raw in ("external", "netbox") else "netbox"
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name, "replace": False,
                   "sessions": sessions, "defaults": defaults,
                   "source_of_truth": sot}
        try:
            rr = await self.request_response(netbox, self._RT_NAC_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", 0) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            sessions_total = int((rd or {}).get("sessions_total", len(sessions)) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            # Hub-authoritative sync log: clean → INFO; errors/failure →
            # [sync-error] WARNING carrying the sink's message so the cause lands
            # in the hub log + GET_ERROR_LOGS (bugfixer).
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] realtime-nac tenant=%s(%s) status=%s "
                               "sent=%d pushed=%d skipped=%d deleted=%d errors=%d — %s",
                               tenant_id, tenant_name, rstate, len(sessions),
                               pushed, skipped, deleted, errors, message or "NetBox error")
            else:
                logger.info("realtime nac sync tenant=%s(%s) result status=%s sent=%d "
                            "pushed=%d skipped=%d deleted=%d errors=%d",
                            tenant_id, tenant_name, rstate,
                            len(sessions), pushed, skipped, deleted, errors)
            status = {**base, "status": rstate,
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted, "sessions_total": sessions_total,
                      "message": message or (f"{len(sessions)} session(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        except Exception as e:
            logger.warning("[sync-error] realtime-nac tenant=%s push failed: %s",
                           tenant_id, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        await self.simulations_store.set_realtime_nac_sync_status(tenant_id, status)
        return status

    # ── entry points ────────────────────────────────────────────────────────

    async def sync_tenant_realtime(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant realtime NAC → IPAM sync ('Sync now' for one
        tenant).

        Pulls globally (one CPPM recent-sessions fetch), attributes by prefix,
        then pushes only ``tenant_id``. Returns that tenant's status, annotated
        with the cycle's global ``sessions_total_global`` and
        ``dropped_unattributed`` for the UI summary.
        """
        sessions, pull = await self._rt_pull_sessions()
        buckets, dropped = await self._rt_attribute(sessions)
        status = await self._rt_push_tenant(tenant_id, buckets.get(tenant_id, []))
        status["sessions_total_global"] = len(sessions)
        status["dropped_unattributed"] = dropped
        status["pull_errors"] = pull.get("errors", [])
        return status

    async def _rt_attribute(self, sessions: List[Dict[str, Any]]
                            ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
        """Bucket sessions by tenant via prefix containment (delegate to the
        shared ``access.attribute_by_prefix``). Sessions whose framed IP sits in
        no tenant prefix are dropped + counted."""
        if attribute_by_prefix is None:  # pragma: no cover - access importable in-app
            return {}, len(sessions)
        return await attribute_by_prefix(self, sessions)

    async def run_realtime_nac_sync_all(self) -> Dict[str, Any]:
        """Full cycle: pull → attribute → push every attributed tenant.

        Tenants are pushed concurrently with a bounded semaphore. Returns
        ``{"results": [<per-tenant status>], "dropped_unattributed": N,
        "sessions_total": M}``. Called by the background loop (which discards the
        return) and the all-tenant 'Sync now'.
        """
        sessions, pull = await self._rt_pull_sessions()
        buckets, dropped = await self._rt_attribute(sessions)
        tids = list(buckets.keys())
        if not tids:
            logger.info("realtime nac sync cycle: %d sessions pulled, 0 tenants matched, "
                        "%d dropped unattributed", len(sessions), dropped)
            return {"results": [], "dropped_unattributed": dropped,
                    "sessions_total": len(sessions),
                    "pull_errors": pull.get("errors", [])}
        sem = asyncio.Semaphore(self._rt_nac_concurrency())

        async def _one(tid: str):
            async with sem:
                try:
                    return await self._rt_push_tenant(tid, buckets.get(tid, []))
                except Exception as e:  # _rt_push_tenant swallows; never let one task kill the gather
                    logger.debug("realtime nac gather tenant=%s: %s", tid, e)
                    return None

        results = await asyncio.gather(*(_one(tid) for tid in tids))
        out = [r for r in results if r]
        pushed = sum(int(r.get("pushed", 0)) for r in out)
        errs = sum(int(r.get("errors", 0)) for r in out)
        if errs > 0:
            logger.warning("[sync-error] realtime-nac cycle: %d sessions, %d tenants, "
                           "%d pushed, %d errors, %d dropped unattributed",
                           len(sessions), len(out), pushed, errs, dropped)
        else:
            logger.info("realtime nac sync cycle: %d sessions, %d tenants, %d pushed, "
                        "%d dropped unattributed", len(sessions), len(out), pushed, dropped)
        # The cycle upserted CPPM-derived sessions into NetBox (only-add-missing)
        # — drop + re-fetch the netbox_ips / netbox_devices tenant caches so a
        # non-admin viewer sees the new IP/device records immediately. Only when
        # the cycle actually pushed something (avoids a per-cycle fetch when the
        # loop has nothing to do). Best-effort; refresh_module_cache swallows.
        if pushed > 0:
            self.refresh_module_cache("netbox_ips")
            self.refresh_module_cache("netbox_devices")
        return {"results": out, "dropped_unattributed": dropped,
                "sessions_total": len(sessions),
                "pull_errors": pull.get("errors", [])}

    async def run_realtime_nac_sync_loop(self):
        """Periodically pull recent CPPM sessions → NetBox per the configured
        interval (default 60s, lookback 2 min).

        Reads the config fresh each cycle (enabled / interval / lookback /
        defaults / concurrency) so a WebUI change takes effect without a
        restart. Disabled → short sleep + re-check. Skips a cycle entirely if no
        NAC spoke or NetBox is offline. Staggered ~75s after startup so it
        doesn't simultaneous-fire with the other heavy syncs.
        """
        await asyncio.sleep(75)  # let spokes connect; stagger after the other syncs
        while True:
            try:
                cfg = self._rt_nac_cfg()
                nac = self._rt_nac_spoke()
                nac_up = bool(nac) and nac not in self._nac_unconfigured_spokes
                ipam_up = bool(self._rt_ipam_spoke())
                if cfg.get("enabled", False) and nac_up and ipam_up:
                    await self.run_realtime_nac_sync_all()
                delay = self._rt_nac_interval() if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] realtime-nac loop cycle failed: %s", e)
                await asyncio.sleep(60)