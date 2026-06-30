"""Network Devices → NetBox device-discovery sync subsystem for the Hub.

Mirrors ``fw_discovery_sync.py`` (NetBox is the **sink**, payload carries
``replace=True``, per-tenant loop, tenant-scoped replace-delete, prefix-
containment attribution, drop+count unattributed). ``api.py`` routes call
``hub.NW_DISCOVERY_SOURCES``, ``hub.sync_tenant_devices()`` (nw variant),
``hub.run_nw_discovery_sync_all()``, ``hub._nw_discovery_source()``,
``hub._nw_discovery_cfg()`` — all resolve via inheritance once
``NwDiscoverySyncMixin`` is added to ``LabManagerHub`` bases.

The nw spoke manages a fleet of switches + gateways (AOS-S / AOS-CX / Juniper
EX / Aruba-HPE gateway). Each device's **ARP table** is the IP↔MAC source of
truth for what is on the network (the MAC table alone has no IP, so it can't be
attributed by prefix). Each cycle the hub pulls ``NW_GET_ARP`` from every
device on every connected nw spoke, merges/dedups, **attributes each record to
a tenant by prefix containment** (the device IP must sit inside one of the
tenant's NetBox prefixes), and pushes per-tenant to the netbox spoke via
``NETBOX_SYNC_DEVICES`` with ``source="Network Devices"`` so the netbox sink
tags the records nw-owned (and replace-deletes only nw-owned records, never
touching opnsense-discovered ones). Unmatched IPs are dropped + counted —
NetBox stays tenant-authoritative, no orphan devices.

Like firewall discovery, nw discovery is **not tenant-scoped at the source**
(ARP is per-device, per-subnet), so the hub pulls once per cycle, attributes by
prefix, then pushes per-tenant. Adding another network-device product is a
one-entry addition to ``NW_DISCOVERY_SOURCES`` + a spoke implementing the arp
command.

This module is a **leaf**: it imports only stdlib + ``access`` helpers
(``fetch_tenant_prefixes`` / ``attribute_by_prefix`` / ``norm_mac`` — sibling
leaves that import neither ``main`` nor ``api``). It MUST NOT import ``main``
or ``api`` (dependency direction is ``main → nw_discovery_sync`` only).

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import time
import datetime as _dt
import logging
from typing import Any, Dict, List, Tuple

try:
    from access import attribute_by_prefix, norm_mac  # sibling leaf (no main/api back-import)
except Exception:  # pragma: no cover - access always importable in-app
    attribute_by_prefix = None  # type: ignore
    norm_mac = None  # type: ignore

logger = logging.getLogger("Hub")


class NwDiscoverySyncMixin:
    """Pulls the ARP table from every device on every connected nw spoke,
    attributes each IP↔MAC record to a tenant by prefix containment, and pushes
    the per-tenant device set to the netbox (IPAM) spoke via
    ``NETBOX_SYNC_DEVICES`` so NetBox DCIM devices + IP records mirror what the
    switches/gateways actually see on the network — tenant-tagged, with
    ``custom_fields.mac_address`` on the IP (which feeds the IPAM→CPPM endpoint
    sync). The nw source is selectable via ``source`` (default "nw"); adding a
    network-device product is a one-entry addition to ``NW_DISCOVERY_SOURCES``
    + a spoke implementing the arp command. The devices are the source of
    truth: each sync is authoritative for the tenant (replace=True → the sink
    overwrites that tenant's nw-discovered-device set to match, deleting stale
    records). The netbox write handler lives in the external netbox spoke repo.
    """

    # NW_DISCOVERY_SOURCES maps a source name → how the hub talks to that
    # product:
    #   module_type   : spoke module type to resolve (get_all_spokes_by_type)
    #   arp_command   : command to fetch a device's ARP table (request
    #                   {"device_id": <id>}; response {"status":"SUCCESS",
    #                   "data":[{ip, mac, interface}, ...]})
    #   label         : human label for the WebUI source selector + the push
    #                   payload's ``source`` field (used by the netbox sink as
    #                   the discovered_from ownership tag).
    NW_DISCOVERY_SOURCES: Dict[str, Dict[str, str]] = {
        "nw": {
            "module_type": "nw",
            "arp_command": "NW_GET_ARP",
            "label": "Network Devices",
        },
    }

    # NetBox (IPAM spoke) is the device-record writer. Fixed today.
    _NW_DISCOVERY_TARGET_MODULE = "ipam"
    _NW_DISCOVERY_PUSH_COMMAND = "NETBOX_SYNC_DEVICES"
    _NW_DISCOVERY_CFG_KEY = "nw_netbox_device_sync"

    # ── config helpers ──────────────────────────────────────────────────────

    def _nw_discovery_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/mode/interval/daily_time/
        defaults)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._NW_DISCOVERY_CFG_KEY, {})) or {}

    def _nw_discovery_source(self) -> Dict[str, str]:
        """Resolve the configured nw source registry entry (falls back to "nw")."""
        name = str(self._nw_discovery_cfg().get("source", "nw")).strip().lower()
        return self.NW_DISCOVERY_SOURCES.get(name) or self.NW_DISCOVERY_SOURCES["nw"]

    def _nw_spokes(self) -> List[str]:
        """Connected nw spoke ids to pull from this cycle."""
        return list(self.get_all_spokes_by_type("nw") or [])

    def _nw_devices_for_spoke(self, spoke_id: str) -> List[Dict[str, Any]]:
        """Devices bound to this nw spoke (or unbound devices when none are
        bound to it — single-product deployments don't bind spoke_id). Read
        from global_config so there's no extra round-trip."""
        devices = (self.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
        if not mine:
            mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
        return mine

    def _nw_discovery_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        try:
            n = int(self._nw_discovery_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        return max(1, min(8, n))

    def _nw_discovery_next_delay(self, cfg: Dict[str, Any]) -> float:
        """Seconds to sleep before the next scheduled sync, per the config mode.

        ``mode`` is ``"daily"`` (once a day at ``daily_time`` "HH:MM", 24h
        local) or interval (every ``interval_seconds``). Clamped to >= 60 s.
        """
        mode = str(cfg.get("mode", "interval")).strip().lower()
        if mode == "daily":
            hhmm = str(cfg.get("daily_time", "02:30")).strip()
            try:
                hh, mm = (int(p) for p in hhmm.split(":")[:2])
                now = _dt.datetime.now()
                target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
                if target <= now:
                    target += _dt.timedelta(days=1)
                return max(60.0, (target - now).total_seconds())
            except Exception:
                logger.debug("nw discovery sync: bad daily_time %r — falling back to interval", hhmm)
        interval = 3600
        try:
            interval = int(cfg.get("interval_seconds", 3600))
        except (TypeError, ValueError):
            interval = 3600
        return max(60.0, float(interval))

    # ── pull / attribute / push ─────────────────────────────────────────────

    async def _nw_pull_discovered(self) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
        """Pull the ARP table from every device on every connected nw spoke,
        merge + dedup. Returns ``(records, pull_info)`` where each record is
        ``{ip, mac, hostname}`` (mac normalized; hostname "" — ARP carries no
        hostname) and ``pull_info`` is ``{"errors": [...]}``. Dedup by MAC
        (primary) then IP.
        """
        se = self._nw_discovery_source()
        spokes = self._nw_spokes()
        raw: List[Dict[str, str]] = []
        errors: List[str] = []
        if not spokes:
            return [], {"errors": ["no nw spoke connected"]}

        async def _fetch(sid: str, device: Dict[str, Any]) -> None:
            did = device.get("id", "")
            dname = device.get("name", did)
            try:
                r = await self.request_response(sid, se.get("arp_command", "NW_GET_ARP"),
                                                {"device_id": did}, timeout=30.0)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
                if isinstance(d, dict) and d.get("status") == "ERROR":
                    errors.append(f"ARP({dname}@{sid}): {d.get('message', 'error')}")
                    return
                rows = (d.get("data") if isinstance(d, dict) else None) or []
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    ip = str(row.get("ip") or "").strip()
                    if ip == "unknown":
                        ip = ""
                    mac = norm_mac(row.get("mac")) if norm_mac else str(row.get("mac") or "")
                    if not ip and not mac:
                        continue
                    raw.append({"ip": ip, "mac": mac, "hostname": "", "_src": dname})
            except Exception as e:
                errors.append(f"ARP({dname}@{sid}): {e}")

        fetches = []
        for sid in spokes:
            for device in self._nw_devices_for_spoke(sid):
                fetches.append(_fetch(sid, device))
        await asyncio.gather(*fetches, return_exceptions=True)

        # Merge + dedup: key by MAC (primary), else by ip:<ip>.
        merged: Dict[str, Dict[str, str]] = {}
        for rec in raw:
            mac, ip = rec.get("mac", ""), rec.get("ip", "")
            key = mac if mac else (f"ip:{ip}" if ip else "")
            if not key:
                continue
            ex = merged.get(key)
            if ex is None:
                merged[key] = {"ip": ip, "mac": mac, "hostname": rec.get("hostname", "")}
            else:
                if not ex.get("ip") and ip:
                    ex["ip"] = ip
                if not ex.get("mac") and mac:
                    ex["mac"] = mac
        return list(merged.values()), {"errors": errors}

    async def _nw_attribute(self, records: List[Dict[str, str]]
                            ) -> Tuple[Dict[str, List[Dict[str, str]]], int]:
        """Bucket discovered records by tenant via prefix containment (delegate
        to the shared ``access.attribute_by_prefix``). Records with no IP, an
        unparseable IP, or an IP no tenant owns are ``dropped`` (counted)."""
        if attribute_by_prefix is None:  # pragma: no cover - access importable in-app
            return {}, len(records)
        return await attribute_by_prefix(self, records)

    async def _nw_push_tenant(self, tenant_id: str,
                              devices: List[Dict[str, str]]) -> Dict[str, Any]:
        """Push one tenant's nw-discovered devices to NetBox via
        NETBOX_SYNC_DEVICES. Records per-tenant last-sync status. Payload
        carries ``replace=True`` + ``source="Network Devices"`` (the netbox
        sink tags records nw-owned and replace-deletes only nw-owned records).
        Best-effort: never raises."""
        now = time.time()
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "discovered_total": len(devices)}
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
            await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
            return status
        if not netbox_slug:
            status = {**base, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0,
                      "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
            await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
            return status
        defaults = self._nw_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name,
                   "source": self._nw_discovery_source().get("label", "Network Devices"),
                   "replace": True, "devices": devices, "defaults": defaults}
        try:
            rr = await self.request_response(netbox, self._NW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(devices)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] nw-discovery tenant=%s(%s) status=%s "
                               "sent=%d pushed=%d skipped=%d deleted=%d errors=%d — %s",
                               tenant_id, tenant_name, rstate, len(devices),
                               pushed, skipped, deleted, errors, message or "NetBox error")
            else:
                logger.info("nw discovery sync tenant=%s(%s) result status=%s sent=%d "
                            "pushed=%d skipped=%d deleted=%d errors=%d",
                            tenant_id, tenant_name, rstate,
                            len(devices), pushed, skipped, deleted, errors)
            status = {**base, "status": rstate,
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(devices)} device(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        except Exception as e:
            logger.warning("[sync-error] nw-discovery tenant=%s push failed: %s",
                           tenant_id, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        await self.simulations_store.set_nw_discovery_sync_status(tenant_id, status)
        return status

    # ── entry points ────────────────────────────────────────────────────────

    async def sync_tenant_nw_devices(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant NW → NetBox sync ('Sync now' for one tenant).

        Named ``sync_tenant_nw_devices`` (not ``sync_tenant_devices``) to avoid
        an MRO clash with ``FwDiscoverySyncMixin.sync_tenant_devices`` — both
        mixins are mixed into ``LabManagerHub`` together. Pulls globally,
        attributes by prefix, pushes only ``tenant_id``.
        """
        records, pull = await self._nw_pull_discovered()
        buckets, dropped = await self._nw_attribute(records)
        status = await self._nw_push_tenant(tenant_id, buckets.get(tenant_id, []))
        status["discovered_total_global"] = len(records)
        status["dropped_unattributed"] = dropped
        status["pull_errors"] = pull.get("errors", [])
        return status

    async def run_nw_discovery_sync_all(self) -> Dict[str, Any]:
        """Full cycle: pull → attribute → push every attributed tenant
        concurrently (bounded). Returns ``{"results": [...],
        "dropped_unattributed": N, "discovered_total": M}``."""
        records, pull = await self._nw_pull_discovered()
        buckets, dropped = await self._nw_attribute(records)
        tids = list(buckets.keys())
        if not tids:
            logger.info("nw discovery sync cycle: %d records pulled, 0 tenants matched, "
                        "%d dropped unattributed", len(records), dropped)
            return {"results": [], "dropped_unattributed": dropped,
                    "discovered_total": len(records)}
        sem = asyncio.Semaphore(self._nw_discovery_concurrency())

        async def _one(tid: str):
            async with sem:
                try:
                    return await self._nw_push_tenant(tid, buckets.get(tid, []))
                except Exception as e:  # _nw_push_tenant swallows; never kill the gather
                    logger.debug("nw discovery gather tenant=%s: %s", tid, e)
                    return None

        results = await asyncio.gather(*(_one(tid) for tid in tids))
        out = [r for r in results if r]
        pushed = sum(int(r.get("pushed", 0)) for r in out)
        errs = sum(int(r.get("errors", 0)) for r in out)
        if errs > 0:
            logger.warning("[sync-error] nw-discovery cycle: %d records, %d tenants, "
                           "%d pushed, %d errors, %d dropped unattributed",
                           len(records), len(out), pushed, errs, dropped)
        else:
            logger.info("nw discovery sync cycle: %d records, %d tenants, %d pushed, "
                        "%d dropped unattributed", len(records), len(out), pushed, dropped)
        return {"results": out, "dropped_unattributed": dropped,
                "discovered_total": len(records)}

    async def run_nw_discovery_sync_loop(self):
        """Periodically sync nw-discovered devices → NetBox per schedule.

        Reads config fresh each cycle so a WebUI change takes effect without a
        restart. Disabled → short sleep + re-check. Skips a cycle if no nw
        spoke or NetBox is offline. Staggered ~75s after the fw-discovery loop
        (60s) so the heavy syncs don't simultaneous-fire on startup.
        """
        await asyncio.sleep(75)  # let spokes connect; stagger after fw-discovery
        while True:
            try:
                cfg = self._nw_discovery_cfg()
                nw_up = bool(self._nw_spokes())
                if cfg.get("enabled", False) and nw_up and \
                        self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE):
                    await self.run_nw_discovery_sync_all()
                delay = self._nw_discovery_next_delay(cfg) if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.warning("[sync-error] nw-discovery loop cycle failed: %s", e)
                await asyncio.sleep(60)