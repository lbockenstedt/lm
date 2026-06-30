"""Firewall → NetBox device-discovery sync subsystem for the Hub.

Mirrors ``vm_sync.py`` (NetBox is the **sink**, payload carries ``replace=True``,
per-tenant loop, tenant-scoped replace-delete) and ``endpoint_sync.py``
(registry / loop / per-tenant last-sync status / UI-source-picker patterns).
``api.py`` routes call ``hub.FIREWALL_DISCOVERY_SOURCES``, ``hub.sync_tenant_devices()``,
``hub.run_fw_discovery_sync_all()``, ``hub._fw_discovery_source()``,
``hub._fw_discovery_cfg()`` — all resolve via inheritance once
``FwDiscoverySyncMixin`` is added to ``LabManagerHub`` bases. The method bodies
take ``self`` and use the same state/spoke helpers as the other syncs, so there
is no rename and no churn.

The firewall (OPNsense) is the source of truth for *what is on the network*:
DHCP leases (dynamic IPs + hostnames) and the ARP table (every IP↔MAC pair the
firewall has recently spoken to — including **static-IP** devices DHCP can't
see, which is the gap that left their NetBox IP records without a
``mac_address`` and broke the CPPM endpoint sync's IP→MAC resolution). Each
cycle the hub pulls both, merges/dedups, **attributes each record to a tenant
by prefix containment** (a device's IP must sit inside one of the tenant's
NetBox prefixes), and pushes per-tenant to the netbox spoke via
``NETBOX_SYNC_DEVICES``. Discovered MACs written onto NetBox IP records then
feed the existing IPAM→CPPM endpoint sync. Unmatched IPs (no tenant prefix
contains them) are dropped + counted — NetBox stays tenant-authoritative, no
orphan devices.

A key difference from vm_sync/endpoint_sync: firewall discovery is **not
tenant-scoped at the source** (DHCP/ARP are per-firewall, per-subnet, not
per-tenant). So the hub pulls once per cycle, attributes by prefix, then pushes
per-tenant — whereas vm_sync/endpoint_sync pull per-tenant (each tenant has its
own proxmox_tag / netbox_tenant_slug scope). The firewall source is selectable
via the ``source`` config field (default "opnsense"); the pull subset via
``source_data`` (``both``/``dhcp``/``arp``). Adding a firewall product is a
one-entry addition to ``FIREWALL_DISCOVERY_SOURCES`` below + a spoke that
implements the dhcp/arp commands.

This module is a **leaf**: it imports only stdlib + ``access.fetch_tenant_prefixes``
(a sibling leaf that itself imports neither ``main`` nor ``api``). It MUST NOT
import ``main`` or ``api`` (no back-import — that would create a cycle, since
``main`` imports this module to pull in the mixin). Dependency direction is
``main → fw_discovery_sync`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import re
import time
import asyncio
import datetime as _dt
import ipaddress
import logging
from typing import Any, Dict, List, Optional, Tuple

try:
    from access import fetch_tenant_prefixes  # sibling leaf (no main/api back-import)
except Exception:  # pragma: no cover - access always importable in-app
    fetch_tenant_prefixes = None  # type: ignore

logger = logging.getLogger("Hub")


class FwDiscoverySyncMixin:
    """Pulls DHCP leases + the ARP table from a firewall source spoke, attributes
    each discovered device to a tenant by prefix containment, and pushes the
    per-tenant device set to the netbox (IPAM) spoke via ``NETBOX_SYNC_DEVICES``
    so NetBox DCIM devices + IP records mirror what the firewall actually sees
    on the network — tenant-tagged, with ``custom_fields.mac_address`` on the IP
    (which feeds the IPAM→CPPM endpoint sync). The firewall source is selectable
    via the ``source`` config field (default "opnsense"); the pull subset via
    ``source_data`` (``both``/``dhcp``/``arp``). Adding a firewall product is a
    one-entry addition to ``FIREWALL_DISCOVERY_SOURCES`` below + a spoke that
    implements the dhcp/arp commands. The firewall is the source of truth: each
    sync is authoritative for the tenant (payload carries replace=True → the
    spoke overwrites that tenant's discovered-device set to match, deleting
    stale records). The netbox write handler (``NETBOX_SYNC_DEVICES`` /
    ``sync_devices``) lives in the external netbox spoke repo (not in this
    tree); the hub only schedules + relays + records per-tenant last-sync
    status.
    #
    # FIREWALL_DISCOVERY_SOURCES maps a source name → how the hub talks to that
    # product:
    #   module_type    : spoke module type to resolve (get_all_spokes_by_type)
    #   dhcp_command   : command to fetch DHCP leases (dynamic IPs + hostnames)
    #   arp_command    : command to fetch the ARP table (static-IP devices too)
    #   label          : human label for the WebUI source selector + the push
    #                    payload's ``source`` field
    # The spoke contract for <dhcp_command>: request {"limit": 0} (0 = bypass the
    # spoke's interactive 200-row cap so the sync gets the full lease set);
    # response {"status":"SUCCESS","data":[{ip,hostname,mac,lease_end}, ...]}.
    # For <arp_command>: request {}; response {"status":"SUCCESS",
    # "data":[{ip,mac,hostname,interface}, ...]}. The hub normalizes MACs and
    # merges/dedups; the netbox sink re-normalizes defensively.
    #
    # The netbox spoke (module_type "ipam") is the device-record writer today. It
    # is not in FIREWALL_DISCOVERY_SOURCES (that registry is the *pull* side);
    # the push command + target module are fixed below.
    """

    FIREWALL_DISCOVERY_SOURCES: Dict[str, Dict[str, str]] = {
        "opnsense": {
            "module_type": "firewall",
            "dhcp_command": "OPNSENSE_GET_DHCP_LEASES",
            "arp_command": "OPNSENSE_GET_ARP_TABLE",
            "label": "OPNsense",
        },
    }

    # NetBox (IPAM spoke) is the device-record writer. Fixed today.
    _FW_DISCOVERY_TARGET_MODULE = "ipam"
    _FW_DISCOVERY_PUSH_COMMAND = "NETBOX_SYNC_DEVICES"

    _FW_DISCOVERY_CFG_KEY = "opnsense_netbox_device_sync"

    # ── config helpers ──────────────────────────────────────────────────────

    def _fw_discovery_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh (enabled/source/source_data/mode/interval/
        daily_time/firewall_id/defaults)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._FW_DISCOVERY_CFG_KEY, {})) or {}

    def _fw_discovery_source(self) -> Dict[str, str]:
        """Resolve the configured firewall source registry entry (falls back to OPNsense)."""
        name = str(self._fw_discovery_cfg().get("source", "opnsense")).strip().lower()
        return self.FIREWALL_DISCOVERY_SOURCES.get(name) or self.FIREWALL_DISCOVERY_SOURCES["opnsense"]

    def _fw_firewall_spokes(self) -> List[str]:
        """Connected firewall spoke ids to pull from this cycle.

        A pinned ``firewall_id`` (→ ``get_spoke_for_firewall``) scopes the pull
        to one firewall; unset → every connected firewall spoke
        (``get_all_spokes_by_type("firewall")``). Empty when none are connected.
        """
        cfg = self._fw_discovery_cfg()
        pinned = str(cfg.get("firewall_id") or "").strip()
        if pinned:
            sid = self.get_spoke_for_firewall(pinned)
            return [sid] if sid else []
        return list(self.get_all_spokes_by_type("firewall") or [])

    def _fw_discovery_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        try:
            n = int(self._fw_discovery_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        return max(1, min(8, n))

    def _fw_discovery_next_delay(self, cfg: Dict[str, Any]) -> float:
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
                logger.debug("fw discovery sync: bad daily_time %r — falling back to interval", hhmm)
        interval = 3600
        try:
            interval = int(cfg.get("interval_seconds", 3600))
        except (TypeError, ValueError):
            interval = 3600
        return max(60.0, float(interval))

    # ── pull / attribute / push ─────────────────────────────────────────────

    @staticmethod
    def _fw_norm_mac(m: Any) -> str:
        """Canonical lower-colon MAC (``aa:bb:cc:dd:ee:ff``) for dedup + payload.

        '' for an absent/unknown MAC — the netbox sink tolerates a blank mac
        (it keys device matching by IP). Non-hex garbage is returned stripped
        lower so two spellings of the same MAC still dedup.
        """
        s = str(m or "").strip().lower()
        if not s or s == "unknown":
            return ""
        hexd = re.sub(r"[^0-9a-f]", "", s)
        if len(hexd) == 12:
            return ":".join(hexd[i:i + 2] for i in range(0, 12, 2))
        return s

    async def _fw_pull_discovered(self) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
        """Pull DHCP leases + ARP from every configured firewall spoke, merge + dedup.

        Returns ``(records, pull_info)`` where each record is
        ``{ip, mac, hostname}`` (mac normalized, ''/unknown stripped to '') and
        ``pull_info`` is ``{"errors": [<per-spoke parse/transport errors>]}``.
        Dedup is by MAC (primary) then IP — a device with no MAC keys by its IP.
        DHCP hostnames win over ARP hostnames on merge.
        """
        se = self._fw_discovery_source()
        cfg = self._fw_discovery_cfg()
        src_data = str(cfg.get("source_data", "both")).strip().lower()
        want_dhcp = src_data in ("both", "dhcp")
        want_arp = src_data in ("both", "arp")
        spokes = self._fw_firewall_spokes()
        raw: List[Dict[str, str]] = []
        errors: List[str] = []
        if not spokes:
            return [], {"errors": ["no firewall spoke connected"]}

        async def _fetch(sid: str, cmd: str, payload: Dict[str, Any], tag: str) -> None:
            try:
                r = await self.request_response(sid, cmd, payload, timeout=30.0)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
                if isinstance(d, dict) and d.get("status") == "ERROR":
                    errors.append(f"{tag}({sid}): {d.get('message', 'error')}")
                    return
                rows = (d.get("data") if isinstance(d, dict) else None) or []
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    ip = str(row.get("ip") or "").strip()
                    mac = self._fw_norm_mac(row.get("mac"))
                    hostname = str(row.get("hostname") or "").strip()
                    if hostname == "unknown":
                        hostname = ""
                    if ip == "unknown":
                        ip = ""
                    if not ip and not mac:
                        continue  # nothing to attribute or push
                    raw.append({"ip": ip, "mac": mac, "hostname": hostname, "_src": tag})
            except Exception as e:
                errors.append(f"{tag}({sid}): {e}")

        fetches = []
        for sid in spokes:
            if want_dhcp:
                fetches.append(_fetch(sid, se.get("dhcp_command", "OPNSENSE_GET_DHCP_LEASES"),
                                      {"limit": 0}, "DHCP"))
            if want_arp:
                fetches.append(_fetch(sid, se.get("arp_command", "OPNSENSE_GET_ARP_TABLE"),
                                      {}, "ARP"))
        await asyncio.gather(*fetches, return_exceptions=True)

        # Merge + dedup: key by MAC (primary), else by ip:<ip>. DHCP hostname
        # preferred; fill in ip/mac the other source supplied.
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
                if rec.get("_src") == "dhcp" and rec.get("hostname"):
                    ex["hostname"] = rec["hostname"]
                elif not ex.get("hostname") and rec.get("hostname"):
                    ex["hostname"] = rec["hostname"]
                if not ex.get("ip") and ip:
                    ex["ip"] = ip
                if not ex.get("mac") and mac:
                    ex["mac"] = mac
        return list(merged.values()), {"errors": errors}

    async def _fw_attribute(self, records: List[Dict[str, str]]
                            ) -> Tuple[Dict[str, List[Dict[str, str]]], int]:
        """Bucket discovered records by tenant via prefix containment.

        Builds the tenant→networks map once per cycle (concurrent prefix fetch,
        bounded so hundreds of tenants don't stampede the netbox spoke), then
        assigns each record to the first tenant whose prefix contains its IP.
        Records with no IP, an unparseable IP, or an IP no tenant owns are
        ``dropped`` (counted) — keeps NetBox tenant-authoritative, no orphans.
        Returns ``({tenant_id: [records]}, dropped_count)``.
        """
        tenants = (self.state.tenant_state or {}).get("tenants", {}) or {}
        tids = [str(tid) for tid in tenants.keys()]
        nets_by_tid: Dict[str, List[Any]] = {}
        if fetch_tenant_prefixes is not None and tids:
            sem = asyncio.Semaphore(8)

            async def _nets_for(tid: str):
                async with sem:
                    try:
                        prefs = await fetch_tenant_prefixes(self, tid)
                    except Exception:
                        prefs = []
                    nets: List[Any] = []
                    for p in prefs or []:
                        try:
                            nets.append(ipaddress.ip_network(str(p), strict=False))
                        except Exception:
                            pass
                    return tid, nets

            for tid, nets in await asyncio.gather(*(_nets_for(tid) for tid in tids)):
                nets_by_tid[tid] = nets

        buckets: Dict[str, List[Dict[str, str]]] = {}
        dropped = 0
        for rec in records:
            ip_s = (rec.get("ip") or "").split("/")[0].strip()
            if not ip_s:
                dropped += 1
                continue
            try:
                addr = ipaddress.ip_address(ip_s)
            except Exception:
                dropped += 1
                continue
            matched: Optional[str] = None
            for tid in tids:
                for net in nets_by_tid.get(tid) or []:
                    if addr in net:
                        matched = tid
                        break
                if matched:
                    break
            if matched:
                buckets.setdefault(matched, []).append(rec)
            else:
                dropped += 1
        return buckets, dropped

    async def _fw_push_tenant(self, tenant_id: str,
                              devices: List[Dict[str, str]]) -> Dict[str, Any]:
        """Push one tenant's discovered devices to NetBox via NETBOX_SYNC_DEVICES.

        Records the per-tenant last-sync status (success/error/skipped). The
        payload carries ``replace=True`` so the sink overwrites the tenant's
        discovered-device set to match (stale ones deleted), and ``defaults``
        (role/device_type/site slugs) for creation. Idempotent + best-effort: a
        netbox outage or an unbound tenant yields an error/skipped status, never
        an unhandled exception (the loop depends on this).
        """
        now = time.time()
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "discovered_total": len(devices)}
        netbox = self.get_spoke_by_type(self._FW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
            await self.simulations_store.set_fw_discovery_sync_status(tenant_id, status)
            return status
        if not netbox_slug:
            status = {**base, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0,
                      "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
            await self.simulations_store.set_fw_discovery_sync_status(tenant_id, status)
            return status
        defaults = self._fw_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name,
                   "source": self._fw_discovery_source().get("label", "OPNsense"),
                   "replace": True, "devices": devices, "defaults": defaults}
        try:
            rr = await self.request_response(netbox, self._FW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(devices)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            logger.info("fw discovery sync tenant=%s(%s) result status=%s sent=%d "
                        "pushed=%d skipped=%d deleted=%d errors=%d",
                        tenant_id, tenant_name,
                        "success" if rstatus != "ERROR" else "error",
                        len(devices), pushed, skipped, deleted, errors)
            status = {**base, "status": "success" if rstatus != "ERROR" else "error",
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(devices)} device(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        except Exception as e:
            logger.debug("fw discovery push for %s failed: %s", tenant_id, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        await self.simulations_store.set_fw_discovery_sync_status(tenant_id, status)
        return status

    # ── entry points ────────────────────────────────────────────────────────

    async def sync_tenant_devices(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant Firewall → NetBox sync ('Sync now' for one tenant).

        Pulls globally (per-firewall), attributes by prefix, then pushes only
        ``tenant_id``. Returns that tenant's status, annotated with the cycle's
        global ``discovered_total_global`` and ``dropped_unattributed`` for the
        UI summary. A tenant with no attributed devices still gets a pushed
        status (the sink's replace-delete then reconciles that tenant's set).
        """
        records, pull = await self._fw_pull_discovered()
        buckets, dropped = await self._fw_attribute(records)
        status = await self._fw_push_tenant(tenant_id, buckets.get(tenant_id, []))
        status["discovered_total_global"] = len(records)
        status["dropped_unattributed"] = dropped
        status["pull_errors"] = pull.get("errors", [])
        return status

    async def run_fw_discovery_sync_all(self) -> Dict[str, Any]:
        """Full cycle: pull → attribute → push every attributed tenant.

        Tenants are pushed concurrently with a bounded semaphore. Returns
        ``{"results": [<per-tenant status>], "dropped_unattributed": N,
        "discovered_total": M}``. Called by the background loop (which discards
        the return) and the all-tenant 'Sync now'.
        """
        records, pull = await self._fw_pull_discovered()
        buckets, dropped = await self._fw_attribute(records)
        tids = list(buckets.keys())
        if not tids:
            logger.info("fw discovery sync cycle: %d records pulled, 0 tenants matched, "
                        "%d dropped unattributed", len(records), dropped)
            return {"results": [], "dropped_unattributed": dropped,
                    "discovered_total": len(records)}
        sem = asyncio.Semaphore(self._fw_discovery_concurrency())

        async def _one(tid: str):
            async with sem:
                try:
                    return await self._fw_push_tenant(tid, buckets.get(tid, []))
                except Exception as e:  # _fw_push_tenant swallows; never let one task kill the gather
                    logger.debug("fw discovery gather tenant=%s: %s", tid, e)
                    return None

        results = await asyncio.gather(*(_one(tid) for tid in tids))
        out = [r for r in results if r]
        pushed = sum(int(r.get("pushed", 0)) for r in out)
        logger.info("fw discovery sync cycle: %d records, %d tenants, %d pushed, "
                    "%d dropped unattributed", len(records), len(out), pushed, dropped)
        return {"results": out, "dropped_unattributed": dropped,
                "discovered_total": len(records)}

    async def run_fw_discovery_sync_loop(self):
        """Periodically sync firewall-discovered devices → NetBox per schedule.

        Reads the config fresh each cycle (enabled / source / source_data / mode
        / interval / daily time / firewall_id) so a WebUI change takes effect
        without a restart. Disabled → short sleep + re-check. Skips a cycle
        entirely if no firewall spoke or NetBox is offline. Staggered ~60s after
        the vm-sync loop (45s) and endpoint-sync loop (30s) so the three heavy
        syncs don't simultaneous-fire on startup.
        """
        await asyncio.sleep(60)  # let spokes connect; stagger after the other two syncs
        while True:
            try:
                cfg = self._fw_discovery_cfg()
                se = self._fw_discovery_source()
                fw_up = bool(self._fw_firewall_spokes())
                if cfg.get("enabled", False) and fw_up and \
                        self.get_spoke_by_type(self._FW_DISCOVERY_TARGET_MODULE):
                    await self.run_fw_discovery_sync_all()
                delay = self._fw_discovery_next_delay(cfg) if cfg.get("enabled", False) else 60
                await asyncio.sleep(delay)
            except Exception as e:
                logger.debug("fw discovery sync loop: %s", e)
                await asyncio.sleep(60)