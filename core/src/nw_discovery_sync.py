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
import datetime as _dt
import logging
import re
from typing import Any, Dict, List, Tuple

try:
    from access import attribute_by_prefix, norm_mac  # sibling leaf (no main/api back-import)
except Exception:  # pragma: no cover - access always importable in-app
    attribute_by_prefix = None  # type: ignore
    norm_mac = None  # type: ignore
from access import unwrap_spoke  # sibling leaf (no main/api back-import)

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
    #   mac_command   : command to fetch a device's MAC table (same request/
    #                   response shape; rows are {mac, vlan, interface} — NO ip,
    #                   so they can't be tenant-attributed and are pushed
    #                   UNSCOPED so the MAC is still recorded on a global device
    #                   carrying its source switch/port). Optional — a product
    #                   with no MAC-table command is ARP-only.
    #   label         : human label for the WebUI source selector + the push
    #                   payload's ``source`` field (used by the netbox sink as
    #                   the discovered_from ownership tag).
    NW_DISCOVERY_SOURCES: Dict[str, Dict[str, str]] = {
        "nw": {
            "module_type": "nw",
            "arp_command": "NW_GET_ARP",
            "mac_command": "NW_GET_MAC_TABLE",
            "label": "Network Devices",
        },
    }

    # NetBox (IPAM spoke) is the device-record writer. Fixed today.
    _NW_DISCOVERY_TARGET_MODULE = "ipam"
    _NW_DISCOVERY_PUSH_COMMAND = "NETBOX_SYNC_DEVICES"
    _NW_DISCOVERY_CFG_KEY = "nw_netbox_device_sync"

    # POLL NOW: per-device full poll (probe+info+interfaces+arp+mac) + push the
    # device + its interfaces to NetBox as a dcim.device inventory record (a
    # different sink from the ARP-neighbor→endpoint NETBOX_SYNC_DEVICES flow).
    _NW_POLL_COMMAND = "NW_POLL"
    _NW_DEVICE_PUSH_COMMAND = "NETBOX_SYNC_NW_DEVICE"

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
        """Pull the ARP table (and MAC table, when the source provides a
        ``mac_command``) from every device on every connected nw spoke, merge +
        dedup. Returns ``(records, pull_info)`` where each record is
        ``{ip, mac, hostname, source_switch_name, source_switch_ip,
        source_switch_port}`` (mac normalized; hostname "" — ARP/MAC tables
        carry no hostname) and ``pull_info`` is ``{"errors": [...]}``.

        The source-switch identity (device name + mgmt IP) + the port the MAC
        was seen on are attached to EVERY record so NetBox answers "where is
        this MAC?" — the device's switch_name/switch_ip/switch_port custom
        fields. MAC-table rows have no IP → they surface here as MAC-only
        records (``ip == ""``); the entry points split them off and push them
        UNSCOPED (no tenant) since prefix attribution needs an IP. Dedup by MAC
        (primary) then IP; a MAC seen on the MAC table that later shows an IP in
        ARP merges into one IP-bearing record (so the device gets its tenant).
        """
        se = self._nw_discovery_source()
        spokes = self._nw_spokes()
        raw: List[Dict[str, str]] = []
        errors: List[str] = []
        if not spokes:
            return [], {"errors": ["no nw spoke connected"]}

        # Bound the fetch phase so a single spoke backing M devices doesn't get
        # M concurrent request_response calls (2M if mac_command set: ARP+MAC).
        # The push phase at the bottom already uses this semaphore; the fetch
        # phase didn't — that was the only true stampede-to-one-spoke in the
        # codebase.
        fetch_sem = asyncio.Semaphore(self._nw_discovery_concurrency())

        async def _fetch(sid: str, device: Dict[str, Any]) -> None:
            did = device.get("id", "")
            dname = device.get("name", did)
            daddr = str(device.get("address") or "").strip()
            # Switch identity carried on every record so the NetBox device
            # records where the MAC was last seen.
            sw = {"source_switch_name": dname, "source_switch_ip": daddr}
            cmds = [se.get("arp_command", "NW_GET_ARP")]
            mac_cmd = se.get("mac_command")
            if mac_cmd:
                cmds.append(mac_cmd)
            for cmd in cmds:
                if not cmd:
                    continue
                try:
                    async with fetch_sem:
                        r = await self.request_response(sid, cmd, {"device_id": did},
                                                        timeout=30.0)
                    d = unwrap_spoke(r) if isinstance(r, dict) else {}
                    if isinstance(d, dict) and d.get("status") == "ERROR":
                        errors.append(f"{cmd}({dname}@{sid}): "
                                      f"{d.get('message', 'error')}")
                        continue
                    rows = (d.get("data") if isinstance(d, dict) else None) or []
                    for row in rows or []:
                        if not isinstance(row, dict):
                            continue
                        ip = str(row.get("ip") or "").strip()
                        if ip == "unknown":
                            ip = ""
                        mac = norm_mac(row.get("mac")) if norm_mac else \
                            str(row.get("mac") or "")
                        port = str(row.get("interface") or row.get("port") or "").strip()
                        if not ip and not mac:
                            continue
                        rec: Dict[str, str] = {"ip": ip, "mac": mac, "hostname": ""}
                        rec.update(sw)
                        if port:
                            rec["source_switch_port"] = port
                        raw.append(rec)
                except Exception as e:
                    errors.append(f"{cmd}({dname}@{sid}): {e}")

        fetches = []
        for sid in spokes:
            for device in self._nw_devices_for_spoke(sid):
                fetches.append(_fetch(sid, device))
        await asyncio.gather(*fetches, return_exceptions=True)

        # Merge + dedup: key by MAC (primary), else by ip:<ip>. Preserve the
        # source-switch fields (fill from whichever sighting carried them) so a
        # MAC-only sighting later enriched with an IP keeps its switch/port.
        merged: Dict[str, Dict[str, str]] = {}
        for rec in raw:
            mac, ip = rec.get("mac", ""), rec.get("ip", "")
            key = mac if mac else (f"ip:{ip}" if ip else "")
            if not key:
                continue
            ex = merged.get(key)
            if ex is None:
                merged[key] = dict(rec)
            else:
                if not ex.get("ip") and ip:
                    ex["ip"] = ip
                if not ex.get("mac") and mac:
                    ex["mac"] = mac
                for k in ("source_switch_name", "source_switch_ip",
                          "source_switch_port"):
                    if not ex.get(k) and rec.get(k):
                        ex[k] = rec[k]
        return list(merged.values()), {"errors": errors}

    async def _nw_attribute(self, records: List[Dict[str, str]]
                            ) -> Tuple[Dict[str, List[Dict[str, str]]], int]:
        """Bucket discovered records by tenant via prefix containment (delegate
        to the shared ``access.attribute_by_prefix``). Records with no IP, an
        unparseable IP, or an IP no tenant owns are ``dropped`` (counted)."""
        if attribute_by_prefix is None:  # pragma: no cover - access importable in-app
            return {}, len(records)
        return await attribute_by_prefix(self, records)

    async def _nw_push_unscoped_mac_sightings(self, devices: List[Dict[str, str]]
                                              ) -> Dict[str, Any]:
        """Push MAC-only sightings (no IP → no tenant) to NetBox UNSCOPED
        (``tenant_slug=""``, ``replace=False``) so a MAC seen on a switch MAC
        table but with no known IP is still recorded in NetBox, carrying its
        source switch/port (the "where is this MAC" answer).

        Only-add-missing (``replace=False``): a later IP sighting for that MAC
        adopts the device via the netbox sink's MAC-match tier and assigns the
        IP + tenant. Best-effort: never raises. Not persisted to the per-tenant
        store (it is global, not tenant-scoped) — logged + returned only.
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "message": "NetBox spoke not connected"}
        if not devices:
            return {"mac_only_total": 0, "last_sync_ts": now, "status": "success",
                    "pushed": 0, "errors": 0, "skipped": 0, "deleted": 0,
                    "message": "no MAC-only sightings"}
        defaults = self._nw_discovery_cfg().get("defaults", {}) or {}
        payload = {"tenant_id": "", "tenant_slug": "", "tenant_name": "",
                   "source": self._nw_discovery_source().get("label", "Network Devices"),
                   "replace": False, "devices": devices, "defaults": defaults}
        try:
            rr = await self.request_response(netbox, self._NW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", 0) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            rstate = "success" if rstatus != "ERROR" else "error"
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] nw-discovery mac-only unscoped "
                               "sent=%d status=%s pushed=%d skipped=%d errors=%d — %s",
                               len(devices), rstate, pushed, skipped, errors,
                               message or "NetBox error")
            else:
                logger.info("nw discovery sync mac-only unscoped sent=%d pushed=%d "
                            "skipped=%d", len(devices), pushed, skipped)
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": rstate, "pushed": pushed, "errors": errors,
                    "skipped": skipped, "deleted": deleted,
                    "message": message or (f"{len(devices)} MAC-only sighting(s) sent"
                                            if rstatus != "ERROR" else "NetBox error")}
        except Exception as e:
            logger.warning("[sync-error] nw-discovery mac-only unscoped push failed: %s", e)
            return {"mac_only_total": len(devices), "last_sync_ts": now,
                    "status": "error", "pushed": 0, "errors": 0, "skipped": 0,
                    "deleted": 0, "message": str(e)}

    async def _nw_push_tenant(self, tenant_id: str,
                              devices: List[Dict[str, str]]) -> Dict[str, Any]:
        """Push one tenant's nw-discovered devices to NetBox via
        NETBOX_SYNC_DEVICES. Records per-tenant last-sync status. Payload
        carries ``replace=True`` + ``source="Network Devices"`` (the netbox
        sink tags records nw-owned and replace-deletes only nw-owned records).
        Best-effort: never raises."""
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
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
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
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

    async def push_nw_device_inventory(self, device_cfg: Dict[str, Any],
                                       device_info: Dict[str, Any],
                                       interfaces: List[Dict[str, Any]]
                                       ) -> "tuple[Dict[str, Any], List[str], str]":
        """Push one nw device + its interfaces to NetBox as a dcim.device
        inventory record from **already-gathered** poll data (no re-poll).

        Shared by the manual ``poll_nw_device`` (Poll Now) and the spoke-driven
        auto-poll (NW_POLL_RESULT handler) so a device's inventory syncs to
        NetBox on its own ``poll_interval`` cadence. Tenant is attributed by the
        device's mgmt-address prefix containment. Returns
        ``(netbox_push_summary, errors, tenant_slug)`` — the resolved slug is
        threaded back so callers (poll_nw_device) can report it without
        re-attributing; best-effort — never raises.
        """
        errors: List[str] = []
        device_info = device_info or {}
        device_id = str(device_cfg.get("id", "") or device_cfg.get("name", ""))

        # Attribute tenant by the device's mgmt-address prefix containment.
        tenant_slug = ""
        if device_cfg.get("address") and attribute_by_prefix is not None:
            try:
                buckets, _dropped = await attribute_by_prefix(
                    self, [{"ip": str(device_cfg.get("address")), "mac": "",
                            "hostname": ""}])
                tid = next(iter(buckets), None)
                if tid:
                    tcfg = self.state.get_tenant(tid) or {}
                    tenant_slug = str(tcfg.get("netbox_tenant_slug") or "").strip()
            except Exception as e:
                logger.debug("nw device push tenant attribution for %s: %s",
                             device_id, e)

        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            errors.append("NetBox spoke not connected — poll only (no push)")
            return {}, errors, tenant_slug

        payload = {
            "device": {
                "id": device_cfg.get("id", device_id),
                "name": device_cfg.get("name", "") or device_id,
                "address": device_cfg.get("address", ""),
                "object_type": device_cfg.get("object_type", ""),
                "model": str(device_info.get("model", "") or ""),
                "serial": str(device_info.get("serial", "") or ""),
                "firmware": str(device_info.get("firmware", "") or ""),
            },
            "interfaces": interfaces or [],
            "tenant_slug": tenant_slug,
            "defaults": self._nw_discovery_cfg().get("defaults", {}) or {},
            "source": self._nw_discovery_source().get("label", "Network Devices"),
        }
        try:
            rr = await self.request_response(netbox, self._NW_DEVICE_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            netbox_push = {
                "status": str((rd or {}).get("status") or "").upper(),
                "pushed": int((rd or {}).get("pushed", 0) or 0),
                "errors": int((rd or {}).get("errors", 0) or 0),
                "skipped": int((rd or {}).get("skipped", 0) or 0),
                "deleted": int((rd or {}).get("deleted", 0) or 0),
                "interfaces_total": int((rd or {}).get("interfaces_total", 0) or 0),
                "message": (rd or {}).get("message", ""),
            }
            if netbox_push["status"] == "ERROR" or netbox_push["errors"]:
                errors.append(f"netbox: {netbox_push['message'] or 'error'}")
            return netbox_push, errors, tenant_slug
        except Exception as e:
            errors.append(f"netbox push: {e}")
            return {"status": "ERROR", "message": str(e)}, errors, tenant_slug

    async def apply_nw_auto_poll(self, device_id: str,
                                 pdata: Dict[str, Any]) -> None:
        """Handle a spoke-driven auto-poll result (NW_POLL_RESULT): warm the
        per-device cache so sub-views load instantly, then push the device +
        interfaces to NetBox on this device's own poll cadence (per-device
        inventory sync). Best-effort — a NetBox miss never blocks cache-warming.
        """
        if not isinstance(pdata, dict):
            return
        try:
            await self.nw_cache_set_poll(device_id, pdata)
        except Exception as e:
            logger.debug("nw auto-poll cache-warm %s failed: %s", device_id, e)
        # Per-device NetBox inventory sync (the "sync process" for nw devices).
        devices = (self.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        device_cfg = next((d for d in devices if isinstance(d, dict)
                           and d.get("id") == device_id), None)
        if not device_cfg:
            return
        try:
            _push, errs, _slug = await self.push_nw_device_inventory(
                device_cfg, pdata.get("device_info") or {},
                pdata.get("interfaces") or [])
            if errs:
                logger.debug("nw auto-poll NetBox push %s: %s", device_id, errs)
        except Exception as e:
            logger.warning("[sync-error] nw auto-poll NetBox push %s: %s",
                           device_id, e)

    async def poll_nw_device(self, device_id: str) -> Dict[str, Any]:
        """POLL NOW for one network device: send ``NW_POLL`` to the owning nw
        spoke, then push the device + its interfaces to NetBox via
        ``NETBOX_SYNC_NW_DEVICE`` (a dcim.device inventory upsert — distinct
        from the ARP-neighbor→endpoint ``NETBOX_SYNC_DEVICES`` flow).

        Tenant attribution is by the device's **management address** prefix
        containment (same ``attribute_by_prefix`` helper the discovery sync
        uses, applied to a one-record set). Unattributed → empty tenant_slug
        (global/unassigned in NetBox).

        Returns ``{status, reachable, latency_ms, device_info, interfaces, arp,
        mac_table, netbox_push, tenant_slug, errors, message}``. Best-effort:
        a NetBox push failure doesn't mask the poll results.
        """
        errors: List[str] = []
        cfg = (self.state.system_state.get("global_config", {})
               .get("nw_devices", []) or [])
        device_cfg = next((d for d in cfg if isinstance(d, dict)
                           and d.get("id") == device_id), None)
        if not device_cfg:
            return {"status": "ERROR", "reachable": False, "errors":
                    [f"device {device_id} not in nw_devices config"],
                    "message": f"device {device_id} not configured"}

        # Resolve the owning connected nw spoke (prefer the device's bound
        # spoke_id; else any connected nw spoke).
        spoke_id = ""
        bound = str(device_cfg.get("spoke_id") or "").strip()
        nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
        if bound and bound in nw_spokes:
            spoke_id = bound
        elif nw_spokes:
            spoke_id = nw_spokes[0]
        if not spoke_id:
            return {"status": "ERROR", "reachable": False, "errors":
                    ["no nw spoke connected"], "message": "no nw spoke connected"}

        # 1) Poll.
        poll_res: Dict[str, Any] = {}
        try:
            rr = await self.request_response(spoke_id, self._NW_POLL_COMMAND,
                                             {"device_id": device_id}, timeout=60.0)
            poll_res = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            if isinstance(poll_res, dict) and poll_res.get("status") == "ERROR":
                errors.append(f"poll: {poll_res.get('message', 'error')}")
                poll_res = {"data": {}}
        except Exception as e:
            errors.append(f"poll: {e}")
            poll_res = {"data": {}}

        pdata = poll_res.get("data") if isinstance(poll_res, dict) else None
        if not isinstance(pdata, dict):
            pdata = {}
        reachable = bool(pdata.get("reachable"))
        latency_ms = pdata.get("latency_ms")
        device_info = pdata.get("device_info") or {}
        interfaces = pdata.get("interfaces") or []
        arp = pdata.get("arp") or []
        mac_table = pdata.get("mac_table") or []
        endpoints = pdata.get("endpoints") or []
        vlans = pdata.get("vlans") or []
        poll_errors = poll_res.get("errors") if isinstance(poll_res, dict) else None
        if isinstance(poll_errors, list):
            errors.extend(poll_errors)

        # 2+3) Attribute tenant + push the device inventory to NetBox (shared
        # with the spoke-driven auto-poll via push_nw_device_inventory, which
        # also returns the resolved tenant_slug for the poll report).
        netbox_push, push_errors, tenant_slug = await self.push_nw_device_inventory(
            device_cfg, device_info, interfaces)
        errors.extend(push_errors)

        status = "SUCCESS" if (reachable and not errors) else (
            "PARTIAL" if reachable else "ERROR")
        return {
            "status": status,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "device_info": device_info,
            "interfaces": interfaces,
            "arp": arp,
            "mac_table": mac_table,
            "endpoints": endpoints,
            "vlans": vlans,
            "netbox_push": netbox_push,
            "tenant_slug": tenant_slug,
            "errors": errors,
            "message": (f"reachable={reachable}, "
                        f"{len(interfaces) if isinstance(interfaces, list) else 0} "
                        f"interface(s), "
                        f"{len(arp) if isinstance(arp, list) else 0} arp, "
                        f"{len(mac_table) if isinstance(mac_table, list) else 0} mac"
                        + (f", NetBox={netbox_push.get('status','n/a')}"
                           if netbox_push else "")
                        + (f", errors={len(errors)}" if errors else "")),
        }

    async def sync_tenant_nw_devices(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant NW → NetBox sync ('Sync now' for one tenant).

        Named ``sync_tenant_nw_devices`` (not ``sync_tenant_devices``) to avoid
        an MRO clash with ``FwDiscoverySyncMixin.sync_tenant_devices`` — both
        mixins are mixed into ``LabManagerHub`` together. Pulls globally,
        attributes by prefix, pushes only ``tenant_id``.
        """
        records, pull = await self._nw_pull_discovered()
        # On-demand single-tenant sync is IP-bearing only — MAC-only sightings
        # are global (no tenant) and are pushed by the full cycle, not here.
        ip_records = [r for r in records if r.get("ip")]
        buckets, dropped = await self._nw_attribute(ip_records)
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
        # Split IP-bearing (tenant-attributable) from MAC-only sightings (no IP
        # → no tenant). A MAC seen on a switch MAC table with no IP is pushed
        # unscoped so NetBox still records it with its switch/port; a later IP
        # sighting for that MAC adopts the device and assigns the tenant.
        ip_records = [r for r in records if r.get("ip")]
        mac_only = [r for r in records if not r.get("ip") and r.get("mac")]
        buckets, dropped = await self._nw_attribute(ip_records)
        tids = list(buckets.keys())
        if not tids and not mac_only:
            logger.info("nw discovery sync cycle: %d records pulled, 0 tenants matched, "
                        "%d dropped unattributed", len(records), dropped)
            return {"results": [], "dropped_unattributed": dropped,
                    "discovered_total": len(records), "mac_only_total": 0}
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
        # MAC-only sightings pushed unscoped (global, only-add-missing).
        mac_only_status = await self._nw_push_unscoped_mac_sightings(mac_only)
        merrs = int(mac_only_status.get("errors", 0) or 0)
        if errs > 0 or merrs > 0:
            logger.warning("[sync-error] nw-discovery cycle: %d records, %d tenants, "
                           "%d pushed, %d errors, %d dropped unattributed, "
                           "%d mac-only unscoped",
                           len(records), len(out), pushed, errs, dropped, len(mac_only))
        else:
            logger.info("nw discovery sync cycle: %d records, %d tenants, %d pushed, "
                        "%d dropped unattributed, %d mac-only unscoped",
                        len(records), len(out), pushed, dropped, len(mac_only))
        # Upserted NW-discovered devices into NetBox — refresh netbox_devices so
        # a non-admin viewer sees them immediately. Only when the cycle pushed.
        if pushed > 0:
            self.refresh_module_cache("netbox_devices")
        return {"results": out, "dropped_unattributed": dropped,
                "discovered_total": len(records),
                "mac_only_total": len(mac_only),
                "mac_only_status": mac_only_status}

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

    # ── NetBox → NW fleet import (NetBox is source of truth) ─────────────────
    # Reverse of the discovery/inventory push: devices already in NetBox whose
    # role matches the configured category are imported into the nw fleet so the
    # nw module manages them. A user who adds a device manually still gets it
    # written to NetBox (add_nw_device → push_nw_device_inventory), so NetBox
    # stays complete/authoritative either way.

    @staticmethod
    def _nw_role_norm(s: Any) -> str:
        """Normalize a role name/slug for case/space/hyphen-insensitive matching."""
        return re.sub(r"[\s_-]+", "", str(s or "").strip().lower())

    def _nw_import_cfg(self) -> Dict[str, Any]:
        """Module-level NetBox→NW import config from
        ``global_config.nw_netbox_import`` with defaults."""
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get("nw_netbox_import", {}) or {}
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (cfg.get("roles") or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }

    def _nw_import_object_type(self, cfg: Dict[str, Any], role: str,
                              device_type: str) -> str:
        """Map a NetBox role/device_type to an nw object_type via the config map
        (case-insensitive on role then device_type), else the default."""
        valid = {"aos_switch", "cx_switch", "ex_switch", "gateway"}
        norm_map = {self._nw_role_norm(k): v for k, v in cfg["object_type_map"].items()}
        for key in (role, device_type):
            mv = norm_map.get(self._nw_role_norm(key))
            if mv in valid:
                return mv
        dot = cfg["default_object_type"]
        return dot if dot in valid else "gateway"

    async def run_nw_netbox_import_all(self) -> Dict[str, Any]:
        """Pull NetBox devices, keep those whose role matches the configured
        category, and upsert them into the nw fleet (``source="netbox"``).

        NetBox is source of truth: name/address/object_type track NetBox each
        cycle, but a device's user-entered credentials / poll_interval / bound
        spoke are preserved. NetBox-sourced devices that no longer match (deleted
        or re-roled in NetBox) are removed; manually-added devices are untouched.
        Pushes the updated fleet to every connected nw spoke.
        """
        cfg = self._nw_import_cfg()
        if not cfg["enabled"] or not cfg["roles"]:
            return {"status": "SKIPPED", "reason": "disabled or no roles configured"}
        netbox = self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            return {"status": "ERROR", "message": "NetBox (ipam) spoke not connected"}

        rr = await self.request_response(netbox, "NETBOX_GET_DEVICES", {}, timeout=60.0)
        data = unwrap_spoke(rr) if isinstance(rr, dict) else {}
        devices = data.get("devices") if isinstance(data, dict) else []
        if not isinstance(devices, list):
            devices = []
        roles_norm = {self._nw_role_norm(r) for r in cfg["roles"]}
        matched = [d for d in devices if isinstance(d, dict)
                   and self._nw_role_norm(d.get("role")) in roles_norm]

        nw_spokes = list(self.get_all_spokes_by_type("nw") or [])
        target_spoke = cfg["spoke_id"] or (nw_spokes[0] if nw_spokes else "")

        gc = self.state.system_state.get("global_config", {})
        fleet = gc.get("nw_devices", []) or []
        by_id = {d.get("id"): d for d in fleet if isinstance(d, dict)}
        seen, added, updated = set(), 0, 0
        for d in matched:
            did = f"nbimport-{d.get('id')}"
            seen.add(did)
            addr = str(d.get("primary_ip") or "").split("/")[0]
            ot = self._nw_import_object_type(cfg, d.get("role"), d.get("device_type"))
            existing = by_id.get(did)
            if existing:
                # NetBox owns name/address/object_type/role; keep user creds etc.
                changed = False
                for k, v in (("name", d.get("name") or existing.get("name")),
                             ("address", addr or existing.get("address")),
                             ("object_type", ot),
                             ("netbox_role", d.get("role") or "")):
                    if existing.get(k) != v:
                        existing[k] = v
                        changed = True
                updated += 1 if changed else 0
            else:
                fleet.append({
                    "id": did, "name": d.get("name") or did, "address": addr,
                    "object_type": ot, "transport": "auto", "source": "netbox",
                    "netbox_id": d.get("id"), "netbox_role": d.get("role") or "",
                    "spoke_id": target_spoke, "poll_interval": None,
                })
                added += 1

        # Prune NetBox-sourced devices that no longer match (NetBox = SoT). Never
        # touch manually-added / discovery devices (source != "netbox").
        before = len(fleet)
        fleet[:] = [d for d in fleet if not (isinstance(d, dict)
                    and d.get("source") == "netbox" and d.get("id") not in seen)]
        removed = before - len(fleet)

        gc["nw_devices"] = fleet
        self.state.system_state["global_config"] = gc
        self.state._mark_dirty()

        pushed = 0
        for sid in nw_spokes:
            try:
                await self.push_config_to_spoke(sid)
                pushed += 1
            except Exception as e:  # noqa: BLE001
                logger.debug("nw import fleet push to %s failed: %s", sid, e)

        logger.info("nw netbox import: %d device(s) matched role(s) %s → +%d added, "
                    "~%d updated, -%d removed; pushed %d spoke(s)",
                    len(matched), cfg["roles"], added, updated, removed, pushed)
        return {"status": "SUCCESS", "matched": len(matched), "added": added,
                "updated": updated, "removed": removed, "pushed": pushed}

    async def run_nw_netbox_import_loop(self):
        """Periodic NetBox→NW fleet import per the configured interval. Reads
        config fresh each cycle; disabled → short re-check. Staggered ~110s after
        boot so it doesn't stampede with the discovery/fw loops."""
        await asyncio.sleep(110)
        while True:
            try:
                cfg = self._nw_import_cfg()
                if (cfg["enabled"] and cfg["roles"]
                        and self.get_all_spokes_by_type("nw")
                        and self.get_spoke_by_type(self._NW_DISCOVERY_TARGET_MODULE)):
                    await self.run_nw_netbox_import_all()
                await asyncio.sleep(max(60, cfg["interval"]) if cfg["enabled"] else 120)
            except Exception as e:
                logger.warning("[sync-error] nw netbox import loop failed: %s", e)
                await asyncio.sleep(120)