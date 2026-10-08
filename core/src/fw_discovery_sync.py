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
import asyncio
import datetime as _dt
import logging
from typing import Any, Dict, List, Tuple

try:
    from access import fetch_tenant_prefixes, attribute_by_prefix  # sibling leaf (no main/api back-import)
except Exception:  # pragma: no cover - access always importable in-app
    fetch_tenant_prefixes = None  # type: ignore
    attribute_by_prefix = None  # type: ignore
from access import unwrap_spoke  # sibling leaf (no main/api back-import)
from sync_loop import next_schedule_delay, run_sync_loop  # sibling leaf

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
        # LM's own Kea. When DHCP moves off the firewall and onto the DHCP
        # module, OPNsense stops seeing leases, so nothing reaches NetBox even
        # though the leases are plainly visible in the DHCP UI (which reads Kea
        # directly via the same command). No ARP table — Kea only knows what it
        # leased, so static-IP devices still need the firewall or nw/ARP source.
        # Kea answers with {"leases": [...]} in Kea-native field names, hence
        # rows_key + the ip-address/hw-address aliases in _fw_pull_discovered.
        "kea": {
            "module_type": "dhcp",
            "dhcp_command": "DHCP_LIST_LEASES",
            "rows_key": "leases",
            "label": "Kea (LM DHCP)",
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
        """Resolve ONE firewall source registry entry — the configured source,
        or (unset/"auto"/unknown) the first of whatever
        ``_fw_discovery_sources()`` (plural) resolves to this cycle. Kept for
        callers that only ever need a single representative source (e.g. the
        Setup UI's "active" display); the actual pull/push pipeline uses
        ``_fw_discovery_sources()``.
        """
        sources = self._fw_discovery_sources()
        return sources[0][1] if sources else self.FIREWALL_DISCOVERY_SOURCES["opnsense"]

    def _fw_discovery_sources(self) -> List[Tuple[str, Dict[str, str]]]:
        """Resolve every firewall source to pull from this cycle.

        The ``source`` config field:
          - unset / "" / "auto" (**the default**) → every registered source
            whose ``module_type`` currently has at least one connected spoke.
            This is the fix for the "DHCP sync was built for OPNsense, Kea was
            added later" gap: the "kea" registry entry has always been fully
            implemented (see ``FIREWALL_DISCOVERY_SOURCES`` above) but was
            unreachable because the old single-source resolver defaulted to
            "opnsense" — a Kea-only deployment (or one running both OPNsense
            and Kea) silently never synced Kea's dynamic leases into NetBox at
            all, even though nothing was actually broken in the Kea pull path
            itself. Every dynamic Kea lease now gets a corresponding NetBox
            device/IP record by default, same as OPNsense always has.
          - an explicit known name (e.g. ``"opnsense"``, ``"kea"``) → ONLY that
            one source — an operator who deliberately pinned a single source
            keeps that exact behavior, unchanged.
          - an explicit but unknown name → falls back to "auto" (same safety
            net the old code had in defaulting to OPNsense, just widened to
            "try every connected source" instead of one hard-coded product).

        Each resolved source is pulled AND PUSHED entirely separately (see
        ``run_fw_discovery_sync_all``/``sync_tenant_devices``) — the netbox
        sink's ``replace=True`` semantics are scoped per ``source`` label
        (``custom_fields.discovered_from``), so merging two sources' records
        into one push would let one source's replace-delete wrongly remove
        devices the OTHER source owns.
        """
        name = str(self._fw_discovery_cfg().get("source", "") or "").strip().lower()
        if name and name != "auto" and name in self.FIREWALL_DISCOVERY_SOURCES:
            return [(name, self.FIREWALL_DISCOVERY_SOURCES[name])]
        return [(n, se) for n, se in self.FIREWALL_DISCOVERY_SOURCES.items()
                if self.get_all_spokes_by_type(se.get("module_type", ""))]

    def _fw_firewall_spokes(self, source_entry: Dict[str, str]) -> List[str]:
        """Connected source spoke ids to pull from this cycle for ONE source.

        The spoke type comes from ``source_entry``'s ``module_type`` — it used
        to be hard-coded to ``"firewall"``, which made that registry field dead
        metadata and meant a non-firewall source (Kea) could never resolve a
        spoke. A pinned ``firewall_id`` (→ ``get_spoke_for_firewall``) scopes
        the pull to one firewall; it only applies to firewall-type sources.
        Unset (or a non-firewall source) → every connected spoke of the
        source's type. Empty when none connected.
        """
        cfg = self._fw_discovery_cfg()
        module_type = source_entry.get("module_type", "firewall")
        pinned = str(cfg.get("firewall_id") or "").strip()
        if pinned and module_type == "firewall":
            sid = self.get_spoke_for_firewall(pinned)
            return [sid] if sid else []
        return list(self.get_all_spokes_by_type(module_type) or [])

    def _fw_discovery_concurrency(self) -> int:
        """Max tenants pushed in parallel per cycle. Clamp 1..8; default 4."""
        try:
            n = int(self._fw_discovery_cfg().get("concurrency", 4))
        except (TypeError, ValueError):
            n = 4
        return max(1, min(8, n))

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

    async def _fw_pull_discovered(self, source_entry: Dict[str, str]
                                  ) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
        """Pull DHCP leases + ARP from every connected spoke of ONE source, merge + dedup.

        Returns ``(records, pull_info)`` where each record is
        ``{ip, mac, hostname}`` (mac normalized, ''/unknown stripped to '') and
        ``pull_info`` is ``{"errors": [<per-spoke parse/transport errors>]}``.
        Dedup is by MAC (primary) then IP — a device with no MAC keys by its IP.
        DHCP hostnames win over ARP hostnames on merge.
        """
        se = source_entry
        cfg = self._fw_discovery_cfg()
        src_data = str(cfg.get("source_data", "both")).strip().lower()
        want_dhcp = src_data in ("both", "dhcp")
        want_arp = src_data in ("both", "arp")
        spokes = self._fw_firewall_spokes(source_entry)
        raw: List[Dict[str, str]] = []
        errors: List[str] = []
        if not spokes:
            return [], {"errors": [f"no {se.get('label', 'firewall')} spoke connected"]}

        # Bound the fetch phase to match the push phase (which already uses
        # _fw_discovery_concurrency); without this the fetch gather fires every
        # firewall spoke's DHCP+ARP fetch concurrently with no cap.
        fetch_sem = asyncio.Semaphore(self._fw_discovery_concurrency())

        async def _fetch(sid: str, cmd: str, payload: Dict[str, Any], tag: str) -> None:
            try:
                async with fetch_sem:
                    r = await self.request_response(sid, cmd, payload, timeout=30.0)
                d = unwrap_spoke(r) if isinstance(r, dict) else {}
                if isinstance(d, dict) and d.get("status") == "ERROR":
                    errors.append(f"{tag}({sid}): {d.get('message', 'error')}")
                    return
                # Sources do not agree on where the list lives: OPNsense answers
                # under "data", Kea under "leases".
                rows_key = se.get("rows_key", "data")
                rows = (d.get(rows_key) if isinstance(d, dict) else None) or []
                for row in rows or []:
                    if not isinstance(row, dict):
                        continue
                    # ...nor on field names: Kea returns its native
                    # ip-address/hw-address rather than ip/mac.
                    ip = str(row.get("ip") or row.get("ip-address") or "").strip()
                    mac = self._fw_norm_mac(row.get("mac") or row.get("hw-address"))
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
            # Only pull ARP from a source that actually has an ARP table. This
            # used to default to the OPNsense command for ANY source, which
            # would send OPNSENSE_GET_ARP_TABLE to a Kea spoke that cannot
            # answer it and log a per-cycle error.
            if want_arp and se.get("arp_command"):
                fetches.append(_fetch(sid, se["arp_command"], {}, "ARP"))
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
                # The DHCP hostname is the authoritative one (the client told
                # the server its name); ARP only ever has a reverse-lookup
                # guess. This compared against lowercase "dhcp" while _fetch
                # tags rows "DHCP", so the rule never fired and an ARP hostname
                # could win.
                if str(rec.get("_src", "")).lower() == "dhcp" and rec.get("hostname"):
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

        Thin delegate to the shared ``access.attribute_by_prefix`` helper
        (extracted so the firewall-discovery sync and the realtime NAC→IPAM
        reverse sync share one attribution path). Builds the tenant→networks map
        once per cycle (concurrent prefix fetch, bounded so hundreds of tenants
        don't stampede the netbox spoke), then assigns each record to the first
        tenant whose prefix contains its IP. Records with no IP, an unparseable
        IP, or an IP no tenant owns are ``dropped`` (counted) — keeps NetBox
        tenant-authoritative, no orphans. Returns ``({tenant_id: [records]},
        dropped_count)``.
        """
        if attribute_by_prefix is None:  # pragma: no cover - access importable in-app
            return {}, len(records)
        return await attribute_by_prefix(self, records)

    async def _fw_push_tenant(self, tenant_id: str, devices: List[Dict[str, str]],
                              source_entry: Dict[str, str]) -> Dict[str, Any]:
        """Push one tenant's discovered devices FROM ONE SOURCE to NetBox via
        NETBOX_SYNC_DEVICES.

        Returns the status dict (tagged with this source's ``label``) but does
        NOT persist it — a tenant can have multiple sources pushed in the same
        cycle (see ``_fw_discovery_sources``), and the caller combines all of a
        tenant's per-source statuses into one before writing it via
        ``simulations_store.set_fw_discovery_sync_status``. The payload carries
        ``replace=True`` so the sink overwrites ONLY this source's slice of the
        tenant's discovered-device set (scoped by ``custom_fields.
        discovered_from`` on the netbox side) — never the other source's
        records. Idempotent + best-effort: a netbox outage or an unbound tenant
        yields an error/skipped status, never an unhandled exception (the loop
        depends on this).
        """
        now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tenant_cfg = self.state.get_tenant(tenant_id) or {}
        tenant_name = tenant_cfg.get("name") or tenant_id
        netbox_slug = str(tenant_cfg.get("netbox_tenant_slug") or "").strip()
        source_label = source_entry.get("label", "OPNsense")
        base = {"tenant_id": tenant_id, "tenant_name": tenant_name,
                "last_sync_ts": now, "discovered_total": len(devices),
                "source": source_label}
        netbox = self.get_spoke_by_type(self._FW_DISCOVERY_TARGET_MODULE)
        if not netbox:
            return {**base, "status": "error", "pushed": 0, "errors": 0,
                    "skipped": 0, "deleted": 0, "message": "NetBox spoke not connected"}
        if not netbox_slug:
            return {**base, "status": "skipped", "pushed": 0, "errors": 0,
                    "skipped": 0, "deleted": 0,
                    "message": "tenant not bound to NetBox (no netbox_tenant_slug)"}
        defaults = self._fw_discovery_cfg().get("defaults", {}) or {}
        # Source of truth for discovered devices: "external" (the discovery feed
        # owns the device → overwrite IP mac/dns_name + rename, populating the
        # MAC the NetBox→CPPM endpoint sync keys on) or "netbox" (NetBox owns the
        # device → only-add-missing: refresh last_seen only, never overwrite a
        # hand-managed device). Default netbox (a source of truth cannot be
        # overwritten); flip to external in the WebUI to repopulate MACs. An
        # unknown/blank value falls back to the default.
        sot_raw = str((self.state.system_state.get("global_config", {}) or {})
                     .get("source_of_truth", {}).get("device_sync", "netbox")
                     ).strip().lower()
        sot = sot_raw if sot_raw in ("external", "netbox") else "netbox"
        payload = {"tenant_id": tenant_id, "tenant_slug": netbox_slug,
                   "tenant_name": tenant_name,
                   "source": source_label,
                   "replace": True, "devices": devices, "defaults": defaults,
                   "source_of_truth": sot}
        try:
            rr = await self.request_response(netbox, self._FW_DISCOVERY_PUSH_COMMAND,
                                             payload, timeout=120.0)
            rd = unwrap_spoke(rr) if isinstance(rr, dict) else {}
            rstatus = str((rd or {}).get("status") or "").upper()
            pushed = int((rd or {}).get("pushed", len(devices)) or 0)
            errors = int((rd or {}).get("errors", 0) or 0)
            skipped = int((rd or {}).get("skipped", 0) or 0)
            deleted = int((rd or {}).get("deleted", 0) or 0)
            message = (rd or {}).get("message", "")
            # Any per-record errors must NOT be reported as a clean success —
            # a sink can return batch status SUCCESS alongside a nonzero error
            # count (e.g. "1 upserted, 180 errors"); treating that as
            # "success" (the previous behavior) hid a mostly-failed push
            # behind a green status.
            rstate = "success" if (rstatus != "ERROR" and errors == 0) else "error"
            # Hub-authoritative sync log: on a clean push keep the INFO summary,
            # but on any errors/failure emit a [sync-error] WARNING carrying the
            # sink's message (the first-error text) so the cause lands in the hub
            # log + GET_ERROR_LOGS (ab) — one place to go, no spoke-log dig.
            if errors > 0 or rstatus == "ERROR":
                logger.warning("[sync-error] fw-discovery tenant=%s(%s) source=%s status=%s "
                               "sent=%d pushed=%d skipped=%d deleted=%d errors=%d — %s",
                               tenant_id, tenant_name, source_label, rstate, len(devices),
                               pushed, skipped, deleted, errors, message or "NetBox error")
            else:
                logger.info("fw discovery sync tenant=%s(%s) source=%s result status=%s sent=%d "
                            "pushed=%d skipped=%d deleted=%d errors=%d",
                            tenant_id, tenant_name, source_label, rstate,
                            len(devices), pushed, skipped, deleted, errors)
            status = {**base, "status": rstate,
                      "pushed": pushed, "errors": errors, "skipped": skipped,
                      "deleted": deleted,
                      "message": message or (f"{len(devices)} device(s) sent"
                                              if rstatus != "ERROR" else "NetBox error")}
        except Exception as e:
            logger.warning("[sync-error] fw-discovery tenant=%s source=%s push failed: %s",
                           tenant_id, source_label, e)
            status = {**base, "status": "error", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": str(e)}
        return status

    def _fw_combine_statuses(self, statuses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Merge one tenant's per-source push statuses (from ``_fw_discovery_sources``'
        separate pulls/pushes) into the ONE combined record the status store/UI
        expects (unchanged schema — ``get_all_fw_discovery_sync_status`` /
        the Setup → Sync status card are single-source-shaped).

        Counters sum; ``status`` is "error" if any source errored, else
        "success" if any succeeded, else "skipped"; ``message`` concatenates
        each source's own message prefixed with its label so a per-source
        failure (e.g. "Kea: NetBox spoke not connected") stays visible even
        though the stored record is one dict. The full per-source breakdown
        also survives under ``sources`` for anything that wants it.
        """
        if len(statuses) == 1:
            out = dict(statuses[0])
            out["sources"] = [statuses[0]]
            return out
        any_error = any(s.get("status") == "error" for s in statuses)
        any_success = any(s.get("status") == "success" for s in statuses)
        combined_status = "error" if any_error else ("success" if any_success else "skipped")
        messages = [f"{s.get('source', '?')}: {s.get('message')}" for s in statuses if s.get("message")]
        return {
            "tenant_id": statuses[0].get("tenant_id"),
            "tenant_name": statuses[0].get("tenant_name"),
            "last_sync_ts": max((s.get("last_sync_ts") or "" for s in statuses), default=""),
            "discovered_total": sum(int(s.get("discovered_total", 0) or 0) for s in statuses),
            "status": combined_status,
            "pushed": sum(int(s.get("pushed", 0) or 0) for s in statuses),
            "errors": sum(int(s.get("errors", 0) or 0) for s in statuses),
            "skipped": sum(int(s.get("skipped", 0) or 0) for s in statuses),
            "deleted": sum(int(s.get("deleted", 0) or 0) for s in statuses),
            "message": "; ".join(messages),
            "sources": statuses,
        }

    # ── entry points ────────────────────────────────────────────────────────

    async def sync_tenant_devices(self, tenant_id: str) -> Dict[str, Any]:
        """On-demand single-tenant Firewall → NetBox sync ('Sync now' for one tenant).

        Pulls EVERY resolved source globally (per-firewall), attributes by
        prefix, pushes only ``tenant_id`` — once per source, so each source's
        replace-delete stays scoped to its own records — then combines the
        per-source statuses into one before persisting. Returns that combined
        status, annotated with the cycle's global ``discovered_total_global``
        and ``dropped_unattributed`` for the UI summary. A tenant with no
        attributed devices still gets a pushed status per source (the sink's
        replace-delete then reconciles that tenant's set for that source).
        """
        sources = self._fw_discovery_sources()
        if not sources:
            now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            tenant_name = (self.state.get_tenant(tenant_id) or {}).get("name") or tenant_id
            # "skipped", not "error": nothing is configured, which is not the
            # same as an attempted sync failing — this now matches
            # ``run_fw_discovery_sync_all``'s equivalent no-source path.
            status = {"tenant_id": tenant_id, "tenant_name": tenant_name, "last_sync_ts": now,
                      "discovered_total": 0, "status": "skipped", "pushed": 0, "errors": 0,
                      "skipped": 0, "deleted": 0, "message": "no firewall discovery source connected"}
            await self.simulations_store.set_fw_discovery_sync_status(tenant_id, status)
            return {**status, "discovered_total_global": 0, "dropped_unattributed": 0, "pull_errors": []}

        per_source_statuses = []
        discovered_total_global = 0
        dropped_total = 0
        pull_errors: List[str] = []
        for name, entry in sources:
            records, pull = await self._fw_pull_discovered(entry)
            discovered_total_global += len(records)
            src_errors = pull.get("errors", [])
            pull_errors.extend(f"{entry.get('label', name)}: {e}" for e in src_errors)
            buckets, dropped = await self._fw_attribute(records)
            dropped_total += dropped
            if src_errors:
                # A partial/failed pull for this source must never drive a
                # replace=True push — an incomplete record set would make the
                # sink delete devices that only the failed spoke(s) knew
                # about. Skip the push entirely and surface the pull failure
                # as this source's own status instead of silently proceeding
                # with whatever the OTHER (successful) spokes returned.
                now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                tenant_name = (self.state.get_tenant(tenant_id) or {}).get("name") or tenant_id
                per_source_statuses.append({
                    "tenant_id": tenant_id, "tenant_name": tenant_name, "last_sync_ts": now,
                    "discovered_total": len(records), "source": entry.get("label", name),
                    "status": "error", "pushed": 0, "errors": 0, "skipped": 0, "deleted": 0,
                    "message": f"pull failed, push skipped: {'; '.join(src_errors)}"})
                continue
            per_source_statuses.append(
                await self._fw_push_tenant(tenant_id, buckets.get(tenant_id, []), entry))

        combined = self._fw_combine_statuses(per_source_statuses)
        await self.simulations_store.set_fw_discovery_sync_status(tenant_id, combined)
        combined["discovered_total_global"] = discovered_total_global
        combined["dropped_unattributed"] = dropped_total
        combined["pull_errors"] = pull_errors
        return combined

    async def run_fw_discovery_sync_all(self) -> Dict[str, Any]:
        """Full cycle: pull → attribute → push every attributed tenant, for
        EVERY resolved source (see ``_fw_discovery_sources``).

        Each source is pulled and pushed to completion before the next source
        starts (never interleaved for the same tenant — avoids two sources'
        replace=True pushes racing each other), with tenants WITHIN one
        source's push still bounded/parallel via the semaphore. A tenant that
        appears in more than one source's buckets gets one combined status
        (see ``_fw_combine_statuses``) persisted once. A source whose pull had
        ANY error is skipped entirely for this cycle (never partially pushed —
        see ``simulations_store.get_fw_discovery_last_nonzero_tenants`` for why
        a clean pull also pushes an empty reconciling update to tenants that
        dropped to zero records). Returns ``{"results": [<per-tenant combined
        status>], "dropped_unattributed": N, "discovered_total": M}``. Called
        by the background loop (which discards the return) and the
        all-tenant 'Sync now'.
        """
        sources = self._fw_discovery_sources()
        if not sources:
            logger.info("fw discovery sync cycle: no firewall discovery source connected")
            return {"results": [], "dropped_unattributed": 0, "discovered_total": 0}

        sem = asyncio.Semaphore(self._fw_discovery_concurrency())
        per_tenant: Dict[str, List[Dict[str, Any]]] = {}
        discovered_total = 0
        dropped_total = 0

        for name, entry in sources:
            records, pull = await self._fw_pull_discovered(entry)
            discovered_total += len(records)
            src_errors = pull.get("errors", [])
            source_label = entry.get("label", name)
            if src_errors:
                # Same rule as sync_tenant_devices: a partial/failed pull must
                # never drive a replace=True push — proceeding here could
                # delete devices only a down spoke knew about. Skip the whole
                # source this cycle; the next successful cycle will catch up.
                logger.warning("[sync-error] fw-discovery source=%s pull failed (%s) — "
                               "skipping push this cycle to avoid an incomplete replace=True",
                               source_label, "; ".join(src_errors))
                continue
            buckets, dropped = await self._fw_attribute(records)
            dropped_total += dropped
            active_tids = set(buckets.keys())
            # Reconciliation: a tenant this source previously pushed a
            # NON-EMPTY device set for, but that now has zero current
            # records, would otherwise never get pushed again at all (buckets
            # has no entry for it) — leaving its stale NetBox devices behind
            # forever. Push an explicit empty replace=True for exactly those
            # tenants so the sink's own tenant+source-scoped delete reconciles
            # them, same as any other tenant's push.
            previous_tids = set(await self.simulations_store
                                .get_fw_discovery_last_nonzero_tenants(source_label))
            stale_tids = previous_tids - active_tids
            tids = sorted(active_tids | stale_tids)
            if not tids:
                await self.simulations_store.set_fw_discovery_last_nonzero_tenants(
                    source_label, [])
                continue

            async def _one(tid: str, entry=entry, buckets=buckets, name=name):
                async with sem:
                    try:
                        return tid, await self._fw_push_tenant(tid, buckets.get(tid, []), entry)
                    except Exception as e:  # never let one task kill the gather
                        logger.debug("fw discovery gather tenant=%s source=%s: %s", tid, name, e)
                        return tid, None

            results = await asyncio.gather(*(_one(tid) for tid in tids))
            for tid, status in results:
                if status:
                    per_tenant.setdefault(tid, []).append(status)
            await self.simulations_store.set_fw_discovery_last_nonzero_tenants(
                source_label, sorted(active_tids))

        if not per_tenant:
            logger.info("fw discovery sync cycle: %d records pulled across %d source(s), "
                        "0 tenants matched, %d dropped unattributed",
                        discovered_total, len(sources), dropped_total)
            return {"results": [], "dropped_unattributed": dropped_total,
                    "discovered_total": discovered_total}

        out = []
        for tid, statuses in per_tenant.items():
            combined = self._fw_combine_statuses(statuses)
            await self.simulations_store.set_fw_discovery_sync_status(tid, combined)
            out.append(combined)

        pushed = sum(int(r.get("pushed", 0)) for r in out)
        errs = sum(int(r.get("errors", 0)) for r in out)
        if errs > 0:
            logger.warning("[sync-error] fw-discovery cycle: %d records across %d source(s), "
                           "%d tenants, %d pushed, %d errors, %d dropped unattributed",
                           discovered_total, len(sources), len(out), pushed, errs, dropped_total)
        else:
            logger.info("fw discovery sync cycle: %d records across %d source(s), %d tenants, "
                        "%d pushed, %d dropped unattributed",
                        discovered_total, len(sources), len(out), pushed, dropped_total)
        # Pushed firewall interface/IP facts into NetBox — refresh netbox_devices
        # so a non-admin viewer sees them immediately. Only when the cycle pushed.
        if pushed > 0:
            self.refresh_module_cache("netbox_devices")
        return {"results": out, "dropped_unattributed": dropped_total,
                "discovered_total": discovered_total}

    async def run_fw_discovery_sync_loop(self):
        """Periodically sync firewall-discovered devices → NetBox per schedule.

        Reads the config fresh each cycle (enabled / source / source_data / mode
        / interval / daily time / firewall_id) so a WebUI change takes effect
        without a restart. Disabled → short sleep + re-check. Skips a cycle
        entirely if no firewall spoke or NetBox is offline. Staggered ~60s after
        the vm-sync loop (45s) and endpoint-sync loop (30s) so the three heavy
        syncs don't simultaneous-fire on startup.
        """
        def _guard() -> bool:
            cfg = self._fw_discovery_cfg()
            return bool(cfg.get("enabled", False)
                        and self._fw_discovery_sources()
                        and self.get_spoke_by_type(self._FW_DISCOVERY_TARGET_MODULE))

        def _delay() -> float:
            cfg = self._fw_discovery_cfg()
            if not cfg.get("enabled", False):
                return 60
            return next_schedule_delay(cfg, default_daily_time="02:00",
                                       log_name="fw discovery sync")

        # stagger 60s: let spokes connect; stagger after the other two syncs
        await run_sync_loop(stagger=60, guard=_guard,
                            body=self.run_fw_discovery_sync_all, delay=_delay,
                            error_label="fw-discovery loop cycle failed")