"""NetBox → Unbound/Kea auto-sync subsystem for the Hub.

NetBox is the source of truth for IPAM. This mixin keeps the DNS (Unbound) and
DHCP (Kea) spokes reconciled to NetBox on a periodic schedule, so an operator
who adds a reservation or a DNS name in NetBox sees it land in Kea/Unbound
without pressing a "Sync now" button.

Design mirrors the other discovery-sync mixins (``EndpointSyncMixin``,
``FwDiscoverySyncMixin`` …): a self-contained mixin added to ``LabManagerHub``
bases, driven by ``global_config["dns_dhcp_sync"]`` (``enabled`` default True,
``interval`` seconds default 300). The extraction+push helpers are shared by
both the background loop and the on-demand ``POST /api/dns/sync`` /
``POST /api/dhcp/sync`` routes so the two paths can never diverge.

The sync is **only-add-missing** on the spoke side (DNS_SYNC / DHCP_SYNC
compare against existing names/IPs and add what's absent), so re-running is
cheap and idempotent — it never clobbers records an operator added directly on
the resolver.

This module is a **leaf**: it imports only stdlib and must NOT import ``main``
or ``api`` (dependency direction is ``main → dns_dhcp_sync`` only).

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Tuple

from access import unwrap_spoke  # sibling leaf (no main/api back-import)
from sync_loop import run_sync_loop  # sibling leaf

logger = logging.getLogger("Hub")

_CFG_KEY = "dns_dhcp_sync"
_DEFAULT_INTERVAL = 300  # seconds


def build_dns_records(ips_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """NetBox IP list → Unbound A-record sync payload.

    An IP contributes a record only when it has a ``dns_name`` and a concrete
    address. Shared by the loop and ``POST /api/dns/sync`` so both build the
    identical payload.
    """
    records: List[Dict[str, Any]] = []
    for entry in (ips_data.get("ip_addresses") or []):
        dns_name = (entry.get("dns_name") or "").strip()
        address = (entry.get("address") or "").split("/")[0].strip()
        if dns_name and address:
            records.append({"name": dns_name, "type": "A", "value": address, "ttl": 300})
    return records


def build_dhcp_payload(pfx_data: Dict[str, Any],
                       ips_data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """NetBox prefixes + IPs → (subnets, reservations) Kea sync payload.

    Subnets come from prefixes (gateway/dns_servers off custom_fields); a
    reservation is minted for every IP carrying a ``custom_fields.mac_address``.
    Shared by the loop and ``POST /api/dhcp/sync``.

    Only prefixes explicitly opted into DHCP become Kea scopes — a bare
    top-level allocation (e.g. a tenant's whole /17) must never turn into a
    single giant scope covering the entire block. A prefix is eligible only
    when BOTH:
      - ``status`` is NOT ``container`` (NetBox's own convention for an
        aggregate/parent block that is never meant to hand out addresses
        directly — it exists only to be carved into child prefixes), and
      - ``custom_fields.dhcp_enabled`` is truthy — the explicit opt-in
        checkbox for "this specific prefix is a DHCP scope", so a tenant can
        allocate a large parent block and then carve out smaller
        active/dhcp-enabled child prefixes without the parent ever being
        synced as a scope itself.

    All other DHCP options (search domain, NTP servers, TFTP/boot file,
    NetBIOS servers, broadcast address, lease time, …) are likewise plain
    NetBox prefix ``custom_fields`` — see ``dhcp/src/kea_manager.py``'s
    ``_ADVANCED_OPTION_MAP`` for the full option → Kea option-data mapping.
    NetBox itself is still the single source of truth for a scope's config;
    this function only translates its custom fields into Kea's shape.
    """
    def _csv(raw: str) -> List[str]:
        return [v.strip() for v in (raw or "").split(",") if v.strip()]

    subnets: List[Dict[str, Any]] = []
    for p in (pfx_data.get("prefixes") or []):
        prefix_str = p.get("prefix", "")
        if not prefix_str:
            continue
        if (p.get("status") or "").lower() == "container":
            continue  # aggregate/parent block — never a DHCP scope itself
        cf = p.get("custom_fields") or {}
        if not cf.get("dhcp_enabled"):
            continue  # not opted in — carve child prefixes with the checkbox on
        subnets.append({
            "subnet":              prefix_str,
            "description":         p.get("description", ""),
            "gateway":             cf.get("gateway", ""),
            "dns_servers":         _csv(cf.get("dns_servers")),
            "search_domains":      _csv(cf.get("search_domain")),
            "domain_name":         (cf.get("domain_name") or "").strip(),
            "ntp_servers":         _csv(cf.get("ntp_servers")),
            "tftp_server_name":    (cf.get("tftp_server_name") or "").strip(),
            "boot_file_name":      (cf.get("boot_file_name") or "").strip(),
            "netbios_name_servers": _csv(cf.get("netbios_name_servers")),
            "broadcast_address":   (cf.get("broadcast_address") or "").strip(),
            "lease_time":          cf.get("lease_time") or None,
            "exclusion_ranges":    (cf.get("exclusion_ranges") or cf.get("exclusions") or "").strip(),
            "pools":               [],
        })

    reservations: List[Dict[str, Any]] = []
    for ip in (ips_data.get("ip_addresses") or []):
        mac = ((ip.get("custom_fields") or {}).get("mac_address") or "").strip()
        address = (ip.get("address") or "").split("/")[0].strip()
        if mac and address:
            reservations.append({
                "ip":       address,
                "mac":      mac,
                "hostname": ip.get("dns_name", ""),
                "subnet":   "",
            })
    return subnets, reservations


def dhcp_skip_warning(spoke_result: Any) -> Dict[str, Any]:
    """``{"warning": ...}`` when Kea silently dropped reservations, else ``{}``.

    A push whose every reservation was skipped still returns SUCCESS — the
    spoke did exactly what it was told, there was simply no enabled scope to
    put them in. The hub then records ``status: "ok"`` and the WebUI shows an
    empty reservation list, which is indistinguishable from "you have no
    reservations". A live fleet sat at 123 sent / 0 applied for exactly this
    reason and the only way to find out was to diff kea-dhcp4.conf by hand.

    A reservation lands only when its IP falls inside a prefix synced as a
    scope (see ``build_dhcp_payload``), so the fix is almost always ticking
    ``dhcp_enabled`` on the prefix that owns those addresses. Say so.
    """
    results = spoke_result if isinstance(spoke_result, list) else [spoke_result]
    skipped = applied = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        try:
            skipped += int(r.get("reservations_skipped") or 0)
            applied += int(r.get("reservations") or 0)
        except (TypeError, ValueError):
            continue
    if skipped <= 0:
        return {}
    what = "every" if applied == 0 else f"{skipped} of {skipped + applied}"
    return {"warning": (
        f"{what} reservation was not applied because its address falls outside "
        f"every DHCP-enabled prefix. Tick 'dhcp_enabled' on the NetBox prefix "
        f"that owns those addresses, or move the reservations into a synced "
        f"scope." if applied == 0 else
        f"{what} reservations were not applied because their addresses fall "
        f"outside every DHCP-enabled prefix. Tick 'dhcp_enabled' on the NetBox "
        f"prefix that owns those addresses."),
        "reservations_skipped": skipped}


class DnsDhcpSyncMixin:
    """Periodic NetBox → Unbound/Kea reconciliation for ``LabManagerHub``.

    Exposes ``sync_dns_from_netbox()`` / ``sync_dhcp_from_netbox()`` (also called
    by the on-demand API routes) and ``run_dns_dhcp_sync_loop()`` (started in
    ``LabManagerHub.start``). Per-run status is recorded in
    ``dns_dhcp_sync_status`` for the WebUI status tiles.
    """

    def _dds_cfg(self) -> Dict[str, Any]:
        """Read the sync config fresh: enabled (default True), interval (default 300s)."""
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_CFG_KEY, {}) or {}
        return {
            "enabled":  bool(cfg.get("enabled", True)),
            "interval": int(cfg.get("interval", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL),
        }

    @property
    def dns_dhcp_sync_status(self) -> Dict[str, Any]:
        """Last-run status for each side; lazily initialized (mixin has no __init__)."""
        st = getattr(self, "_dns_dhcp_sync_status", None)
        if st is None:
            st = {"dns": {}, "dhcp": {}}
            self._dns_dhcp_sync_status = st
        return st

    def _record_status(self, side: str, **fields) -> Dict[str, Any]:
        entry = {"last_run": time.time(), **fields}
        self.dns_dhcp_sync_status[side] = entry
        return entry

    async def _netbox_ips(self) -> Dict[str, Any]:
        nb = self.get_spoke_by_type("ipam")
        if not nb:
            raise RuntimeError("NetBox spoke not connected")
        # NETBOX_GET_IPS paginates the full IP set (up to 100k records via
        # _api_get_all) and is serialized through the engine's HTTP semaphore
        # alongside any concurrent NETBOX_GET_PREFIXES (see
        # _netbox_prefixes_and_ips). The bare 5.0s request_response default
        # routinely fires on any non-trivial fleet → the recurring
        # "Request Timeout from lm-svcs-netbox after 5.0s" in the hub log. The
        # other IPAM read loops (endpoint_sync/vm_sync/staleness_sweep/...) all
        # pass 30s+; this loop was the lone outlier. 30s matches them.
        return unwrap_spoke(await self.request_response(nb, "NETBOX_GET_IPS", {}, timeout=30.0))

    async def _netbox_prefixes_and_ips(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        nb = self.get_spoke_by_type("ipam")
        if not nb:
            raise RuntimeError("NetBox spoke not connected")
        pfx_raw, ips_raw = await asyncio.gather(
            self.request_response(nb, "NETBOX_GET_PREFIXES", {}, timeout=30.0),
            self.request_response(nb, "NETBOX_GET_IPS", {}, timeout=30.0),
        )
        return unwrap_spoke(pfx_raw), unwrap_spoke(ips_raw)

    def _get_dhcp_spokes(self) -> List[str]:
        """All connected, approved DHCP spokes to sync to."""
        if hasattr(self, "get_all_spokes_by_type") and hasattr(self, "active_connections"):
            all_spokes = [
                s for s in (self.get_all_spokes_by_type("dhcp") or [])
                if s in self.active_connections and getattr(self, "approved_modules", {}).get(s, False)
            ]
            if all_spokes:
                return all_spokes
        single = self.get_spoke_by_type("dhcp")
        return [single] if single else []

    def _get_dns_spokes(self) -> List[str]:
        """All connected, approved DNS spokes to sync to."""
        if hasattr(self, "get_all_spokes_by_type") and hasattr(self, "active_connections"):
            all_spokes = [
                s for s in (self.get_all_spokes_by_type("dns") or [])
                if s in self.active_connections and getattr(self, "approved_modules", {}).get(s, False)
            ]
            if all_spokes:
                return all_spokes
        single = self.get_spoke_by_type("dns")
        return [single] if single else []

    async def sync_dns_from_netbox(self) -> Dict[str, Any]:
        """Reconcile Unbound to NetBox DNS names. Returns a status dict.

        ``status`` is ``ok`` on success, ``skipped`` when a required spoke is
        offline (loop no-ops quietly), or ``error`` on failure.
        """
        dns_spokes = self._get_dns_spokes()
        if not dns_spokes or not self.get_spoke_by_type("ipam"):
            missing = "DNS" if not dns_spokes else "NetBox"
            return self._record_status("dns", status="skipped",
                                       reason=f"{missing} spoke not connected")
        try:
            records = build_dns_records(await self._netbox_ips())
            results = await asyncio.gather(*[
                self.request_response(sid, "DNS_SYNC", {"records": records}, timeout=30.0)
                for sid in dns_spokes
            ], return_exceptions=True)
            spoke_errors = [r for r in results if isinstance(r, Exception)]
            if spoke_errors:
                logger.warning("DNS auto-sync failed: %s", spoke_errors[0])
                return self._record_status("dns", status="error", error=str(spoke_errors[0]))
            spoke_results = [unwrap_spoke(r) for r in results]
            return self._record_status("dns", status="ok",
                                       records_synced=len(records),
                                       spoke_result=spoke_results[0] if len(spoke_results) == 1 else spoke_results)
        except Exception as e:  # noqa: BLE001 — best-effort loop must not die
            logger.warning("DNS auto-sync failed: %s", e)
            return self._record_status("dns", status="error", error=str(e))

    async def sync_dhcp_from_netbox(self) -> Dict[str, Any]:
        """Reconcile Kea to NetBox prefixes + reservations. Returns a status dict."""
        dhcp_spokes = self._get_dhcp_spokes()
        if not dhcp_spokes or not self.get_spoke_by_type("ipam"):
            missing = "DHCP" if not dhcp_spokes else "NetBox"
            return self._record_status("dhcp", status="skipped",
                                       reason=f"{missing} spoke not connected")
        try:
            pfx_data, ips_data = await self._netbox_prefixes_and_ips()
            subnets, reservations = build_dhcp_payload(pfx_data, ips_data)
            results = await asyncio.gather(*[
                self.request_response(sid, "DHCP_SYNC", {
                    "subnets": subnets, "reservations": reservations}, timeout=30.0)
                for sid in dhcp_spokes
            ], return_exceptions=True)
            spoke_errors = [r for r in results if isinstance(r, Exception)]
            if spoke_errors:
                logger.warning("DHCP auto-sync failed: %s", spoke_errors[0])
                return self._record_status("dhcp", status="error", error=str(spoke_errors[0]))
            spoke_results = [unwrap_spoke(r) for r in results]
            single = spoke_results[0] if len(spoke_results) == 1 else spoke_results
            return self._record_status("dhcp", status="ok",
                                       subnets_synced=len(subnets),
                                       reservations_synced=len(reservations),
                                       **dhcp_skip_warning(single),
                                       spoke_result=single)
        except Exception as e:  # noqa: BLE001
            logger.warning("DHCP auto-sync failed: %s", e)
            return self._record_status("dhcp", status="error", error=str(e))

    async def _sync_dns_dhcp_once(self) -> None:
        """One loop tick: fetch NetBox prefixes+IPs ONCE, build both payloads,
        and skip the spoke push entirely when neither changed since the last
        tick.

        The previous loop called ``sync_dns_from_netbox`` then
        ``sync_dhcp_from_netbox`` sequentially, each fetching the full NetBox IP
        set independently (2 paginated 100k-row fetches per cycle) and pushing
        unconditionally — so an idle fleet still paid 2 NetBox fetches + an
        ``unbound-control reload`` (10s) + 3 Kea RPCs every 300s. Hashing the
        payloads and skipping the push when unchanged removes the expensive
        spoke-side write/reload/RPC storm on idle fleets. NetBox is still
        fetched each tick (it's the change signal), but only once.
        """
        ipam = self.get_spoke_by_type("ipam")
        if not ipam:
            return
        dns_spokes = self._get_dns_spokes()
        dhcp_spokes = self._get_dhcp_spokes()
        if not dns_spokes and not dhcp_spokes:
            return
        try:
            pfx_data, ips_data = await self._netbox_prefixes_and_ips()
        except Exception as e:  # noqa: BLE001
            logger.warning("DNS/DHCP sync: NetBox fetch failed: %s", e)
            self._record_status("dns", status="error", error=str(e))
            self._record_status("dhcp", status="error", error=str(e))
            return

        records = build_dns_records(ips_data)
        subnets, reservations = build_dhcp_payload(pfx_data, ips_data)

        dns_hash = hashlib.sha256(json.dumps(records, sort_keys=True,
                                             default=str).encode()).hexdigest()
        dhcp_hash = hashlib.sha256(json.dumps(
            {"subnets": subnets, "reservations": reservations},
            sort_keys=True, default=str).encode()).hexdigest()

        last = getattr(self, "_last_sync_hashes", None) or {}
        dns_changed = last.get("dns") != dns_hash
        dhcp_changed = last.get("dhcp") != dhcp_hash

        pushes = []
        dns_indices = []
        dhcp_indices = []
        if dns_spokes and dns_changed:
            for sid in dns_spokes:
                dns_indices.append(len(pushes))
                pushes.append(self.request_response(sid, "DNS_SYNC",
                                                    {"records": records}, timeout=30.0))
        if dhcp_spokes and dhcp_changed:
            for sid in dhcp_spokes:
                dhcp_indices.append(len(pushes))
                pushes.append(self.request_response(sid, "DHCP_SYNC", {
                    "subnets": subnets, "reservations": reservations}, timeout=30.0))

        if not pushes:
            # Nothing changed — record a "skipped (unchanged)" status so the UI
            # status card reflects that the loop is alive without a spoke push.
            self._record_status("dns", status="ok", records_synced=len(records),
                                skipped_unchanged=True)
            self._record_status("dhcp", status="ok", subnets_synced=len(subnets),
                                reservations_synced=len(reservations),
                                skipped_unchanged=True)
            self._last_sync_hashes = {"dns": dns_hash, "dhcp": dhcp_hash}
            return

        results = await asyncio.gather(*pushes, return_exceptions=True)
        # Latch each side's hash ONLY when that side's push actually SUCCEEDED.
        # A failed/unapplied push (e.g. spoke transiently offline) must leave the
        # old hash in place so the change is retried next cycle rather than
        # latched-as-synced forever.
        new_hashes = dict(getattr(self, "_last_sync_hashes", None) or {})
        if dns_spokes and dns_changed:
            dns_res = [results[i] for i in dns_indices]
            dns_errors = [r for r in dns_res if isinstance(r, Exception)]
            if dns_errors:
                logger.warning("DNS auto-sync push failed: %s", dns_errors[0])
                self._record_status("dns", status="error", error=str(dns_errors[0]))
            else:
                spoke_res = [unwrap_spoke(r) for r in dns_res]
                self._record_status("dns", status="ok", records_synced=len(records),
                                    spoke_result=spoke_res[0] if len(spoke_res) == 1 else spoke_res)
                new_hashes["dns"] = dns_hash
        else:
            self._record_status("dns", status="ok", records_synced=len(records),
                                skipped_unchanged=True)
            new_hashes["dns"] = dns_hash

        if dhcp_spokes and dhcp_changed:
            dhcp_res = [results[i] for i in dhcp_indices]
            dhcp_errors = [r for r in dhcp_res if isinstance(r, Exception)]
            if dhcp_errors:
                logger.warning("DHCP auto-sync push failed: %s", dhcp_errors[0])
                self._record_status("dhcp", status="error", error=str(dhcp_errors[0]))
            else:
                spoke_res = [unwrap_spoke(r) for r in dhcp_res]
                single = spoke_res[0] if len(spoke_res) == 1 else spoke_res
                self._record_status("dhcp", status="ok", subnets_synced=len(subnets),
                                    reservations_synced=len(reservations),
                                    **dhcp_skip_warning(single),
                                    spoke_result=single)
                new_hashes["dhcp"] = dhcp_hash
        else:
            self._record_status("dhcp", status="ok", subnets_synced=len(subnets),
                                reservations_synced=len(reservations),
                                skipped_unchanged=True)
            new_hashes["dhcp"] = dhcp_hash
        self._last_sync_hashes = new_hashes

    async def run_dns_dhcp_sync_loop(self):
        """Background loop: reconcile Unbound + Kea to NetBox every ``interval`` s.

        Disabled (skipped, not stopped) while ``global_config.dns_dhcp_sync
        .enabled`` is False, so toggling it in the WebUI takes effect without a
        hub restart. Skips quietly whenever the NetBox / DNS / DHCP spokes are
        offline — nothing to reconcile against.
        """
        logger.info("DNS/DHCP NetBox auto-sync loop started.")

        def _delay() -> float:
            try:
                return max(30, self._dds_cfg()["interval"])
            except Exception:  # noqa: BLE001 — bad config falls back to default
                return max(30, _DEFAULT_INTERVAL)

        async def _body():
            # Single NetBox fetch + skip-if-unchanged (see
            # _sync_dns_dhcp_once). The manual /api/dns|dhcp/sync buttons
            # still call the per-side methods directly (they re-fetch,
            # which is correct for an explicit button press).
            await self._sync_dns_dhcp_once()

        await run_sync_loop(
            stagger=0, guard=lambda: bool(self._dds_cfg()["enabled"]),
            body=_body, delay=_delay,
            on_error=lambda e: logger.error("Error in DNS/DHCP auto-sync loop: %s", e),
            error_delay=_delay)
