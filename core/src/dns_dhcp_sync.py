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
    """
    subnets: List[Dict[str, Any]] = []
    for p in (pfx_data.get("prefixes") or []):
        prefix_str = p.get("prefix", "")
        if not prefix_str:
            continue
        cf = p.get("custom_fields") or {}
        dns_servers = cf.get("dns_servers") or ""
        subnets.append({
            "subnet":      prefix_str,
            "description": p.get("description", ""),
            "gateway":     cf.get("gateway", ""),
            "dns_servers": [s for s in dns_servers.split(",") if s] if dns_servers else [],
            "pools":       [],
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

    async def sync_dns_from_netbox(self) -> Dict[str, Any]:
        """Reconcile Unbound to NetBox DNS names. Returns a status dict.

        ``status`` is ``ok`` on success, ``skipped`` when a required spoke is
        offline (loop no-ops quietly), or ``error`` on failure.
        """
        dns_spoke = self.get_spoke_by_type("dns")
        if not dns_spoke or not self.get_spoke_by_type("ipam"):
            missing = "DNS" if not dns_spoke else "NetBox"
            return self._record_status("dns", status="skipped",
                                       reason=f"{missing} spoke not connected")
        try:
            records = build_dns_records(await self._netbox_ips())
            result = await self.request_response(dns_spoke, "DNS_SYNC", {"records": records}, timeout=30.0)
            return self._record_status("dns", status="ok",
                                       records_synced=len(records),
                                       spoke_result=unwrap_spoke(result))
        except Exception as e:  # noqa: BLE001 — best-effort loop must not die
            logger.warning("DNS auto-sync failed: %s", e)
            return self._record_status("dns", status="error", error=str(e))

    async def sync_dhcp_from_netbox(self) -> Dict[str, Any]:
        """Reconcile Kea to NetBox prefixes + reservations. Returns a status dict."""
        dhcp_spoke = self.get_spoke_by_type("dhcp")
        if not dhcp_spoke or not self.get_spoke_by_type("ipam"):
            missing = "DHCP" if not dhcp_spoke else "NetBox"
            return self._record_status("dhcp", status="skipped",
                                       reason=f"{missing} spoke not connected")
        try:
            pfx_data, ips_data = await self._netbox_prefixes_and_ips()
            subnets, reservations = build_dhcp_payload(pfx_data, ips_data)
            result = await self.request_response(dhcp_spoke, "DHCP_SYNC", {
                "subnets": subnets, "reservations": reservations}, timeout=30.0)
            return self._record_status("dhcp", status="ok",
                                       subnets_synced=len(subnets),
                                       reservations_synced=len(reservations),
                                       spoke_result=unwrap_spoke(result))
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
        dns_spoke = self.get_spoke_by_type("dns")
        dhcp_spoke = self.get_spoke_by_type("dhcp")
        if not dns_spoke and not dhcp_spoke:
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
        if dns_spoke and dns_changed:
            pushes.append(self.request_response(dns_spoke, "DNS_SYNC",
                                                {"records": records}, timeout=30.0))
        if dhcp_spoke and dhcp_changed:
            pushes.append(self.request_response(dhcp_spoke, "DHCP_SYNC", {
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
        ri = 0
        if dns_spoke and dns_changed:
            r = results[ri]; ri += 1
            if isinstance(r, Exception):
                logger.warning("DNS auto-sync push failed: %s", r)
                self._record_status("dns", status="error", error=str(r))
            else:
                self._record_status("dns", status="ok", records_synced=len(records),
                                    spoke_result=unwrap_spoke(r))
        else:
            self._record_status("dns", status="ok", records_synced=len(records),
                                skipped_unchanged=True)
        if dhcp_spoke and dhcp_changed:
            r = results[ri]
            if isinstance(r, Exception):
                logger.warning("DHCP auto-sync push failed: %s", r)
                self._record_status("dhcp", status="error", error=str(r))
            else:
                self._record_status("dhcp", status="ok", subnets_synced=len(subnets),
                                    reservations_synced=len(reservations),
                                    spoke_result=unwrap_spoke(r))
        else:
            self._record_status("dhcp", status="ok", subnets_synced=len(subnets),
                                reservations_synced=len(reservations),
                                skipped_unchanged=True)
        self._last_sync_hashes = {"dns": dns_hash, "dhcp": dhcp_hash}

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
