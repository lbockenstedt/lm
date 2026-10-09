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
import ipaddress
import json
import logging
import re
import time
from typing import Any, Dict, List, Tuple

from access import unwrap_spoke  # sibling leaf (no main/api back-import)
from sync_loop import run_sync_loop  # sibling leaf

logger = logging.getLogger("Hub")

_CFG_KEY = "dns_dhcp_sync"
_DEFAULT_INTERVAL = 300  # seconds
# Real-time Kea -> Unbound registration hook (dhcp/src/kea_dns_hook.py). On by
# default; global_config["dhcp_dns_hook"]["enabled"]=false turns it off. The
# default unbound-control target assumes Kea + Unbound share a host.
_HOOK_CFG_KEY = "dhcp_dns_hook"
_HOOK_DEFAULT_TARGETS = ["127.0.0.1@8953"]

_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")  # one DNS label


def _scope_domains(pfx_data: Dict[str, Any]) -> List[Tuple[Any, str]]:
    """DHCP scopes (NetBox prefixes Kea serves) -> [(network, domain_name)],
    most specific prefix first."""

    result = []
    for p in (pfx_data or {}).get("prefixes") or []:
        if not isinstance(p, dict):
            continue
        st = p.get("status")
        if isinstance(st, dict):
            st = st.get("value") or ""
        if str(st).lower() == "container":
            continue
        cf = p.get("custom_fields") or {}
        if not cf.get("dhcp_enabled"):
            continue
        dom = str(cf.get("domain_name") or "").strip().strip(".").lower()
        if not dom or not all(_LABEL_RE.match(l) for l in dom.split(".")):
            continue
        try:
            net = ipaddress.ip_network(str(p.get("prefix") or ""), strict=False)
        except ValueError:
            continue
        result.append((net, dom))
    return sorted(result, key=lambda t: t[0].prefixlen, reverse=True)


def qualify_dns_name(name: str, address: str, scopes: List[Tuple[Any, str]]) -> str:
    """Append the containing DHCP scope's domain to a single-label host name."""

    orig = (name or "").strip()
    n = orig.rstrip(".")
    if not n or "." in n or not scopes:
        return orig
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return orig
    for net, dom in scopes:
        if ip.version == net.version and ip in net:
            return f"{n}.{dom}"
    return orig



def build_dns_records(ips_data: Dict[str, Any],
                      pfx_data: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    """NetBox IP list → Unbound A/AAAA-record sync payload.

    An IP contributes a record only when it has a ``dns_name`` and a concrete
    address. Record type is derived from the address family — an IPv6 address
    becomes ``AAAA``, not ``A`` (Unbound's own record validation rejects an
    IPv6 value under type ``A``, so a dual-stack device's v6 address was
    previously silently dropped/rejected by the sync rather than landing as
    an AAAA record). Shared by the loop and ``POST /api/dns/sync`` so both
    build the identical payload.

    A single-label name (a DHCP hostname like ``printer1``) gets the
    ``domain_name`` of the DHCP scope (dhcp_enabled prefix) containing its
    address appended — the same domain Kea hands that client — so DNS holds
    ``printer1.lab.example``. Names that already contain a dot are untouched.
    """
    scopes = _scope_domains(pfx_data) if pfx_data else []
    records: List[Dict[str, Any]] = []
    for entry in (ips_data.get("ip_addresses") or []):
        dns_name = (entry.get("dns_name") or "").strip()
        address = (entry.get("address") or "").split("/")[0].strip()
        if not (dns_name and address):
            continue
        try:
            rtype = "AAAA" if ipaddress.ip_address(address).version == 6 else "A"
        except ValueError:
            continue  # malformed address — skip rather than mis-sync
        records.append({"name": qualify_dns_name(dns_name, address, scopes),
                        "type": rtype, "value": address, "ttl": 300})
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

    def _dns_hook_desired(self) -> Dict[str, Any]:
        """Desired real-time DNS hook settings, normalized the way the dhcp
        spoke stores them (kea_dns_hook.validate_settings) so a converged node
        never reads as drifted."""
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_HOOK_CFG_KEY, {}) or {}
        targets = [str(t).strip() for t in (cfg.get("targets") or []) if str(t).strip()]
        try:
            ttl = int(cfg.get("ttl", 300) or 300)
        except (TypeError, ValueError):
            ttl = 300
        return {
            "enabled":      bool(cfg.get("enabled", True)),
            "targets":      targets or list(_HOOK_DEFAULT_TARGETS),
            "domain":       str(cfg.get("domain") or "").strip().rstrip(".").lower(),
            "ttl":          ttl,
            "register_ptr": bool(cfg.get("register_ptr", False)),
        }

    async def _reconcile_dns_hook(self) -> Dict[str, Any]:
        """Converge every DHCP spoke's real-time Kea->Unbound DNS hook to
        global_config["dhcp_dns_hook"]; only pushes when a node has drifted."""
        desired = self._dns_hook_desired()
        spokes = self._get_dhcp_spokes()
        applied = []
        errors = {}

        if not spokes:
            return self._record_status("dns_hook", status="skipped", enabled=desired["enabled"], reason="DHCP spoke not connected")

        def _drifted(node: dict) -> bool:
            s = (node or {}).get("settings") or {}
            if not desired["enabled"]:
                return bool(s.get("enabled")) or node.get("loaded_in_running_config") is True
            if not s.get("enabled") or node.get("loaded_in_running_config") is False:
                return True
            for k in ("targets", "domain", "ttl", "register_ptr"):
                if s.get(k) != desired[k]:
                    return True
            return False

        for sid in spokes:
            try:
                st = unwrap_spoke(await self.request_response(sid, "DHCP_DNS_HOOK_STATUS", {}, timeout=30.0)) or {}
                members = st.get("members")
                if st.get("status") == "ERROR" and not members and "settings" not in st:
                    # e.g. a dhcp spoke too old to know the command — report,
                    # don't blindly re-push config every tick.
                    errors[sid] = str(st.get("message") or st.get("error") or "status read failed")
                    continue
                nodes = list(members.values()) if isinstance(members, dict) and members else [st]
                if not any(_drifted(n if isinstance(n, dict) else {}) for n in nodes):
                    continue
                res = unwrap_spoke(await self.request_response(sid, "DHCP_DNS_HOOK_CONFIG", {"settings": dict(desired), "hook_dir": ""}, timeout=30.0)) or {}
                if res.get("status") in ("SUCCESS", "PARTIAL"):
                    applied.append(sid)
                    logger.info("DNS hook %s on %s", "enabled" if desired["enabled"] else "disabled", sid)
                else:
                    errors[sid] = str(res.get("message") or res.get("error") or res.get("member_errors") or "config failed")
            except Exception as e:
                errors[sid] = str(e)
                logger.warning("DNS hook reconcile %s failed: %s", sid, e)

        return self._record_status("dns_hook", status=("error" if errors else "ok"), enabled=desired["enabled"], applied=applied, errors=errors, spokes=len(spokes))

    @property
    def dns_dhcp_sync_status(self) -> Dict[str, Any]:
        """Last-run status for each side; lazily initialized (mixin has no __init__)."""
        st = getattr(self, "_dns_dhcp_sync_status", None)
        if st is None:
            st = {"dns": {}, "dhcp": {}, "dns_hook": {}}
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

    def _ipam_spoke_candidates(self) -> List[str]:
        """Connected IPAM spokes, the one bound to a configured ipam_instance
        first. With several IPAM spokes connected (e.g. a dedicated NetBox
        spoke plus a netbox role on a generic agent) "first registered wins"
        can land on one with no NetBox URL configured."""
        first = self.get_spoke_by_type("ipam")
        spokes = []
        if hasattr(self, "get_all_spokes_by_type"):
            spokes = list(self.get_all_spokes_by_type("ipam") or [])
        if first and first not in spokes:
            spokes.insert(0, first)
        pk = getattr(self, "_primary_key", None) or (lambda s: s)
        gc = (self.state.system_state or {}).get("global_config", {}) or {}
        bound = {pk(str(i.get("spoke_id"))) for i in (gc.get("ipam_instances") or [])
                 if isinstance(i, dict) and i.get("spoke_id")}
        return sorted(spokes, key=lambda s: 0 if pk(s) in bound else 1)

    async def _netbox_prefixes_and_ips(self, filters: Dict[str, Any] = None
                                       ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Fetch NetBox prefixes + IPs, failing over across IPAM spokes.

        Raises unless a spoke returns BOTH lists. A spoke-side failure comes
        back as ``{"status": "ERROR", ...}`` with no ``prefixes`` key; treating
        that as "zero prefixes" made the sync push an empty subnet4 and wipe
        every Kea scope whenever NetBox was unreachable from the chosen spoke.

        ``filters`` (``tenant`` / ``tenant_group``, see ``_sync_scope``) is
        passed to both reads so a tenant-dedicated target only gets its own
        tenant's prefixes and IPs.
        """
        req = dict(filters or {})
        candidates = self._ipam_spoke_candidates()
        if not candidates:
            raise RuntimeError("NetBox spoke not connected")
        errors = []
        for nb in candidates:
            try:
                pfx_raw, ips_raw = await asyncio.gather(
                    self.request_response(nb, "NETBOX_GET_PREFIXES", dict(req), timeout=30.0),
                    self.request_response(nb, "NETBOX_GET_IPS", dict(req), timeout=30.0),
                )
            except Exception as e:  # noqa: BLE001 — try the next IPAM spoke
                errors.append(f"{nb}: {e}")
                continue
            pfx, ips = unwrap_spoke(pfx_raw), unwrap_spoke(ips_raw)
            bad = [f"{what}: {(d or {}).get('message') if isinstance(d, dict) else d!r}"
                   for what, d, key in (("prefixes", pfx, "prefixes"),
                                        ("ip_addresses", ips, "ip_addresses"))
                   if not isinstance(d, dict) or str(d.get("status", "")).upper() == "ERROR"
                   or not isinstance(d.get(key), list)]
            if bad:
                errors.append(f"{nb}: " + "; ".join(bad))
                continue
            return pfx, ips
        raise RuntimeError("NetBox fetch failed on every IPAM spoke — " + " | ".join(errors))

    def _sync_scope(self, spoke_id):
        """NetBox read scope for one DHCP/DNS target spoke (tenant isolation).

        Returns ``(key, filters)``:
          * ``("", {})`` — spoke not dedicated to a real tenant (unassigned,
            shared or Admin): unfiltered, it serves shared infra.
          * ``("tenant:<key>", {tenant|tenant_group: slug})`` — a spoke
            dedicated to a real tenant only ever sees that tenant's data.
          * ``(None, None)`` — tenant-dedicated spoke whose tenant has no
            NetBox mapping (or the binding is unreadable): the caller skips it,
            never pushing another tenant's subnets nor an empty set.
        """
        from access import spoke_is_unbound, netbox_tenant_scope
        try:
            if spoke_is_unbound(self, spoke_id):
                return "", {}
            tenant = self.state.get_spoke_tenant(spoke_id) or ""
            scope = netbox_tenant_scope(self, tenant)
        except Exception as e:  # noqa: BLE001 — fail closed
            logger.warning("DNS/DHCP sync: tenant scope for %s unreadable: %s", spoke_id, e)
            return None, None
        filters = {k: scope.get(k) for k in ("tenant", "tenant_group") if scope.get(k)}
        if not filters:
            logger.warning("DNS/DHCP sync: %s is bound to tenant %r with no NetBox "
                           "tenant mapping — not synced", spoke_id, tenant)
            return None, None
        return "tenant:" + str(scope.get("key")), filters

    def _scope_groups(self, spokes):
        """Group target spokes by ``_sync_scope`` →
        ``({key: (filters, [sids])}, [skipped sids])``."""
        groups, skipped = {}, []
        for sid in spokes:
            key, filters = self._sync_scope(sid)
            if key is None:
                skipped.append(sid)
                continue
            groups.setdefault(key, (filters, []))[1].append(sid)
        return groups, skipped

    @staticmethod
    def _hash_key(side: str, scope_key: str) -> str:
        return side if not scope_key else f"{side}|{scope_key}"

    async def _scoped_push(self, side: str, spokes: List[str]):
        """On-demand (non-hashed) push of one side to ``spokes``, one NetBox
        fetch per tenant scope. Returns ``(counts, spoke_results, skipped)``;
        raises on a fetch or push failure."""
        groups, skipped = self._scope_groups(spokes)
        counts = ({"records_synced": 0} if side == "dns" else
                  {"subnets_synced": 0, "reservations_synced": 0})
        spoke_results = []
        for _key, (filters, sids) in groups.items():
            pfx_data, ips_data = await self._netbox_prefixes_and_ips(filters)
            if side == "dns":
                records = build_dns_records(ips_data, pfx_data)
                payload, cmd = {"records": records}, "DNS_SYNC"
                counts["records_synced"] += len(records)
            else:
                subnets, reservations = build_dhcp_payload(pfx_data, ips_data)
                payload, cmd = {"subnets": subnets, "reservations": reservations}, "DHCP_SYNC"
                counts["subnets_synced"] += len(subnets)
                counts["reservations_synced"] += len(reservations)
            results = await asyncio.gather(*[
                self.request_response(sid, cmd, payload, timeout=30.0) for sid in sids
            ], return_exceptions=True)
            errs = [r for r in results if isinstance(r, Exception)]
            if errs:
                raise errs[0]
            spoke_results.extend(unwrap_spoke(r) for r in results)
        return counts, spoke_results, skipped

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
            counts, spoke_results, skipped = await self._scoped_push("dns", dns_spokes)
            extra = {"skipped_spokes": skipped} if skipped else {}
            return self._record_status("dns", status="ok", **counts, **extra,
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
            counts, spoke_results, skipped = await self._scoped_push("dhcp", dhcp_spokes)
            single = spoke_results[0] if len(spoke_results) == 1 else spoke_results
            extra = {"skipped_spokes": skipped} if skipped else {}
            return self._record_status("dhcp", status="ok", **counts, **extra,
                                       **dhcp_skip_warning(single),
                                       spoke_result=single)
        except Exception as e:  # noqa: BLE001
            logger.warning("DHCP auto-sync failed: %s", e)
            return self._record_status("dhcp", status="error", error=str(e))

    async def _sync_dns_dhcp_once(self) -> None:
        """One loop tick: fetch NetBox prefixes+IPs ONCE per tenant scope,
        build the DNS/DHCP payloads, and skip a spoke push when its payload is
        unchanged since the last tick.

        Hashing the payloads and skipping unchanged pushes avoids an
        ``unbound-control reload`` + Kea RPC storm on idle fleets; NetBox is
        still fetched each tick (it's the change signal).

        Tenant isolation: spokes are grouped by ``_sync_scope`` — a spoke
        dedicated to a real tenant only receives that tenant's NetBox data,
        unbound (shared/admin/unassigned) spokes keep the unfiltered set.
        Hashes are kept per (side, scope); a failed fetch or push never
        latches a hash and never pushes an empty set for that scope.
        """
        ipam = self.get_spoke_by_type("ipam")
        if not ipam:
            return
        dns_spokes = self._get_dns_spokes()
        dhcp_spokes = self._get_dhcp_spokes()
        if not dns_spokes and not dhcp_spokes:
            return

        dns_groups, dns_skipped = self._scope_groups(dns_spokes)
        dhcp_groups, dhcp_skipped = self._scope_groups(dhcp_spokes)

        scopes = {}
        for groups in (dns_groups, dhcp_groups):
            for key, (filters, _sids) in groups.items():
                scopes.setdefault(key, filters)

        fetched, fetch_errors = {}, {}
        for key, filters in scopes.items():
            try:
                fetched[key] = await self._netbox_prefixes_and_ips(filters)
            except Exception as e:  # noqa: BLE001
                fetch_errors[key] = str(e)
                logger.warning("DNS/DHCP sync: NetBox fetch failed (%s): %s", key or "all", e)

        last = getattr(self, "_last_sync_hashes", None) or {}
        new_hashes = dict(last)
        st = {side: {"error": None, "records_synced": 0, "subnets_synced": 0,
                     "reservations_synced": 0, "spoke_results": []}
              for side in ("dns", "dhcp")}

        pushes, push_groups = [], []
        for side, groups in (("dns", dns_groups), ("dhcp", dhcp_groups)):
            for key, (_filters, sids) in groups.items():
                if key not in fetched:
                    if st[side]["error"] is None:
                        st[side]["error"] = fetch_errors.get(key) or "NetBox fetch failed"
                    continue
                pfx, ips = fetched[key]
                if side == "dns":
                    records = build_dns_records(ips, pfx)
                    payload = {"records": records}
                    h = hashlib.sha256(json.dumps(records, sort_keys=True,
                                                  default=str).encode()).hexdigest()
                    st[side]["records_synced"] += len(records)
                else:
                    subnets, reservations = build_dhcp_payload(pfx, ips)
                    payload = {"subnets": subnets, "reservations": reservations}
                    h = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                                  default=str).encode()).hexdigest()
                    st[side]["subnets_synced"] += len(subnets)
                    st[side]["reservations_synced"] += len(reservations)
                hk = self._hash_key(side, key)
                if last.get(hk) == h:
                    new_hashes[hk] = h
                    continue
                cmd = "DNS_SYNC" if side == "dns" else "DHCP_SYNC"
                indices = []
                for sid in sids:
                    indices.append(len(pushes))
                    pushes.append(self.request_response(sid, cmd, payload, timeout=30.0))
                push_groups.append((side, hk, h, indices))

        results = await asyncio.gather(*pushes, return_exceptions=True) if pushes else []
        # Latch a scope's hash ONLY when every push for it succeeded, so a
        # transiently-offline spoke is retried next cycle.
        for side, hk, h, indices in push_groups:
            res = [results[i] for i in indices]
            errs = [r for r in res if isinstance(r, Exception)]
            if errs:
                logger.warning("%s auto-sync push failed: %s", side.upper(), errs[0])
                if st[side]["error"] is None:
                    st[side]["error"] = str(errs[0])
            else:
                new_hashes[hk] = h
                st[side]["spoke_results"].extend(unwrap_spoke(r) for r in res)

        for side, skipped in (("dns", dns_skipped), ("dhcp", dhcp_skipped)):
            s = st[side]
            if s["error"]:
                self._record_status(side, status="error", error=s["error"])
                continue
            fields = ({"records_synced": s["records_synced"]} if side == "dns" else
                      {"subnets_synced": s["subnets_synced"],
                       "reservations_synced": s["reservations_synced"]})
            results_ = s["spoke_results"]
            if results_:
                single = results_[0] if len(results_) == 1 else results_
                if side == "dhcp":
                    fields.update(dhcp_skip_warning(single))
                fields["spoke_result"] = single
            else:
                fields["skipped_unchanged"] = True
            if skipped:
                fields["skipped_spokes"] = list(skipped)
            self._record_status(side, status="ok", **fields)

        self._last_sync_hashes = new_hashes

    async def run_dns_dhcp_sync_loop(self):
        """Background loop: reconcile Unbound + Kea to NetBox every ``interval`` s.

        The NetBox reconciliation is skipped (not stopped) while
        ``global_config.dns_dhcp_sync.enabled`` is False; the real-time DNS
        hook (``global_config.dhcp_dns_hook.enabled``, default on) is
        reconciled every tick regardless, so toggling it in the WebUI takes effect without a
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
            # The real-time hook has its own on/off knob, so it converges even
            # while the NetBox reconciliation below is disabled.
            try:
                await self._reconcile_dns_hook()
            except Exception as e:  # noqa: BLE001
                logger.warning("DNS hook reconcile failed: %s", e)
            if not self._dds_cfg()["enabled"]:
                return
            # Single NetBox fetch + skip-if-unchanged (see
            # _sync_dns_dhcp_once). The manual /api/dns|dhcp/sync buttons
            # still call the per-side methods directly (they re-fetch,
            # which is correct for an explicit button press).
            await self._sync_dns_dhcp_once()

        await run_sync_loop(
            stagger=0,
            body=_body, delay=_delay,
            on_error=lambda e: logger.error("Error in DNS/DHCP auto-sync loop: %s", e),
            error_delay=_delay)

    async def run_dns_dhcp_feed_loop(self):
        """Background data feed for the DNS/DHCP pages.

        Those pages are stale-while-revalidate over the warm cache, which
        previously only revalidated when a tab was opened — so an idle hub
        showed hours-old "cached" data until someone clicked. This keeps the
        cache continuously fresh (every 60s, inside the 300s "cached" badge
        threshold) via ``hub.net_services_feed_once`` (set by routes.net_services).
        """
        logger.info("DNS/DHCP page data-feed loop started.")

        async def _body():
            feed = getattr(self, "net_services_feed_once", None)
            if feed:
                await feed()

        await run_sync_loop(
            stagger=20, body=_body, delay=lambda: 60.0,
            on_error=lambda e: logger.warning("DNS/DHCP feed loop error: %s", e),
            error_delay=60.0)
