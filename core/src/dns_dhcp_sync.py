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

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio runs NetBox reads and spoke pushes concurrently.
import asyncio
# hashlib fingerprints payloads so unchanged pushes can be skipped.
import hashlib
# ipaddress parses addresses and prefixes for record types and scope matching.
import ipaddress
# json serialises payloads deterministically for hashing.
import json
# Standard-library logging for sync results and failures.
import logging
# re validates DNS labels.
import re
# time stamps each side's last run.
import time
# Type hints only.
from typing import Any, Dict, List, Tuple

# Unwraps a spoke's reply envelope into its payload.
from access import unwrap_spoke  # sibling leaf (no main/api back-import)
# Shared periodic-loop runner.
from sync_loop import run_sync_loop  # sibling leaf

# Use the hub's main logger so sync lines appear with other hub output.
logger = logging.getLogger("Hub")

# global_config key for this sync and the default interval.
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

    # (network, domain) pairs.
    result = []
    # Look at every prefix.
    for p in (pfx_data or {}).get("prefixes") or []:
        if not isinstance(p, dict):
            continue
        # Status may be a plain string or a {"value": ...} dict; skip container (parent) prefixes.
        st = p.get("status")
        if isinstance(st, dict):
            st = st.get("value") or ""
        if str(st).lower() == "container":
            continue
        # Only DHCP-enabled prefixes count as scopes.
        cf = p.get("custom_fields") or {}
        if not cf.get("dhcp_enabled"):
            continue
        # Domain name, normalised; skip if missing or any label is invalid.
        dom = str(cf.get("domain_name") or "").strip().strip(".").lower()
        if not dom or not all(_LABEL_RE.match(l) for l in dom.split(".")):
            continue
        # Parse the prefix; skip if invalid.
        try:
            net = ipaddress.ip_network(str(p.get("prefix") or ""), strict=False)
        except ValueError:
            continue
        # Keep it.
        result.append((net, dom))
    # Longest prefix (most specific) first.
    return sorted(result, key=lambda t: t[0].prefixlen, reverse=True)


def qualify_dns_name(name: str, address: str, scopes: List[Tuple[Any, str]]) -> str:
    """Append the containing DHCP scope's domain to a single-label host name."""

    # Trim whitespace and a trailing dot.
    orig = (name or "").strip()
    n = orig.rstrip(".")
    # Leave it alone if empty, already qualified, or there are no scopes.
    if not n or "." in n or not scopes:
        return orig
    # Parse the address; leave the name alone if invalid.
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return orig
    # Use the first (most specific) scope containing the address.
    for net, dom in scopes:
        if ip.version == net.version and ip in net:
            return f"{n}.{dom}"
    # No scope contains it.
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
    # DHCP scopes used to qualify bare host names.
    scopes = _scope_domains(pfx_data) if pfx_data else []
    # Build one record per usable IP.
    records: List[Dict[str, Any]] = []
    for entry in (ips_data.get("ip_addresses") or []):
        # DNS name and the address without its prefix length.
        dns_name = (entry.get("dns_name") or "").strip()
        address = (entry.get("address") or "").split("/")[0].strip()
        # Need both a name and an address.
        if not (dns_name and address):
            continue
        # A for IPv4, AAAA for IPv6.
        try:
            rtype = "AAAA" if ipaddress.ip_address(address).version == 6 else "A"
        except ValueError:
            continue  # malformed address — skip rather than mis-sync
        # Add the record, qualifying a bare name with its scope's domain.
        records.append({"name": qualify_dns_name(dns_name, address, scopes),
                        "type": rtype, "value": address, "ttl": 300})
    return records


def _lease_networks(pfx_data: Dict[str, Any]) -> List[Any]:
    """Every non-container NetBox prefix in this scope's data."""
    nets = []
    for p in (pfx_data or {}).get("prefixes") or []:
        if not isinstance(p, dict):
            continue
        st = p.get("status")
        if isinstance(st, dict):
            st = st.get("value") or ""
        if str(st).lower() == "container":
            continue
        try:
            nets.append(ipaddress.ip_network(str(p.get("prefix") or ""), strict=False))
        except ValueError:
            continue
    return nets


def apply_kea_leases(records: List[Dict[str, Any]], leases: List[Dict[str, Any]],
                     pfx_data: Dict[str, Any] = None,
                     now: float = None) -> List[Dict[str, Any]]:
    """Point a NetBox host name at the address Kea actually leased it.

    NetBox does not follow a DHCP client that moves to a new address, so DNS
    kept the old one (and two hosts could swap). For each active Kea lease
    whose host name already has an A record, that record's address becomes
    the lease address. Names with no NetBox record are left to the real-time
    hook. Only leases inside this scope's NetBox prefixes count, so one
    tenant's leases never touch another tenant's records.
    """
    if not leases:
        return records
    now = time.time() if now is None else now
    scopes = _scope_domains(pfx_data) if pfx_data else []
    nets = _lease_networks(pfx_data)
    # Lower-case qualified name -> (cltt, address), newest lease wins.
    leased: Dict[str, Tuple[int, str]] = {}
    for lease in leases:
        if not isinstance(lease, dict) or int(lease.get("state") or 0) != 0:
            continue
        address = str(lease.get("ip-address") or lease.get("ip") or "").strip()
        name = str(lease.get("hostname") or "").strip().rstrip(".").lower()
        try:
            ip = ipaddress.ip_address(address)
            cltt = int(lease.get("cltt") or 0)
            expires = cltt + int(lease.get("valid-lft") or 0)
        except (ValueError, TypeError):
            continue
        if ip.version != 4 or not name or (cltt and expires < now):
            continue
        if not all(_LABEL_RE.match(l) for l in name.split(".")):
            continue
        if not any(ip in net for net in nets if net.version == 4):
            continue
        fqdn = qualify_dns_name(name, address, scopes).lower()
        if fqdn not in leased or cltt >= leased[fqdn][0]:
            leased[fqdn] = (cltt, address)

    out: List[Dict[str, Any]] = []
    done = set()
    for rec in records:
        key = str(rec.get("name") or "").rstrip(".").lower()
        if rec.get("type") != "A" or key not in leased:
            out.append(rec)
            continue
        # Collapse every A record for a leased name into one at the lease address.
        if key not in done:
            done.add(key)
            out.append(dict(rec, value=leased[key][1]))
    return out


def is_dhcp_scope(prefix: Dict[str, Any]) -> bool:
    """Whether a NetBox prefix row becomes a Kea scope (see ``build_dhcp_payload``).

    It needs a prefix value, a status other than ``container`` and a truthy
    ``custom_fields.dhcp_enabled``.
    """
    # Rows without a prefix value are never scopes.
    if not isinstance(prefix, dict) or not prefix.get("prefix"):
        return False
    # Aggregate/parent blocks are never scopes themselves.
    status = prefix.get("status")
    if isinstance(status, dict):
        status = status.get("value")
    if str(status or "").lower() == "container":
        return False
    # Only prefixes explicitly opted in with the checkbox.
    return bool((prefix.get("custom_fields") or {}).get("dhcp_enabled"))


def build_dhcp_payload(pfx_data: Dict[str, Any],
                       ips_data: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """NetBox prefixes + IPs → (subnets, reservations) Kea sync payload.

    Subnets come from prefixes (gateway/dns_servers off custom_fields); a
    reservation is minted for every IP carrying a truthy
    ``custom_fields.dhcp_reservation`` AND a ``custom_fields.mac_address``.
    Shared by the loop and ``POST /api/dhcp/sync``.

    ``dhcp_reservation`` is a separate, explicit opt-in from ``mac_address``
    on purpose: nw/firewall ARP discovery and the CPPM access-tracker sync
    stamp ``mac_address`` on ANY device they see for identity purposes (and
    the DHCP-lease write-back fills it in too, for DNS), so a plain dynamic
    lease picks up a ``mac_address`` the moment the host ARPs on the network.
    Minting a reservation off ``mac_address`` presence alone turned every such
    lease into a static reservation on the next sync — a lease and a
    reservation are different things and must stay that way.

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
        """Split a comma-separated string into trimmed, non-empty items."""
        return [v.strip() for v in (raw or "").split(",") if v.strip()]

    # Build one Kea subnet per eligible prefix.
    subnets: List[Dict[str, Any]] = []
    for p in (pfx_data.get("prefixes") or []):
        # Skip prefixes that are not opted-in DHCP scopes.
        if not is_dhcp_scope(p):
            continue
        prefix_str = p.get("prefix", "")
        # Custom fields hold the DHCP options.
        cf = p.get("custom_fields") or {}
        # Translate NetBox custom fields into the spoke's subnet shape.
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

    # Build reservations from IPs explicitly marked for one.
    reservations: List[Dict[str, Any]] = []
    for ip in (ips_data.get("ip_addresses") or []):
        # MAC and address (without prefix length).
        cf = ip.get("custom_fields") or {}
        mac = (cf.get("mac_address") or "").strip()
        address = (ip.get("address") or "").split("/")[0].strip()
        # Need a MAC, an address and the explicit opt-in.
        if mac and address and cf.get("dhcp_reservation"):
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
    # Accept one result or a list (one per DHCP spoke).
    results = spoke_result if isinstance(spoke_result, list) else [spoke_result]
    # Total skipped and applied reservations.
    skipped = applied = 0
    for r in results:
        if not isinstance(r, dict):
            continue
        # Ignore non-numeric counters.
        try:
            skipped += int(r.get("reservations_skipped") or 0)
            applied += int(r.get("reservations") or 0)
        except (TypeError, ValueError):
            continue
    # Nothing skipped: no warning.
    if skipped <= 0:
        return {}
    # "every" if none applied, else "N of M".
    what = "every" if applied == 0 else f"{skipped} of {skipped + applied}"
    # Warning text tells the operator how to fix it.
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
        # Read global_config[dns_dhcp_sync]; "or {}" guards against a stored None.
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_CFG_KEY, {}) or {}
        # Apply defaults.
        return {
            "enabled":  bool(cfg.get("enabled", True)),
            "interval": int(cfg.get("interval", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL),
        }

    def _dhcp_hold_declined(self) -> bool:
        """global_config.dhcp_kea.hold_declined: keep DECLINEd addresses out of
        use for Kea's 24h default (True) or only 60s (False, the default)."""
        gc = self.state.system_state.get("global_config", {}) or {}
        return bool((gc.get("dhcp_kea") or {}).get("hold_declined", False))

    def _dns_hook_desired(self) -> Dict[str, Any]:
        """Desired real-time DNS hook settings, normalized the way the dhcp
        spoke stores them (kea_dns_hook.validate_settings) so a converged node
        never reads as drifted."""
        # Read global_config[dhcp_dns_hook].
        gc = self.state.system_state.get("global_config", {}) or {}
        cfg = gc.get(_HOOK_CFG_KEY, {}) or {}
        # Non-empty target strings.
        targets = [str(t).strip() for t in (cfg.get("targets") or []) if str(t).strip()]
        # TTL; fall back to 300 if not a number.
        try:
            ttl = int(cfg.get("ttl", 300) or 300)
        except (TypeError, ValueError):
            ttl = 300
        # Normalised settings with defaults.
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
        # Desired settings, target spokes and result accumulators.
        desired = self._dns_hook_desired()
        spokes = self._get_dhcp_spokes()
        applied = []
        errors = {}

        # No DHCP spoke: record skipped.
        if not spokes:
            return self._record_status("dns_hook", status="skipped", enabled=desired["enabled"], reason="DHCP spoke not connected")

        def _drifted(node: dict) -> bool:
            """Return True if ``node``'s hook state differs from the desired settings."""
            # The node's current settings.
            s = (node or {}).get("settings") or {}
            # Desired off: drifted if it is still on or loaded.
            if not desired["enabled"]:
                return bool(s.get("enabled")) or node.get("loaded_in_running_config") is True
            # Desired on: drifted if off or not loaded.
            if not s.get("enabled") or node.get("loaded_in_running_config") is False:
                return True
            # Or if any setting differs.
            for k in ("targets", "domain", "ttl", "register_ptr"):
                if s.get(k) != desired[k]:
                    return True
            return False

        # Check and, if needed, fix each DHCP spoke.
        for sid in spokes:
            try:
                # Read the spoke's current hook status.
                st = unwrap_spoke(await self.request_response(sid, "DHCP_DNS_HOOK_STATUS", {}, timeout=30.0)) or {}
                members = st.get("members")
                if st.get("status") == "ERROR" and not members and "settings" not in st:
                    # e.g. a dhcp spoke too old to know the command — report,
                    # don't blindly re-push config every tick.
                    errors[sid] = str(st.get("message") or st.get("error") or "status read failed")
                    continue
                # A cluster reports per-member status; otherwise the spoke itself is the only node.
                nodes = list(members.values()) if isinstance(members, dict) and members else [st]
                # Nothing drifted: leave it alone.
                if not any(_drifted(n if isinstance(n, dict) else {}) for n in nodes):
                    continue
                # Push the desired settings.
                res = unwrap_spoke(await self.request_response(sid, "DHCP_DNS_HOOK_CONFIG", {"settings": dict(desired), "hook_dir": ""}, timeout=30.0)) or {}
                # Record success or the error message.
                if res.get("status") in ("SUCCESS", "PARTIAL"):
                    applied.append(sid)
                    logger.info("DNS hook %s on %s", "enabled" if desired["enabled"] else "disabled", sid)
                else:
                    errors[sid] = str(res.get("message") or res.get("error") or res.get("member_errors") or "config failed")
            # Transport failure: record and log.
            except Exception as e:
                errors[sid] = str(e)
                logger.warning("DNS hook reconcile %s failed: %s", sid, e)

        # Record overall status.
        return self._record_status("dns_hook", status=("error" if errors else "ok"), enabled=desired["enabled"], applied=applied, errors=errors, spokes=len(spokes))

    @property
    def dns_dhcp_sync_status(self) -> Dict[str, Any]:
        """Last-run status for each side; lazily initialized (mixin has no __init__)."""
        # Create the status dict on first access.
        st = getattr(self, "_dns_dhcp_sync_status", None)
        if st is None:
            st = {"dns": {}, "dhcp": {}, "dns_hook": {}}
            self._dns_dhcp_sync_status = st
        return st

    def _record_status(self, side: str, **fields) -> Dict[str, Any]:
        """Record ``fields`` plus the current time as ``side``'s last-run status; returns the
        entry.
        """
        # Stamp with the current time and store.
        entry = {"last_run": time.time(), **fields}
        self.dns_dhcp_sync_status[side] = entry
        return entry

    def _ipam_spoke_candidates(self) -> List[str]:
        """Connected IPAM spokes, the one bound to a configured ipam_instance
        first. With several IPAM spokes connected (e.g. a dedicated NetBox
        spoke plus a netbox role on a generic agent) "first registered wins"
        can land on one with no NetBox URL configured."""
        # Primary IPAM spoke, then all IPAM spokes (if the hub supports listing them).
        first = self.get_spoke_by_type("ipam")
        spokes = []
        if hasattr(self, "get_all_spokes_by_type"):
            spokes = list(self.get_all_spokes_by_type("ipam") or [])
        # Make sure the primary is included and first.
        if first and first not in spokes:
            spokes.insert(0, first)
        # Function mapping a spoke id to its primary key (identity if unavailable).
        pk = getattr(self, "_primary_key", None) or (lambda s: s)
        # Spokes referenced by configured IPAM instances.
        gc = (self.state.system_state or {}).get("global_config", {}) or {}
        bound = {pk(str(i.get("spoke_id"))) for i in (gc.get("ipam_instances") or [])
                 if isinstance(i, dict) and i.get("spoke_id")}
        # Bound spokes first, keeping the original order otherwise.
        return sorted(spokes, key=lambda s: 0 if pk(s) in bound else 1)

    async def _netbox_prefixes_and_ips(self, filters: Dict[str, Any] = None,
                                       spoke: str = None
                                       ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Fetch NetBox prefixes + IPs, failing over across IPAM spokes.

        Raises unless a spoke returns BOTH lists. A spoke-side failure comes
        back as ``{"status": "ERROR", ...}`` with no ``prefixes`` key; treating
        that as "zero prefixes" made the sync push an empty subnet4 and wipe
        every Kea scope whenever NetBox was unreachable from the chosen spoke.

        ``filters`` (``tenant`` / ``tenant_group``, see ``_sync_scope``) is
        passed to both reads so a tenant-dedicated target only gets its own
        tenant's prefixes and IPs.

        ``spoke`` reads from that one spoke only, with no failover: a caller
        that writes back by NetBox id must write to the instance it read.
        """
        # Filters for both reads, and spokes to try in order.
        req = dict(filters or {})
        candidates = [spoke] if spoke else self._ipam_spoke_candidates()
        if not candidates:
            raise RuntimeError("NetBox spoke not connected")
        # Try each spoke until one returns both lists.
        errors = []
        for nb in candidates:
            # Read prefixes and IPs in parallel.
            try:
                pfx_raw, ips_raw = await asyncio.gather(
                    self.request_response(nb, "NETBOX_GET_PREFIXES", dict(req), timeout=30.0),
                    self.request_response(nb, "NETBOX_GET_IPS", dict(req), timeout=30.0),
                )
            except Exception as e:  # noqa: BLE001 — try the next IPAM spoke
                errors.append(f"{nb}: {e}")
                continue
            # Unwrap and check each reply is a successful dict containing its list.
            pfx, ips = unwrap_spoke(pfx_raw), unwrap_spoke(ips_raw)
            bad = [f"{what}: {(d or {}).get('message') if isinstance(d, dict) else d!r}"
                   for what, d, key in (("prefixes", pfx, "prefixes"),
                                        ("ip_addresses", ips, "ip_addresses"))
                   if not isinstance(d, dict) or str(d.get("status", "")).upper() == "ERROR"
                   or not isinstance(d.get(key), list)]
            # Any problem: remember it and try the next spoke.
            if bad:
                errors.append(f"{nb}: " + "; ".join(bad))
                continue
            # Both lists OK.
            return pfx, ips
        # Every spoke failed.
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
        # Imported lazily: tenant binding and NetBox tenant scope helpers.
        from access import spoke_is_unbound, netbox_tenant_scope
        # Look up the spoke's tenant and its NetBox scope; any error fails closed.
        try:
            # Unbound spoke: unfiltered.
            if spoke_is_unbound(self, spoke_id):
                return "", {}
            tenant = self.state.get_spoke_tenant(spoke_id) or ""
            scope = netbox_tenant_scope(self, tenant)
        except Exception as e:  # noqa: BLE001 — fail closed
            logger.warning("DNS/DHCP sync: tenant scope for %s unreadable: %s", spoke_id, e)
            return None, None
        # NetBox filters for the tenant.
        filters = {k: scope.get(k) for k in ("tenant", "tenant_group") if scope.get(k)}
        # Tenant has no NetBox mapping: skip the spoke.
        if not filters:
            logger.warning("DNS/DHCP sync: %s is bound to tenant %r with no NetBox "
                           "tenant mapping — not synced", spoke_id, tenant)
            return None, None
        # Scoped key and filters.
        return "tenant:" + str(scope.get("key")), filters

    def _scope_groups(self, spokes):
        """Group target spokes by ``_sync_scope`` →
        ``({key: (filters, [sids])}, [skipped sids])``."""
        # Groups and skipped spokes.
        groups, skipped = {}, []
        # Put each spoke in its scope group, or skip it.
        for sid in spokes:
            key, filters = self._sync_scope(sid)
            if key is None:
                skipped.append(sid)
                continue
            groups.setdefault(key, (filters, []))[1].append(sid)
        return groups, skipped

    @staticmethod
    def _hash_key(side: str, scope_key: str) -> str:
        """Return the hash-cache key for a side and scope ("dns" or "dns|tenant:x")."""
        return side if not scope_key else f"{side}|{scope_key}"

    @staticmethod
    def _push_error(result) -> str:
        """Why a spoke push failed ("" when it worked).

        A spoke that ran but failed (e.g. Kea rejected the config-set and kept
        its OLD config) replies ``{"status": "ERROR"}`` instead of raising. It
        must count as a failure, or the payload hash latches and the change is
        never retried while the WebUI shows "ok".
        """
        if isinstance(result, Exception):
            return str(result) or type(result).__name__
        reply = unwrap_spoke(result)
        if isinstance(reply, dict) and str(reply.get("status", "")).upper() == "ERROR":
            return str(reply.get("message") or reply.get("error") or "spoke reported ERROR")
        return ""

    async def _scoped_push(self, side: str, spokes: List[str]):
        """On-demand (non-hashed) push of one side to ``spokes``, one NetBox
        fetch per tenant scope. Returns ``(counts, spoke_results, skipped)``;
        raises on a fetch or push failure."""
        # Group spokes by tenant scope and set up counters.
        groups, skipped = self._scope_groups(spokes)
        counts = ({"records_synced": 0} if side == "dns" else
                  {"subnets_synced": 0, "reservations_synced": 0})
        spoke_results = []
        # Fetch NetBox once per scope and push to that scope's spokes.
        for _key, (filters, sids) in groups.items():
            pfx_data, ips_data = await self._netbox_prefixes_and_ips(filters)
            # Build the DNS or DHCP payload and count it.
            if side == "dns":
                records = apply_kea_leases(build_dns_records(ips_data, pfx_data),
                                           await self._kea_leases(self._get_dhcp_spokes()),
                                           pfx_data)
                payload, cmd = {"records": records}, "DNS_SYNC"
                counts["records_synced"] += len(records)
            else:
                subnets, reservations = build_dhcp_payload(pfx_data, ips_data)
                payload = {"subnets": subnets, "reservations": reservations,
                           "hold_declined": self._dhcp_hold_declined()}
                cmd = "DHCP_SYNC"
                counts["subnets_synced"] += len(subnets)
                counts["reservations_synced"] += len(reservations)
            # Push to all spokes in this scope in parallel; any failure is raised.
            results = await asyncio.gather(*[
                self.request_response(sid, cmd, payload, timeout=30.0) for sid in sids
            ], return_exceptions=True)
            errs = [e for e in map(self._push_error, results) if e]
            if errs:
                raise RuntimeError(errs[0])
            # Collect the unwrapped spoke results.
            spoke_results.extend(unwrap_spoke(r) for r in results)
        return counts, spoke_results, skipped

    async def _kea_leases(self, dhcp_spokes: List[str]) -> List[Dict[str, Any]]:
        """Active v4 leases from every DHCP spoke. On any failure the last
        good list is reused, so a missed read never flips DNS back to stale
        NetBox addresses for one cycle."""
        if not dhcp_spokes:
            return []
        replies = await asyncio.gather(*[
            self.request_response(sid, "DHCP_LIST_LEASES", {}, timeout=30.0)
            for sid in dhcp_spokes], return_exceptions=True)
        leases: List[Dict[str, Any]] = []
        for sid, raw in zip(dhcp_spokes, replies):
            reply = None if isinstance(raw, BaseException) else unwrap_spoke(raw)
            if not isinstance(reply, dict) or str(reply.get("status", "")).upper() == "ERROR" \
                    or not isinstance(reply.get("leases"), list):
                logger.warning("DNS sync: could not read Kea leases from %s; using last list", sid)
                return getattr(self, "_last_kea_leases", [])
            leases.extend(reply["leases"])
        self._last_kea_leases = leases
        return leases

    def _get_dhcp_spokes(self) -> List[str]:
        """All connected, approved DHCP spokes to sync to."""
        # Prefer every connected, approved DHCP spoke.
        if hasattr(self, "get_all_spokes_by_type") and hasattr(self, "active_connections"):
            all_spokes = [
                s for s in (self.get_all_spokes_by_type("dhcp") or [])
                if s in self.active_connections and getattr(self, "approved_modules", {}).get(s, False)
            ]
            if all_spokes:
                return all_spokes
        # Fallback: the single DHCP spoke, if any.
        single = self.get_spoke_by_type("dhcp")
        return [single] if single else []

    def _get_dns_spokes(self) -> List[str]:
        """All connected, approved DNS spokes to sync to."""
        # Prefer every connected, approved DNS spoke.
        if hasattr(self, "get_all_spokes_by_type") and hasattr(self, "active_connections"):
            all_spokes = [
                s for s in (self.get_all_spokes_by_type("dns") or [])
                if s in self.active_connections and getattr(self, "approved_modules", {}).get(s, False)
            ]
            if all_spokes:
                return all_spokes
        # Fallback: the single DNS spoke, if any.
        single = self.get_spoke_by_type("dns")
        return [single] if single else []

    async def sync_dns_from_netbox(self) -> Dict[str, Any]:
        """Reconcile Unbound to NetBox DNS names. Returns a status dict.

        ``status`` is ``ok`` on success, ``skipped`` when a required spoke is
        offline (loop no-ops quietly), or ``error`` on failure.
        """
        # Need a DNS spoke and NetBox; otherwise record skipped.
        dns_spokes = self._get_dns_spokes()
        if not dns_spokes or not self.get_spoke_by_type("ipam"):
            missing = "DNS" if not dns_spokes else "NetBox"
            return self._record_status("dns", status="skipped",
                                       reason=f"{missing} spoke not connected")
        # Push per scope and record success (or the error).
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
        # Need a DHCP spoke and NetBox; otherwise record skipped.
        dhcp_spokes = self._get_dhcp_spokes()
        if not dhcp_spokes or not self.get_spoke_by_type("ipam"):
            missing = "DHCP" if not dhcp_spokes else "NetBox"
            return self._record_status("dhcp", status="skipped",
                                       reason=f"{missing} spoke not connected")
        # Push per scope and record success (with any skipped-reservation warning) or the error.
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

        ``self._dhcp_delivered`` ends up holding the DHCP scope keys whose Kea
        now has this tick's NetBox data (pushed, or unchanged since the last
        push); the static-reservations rollback undoes only the other scopes.
        """
        # Nothing delivered yet; an early return or a raise leaves it empty.
        self._dhcp_delivered = set()
        # Nothing to do without NetBox or any target spoke.
        ipam = self.get_spoke_by_type("ipam")
        if not ipam:
            return
        dns_spokes = self._get_dns_spokes()
        dhcp_spokes = self._get_dhcp_spokes()
        if not dns_spokes and not dhcp_spokes:
            return

        # Group DNS and DHCP spokes by tenant scope.
        dns_groups, dns_skipped = self._scope_groups(dns_spokes)
        dhcp_groups, dhcp_skipped = self._scope_groups(dhcp_spokes)

        # Distinct scopes across both sides.
        scopes = {}
        for groups in (dns_groups, dhcp_groups):
            for key, (filters, _sids) in groups.items():
                scopes.setdefault(key, filters)

        # Fetch NetBox data once per scope.
        fetched, fetch_errors = {}, {}
        for key, filters in scopes.items():
            try:
                fetched[key] = await self._netbox_prefixes_and_ips(filters)
            except Exception as e:  # noqa: BLE001
                fetch_errors[key] = str(e)
                logger.warning("DNS/DHCP sync: NetBox fetch failed (%s): %s", key or "all", e)

        # Kea's live leases correct NetBox addresses for DHCP hosts.
        leases = await self._kea_leases(dhcp_spokes) if dns_groups else []

        # Hashes from last tick; new ones start as a copy.
        last = getattr(self, "_last_sync_hashes", None) or {}
        new_hashes = dict(last)
        # Per-side status accumulators.
        st = {side: {"error": None, "records_synced": 0, "subnets_synced": 0,
                     "reservations_synced": 0, "spoke_results": []}
              for side in ("dns", "dhcp")}

        # Push coroutines and, per scope, which ones belong to it.
        pushes, push_groups = [], []
        # Build each side's payload per scope.
        for side, groups in (("dns", dns_groups), ("dhcp", dhcp_groups)):
            for key, (_filters, sids) in groups.items():
                # Fetch failed for this scope: record the error and skip.
                if key not in fetched:
                    if st[side]["error"] is None:
                        st[side]["error"] = fetch_errors.get(key) or "NetBox fetch failed"
                    continue
                # This scope's NetBox data.
                pfx, ips = fetched[key]
                # Build the payload, hash it and count it.
                if side == "dns":
                    records = apply_kea_leases(build_dns_records(ips, pfx), leases, pfx)
                    payload = {"records": records}
                    h = hashlib.sha256(json.dumps(records, sort_keys=True,
                                                  default=str).encode()).hexdigest()
                    st[side]["records_synced"] += len(records)
                else:
                    subnets, reservations = build_dhcp_payload(pfx, ips)
                    payload = {"subnets": subnets, "reservations": reservations,
                               "hold_declined": self._dhcp_hold_declined()}
                    h = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                                  default=str).encode()).hexdigest()
                    st[side]["subnets_synced"] += len(subnets)
                    st[side]["reservations_synced"] += len(reservations)
                # Unchanged since last time: skip the push.
                hk = self._hash_key(side, key)
                if last.get(hk) == h:
                    new_hashes[hk] = h
                    if side == "dhcp":
                        self._dhcp_delivered.add(key)
                    continue
                # Queue a push to each spoke in this scope, remembering its index.
                cmd = "DNS_SYNC" if side == "dns" else "DHCP_SYNC"
                indices = []
                for sid in sids:
                    indices.append(len(pushes))
                    pushes.append(self.request_response(sid, cmd, payload, timeout=30.0))
                push_groups.append((side, key, hk, h, indices))

        # Run all pushes in parallel.
        results = await asyncio.gather(*pushes, return_exceptions=True) if pushes else []
        # Latch a scope's hash ONLY when every push for it succeeded, so a
        # transiently-offline spoke is retried next cycle.
        for side, key, hk, h, indices in push_groups:
            res = [results[i] for i in indices]
            errs = [e for e in map(self._push_error, res) if e]
            if errs:
                logger.warning("%s auto-sync push failed: %s", side.upper(), errs[0])
                if st[side]["error"] is None:
                    st[side]["error"] = str(errs[0])
            else:
                new_hashes[hk] = h
                st[side]["spoke_results"].extend(unwrap_spoke(r) for r in res)
                if side == "dhcp":
                    self._dhcp_delivered.add(key)

        # Record each side's status.
        for side, skipped in (("dns", dns_skipped), ("dhcp", dhcp_skipped)):
            s = st[side]
            # Any error: record it.
            if s["error"]:
                self._record_status(side, status="error", error=s["error"])
                continue
            # Counts for this side.
            fields = ({"records_synced": s["records_synced"]} if side == "dns" else
                      {"subnets_synced": s["subnets_synced"],
                       "reservations_synced": s["reservations_synced"]})
            # Attach spoke results, or note the push was skipped as unchanged.
            results_ = s["spoke_results"]
            if results_:
                single = results_[0] if len(results_) == 1 else results_
                if side == "dhcp":
                    fields.update(dhcp_skip_warning(single))
                fields["spoke_result"] = single
            else:
                fields["skipped_unchanged"] = True
            # List spokes skipped for missing tenant scope.
            if skipped:
                fields["skipped_spokes"] = list(skipped)
            self._record_status(side, status="ok", **fields)

        # Save hashes for next tick.
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
        # Log loop start.
        logger.info("DNS/DHCP NetBox auto-sync loop started.")

        def _delay() -> float:
            """Return seconds until the next tick (configured interval, minimum 30 s)."""
            try:
                return max(30, self._dds_cfg()["interval"])
            except Exception:  # noqa: BLE001 — bad config falls back to default
                return max(30, _DEFAULT_INTERVAL)

        async def _body():
            # The real-time hook has its own on/off knob, so it converges even
            # while the NetBox reconciliation below is disabled.
            """One tick: converge the DNS hook, then (if enabled) reconcile Unbound/Kea to
            NetBox.
            """
            try:
                await self._reconcile_dns_hook()
            except Exception as e:  # noqa: BLE001
                logger.warning("DNS hook reconcile failed: %s", e)
            from static_ip_reservations import (reserve_static_hosts_once,
                                                roll_back_if_sync_failed)
            sync_on = self._dds_cfg()["enabled"]
            # The netbox spoke marks statically addressed hosts as
            # reservations first, so this tick's sync already pushes them to
            # Kea. With the sync off the pass records "disabled".
            try:
                await reserve_static_hosts_once(self, sync_enabled=sync_on)
            except Exception as e:  # noqa: BLE001 — never block the sync
                logger.warning("static IP reservations pass failed: %s", e)
            if not sync_on:
                return
            # Single NetBox fetch + skip-if-unchanged (see
            # _sync_dns_dhcp_once). The manual /api/dns|dhcp/sync buttons
            # still call the per-side methods directly (they re-fetch,
            # which is correct for an explicit button press).
            try:
                await self._sync_dns_dhcp_once()
            finally:
                # A scope whose DHCP sync failed (or a sync that raised) would
                # leave the pass's reservations in NetBox only; undo those.
                try:
                    await roll_back_if_sync_failed(self)
                except Exception as e:  # noqa: BLE001
                    logger.warning("static IP reservations rollback failed: %s", e)

        # Run forever with no startup delay; errors are logged and retried after the interval.
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
        # Log loop start.
        logger.info("DNS/DHCP page data-feed loop started.")

        async def _body():
            """One tick: refresh the DNS/DHCP page cache, if the feed function is registered."""
            # Set by routes.net_services; may be absent.
            feed = getattr(self, "net_services_feed_once", None)
            if feed:
                await feed()

        # Every 60 s, starting 20 s after startup.
        await run_sync_loop(
            stagger=20, body=_body, delay=lambda: 60.0,
            on_error=lambda e: logger.warning("DNS/DHCP feed loop error: %s", e),
            error_delay=60.0)
