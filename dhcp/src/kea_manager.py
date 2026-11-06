# Encoding, copying, JSON, logging and regex helpers.
"""Kea DHCP manager: renders LM/NetBox intent into Kea config and talks to the Control Agent.

Holds the pure config builders (subnet4/subnet6, pools, options, reservations) shared with
the HA coordinator, plus the KeaManager client used for sync, leases, reservations, stats,
diagnostics and packet tracing on a single node.
"""
import base64
import copy
import json
import logging
import re
# Type hints.
from typing import Any, Dict, List, Optional, Tuple, Union
# HTTP calls to the Kea Control Agent.
import urllib.error
import urllib.request
# Address math.
import ipaddress
# OS, user lookup, tool lookup and subprocess helpers.
import os
import pwd
import shutil
import subprocess
# CRC32 for stable subnet ids.
import zlib

# Packet-trace helpers; the import path differs between layouts.
try:
    import kea_packet_trace as pkt_trace
except ImportError:  # loaded as a package (src.X)
    from src import kea_packet_trace as pkt_trace  # type: ignore
try:
    import kea_dns_hook
except ImportError:  # loaded as a package (src.X)
    from src import kea_dns_hook  # type: ignore

# Module logger.
logger = logging.getLogger("KeaManager")


def worker_code_version() -> dict:
    """Best-effort ``{commit, commit_time, dirty}`` for the running worker's
    own checkout — added because a recurring "same error keeps coming back"
    report turned out to be a stale checkout that never received a merged
    fix (this worker's only code-update path is re-running the installer;
    there is no self-update). Surfacing the actual running commit + when it
    landed in diagnostics lets an operator immediately tell "still on old
    code" apart from "the fix is deployed but the failure is real", instead
    of needing separate manual git access to the host.
    """
    # Repo root is three levels up from this file.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    out = {"commit": "", "commit_time": "", "dirty": None}
    # Without git or a checkout there is nothing to report.
    if not shutil.which("git") or not os.path.isdir(os.path.join(repo_root, ".git")):
        return out
    # Short commit hash.
    try:
        commit = subprocess.run(
            ["git", "-C", repo_root, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=10)
        if commit.returncode == 0:
            out["commit"] = commit.stdout.strip()
        # Commit time.
        ctime = subprocess.run(
            ["git", "-C", repo_root, "log", "-1", "--format=%cI"],
            capture_output=True, text=True, timeout=10)
        if ctime.returncode == 0:
            out["commit_time"] = ctime.stdout.strip()
        # Whether the checkout has local changes.
        dirty = subprocess.run(
            ["git", "-C", repo_root, "status", "--porcelain"],
            capture_output=True, text=True, timeout=10)
        if dirty.returncode == 0:
            out["dirty"] = bool(dirty.stdout.strip())
    except Exception:  # noqa: BLE001 — best-effort only
        pass
    # Return whatever was collected.
    return out


def _stable_subnet_id(subnet_str: str, taken: set) -> int:
    """Deterministic Kea ``subnet-id`` for a CIDR, stable across syncs.

    The old scheme assigned ``id = enumerate(subnets, start=1)`` — a bare
    list POSITION. Any NetBox-side change that shifts the list (a scope
    removed, reordered, or one inserted ahead of others) silently reassigns
    every downstream subnet to a DIFFERENT numeric id on the very next sync.
    Kea does not purge ``statistic-get-all`` history for an id that
    disappears from ``subnet4`` on a ``config-set`` — those samples linger
    in the running daemon's memory until it restarts — so each reshuffle
    left the OLD id's stats behind as a permanent "Unknown scope (not in
    NetBox — stale?)" 0/0 entry in the Overview, and every subsequent
    NetBox edit minted a fresh batch of them.

    Deriving the id from the CIDR itself instead means a given scope keeps
    the same id release over release regardless of how many OTHER scopes
    are added, removed, or reordered around it — nothing is orphaned, so
    nothing goes stale. ``taken`` guards the astronomically unlikely CRC32
    collision by linear-probing to the next free id.
    """
    # Base id from the CIDR's CRC32.
    base = zlib.crc32(subnet_str.encode()) & 0x7FFFFFFF or 1  # never 0
    sid = base
    # Probe forward past ids already in use.
    while sid in taken:
        sid = (sid % 0x7FFFFFFF) + 1
    # Claim the id.
    taken.add(sid)
    return sid


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to colon-separated lowercase format (aa:bb:cc:dd:ee:ff)."""
    # Empty input stays empty.
    if not mac:
        return ""
    # Keep only hex digits; 12 of them become aa:bb:... form.
    clean = re.sub(r'[^0-9a-fA-F]', '', str(mac)).lower()
    if len(clean) == 12:
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))
    # Otherwise just tidy separators and case.
    return str(mac).strip().lower().replace("-", ":")


def _add_option(kea_subnet: dict, name: str, value) -> None:
    """Append one Kea ``option-data`` entry if ``value`` is non-empty.

    ``value`` may be a plain string or a list (comma-joined the way Kea
    expects a multi-value option, e.g. multiple NTP servers).
    """
    # Join list values into one comma-separated string.
    if isinstance(value, (list, tuple)):
        value = ", ".join(v for v in value if v)
    # Skip empty values.
    if not value:
        return
    # Add the option.
    kea_subnet["option-data"].append({"name": name, "data": value})


def _clean_gateway(raw, net) -> str:
    """The scope gateway as a bare IPv4 address, or "" when it is unusable.

    The value is free text from NetBox. Kea rejects the WHOLE config-set when
    one ``routers`` option is malformed (e.g. "172.21.0.1/24"), and then keeps
    running its old config — so one bad gateway silently froze every scope.
    A trailing "/mask" is dropped; anything else invalid is logged and skipped.
    """
    value = str(raw or "").strip().split("/")[0].strip()
    if not value:
        return ""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        logger.warning("Scope %s: gateway %r is not an IP address — no router option sent", net, raw)
        return ""
    if ip.version != 4:
        logger.warning("Scope %s: gateway %s is not IPv4 — no router option sent", net, ip)
        return ""
    if ip not in net:
        logger.warning("Scope %s: gateway %s is outside the subnet", net, ip)
    return str(ip)


def _routers_of(options) -> str:
    """The ``routers`` option value from a Kea option-data list ("" if none)."""
    for o in options or []:
        if isinstance(o, dict) and (o.get("name") == "routers" or o.get("code") == 3):
            return str(o.get("data") or "").strip()
    return ""


def scope_gateway_findings(config: dict) -> tuple:
    """Per-scope default gateway as Kea will hand it out, plus problems.

    Returns ``(gateways, problems)``: ``gateways`` maps subnet → router ("" when
    none); ``problems`` lists one readable line per scope with no router or a
    router outside the subnet. A subnet-level ``routers`` option wins over the
    global one, matching Kea.
    """
    global_router = _routers_of((config or {}).get("option-data"))
    gateways, problems = {}, []
    for sub in (config or {}).get("subnet4") or []:
        subnet = str(sub.get("subnet") or "")
        router = _routers_of(sub.get("option-data")) or global_router
        gateways[subnet] = router
        if not router:
            problems.append(f"Scope {subnet} hands out no default gateway — set "
                            "Gateway on its NetBox prefix, then sync DHCP.")
            continue
        try:
            net = ipaddress.ip_network(subnet, strict=False)
            outside = [r.strip() for r in router.split(",")
                       if ipaddress.ip_address(r.strip()) not in net]
        except ValueError:
            problems.append(f"Scope {subnet} has an unreadable gateway {router!r}.")
            continue
        if outside:
            problems.append(f"Scope {subnet} gateway {', '.join(outside)} is outside "
                            "the subnet — clients cannot reach it.")
    return gateways, problems


# Standard DHCPv4 options beyond gateway/DNS that a scope may carry, sourced
# from the same NetBox prefix custom_fields as gateway/dns_servers (see
# ``dns_dhcp_sync.build_dhcp_payload``). Table-driven so adding another
# standard option is a one-line addition here plus the matching
# custom_fields read on the sync side, instead of a new one-off `if` block
# per option. Each entry is (subnet-dict key, Kea option-data "name").
_ADVANCED_OPTION_MAP = [
    ("domain_name",          "domain-name"),
    ("ntp_servers",          "ntp-servers"),
    ("tftp_server_name",     "tftp-server-name"),
    ("boot_file_name",       "boot-file-name"),
    ("netbios_name_servers", "netbios-name-servers"),
    ("broadcast_address",    "broadcast-address"),
]


def _parse_exclusion_ranges(raw_exclusions) -> list:
    """Parse exclusion ranges string or list into a list of (start_int, end_int) tuples."""
    # Nothing to parse.
    if not raw_exclusions:
        return []
    # Split a string on commas/semicolons, or take a collection as is.
    items = []
    if isinstance(raw_exclusions, str):
        items = [x.strip() for x in raw_exclusions.replace(";", ",").split(",") if x.strip()]
    elif isinstance(raw_exclusions, (list, tuple, set)):
        items = list(raw_exclusions)

    # Turn each item into an (start, end) integer range.
    parsed = []
    for item in items:
        # Dict items carry start/end.
        if isinstance(item, dict):
            s, e = item.get("start"), item.get("end")
            if s and e:
                # Skip unparseable addresses.
                try:
                    s_int = int(ipaddress.ip_address(str(s).strip()))
                    e_int = int(ipaddress.ip_address(str(e).strip()))
                    parsed.append((min(s_int, e_int), max(s_int, e_int)))
                except ValueError:
                    continue
        # String items are "a-b" ranges or single addresses.
        elif isinstance(item, str):
            item = item.strip()
            if not item:
                continue
            # A range.
            if "-" in item:
                parts = item.split("-", 1)
                try:
                    s_int = int(ipaddress.ip_address(parts[0].strip()))
                    e_int = int(ipaddress.ip_address(parts[1].strip()))
                    parsed.append((min(s_int, e_int), max(s_int, e_int)))
                except ValueError:
                    continue
            # A single address.
            else:
                try:
                    ip_int = int(ipaddress.ip_address(item))
                    parsed.append((ip_int, ip_int))
                except ValueError:
                    continue
    # Return the ranges.
    return parsed


def _pools_without(pools: list, ip: str) -> list:
    """Return ``pools`` with ``ip`` removed, so Kea never offers e.g. the gateway.

    Offering the router's own address makes the client's ARP probe hit the
    router, the client sends DHCPDECLINE and Kea parks the address as Declined.
    """
    target = int(ipaddress.ip_address(ip))
    ranges = []
    for p in pools:
        start, end = (int(ipaddress.ip_address(x.strip())) for x in p["pool"].split("-"))
        ranges.append((start, end))
    if not any(start <= target <= end for start, end in ranges):
        return pools
    return _carve_pools(ranges, [(target, target)])


def _carve_pools(base_ranges: list, exclusions: list) -> list:
    """Carve exclusion ranges out of base IP ranges [(start_int, end_int)]."""
    # No exclusions: one pool per valid base range.
    if not exclusions:
        return [{"pool": f"{ipaddress.ip_address(s)} - {ipaddress.ip_address(e)}"}
                for s, e in base_ranges if s <= e]

    # Sort exclusions and merge overlapping or adjacent ones.
    sorted_ex = sorted(exclusions, key=lambda x: x[0])
    merged_ex = []
    for ex_s, ex_e in sorted_ex:
        if not merged_ex:
            merged_ex.append((ex_s, ex_e))
        else:
            prev_s, prev_e = merged_ex[-1]
            if ex_s <= prev_e + 1:
                merged_ex[-1] = (prev_s, max(prev_e, ex_e))
            else:
                merged_ex.append((ex_s, ex_e))

    # Walk each base range, emitting the gaps between exclusions as pools.
    result_pools = []
    for base_s, base_e in base_ranges:
        curr = base_s
        for ex_s, ex_e in merged_ex:
            # Skip exclusions outside the current range.
            if ex_e < curr or ex_s > base_e:
                continue
            # Emit the part before this exclusion.
            if ex_s > curr:
                result_pools.append({
                    "pool": f"{ipaddress.ip_address(curr)} - {ipaddress.ip_address(min(ex_s - 1, base_e))}"
                })
            # Move past the exclusion; stop if it covers the rest.
            curr = max(curr, ex_e + 1)
            if curr > base_e:
                break
        # Emit whatever is left of the range.
        if curr <= base_e:
            result_pools.append({
                "pool": f"{ipaddress.ip_address(curr)} - {ipaddress.ip_address(base_e)}"
            })
    return result_pools


#: Global ``Dhcp4`` settings the coordinator owns on every node, alongside
#: ``subnet4``. ``authoritative`` is pinned OFF (Kea's default). With it on, a
#: device that boots with its address already up and sends INIT-REBOOT for it
#: gets a DHCPNAK, re-DISCOVERs, is offered that same address, ARP-probes it,
#: hears ITSELF answer and sends DHCPDECLINE — so the address sits Declined.
#: Off, Kea just ignores an INIT-REBOOT it has no lease for and the device keeps
#: its address. DHCPv4-only: Kea has no ``authoritative`` for Dhcp6.
#:
#: ``decline-probation-period`` is how long Kea parks an address a client
#: DHCPDECLINEd. Kea's default is 24h; LM uses 60s unless the operator turns
#: "Hold declined addresses" on (System → Sync), so a device that declines its
#: own address is not locked out of it for a day.
DECLINE_PROBATION_SHORT = 60
DECLINE_PROBATION_HOLD = 86400
DHCP_SETTINGS_PATH = os.getenv("LM_DHCP_SETTINGS", "/etc/lm-dhcp/kea-settings.json")


def _read_hold_declined() -> bool:
    """The saved "hold declined addresses" choice (False when unset)."""
    try:
        with open(DHCP_SETTINGS_PATH) as fh:
            return bool(json.load(fh).get("hold_declined"))
    except (OSError, ValueError, AttributeError):
        return False


DHCP4_COORDINATOR_GLOBALS = {
    "authoritative": False,
    "decline-probation-period": (DECLINE_PROBATION_HOLD if _read_hold_declined()
                                 else DECLINE_PROBATION_SHORT),
}


def set_hold_declined(hold: bool) -> None:
    """Apply the hub's "hold declined addresses" choice to every later render.

    Saved to disk so a spoke restart (or an HA reconcile before the next hub
    sync) keeps the operator's choice.
    """
    period = DECLINE_PROBATION_HOLD if hold else DECLINE_PROBATION_SHORT
    if DHCP4_COORDINATOR_GLOBALS["decline-probation-period"] == period:
        return
    DHCP4_COORDINATOR_GLOBALS["decline-probation-period"] = period
    try:
        os.makedirs(os.path.dirname(DHCP_SETTINGS_PATH), exist_ok=True)
        with open(DHCP_SETTINGS_PATH, "w") as fh:
            json.dump({"hold_declined": bool(hold)}, fh)
    except OSError as e:
        logger.warning("Could not save %s: %s", DHCP_SETTINGS_PATH, e)


def build_subnet4(subnets: list, reservations: list) -> tuple:
    """Translate LM/NetBox intent into Kea's ``subnet4`` list.

    Returns ``(kea_subnets, applied_reservations, skipped_reservations)``.
    Extracted from :meth:`KeaManager.sync` so an HA pair can be handed the
    IDENTICAL scope + reservation block for both nodes — two nodes computing
    their own subnet list independently is how a "HA pair" ends up handing out
    overlapping addresses.
    """
    # Output list, applied-reservation flags and ids in use.
    kea_subnets = []
    applied = [False] * len(reservations)
    used_ids: set = set()
    # Build one Kea subnet per valid input subnet.
    for s in subnets:
        subnet_str = s.get("subnet", "")
        # Skip invalid CIDRs.
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError:
            logger.warning("Invalid subnet %s — skipping", subnet_str)
            continue
        # Stable id from the CIDR.
        idx = _stable_subnet_id(subnet_str, used_ids)

        # Pools from explicit start/end pairs.
        pools = [
            {"pool": f"{p['start']} - {p['end']}"}
            for p in s.get("pools", [])
            if p.get("start") and p.get("end")
        ]
        # Apply exclusion ranges by carving them out of the pools.
        excl_raw = s.get("exclusion_ranges") or s.get("exclusions")
        if excl_raw:
            exclusions = _parse_exclusion_ranges(excl_raw)
            # With explicit pools, use their valid start/end pairs as base ranges.
            if pools:
                base_ranges = []
                for p in s.get("pools", []):
                    if p.get("start") and p.get("end"):
                        try:
                            s_int = int(ipaddress.ip_address(p["start"]))
                            e_int = int(ipaddress.ip_address(p["end"]))
                            if s_int <= e_int:
                                base_ranges.append((s_int, e_int))
                        # Skip unparseable pool bounds.
                        except ValueError:
                            pass
            # Without pools, the base range is every host address in the subnet.
            else:
                first = int(net.network_address) + 1
                last = int(net.broadcast_address) - 1
                base_ranges = [(first, last)] if first <= last else []
            # Remove the excluded addresses.
            pools = _carve_pools(base_ranges, exclusions)
        elif not pools:
            # Default pool: .10 → .254
            first = int(net.network_address) + 10
            last  = int(net.broadcast_address) - 1
            if first <= last:
                pools = [{"pool": f"{ipaddress.ip_address(first)} - {ipaddress.ip_address(last)}"}]

        # The Kea subnet entry.
        kea_subnet = {
            "id":     idx,
            "subnet": str(net),
            "pools":  pools,
            "option-data": [],
        }
        # Carry the NetBox prefix description through in Kea's user-context so
        # the UI can label a scope by its real name/purpose instead of a bare
        # "subnet <id>" — Kea persists arbitrary user-context data untouched
        # and returns it back on subnet4-list, so this round-trips for free.
        description = (s.get("description") or "").strip()
        if description:
            kea_subnet["user-context"] = {"description": description}
        # Router option from the gateway (cleaned; a bad value must not break the config-set).
        gateway = _clean_gateway(s.get("gateway"), net)
        if gateway:
            kea_subnet["option-data"].append({"name": "routers", "data": gateway})
            kea_subnet["pools"] = _pools_without(kea_subnet["pools"], gateway)
        # DNS servers option.
        dns = s.get("dns_servers", [])
        if dns:
            kea_subnet["option-data"].append(
                {"name": "domain-name-servers", "data": ", ".join(dns)}
            )
        # Search domains and the other table-driven options.
        _add_option(kea_subnet, "domain-search", s.get("search_domains"))
        for key, opt_name in _ADVANCED_OPTION_MAP:
            _add_option(kea_subnet, opt_name, s.get(key))
        # valid-lifetime is a Kea subnet-level property (the DHCP lease time
        # in seconds), not an option-data entry — only set it when the scope
        # opted out of Kea's built-in global default.
        lease_time = s.get("lease_time")
        try:
            if lease_time:
                kea_subnet["valid-lifetime"] = int(lease_time)
        except (TypeError, ValueError):
            logger.warning("Ignoring non-numeric lease_time %r for %s",
                           lease_time, subnet_str)

        # Attach reservations that belong to this subnet. Guard ip/mac with
        # .get and wrap ip_network in try — one malformed reservation (missing
        # or invalid ip) must be skipped, not KeyError/ValueError out of the
        # whole sync (which would then config-set the subnet with NO reservations).
        subnet_res = []
        # Skip reservations missing an IP or MAC.
        for res_idx, r in enumerate(reservations):
            ip, mac = r.get("ip"), r.get("mac")
            if not ip or not mac:
                continue
            # Belongs here if its subnet id/CIDR matches or its IP is inside the subnet.
            try:
                in_subnet = (str(r.get("subnet_id")) == str(idx)
                             or r.get("subnet") == subnet_str
                             or net.overlaps(ipaddress.ip_network(f"{ip}/32")))
            except ValueError:
                continue  # malformed reservation IP
            # Add it in Kea's form and mark it applied.
            if in_subnet:
                subnet_res.append({
                    "ip-address": ip,
                    "hw-address": _normalize_mac(mac),
                    "hostname": r.get("hostname", ""),
                })
                applied[res_idx] = True
        # Attach the reservations, if any.
        if subnet_res:
            kea_subnet["reservations"] = subnet_res

        # Add the finished subnet.
        kea_subnets.append(kea_subnet)

    # Scopes going out with no default gateway are a silent client-side
    # outage (Kea logs nothing), so say so on every sync.
    no_gateway = [k["subnet"] for k in kea_subnets
                  if not _routers_of(k["option-data"])]
    if no_gateway:
        logger.warning("DHCP scopes with no default gateway (set Gateway on the "
                       "NetBox prefix): %s", ", ".join(no_gateway))

    # Count applied and skipped reservations.
    applied_count = sum(1 for flag in applied if flag)
    return kea_subnets, applied_count, len(reservations) - applied_count


def build_subnet6(subnets: list, reservations: list) -> tuple:
    """Translate LM/NetBox intent into Kea's ``subnet6`` list (DHCPv6).

    Mirrors :func:`build_subnet4`'s contract — ``(kea_subnets, applied_count,
    skipped_count)`` — but adapted to DHCPv6 semantics:

    - No ``gateway``/``routers`` option: DHCPv6 clients learn their default
      router from Router Advertisements, never from the DHCP server.
    - The DNS option name is ``dns-servers`` (RFC 3646), not
      ``domain-name-servers``.
    - No network/broadcast address reservation: IPv6 has no broadcast
      address, so (unlike v4's ".10 → .254") the default pool spans the
      WHOLE subnet — handing out a full /64 pool is the normal, expected
      Kea DHCPv6 configuration.
    - Reservations are matched by ``hw-address`` (this fleet has no DUID
      capture path yet) and use DHCPv6's ``ip-addresses`` key — a LIST, not
      the singular ``ip-address`` v4 uses — because a v6 host reservation
      can in principle carry more than one address. Matching by hw-address
      requires the subnet's ``Dhcp6.host-reservation-identifiers`` include
      ``"hw-address"``; :meth:`KeaManager.sync6` ensures that's set.
    """
    # Output list, applied-reservation flags and ids in use.
    kea_subnets = []
    applied = [False] * len(reservations)
    used_ids: set = set()
    # Build one Kea subnet per valid IPv6 input subnet.
    for s in subnets:
        subnet_str = s.get("subnet", "")
        # Skip invalid CIDRs.
        try:
            net = ipaddress.ip_network(subnet_str, strict=False)
        except ValueError:
            logger.warning("Invalid subnet6 %s — skipping", subnet_str)
            continue
        # Skip non-IPv6 subnets.
        if net.version != 6:
            logger.warning("build_subnet6: %s is not IPv6 — skipping", subnet_str)
            continue
        # Stable id from the CIDR.
        idx = _stable_subnet_id(subnet_str, used_ids)

        # Pools from explicit start/end pairs.
        pools = [
            {"pool": f"{p['start']} - {p['end']}"}
            for p in s.get("pools", [])
            if p.get("start") and p.get("end")
        ]
        # Apply exclusion ranges by carving them out of the pools.
        excl_raw = s.get("exclusion_ranges") or s.get("exclusions")
        if excl_raw:
            exclusions = _parse_exclusion_ranges(excl_raw)
            # With explicit pools, use their valid start/end pairs as base ranges.
            if pools:
                base_ranges = []
                for p in s.get("pools", []):
                    if p.get("start") and p.get("end"):
                        try:
                            s_int = int(ipaddress.ip_address(p["start"]))
                            e_int = int(ipaddress.ip_address(p["end"]))
                            if s_int <= e_int:
                                base_ranges.append((s_int, e_int))
                        # Skip unparseable pool bounds.
                        except ValueError:
                            pass
            # Without pools, the base range is the whole subnet.
            else:
                base_ranges = [(int(net.network_address), int(net.broadcast_address))]
            # Remove the excluded addresses.
            pools = _carve_pools(base_ranges, exclusions)
        elif not pools:
            # Default pool: the whole subnet — IPv6 has no reserved
            # network/broadcast address the way v4 does.
            pools = [{"pool": f"{net.network_address} - {net.broadcast_address}"}]

        # The Kea subnet entry, with an optional description.
        kea_subnet = {
            "id":     idx,
            "subnet": str(net),
            "pools":  pools,
            "option-data": [],
        }
        description = (s.get("description") or "").strip()
        if description:
            kea_subnet["user-context"] = {"description": description}
        # DNS servers option.
        dns = s.get("dns_servers", [])
        if dns:
            kea_subnet["option-data"].append(
                {"name": "dns-servers", "data": ", ".join(dns)}
            )
        # Search domains option.
        _add_option(kea_subnet, "domain-search", s.get("search_domains"))
        # Optional lease time; ignore non-numeric values.
        lease_time = s.get("lease_time")
        try:
            if lease_time:
                kea_subnet["valid-lifetime"] = int(lease_time)
        except (TypeError, ValueError):
            logger.warning("Ignoring non-numeric lease_time %r for %s",
                           lease_time, subnet_str)

        # Attach reservations that belong to this subnet.
        subnet_res = []
        for res_idx, r in enumerate(reservations):
            ip, mac = r.get("ip"), r.get("mac")
            # Skip reservations missing an IP or MAC.
            if not ip or not mac:
                continue
            # Skip invalid or non-IPv6 addresses.
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip_obj.version != 6:
                continue
            # Belongs here if its subnet id/CIDR matches or its IP is inside the subnet.
            in_subnet = (str(r.get("subnet_id")) == str(idx)
                         or r.get("subnet") == subnet_str
                         or ip_obj in net)
            # Add it in Kea's v6 form and mark it applied.
            if in_subnet:
                subnet_res.append({
                    "ip-addresses": [ip],
                    "hw-address": _normalize_mac(mac),
                    "hostname": r.get("hostname", ""),
                })
                applied[res_idx] = True
        # Attach the reservations, if any.
        if subnet_res:
            kea_subnet["reservations"] = subnet_res

        # Add the finished subnet.
        kea_subnets.append(kea_subnet)

    # Count applied and skipped reservations.
    applied_count = sum(1 for flag in applied if flag)
    return kea_subnets, applied_count, len(reservations) - applied_count



class KeaManager:
    """
    Manages Kea DHCP4 via the Kea Control Agent REST API.
    Default CA port is 8001 (we use 8001 to avoid conflict with the LM hub on 8000).
    """

    def __init__(self, ca_url: str = "http://localhost:8001"):
        """Create a manager for one Kea Control Agent.

        Args:
            ca_url: Control Agent URL.
        """
        # Store the URL without a trailing slash.
        self.ca_url = ca_url.rstrip("/")

    # ── Kea Control Agent RPC ─────────────────────────────────────────

    def _rpc(self, service: str, command: str, args: dict = None) -> dict:
        """Call a Kea command and return only its arguments.

        Args:
            service: Kea service, e.g. "dhcp4".
            command: Kea command name.
            args: Optional command arguments.

        Returns:
            The response's "arguments" dict, or {} if absent.
        """
        # Delegate to the full call and keep the arguments.
        return self._rpc_full(service, command, args).get("arguments", {})

    def _rpc_full(self, service: str, command: str, args: dict = None) -> dict:
        """Same call as :meth:`_rpc`, but returns the FULL Kea response object.

        Callers that must tell "succeeded, found nothing" (Kea ``result: 3``)
        apart from "succeeded and acted" (``result: 0``) need the result code,
        which :meth:`_rpc` throws away. Transport/protocol failures still raise.
        """
        # Build the request body.
        payload = {"command": command, "service": [service]}
        if args is not None:
            payload["arguments"] = args
        # POST it as JSON.
        req = urllib.request.Request(self.ca_url, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
        # Send and parse; Kea may wrap the reply in a list.
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                result = json.loads(r.read())
            if isinstance(result, list):
                result = result[0]
            code = result.get("result", 0)
            # Kea's control channel uses result=3 ("empty") for queries that
            # succeeded but found no matching data — e.g. lease4-get-all on a
            # subnet with no active leases yet (exactly the case right after
            # DHCP starts serving again). Treating it as an error made every
            # diagnostics/list_leases call on an otherwise-healthy, freshly
            # recovered node fail with a misleading "Kea error" / lease
            # retrieval failure, even though there was genuinely nothing
            # wrong — only 1 (error) and 2 (unsupported) are real failures.
            if code not in (0, 3):
                raise RuntimeError(result.get("text", "Kea error"))
            return result
        # Network or parse failures become RuntimeError.
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RuntimeError(f"Kea CA unreachable: {e}")

    # ── Subnet (scope) management ─────────────────────────────────────

    def list_subnets(self) -> list:
        """Configured subnet4 scopes, straight from the running config.

        Deliberately NOT the ``subnet4-list`` command — that RPC requires
        ``libdhcp_subnet_cmds.so`` to be loaded, which this install's
        hooks-libraries does NOT include (only ``lease_cmds`` + ``ha`` are
        loaded; see kea-dhcp4.conf). Without that hook Kea answers
        ``result: 2`` ("command not supported"); our own ``_rpc()`` raises
        on any code other than 0/3, so this used to be silently swallowed by
        the try/except below, returning an empty list — every caller
        (get_stats' pool utilization, the WebUI Subnets/Overview tabs,
        diagnostics' id_to_cidr map) then saw ZERO subnets even though the
        subnet was correctly synced and actively serving DHCP.
        ``config-get`` is a core Kea command needing no optional hook, and
        its ``Dhcp4.subnet4`` array carries the exact same id/subnet/pools/
        user-context shape build_subnet4() writes — so this sources the
        identical data the removed RPC would have returned, just from a
        command guaranteed to exist.
        """
        # Read subnet4 from the running config.
        try:
            return self.get_config().get("subnet4", []) or []
        # On failure, log it and return no subnets.
        except Exception as e:
            logger.error("list_subnets failed: %s", e)
            return []

    def get_config(self) -> dict:
        """Return the running Dhcp4 config.

        Returns:
            The "Dhcp4" section from config-get, or {}.
        """
        # Fetch the config and keep the Dhcp4 section.
        return self._rpc("dhcp4", "config-get").get("Dhcp4", {})

    def _set_config(self, dhcp4_config: dict):
        """Set and persist a Dhcp4 config; any failure raises.

        Args:
            dhcp4_config: Full Dhcp4 section to apply.
        """
        # Apply the config, then write it to disk.
        self._rpc("dhcp4", "config-set", {"Dhcp4": dhcp4_config})
        self._rpc("dhcp4", "config-write", {})

    def apply_config(self, dhcp4_config: dict) -> dict:
        """``config-set`` then ``config-write`` as two OBSERVABLE steps.

        ``_set_config`` collapses both into one exception, which loses the one
        distinction that matters for rollback: a ``config-write`` failure means
        the new config is ALREADY RUNNING (config-set succeeded) but is not
        persisted — the node is mutated and must be restored, whereas a
        ``config-set`` failure left it untouched. Returns
        ``{"set": bool, "written": bool, "error": str}``.
        """
        # Apply the config; failure means nothing changed.
        try:
            self._rpc("dhcp4", "config-set", {"Dhcp4": dhcp4_config})
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"set": False, "written": False, "error": str(e)}
        # Persist it; failure means it is running but not saved.
        try:
            self._rpc("dhcp4", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"set": True, "written": False, "error": str(e)}
        # Both steps succeeded.
        return {"set": True, "written": True, "error": ""}

    def write_config(self) -> dict:
        """Retry ``config-write`` alone against the ALREADY-set running config
        — used by the worker's config-write-permission self-heal, which fixes
        ``/etc/kea/kea-dhcp4.conf`` on disk and then just needs Kea to persist
        what it's already running, with no need to re-send/re-validate the
        whole config via ``config-set``. Returns ``{"written": bool,
        "error": str}``."""
        # Persist the running config.
        try:
            self._rpc("dhcp4", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"written": False, "error": str(e)}
        # Written.
        return {"written": True, "error": ""}


    def sync(self, subnets: list, reservations: list) -> dict:
        """
        Full sync: replace all subnets and reservations.

        subnets:      [{subnet, gateway, dns_servers, pools: [{start, end}], description}]
        reservations: [{ip, mac, hostname, subnet}]
        """
        # Read the current config.
        try:
            cfg = self.get_config()
        except Exception as e:
            return {"status": "ERROR", "message": f"Cannot read Kea config: {e}"}

        # Build the new subnet list.
        kea_subnets, _applied, _skipped = build_subnet4(subnets, reservations)

        # Replace the subnets, add the coordinator globals and apply.
        cfg["subnet4"] = kea_subnets
        cfg.update(copy.deepcopy(DHCP4_COORDINATOR_GLOBALS))
        try:
            self._set_config(cfg)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        # Log and report counts.
        logger.info("Synced %d subnets, %d reservations to Kea", len(kea_subnets), len(reservations))
        released = self.release_held_declines().get("released", [])
        return {"status": "SUCCESS", "subnets": len(kea_subnets), "reservations": len(reservations),
                "released_declines": len(released)}

    def release_held_declines(self, release_all: bool = False) -> dict:
        """Free declined addresses so the pool can hand them out again.

        By default only addresses held longer than the current probation
        period: Kea keeps the probation that applied when a client declined,
        so a decline storm under a 24h hold (Kea's default, or "Hold declined
        addresses" on) keeps the pool short for a day even after the hold is
        turned off. Run after every sync so the pool recovers by itself.
        ``release_all`` frees every declined address (the Diagnostics button).
        """
        try:
            period = 0 if release_all else self.get_config().get(
                "decline-probation-period", DECLINE_PROBATION_HOLD)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"Cannot read Kea config: {e}", "released": []}
        released = []
        for lease in self.list_leases():
            if lease.get("state") == 1 and lease.get("valid-lft", 0) > period:
                self.delete_lease(lease["ip-address"])
                released.append(lease["ip-address"])
        if released:
            logger.warning("Released %d declined address(es) held longer than %ss: %s",
                           len(released), period, ", ".join(released[:20]))
        return {"status": "SUCCESS", "released": released}

    # ── Real-time DNS registration hook (Option 1) ─────────────────────

    def configure_dns_hook(self, settings: dict, hook_dir: str = "") -> dict:
        """Enable/update/disable the real-time Kea -> Unbound ``run_script``
        hook on this node.

        Mirrors ``sync()``'s get_config -> mutate -> apply_config shape, but
        only ever touches the ONE ``hooks-libraries`` entry this feature owns
        (see ``kea_dns_hook.remove_dns_hook_entry``) — every other entry
        (``lease_cmds``, ``ha``, an operator's own hooks) passes through
        untouched, same guarantee ``sync()`` gives ``subnet4`` relative to the
        rest of the config.
        """
        try:
            clean = kea_dns_hook.validate_settings(settings)
        except kea_dns_hook.DnsHookConfigError as e:
            return {"status": "ERROR", "message": str(e)}

        try:
            cfg = self.get_config()
        except Exception as e:
            return {"status": "ERROR", "message": f"Cannot read Kea config: {e}"}

        hooks = kea_dns_hook.remove_dns_hook_entry(cfg.get("hooks-libraries", []))
        if clean["enabled"]:
            hooks.append(kea_dns_hook.build_dns_hook_entry(hook_dir))
        cfg["hooks-libraries"] = hooks

        try:
            kea_dns_hook.write_hook_files(clean)
        except OSError as e:
            return {"status": "ERROR", "message": f"Cannot write hook files: {e}"}

        result = self.apply_config(cfg)
        if not result.get("set"):
            return {"status": "ERROR", "message": result.get("error", "config-set failed")}
        if not result.get("written"):
            # Running config IS updated (hook is live); only persistence
            # failed — same "mutated but not durable" case apply_config's own
            # docstring calls out, surfaced here rather than swallowed.
            return {"status": "PARTIAL", "message": result.get("error", "config-write failed"),
                    "enabled": clean["enabled"]}
        logger.info("DNS hook %s (targets=%s)", "enabled" if clean["enabled"] else "disabled",
                    clean["targets"])
        return {"status": "SUCCESS", "enabled": clean["enabled"], "settings": clean}

    def dns_hook_status(self) -> dict:
        """On-disk hook settings/log tail, independent of whether Kea's
        running config currently loads the hook (so a drifted/removed
        hooks-libraries entry is still diagnosable)."""
        status = kea_dns_hook.read_status()
        try:
            hooks = self.get_config().get("hooks-libraries", []) or []
            status["loaded_in_running_config"] = any(
                str(h.get("library", "")).endswith(kea_dns_hook.RUN_SCRIPT_LIB)
                and (h.get("parameters") or {}).get("name") == kea_dns_hook.DNS_HOOK_SCRIPT_PATH
                for h in hooks if isinstance(h, dict)
            )
        except Exception as e:  # noqa: BLE001
            status["loaded_in_running_config"] = None
            status["running_config_error"] = str(e)
        return status

    # ── Lease queries ─────────────────────────────────────────────────

    def list_leases(self, subnet: str = None) -> list:
        """List active DHCPv4 leases.

        Args:
            subnet: Optional CIDR to filter by.

        Returns:
            Kea lease dicts, or [] on failure.
        """
        try:
            # ``lease4-get-all`` has no "all leases" sentinel value, and per
            # ISC docs omitting "arguments" entirely is supposed to mean
            # "every subnet" — but this HA-hooked node rejects a bare/no-args
            # call with "'subnets' parameter not specified" regardless (the
            # HA hook likely intercepts lease4-get-all and requires an
            # explicit subnet list to know which node's view is authoritative
            # for each one). Always pass "subnets" explicitly: every
            # currently-configured subnet ID for "all", or the one matching
            # ``subnet`` when filtering.
            # Collect subnet ids: all, or only the one matching the filter.
            kea_subnets = self.list_subnets()
            ids = [s["id"] for s in kea_subnets if "id" in s]
            if subnet:
                ids = [s["id"] for s in kea_subnets if s.get("subnet") == subnet]
            # Fetch the leases.
            data = self._rpc("dhcp4", "lease4-get-all", {"subnets": ids})
            return data.get("leases", [])
        # On failure, log it and return none.
        except Exception as e:
            logger.error("list_leases failed: %s", e)
            return []

    def delete_lease(self, ip: str) -> dict:
        """Delete an active lease by IP from Kea via lease4-del RPC."""
        # Ask Kea to delete the lease.
        try:
            res = self._rpc("dhcp4", "lease4-del", {"ip-address": ip})
            return {"status": "SUCCESS", "result": res}
        # Treat failure (usually "no such lease") as success with not_found set.
        except Exception as e:
            logger.debug("delete_lease %s: %s", ip, e)
            return {"status": "SUCCESS", "message": str(e), "not_found": True}

    def purge_leases_for_mac_or_ip(self, mac: str = None, ip: str = None) -> list:
        """Purge any active lease for a given MAC or IP address."""
        # Purge the given IP first.
        purged = []
        if ip:
            self.delete_lease(ip)
            purged.append(ip)
        # Then purge every other lease held by the MAC.
        if mac:
            norm_mac = _normalize_mac(mac)
            try:
                leases = self.list_leases()
                for l in leases:
                    l_ip = l.get("ip-address") or l.get("ip")
                    l_mac = _normalize_mac(l.get("hw-address") or l.get("mac"))
                    if l_mac and l_mac == norm_mac and l_ip and l_ip not in purged:
                        self.delete_lease(l_ip)
                        purged.append(l_ip)
            except Exception as e:
                # A surviving lease means the client keeps its current address
                # and never picks up the reservation, so this must not stay a
                # debug-level detail.
                logger.warning("Could not purge leases for %s: %s", norm_mac, e)
        # Return the purged addresses.
        return purged

    # ── Manual reservation CRUD ───────────────────────────────────────

    def add_reservation(self, subnet_id: Any, ip: str, mac: str, hostname: str = "") -> dict:
        """Add a static reservation to one subnet and purge the client's old leases.

        Args:
            subnet_id: Kea subnet id.
            ip: Reserved address.
            mac: Client MAC.
            hostname: Optional hostname.

        Returns:
            Result dict with the purged leases, or an error if the subnet is missing.
        """
        # Load the config and normalize the MAC.
        cfg = self.get_config()
        norm_mac = _normalize_mac(mac)
        # Find the subnet and append the reservation.
        for sub in cfg.get("subnet4", []):
            if str(sub.get("id")) == str(subnet_id):
                sub.setdefault("reservations", [])
                sub["reservations"].append({
                    "ip-address": ip,
                    "hw-address": norm_mac,
                    "hostname":   hostname,
                })
                break
        # No matching subnet.
        else:
            return {"status": "ERROR", "message": f"Subnet {subnet_id} not found"}
        # Apply the config and purge the client's existing leases.
        self._set_config(cfg)
        purged = self.purge_leases_for_mac_or_ip(mac=norm_mac, ip=ip)
        return {"status": "SUCCESS", "lease_purge": {"purged": purged}}

    def list_reservations(self) -> list:
        """Return all static reservations across subnets."""
        # Read the config; on failure return an empty list.
        out = []
        try:
            cfg = self.get_config()
        except Exception as e:
            logger.error("list_reservations failed: %s", e)
            return out
        # Flatten every subnet's reservations.
        for sub in cfg.get("subnet4", []):
            for r in sub.get("reservations", []):
                out.append({
                    "ip":        r.get("ip-address", ""),
                    "mac":       r.get("hw-address", ""),
                    "hostname":  r.get("hostname", ""),
                    "subnet_id": sub.get("id"),
                    "subnet":    sub.get("subnet", ""),
                })
        return out

    def update_reservation(self, old_ip: str, subnet_id: Any, ip: str,
                           mac: str, hostname: str = "") -> dict:
        """Update a reservation by IP in ONE config write.

        Previously this deleted the old entry in one ``config-set`` and added
        the replacement in a second: a failure (or a crash) between the two left
        the reservation DELETED and never re-created, so the host silently
        dropped to a dynamic lease. The removal and the insertion are now a
        single atomic write — either the replacement lands or nothing changes.
        Reservations still move freely between subnets, because the whole
        ``subnet4`` block is rewritten in that one write."""
        # Subnet, IP and MAC are required.
        if not all([subnet_id, ip, mac]):
            return {"status": "ERROR", "message": "subnet_id, ip, and mac are required"}
        # Load the config.
        cfg = self.get_config()
        target = None
        norm_mac = _normalize_mac(mac)
        # Find the target subnet and drop the old entry from every subnet.
        for sub in cfg.get("subnet4", []):
            if str(sub.get("id")) == str(subnet_id):
                target = sub
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != old_ip
            ]
        # The target subnet must exist.
        if target is None:
            return {"status": "ERROR", "message": f"Subnet {subnet_id} not found"}
        # Add the replacement entry.
        target.setdefault("reservations", [])
        target["reservations"].append({
            "ip-address": ip,
            "hw-address": norm_mac,
            "hostname":   hostname,
        })
        # Write once, then purge leases for the new IP/MAC and the old IP.
        try:
            self._set_config(cfg)
            purged = self.purge_leases_for_mac_or_ip(mac=norm_mac, ip=ip)
            if old_ip and old_ip != ip:
                purged += self.purge_leases_for_mac_or_ip(ip=old_ip)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}
        return {"status": "SUCCESS", "lease_purge": {"purged": purged}}

    def delete_reservation(self, ip: str) -> dict:
        """Remove the reservation for an IP from every subnet.

        Args:
            ip: Reserved address.

        Returns:
            {"status": "SUCCESS"}; config errors raise.
        """
        # Drop the entry from every subnet, then apply.
        cfg = self.get_config()
        for sub in cfg.get("subnet4", []):
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if r.get("ip-address") != ip
            ]
        self._set_config(cfg)
        return {"status": "SUCCESS"}

    # ── DHCPv6 (dual-stack) ────────────────────────────────────────────
    #
    # Parallels the DHCPv4 methods above against Kea's separate ``dhcp6``
    # Control Agent service / ``Dhcp6`` config tree — Kea runs DHCPv4 and
    # DHCPv6 as independent daemons with independent config, so every RPC
    # here targets ``service=["dhcp6"]`` and reads/writes ``Dhcp6`` instead
    # of ``Dhcp4``. This first pass covers config sync, leases, and
    # reservations for a single (non-HA) node; HA/cluster dual-stack
    # propagation is tracked as follow-up work.

    def get_config6(self) -> dict:
        """Return the running Dhcp6 config.

        Returns:
            The "Dhcp6" section from config-get, or {}.
        """
        # Fetch the config and keep the Dhcp6 section.
        return self._rpc("dhcp6", "config-get").get("Dhcp6", {})

    def _set_config6(self, dhcp6_config: dict):
        """Set and persist a Dhcp6 config; any failure raises.

        Args:
            dhcp6_config: Full Dhcp6 section to apply.
        """
        # Apply the config, then write it to disk.
        self._rpc("dhcp6", "config-set", {"Dhcp6": dhcp6_config})
        self._rpc("dhcp6", "config-write", {})

    def apply_config6(self, dhcp6_config: dict) -> dict:
        """``config-set`` then ``config-write`` as two observable steps —
        see :meth:`apply_config` for why these are kept separate."""
        # Apply the config; failure means nothing changed.
        try:
            self._rpc("dhcp6", "config-set", {"Dhcp6": dhcp6_config})
        except Exception as e:  # noqa: BLE001 — a rejected config is the answer
            return {"set": False, "written": False, "error": str(e)}
        # Persist it; failure means it is running but not saved.
        try:
            self._rpc("dhcp6", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"set": True, "written": False, "error": str(e)}
        # Both steps succeeded.
        return {"set": True, "written": True, "error": ""}

    def write_config6(self) -> dict:
        """Retry ``config-write`` alone against the already-set running
        DHCPv6 config — see :meth:`write_config`."""
        # Persist the running config.
        try:
            self._rpc("dhcp6", "config-write", {})
        except Exception as e:  # noqa: BLE001
            return {"written": False, "error": str(e)}
        # Written.
        return {"written": True, "error": ""}

    def list_subnets6(self) -> list:
        """Configured subnet6 scopes, straight from the running config — see
        :meth:`list_subnets` for why this reads ``config-get`` rather than
        the ``subnet6-list`` hook command."""
        # Read subnet6 from the running config.
        try:
            return self.get_config6().get("subnet6", []) or []
        # On failure, log it and return no subnets.
        except Exception as e:
            logger.error("list_subnets6 failed: %s", e)
            return []

    def sync6(self, subnets: list, reservations: list) -> dict:
        """Full DHCPv6 sync: replace all subnet6 scopes and reservations.

        subnets:      [{subnet, dns_servers, pools: [{start, end}], description}]
        reservations: [{ip, mac, hostname, subnet}] (IPv4 rows are ignored —
                       :func:`build_subnet6` filters by address family)
        """
        # Read the current Dhcp6 config.
        try:
            cfg = self.get_config6()
        except Exception as e:
            return {"status": "ERROR", "message": f"Cannot read Kea DHCPv6 config: {e}"}

        # Build the new subnet6 list.
        kea_subnets, _applied, _skipped = build_subnet6(subnets, reservations)

        # hw-address reservation matching in DHCPv6 requires this identifier
        # be explicitly enabled — Kea defaults to DUID-only for v6. Without
        # it, every hw-address reservation written above would silently
        # never match a client (no error, the client just never gets its
        # reserved address).
        identifiers = cfg.get("host-reservation-identifiers") or []
        if "hw-address" not in identifiers:
            cfg["host-reservation-identifiers"] = list(identifiers) + ["hw-address"]

        # Replace the subnets and apply.
        cfg["subnet6"] = kea_subnets
        try:
            self._set_config6(cfg)
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

        # Log and report counts.
        logger.info("Synced %d subnet6 scopes, %d reservations to Kea DHCPv6",
                   len(kea_subnets), len(reservations))
        return {"status": "SUCCESS", "subnets": len(kea_subnets), "reservations": len(reservations)}

    def list_leases6(self, subnet: str = None, strict: bool = False) -> list:
        """Active DHCPv6 leases. ``strict=True`` re-raises instead of hiding an
        unreachable Kea behind an empty list (a purge caller must be able to
        tell "no leases" from "could not read the lease database")."""
        # Collect subnet ids: all, or only the one matching the filter.
        try:
            kea_subnets = self.list_subnets6()
            ids = [s["id"] for s in kea_subnets if "id" in s]
            if subnet:
                ids = [s["id"] for s in kea_subnets if s.get("subnet") == subnet]
            # Fetch the leases.
            data = self._rpc("dhcp6", "lease6-get-all", {"subnets": ids})
            return data.get("leases", [])
        # On failure, log it; re-raise only in strict mode.
        except Exception as e:
            logger.error("list_leases6 failed: %s", e)
            if strict:
                raise
            return []

    def delete_lease6(self, ip: str) -> dict:
        """Delete an active DHCPv6 lease by address via ``lease6-del``.

        THREE distinct outcomes, three distinct values — collapsing them made
        an unreachable Kea look like a clean purge:

        * deleted      → ``SUCCESS`` with ``not_found: False``
        * no such lease→ ``SUCCESS`` with ``not_found: True`` (Kea ``result: 3``)
        * RPC failed   → ``ERROR`` with the failure message
        """
        # Ask Kea to delete the lease; RPC failure is an ERROR.
        try:
            res = self._rpc_full("dhcp6", "lease6-del", {"ip-address": ip})
        except Exception as e:  # noqa: BLE001
            logger.warning("delete_lease6 %s failed: %s", ip, e)
            return {"status": "ERROR", "message": str(e)}
        # Kea result 3 means there was no such lease.
        if int(res.get("result", 0) or 0) == 3:
            return {"status": "SUCCESS", "not_found": True,
                    "message": res.get("text") or "no such DHCPv6 lease"}
        # Deleted.
        return {"status": "SUCCESS", "not_found": False,
                "result": res.get("arguments", {})}

    def purge_leases6_for_mac_or_ip(self, mac: str = None, ip: str = None) -> list:
        """Purge active DHCPv6 lease(s) for a MAC and/or address.

        Returns ONLY the addresses that actually had a lease removed. Raises
        ``RuntimeError`` if a delete or the lease lookup failed, so a failed
        purge can never be reported as a clean one.
        """
        # Delete the given IP's lease, counting it only if one existed.
        purged = []
        if ip:
            res = self.delete_lease6(ip)
            if res.get("status") != "SUCCESS":
                raise RuntimeError(res.get("message")
                                   or f"lease6-del failed for {ip}")
            if not res.get("not_found"):
                purged.append(ip)
        # Then delete every other lease held by the MAC.
        if mac:
            norm_mac = _normalize_mac(mac)
            try:
                leases = self.list_leases6(strict=True)
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(
                    f"could not read the DHCPv6 lease database for {norm_mac}: {e}")
            # Delete each matching lease, failing loudly on any error.
            for l in leases:
                l_ip = l.get("ip-address") or l.get("ip")
                l_mac = _normalize_mac(l.get("hw-address") or l.get("mac"))
                if l_mac and l_mac == norm_mac and l_ip and l_ip not in purged:
                    res = self.delete_lease6(l_ip)
                    if res.get("status") != "SUCCESS":
                        raise RuntimeError(res.get("message")
                                           or f"lease6-del failed for {l_ip}")
                    if not res.get("not_found"):
                        purged.append(l_ip)
        # Return the addresses actually purged.
        return purged

    def add_reservation6(self, subnet_id: Any, ip: str, mac: str, hostname: str = "") -> dict:
        """Add a DHCPv6 reservation to one subnet and purge the client's old leases.

        Args:
            subnet_id: Kea subnet id.
            ip: Reserved IPv6 address.
            mac: Client MAC.
            hostname: Optional hostname.

        Returns:
            Result dict; PARTIAL if the reservation applied but the lease purge failed.
        """
        # Load the config and normalize the MAC.
        cfg = self.get_config6()
        norm_mac = _normalize_mac(mac)
        # Find the subnet and append the reservation.
        for sub in cfg.get("subnet6", []):
            if str(sub.get("id")) == str(subnet_id):
                sub.setdefault("reservations", [])
                sub["reservations"].append({
                    "ip-addresses": [ip],
                    "hw-address":   norm_mac,
                    "hostname":     hostname,
                })
                break
        # No matching subnet.
        else:
            return {"status": "ERROR", "message": f"Subnet6 {subnet_id} not found"}
        # Make sure hw-address matching is enabled, then apply.
        identifiers = cfg.get("host-reservation-identifiers") or []
        if "hw-address" not in identifiers:
            cfg["host-reservation-identifiers"] = list(identifiers) + ["hw-address"]
        self._set_config6(cfg)
        # The reservation is already written and persisted at this point, so a
        # failed lease purge must NOT be reported as a failed reservation —
        # it is a distinct, lesser state: applied, but the client keeps its
        # stale address until that lease expires.
        try:
            purged = self.purge_leases6_for_mac_or_ip(mac=norm_mac, ip=ip)
        except Exception as e:  # noqa: BLE001
            logger.warning("DHCPv6 reservation for %s applied, but the previous "
                           "lease could not be purged: %s", ip, e)
            return {"status": "PARTIAL", "reservation_applied": True,
                    "lease_purge": {"purged": [], "error": str(e)},
                    "message": (f"Reservation for {ip} applied, but the previous "
                                f"lease could not be removed ({e}). The client "
                                f"will keep its current address until that lease "
                                f"expires.")}
        # Applied and purged.
        return {"status": "SUCCESS", "reservation_applied": True,
                "lease_purge": {"purged": purged}}

    def list_reservations6(self) -> list:
        """Return all static DHCPv6 reservations across subnet6 scopes."""
        # Read the config; on failure return an empty list.
        out = []
        try:
            cfg = self.get_config6()
        except Exception as e:
            logger.error("list_reservations6 failed: %s", e)
            return out
        # Flatten every subnet's reservations, taking the first address of each.
        for sub in cfg.get("subnet6", []):
            for r in sub.get("reservations", []):
                addrs = r.get("ip-addresses") or ([r["ip-address"]] if r.get("ip-address") else [])
                out.append({
                    "ip":        addrs[0] if addrs else "",
                    "mac":       r.get("hw-address", ""),
                    "hostname":  r.get("hostname", ""),
                    "subnet_id": sub.get("id"),
                    "subnet":    sub.get("subnet", ""),
                })
        return out

    def delete_reservation6(self, ip: str) -> dict:
        """Remove the DHCPv6 reservation for an address from every subnet.

        Args:
            ip: Reserved IPv6 address.

        Returns:
            {"status": "SUCCESS"}; config errors raise.
        """
        # Drop matching entries from every subnet, then apply.
        cfg = self.get_config6()
        for sub in cfg.get("subnet6", []):
            sub["reservations"] = [
                r for r in sub.get("reservations", [])
                if ip not in (r.get("ip-addresses") or [])
            ]
        self._set_config6(cfg)
        return {"status": "SUCCESS"}

    # ── Statistics ────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Kea DHCP4 statistics via ``statistic-get-all``, normalized for the UI.

        Kea returns each statistic as a list of ``[value, timestamp]`` samples
        (newest first), plus per-subnet keys of the form
        ``subnet[<id>].<name>``. We pull the latest sample of the pool-size /
        assignment counters and derive a utilization percentage per subnet and
        overall, and surface the headline packet counters.
        """
        # Fetch all statistics.
        try:
            raw = self._rpc("dhcp4", "statistic-get-all", {})
        except Exception as e:
            # Kea CA not reachable (e.g. kea-ctrl-agent not installed/running on
            # this spoke). The DHCP module is legitimately dormant on a box
            # without Kea — surface an IDLE state, not a red ERROR, so the
            # Overview tile renders empty stats + a note instead of "Error:
            # Kea CA unreachable …". The module-health tile still sees
            # running=False via get_status telemetry.
            logger.warning("get_stats: Kea CA unreachable at %s: %s", self.ca_url, e)
            return {"status": "SUCCESS", "global": {}, "subnets": [],
                    "kea_running": False,
                    "note": f"Kea Control Agent not reachable at {self.ca_url} — "
                            f"start kea-ctrl-agent to enable DHCP."}

        def latest(key):
            """Return the newest sample value for a statistic.

            Args:
                key: Statistic name.

            Returns:
                The value, or None if absent.
            """
            # Samples are [value, timestamp] lists, newest first.
            v = raw.get(key)
            if isinstance(v, list) and v and isinstance(v[0], list) and v[0]:
                return v[0][0]
            return None

        def num(key):
            """Return the newest numeric value for a statistic.

            Args:
                key: Statistic name.

            Returns:
                The value, or 0 if absent or not a number.
            """
            # Non-numbers become 0.
            val = latest(key)
            return val if isinstance(val, (int, float)) else 0

        # Map subnet ids to CIDRs.
        id_to_cidr = {s.get("id"): s.get("subnet", "") for s in self.list_subnets()}
        # user-context.description round-trips the NetBox prefix description
        # (see build_subnet4) — used to label a scope by its real name instead
        # of the bare "subnet <id>" fallback the UI used previously.
        id_to_desc = {
            s.get("id"): ((s.get("user-context") or {}).get("description") or "")
            for s in self.list_subnets()
        }

        # Kea's "assigned-addresses" statistic is a counter that only moves on
        # allocation/explicit release/reclamation events — it is NOT
        # guaranteed to reflect what's actually in the lease table right now
        # (e.g. a lease that vanished from lease4-get-all without Kea running
        # its reclamation timer leaves the counter stuck showing it as still
        # "assigned"). That drift is exactly what surfaced as "1 assigned
        # lease" on the Overview tile while the Leases tab — which reads
        # lease4-get-all directly — showed nothing. Count live, non-expired
        # leases ourselves so the two tabs can never disagree.
        assigned_by_subnet = {}
        try:
            # Count active leases per subnet; skip leases without a subnet id.
            for lease in self.list_leases():
                sid = lease.get("subnet-id")
                if sid is None:
                    continue
                # state: 0 = default/active, 1 = declined, 2 = expired-reclaimed.
                if lease.get("state", 0) not in (0, None):
                    continue
                assigned_by_subnet[sid] = assigned_by_subnet.get(sid, 0) + 1
        # If the lease list fails, fall back to Kea's counter.
        except Exception as e:
            logger.warning("get_stats: live lease count failed, falling back "
                           "to Kea's assigned-addresses statistic: %s", e)
            assigned_by_subnet = {}

        # Collect subnet ids that appear in the statistics.
        subnet_ids = set()
        for k in raw:
            m = re.match(r"subnet\[(\d+)\]\.", k)
            if m:
                subnet_ids.add(int(m.group(1)))

        # Kea does NOT purge statistic-get-all history for a subnet-id that
        # disappears from subnet4 on a config-set — those samples linger in
        # the running daemon's memory until it restarts. Before build_subnet4
        # switched to stable CIDR-derived ids, every NetBox-side reorder/
        # add/remove reassigned ids and left the OLD id's stats behind
        # forever as a meaningless "Unknown scope (not in NetBox — stale?)"
        # 0/0 row. Those ids no longer belong to any currently-configured
        # subnet — drop them outright instead of rendering a placeholder;
        # they carry no scope to label and no address pool to report on.
        stale_ids = subnet_ids - set(id_to_cidr)
        if stale_ids:
            logger.info("get_stats: dropping %d orphaned subnet stat id(s) "
                        "no longer in the live Kea config: %s",
                        len(stale_ids), sorted(stale_ids))
        subnet_ids &= set(id_to_cidr)

        # Build one stats row per subnet.
        subnets = []
        for sid in sorted(subnet_ids):
            total    = num(f"subnet[{sid}].total-addresses")
            assigned = assigned_by_subnet.get(sid, 0)
            declined = num(f"subnet[{sid}].declined-addresses")
            util = round(assigned / total * 100, 1) if total else 0.0
            subnets.append({
                "subnet_id":          sid,
                "subnet":             id_to_cidr.get(sid, ""),
                "description":        id_to_desc.get(sid, ""),
                "total_addresses":    total,
                "assigned_addresses": assigned,
                "declined_addresses": declined,
                "utilization_pct":    util,
            })

        # Overall totals, utilization and packet counters.
        g_total    = sum(s["total_addresses"] for s in subnets)
        g_assigned = sum(s["assigned_addresses"] for s in subnets)
        global_stats = {
            "total_addresses":    g_total,
            "assigned_addresses": g_assigned,
            "declined_addresses": num("declined-addresses"),
            "utilization_pct":    round(g_assigned / g_total * 100, 1) if g_total else 0.0,
            "pkt4_received":      num("pkt4-received"),
            "pkt4_discover":      num("pkt4-discover-received"),
            "pkt4_request":       num("pkt4-request-received"),
            "pkt4_offer_sent":    num("pkt4-offer-sent"),
            "pkt4_ack_sent":      num("pkt4-ack-sent"),
            "pkt4_nak_sent":      num("pkt4-nak-sent"),
        }
        return {"status": "SUCCESS", "global": global_stats, "subnets": subnets}

    def status(self) -> dict:
        """Check whether Kea answers on the Control Agent.

        Returns:
            Dict with running, subnet_count and ca_url.
        """
        # Kea is running if version-get succeeds.
        try:
            self._rpc("dhcp4", "version-get")
            running = True
        except Exception:
            running = False
        # Subnet count only when running.
        return {
            "running":      running,
            "subnet_count": len(self.list_subnets()) if running else 0,
            "ca_url":       self.ca_url,
        }

    #: File whose absence/emptiness silently blocks kea-ctrl-agent.service from
    #: ever starting via its own ConditionFileNotEmpty= gate (see
    #: install_dhcp.sh) — a fully mechanical, safe-to-recreate condition that
    #: previously required the operator to notice and manually recreate the
    #: file (or reinstall the whole role) before Kea's CA would come back.
    _API_PASSWORD_FILE = "/etc/kea/kea-api-password"

    def _self_heal(self) -> list:
        """Best-effort, fixed-argv repair of conditions diagnostics() can fully
        explain and safely fix without operator action — never anything that
        touches DHCP scope/reservation data. Returns the list of repair
        actions taken (each a short human-readable string) for the UI/log.
        """
        # Run each repair independently so one failure does not stop the rest.
        actions = []
        try:
            actions.extend(self._heal_api_password_file())
        except Exception as e:  # noqa: BLE001 — self-heal must never crash diagnostics
            logger.warning("self-heal (api password) failed: %s", e)
        try:
            actions.extend(self._heal_inactive_units())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (units) failed: %s", e)
        try:
            actions.extend(self._heal_missing_interfaces())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (interfaces) failed: %s", e)
        try:
            actions.extend(self._heal_control_socket_ownership())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (control socket) failed: %s", e)
        try:
            actions.extend(self._heal_config_dir_mode())
        except Exception as e:  # noqa: BLE001
            logger.warning("self-heal (config dir mode) failed: %s", e)
        # Return what was done.
        return actions

    _CONFIG_DIR = "/etc/kea"

    def _heal_config_dir_mode(self) -> list:
        """Align /etc/kea with the unit's ConfigurationDirectoryMode (0755).

        The Debian package creates it 0750, so systemd logs "ConfigurationDirectory
        'kea' already exists but the mode is different" on every start. Harmless,
        but it buries real errors in the warnings panel. install_dhcp.sh fixes new
        installs; this fixes hosts installed before that.
        """
        try:
            mode = os.stat(self._CONFIG_DIR).st_mode & 0o777
        except OSError:
            return []
        if mode == 0o755:
            return []
        os.chmod(self._CONFIG_DIR, 0o755)
        return [f"set {self._CONFIG_DIR} mode {oct(mode)[2:]} -> 755"]

    def _heal_api_password_file(self) -> list:
        """Recreate the Kea API password file if it is missing or empty.

        Returns:
            List with one action string if the file was recreated, else [].
        """
        # Decide whether the file needs creating.
        path = self._API_PASSWORD_FILE
        try:
            needs_create = not os.path.exists(path) or os.path.getsize(path) == 0
        except OSError:
            needs_create = True
        # Present and non-empty: nothing to do.
        if not needs_create:
            return []
        # Write a random password, restrict permissions and give it to the _kea group.
        try:
            with open(path, "wb") as fh:
                fh.write(base64.b64encode(os.urandom(32)))
            os.chmod(path, 0o640)
            try:
                shutil.chown(path, group="_kea")
            except (LookupError, PermissionError, OSError):
                pass  # best-effort, same as the installer
        # Could not write it.
        except OSError as e:
            logger.warning("could not recreate %s: %s", path, e)
            return []
        # Log and report the repair.
        logger.info("self-heal: recreated missing/empty %s", path)
        return [f"recreated missing {path}"]

    def _heal_inactive_units(self) -> list:
        """Restart kea-dhcp4-server/kea-ctrl-agent if systemd reports them
        failed/inactive-but-enabled. A crash-looped or one-off-killed unit is
        exactly the case an uninstall/reinstall used to be needed to clear —
        ``systemctl restart`` is the same fixed, argument-free recovery a
        reinstall ultimately performs, without touching any configuration.
        """
        # Check both Kea units.
        actions = []
        for unit in ("kea-dhcp4-server", "kea-ctrl-agent"):
            state = self._unit_status(unit)
            active = state.get("ActiveState")
            load = state.get("LoadState")
            # Skip units that are not loaded or already active.
            if load != "loaded" or active == "active":
                continue
            # Only failed or inactive units get restarted.
            if active not in ("failed", "inactive"):
                continue
            # Restart and record the outcome.
            result = self._run_diag(["systemctl", "restart", unit], timeout=20)
            if result["ok"]:
                actions.append(f"restarted {unit} (was {active})")
                logger.info("self-heal: restarted %s (was %s)", unit, active)
            else:
                logger.warning(
                    "self-heal: restart of %s failed: %s", unit, result["error"])
        return actions

    def _heal_missing_interfaces(self) -> list:
        """Set ``interfaces-config.interfaces`` when it is empty.

        ``interfaces-config`` is node-owned (see ``build_node_config`` /
        ``COORDINATOR_OWNED_KEYS`` in ``kea_ha.py``) — the LM sync path never
        touches it, and the stock Debian ``kea-dhcp4-server`` package ships it
        as ``[]`` ("listen on nothing") with a comment telling the operator to
        fill it in by hand. Nothing in ``install_dhcp.sh`` ever did, so a node
        can run for a long time looking completely healthy — service active,
        HA heartbeats fine, control agent answering, config-get fine — while
        Kea has never actually opened a DHCPv4 socket and every real client is
        silently getting no offer at all. This is exactly the case behind the
        "Nothing is listening on DHCP server port UDP/67" recommendation.

        Heals by setting ``interfaces`` to ``["*"]`` — listen on every
        interface, the same safe default an operator would type by hand — via
        ``config-set``/``config-write``, then restarting the daemon: Kea's
        DHCPv4 socket set is bound once at startup, so a ``config-set`` alone
        (no restart) updates the on-disk/running JSON but does not open the
        new listener until the process restarts.
        """
        # Read the running config.
        try:
            config = self.get_config()
        except Exception as e:
            logger.warning("self-heal (interfaces): could not read config: %s", e)
            # Surface the failure instead of silently returning [] — a caller
            # reading "no self-heal actions" has no way to tell "nothing
            # needed fixing" apart from "the heal itself couldn't even check",
            # which is exactly the ambiguity that let this stay broken.
            return [f"could not check interfaces-config: {e}"]
        # Current interfaces list.
        raw_interfaces = ((config.get("interfaces-config", {}) or {})
                          .get("interfaces", []) or [])
        # Filter out blank/whitespace-only entries — Kea's config-get has been
        # observed to echo an "empty" interfaces list back as ``[""]`` rather
        # than ``[]``, which is still falsy/non-listening but IS a non-empty
        # Python list, so a plain truthiness check would wrongly treat it as
        # "already configured" and silently skip healing (matches the same
        # stricter filtering diagnostics() already applies below).
        interfaces = [v for v in raw_interfaces if str(v).strip()]
        # Already configured: nothing to do.
        if interfaces:
            return []
        # Set interfaces to "*" in a copy of the config and apply it.
        new_config = copy.deepcopy(config)
        new_config.setdefault("interfaces-config", {})["interfaces"] = ["*"]
        try:
            result = self.apply_config(new_config)
        except Exception as e:
            logger.warning("self-heal (interfaces): apply failed: %s", e)
            return [f"failed to set interfaces-config: {e}"]
        # Both set and write must succeed.
        if not (result.get("set") and result.get("written")):
            logger.warning("self-heal (interfaces): apply did not succeed: %s", result)
            return [f"could not set interfaces-config: "
                    f"{result.get('error') or 'config-set/config-write did not report success'}"]
        # Restart Kea so it opens the new listener.
        restart = self._run_diag(["systemctl", "restart", "kea-dhcp4-server"], timeout=20)
        if not restart["ok"]:
            logger.warning(
                "self-heal (interfaces): config updated but restart failed: %s",
                restart["error"])
            return ["set interfaces-config to listen on all interfaces "
                    "(restart failed — apply manually with systemctl restart "
                    "kea-dhcp4-server)"]
        # Log and report the repair.
        logger.info(
            "self-heal: interfaces-config was empty (Kea was listening on "
            "nothing); set to listen on all interfaces and restarted "
            "kea-dhcp4-server")
        return ["set interfaces-config to listen on all interfaces "
                "(was empty) and restarted kea-dhcp4-server"]

    #: Kea's control socket, and the runtime directory holding it. Both units
    #: declare ``RuntimeDirectory=kea`` with ``User=_kea``, so systemd
    #: re-creates and re-chowns the directory on every start — which is what
    #: makes a plain restart a complete, data-safe repair for a hijacked one.
    _CTRL_SOCKET_DEFAULT = "/run/kea/kea4-ctrl-socket"

    def _config_ctrl_socket_path(self) -> str:
        """The dhcp4 control socket path, read from the ON-DISK config.

        Deliberately not via ``get_config()``: reaching the config means
        talking to the control agent through the very socket this check
        exists to validate, so the RPC is exactly what fails when there is
        something to heal.
        """
        # Read the on-disk config; fall back to the default path.
        try:
            with open("/etc/kea/kea-dhcp4.conf", "r") as fh:
                raw = fh.read()
        except OSError:
            return self._CTRL_SOCKET_DEFAULT
        # Pull out socket-name, else use the default.
        m = re.search(r'"socket-name"\s*:\s*"([^"]+)"', raw)
        return m.group(1) if m else self._CTRL_SOCKET_DEFAULT

    def _heal_control_socket_ownership(self) -> list:
        """Restart Kea when its runtime dir/control socket is owned by someone
        other than the user the daemons actually run as.

        Kea's runtime directory is SHARED by name (``/run/kea``). Anything
        else that starts a Kea as root — notably a co-located ``-sim`` stack —
        creates it first, as ``root:root 0750``. ``kea-dhcp4-server`` and
        ``kea-ctrl-agent`` run as ``_kea`` and then cannot even traverse their
        own runtime directory, so every ``config-get``/``config-set`` the hub
        issues comes back as ``"unable to forward command to the dhcp4
        service: Permission denied. The server is likely to be offline"``.

        This was invisible to ``_heal_inactive_units``, which only restarts
        units systemd reports as failed/inactive: BOTH units stay perfectly
        ``active`` here — they are running, they are just locked out of their
        own socket. The whole DHCP cluster silently contributes nothing to the
        hub (no subnets, no reservations, no leases) while looking healthy in
        systemd, and the sync's reservation apply fails at ``read-config``.

        Restarting is the complete fix precisely because ``RuntimeDirectory=``
        makes systemd re-create and re-chown the directory for the unit's own
        ``User=``. No configuration and no lease/reservation data is touched.
        """
        # Socket path and its runtime directory.
        socket_path = self._config_ctrl_socket_path()
        run_dir = os.path.dirname(socket_path) or "/run/kea"
        # Look up the _kea user id.
        try:
            want_uid = pwd.getpwnam("_kea").pw_uid
        except KeyError:
            return []  # not a packaged/_kea install — nothing to reason about
        # Find paths not owned by _kea.
        offenders = []
        for path in (run_dir, socket_path):
            try:
                if os.stat(path).st_uid != want_uid:
                    offenders.append(path)
            except OSError:
                continue  # absent is _heal_inactive_units' problem, not ours
        # Everything is owned correctly.
        if not offenders:
            return []
        logger.warning(
            "self-heal: %s not owned by _kea — Kea is locked out of its own "
            "control socket; restarting so systemd re-chowns RuntimeDirectory",
            ", ".join(offenders))
        actions = []
        # dhcp4 first: it owns the socket the control agent connects to, so
        # restarting the CA first would only have it reconnect to the stale,
        # still-misowned socket.
        for unit in ("kea-dhcp4-server", "kea-ctrl-agent"):
            result = self._run_diag(["systemctl", "restart", unit], timeout=20)
            if not result["ok"]:
                logger.warning("self-heal: restart of %s failed: %s",
                               unit, result["error"])
                actions.append(f"failed to restart {unit}: {result['error']}")
                return actions
            actions.append(f"restarted {unit}")
        # Check again after the restarts.
        still_wrong = []
        for path in offenders:
            try:
                if os.stat(path).st_uid != want_uid:
                    still_wrong.append(path)
            except OSError:
                still_wrong.append(path)
        if still_wrong:
            # Say so rather than reporting a clean repair — the usual cause is
            # the root-owned process that took the directory still running and
            # re-creating it, which needs an operator.
            return [f"restarted Kea but {', '.join(still_wrong)} is still not "
                    f"owned by _kea (something else running as root is "
                    f"re-creating {run_dir})"]
        # Report the repair.
        return [f"restarted Kea: {', '.join(offenders)} was not owned by _kea "
                f"(control socket was unreachable)"]

    def diagnostics(self) -> dict:
        """Return Kea service, config, interface, listener, CA, and lease checks."""
        # Run the self-heal repairs first.
        repairs = self._self_heal()
        # Unit states and a config syntax check.
        units = {
            name: self._unit_status(name)
            for name in ("kea-dhcp4-server", "kea-ctrl-agent")
        }
        config_test = self._run_diag(
            ["kea-dhcp4", "-t", "/etc/kea/kea-dhcp4.conf"], timeout=10)
        # The control agent has its OWN config file (kea-ctrl-agent.conf) and
        # its own syntax-check binary invocation. A "Control Agent is not
        # active" recommendation with no further detail forced a manual SSH
        # to find out WHY — this test + the dedicated journal tail below give
        # the actual failure reason (bad JSON, socket path, port already
        # bound, etc.) directly in the diagnostics panel.
        ca_config_test = self._run_diag(
            ["kea-ctrl-agent", "-t", "/etc/kea/kea-ctrl-agent.conf"], timeout=10)
        # Listening sockets (retry without process info if that fails).
        sockets = self._run_diag(["ss", "-H", "-lntup"])
        if not sockets["ok"]:
            sockets = self._run_diag(["ss", "-H", "-lntu"])
        # Keep lines for port 67 (DHCP) and 8001 (Control Agent).
        listener_lines = [
            line.strip() for line in sockets["output"].splitlines()
            if re.search(r"(?:\]:|:)(?:67|8001)(?:\s|$)", line)
        ]
        dhcp_listeners = [line for line in listener_lines
                          if re.search(r"(?:\]:|:)67(?:\s|$)", line)]
        ca_listeners = [line for line in listener_lines
                        if re.search(r"(?:\]:|:)8001(?:\s|$)", line)]

        # Query the Control Agent for version, config and leases.
        ca = {"reachable": False, "config_loaded": False,
              "url": self.ca_url, "version": "", "error": ""}
        config = {}
        leases = None
        try:
            version = self._rpc("dhcp4", "version-get")
            ca["reachable"] = True
            ca["version"] = str(
                version.get("extended") or version.get("version") or "")
        # Unreachable: keep the error.
        except Exception as e:
            ca["error"] = str(e)
        # Reachable: load the config.
        if ca["reachable"]:
            try:
                config = self.get_config()
                ca["config_loaded"] = True
            # Config failed: keep the error.
            except Exception as e:
                ca["error"] = str(e)
            try:
                # Always pass "subnets" explicitly — per ISC docs, omitting
                # "arguments" entirely means "every subnet", but this
                # HA-hooked node rejects a bare/no-args call with
                # "'subnets' parameter not specified" regardless (the HA hook
                # likely intercepts lease4-get-all and requires an explicit
                # subnet list to know which node's view is authoritative for
                # each one). Reuse the subnet4 IDs from the config already
                # fetched above rather than a second config-get/subnet4-list
                # round trip.
                subnet_ids = [s["id"] for s in (config.get("subnet4", []) or [])
                              if "id" in s]
                lease_data = self._rpc(
                    "dhcp4", "lease4-get-all", {"subnets": subnet_ids})
                leases = lease_data.get("leases", [])
            # Lease query failed: keep the first error.
            except Exception as e:
                if not ca["error"]:
                    ca["error"] = str(e)

        # Configured interfaces, and those that do not exist on this host.
        interfaces = [
            str(value).split("/", 1)[0].strip()
            for value in ((config.get("interfaces-config", {}) or {})
                          .get("interfaces", []) or [])
            if str(value).strip()
        ]
        missing_interfaces = [
            iface for iface in interfaces
            if iface != "*" and not os.path.exists(f"/sys/class/net/{iface}")
        ]
        # Subnets and lease database details.
        subnets = config.get("subnet4", []) or []
        lease_file = ((config.get("lease-database", {}) or {}).get("name") or "")
        lease_db = {
            "path": lease_file,
            "exists": bool(lease_file and os.path.exists(lease_file)),
            "leases": len(leases) if leases is not None else None,
        }
        # Recent warnings from both Kea units.
        recent = self._run_diag([
            "journalctl", "-u", "kea-dhcp4-server", "-u", "kea-ctrl-agent",
            "-p", "warning", "-n", "20", "--since", "7 days ago", "--no-pager",
        ])
        recent_errors = [
            line for line in recent["output"].splitlines()
            if line.strip() and "-- No entries --" not in line
        ][-20:]
        # kea-ctrl-agent's OWN tail, unfiltered by priority. When the CA unit
        # itself never came up (crash-looped, port already bound, bad JSON in
        # kea-ctrl-agent.conf), the failure is usually logged at "info"/"err"
        # around process exit — the combined "-p warning" tail above can miss
        # it entirely if kea-dhcp4-server is chattier. This is what actually
        # answers "why is Control Agent FAIL / connection refused".
        ca_recent = self._run_diag([
            "journalctl", "-u", "kea-ctrl-agent", "-n", "20",
            "--no-pager", "-o", "cat",
        ])
        ca_recent_errors = [
            line for line in ca_recent["output"].splitlines()
            if line.strip() and "-- No entries --" not in line
        ][-20:]

        # Build recommendations, starting with any repairs made.
        recommendations = []
        for action in repairs:
            recommendations.append(f"Self-healed: {action}. Re-checking findings above.")
        # DHCP4 service not active.
        if units["kea-dhcp4-server"].get("ActiveState") != "active":
            recommendations.append(
                "Kea DHCP4 is not active; inspect its service status and recent log.")
        # Control Agent not active: add its exit status and the likely reason.
        ca_unit = units["kea-ctrl-agent"]
        if ca_unit.get("ActiveState") != "active":
            detail = (
                f" (exit status {ca_unit['ExecMainStatus']})"
                if ca_unit.get("ExecMainStatus") not in (None, "", "0") else "")
            recommendations.append(
                "Kea Control Agent is not active; the LM DHCP module cannot "
                f"manage Kea{detail}.")
            if not ca_config_test["ok"]:
                recommendations.append(
                    "kea-ctrl-agent.conf failed its own syntax check: "
                    + (ca_config_test["error"] or ca_config_test["output"]
                       or "see config_test output").strip()[:300])
            elif ca_recent_errors:
                recommendations.append(
                    "kea-ctrl-agent recent log: " + ca_recent_errors[-1][:300])
        # Config validation failure.
        if not config_test["ok"]:
            recommendations.append(
                "Kea configuration validation failed; fix the reported config error.")
        # Control Agent unreachable, or reachable but config failed.
        if not ca["reachable"]:
            recommendations.append(
                f"Kea Control Agent did not answer at {self.ca_url}.")
        elif not ca["config_loaded"]:
            recommendations.append(
                "Kea Control Agent answered, but DHCP4 configuration retrieval failed.")
        # Lease query failed.
        if leases is None:
            recommendations.append(
                "Kea lease retrieval failed; the active lease count is unavailable.")
        # Configured interfaces that do not exist.
        if missing_interfaces:
            recommendations.append(
                "Configured DHCP interface(s) are missing: "
                + ", ".join(missing_interfaces) + ".")
        # No DHCP listener.
        if not dhcp_listeners:
            recommendations.append(
                "Nothing is listening on DHCP server port UDP/67.")
        # Scopes with no (or an unreachable) default gateway.
        scope_gateways, gateway_problems = scope_gateway_findings(config)
        recommendations.extend(gateway_problems)

        # Healthy only when every check passes.
        healthy = (
            units["kea-dhcp4-server"].get("ActiveState") == "active"
            and units["kea-ctrl-agent"].get("ActiveState") == "active"
            and config_test["ok"]
            and ca["reachable"]
            and ca["config_loaded"]
            and leases is not None
            and not missing_interfaces
            and bool(dhcp_listeners)
        )
        # Full diagnostics report.
        return {
            "status": "SUCCESS",
            "healthy": healthy,
            "worker_code_version": worker_code_version(),
            "self_healed": repairs,
            "units": units,
            "ca": ca,
            "config_test": config_test,
            "ca_config_test": ca_config_test,
            "ca_recent_errors": ca_recent_errors,
            "interfaces_configured": interfaces,
            "interface_missing": missing_interfaces,
            "subnets": [
                {"id": s.get("id"), "subnet": s.get("subnet", ""),
                 "gateway": scope_gateways.get(str(s.get("subnet") or ""), ""),
                 "pools": [p.get("pool", "") for p in (s.get("pools", []) or [])]}
                for s in subnets
            ],
            "lease_db": lease_db,
            "listeners": {
                "dhcp4": dhcp_listeners,
                "control_agent": ca_listeners,
                "error": sockets["error"],
            },
            "last_errors": recent_errors,
            "recommendations": recommendations,
        }

    def packet_trace(self, mac: str = "", minutes: Any = 30,
                     capture_seconds: Any = 0) -> dict:
        """DHCPv4 request/error trace: is this server seeing the client, and
        where does the exchange stop?

        Read-only. Combines Kea's journal (``DHCP4_PACKET_RECEIVED`` /
        ``PACKET_SEND`` / ``LEASE_ALLOC`` are INFO-level), an optional raw
        UDP/67-68 capture of ``capture_seconds`` while the client retries, the
        ``pkt4-*`` counter delta across that window, and the client's current
        lease/reservation. See ``kea_packet_trace``.
        """
        # Validate the MAC and clamp the time windows.
        try:
            mac = pkt_trace.normalize_mac(mac)
        except ValueError as e:
            return {"status": "ERROR", "message": str(e)}
        minutes = pkt_trace.clamp_int(minutes, 30, 1, pkt_trace.MAX_LOOKBACK_MINUTES)
        capture_seconds = pkt_trace.clamp_int(
            capture_seconds, 0, 0, pkt_trace.MAX_CAPTURE_SECONDS)

        # Errors collected along the way.
        errors = []

        def counters():
            """Read the current packet counters.

            Returns:
                Counter dict, or None if the stats call failed (the error is recorded).
            """
            # Fetch stats and pick out the packet counters.
            try:
                return pkt_trace.packet_counters(
                    self._rpc("dhcp4", "statistic-get-all", {}))
            except Exception as e:  # noqa: BLE001
                errors.append(f"statistic-get-all: {e}")
                return None

        # Counters before and after an optional capture, plus the Kea journal.
        before = counters()
        capture = pkt_trace.capture_dhcp(capture_seconds, mac)
        after = counters() if capture_seconds else before
        journal = pkt_trace.read_kea_journal(minutes, mac)
        # Record journal and capture errors.
        if journal["error"]:
            errors.append(f"journal: {journal['error']}")
        if capture["error"]:
            errors.append(f"capture: {capture['error']}")

        # Read the config for interfaces and reservations.
        config = {}
        try:
            config = self.get_config()
        except Exception as e:  # noqa: BLE001
            errors.append(f"config-get: {e}")
        # Configured interfaces and this host's IPv4 addresses.
        interfaces = [str(v).strip() for v in
                      ((config.get("interfaces-config", {}) or {})
                       .get("interfaces", []) or []) if str(v).strip()]
        local_ips = pkt_trace.local_ipv4s()
        events = journal["events"]
        # Base result.
        result = {
            "status": "SUCCESS",
            "mac": mac,
            "minutes": minutes,
            "capture": capture,
            "counters": after or {},
            "counters_delta": (pkt_trace.counter_delta(before, after)
                               if capture_seconds and before is not None
                               and after is not None else {}),
            "interfaces_configured": interfaces,
            "server_ips": local_ips,
            "events": events[-pkt_trace.MAX_EVENTS:],
            "events_total": len(events),
            "server_problems": journal["problems"],
            "errors": errors,
        }
        # No MAC: summarize every client seen.
        if not mac:
            result["clients"] = pkt_trace.summarize_all_clients(events)
            return result

        # Per-client summary and verdict.
        result["summary"] = pkt_trace.summarize_client(events, capture["packets"])
        result["verdict"] = pkt_trace.verdict_for_client(
            mac, events, capture, minutes, interfaces, local_ips)
        # The client's current leases.
        try:
            leases = self._rpc("dhcp4", "lease4-get-by-hw-address",
                               {"hw-address": mac}).get("leases", []) or []
            result["leases"] = [
                {"ip": l.get("ip-address", ""), "subnet_id": l.get("subnet-id"),
                 "state": l.get("state"), "cltt": l.get("cltt"),
                 "valid_lft": l.get("valid-lft"), "hostname": l.get("hostname", "")}
                for l in leases]
        except Exception as e:  # noqa: BLE001
            result["leases"] = None
            errors.append(f"lease4-get-by-hw-address: {e}")
        # The client's reservations from the config.
        result["reservations"] = [
            {"ip": r.get("ip-address", ""), "subnet_id": sub.get("id"),
             "subnet": sub.get("subnet", ""), "hostname": r.get("hostname", "")}
            for sub in (config.get("subnet4", []) or [])
            for r in (sub.get("reservations", []) or [])
            if _normalize_mac(r.get("hw-address", "")) == mac
        ]
        return result

    @staticmethod
    def _run_diag(cmd, timeout=5):
        """Run a diagnostic command and capture its outcome.

        Args:
            cmd: Command and arguments.
            timeout: Seconds before giving up.

        Returns:
            Dict with ok, exit_code, output (trimmed to 4000 chars) and error.
        """
        # Run it and keep stdout (or stderr), trimmed.
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout)
            output = (result.stdout or result.stderr or "").strip()[:4000]
            return {
                "ok": result.returncode == 0,
                "exit_code": result.returncode,
                "output": output,
                "error": "" if result.returncode == 0 else (output or "command failed"),
            }
        # Could not run it at all.
        except Exception as e:
            return {"ok": False, "exit_code": None, "output": "", "error": str(e)}

    def _unit_status(self, unit):
        """Read key systemd properties for a unit.

        Args:
            unit: Unit name.

        Returns:
            Dict of property values plus an "error" key.
        """
        # Ask systemctl for the properties.
        result = self._run_diag([
            "systemctl", "show", unit,
            "--property=LoadState,ActiveState,SubState,NRestarts,ExecMainStatus",
        ])
        # Parse key=value lines.
        values = {}
        for line in result["output"].splitlines():
            key, sep, value = line.partition("=")
            if sep:
                values[key] = value
        # Add any command error.
        values["error"] = result["error"]
        return values
