"""Reserve statically addressed hosts in DHCP (NetBox → Kea).

A host configured with a static IP inside a Kea-served scope is invisible to
Kea: it holds no lease, so Kea may hand the same address to another client.
This pass finds such hosts and marks their NetBox IP as a DHCP reservation
(``custom_fields.mac_address`` + ``dhcp_reservation: true``), the same shape
the WebUI reservation write-back uses. ``build_dhcp_payload`` then pushes it
to Kea on the next NetBox → Kea sync, which runs straight after this pass.

Candidates come from two places, per tenant:

* **Agents** — a connected generic agent bound to the tenant answers
  ``GET_HOST_ADDRESSING`` with each IPv4 address, its MAC and its mode
  (``static`` / ``dhcp`` / ``unknown``). Only ``static`` is a candidate; an
  agent's ``dhcp`` answer vetoes the address.
* **Network sweep** — hosts the sweep saw answering in the last day
  (``nw_seen_hosts``) whose MAC the latest nw discovery cycle saw in a live
  ARP table (``_nw_live_arp``). No live MAC, no candidate.

Every candidate goes through ``plan_static_reservations``, which is
deliberately conservative: it only marks an IP that NetBox already records in
the tenant's scope, inside a DHCP-enabled prefix, with no Kea lease for the IP
or the MAC, and it never overwrites a reservation or MAC that differs — those
are reported as conflicts instead. Kea leases are read strictly (an unreadable
Kea skips the whole pass rather than reading as "no leases").

Config: ``global_config.static_ip_reservations`` ``{enabled: true,
interval: 900}``. Status: ``GET /api/dns-dhcp/sync-status`` →
``static_reservations``.

This module is a **leaf**: stdlib plus sibling leaves only.

Audience: Hub developers.
"""

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio bounds the agent polls.
import asyncio
# ipaddress matches addresses to prefixes.
import ipaddress
# Standard-library logging for pass results and conflicts.
import logging
# time stamps and throttles each pass.
import time
# Type hints only.
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Tenant scoping, spoke ownership and MAC normalisation.
from access import (get_netbox_spoke, netbox_tenant_scope, norm_mac,
                    spoke_owner_tenant, tenant_is_shared, unwrap_spoke)
# The one rule for "this prefix is a Kea scope".
from dns_dhcp_sync import is_dhcp_scope

# Use the hub's main logger so pass lines appear with other hub output.
logger = logging.getLogger("Hub")

# global_config key and defaults.
_CFG_KEY = "static_ip_reservations"
_DEFAULT_INTERVAL = 900          # seconds between passes
# Sweep candidates: seen answering within a day, MAC from an ARP map under 2h old.
_SEEN_WINDOW = 24 * 3600
_ARP_MAX_AGE = 2 * 3600
# Bounds: concurrent agent polls, agent reply timeout, NetBox writes per pass.
_AGENT_CONCURRENCY = 8
_AGENT_TIMEOUT = 15.0
_MAX_WRITES_PER_PASS = 25


def _host(address: Any) -> str:
    """``"10.0.0.5/24"`` → ``"10.0.0.5"``; ``""`` for anything not an IPv4 host."""
    # Strip the prefix length and validate.
    try:
        ip = ipaddress.ip_address(str(address or "").split("/")[0].strip())
    except ValueError:
        return ""
    return str(ip) if ip.version == 4 else ""


def _scopes(pfx_data: Dict[str, Any]) -> List[Tuple[Any, str]]:
    """DHCP-served prefixes as ``[(network, vrf)]``, most specific first."""
    # Keep only Kea scopes (same rule as build_dhcp_payload).
    out = []
    for p in (pfx_data or {}).get("prefixes") or []:
        if not is_dhcp_scope(p):
            continue
        try:
            net = ipaddress.ip_network(str(p["prefix"]), strict=False)
        except ValueError:
            continue
        if net.version == 4:
            out.append((net, str(p.get("vrf") or "")))
    # Most specific first so a nested scope wins.
    return sorted(out, key=lambda s: -s[0].prefixlen)


def plan_static_reservations(pfx_data: Dict[str, Any], ips_data: Dict[str, Any],
                             leases: Iterable[Dict[str, Any]],
                             candidates: Iterable[Dict[str, Any]]) -> Dict[str, List]:
    """Decide which candidates become reservations. Pure; no I/O.

    Args:
        pfx_data: ``NETBOX_GET_PREFIXES`` reply for one tenant scope.
        ips_data: ``NETBOX_GET_IPS`` reply for the same scope.
        leases: Kea v4 lease dicts (``ip-address``, ``hw-address``).
        candidates: ``{ip, mac, mode, source}``; ``mode`` is ``static``,
            ``dhcp`` (agent saw a lease: veto) or ``unknown``.

    Returns:
        ``{"reserve": [{ip_id, ip, mac, source}], "conflicts": [{ip, mac,
        reason}], "skipped": [{ip, reason}]}``.
    """
    reserve: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    scopes = _scopes(pfx_data)

    # Index NetBox IPs by host address; existing reservations by MAC.
    nb_rows: Dict[str, List[Dict[str, Any]]] = {}
    reserved_mac_at: Dict[str, str] = {}
    for row in (ips_data or {}).get("ip_addresses") or []:
        ip = _host(row.get("address"))
        if not ip:
            continue
        nb_rows.setdefault(ip, []).append(row)
        cf = row.get("custom_fields") or {}
        mac = norm_mac(cf.get("mac_address"))
        if cf.get("dhcp_reservation") and mac:
            reserved_mac_at.setdefault(mac, ip)

    # Index Kea leases by IP and the set of MACs holding any lease.
    lease_macs_by_ip: Dict[str, set] = {}
    leased_macs = set()
    for lease in leases or []:
        ip = _host(lease.get("ip-address") or lease.get("ip"))
        mac = norm_mac(lease.get("hw-address") or lease.get("mac"))
        if ip:
            lease_macs_by_ip.setdefault(ip, set()).add(mac)
        if mac:
            leased_macs.add(mac)

    # Merge candidates per IP: an agent "dhcp" answer vetoes; MACs must agree.
    merged: Dict[str, Dict[str, Any]] = {}
    for c in candidates or []:
        ip, mac = _host(c.get("ip")), norm_mac(c.get("mac"))
        if not ip:
            continue
        m = merged.setdefault(ip, {"ip": ip, "macs": set(), "modes": set(), "sources": set()})
        if mac:
            m["macs"].add(mac)
        m["modes"].add(str(c.get("mode") or "unknown"))
        m["sources"].add(str(c.get("source") or ""))
    # A MAC seen at several candidate IPs (proxy ARP, multi-homed) is ambiguous.
    mac_ip_count: Dict[str, int] = {}
    for m in merged.values():
        for mac in m["macs"]:
            mac_ip_count[mac] = mac_ip_count.get(mac, 0) + 1

    for ip, m in sorted(merged.items()):
        # Step 1: exactly one valid, known MAC, used at no other candidate IP.
        macs = {x for x in m["macs"] if len(x) == 17}
        if len(macs) != 1:
            skipped.append({"ip": ip, "reason": "mac unknown or ambiguous"})
            continue
        mac = next(iter(macs))
        if mac_ip_count.get(mac, 0) > 1:
            skipped.append({"ip": ip, "reason": "mac seen at several addresses"})
            continue
        # Step 2: every source must say static; an agent's dhcp/unknown vetoes.
        if "dhcp" in m["modes"]:
            skipped.append({"ip": ip, "reason": "agent reports dhcp"})
            continue
        if m["modes"] != {"static"}:
            skipped.append({"ip": ip, "reason": "not known to be static"})
            continue
        # Step 3: inside a Kea-served prefix of this tenant.
        addr = ipaddress.ip_address(ip)
        scope = next((s for s in scopes if addr in s[0]), None)
        if scope is None:
            skipped.append({"ip": ip, "reason": "outside any dhcp scope"})
            continue
        net, scope_vrf = scope
        if addr in (net.network_address, net.broadcast_address):
            skipped.append({"ip": ip, "reason": "network or broadcast address"})
            continue
        # Step 4: exactly one NetBox IP object, in the scope's VRF.
        rows = nb_rows.get(ip) or []
        if len(rows) != 1:
            skipped.append({"ip": ip, "reason": "no netbox ip" if not rows
                            else "several netbox ips"})
            continue
        row = rows[0]
        if scope_vrf and str(row.get("vrf") or "") and str(row.get("vrf")) != scope_vrf:
            skipped.append({"ip": ip, "reason": "vrf differs from scope"})
            continue
        if str(row.get("status") or "").lower() == "dhcp":
            skipped.append({"ip": ip, "reason": "netbox status is dhcp"})
            continue
        cf = row.get("custom_fields") or {}
        nb_mac = norm_mac(cf.get("mac_address"))
        # Step 5: never overwrite a different reservation or MAC.
        if cf.get("dhcp_reservation"):
            if nb_mac == mac:
                skipped.append({"ip": ip, "reason": "already reserved"})
            else:
                conflicts.append({"ip": ip, "mac": mac,
                                  "reason": "reserved for another mac"})
            continue
        if nb_mac and nb_mac != mac:
            conflicts.append({"ip": ip, "mac": mac, "reason": "netbox mac differs"})
            continue
        if reserved_mac_at.get(mac, ip) != ip:
            conflicts.append({"ip": ip, "mac": mac,
                              "reason": "mac reserved at another address"})
            continue
        # Step 6: any Kea lease for the IP or the MAC means not static.
        lease_macs = lease_macs_by_ip.get(ip)
        if lease_macs:
            if lease_macs == {mac}:
                skipped.append({"ip": ip, "reason": "dynamic lease"})
            else:
                conflicts.append({"ip": ip, "mac": mac,
                                  "reason": "leased to another mac"})
            continue
        if mac in leased_macs:
            skipped.append({"ip": ip, "reason": "mac holds a lease"})
            continue
        # Static, unclaimed and in scope: reserve it.
        reserve.append({"ip_id": row.get("id"), "ip": ip, "mac": mac,
                        "source": ",".join(sorted(x for x in m["sources"] if x))})
    return {"reserve": reserve, "conflicts": conflicts, "skipped": skipped}


def _cfg(hub) -> Dict[str, Any]:
    """Read ``global_config.static_ip_reservations`` fresh, with defaults."""
    # "or {}" guards against a stored None.
    gc = hub.state.system_state.get("global_config", {}) or {}
    cfg = gc.get(_CFG_KEY, {}) or {}
    return {"enabled": bool(cfg.get("enabled", True)),
            "interval": int(cfg.get("interval", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL)}


def _sweep_candidates(hub, tid: str, now: float) -> List[Dict[str, Any]]:
    """Recently seen sweep hosts of ``tid`` that have a fresh live-ARP MAC."""
    # The latest nw discovery ARP map for the tenant, if fresh.
    arp = (getattr(hub, "_nw_live_arp", None) or {}).get(tid) or {}
    if now - float(arp.get("at") or 0) > _ARP_MAX_AGE:
        return []
    macs = arp.get("macs") or {}
    # Hosts the sweep saw answering within the window.
    gc = hub.state.system_state.get("global_config", {}) or {}
    seen = ((gc.get("nw_seen_hosts") or {}).get(tid)) or {}
    out = []
    for ip, entry in seen.items():
        if now - float((entry or {}).get("last_seen") or 0) > _SEEN_WINDOW:
            continue
        mac = norm_mac(macs.get(ip))
        if mac:
            out.append({"ip": ip, "mac": mac, "mode": "static", "source": "sweep"})
    return out


async def _agent_candidates(hub) -> Dict[str, List[Dict[str, Any]]]:
    """``{tid: [candidate]}`` from connected agents bound to a real tenant.

    Unbound and shared agents are skipped (their hosts have no single owning
    tenant). Polls run at most ``_AGENT_CONCURRENCY`` at a time; an agent that
    errors, times out or predates ``GET_HOST_ADDRESSING`` contributes nothing.
    """
    # Connected agents with an owning tenant.
    active = getattr(hub, "active_connections", None)
    agents = []
    for sid in hub.get_all_spokes_by_type("agent") or []:
        if active is not None and sid not in active:
            continue
        tid = spoke_owner_tenant(hub, sid)
        if tid:
            agents.append((sid, tid))
    sem = asyncio.Semaphore(_AGENT_CONCURRENCY)

    async def _poll(sid: str) -> List[Dict[str, Any]]:
        """One agent's addresses, or [] on any failure."""
        # Bounded, best-effort read.
        async with sem:
            try:
                reply = unwrap_spoke(await hub.request_response(
                    sid, "GET_HOST_ADDRESSING", {}, timeout=_AGENT_TIMEOUT))
            except Exception as e:  # noqa: BLE001
                logger.debug("static reservations: agent %s: %s", sid, e)
                return []
        if not isinstance(reply, dict) or reply.get("status") != "SUCCESS":
            return []
        return [a for a in reply.get("addresses") or [] if isinstance(a, dict)]

    # Poll and group by tenant.
    results = await asyncio.gather(*[_poll(sid) for sid, _ in agents])
    out: Dict[str, List[Dict[str, Any]]] = {}
    for (sid, tid), addresses in zip(agents, results):
        for a in addresses:
            out.setdefault(tid, []).append({
                "ip": a.get("ip"), "mac": a.get("mac"),
                "mode": a.get("mode") or "unknown", "source": "agent"})
    return out


async def _strict_leases(hub, spokes: List[str]) -> Optional[List[Dict[str, Any]]]:
    """Every v4 lease from ``spokes``, or None unless EVERY spoke answered a
    strict read (old spokes, Kea errors and HA member errors all → None)."""
    if not spokes:
        return None
    # Ask each spoke for a strict lease list.
    replies = await asyncio.gather(*[
        hub.request_response(sid, "DHCP_LIST_LEASES", {"strict": True}, timeout=30.0)
        for sid in spokes], return_exceptions=True)
    leases: List[Dict[str, Any]] = []
    for sid, raw in zip(spokes, replies):
        reply = None if isinstance(raw, BaseException) else unwrap_spoke(raw)
        # Anything short of a clean strict answer makes the lease view untrustworthy.
        if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                or reply.get("strict") is not True or reply.get("member_errors") \
                or not isinstance(reply.get("leases"), list):
            logger.warning("static reservations: no strict lease read from %s; "
                           "pass skipped", sid)
            return None
        leases.extend(x for x in reply["leases"] if isinstance(x, dict))
    return leases


async def reserve_static_hosts_once(hub, now: Optional[float] = None,
                                    force: bool = False) -> Dict[str, Any]:
    """One pass: find static hosts per tenant and mark them reserved in NetBox.

    Throttled to ``interval`` unless ``force``. Tenants run one at a time;
    at most ``_MAX_WRITES_PER_PASS`` NetBox writes per pass. Records status
    under ``static_reservations`` and returns it.
    """
    now = time.time() if now is None else now
    cfg = _cfg(hub)
    # Step 1: honour the kill switch and the interval.
    if not cfg["enabled"]:
        return {"status": "disabled"}
    if not force and now - float(getattr(hub, "_static_res_last", 0) or 0) < cfg["interval"]:
        return {"status": "throttled"}
    hub._static_res_last = now

    # Step 2: gather candidates per real (non-shared) tenant.
    by_tid = await _agent_candidates(hub)
    for tid in list((getattr(hub, "_nw_live_arp", None) or {}).keys()):
        by_tid.setdefault(tid, [])
        by_tid[tid].extend(_sweep_candidates(hub, tid, now))
    by_tid = {t: c for t, c in by_tid.items() if c and t and not tenant_is_shared(t)}
    totals = {"tenants": 0, "reserved": [], "conflicts": [], "skipped": 0,
              "errors": []}
    if not by_tid:
        return hub._record_status("static_reservations", status="ok", **totals)

    # Step 3: Kea DHCP spokes grouped by the tenant scope they serve.
    groups, _skipped = hub._scope_groups(hub._get_dhcp_spokes())
    ipam = get_netbox_spoke(hub)
    writes = 0
    for tid, candidates in sorted(by_tid.items()):
        # The tenant's NetBox scope; no mapping → never touch it.
        scope = netbox_tenant_scope(hub, tid)
        filters = {k: scope[k] for k in ("tenant", "tenant_group") if scope.get(k)}
        if not filters:
            continue
        # Only the Kea spokes that would serve this tenant's scopes.
        spokes = list((groups.get("tenant:" + str(scope.get("key"))) or ({}, []))[1]) \
            + list((groups.get("") or ({}, []))[1])
        # No Kea serves this tenant: nothing to protect.
        if not spokes:
            continue
        leases = await _strict_leases(hub, spokes)
        if leases is None:
            totals["errors"].append({"tenant": tid, "error": "no strict kea lease read"})
            continue
        try:
            pfx_data, ips_data = await hub._netbox_prefixes_and_ips(filters)
        except Exception as e:  # noqa: BLE001
            totals["errors"].append({"tenant": tid, "error": f"netbox read: {e}"})
            continue
        plan = plan_static_reservations(pfx_data, ips_data, leases, candidates)
        totals["tenants"] += 1
        totals["skipped"] += len(plan["skipped"])
        # Step 4: report conflicts; never resolve them automatically.
        for c in plan["conflicts"]:
            logger.warning("static reservations: conflict %s (%s): %s",
                           c["ip"], c["mac"], c["reason"])
            totals["conflicts"].append({"tenant": tid, **c})
        # Step 5: write the reservations, capped per pass.
        for r in plan["reserve"]:
            if writes >= _MAX_WRITES_PER_PASS or not ipam or r.get("ip_id") is None:
                break
            writes += 1
            try:
                res = unwrap_spoke(await hub.request_response(
                    ipam, "NETBOX_UPDATE_IP_ADDR",
                    {"ip_id": r["ip_id"], "custom_fields": {
                        "mac_address": r["mac"], "dhcp_reservation": True}},
                    timeout=30.0))
            except Exception as e:  # noqa: BLE001
                res = {"status": "ERROR", "message": str(e)}
            if not isinstance(res, dict) or res.get("status") != "SUCCESS":
                totals["errors"].append({"tenant": tid, "ip": r["ip"],
                                         "error": (res or {}).get("message", "write failed")})
                continue
            logger.info("static reservations: reserved %s for %s (%s)",
                        r["ip"], r["mac"], r["source"])
            totals["reserved"].append({"tenant": tid, "ip": r["ip"],
                                       "mac": r["mac"], "source": r["source"]})

    # Step 6: refresh cached IPs and record the pass.
    if totals["reserved"]:
        hub.refresh_module_cache("netbox_ips")
    return hub._record_status("static_reservations",
                              status="error" if totals["errors"] else "ok", **totals)
