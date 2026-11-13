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
  ARP table (``_nw_live_arp``). No live MAC, no candidate. A sweep-only
  candidate also needs positive evidence: its IP must lie outside every Kea
  pool of its subnet (a DHCP client always gets a pool address, so a host
  outside the pools cannot be an offline DHCP client whose lease expired).
  An agent's ``static`` is not pool-checked: a static host inside a pool is
  the very clash this pass prevents, and a DHCP client of this Kea holds a
  lease, which vetoes it anyway.

Every candidate goes through ``plan_static_reservations``, which is
deliberately conservative: it only marks an IP that NetBox already records in
the tenant's scope, inside a DHCP-enabled prefix of exactly the IP's VRF, with
one well-formed MAC, no Kea lease for the IP or the MAC, and it never
overwrites a reservation or MAC that differs — those are reported as
conflicts instead. Leases and pools come from the tenant's OWN Kea when it
has one, else from the shared Kea, and are read strictly (an unreadable Kea
skips the tenant rather than reading as "no leases").

Config: ``global_config.static_ip_reservations`` ``{enabled: false,
interval: 900}``; off until an operator turns it on, since it writes to NetBox
and so to Kea. Status: ``GET /api/dns-dhcp/sync-status`` →
``static_reservations``, cut to the viewer's tenant (``status_for_tenant``).
NetBox reads for tenants the pass did not write to are handed to the same
tick's sync (``_hand_over_netbox_reads``), so each scope is read once.

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
# re validates MAC addresses.
import re
# time stamps and throttles each pass.
import time
# Type hints only.
from typing import Any, Dict, Iterable, List, Optional, Tuple

# Tenant scoping, spoke ownership and MAC normalisation.
from access import (netbox_tenant_scope, norm_mac, same_tenant,
                    spoke_owner_tenant, tenant_has_own_spoke, tenant_is_shared,
                    tenant_shared_fallback_blocked, unwrap_spoke)
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
# A normalised MAC: six hex octets.
_MAC_RE = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")


def _mac(value: Any) -> Optional[str]:
    """Normalised MAC; ``""`` when absent, ``None`` when present but malformed."""
    # Absent is not an observation.
    if value is None or not str(value).strip():
        return ""
    # Present: it must be six hex octets after normalisation.
    mac = norm_mac(value)
    return mac if _MAC_RE.fullmatch(mac or "") else None


def _vrf(value: Any) -> str:
    """A NetBox VRF as one comparable string: dict → id (else name),
    anything else → its name; None/"" → ``""`` (the global table)."""
    # A nested VRF object: prefer the id.
    if isinstance(value, dict):
        key = value.get("id")
        return str(key) if key not in (None, "") else str(value.get("name") or "")
    # A name, or nothing.
    return str(value or "").strip()


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
            out.append((net, _vrf(p.get("vrf"))))
    # Most specific first so a nested scope wins.
    return sorted(out, key=lambda s: -s[0].prefixlen)


def _kea_pools(kea_subnets: Optional[Iterable[Dict[str, Any]]]) -> List[Tuple[Any, Optional[List[Tuple[int, int]]]]]:
    """Kea v4 subnets as ``[(network, [(first, last)] or None)]``, most
    specific first. ``None`` pools means a pool could not be parsed."""
    out = []
    for sub in kea_subnets or []:
        # The subnet itself.
        try:
            net = ipaddress.ip_network(str(sub.get("subnet") or ""), strict=False)
        except ValueError:
            continue
        # Each pool is "a - b" or a CIDR; anything else makes the pools unknown.
        ranges: Optional[List[Tuple[int, int]]] = []
        for p in sub.get("pools") or []:
            text = str((p or {}).get("pool") if isinstance(p, dict) else p or "")
            try:
                if "/" in text:
                    pn = ipaddress.ip_network(text.strip(), strict=False)
                    ranges.append((int(pn.network_address), int(pn.broadcast_address)))
                else:
                    a, b = text.split("-")
                    ranges.append((int(ipaddress.ip_address(a.strip())),
                                   int(ipaddress.ip_address(b.strip()))))
            except ValueError:
                ranges = None
                break
        out.append((net, ranges))
    # Most specific first.
    return sorted(out, key=lambda s: -s[0].prefixlen)


def plan_static_reservations(pfx_data: Dict[str, Any], ips_data: Dict[str, Any],
                             leases: Iterable[Dict[str, Any]],
                             candidates: Iterable[Dict[str, Any]],
                             kea_subnets: Optional[Iterable[Dict[str, Any]]] = None
                             ) -> Dict[str, List]:
    """Decide which candidates become reservations. Pure; no I/O.

    Args:
        pfx_data: ``NETBOX_GET_PREFIXES`` reply for one tenant scope.
        ips_data: ``NETBOX_GET_IPS`` reply for the same scope.
        leases: Kea v4 lease dicts (``ip-address``, ``hw-address``).
        candidates: ``{ip, mac, mode, source}``; ``mode`` is ``static``,
            ``dhcp`` (agent saw a lease: veto) or ``unknown``.
        kea_subnets: Kea v4 subnets (``subnet``, ``pools``) from the same
            Kea; a sweep-only candidate must sit outside every pool. None →
            pools unknown, so sweep-only candidates are skipped.

    Returns:
        ``{"reserve": [{ip_id, ip, mac, source}], "conflicts": [{ip, mac,
        reason}], "skipped": [{ip, reason}]}``.
    """
    reserve: List[Dict[str, Any]] = []
    conflicts: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []
    scopes = _scopes(pfx_data)
    kea_nets = _kea_pools(kea_subnets)

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
        ip, mac = _host(c.get("ip")), _mac(c.get("mac"))
        if not ip:
            continue
        m = merged.setdefault(ip, {"ip": ip, "macs": set(), "modes": set(),
                                   "sources": set(), "bad_mac": False})
        # A malformed MAC from any source vetoes the IP (never dropped silently).
        if mac is None:
            m["bad_mac"] = True
        elif mac:
            m["macs"].add(mac)
        m["modes"].add(str(c.get("mode") or "unknown"))
        m["sources"].add(str(c.get("source") or ""))
    # A MAC seen at several candidate IPs (proxy ARP, multi-homed) is ambiguous.
    # An address an agent calls "unknown" (a secondary or VIP) is never
    # reserved, so it does not make the host's own static address ambiguous.
    mac_ip_count: Dict[str, int] = {}
    for m in merged.values():
        if "unknown" in m["modes"]:
            continue
        for mac in m["macs"]:
            mac_ip_count[mac] = mac_ip_count.get(mac, 0) + 1

    for ip, m in sorted(merged.items()):
        # Step 1: exactly one well-formed MAC, used at no other candidate IP.
        if m["bad_mac"]:
            skipped.append({"ip": ip, "reason": "malformed mac"})
            continue
        if len(m["macs"]) > 1:
            skipped.append({"ip": ip, "reason": "conflicting macs"})
            continue
        if not m["macs"]:
            skipped.append({"ip": ip, "reason": "mac unknown"})
            continue
        mac = next(iter(m["macs"]))
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
        # Step 3: inside some Kea-served prefix of this tenant.
        addr = ipaddress.ip_address(ip)
        if not any(addr in s[0] for s in scopes):
            skipped.append({"ip": ip, "reason": "outside any dhcp scope"})
            continue
        # Step 4: exactly one NetBox IP object.
        rows = nb_rows.get(ip) or []
        if len(rows) != 1:
            skipped.append({"ip": ip, "reason": "no netbox ip" if not rows
                            else "several netbox ips"})
            continue
        row = rows[0]
        # Step 4b: the scope is the most specific DHCP prefix in EXACTLY the IP's VRF.
        scope = next((s for s in scopes if addr in s[0] and s[1] == _vrf(row.get("vrf"))), None)
        if scope is None:
            skipped.append({"ip": ip, "reason": "vrf differs from scope"})
            continue
        net = scope[0]
        if addr in (net.network_address, net.broadcast_address):
            skipped.append({"ip": ip, "reason": "network or broadcast address"})
            continue
        # NetBox returns status as "dhcp" or as {"value": "dhcp", "label": "DHCP"}.
        status = row.get("status")
        if isinstance(status, dict):
            status = status.get("value")
        if str(status or "").lower() == "dhcp":
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
        # Step 7: a sweep-only host needs positive evidence — an IP outside
        # every Kea pool (a DHCP client always holds a pool address). An
        # agent's "static" is host-level evidence and is NOT pool-checked: a
        # static host inside a pool is exactly the clash this pass prevents,
        # and a DHCP client of this Kea (even with an infinite lease) holds a
        # lease, which step 6 already vetoes.
        if "agent" not in m["sources"]:
            kea = next((k for k in kea_nets if addr in k[0]), None)
            if kea is None or kea[1] is None:
                skipped.append({"ip": ip, "reason": "kea pools unknown"})
                continue
            if any(lo <= int(addr) <= hi for lo, hi in kea[1]):
                skipped.append({"ip": ip, "reason": "inside a dhcp pool"})
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
    return {"enabled": bool(cfg.get("enabled", False)),
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
        mac = macs.get(ip)
        if mac:
            out.append({"ip": ip, "mac": mac, "mode": "static", "source": "sweep"})
    return out


async def _agent_candidates(hub) -> Tuple[Dict[str, List[Dict[str, Any]]], set]:
    """``({tid: [candidate]}, failed_tids)`` from connected agents bound to a
    real tenant.

    Unbound and shared agents are skipped (their hosts have no single owning
    tenant). Polls run at most ``_AGENT_CONCURRENCY`` at a time. An agent that
    predates ``GET_HOST_ADDRESSING`` contributes nothing, like a host with no
    agent. An agent that errors or times out puts its tenant in
    ``failed_tids``: it might have said ``dhcp`` or ``unknown`` for an address
    another source saw, so that whole tenant waits for a pass where every
    agent answered.
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

    async def _poll(sid: str) -> Optional[List[Dict[str, Any]]]:
        """One agent's addresses; [] for an older agent, None on failure."""
        # Bounded, best-effort read.
        async with sem:
            try:
                reply = unwrap_spoke(await hub.request_response(
                    sid, "GET_HOST_ADDRESSING", {}, timeout=_AGENT_TIMEOUT))
            except Exception as e:  # noqa: BLE001
                logger.debug("static reservations: agent %s: %s", sid, e)
                return None
        if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
            return [a for a in reply.get("addresses") or [] if isinstance(a, dict)]
        if isinstance(reply, dict) and "unknown agent command" in str(reply.get("message", "")).lower():
            return []
        return None

    # Poll and group by tenant.
    results = await asyncio.gather(*[_poll(sid) for sid, _ in agents])
    out: Dict[str, List[Dict[str, Any]]] = {}
    failed = set()
    for (sid, tid), addresses in zip(agents, results):
        if addresses is None:
            failed.add(tid)
            continue
        for a in addresses:
            out.setdefault(tid, []).append({
                "ip": a.get("ip"), "mac": a.get("mac"),
                "mode": a.get("mode") or "unknown", "source": "agent"})
    return out, failed


async def _strict_read(hub, spokes: List[str], command: str,
                      key: str) -> Optional[List[Dict[str, Any]]]:
    """Every ``key`` row (leases or subnets) from ``spokes``, or None unless
    EVERY spoke answered a strict read (old spokes, Kea errors and HA member
    errors all → None)."""
    if not spokes:
        return None
    # Ask each spoke for a strict list.
    replies = await asyncio.gather(*[
        hub.request_response(sid, command, {"strict": True}, timeout=30.0)
        for sid in spokes], return_exceptions=True)
    rows: List[Dict[str, Any]] = []
    for sid, raw in zip(spokes, replies):
        reply = None if isinstance(raw, BaseException) else unwrap_spoke(raw)
        # Anything short of a clean strict answer makes the Kea view untrustworthy.
        if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                or reply.get("strict") is not True or reply.get("member_errors") \
                or not isinstance(reply.get(key), list):
            logger.warning("static reservations: no strict %s from %s; "
                           "tenant skipped", command, sid)
            return None
        rows.extend(x for x in reply[key] if isinstance(x, dict))
    return rows


def _tenant_kea_spokes(hub, tid: str, key: str, groups: Dict[str, Any]) -> List[str]:
    """The Kea spokes whose leases count for ``tid``: its OWN Kea when it has
    one (even if offline → none), else the shared/unbound Kea (fleet "own
    instance beats shared" rule, ``tenant_shared_fallback_blocked``)."""
    # The tenant's own connected Kea spokes.
    own = list((groups.get("tenant:" + key) or ({}, []))[1])
    if own:
        return own
    # It owns one that is offline, or may not use shared: nothing to read.
    if tenant_shared_fallback_blocked(hub, tid, "dhcp"):
        return []
    # Otherwise the shared Kea.
    return list((groups.get("") or ({}, []))[1])


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
    # Step 2: run the pass; stamp the throttle only once it completed, so a
    # pass that raised is retried on the next tick.
    result = await _run_pass(hub, now)
    hub._static_res_last = now
    return result


async def _run_pass(hub, now: float) -> Dict[str, Any]:
    """The body of ``reserve_static_hosts_once`` (no throttle)."""
    # Step 1: gather candidates per real (non-shared) tenant.
    by_tid, failed_tids = await _agent_candidates(hub)
    for tid in list((getattr(hub, "_nw_live_arp", None) or {}).keys()):
        by_tid.setdefault(tid, [])
        by_tid[tid].extend(_sweep_candidates(hub, tid, now))
    # A tenant with an agent that did not answer waits: every source must say static.
    by_tid = {t: c for t, c in by_tid.items()
              if c and t and t not in failed_tids and not tenant_is_shared(t)}
    totals = {"tenants": 0, "reserved": [], "conflicts": [], "skipped": 0, "deferred": 0,
              "errors": [{"tenant": t, "error": "agent poll failed; tenant waits"}
                         for t in sorted(failed_tids) if not tenant_is_shared(t)]}
    if not by_tid:
        return hub._record_status("static_reservations",
                                  status="error" if totals["errors"] else "ok", **totals)

    # Step 2: Kea DHCP spokes grouped by the tenant scope they serve.
    groups, _skipped = hub._scope_groups(hub._get_dhcp_spokes())
    # One IPAM spoke for reads and writes: NetBox ids only mean something on
    # the instance they came from. It is the sync's first choice too, so the
    # reads handed over below match what the sync would fetch.
    ipam = next(iter(hub._ipam_spoke_candidates()), None)
    writes = 0
    # NetBox reads still current after this pass, handed to the sync.
    reads: Dict[str, Any] = {}
    for tid, candidates in sorted(by_tid.items()):
        # The tenant's NetBox scope; no mapping → never touch it.
        scope = netbox_tenant_scope(hub, tid)
        filters = {k: scope[k] for k in ("tenant", "tenant_group") if scope.get(k)}
        if not filters:
            continue
        # The tenant's own Kea, else the shared one; none → nothing to protect.
        spokes = _tenant_kea_spokes(hub, tid, str(scope.get("key")), groups)
        if not spokes:
            # Its own Kea is offline: the pass could not do the work.
            if tenant_has_own_spoke(hub, tid, "dhcp"):
                totals["errors"].append({"tenant": tid, "error": "own kea not connected"})
            continue
        leases = await _strict_read(hub, spokes, "DHCP_LIST_LEASES", "leases")
        if leases is None:
            totals["errors"].append({"tenant": tid, "error": "no strict kea lease read"})
            continue
        # Pools are only needed for sweep-only candidates; unknown → those skip.
        kea_subnets = None
        if any(c.get("source") == "sweep" for c in candidates):
            kea_subnets = await _strict_read(hub, spokes, "DHCP_LIST_SUBNETS", "subnets")
            if kea_subnets is None:
                totals["errors"].append({"tenant": tid, "error": "no strict kea subnet read"})
        try:
            pfx_data, ips_data = await hub._netbox_prefixes_and_ips(filters, spoke=ipam)
        except Exception as e:  # noqa: BLE001
            totals["errors"].append({"tenant": tid, "error": f"netbox read: {e}"})
            continue
        read_key = hub._filters_key(filters)
        reads[read_key] = (pfx_data, ips_data)
        plan = plan_static_reservations(pfx_data, ips_data, leases, candidates, kea_subnets)
        totals["tenants"] += 1
        totals["skipped"] += len(plan["skipped"])
        # Step 3: log MAC vetoes; report conflicts, never resolve them automatically.
        for sk in plan["skipped"]:
            if sk["reason"] in ("malformed mac", "conflicting macs"):
                logger.warning("static reservations: %s skipped: %s", sk["ip"], sk["reason"])
        for c in plan["conflicts"]:
            logger.warning("static reservations: conflict %s (%s): %s",
                           c["ip"], c["mac"], c["reason"])
            totals["conflicts"].append({"tenant": tid, **c})
        # Step 4: write the reservations, capped per pass.
        for r in plan["reserve"]:
            # Over the cap: counted, and written by a later pass.
            if writes >= _MAX_WRITES_PER_PASS or not ipam:
                totals["deferred"] += 1
                continue
            if r.get("ip_id") is None:
                continue
            writes += 1
            # A write (even a failed one) may change NetBox: the sync re-reads.
            reads.pop(read_key, None)
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

    # Step 5: hand unchanged reads to the sync, refresh cached IPs and record the pass.
    hub._hand_over_netbox_reads(reads)
    if totals["reserved"]:
        hub.refresh_module_cache("netbox_ips")
    return hub._record_status("static_reservations",
                              status="error" if totals["errors"] else "ok", **totals)


def status_for_tenant(status: Dict[str, Any], tid: Optional[str]) -> Dict[str, Any]:
    """The ``static_reservations`` status as tenant ``tid`` may see it.

    The pass is fleet-wide, so its reserved/conflict/error lists name every
    tenant's IPs and MACs. A viewer sees only ``tid``'s entries; ``tid`` None
    or ``""`` (a global admin who has not switched into a tenant, or a user
    with no tenant) sees none. The fleet-wide counters are left out and
    ``status`` reflects only the viewer's own errors.
    """
    if not isinstance(status, dict):
        return status
    # Keep only this tenant's rows; drop counters that span tenants.
    out = {k: v for k, v in status.items() if k not in ("tenants", "skipped", "deferred")}
    for key in ("reserved", "conflicts", "errors"):
        out[key] = [r for r in status.get(key) or []
                    if isinstance(r, dict) and tid and same_tenant(r.get("tenant"), tid)]
    if out.get("status") in ("ok", "error"):
        out["status"] = "error" if out["errors"] else "ok"
    return out
