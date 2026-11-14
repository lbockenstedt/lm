"""Reserve statically addressed hosts in DHCP — the hub side.

A host with a static IP inside a Kea scope holds no lease, so Kea may hand
its address to another client. The netbox spoke finds such hosts and marks
their NetBox IP as a DHCP reservation (``NETBOX_RESERVE_STATIC_HOSTS``, see
the netbox repo's ``API_SPEC.md``); the NetBox → Kea sync that runs straight
after the pass pushes it to Kea.

The hub only does what the spoke cannot (fleet rule 3.1):

* **Policy** — ``global_config.static_ip_reservations`` ``{enabled: false,
  interval: 900}`` and the write cap.
* **Relay** — per tenant, the raw ``GET_HOST_ADDRESSING`` answers of its
  connected agents, the sweep's sightings joined with the latest live ARP
  MACs (with their ages), and a strict lease and subnet read of the tenant's
  Kea (its OWN Kea when it has one, else the shared Kea). Spokes cannot reach
  each other, so the hub carries these in one command per pass.
* **State** — the spoke's report (``changes`` with before/after,
  ``conflicts``, ``errors``, and what a rollback restored, left alone or
  could not undo) is stored as ``static_reservations`` in the
  DNS/DHCP sync status and cut to the viewer's tenant by
  ``status_for_tenant``.
* **Rollback trigger** — when the DHCP sync that follows a pass fails for a
  tenant's Kea scope, the hub asks the spoke to roll back that tenant's
  writes (``roll_back_if_sync_failed``); other tenants' writes stay.
* **Device replacement** — an IP NetBox reserves for old MAC A whose host
  now answers with new MAC B is a conflict the spoke can resolve by moving
  the reservation (and the interface MAC) to B. Automatically
  (``auto_replace``, on by default) it waits for two things the spoke cannot
  know, and the hub keeps them **in memory**, per tenant and IP:
  ``_static_res_watch`` (when B was first seen there, so B must show on
  passes 30 minutes apart) and ``_static_res_macs`` plus
  ``_static_res_agent_since`` (when A was last seen by the nw sweep/ARP or
  an agent, and since when both have watched without a gap). They go to the
  spoke as ``replace_watch`` ages; no tenant id leaves the hub. A restart
  (or the feature or a source going quiet) only restarts the wait, which
  errs on the safe side, so nothing is persisted. ``use_new_mac`` is the
  "Use new MAC" button: the same replacement for one IP now, without the
  waits.

An older netbox spoke answers "Unknown command": the pass records
``unsupported`` and writes nothing. An older agent answering "Unknown
command" for ``GET_HOST_ADDRESSING`` contributes no addresses; an agent that
errors or times out holds its tenant back for the pass.

This module is a **leaf**: stdlib plus sibling leaves only.

Audience: Hub developers.
"""

# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio bounds the agent polls.
import asyncio
# Standard-library logging for pass results.
import logging
# time stamps and throttles each pass.
import time
# Type hints only.
from typing import Any, Dict, List, Optional, Tuple

# Tenant scoping and spoke ownership.
from access import (netbox_tenant_scope, same_tenant, spoke_owner_tenant,
                    tenant_has_own_spoke, tenant_is_shared,
                    tenant_shared_fallback_blocked, unwrap_spoke)

# Use the hub's main logger so pass lines appear with other hub output.
logger = logging.getLogger("Hub")

# The netbox spoke command that plans and writes (and rolls back) a pass,
# and the "Use new MAC" button's one-IP replacement.
COMMAND = "NETBOX_RESERVE_STATIC_HOSTS"
REPLACE_COMMAND = "NETBOX_REPLACE_RESERVATION_MAC"
# global_config key and defaults.
_CFG_KEY = "static_ip_reservations"
_DEFAULT_INTERVAL = 900          # seconds between passes
# Bounds: concurrent agent polls, agent reply timeout, NetBox writes per pass,
# and how long the spoke may take to read NetBox and write.
_AGENT_CONCURRENCY = 8
_AGENT_TIMEOUT = 15.0
_MAX_WRITES_PER_PASS = 25
_SPOKE_TIMEOUT = 300.0
# Codes a peer may use for "I do not know this command".
_UNKNOWN_CODES = ("UNKNOWN_COMMAND", "UNSUPPORTED_COMMAND")
# Old-MAC watch: a sweep/ARP gap longer than this restarts the clock, and a
# sighting older than _SEEN_KEEP no longer matters (the spoke wants a day).
_ARP_GAP = 7200
_SEEN_KEEP = 2 * 86400
_TOO_OLD = "netbox spoke too old; update it"
# The spoke's conflict reason for an IP NetBox reserves for another MAC: the
# only conflict the "Use new MAC" button acts on.
_OTHER_MAC_REASON = "reserved for another mac"


def is_unknown_command(reply: Any) -> bool:
    """Whether ``reply`` is an older peer's "I do not know this command".

    Every fleet variant is an ERROR: ``{"message": "Unknown command: X"}``
    (netbox), ``{"error": "Unknown command: X"}`` (dhcp, dns, henet),
    ``"Unknown agent command 'X'"`` (agent), or a ``code`` of
    ``UNKNOWN_COMMAND`` / ``UNSUPPORTED_COMMAND``. Any other ERROR is a real
    failure.
    """
    if not isinstance(reply, dict) or str(reply.get("status", "")).upper() != "ERROR":
        return False
    if str(reply.get("code", "")).upper() in _UNKNOWN_CODES:
        return True
    text = f"{reply.get('message') or ''} {reply.get('error') or ''}".lower()
    return "unknown command" in text or "unknown agent command" in text


def _cfg(hub) -> Dict[str, Any]:
    """Read ``global_config.static_ip_reservations`` fresh, with defaults."""
    # "or {}" guards against a stored None.
    gc = hub.state.system_state.get("global_config", {}) or {}
    cfg = gc.get(_CFG_KEY, {}) or {}
    return {"enabled": bool(cfg.get("enabled", False)),
            "interval": int(cfg.get("interval", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL),
            "auto_replace": bool(cfg.get("auto_replace", True))}


def _mac_key(value: Any) -> str:
    """``value`` as ``aa:bb:cc:dd:ee:ff``, or "" when it is not a MAC."""
    hexd = "".join(ch for ch in str(value or "").lower() if ch in "0123456789abcdef")
    return ":".join(hexd[i:i + 2] for i in range(0, 12, 2)) if len(hexd) == 12 else ""


def note_mac_sightings(hub, macs: Any, complete: bool, now: Optional[float] = None) -> None:
    """Remember every MAC one nw discovery cycle saw (ARP and MAC tables).

    ``complete`` is False when any device or spoke failed to answer: a MAC
    behind it could not be seen, so the watch restarts (``since`` None) and
    no old MAC counts as unseen until a full cycle comes back. A gap of more
    than ``_ARP_GAP`` between full cycles restarts it too.
    """
    now = time.time() if now is None else now
    st = getattr(hub, "_static_res_macs", None) or {"since": None, "at": 0.0, "seen": {}}
    if not complete or now - st["at"] > _ARP_GAP:
        st["since"] = None
    if complete:
        st["at"] = now
        if st["since"] is None:
            st["since"] = now
    for mac in macs or []:
        key = _mac_key(mac)
        if key:
            st["seen"][key] = now
    st["seen"] = {m: t for m, t in st["seen"].items() if now - t <= _SEEN_KEEP}
    hub._static_res_macs = st


def _old_unseen_age(hub, tid: str, old_mac: str, now: float) -> Optional[float]:
    """How long ``old_mac`` has gone unseen by every source of ``tid``, or
    None when some source cannot vouch: the sweep/ARP watch has a gap or
    this tenant has no fresh ARP map, or its agents have not answered every
    pass since the watch began."""
    st = getattr(hub, "_static_res_macs", None) or {}
    arp = (getattr(hub, "_nw_live_arp", None) or {}).get(tid) or {}
    agent_since = (getattr(hub, "_static_res_agent_since", None) or {}).get(tid)
    if st.get("since") is None or now - float(st.get("at") or 0) > _ARP_GAP \
            or now - float(arp.get("at") or 0) > _ARP_GAP or agent_since is None:
        return None
    last = max(float((st.get("seen") or {}).get(_mac_key(old_mac)) or 0),
               float(st["since"]), float(agent_since))
    return max(0.0, now - last)


def _sweep_rows(hub, tid: str, now: float) -> List[Dict[str, Any]]:
    """Sweep sightings of ``tid`` that have a live-ARP MAC, with their ages.

    ``nw_seen_hosts`` (when the sweep last saw each IP answer) and
    ``_nw_live_arp`` (the latest nw discovery ARP map) are hub state; the
    spoke decides what is fresh enough.
    """
    arp = (getattr(hub, "_nw_live_arp", None) or {}).get(tid) or {}
    macs = arp.get("macs") or {}
    arp_age = now - float(arp.get("at") or 0)
    gc = hub.state.system_state.get("global_config", {}) or {}
    seen = ((gc.get("nw_seen_hosts") or {}).get(tid)) or {}
    return [{"ip": ip, "mac": macs[ip], "arp_age": arp_age,
             "seen_age": now - float((entry or {}).get("last_seen") or 0)}
            for ip, entry in seen.items() if macs.get(ip)]


def _offline_agent_tenants(hub) -> set:
    """Tenants with an approved, bound agent that is not connected now: it
    cannot say whether it saw the old MAC, so they cannot vouch for it being
    gone. Read from the persisted registry (``get_all_spokes_by_type`` lists
    only connected spokes)."""
    active = getattr(hub, "active_connections", None) or {}
    approved = getattr(hub, "approved_modules", None) or {}
    meta = hub.state.system_state.get("module_metadata", {}) or {}
    return {tid for sid, m in meta.items()
            if isinstance(m, dict) and m.get("module_type") == "agent"
            and approved.get(sid) and sid not in active
            and (tid := spoke_owner_tenant(hub, sid))}


async def _agent_addresses(hub, only_tid: Optional[str] = None
                           ) -> Tuple[Dict[str, List[Dict[str, Any]]], set, set]:
    """``({tid: [address rows]}, failed_tids, older_tids)`` from connected agents bound to
    a tenant (only ``only_tid``'s when given).

    Unbound agents are skipped (their hosts have no owning tenant). Polls
    run at most ``_AGENT_CONCURRENCY`` at a time. An older agent
    (``is_unknown_command``) contributes nothing, like a host with no agent,
    and puts its tenant in ``older_tids`` (it cannot vouch that an old MAC
    is gone).
    An agent that errors or times out puts its tenant in ``failed_tids``: it
    might have said ``dhcp`` for an address the sweep saw, so the tenant
    waits for a pass where every agent answered.
    """
    # Connected agents with an owning tenant.
    active = getattr(hub, "active_connections", None)
    agents = []
    for sid in hub.get_all_spokes_by_type("agent") or []:
        if active is not None and sid not in active:
            continue
        tid = spoke_owner_tenant(hub, sid)
        if tid and (only_tid is None or same_tenant(tid, only_tid)):
            agents.append((sid, tid))
    sem = asyncio.Semaphore(_AGENT_CONCURRENCY)

    async def _poll(sid: str) -> Any:
        """One agent's address rows; "older" for an older agent, None on failure."""
        async with sem:
            try:
                reply = unwrap_spoke(await hub.request_response(
                    sid, "GET_HOST_ADDRESSING", {}, timeout=_AGENT_TIMEOUT))
            except Exception as e:  # noqa: BLE001
                logger.debug("static reservations: agent poll failed: %s", e)
                return None
        if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
            return [a for a in reply.get("addresses") or [] if isinstance(a, dict)]
        if is_unknown_command(reply):
            return "older"
        return None

    # Poll and group by tenant.
    results = await asyncio.gather(*[_poll(sid) for sid, _ in agents])
    out: Dict[str, List[Dict[str, Any]]] = {}
    failed, older = set(), set()
    for (_sid, tid), rows in zip(agents, results):
        if rows is None:
            failed.add(tid)
            continue
        if rows == "older":
            older.add(tid)
            rows = []
        out.setdefault(tid, []).extend(
            {"ip": a.get("ip"), "mac": a.get("mac"), "mode": a.get("mode")} for a in rows)
    return out, failed, older


async def _strict_read(hub, spokes: List[str], command: str,
                      key: str) -> Optional[List[Dict[str, Any]]]:
    """Every ``key`` row (leases or subnets) from ``spokes``, or None unless
    EVERY spoke answered a strict read (old spokes, Kea errors and HA member
    errors all → None)."""
    if not spokes:
        return None
    replies = await asyncio.gather(*[
        hub.request_response(sid, command, {"strict": True}, timeout=30.0)
        for sid in spokes], return_exceptions=True)
    rows: List[Dict[str, Any]] = []
    for raw in replies:
        reply = None if isinstance(raw, BaseException) else unwrap_spoke(raw)
        # Anything short of a clean strict answer makes the Kea view untrustworthy.
        if not isinstance(reply, dict) or reply.get("status") != "SUCCESS" \
                or reply.get("strict") is not True or reply.get("member_errors") \
                or not isinstance(reply.get(key), list):
            logger.warning("static reservations: no strict %s; tenant skipped", command)
            return None
        rows.extend(x for x in reply[key] if isinstance(x, dict))
    return rows


def _tenant_kea_spokes(hub, tid: str, key: str,
                       groups: Dict[str, Any]) -> Tuple[str, List[str]]:
    """``(sync scope key, Kea spokes)`` serving ``tid``: its OWN Kea when it
    has one (even if offline → none), else the shared/unbound Kea (fleet "own
    instance beats shared" rule, ``tenant_shared_fallback_blocked``)."""
    own = list((groups.get("tenant:" + key) or ({}, []))[1])
    if own:
        return "tenant:" + key, own
    if tenant_shared_fallback_blocked(hub, tid, "dhcp"):
        return "", []
    return "", list((groups.get("") or ({}, []))[1])


def _record(hub, **fields) -> Dict[str, Any]:
    """Store ``fields`` as the ``static_reservations`` status."""
    return hub._record_status("static_reservations", **fields)


async def reserve_static_hosts_once(hub, now: Optional[float] = None, force: bool = False,
                                    sync_enabled: bool = True) -> Dict[str, Any]:
    """One pass, throttled to ``interval`` unless ``force``.

    Off (the switch, or the DNS/DHCP sync it rides on) records ``disabled``
    with the reason, so the status never shows an old pass as current, and
    drops the replacement watch: the agents are not polled while off.
    """
    now = time.time() if now is None else now
    cfg = _cfg(hub)
    if not cfg["enabled"] or not sync_enabled:
        hub._static_res_pending = None
        hub._static_res_watch = {}
        hub._static_res_agent_since = {}
        return _record(hub, status="disabled",
                       reason="turned off" if not cfg["enabled"] else "dns/dhcp sync is off")
    if not force and now - float(getattr(hub, "_static_res_last", 0) or 0) < cfg["interval"]:
        return {"status": "throttled"}
    # Stamp the throttle only once the pass completed, so a pass that raised
    # is retried on the next tick.
    result = await _run_pass(hub, now, cfg["auto_replace"])
    hub._static_res_last = now
    return result


async def _tenant_entry(hub, tid: str, rows: List[Dict[str, Any]], now: float,
                        groups: Dict[str, Any], kea: Dict[str, Any],
                        kea_keys: Dict[Tuple[str, ...], Optional[str]], ref: str
                        ) -> Tuple[Optional[Dict[str, Any]], str, Optional[str], str]:
    """The spoke's entry for tenant ``tid``: ``(entry, Kea scope key, error,
    skip reason)``.

    ``entry`` is None when the tenant is skipped, with ``error`` saying why
    when the status should show it and the skip reason always (for the log). Each Kea is read once per pass: ``kea``
    collects the reads under short keys, ``kea_keys`` maps Kea spokes to them.
    """
    sweep = _sweep_rows(hub, tid, now)
    if not rows and not sweep:
        return None, "", None, "no agent or sweep rows"
    # The tenant's NetBox scope; no mapping → never touch it.
    scope = netbox_tenant_scope(hub, tid)
    filters = {k: scope[k] for k in ("tenant", "tenant_group") if scope.get(k)}
    if not filters:
        return None, "", None, "no netbox scope mapping"
    skey, spokes = _tenant_kea_spokes(hub, tid, str(scope.get("key")), groups)
    if not spokes:
        return None, "", ("own kea not connected"
                          if tenant_has_own_spoke(hub, tid, "dhcp") else None), "no kea"
    ck = tuple(sorted(spokes))
    if ck not in kea_keys:
        leases = await _strict_read(hub, spokes, "DHCP_LIST_LEASES", "leases")
        subnets = (await _strict_read(hub, spokes, "DHCP_LIST_SUBNETS", "subnets")
                   if leases is not None else None)
        kea_keys[ck] = None if subnets is None else f"k{len(kea)}"
        if kea_keys[ck]:
            kea[kea_keys[ck]] = {"leases": leases, "subnets": subnets}
    if kea_keys[ck] is None:
        return None, "", "no strict kea read", "no strict kea read"
    return ({"ref": ref, "filters": filters, "agent_addresses": rows, "sweep": sweep,
             "kea": kea_keys[ck]}, skey, None, "")


def _replace_watch(hub, tid: str, now: float) -> List[Dict[str, Any]]:
    """The hub's view of ``tid``'s pending replacements, as ages for the spoke."""
    watch = (getattr(hub, "_static_res_watch", None) or {}).get(tid) or {}
    return [{"ip": ip, "old_mac": w["old_mac"], "new_mac": w["new_mac"],
             "first_seen_age": max(0.0, now - w["first_seen"]),
             "old_unseen_age": _old_unseen_age(hub, tid, w["old_mac"], now)}
            for ip, w in sorted(watch.items())]


def _update_watch(hub, pending: List[Dict[str, Any]], now: float) -> None:
    """Rebuild the watch from this pass's ``pending_replace`` rows (tenant
    ids already mapped). A row keeps its first sighting only while both MACs
    stay the same; an IP no longer pending is dropped."""
    old = getattr(hub, "_static_res_watch", None) or {}
    new: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for p in pending:
        tid, ip = p.get("tenant"), str(p.get("ip") or "")
        o, n = _mac_key(p.get("old_mac")), _mac_key(p.get("new_mac"))
        if not tid or not ip or not o or not n:
            continue
        prev = (old.get(tid) or {}).get(ip) or {}
        first = prev["first_seen"] if (prev.get("old_mac"), prev.get("new_mac")) == (o, n) \
            else now
        new.setdefault(tid, {})[ip] = {"old_mac": o, "new_mac": n, "first_seen": first}
        p["first_seen_age"] = max(0.0, now - first)
    hub._static_res_watch = new


async def _run_pass(hub, now: float, auto_replace: bool = True) -> Dict[str, Any]:
    """Gather each tenant's inputs, send them to the netbox spoke, store its report."""
    hub._static_res_pending = None
    hub._dhcp_delivered = None
    agents, failed_tids, older_tids = await _agent_addresses(hub)
    errors: List[Dict[str, Any]] = [
        {"tenant": t, "error": "agent poll failed; tenant waits"}
        for t in sorted(failed_tids) if not tenant_is_shared(t)]
    # Agents vouch for a tenant only while every poll answers.
    since = getattr(hub, "_static_res_agent_since", None) or {}
    # Agents that failed, are not connected or cannot report MACs at all.
    quiet = failed_tids | older_tids | _offline_agent_tenants(hub)
    for tid in quiet:
        since.pop(tid, None)
    tids = set(agents) | set(getattr(hub, "_nw_live_arp", None) or {})
    for tid in tids - quiet:
        since.setdefault(tid, now)
    hub._static_res_agent_since = since
    seen = (getattr(hub, "_static_res_macs", None) or {}).get("seen")
    if seen is not None:
        for rows in agents.values():
            for a in rows:
                key = _mac_key(a.get("mac"))
                if key:
                    seen[key] = now

    # Step 1: one entry per tenant with candidates; each Kea read once.
    groups, _skipped = hub._scope_groups(hub._get_dhcp_spokes())
    tenants: List[Dict[str, Any]] = []
    refs: Dict[str, str] = {}
    scopes: Dict[str, str] = {}
    kea: Dict[str, Any] = {}
    kea_keys: Dict[Tuple[str, ...], Optional[str]] = {}
    left_out: Dict[str, int] = {}
    # A tenant whose only agent failed is in failed_tids, not tids.
    for tid in sorted(t for t in tids | failed_tids if t):
        if tid in failed_tids or tenant_is_shared(tid):
            why = "shared tenant" if tenant_is_shared(tid) else "agent poll failed"
            left_out[why] = left_out.get(why, 0) + 1
            continue
        ref = str(len(tenants))
        entry, skey, err, why = await _tenant_entry(hub, tid, agents.get(tid, []), now,
                                                    groups, kea, kea_keys, ref)
        if err:
            errors.append({"tenant": tid, "error": err})
        if entry is None:
            left_out[why] = left_out.get(why, 0) + 1
            continue
        if auto_replace:
            entry["replace_watch"] = _replace_watch(hub, tid, now)
        refs[ref] = tid
        scopes[ref] = skey
        tenants.append(entry)
    if not tenants:
        # Nothing is pending now: the waits restart when a tenant returns.
        hub._static_res_watch = {}
        logger.info("static reservations: no tenant to check; %s",
                    _breakdown(left_out) or "no tenant has agent or sweep data")
        return _record(hub, status=_pass_status([], errors, []), clean=[], reserved=[],
                       conflicts=[], errors=errors, tenants=0, skipped=0,
                       skipped_reasons={}, deferred=0, auto_replace=auto_replace)

    # Step 2: the spoke plans and writes. Reads and writes go to the IPAM
    # spoke the sync reads first, so a reservation lands where the sync looks.
    ipam = next(iter(hub._ipam_spoke_candidates()), None)
    if not ipam:
        errors.append({"tenant": None, "error": "netbox spoke not connected"})
        return _record(hub, status="error", clean=[], reserved=[], conflicts=[],
                       errors=errors, tenants=0, skipped=0, skipped_reasons={}, deferred=0,
                       auto_replace=auto_replace)
    try:
        reply = unwrap_spoke(await hub.request_response(
            ipam, COMMAND, {"tenants": tenants, "kea": kea, "auto_replace": auto_replace,
                            "max_writes": _MAX_WRITES_PER_PASS}, timeout=_SPOKE_TIMEOUT))
    except Exception as e:  # noqa: BLE001
        reply = {"status": "ERROR", "message": str(e) or type(e).__name__}
    if is_unknown_command(reply):
        logger.warning("static reservations: the netbox spoke is too old for %s", COMMAND)
        hub._static_res_watch = {}
        return _record(hub, status="unsupported", clean=[], reserved=[], conflicts=[],
                       errors=[{"tenant": None, "error": _TOO_OLD}],
                       tenants=0, skipped=0, skipped_reasons={}, deferred=0,
                       replace_supported=False)
    if not isinstance(reply, dict) or not isinstance(reply.get("changes"), list):
        msg = (reply or {}).get("message") if isinstance(reply, dict) else None
        errors.append({"tenant": None, "error": f"netbox spoke: {msg or 'no report'}"})
        hub._static_res_watch = {}
        return _record(hub, status="error", clean=[], reserved=[], conflicts=[],
                       errors=errors, tenants=0, skipped=0, skipped_reasons={}, deferred=0,
                       auto_replace=auto_replace)

    # Step 3: map the spoke's opaque refs back to tenants and store the report.
    def _rows(key: str) -> List[Dict[str, Any]]:
        """The spoke's ``key`` rows with ``ref`` replaced by the tenant id."""
        return _tenant_rows(reply.get(key), refs, key)

    # A spoke without device replacement sends no "replaced" list.
    supported = isinstance(reply.get("replaced"), list)
    reserved, conflicts = _rows("changes"), _rows("conflicts")
    replaced, pending = _rows("replaced"), _rows("pending_replace")
    errors += _rows("errors")
    _update_watch(hub, pending, now)
    for p in pending:
        # No source can vouch that the old MAC is gone: this one waits for
        # the button, not the clock.
        p["old_mac_unconfirmed"] = _old_unseen_age(
            hub, str(p.get("tenant") or ""), _mac_key(p.get("old_mac")), now) is None
    evaluated = {refs[str(r)] for r in reply.get("evaluated") or [] if str(r) in refs}
    clean = sorted(evaluated - {e.get("tenant") for e in errors})
    if reserved or replaced or reply.get("rolled_back"):
        hub.refresh_module_cache("netbox_ips")
    raw = [c for k in ("changes", "replaced") for c in reply.get(k) or []
           if isinstance(c, dict)]
    if raw:
        # The raw rows (opaque refs, no tenant ids) for a later rollback.
        hub._static_res_pending = {"ipam": ipam, "refs": refs, "scopes": scopes,
                                   "changes": raw}
    # An older netbox spoke sends no skipped_reasons.
    skipped_reasons = _counts(reply.get("skipped_reasons"))
    by_ref = reply.get("skipped_by_ref")
    skipped_by_tenant = _tenant_rows(
        [{"ref": r, "reasons": _counts(c)} for r, c in by_ref.items()]
        if isinstance(by_ref, dict) else [], refs, "skipped_by_ref")
    logger.info("static reservations: %d reserved, %d replaced, %d conflicts, %d errors%s",
                len(reserved), len(replaced), len(conflicts), len(errors),
                f"; skipped: {_breakdown(skipped_reasons)}" if skipped_reasons else "")
    return _record(hub, status=_pass_status(clean, errors, conflicts), clean=clean,
                   reserved=reserved, replaced=replaced, pending_replace=pending,
                   conflicts=conflicts, errors=errors,
                   rolled_back=_rows("rolled_back"), rollback_kept=_rows("rollback_kept"),
                   rollback_failed=_rows("rollback_failed"),
                   tenants=len(evaluated), skipped=int(reply.get("skipped") or 0),
                   skipped_reasons=skipped_reasons, skipped_by_tenant=skipped_by_tenant,
                   deferred=int(reply.get("deferred") or 0),
                   auto_replace=auto_replace, replace_supported=supported)


async def use_new_mac(hub, tid: str, ip: str, old_mac: str, new_mac: str,
                      now: Optional[float] = None) -> Dict[str, Any]:
    """The "Use new MAC" button: move ``ip``'s reservation in tenant ``tid``
    from ``old_mac`` to ``new_mac`` now.

    Only for a "different MAC at this IP" conflict the last pass showed this
    tenant. The spoke (``REPLACE_COMMAND``) skips the automatic waits but
    keeps every other check and the compare-and-set, with fresh agent, sweep
    and Kea inputs. A DHCP sync that starts after it and fails for the
    tenant's Kea scope rolls it back, like a pass.

    Returns ``{"status": "ok", "replaced": row}``, ``{"status":
    "unsupported", "error"}`` (an older netbox spoke) or ``{"status":
    "error", "error"}``.
    """
    fixed_now, now = now is not None, time.time() if now is None else now
    old, new = _mac_key(old_mac), _mac_key(new_mac)
    if not _cfg(hub)["enabled"]:
        return {"status": "error", "error": "static host reservations are off"}
    if not hub._dds_cfg().get("enabled"):
        return {"status": "error", "error": "dns/dhcp sync is off"}
    st = (getattr(hub, "dns_dhcp_sync_status", None) or {}).get("static_reservations") or {}
    if st.get("replace_supported") is False:
        return {"status": "unsupported", "error": _TOO_OLD}
    if not tid or tenant_is_shared(tid) or not old or not new or old == new or not any(
            isinstance(c, dict) and c.get("tenant") is not None
            and same_tenant(c.get("tenant"), tid) and c.get("ip") == ip
            and c.get("reason") == _OTHER_MAC_REASON and _mac_key(c.get("old_mac")) == old and _mac_key(c.get("mac")) == new
            for c in st.get("conflicts") or []):
        return {"status": "error", "error": "the last pass shows no such conflict; refresh"}

    # Fresh inputs for this one tenant.
    agents, failed, _older = await _agent_addresses(hub, only_tid=tid)
    if failed:
        return {"status": "error", "error": "an agent did not answer; try again"}
    groups, _skipped = hub._scope_groups(hub._get_dhcp_spokes())
    kea: Dict[str, Any] = {}
    rows = [r for t, rs in agents.items() for r in rs]
    entry, skey, err, _why = await _tenant_entry(hub, tid, rows, now, groups, kea, {}, "m")
    if entry is None:
        return {"status": "error", "error": err or "no source sees this tenant's hosts now"}
    ipam = next(iter(hub._ipam_spoke_candidates()), None)
    if not ipam:
        return {"status": "error", "error": "netbox spoke not connected"}

    # The spoke checks and writes.
    try:
        reply = unwrap_spoke(await hub.request_response(
            ipam, REPLACE_COMMAND, {"tenants": [entry], "kea": kea, "ip": ip,
                                    "old_mac": old, "new_mac": new}, timeout=_SPOKE_TIMEOUT))
    except Exception as e:  # noqa: BLE001
        reply = {"status": "ERROR", "message": str(e) or type(e).__name__}
    if is_unknown_command(reply):
        return {"status": "unsupported", "error": _TOO_OLD}
    if isinstance(reply, dict) and (reply.get("replaced") or reply.get("rolled_back")
                                    or reply.get("rollback_kept")
                                    or reply.get("rollback_failed")):
        hub.refresh_module_cache("netbox_ips")
    mine = lambda r: (isinstance(r, dict) and r.get("ip") == ip  # noqa: E731
                      and r.get("tenant") is not None and same_tenant(r.get("tenant"), tid))
    rows = [r for r in (reply.get("replaced") if isinstance(reply, dict) else None) or []
            if isinstance(r, dict) and r.get("ip") == ip]
    # Only a row the rollback can use: this request's ref, its NetBox id and
    # both field sets.
    done = [r for r in rows if r.get("ref") == "m" and r.get("ip_id") is not None
            and isinstance(r.get("before"), dict) and isinstance(r.get("after"), dict)]
    if rows and not done:
        logger.warning("static reservations: unusable replaced row for %s from the netbox spoke", ip)
        return {"status": "error", "error": "the netbox spoke sent an unusable report; "
                                            "check this address in NetBox"}
    if not done or reply.get("status") != "SUCCESS":
        msg = reply.get("message") if isinstance(reply, dict) else None
        return {"status": "error", "error": msg or "the netbox spoke sent no report"}

    # Keep it for the rollback and show it on the card. A repeat after a
    # lost reply (``already``) comes back as the same row. Only a DHCP sync
    # that starts after the write is done can judge it.
    change = done[0]
    manual = getattr(hub, "_static_res_manual", None) or []
    manual.append({"ipam": ipam, "tid": tid, "scope": skey, "change": change,
                   "at": now if fixed_now else time.time()})
    hub._static_res_manual = manual
    ((getattr(hub, "_static_res_watch", None) or {}).get(tid) or {}).pop(ip, None)
    row = _tenant_rows([change], {"m": tid}, "replaced")[0]
    # Re-read: a pass may have stored a newer report during the spoke call.
    st = (getattr(hub, "dns_dhcp_sync_status", None) or {}).get("static_reservations") or {}
    st = dict(st, replaced=list(st.get("replaced") or []) + [row],
              conflicts=[c for c in st.get("conflicts") or [] if not mine(c)],
              pending_replace=[p for p in st.get("pending_replace") or [] if not mine(p)])
    hub.dns_dhcp_sync_status["static_reservations"] = st
    logger.info("static reservations: %s moved to a new mac by hand", ip)
    return {"status": "ok", "replaced": row}


def _tenant_rows(rows: Any, refs: Dict[str, str], key: str) -> List[Dict[str, Any]]:
    """The spoke's ``rows`` with their opaque ``ref`` swapped for the tenant id.

    A row naming a ref this pass never sent belongs to no known tenant: an
    error becomes a pass-wide row that names no IP, anything else is dropped,
    so a confused spoke can never show one tenant's IPs to another.
    """
    out = []
    for r in rows or []:
        if not isinstance(r, dict):
            continue
        tid = refs.get(str(r.get("ref")))
        if tid is None:
            logger.warning("static reservations: netbox spoke sent a %s row for an "
                           "unknown ref", key)
            if key == "errors":
                out.append({"tenant": None, "error": "netbox spoke reported an "
                                                     "error for an unknown tenant"})
            continue
        # The ref decides the tenant; a "tenant" key from the spoke never does.
        out.append({**{k: v for k, v in r.items() if k not in ("ref", "tenant")},
                    "tenant": tid})
    return out


async def roll_back_if_sync_failed(hub) -> Optional[Dict[str, Any]]:
    """Undo the writes whose tenant's DHCP sync failed.

    Runs after the DHCP sync that follows a pass. A change whose tenant's Kea
    scope is not in ``hub._dhcp_delivered`` (its NetBox fetch or Kea push
    failed, its Kea vanished, or the sync raised) would otherwise sit in
    NetBox but not in Kea; changes whose scope was delivered stay. The same
    goes for a "Use new MAC" replacement, judged by the first sync that
    started after it (``hub._dhcp_delivered_at``). The spoke restores each
    IP's ``before`` only where NetBox still holds ``after``; an IP edited
    since is left alone (``rollback_kept``). The rollback carries only
    opaque refs, never tenant ids.
    Returns the updated status, or None when there was nothing to undo.
    """
    delivered = getattr(hub, "_dhcp_delivered", None)
    if delivered is None:
        return None
    out = None
    # Button replacements that a whole sync has run after.
    started = getattr(hub, "_dhcp_delivered_at", None)
    manual = getattr(hub, "_static_res_manual", None) or []
    if manual and started is not None:
        hub._static_res_manual = [m for m in manual if m["at"] >= started]
        for m in manual:
            if m["at"] < started and m["scope"] not in delivered:
                out = await _undo(hub, m["ipam"], {"m": m["tid"]}, [m["change"]])
    # The last pass's writes; act once.
    pending = getattr(hub, "_static_res_pending", None)
    if not pending:
        return out
    hub._static_res_pending = None
    changes = [c for c in pending["changes"]
               if pending["scopes"].get(str(c.get("ref"))) not in delivered]
    if changes:
        out = await _undo(hub, pending["ipam"], pending["refs"], changes)
    return out


async def _undo(hub, ipam: str, refs: Dict[str, str],
                changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Ask spoke ``ipam`` to roll ``changes`` back and fold the outcome into
    the stored status, per tenant (``refs`` maps their refs to tenants)."""
    try:
        reply = unwrap_spoke(await hub.request_response(
            ipam, COMMAND, {"rollback": changes}, timeout=_SPOKE_TIMEOUT))
    except Exception as e:  # noqa: BLE001
        reply = {"status": "ERROR", "message": str(e) or type(e).__name__}
    if isinstance(reply, dict) and isinstance(reply.get("rolled_back"), list):
        done = reply["rolled_back"]
        kept = reply.get("rollback_kept") or []
        failed = reply.get("rollback_failed") or []
    else:
        why = (reply or {}).get("message") if isinstance(reply, dict) else None
        done, kept = [], []
        failed = [{**c, "error": why or "no rollback report"} for c in changes]
    logger.warning("static reservations: dhcp sync failed; rolled back %d, %d left",
                   len(done), len(kept) + len(failed))
    hub.refresh_module_cache("netbox_ips")

    # Fold the outcome into the stored status, per tenant.
    done, kept, failed = (_tenant_rows(done, refs, "rolled_back"),
                          _tenant_rows(kept, refs, "rollback_kept"),
                          _tenant_rows(failed, refs, "rollback_failed"))
    st = dict((hub.dns_dhcp_sync_status or {}).get("static_reservations") or {})
    errors = list(st.get("errors") or [])
    errors += [{"tenant": c["tenant"], "ip": c.get("ip"),
                "error": "dhcp sync failed; reservation rolled back"} for c in done]
    errors += [{"tenant": c["tenant"], "ip": c.get("ip"),
                "error": f"dhcp sync failed; left in place: {c.get('reason')}"} for c in kept]
    errors += [{"tenant": c["tenant"], "ip": c.get("ip"),
                "error": f"dhcp sync failed; rollback failed: {c.get('error')}"} for c in failed]
    undone = {(refs.get(str(c.get("ref"))), c.get("ip_id")) for c in changes}
    for key in ("reserved", "replaced"):
        if key in st:
            st[key] = [r for r in st.get(key) or []
                       if (r.get("tenant"), r.get("ip_id")) not in undone]
    st.update(status=_pass_status(st.get("clean"), errors, st.get("conflicts")),
              errors=errors,
              # Add to any rows an earlier rollback in this status left.
              rolled_back=list(st.get("rolled_back") or []) + done,
              rollback_kept=list(st.get("rollback_kept") or []) + kept,
              rollback_failed=list(st.get("rollback_failed") or []) + failed)
    hub.dns_dhcp_sync_status["static_reservations"] = st
    return st


def _counts(raw: Any) -> Dict[str, int]:
    """The spoke's ``{reason: count}``, keeping only integer counts."""
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, int) and not isinstance(v, bool)}


def _breakdown(counts: Dict[str, Any]) -> str:
    """``counts`` as ``"reason=n, ..."``, largest first."""
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def _pass_status(clean, errors, conflicts) -> str:
    """``error`` beats ``conflicts`` beats ``ok`` (some tenant evaluated
    cleanly); ``skipped`` when nothing was evaluated."""
    if errors:
        return "error"
    if conflicts:
        return "conflicts"
    return "ok" if clean else "skipped"


def status_for_tenant(status: Dict[str, Any], tid: Optional[str]) -> Dict[str, Any]:
    """The ``static_reservations`` status as tenant ``tid`` may see it.

    The pass is fleet-wide, so its rows name every tenant's IPs and MACs. A
    viewer sees only ``tid``'s rows; ``tid`` None or ``""`` sees none, only
    the pass-wide ``status`` word. Fleet-wide counters and the clean-tenant
    list are dropped; ``skipped_reasons`` becomes ``tid``'s own per-reason
    skip counts (``{}`` with no ``tid``). A tenant's ``status`` is its own: ``error`` with its
    own errors, else ``conflicts`` with its own conflicts, ``ok`` when it was
    evaluated cleanly, else ``skipped``. Pass-wide rows with no tenant (the
    netbox spoke unreachable or too old) are kept for everyone, since they
    name no tenant.
    """
    if not isinstance(status, dict):
        return status
    out = {k: v for k, v in status.items()
           if k not in ("tenants", "skipped", "deferred", "clean", "skipped_reasons",
                        "skipped_by_tenant")}
    def _visible(key: str, row: Any) -> bool:
        """A row is shown to its own tenant; a pass-wide error to everyone."""
        if not isinstance(row, dict):
            return False
        if row.get("tenant") is None:
            return key == "errors"
        return bool(tid) and same_tenant(row.get("tenant"), tid)

    for key in ("reserved", "replaced", "pending_replace", "conflicts", "errors",
                "rolled_back", "rollback_kept", "rollback_failed"):
        if key in status:
            out[key] = [r for r in status.get(key) or [] if _visible(key, r)]
    if "skipped_reasons" in status:
        out["skipped_reasons"] = {}
        for row in status.get("skipped_by_tenant") or []:
            if tid and isinstance(row, dict) and same_tenant(row.get("tenant"), tid):
                for k, v in (row.get("reasons") or {}).items():
                    out["skipped_reasons"][k] = out["skipped_reasons"].get(k, 0) + v
    if tid and out.get("status") in ("ok", "error", "conflicts", "skipped"):
        if out.get("errors"):
            out["status"] = "error"
        elif out.get("conflicts"):
            out["status"] = "conflicts"
        elif any(same_tenant(t, tid) for t in status.get("clean") or []):
            out["status"] = "ok"
        else:
            out["status"] = "skipped"
    return out
