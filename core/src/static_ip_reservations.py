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

# The netbox spoke command that plans and writes (and rolls back) a pass.
COMMAND = "NETBOX_RESERVE_STATIC_HOSTS"
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
            "interval": int(cfg.get("interval", _DEFAULT_INTERVAL) or _DEFAULT_INTERVAL)}


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


async def _agent_addresses(hub) -> Tuple[Dict[str, List[Dict[str, Any]]], set]:
    """``({tid: [address rows]}, failed_tids)`` from connected agents bound to
    a tenant.

    Unbound agents are skipped (their hosts have no owning tenant). Polls
    run at most ``_AGENT_CONCURRENCY`` at a time. An older agent
    (``is_unknown_command``) contributes nothing, like a host with no agent.
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
        if tid:
            agents.append((sid, tid))
    sem = asyncio.Semaphore(_AGENT_CONCURRENCY)

    async def _poll(sid: str) -> Optional[List[Dict[str, Any]]]:
        """One agent's address rows; [] for an older agent, None on failure."""
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
            return []
        return None

    # Poll and group by tenant.
    results = await asyncio.gather(*[_poll(sid) for sid, _ in agents])
    out: Dict[str, List[Dict[str, Any]]] = {}
    failed = set()
    for (_sid, tid), rows in zip(agents, results):
        if rows is None:
            failed.add(tid)
            continue
        out.setdefault(tid, []).extend(
            {"ip": a.get("ip"), "mac": a.get("mac"), "mode": a.get("mode")} for a in rows)
    return out, failed


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
    with the reason, so the status never shows an old pass as current.
    """
    now = time.time() if now is None else now
    cfg = _cfg(hub)
    if not cfg["enabled"] or not sync_enabled:
        hub._static_res_pending = None
        return _record(hub, status="disabled",
                       reason="turned off" if not cfg["enabled"] else "dns/dhcp sync is off")
    if not force and now - float(getattr(hub, "_static_res_last", 0) or 0) < cfg["interval"]:
        return {"status": "throttled"}
    # Stamp the throttle only once the pass completed, so a pass that raised
    # is retried on the next tick.
    result = await _run_pass(hub, now)
    hub._static_res_last = now
    return result


async def _run_pass(hub, now: float) -> Dict[str, Any]:
    """Gather each tenant's inputs, send them to the netbox spoke, store its report."""
    hub._static_res_pending = None
    hub._dhcp_delivered = None
    agents, failed_tids = await _agent_addresses(hub)
    errors: List[Dict[str, Any]] = [
        {"tenant": t, "error": "agent poll failed; tenant waits"}
        for t in sorted(failed_tids) if not tenant_is_shared(t)]

    # Step 1: one entry per tenant with candidates; each Kea read once.
    groups, _skipped = hub._scope_groups(hub._get_dhcp_spokes())
    tenants: List[Dict[str, Any]] = []
    refs: Dict[str, str] = {}
    scopes: Dict[str, str] = {}
    kea: Dict[str, Any] = {}
    kea_keys: Dict[Tuple[str, ...], Optional[str]] = {}
    tids = set(agents) | set(getattr(hub, "_nw_live_arp", None) or {})
    for tid in sorted(t for t in tids if t):
        if tid in failed_tids or tenant_is_shared(tid):
            continue
        sweep = _sweep_rows(hub, tid, now)
        if not agents.get(tid) and not sweep:
            continue
        # The tenant's NetBox scope; no mapping → never touch it.
        scope = netbox_tenant_scope(hub, tid)
        filters = {k: scope[k] for k in ("tenant", "tenant_group") if scope.get(k)}
        if not filters:
            continue
        skey, spokes = _tenant_kea_spokes(hub, tid, str(scope.get("key")), groups)
        if not spokes:
            if tenant_has_own_spoke(hub, tid, "dhcp"):
                errors.append({"tenant": tid, "error": "own kea not connected"})
            continue
        ck = tuple(sorted(spokes))
        if ck not in kea_keys:
            leases = await _strict_read(hub, spokes, "DHCP_LIST_LEASES", "leases")
            subnets = (await _strict_read(hub, spokes, "DHCP_LIST_SUBNETS", "subnets")
                       if leases is not None else None)
            kea_keys[ck] = None if subnets is None else f"k{len(kea)}"
            if kea_keys[ck]:
                kea[kea_keys[ck]] = {"leases": leases, "subnets": subnets}
        if kea_keys[ck] is None:
            errors.append({"tenant": tid, "error": "no strict kea read"})
            continue
        refs[str(len(tenants))] = tid
        scopes[str(len(tenants))] = skey
        tenants.append({"ref": str(len(tenants)), "filters": filters,
                        "agent_addresses": agents.get(tid, []), "sweep": sweep,
                        "kea": kea_keys[ck]})
    if not tenants:
        return _record(hub, status=_pass_status([], errors, []), clean=[], reserved=[],
                       conflicts=[], errors=errors, tenants=0, skipped=0, deferred=0)

    # Step 2: the spoke plans and writes. Reads and writes go to the IPAM
    # spoke the sync reads first, so a reservation lands where the sync looks.
    ipam = next(iter(hub._ipam_spoke_candidates()), None)
    if not ipam:
        errors.append({"tenant": None, "error": "netbox spoke not connected"})
        return _record(hub, status="error", clean=[], reserved=[], conflicts=[],
                       errors=errors, tenants=0, skipped=0, deferred=0)
    try:
        reply = unwrap_spoke(await hub.request_response(
            ipam, COMMAND, {"tenants": tenants, "kea": kea,
                            "max_writes": _MAX_WRITES_PER_PASS}, timeout=_SPOKE_TIMEOUT))
    except Exception as e:  # noqa: BLE001
        reply = {"status": "ERROR", "message": str(e) or type(e).__name__}
    if is_unknown_command(reply):
        logger.warning("static reservations: the netbox spoke is too old for %s", COMMAND)
        return _record(hub, status="unsupported", clean=[], reserved=[], conflicts=[],
                       errors=[{"tenant": None, "error": "netbox spoke too old; update it"}],
                       tenants=0, skipped=0, deferred=0)
    if not isinstance(reply, dict) or not isinstance(reply.get("changes"), list):
        msg = (reply or {}).get("message") if isinstance(reply, dict) else None
        errors.append({"tenant": None, "error": f"netbox spoke: {msg or 'no report'}"})
        return _record(hub, status="error", clean=[], reserved=[], conflicts=[],
                       errors=errors, tenants=0, skipped=0, deferred=0)

    # Step 3: map the spoke's opaque refs back to tenants and store the report.
    def _rows(key: str) -> List[Dict[str, Any]]:
        """The spoke's ``key`` rows with ``ref`` replaced by the tenant id."""
        return _tenant_rows(reply.get(key), refs, key)

    reserved, conflicts = _rows("changes"), _rows("conflicts")
    errors += _rows("errors")
    evaluated = {refs[str(r)] for r in reply.get("evaluated") or [] if str(r) in refs}
    clean = sorted(evaluated - {e.get("tenant") for e in errors})
    if reserved or reply.get("rolled_back"):
        hub.refresh_module_cache("netbox_ips")
    if reserved:
        # The raw rows (opaque refs, no tenant ids) for a later rollback.
        hub._static_res_pending = {"ipam": ipam, "refs": refs, "scopes": scopes,
                                   "changes": [c for c in reply["changes"]
                                               if isinstance(c, dict)]}
    logger.info("static reservations: %d reserved, %d conflicts, %d errors",
                len(reserved), len(conflicts), len(errors))
    return _record(hub, status=_pass_status(clean, errors, conflicts), clean=clean,
                   reserved=reserved, conflicts=conflicts, errors=errors,
                   rolled_back=_rows("rolled_back"), rollback_kept=_rows("rollback_kept"),
                   rollback_failed=_rows("rollback_failed"),
                   tenants=len(evaluated), skipped=int(reply.get("skipped") or 0),
                   deferred=int(reply.get("deferred") or 0))


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
    """Undo the last pass's writes for each tenant whose DHCP sync failed.

    Runs after the DHCP sync that follows a pass. A change whose tenant's Kea
    scope is not in ``hub._dhcp_delivered`` (its NetBox fetch or Kea push
    failed, its Kea vanished, or the sync raised) would otherwise sit in
    NetBox but not in Kea; changes whose scope was delivered stay. The spoke
    restores each IP's ``before`` only where NetBox still holds ``after``; an
    IP edited since is left alone (``rollback_kept``). The rollback carries
    only the pass's opaque refs, never tenant ids.
    Returns the updated status, or None when there was nothing to undo.
    """
    # Act once, and only on a sync that ran after the pass.
    pending = getattr(hub, "_static_res_pending", None)
    delivered = getattr(hub, "_dhcp_delivered", None)
    if not pending or delivered is None:
        return None
    hub._static_res_pending = None
    changes = [c for c in pending["changes"]
               if pending["scopes"].get(str(c.get("ref"))) not in delivered]
    if not changes:
        return None

    # Ask the spoke to undo them.
    try:
        reply = unwrap_spoke(await hub.request_response(
            pending["ipam"], COMMAND, {"rollback": changes}, timeout=_SPOKE_TIMEOUT))
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
    refs = pending["refs"]
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
    reserved = [r for r in st.get("reserved") or []
                if (r.get("tenant"), r.get("ip_id")) not in undone]
    st.update(status=_pass_status(st.get("clean"), errors, st.get("conflicts")),
              reserved=reserved, errors=errors, rolled_back=done,
              rollback_kept=kept, rollback_failed=failed)
    hub.dns_dhcp_sync_status["static_reservations"] = st
    return st


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
    list are dropped. A tenant's ``status`` is its own: ``error`` with its
    own errors, else ``conflicts`` with its own conflicts, ``ok`` when it was
    evaluated cleanly, else ``skipped``. Pass-wide rows with no tenant (the
    netbox spoke unreachable or too old) are kept for everyone, since they
    name no tenant.
    """
    if not isinstance(status, dict):
        return status
    out = {k: v for k, v in status.items()
           if k not in ("tenants", "skipped", "deferred", "clean")}
    def _visible(key: str, row: Any) -> bool:
        """A row is shown to its own tenant; a pass-wide error to everyone."""
        if not isinstance(row, dict):
            return False
        if row.get("tenant") is None:
            return key == "errors"
        return bool(tid) and same_tenant(row.get("tenant"), tid)

    for key in ("reserved", "conflicts", "errors", "rolled_back", "rollback_kept",
                "rollback_failed"):
        if key in status:
            out[key] = [r for r in status.get(key) or [] if _visible(key, r)]
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
