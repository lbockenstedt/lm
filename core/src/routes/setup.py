"""Hub Setup routes: spokes, sync loops, module configs, metadata."""
# asyncio provides the per-event-loop lock for the spokes cache.
import asyncio
# Hub-wide helpers: HTTP errors, hub message builder, logger, time and reply unwrapping.
from api import (
    HTTPException, Request, _hub_msg, logger, time, _unwrap_spoke,
)
# Tenant helpers: is a tenant shared, and may this session see a given spoke.
from access import tenant_is_shared as _tenant_is_shared, spoke_visible_to_session as _spoke_visible
# Ids of spokes that connect directly to the hub (not relayed through another spoke).
from spoke_alert_sync import direct_module_ids as _direct_module_ids

# ── /setup/pending_spokes cache (stale-while-revalidate) ─────────────────────
# The Spokes & Agents page polls /setup/pending_spokes on every load + every
# poll tick; the handler iterates known_modules and per-spoke reads
# (module_metadata, approved_modules, get_spoke_events for the rename banner).
# Mirror the /api/pxmx/agents SWR cache (routes/pxmx.py): instant serve from a
# fresh cache, one background refresh at the fresh-TTL boundary, and a forced
# refresh only when there's no servable cache. One hub per process → a
# module-level cache is fine.
_SPOKES_CACHE: dict = {"data": None, "ts": 0.0, "refreshing": False}
_SPOKES_FRESH_S = 5.0    # serve cached payload verbatim while younger than this
_SPOKES_STALE_S = 30.0   # still servable (background refresh kicks in here)
# Per-loop lock: a module-level asyncio.Lock() binds to the first event loop
# that acquires it, which breaks across ``asyncio.run()`` (tests) and would
# break a hub that ever recreates its loop. One lock per running loop gives
# correct mutual exclusion within a loop (one uvicorn loop in production)
# without cross-loop coupling. (Verbatim mirror of pxmx._agents_lock.)
_spokes_locks: dict = {}


def _spokes_lock() -> "asyncio.Lock":
    """Return the spokes-cache lock for the current event loop, creating it on first use."""
    # Key the lock by the running loop so each loop gets its own.
    loop = asyncio.get_running_loop()
    lk = _spokes_locks.get(id(loop))
    if lk is None:
        lk = asyncio.Lock()
        _spokes_locks[id(loop)] = lk
    return lk


# module_type prefix fallback for offline spokes (was nested in the handler;
# hoisted to module scope so the SWR compute fn can use it without a closure).
_PREFIX_MODULE = {
    "pxmx": "hypervisor", "opn": "firewall", "cppm": "nac",
    "cs": "simulation", "netbox": "ipam", "ldap": "directory",
    "dns": "dns", "dhcp": "dhcp", "nw": "nw",
    "henet": "henet",
}


def _module_type_for(hub, sid: str):
    """Live registration wins; then the module_type we PERSISTED at registration
    (module_metadata[sid].module_type) so an OFFLINE spoke/agent keeps its true
    type; then a spoke_id-prefix fallback for legacy dedicated ids. The
    persisted read is what lets a disconnected generic agent (module_type
    "agent") or a role sub-spoke "{base}-{role}" keep its category instead of
    falling through to "—" or a wrong prefix guess."""
    # Live registration first.
    mt = hub.spoke_module_types.get(hub._primary_key(sid))
    if mt:
        return mt
    # Then the type saved at registration.
    meta = (hub.state.system_state.get("module_metadata", {}) or {}).get(sid, {}) or {}
    if meta.get("module_type"):
        return meta["module_type"]
    # Finally guess from the spoke id prefix.
    for prefix, fallback in _PREFIX_MODULE.items():
        if sid == prefix or sid.startswith(prefix + "-"):
            return fallback
    return None


def _identity_change_for(hub, sid: str, meta: dict):
    """Latest unacknowledged identity_changed/hostname_changed event for a spoke.

    Returns ``None`` when there is no such event newer than the last ack ts
    (``module_metadata[sid]["change_acked_ts"]``), so the WebUI only shows the
    amber "renamed" banner until an admin dismisses it. Mirrored for agents
    via the parent spoke's event timeline.
    """
    # Time of the last admin acknowledgement (0 if never).
    acked_ts = float(meta.get("change_acked_ts") or 0.0)
    # Return the newest rename/reimage event after that time.
    for ev in hub.get_spoke_events(sid, limit=20):
        if ev.get("event") in ("identity_changed", "hostname_changed", "reimaged"):
            if ev.get("ts", 0) > acked_ts:
                return ev
    return None


async def _aggregate_spokes(hub):
    """Recompute the /setup/pending_spokes payload from live hub state.
    Pure hub-local reads (no spoke fan-out), so it is cheap; module-level (not
    a route closure) so it depends only on ``hub`` and is unit-testable with a
    stub hub. Does not itself catch exceptions — ``_maybe_refresh_spokes``
    serves stale on failure rather than blanking the tile."""
    # Known spokes plus their stored names and metadata.
    known_spokes = list(hub.state.system_state.get("known_modules", []) or [])
    module_names = hub.state.system_state.get("module_names", {})
    module_metadata = hub.state.system_state.get("module_metadata", {})

    # An approved spoke can exist in ``approved_modules`` (keyed by primary key)
    # WITHOUT ever being mirrored into ``known_modules`` — see the
    # /setup/spokes/purge-prefix "not yet mirrored into known_modules" catch.
    # The out-of-contact alert loop iterates ``approved_modules``, so such a
    # spoke fires a footer alert while never getting a row here → the admin sees
    # "out of contact" but has no row to Decommission/Force Delete. Union the
    # orphans in so every approved (non-relayed-agent) spoke gets a deletable
    # row. Relayed pxmx node-agents that leaked into approved_modules are
    # excluded (they render in the Agents table, keyed by composite id — the
    # same set the alert loop skips via _selfheal_leaked_agents).
    # Primary keys already in the list.
    _covered = {hub._primary_key(sid) for sid in known_spokes}
    # Relayed agent ids and direct-connect ids; a lookup failure means none.
    try:
        _relay_ids = hub._relayed_agent_ids()
    except Exception:
        _relay_ids = set()
    try:
        _direct_ids = _direct_module_ids(hub.state.system_state)
    except Exception:
        _direct_ids = set()
    # Add approved spokes missing from the list, skipping relayed agents.
    for pk, ap in (hub.approved_modules or {}).items():
        if (ap and pk not in _covered
                and (pk not in _relay_ids or pk in _direct_ids)):
            known_spokes.append(pk)

    # Build one row per spoke.
    spokes_status = []
    for sid in known_spokes:
        meta = module_metadata.get(sid, {}) or {}
        spokes_status.append({
            "spoke_id": sid,
            "display_name": module_names.get(sid, sid),
            "approved": hub.approved_modules.get(hub._primary_key(sid), False),
            # Soft-retire flag so the WebUI can pick Decommission vs Restore even
            # for a spoke with NO /setup/diagnostics telemetry entry (the delete
            # action row must not depend on diag being present).
            "decommissioned": bool(getattr(hub.state, "is_module_decommissioned",
                                            lambda _pk: False)(hub._primary_key(sid))),
            "module_type": _module_type_for(hub, sid),
            "hostname": meta.get("hostname", ""),
            # Revocation surface (admin action OR automatic tenant-side threat
            # response): the WebUI shows a "Revoked" badge + the reason so an
            # operator immediately sees WHY a node lost access without digging
            # through logs. Cleared on re-approval.
            "revoked": bool(meta.get("revoked")),
            "revoke_reason": meta.get("revoke_reason", "") or "",
            "revoked_ts": meta.get("revoked_ts", 0) or 0,
            "revoked_by": meta.get("revoked_by", "") or "",
            "install_uuid": meta.get("install_uuid", ""),
            "spoke_guid": meta.get("install_uuid", ""),
            "identity_change": _identity_change_for(hub, sid, meta),
            "tenant_id": hub.state.get_spoke_tenant(sid) or "",
            "tenant_shared": _tenant_is_shared(hub.state.get_spoke_tenant(sid) or ""),
            # B4: explicit parent linkage for role sub-spokes. Post-B1 both the
            # base agent + the role sub-spoke are independent guid keys, so the
            # pre-B1 ``{base}-{role}`` string-prefix match broke. ``parent_name``
            # is the raw parent name stamped at connect; resolve it to the
            # parent's current primary key so it matches the parent row's own
            # ``spoke_id``. ``role_name`` is the _ROLE_MAP key. Blank for base
            # spokes / pre-B1 entries (WebUI falls back to the prefix match).
            "parent_spoke_id": (hub._primary_key(meta.get("parent_name", ""))
                                if meta.get("parent_name") else ""),
            "role_name": meta.get("role_name", ""),
        })
    return {"spokes": spokes_status}


async def _maybe_refresh_spokes(hub, force=False):
    """Under ``_spokes_lock``: serve the cached payload if it's still fresh
    (unless ``force``); otherwise recompute and store. Serializes concurrent
    first-loaders into a single recompute; later waiters re-check under the
    lock and return the just-refreshed payload. Returns the served payload
    (fresh, recomputed, or stale-on-failure). Mirrors pxmx._maybe_refresh_agents.

    ``force`` means "the caller already decided the cache is unservable" — it
    does NOT bypass a genuinely-fresh result (if a concurrent caller refreshed
    while this one waited on the lock, serving it is the whole point)."""
    # Only one refresh runs at a time.
    async with _spokes_lock():
        # Serve the cache if it is fresh enough.
        cached = _SPOKES_CACHE["data"]
        age = (time.time() - _SPOKES_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _SPOKES_FRESH_S:
            return cached
        # Recompute and store the new payload.
        _SPOKES_CACHE["refreshing"] = True
        try:
            result = await _aggregate_spokes(hub)
            _SPOKES_CACHE["data"] = result
            _SPOKES_CACHE["ts"] = time.time()
            return result
        except Exception:
            logger.exception("spokes cache refresh failed")
            return cached  # serve stale rather than blanking the tile
        # Always clear the refreshing flag.
        finally:
            _SPOKES_CACHE["refreshing"] = False


def _is_relayed_agent(sid, relay_ids, direct_ids):
    """True when ``sid`` is a RELAYED node-agent: it reaches the hub through a
    parent hypervisor spoke rather than holding its own WebSocket.

    A device-mode agent also appears in ``relay_ids`` (it populates
    ``agent_config``/``agent_info``), but it dials the hub directly and is a
    real module spoke, so it must NOT be treated as relayed — otherwise a
    genuine outage of one gets dismissed as "not a real outage".

    Module-level + pure so it is unit-testable (mirrors
    ``_is_stuck_never_keyed``)."""
    return sid in relay_ids and sid not in direct_ids


def _agent_last_seen_for(relayed_last, *keys):
    """Freshest relay timestamp for a registry row, trying every key the
    agent's state may live under (spoke alias, agent alias/guid, raw id).
    ``None`` when none has ever relayed. Pure for unit tests."""
    # Look up every non-empty key and keep only real positive timestamps.
    vals = [relayed_last.get(k) for k in keys if k]
    vals = [v for v in vals if isinstance(v, (int, float)) and v > 0]
    # Return the newest one, or None.
    return max(vals) if vals else None


def _agent_name_to_guid(agent_config, agent_info):
    """``{raw agent name: guid}`` built from persisted ``agent_config``
    (hostname / display_name) and in-memory ``agent_info`` (agent_id).
    Only keys whose own id differs from the name (i.e. guid-migrated) count,
    and a name claimed by two different guids is dropped as ambiguous rather
    than guessed. Pure for unit tests."""
    # Name -> guid map, plus names seen with more than one guid.
    found = {}
    ambiguous = set()

    def _add(name, guid):
        """Record ``name`` -> ``guid``, marking the name ambiguous if it maps to another guid."""
        # Ignore empty values and ids that are not migrated (name equals guid).
        if not name or not guid or name == guid:
            return
        # A second, different guid for the same name makes it ambiguous.
        if found.get(name, guid) != guid:
            ambiguous.add(name)
        found[name] = guid

    # Names from persisted agent config.
    for guid, cfg in (agent_config or {}).items():
        if isinstance(cfg, dict):
            for field in ("agent_id", "hostname", "display_name"):
                _add(cfg.get(field), guid)
    # Names from live agent info.
    for guid, info in (agent_info or {}).items():
        if isinstance(info, dict):
            _add(info.get("agent_id"), guid)
    # Drop ambiguous names.
    return {n: g for n, g in found.items() if n not in ambiguous}


def _leaked_approved_agent_ids(approved, relay_ids, direct_ids):
    """Approved ids that the leak self-heal would pop.

    MUST stay identical to the predicate in
    ``SpokeAlertMixin._selfheal_leaked_agents`` — this is the diagnostic that
    reports on that self-heal, so any divergence makes it accuse a correctly
    working self-heal of failing. It previously omitted ``direct_ids`` and so
    reported every healthy device-mode agent, permanently."""
    return (set(approved) & set(relay_ids)) - set(direct_ids)


def _dhcp_ha_member_count(status):
    """Kea HA member count from a ``DHCP_HA_STATUS`` reply, or ``None``.

    ``None`` means "could not tell" (the relay failed, or the spoke answered
    something without a usable ``members``/``member_count``) and must never be
    read as "no members" — a watchdog that fires on an unreachable spoke is a
    watchdog operators learn to ignore. Only an explicit, well-formed count is
    returned.

    Module-level + pure so it is unit-testable (mirrors
    ``_is_stuck_never_keyed``)."""
    # Anything but a dict is unknown.
    if not isinstance(status, dict):
        return None
    # Prefer the members list: count entries with an id.
    members = status.get("members")
    if isinstance(members, list):
        return sum(1 for m in members if isinstance(m, dict) and m.get("id"))
    # Otherwise use member_count; a bool is not a valid count.
    raw = status.get("member_count")
    if isinstance(raw, bool):
        return None
    # A non-number count is unknown.
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return None


def _dhcp_spokes_without_cluster(status_by_spoke):
    """The dhcp spokes that advertise the role but manage no Kea at all.

    ``status_by_spoke`` maps spoke_id -> unwrapped ``DHCP_HA_STATUS`` reply (or
    ``None`` when the relay failed). A spoke whose cluster is empty has no Kea
    to answer for, so every DHCP read routed to it (diagnostics / stats /
    status) reports the SERVICE as dead — see ``_dhcp_spoke_for_request`` in
    ``routes/net_services.py``, where a tenantless admin falls through to
    ``get_spoke_by_type("dhcp")`` and takes whichever dhcp spoke sits first in
    ``spoke_module_types`` insertion order. One stray ``dhcp`` role on a host
    that never had Kea installed is therefore enough to make a healthy HA pair
    look completely down.

    Module-level + pure so it is unit-testable."""
    # Spokes whose reported cluster has exactly zero members.
    return {sid for sid, st in (status_by_spoke or {}).items()
            if _dhcp_ha_member_count(st) == 0}


def _is_stuck_never_keyed(approved, connected, has_key, is_relayed_agent, seen):
    """True when a registration is stuck in the "approve → never reports in"
    state: it is APPROVED yet has NEVER been seen, holds NO session key, is NOT
    connected and is NOT a relayed agent.

    Approval only mints + pushes a session key while the spoke is in
    ``active_connections`` (``approve_spoke`` / ``handle_connection`` zero-touch
    branch). Approve a spoke that was offline at the time — or a host-only
    registration that never opens its own socket — and nothing is keyed, so the
    row sits at offline / no key / never with only a Delete action and clicking
    Approve never makes it report in. The only recovery is to delete it
    everywhere so the box can re-present for approval while connected.

    Module-level + pure so it is unit-testable with plain values (mirrors
    ``_aggregate_spokes``)."""
    return bool(approved) and not connected and not has_key \
        and not is_relayed_agent and not seen


async def _deliver_agent_approval(hub, target_spoke: str, agent_id: str) -> str:
    """Durably deliver ``APPROVAL_SUCCESS`` for a relayed node-agent to the
    agent-hosting (hypervisor/simulation) spoke that owns it. Returns the
    disposition — ``"pushed"`` (spoke online) or ``"queued"`` (spoke offline,
    parked for the reconnect flush) — for the caller's log line and tests.

    Goes through the MAILBOX, not the low-level fire-and-forget
    ``send_to_spoke`` the approve path used before. The owning spoke FLAPS
    (periodic self-update reconnects — see the ``Spoke <id> is not connected``
    mailbox warnings), so a raw send that raced with a disconnect was silently
    lost and NEVER redelivered, leaving the agent pending forever even though
    the hub logged "relayed". The mailbox fixes both legs:

    * online → ``mailbox.push`` writes immediately AND records in
      ``pending_ack``; the retry loop resends with backoff until the spoke's
      ``COMMAND_RESULT`` acks it (or re-queues it offline if the socket drops
      mid-flight), so a reconnect can't drop it.
    * offline → ``mailbox.queue_for_spoke`` parks it under the spoke's primary
      key so ``flush_mailbox`` delivers it the instant the spoke returns —
      instead of the old warn-and-drop dead-end.

    Redelivery is safe: ``approve_pending_agent`` is idempotent (an already
    approved/connected agent no-ops), and an admin deny/delete calls
    ``mailbox.clear_spoke`` which purges any still-queued approval."""
    # Wrap APPROVAL_SUCCESS in a relay message addressed to the agent.
    pk = hub._primary_key(target_spoke)
    msg = _hub_msg(target_spoke, "SPOKE_RELAY", {
        "target_agent_id": hub._agent_relay_name(agent_id),
        "command": "APPROVAL_SUCCESS",
        "payload": {},
    })
    # Online: push through the mailbox (retried until acked).
    if pk in hub.active_connections:
        await hub.mailbox.push(msg, hub.send_to_spoke)
        return "pushed"
    # Offline: queue it for delivery when the spoke reconnects.
    await hub.mailbox.queue_for_spoke(pk, msg)
    return "queued"


async def _perform_agent_approval(hub, spoke_id: str, agent_id: str,
                                  explicit_tenant: str = None) -> dict:
    """Approve a relayed node-agent (persist the flag + durably relay
    ``APPROVAL_SUCCESS`` to its owning agent-hosting spoke). The single source
    of truth shared by the WebUI approve route, the loopback admin ops API,
    and the PSK auto-approve path (``main.py::_try_psk_agent_auto_approve``)
    so all three behave identically. Returns a summary dict for the caller.

    ``explicit_tenant``, when given, is an already-validated tenant (e.g. from
    a matched onboarding PSK) that WINS over the spoke-tenant-inherit logic
    below — the credential is the authoritative signal, not the parent spoke's
    binding."""
    # A Proxmox node agent connects THROUGH the pxmx hypervisor spoke,
    # not directly to the hub, so it must NOT be registered as a
    # hub-direct spoke (known_modules). Doing so made /setup/diagnostics
    # render a bogus OFFLINE spoke row for it — the hub has no
    # WebSocket for the agent, so get_diagnostics() emitted
    # connection_state="OFFLINE"/authenticated=False even though the
    # agent was genuinely connected (its real state lives in the
    # spoke's GET_AGENTS response, shown in the Agents table). Persist
    # the approval flag only, and clean up any prior leak so an
    # already-registered agent stops showing as an offline spoke.
    hub.approved_modules[agent_id] = True
    approved_map = hub.state.system_state.setdefault("approved_modules", {})
    approved_map[agent_id] = True
    known = hub.state.system_state.get("known_modules", [])
    if agent_id in known:
        known.remove(agent_id)
    await hub.state.save_state_now()

    # Resolve the spoke that actually owns this agent rather than
    # trusting the path's spoke_id blindly — the WebUI's approve
    # button doesn't always know which spoke a given agent is
    # connected through (a cs-dialed agent in the split-topology case
    # is not on the pxmx spoke), so a caller-supplied wrong spoke_id
    # would silently no-op (relay sent to a spoke that has never
    # heard of this agent_id, leaving it pending forever). Falls back
    # to the path param when agent_info has no entry yet (e.g.
    # approving before the first relayed frame has arrived).
    # Find the spoke the agent actually connects through, or use the given one.
    _resolved = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False)
    target_spoke = _resolved or spoke_id
    logger.info(
        "approve_agent: agent=%s → target_spoke=%s (%s; requested spoke_id=%s)",
        agent_id, target_spoke,
        "agent_info index" if _resolved else "fallback to requested spoke_id",
        spoke_id)

    # Bind a tenant onto the agent's client_simulation.tenant_id — either the
    # caller-supplied explicit_tenant (an already-validated onboarding PSK,
    # which always wins and OVERRIDES any existing pin) or, absent that,
    # inherit the parent spoke's tenant binding (Setup → Spokes & Agents'
    # "Tenant" button / Simulations → Spoke Management) so an agent connecting
    # to a tenant-bound spoke is assigned automatically — no per-agent config
    # needed. The inherit-only path seeds ONLY when the agent has no explicit
    # tenant of its own yet (an existing override, e.g. set via the Agent
    # Configuration modal, is left alone), and skips the SHARED tenant: a
    # shared spoke can serve agents belonging to different tenants, so
    # inheriting it here would silently mis-tag every agent as "shared"
    # instead of leaving it for an admin (or a tenant-scoped onboarding PSK)
    # to route explicitly.
    if explicit_tenant:
        tenant_to_bind = explicit_tenant
    # No explicit tenant: inherit the spoke's tenant unless it is the shared tenant.
    else:
        spoke_tenant = hub.state.get_spoke_tenant(target_spoke)
        from access import tenant_is_shared  # lazy: avoid import cycle
        tenant_to_bind = spoke_tenant if (spoke_tenant and not tenant_is_shared(spoke_tenant)) else None

    # Auto-enable Client-Simulation when this agent connects through a
    # simulation (cs) spoke — dialing that spoke's /ws/agent listener at all
    # is itself a strong signal of intent (the box was specifically pointed
    # at a cs spoke, typically because the operator wants it hosting
    # client-sim traffic), so no separate manual toggle should be required.
    # Set ONCE, here at approval time only — never re-forced on a later
    # approval/reconnect, so a subsequent manual disable (Setup's Agent
    # Config modal, or the tenant-admin CS toggle) sticks.
    spoke_pk = hub._primary_key(target_spoke)
    spoke_module_type = (getattr(hub, "spoke_module_types", {}) or {}).get(spoke_pk) \
        or hub.state.system_state.get("module_metadata", {}).get(target_spoke, {}).get("module_type")
    # Agents approved through a simulation spoke get Client-Simulation turned on.
    auto_enable_cs = (spoke_module_type == "simulation")

    # Store the tenant and/or CS flag in the agent's saved config.
    cs_cfg = None
    if tenant_to_bind or auto_enable_cs:
        agent_cfg_store = hub.state.system_state.setdefault("agent_config", {})
        agent_pk = hub._agent_primary_key(agent_id)
        entry = dict(agent_cfg_store.get(agent_pk, {}))
        cs_cfg = dict(entry.get("client_simulation") or {})
        # Set the tenant when explicit, or when the agent has none yet.
        if tenant_to_bind and (explicit_tenant or not cs_cfg.get("tenant_id")):
            cs_cfg["tenant_id"] = tenant_to_bind
        if auto_enable_cs:
            cs_cfg["enabled"] = True
        entry["client_simulation"] = cs_cfg
        agent_cfg_store[agent_pk] = entry
        hub.state._mark_dirty()

    # Push the new CS config to the agent now; on failure it still applies on reconnect.
    if auto_enable_cs:
        from routes.pxmx import push_pxmx_agent_config  # lazy: avoid import cycle
        try:
            await push_pxmx_agent_config(hub, agent_id, {"client_simulation": cs_cfg},
                                         owning_spoke=target_spoke)
        except Exception:  # noqa: BLE001 — best-effort; persisted state above still applies on reconnect
            logger.exception(
                f"approve_agent: CS auto-enable push failed for agent={agent_id} "
                f"(will still apply once the spoke re-pushes stored config on the "
                f"agent's next register)")

    # So the Agents tile / My Devices reflect this approval (pending →
    # approved, tenant bound, CS maybe auto-enabled) immediately instead of a
    # cached pre-approval snapshot for up to _AGENTS_STALE_S (30s). Shared by
    # all three approval callers (admin click, PSK auto-approve, tenant-admin
    # self-service), so this fix applies everywhere at once.
    from routes.pxmx import bust_pxmx_agents_cache  # lazy: avoid import cycle
    bust_pxmx_agents_cache()

    # Deliver the approval, then log whether it was pushed or queued.
    connected = hub._primary_key(target_spoke) in hub.active_connections
    _disp = await _deliver_agent_approval(hub, target_spoke, agent_id)
    if connected:
        logger.info(
            "approve_agent: durably relayed APPROVAL_SUCCESS for "
            "agent=%s to spoke=%s (mailbox %s — retried until acked, "
            "survives a reconnect flap)", agent_id, target_spoke, _disp)
    else:
        # No longer a silent dead-end: the owning spoke is offline right
        # now (it flaps on self-update), so QUEUE the approval for the
        # reconnect flush instead of dropping it. The approval flag is
        # already persisted above; _deliver_agent_approval parks the
        # relay under the spoke's primary key so flush_mailbox delivers
        # it the moment the spoke comes back — the agent then leaves
        # pending without another admin click.
        logger.warning(
            "approve_agent: owning spoke '%s' for agent '%s' is "
            "NOT connected — APPROVAL_SUCCESS was %s for the reconnect flush "
            "(no longer dropped). If the agent stays pending, verify the "
            "agent-hosting spoke (hypervisor/simulation) comes back online.",
            target_spoke, agent_id, _disp)
    # Summary for the caller.
    return {"agent_id": agent_id, "target_spoke": target_spoke,
            "spoke_connected": connected, "disposition": _disp,
            "tenant_inherited": tenant_to_bind or None,
            "cs_auto_enabled": auto_enable_cs}


def _bust_spokes_cache():
    """Debounced invalidation of the spokes cache. Called from setup mutation
    endpoints (approve/revoke/delete/purge/ack/metadata rename). Rather than
    cold-busting (ts=0), which forced a BLOCKING full recompute on the next GET
    and — under admin churn (many mutations back-to-back) — made every poll
    bypass the SWR cache entirely, this DEMOTES the cache to "just past fresh":
    the next GET serves the current payload instantly and kicks a single
    background refresh, so the mutation is reflected within the fresh-TTL window
    without thrash. A cold cache (data is None) still forced-refreshes on the
    next GET (the age check requires a servable payload). Also busts the
    /setup/diagnostics cache — the same mutations surface there too."""
    # Keep data but mark it just past fresh, so the next GET refreshes in the background.
    if _SPOKES_CACHE.get("data") is not None:
        _SPOKES_CACHE["ts"] = min(_SPOKES_CACHE["ts"], time.time() - _SPOKES_FRESH_S)
    # No cached data: force a refresh on the next GET.
    else:
        _SPOKES_CACHE["ts"] = 0.0
    # Also refresh the diagnostics cache, if that module is loaded.
    try:
        from routes import setup_admin  # lazy: avoid any import-cycle at load
        setup_admin._bust_diag_cache()
    except Exception:
        logger.debug("diag cache bust skipped (setup_admin unavailable)", exc_info=True)


async def _purge_spoke_from_dhcp_dns_clusters(hub, spoke_id: str):
    """Remove ``spoke_id`` as a member from every connected DHCP (Kea HA) and
    DNS (resolver cluster) spoke that currently lists it, so a deleted spoke
    stops showing up as a permanently-unreachable "ghost" member on the
    survivor's HA-pair/cluster diagnostics. Uses each module's own
    HA_STATUS/CLUSTER_STATUS RPC to check membership first (cheap, and avoids
    sending a rewrite to spokes that don't reference this id at all), then
    the same HA_CONFIG/CLUSTER_CONFIG RPC the Edit Cluster UI uses to declare
    the trimmed member list. Never raises — this is best-effort cleanup, not
    a precondition for the delete itself; a spoke that is offline, errors, or
    simply doesn't reference the id is skipped silently."""
    # Check DHCP HA pairs and DNS resolver clusters the same way.
    for module_type, status_cmd, config_cmd in (
            ("dhcp", "DHCP_HA_STATUS", "DHCP_HA_CONFIG"),
            ("dns", "DNS_CLUSTER_STATUS", "DNS_CLUSTER_CONFIG")):
        # All spokes of this type; a lookup failure means none.
        try:
            candidates = hub.get_all_spokes_by_type(module_type) or []
        except Exception:  # noqa: BLE001
            candidates = []
        # Check each cluster spoke for the deleted member.
        for cluster_spoke_id in candidates:
            if hub._primary_key(cluster_spoke_id) == hub._primary_key(spoke_id):
                continue  # the deleted spoke can't purge itself
            # Ask the spoke for its current members; any failure is logged and skipped.
            try:
                status = await hub.request_response(
                    cluster_spoke_id, status_cmd, {}, timeout=15.0)
                payload = (status.get("payload", {}).get("data", status)
                           if isinstance(status, dict) else status)
                members = [m for m in (payload or {}).get("members") or []
                           if isinstance(m, dict)]
                # Members left after removing the deleted spoke (by raw id or primary key).
                remaining = [m for m in members
                             if str(m.get("id") or "") != str(spoke_id)
                             and hub._primary_key(str(m.get("id") or "")) != hub._primary_key(spoke_id)]
                if len(remaining) == len(members):
                    continue  # this cluster never referenced the deleted spoke
                # Send the trimmed member list back to the spoke.
                await hub.request_response(
                    cluster_spoke_id, config_cmd, {"members": remaining},
                    timeout=30.0)
                logger.info(
                    "purged deleted spoke '%s' from %s cluster on '%s'",
                    spoke_id, module_type, cluster_spoke_id)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "could not purge deleted spoke '%s' from %s cluster on "
                    "'%s': %s", spoke_id, module_type, cluster_spoke_id, e)


async def hard_delete_spoke(hub, spoke_id: str):
    """Permanently remove a spoke/generic-agent registration and all of its
    runtime state — the single source of truth shared by the Global-Admin
    ``DELETE /setup/spokes/{id}`` route and the tenant-admin
    ``DELETE /tenant/{tenant}/spokes/{id}`` route (routes/onboarding.py). The
    caller is responsible for authorization (admin gate or per-tenant ownership
    check) BEFORE invoking this — this helper does no auth.

    Closes the live WebSocket if connected (its disconnect handler clears
    active_connections / spoke_module_types / spoke_telemetry), drops the
    in-memory approval mirror, removes the persisted registration + metadata,
    wipes the crypto material (current key + history), clears queued mail, and
    evicts the per-spoke runtime caches. The spoke must fully re-onboard to
    return. Also busts the spokes cache so the change surfaces immediately.
    """
    # Close the spoke's live connection, if any.
    pk = hub._primary_key(spoke_id)
    ws = hub.active_connections.get(pk)
    if ws is not None:
        try:
            await ws.close(code=1008, reason="Removed")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not close live WS for {spoke_id} during delete: {e}")
    # A deleted spoke can still be a MEMBER of a Kea HA pair / DNS resolver
    # cluster another DHCP/DNS spoke's own HA coordinator persists on disk
    # (cluster_config / kea-ha.json equivalents) — the hub has no authority
    # over that file, so simply removing the hub registration here left a
    # "ghost" member the surviving node's diagnostics/HA-status pages kept
    # fanning out to (and reporting unreachable) forever, with no UI action
    # able to clear it. Best-effort ask every connected DHCP/DNS spoke to
    # drop this id from its own topology BEFORE the hub forgets about it —
    # never raises; a spoke that is offline or doesn't recognize the member
    # is simply skipped (nothing to clean up there).
    await _purge_spoke_from_dhcp_dns_clusters(hub, spoke_id)
    # Forget the approval, the stored registration and its keys.
    hub.approved_modules.pop(pk, None)
    hub.state.remove_module(spoke_id)
    hub.key_manager.delete_spoke_key(pk)
    # Drop queued/pending messages — the key is gone, so they can no longer be
    # signed and would retry against the keyless spoke (log flood).
    await hub.mailbox.clear_spoke(pk)
    # Drop per-spoke runtime caches (simulations_cache, telemetry, rate_limiters,
    # events, recovery, agent_logs) — the disconnect handler only clears
    # active_connections/spoke_module_types, so without this the per-spoke dicts
    # grow unbounded as spokes are deleted/recreated over time.
    hub._evict_spoke(spoke_id)
    # Make the Spokes view refresh soon.
    _bust_spokes_cache()


# ── /status cache (stale-while-revalidate) ──────────────────────────────────
# The AUTHENTICATED /status body is polled by every open WebUI tab every ~10s
# and recomputes hub.get_system_metrics() + spokes_in_contact() +
# heartbeat.get_all_statuses() + get_active_spoke_alerts() on every hit. The
# body is user-INVARIANT (it carries no per-user / per-permission fields — see
# the handler), so ONE process-wide cache serves every authenticated session
# identically. Short TTLs (fresh 2s / servable-stale 5s) keep it near-live while
# collapsing the N-tabs × 10s fan-out into one recompute per ~2s. Mirrors the
# /setup/pending_spokes + /setup/diagnostics SWR caches above. The anonymous
# body (readiness + live connection COUNT) is NOT cached — it is already trivial.
_STATUS_CACHE: dict = {"data": None, "ts": 0.0, "refreshing": False}
_STATUS_FRESH_S = 2.0    # serve cached payload verbatim while younger than this
_STATUS_STALE_S = 5.0    # still servable (background refresh kicks in here)
_status_locks: dict = {}


def _status_lock() -> "asyncio.Lock":
    """Return the /status cache lock for the current event loop, creating it on first use."""
    # Key the lock by the running loop so each loop gets its own.
    loop = asyncio.get_running_loop()
    lk = _status_locks.get(id(loop))
    if lk is None:
        lk = asyncio.Lock()
        _status_locks[id(loop)] = lk
    return lk


async def _aggregate_status(hub):
    """Recompute the authenticated /status body from live hub state. Byte-for-byte
    the same dict the handler used to build inline; module-level (not a closure)
    so it depends only on ``hub`` and is unit-testable with a stub hub."""
    # Hub system metrics.
    metrics = await hub.get_system_metrics()
    # Operator alerts surfaced in the header badge: spoke out-of-contact +
    # fleet-availability (per-tenant client-sim health) + out-of-dongles (per
    # Proxmox host). All share the {spoke_id, name, tier, ...} shape so the WebUI
    # renders them uniformly. Derive the COUNT from this same filtered list so the
    # badge number can never disagree with the dropdown — the count used to be a
    # raw len(_spoke_alerts), which over-counts any entry the tier-filtered getter
    # drops (e.g. an orphaned/non-active entry).
    # Tag each entry with its PRODUCER. They share a shape, but they are not the
    # same kind of thing: only the first is a spoke/agent that has stopped talking
    # to the hub. A fleet-availability or out-of-dongles alert is a synthetic key
    # (fleet:<tenant> / dongles:<host>) describing lab capacity — listing those
    # under "Out-of-contact alerts" told the operator three Proxmox hosts and a
    # tenant had gone silent, which is not what they mean. The WebUI groups on
    # this field; entries from an older hub carry no source and are treated as
    # spoke out-of-contact (the previous behaviour).
    def _tag(alerts, source):
        """Return copies of ``alerts`` tagged with their producer ``source``."""
        return [{**a, "source": source} for a in (alerts or [])]

    # All active alerts from every producer.
    active_alerts = (
        _tag(hub.get_active_spoke_alerts(), "spoke_out_of_contact")
        + _tag(hub.get_fleet_alerts() if hasattr(hub, "get_fleet_alerts") else [],
               "fleet_availability")
        # Relayed node agents (pxmx/cs). Their own producer, because the
        # spoke_out_of_contact sweep deliberately skips them — without this a
        # whole fleet of dead agents raised NO alert and the tray stayed green.
        + _tag(hub.get_agent_alerts() if hasattr(hub, "get_agent_alerts") else [],
               "agent_out_of_contact"))
    # The full status body.
    return {
        "ready": True,
        "active_connections": list(hub.active_connections.keys()),
        # Display "online" set: connected now OR seen within the grace window.
        "in_contact": hub.spokes_in_contact(),
        "spoke_module_types": dict(hub.spoke_module_types),
        "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
        "active_alert_count": len(active_alerts),
        "active_alerts": active_alerts,
        "metrics": metrics,
    }


async def _maybe_refresh_status(hub, force=False):
    """Under ``_status_lock``: serve the cached body if fresh (unless ``force``);
    otherwise recompute and store. Serializes concurrent first-loaders into a
    single recompute; serves stale on failure. Mirrors _maybe_refresh_spokes."""
    # Only one refresh runs at a time.
    async with _status_lock():
        # Serve the cache if it is fresh enough.
        cached = _STATUS_CACHE["data"]
        age = (time.time() - _STATUS_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _STATUS_FRESH_S:
            return cached
        # Recompute and store the new body.
        _STATUS_CACHE["refreshing"] = True
        try:
            result = await _aggregate_status(hub)
            _STATUS_CACHE["data"] = result
            _STATUS_CACHE["ts"] = time.time()
            return result
        except Exception:
            logger.exception("status cache refresh failed")
            return cached  # serve stale rather than blanking the WebUI
        # Always clear the refreshing flag.
        finally:
            _STATUS_CACHE["refreshing"] = False


def register(app, hub, ctx):
    """Register setup routes on the Hub app."""
    # Short names for the shared auth helpers.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    @app.get("/setup/spoke-hosts")
    async def get_spoke_hosts():
        """Return the remote IP for each connected spoke, keyed by module_type.
        Used by the WebUI to auto-populate service URL fields."""
        hub = app.state.hub
        # Map module type -> IP of a connected spoke of that type.
        result = {}
        for spoke_id, telemetry in hub.spoke_telemetry.items():
            # Skip spokes with no known IP.
            ip = telemetry.get("remote_ip")
            if not ip:
                continue
            # Record the IP under the spoke's module type.
            module_type = hub.spoke_module_types.get(spoke_id)
            if module_type:
                result[module_type] = {"ip": ip, "spoke_id": spoke_id}
        return {"hosts": result}

    @app.post("/setup/hub-backlog/purge")
    async def purge_hub_backlog(request: Request):
        """Diag (System → Hub Status 'Drop Backlog'): drop the hub's outbound
        message backlog — all, or only ``?type=SPOKE_UPDATE`` — from both
        pending_ack and the per-spoke offline queues. For clearing a backlog
        that won't drain (e.g. undeliverable SPOKE_UPDATE to a flapping spoke)
        without deleting/re-approving the spoke. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Optional message type filter, and the backlog size before purging.
        msg_type = request.query_params.get("type") or None
        before = hub.mailbox.backlog_stats().get("total", 0)
        # Drop the messages and log who did it.
        dropped = await hub.mailbox.purge_all(msg_type=msg_type)
        logger.warning("[diag] Hub backlog purge by %s: dropped %d%s (was %d)",
                       (sess.get("username") if isinstance(sess, dict) else "?"),
                       dropped, f" of type {msg_type}" if msg_type else "", before)
        return {"dropped": dropped, "type": msg_type or "all",
                "backlog": hub.mailbox.backlog_stats()}

    @app.post("/setup/rate-limit-drops/reset")
    async def reset_rate_limit_drops(request: Request):
        """Reset the per-spoke rate-limit drop counters (in-memory running totals
        shown in System → Hub Status). Otherwise they only reset on a hub
        restart. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Count the spokes being reset, then clear the counters.
        n = len(getattr(hub, "rate_limit_drops", {}) or {})
        try:
            hub.rate_limit_drops.clear()
        except Exception:  # noqa: BLE001
            hub.rate_limit_drops = {}
        # Audit log.
        logger.info("[diag] rate-limit drop counters reset (%d spoke(s)) by %s", n,
                    (sess.get("username") if isinstance(sess, dict) else "?"))
        return {"status": "ok", "cleared_spokes": n}

    @app.post("/setup/hub/restart")
    async def restart_hub_service(request: Request):
        """Restart the hub service (lm.service) so freshly-pulled code is loaded —
        e.g. after an update that added a route, curing a stale-process 405 on a
        new endpoint (System → Hub Status 'Restart hub service'). Uses the
        canonical ``lm-self-restart`` path: a transient systemd unit restarts lm
        ~3s later (outside lm's cgroup), so this response returns first. Spokes
        reconnect automatically. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # The restart helper must exist on this deployment.
        restart = getattr(hub, "_hub_self_restart", None)
        if restart is None:
            raise HTTPException(status_code=503,
                                detail="hub self-restart is unavailable on this deployment")
        logger.warning("[diag] Hub service restart requested by %s",
                       (sess.get("username") if isinstance(sess, dict) else "?"))
        # Schedule the restart; a failure is reported as 502.
        try:
            msg = await restart()
        except Exception as e:  # noqa: BLE001
            logger.warning("[diag] hub self-restart failed: %s", e)
            raise HTTPException(status_code=502, detail=f"restart could not be scheduled: {e}")
        return {"status": "scheduled",
                "message": msg or "lm.service restarting to apply the latest code"}

    @app.get("/status")
    async def get_status(request: Request):
        """Hub status for the WebUI and health probes.

        Anonymous callers get readiness and a connection count only; signed-in users get the full
        (cached) status body.
        """
        # 503 until the hub's WebSocket server is up.
        hub = app.state.hub
        if not getattr(hub, "is_ready", False):
            raise HTTPException(status_code=503, detail="Hub is not yet ready (WebSocket server starting)")
        # /status is public (see api.py access_control_middleware) so an anonymous
        # caller — a health probe, or anyone reaching an internet-exposed Azure hub
        # — gets a SECRET-FREE minimal body: readiness + a connection COUNT only.
        # The full operational body (spoke IDs, module types, heartbeats, alerts,
        # metrics) is returned only to an authenticated session — it reveals the
        # fleet shape and is consumed solely by the WebUI, which always sends its
        # cookie (credentials: 'same-origin'). ``system_state`` (users' password
        # hashes + global_config firewall/NAC/IPAM/LDAP credentials + tenant map +
        # spoke IPs) is NEVER returned here, authenticated or not — it was a
        # one-shot total compromise for any unauthenticated caller.
        sess = _session_user(request)
        conn_count = len(hub.active_connections)
        if not sess:
            return {"ready": True, "active_connection_count": conn_count}
        # Authenticated body is user-invariant → serve the process-wide SWR
        # cache. Inside the stale window serve instantly; past fresh-TTL kick ONE
        # background refresh (the ``not refreshing`` guard avoids a pile-up). The
        # WebUI colours tiles from ``in_contact`` (connected now OR seen within
        # the grace window), so a transient loop stall / brief reconnect doesn't
        # flip a module offline — only genuine long absence does.
        # Read the cached body and its age.
        cached = _STATUS_CACHE["data"]
        age = (time.time() - _STATUS_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _STATUS_STALE_S:
            if age >= _STATUS_FRESH_S and not _STATUS_CACHE["refreshing"]:
                asyncio.create_task(_maybe_refresh_status(hub))
            return cached
        # No servable cache → forced refresh (the lock serializes first-loaders).
        return await _maybe_refresh_status(hub, force=True)


    @app.get("/vm/{vm_id}/firewall")
    async def get_vm_firewall(request: Request, vm_id: str):
        """A VM's OPNsense firewall rules keyed by the VM's cached IP. Admin-only:
        the resources cache tenant_id is not reliably populated, so without an
        ownership check a non-admin enumerating vm_id could read another tenant's
        firewall rules. (Per-tenant VM detail uses /vm/{vm_id}/details which is
        tenant-scoped; this endpoint is not used by the WebUI.)"""
        # Signed in and Global Admin only.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub

        # 1. Find the IP for this VM from the state manager
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        if not ip:
            raise HTTPException(status_code=404, detail=f"No IP address found for VM {vm_id}")

        # 2. Identify the OPNsense spoke
        opn_spoke = hub.get_spoke_by_type("firewall")

        if not opn_spoke:
            raise HTTPException(status_code=503, detail="No spoke connected")

        # 3. Use the async bridge to request rules from the spoke
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
            # Return the spoke's rule data.
            return result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("get_vm_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Setup: spoke approval / secrets / agents (/setup/spokes/*) ───────────
    @app.post("/setup/spokes/{spoke_id}/reset-secret")
    async def reset_spoke_secret(spoke_id: str):
        """Delete a spoke's secret so it can be onboarded again (Global Admin, via /setup gate)."""
        # Delete the key; any failure is reported as a 500.
        hub = app.state.hub
        try:
            hub.key_manager.delete_spoke_key(hub._primary_key(spoke_id))
            # Drop any queued/pending messages for this spoke — without its key
            # they can no longer be signed and would retry against the keyless
            # spoke (log flood). Re-onboarding generates a fresh key + pushes.
            await hub.mailbox.clear_spoke(hub._primary_key(spoke_id))
            return {"status": "ok", "message": f"Secret for spoke {spoke_id} has been reset. It can now be re-onboarded."}
        except Exception as e:
            logger.exception("reset_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/rotate-secret")
    async def rotate_spoke_secret(spoke_id: str):
        """On-demand, in-place session-secret rotation (item 9b). Non-disruptive:
        the spoke stays connected/approved and is pushed a new secret signed with
        the pre-rotation secret. For suspected compromise where the OLD secret
        must stop working immediately, use /revoke or /reset-secret instead."""
        hub = app.state.hub
        # Rotate now; an ERROR result means the spoke was not found.
        try:
            result = await hub.rotate_spoke_secret_now(spoke_id)
            if result.get("status") == "ERROR":
                raise HTTPException(status_code=404, detail=result.get("message"))
            return result
        # Let HTTP errors through unchanged; wrap anything else as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("rotate_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/rotate-all")
    async def rotate_all_spoke_secrets():
        """On-demand in-place rotation for every approved spoke with a key
        (item 9b) — the "rotate everything after an incident" lever. Admin only.
        Each spoke is rotated non-disruptively via rotate_spoke_secret_now."""
        hub = app.state.hub
        # Rotate every spoke; any failure is reported as a 500.
        try:
            return await hub.rotate_all_spoke_secrets_now()
        except Exception as e:
            logger.exception("rotate_all_spoke_secrets failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/revoke")
    async def revoke_spoke(spoke_id: str):
        """Immediate, non-destructive revocation (item 9c): close the live WS,
        drop approval (re-approval required to return), wipe the crypto material
        so the old secret no longer verifies on reconnect — but KEEP the
        registration record so the operator sees it was revoked and can re-onboard
        + re-approve the same id. For a full wipe (remove the record too), use
        DELETE /setup/spokes/{id} instead."""
        hub = app.state.hub
        # Revoke, then refresh the Spokes view soon.
        try:
            res = await hub.revoke_spoke(spoke_id)
            _bust_spokes_cache()
            return res
        except Exception as e:
            logger.exception("revoke_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/spokes/{spoke_id}")
    async def delete_spoke(spoke_id: str):
        """Permanently remove a spoke/generic-agent registration.

        Closes the live WebSocket if the spoke is currently connected (the
        disconnect handler then clears active_connections / spoke_module_types /
        spoke_telemetry), drops the in-memory approval mirror, removes the
        persisted registration + metadata, and wipes the crypto material
        (current key + history). The spoke must fully re-onboard to return.
        """
        hub = app.state.hub
        # Run the shared hard-delete; any failure is reported as a 500.
        try:
            await hard_delete_spoke(hub, spoke_id)
            return {"status": "ok", "message": f"Spoke '{spoke_id}' removed."}
        except Exception as e:
            logger.exception("delete_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/decommission")
    async def decommission_spoke(spoke_id: str):
        """Soft-retire a spoke/generic-agent: keep the registration record (so it
        stays visible + re-onboardable) but flag it decommissioned so the
        out-of-contact alert loop skips it and the UI badged it grey. Reversible
        via /setup/spokes/{id}/restore. For a full wipe use DELETE instead."""
        hub = app.state.hub
        # Flag the spoke as decommissioned (``changed`` is False if it already was).
        try:
            pk = hub._primary_key(spoke_id)
            changed = hub.state.decommission_module(pk)
            # Clear any active out-of-contact alert immediately so a just-retired
            # box stops firing this cycle (the alert loop also clears, but this
            # makes the UI/log drop it without waiting up to 30 s).
            try:
                hub._spoke_alert_clear(pk)
                hub._spoke_alert_tier.pop(pk, None)
                hub._spoke_absent_since.pop(pk, None)
            except Exception:  # noqa: BLE001 — alert state is best-effort
                pass
            # Log only a real change, then refresh the Spokes view soon.
            if changed:
                logger.info("Spoke '%s' decommissioned (soft-retire, alerts suppressed).", spoke_id)
            _bust_spokes_cache()
            return {"decommissioned": True, "changed": changed}
        except Exception as e:
            logger.exception("decommission_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/restore")
    async def restore_spoke(spoke_id: str):
        """Un-decommission a soft-retired spoke/generic-agent (re-enables
        out-of-contact alerting). The record was never removed."""
        hub = app.state.hub
        # Clear the decommission flag (``changed`` is False if it was not set).
        try:
            pk = hub._primary_key(spoke_id)
            changed = hub.state.restore_module(pk)
            if changed:
                logger.info("Spoke '%s' restored from decommission.", spoke_id)
            _bust_spokes_cache()
            return {"decommissioned": False, "changed": changed}
        except Exception as e:
            logger.exception("restore_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/purge-prefix")
    async def purge_spokes_prefix(request: Request):
        """Bulk-remove every spoke/agent whose id starts with a prefix (default
        'loadtest-'), running the same teardown as DELETE /setup/spokes/{id} for
        each. For cleaning up synthetic load-test spokes in one shot / resetting
        between runs. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # The id prefix to purge (default "loadtest-"); it must not be empty.
        prefix = (request.query_params.get("prefix") or "loadtest-").strip()
        if not prefix:
            raise HTTPException(status_code=400, detail="prefix required")

        def _mid(m):
            """Return the spoke id from a known_modules entry (string or dict), or None."""
            if isinstance(m, str):
                return m
            if isinstance(m, dict):
                return m.get("id") or m.get("spoke_id")
            return None

        # Collect ids from known_modules that match the prefix.
        targets = set()
        for m in list(hub.state.system_state.get("known_modules", []) or []):
            mid = _mid(m)
            if mid and mid.startswith(prefix):
                targets.add(mid)
        # Catch anything connected/approved not yet mirrored into known_modules.
        for mid in list(hub.approved_modules) + list(getattr(hub, "active_connections", {})):
            if isinstance(mid, str) and mid.startswith(prefix):
                targets.add(mid)

        # Tear down each target; one failure does not stop the rest.
        removed = 0
        for spoke_id in sorted(targets):
            try:
                # Close its live connection, if any.
                ws = hub.active_connections.get(hub._primary_key(spoke_id))
                if ws is not None:
                    try:
                        await ws.close(code=1008, reason="load-test purge")
                    except Exception:
                        pass
                # Forget approval, registration, keys, queued messages and runtime caches.
                hub.approved_modules.pop(hub._primary_key(spoke_id), None)
                hub.state.remove_module(spoke_id)
                hub.key_manager.delete_spoke_key(hub._primary_key(spoke_id))
                await hub.mailbox.clear_spoke(hub._primary_key(spoke_id))
                hub._evict_spoke(spoke_id)
                removed += 1
            except Exception as e:  # noqa: BLE001 — best-effort per spoke
                logger.warning("purge_spokes_prefix: %s failed: %s", spoke_id, e)
        # Audit log, then refresh the Spokes view soon.
        logger.warning("[diag] purged %d spoke(s) with prefix '%s' by %s",
                       removed, prefix,
                       (sess.get("username") if isinstance(sess, dict) else "?"))
        _bust_spokes_cache()
        return {"status": "ok", "removed": removed, "prefix": prefix}

    @app.post("/setup/spokes/{spoke_id}/ack-change")
    async def ack_identity_change(spoke_id: str):
        """Dismiss the amber "renamed" banner for a spoke/agent.

        Stamps ``change_acked_ts`` into module_metadata so ``_identity_change_for``
        stops surfencing the latest identity_changed/hostname_changed/reimaged
        event until a newer one arrives. Idempotent.
        """
        hub = app.state.hub
        # Stamp the acknowledgement time and mark state for saving.
        try:
            hub.state.update_module_metadata(
                spoke_id, {"change_acked_ts": time.time()}
            )
            hub.state._mark_dirty()
            _bust_spokes_cache()
            return {"status": "ok", "spoke_id": spoke_id}
        except Exception as e:
            logger.exception("ack_identity_change failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/rotate-key/{spoke_id}")
    async def rotate_key_live(spoke_id: str):
        """
        Generate a new spoke secret and push it to the live spoke in a single call.

        Flow:
          1. Hub generates new secret via key_manager.rotate_key()
          2. Hub sends SPOKE_UPDATE_SESSION_KEY to the spoke over the live WS
          3. Spoke updates self.secret + self.signer, persists to .env, acks
          4. Hub returns the new secret (store it securely; the old one is invalidated)

        If the spoke is not currently connected, the new key is stored and the spoke
        will use it on its next connection (key_manager accepts the new key from then on).
        """
        hub = app.state.hub
        try:
            # Capture the secret the spoke currently holds BEFORE rotating, so
            # the key-delivery push is signed with it — the spoke can't verify a
            # frame signed with the new secret it hasn't installed yet.
            prev_secret = hub.key_manager.current_session_secret(hub._primary_key(spoke_id))
            new_key = hub.key_manager.rotate_key(hub._primary_key(spoke_id))
            new_secret = new_key.secret

            # Push the new key if the spoke is connected; otherwise it is used on next connect.
            spoke_conn = hub.active_connections.get(hub._primary_key(spoke_id))
            if spoke_conn:
                # Push it; failure leaves the new key stored but not pushed.
                try:
                    result = await hub.request_response(
                        spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret},
                        signing_secret=prev_secret,
                    )
                    pushed = result.get("status") == "SUCCESS"
                except Exception as push_err:
                    logger.warning(f"Could not push new key to spoke {spoke_id}: {push_err}")
                    pushed = False
            else:
                pushed = False

            return {
                "status":    "ok",
                "spoke_id":  spoke_id,
                "pushed":    pushed,
                "message":   ("New key pushed to live spoke and persisted." if pushed
                               else "New key stored. Spoke will pick it up on next connect."),
            }
        except Exception as e:
            logger.exception("rotate_key_live failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spokes/{spoke_id}/agents")
    async def get_spoke_agents(spoke_id: str):
        """List the other known spokes, reported as the agents of ``spoke_id``."""
        # Every known spoke except this one.
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        agents = [sid for sid in known_spokes if sid != spoke_id]
        return {"spoke_id": spoke_id, "agents": agents}

    @app.post("/setup/spokes/{spoke_id}/agents/{agent_id}/approve")
    async def approve_agent_under_spoke(spoke_id: str, agent_id: str):
        """Approve a relayed agent under a spoke (see _perform_agent_approval)."""
        hub = app.state.hub
        # Approve; any failure is reported as a 500.
        try:
            await _perform_agent_approval(hub, spoke_id, agent_id)
        except Exception as e:
            logger.exception("approve_agent_under_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            # Approving a relayed agent mutates known_modules/approved_modules
            # (leaked-id self-heal surface) — bust the spokes cache.
            _bust_spokes_cache()

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        """List every spoke with its approval, type, tenant and revoke details (cached).

        Returns {"spokes": [...]}.
        """
        # Read the cached payload and its age.
        hub = app.state.hub

        # Serves a stale-while-revalidate cache (``_SPOKES_CACHE``): fresh
        # within ``_SPOKES_FRESH_S`` (instant serve), servable-stale until
        # ``_SPOKES_STALE_S`` (instant serve + one background refresh), and a
        # forced refresh only when there's no servable cache. Keeps Setup →
        # Spokes & Agents instant on repeat loads. Mutation endpoints call
        # ``_bust_spokes_cache()`` so an admin action is reflected at once.
        cached = _SPOKES_CACHE["data"]
        age = (time.time() - _SPOKES_CACHE["ts"]) if cached is not None else None

        # Inside the stale window → serve instantly; past fresh-TTL, kick ONE
        # background refresh (the ``not refreshing`` guard avoids a pile-up).
        if cached is not None and age is not None and age < _SPOKES_STALE_S:
            if age >= _SPOKES_FRESH_S and not _SPOKES_CACHE["refreshing"]:
                asyncio.create_task(_maybe_refresh_spokes(hub))
            return cached

        # No servable cache → forced refresh. The lock serializes concurrent
        # first-loaders into a single recompute; each re-checks under the lock.
        result = await _maybe_refresh_spokes(hub, force=True)
        return result or {"spokes": []}

    @app.post("/setup/approve_spoke")
    async def approve_spoke(request: Request):
        """Approve or un-approve a spoke and optionally bind it to a tenant.

        Expects JSON {"spoke_id", "action": "approve"|"unapprove", "tenant_id"?}; a connected spoke
        is told at once.
        """
        # Read the spoke id and action; the id is required.
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            action = data.get("action", "approve")

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            # Un-approve: store the flag and drop queued messages.
            if action == "unapprove":
                hub.state.register_module(spoke_id, approved=False)
                hub.approved_modules[hub._primary_key(spoke_id)] = False
                # An un-approved spoke's session key is no longer valid for
                # outbound commands; drop queued messages so they don't retry
                # against it. Re-approval generates a fresh key + pushes.
                await hub.mailbox.clear_spoke(hub._primary_key(spoke_id))
            # Approve: store the flag.
            else:
                hub.state.register_module(spoke_id, approved=True)
                hub.approved_modules[hub._primary_key(spoke_id)] = True
                # Re-approval clears any prior revoke reason so the spokes/agents
                # module + tenant view stop showing a stale "revoked" badge.
                try:
                    hub.state.update_module_metadata(hub._primary_key(spoke_id), {
                        "revoked": False, "revoke_reason": "",
                        "revoked_ts": 0, "revoked_by": ""})
                except Exception:  # noqa: BLE001 — cosmetic; never block approval
                    pass

            # Spoke→tenant binding (admin assigns at approval time). Omitting
            # tenant_id leaves any existing binding untouched.
            tenant_id = data.get("tenant_id")
            if tenant_id is not None:
                hub.state.set_spoke_tenant(spoke_id, tenant_id)

            # Save state immediately.
            await hub.state.save_state_now()

            # Tell a connected spoke the result right away.
            if hub._primary_key(spoke_id) in hub.active_connections:
                if action != "unapprove":
                    # Generate a session secret for the spoke (idempotent — reuses existing key if present).
                    # Sign the key-delivery push with the secret the spoke currently holds (None = pending,
                    # it accepts anyway) so it can verify and install the new secret.
                    prev_secret = hub.key_manager.current_session_secret(hub._primary_key(spoke_id))
                    session_secret = hub.key_manager.generate_first_secret(hub._primary_key(spoke_id))
                    key_msg = _hub_msg(spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": session_secret})
                    await hub.send_to_spoke(key_msg, signing_secret=prev_secret)

                # Send APPROVED or DENIED.
                msg_type = "APPROVED" if action != "unapprove" else "DENIED"
                approval_msg = _hub_msg(spoke_id, msg_type, {})
                await hub.send_to_spoke(approval_msg)

                # After approval, push its config and ask for its version.
                if action != "unapprove":
                    await hub.push_config_to_spoke(spoke_id)
                    # Query the spoke's version now that it's approved + keyed,
                    # so a spoke approved AFTER connecting (not via PSK
                    # self-provision) still reports a version on the
                    # Diagnostics page without reconnecting. Mirrors the
                    # connect-time get_version in main.py. Best-effort.
                    try:
                        await hub.send_to_spoke(_hub_msg(spoke_id, "get_version", {}))
                    except Exception as e:
                        logger.error(f"Failed to request version from {spoke_id}: {e}")

            return {"status": "ok", "message": f"Spoke {spoke_id} {'approved' if action != 'unapprove' else 'un-approved'}."}
        # Let HTTP errors through unchanged; wrap anything else as a 500.
        except HTTPException:
            raise  # 4xx must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("approve_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            # Approval status + tenant binding are surfaced by /setup/pending_spokes;
            # bust so the WebUI reflects the change immediately.
            _bust_spokes_cache()

    # ── Product config pairs: cppm/pxmx/ldap/dns/dhcp (/setup/*-config) ───────
    @app.get("/setup/cppm-config")
    async def get_cppm_config():
        """Return the stored ClearPass (CPPM) settings."""
        # Read the cppm section of the global config.
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("cppm", {})
        return {"config": config}

    @app.post("/setup/cppm-config")
    async def update_cppm_config(request: Request):
        """Save the ClearPass (CPPM) settings and push them to the NAC spoke if connected."""
        # Read the new settings.
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Store them in the global config and mark state for saving.
            global_config = hub.state.system_state.get("global_config", {})
            global_config["cppm"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Push to the NAC spoke if connected; otherwise report a partial success.
            cppm_spoke = hub.get_spoke_by_type("nac")
            if cppm_spoke:
                msg = _hub_msg(cppm_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but CPPM spoke is not connected.", "pushed": False}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("update_cppm_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── NetBox → CPPM endpoint sync (hub-orchestrated) ──────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup →
    # NAC "NetBox → ClearPass Endpoint Sync" card. Config (enabled /
    # mode / interval_seconds / daily_time) is stored under
    # global_config["netbox_cppm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_endpoint_sync_loop) reads that same key.

    @app.post("/setup/endpoint-sync/run")
    async def run_endpoint_sync(request: Request):
        """On-demand NetBox → CPPM endpoint sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant; absent →
        all tenants bound to NetBox. Returns per-tenant results + a summary.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Sync one tenant if given, otherwise every NetBox-bound tenant.
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_endpoints(target)]
        else:
            results = [await hub.sync_tenant_endpoints(tid)
                       for tid in hub._endpoint_sync_tenants()]
        # Totals across tenants.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "tenants": len(results)}}

    @app.get("/setup/endpoint-sync/status")
    async def endpoint_sync_status(request: Request):
        """Per-tenant last-sync status for the Setup → NAC card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Build one status row per tenant.
        statuses = hub.simulations_store.get_all_endpoint_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "message": st.get("message", ""),
                "endpoints_total": st.get("endpoints_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
                "skipped_details": st.get("skipped_details", []),
            })
        return {"tenants": tenants}

    @app.get("/setup/endpoint-sync/sources")
    async def endpoint_sync_sources(request: Request):
        """List the available IPAM pull-sources for the sync source selector.

        Driven by Hub.IPAM_SOURCES so adding a product is a one-entry registry
        change and the WebUI dropdown picks it up with no client change.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # The source in use, plus every registered source and whether its spoke is connected.
        active = hub._endpoint_sync_source().get("module_type")
        sources = []
        for name, se in hub.IPAM_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        return {"active": active, "sources": sources}

    # ── Hypervisor → NetBox VM sync (hub-orchestrated) ───────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup → IPAM
    # "Hypervisor → NetBox VM Sync" card. Config (enabled / mode /
    # interval_seconds / daily_time) is stored under
    # global_config["pxmx_netbox_vm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_vm_sync_loop) reads that same key.

    @app.post("/setup/vm-sync/run")
    async def run_vm_sync(request: Request):
        """On-demand Hypervisor → NetBox VM sync ('Sync now').

        The sync is cluster-wide (one grab-all pull + one NetBox push); a body
        ``{"tenant_id": "<id>"}`` just selects which per-tenant row to return
        (the pull still grabs everything so the NetBox mirror stays complete).
        Absent → returns every per-tenant row + an unassigned row. Returns
        per-tenant results + a summary.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # One tenant's row if given; otherwise run the full sync and return every row.
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_vms(target)]
        else:
            agg = await hub.sync_all_vms()
            results = agg.get("results", []) or []
        # Totals across rows.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors,
                            "deleted": deleted, "tenants": len(results)}}

    @app.get("/setup/vm-sync/status")
    async def vm_sync_status(request: Request):
        """Per-tenant last-VM-sync status for the Setup → IPAM card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Build one status row per tenant.
        statuses = hub.simulations_store.get_all_vm_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "vms_total": st.get("vms_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/vm-sync/sources")
    async def vm_sync_sources(request: Request):
        """List the available hypervisor pull-sources for the sync source selector.

        Driven by Hub.HYPERVISOR_SOURCES so adding a product is a one-entry
        registry change and the WebUI dropdown picks it up with no client change.
        Also returns the connected pxmx agents (the actual Proxmox servers /
        clusters the sync can be scoped to) so the UI can list them and let the
        admin pick one instead of just the generic source type.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # The source in use, plus every registered source and whether its spoke is connected.
        active = hub._vm_sync_source().get("module_type")
        sources = []
        for name, se in hub.HYPERVISOR_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        # Connected pxmx agents — the real servers the sync pulls from. Empty
        # when the hypervisor spoke is down (sources[*].connected already flags
        # that; agents just enriches with the per-server detail).
        agents: list = []
        # Ask the hypervisor spoke for its agents; a failure leaves the list empty.
        pxmx_spoke = hub.get_hypervisor_spoke()
        if pxmx_spoke:
            try:
                r = await hub.request_response(pxmx_spoke, "GET_AGENTS", {}, timeout=30.0)
                # Unwrap the reply and keep the fields the UI shows.
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                for a in (d or {}).get("agents", []) if isinstance(d, dict) else []:
                    agents.append({
                        "agent_id":   a.get("agent_id", ""),
                        "hostname":   a.get("hostname", ""),
                        "cluster":    a.get("cluster_name", "") or a.get("hostname", ""),
                        "nodes":      a.get("nodes", []) or [],
                        "vm_count":   a.get("vm_count", 0) or 0,
                        "status":     a.get("status", "connected"),
                    })
            except Exception as e:
                logger.debug("vm_sync_sources: GET_AGENTS failed: %s", e)
        return {"active": active, "sources": sources, "agents": agents}

    # ── Firewall → NetBox device-discovery sync (Setup → Sync) ──
    # global_config["opnsense_netbox_device_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_fw_discovery_sync_loop) reads that same key.

    @app.post("/setup/fw-discovery-sync/run")
    async def run_fw_discovery_sync(request: Request):
        """On-demand Firewall → NetBox device-discovery sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/deleted/
        skipped/dropped_unattributed/discovered_total).
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # One tenant if given (its own counts), otherwise every tenant (aggregate counts).
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_devices(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            discovered = int(results[0].get("discovered_total_global", 0) or 0)
        else:
            agg = await hub.run_fw_discovery_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            discovered = int(agg.get("discovered_total", 0) or 0)
        # Totals across tenants.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped, "discovered_total": discovered}}

    @app.get("/setup/fw-discovery-sync/status")
    async def fw_discovery_sync_status(request: Request):
        """Per-tenant last firewall-discovery-sync status for the Setup → Sync card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Build one status row per tenant.
        statuses = hub.simulations_store.get_all_fw_discovery_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "discovered_total": st.get("discovered_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/fw-discovery-sync/sources")
    async def fw_discovery_sync_sources(request: Request):
        """List the available firewall pull-sources + the firewalls the sync can
        be scoped to, for the Setup → Sync source selector + firewall picker.

        Driven by Hub.FIREWALL_DISCOVERY_SOURCES so adding a product is a
        one-entry registry change and the WebUI dropdown picks it up with no
        client change. ``firewalls`` come from global_config["firewalls"]
        (each → {id, name, spoke_id, connected}) so the admin can pin the sync
        to one firewall. ``netbox_connected`` flags whether the sink is up.

        A synthetic ``"auto"`` entry is prepended — the default (unset
        ``source`` config) — which pulls+pushes EVERY connected registry
        source each cycle (see ``_fw_discovery_sources``), rather than only
        OPNsense. ``active`` lists every source name currently resolved by
        the live config (one name when pinned, every connected one for auto).
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Sources the current config resolves to, and which registered sources are connected.
        active = [name for name, _ in hub._fw_discovery_sources()]
        connected_names = [name for name, se in hub.FIREWALL_DISCOVERY_SOURCES.items()
                           if hub.get_all_spokes_by_type(se.get("module_type", ""))]
        # The synthetic "auto" choice comes first, then each registered source.
        sources = [{"name": "auto", "label": "Auto (every connected source)",
                   "module_type": "", "connected": bool(connected_names)}]
        for name, se in hub.FIREWALL_DISCOVERY_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_all_spokes_by_type(se.get("module_type", "")))})
        # Each configured firewall with its spoke and whether that spoke is connected.
        firewalls = []
        for fw in hub.state.system_state.get("global_config", {}).get("firewalls", []) or []:
            sid = fw.get("spoke_id") if isinstance(fw, dict) else None
            firewalls.append({
                "id": fw.get("id", "") if isinstance(fw, dict) else "",
                "name": fw.get("name", fw.get("id", "")) if isinstance(fw, dict) else "",
                "spoke_id": sid or "",
                "connected": bool(sid and hub._primary_key(sid) in getattr(hub, "active_connections", {})),
            })
        return {"active": active, "sources": sources, "firewalls": firewalls,
                "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    # ── Realtime NAC → IPAM reverse sync (Setup → Sync, "IPAM ↔ NAC Sync" card) ─
    # The bidirectional counterpart to the forward endpoint-sync routes above.
    # Pulls recent ClearPass Access Tracker sessions from the CPPM (NAC) spoke
    # and adds the MACs NetBox is missing (only-add-missing). See
    # RealtimeIpamNacSyncMixin (core/src/realtime_ipam_nac_sync.py). Config
    # toggle persists via POST /setup/config into
    # global_config["realtime_ipam_nac_sync"].
    @app.post("/setup/realtime-nac-sync/run")
    async def run_realtime_nac_sync(request: Request):
        """On-demand realtime NAC → IPAM reverse sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/skipped/
        deleted/dropped_unattributed/sessions_total).
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # One tenant if given (its own counts), otherwise every tenant (aggregate counts).
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_realtime(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            sessions_total = int(results[0].get("sessions_total_global", 0) or 0)
        else:
            agg = await hub.run_realtime_nac_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            sessions_total = int(agg.get("sessions_total", 0) or 0)
        # Totals across tenants.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped,
                            "sessions_total": sessions_total}}

    @app.get("/setup/realtime-nac-sync/status")
    async def realtime_nac_sync_status(request: Request):
        """Per-tenant last realtime-NAC-sync status for the Setup → Sync card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Build one status row per tenant.
        statuses = hub.simulations_store.get_all_realtime_nac_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "sessions_total": st.get("sessions_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/realtime-nac-sync/sources")
    async def realtime_nac_sync_sources(request: Request):
        """Connection state for the realtime reverse-sync card: whether the NAC
        (CPPM) pull source and the IPAM (netbox) push sink are connected."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return {"nac_connected": bool(hub.get_spoke_by_type("nac")),
                "ipam_connected": bool(hub.get_spoke_by_type("ipam"))}

    # ── NetBox staleness sweep (Setup → Sync, cluster-wide) ──────────────
    # global_config["staleness_sweep"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_staleness_sweep_loop) reads that same key.
    @app.post("/setup/staleness-sweep/run")
    async def run_staleness_sweep(request: Request):
        """On-demand NetBox staleness sweep ('Sweep now').

        Runs one cluster-wide sweep on the IPAM (netbox) spoke: devices/VMs not
        seen for ``stale_days`` → offline + decommissioned_at; offline + aged past
        ``delete_days`` → deleted (IPs free automatically); unassigned stale IPs →
        freed. Returns the spoke's result + a summary.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Run the sweep and summarise the result.
        result = await hub.run_staleness_sweep_all()
        return {"result": result,
                "summary": {"scanned": result.get("scanned", 0),
                            "decommissioned": result.get("decommissioned", 0),
                            "deleted": result.get("deleted", 0),
                            "ip_freed": result.get("ip_freed", 0),
                            "errors": result.get("errors", 0),
                            "status": result.get("status")}}

    @app.get("/setup/staleness-sweep/status")
    async def staleness_sweep_status(request: Request):
        """Last cluster-wide staleness-sweep status for the Setup → Sync card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return await hub.simulations_store.get_staleness_sweep_status()

    @app.post("/setup/netbox-dedupe/run")
    async def run_netbox_dedupe(request: Request):
        """Find (and optionally merge) duplicate NetBox devices sharing a serial
        or MAC — the pre-existing duplicates the unified sync ladder can't
        retroactively fix.

        POST ``{apply: bool, tenant_slug?: str}``. ``apply=false`` (default) is a
        DRY RUN that returns the duplicate groups it WOULD merge (survivor +
        duplicate ids) without changing anything; ``apply=true`` performs the
        merge (gap-only backfill onto the survivor, then delete the duplicates).
        Scope to one tenant via ``tenant_slug`` (empty = all).
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Dry run unless apply is true; optional tenant scope.
        apply = bool(body.get("apply", False))
        tenant_slug = str(body.get("tenant_slug") or "").strip()
        # NetBox must be connected.
        ipam = hub.get_spoke_by_type("ipam")
        if not ipam:
            return {"result": {"status": "error", "groups": [], "scanned": 0,
                               "merged": 0, "applied": apply,
                               "message": "NetBox spoke not connected"}}
        # Ask NetBox to find/merge duplicates (up to 3 minutes); failures are returned as errors.
        try:
            rr = await hub.request_response(
                ipam, "NETBOX_DEDUPE_DEVICES",
                {"apply": apply, "tenant_slug": tenant_slug}, timeout=180.0)
            rd = _unwrap_spoke(rr) if isinstance(rr, dict) else {}
        except Exception as e:
            logger.warning("[sync-error] netbox-dedupe failed: %s", e)
            return {"result": {"status": "error", "groups": [], "scanned": 0,
                               "merged": 0, "applied": apply, "message": str(e)}}
        # Log a warning when the run reported errors.
        if int((rd or {}).get("errors", 0) or 0) > 0:
            logger.warning("[sync-error] netbox-dedupe status=%s groups=%d merged=%d errors=%d — %s",
                           (rd or {}).get("status"), len((rd or {}).get("groups", [])),
                           (rd or {}).get("merged", 0), (rd or {}).get("errors", 0),
                           (rd or {}).get("message", ""))
        # Return NetBox's result.
        return {"result": rd or {}}

    # ── GitHub repo sync (Setup → Sync, replaces the old autoupdate loop) ───
    # global_config["repo_sync"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_repo_sync_loop) reads that same key.
    @app.post("/setup/repo-sync/run")
    async def run_repo_sync(request: Request):
        """On-demand GitHub repo sync ('Sync now').

        Pulls each hub-local ``provisioning_repos/*`` git repo, then runs the
        version-gated hub pull + ``SPOKE_UPDATE`` fan-out to every approved
        spoke (``perform_update``). The hub self-restarts only when its own
        code changed; spokes self-pull and restart on their own version change.
        Returns the per-repo results + the hub update result.

        Operator-initiated → ``force=True`` so any hub restart sentinel bypasses
        the maintenance-window/idle gate (restart now, not deferred). A no-op
        sync (already current, not stale) restarts nothing.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Run the full sync now and summarise per-repo outcomes.
        result = await hub.run_repo_sync_all(force=True)
        prov = result.get("provisioning_repos", []) or []
        return {"result": result,
                "summary": {"status": (result.get("hub") or {}).get("status"),
                            "provisioning_repos": len(prov),
                            "provisioning_repos_ok":
                                sum(1 for r in prov if r.get("status") == "ok"),
                            "provisioning_repos_error":
                                sum(1 for r in prov if r.get("status") == "error"),
                            "message": result.get("message")}}

    @app.get("/setup/repo-sync/status")
    async def repo_sync_status(request: Request):
        """Last GitHub repo-sync status for the Setup → Sync card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return await hub.simulations_store.get_repo_sync_status()

    # ── Spoke out-of-contact alerts (Setup → Sync) ───────────────────────
    # global_config["spoke_alert"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_spoke_alert_loop) reads that same key. This route exposes the
    # live active-alert list for the Sync sub-block; /status also carries the
    # count + list for the header badge (no extra polling).
    @app.get("/setup/spoke-alerts")
    async def spoke_alerts(request: Request):
        """Active spoke out-of-contact alerts (warning/error tiers) for the
        Setup → Sync card. Each entry: {spoke_id, tier, since_ts, duration_s,
        detail}."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return {"active_alerts": hub.get_active_spoke_alerts()}

    # ── Alert-state forensics (System → Hub Status) ──────────────────────────
    # The footer MODULE STATUS dot turns red on ANY active error-tier alert, and
    # /status merges several producers into one list (spoke out-of-contact +
    # relayed-agent out-of-contact + fleet availability). That makes "every
    # spoke is green but the dot is red" look like a contradiction when it isn't.
    # Worse, a relayed pxmx node-agent that leaks into approved_modules is keyed
    # in heartbeat under a COMPOSITE "{parent}:{agent_id}" key, so the alert
    # loop's bare-id lookup misses, the absent clock runs, and it escalates to a
    # permanent false "out of contact" for an agent the Agents table shows
    # online (spoke_alert_sync.py:296-311). This route dumps the raw state both
    # code paths read and pre-computes the verdicts, so the answer is on the page
    # instead of requiring a live Python shell on the hub. Read-only.
    # ── Spoke Registry Diagnostics ───────────────────────────────────────────
    # A rebuilt spoke that was never deregistered leaves its OLD id in hub state,
    # still tenant-bound and still ELECTABLE. get_client_sim_spoke() returns
    # bound[0] over the CONNECTED candidates (hub_spoke_registry.py:441), so with
    # several cs spokes on one tenant the broker flips cycle to cycle: the same
    # host logs a different cs_spoke minutes apart, and the quota reconcile reads
    # a different effective set each pass and never converges ("STILL stale after
    # 3 re-push(es)"). The operator often CANNOT clean this up from the Spokes
    # list, because a registration with no tenant_id is admin-only in
    # spoke_visible_to_session() (access.py:859) while get_client_sim_spoke()
    # will still claim it for a tenant (hub_spoke_registry.py:446). This route is
    # the authoritative enumeration — every registration, whether or not the
    # caller's tenant view would show it — plus the elected broker per tenant so
    # a flip is visible rather than inferred. Read-only; deletion goes through
    # the existing DELETE /setup/spokes/{id}.
    @app.get("/setup/spoke-registry-diag")
    async def spoke_registry_diag(request: Request):
        """Every spoke registration the hub holds, with the ghost/visibility/
        broker-election facts needed to tell a live spoke from a leftover.
        Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")

        def _safe_tenant(h, sid):
            """Return the tenant bound to spoke ``sid``, or "" on any error."""
            try:
                return h.state.get_spoke_tenant(sid) or ""
            except Exception:                       # noqa: BLE001 — diag never 500s
                return ""

        # Snapshot every store a registration can live in.
        now = time.time()
        md = (hub.state.system_state.get("module_metadata", {}) or {})
        approved = hub.approved_modules or {}
        conns = getattr(hub, "active_connections", {}) or {}
        types = getattr(hub, "spoke_module_types", {}) or {}
        # Ids that hold a session key, and last heartbeat times; errors mean empty.
        try:
            keys = set((hub.key_manager.keys or {}).keys())
        except Exception:                               # noqa: BLE001 — diag never 500s
            keys = set()
        try:
            last_seen = dict(hub.heartbeat.last_seen or {})
        except Exception:                               # noqa: BLE001
            last_seen = {}

        # Union of every store a registration can live in — a ghost is usually
        # missing from some of them, so intersecting would hide the thing we are
        # looking for.
        ids = set(md) | set(approved) | set(conns) | set(types)

        # One output row per registration.
        rows = []
        # Liveness for RELAYED node agents, keyed by agent primary key. Same
        # source the alert producer uses, so the two can never disagree.
        import time as _t
        _now = _t.time()
        _RELAY_LIVE_S = 300          # matches the spoke alert warn threshold
        try:
            _relayed_last = hub._relayed_agent_last_seen()
        except Exception:            # noqa: BLE001 — never break the page
            _relayed_last = {}
        # Every id the hub knows as a relayed node agent (agent_config /
        # agent_info / composite heartbeats), minus device-mode agents that
        # hold their own socket — the SAME predicate the alert self-heal uses.
        try:
            _relay_ids = hub._relayed_agent_ids()
        except Exception:            # noqa: BLE001
            _relay_ids = set()
        try:
            _direct_ids = _direct_module_ids(hub.state.system_state)
        except Exception:            # noqa: BLE001
            _direct_ids = set()
        # Durable name → guid map for relayed agents. The in-memory
        # agent_id_alias is only re-armed when an agent next relays in, so
        # after a hub restart it is empty and a raw-name row (left behind in
        # module_metadata by the old approved_modules leak) cannot reach its
        # guid-keyed agent_config / heartbeat state without this.
        _agent_name_guid = _agent_name_to_guid(
            hub.state.system_state.get("agent_config") or {},
            getattr(hub, "agent_info", {}) or {})

        # Build a row for each registration.
        for sid in sorted(ids):
            # Stored metadata and tenant for this id.
            meta = md.get(sid) or {}
            tenant = meta.get("tenant_id") or ""
            # Resolve the primary key; on error use the raw id.
            try:
                pk = hub._primary_key(sid)
            except Exception:                           # noqa: BLE001
                pk = sid
            # Last heartbeat and whether it holds a socket now.
            seen = last_seen.get(pk) or last_seen.get(sid)
            connected = sid in conns
            # RELAYED node agents (pxmx/cs) are never in active_connections and
            # never carry a bare heartbeat key — they dial their PARENT SPOKE and
            # are tracked under the composite {spoke_pk}:{agent_pk} key. Testing
            # them with the spoke-only lookups above reported four agents that
            # were Online and seen 36s ago as "offline · no session key · never",
            # directly contradicting Spokes & Agents on the same screen.
            # Same blind spot already fixed on the agent card, the out-of-contact
            # alerts and the dashboard tile; this is the fourth surface.
            # Agent state is keyed by the AGENT alias (name → install guid),
            # not the spoke alias: once an agent is guid-migrated a row still
            # registered under its raw name ("mipbe-ssplm-pxmx01") found no
            # relay traffic via pk/sid and read "offline · no key · never"
            # (the dashboard tile had the same bug, fixed with this lookup).
            # Resolve the agent key, falling back to the durable name -> guid map.
            try:
                apk = hub._agent_primary_key(sid)
            except Exception:                           # noqa: BLE001
                apk = sid
            if apk == sid:
                apk = _agent_name_guid.get(sid, sid)
            # Latest relay time, and whether this id is a relayed agent.
            _agent_last = _agent_last_seen_for(_relayed_last, pk, apk, sid)
            is_relayed_agent = bool(_agent_last) or any(
                _is_relayed_agent(k, _relay_ids, _direct_ids) for k in {sid, pk, apk})
            # For relayed agents, use relay traffic as last-seen and liveness.
            if is_relayed_agent:
                if _agent_last and (not seen or _agent_last > seen):
                    seen = _agent_last
                # Fresh relay traffic IS the agent's liveness — it has no socket
                # of its own to be "connected" on.
                connected = connected or bool(_agent_last and (_now - _agent_last) < _RELAY_LIVE_S)
            # Whether a session key exists under either id.
            has_key = sid in keys or pk in keys
            # "Approve → never reports in": an APPROVED registration that has
            # NEVER been seen, holds NO session key, is NOT connected and is NOT
            # a relayed agent is stuck. Approval only mints + pushes a session
            # key when the spoke is in active_connections (setup.approve_spoke /
            # main.handle_connection zero-touch branch); approve a spoke that was
            # not connected at the time and nothing is keyed, and a host-only
            # registration (module_type "—", never its own socket) has no
            # zero-touch reconnect to re-key on either. The row then sits at
            # offline / no key / never with only a Delete action, and the ONLY
            # way out is to delete it everywhere so the box can re-present for
            # approval while connected — exactly the operator report. The
            # duplicate/visibility checks never covered this, so the page
            # (mis)reported "no problems detected".
            stuck_never_keyed = _is_stuck_never_keyed(
                approved.get(sid, False), connected, has_key,
                is_relayed_agent, seen)
            # Human-readable reasons this row may be a ghost.
            reasons = []
            if not connected:
                reasons.append("not connected")
            elif is_relayed_agent:
                reasons.append("relayed agent (no own socket — liveness via parent spoke)")
            if not has_key and not is_relayed_agent:
                reasons.append("no session key")
            # Relayed agents are never approved as modules (approval lives on
            # the parent spoke), so "not approved" is not a fault for them.
            if not approved.get(sid, False) and not is_relayed_agent:
                reasons.append("not approved")
            if stuck_never_keyed:
                reasons.append("approved but never seen / never keyed — "
                               "delete everywhere and re-approve while connected")
            # Add the row.
            rows.append({
                "spoke_id": sid,
                "module_type": types.get(sid) or meta.get("module_type") or "",
                "tenant_id": tenant,
                "install_uuid": (meta.get("install_uuid") or "")[:8],
                "hostname": meta.get("hostname") or "",
                "approved": bool(approved.get(sid, False)),
                "connected": connected,
                # A relayed agent has no session key of its own (its parent
                # spoke holds it), so "no key" is normal for these and must not
                # read as a fault.
                "is_relayed_agent": is_relayed_agent,
                "has_key": has_key,
                # Stuck "approve → never reports in" signature (see above). The
                # WebUI can surface a "Delete & re-approve" hint on these rows.
                "stuck_never_keyed": stuck_never_keyed,
                "last_seen": seen,
                "last_seen_age_s": int(now - seen) if seen else None,
                # The exact rule the Spokes list applies: no tenant_id → only an
                # admin session sees the row. This column is what explains
                # "I deleted everything I could see and it still flaps".
                "admin_only": not tenant,
                # Advisory, never automatic: a live spoke is simply one that is
                # connected. Everything else is a deletion CANDIDATE for a human.
                "ghost_candidate": not connected,
                "ghost_reasons": reasons,
                # Filled in below once every row is known.
                "legacy_twin_of": "",
            })

        # ── Pre-rename twins ────────────────────────────────────────────────
        # The cs spoke derived its id as "<hostname>-spoke" from 2026-07-02
        # (cs 5259950) until 2026-07-20 (cs ab7176d, "derive spoke id as bare
        # hostname"). A box that ran across that change therefore holds TWO
        # registrations for one machine — "cs-svr-02-spoke" and "cs-svr-02".
        # install_uuid correlation would normally migrate the old id onto the
        # new one, but it cannot when the UUID was regenerated in between (a
        # --purge-env / rebuild), so the pre-rename record survives as an
        # orphan: usually tenant-less and disconnected, yet still holding the
        # host/USB telemetry it accumulated. The hub keeps rendering that, so
        # hosts appear under a spoke that no longer runs them and the fleet
        # looks like it is fighting over ownership. Name the pair here; the
        # operator decides, we never auto-delete a registration.
        _by_id = {r["spoke_id"] for r in rows}
        # Mark "<name>-spoke" rows whose bare "<name>" row also exists.
        for r in rows:
            sid = r["spoke_id"]
            if sid.endswith("-spoke") and sid[: -len("-spoke")] in _by_id:
                r["legacy_twin_of"] = sid[: -len("-spoke")]
                r["ghost_reasons"] = list(r["ghost_reasons"]) + ["pre-rename twin"]

        # Broker election per tenant, using the SAME helper the cs bridge calls,
        # so the page shows what the bridge will actually pick — not a re-derived
        # guess that could disagree with it.
        # Client-sim spokes and the tenants they are bound to.
        cs_ids = {r["spoke_id"] for r in rows
                  if (r["module_type"] or "").lower() in ("client-sim", "simulation")}
        brokers = {}
        tenants = {r["tenant_id"] for r in rows if r["spoke_id"] in cs_ids}
        # Tenantless spokes are not a tenant.
        tenants.discard("")
        # For each tenant, record the elected broker and the eligible connected candidates.
        for t in sorted(tenants):
            # Ask the same election the cs bridge uses; a failure means none elected.
            try:
                elected = hub.get_client_sim_spoke(t)
            except Exception as e:                      # noqa: BLE001
                logger.debug("[registry-diag] election for %s failed: %s", t, e)
                elected = None
            # Connected, approved cs spokes bound to this tenant or to no tenant.
            cands = [r["spoke_id"] for r in rows
                     if r["spoke_id"] in cs_ids and r["connected"]
                     and r["approved"] and (r["tenant_id"] == t or not r["tenant_id"])]
            brokers[t] = {
                "elected": elected,
                "candidates": cands,
                # >1 connected candidate is now informational, not a fault: the
                # election is sticky (hub_spoke_registry._sticky_cs_broker), so
                # the broker holds until the incumbent stops being eligible.
                "multiple": len(cands) > 1,
            }

        # Plain-English findings for the operator.
        findings = []
        # Several eligible brokers for one tenant.
        for t, b in brokers.items():
            if b["multiple"]:
                findings.append(
                    f"Tenant {t!r} has {len(b['candidates'])} connected Client-Sim spokes. "
                    f"The broker is pinned to {b['elected']} and only moves if that spoke "
                    f"stops being connected/approved/bound — a reconnect elsewhere no longer "
                    f"reassigns it. Extra spokes are still worth pruning if they are leftovers.")
        # Registrations with no tenant (visible to Global Admins only).
        hidden = [r["spoke_id"] for r in rows if r["admin_only"]]
        if hidden:
            findings.append(
                f"{len(hidden)} registration(s) have no tenant_id — invisible in a "
                f"non-admin Spokes list, yet still claimable as a tenant's broker. "
                f"They can only be found and deleted from an admin session.")
        # Disconnected Client-Sim registrations.
        ghosts = [r["spoke_id"] for r in rows if r["ghost_candidate"] and r["spoke_id"] in cs_ids]
        if ghosts:
            findings.append(
                f"{len(ghosts)} Client-Sim registration(s) are not connected — the usual "
                f"signature of a rebuilt box whose old id was never deregistered. "
                f"Confirm the box is gone, then delete.")
        # Pre-rename twins.
        twins = [r for r in rows if r["legacy_twin_of"]]
        if twins:
            findings.append(
                "Pre-rename twins found: " + ", ".join(
                    f"{r['spoke_id']} → {r['legacy_twin_of']}" for r in twins) +
                ". The cs spoke derived its id as '<hostname>-spoke' until 2026-07-20; each "
                "of these is the SAME box as the id on the right, registered twice. The old "
                "record still holds host/USB telemetry, so hosts show up under a spoke that "
                "no longer runs them. Delete the '-spoke' side once its twin is connected.")
        # Approved-but-never-keyed registrations.
        stuck = [r["spoke_id"] for r in rows if r.get("stuck_never_keyed")]
        if stuck:
            findings.append(
                f"{len(stuck)} registration(s) are approved but have NEVER been seen, hold no "
                f"session key and are not connected: " + ", ".join(stuck) + ". Approval only "
                f"mints and pushes a session key while the spoke is connected, so approving one "
                f"that was offline (or a host-only registration with no socket of its own) keys "
                f"nothing and it stays offline / no key / never — clicking Approve never makes it "
                f"report in. Delete each one everywhere, then let the box reconnect and approve it "
                f"WHILE it is connected.")
        # Say so when nothing was found.
        if not findings:
            findings.append("No duplicate-registration or visibility problems detected.")

        # ── Orphaned telemetry ──────────────────────────────────────────────
        # simulations_cache is keyed by spoke id and PERSISTS independently of
        # the registration table. Deleting a spoke pops its entry
        # (hub_spoke_registry._evict_spoke_caches), but an id that exists ONLY
        # in the cache — a spoke whose id changed under it, e.g. the cs
        # "<hostname>-spoke" era before 2026-07-20 — is unreachable that way:
        # DELETE /setup/spokes/<id> has no registration to act on. The entry
        # then keeps claiming the proxmox_hosts it last reported, so those
        # hosts render under a spoke that no longer runs them and the fleet
        # looks like it is fighting over ownership. Surface them separately —
        # they are NOT spokes and must not be mixed into the rows above.
        # Cached telemetry whose id is not any registration.
        orphans = []
        for sid, data in (getattr(hub, "simulations_cache", {}) or {}).items():
            # Skip ids that are real registrations.
            if sid in ids:
                continue
            # List the hostnames this orphan still claims.
            data = data or {}
            hosts = data.get("proxmox_hosts")
            hostnames = ([(h or {}).get("hostname") or "?" for h in hosts]
                         if isinstance(hosts, list) else [])
            orphans.append({
                "spoke_id": sid,
                "hosts": hostnames,
                "host_count": len(hostnames),
                "tenant_id": _safe_tenant(hub, sid),
            })
        # Sort orphans by id and report them.
        orphans.sort(key=lambda o: o["spoke_id"])
        if orphans:
            findings.append(
                f"{len(orphans)} cached telemetry entr(ies) belong to spoke id(s) that no "
                f"longer exist: " + ", ".join(
                    f"{o['spoke_id']} (claims {o['host_count']} host(s))" for o in orphans) +
                ". These are NOT registrations — deleting a spoke cannot reach them — so the "
                "hosts they claim keep rendering under an id that no longer runs them. "
                "Purge them below.")

        # Return everything for the diagnostics page.
        return {"generated": now, "rows": rows, "brokers": brokers,
                "orphan_telemetry": orphans, "findings": findings}

    @app.post("/setup/spoke-registry-diag/purge-telemetry")
    async def purge_orphan_telemetry(request: Request):
        """Drop cached telemetry for ids that are not registered spokes.

        Refuses any id that IS a live registration — that entry is real data
        for a real spoke, and this route exists only to reap the unreachable
        leftovers. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the ids to purge; at least one is required.
        body = await request.json()
        want = [str(x) for x in (body.get("ids") or [])]
        if not want:
            raise HTTPException(status_code=400, detail="ids required")

        # Every id that is a real registration in any store.
        md = (hub.state.system_state.get("module_metadata", {}) or {})
        known = (set(md) | set(hub.approved_modules or {})
                 | set(getattr(hub, "active_connections", {}) or {})
                 | set(getattr(hub, "spoke_module_types", {}) or {}))
        cache = getattr(hub, "simulations_cache", {}) or {}
        # Drop each orphan from the cache; refuse real registrations.
        purged, refused = [], []
        for sid in want:
            if sid in known:
                refused.append(sid)          # a real spoke — never reap from here
                continue
            if cache.pop(sid, None) is not None:
                purged.append(sid)
        # Save the cache to disk if anything changed; failure only logs.
        if purged:
            try:
                await asyncio.to_thread(hub._save_simulations_cache)
            except Exception as e:           # noqa: BLE001 — in-memory drop already took
                logger.warning("[registry-diag] purged %s but could not persist: %s",
                               purged, e)
            logger.warning("[registry-diag] purged orphan telemetry for %s", purged)
        return {"status": "ok", "purged": purged, "refused": refused}

    @app.get("/setup/alert-diagnostics")
    async def alert_diagnostics(request: Request):
        """Forensics for the footer alert badge: every active alert tagged with
        its PRODUCER, the raw id sets both the alert loop and the Spokes & Agents
        filter compare against, and computed ``findings`` naming any false
        positive / stale-state condition. Admin only."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")

        def _safe(fn, default):
            """Call ``fn()`` and return its result, or ``default`` if it raises."""
            try:
                return fn()
            except Exception as e:                      # noqa: BLE001 — diag never 500s
                logger.debug("[alert-diag] %s failed: %s", getattr(fn, "__name__", fn), e)
                return default

        # Snapshot the approval, relay-agent and alert state the alert loop reads.
        now = time.time()
        approved = {s for s, a in (hub.approved_modules or {}).items() if a}
        relay_ids = _safe(hub._relayed_agent_ids, set())
        # Device-mode agents dial the hub directly, so they are BOTH a module
        # spoke (own WebSocket, must stay approved) and an agent_config/
        # agent_info entry that _relayed_agent_ids() matches. The self-heal
        # subtracts them; this view must use the SAME predicate or it reports
        # every healthy device-mode agent as a self-heal failure forever.
        direct_module_ids = _safe(
            lambda: _direct_module_ids(hub.state.system_state), set())
        spoke_alerts = dict(getattr(hub, "_spoke_alerts", {}) or {})
        tier_map = dict(getattr(hub, "_spoke_alert_tier", {}) or {})
        absent = dict(getattr(hub, "_spoke_absent_since", {}) or {})
        last_seen = dict(getattr(hub.heartbeat, "last_seen", {}) or {})
        connected = set(getattr(hub, "active_connections", {}) or {})
        # Persisted copy — hub.approved_modules is normally the SAME object
        # (main.py:330 → manager.get_approved_modules), but a self-heal pop that
        # never marks state dirty (or a get() that returned a fresh dict) makes
        # these diverge, which is how an evicted agent id comes BACK on restart.
        persisted = {s for s, a in ((hub.state.system_state.get("approved_modules") or {})
                                    ).items() if a}

        # Alert thresholds (warn/error seconds) and alert config.
        warn_s, error_s = _safe(hub._spoke_alert_thresholds, (300, 1800))
        cfg = _safe(hub._spoke_alert_cfg, {})

        # ── DHCP role-capability probe ───────────────────────────────────────
        # Live DHCP_HA_STATUS for every connected, approved dhcp spoke. Best
        # effort and bounded: a spoke that fails to answer maps to None, which
        # _dhcp_ha_member_count reads as "unknown" (never as "empty"), so an
        # unreachable spoke cannot raise the finding below.
        dhcp_spokes = sorted(
            s for s in _safe(lambda: hub.get_all_spokes_by_type("dhcp") or [], [])
            if hub._primary_key(s) in (getattr(hub, "active_connections", {}) or {})
            and (hub.approved_modules or {}).get(s, False))
        # Ask every connected dhcp spoke in parallel; failures become None (unknown).
        dhcp_ha = {}
        if dhcp_spokes:
            replies = await asyncio.gather(*[
                hub.request_response(sid, "DHCP_HA_STATUS", {}, timeout=15.0)
                for sid in dhcp_spokes], return_exceptions=True)
            for sid, reply in zip(dhcp_spokes, replies):
                if isinstance(reply, BaseException):
                    logger.debug("[alert-diag] DHCP_HA_STATUS %s failed: %s", sid, reply)
                    dhcp_ha[sid] = None
                else:
                    dhcp_ha[sid] = _unwrap_spoke(reply)
        # Spokes reporting an empty Kea cluster.
        clusterless = _dhcp_spokes_without_cluster(dhcp_ha)
        # The spoke a tenantless admin read actually lands on.
        default_dhcp = _safe(lambda: hub.get_spoke_by_type("dhcp"), None)

        # Composite heartbeat keys, grouped by the agent-id tail the alert loop
        # FAILS to match (the bare id) — the direct evidence for a false positive.
        # Group composite heartbeat keys by agent id.
        composite = {}
        for k in last_seen:
            if ":" in k:
                parent, tail = k.split(":", 1)
                composite.setdefault(tail, []).append(
                    {"key": k, "parent": parent,
                     "age_s": int(max(0.0, now - (last_seen.get(k) or now)))})

        # Every active alert, tagged with the module that produced it.
        # Collect alerts from each producer that exists on this hub.
        alerts = []
        for src, getter in (("spoke_out_of_contact", "get_active_spoke_alerts"),
                            # Relayed node agents — the producer the spoke sweep
                            # cannot see. Without it this forensics view showed
                            # "no alerts" during a total agent outage.
                            ("agent_out_of_contact", "get_agent_alerts"),
                            ("fleet_availability", "get_fleet_alerts")):
            fn = getattr(hub, getter, None)
            if not fn:
                continue
            for a in _safe(fn, []):
                alerts.append({**a, "source": src})

        # Per-alert forensics for the spoke producer only (fleet/dongle alerts
        # are synthetic keys with no heartbeat/approval to cross-check).
        # One forensics row per spoke out-of-contact alert.
        rows = []
        for sid, a in spoke_alerts.items():
            rows.append({
                "spoke_id": sid,
                "tier": a.get("tier"),
                "detail": a.get("detail", ""),
                "duration_s": int(a.get("duration_s", 0) or 0),
                "is_approved": sid in approved,
                "is_relayed_agent": _is_relayed_agent(sid, relay_ids, direct_module_ids),
                "heartbeat_bare": last_seen.get(sid),
                "heartbeat_composite": composite.get(sid, []),
                "is_connected": sid in connected,
                "absent_since": absent.get(sid),
                "latched_tier": tier_map.get(sid),
            })
        # Errors first, then by id.
        rows.sort(key=lambda r: (r["tier"] != "error", r["spoke_id"]))

        # ── verdicts ─────────────────────────────────────────────────────────
        findings = []

        def _add(code, severity, detail, ids):
            """Add a finding with ``code``, ``severity`` and ``detail`` when ``ids`` is non-empty.
            """
            if ids:
                findings.append({"code": code, "severity": severity,
                                 "detail": detail, "ids": sorted(ids)})

        _add("relayed_agent_false_positive", "error",
             "Relayed node-agent has an active out-of-contact alert. Its heartbeat "
             "lives under a composite '{parent}:{agent_id}' key, so the alert loop's "
             "bare-id lookup returns None and the absent clock escalates it — the "
             "Agents table shows it ONLINE. Not a real outage.",
             {r["spoke_id"] for r in rows if r["is_relayed_agent"]})

        _add("leaked_agent_approved", "warning",
             "Relayed node-agent id is still in approved_modules; the alert loop "
             "self-heal (_selfheal_leaked_agents) should have popped it.",
             _leaked_approved_agent_ids(approved, relay_ids, direct_module_ids))

        _add("alert_without_approval", "warning",
             "Active alert for an id that is no longer approved — orphaned entry in "
             "_spoke_alerts that no loop iteration will clear (the loop only walks "
             "approved ids).",
             {r["spoke_id"] for r in rows if not r["is_approved"]})

        _add("latched_tier_without_alert", "warning",
             "_spoke_alert_tier still holds warning/error with no matching "
             "_spoke_alerts entry. If the id re-enters approved_modules the loop "
             "reads tier == current, takes the no-transition branch, and RE-ARMS "
             "the alert instead of clearing it.",
             {s for s, t in tier_map.items()
              if t in ("warning", "error") and s not in spoke_alerts})

        _add("approved_persist_drift", "warning",
             "In-memory approved_modules disagrees with the persisted copy. A "
             "self-heal eviction that was never marked dirty returns on the next "
             "hub restart — the alert then re-fires after the error threshold.",
             approved ^ persisted)

        _add("connected_but_alerting", "warning",
             "Spoke holds a live hub connection yet has an active out-of-contact "
             "alert.",
             {r["spoke_id"] for r in rows if r["is_connected"]})

        _add("dhcp_spoke_without_cluster", "warning",
             "DHCP spoke advertises the 'dhcp' role but manages no Kea cluster "
             "(DHCP_HA_STATUS reported zero members). It has nothing to answer "
             "for, so any DHCP read routed to it reports the whole DHCP service "
             "as down. Either configure its HA pair or unload the stray 'dhcp' "
             "role from that host.",
             clusterless)

        _add("dhcp_default_spoke_without_cluster", "error",
             "The dhcp spoke that answers a tenantless admin read manages no Kea "
             "cluster. _dhcp_spoke_for_request falls through to "
             "get_spoke_by_type('dhcp'), which returns the FIRST dhcp spoke in "
             "spoke_module_types insertion order — not the healthiest one — so "
             "Diagnostics / Overview / Status are reporting on a host with no "
             "Kea while a real HA pair is up. Not a DHCP outage.",
             {default_dhcp} & clusterless if default_dhcp else set())

        # Friendly names for every id the card renders (lookup rows + finding
        # ids), so the WebUI never has to show a bare UUID.
        name_of = getattr(hub, "_alert_display_name", None) or (lambda s: s)
        shown = {r["spoke_id"] for r in rows}
        for f in findings:
            shown.update(f["ids"])
        names = {s: _safe(lambda s=s: name_of(s), s) for s in shown if s}

        # Return the alerts, forensics rows, findings and supporting evidence.
        return {
            "generated_ts": now,
            "names": names,
            "config": {"enabled": bool(cfg.get("enabled", False)),
                       "warn_s": warn_s, "error_s": error_s},
            "counts": {
                "approved": len(approved),
                "relay_ids": len(relay_ids),
                "spoke_alerts": len(spoke_alerts),
                "alerts_total": len(alerts),
                "by_source": {s: sum(1 for a in alerts if a["source"] == s)
                              for s in ("spoke_out_of_contact", "agent_out_of_contact",
                                        "fleet_availability")},
            },
            "alerts": alerts,
            "spoke_alert_rows": rows,
            "findings": findings,
            "approved_ids": sorted(approved),
            "relay_ids": sorted(relay_ids),
            # Evidence for the two dhcp_* findings: what each dhcp spoke
            # reported, and which one the tenantless read path selects.
            "dhcp_cluster": {
                "default_spoke": default_dhcp,
                "members": {sid: _dhcp_ha_member_count(st)
                            for sid, st in dhcp_ha.items()},
            },
        }

    # ── Network Devices → NetBox device-discovery sync (Setup → Sync) ──
    # global_config["nw_netbox_device_sync"] is saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_nw_discovery_sync_loop) reads that same key.
    @app.post("/setup/nw-discovery-sync/run")
    async def run_nw_discovery_sync(request: Request):
        """On-demand Network Devices → NetBox device-discovery sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/skipped/
        deleted/dropped_unattributed/discovered_total).
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # A missing or invalid JSON body is treated as empty.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # One tenant if given (its own counts), otherwise every tenant (aggregate counts).
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_nw_devices(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            discovered = int(results[0].get("discovered_total_global", 0) or 0)
        else:
            agg = await hub.run_nw_discovery_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            discovered = int(agg.get("discovered_total", 0) or 0)
        # Totals across tenants.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped,
                            "discovered_total": discovered}}

    @app.get("/setup/nw-discovery-sync/status")
    async def nw_discovery_sync_status(request: Request):
        """Per-tenant last nw-discovery-sync status for the Setup → Sync card."""
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Build one status row per tenant.
        statuses = hub.simulations_store.get_all_nw_discovery_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "discovered_total": st.get("discovered_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/nw-discovery-sync/sources")
    async def nw_discovery_sync_sources(request: Request):
        """Available nw pull-sources + the network devices the sync can be scoped
        to, for the Setup → Sync source selector + device picker.

        Driven by ``hub.NW_DISCOVERY_SOURCES`` so adding a network-device product
        is a one-entry registry change and the WebUI dropdown picks it up with no
        client change. ``devices`` come from ``global_config["nw_devices"]``
        (each → {id, name, spoke_id, connected}) so the admin can pin the sync.
        ``netbox_connected`` flags whether the IPAM sink is up.
        """
        hub = app.state.hub
        # Only Global Admins may do this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # The source in use, plus every registered source and whether its spokes are connected.
        active = hub._nw_discovery_source().get("module_type")
        sources = []
        for name, se in hub.NW_DISCOVERY_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_all_spokes_by_type(se.get("module_type", "")))})
        # Each configured network device with its spoke and whether that spoke is connected.
        devices = []
        for d in hub.state.system_state.get("global_config", {}).get("nw_devices", []) or []:
            sid = d.get("spoke_id") if isinstance(d, dict) else None
            devices.append({
                "id": d.get("id", "") if isinstance(d, dict) else "",
                "name": d.get("name", d.get("id", "")) if isinstance(d, dict) else "",
                "spoke_id": sid or "",
                "connected": bool(sid and hub._primary_key(sid) in getattr(hub, "active_connections", {})),
            })
        return {"active": active, "sources": sources, "devices": devices,
                "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    @app.get("/setup/pxmx-config")
    async def get_pxmx_config():
        """Return the stored Proxmox settings, or defaults when unset."""
        # Read the pxmx section of the global config, with defaults.
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("pxmx", {
            "default_node": "pve",
            "cluster_id": "cluster-1"
        })
        return {"config": config}

    @app.post("/setup/pxmx-config")
    async def update_pxmx_config(request: Request):
        """Save the Proxmox settings and push them to the hypervisor spoke if connected."""
        # Read the new settings.
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Store them in the global config and mark state for saving.
            global_config = hub.state.system_state.get("global_config", {})
            global_config["pxmx"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Push to the hypervisor spoke if connected; otherwise report a partial success.
            pxmx_spoke = hub.get_hypervisor_spoke()
            if pxmx_spoke:
                msg = _hub_msg(pxmx_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but Proxmox spoke is not connected.", "pushed": False}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("update_pxmx_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # NOTE: /setup/ldap-config (GET+POST) used to be defined here as well.
    # Starlette dispatches to the FIRST matching route and this module is
    # registered before routes/ldap.py, so this copy silently shadowed the
    # real one -- returning the stored config verbatim (leaking the plaintext
    # admin_pw to the browser) and skipping base-DN/admin-DN validation and
    # the blank-password-keeps-existing rule. Removed; routes/ldap.py owns it.

    @app.get("/setup/dns-config")
    async def get_dns_config():
        """Return the stored DNS/Unbound configuration (global_config.dns)."""
        # Read the dns section of the global config.
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dns", {})
        return {"config": config}

    @app.post("/setup/dns-config")
    async def update_dns_config(request: Request):
        """Save the DNS settings in the global config (not pushed to spokes here)."""
        # Read the new settings, store them and mark state for saving.
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dns"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            return {"status": "ok"}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("update_dns_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/dhcp-config")
    async def get_dhcp_config():
        """Return the stored DHCP/Kea configuration (global_config.dhcp)."""
        # Read the dhcp section of the global config.
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dhcp", {})
        return {"config": config}

    @app.post("/setup/dhcp-config")
    async def update_dhcp_config(request: Request):
        """Save the DHCP settings in the global config (not pushed to spokes here)."""
        # Read the new settings, store them and mark state for saving.
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dhcp"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            return {"status": "ok"}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("update_dhcp_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-metadata")
    async def update_spoke_metadata(request: Request):
        """Merge new metadata (e.g. display name, hostname) into a known spoke's record.

        Expects JSON {"spoke_id": ..., "metadata": {...}}.
        """
        # Read the spoke id and metadata; the id is required.
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            metadata = data.get("metadata", {})

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            # The spoke must be known.
            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail=f"Spoke '{spoke_id}' not found in known_modules: {known_modules}")

            # Merge the metadata and mark state for saving.
            hub.state.update_module_metadata(spoke_id, metadata)
            hub.state._mark_dirty()

            return {"status": "ok", "message": f"Metadata for spoke {spoke_id} updated."}
        # Let HTTP errors through unchanged; wrap anything else as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Error updating spoke metadata")
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            # display_name / hostname edits are surfaced by /setup/pending_spokes.
            _bust_spokes_cache()

    @app.get("/setup/spoke-metadata/{spoke_id}")
    async def get_spoke_metadata(spoke_id: str):
        """Return the stored metadata for one spoke, or 404."""
        # Read the spoke's metadata.
        hub = app.state.hub
        metadata = hub.state.system_state.get("module_metadata", {}).get(spoke_id, {})
        if not metadata:
            raise HTTPException(status_code=404, detail="Spoke metadata not found")
        return {"metadata": metadata}

    @app.get("/setup/firewalls")
    async def get_firewalls(request: Request):
        """List configured firewalls the caller may see.

        Global Admins see all; others see their own tenants' and shared firewalls.
        """
        # Read every configured firewall.
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        # Tenant-scope the DEVICE list: a non-admin sees firewalls in the shared
        # tenant + their own tenant(s); a firewall bound to another tenant, or
        # unassigned, is hidden (admin-only). Object-level rule filtering
        # (_filter_fw) and the write gate are unchanged. Admins see all.
        sess = _session_user(request)
        if not _is_admin(sess):
            firewalls = [f for f in firewalls
                         if _spoke_visible(sess, (f or {}).get("tenant_id", ""))]
            # A tenant with its own firewall no longer sees the shared ones.
            # access holds the tenant/firewall ownership helpers.
            import access
            tid = access.request_effective_tenant(sess, request)
            if access.tenant_has_own_firewall(hub, tid):
                firewalls = [f for f in firewalls
                             if access.firewall_owner_tenant(hub, (f or {}).get("id"))]
        # Return the filtered list.
        return {"firewalls": firewalls}
