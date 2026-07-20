"""Proxmox agents/nodes/VMs + aggregate + VM-detail + console-create routes."""
import asyncio

from api import (
    HTTPException, Request, _cache_entry, access, get_tenant_scoping, logger, secrets,
    spoke_or_503, time, uuid,
)

# ── /api/pxmx/agents cache (stale-while-revalidate) ─────────────────────────
# The Agents tile + the Setup → Spokes & Agents page fans GET_AGENTS out to
# EVERY agent-hosting spoke (hypervisor + simulation) with a 5s request_timeout
# EACH, sequentially — on a slow/stressed lab that's N×5s per page load, and a
# spoke in a reconnect loop (the pxmx agent-spoke churn) blocks the whole tile.
# Cache the aggregated payload and serve stale-while-revalidate: instant
# returns from cache, a single background refresh at the fresh-TTL boundary,
# and a CONCURRENT fan-out (asyncio.gather) so a forced refresh costs
# max(5s) instead of N×5s. One hub per process → a module-level cache is fine.
_AGENTS_CACHE: dict = {"data": None, "ts": 0.0, "refreshing": False}
_AGENTS_FRESH_S = 5.0    # serve cached payload verbatim while younger than this
_AGENTS_STALE_S = 30.0   # still servable (background refresh kicks in here)
# Per-loop lock: a module-level asyncio.Lock() binds to the first event loop
# that acquires it, which breaks across ``asyncio.run()`` (tests) and would
# break a hub that ever recreates its loop. One lock per running loop gives
# correct mutual exclusion within a loop (one uvicorn loop in production)
# without cross-loop coupling.
_agents_locks: dict = {}

# Bounded fan-out for the aggregate /agents, /vms, hypervisor-tile gathers so
# the hub doesn't open N simultaneous request_response calls when the fleet of
# agent-hosting / opnsense / hypervisor spokes grows.
_FANOUT_SEM = asyncio.Semaphore(8)


def _agents_lock() -> "asyncio.Lock":
    loop = asyncio.get_running_loop()
    lk = _agents_locks.get(id(loop))
    if lk is None:
        lk = asyncio.Lock()
        _agents_locks[id(loop)] = lk
    return lk


async def _aggregate_agents(hub, agent_spokes):
    """Fan GET_AGENTS out to every agent-hosting spoke CONCURRENTLY and merge
    the responses into one tile payload. One dead/slow spoke (the pxmx
    agent-spoke reconnect loop) no longer blocks the others — each request
    still has its 5s request_timeout, but with ``asyncio.gather`` the
    wall-clock cost is max(5s), not N×5s. Never raises; a per-spoke failure
    logs a warning and is skipped so the tile stays populated.

    Module-level (not a route closure) so it depends only on ``hub`` and the
    spoke list, and is unit-testable with a stub hub.
    """
    agent_cfg = hub.state.system_state.get("agent_config", {})
    names = hub.state.system_state.get("agent_display_names", {})
    now = time.time()

    def _agent_identity_change_for(hub, parent_spoke, aid, cfg):
        """Latest unacked rename/reimage event for an agent.

        Agent identity events are recorded on the PARENT spoke's timeline
        (with ``"agent "`` in the detail), so scan that and return the newest
        one newer than the agent's ``change_acked_ts``.
        """
        acked_ts = float(cfg.get("change_acked_ts") or 0.0)
        for ev in hub.get_spoke_events(parent_spoke, limit=30):
            if ev.get("event") in ("identity_changed", "hostname_changed", "reimaged"):
                detail = ev.get("detail", "") or ""
                if "agent " in detail and aid in detail and ev.get("ts", 0) > acked_ts:
                    return ev
        return None

    async def _one(parent_spoke):
        try:
            async with _FANOUT_SEM:
                return await hub.request_response(parent_spoke, "GET_AGENTS", {}, timeout=30.0)
        except Exception as exc:  # noqa: BLE001 — one dead spoke shouldn't blank the tile
            logger.warning("GET_AGENTS failed for spoke %s: %s", parent_spoke, exc)
            return None

    results = await asyncio.gather(*[_one(s) for s in agent_spokes])
    all_agents: list = []
    all_pending: list = []
    for parent_spoke, result in zip(agent_spokes, results):
        if result is None:
            continue
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        if not isinstance(data, dict):
            continue
        for a in data.get("agents", []) or []:
            aid = a["agent_id"]
            a["spoke_id"] = parent_spoke
            # B2: agent_config / agent_display_names / the {spoke}:{agent}
            # composite heartbeat are guid-keyed post-arm; resolve the agent +
            # spoke primary keys so reads land on the guid-keyed state. Pre-arm
            # the aliases are empty → identity (same as today).
            agent_pk = hub._agent_primary_key(aid)
            spoke_pk = hub._primary_key(parent_spoke)
            a["spoke_guid"] = spoke_pk
            cfg = agent_cfg.get(agent_pk, {})
            if cfg.get("display_name"):
                a["display_name"] = cfg["display_name"]
            elif agent_pk in names:
                a["display_name"] = names[agent_pk]
            if cfg.get("client_simulation"):
                a["client_simulation"] = cfg["client_simulation"]
            # Hub-tracked per-agent heartbeat (keyed spoke_pk:agent_pk, fed by
            # the owning spoke relaying AGENT_HEARTBEAT up).
            hb_key = f"{spoke_pk}:{agent_pk}"
            hb_last = hub.heartbeat.last_seen.get(hb_key)
            a["heartbeat_age_s"] = max(0, int(now - hb_last)) if isinstance(hb_last, (int, float)) else None
            a["heartbeat_status"] = str(hub.heartbeat.get_status(hb_key).value)
            a["hostname"] = cfg.get("hostname", "") or a.get("hostname", "") or aid
            a["install_uuid"] = cfg.get("install_uuid", "")
            a["identity_change"] = _agent_identity_change_for(hub, parent_spoke, aid, cfg)
            all_agents.append(a)
        for p in data.get("pending_agents", []) or []:
            p["spoke_id"] = parent_spoke
            all_pending.append(p)
    return {"agents": all_agents, "pending_agents": all_pending, "spoke_connected": True}


def _offline_relay_agents(hub, live_ids):
    """Reconstruct a last-known roster of relayed node agents (Proxmox / cs)
    that are NOT currently live — so an operator can still SEE and DELETE an
    agent whose parent spoke is offline.

    Relayed agents are deliberately kept OUT of ``known_modules`` (they connect
    through a parent spoke, not the hub), so they vanish the moment that spoke
    drops — with no row to delete (the reported gap). We rebuild them from the
    persisted side-data that DOES survive a disconnect:
      * composite heartbeat keys ``{spoke_pk}:{agent_pk}`` (persisted via
        ``spoke_last_seen``) → the agent↔parent-spoke link + last-seen age,
      * ``agent_config`` (guid-keyed per-agent config) → hostname / display /
        install_uuid / client_simulation,
      * ``agent_display_names``.
    ``live_ids`` = agent ids already returned live (skipped). ``known_modules``
    ids (true spokes / generic hub-direct agents — they have their own offline
    handling) are excluded. Never raises."""
    try:
        ss = hub.state.system_state
        agent_cfg = ss.get("agent_config", {}) or {}
        names = ss.get("agent_display_names", {}) or {}
        known = set(ss.get("known_modules", []) or [])
        meta = ss.get("module_metadata", {}) or {}
        now = time.time()

        # agent_pk → (parent spoke_pk, last_seen) from the composite heartbeat keys.
        parent_of, last_of = {}, {}
        for key, ts in (hub.heartbeat.last_seen or {}).items():
            if ":" not in key:
                continue
            spoke_pk, agent_pk = key.split(":", 1)
            parent_of[agent_pk] = spoke_pk
            last_of[agent_pk] = ts

        candidate_pks = set(parent_of) | set(agent_cfg) | set(names)
        live = set(live_ids or [])
        out = []
        for apk in candidate_pks:
            if not apk or apk in known:
                continue  # true spoke / generic hub agent — handled elsewhere
            cfg = agent_cfg.get(apk, {}) or {}
            raw = cfg.get("agent_id") or apk
            if apk in live or raw in live:
                continue  # already represented by a live/pending row
            spoke_pk = parent_of.get(apk, "")
            # Only surface agents whose parent spoke is currently OFFLINE — a
            # live parent already lists its agents via GET_AGENTS.
            if spoke_pk and hub.is_spoke_in_contact(spoke_pk):
                continue
            last = last_of.get(apk)
            age = max(0, int(now - last)) if isinstance(last, (int, float)) else None
            spoke_meta = meta.get(spoke_pk, {}) or {}
            out.append({
                "agent_id": raw,
                "spoke_id": spoke_pk,
                "spoke_guid": spoke_pk,
                "spoke_hostname": spoke_meta.get("hostname", ""),
                "display_name": (cfg.get("display_name") or names.get(apk)
                                 or cfg.get("hostname") or raw),
                "hostname": cfg.get("hostname", "") or raw,
                "install_uuid": cfg.get("install_uuid", ""),
                "client_simulation": cfg.get("client_simulation") or {},
                "heartbeat_age_s": age,
                "heartbeat_status": "OFFLINE",
                "last_seen": last if isinstance(last, (int, float)) else None,
                "offline": True,
            })
        return out
    except Exception:  # noqa: BLE001 — the offline roster must never blank the tile
        logger.exception("offline relay-agent reconstruction failed")
        return []


def _purge_agent_state(hub, agent_id):
    """Drop ALL persisted + in-memory hub-side state for a relayed agent, so a
    DELETE removes an OFFLINE agent for good (parent spoke down) and it never
    re-appears as a ghost offline row. Mirrors ``_evict_spoke`` for the agent-
    relay path. Best-effort; returns True if anything was removed."""
    ss = hub.state.system_state
    apk = hub._agent_primary_key(agent_id)
    keys = {apk, agent_id}
    dirty = False
    for store in ("agent_config", "agent_display_names"):
        d = ss.get(store, {}) or {}
        for k in keys:
            if k in d:
                d.pop(k, None)
                dirty = True
    # composite heartbeat keys {spoke_pk}:{agent_pk} — in-mem + persisted
    for k in list((hub.heartbeat.last_seen or {}).keys()):
        if ":" in k and k.split(":", 1)[1] in keys:
            hub.heartbeat.last_seen.pop(k, None)
            try:
                hub.state.clear_spoke_last_seen(k)
            except Exception:  # noqa: BLE001
                pass
            dirty = True
    for k in list((getattr(hub, "approved_modules", {}) or {}).keys()):
        if k in keys:
            hub.approved_modules.pop(k, None)
            dirty = True
    # in-memory agent_info (evicted on disconnect, but purge if the hub restarted
    # with a stale entry or the agent is somehow still half-tracked)
    for k in list((getattr(hub, "agent_info", {}) or {}).keys()):
        info = hub.agent_info.get(k) or {}
        if k in keys or info.get("agent_id") == agent_id:
            hub.agent_info.pop(k, None)
    # agent_id_alias (name→guid) entries resolving to this agent — else a
    # reconnect could resurrect the guid (same hazard _evict_spoke guards).
    for _name, _guid in list(getattr(hub, "agent_id_alias", {}).items()):
        if _guid in keys or _name in keys:
            hub.agent_id_alias.pop(_name, None)
            dirty = True
    if dirty:
        hub.state._mark_dirty()
    return dirty


async def _maybe_refresh_agents(hub, agent_spokes, force=False):
    """Under ``_agents_lock``: serve the cached payload if it's still fresh
    (unless ``force``); otherwise recompute it concurrently and store.
    Serializing here collapses N simultaneous page-loads into a single
    GET_AGENTS fan-out — later waiters re-check under the lock and return the
    just-refreshed payload instead of re-fanning. Returns the served payload
    (fresh, recomputed, or stale-on-failure). Module-level for testability.

    ``force`` means "the caller already decided the cache is unservable and
    wants a refresh" — but it does NOT bypass a genuinely-fresh result. If a
    concurrent caller refreshed while this one waited on the lock, the cache
    is now fresh and serving it (rather than re-fanning) is the whole point
    of serializing here. So the fresh-cache re-check below is unconditional."""
    async with _agents_lock():
        cached = _AGENTS_CACHE["data"]
        age = (time.time() - _AGENTS_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _AGENTS_FRESH_S:
            return cached
        _AGENTS_CACHE["refreshing"] = True
        try:
            result = await _aggregate_agents(hub, agent_spokes)
            _AGENTS_CACHE["data"] = result
            _AGENTS_CACHE["ts"] = time.time()
            try:  # warm-start snapshot (off-thread) so the Agents tile seeds on restart
                from tenant_sharded import snapshot_save
                from security.encryption import hub_encryption
                import os as _os
                await asyncio.to_thread(
                    snapshot_save,
                    _os.path.join(hub.state.data_dir, "pxmx", "agents_cache.json"),
                    {"data": result, "ts": _AGENTS_CACHE["ts"]},
                    encrypt=lambda s: hub_encryption.encrypt(s))
            except Exception:  # noqa: BLE001
                pass
            return result
        except Exception:
            logger.exception("agents cache refresh failed")
            return cached  # serve stale rather than blanking the tile
        finally:
            _AGENTS_CACHE["refreshing"] = False


def register(app, hub, ctx):
    """Register pxmx routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    # Warm-start the aggregated agents cache so the Agents tile seeds on restart
    # instead of blanking until every agent spoke reconnects (stale-while-revalidate).
    try:
        from tenant_sharded import snapshot_load
        from security.encryption import hub_encryption
        import os as _os
        _snap = snapshot_load(
            _os.path.join(hub.state.data_dir, "pxmx", "agents_cache.json"),
            decrypt=lambda b: hub_encryption.decrypt(b))
        if isinstance(_snap, dict) and _snap.get("data") is not None:
            _AGENTS_CACHE["data"] = _snap["data"]
            _AGENTS_CACHE["ts"] = float(_snap.get("ts", 0) or 0)
    except Exception:  # noqa: BLE001
        pass
    _resolve_tenant = ctx._resolve_tenant
    _filter_tenant = ctx._filter_tenant

    async def _assert_vm_owned(request, unique_id="", vmid=None, node="", agent_id=""):
        """VM-ownership gate for the VNC console. Global Admin → any VM. Otherwise
        the caller must be a write-user or above (access.has_edit_access) AND own
        the VM — its ips/tags (GET_VM_INFO) must survive the hypervisor tenant
        filter, the same attribution as the VM list + /vm/{id}/details. FAIL-CLOSED
        (403) on an unattributable VM. Mirrors _assert_vm_control in pxmx_vm.py.
        Console is a control-tier action (full keyboard/mouse), so view users are
        rejected even for their own VM."""
        sess = _session_user(request)
        if _is_admin(sess):
            return
        if not access.has_edit_access(sess):
            raise HTTPException(status_code=403, detail="Edit access required for VM console")
        hub = app.state.hub
        spoke = (hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False)
                 if agent_id else None) or hub.get_hypervisor_spoke()
        info = {}
        if spoke:
            try:
                raw = await hub.request_response(
                    spoke, "GET_VM_INFO", {"vm_id": unique_id, "vmid": vmid, "node": node})
                info = raw.get("payload", {}).get("data", {}) if isinstance(raw, dict) else {}
            except Exception:  # noqa: BLE001 — fail-closed below
                info = {}
        vm_record = {"ips": info.get("ips") or [], "tags": info.get("tags") or [],
                     "pool": info.get("pool") or ""}
        # Toggle-independent, fail-closed ownership (subnet or tenant tag) — NOT
        # _filter_tenant, which fails OPEN when the hypervisor display filter is off.
        if not await access.vm_in_tenant_scope(hub, sess, vm_record):
            raise HTTPException(status_code=403, detail="not authorized for this VM's tenant")

    @app.get("/vm/{vm_id}/details")
    async def get_vm_details(request: Request, vm_id: str):
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        details = {
            "vm_id": vm_id,
            "ip": ip,
            "metadata": res_info,
            "proxmox": {"status": "OFFLINE"},
            "opnsense": {"status": "OFFLINE", "rules": [], "dhcp": None},
            "cppm": {"status": "OFFLINE", "policy": "Unknown"}
        }

        pxmx_spoke = hub.get_hypervisor_spoke()
        px_res: dict = {}
        if pxmx_spoke:
            px_res_raw = await hub.request_response(pxmx_spoke, "GET_VM_INFO", {"vm_id": vm_id})
            px_res = px_res_raw.get("payload", {}).get("data", {}) if isinstance(px_res_raw, dict) else {}
            details["proxmox"] = px_res if px_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": px_res.get("message", "Unknown error")}

        # SECURITY: a non-admin may only read a VM they could see in the
        # tenant-filtered /api/pxmx/vms list. The resources cache tenant_id is
        # not reliably populated (map_tenant_resource is currently never
        # called), so ownership is decided the same way the list endpoint does:
        # the VM record (ips/tags/pool from GET_VM_INFO, plus the cached IP)
        # must survive the hypervisor tenant filter (subnet + tag + template-
        # pool). Fail-closed (403) when the VM can't be attributed. Admins
        # bypass. Prevents enumerating another tenant's VM proxmox/opnsense/
        # cppm data by vm_id.
        if not _is_admin(sess):
            vm_record = {
                "ips": (px_res.get("ips") or ([ip] if ip else [])),
                "tags": px_res.get("tags") or [],
                "pool": px_res.get("pool") or "",
            }
            kept = await _filter_tenant(request, [vm_record], "hypervisor", ["ips"])
            if not kept:
                raise HTTPException(status_code=403,
                                    detail="not authorized for this VM's tenant")

        opn_spokes = hub.get_all_spokes_by_type("firewall")
        if opn_spokes and ip:
            rules_data = None
            lease = None

            for spoke_id in opn_spokes:
                try:
                    rules_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
                    dhcp_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_DHCP_LEASES", {})

                    rules_res = rules_raw.get("payload", {}).get("data", {}) if isinstance(rules_raw, dict) else {}
                    dhcp_res = dhcp_raw.get("payload", {}).get("data", []) if isinstance(dhcp_raw, dict) else []

                    if rules_res.get("status") == "SUCCESS" and rules_res.get("rules"):
                        rules_data = rules_res
                        break

                    if isinstance(dhcp_res, list):
                        lease = next((l for l in dhcp_res if l.get("ip") == ip), None)
                        if lease:
                            rules_data = rules_res
                            break
                except Exception as e:
                    logger.error(f"Error querying OPNsense spoke {spoke_id} for VM {vm_id}: {e}")

            if rules_data:
                details["opnsense"] = {
                    "status": "ONLINE",
                    "rules": rules_data.get("rules", []),
                    "dhcp": lease
                }
            else:
                details["opnsense"] = {"status": "OFFLINE", "rules": [], "dhcp": None}

        cppm_spoke = hub.get_spoke_by_type("nac")
        if cppm_spoke and ip:
            cppm_res_raw = await hub.request_response(cppm_spoke, "CPPM_GET_POLICY_BY_IP", {"ip": ip})
            cppm_res = cppm_res_raw.get("payload", {}).get("data", {}) if isinstance(cppm_res_raw, dict) else {}
            details["cppm"] = cppm_res if cppm_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": cppm_res.get("message", "Unknown error")}

        return details

    @app.get("/api/aggregate/opnsense")
    async def aggregate_opnsense(request: Request):
        """Fleet-wide OPNsense health + interfaces across every firewall spoke.
        Admin-only: it returns every firewall's interface topology (IPs/uplinks)
        across all tenants, not a per-tenant view — a non-admin enumerating this
        would see other tenants' infra. The per-tenant firewall view is
        /api/firewall/{fwId}/... (already tenant-scoped)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        opn_spokes = hub.get_all_spokes_by_type("firewall")

        async def _one(sid):
            try:
                # Health + interface status are independent — fetch both at once
                # per spoke, and all spokes run concurrently so the dashboard
                # latency is one round-trip, not N×2.
                async with _FANOUT_SEM:
                    health_raw, int_raw = await _asyncio.gather(
                        hub.request_response(sid, "GET_SYSTEM_HEALTH", {}),
                        hub.request_response(sid, "GET_INTERFACE_STATUS", {}),
                    )
                health_data = health_raw.get("payload", {}).get("data", {}) if isinstance(health_raw, dict) else {}
                int_data = int_raw.get("payload", {}).get("data", {}) if isinstance(int_raw, dict) else {}
                return {"spoke_id": sid, "spoke_online": True,
                        "health": health_data, "interfaces": int_data, "status": "ONLINE"}
            except Exception as e:
                return {"spoke_id": sid, "spoke_online": False, "status": "ERROR", "error": str(e)}

        results = await _asyncio.gather(*(_one(sid) for sid in opn_spokes))
        return {"hosts": list(results)}

    @app.get("/api/aggregate/proxmox")
    async def aggregate_proxmox(request: Request):
        """Fleet-wide Proxmox VM inventory (GET_VM_INFO{vm_id:'all'} per
        hypervisor spoke). Admin-only: it returns every VM on every hypervisor
        across all tenants — a non-admin enumerating this would see other
        tenants' full VM lists. The per-tenant view is /api/pxmx/vms (already
        tenant-scoped)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        pxmx_spokes = hub.get_all_spokes_by_type("hypervisor")

        async def _one(sid):
            try:
                async with _FANOUT_SEM:
                    res_raw = await hub.request_response(sid, "GET_VM_INFO", {"vm_id": "all"})
                res_data = res_raw.get("payload", {}).get("data", {}) if isinstance(res_raw, dict) else {}
                return {"spoke_id": sid, "spoke_online": True, "data": res_data, "status": "ONLINE"}
            except Exception as e:
                return {"spoke_id": sid, "spoke_online": False, "status": "ERROR", "error": str(e)}

        results = await _asyncio.gather(*(_one(sid) for sid in pxmx_spokes))
        return {"hosts": list(results)}

    @app.get("/api/pxmx/agent-install-cmd")
    async def get_pxmx_agent_install_cmd(request: Request):
        """Return a ready-to-paste install command for the pxmx node agent.

        NOTE — this is the **co-located / all-in-one (loopback)** path: it points
        the agent at THIS hub box's `/ws/agent` route, which the hub byte-proxies
        to a co-located pxmx spoke's loopback listener (``agent → hub → spoke``).
        For a **standalone** pxmx spoke on a separate box (``agent → spoke →
        hub``, the default), do NOT use this command — run ``install_pxmx.sh``
        on the spoke box and use the ``--spoke-ip <spoke>`` command it prints (a
        standalone spoke does not broadcast ``_lm-hub`` mDNS, so the agent cannot
        auto-discover it). See docs/pxmx.md.

        The command hands the agent just ``--spoke-ip <host>``; the agent probes
        that host's known ``/ws/agent`` endpoints and auto-determines the scheme
        + port + path (see the pxmx agent's discovery.resolve_agent_url). We
        still compute the expected URL below for the modal to display.
        """
        import socket as _socket
        host = request.headers.get("host", "").split(":")[0] or _socket.gethostbyname(_socket.gethostname())
        hub = app.state.hub
        # Co-located/all-in-one: the pxmx agent listener on the hub box is wss on
        # LM_PXMX_AGENT_PORT (8443 loopback; 443 if the hub box also serves it
        # directly); omit the port when it's 443. Without TLS, legacy plaintext
        # :8766. (Standalone spokes serve their own :443 — not reflected here.)
        # Display-only: the agent re-derives this itself from --spoke-ip.
        if getattr(hub, "tls_enabled", False):
            agent_port = int(getattr(hub, "pxmx_agent_port", 8443))
            spoke_url = f"wss://{host}" if agent_port == 443 else f"wss://{host}:{agent_port}"
        else:
            spoke_url = f"ws://{host}:8766"
        cmd = (
            f"curl -sSL https://raw.githubusercontent.com/lbockenstedt/pxmx/main/agent/install_agent.sh "
            f"| sudo bash -s -- "
            f"--spoke-ip {host}"
        )
        return {"cmd": cmd, "spoke_url": spoke_url, "spoke_ip": host}

    @app.get("/api/pxmx/agents")
    async def get_pxmx_agents():
        """Agents tile data source. Aggregates GET_AGENTS across EVERY
        agent-hosting spoke (hypervisor=pxmx, simulation=cs — both subclass
        AgentHostingControlPlane), not just pxmx: a Proxmox host agent can now
        dial a cs spoke's /ws/agent directly (the split-topology work), and
        those agents were previously invisible here entirely — the tile only
        ever asked the pxmx spoke. Each agent is tagged with its own owning
        spoke_id so approve/revoke route correctly regardless of which spoke
        it's actually connected to.

        Serves a stale-while-revalidate cache (``_AGENTS_CACHE``): fresh
        within ``_AGENTS_FRESH_S`` (instant serve), servable-stale until
        ``_AGENTS_STALE_S`` (instant serve + one background refresh), and a
        forced refresh only when there's no servable cache. This keeps Setup →
        Spokes & Agents instant on repeat loads and stops a single slow /
        reconnecting spoke from blocking the tile every page view."""
        hub = app.state.hub
        agent_spokes = list(dict.fromkeys(
            hub.get_all_spokes_by_type("hypervisor") + hub.get_all_spokes_by_type("simulation")
        ))

        if not agent_spokes:
            # No agent-hosting spoke connected → no live roster, but STILL surface
            # any relayed agents whose parent spoke is offline so they can be
            # seen + deleted (was: empty, agents invisible/undeletable).
            live = {"agents": [], "pending_agents": [], "spoke_connected": False}
        else:
            cached = _AGENTS_CACHE["data"]
            age = (time.time() - _AGENTS_CACHE["ts"]) if cached is not None else None
            # Inside the stale window → serve instantly; past fresh-TTL, kick ONE
            # background refresh (the ``not refreshing`` guard avoids a pile-up).
            if cached is not None and age is not None and age < _AGENTS_STALE_S:
                if age >= _AGENTS_FRESH_S and not _AGENTS_CACHE["refreshing"]:
                    asyncio.create_task(_maybe_refresh_agents(hub, agent_spokes))
                live = cached
            else:
                # No servable cache → forced refresh. The lock serializes concurrent
                # first-loaders into a single fan-out; each re-checks under the lock.
                live = await _maybe_refresh_agents(hub, agent_spokes, force=True) \
                    or {"agents": [], "pending_agents": [], "spoke_connected": True}

        # Append the offline relayed-agent roster (reconstructed from persisted
        # side-data) without mutating the shared SWR cache object.
        live_ids = {a.get("agent_id") for a in live.get("agents", []) if a.get("agent_id")}
        live_ids |= {a.get("agent_id") for a in live.get("pending_agents", []) if a.get("agent_id")}
        out = dict(live)
        out["offline_agents"] = _offline_relay_agents(hub, live_ids)
        return out

    @app.post("/api/pxmx/agents/{agent_id}/revoke")
    async def revoke_pxmx_agent(agent_id: str):
        hub = app.state.hub
        # Resolve the spoke that actually owns this agent (may be a cs spoke
        # in the split-topology case, not necessarily pxmx) rather than
        # always targeting the hypervisor spoke.
        owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
            or hub.get_hypervisor_spoke()
        if not owning_spoke:
            raise HTTPException(status_code=503, detail="No agent-hosting spoke connected")
        try:
            result = await hub.request_response(owning_spoke, "SPOKE_RELAY", {
                "target_agent_id": hub._agent_relay_name(agent_id),
                "command": "REVOKE_AGENT",
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            if data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502, detail=data.get("message", "Relay failed"))
            return {"status": "ok", "message": f"Agent '{agent_id}' disconnected"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("revoke_pxmx_agent failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/ack-change")
    async def ack_agent_identity_change(agent_id: str):
        """Dismiss the amber "renamed" banner for a pxmx node agent (idempotent)."""
        hub = app.state.hub
        try:
            agent_pk = hub._agent_primary_key(agent_id)
            cfg = hub.state.system_state.setdefault("agent_config", {}).setdefault(agent_pk, {})
            cfg["change_acked_ts"] = time.time()
            hub.state._mark_dirty()
            return {"status": "ok", "agent_id": agent_id}
        except Exception as e:
            logger.exception("ack_agent_identity_change failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/rename")
    async def rename_pxmx_agent(agent_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        display_name = (data.get("display_name") or "").strip()
        if not display_name:
            raise HTTPException(status_code=400, detail="display_name required")
        hub.state.system_state.setdefault("agent_display_names", {})[hub._agent_primary_key(agent_id)] = display_name
        hub.state._mark_dirty()
        return {"status": "ok", "message": f"Agent '{agent_id}' renamed to '{display_name}'"}

    @app.get("/api/pxmx/agents/{agent_id}/config")
    async def get_pxmx_agent_config(agent_id: str):
        """Return the stored per-agent config (display name + Client Simulation mode)."""
        hub = app.state.hub
        agent_pk = hub._agent_primary_key(agent_id)
        cfg = hub.state.system_state.get("agent_config", {}).get(agent_pk, {})
        # Fall back to the legacy display-name override if agent_config has none yet.
        if not cfg.get("display_name"):
            legacy = hub.state.system_state.get("agent_display_names", {}).get(agent_pk)
            if legacy:
                cfg = dict(cfg)
                cfg["display_name"] = legacy
        return {"config": cfg}

    @app.post("/api/pxmx/agents/{agent_id}/config")
    async def set_pxmx_agent_config(agent_id: str, request: Request):
        """Persist per-agent config (display name + Client Simulation mode) and push
        the client_simulation config down to the agent via the pxmx spoke.
        Reuses the spoke's SET_AGENT_CONFIG command, which persists in the spoke and
        re-pushes UPDATE_CONFIG to the agent on reconnect (see proxmox_spoke.py:55-64)."""
        hub = app.state.hub
        try:
            data = await request.json()
            display_name = (data.get("display_name") or "").strip() or None
            cs = data.get("client_simulation") or {}
            cs_cfg = {
                "enabled": bool(cs.get("enabled")),
                "tenant_id": (cs.get("tenant_id") or "").strip() or None,
            }
            # Managed crontab (optional): the operator-pasted crontab content this
            # node's agent keeps root's crontab in sync with. Only touched when the
            # key is present in the request so a client_simulation-only save (or a
            # node that never uses crontab) leaves it alone; sending "" clears it.
            has_cron = "managed_crontab" in data
            cron_val = data.get("managed_crontab")
            if has_cron:
                cron_val = "" if cron_val is None else str(cron_val)

            # Persist (merge with any existing entry so partial updates keep fields).
            store = hub.state.system_state.setdefault("agent_config", {})
            agent_pk = hub._agent_primary_key(agent_id)
            entry = dict(store.get(agent_pk, {}))
            if display_name:
                entry["display_name"] = display_name
            entry["client_simulation"] = cs_cfg
            if has_cron:
                entry["managed_crontab"] = cron_val
            store[agent_pk] = entry
            hub.state._mark_dirty()

            # The config pushed down to the agent — include managed_crontab only
            # when this save carried it (the agent applies it on UPDATE_CONFIG).
            push_cfg = {"client_simulation": cs_cfg}
            if has_cron:
                push_cfg["managed_crontab"] = cron_val

            # Best-effort push to a live agent. SET_AGENT_CONFIG persists spoke-side
            # even when the agent is offline, so a failure here just means the agent
            # picks up the config on its next connect/reconnect — but that only
            # works if the OWNING SPOKE actually received this SET_AGENT_CONFIG in
            # the first place. If the spoke itself was momentarily unreachable
            # (mid self-update restart, brief reconnect blip — the same window
            # that made hub-config saves report "0 spokes"), a bare
            # request_response would raise immediately and this command would
            # just be dropped with nothing spoke-side to push down once the
            # agent reconnects. push_or_queue_to_spoke queues it via the Mailbox
            # instead, so it's delivered (and persists spoke-side) the moment the
            # spoke itself comes back.
            pushed = False
            queued = False
            owning_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
                or hub.get_hypervisor_spoke()
            if owning_spoke:
                try:
                    push = getattr(hub, "push_or_queue_to_spoke", None)
                    if callable(push):
                        outcome = await push(owning_spoke, "SET_AGENT_CONFIG", {
                            "agent_id": agent_id,
                            "config": push_cfg,
                        })
                        queued = bool(outcome.get("queued"))
                        rdata = outcome.get("result") or {}
                        rdata = rdata.get("payload", {}).get("data", rdata) if isinstance(rdata, dict) else rdata
                        pushed = queued or (isinstance(rdata, dict) and rdata.get("status") == "SUCCESS")
                    else:
                        res = await hub.request_response(owning_spoke, "SET_AGENT_CONFIG", {
                            "agent_id": agent_id,
                            "config": push_cfg,
                        })
                        rdata = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
                        pushed = rdata.get("status") == "SUCCESS"
                except Exception as e:
                    logger.info(f"SET_AGENT_CONFIG push for '{agent_id}' failed (will re-push on reconnect): {e}")

            return {
                "status": "ok" if pushed else "partial_success",
                "message": ("Config queued — spoke temporarily unreachable, will apply on reconnect." if queued
                            else "Config saved and pushed to agent." if pushed
                            else "Config saved; agent will receive it on next connect/reconnect."),
                "pushed": pushed,
                "queued": queued,
                # Read the SAME key we wrote (agent_pk = the guid-primary key), not
                # the raw agent_id — post guid-migration they differ, so store[agent_id]
                # KeyError'd and 500'd the save even though the config had persisted.
                "config": store.get(agent_pk, entry),
            }
        except Exception as e:
            logger.exception("set_pxmx_agent_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/agents/{agent_id}/cs-command")
    async def pxmx_agent_cs_command(agent_id: str, request: Request):
        """Admin/debug: send a Client-Simulation fast command to a Proxmox agent
        — start/stop/reboot/snapshot_vm, the start_vms/stop_vms/snapshot_vms
        batches, unlock_template, clear_provision_lock, clear_usb_quarantine.

        Relays through the pxmx spoke as SPOKE_RELAY {command: CS_COMMAND}; the
        agent returns SUCCESS or ERROR (a cs_guard refusal — e.g. vmid below the
        90000 floor or a protected container — comes back as ERROR with the
        guard's message). Sync only: long ops (delete/reclone/reseed/backup) are
        not exposed here (they'd exceed the spoke's 15s relay window)."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        action = (body.get("action") or "").strip()
        if not action:
            raise HTTPException(status_code=400, detail="missing 'action'")
        pxmx_spoke = spoke_or_503(hub.get_hypervisor_spoke(), "hypervisor")
        try:
            result = await hub.request_response(pxmx_spoke, "SPOKE_RELAY", {
                "target_agent_id": hub._agent_relay_name(agent_id),
                "command": "CS_COMMAND",
                "data": body,
            })
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"CS command relay failed: {e}")

    @app.delete("/api/pxmx/agents/{agent_id}")
    async def delete_pxmx_agent(agent_id: str):
        """Remove a Proxmox node agent: best-effort disconnect of a live agent
        (relayed through the hypervisor spoke) plus removal of any persisted
        display-name override. If the agent is already dead / the hypervisor
        spoke is offline, the relay is skipped and we still clear the override."""
        hub = app.state.hub
        relayed = False
        pxmx_spoke = hub.get_hypervisor_spoke()
        if pxmx_spoke:
            try:
                result = await hub.request_response(pxmx_spoke, "SPOKE_RELAY", {
                    "target_agent_id": hub._agent_relay_name(agent_id),
                    "command": "REVOKE_AGENT",
                })
                data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
                relayed = data.get("status") == "SUCCESS"
            except Exception as e:
                # Agent may already be disconnected — non-fatal for a delete.
                logger.info(f"Revoke relay for delete of agent '{agent_id}' skipped/failed (may be dead): {e}")
        # Purge ALL persisted + in-memory hub state for this agent so an OFFLINE
        # agent (parent spoke down) is removed for good and never re-appears as a
        # ghost offline row — not just the display-name override as before.
        _purge_agent_state(hub, agent_id)
        msg = ("Agent disconnected and removed." if relayed else "Agent removed (was not connected).")
        return {"status": "ok", "message": msg}

    @app.delete("/api/pxmx/server")
    async def delete_pxmx_server(request: Request):
        """Remove a hypervisor SERVER (pxmx host) from the Hypervisors →
        Overview / Virtual Machines view: purge its agent's hub state and clear
        the cached VM list so its now-stale VMs + node stop showing. For a host
        that's been intentionally shut down. Body: ``{agent_id?, node?, hostname?,
        cluster?}`` — agent_id preferred (UI resolves it from the node's VMs);
        else the agent whose hostname matches ``node`` is used. VM data is served
        live from connected agents, so a server that's STILL online will
        re-appear on the next poll — this is for removing dead/stale ones."""
        if not _is_admin(_session_user(request)):
            raise HTTPException(status_code=403, detail="Admin access required")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        agent_id = str((body or {}).get("agent_id") or "").strip()
        node = str((body or {}).get("node") or (body or {}).get("hostname") or "").strip()
        # Resolve the agent by hostname when the UI couldn't map the node → agent.
        if not agent_id and node:
            ss = hub.state.system_state
            for pk, cfg in (ss.get("agent_config", {}) or {}).items():
                if str((cfg or {}).get("hostname", "")).strip().lower() == node.lower():
                    agent_id = pk
                    break
            if not agent_id:
                for pk, info in (getattr(hub, "agent_info", {}) or {}).items():
                    if str((info or {}).get("hostname", "")).strip().lower() == node.lower():
                        agent_id = (info or {}).get("agent_id") or pk
                        break
        purged = None
        if agent_id:
            # Best-effort live disconnect through the owning spoke (mirrors
            # delete_pxmx_agent), then purge ALL persisted + in-mem agent state.
            try:
                owning = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) \
                    or hub.get_hypervisor_spoke()
                if owning:
                    try:
                        await hub.request_response(owning, "SPOKE_RELAY", {
                            "target_agent_id": hub._agent_relay_name(agent_id),
                            "command": "REVOKE_AGENT"}, timeout=8.0)
                    except Exception:  # noqa: BLE001 — agent may be dead already
                        pass
                _purge_agent_state(hub, agent_id)
                purged = agent_id
            except Exception as e:  # noqa: BLE001
                logger.info("delete_pxmx_server: purge of '%s' failed: %s", agent_id, e)
        # HIDE the node persistently — the Hypervisors nodes come from a LIVE
        # GET_NODE_STATS, and a shut-down host is still reported (status=offline)
        # by its cluster peers, so purging the agent + clearing the cache alone
        # would let it re-appear on the next poll (the reported bug: "success
        # toast but it doesn't delete"). get_pxmx_nodes/_with_tpl filter this set;
        # a node that comes back ONLINE is auto-unhidden there.
        hidden_added = False
        if node:
            try:
                ss = hub.state.system_state
                hidden = ss.setdefault("pxmx_hidden_nodes", [])
                if node not in hidden:
                    hidden.append(node)
                    hub.state._mark_dirty()
                    hidden_added = True
            except Exception:  # noqa: BLE001
                pass
        # Clear the cached VM list (so the dead server's VMs vanish immediately;
        # the next live poll repopulates from connected agents only) + the agents
        # SWR cache (so it drops from the Agents tile too).
        try:
            hub.warm_cache.pop("pxmx_vms", None)
        except Exception:  # noqa: BLE001
            pass
        try:
            _AGENTS_CACHE["data"] = None
            _AGENTS_CACHE["ts"] = 0.0
        except Exception:  # noqa: BLE001
            pass
        return {"status": "ok", "purged_agent": purged, "hidden": hidden_added or bool(node),
                "message": ("Server hidden from the Hypervisors view + cached VMs cleared"
                            + (f"; agent {purged} purged" if purged else "")
                            + ". It re-appears automatically only if the host comes back online.")}

    @app.get("/api/pxmx/nodes")
    async def get_pxmx_nodes(request: Request):
        hub = app.state.hub
        # Whole-cluster hypervisor node stats are infrastructure-wide (every
        # node, all tenants' capacity) — Global-Admin-only. Was reachable by any
        # authenticated user with no tenant filter.
        if not _is_admin(_session_user(request)):
            raise HTTPException(status_code=403, detail="Admin access required")
        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            return {"nodes": [], "spoke_connected": False}
        try:
            result = await hub.request_response(pxmx_spoke, "GET_NODE_STATS", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Operator-hidden (deleted) servers: filter them out of the live feed
            # so a shut-down host that cluster peers still report as offline stays
            # gone. AUTO-UNHIDE any hidden node that reports back ONLINE (the host
            # returned) so a live node is never permanently hidden.
            if isinstance(data, dict) and isinstance(data.get("nodes"), list):
                ss = hub.state.system_state
                hidden = list(ss.get("pxmx_hidden_nodes", []) or [])
                if hidden:
                    hset = set(hidden)
                    back = {str(n.get("node") or "") for n in data["nodes"]
                            if isinstance(n, dict) and str(n.get("status") or "").lower() == "online"
                            and str(n.get("node") or "") in hset}
                    if back:
                        remaining = [h for h in hidden if h not in back]
                        ss["pxmx_hidden_nodes"] = remaining
                        hub.state._mark_dirty()
                        hset -= back
                    data = dict(data)
                    data["nodes"] = [n for n in data["nodes"]
                                     if not (isinstance(n, dict) and str(n.get("node") or "") in hset)]
            return data
        except Exception as e:
            logger.exception("get_pxmx_nodes failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── pxmx / Proxmox: VMs + agent commands (/api/pxmx/*) ───────────────────
    @app.get("/api/pxmx/vms")
    async def get_pxmx_vms(request: Request, agent_id: str = None, tenant: str = None):
        """
        Aggregate VM/CT list from all connected pxmx agents.
        Each VM includes unique_id ("<cluster>/<node>/<vmid>"), agent_id, cluster, node, vmid.
        Pass ?agent_id=<id> to scope to a single agent.
        Pass ?tenant=<id> to filter by that tenant's proxmox_tag setting AND to
        subnet-filter the returned VMs by that tenant's NetBox prefixes (each VM
        carries an ``ips`` list; VMs whose ``ips`` all fall outside the tenant's
        prefixes are dropped). The subnet filter is applied on all three return
        paths (tenant cache hit / spoke-down cache / live) via
        ``_filter_tenant`` so an admin acting as a tenant sees only that
        tenant's VMs — the toggle is the ``hypervisor`` subnet-filter module.
        """
        hub = app.state.hub
        # see _netbox_list_get (variant: hypervisor spoke, proxmox_tag payload, and
        # a non-503 spoke-down shape {vms:[], spoke_connected:False} — inline).
        logger.debug("relay %s %s tenant=%s agent_id=%s", request.method, request.url.path, tenant, agent_id)
        # Template-pool names are advertised to the UI so it can mark which VMs
        # are clonable templates (clone-from-template). Computed once, merged into
        # the response envelope on every return path below.
        template_pools = access._template_pools(hub)
        # Delete-protection safeguard (union across all tenants) — stamped on
        # each VM as ``protected`` so the UI can lock the Delete button. Computed
        # once; every return path goes through _with_tpl so the flag is set on
        # live, warm, and cached reads alike.
        protected_set = hub.simulations_store.get_all_protected_vms()

        _hidden_nodes = set(hub.state.system_state.get("pxmx_hidden_nodes", []) or [])

        def _with_tpl(data):
            if isinstance(data, dict):
                data = dict(data)
                data["template_pools"] = template_pools
                vms = data.get("vms")
                if isinstance(vms, list):
                    # Drop VMs on operator-hidden (deleted) servers so a removed
                    # host's stale VMs don't re-appear from the live/cluster feed.
                    if _hidden_nodes:
                        vms = [v for v in vms if not (isinstance(v, dict)
                               and str(v.get("node") or "") in _hidden_nodes)]
                        data["vms"] = vms
                    for v in vms:
                        if isinstance(v, dict):
                            v["protected"] = v.get("unique_id") in protected_set
            return data

        sess = _session_user(request)
        if not agent_id and not tenant and sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            if tid:
                cached = _cache_entry(tid, "pxmx_vms")
                if cached:
                    return _with_tpl(await _filter_tenant(request, cached["data"], "hypervisor", ["ips"], tenant))
        # Tenant scope for the live fetch (proxmox_tag filter) — also the warm-
        # cache scope key so a cached raw envelope is only served back to the same
        # scope (tenant isolation preserved). admins / a tenant with no
        # proxmox_tag → "_all_" (the live fetch returns every VM, then
        # _filter_tenant subnet-filters per reader on the way out — same as live).
        scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
        tag = scoping.get("proxmox_tag") or ""
        warm_key = f"{tag or '_all_'}|agent={agent_id or ''}"

        async def _warm_or_empty():
            """Serve the last-known VM list (stale) when the spoke is down / a
            live fetch overruns — mirrors the netbox/cppm warm cache so the
            Hypervisors page renders instantly after a hub restart instead of
            going empty until PXMX_LIST_VMS returns. Falls back to the empty
            spoke-down envelope when no snapshot exists."""
            cached = hub.warm_get("pxmx_vms", warm_key)
            if cached is None:
                return _with_tpl({"vms": [], "spoke_connected": False})
            out = await _filter_tenant(request, cached, "hypervisor", ["ips"], tenant)
            if isinstance(out, dict):
                out = dict(out)
                out["stale"] = True
                out["spoke_connected"] = False
            return _with_tpl(out)

        pxmx_spoke = hub.get_hypervisor_spoke()
        if not pxmx_spoke:
            if sess:
                tid = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tid, "pxmx_vms") if tid else None
                if cached:
                    return _with_tpl(await _filter_tenant(request, cached["data"], "hypervisor", ["ips"], tenant))
            return await _warm_or_empty()
        try:
            payload: dict = {}
            if agent_id:
                payload["agent_id"] = agent_id
            if scoping.get("proxmox_tag"):
                payload["tag_filter"] = scoping["proxmox_tag"]
            # 30s (not the 5s relay default) — a large Proxmox fleet with guest
            # IP annotation (QGA / lxc netns per-NIC) routinely exceeds 5s; the
            # warm cache covers an overrun so the page still renders. Matches the
            # vmid_alloc PXMX_LIST_VMS budget.
            result = await hub.request_response(pxmx_spoke, "PXMX_LIST_VMS", payload, timeout=30.0)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            await hub.warm_set("pxmx_vms", warm_key, data)  # cache raw (pre-filter)
            return _with_tpl(await _filter_tenant(request, data, "hypervisor", ["ips"], tenant))
        except Exception as e:
            logger.exception("get_pxmx_vms failed")
            # Live fetch failed (timeout / spoke error) — serve stale from the
            # warm cache if we have it, else surface the error.
            cached = hub.warm_get("pxmx_vms", warm_key)
            if cached is not None:
                out = await _filter_tenant(request, cached, "hypervisor", ["ips"], tenant)
                if isinstance(out, dict):
                    out = dict(out)
                    out["stale"] = True
                return _with_tpl(out)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/pxmx/shell")
    async def pxmx_create_shell(request: Request):
        """Interactive host shell (xterm terminal) on a Proxmox node — spawns a
        root PTY bash on the host via the agent. GATED: opt-in toggle
        (global_config['pxmx']['host_shell_enabled'], OFF by default) + Global
        Admin (any host) or Tenant Admin (own tenant's hypervisor only) + audit.
        Mints a session + ws_token; the browser connects to
        /ws/console-shell/{session_id}?token=."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        hub = app.state.hub
        is_ga = _is_admin(sess)
        if not (is_ga or access.is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="Global or Tenant Admin required for the host shell")
        try:
            body = await request.json()
        except Exception:
            body = {}
        agent_id = str((body or {}).get("agent_id") or "").strip()
        unique_id = str((body or {}).get("unique_id") or "").strip()
        pxmx_spoke = spoke_or_503((hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False)
                                   if agent_id else None) or hub.get_hypervisor_spoke(),
                                  "Hypervisor")
        tenant_id = sess.get("tenant_id") or ""
        spoke_tenant = hub.state.get_spoke_tenant(pxmx_spoke) or ""
        if not is_ga and spoke_tenant and spoke_tenant != tenant_id:
            raise HTTPException(status_code=403, detail="not your tenant's hypervisor")
        # Opt-in gate: the target hypervisor's tenant config must enable the shell
        # (Setup → Hypervisors → "Enable host terminal"). OFF by default.
        try:
            hv = await hub.simulations_store.get_hypervisors_config(spoke_tenant)
        except Exception:  # noqa: BLE001
            hv = {}
        if not (hv or {}).get("host_shell_enabled", False):
            raise HTTPException(status_code=403,
                                detail="Host terminal is disabled for this hypervisor — enable it in Setup → Hypervisors")
        session_id = str(uuid.uuid4())
        ws_token = secrets.token_urlsafe(32)
        hub.register_shell_session(session_id, {
            "spoke_id": pxmx_spoke, "tenant_id": tenant_id,
            "agent_id": agent_id, "ws_token": ws_token,
        })
        logger.info("AUDIT host-shell OPEN user=%s tenant=%s spoke=%s agent=%s session=%s",
                    sess.get("username") or sess.get("user_id"), tenant_id or "-",
                    pxmx_spoke, agent_id or "-", session_id)
        try:
            res = await hub.request_response(pxmx_spoke, "SHELL_START", {
                "session_id": session_id, "unique_id": unique_id,
                "agent_id": agent_id, "target_agent_id": hub._agent_relay_name(agent_id),
            }, timeout=30.0)
        except Exception as e:
            hub.unregister_shell_session(session_id)
            logger.exception("pxmx_create_shell SHELL_START failed")
            raise HTTPException(status_code=502, detail=f"failed to start shell: {e}")
        data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
        if isinstance(data, dict) and data.get("status") == "ERROR":
            hub.unregister_shell_session(session_id)
            raise HTTPException(status_code=502, detail=data.get("message", "agent refused SHELL_START"))
        return {"session_id": session_id, "ws_token": ws_token,
                "ws_url": f"/ws/console-shell/{session_id}"}

    @app.post("/api/pxmx/console")
    async def pxmx_create_console(request: Request):
        """Hypervisors view VNC console — create a console session for a VM.

        Body: ``{unique_id, vmid, node, type}``. Mints a one-shot ``session_id``
        + ``ws_token`` and tells the pxmx spoke→agent to open a Proxmox
        vncwebsocket locally (agent-terminates-WSS) and relay frames over the
        existing WS legs. Authorized by _assert_vm_owned: admin any, else a
        write-user/tenant-admin who OWNS the VM (console is control-tier). The
        browser then connects to ``/ws/console/{session_id}?token=<ws_token>`` for the
        noVNC byte relay. Fire-and-forget VNC_START — the agent emits
        VNC_READY/VNC_ERROR up, which the browser WS picks up."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
        except Exception:
            body = {}
        unique_id = str((body or {}).get("unique_id", "")).strip()
        parts = unique_id.split("/")
        if len(parts) < 3:
            raise HTTPException(status_code=400, detail="invalid unique_id (expect <cluster>/<node>/<vmid>)")
        cluster, node, vmid_s = parts[0], parts[1], parts[2]
        try:
            vmid = int(vmid_s)
        except ValueError:
            raise HTTPException(status_code=400, detail="invalid vmid in unique_id")
        # Admin → any VM; a write-user/tenant-admin → only a VM in their tenant.
        await _assert_vm_owned(request, unique_id=unique_id, vmid=vmid, node=node,
                               agent_id=str((body or {}).get("agent_id") or "").strip())
        hub = app.state.hub
        # Route to the spoke that actually relays the VM's host agent (hosts are
        # not clustered — a vncwebsocket must open on the VM's own host or it
        # fails → "agent refused VNC_START"). Mirrors the revoke/ack-change
        # routes: get_spoke_for_agent(agent_id) with target_agent_id in the
        # payload so a multi-agent spoke relays to the right agent. Falls back to
        # the global hypervisor spoke when agent_id is absent (single-host).
        agent_id = str((body or {}).get("agent_id") or "").strip()
        pxmx_spoke = spoke_or_503((hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False)
                                   if agent_id else None) or hub.get_hypervisor_spoke(),
                                  "Hypervisor")
        session_id = str(uuid.uuid4())
        ws_token = secrets.token_urlsafe(32)
        tenant_id = sess.get("tenant_id") or ""
        hub.register_vnc_session(session_id, {
            "spoke_id": pxmx_spoke,
            "tenant_id": tenant_id,
            "ws_token": ws_token,
            "vmid": vmid,
            "node": node,
            "unique_id": unique_id,
        })
        try:
            # request_response (NOT send_to_spoke_command): the spoke→agent
            # opens the Proxmox vncwebsocket synchronously and returns the
            # Proxmox ticket, which doubles as the RFB VNC password noVNC must
            # present during the security handshake. We pass it to the browser
            # so noVNC authenticates with it; without it noVNC sends an empty
            # password and Proxmox drops the RFB session → "Security failure" /
            # blank console. 30s covers spoke→agent (25s) + the WSS open.
            vnc_res = await hub.request_response(pxmx_spoke, "VNC_START", {
                "session_id": session_id,
                "unique_id": unique_id,
                "vmid": vmid,
                "node": node,
                "type": str((body or {}).get("type", "qemu")),
                "target_agent_id": hub._agent_relay_name(agent_id),
            }, timeout=50.0)
        except Exception as e:
            hub.unregister_vnc_session(session_id)
            logger.exception("pxmx_create_console VNC_START failed")
            raise HTTPException(status_code=502, detail=f"failed to start console: {e}")
        # request_response returns the ENVELOPE ({header, payload:{type, data}});
        # status/ticket/message live in payload.data (spoke→agent may nest twice
        # in the relay topology). Peel payload.data layers until we reach the
        # status-bearing dict — reading the envelope's top-level .status was
        # always None, so the "agent refused VNC_START" branch fired no matter
        # what the agent actually returned. Mirrors aggregate_proxmox's unwrap.
        for _ in range(3):
            if isinstance(vnc_res, dict) and "status" not in vnc_res and "payload" in vnc_res:
                vnc_res = vnc_res.get("payload", {}).get("data", vnc_res)
            else:
                break
        ticket = ""
        if isinstance(vnc_res, dict):
            if vnc_res.get("status") not in ("SUCCESS", "OK"):
                hub.unregister_vnc_session(session_id)
                # "ACCEPTED" (no ticket) = the agent is on the OLD VNC code that
                # acked fire-and-forget and never returned the Proxmox ticket —
                # i.e. the agent hasn't self-updated to match the spoke/hub yet.
                if vnc_res.get("status") == "ACCEPTED":
                    detail = ("agent returned ACCEPTED (no ticket) — the pxmx agent "
                              "on the Proxmox host is still on the old VNC code; "
                              "wait for its self-update or restart lm-pxmx-agent")
                else:
                    detail = vnc_res.get("message") or vnc_res.get("error") or "agent refused VNC_START"
                raise HTTPException(status_code=502, detail=f"failed to start console: {detail}")
            ticket = str(vnc_res.get("ticket") or "")
        return {"session_id": session_id, "ws_token": ws_token,
                "ticket": ticket, "expires_in": 60}
