"""onboarding.py — generic, module-agnostic tenant self-service spoke
onboarding (the "Add Server" button).

A tenant-admin generates a PSK for their OWN tenant; ANY new spoke (nac, dns,
dhcp, nw, certificates, ...) that connects to the hub presenting that PSK
auto-approves + auto-binds to the tenant — see
``main.py::LabManagerHub._try_psk_self_provision``, which is already
module_type-agnostic (it just registers+approves+binds whatever spoke_id
presented a valid PSK). Nothing there needed to change; this file is purely
the tenant-facing surface to generate/list/revoke that PSK without going
through the Global-Admin-only ``/setup/*`` spoke-approval screen.

Distinct from ``/sim/api/tenant/{tenant}/onboarding-psk``
(simulations/routes.py), which manages the SAME underlying PSK store
(``hub.simulations_store``) but ALSO pushes the PSK to the tenant's
Client-Sim spoke for a DIFFERENT mechanism — that spoke's own sub-agent
vouch/relay onboarding (a cs-spoke-hosts-its-own-children flow). This file
is the generic path for onboarding a spoke that connects DIRECTLY to the
hub, with no cs spoke involved — the PSK itself isn't module-scoped (any
spoke type can use it), only tenant-scoped, so reusing the same store here
is correct; the cs-specific push side effect is not.

Mounted under ``/tenant/*`` so the existing tenant-admin-or-admin middleware
gate (api.py, ``path.startswith("/tenant/")``) covers it for free — this
file only adds the per-tenant ownership check on top (a tenant-admin may
manage only their OWN tenant's PSKs).
"""
# Cryptographically strong random generator used to mint new PSKs.
import secrets

# Request/exception types and the shared logger from the main API module.
from api import HTTPException, Request, logger


def register(app, hub, ctx):
    """Register the generic onboarding-PSK routes on the Hub app."""
    # Pull the shared session/role helpers out of ctx once for the route closures below.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin

    def _require_owns_tenant(request: Request, tenant: str):
        """The ``/tenant/*`` middleware gate already requires tenant-admin-or-
        admin to reach here; re-checked anyway (defense in depth, matching
        tenant_devices.py's ``_bind_gate`` — never trust the middleware
        alone), plus the per-tenant ownership check a tenant-admin needs
        (never another tenant's PSKs — mirrors tenant_devices.py's
        ``_owns``)."""
        # Global Admins may manage any tenant.
        sess = _session_user(request)
        if _is_admin(sess):
            return sess
        # Otherwise the caller must at least be a tenant-admin.
        if not (sess and _is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin access required")
        # ...and the tenant in the URL must be one of the tenants their account belongs to.
        allowed = (sess or {}).get("user", {}).get("tenants") or []
        if tenant not in allowed:
            raise HTTPException(status_code=403,
                                detail="You may only manage your own tenant's onboarding PSKs")
        return sess

    def _configured_hub_url() -> str:
        """The configured hub address, echoed to the My Devices page so the
        install command can point a new spoke at the HUB.

        Served from THIS tenant-accessible route on purpose. The WebUI used to
        read it from ``/setup/config``, which is admin-only -- so for a tenant
        admin that fetch 403'd, the URL came back empty and the install command
        silently fell back to ``location.host`` (the proxy serving the WebUI,
        e.g. the legacy ``labmanager`` alias) instead of the real hub. Not a
        secret: this exact address is printed in the install command below it."""
        # Read global_config.hub.url defensively; any missing level yields an empty string.
        try:
            return str((((hub.state.system_state.get("global_config") or {})
                         .get("hub") or {}).get("url") or "")).strip()
        except Exception:  # noqa: BLE001 -- never break the key list over this
            return ""

    @app.get("/tenant/{tenant}/onboarding-psk", operation_id="tenant_list_onboarding_psks")
    async def list_onboarding_psks(request: Request, tenant: str):
        """List the tenant's onboarding PSKs plus the hub URL the install command should point at.
        """
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # Return the tenant's PSKs from the shared PSK store and the configured hub URL.
        return {"psks": await hub.simulations_store.get_psks(tenant),
                "hub_url": _configured_hub_url()}

    @app.post("/tenant/{tenant}/onboarding-psk", operation_id="tenant_generate_onboarding_psk")
    async def generate_onboarding_psk(request: Request, tenant: str):
        """Mint a new onboarding PSK for ``tenant``. The caller pastes it (with
        the tenant id) into a new box's install command — see
        ``agent/install_agent.sh --onboarding-psk``/``--tenant-hint``."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # 24 random bytes encoded URL-safe (32 chars): unguessable and safe to paste on a shell
        # command line.
        psk = secrets.token_urlsafe(24)
        # Store it against the tenant so a spoke presenting it is auto-approved and bound there.
        await hub.simulations_store.add_psk(tenant, psk)
        logger.info("onboarding-psk: generated for tenant %s", tenant)
        # Hand the PSK back once so the tenant-admin can copy it into the install command.
        return {"psk": psk, "tenant_id": tenant}

    @app.delete("/tenant/{tenant}/onboarding-psk", operation_id="tenant_revoke_onboarding_psk")
    async def revoke_onboarding_psk(request: Request, tenant: str):
        """Revoke one of the tenant's onboarding PSKs so it can no longer onboard new spokes."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # The PSK to revoke is sent in the JSON body.
        body = await request.json()
        psk = body.get("psk") if isinstance(body, dict) else None
        # Remove it from the store (nothing to do when no PSK was given).
        removed = await hub.simulations_store.remove_psk(tenant, psk) if psk else False
        # Only log when something was actually revoked.
        if removed:
            logger.info("onboarding-psk: revoked for tenant %s", tenant)
        return {"removed": removed}

    @app.get("/tenant/{tenant}/spokes", operation_id="tenant_list_own_spokes")
    async def list_tenant_spokes(request: Request, tenant: str):
        """Every spoke/agent bound to ``tenant`` — approved AND pending,
        connected AND offline — so a tenant-admin can see and onboard their own
        fleet from My Devices without the Global-Admin-only ``/setup`` spoke
        screens, and without needing an already-approved Simulations spoke to
        unlock the nav (the onboarding chicken/egg). Tenant-scoped: a
        tenant-admin sees only registrations bound to a tenant they own; a
        Global Admin may pass any tenant. Module-agnostic (nac/dns/dhcp/nw/
        certificates/simulation/…), mirroring the tenant-agnostic PSK the same
        file mints."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # Gather the hub's registries: known spokes, display names, metadata, live connections,
        # module types and telemetry.
        st = hub.state.system_state
        known = st.get("known_modules", []) or []
        names = st.get("module_names", {}) or {}
        meta = st.get("module_metadata", {}) or {}
        conns = getattr(hub, "active_connections", {}) or {}
        live_types = getattr(hub, "spoke_module_types", {}) or {}
        telemetry = getattr(hub, "spoke_telemetry", {}) or {}
        # Walk every known spoke and keep only those bound to this tenant.
        out = []
        for sid in known:
            # Tenant binding is the ownership signal — never a client claim.
            if (hub.state.get_spoke_tenant(sid) or "") != tenant:
                continue
            # Live data is keyed by the spoke's primary key, so resolve it once.
            pk = hub._primary_key(sid)
            m = meta.get(sid, {}) or {}
            # Build the row the My Devices page shows for this spoke.
            out.append({
                "spoke_id": sid,
                "display_name": names.get(sid) or m.get("hostname") or sid,
                "hostname": m.get("hostname") or "",
                "module_type": live_types.get(pk) or m.get("module_type") or "",
                "ip": (telemetry.get(pk, {}) or {}).get("remote_ip", "") or "",
                "connected": pk in conns,
                "approved": bool(hub.approved_modules.get(pk, False)),
                "revoked": bool(m.get("revoked")),
                "revoke_reason": m.get("revoke_reason", "") or "",
                "revoked_ts": m.get("revoked_ts", 0) or 0,
                "revoked_by": m.get("revoked_by", "") or "",
                "tenant_id": tenant,
            })
        # Sort by module type then id so the list is stable between refreshes.
        out.sort(key=lambda s: (s["module_type"], s["spoke_id"]))
        return {"tenant_id": tenant, "spokes": out}

    @app.get("/tenant/{tenant}/agents", operation_id="tenant_list_own_agents")
    async def list_tenant_agents(request: Request, tenant: str):
        """Relayed node-agents (a Proxmox host agent dialing a hypervisor/
        simulation spoke's ``/ws/agent`` — NOT a hub-direct spoke, see
        ``list_tenant_spokes`` for that) scoped to ``tenant``, so a
        tenant-admin can see — and approve, via
        ``approve_tenant_agent`` below — their own pending agents from My
        Devices, without the Global-Admin-only Setup screen AND without
        needing the ``pxmx`` module right (``GET /api/pxmx/agents`` requires
        it; this route doesn't, since My Devices is the generic self-service
        surface independent of per-module rights). Reuses the same cached
        aggregation + tenant filter as the admin tile
        (``routes.pxmx.pxmx_agents_payload``) — one cache, two surfaces."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        from routes.pxmx import pxmx_agents_payload  # lazy: avoid import cycle
        # Reuse the cached, tenant-filtered aggregation the admin Proxmox tile uses.
        payload = await pxmx_agents_payload(hub, tenant)
        # Return the three agent lists the My Devices page renders.
        return {"tenant_id": tenant,
                "agents": payload.get("agents", []),
                "pending_agents": payload.get("pending_agents", []),
                "offline_agents": payload.get("offline_agents", [])}

    @app.post("/tenant/{tenant}/agents/{spoke_id}/{agent_id}/approve",
              operation_id="tenant_approve_own_agent")
    async def approve_tenant_agent(request: Request, tenant: str, spoke_id: str, agent_id: str):
        """Tenant-admin self-service approval for a relayed node-agent pending
        on one of THEIR OWN spokes — the tenant-admin counterpart to Setup →
        Spokes & Agents' admin-only Approve button. Restricted to a spoke
        ALREADY bound to ``tenant`` (anti-IDOR, and matches the "an agent
        auto-ties to the tenant of the spoke it connects through, unless that
        spoke is shared" rule) — a spoke bound to another tenant, unbound, or
        the SHARED tenant (ambiguous — it can serve agents belonging to
        different tenants) must still go through an admin, or the agent can
        skip this click entirely with a tenant-scoped onboarding PSK (see
        main.py's ``_try_psk_agent_auto_approve``)."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # The spoke the agent connects through must be bound to exactly this tenant; anything else
        # looks like "not found".
        bound = hub.state.get_spoke_tenant(spoke_id) or ""
        if bound != tenant:
            raise HTTPException(status_code=404, detail="Not found")
        from routes.setup import _perform_agent_approval  # lazy: avoid import cycle
        # Run the same approval routine the admin screen uses, pinning the agent to this tenant.
        try:
            summary = await _perform_agent_approval(hub, spoke_id, agent_id,
                                                     explicit_tenant=tenant)
        # Unexpected failures are logged with a traceback and surfaced as a 500.
        except Exception as e:  # noqa: BLE001
            logger.exception("approve_tenant_agent failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Audit-log who approved which agent.
        logger.info("tenant agent approve: agent '%s' approved by tenant %s via spoke '%s'",
                    agent_id, tenant, spoke_id)
        return {"status": "ok", **summary}

    @app.post("/tenant/{tenant}/agents/{agent_id}/cs-config",
              operation_id="tenant_set_agent_cs_enabled")
    async def set_tenant_agent_cs_config(request: Request, tenant: str, agent_id: str):
        """Tenant-admin self-service toggle for Client-Simulation mode on
        THEIR OWN already-approved Proxmox node agent — the tenant-admin
        counterpart to the Global-Admin-only ``POST
        /api/pxmx/agents/{agent_id}/config`` (which ALSO exposes
        display_name/crontab/an arbitrary tenant re-pin, so that route stays
        admin-only). This route only ever flips ``enabled`` — it reaffirms
        the agent's OWN already-pinned tenant_id, it can never move the
        agent to a different tenant. Gated on that pin (not the owning
        spoke's binding, unlike ``approve_tenant_agent``): a PSK-auto-approved
        or admin-approved agent may be bound to a tenant whose OWN spoke
        isn't (e.g. approved via a shared spoke), so the agent's tenant_id is
        the authoritative ownership signal here."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # The desired on/off state comes from the JSON body (anything malformed means off).
        body = await request.json()
        enabled = bool(body.get("enabled")) if isinstance(body, dict) else False
        # Look up (creating if needed) the agent's stored config and its client-simulation block.
        agent_pk = hub._agent_primary_key(agent_id)
        store = hub.state.system_state.setdefault("agent_config", {})
        entry = dict(store.get(agent_pk, {}))
        cs_cfg = dict(entry.get("client_simulation") or {})
        # The agent must already be pinned to this tenant; otherwise pretend it does not exist.
        bound = (cs_cfg.get("tenant_id") or "").strip()
        if bound != tenant:
            raise HTTPException(status_code=404, detail="Not found")
        # Flip only the enabled flag and write the config back, flagging state for saving.
        cs_cfg["enabled"] = enabled
        entry["client_simulation"] = cs_cfg
        store[agent_pk] = entry
        hub.state._mark_dirty()
        from routes.pxmx import push_pxmx_agent_config, bust_pxmx_agents_cache  # lazy: avoid import cycle
        # Push the new client-simulation config to the agent (or queue it if offline).
        pushed, queued = await push_pxmx_agent_config(
            hub, agent_id, {"client_simulation": cs_cfg})
        # So the toggle reflects immediately on the next My Devices refresh
        # instead of a cached pre-toggle snapshot for up to 30s.
        bust_pxmx_agents_cache()
        # Audit-log the change and report whether it was pushed live or queued.
        logger.info("tenant agent cs-config: agent '%s' enabled=%s set by tenant %s",
                    agent_id, enabled, tenant)
        return {"status": "ok", "enabled": enabled, "pushed": pushed, "queued": queued}

    @app.delete("/tenant/{tenant}/spokes/{spoke_id}", operation_id="tenant_delete_own_spoke")
    async def delete_tenant_spoke(request: Request, tenant: str, spoke_id: str):
        """Permanently remove a spoke/agent bound to ``tenant`` — the tenant-admin
        counterpart to the Global-Admin ``DELETE /setup/spokes/{id}``. Two gates
        stack: ``_require_owns_tenant`` (caller must own ``tenant``) AND the
        spoke's own tenant binding must equal ``tenant`` — a spoke bound to
        another tenant (or the shared tenant, which is admin-managed) is treated
        as not-found so existence never leaks across tenants (anti-IDOR, mirrors
        tenant_devices.py ``_owns``). The actual teardown reuses the shared
        ``hard_delete_spoke`` helper so admin + tenant deletes stay identical."""
        # Refuse unless the caller owns this tenant.
        _require_owns_tenant(request, tenant)
        # Ownership by tenant binding — never a client claim. A tenant-admin may
        # only delete a spoke homed to a tenant they own; the shared tenant is
        # admin-managed and thus excluded (get_spoke_tenant returns the real
        # binding, so a shared spoke won't match a tenant-admin's own tenant).
        sess = _session_user(request)
        bound = hub.state.get_spoke_tenant(spoke_id) or ""
        if bound != tenant and not _is_admin(sess):
            raise HTTPException(status_code=404, detail="Not found")
        # Do the full teardown; any failure is logged with a traceback and surfaced as a 500.
        try:
            from routes.setup import hard_delete_spoke  # lazy: avoid import cycle
            await hard_delete_spoke(hub, spoke_id)
            logger.info("tenant spoke delete: '%s' removed by tenant %s", spoke_id, tenant)
            return {"status": "ok", "message": f"Spoke '{spoke_id}' removed."}
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_tenant_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))
