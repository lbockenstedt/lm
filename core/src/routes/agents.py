"""Generic-agent provision + agent command/load-role routes."""
from api import (
    HTTPException, Request, logger,
)
from access import valid_display_name, valid_identifier, can_bind_spoke


def _agent_role_preflight(hub, spoke_id):
    """Shared connected + authenticated preflight for the role-management routes
    (admin ``/api/agent/*`` and tenant ``/tenant/agent/*``). Raises 503 with an
    actionable hint when the agent is offline or a legacy/incompatible node that
    connects but never adopts a session key (so LOAD_ROLE would hang to the 120s
    timeout)."""
    if hub._primary_key(spoke_id) not in hub.active_connections:
        raise HTTPException(status_code=503, detail=f"Agent {spoke_id} not connected")
    _ok, reason = hub.spoke_can_accept_commands(spoke_id)
    if reason == hub._CMD_UNAUTHENTICATED:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Agent {spoke_id} is connected but not authenticated — it has "
                f"not adopted a session key, so it cannot load roles. This is a "
                f"legacy/incompatible agent: reinstall it via install_menu.sh "
                f"(agent/install_agent.sh), approve the base generic node, then retry."
            ),
        )


async def _load_roles_impl(hub, spoke_id, data):
    """Core LOAD_ROLE dispatch shared by the admin + tenant role routes. Accepts
    either a batch (``{"roles": [...]}`` loaded sequentially) or a single
    ``{"role": ..., "config": ...}``. Returns the agent's payload/results. The
    caller MUST run :func:`_agent_role_preflight` first."""
    roles = data.get("roles")
    if isinstance(roles, list) and roles:
        results = []
        for r in roles:
            rname = (r.get("role") if isinstance(r, dict) else r)
            rcfg = (r.get("config", {}) if isinstance(r, dict) else {})
            if not rname:
                results.append({"role": None, "status": "ERROR",
                                "message": "role is required"})
                continue
            if rname == "ldap-server":
                rcfg = _enrich_ldap_server_config(hub, rcfg)
            try:
                res = await hub.request_response(spoke_id, "LOAD_ROLE",
                                                 {"role": rname, "config": rcfg},
                                                 timeout=120.0)
                pl = res.get("payload", {}).get("data", res) if isinstance(res, dict) else res
                if isinstance(pl, dict) and pl.get("status") == "SUCCESS" \
                        and pl.get("morph") is True and pl.get("module_type"):
                    hub.spoke_module_types[hub._primary_key(spoke_id)] = pl["module_type"]
                    logger.info("Agent %s morphed to module_type %s",
                                spoke_id, pl["module_type"])
                results.append({"role": rname,
                                **(pl if isinstance(pl, dict) else {"result": pl})})
            except Exception as e:  # noqa: BLE001 — one role's failure ≠ batch fail
                logger.exception("load_agent_role[%s] failed", rname)
                results.append({"role": rname, "status": "ERROR", "message": str(e)})
        return {"status": "SUCCESS", "results": results}
    role   = data.get("role")
    config = data.get("config", {})
    if not role:
        raise HTTPException(status_code=400, detail="role is required")
    if role == "ldap-server":
        config = _enrich_ldap_server_config(hub, config)
    # LOAD_ROLE on the multi-role agent shallow-clones the role's sibling repo on
    # first load — a network git clone that routinely exceeds the 5s default.
    result = await hub.request_response(spoke_id, "LOAD_ROLE",
                                        {"role": role, "config": config},
                                        timeout=120.0)
    payload = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
    # Multi-role agent: the base stays module_type "agent" and HOSTS the role as
    # a new sub-spoke; only a legacy single-role morph (explicit ``morph: true``)
    # rewrites the base's module_type.
    if isinstance(payload, dict) and payload.get("status") == "SUCCESS":
        if payload.get("morph") is True:
            new_mtype = payload.get("module_type")
            if new_mtype:
                hub.spoke_module_types[hub._primary_key(spoke_id)] = new_mtype
                logger.info("Agent %s morphed to module_type %s", spoke_id, new_mtype)
        else:
            sub_id = payload.get("sub_spoke_id")
            if sub_id:
                logger.info("Agent %s hosting role sub-spoke %s (module_type=%s)",
                            spoke_id, sub_id, payload.get("module_type"))
    return payload


def _enrich_ldap_server_config(hub, cfg):
    """Inject the Entra app creds into an ``ldap-server`` LOAD_ROLE config from
    the hub's OIDC config so the WebUI never has to handle them. The installer
    consumes --entra-tenant/--entra-client/--entra-cert/--entra-key; source them
    from get_oidc_config (tenant_id, client_id, cert path, key path). Only fills
    values the caller didn't already provide."""
    cfg = dict(cfg or {})
    try:
        from security.oidc import get_oidc_config
        oc = get_oidc_config(hub)
        cfg.setdefault("entra_tenant", oc.tenant_id)
        cfg.setdefault("entra_client", oc.client_id)
        cfg.setdefault("entra_cert", oc.cert_path)
        cfg.setdefault("entra_key", oc.key_path)
    except Exception as e:  # noqa: BLE001 — Entra optional; deploy LDAP anyway
        logger.warning("ldap-server: could not source Entra creds from OIDC: %s", e)
    return cfg


def register(app, hub, ctx):
    """Register agents routes on the Hub app."""

    @app.post("/api/generic/provision")
    async def provision_generic_agent(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            agent_id = data.get("agent_id")
            module_id = data.get("module_id")
            repo_url = data.get("repo_url")
            custom_spoke_id = data.get("spoke_id")
            display_name = data.get("display_name")

            if not agent_id or not module_id:
                raise HTTPException(status_code=400, detail="Missing agent_id or module_id")
            # Validate identifiers BEFORE they're relayed to the agent. module_id
            # is mapped to a role and sent in a LOAD_ROLE payload to the agent; an
            # arbitrary string would be forwarded verbatim, so confine it to the
            # identifier grammar (and the known role set below). agent_id /
            # custom_spoke_id are used as spoke lookups/keys; display_name is
            # stored/rendered (no shell), so it gets the softer display check.
            if not valid_identifier(agent_id):
                raise HTTPException(status_code=400, detail="Invalid agent_id")
            if not valid_identifier(module_id):
                raise HTTPException(status_code=400, detail="Invalid module_id")
            if custom_spoke_id and not valid_identifier(custom_spoke_id):
                raise HTTPException(status_code=400, detail="Invalid spoke_id")
            if display_name and not valid_display_name(display_name):
                raise HTTPException(status_code=400, detail="Invalid display_name")

            if hub._primary_key(agent_id) not in hub.active_connections:
                raise HTTPException(status_code=503, detail=f"Generic agent {agent_id} not connected")

            # Unified model: provisioning a module on an agent = loading its ROLE
            # (the agent self-installs from _ROLE_MAP — the caller's repo_url is no
            # longer needed). The module runs as a sub-spoke {agent}-{role}.
            role = {
                "cppm": "cppm", "cs": "simulation", "dhcp": "dhcp", "dns": "dns",
                "ldap": "ldap", "netbox": "netbox", "opnsense": "opnsense",
                "pxmx": "proxmox", "nw": "network", "le": "le", "console": "console",
                "statuspage": "statuspage",
            }.get(module_id, module_id)
            result = await hub.request_response(agent_id, "LOAD_ROLE", {"role": role})
            return result
        except HTTPException:
            raise  # 4xx/503 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.error(f"Provisioning failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # ─── Generic Agent API ────────────────────────────────────────────────────

    @app.get("/api/agents")
    async def list_agents(request: Request):
        """List all connected generic agents and their active roles.

        Fleet-wide roster (every connected agent + its loaded roles, regardless
        of tenant) — Global-Admin-only. ``/api/agent/`` (singular, the command/
        load-role namespace) is already admin-gated by the middleware's
        ``_ADMIN_API_PREFIXES``; this plural roster was missed, so any
        authenticated user (incl. a single-tenant non-admin) could enumerate the
        whole fleet. A tenant Admin doesn't gain fleet visibility via the role
        split (fleet stays Global-only — see the RBAC invariant)."""
        sess = ctx._session_user(request)
        if not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        hub = app.state.hub
        agents = []
        _meta = hub.state.system_state.get("module_metadata", {})
        for sid, mtype in hub.spoke_module_types.items():
            if mtype == "agent" and sid in hub.active_connections:
                agents.append({
                    "spoke_id": sid,
                    "module_type": mtype,
                    # Canonical guid (alias of install_uuid; primary key in Phase 2).
                    "spoke_guid": ((_meta.get(sid) or {}).get("install_uuid", "")),
                })
        return {"agents": agents}

    @app.post("/api/agent/{spoke_id}/command")
    async def send_agent_command(spoke_id: str, request: Request):
        """Send any command to a connected generic agent."""
        hub = app.state.hub
        if hub._primary_key(spoke_id) not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Agent {spoke_id} not connected")
        # Fail fast on a connected-but-unauthenticated agent (see
        # LabManagerHub.spoke_can_accept_commands). The Load Role modal's
        # GET_AVAILABLE_ROLES fetch rides this route at the default 5s
        # request_response timeout; a protocol-incompatible legacy
        # GenericLeafAgent never adopts a session key, so without this gate
        # every modal open hangs 5s with "Timed out waiting for spoke
        # response". Surface the same actionable reinstall hint as load-role.
        _ok, reason = hub.spoke_can_accept_commands(spoke_id)
        if reason == hub._CMD_UNAUTHENTICATED:
            raise HTTPException(
                status_code=503,
                detail=(
                    f"Agent {spoke_id} is connected but not authenticated — it has "
                    f"not adopted a session key, so it cannot accept commands. "
                    f"This is a legacy/incompatible agent: reinstall it via "
                    f"install_menu.sh (agent/install_agent.sh), approve the base "
                    f"generic node, then retry."
                ),
            )
        try:
            data = await request.json()
            command = data.get("command")
            payload = data.get("data", {})
            if not command:
                raise HTTPException(status_code=400, detail="command is required")
            # Long-running agent ops (curl+install/manage.py) blow past the 5s
            # default request_response timeout — give them the 120s window used by
            # load-role. NETBOX_RESET_ADMIN_PASSWORD fetches install.sh + runs a
            # Django shell on the deployed NetBox.
            _LONG_OPS = {"NETBOX_RESET_ADMIN_PASSWORD"}
            if command in _LONG_OPS:
                result = await hub.request_response(spoke_id, command, payload, timeout=180.0)
            else:
                result = await hub.request_response(spoke_id, command, payload)
            return result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("send_agent_command failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/agent/{spoke_id}/load-role")
    async def load_agent_role(spoke_id: str, request: Request):
        """
        Morph a generic agent into a specific role (dns, dhcp, …).
        The agent installs required packages, loads the role, and re-registers
        its module_type so hub APIs can route to it.
        """
        hub = app.state.hub
        _agent_role_preflight(hub, spoke_id)
        try:
            data = await request.json()
            return await _load_roles_impl(hub, spoke_id, data)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("load_agent_role failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── Tenant-scoped role management (a tenant-admin's OWN spokes) ───────────
    # A tenant-admin can't reach /api/agent/* (admin-only: arbitrary remote code
    # on agents). These three routes expose ONLY role load/unload/list, gated by
    # can_bind_spoke (Global Admin → any spoke; tenant-admin → strictly a spoke
    # bound to one of their OWN tenants, never shared/other-tenant), so a tenant
    # admin can morph roles on the nodes they own without the arbitrary-command
    # surface. The /tenant/ prefix is already tenant-admin-gated by the api.py
    # middleware; this adds the per-spoke ownership check.
    def _tenant_role_guard(request, spoke_id):
        sess = ctx._session_user(request)
        if not can_bind_spoke(hub, sess, hub._primary_key(spoke_id)):
            raise HTTPException(
                status_code=403,
                detail="You can only manage roles on a spoke assigned to your tenant.")

    @app.post("/tenant/agent/{spoke_id}/load-role")
    async def tenant_load_agent_role(spoke_id: str, request: Request):
        """Load one or more roles on a spoke the caller owns (tenant-scoped twin
        of ``/api/agent/{spoke_id}/load-role``)."""
        hub = app.state.hub
        _tenant_role_guard(request, spoke_id)
        _agent_role_preflight(hub, spoke_id)
        try:
            data = await request.json()
            return await _load_roles_impl(hub, spoke_id, data)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("tenant_load_agent_role failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/tenant/agent/{spoke_id}/unload-role")
    async def tenant_unload_agent_role(spoke_id: str, request: Request):
        """Unload a single role from a spoke the caller owns. Only UNLOAD_ROLE is
        relayed (no arbitrary-command surface)."""
        hub = app.state.hub
        _tenant_role_guard(request, spoke_id)
        _agent_role_preflight(hub, spoke_id)
        try:
            data = await request.json()
            role = data.get("role")
            if not role:
                raise HTTPException(status_code=400, detail="role is required")
            result = await hub.request_response(spoke_id, "UNLOAD_ROLE",
                                                {"role": role}, timeout=60.0)
            return result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("tenant_unload_agent_role failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/tenant/agent/{spoke_id}/roles")
    async def tenant_list_agent_roles(spoke_id: str, request: Request):
        """List the roles currently loaded on a spoke the caller owns (relays
        GET_AVAILABLE_ROLES). Returns the agent's payload ({available, active})."""
        hub = app.state.hub
        _tenant_role_guard(request, spoke_id)
        _agent_role_preflight(hub, spoke_id)
        try:
            result = await hub.request_response(spoke_id, "GET_AVAILABLE_ROLES", {})
            return result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("tenant_list_agent_roles failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── DNS API ──────────────────────────────────────────────────────────────
