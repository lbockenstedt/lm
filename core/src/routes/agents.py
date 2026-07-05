"""Generic-agent provision + agent command/load-role routes."""
from api import (
    HTTPException, Request, logger,
)


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

            if agent_id not in hub.active_connections:
                raise HTTPException(status_code=503, detail=f"Generic agent {agent_id} not connected")

            # Unified model: provisioning a module on an agent = loading its ROLE
            # (the agent self-installs from _ROLE_MAP — the caller's repo_url is no
            # longer needed). The module runs as a sub-spoke {agent}-{role}.
            role = {
                "cppm": "cppm", "cs": "simulation", "dhcp": "dhcp", "dns": "dns",
                "ldap": "ldap", "netbox": "netbox", "opnsense": "opnsense",
                "pxmx": "proxmox", "nw": "network", "le": "le", "console": "console",
            }.get(module_id, module_id)
            result = await hub.request_response(agent_id, "LOAD_ROLE", {"role": role})
            return result
        except Exception as e:
            logger.error(f"Provisioning failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # ─── Generic Agent API ────────────────────────────────────────────────────

    @app.get("/api/agents")
    async def list_agents():
        """List all connected generic agents and their active roles."""
        hub = app.state.hub
        agents = []
        for sid, mtype in hub.spoke_module_types.items():
            if mtype == "agent" and sid in hub.active_connections:
                agents.append({"spoke_id": sid, "module_type": mtype})
        return {"agents": agents}

    @app.post("/api/agent/{spoke_id}/command")
    async def send_agent_command(spoke_id: str, request: Request):
        """Send any command to a connected generic agent."""
        hub = app.state.hub
        if spoke_id not in hub.active_connections:
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
        if spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Agent {spoke_id} not connected")
        # Fail fast on a connected-but-unauthenticated agent (see
        # LabManagerHub.spoke_can_accept_commands). A protocol-incompatible
        # legacy GenericLeafAgent connects + heartbeats but never adopts a
        # session key, so LOAD_ROLE would otherwise hang to the 120s
        # request_response timeout with a generic "Timed out waiting for spoke
        # response". Surface an actionable reinstall hint instead.
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
        try:
            data   = await request.json()
            role   = data.get("role")
            config = data.get("config", {})
            if not role:
                raise HTTPException(status_code=400, detail="role is required")
            # LOAD_ROLE on the multi-role agent shallow-clones the role's sibling
            # repo (e.g. github.com/lbockenstedt/opnsense.git) on first load — a
            # network git clone that routinely exceeds the 5s request_response
            # default and surfaced as "Timed out waiting for spoke response".
            # 120s mirrors the long-op timeout used elsewhere (api.py:2536).
            result = await hub.request_response(spoke_id, "LOAD_ROLE",
                                                {"role": role, "config": config},
                                                timeout=120.0)
            payload = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            # Multi-role agent: the base stays module_type "agent" and HOSTS the
            # role as a new sub-spoke ({base}-{role}) that registers its own
            # module_type on connect — so do NOT overwrite the base's type here.
            # Legacy single-role morph (base BECAME the role) is gated on an
            # explicit `morph: true` in the response, which the multi-role agent
            # never sends; only then do we update spoke_module_types[base].
            if isinstance(payload, dict) and payload.get("status") == "SUCCESS":
                if payload.get("morph") is True:
                    new_mtype = payload.get("module_type")
                    if new_mtype:
                        hub.spoke_module_types[spoke_id] = new_mtype
                        logger.info("Agent %s morphed to module_type %s", spoke_id, new_mtype)
                else:
                    sub_id = payload.get("sub_spoke_id")
                    if sub_id:
                        logger.info("Agent %s hosting role sub-spoke %s (module_type=%s)",
                                    spoke_id, sub_id, payload.get("module_type"))
            return payload
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("load_agent_role failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── DNS API ──────────────────────────────────────────────────────────────
