import os
import subprocess
import json
import time
import uuid
import logging
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Any
import uvicorn

logger = logging.getLogger("Hub")

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement

def create_app(hub):
    app = FastAPI(title="Lab Manager Hub API")

    # Enable CORS to allow WebUI to connect from different origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Attach hub instance to app state for access in routes
    app.state.hub = hub

    @app.get("/status")
    async def get_status():
        hub = app.state.hub
        if not getattr(hub, "is_ready", False):
            raise HTTPException(status_code=503, detail="Hub is not yet ready (WebSocket server starting)")
        metrics = await hub.get_system_metrics()
        return {
            "active_connections": list(hub.active_connections.keys()),
            "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
            "state": hub.state.system_state,
            "metrics": metrics
        }


    @app.get("/vm/{vm_id}/firewall")
    async def get_vm_firewall(vm_id: str):
        hub = app.state.hub

        # 1. Find the IP for this VM from the state manager
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        if not ip:
            raise HTTPException(status_code=404, detail=f"No IP address found for VM {vm_id}")

        # 2. Identify the OPNsense spoke
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)

        if not opn_spoke:
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")

        # 3. Use the async bridge to request rules from the spoke
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
            return result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/reset-secret")
    async def reset_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            hub.key_manager.delete_spoke_key(spoke_id)
            return {"status": "success", "message": f"Secret for spoke {spoke_id} has been reset. It can now be re-onboarded."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/rotate-secret")
    async def rotate_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            new_key = hub.key_manager.rotate_key(spoke_id)
            return {"status": "success", "new_secret": new_key.secret}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spokes/{spoke_id}/agents")
    async def get_spoke_agents(spoke_id: str):
        hub = app.state.hub
        # In the current state, agents are tracked in the system_state under 'known_modules'
        # We filter for agents that are associated with this spoke.
        # Note: This requires the la-manager state to track agent-to-spoke mapping.
        known_spokes = hub.state.system_state.get("known_modules", [])
        # For now, we return agents that have 'pxmx' or other patterns if they are linked
        # In the future, we will have an explicit map in state_manager.
        agents = [sid for sid in known_spokes if sid != spoke_id] # Placeholder
        return {"spoke_id": spoke_id, "agents": agents}

    @app.post("/setup/spokes/{spoke_id}/agents/{agent_id}/approve")
    async def approve_agent_under_spoke(spoke_id: str, agent_id: str):
        hub = app.state.hub
        try:
            # Mark the agent as approved in the state
            hub.state.register_module(agent_id, approved=True)
            hub.state.save_state()
            hub.approved_modules[agent_id] = True

            # Relay the approval to the agent via the spoke
            if spoke_id in hub.active_connections:
                msg_id = str(uuid.uuid4())
                msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=spoke_id
                    ),
                    payload=MessagePayload(
                        type="SPOKE_RELAY",
                        data={
                            "target_agent_id": agent_id,
                            "command": "APPROVAL_SUCCESS",
                            "payload": {}
                        }
                    )
                )
                await hub.send_to_spoke(msg)

            return {"status": "success", "message": f"Agent {agent_id} approved under spoke {spoke_id}"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        module_names = hub.state.system_state.get("module_names", {})

        spokes_status = []
        for sid in known_spokes:
            spokes_status.append({
                "spoke_id": sid,
                "display_name": module_names.get(sid, sid),
                "approved": hub.approved_modules.get(sid, False)
            })

        return {"spokes": spokes_status}

    @app.post("/setup/approve_spoke")
    async def approve_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            action = data.get("action", "approve") # Default to approve

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            if action == "unapprove":
                # Remove approval status
                hub.state.register_module(spoke_id, approved=False)
                hub.approved_modules[spoke_id] = False
            else:
                # Update approval status
                hub.state.register_module(spoke_id, approved=True)
                hub.approved_modules[spoke_id] = True

            hub.state.save_state() # Persist status immediately

            # Notify the spoke if connected
            if spoke_id in hub.active_connections:
                msg_id = str(uuid.uuid4())
                msg_type = "APPROVED" if action != "unapprove" else "DENIED"
                approval_msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=spoke_id
                    ),
                    payload=MessagePayload(type=msg_type, data={})
                )
                await hub.send_to_spoke(approval_msg)

                # Immediately push config and hub secret now that it's approved
                if action != "unapprove":
                    await hub.push_config_to_spoke(spoke_id)

            return {"status": "success", "message": f"Spoke {spoke_id} {'approved' if action != 'unapprove' else 'un-approved'}."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/cppm-config")
    async def get_cppm_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("cppm", {})
        return {"config": config}

    @app.post("/setup/cppm-config")
    async def update_cppm_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Save to persistent state
            global_config = hub.state.system_state.get("global_config", {})
            global_config["cppm"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            # Push to CPPM spoke if connected
            cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
            if cppm_spoke:
                msg_id = str(uuid.uuid4())
                msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=cppm_spoke
                    ),
                    payload=MessagePayload(type="update_config", data=config)
                )
                await hub.send_to_spoke(msg)
                return {"status": "success", "message": "Configuration updated and pushed to spoke."}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but CPPM spoke is not connected."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/pxmx-config")
    async def get_pxmx_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("pxmx", {
            "default_node": "pve",
            "cluster_id": "cluster-1"
        })
        return {"config": config}

    @app.post("/setup/pxmx-config")
    async def update_pxmx_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["pxmx"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            pxmx_spoke = next((sid for sid in hub.active_connections if "pxmx" in sid), None)
            if pxmx_spoke:
                msg_id = str(uuid.uuid4())
                msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=pxmx_spoke
                    ),
                    payload=MessagePayload(type="update_config", data=config)
                )
                await hub.send_to_spoke(msg)
                return {"status": "success", "message": "Configuration updated and pushed to spoke."}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but Proxmox spoke is not connected."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/ldap-config")
    async def get_ldap_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("ldap", {})
        return {"config": config}

    @app.post("/setup/ldap-config")
    async def update_ldap_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Map lowercase keys from UI to uppercase keys for spoke
            spoke_config = {
                "LDAP_SERVER_URL": config.get("server_url"),
                "LDAP_BASE_DN": config.get("base_dn"),
                "LDAP_ADMIN_DN": config.get("admin_dn"),
                "LDAP_ADMIN_PW": config.get("admin_pw"),
            }
            # Remove None values
            spoke_config = {k: v for k, v in spoke_config.items() if v is not None}

            global_config = hub.state.system_state.get("global_config", {})
            global_config["ldap"] = config # Store lowercase version in state for UI
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            ldap_spoke = next((sid for sid in hub.active_connections if "ldap" in sid), None)
            if ldap_spoke:
                msg_id = str(uuid.uuid4())
                msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=ldap_spoke
                    ),
                    payload=MessagePayload(type="UPDATE_CONFIG", data=spoke_config)
                )
                await hub.send_to_spoke(msg)
                return {"status": "success", "message": "LDAP configuration updated and pushed to spoke."}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but LDAP spoke is not connected."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-metadata")
    async def update_spoke_metadata(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            metadata = data.get("metadata", {})
            display_name = metadata.get("display_name")
            description = metadata.get("description")

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            if spoke_id not in hub.state.system_state["known_modules"]:
                raise HTTPException(status_code=404, detail="Spoke not found")

            hub.state.update_module_metadata(spoke_id, metadata)
            hub.state.save_state()

            # If display name changed, we can also trigger a hostname update if requested
            # However, usually hostname is a separate field.
            # If the user wants to sync display_name to hostname, we do it here.

            return {"status": "success", "message": f"Metadata for spoke {spoke_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spoke-metadata/{spoke_id}")
    async def get_spoke_metadata(spoke_id: str):
        hub = app.state.hub
        metadata = hub.state.system_state.get("module_metadata", {}).get(spoke_id, {})
        if not metadata:
            raise HTTPException(status_code=404, detail="Spoke metadata not found")
        return {"metadata": metadata}

    @app.get("/setup/firewalls")
    async def get_firewalls():
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        return {"firewalls": firewalls}

    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str):
        hub = app.state.hub
        logger.info(f"API: Triggering cache refresh for firewall {firewall_id}")
        success = await hub.poll_opnsense_rules(firewall_id=firewall_id)
        if not success:
            logger.error(f"API: Cache refresh failed for firewall {firewall_id}")
            raise HTTPException(status_code=503, detail=f"Failed to refresh cache for firewall {firewall_id} (Spoke not connected or API error)")

        return {"status": "success", "message": f"Cache for firewall {firewall_id} refreshed successfully!"}

    @app.get("/api/firewall/{firewall_id}/{endpoint}")
    async def get_firewall_data(firewall_id: str, endpoint: str):
        hub = app.state.hub

        # 1. Find the firewall config
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")

        # 2. Map endpoint to spoke command based on model
        model = fw.get("model", "opnsense").lower()
        command_map = {
            "opnsense": {
                "rules": "OPNSENSE_GET_ALL_RULES",
                "interfaces": "GET_INTERFACE_STATUS",
                "health": "GET_SYSTEM_HEALTH",
                "dhcp": "OPNSENSE_GET_DHCP_LEASES",
                "nat": "OPNSENSE_GET_NAT_POLICIES",
                "dns": "OPNSENSE_GET_DNS_RECORDS",
            },
            "juniper": {
                # Placeholder for future Juniper commands
                "rules": "JUNIPER_GET_RULES",
                "health": "JUNIPER_GET_HEALTH",
            }
        }

        model_commands = command_map.get(model, {})
        spoke_cmd = model_commands.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported for model {model}")

        # 3. Identify the spoke
        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")

        try:
            result = await hub.request_response(spoke_id, spoke_cmd, {})
            # Robust extraction
            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    data = result
            else:
                data = result
            return data
        except Exception as e:
            logger.error(f"Error fetching {endpoint} for firewall {firewall_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/firewalls")
    async def add_firewall(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_fw = data.get("firewall", {})
            if not new_fw.get("name") or not new_fw.get("model"):
                raise HTTPException(status_code=400, detail="Missing firewall name or model")

            if "id" not in new_fw:
                import uuid
                new_fw["id"] = str(uuid.uuid4())

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])
            firewalls.append(new_fw)
            global_config["firewalls"] = firewalls
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "success", "firewall": new_fw}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/firewalls/{firewall_id}")
    async def update_firewall(firewall_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])

            fw_index = next((i for i, fw in enumerate(firewalls) if fw["id"] == firewall_id), None)
            if fw_index is None:
                raise HTTPException(status_code=404, detail="Firewall not found")

            firewalls[fw_index].update(update_data)
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            # Push config to the associated spoke if connected
            spoke_id = firewalls[fw_index].get("spoke_id")
            if spoke_id and spoke_id in hub.active_connections:
                msg_id = str(uuid.uuid4())
                msg = Message(
                    header=MessageHeader(
                        message_id=msg_id,
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=spoke_id
                    ),
                    payload=MessagePayload(type="UPDATE_CONFIG", data=firewalls[fw_index])
                )
                await hub.send_to_spoke(msg)
                return {"status": "success", "message": "Firewall configuration updated and pushed to spoke."}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but associated spoke is not connected."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/firewalls/{firewall_id}")
    async def delete_firewall(firewall_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        firewalls = global_config.get("firewalls", [])

        original_len = len(firewalls)
        firewalls[:] = [fw for fw in firewalls if fw["id"] != firewall_id]

        if len(firewalls) == original_len:
            raise HTTPException(status_code=404, detail="Firewall not found")

        hub.state.system_state["global_config"] = global_config
        hub.state.save_state()
        return {"status": "success", "message": f"Firewall {firewall_id} deleted."}

    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str):
        hub = app.state.hub
        logger.info(f"API: Triggering cache refresh for firewall {firewall_id}")
        success = await hub.poll_opnsense_rules(firewall_id=firewall_id)
        if not success:
            logger.error(f"API: Cache refresh failed for firewall {firewall_id}")
            raise HTTPException(status_code=503, detail=f"Failed to refresh cache for firewall {firewall_id} (Spoke not connected or API error)")

        return {"status": "success", "message": f"Cache for firewall {firewall_id} refreshed successfully!"}

    @app.get("/cppm/refresh")
    async def refresh_cppm_cache():
        hub = app.state.hub
        logger.info("API: Triggering CPPM cache refresh")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected for refresh")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_REFRESH_CACHE", {})
            return result
        except Exception as e:
            logger.error(f"API: Error refreshing CPPM cache: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/cppm/health")
    async def get_cppm_health():
        hub = app.state.hub
        logger.info("API: Requesting CPPM health")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_SYSTEM_HEALTH", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM health: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM health: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/devices")
    async def get_cppm_devices():
        hub = app.state.hub
        logger.info("API: Requesting CPPM devices")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM devices: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/roles")
    async def get_cppm_roles():
        hub = app.state.hub
        logger.info("API: Requesting CPPM roles")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ROLES", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/logs")
    async def get_cppm_logs(start: str, end: str):
        hub = app.state.hub
        logger.info(f"API: Requesting CPPM logs from {start} to {end}")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "GET_LOGS", {"start": start, "end": end})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM logs: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/vm/{vm_id}/details")

    async def get_vm_details(vm_id: str):
        hub = app.state.hub
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        details = {
            "vm_id": vm_id,
            "metadata": res_info,
            "proxmox": {"status": "OFFLINE"},
            "opnsense": {"status": "OFFLINE", "rules": [], "dhcp": None},
            "cppm": {"status": "OFFLINE", "policy": "Unknown"}
        }

        # 1. Fetch from Proxmox
        pxmx_spoke = next((sid for sid in hub.active_connections if "pxmx" in sid), None)
        if pxmx_spoke:
            px_res_raw = await hub.request_response(pxmx_spoke, "GET_VM_INFO", {"vm_id": vm_id})
            px_res = px_res_raw.get("payload", {}).get("data", {}) if isinstance(px_res_raw, dict) else {}
            details["proxmox"] = px_res if px_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": px_res.get("message", "Unknown error")}

        # 2. Fetch from OPNsense
        opn_spokes = [sid for sid in hub.active_connections if "opn" in sid]
        if opn_spokes and ip:
            # Try to find rules for this IP from any connected OPNsense spoke
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
                        break # Found the firewall managing this VM

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

        # 3. Fetch from CPPM
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if cppm_spoke and ip:
            cppm_res_raw = await hub.request_response(cppm_spoke, "CPPM_GET_POLICY_BY_IP", {"ip": ip})
            cppm_res = cppm_res_raw.get("payload", {}).get("data", {}) if isinstance(cppm_res_raw, dict) else {}
            details["cppm"] = cppm_res if cppm_res.get("status") == "SUCCESS" else {"status": "ERROR", "error": cppm_res.get("message", "Unknown error")}

        return details

    @app.get("/api/aggregate/opnsense")
    async def aggregate_opnsense():
        hub = app.state.hub
        opn_spokes = [sid for sid in hub.active_connections if "opn" in sid]

        results = []
        for sid in opn_spokes:
            try:
                # Fetch health and interface status to provide a summary
                health_raw = await hub.request_response(sid, "GET_SYSTEM_HEALTH", {})
                int_raw = await hub.request_response(sid, "GET_INTERFACE_STATUS", {})

                health_data = health_raw.get("payload", {}).get("data", {}) if isinstance(health_raw, dict) else {}
                int_data = int_raw.get("payload", {}).get("data", {}) if isinstance(int_raw, dict) else {}

                results.append({
                    "spoke_id": sid,
                    "spoke_online": True,
                    "health": health_data,
                    "interfaces": int_data,
                    "status": "ONLINE"
                })
            except Exception as e:
                results.append({
                    "spoke_id": sid,
                    "spoke_online": False,
                    "status": "ERROR",
                    "error": str(e)
                })

        return {"hosts": results}

    @app.get("/api/aggregate/proxmox")
    async def aggregate_proxmox():
        hub = app.state.hub
        pxmx_spokes = [sid for sid in hub.active_connections if "pxmx" in sid]

        results = []
        for sid in pxmx_spokes:
            try:
                # Assuming Proxmox spokes have a similar health/info command
                res_raw = await hub.request_response(sid, "GET_VM_INFO", {"vm_id": "all"})
                res_data = res_raw.get("payload", {}).get("data", {}) if isinstance(res_raw, dict) else {}

                results.append({
                    "spoke_id": sid,
                    "spoke_online": True,
                    "data": res_data,
                    "status": "ONLINE"
                })
            except Exception as e:
                results.append({
                    "spoke_id": sid,
                    "spoke_online": False,
                    "status": "ERROR",
                    "error": str(e)
                })

        return {"hosts": results}

    @app.get("/setup/debug-mode")
    async def get_debug_mode():
        hub = app.state.hub
        enabled = hub.state.get_global_config().get("debug_mode", False)
        return {"enabled": enabled}

    @app.post("/setup/debug-mode")
    async def toggle_debug_mode(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            enabled = data.get("enabled", False)

            # Update state
            global_config = hub.state.get_global_config()
            global_config["debug_mode"] = enabled
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            # Broadcast to all spokes
            await hub.broadcast_log_level(enabled)

            return {"status": "success", "enabled": enabled}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/docs/{section}")

    async def get_docs(section: str):
        """
        Extracts a specific help section from the README.md file.
        """
        try:
            readme_path = os.path.join(os.path.dirname(__file__), "../../README.md")
            if not os.path.exists(readme_path):
                raise HTTPException(status_code=404, detail="README.md documentation not found")

            with open(readme_path, "r") as f:
                content = f.read()

            # Documentation sections start with '### 📖 Help: section_id'
            marker = "### 📖 Help:"
            sections = content.split(marker)

            for s in sections[1:]: # Skip content before the first marker
                lines = s.split('\n')
                header = lines[0].strip()
                if header == section:
                    # Return everything until the next marker or end of file
                    # The 'sections' split already handles the boundaries,
                    # we just need to return the content after the section_id header
                    body = '\n'.join(lines[1:]).strip()
                    return {"content": body}

            raise HTTPException(status_code=404, detail=f"Help section '{section}' not found in documentation.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading documentation section {section}: {e}")
            raise HTTPException(status_code=500, detail=f"Error retrieving documentation: {str(e)}")

    @app.get("/setup/appearance")
    async def get_appearance():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("appearance", {
            "primary_color": "#01A982",
            "navy_color": "#263040",
            "logo_url": "assets/logo.png",
            "logo_url_right": "hpe-svg",
            "show_logo_left": True,
            "show_logo_right": True
        })
        return {"config": config}

    @app.post("/setup/appearance")
    async def update_appearance(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["appearance"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "success", "message": "Appearance settings updated."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/logs")


    @app.get("/setup/logs")
    async def get_system_logs():
        hub = app.state.hub
        return {"logs": list(hub.logs)}

    @app.get("/setup/logs/{module}")
    async def get_module_logs(module: str):
        try:
            # Map short UI module names to actual log filenames
            log_name_map = {
                "opn": "opnsense"
            }
            filename = log_name_map.get(module, module)

            # Log files are stored in /var/log/lm/<module>.log
            log_path = f"/var/log/lm/{filename}.log"
            if not os.path.exists(log_path):
                raise HTTPException(status_code=404, detail=f"Log file for {module} not found at {log_path}.")

            with open(log_path, "r") as f:
                logs = f.readlines()

            # Return last 500 lines
            return {"logs": [log.strip() for log in logs[-500:]]}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading logs for {module}: {e}")
            raise HTTPException(status_code=500, detail=f"Permission or I/O error reading {log_path}: {str(e)}")

    # --- Client Simulation API ---

    async def get_cs_spoke(hub):
        spoke_id = next((sid for sid in hub.active_connections if "cs" in sid), None)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="Client Simulation spoke not connected")
        return spoke_id

    @app.post("/api/sim/start")
    async def start_simulation(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            profile = data.get("profile", "default")
            spoke_id = await get_cs_spoke(hub)
            result = await hub.request_response(spoke_id, "CS_START_SIMULATION", {"profile": profile})
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/sim/stop")
    async def stop_simulation():
        hub = app.state.hub
        try:
            spoke_id = await get_cs_spoke(hub)
            result = await hub.request_response(spoke_id, "CS_STOP_SIMULATION", {})
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/sim/status")
    async def get_sim_status():
        hub = app.state.hub
        try:
            spoke_id = await get_cs_spoke(hub)
            result = await hub.request_response(spoke_id, "CS_GET_STATUS", {})
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/sim/telemetry/{vm_id}")
    async def get_sim_telemetry(vm_id: str):
        hub = app.state.hub
        try:
            spoke_id = await get_cs_spoke(hub)
            result = await hub.request_response(spoke_id, "CS_GET_TELEMETRY", {"vm_id": vm_id})
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/api-probe")
    async def probe_spoke_api(spoke_id: str, path: str):
        """
        Generic probe endpoint to explore any spoke's API.
        """
        hub = app.state.hub
        if spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Spoke {spoke_id} not connected")

        try:
            # Use a generic command type that the spoke should handle by calling the provided path
            result = await hub.request_response(spoke_id, "PROBE_API", {"path": path})
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Probe failed: {str(e)}")


    @app.get("/setup/diagnostics")
    async def get_diagnostics():
        hub = app.state.hub
        metrics = await hub.get_system_metrics()
        diagnostics = []
        # Get all known modules (approved or pending)
        known_spokes = hub.state.system_state.get("known_modules", [])

        for sid in known_spokes:
            ws = hub.active_connections.get(sid)
            telemetry = hub.spoke_telemetry.get(sid, {})

            diagnostics.append({
                "spoke_id": sid,
                "authenticated": sid in hub.active_connections,
                "approved": hub.approved_modules.get(sid, False),
                "heartbeat_status": hub.heartbeat.get_status(sid),
                "connection_state": ws.state if ws else "OFFLINE",
                "version": hub.spoke_versions.get(sid, "unknown"),
                "last_attempt": telemetry.get("last_attempt"),
                "last_status": telemetry.get("status", "UNKNOWN"),
                "last_error": telemetry.get("error")
            })

        # Get Hub version
        hub_version = await hub.get_local_version()

        # Get WebUI version (read from file)
        webui_version = "unknown"
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../ui/VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../../../GitHub/webui/VERSION")
            with open(version_path, "r") as f:
                webui_version = f.read().strip()
        except Exception:
            pass

        return {
            "spokes": diagnostics,
            "hub_version": hub_version,
            "webui_version": webui_version,
            "system": metrics
        }

    # --- LDAP Management API ---
    async def get_ldap_spoke(hub):
        spoke_id = next((sid for sid in hub.active_connections if "ldap" in sid), None)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        return spoke_id

    @app.get("/api/ldap/ous")
    async def get_ldap_ous():
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            result = await hub.request_response(spoke_id, "LIST_OUS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/ous")
    async def create_ldap_ou(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_OU", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/users")
    async def get_ldap_users():
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            result = await hub.request_response(spoke_id, "LIST_USERS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_USER", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/groups")
    async def get_ldap_groups():
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            result = await hub.request_response(spoke_id, "LIST_GROUPS", {})
            return result.get("data", result) if isinstance(result, dict) else result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "CREATE_GROUP", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/group")
    async def add_ldap_user_to_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "ADD_USER_TO_GROUP", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users/group")
    async def remove_ldap_user_from_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "REMOVE_USER_FROM_GROUP", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/entity")
    async def delete_ldap_entity(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            result = await hub.request_response(spoke_id, "DELETE_ENTITY", data)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/update")
    async def trigger_update(request: Request):
        """
        Triggers a git pull and restarts the service to apply updates.
        """
        hub = app.state.hub
        # Check for force parameter in query string
        force_param = request.query_params.get("force", "false")
        force = force_param.lower() == "true"
        logger.info(f"API: Triggering update with force={force} (param: {force_param})")
        success = await hub.perform_update(force=force)
        if isinstance(success, dict):

            if success.get("status") == "success":
                return {"status": "success", "message": success["message"]}
            elif success.get("status") == "no_update":
                return {"status": "no_update", "message": success["message"]}
            else:
                raise HTTPException(status_code=500, detail=success.get("message", "Update failed"))
        elif success:
            return {"status": "success", "message": "Update triggered. The server is restarting..."}
        else:
            raise HTTPException(status_code=500, detail="Update failed. Check Hub logs.")

    @app.get("/setup/modules")
    async def get_modules():
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        is_single_server = global_config.get("single_server_mode", False)

        modules = {
            "cppm": {"path": "cppm/install.sh", "installed": False},
            "cs": {"path": "cs/install_cs.sh", "installed": False},
            "ldap": {"path": "ldap/install_ldap.sh", "installed": False},
            "netbox": {"path": "netbox/install.sh", "installed": False},
            "opnsense": {"path": "opnsense/install_opnsense.sh", "installed": False},
            "pxmx": {"path": "pxmx/install_pxmx.sh", "installed": False},
        }

        # Check if module is 'installed' by seeing if it's connected as a spoke
        for mod in modules:
            if any(mod in sid for sid in hub.active_connections):
                modules[mod]["installed"] = True

        return {
            "single_server_mode": is_single_server,
            "modules": modules
        }

    @app.post("/setup/install-module")
    async def install_module(request: Request):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        if not global_config.get("single_server_mode", False):
            raise HTTPException(status_code=403, detail="On-demand installation is only supported in single-server mode.")

        try:
            data = await request.json()
            module_id = data.get("module_id")
            custom_spoke_id = data.get("spoke_id")
            display_name = data.get("display_name")

            if not module_id:
                raise HTTPException(status_code=400, detail="Missing module_id")

            modules = {
                "cppm": "cppm/install.sh",
                "cs": "cs/install_cs.sh",
                "ldap": "ldap/install_ldap.sh",
                "netbox": "netbox/install.sh",
                "opnsense": "opnsense/install_opnsense.sh",
                "pxmx": "pxmx/install_pxmx.sh",
            }

            script_path = modules.get(module_id)
            if not script_path:
                raise HTTPException(status_code=404, detail="Module not found")

            # Hub API address for the module
            hub_url = f"ws://{hub.host}:{hub.port}"

            # Use custom spoke ID if provided, otherwise generate default
            spoke_id = custom_spoke_id if custom_spoke_id else f"{module_id}-spoke-1"

            # Register the module and its display name
            hub.state.register_module(spoke_id, approved=False, display_name=display_name or spoke_id)
            hub.known_modules = hub.state.system_state["known_modules"]

            first_secret = hub.key_manager.generate_first_secret(spoke_id)

            # Execute installation script as a background process
            full_cmd = f"bash {script_path} --hub {hub_url} --id {spoke_id} --secret {first_secret} --all-prereqs"

            # Start the process without blocking the API
            subprocess.Popen(full_cmd, shell=True, cwd=os.path.join(os.path.dirname(__file__), "../../.."))

            return {"status": "success", "message": f"Installation of {module_id} triggered for {spoke_id} in background."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-name")
    async def rename_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            new_name = data.get("display_name")
            new_hostname = data.get("hostname")

            if not spoke_id or not new_name:
                raise HTTPException(status_code=400, detail="Missing spoke_id or display_name")

            if spoke_id not in hub.state.system_state["known_modules"]:
                raise HTTPException(status_code=404, detail="Spoke not found")

            hub.state.set_module_name(spoke_id, new_name)
            hub.state.save_state()

            # If a new hostname was provided, send the command to the spoke
            if new_hostname:
                if spoke_id in hub.active_connections:
                    msg_id = str(uuid.uuid4())
                    msg = Message(
                        header=MessageHeader(
                            message_id=msg_id,
                            timestamp=time.time(),
                            sender_id="hub",
                            destination_id=spoke_id
                        ),
                        payload=MessagePayload(type="SPOKE_SET_HOSTNAME", data={"hostname": new_hostname})
                    )
                    await hub.send_to_spoke(msg)
                    hostname_status = "Hostname update triggered."
                else:
                    hostname_status = "Spoke not connected; hostname update will be queued."
                    # Queue it in mailbox for when they connect
                    msg_id = str(uuid.uuid4())
                    msg = Message(
                        header=MessageHeader(
                            message_id=msg_id,
                            timestamp=time.time(),
                            sender_id="hub",
                            destination_id=spoke_id
                        ),
                        payload=MessagePayload(type="SPOKE_SET_HOSTNAME", data={"hostname": new_hostname})
                    )
                    await hub.mailbox.push(msg, hub.send_to_spoke)
            else:
                hostname_status = ""

            return {"status": "success", "message": f"Spoke {spoke_id} renamed to {new_name}. {hostname_status}".strip()}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/tenants")
    async def get_tenants():
        hub = app.state.hub
        # Return list of tenant IDs and basic info from tenant_state
        tenants = hub.state.tenant_state.get("tenants", {})
        tenant_list = [{"id": tid, "name": tid} for tid in tenants.keys()]

        # Always include default if not present
        if "default" not in [t["id"] for t in tenant_list]:
            tenant_list.append({"id": "default", "name": "Default Tenant"})

        return {"tenants": tenant_list}

    @app.get("/setup/tenants/{tenant_id}")
    async def get_tenant_details(tenant_id: str):
        hub = app.state.hub
        logger.info(f"API: Fetching details for tenant {tenant_id}")
        tenant = hub.state.get_tenant(tenant_id)
        if tenant is None:
            logger.warning(f"API: Tenant {tenant_id} not found in state. Available: {list(hub.state.tenant_state.get('tenants', {}).keys())}")
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return {"tenant_id": tenant_id, "config": tenant}

    @app.post("/setup/tenants")
    async def create_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id")
            if not tenant_id:
                raise HTTPException(status_code=400, detail="Missing tenant_id")

            hub.state.update_tenant(tenant_id, {})
            hub.state.save_state()
            return {"status": "success", "message": f"Tenant {tenant_id} created."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/tenant")
    async def update_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id", "default")
            config = data.get("config", {})

            hub.state.update_tenant(tenant_id, config)

            # If the config indicates this should be the active tenant, update system state
            if config.get("active"):
                hub.state.set_active_tenant(tenant_id)

            hub.state.save_state() # Immediate persist

            return {"status": "success", "message": f"Tenant {tenant_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    @app.post("/setup/generate-secret")
    async def generate_secret(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            secret = hub.key_manager.generate_first_secret(spoke_id)
            return {"spoke_id": spoke_id, "secret": secret}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/assign-tenant")
    async def assign_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            # Verify tenant exists
            if not hub.state.get_tenant(tenant_id):
                raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

            hub.state.assign_user_to_tenant(user_id, tenant_id)
            return {"status": "success", "message": f"User {user_id} assigned to tenant {tenant_id}"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/remove-tenant")
    async def remove_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            hub.state.remove_user_from_tenant(user_id, tenant_id)
            return {"status": "success", "message": f"User {user_id} removed from tenant {tenant_id}"}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/users")
    async def get_users():
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        return {"users": users}

    @app.post("/setup/users")
    async def update_user(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            permissions = data.get("permissions", {})

            if not user_id:
                raise HTTPException(status_code=400, detail="Missing user_id")

            if "users" not in hub.state.system_state:
                hub.state.system_state["users"] = {}

            hub.state.system_state["users"][user_id] = {
                "permissions": permissions,
                "updated_at": time.time()
            }
            hub.state.save_state()

            return {"status": "success", "message": f"User {user_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/users/{user_id}")
    async def delete_user(user_id: str):
        hub = app.state.hub
        if "users" in hub.state.system_state and user_id in hub.state.system_state["users"]:
            del hub.state.system_state["users"][user_id]
            hub.state.save_state()
            return {"status": "success", "message": f"User {user_id} deleted."}
        raise HTTPException(status_code=404, detail="User not found")

    @app.get("/setup/github-repos")
    async def get_github_repos():
        try:
            async with httpx.AsyncClient() as client:
                # Fetch public repos for lbockenstedt
                resp = await client.get("https://api.github.com/users/lbockenstedt/repos")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail="Failed to fetch repos from GitHub")
                repos = resp.json()
                return {
                    "repos": [
                        {"name": r["name"], "url": r["clone_url"], "description": r["description"]}
                        for r in repos
                    ]
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/github-branches/{repo}")
    async def get_github_branches(repo: str):
        try:
            # The repo might be the full name (lbockenstedt/lm) or just the name (lm)
            if "/" not in repo:
                repo_full = f"lbockenstedt/{repo}"
            else:
                repo_full = repo

            async with httpx.AsyncClient() as client:
                resp = await client.get(f"https://api.github.com/repos/{repo_full}/branches")
                if resp.status_code != 200:
                    raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch branches for {repo_full}")
                branches = resp.json()
                return {
                    "branches": [b["name"] for b in branches]
                }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/config")
    async def get_global_config():
        hub = app.state.hub
        return {"global_config": hub.state.system_state.get("global_config", {})}

    @app.post("/setup/config")
    async def update_global_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            hub.state.system_state["global_config"].update(config)
            hub.state.save_state() # Immediate persist

            return {"status": "success", "message": "Global configuration updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")


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

            if not agent_id or not module_id or not repo_url:
                raise HTTPException(status_code=400, detail="Missing agent_id, module_id, or repo_url")

            if agent_id not in hub.active_connections:
                raise HTTPException(status_code=503, detail=f"Generic agent {agent_id} not connected")

            # Generate credentials for the new spoke
            spoke_id = custom_spoke_id if custom_spoke_id else f"{module_id}-spoke-1"

            # Register the module and its display name
            hub.state.register_module(spoke_id, approved=False, display_name=display_name or spoke_id)
            hub.known_modules = hub.state.system_state["known_modules"]

            secret = hub.key_manager.generate_first_secret(spoke_id)
            hub_secret = hub.key_manager.hub_secret # Simplified for now

            provision_data = {
                "module_id": module_id,
                "repo_url": repo_url,
                "hub_url": f"ws://{hub.host}:{hub.port}",
                "spoke_id": spoke_id,
                "secret": secret,
                "hub_secret": hub_secret
            }

            msg_id = str(uuid.uuid4())
            msg = Message(
                header=MessageHeader(
                    message_id=msg_id,
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=agent_id
                ),
                payload=MessagePayload(type="PROVISION_MODULE", data=provision_data)
            )

            result = await hub.request_response(agent_id, "PROVISION_MODULE", provision_data)
            return result
        except Exception as e:
            logger.error(f"Provisioning failed: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # --- Static File Serving ---
    # We serve the UI directly from the 'WebUI' directory (Vanilla JS version)
    ui_path = os.path.join(os.path.dirname(__file__), "../../WebUI")

    if os.path.exists(ui_path):
        # Serve the index.html for any route not matched by the API
        @app.get("/{full_path:path}")
        async def serve_ui(full_path: str):
            # If it's a request for a file that exists in the ui folder, serve it
            file_path = os.path.join(ui_path, full_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                response = FileResponse(file_path)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            # Fallback to index.html for all other routes
            index_html_path = os.path.join(ui_path, "index.html")
            if os.path.exists(index_html_path):
                response = FileResponse(index_html_path)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            raise HTTPException(status_code=404, detail="UI index.html not found in WebUI folder")
    else:
        # Fallback if ui directory is missing
        @app.get("/")
        async def root():
            return {"message": "Hub API is running. UI folder not found. Please check repository structure."}

    return app

def run_api_server(hub, port=8000):
    app = create_app(hub)
    uvicorn.run(app, host="0.0.0.0", port=port)
