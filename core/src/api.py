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

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])

        spokes_status = []
        for sid in known_spokes:
            spokes_status.append({
                "spoke_id": sid,
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

    @app.get("/setup/firewalls")
    async def get_firewalls():
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        return {"firewalls": firewalls}

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

    @app.get("/opn/refresh")
    async def refresh_opn_cache():
        hub = app.state.hub
        logger.info("API: Triggering OPNsense cache refresh")
        success = await hub.poll_opnsense_rules()
        if not success:
            logger.error("API: OPNsense cache refresh failed")
            raise HTTPException(status_code=503, detail="Failed to refresh OPNsense cache (Spoke not connected or API error)")

        return {"status": "success", "message": "OPNsense cache refreshed successfully!"}

    @app.get("/opn/interfaces")
    async def get_opn_interfaces():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense interfaces")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "GET_INTERFACE_STATUS", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense interfaces: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense interfaces: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/health")
    async def get_opn_health():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense health")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "GET_SYSTEM_HEALTH", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense health: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense health: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/dhcp")
    async def get_opn_dhcp():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense DHCP leases")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_DHCP_LEASES", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense DHCP leases: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense DHCP leases: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/firewall/all")
    async def get_opn_firewall_all():
        hub = app.state.hub

        # Return cached data if available
        if hub.opnsense_cache:
            logger.info("API: Serving OPNsense firewall rules from cache")
            return hub.opnsense_cache

        logger.info("API: No cache available, requesting OPNsense all firewall rules")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_ALL_RULES", {})

            # Robust extraction: handle both wrapped (payload) and flat responses
            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    # If it's a flat success response from the spoke, it might be the result itself
                    data = result
            else:
                data = result

            logger.info(f"API: Received OPNsense firewall rules: {data}")

            # Update cache if data was successfully retrieved
            if data:
                hub.opnsense_cache = data

            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense firewall rules: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/firewall/stats")
    async def get_opn_firewall_stats():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense firewall stats")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_FIREWALL_STATS", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense firewall stats: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense firewall stats: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/nat")
    async def get_opn_nat():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense NAT policies")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_NAT_POLICIES", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense NAT policies: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense NAT policies: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/opn/dns")
    async def get_opn_dns():
        hub = app.state.hub
        logger.info("API: Requesting OPNsense DNS records")
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if not opn_spoke:
            logger.error("API: No OPNsense spoke connected")
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_DNS_RECORDS", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received OPNsense DNS records: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching OPNsense DNS records: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

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

    @app.get("/cppm/policies")
    async def get_cppm_policies():
        hub = app.state.hub
        logger.info("API: Requesting CPPM policies")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_ALL_POLICIES", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM policies: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM policies: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/cppm/endpoints")
    async def get_cppm_endpoints():
        hub = app.state.hub
        logger.info("API: Requesting CPPM endpoints")
        cppm_spoke = next((sid for sid in hub.active_connections if "cppm" in sid), None)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_ALL_ENDPOINTS", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM endpoints: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM endpoints: {e}", exc_info=True)
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
        opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)
        if opn_spoke and ip:
            rules_raw = await hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
            dhcp_raw = await hub.request_response(opn_spoke, "OPNSENSE_GET_DHCP_LEASES", {})

            rules_data = rules_raw.get("payload", {}).get("data", {}) if isinstance(rules_raw, dict) else {}
            dhcp_data = dhcp_raw.get("payload", {}).get("data", []) if isinstance(dhcp_raw, dict) else []

            lease = next((l for l in dhcp_data if l.get("ip") == ip), None) if isinstance(dhcp_data, list) else None

            details["opnsense"] = {
                "status": "ONLINE",
                "rules": rules_data.get("rules", []) if rules_data.get("status") == "SUCCESS" else [],
                "dhcp": lease
            }

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

    @app.post("/setup/update")
    async def trigger_update(request: Request):
        """
        Triggers a git pull and restarts the service to apply updates.
        """
        hub = app.state.hub
        # Check for force parameter in query string
        force = request.query_params.get("force", "false").lower() == "true"
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

            # Generate spoke ID and first secret for onboarding
            spoke_id = f"{module_id}-spoke-1"
            first_secret = hub.key_manager.generate_first_secret(spoke_id)

            # Execute installation script as a background process
            # We now pass the spoke_id and the first_secret to the install script
            full_cmd = f"bash {script_path} --hub {hub_url} --id {spoke_id} --secret {first_secret} --all-prereqs"

            # Start the process without blocking the API
            subprocess.Popen(full_cmd, shell=True, cwd=os.path.join(os.path.dirname(__file__), "../../.."))

            return {"status": "success", "message": f"Installation of {module_id} triggered for {spoke_id} in background."}
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
        tenant = hub.state.get_tenant(tenant_id)
        if not tenant:
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
