import os
import subprocess
import json
import time
import uuid
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Any
import uvicorn

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement

def create_app(hub):
    app = FastAPI(title="Lab Manager Hub API")

    # Attach hub instance to app state for access in routes
    app.state.hub = hub

    @app.get("/status")
    async def get_status():
        hub = app.state.hub
        metrics = await hub.get_system_metrics()
        return {
            "active_connections": list(hub.active_connections.keys()),
            "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
            "state": hub.state.state,
            "metrics": metrics
        }

    @app.get("/vm/{vm_id}/firewall")
    async def get_vm_firewall(vm_id: str):
        hub = app.state.hub

        # 1. Find the IP for this VM from the state manager
        res_info = hub.state.state.get("resources", {}).get(vm_id, {})
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
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        hub = app.state.hub
        known_spokes = hub.state.state.get("known_spokes", [])

        spokes_status = []
        for sid in known_spokes:
            spokes_status.append({
                "spoke_id": sid,
                "approved": hub.approved_spokes.get(sid, False)
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
                hub.approved_spokes[spoke_id] = False
            else:
                # Update approval status
                hub.approved_spokes[spoke_id] = True

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

            return {"status": "success", "message": f"Spoke {spoke_id} {'approved' if action != 'unapprove' else 'un-approved'}."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/cppm-config")
    async def get_cppm_config():
        hub = app.state.hub
        config = hub.state.state.get("global_config", {}).get("cppm", {})
        return {"config": config}

    @app.post("/setup/cppm-config")
    async def update_cppm_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Save to persistent state
            global_config = hub.state.state.get("global_config", {})
            global_config["cppm"] = config
            hub.state.state["global_config"] = global_config
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

    @app.get("/setup/appearance")
    async def get_appearance():
        hub = app.state.hub
        config = hub.state.state.get("global_config", {}).get("appearance", {
            "primary_color": "#01A982",
            "navy_color": "#263040",
            "logo_url": "hpe-svg", # Special keyword for the built-in HPE logo
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

            global_config = hub.state.state.get("global_config", {})
            global_config["appearance"] = config
            hub.state.state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "success", "message": "Appearance settings updated."}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/logs")


    async def get_system_logs():
        hub = app.state.hub
        return {"logs": list(hub.logs)}

    @app.get("/setup/diagnostics")
    async def get_diagnostics():
        hub = app.state.hub
        metrics = await hub.get_system_metrics()
        diagnostics = []
        for sid, ws in hub.active_connections.items():
            diagnostics.append({
                "spoke_id": sid,
                "authenticated": True,
                "approved": hub.approved_spokes.get(sid, False),
                "heartbeat_status": hub.heartbeat.get_status(sid),
                "connection_state": ws.state,
                "version": hub.spoke_versions.get(sid, "unknown")
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
    async def trigger_update():
        """
        Triggers a git pull and restarts the service to apply updates.
        """
        hub = app.state.hub
        success = await hub.perform_update()
        if success:
            return {"status": "success", "message": "Update triggered. The server is restarting..."}
        else:
            raise HTTPException(status_code=500, detail="Update failed. Check Hub logs.")

    @app.get("/setup/modules")
    async def get_modules():
        hub = app.state.hub
        global_config = hub.state.state.get("global_config", {})
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
        global_config = hub.state.state.get("global_config", {})
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

    @app.post("/setup/tenant")
    async def update_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id", "default")
            config = data.get("config", {})

            hub.state.update_tenant(tenant_id, config)
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

    @app.get("/setup/config")
    async def get_global_config():
        hub = app.state.hub
        return {"global_config": hub.state.state.get("global_config", {})}

    @app.post("/setup/config")
    async def update_global_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            hub.state.state["global_config"].update(config)
            hub.state.save_state() # Immediate persist

            return {"status": "success", "message": "Global configuration updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    # --- Static File Serving ---
    # We serve the UI directly from the 'ui' directory (Vanilla JS version)
    ui_path = os.path.join(os.path.dirname(__file__), "../../ui")

    if os.path.exists(ui_path):
        # Serve the index.html for any route not matched by the API
        @app.get("/{full_path:path}")
        async def serve_ui(full_path: str):
            # If it's a request for a file that exists in the ui folder, serve it
            file_path = os.path.join(ui_path, full_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return FileResponse(file_path)

            # Fallback to index.html for all other routes
            index_html_path = os.path.join(ui_path, "index.html")
            if os.path.exists(index_html_path):
                return FileResponse(index_html_path)

            raise HTTPException(status_code=404, detail="UI index.html not found in ui folder")
    else:
        # Fallback if ui directory is missing
        @app.get("/")
        async def root():
            return {"message": "Hub API is running. UI folder not found. Please check repository structure."}

    return app

def run_api_server(hub, port=8000):
    app = create_app(hub)
    uvicorn.run(app, host="0.0.0.0", port=port)
