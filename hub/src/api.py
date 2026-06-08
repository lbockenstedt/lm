import os
import subprocess
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Any
import uvicorn
import json

def create_app(hub):
    app = FastAPI(title="Lab Manager Hub API")

    # Attach hub instance to app state for access in routes
    app.state.hub = hub

    @app.get("/status")
    async def get_status():
        hub = app.state.hub
        return {
            "active_connections": list(hub.active_connections.keys()),
            "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
            "state": hub.state.state
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

    @app.post("/setup/update")
    async def trigger_update():
        """
        Triggers a git pull and restarts the service to apply updates.
        """
        try:
            # Use a shell command to pull and then restart
            # We target /root/lab-manager/lm specifically
            cmd = "cd /root/lab-manager/lm && git pull"
            subprocess.run(cmd, shell=True, check=True)

            # Restart the systemd service
            subprocess.Popen(["systemctl", "restart", "lab-manager"])

            return {"status": "success", "message": "Update triggered. The server is restarting..."}
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"Update failed: {str(e)}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    @app.get("/setup/config")
    async def get_setup_config():
        hub = app.state.hub
        return {
            "tenants": hub.state.state["tenants"],
            "global_config": hub.state.state["global_config"]
        }

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
