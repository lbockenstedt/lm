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
    async def get_pending_spokes():
        hub = app.state.hub
        pending = [sid for sid in hub.active_connections if not hub.approved_spokes.get(sid, False)]
        return {"pending_spokes": pending}

    @app.post("/setup/approve_spoke")
    async def approve_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            # Update approval status
            hub.approved_spokes[spoke_id] = True

            # Send APPROVED message to the spoke
            msg_id = str(uuid.uuid4())
            approval_msg = Message(
                header=MessageHeader(
                    message_id=msg_id,
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=spoke_id
                ),
                payload=MessagePayload(type="APPROVED", data={})
            )
            await hub.send_to_spoke(approval_msg)

            return {"status": "success", "message": f"Spoke {spoke_id} approved."}
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
                "connection_state": ws.state
            })
        return {
            "spokes": diagnostics,
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
