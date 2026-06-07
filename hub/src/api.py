import os
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

    # --- Static File Serving ---
    # This mimics the webui-hub pattern: serve the built frontend from the dist folder
    ui_dist_path = os.path.join(os.path.dirname(__file__), "../../ui/dist")

    if os.path.exists(ui_dist_path):
        # Serve the static assets (js, css, images)
        app.mount("/assets", StaticFiles(directory=os.path.join(ui_dist_path, "assets")), name="static")

        # Serve the index.html for any route not matched by the API
        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str):
            # If it's a request for a file that exists in dist, serve it
            file_path = os.path.join(ui_dist_path, full_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                return FileResponse(file_path)
            # Otherwise, serve index.html (standard for React SPAs)
            return FileResponse(os.path.join(ui_dist_path, "index.html"))
    else:
        # Fallback if dist folder is missing (e.g., during initial dev)
        @app.get("/")
        async def root():
            return {"message": "Hub API is running. UI build folder (dist) not found. Please run 'npm run build' in the ui directory."}

def run_api_server(hub, port=8000):
    app = create_app(hub)
    uvicorn.run(app, host="0.0.0.0", port=port)
