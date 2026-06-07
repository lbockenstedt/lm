import json
import asyncio
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
import re

class HubAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            hub = self.server.hub
            status = {
                "active_connections": list(hub.active_connections.keys()),
                "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
                "state": hub.state.state
            }
            self.wfile.write(json.dumps(status).encode())

        elif self.path.startswith("/vm/") and "/firewall" in self.path:
            # Path format: /vm/{vm_id}/firewall
            match = re.match(r"/vm/([^/]+)/firewall", self.path)
            if match:
                vm_id = match.group(1)
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()

                hub = self.server.hub

                # 1. Find the IP for this VM from the state manager
                # In this mock, we'll look in resources -> vm_id -> metadata -> ip
                res_info = hub.state.state.get("resources", {}).get(vm_id, {})
                ip = res_info.get("metadata", {}).get("ip")

                if not ip:
                    self.wfile.write(json.dumps({"status": "ERROR", "message": f"No IP address found for VM {vm_id}"}).encode())
                    return

                # 2. Identify the OPNsense spoke
                # For this demo, we'll assume the first active connection that is an opnsense spoke
                # In production, this would be a lookup in the state manager.
                opn_spoke = next((sid for sid in hub.active_connections if "opn" in sid), None)

                if not opn_spoke:
                    self.wfile.write(json.dumps({"status": "ERROR", "message": "No OPNsense spoke connected"}).encode())
                    return

                # 3. Use the async bridge to request rules from the spoke
                future = asyncio.run_coroutine_threadsafe(
                    hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip}),
                    hub.loop
                )
                result = future.result(timeout=5)
                self.wfile.write(json.dumps(result).encode())
            else:
                self.send_response(404)
                self.end_headers()

        else:
            self.send_response(404)
            self.end_headers()

def run_api_server(hub, port=8000):
    server = HTTPServer(("0.0.0.0", port), HubAPIHandler)
    server.hub = hub
    print(f"Hub API started on port {port}")
    server.serve_forever()
