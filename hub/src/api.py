import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

class HubAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            # We'll get the hub instance from the server object
            hub = self.server.hub
            status = {
                "active_connections": list(hub.active_connections.keys()),
                "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
                "state": hub.state.state
            }
            self.wfile.write(json.dumps(status).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_api_server(hub, port=8000):
    server = HTTPServer(("0.0.0.0", port), HubAPIHandler)
    server.hub = hub
    print(f"Hub API started on port {port}")
    server.serve_forever()
