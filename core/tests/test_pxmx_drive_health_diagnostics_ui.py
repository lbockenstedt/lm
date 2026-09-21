import pytest
import os

@pytest.mark.asyncio
async def test_get_pxmx_drive_health_diagnostics():
    from routes.pxmx import register
    from unittest.mock import AsyncMock, patch, MagicMock

    class MockApp:
        def __init__(self):
            self.routes = {}
            self.state = type('State', (), {})()
            self.state.hub = None
        def get(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator
        def post(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator
        def put(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator
        def delete(self, path):
            def decorator(func):
                self.routes[path] = func
                return func
            return decorator
    
    app = MockApp()
    hub = AsyncMock()
    app.state.hub = hub
    
    class MockCtx:
        def _session_user(self, req):
            return {"username": "test"}
        def _session_admin(self, req):
            return {"username": "test"}
        def _resolve_tenant(self, req, t): return t
        def _filter_tenant(self, h, t, items): return items
        def _get_active_tenant(self, req):
            return "test"
        def _is_admin(self, user):
            return True
    
    ctx = MockCtx()
    
    # Use regular mock for sync methods
    hub.get_hypervisor_spokes_for_tenant = MagicMock(return_value=["spoke-1"])
    
    register(app, hub, ctx)
    
    get_pxmx_drive_health = app.routes.get("/api/pxmx/drive-health")
    assert get_pxmx_drive_health is not None
    
    async def mock_hub_request_response(sid, action, payload, timeout=30.0):
        return {
            "payload": {
                "data": {
                    "nodes": [
                        {
                            "node": "node1",
                            "status": "ERROR",
                            "message": "smartctl failed to run",
                            "agent_version": "2.5.1",
                            "diagnostics": {
                                "smartctl_installed": False,
                                "is_hpe": True,
                                "has_raid": True,
                                "ssacli_installed": False
                            },
                            "drives": [],
                            "summary": {}
                        }
                    ],
                    "status": "SUCCESS"
                }
            }
        }
    
    hub.request_response = mock_hub_request_response
    
    class MockRequest:
        pass
        
    result = await get_pxmx_drive_health(MockRequest(), node="node1", tenant="test")
    
    assert result["spoke_connected"] is True
    assert len(result["nodes"]) == 1
    n = result["nodes"][0]
    assert n["node"] == "node1"
    assert n["status"] == "ERROR"
    assert n["error"] == "smartctl failed to run"
    assert n["agent_version"] == "2.5.1"
    assert n["diagnostics"]["smartctl_installed"] is False
    assert n["diagnostics"]["is_hpe"] is True
    assert n["diagnostics"]["has_raid"] is True
    assert n["diagnostics"]["ssacli_installed"] is False

def test_main_js_content():
    js_path = "/Users/lbockenstedt/vscode/lm/WebUI/main.js"
    with open(js_path, "r") as f:
        content = f.read()
    
    assert "smartctl: Installed" in content
    assert "smartctl: Missing" in content
    assert "HPE Server" in content
    assert "ssacli: Installed" in content
    assert "ssacli: Missing" in content
    assert "Software Prerequisites Incomplete" in content
    assert "apt-get update && apt-get install -y smartmontools" in content
