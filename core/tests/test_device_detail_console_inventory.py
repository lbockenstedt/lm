import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from api import Request, FastAPI

from routes.console import console_port_search_blob, console_port_result
from routes.cppm import register

# Mock Hub
class MockHub:
    def __init__(self):
        self.state = MagicMock()
        self.get_spoke_by_type = MagicMock(return_value=None)
        self.get_all_spokes_by_type = MagicMock(return_value=[])
        self.get_hypervisor_spoke = MagicMock(return_value=None)
        self.request_response = AsyncMock(return_value={"payload": {"data": {}}})

class MockCtx:
    def __init__(self):
        self._session_user = lambda r: {"user": "admin"}
        self._is_admin = lambda s: True
        self._effective_tenant = lambda r, explicit=None: None
        self._effective_tenant_slug = lambda r, explicit=None: None
        self._filter_session = AsyncMock(return_value=[])
        self._filter_tenant = AsyncMock(return_value=[])
        self._gate_record_tenant = AsyncMock(return_value=None)

def test_console_port_search_blob():
    p = {
        "probe": {
            "identity": {
                "serial": "SN9999",
                "mac": "11:22:33:44:55:66"
            }
        }
    }
    blob = console_port_search_blob(p)
    assert "sn9999" in blob
    assert "11:22:33:44:55:66" in blob

def test_console_port_result():
    p = {
        "probe": {
            "identity": {
                "serial": "SN12345",
                "model": "RouterX",
                "mac": "00:11:22:33:44:55"
            }
        }
    }
    res = console_port_result(p)
    assert res.get("serial") == "SN12345"
    assert res.get("device_type") == "RouterX"
    assert res.get("mac") == "00:11:22:33:44:55"
    assert res.get("source") == "console"

@pytest.mark.asyncio
async def test_get_device_detail_console_correlation(monkeypatch):
    app = FastAPI()
    app.state.hub = MockHub()
    ctx = MockCtx()
    
    app.state.console_list_visible_ports = AsyncMock(return_value={
        "ports": [
            {
                "alias": "console1",
                "device": "/dev/ttyUSB0",
                "port_id": "port-1",
                "spoke_id": "spoke-1",
                "probe": {
                    "identity": {
                        "serial": "SN12345",
                        "hostname": "switch-01",
                        "model": "catalyst"
                    }
                }
            }
        ]
    })
    
    register(app, app.state.hub, ctx)
    
    # Extract the route function
    route_func = next((r.endpoint for r in app.routes if getattr(r, "path", "") == "/api/device-detail"), None)
    assert route_func is not None
    
    request = Request({"type": "http", "method": "GET"})
    
    # Test correlation by serial
    res = await route_func(request, serial="sn12345")
    assert "console" in res
    assert len(res["console"]) == 1
    assert res["console"][0]["serial"] == "SN12345"

def test_webui_main_js_no_bypass():
    import os
    with open("/Users/lbockenstedt/vscode/lm/WebUI/main.js", "r") as f:
        content = f.read()
    
    # Assert it DOES NOT contain the old bypass logic
    assert "if (item.source === 'console' && item.spoke_id && item.port_id)" not in content
    assert "openConsoleTerminal(item.spoke_id, item.port_id);" not in content

def test_webui_main_js_forwards_serial():
    import os
    with open("/Users/lbockenstedt/vscode/lm/WebUI/main.js", "r") as f:
        content = f.read()
    
    assert "params.set('serial', item.serial);" in content
    assert "params.set('port_id', item.port_id);" in content
    assert "params.set('device', item.device);" in content
