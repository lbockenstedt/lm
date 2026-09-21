import pytest
from unittest.mock import AsyncMock, MagicMock
from hub_vnc_console import HubVncConsoleMixin

class DummyHub(HubVncConsoleMixin):
    def __init__(self, state):
        self.state = state
    
    def get_spoke_by_type(self, spoke_type):
        pass

@pytest.mark.asyncio
async def test_handle_console_probe_syncs_ip_to_netbox():
    state = MagicMock()
    state.get_tenant.return_value = {"name": "Tenant A", "netbox_tenant_slug": "tenant-a"}
    
    vnc_console = DummyHub(state)
    
    vnc_console._auto_llm_console_identify = AsyncMock(return_value=False)
    vnc_console._console_netbox_sync_enabled = MagicMock(return_value=True)
    
    netbox = MagicMock()
    vnc_console.get_spoke_by_type = MagicMock(return_value=netbox)
    vnc_console._authorized_probe_tenant = AsyncMock(return_value="tenant-a")
    vnc_console.request_response = AsyncMock()
    vnc_console._record_console_sync_status = MagicMock()

    probe_data = {
        "vendor": "cisco",
        "identity": {
            "ip": "10.20.30.40",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hostname": "switch-01",
            "serial": "ABC12345"
        }
    }

    await vnc_console._handle_console_probe("spoke-1", probe_data)

    vnc_console.request_response.assert_called_once()
    args, kwargs = vnc_console.request_response.call_args
    assert args[0] == netbox
    assert args[1] == "NETBOX_SYNC_DEVICES"
    
    payload = args[2]
    assert len(payload["devices"]) == 1
    device_rec = payload["devices"][0]
    
    assert device_rec["ip"] == "10.20.30.40"
    assert device_rec["mac"] == "aa:bb:cc:dd:ee:ff"
    assert device_rec["hostname"] == "switch-01"
    assert device_rec["serial"] == "ABC12345"
