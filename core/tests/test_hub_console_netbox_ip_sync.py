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


def _probe_hub():
    state = MagicMock()
    state.get_tenant.return_value = {"name": "Tenant A", "netbox_tenant_slug": "tenant-a"}
    hub = DummyHub(state)
    hub._auto_llm_console_identify = AsyncMock(return_value=False)
    hub._console_netbox_sync_enabled = MagicMock(return_value=True)
    hub.get_spoke_by_type = MagicMock(return_value=MagicMock())
    hub._authorized_probe_tenant = AsyncMock(return_value="tenant-a")
    hub.request_response = AsyncMock()
    hub._record_console_sync_status = MagicMock()
    return hub


@pytest.mark.asyncio
@pytest.mark.parametrize("noise", ["Password:", "hostname", "N/A", "standby", "6300", ""])
async def test_console_probe_never_names_device_after_adapter_or_prompt_noise(noise):
    # Prompt noise and the USB adapter / port id named junk NetBox devices
    # ("FT232R USB UART", "uart-ttyS0"); with nothing else known, skip the sync.
    hub = _probe_hub()
    await hub._handle_console_probe("spoke-1", {
        "vendor": "aruba", "product": "FT232R USB UART", "port_id": "uart-ttyS0",
        "identity": {"hostname": noise}})
    hub.request_response.assert_not_called()


@pytest.mark.asyncio
async def test_console_probe_falls_back_to_serial_for_the_name():
    hub = _probe_hub()
    await hub._handle_console_probe("spoke-1", {
        "vendor": "aruba", "product": "FT232R USB UART",
        "identity": {"hostname": "Password:", "serial": "SG12345"}})
    rec = hub.request_response.call_args[0][2]["devices"][0]
    assert rec["hostname"] == "SG12345"


@pytest.mark.asyncio
async def test_console_probe_sends_the_identified_device_class_as_role():
    hub = _probe_hub()
    await hub._handle_console_probe("spoke-1", {
        "vendor": "Juniper",
        "identity": {"hostname": "fw-01", "model": "SRX345", "type": "Firewall"}})
    rec = hub.request_response.call_args[0][2]["devices"][0]
    assert rec["model"] == "SRX345" and rec["role"] == "firewall"


@pytest.mark.asyncio
async def test_console_probe_skips_repeat_push_of_unchanged_device():
    # Console spokes re-probe the same port all day; each push is a paced
    # NetBox feed, so an identical record already synced is not sent again.
    hub = _probe_hub()
    probe = {"vendor": "cisco", "identity": {"ip": "10.0.0.5", "hostname": "sw-1",
                                             "serial": "S1"}}
    await hub._handle_console_probe("spoke-1", probe)
    await hub._handle_console_probe("spoke-1", probe)
    assert hub.request_response.call_count == 1
    assert hub.request_response.call_args.kwargs["timeout"] == 600.0

    # A changed record (new IP) is pushed.
    await hub._handle_console_probe("spoke-1", {
        "vendor": "cisco", "identity": {"ip": "10.0.0.6", "hostname": "sw-1",
                                        "serial": "S1"}})
    assert hub.request_response.call_count == 2
