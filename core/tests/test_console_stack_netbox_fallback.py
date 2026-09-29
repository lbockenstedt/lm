"""Deepen VSF stack identification via NetBox when the conductor isn't one of
the caller's own visible console ports (see routes.console._resolve_stack_via_netbox).

Every console device the hub auto-identifies is already synced into NetBox
under its own ``mac`` (hub_vnc_console._handle_console_probe /
NETBOX_SYNC_DEVICES), so a standby stuck at "conductor not on console" can
often still be named by looking the conductor's MAC up there.
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from routes.console import _correlate_stacks, _resolve_stack_via_netbox, console_port_result


def _standby_port(spoke="spokeB", pid="ttyUSB9"):
    stack = {
        "is_stack": True, "role": "standby", "member_id": 2, "topology": "",
        "stack_mac": "", "local_mac": "34:c5:15:9b:52:00",
        "conductor_mac": "8c:85:c1:4b:c7:80", "sw_version": "FL.10.13.1000",
        "members": [
            {"member_id": 1, "mac": "8c:85:c1:4b:c7:80", "model": "JL662A",
             "role": "conductor", "present": True},
            {"member_id": 2, "mac": "34:c5:15:9b:52:00", "model": "JL666A",
             "role": "standby", "present": True},
        ],
    }
    return {"spoke_id": spoke, "port_id": pid, "probe": {"identity": {}, "stack": stack}}


@pytest.mark.asyncio
async def test_netbox_fallback_names_a_conductor_no_visible_port_reaches():
    standby = _standby_port()
    ports = [standby]
    _correlate_stacks(ports)   # no peer visible -> conductor_port_id stays unset
    assert "conductor_port_id" not in standby["probe"]["stack"]

    hub = MagicMock()
    netbox = MagicMock()
    hub.get_spoke_by_type = MagicMock(return_value=netbox)
    hub.request_response = AsyncMock(return_value={
        "status": "SUCCESS",
        "devices": [{"name": "BO-SYDm-ACSW01", "mac": "8c:85:c1:4b:c7:80"}],
    })

    await _resolve_stack_via_netbox(ports, hub)

    stack = standby["probe"]["stack"]
    assert stack["conductor_hostname"] == "BO-SYDm-ACSW01"
    assert stack["conductor_source"] == "netbox"
    hub.request_response.assert_called_once()
    args, kwargs = hub.request_response.call_args
    assert args[0] == netbox
    assert args[1] == "NETBOX_GET_DEVICES"

    result = console_port_result(standby)
    assert result["name"] == "BO-SYDm-ACSW01 (standby)"


@pytest.mark.asyncio
async def test_netbox_fallback_skips_when_conductor_already_found_in_memory():
    """A conductor already resolved via another visible console port is
    authoritative — no NetBox call should even be attempted."""
    standby = _standby_port()
    conductor = {
        "spoke_id": "spokeA", "port_id": "ttyUSB0",
        "probe": {"identity": {"mac": "8c:85:c1:4b:c7:80", "hostname": "BO-SYDm-ACSW01"},
                  "stack": dict(_standby_port()["probe"]["stack"], role="conductor",
                                member_id=1, local_mac="8c:85:c1:4b:c7:80")},
    }
    ports = [standby, conductor]
    _correlate_stacks(ports)
    assert standby["probe"]["stack"]["conductor_port_id"] == "ttyUSB0"

    hub = MagicMock()
    hub.get_spoke_by_type = MagicMock(return_value=MagicMock())
    hub.request_response = AsyncMock()

    await _resolve_stack_via_netbox(ports, hub)

    hub.request_response.assert_not_called()
    assert standby["probe"]["stack"].get("conductor_source") != "netbox"


@pytest.mark.asyncio
async def test_netbox_fallback_degrades_silently_when_no_ipam_spoke():
    standby = _standby_port()
    ports = [standby]
    _correlate_stacks(ports)

    hub = MagicMock()
    hub.get_spoke_by_type = MagicMock(return_value=None)
    hub.request_response = AsyncMock()

    await _resolve_stack_via_netbox(ports, hub)   # must not raise

    assert "conductor_hostname" not in standby["probe"]["stack"]


@pytest.mark.asyncio
async def test_netbox_fallback_degrades_silently_on_error():
    standby = _standby_port()
    ports = [standby]
    _correlate_stacks(ports)

    hub = MagicMock()
    hub.get_spoke_by_type = MagicMock(return_value=MagicMock())
    hub.request_response = AsyncMock(side_effect=RuntimeError("spoke offline"))

    await _resolve_stack_via_netbox(ports, hub)   # must not raise

    assert "conductor_hostname" not in standby["probe"]["stack"]


def test_console_port_result_falls_back_to_conductor_label():
    """Even without going through the async NetBox path, a stack member whose
    conductor_hostname is already known (e.g. from _correlate_stacks alone)
    gets a friendly search-result name instead of a bare device path."""
    standby = _standby_port()
    standby["probe"]["stack"]["conductor_hostname"] = "BO-SYDm-ACSW01"
    standby["device"] = "/dev/ttyUSB9"

    result = console_port_result(standby)
    assert result["name"] == "BO-SYDm-ACSW01 (standby)"


def test_console_port_result_prefers_real_identity_and_alias():
    standby = _standby_port()
    standby["probe"]["stack"]["conductor_hostname"] = "BO-SYDm-ACSW01"
    standby["alias"] = "Rack 4 bottom"
    standby["device"] = "/dev/ttyUSB9"

    assert console_port_result(standby)["name"] == "Rack 4 bottom"

    standby["probe"]["identity"]["hostname"] = "real-hostname"
    assert console_port_result(standby)["name"] == "real-hostname"
