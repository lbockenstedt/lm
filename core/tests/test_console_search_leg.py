"""Console leg of the global search / device-detail fan-out.

``console_port_matches`` / ``console_port_result`` turn a tenant-scoped console
port (as returned by ``_list_visible_console_ports``) into a searchable haystack
and a connect-ready result row, so a device found in LM also surfaces its serial
console (``openConsoleTerminal(spoke_id, port_id)``). Pure functions — tested
without standing up FastAPI.
"""
from routes.console import (
    console_port_search_blob, console_port_matches, console_port_result,
)


def _port(**over):
    p = {
        "port_id": "usb-067b:2303@6-2.1",
        "device": "/dev/ttyUSB0",
        "alias": "",
        "spoke_id": "lm-agent-console",
        "agent_name": "lrb",
        "tenant_id": "lrb",
        "settings": {"baud": 9600},
        "in_use": False,
        "dpa": None,
        "probe": {"vendor": "procurve",
                  "identity": {"hostname": "MIA-GW-02", "ip": "10.20.0.5",
                               "vendor": "aruba", "model": "Aruba CX 6300"}},
    }
    p.update(over)
    return p


def test_search_blob_includes_all_identifiers_lowercased():
    blob = console_port_search_blob(_port(alias="core-sw"))
    for token in ("mia-gw-02", "10.20.0.5", "aruba", "aruba cx 6300",
                  "/dev/ttyusb0", "core-sw", "lrb"):
        assert token in blob


def test_matches_by_hostname_ip_model_alias_and_device():
    p = _port(alias="core-sw")
    assert console_port_matches(p, "mia-gw-02")     # hostname
    assert console_port_matches(p, "10.20.0.5")     # identified IP
    assert console_port_matches(p, "cx 6300")       # model fragment
    assert console_port_matches(p, "core-sw")       # alias
    assert console_port_matches(p, "ttyusb0")       # device path


def test_no_match_and_empty_needle_are_false():
    p = _port()
    assert not console_port_matches(p, "nonexistent-host")
    assert not console_port_matches(p, "")


def test_result_row_carries_connect_coordinates():
    r = console_port_result(_port(in_use=True))
    assert r["source"] == "console" and r["type"] == "console"
    assert r["name"] == "MIA-GW-02"           # hostname preferred as the name
    assert r["spoke_id"] == "lm-agent-console"
    assert r["port_id"] == "usb-067b:2303@6-2.1"
    assert r["device"] == "/dev/ttyUSB0"
    assert r["baud"] == 9600
    assert r["ip"] == "10.20.0.5"
    assert r["model"] == "Aruba CX 6300"
    assert r["in_use"] is True


def test_result_name_falls_back_to_alias_then_device():
    no_host = _port(probe={"identity": {}}, alias="edge-1")
    assert console_port_result(no_host)["name"] == "edge-1"
    bare = _port(probe={}, alias="")
    assert console_port_result(bare)["name"] == "/dev/ttyUSB0"
