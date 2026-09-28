"""DHCPv6 dual-stack support in ``dhcp/src/kea_manager.py``.

Prior to this, the Kea manager only ever built/read/wrote ``subnet4`` /
``Dhcp4`` — there was no way to hand a dual-stack lab (e.g. an IPv6 GUA /48
routed via an HE.net tunnel) a DHCPv6 scope at all. Covers ``build_subnet6``
and the ``KeaManager`` v6 config/lease/reservation methods, mirroring the
existing v4 test file's structure and RPC-mocking pattern.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


ROOT = Path(__file__).resolve().parents[2]
DHCP_SRC = ROOT / "dhcp" / "src"


def _load_kea_manager():
    if str(DHCP_SRC) not in sys.path:
        sys.path.insert(0, str(DHCP_SRC))
    spec = importlib.util.spec_from_file_location(
        "lm_kea_manager_dhcpv6test", DHCP_SRC / "kea_manager.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kea_manager = _load_kea_manager()


# ── build_subnet6 ────────────────────────────────────────────────────────────

def test_build_subnet6_basic_pool_and_description():
    subs, applied, skipped = kea_manager.build_subnet6(
        [{"subnet": "2001:470:4948:1::/64", "description": "Lab mgmt v6", "pools": []}], [])
    assert len(subs) == 1
    assert subs[0]["subnet"] == "2001:470:4948:1::/64"
    assert subs[0]["user-context"] == {"description": "Lab mgmt v6"}
    # Default pool spans the WHOLE subnet — no v4-style .10/.254 host carve-out.
    assert subs[0]["pools"] == [{"pool": "2001:470:4948:1:: - 2001:470:4948:1:ffff:ffff:ffff:ffff"}]
    assert applied == 0 and skipped == 0


def test_build_subnet6_no_gateway_option_and_dns_servers_option_name():
    subs, _applied, _skipped = kea_manager.build_subnet6([{
        "subnet": "2001:470:4948:1::/64", "pools": [],
        "gateway": "2001:470:4948:1::1",  # must be ignored — no routers option in DHCPv6
        "dns_servers": ["2001:470:20::2"],
        "search_domains": ["lab.local"],
        "lease_time": 3600,
    }], [])
    opts = {o["name"]: o["data"] for o in subs[0]["option-data"]}
    assert "routers" not in opts
    assert opts["dns-servers"] == "2001:470:20::2"
    assert opts["domain-search"] == "lab.local"
    assert subs[0]["valid-lifetime"] == 3600


def test_build_subnet6_rejects_ipv4_subnet():
    subs, _applied, _skipped = kea_manager.build_subnet6(
        [{"subnet": "10.0.0.0/24", "pools": []}], [])
    assert subs == []


def test_build_subnet6_reservation_uses_ip_addresses_list_and_hw_address():
    subs, applied, skipped = kea_manager.build_subnet6(
        [{"subnet": "2001:470:4948:1::/64", "pools": []}],
        [{"ip": "2001:470:4948:1::10", "mac": "AA:BB:CC:DD:EE:FF", "hostname": "host1"}])
    assert applied == 1 and skipped == 0
    res = subs[0]["reservations"][0]
    assert res["ip-addresses"] == ["2001:470:4948:1::10"]
    assert res["hw-address"] == "aa:bb:cc:dd:ee:ff"
    assert res["hostname"] == "host1"


def test_build_subnet6_ignores_ipv4_reservations():
    """A mixed-family reservation list (the common case once dual-stack sync
    passes both v4 and v6 rows together) must not crash and must not attach
    an IPv4 reservation to a v6 subnet."""
    subs, applied, skipped = kea_manager.build_subnet6(
        [{"subnet": "2001:470:4948:1::/64", "pools": []}],
        [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "v4host"}])
    assert applied == 0 and skipped == 1
    assert "reservations" not in subs[0]


def test_build_subnet4_ignores_ipv6_reservations():
    """Symmetric guard on the v4 side: a v6 reservation row must not crash
    build_subnet4 or attach to a v4 subnet."""
    subs, applied, skipped = kea_manager.build_subnet4(
        [{"subnet": "10.0.0.0/24", "pools": []}],
        [{"ip": "2001:470:4948:1::10", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "v6host"}])
    assert applied == 0 and skipped == 1
    assert "reservations" not in subs[0]


# ── KeaManager DHCPv6 RPC methods ────────────────────────────────────────────

def _manager_with_rpc(rpc_side_effect):
    mgr = kea_manager.KeaManager("http://localhost:8001")
    mgr._rpc = MagicMock(side_effect=rpc_side_effect)
    return mgr


def test_sync6_enables_hw_address_identifier_and_writes_subnet6():
    calls = []

    def rpc(service, command, args=None):
        calls.append((service, command, args))
        if command == "config-get":
            return {"Dhcp6": {"host-reservation-identifiers": ["duid"]}}
        return {}

    mgr = _manager_with_rpc(rpc)
    result = mgr.sync6(
        [{"subnet": "2001:470:4948:1::/64", "pools": []}],
        [{"ip": "2001:470:4948:1::10", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "h1"}])
    assert result["status"] == "SUCCESS"
    assert result["subnets"] == 1

    set_call = next(c for c in calls if c[1] == "config-set")
    sent_cfg = set_call[2]["Dhcp6"]
    assert "hw-address" in sent_cfg["host-reservation-identifiers"]
    assert "duid" in sent_cfg["host-reservation-identifiers"]  # existing identifiers preserved
    assert sent_cfg["subnet6"][0]["subnet"] == "2001:470:4948:1::/64"
    assert any(c[1] == "config-write" for c in calls)
    assert all(c[0] == "dhcp6" for c in calls)  # every RPC targets the dhcp6 service


def test_sync6_config_get_failure_returns_error_without_writing():
    def rpc(service, command, args=None):
        if command == "config-get":
            raise RuntimeError("Kea CA unreachable")
        raise AssertionError(f"unexpected RPC {command}")

    mgr = _manager_with_rpc(rpc)
    result = mgr.sync6([{"subnet": "2001:470:4948:1::/64", "pools": []}], [])
    assert result["status"] == "ERROR"
    assert "Kea DHCPv6 config" in result["message"]


def test_list_leases6_passes_subnet_ids_and_targets_dhcp6_service():
    def rpc(service, command, args=None):
        if command == "config-get":
            return {"Dhcp6": {"subnet6": [{"id": 7, "subnet": "2001:470:4948:1::/64"}]}}
        if command == "lease6-get-all":
            assert service == "dhcp6"
            assert args == {"subnets": [7]}
            return {"leases": [{"ip-address": "2001:470:4948:1::10"}]}
        raise AssertionError(f"unexpected RPC {command}")

    mgr = _manager_with_rpc(rpc)
    leases = mgr.list_leases6()
    assert leases == [{"ip-address": "2001:470:4948:1::10"}]


def test_delete_lease6_uses_lease6_del_on_dhcp6_service():
    mgr = kea_manager.KeaManager("http://localhost:8001")
    mgr._rpc = MagicMock(return_value={})
    result = mgr.delete_lease6("2001:470:4948:1::10")
    assert result["status"] == "SUCCESS"
    mgr._rpc.assert_called_once_with("dhcp6", "lease6-del", {"ip-address": "2001:470:4948:1::10"})


def test_add_reservation6_and_list_reservations6_round_trip():
    state = {"Dhcp6": {"subnet6": [{"id": 3, "subnet": "2001:470:4948:1::/64"}]}}

    def rpc(service, command, args=None):
        if command == "config-get":
            return state
        if command == "config-set":
            state["Dhcp6"] = args["Dhcp6"]
            return {}
        if command == "config-write":
            return {}
        if command == "lease6-get-all":
            return {"leases": []}
        raise AssertionError(f"unexpected RPC {command}")

    mgr = _manager_with_rpc(rpc)
    add_result = mgr.add_reservation6(3, "2001:470:4948:1::20", "AA:BB:CC:DD:EE:01", "host2")
    assert add_result["status"] == "SUCCESS"

    reservations = mgr.list_reservations6()
    assert reservations == [{
        "ip": "2001:470:4948:1::20", "mac": "aa:bb:cc:dd:ee:01",
        "hostname": "host2", "subnet_id": 3, "subnet": "2001:470:4948:1::/64",
    }]


def test_delete_reservation6_removes_only_matching_ip():
    state = {"Dhcp6": {"subnet6": [{
        "id": 3, "subnet": "2001:470:4948:1::/64",
        "reservations": [
            {"ip-addresses": ["2001:470:4948:1::20"], "hw-address": "aa:bb:cc:dd:ee:01"},
            {"ip-addresses": ["2001:470:4948:1::21"], "hw-address": "aa:bb:cc:dd:ee:02"},
        ],
    }]}}

    def rpc(service, command, args=None):
        if command == "config-get":
            return state
        if command == "config-set":
            state["Dhcp6"] = args["Dhcp6"]
            return {}
        if command == "config-write":
            return {}
        raise AssertionError(f"unexpected RPC {command}")

    mgr = _manager_with_rpc(rpc)
    result = mgr.delete_reservation6("2001:470:4948:1::20")
    assert result["status"] == "SUCCESS"
    remaining = state["Dhcp6"]["subnet6"][0]["reservations"]
    assert len(remaining) == 1
    assert remaining[0]["ip-addresses"] == ["2001:470:4948:1::21"]
