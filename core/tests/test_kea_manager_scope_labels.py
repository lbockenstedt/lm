"""Kea scope labeling — ``build_subnet4``'s NetBox description passthrough and
``KeaManager.get_stats``'s per-subnet description surfacing (``dhcp/src/kea_manager.py``).

Covers the "Scope Utilization" UI fix: a subnet with no real NetBox-sourced
CIDR/description used to render as a bare, meaningless "subnet <id>" label —
this passes the NetBox prefix ``description`` through Kea's ``user-context``
(which Kea persists untouched and returns via ``subnet4-list``) so the stats
API and UI can label a scope by its real name instead.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock


ROOT = Path(__file__).resolve().parents[2]
DHCP_SRC = ROOT / "dhcp" / "src"


def _load_kea_manager():
    if str(DHCP_SRC) not in sys.path:
        sys.path.insert(0, str(DHCP_SRC))
    spec = importlib.util.spec_from_file_location(
        "lm_kea_manager_scopetest", DHCP_SRC / "kea_manager.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kea_manager = _load_kea_manager()


def test_build_subnet4_carries_description_into_user_context():
    subs, _applied, _skipped = kea_manager.build_subnet4(
        [{"subnet": "10.0.0.0/24", "description": "Lab Tenant A VLAN10", "pools": []}], [])
    assert subs[0]["user-context"] == {"description": "Lab Tenant A VLAN10"}


def test_build_subnet4_omits_user_context_when_no_description():
    subs, _applied, _skipped = kea_manager.build_subnet4(
        [{"subnet": "10.0.0.0/24", "pools": []}], [])
    assert "user-context" not in subs[0]


def test_build_subnet4_applies_full_dhcp_option_suite():
    subs, _applied, _skipped = kea_manager.build_subnet4([{
        "subnet": "10.0.0.0/24", "pools": [],
        "gateway": "10.0.0.1",
        "dns_servers": ["10.0.0.2", "10.0.0.3"],
        "search_domains": ["lab.local", "corp.local"],
        "domain_name": "lab.local",
        "ntp_servers": ["10.0.0.4"],
        "tftp_server_name": "tftp.lab.local",
        "boot_file_name": "pxelinux.0",
        "netbios_name_servers": ["10.0.0.5"],
        "broadcast_address": "10.0.0.255",
        "lease_time": 7200,
    }], [])
    opts = {o["name"]: o["data"] for o in subs[0]["option-data"]}
    assert opts["routers"] == "10.0.0.1"
    assert opts["domain-name-servers"] == "10.0.0.2, 10.0.0.3"
    assert opts["domain-search"] == "lab.local, corp.local"
    assert opts["domain-name"] == "lab.local"
    assert opts["ntp-servers"] == "10.0.0.4"
    assert opts["tftp-server-name"] == "tftp.lab.local"
    assert opts["boot-file-name"] == "pxelinux.0"
    assert opts["netbios-name-servers"] == "10.0.0.5"
    assert opts["broadcast-address"] == "10.0.0.255"
    assert subs[0]["valid-lifetime"] == 7200


def test_build_subnet4_omits_advanced_options_when_absent():
    subs, _applied, _skipped = kea_manager.build_subnet4(
        [{"subnet": "10.0.0.0/24", "pools": []}], [])
    assert subs[0]["option-data"] == []
    assert "valid-lifetime" not in subs[0]


def test_build_subnet4_ignores_non_numeric_lease_time():
    subs, _applied, _skipped = kea_manager.build_subnet4(
        [{"subnet": "10.0.0.0/24", "pools": [], "lease_time": "not-a-number"}], [])
    assert "valid-lifetime" not in subs[0]


def test_get_stats_surfaces_subnet_description_from_user_context():
    mgr = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    mgr.ca_url = "http://localhost:8001"

    def fake_rpc(service, command, args=None):
        if command == "statistic-get-all":
            return {
                "subnet[1].total-addresses": [[254, "2024-01-01"]],
                "subnet[1].assigned-addresses": [[10, "2024-01-01"]],
                "subnet[1].declined-addresses": [[0, "2024-01-01"]],
                "declined-addresses": [[0, "2024-01-01"]],
                "pkt4-received": [[0, "2024-01-01"]],
                "pkt4-discover-received": [[0, "2024-01-01"]],
                "pkt4-request-received": [[0, "2024-01-01"]],
            }
        if command == "config-get":
            return {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24",
                                           "user-context": {"description": "Lab Tenant A VLAN10"}}]}}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    assert stats["subnets"][0]["subnet"] == "10.0.0.0/24"
    assert stats["subnets"][0]["description"] == "Lab Tenant A VLAN10"


def test_get_stats_empty_description_when_no_user_context():
    mgr = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    mgr.ca_url = "http://localhost:8001"

    def fake_rpc(service, command, args=None):
        if command == "statistic-get-all":
            return {
                "subnet[1].total-addresses": [[254, "2024-01-01"]],
                "subnet[1].assigned-addresses": [[0, "2024-01-01"]],
                "subnet[1].declined-addresses": [[0, "2024-01-01"]],
                "declined-addresses": [[0, "2024-01-01"]],
                "pkt4-received": [[0, "2024-01-01"]],
                "pkt4-discover-received": [[0, "2024-01-01"]],
                "pkt4-request-received": [[0, "2024-01-01"]],
            }
        if command == "config-get":
            return {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    assert stats["subnets"][0]["description"] == ""


# ── stale-scope regression: id stability + orphaned-stat filtering ────────

def test_build_subnet4_ids_are_stable_across_list_reordering():
    """The id for a given CIDR must not depend on its position in the list —
    that positional scheme was the root cause of the "Unknown scope (not in
    NetBox — stale?)" bug: any NetBox-side add/remove/reorder reassigned
    every downstream subnet to a new numeric id, orphaning the old one's
    Kea statistics forever.
    """
    a = {"subnet": "10.0.0.0/24", "pools": []}
    b = {"subnet": "10.0.1.0/24", "pools": []}
    c = {"subnet": "10.0.2.0/24", "pools": []}

    subs1, _, _ = kea_manager.build_subnet4([a, b, c], [])
    subs2, _, _ = kea_manager.build_subnet4([c, a, b], [])  # reordered + one removed later

    id_by_cidr_1 = {s["subnet"]: s["id"] for s in subs1}
    id_by_cidr_2 = {s["subnet"]: s["id"] for s in subs2}
    assert id_by_cidr_1 == id_by_cidr_2

    subs3, _, _ = kea_manager.build_subnet4([a, c], [])  # b removed entirely
    id_by_cidr_3 = {s["subnet"]: s["id"] for s in subs3}
    assert id_by_cidr_3["10.0.0.0/24"] == id_by_cidr_1["10.0.0.0/24"]
    assert id_by_cidr_3["10.0.2.0/24"] == id_by_cidr_1["10.0.2.0/24"]


def test_build_subnet4_ids_are_deterministic_from_cidr():
    subs1, _, _ = kea_manager.build_subnet4([{"subnet": "192.168.5.0/24", "pools": []}], [])
    subs2, _, _ = kea_manager.build_subnet4([{"subnet": "192.168.5.0/24", "pools": []}], [])
    assert subs1[0]["id"] == subs2[0]["id"]


def test_get_stats_drops_orphaned_subnet_ids_not_in_live_config():
    """A subnet-id present in statistic-get-all history but absent from the
    CURRENT subnet4-list is a leftover from a subnet Kea no longer serves
    (removed/reassigned NetBox-side) — it must be dropped, not rendered as
    an "Unknown scope" placeholder.
    """
    mgr = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    mgr.ca_url = "http://localhost:8001"

    def fake_rpc(service, command, args=None):
        if command == "statistic-get-all":
            return {
                "subnet[1].total-addresses": [[254, "2024-01-01"]],
                "subnet[1].assigned-addresses": [[10, "2024-01-01"]],
                "subnet[1].declined-addresses": [[0, "2024-01-01"]],
                # id 42 is stale: no longer in subnet4-list below
                "subnet[42].total-addresses": [[0, "2024-01-01"]],
                "subnet[42].assigned-addresses": [[0, "2024-01-01"]],
                "subnet[42].declined-addresses": [[0, "2024-01-01"]],
                "declined-addresses": [[0, "2024-01-01"]],
                "pkt4-received": [[0, "2024-01-01"]],
                "pkt4-discover-received": [[0, "2024-01-01"]],
                "pkt4-request-received": [[0, "2024-01-01"]],
            }
        if command == "config-get":
            return {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    ids = [s["subnet_id"] for s in stats["subnets"]]
    assert ids == [1]
    assert 42 not in ids


def test_get_stats_assigned_addresses_reflects_live_leases_not_stale_stat():
    """Kea's ``assigned-addresses`` statistic doesn't reliably decrement when
    a lease disappears without Kea's reclamation timer running — this used
    to surface as "1 assigned lease" on the Overview tile while the Leases
    tab (``lease4-get-all``) showed nothing. Overview must count live leases
    itself so the two tabs can never disagree.
    """
    mgr = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    mgr.ca_url = "http://localhost:8001"

    def fake_rpc(service, command, args=None):
        if command == "statistic-get-all":
            # Stale counter says 1 assigned address, but no lease actually exists.
            return {
                "subnet[1].total-addresses": [[254, "2024-01-01"]],
                "subnet[1].assigned-addresses": [[1, "2024-01-01"]],
                "subnet[1].declined-addresses": [[0, "2024-01-01"]],
                "declined-addresses": [[0, "2024-01-01"]],
                "pkt4-received": [[0, "2024-01-01"]],
                "pkt4-discover-received": [[0, "2024-01-01"]],
                "pkt4-request-received": [[0, "2024-01-01"]],
            }
        if command == "config-get":
            return {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        if command == "lease4-get-all":
            return {"leases": []}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    assert stats["subnets"][0]["assigned_addresses"] == 0
    assert stats["global"]["assigned_addresses"] == 0


def test_get_stats_assigned_addresses_counts_only_active_leases():
    mgr = kea_manager.KeaManager.__new__(kea_manager.KeaManager)
    mgr.ca_url = "http://localhost:8001"

    def fake_rpc(service, command, args=None):
        if command == "statistic-get-all":
            return {
                "subnet[1].total-addresses": [[254, "2024-01-01"]],
                "subnet[1].assigned-addresses": [[0, "2024-01-01"]],
                "subnet[1].declined-addresses": [[0, "2024-01-01"]],
                "declined-addresses": [[0, "2024-01-01"]],
                "pkt4-received": [[0, "2024-01-01"]],
                "pkt4-discover-received": [[0, "2024-01-01"]],
                "pkt4-request-received": [[0, "2024-01-01"]],
            }
        if command == "config-get":
            return {"Dhcp4": {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24"}]}}
        if command == "lease4-get-all":
            return {"leases": [
                {"ip-address": "10.0.0.5", "subnet-id": 1, "state": 0},
                {"ip-address": "10.0.0.6", "subnet-id": 1, "state": 2},  # expired-reclaimed
                {"ip-address": "10.0.0.7", "subnet-id": 1, "state": 1},  # declined
            ]}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    assert stats["subnets"][0]["assigned_addresses"] == 1
