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
