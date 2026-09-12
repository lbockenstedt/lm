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
        if command == "subnet4-list":
            return {"subnets": [{"id": 1, "subnet": "10.0.0.0/24",
                                  "user-context": {"description": "Lab Tenant A VLAN10"}}]}
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
        if command == "subnet4-list":
            return {"subnets": [{"id": 1, "subnet": "10.0.0.0/24"}]}
        return {}

    mgr._rpc = MagicMock(side_effect=fake_rpc)
    stats = mgr.get_stats()
    assert stats["subnets"][0]["description"] == ""
