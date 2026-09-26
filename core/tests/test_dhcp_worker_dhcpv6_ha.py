"""DHCPv6 worker ops (dhcp/src/dhcp_worker.py) — the dhcp6 daemon's half of
an HA apply/rollback, plus the read-only ops used for HA fanout.

Mirrors the safety-critical v4 contract on a separate ``self._snapshot6``:
SUCCESS only when BOTH config-set and config-write land, and a config-write
failure triggers an immediate local restore attempt, never a silent success.
"""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[2]
DHCP_SRC = ROOT / "dhcp" / "src"


def _load_dhcp_worker():
    if str(DHCP_SRC) not in sys.path:
        sys.path.insert(0, str(DHCP_SRC))
    spec = importlib.util.spec_from_file_location(
        "lm_dhcp_worker_v6test", DHCP_SRC / "dhcp_worker.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


dhcp_worker = _load_dhcp_worker()


def _ops(mgr=None):
    return dhcp_worker.DhcpWorkerOps(mgr or MagicMock())


def test_get_config6_returns_the_running_dhcp6_config():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": [], "interfaces-config": {}}
    ops = _ops(mgr)
    result = ops.get_config6({})
    assert result["status"] == "SUCCESS"
    assert result["config"]["subnet6"] == []


def test_validate6_requires_a_dhcp6_key():
    ops = _ops()
    result = ops.validate6({})
    assert result["status"] == "ERROR"


def test_validate6_calls_config_test_against_the_dhcp6_service():
    mgr = MagicMock()
    ops = _ops(mgr)
    result = ops.validate6({"config": {"Dhcp6": {"subnet6": []}}})
    mgr._rpc.assert_called_once_with("dhcp6", "config-test", {"Dhcp6": {"subnet6": []}})
    assert result["status"] == "SUCCESS"


def test_apply6_success_reports_mutated_true():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": []}
    mgr.apply_config6.return_value = {"set": True, "written": True}
    ops = _ops(mgr)
    result = ops.apply6({"config": {"Dhcp6": {"subnet6": []}}, "version": 3})
    assert result["status"] == "SUCCESS"
    assert result["mutated"] is True
    assert result["version"] == 3


def test_apply6_config_set_rejected_reports_not_mutated():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": []}
    mgr.apply_config6.return_value = {"set": False, "error": "hook libraries failed to load"}
    ops = _ops(mgr)
    result = ops.apply6({"config": {"Dhcp6": {"subnet6": []}}})
    assert result["status"] == "ERROR"
    assert result["mutated"] is False


def test_apply6_write_failure_restores_and_reports_error_when_restore_succeeds():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": [], "tag": "snapshot"}
    mgr.apply_config6.side_effect = [
        {"set": True, "written": False, "error": "disk full"},  # the apply
        {"set": True, "written": True},                          # the restore
    ]
    ops = _ops(mgr)
    result = ops.apply6({"config": {"Dhcp6": {"subnet6": []}}})
    assert result["status"] == "ERROR"
    assert result["mutated"] is False
    assert result["restored"] is True


def test_apply6_write_failure_partial_when_restore_also_fails():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": []}
    mgr.apply_config6.side_effect = [
        {"set": True, "written": False, "error": "disk full"},
        {"set": False, "error": "also broken"},
    ]
    ops = _ops(mgr)
    result = ops.apply6({"config": {"Dhcp6": {"subnet6": []}}})
    assert result["status"] == "PARTIAL"
    assert result["mutated"] is True
    assert result["restored"] is False


def test_rollback6_uses_the_v6_snapshot_not_the_v4_one():
    mgr = MagicMock()
    mgr.get_config6.return_value = {"subnet6": [], "marker": "v6-snapshot"}
    mgr.apply_config6.return_value = {"set": True, "written": True}
    ops = _ops(mgr)
    ops._snapshot = {"marker": "v4-snapshot-must-not-be-used"}
    ops.apply6({"config": {"Dhcp6": {"subnet6": []}}})
    result = ops.rollback6({})
    assert result["status"] == "SUCCESS"
    restored = mgr.apply_config6.call_args[0][0]
    assert restored["marker"] == "v6-snapshot"


def test_rollback6_without_a_prior_apply_errors():
    ops = _ops()
    result = ops.rollback6({})
    assert result["status"] == "ERROR"


def test_ha_status6_uses_the_dhcp6_service():
    mgr = MagicMock()
    mgr._rpc.return_value = {"high-availability": []}
    mgr.get_config6.return_value = {"subnet6": [{"id": 1}]}
    ops = _ops(mgr)
    result = ops.ha_status6({})
    mgr._rpc.assert_called_once_with("dhcp6", "status-get", {})
    assert result["status"] == "SUCCESS"
    assert result["subnet_count"] == 1


def test_list_subnets6_delegates_to_the_manager():
    mgr = MagicMock()
    mgr.list_subnets6.return_value = [{"id": 1}]
    ops = _ops(mgr)
    result = ops.list_subnets6({})
    assert result == {"status": "SUCCESS", "subnets": [{"id": 1}]}


def test_delete_lease6_purges_by_ip_old_ip_and_mac():
    mgr = MagicMock()
    mgr.purge_leases6_for_mac_or_ip.side_effect = [
        {"2001:db8::1"}, {"2001:db8::2"}]
    ops = _ops(mgr)
    result = ops.delete_lease6({"ip": "2001:db8::1", "old_ip": "2001:db8::2",
                                "mac": "aa:bb:cc:dd:ee:ff"})
    assert result["status"] == "SUCCESS"
    assert set(result["purged"]) == {"2001:db8::1", "2001:db8::2"}


def test_op_table_registers_every_v6_op():
    ops = _ops()
    table = ops.op_table()
    for name in ("KEAW_GET_CONFIG6", "KEAW_VALIDATE6", "KEAW_APPLY6",
                "KEAW_ROLLBACK6", "KEAW_STANDDOWN6", "KEAW_HA_STATUS6",
                "KEAW_LIST_SUBNETS6", "KEAW_LIST_LEASES6", "KEAW_LIST_RES6",
                "KEAW_DEL_LEASE6"):
        assert name in table
