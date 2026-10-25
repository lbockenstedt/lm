"""Regression gates for the DHCPv6 HA review fixes ported from the sibling
dhcp repo (c25b292 / 6874afa).

* ``kea_ha.DHCP_WORKER_OPS`` is the op allowlist handed to
  ``ClusterCoordinator`` — a v6 op missing from it can never be issued, which
  left the whole DHCPv6 HA path dead.
* The spoke must hand the coordinator its configured ``desired_state6`` path.
* A FAILED DHCPv6 lease purge must never be reported as a clean one — at the
  ``KeaManager``, the worker op, and the coordinator fan-out.
"""

import asyncio
from unittest.mock import MagicMock

import pytest

import kea_manager
from dhcp_spoke import DHCPSpoke
from dhcp_worker import DhcpWorkerOps
from kea_ha import DHCP_WORKER_OPS

V6_OPS = ("KEAW_GET_CONFIG6", "KEAW_VALIDATE6", "KEAW_APPLY6", "KEAW_ROLLBACK6",
          "KEAW_STANDDOWN6", "KEAW_HA_STATUS6", "KEAW_LIST_SUBNETS6",
          "KEAW_LIST_LEASES6", "KEAW_LIST_RES6", "KEAW_DEL_LEASE6")


def _run(coro):
    return asyncio.run(coro)


# ── c25b292: v6 ops allowlisted, desired_state6 wired, worker purge errors ──

def test_every_v6_worker_op_is_allowlisted():
    assert set(V6_OPS) <= set(DHCP_WORKER_OPS)
    assert set(V6_OPS) <= set(DhcpWorkerOps(MagicMock()).op_table())


def test_cluster_coordinator_accepts_v6_ops():
    try:
        from core.src.messaging.service_cluster import ClusterCoordinator
    except ImportError:
        from messaging.service_cluster import ClusterCoordinator  # type: ignore
    coord = ClusterCoordinator("dhcp", DHCP_WORKER_OPS, lambda: None, members=[])
    for op in V6_OPS:
        coord._check(op)  # must not raise ValueError
    with pytest.raises(ValueError):
        coord._check("KEAW_NOT_A_REAL_OP6")


def test_spoke_passes_desired_state6_to_the_cluster(tmp_path):
    path6 = str(tmp_path / "desired6.json")
    spoke = DHCPSpoke("dhcp-1", {
        "cluster_members": [],
        "cluster_config": str(tmp_path / "cluster.json"),
        "desired_state": str(tmp_path / "desired.json"),
        "desired_state6": path6,
    })
    assert spoke.cluster.state_path6 == path6


def test_worker_delete_lease6_reports_error_when_purge_fails():
    mgr = MagicMock()
    mgr.purge_leases6_for_mac_or_ip.side_effect = RuntimeError("Kea CA unreachable")
    out = DhcpWorkerOps(mgr).delete_lease6({"ip": "2001:db8::10"})
    assert out["status"] == "ERROR"
    assert "Kea CA unreachable" in out["message"]


def test_worker_delete_lease6_success_reports_purged():
    mgr = MagicMock()
    mgr.purge_leases6_for_mac_or_ip.return_value = ["2001:db8::10"]
    out = DhcpWorkerOps(mgr).delete_lease6({"ip": "2001:db8::10"})
    assert out == {"status": "SUCCESS", "purged": ["2001:db8::10"]}


# ── 6874afa: KeaManager tri-state delete_lease6 + raising purge ────────────

def _mgr():
    return kea_manager.KeaManager("http://localhost:8001")


def test_rpc_full_returns_whole_response_and_rpc_only_arguments():
    mgr = _mgr()
    resp = MagicMock()
    resp.json.return_value = [{"result": 3, "text": "not found"}]
    mgr._session = MagicMock()
    mgr._session.post.return_value = resp
    assert mgr._rpc_full("dhcp6", "lease6-del", {}) == {"result": 3, "text": "not found"}
    resp.json.return_value = [{"result": 0, "arguments": {"a": 1}}]
    assert mgr._rpc("dhcp6", "x") == {"a": 1}
    resp.json.return_value = [{"result": 1, "text": "boom"}]
    with pytest.raises(RuntimeError, match="boom"):
        mgr._rpc_full("dhcp6", "x")


def test_delete_lease6_distinguishes_deleted_not_found_and_failed():
    mgr = _mgr()
    mgr._rpc_full = MagicMock(return_value={"result": 0, "text": "deleted"})
    out = mgr.delete_lease6("2001:db8::10")
    assert out["status"] == "SUCCESS" and out["not_found"] is False

    mgr._rpc_full = MagicMock(return_value={"result": 3, "text": "no lease"})
    out = mgr.delete_lease6("2001:db8::10")
    assert out["status"] == "SUCCESS" and out["not_found"] is True

    mgr._rpc_full = MagicMock(side_effect=RuntimeError("Kea CA unreachable"))
    out = mgr.delete_lease6("2001:db8::10")
    assert out["status"] == "ERROR" and "unreachable" in out["message"]


def test_purge_leases6_only_reports_actually_deleted_addresses():
    mgr = _mgr()
    mgr.list_leases6 = MagicMock(return_value=[
        {"ip-address": "2001:db8::20", "hw-address": "aa:bb:cc:dd:ee:01"},
        {"ip-address": "2001:db8::30", "hw-address": "aa:bb:cc:dd:ee:02"},
    ])
    mgr.delete_lease6 = MagicMock(side_effect=lambda ip: (
        {"status": "SUCCESS", "not_found": True} if ip == "2001:db8::10"
        else {"status": "SUCCESS", "not_found": False}))
    purged = mgr.purge_leases6_for_mac_or_ip(mac="AA:BB:CC:DD:EE:01", ip="2001:db8::10")
    assert purged == ["2001:db8::20"]
    mgr.list_leases6.assert_called_once_with(strict=True)


def test_purge_leases6_raises_when_a_delete_fails():
    mgr = _mgr()
    mgr.delete_lease6 = MagicMock(return_value={"status": "ERROR", "message": "down"})
    with pytest.raises(RuntimeError, match="down"):
        mgr.purge_leases6_for_mac_or_ip(ip="2001:db8::10")


def test_purge_leases6_raises_when_the_lease_db_is_unreadable():
    mgr = _mgr()
    mgr.list_subnets6 = MagicMock(side_effect=RuntimeError("Kea CA unreachable"))
    with pytest.raises(RuntimeError, match="could not read the DHCPv6 lease database"):
        mgr.purge_leases6_for_mac_or_ip(mac="aa:bb:cc:dd:ee:01")


def test_list_leases6_non_strict_still_hides_failures():
    mgr = _mgr()
    mgr.list_subnets6 = MagicMock(side_effect=RuntimeError("down"))
    assert mgr.list_leases6() == []
    with pytest.raises(RuntimeError):
        mgr.list_leases6(strict=True)


def test_add_reservation6_is_partial_when_lease_purge_fails():
    mgr = _mgr()
    mgr.get_config6 = MagicMock(return_value={"subnet6": [{"id": 3}]})
    mgr._set_config6 = MagicMock()
    mgr.purge_leases6_for_mac_or_ip = MagicMock(side_effect=RuntimeError("down"))
    out = mgr.add_reservation6(3, "2001:db8::20", "aa:bb:cc:dd:ee:01")
    assert out["status"] == "PARTIAL"
    assert out["reservation_applied"] is True
    assert out["lease_purge"]["error"] == "down"
    mgr._set_config6.assert_called_once()


def test_add_reservation6_success_reports_purged():
    mgr = _mgr()
    mgr.get_config6 = MagicMock(return_value={"subnet6": [{"id": 3}]})
    mgr._set_config6 = MagicMock()
    mgr.purge_leases6_for_mac_or_ip = MagicMock(return_value=["2001:db8::20"])
    out = mgr.add_reservation6(3, "2001:db8::20", "aa:bb:cc:dd:ee:01")
    assert out["status"] == "SUCCESS"
    assert out["lease_purge"] == {"purged": ["2001:db8::20"]}


# ── 6874afa: HA DHCP_DEL_LEASE6 reflects member failures ───────────────────

class _FanoutTransport:
    enabled = True
    members = [{"id": "a"}, {"id": "b"}]

    def __init__(self, reply):
        self.reply = reply
        self.calls = []

    async def fanout(self, command, data, timeout=20.0, member_ids=None):
        self.calls.append((command, data))
        return self.reply


def _ha_spoke(tmp_path, reply):
    spoke = DHCPSpoke("dhcp-1", {
        "cluster_members": [],
        "cluster_config": str(tmp_path / "cluster.json"),
        "desired_state": str(tmp_path / "desired.json"),
        "desired_state6": str(tmp_path / "desired6.json"),
    })
    spoke.mgr = MagicMock()
    spoke.cluster.transport = _FanoutTransport(reply)
    return spoke


@pytest.mark.parametrize("reply,status", [
    ({"results": {"a": {"status": "SUCCESS"}, "b": {"status": "SUCCESS"}}}, "SUCCESS"),
    ({"results": {"a": {"status": "SUCCESS"}, "b": {"status": "ERROR",
                                                    "message": "down"}}}, "PARTIAL"),
    ({"results": {"a": {"status": "ERROR"}, "b": "garbage"}}, "ERROR"),
    ({"results": {}}, "ERROR"),
    ({"status": "ERROR", "message": "HA disabled"}, "ERROR"),
])
def test_ha_del_lease6_status_reflects_member_results(tmp_path, reply, status):
    spoke = _ha_spoke(tmp_path, reply)
    out = _run(spoke.handle_command("DHCP_DEL_LEASE6", {"ip": "2001:db8::10"}))
    assert out["status"] == status
    assert spoke.cluster.transport.calls == [("KEAW_DEL_LEASE6", {"ip": "2001:db8::10"})]
    if status == "PARTIAL":
        assert out["member_errors"] == {"b": "down"}
    if status == "ERROR" and reply.get("results"):
        assert set(out["member_errors"]) == {"a", "b"}
