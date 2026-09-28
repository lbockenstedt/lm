"""DHCPSpoke's DHCPv6 HA-cluster command routing (dhcp/src/dhcp_spoke.py).

DHCPv6 used to be refused outright whenever the pair was HA-clustered
(``self.cluster.enabled``). These tests hold the routed commands to the same
contract as their v4 counterparts: DHCP_SYNC6/DHCP_ADD_RES6/DHCP_DEL_RES6 go
through the coordinator's v6-suffixed transaction methods, and lease-purge
failures on a reservation upsert still downgrade the result to PARTIAL
instead of a silent SUCCESS.
"""
import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock

DHCP_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dhcp", "src"))
if DHCP_SRC not in sys.path:
    sys.path.insert(0, DHCP_SRC)

import dhcp_spoke  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_spoke():
    spoke = dhcp_spoke.DHCPSpoke.__new__(dhcp_spoke.DHCPSpoke)
    spoke.cluster = MagicMock()
    spoke.cluster.enabled = True
    spoke.cluster.transport = MagicMock()
    spoke.cluster.transport.fanout = AsyncMock()
    spoke._transport = spoke.cluster.transport
    spoke.cluster.apply6 = AsyncMock(return_value={"status": "SUCCESS"})
    spoke.cluster.mutate_reservation6 = AsyncMock(return_value={"status": "SUCCESS"})
    spoke.cluster.desired6 = {"subnets": [{"subnet": "2001:db8::/64"}], "reservations": []}
    spoke.cluster.status6 = AsyncMock(return_value={"status": "SUCCESS"})
    return spoke


def test_dhcp_sync6_on_an_ha_pair_goes_through_apply6_not_apply():
    spoke = _make_spoke()
    spoke.cluster.apply = AsyncMock(side_effect=AssertionError("v4 apply must not run"))
    result = _run(spoke.handle_command("DHCP_SYNC6", {"subnets": [], "reservations": []}))
    assert result["status"] == "SUCCESS"
    spoke.cluster.apply6.assert_awaited_once()


def test_dhcp_ha_status6_reports_disabled_cleanly_when_no_pair_is_configured():
    spoke = _make_spoke()
    spoke.cluster.enabled = False
    spoke.cluster.mode = "hot-standby"
    result = _run(spoke.handle_command("DHCP_HA_STATUS6", {}))
    assert result["status"] == "SUCCESS"
    assert result["enabled"] is False


def test_dhcp_ha_apply6_refuses_when_nothing_was_synced():
    spoke = _make_spoke()
    spoke.cluster.desired6 = {"subnets": [], "reservations": []}
    result = _run(spoke.handle_command("DHCP_HA_APPLY6", {}))
    assert result["status"] == "ERROR"
    spoke.cluster.apply6.assert_not_awaited()


def test_dhcp_ha_apply6_reapplies_the_committed_desired_state():
    spoke = _make_spoke()
    result = _run(spoke.handle_command("DHCP_HA_APPLY6", {}))
    assert result["status"] == "SUCCESS"
    spoke.cluster.apply6.assert_awaited_once_with(
        [{"subnet": "2001:db8::/64"}], [])


def test_add_res6_purges_the_old_lease_on_every_node():
    spoke = _make_spoke()
    spoke.cluster.transport.fanout.return_value = {
        "results": {"node-a": {"status": "SUCCESS", "purged": ["2001:db8::5"]}}}
    result = _run(spoke.handle_command(
        "DHCP_ADD_RES6", {"ip": "2001:db8::5", "mac": "aa:bb:cc:dd:ee:ff"}))
    assert result["status"] == "SUCCESS"
    assert result["lease_purge"]["purged"] == ["2001:db8::5"]
    spoke.cluster.transport.fanout.assert_awaited_once()
    assert spoke.cluster.transport.fanout.await_args[0][0] == "KEAW_DEL_LEASE6"


def test_add_res6_downgrades_to_partial_when_the_lease_purge_fails_on_a_node():
    spoke = _make_spoke()
    spoke.cluster.transport.fanout.return_value = {
        "results": {"node-a": {"status": "ERROR", "message": "unreachable"}}}
    result = _run(spoke.handle_command(
        "DHCP_ADD_RES6", {"ip": "2001:db8::5", "mac": "aa:bb:cc:dd:ee:ff"}))
    assert result["status"] == "PARTIAL"
    assert "node-a" in result["lease_purge"]["errors"]


def test_del_res6_does_not_attempt_a_lease_purge():
    spoke = _make_spoke()
    result = _run(spoke.handle_command("DHCP_DEL_RES6", {"ip": "2001:db8::5"}))
    assert result["status"] == "SUCCESS"
    spoke.cluster.transport.fanout.assert_not_awaited()


def test_list_subnets6_fans_out_to_the_v6_worker_op():
    spoke = _make_spoke()
    spoke.cluster.transport.fanout.return_value = {
        "results": {"node-a": {"status": "SUCCESS",
                                "subnets": [{"subnet": "2001:db8::/64"}]}}}
    result = _run(spoke.handle_command("DHCP_LIST_SUBNETS6", {}))
    assert result["status"] == "SUCCESS"
    assert spoke.cluster.transport.fanout.await_args[0][0] == "KEAW_LIST_SUBNETS6"
