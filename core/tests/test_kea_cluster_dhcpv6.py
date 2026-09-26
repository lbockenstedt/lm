"""KeaHACoordinator's DHCPv6 transaction path (dhcp/src/kea_cluster.py).

Kea runs dhcp4/dhcp6 as fully independent daemons/config trees, so the HA
coordinator needs a parallel (not merged) transaction for ``subnet6``: its own
worker RPCs (``KEAW_*6``), its own version counter, and its own crash-recovery
journal — sharing any of those with the v4 path would let an unrelated v4-only
apply bump the v6 version (or vice versa) and make a "pending candidate" on
restart ambiguous about which daemon it belongs to.

These tests exercise ``apply6``/``render6``/``owned_config6`` directly against
a fake transport, mirroring the existing HA-fanout test pattern used for
``dhcp_spoke.py`` (see test_dhcp_ha_stats_dedup.py), and confirm the v4 and v6
transactions are fully independent of one another.
"""
import asyncio
import importlib.util
import os
import sys
import tempfile
from typing import Any, Dict
from unittest.mock import AsyncMock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DHCP_SRC = os.path.join(ROOT, "dhcp", "src")
if DHCP_SRC not in sys.path:
    sys.path.insert(0, DHCP_SRC)

import kea_cluster  # noqa: E402


MEMBERS = [
    {"id": "node-a", "host": "10.0.0.1", "role": "primary"},
    {"id": "node-b", "host": "10.0.0.2", "role": "standby"},
]


class FakeTransport:
    """Minimal ``ClusterCoordinator`` surface KeaHACoordinator needs."""

    def __init__(self, members):
        self.enabled = True
        self.members = members
        self.fanout_result: Dict[str, Any] = {"results": {
            m["id"]: {"status": "SUCCESS"} for m in members}}
        # member_id -> command -> reply (falls back to a generic SUCCESS)
        self.call_results: Dict[str, Dict[str, Any]] = {}
        self.calls = []

    def member_links(self):
        return [{"id": m["id"], "connected": True} for m in self.members]

    async def fanout(self, command, payload, timeout=10.0):
        self.calls.append(("fanout", command, payload))
        return self.fanout_result

    async def call(self, member_id, command, payload, timeout=10.0):
        self.calls.append(("call", member_id, command, payload))
        per_member = self.call_results.get(member_id, {})
        if command in per_member:
            return per_member[command]
        if command in ("KEAW_GET_CONFIG6",):
            return {"status": "SUCCESS", "config": {"Dhcp6": {}}}
        if command in ("KEAW_GET_CONFIG",):
            return {"status": "SUCCESS", "config": {"Dhcp4": {}}}
        return {"status": "SUCCESS"}


def _coordinator(members=None, transport=None):
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    tmp6 = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp6.close()
    transport = transport or FakeTransport(members or MEMBERS)
    coord = kea_cluster.KeaHACoordinator(
        transport, mode="hot-standby", state_path=tmp.name, state_path6=tmp6.name)
    return coord


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


SUBNET6 = [{"subnet": "2001:470:4948:100::/64", "description": "servers",
           "vlan_id": 100, "gateway": None}]


def test_owned_config6_uses_subnet6_key():
    coord = _coordinator()
    owned = coord.owned_config6(SUBNET6, [])
    assert "subnet6" in owned
    assert "subnet4" not in owned


def test_render6_builds_a_config_per_peer_with_dhcp6_hooks():
    coord = _coordinator()
    plan = coord.render6(SUBNET6, [])
    assert set(plan["configs"]) == {"node-a", "node-b"}
    for cfg in plan["configs"].values():
        libs = [h["library"] for h in cfg["hooks-libraries"]]
        assert any(lib.endswith("libdhcp_ha.so") for lib in libs)
        assert any(lib.endswith("libdhcp_lease_cmds.so") for lib in libs)
    assert plan["subnets"] == 1


def test_apply6_success_commits_a_new_version_and_touches_v6_rpcs_only():
    coord = _coordinator()
    result = _run(coord.apply6(SUBNET6, []))
    assert result["status"] == "SUCCESS"
    assert coord.version6 == 1
    assert coord.version == 0  # v4 state untouched
    v6_calls = {c[2] for c in coord.transport.calls if c[0] == "call"}
    assert v6_calls <= {"KEAW_GET_CONFIG6", "KEAW_VALIDATE6", "KEAW_APPLY6"}
    assert "KEAW_GET_CONFIG" not in v6_calls and "KEAW_APPLY" not in v6_calls


def test_apply6_and_apply_keep_independent_versions():
    """A v4 apply must not advance version6, and vice versa."""
    coord = _coordinator()
    v4_result = _run(coord.apply([{"subnet": "172.17.5.0/24", "gateway": None,
                                   "vlan_id": 5, "description": "x"}], []))
    assert v4_result["status"] == "SUCCESS"
    assert coord.version == 1
    assert coord.version6 == 0

    v6_result = _run(coord.apply6(SUBNET6, []))
    assert v6_result["status"] == "SUCCESS"
    assert coord.version6 == 1
    assert coord.version == 1  # unaffected by the v6 apply


def test_apply6_validation_failure_touches_no_node():
    transport = FakeTransport(MEMBERS)
    transport.call_results["node-a"] = {
        "KEAW_VALIDATE6": {"status": "ERROR", "message": "bad config"}}
    coord = _coordinator(transport=transport)
    result = _run(coord.apply6(SUBNET6, []))
    assert result["status"] == "ERROR"
    assert result["stage"] == "validate"
    assert coord.version6 == 0
    apply_calls = [c for c in transport.calls if c[0] == "call" and c[2] == "KEAW_APPLY6"]
    assert not apply_calls


def test_apply6_rolls_back_the_applied_peer_on_a_mid_chain_failure():
    transport = FakeTransport(MEMBERS)
    # node-b applies first (standby-then-primary order); make node-a (primary)
    # fail its apply so node-b's already-applied config must be rolled back.
    transport.call_results["node-a"] = {
        "KEAW_APPLY6": {"status": "ERROR", "message": "config-set rejected",
                        "mutated": False}}
    coord = _coordinator(transport=transport)
    result = _run(coord.apply6(SUBNET6, []))
    assert result["status"] == "ERROR"
    assert coord.version6 == 0
    rollback_targets = [c[1] for c in transport.calls
                        if c[0] == "call" and c[2] == "KEAW_ROLLBACK6"]
    assert "node-b" in rollback_targets


def test_report6_and_status6_are_separate_from_report_and_status():
    coord = _coordinator()
    r4 = coord.report()
    r6 = coord.report6()
    assert r4 is not r6
    assert "last_apply" in r4 and "last_apply" in r6
