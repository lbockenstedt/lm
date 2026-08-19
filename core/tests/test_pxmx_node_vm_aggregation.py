"""Unit tests for ``pxmx_node_vm_aggregation`` — the shared GET_NODE_STATS /
PXMX_LIST_VMS logic used by EVERY agent-hosting control plane (a dedicated
pxmx hypervisor spoke AND a cs/simulation spoke hosting its own Proxmox agent
listener). Ported out of pxmx's ``ProxmoxSpoke`` so a cs-hosted host answers
these two commands identically instead of falling through to "not supported
by <module>" (the Hypervisors-page bug this fixes — see
``messaging/control_plane.py``'s ``handle_system_command``).
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import pxmx_node_vm_aggregation as agg  # noqa: E402
from core.src.messaging.control_plane import BaseControlPlane   # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class _FakeCP:
    """Minimal stand-in for an ``AgentHostingControlPlane`` — only the
    ``connected_agents``/``send_to_agent``/``disk_cache`` surface these
    functions actually use."""

    def __init__(self, connected_agents=None, disk_cache=None):
        self.connected_agents = connected_agents or {}
        self.disk_cache = disk_cache if disk_cache is not None else {}
        self.calls = []

    async def send_to_agent(self, cmd, data, agent_id=None, timeout=None):
        self.calls.append((cmd, data, agent_id))
        return {"ok": True, "rc": 0, "stdout": "[]"}


# ── get_node_stats ────────────────────────────────────────────────────────

def test_get_node_stats_telemetry_cache_hit_no_run_command():
    cp = _FakeCP({"agent-1": {"cluster_name": "clusterA",
                              "nodes": [{"node": "pve1", "status": "online"}]}})
    r = _run(agg.get_node_stats(cp, {}))
    assert r["status"] == "SUCCESS"
    assert r["nodes"] == [{"node": "pve1", "status": "online", "agent_id": "agent-1",
                           "cluster": "clusterA", "telemetry_ts": 0}]
    assert cp.calls == []  # telemetry cache hit — no RUN_COMMAND round-trip


def test_get_node_stats_no_agents_no_cache_returns_empty():
    cp = _FakeCP({})
    r = _run(agg.get_node_stats(cp, {}))
    assert r == {"status": "SUCCESS", "nodes": []}


def test_get_node_stats_no_control_plane():
    r = _run(agg.get_node_stats(None, {}))
    assert r == {"status": "ERROR", "error": "Control plane not initialised"}


def test_get_node_stats_falls_back_to_disk_cache_when_no_agents():
    cp = _FakeCP({}, disk_cache={"agent-1": {"cluster_name": "clusterA",
                                             "nodes": [{"node": "pve9"}]}})
    r = _run(agg.get_node_stats(cp, {}))
    assert r["status"] == "SUCCESS"
    assert r["stale"] is True
    assert r["nodes"][0]["node"] == "pve9"


def test_get_node_stats_dedupes_cluster_mates_by_node_hostname():
    """4 cluster-mate agents each self-report the FULL cluster's node
    membership (real pvesh /cluster/resources behavior) — must collapse to
    one row per physical node, not one row per (agent, node) pair."""
    peers = [{"node": "pve1", "status": "online"},
             {"node": "pve2", "status": "online"},
             {"node": "pve3", "status": "online"},
             {"node": "pve4", "status": "online"}]
    cp = _FakeCP({
        f"agent-{i}": {"cluster_name": f"agent-{i}",  # stale per-agent name
                       "telemetry_ts": 100.0 + i, "nodes": list(peers)}
        for i in range(4)
    })
    r = _run(agg.get_node_stats(cp, {}))
    assert r["status"] == "SUCCESS"
    assert sorted(n["node"] for n in r["nodes"]) == ["pve1", "pve2", "pve3", "pve4"]


def test_get_node_stats_freshest_cluster_mate_wins_on_conflict():
    """When cluster-mates disagree on a node's status (telemetry timing skew),
    the agent with the newer ``telemetry_ts`` wins — not whichever happened
    to be first in dict-iteration order."""
    cp = _FakeCP({
        "agent-old": {"cluster_name": "lab", "telemetry_ts": 100.0,
                      "nodes": [{"node": "pve1", "status": "offline"}]},
        "agent-new": {"cluster_name": "lab", "telemetry_ts": 200.0,
                      "nodes": [{"node": "pve1", "status": "online"}]},
    })
    r = _run(agg.get_node_stats(cp, {}))
    assert len(r["nodes"]) == 1
    assert r["nodes"][0]["status"] == "online"
    assert r["nodes"][0]["agent_id"] == "agent-new"


# ── list_vms ──────────────────────────────────────────────────────────────

def test_list_vms_telemetry_cache_hit():
    cp = _FakeCP({"agent-1": {"cluster_name": "clusterA",
                              "vms": [{"vmid": 101, "node": "pve1",
                                       "status": "running", "tags": ["prod"]}]}})
    r = _run(agg.list_vms(cp, {}))
    assert r["status"] == "SUCCESS"
    assert r["source"] == "telemetry_cache"
    assert r["vms"][0]["unique_id"] == "clusterA/pve1/101"
    assert cp.calls == []


def test_list_vms_tag_filter_excludes_non_matching():
    cp = _FakeCP({"agent-1": {"cluster_name": "c",
                              "vms": [{"vmid": 1, "node": "n", "tags": ["prod"]},
                                      {"vmid": 2, "node": "n", "tags": ["dev"]}]}})
    r = _run(agg.list_vms(cp, {"tag_filter": "dev"}))
    assert [v["vmid"] for v in r["vms"]] == [2]


def test_list_vms_dedupes_cluster_mates_by_node_and_vmid():
    """4 cluster-mate agents each self-report the FULL cluster's VM list —
    must collapse to one row per (node, vmid), not one row per agent."""
    vms = [{"vmid": 101, "node": "pve1"}, {"vmid": 102, "node": "pve2"}]
    cp = _FakeCP({
        f"agent-{i}": {"cluster_name": "lab", "telemetry_ts": 100.0 + i,
                       "vms": list(vms)}
        for i in range(4)
    })
    r = _run(agg.list_vms(cp, {}))
    assert sorted((v["node"], v["vmid"]) for v in r["vms"]) == [
        ("pve1", 101), ("pve2", 102)]


def test_list_vms_freshest_cluster_mate_wins_on_conflict():
    cp = _FakeCP({
        "agent-old": {"cluster_name": "lab", "telemetry_ts": 100.0,
                      "vms": [{"vmid": 101, "node": "pve1", "status": "stopped"}]},
        "agent-new": {"cluster_name": "lab", "telemetry_ts": 200.0,
                      "vms": [{"vmid": 101, "node": "pve1", "status": "running"}]},
    })
    r = _run(agg.list_vms(cp, {}))
    assert len(r["vms"]) == 1
    assert r["vms"][0]["status"] == "running"
    assert r["vms"][0]["agent_id"] == "agent-new"


def test_list_vms_no_control_plane():
    r = _run(agg.list_vms(None, {}))
    assert r == {"status": "ERROR", "error": "Control plane not initialised"}


def test_list_vms_pinned_agent_unreachable_surfaces_error():
    async def _fake_send(cmd, data, agent_id=None, timeout=None):
        return {"status": "ERROR", "message": "agent unreachable"}
    cp = _FakeCP({})
    cp.send_to_agent = _fake_send
    r = _run(agg.list_vms(cp, {"agent_id": "dead-agent"}))
    assert r["status"] == "ERROR"


# ── handle_system_command wiring (mirrors GET_AGENTS) ────────────────────

class _CPWithDispatch(BaseControlPlane):
    """Bypass BaseControlPlane.__init__ (heavy: websockets/threads) — only
    set what handle_system_command's GET_NODE_STATS/PXMX_LIST_VMS branches
    touch, mirroring the cs/pxmx control planes' actual attribute surface."""

    def __init__(self, connected_agents):
        self.connected_agents = connected_agents

    async def send_to_agent(self, cmd, data, agent_id=None, timeout=None):
        return {"ok": True, "rc": 0, "stdout": "[]"}


class _NonAgentHostingCP(BaseControlPlane):
    """A dns/dhcp/nw-style spoke: no connected_agents at all."""

    def __init__(self):
        pass


def test_handle_system_command_answers_get_node_stats_for_agent_hosting_spoke():
    cp = _CPWithDispatch({"a1": {"cluster_name": "c", "nodes": [{"node": "pve1"}]}})
    r = _run(cp.handle_system_command("GET_NODE_STATS", {}))
    assert r["status"] == "SUCCESS"
    assert r["nodes"][0]["node"] == "pve1"


def test_handle_system_command_answers_pxmx_list_vms_for_agent_hosting_spoke():
    cp = _CPWithDispatch({"a1": {"cluster_name": "c", "vms": [{"vmid": 5, "node": "n"}]}})
    r = _run(cp.handle_system_command("PXMX_LIST_VMS", {}))
    assert r["status"] == "SUCCESS"
    assert r["vms"][0]["vmid"] == 5


def test_handle_system_command_ignores_node_stats_for_non_agent_hosting_spoke():
    cp = _NonAgentHostingCP()
    r = _run(cp.handle_system_command("GET_NODE_STATS", {}))
    assert r is None  # falls through to module dispatch, unchanged from before
