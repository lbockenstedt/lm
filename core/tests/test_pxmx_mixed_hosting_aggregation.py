"""Mixed-deployment aggregation for the Hypervisors module (``routes/pxmx.py``).

A Proxmox host can be hosted by a hypervisor (pxmx) spoke OR a simulation (cs)
spoke: once the CS flag is set on a box, its unified agent dials the cs spoke's
``/ws/agent`` yet the box must STILL appear in the Hypervisors module (it can run
a MIX of infra + sim-client VMs), in addition to the Simulation module.

Pre-fix, both the VM list (``/api/pxmx/vms``) and the Overview
(``/api/pxmx/nodes``) resolved a SINGLE ``get_hypervisor_spoke()`` — which
prefers a real pxmx spoke — so in a mixed deployment (a dedicated pxmx host
AND a cs-hosted host) every cs-hosted host silently vanished from the
Hypervisors page. The route now fans the query across EVERY agent-hosting
spoke (hypervisor + simulation) and merges, mirroring the Agents tile.

These lock in:

* the VM list merges VMs from a pxmx spoke AND a cs spoke (no host is hidden);
* the Overview merges nodes from both spoke types;
* node aggregation stays tenant-scoped (only the tenant's BOUND spokes), so a
  merge never leaks another tenant's hosts;
* a single dead spoke never drops the reachable spoke's data.
"""

import pytest

from routes import pxmx


class _Hub:
    """Fan-out fake: maps a spoke id → its canned per-command reply, records
    which spokes were queried, and can make selected spokes raise."""

    def __init__(self, replies, fail=None):
        self._replies = replies            # {sid: {"vms": [...], "nodes": [...]}}
        self._fail = set(fail or [])
        self.queried = []

    async def request_response(self, sid, cmd, payload, timeout=30.0,
                               signing_secret=None):
        self.queried.append(sid)
        if sid in self._fail:
            raise RuntimeError(f"{sid} timeout")
        data = self._replies.get(sid, {})
        return {"payload": {"data": dict(data, spoke_connected=True)}}


# ── _aggregate_pxmx_vms ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vms_merge_across_hypervisor_and_simulation_spokes():
    hub = _Hub({
        "pxmx-1": {"vms": [{"unique_id": "PXMX/PXMX/100", "name": "infra-vm"}]},
        "cs-06":  {"vms": [{"unique_id": "CS/CS/200", "name": "sim-host-vm"}]},
    })
    out = await pxmx._aggregate_pxmx_vms(hub, ["pxmx-1", "cs-06"], {})
    names = sorted(v["name"] for v in out["vms"])
    assert names == ["infra-vm", "sim-host-vm"]
    assert out["spoke_connected"] is True
    assert set(hub.queried) == {"pxmx-1", "cs-06"}


@pytest.mark.asyncio
async def test_vms_one_dead_spoke_does_not_drop_the_other():
    hub = _Hub({
        "pxmx-1": {"vms": [{"unique_id": "PXMX/PXMX/100", "name": "infra-vm"}]},
        "cs-06":  {"vms": [{"unique_id": "CS/CS/200", "name": "sim-host-vm"}]},
    }, fail=["pxmx-1"])
    out = await pxmx._aggregate_pxmx_vms(hub, ["pxmx-1", "cs-06"], {})
    assert [v["name"] for v in out["vms"]] == ["sim-host-vm"]
    assert out["spoke_connected"] is True


@pytest.mark.asyncio
async def test_vms_all_spokes_fail_raises_for_warm_fallback():
    hub = _Hub({"pxmx-1": {}, "cs-06": {}}, fail=["pxmx-1", "cs-06"])
    with pytest.raises(Exception):
        await pxmx._aggregate_pxmx_vms(hub, ["pxmx-1", "cs-06"], {})


# ── _aggregate_pxmx_nodes ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_nodes_merge_across_hypervisor_and_simulation_spokes():
    hub = _Hub({
        "pxmx-1": {"nodes": [{"node": "PXMX", "status": "online"}]},
        "cs-06":  {"nodes": [{"node": "pxmx-cs-svr-06", "status": "online"}]},
    })
    out = await pxmx._aggregate_pxmx_nodes(hub, ["pxmx-1", "cs-06"])
    assert sorted(n["node"] for n in out["nodes"]) == ["PXMX", "pxmx-cs-svr-06"]
    assert out["spoke_connected"] is True


@pytest.mark.asyncio
async def test_nodes_one_dead_spoke_does_not_drop_the_other():
    hub = _Hub({
        "pxmx-1": {"nodes": [{"node": "PXMX", "status": "online"}]},
        "cs-06":  {"nodes": [{"node": "pxmx-cs-svr-06", "status": "online"}]},
    }, fail=["cs-06"])
    out = await pxmx._aggregate_pxmx_nodes(hub, ["pxmx-1", "cs-06"])
    assert [n["node"] for n in out["nodes"]] == ["PXMX"]


@pytest.mark.asyncio
async def test_nodes_all_spokes_fail_raises_for_warm_fallback():
    hub = _Hub({"pxmx-1": {}, "cs-06": {}}, fail=["pxmx-1", "cs-06"])
    with pytest.raises(Exception):
        await pxmx._aggregate_pxmx_nodes(hub, ["pxmx-1", "cs-06"])


@pytest.mark.asyncio
async def test_nodes_dedupes_a_cluster_split_across_dedicated_spokes():
    """The reported bug: a real 4-node PVE cluster where each node is hosted
    by its OWN dedicated/cs spoke (split-topology), not one spoke with 4
    connected agents. Each spoke's single agent still self-reports the FULL
    cluster (pvesh get /cluster/resources is cluster-wide), so 4 spokes x 4
    nodes must collapse to 4 rows, not 16 — the same fan-out duplication
    already fixed one layer down (within one spoke's connected_agents), now
    fixed at the cross-SPOKE layer too."""
    cluster_nodes = [
        {"node": "pxmx-cs-svr-01", "status": "online"},
        {"node": "pxmx-cs-svr-02", "status": "online"},
        {"node": "pxmx-cs-svr-03", "status": "online"},
        {"node": "pxmx-cs-svr-04", "status": "online"},
    ]
    hub = _Hub({
        f"cs-svr-{i:02d}": {"nodes": [dict(n) for n in cluster_nodes],
                            "telemetry_ts": 100.0 + i}
        for i in range(1, 5)
    })
    spokes = [f"cs-svr-{i:02d}" for i in range(1, 5)]
    out = await pxmx._aggregate_pxmx_nodes(hub, spokes)
    assert sorted(n["node"] for n in out["nodes"]) == [
        "pxmx-cs-svr-01", "pxmx-cs-svr-02", "pxmx-cs-svr-03", "pxmx-cs-svr-04"]


@pytest.mark.asyncio
async def test_vms_dedupes_a_cluster_split_across_dedicated_spokes_by_unique_id():
    """Same split-topology duplication for the VM list — must dedup by
    unique_id, not a bare (node, vmid) tuple that collides distinct VMs
    missing both fields (regression: a first cut of this fix used (node,
    vmid) here and silently dropped a real VM in the mixed-hosting test)."""
    vms = [{"unique_id": "lab/pxmx-cs-svr-01/101", "node": "pxmx-cs-svr-01", "vmid": 101},
           {"unique_id": "lab/pxmx-cs-svr-02/102", "node": "pxmx-cs-svr-02", "vmid": 102}]
    hub = _Hub({
        f"cs-svr-{i:02d}": {"vms": [dict(v) for v in vms], "telemetry_ts": 100.0 + i}
        for i in range(1, 5)
    })
    spokes = [f"cs-svr-{i:02d}" for i in range(1, 5)]
    out = await pxmx._aggregate_pxmx_vms(hub, spokes, {})
    assert sorted(v["unique_id"] for v in out["vms"]) == [
        "lab/pxmx-cs-svr-01/101", "lab/pxmx-cs-svr-02/102"]
