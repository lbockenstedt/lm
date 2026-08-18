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
