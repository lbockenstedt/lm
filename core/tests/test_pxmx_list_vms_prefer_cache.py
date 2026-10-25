"""PXMX_LIST_VMS ``prefer_cache`` for pinned ``agent_id`` requests.

A pinned request normally runs the live multi-round-trip PVE query
(10-15s on the live fleet). The Dashboard's Overview counts give it 5s, so
every pinned count timed out on LM-HUB (about 200 timeouts a day). With
``prefer_cache`` the spoke answers from that agent's fresh AGENT_TELEMETRY
snapshot instead and falls back to the live query when there isn't one.

These lock in:
* fresh telemetry answers without any RUN_COMMAND round-trip;
* the reply has the same decoration and tag filtering as the live path;
* stale, missing, or zero telemetry falls back to the live query;
* an unknown/unreachable agent still surfaces the live path's ERROR;
* WITHOUT ``prefer_cache`` nothing changes (delete-verify, VM sync and VMID
  allocation need live truth and never send it);
* a fresh snapshot with no VMs is a real 0, not a reason to go live.
"""
import asyncio
import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import pxmx_node_vm_aggregation as agg  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeCP:
    def __init__(self, connected_agents=None, agent_error=None):
        self.connected_agents = connected_agents or {}
        self.disk_cache = {}
        self.calls = []
        self._agent_error = agent_error

    async def send_to_agent(self, cmd, data, agent_id=None, timeout=None):
        self.calls.append((cmd, data, agent_id))
        if self._agent_error:
            return {"status": "ERROR", "message": self._agent_error}
        return {"ok": True, "rc": 0, "stdout": "[]"}


def _agent(ts, vms, cluster="clusterA"):
    return {"cluster_name": cluster, "telemetry_ts": ts, "vms": vms}


_VMS = [{"vmid": 101, "node": "pve1", "status": "running", "tags": ["lrb"]},
        {"vmid": 102, "node": "pve1", "status": "stopped", "tags": []}]


def test_fresh_telemetry_answers_without_live_query():
    cp = _FakeCP({"a1": _agent(time.time() - 30, _VMS)})
    r = _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True}))
    assert r["status"] == "SUCCESS"
    assert r["source"] == "telemetry_cache"
    assert r["agent_count"] == 1
    assert cp.calls == []  # no RUN_COMMAND round-trip at all
    assert [v["vmid"] for v in r["vms"]] == [101, 102]
    # Same decoration as the live pinned path.
    assert all(v["agent_id"] == "a1" for v in r["vms"])
    assert r["vms"][0]["cluster"] == "clusterA"
    assert r["vms"][0]["unique_id"] == "clusterA/pve1/101"


def test_cached_reply_does_not_mutate_telemetry():
    vms = [dict(v) for v in _VMS]
    cp = _FakeCP({"a1": _agent(time.time(), vms)})
    _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True}))
    assert "agent_id" not in cp.connected_agents["a1"]["vms"][0]


def test_tag_filter_applies_to_cached_reply():
    cp = _FakeCP({"a1": _agent(time.time(), _VMS)})
    r = _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True,
                               "tag_filter": "LRB"}))
    assert [v["vmid"] for v in r["vms"]] == [101]


def test_stale_telemetry_falls_back_to_live():
    old = time.time() - agg.PREFER_CACHE_MAX_AGE_S - 5
    cp = _FakeCP({"a1": _agent(old, _VMS)})
    r = _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True}))
    assert r["source"] == "pinned_agent"
    assert cp.calls  # live RUN_COMMAND path ran


def test_no_telemetry_yet_falls_back_to_live():
    cp = _FakeCP({"a1": {"cluster_name": "clusterA", "vms": []}})  # no telemetry_ts
    r = _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True}))
    assert r["source"] == "pinned_agent"
    assert cp.calls


def test_unknown_agent_still_surfaces_live_error():
    cp = _FakeCP({}, agent_error="Agent 'ghost' not connected")
    r = _run(agg.list_vms(cp, {"agent_id": "ghost", "prefer_cache": True}))
    assert r["status"] == "ERROR"
    assert "ghost" in r["message"]


def test_without_prefer_cache_pinned_stays_live():
    cp = _FakeCP({"a1": _agent(time.time(), _VMS)})
    r = _run(agg.list_vms(cp, {"agent_id": "a1"}))
    assert r["source"] == "pinned_agent"
    assert cp.calls  # default behavior unchanged: live query


def test_fresh_empty_snapshot_is_a_real_zero():
    cp = _FakeCP({"a1": _agent(time.time(), [])})
    r = _run(agg.list_vms(cp, {"agent_id": "a1", "prefer_cache": True}))
    assert r["status"] == "SUCCESS"
    assert r["vms"] == []
    assert r["source"] == "telemetry_cache"
    assert cp.calls == []


def test_prefer_cache_without_agent_id_is_ignored():
    cp = _FakeCP({"a1": _agent(time.time(), _VMS)})
    r = _run(agg.list_vms(cp, {"prefer_cache": True}))
    # Aggregate path, unchanged: already telemetry-first.
    assert r["source"] == "telemetry_cache"
    assert r["agent_count"] == 1
    assert cp.calls == []
