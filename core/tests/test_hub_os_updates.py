"""HubOsUpdatesMixin — fleet inventory + snapshot merge behaviour.

Pins the fix for a real user-reported bug: the OS Updates panel showed "no
nodes reporting" even though spokes/agents were connected and reporting in
over the control plane. Root cause: ``osu_snapshot()`` only ever returned
whatever ``osu_check_fleet()`` had cached in ``self._os_update_state`` — an
in-memory, never-persisted dict that starts empty on every hub boot/restart
and stays empty until an operator explicitly clicks "Check for updates". A
node that's connected but never probed was silently ABSENT from the list
rather than shown with a "not checked yet" status.

``osu_snapshot()`` now merges the live target list (``_osu_targets()`` —
active_connections + agent_info + hub) with whatever's cached: a live node
with no cached check result gets a synthetic ``checked: False`` /
``reason: "not checked yet"`` entry instead of vanishing.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_os_updates import HubOsUpdatesMixin  # noqa: E402


class _FakeState:
    def __init__(self, module_metadata=None):
        self.system_state = {"module_metadata": module_metadata or {}}

    def _mark_dirty(self):
        pass


class _FakeHub(HubOsUpdatesMixin):
    """Minimal hub: active_connections + agent_info + module_metadata, plus a
    canned request_response so _osu_check_one can probe without real I/O."""

    def __init__(self, connections=None, agent_info=None, module_metadata=None,
                responses=None):
        self.state = _FakeState(module_metadata)
        self.active_connections = connections or {}
        self.agent_info = agent_info or {}
        self._responses = responses or {}  # spoke_id/agent_id -> canned payload

    async def request_response(self, target, cmd, data, timeout=None):
        key = (data or {}).get("agent_id") or target
        payload = self._responses.get(key)
        if payload is None:
            raise RuntimeError("no canned response")
        return {"payload": {"data": payload}}


# ── _osu_targets ──────────────────────────────────────────────────────────

def test_targets_include_connected_spokes_agents_and_hub():
    hub = _FakeHub(
        connections={"spoke-1": object()},
        agent_info={"agent-1": {"spoke_id": "spoke-1", "hostname": "host-1"}},
        module_metadata={"spoke-1": {"display_name": "Spoke One", "module_type": "pxmx"}})
    targets = hub._osu_targets()
    keys = {(t["kind"], t["id"]) for t in targets}
    assert ("spoke", "spoke-1") in keys
    assert ("agent", "agent-1") in keys
    assert ("hub", "hub") in keys
    spoke_t = next(t for t in targets if t["kind"] == "spoke")
    assert spoke_t["label"] == "Spoke One"
    assert spoke_t["module_type"] == "pxmx"


def test_agent_without_owning_spoke_is_skipped():
    hub = _FakeHub(agent_info={"orphan-agent": {}})
    targets = hub._osu_targets()
    assert not any(t["kind"] == "agent" for t in targets)


# ── osu_snapshot merge behaviour (the bug fix) ──────────────────────────────

def test_connected_node_never_checked_appears_as_not_checked_yet():
    hub = _FakeHub(connections={"spoke-1": object()},
                   module_metadata={"spoke-1": {"display_name": "Spoke One"}})
    snap = hub.osu_snapshot()
    node = next(n for n in snap["nodes"] if n["kind"] == "spoke")
    assert node["checked"] is False
    assert node["reason"] == "not checked yet"
    assert node["count"] == 0
    assert snap["totals"]["not_checked"] >= 1


def test_hub_always_appears_even_before_any_check():
    hub = _FakeHub()
    snap = hub.osu_snapshot()
    assert any(n["kind"] == "hub" for n in snap["nodes"])
    hub_node = next(n for n in snap["nodes"] if n["kind"] == "hub")
    assert hub_node["checked"] is False


@pytest.mark.asyncio
async def test_after_check_fleet_node_shows_checked_true_with_real_data():
    hub = _FakeHub(
        connections={"spoke-1": object()},
        module_metadata={"spoke-1": {"display_name": "Spoke One"}},
        responses={"spoke-1": {"eligible": True, "count": 3, "security_count": 1}})
    await hub.osu_check_fleet(refresh=False)
    snap = hub.osu_snapshot()
    node = next(n for n in snap["nodes"] if n["kind"] == "spoke")
    assert node["checked"] is True
    assert node["count"] == 3
    assert node["eligible"] is True
    assert snap["totals"]["not_checked"] == 0 or all(
        n["kind"] != "spoke" for n in snap["nodes"] if not n.get("checked"))


@pytest.mark.asyncio
async def test_disconnected_node_drops_out_of_snapshot_after_recheck():
    """A node checked once, then disconnected before the next osu_snapshot()
    call, is no longer a live target -- it must not linger with stale data."""
    hub = _FakeHub(
        connections={"spoke-1": object()},
        module_metadata={"spoke-1": {"display_name": "Spoke One"}},
        responses={"spoke-1": {"eligible": True, "count": 2}})
    await hub.osu_check_fleet(refresh=False)
    assert any(n["kind"] == "spoke" for n in hub.osu_snapshot()["nodes"])
    del hub.active_connections["spoke-1"]
    snap = hub.osu_snapshot()
    assert not any(n["kind"] == "spoke" for n in snap["nodes"])


@pytest.mark.asyncio
async def test_mixed_fleet_some_checked_some_not():
    hub = _FakeHub(
        connections={"spoke-1": object(), "spoke-2": object()},
        module_metadata={"spoke-1": {"display_name": "Spoke One"},
                         "spoke-2": {"display_name": "Spoke Two"}},
        responses={"spoke-1": {"eligible": True, "count": 5}})
    # Only probe spoke-1 by pre-seeding state directly (simulate a check that
    # ran before spoke-2 connected).
    await hub.osu_check_fleet(refresh=False)
    # Reconnect a brand-new spoke-3 after the check ran.
    hub.active_connections["spoke-3"] = object()
    hub.state.system_state["module_metadata"]["spoke-3"] = {"display_name": "Spoke Three"}
    snap = hub.osu_snapshot()
    by_id = {n["id"]: n for n in snap["nodes"]}
    assert by_id["spoke-1"]["checked"] is True
    assert by_id["spoke-3"]["checked"] is False
    assert snap["totals"]["not_checked"] == 1


# ── auto-check schedule (WebUI-configurable) ────────────────────────────────

def test_autocheck_config_defaults_enabled_six_hours_when_unset():
    hub = _FakeHub()
    cfg = hub.osu_autocheck_config()
    assert cfg == {"enabled": True, "interval_hours": 6.0}


def test_seed_defaults_writes_config_once_and_never_overwrites():
    hub = _FakeHub()
    hub.seed_os_updates_check_defaults()
    stored = hub.state.system_state["global_config"]["os_updates_check"]
    assert stored == {"enabled": True, "interval_hours": 6.0}
    # An operator explicitly disabling it must survive a re-seed (e.g. hub
    # restart) — seeding is a ONE-TIME thing, never an overwrite.
    hub.osu_set_autocheck_config(False, 12)
    hub.seed_os_updates_check_defaults()
    assert hub.osu_autocheck_config() == {"enabled": False, "interval_hours": 12.0}


def test_set_autocheck_config_persists_and_reads_back():
    hub = _FakeHub()
    cfg = hub.osu_set_autocheck_config(True, 4)
    assert cfg == {"enabled": True, "interval_hours": 4.0}
    assert hub.osu_autocheck_config() == {"enabled": True, "interval_hours": 4.0}


def test_set_autocheck_config_clamps_bad_interval_to_minimum_one_hour():
    hub = _FakeHub()
    assert hub.osu_set_autocheck_config(True, 0)["interval_hours"] == 1.0
    assert hub.osu_set_autocheck_config(True, -5)["interval_hours"] == 1.0
    assert hub.osu_set_autocheck_config(True, "garbage")["interval_hours"] == 6.0


@pytest.mark.asyncio
async def test_autocheck_loop_runs_check_when_enabled(monkeypatch):
    hub = _FakeHub(connections={"spoke-1": object()},
                   module_metadata={"spoke-1": {"display_name": "Spoke One"}},
                   responses={"spoke-1": {"eligible": True, "count": 1}})
    hub.osu_set_autocheck_config(True, 1)  # 1h -> loop would sleep 3600s normally
    calls = []

    async def _fake_sleep(_secs):
        calls.append(_secs)
        if len(calls) >= 2:  # stagger sleep + one post-body sleep -> stop the loop
            raise asyncio.CancelledError()

    import hub_os_updates as hou
    monkeypatch.setattr(hou.asyncio, "sleep", _fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await hub.run_os_updates_check_loop()
    # The body ran once before the loop was cancelled on its 2nd sleep.
    assert hub._osu_state()["checked_at"] > 0


@pytest.mark.asyncio
async def test_autocheck_loop_skips_body_when_disabled(monkeypatch):
    hub = _FakeHub(connections={"spoke-1": object()},
                   module_metadata={"spoke-1": {"display_name": "Spoke One"}},
                   responses={"spoke-1": {"eligible": True, "count": 1}})
    hub.osu_set_autocheck_config(False, 6)
    calls = []

    async def _fake_sleep(_secs):
        calls.append(_secs)
        if len(calls) >= 2:
            raise asyncio.CancelledError()

    import hub_os_updates as hou
    monkeypatch.setattr(hou.asyncio, "sleep", _fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await hub.run_os_updates_check_loop()
    # Disabled -> body never ran -> checked_at stays at its initial 0.0.
    assert hub._osu_state()["checked_at"] == 0.0
    # Disabled cycles use the short 300s re-check delay, not interval_hours*3600.
    assert 300.0 in calls
