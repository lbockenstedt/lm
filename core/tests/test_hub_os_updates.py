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
import os_update  # noqa: E402


@pytest.fixture(autouse=True)
def _hub_host_not_eligible(monkeypatch):
    """The "hub" node checks THIS machine via os_update.check_updates. Pin it
    so results don't depend on the test host (a Linux CI runner has apt and
    isn't root, so it would count as an extra blocked node)."""
    monkeypatch.setattr(os_update, "check_updates",
                        lambda refresh=True: {"eligible": False, "reason": "test host"})


class _FakeState:
    def __init__(self, module_metadata=None):
        self.system_state = {"module_metadata": module_metadata or {}}

    def _mark_dirty(self):
        pass

    def get_spoke_tenant(self, module_id):
        return self.system_state["module_metadata"].get(module_id, {}).get("tenant_id")


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

def test_tenant_node_keys_are_their_spokes_and_agents_never_the_hub():
    hub = _FakeHub(
        connections={"s1": object(), "s2": object()},
        agent_info={"a1": {"spoke_id": "s1", "hostname": "pve1"},
                    "a2": {"spoke_id": "s2", "hostname": "pve2"}},
        module_metadata={"s1": {"display_name": "one", "tenant_id": "t1"},
                         "s2": {"display_name": "two", "tenant_id": "t2"}})
    assert hub.osu_tenant_node_keys({"t1"}) == {"spoke:s1", "agent:a1"}


def test_targets_skip_an_agent_on_a_spoke_host():
    hub = _FakeHub(
        connections={"spoke-1": object()},
        agent_info={"agent-1": {"spoke_id": "spoke-1", "hostname": "MIPBE-SVCS01.lab.local"},
                    "agent-2": {"spoke_id": "spoke-1", "hostname": "other"}},
        module_metadata={"spoke-1": {"display_name": "mipbe-svcs01", "module_type": "netbox"}})
    assert [t["id"] for t in hub._osu_targets()] == ["spoke-1", "agent-2", "hub"]


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


# ── selective apply / cancel / reboot / persistence ──────────────────────────

class _RecordingHub(_FakeHub):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sent = []

    async def request_response(self, target, cmd, data, timeout=None):
        self.sent.append((target, cmd, dict(data or {})))
        if cmd.endswith("CHECK"):
            return await super().request_response(target, cmd, data, timeout)
        return {"payload": {"data": {"status": "SUCCESS", "message": ""}}}


_PKGS = [{"package": "openssl", "security": True},
         {"package": "curl", "security": False}]


def _checked_hub(features=("packages", "reboot"), blocker=""):
    hub = _RecordingHub(
        connections={"spoke-1": object()},
        agent_info={"guid-123": {"spoke_id": "spoke-1", "agent_id": "pve-host-1",
                                 "hostname": "pve1"}},
        module_metadata={"spoke-1": {"display_name": "Spoke One"}},
        responses={k: {"eligible": True, "count": 2, "packages": _PKGS,
                       "features": list(features), "apply_blocker": blocker,
                       "reboot_required": True}
                   for k in ("spoke-1", "pve-host-1")})
    return hub


async def _drain():
    for _ in range(20):
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_guid_keyed_agent_is_relayed_by_its_raw_agent_id():
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    checks = [s for s in hub.sent if s[1] == "AGENT_OS_UPDATE_CHECK"]
    assert checks and checks[0][2]["agent_id"] == "pve-host-1"
    node = next(n for n in hub.osu_snapshot()["nodes"] if n["kind"] == "agent")
    assert node["id"] == "guid-123" and node["count"] == 2


@pytest.mark.asyncio
async def test_apply_selected_packages_uses_the_package_command():
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    r = await hub.osu_apply_fleet(packages={"agent:guid-123": ["openssl"]},
                                  node_keys=["spoke:spoke-1"])
    assert r == {"status": "SUCCESS", "queued": 2}
    await _drain()
    applies = [s for s in hub.sent if "APPLY" in s[1]]
    assert ("spoke-1", "OS_UPDATE_APPLY", {}) in applies
    assert ("spoke-1", "AGENT_OS_UPDATE_APPLY_PACKAGES",
            {"agent_id": "pve-host-1", "packages": ["openssl"]}) in applies
    assert hub._osu_state()["run"]["status"] == "finished"


@pytest.mark.asyncio
async def test_security_only_sends_only_security_packages():
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    await hub.osu_apply_fleet(node_keys=["spoke:spoke-1"], security_only=True)
    await _drain()
    assert ("spoke-1", "OS_UPDATE_APPLY_PACKAGES", {"packages": ["openssl"]}) in hub.sent


@pytest.mark.asyncio
async def test_bad_selections_are_refused_before_anything_runs():
    hub = _checked_hub(features=())
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    r = await hub.osu_apply_fleet(packages={"spoke:spoke-1": ["openssl"]})
    assert r["status"] == "ERROR" and "LM update" in r["message"]
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    r = await hub.osu_apply_fleet(packages={"spoke:spoke-1": ["not-pending"]})
    assert r["status"] == "ERROR" and "not pending" in r["message"]
    r = await hub.osu_apply_fleet(node_keys=["spoke:nope"])
    assert r["status"] == "ERROR"
    assert not hub.sent and hub._osu_state()["run"] is None


@pytest.mark.asyncio
async def test_blocked_nodes_are_excluded_from_apply_all():
    hub = _checked_hub(blocker="no helper")
    await hub.osu_check_fleet(refresh=False)
    r = await hub.osu_apply_fleet()
    assert r["status"] == "ERROR"
    assert hub.osu_snapshot()["totals"]["blocked"] == 2


@pytest.mark.asyncio
async def test_cancel_skips_queued_nodes():
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    await hub.osu_apply_fleet()
    assert hub.osu_cancel_run("me")["status"] == "SUCCESS"
    await _drain()
    run = hub._osu_state()["run"]
    assert run["status"] == "cancelled"
    assert all(i["status"] == "skipped" for i in run["items"])
    assert hub.osu_cancel_run("me")["status"] == "ERROR"


@pytest.mark.asyncio
async def test_reboot_is_explicit_feature_gated_and_relayed_by_name():
    hub = _checked_hub()
    await hub.osu_check_fleet(refresh=False)
    r = await hub.osu_reboot_node("agent:guid-123", actor="me")
    assert r["status"] == "SUCCESS"
    assert ("spoke-1", "AGENT_OS_REBOOT", {"agent_id": "pve-host-1"}) in hub.sent
    old = _checked_hub(features=())
    await old.osu_check_fleet(refresh=False)
    r = await old.osu_reboot_node("spoke:spoke-1")
    assert r["status"] == "ERROR" and "LM update" in r["message"]
    assert not any(s[1] == "OS_REBOOT" for s in old.sent)


@pytest.mark.asyncio
async def test_state_persists_and_an_inflight_run_loads_as_interrupted(tmp_path):
    hub = _checked_hub()
    hub.cache_dir = str(tmp_path)
    await hub.osu_check_fleet(refresh=False)
    st = hub._osu_state()
    st["run"] = {"status": "running", "done": 0, "total": 2, "current": "x",
                 "items": [{"key": "a", "status": "applying"},
                           {"key": "b", "status": "queued"}]}
    await hub._osu_file().flush_now()
    fresh = _checked_hub()
    fresh.cache_dir = str(tmp_path)
    fresh.osu_load_state()
    run = fresh._osu_state()["run"]
    assert run["status"] == "interrupted"
    assert [i["status"] for i in run["items"]] == ["interrupted", "skipped"]
    node = next(n for n in fresh.osu_snapshot()["nodes"] if n["kind"] == "spoke")
    assert node["checked"] is True and node["count"] == 2


# ── auto-patch ───────────────────────────────────────────────────────────────

def _hub_with(nodes):
    hub = _RecordingHub()
    hub._osu_state()["nodes"] = {}
    hub.osu_snapshot = lambda: {"nodes": nodes}
    hub.osu_set_autopatch_window({"start": "00:00", "end": "00:00"})  # any time
    applied = []

    async def _apply(node_keys=None, actor="", packages=None, security_only=False,
                     reboot_after=None, until=None):
        applied.append((node_keys, actor, security_only))
        hub.applied_packages = packages
        hub.reboot_after = reboot_after
        hub.until = until
        return {"status": "SUCCESS", "queued": len(node_keys)}
    hub.osu_apply_fleet = _apply
    return hub, applied


def _node(kind, nid, count=2, security=1, blocker="", features=("packages",), packages=()):
    return {"kind": kind, "id": nid, "label": nid, "eligible": True, "count": count,
            "security_count": security, "apply_blocker": blocker,
            "features": list(features),
            "packages": [{"package": name, "security": sec} for name, sec in packages]}


def test_new_nodes_are_enrolled_in_autopatch_and_reboot():
    hub = _FakeHub()
    hub._osu_enroll_new_nodes(["hub:hub", "spoke:s1"])  # first run: just remember the fleet
    assert hub.osu_autopatch_config()["nodes"] == []
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub.osu_set_autopatch_node("spoke:s1", False)  # operator opted out
    hub._osu_enroll_new_nodes(["hub:hub", "spoke:s1", "agent:a1"])
    cfg = hub.osu_autopatch_config()
    assert cfg["nodes"] == ["agent:a1"]
    assert cfg["reboot_nodes"] == ["agent:a1"]


def test_autopatch_has_no_nodes_by_default():
    assert _FakeHub().osu_autopatch_config() == {
        "security_only": True, "nodes": [], "exclude": [], "reboot_nodes": [],
        "window": {"start": "01:00", "end": "05:00", "tz": "UTC"}}


def test_autopatch_nodes_are_approved_one_at_a_time():
    hub = _FakeHub()
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub.osu_set_autopatch_node("agent:a1", True)
    hub.osu_set_autopatch_node("spoke:s1", False)
    hub.osu_set_autopatch_security_only(False)
    hub.osu_set_autopatch_exclude([" linux-image-* ", "", "docker-ce"])
    assert hub.osu_autopatch_config() == {"security_only": False, "nodes": ["agent:a1"],
                                          "exclude": ["docker-ce", "linux-image-*"],
                                          "reboot_nodes": ["agent:a1"],
                                          "window": {"start": "01:00", "end": "05:00", "tz": "UTC"}}


def test_autoreboot_is_on_by_default_and_per_node():
    hub = _FakeHub(connections={"spoke-1": object(), "spoke-2": object()})
    hub.osu_set_autopatch_node("spoke:spoke-1", True)
    hub.osu_set_autopatch_node("spoke:spoke-2", True)
    hub.osu_set_autoreboot_node("spoke:spoke-2", False)
    # Re-approving an already approved node keeps the operator's choice.
    hub.osu_set_autopatch_node("spoke:spoke-2", True)
    flags = {n["id"]: n["auto_reboot"] for n in hub.osu_snapshot()["nodes"]}
    assert flags == {"spoke-1": True, "spoke-2": False, "hub": False}
    hub.osu_set_autopatch_node("spoke:spoke-1", False)
    assert hub.osu_autopatch_config()["reboot_nodes"] == []
    with pytest.raises(ValueError):
        hub.osu_set_autoreboot_node("spoke:spoke-1", True)


@pytest.mark.asyncio
async def test_autopatch_asks_to_reboot_only_autoreboot_nodes():
    hub, applied = _hub_with([_node("spoke", "s1"), _node("spoke", "s2")])
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub.osu_set_autopatch_node("spoke:s2", True)
    hub.osu_set_autoreboot_node("spoke:s2", False)
    await hub.osu_autopatch()
    assert hub.reboot_after == ["spoke:s1"]


def _autoreboot_hub(applied):
    """Hub whose apply/reboot are recorded in order; ``applied`` maps a node
    id to how many packages its apply installs."""
    nodes = [_node("spoke", "s1", features=("reboot",)), _node("spoke", "s2", features=("reboot",)),
             _node("hub", "hub", features=("reboot",))]
    hub = _RecordingHub()
    hub.osu_snapshot = lambda: {"nodes": nodes}
    events = []

    async def _apply_one(n):
        events.append(("apply", n["id"]))
        return {"status": "SUCCESS", "applied": applied[n["id"]], "reboot_required": False}

    async def _reboot(n, actor):
        events.append(("reboot", n["id"], actor))
        return {"status": "SUCCESS"}

    async def _no_check(refresh=False):
        return None
    hub._osu_apply_one, hub._osu_reboot, hub.osu_check_fleet = _apply_one, _reboot, _no_check
    return hub, events


@pytest.mark.asyncio
async def test_autoreboot_reboots_spokes_before_patching_the_hub_and_the_hub_last():
    hub, events = _autoreboot_hub({"s1": 3, "s2": 0, "hub": 1})
    await hub.osu_apply_fleet(node_keys=["hub:hub", "spoke:s1", "spoke:s2"], actor="auto-patch",
                              reboot_after=["spoke:s1", "spoke:s2", "hub:hub"])
    await _drain()
    # s2 installed nothing, so it is not rebooted.
    assert events == [("apply", "s1"), ("apply", "s2"), ("reboot", "s1", "auto-reboot"),
                      ("apply", "hub"), ("reboot", "hub", "auto-reboot")]
    items = {i["key"]: i.get("auto_reboot") for i in hub._osu_state()["run"]["items"]}
    assert items == {"spoke:s1": "scheduled", "spoke:s2": None, "hub:hub": "scheduled"}


@pytest.mark.asyncio
async def test_no_reboot_without_reboot_after_or_when_cancelled():
    hub, events = _autoreboot_hub({"s1": 3, "s2": 3, "hub": 1})
    await hub.osu_apply_fleet(node_keys=["spoke:s1"])
    await _drain()
    assert events == [("apply", "s1")]
    hub, events = _autoreboot_hub({"s1": 3, "s2": 3, "hub": 1})
    await hub.osu_apply_fleet(node_keys=["spoke:s1", "spoke:s2"], reboot_after=["spoke:s1"])
    hub.osu_cancel_run("me")
    await _drain()
    assert not any(e[0] == "reboot" for e in events)


def test_snapshot_flags_approved_nodes():
    hub = _FakeHub(connections={"spoke-1": object(), "spoke-2": object()})
    hub.osu_set_autopatch_node("spoke:spoke-1", True)
    flags = {n["id"]: n["auto_patch"] for n in hub.osu_snapshot()["nodes"]}
    assert flags == {"spoke-1": True, "spoke-2": False, "hub": False}


@pytest.mark.asyncio
async def test_autopatch_with_no_approved_nodes_does_nothing():
    hub, applied = _hub_with([_node("spoke", "s1")])
    assert (await hub.osu_autopatch())["status"] == "SKIPPED"
    assert not applied


@pytest.mark.asyncio
async def test_autopatch_only_patches_approved_nodes():
    hub, applied = _hub_with([
        _node("spoke", "s1"),
        _node("spoke", "not-approved"),
        _node("spoke", "s2", security=0),
        _node("agent", "a1", blocker="no helper"),
        _node("agent", "old", features=()),
        _node("hub", "hub"),
    ])
    for k in ("spoke:s1", "spoke:s2", "agent:a1", "agent:old", "hub:hub"):
        hub.osu_set_autopatch_node(k, True)
    await hub.osu_autopatch()
    assert applied == [(["spoke:s1", "hub:hub"], "auto-patch", True)]


@pytest.mark.asyncio
async def test_autopatch_all_updates():
    hub, applied = _hub_with([_node("spoke", "s2", security=0)])
    hub.osu_set_autopatch_node("spoke:s2", True)
    hub.osu_set_autopatch_security_only(False)
    await hub.osu_autopatch()
    assert applied == [(["spoke:s2"], "auto-patch", False)]


@pytest.mark.asyncio
async def test_autopatch_never_installs_excluded_packages():
    pending = [("linux-image-amd64", True), ("openssl", True), ("docker-ce", False), ("vim", False)]
    hub, applied = _hub_with([
        _node("spoke", "s1", count=4, security=2, packages=pending),
        _node("spoke", "only-kernel", count=1, packages=[("linux-image-amd64", True)]),
        _node("agent", "old", features=(), packages=pending),
    ])
    for k in ("spoke:s1", "spoke:only-kernel", "agent:old"):
        hub.osu_set_autopatch_node(k, True)
    hub.osu_set_autopatch_security_only(False)
    hub.osu_set_autopatch_exclude(["linux-image-*", "docker-ce"])
    await hub.osu_autopatch()
    assert applied == [(["spoke:s1"], "auto-patch", False)]
    assert hub.applied_packages == {"spoke:s1": ["openssl", "vim"]}


@pytest.mark.asyncio
async def test_autopatch_exclude_with_security_only():
    pending = [("linux-image-amd64", True), ("openssl", True), ("vim", False)]
    hub, applied = _hub_with([_node("spoke", "s1", count=3, security=2, packages=pending)])
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub.osu_set_autopatch_exclude(["linux-image-*"])
    await hub.osu_autopatch()
    assert hub.applied_packages == {"spoke:s1": ["openssl"]}


@pytest.mark.asyncio
async def test_autopatch_waits_for_a_running_run():
    hub, applied = _hub_with([_node("spoke", "s1")])
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub._osu_state()["run"] = {"status": "running"}
    assert (await hub.osu_autopatch())["status"] == "SKIPPED"
    assert not applied


@pytest.mark.asyncio
async def test_scheduled_check_only_checks(monkeypatch):
    hub = _FakeHub()
    ran = []

    async def _check(refresh=True):
        ran.append("check")

    async def _autopatch():
        ran.append("autopatch")
    hub.osu_check_fleet = _check
    hub.osu_autopatch = _autopatch
    calls = []

    async def _fake_sleep(_secs):
        calls.append(_secs)
        if len(calls) >= 2:
            raise asyncio.CancelledError()

    import hub_os_updates as hou
    monkeypatch.setattr(hou.asyncio, "sleep", _fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await hub.run_os_updates_check_loop()
    assert ran == ["check"]


@pytest.mark.asyncio
async def test_autopatch_tick_checks_then_patches_only_when_due(monkeypatch):
    hub, applied = _hub_with([_node("spoke", "s1")])
    ran = []

    async def _check(refresh=True):
        ran.append("check")
    hub.osu_check_fleet = _check
    ticks = []

    async def _fake_sleep(_secs):
        ticks.append(_secs)
        if len(ticks) >= 3:
            raise asyncio.CancelledError()

    import hub_os_updates as hou
    monkeypatch.setattr(hou.asyncio, "sleep", _fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await hub.run_os_updates_autopatch_loop()
    assert ran == [] and not applied  # nothing approved yet
    hub.osu_set_autopatch_node("spoke:s1", True)
    ticks.clear()
    with pytest.raises(asyncio.CancelledError):
        await hub.run_os_updates_autopatch_loop()
    # Two ticks inside the same window: one check + one run.
    assert ran == ["check"] and len(applied) == 1


# ── fix access ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fix_access_relays_login_to_a_blocked_agent():
    hub = _checked_hub(features=("packages", "reboot", "fix_access"), blocker="no helper")
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    r = await hub.osu_fix_access("agent:guid-123", "root", "pw", actor="admin")
    assert r["status"] == "SUCCESS"
    assert ("spoke-1", "AGENT_OS_FIX_ACCESS",
            {"agent_id": "pve-host-1", "username": "root", "password": "pw"}) in hub.sent


@pytest.mark.asyncio
async def test_fix_access_refuses_unblocked_or_old_nodes():
    hub = _checked_hub(features=("packages", "reboot", "fix_access"))
    await hub.osu_check_fleet(refresh=False)
    assert (await hub.osu_fix_access("spoke:spoke-1", "root", "pw"))["status"] == "ERROR"
    hub = _checked_hub(blocker="no helper")
    await hub.osu_check_fleet(refresh=False)
    r = await hub.osu_fix_access("spoke:spoke-1", "root", "pw")
    assert r["status"] == "ERROR" and "LM update" in r["message"]


@pytest.mark.asyncio
async def test_autopatch_runs_at_most_once_per_window():
    hub, applied = _hub_with([_node("spoke", "s1")])
    hub.osu_set_autopatch_node("spoke:s1", True)
    await hub.osu_autopatch()
    # A hub restart re-runs the loop body straight away — no second run.
    assert (await hub.osu_autopatch())["status"] == "SKIPPED"
    assert len(applied) == 1


def _ts(text, tz="UTC"):
    from datetime import datetime
    from zoneinfo import ZoneInfo
    return datetime.strptime(text, "%Y-%m-%d %H:%M").replace(tzinfo=ZoneInfo(tz)).timestamp()


@pytest.mark.parametrize("start,end,tz,now,expected", [
    ("01:00", "05:00", "UTC", "2026-11-02 03:00", ("2026-11-02 01:00", "2026-11-02 05:00")),
    ("01:00", "05:00", "UTC", "2026-11-02 05:00", None),
    ("01:00", "05:00", "UTC", "2026-11-02 00:59", None),
    # across midnight, both sides of it
    ("22:00", "04:00", "UTC", "2026-11-02 23:30", ("2026-11-02 22:00", "2026-11-03 04:00")),
    ("22:00", "04:00", "UTC", "2026-11-03 01:00", ("2026-11-02 22:00", "2026-11-03 04:00")),
    ("22:00", "04:00", "UTC", "2026-11-03 12:00", None),
    # start == end: any time
    ("02:00", "02:00", "UTC", "2026-11-03 01:59", ("2026-11-02 02:00", "2026-11-03 02:00")),
])
def test_window_bounds(start, end, tz, now, expected):
    import hub_os_updates as hou
    got = hou.window_bounds({"start": start, "end": end, "tz": tz}, _ts(now))
    assert got == (None if expected is None else tuple(_ts(t) for t in expected))


def test_window_is_in_the_configured_timezone():
    import hub_os_updates as hou
    w = {"start": "01:00", "end": "05:00", "tz": "America/Chicago"}
    assert hou.window_bounds(w, _ts("2026-11-02 03:00", "America/Chicago"))
    assert hou.window_bounds(w, _ts("2026-11-02 03:00")) is None  # 21:00 in Chicago


def test_bad_window_is_refused():
    hub = _FakeHub()
    for bad in ({"start": "25:00"}, {"end": "x"}, {"tz": "Mars/Base"}):
        with pytest.raises(ValueError):
            hub.osu_set_autopatch_window(bad)


@pytest.mark.asyncio
async def test_autopatch_waits_for_the_window(monkeypatch):
    import hub_os_updates as hou
    hub, applied = _hub_with([_node("spoke", "s1")])
    hub.osu_set_autopatch_node("spoke:s1", True)
    hub.osu_set_autopatch_window({"start": "01:00", "end": "05:00", "tz": "UTC"})
    monkeypatch.setattr(hou.time, "time", lambda: _ts("2026-11-02 12:00"))
    r = await hub.osu_autopatch()
    assert r["status"] == "SKIPPED" and "maintenance window" in r["message"]
    monkeypatch.setattr(hou.time, "time", lambda: _ts("2026-11-02 01:05"))
    await hub.osu_autopatch()
    assert len(applied) == 1 and hub.until == _ts("2026-11-02 05:00")


@pytest.mark.asyncio
async def test_run_starts_no_node_after_the_window_closes():
    hub, events = _autoreboot_hub({"s1": 1, "s2": 1, "hub": 1})
    await hub.osu_apply_fleet(node_keys=["spoke:s1", "spoke:s2"], until=1.0)
    await _drain()
    assert events == []
    assert {i["message"] for i in hub._osu_state()["run"]["items"]} == {"maintenance window ended"}


# ── auto-reboot of a clustered Proxmox node ─────────────────────────────────

def _cluster_hub(monkeypatch, guests_polls, back_after=1, reboot_required=True):
    """Two clustered pxmx agents. ``guests_polls`` is what successive
    maintenance status calls report as HA guests still on the node; the node
    answers a check without a pending reboot after ``back_after`` polls."""
    import hub_os_updates as hou
    for name in ("_MAINT_POLL_S", "_REBOOT_GRACE_S"):
        monkeypatch.setattr(hou, name, 0)
    feats = ("reboot", "maintenance")
    nodes = [{**_node("agent", a, features=feats), "spoke_id": "sp", "agent_id": a,
              "pve_cluster": {"name": "lab", "node": a, "nodes": 2}} for a in ("pve1", "pve2")]
    hub, events = _autoreboot_hub({"pve1": 1, "pve2": 1})
    hub.osu_snapshot = lambda: {"nodes": nodes}
    apply_one = hub._osu_apply_one

    async def _apply(n):
        d = await apply_one(n)
        return {**d, "reboot_required": reboot_required}
    hub._osu_apply_one = _apply
    polls = list(guests_polls)

    async def _maint(n, action):
        events.append(("maint", n["id"], action))
        guests = polls.pop(0) if action != "disable" and polls else []
        return {"status": "SUCCESS", "ha_guests": guests}
    hub._osu_maintenance = _maint
    checks = {"n": 0}

    async def _check(t, refresh):
        checks["n"] += 1
        return {"eligible": True, "reboot_required": checks["n"] < back_after}
    hub._osu_check_one = _check
    hub._osu_targets = lambda: [{"kind": "agent", "id": a} for a in ("pve1", "pve2")]
    return hub, events


@pytest.mark.asyncio
async def test_cluster_node_reboots_in_maintenance_mode_one_at_a_time(monkeypatch):
    hub, events = _cluster_hub(monkeypatch, [["vm:100"], ["vm:100"], [], [], []], back_after=2)
    await hub.osu_apply_fleet(node_keys=["agent:pve1", "agent:pve2"],
                              reboot_after=["agent:pve1", "agent:pve2"])
    for _ in range(10):
        await _drain()
    # pve1 is fully back and out of maintenance before pve2 is even patched.
    assert events == [
        ("apply", "pve1"), ("maint", "pve1", "enable"), ("maint", "pve1", "status"),
        ("maint", "pve1", "status"), ("reboot", "pve1", "auto-reboot"), ("maint", "pve1", "disable"),
        ("apply", "pve2"), ("maint", "pve2", "enable"), ("reboot", "pve2", "auto-reboot"),
        ("maint", "pve2", "disable")]
    assert {i["auto_reboot"] for i in hub._osu_state()["run"]["items"]} == \
        {"rebooted (cluster maintenance mode)"}


@pytest.mark.asyncio
async def test_cluster_node_without_pending_reboot_is_left_alone(monkeypatch):
    hub, events = _cluster_hub(monkeypatch, [], reboot_required=False)
    await hub.osu_apply_fleet(node_keys=["agent:pve1"], reboot_after=["agent:pve1"])
    await _drain()
    assert events == [("apply", "pve1")]
    assert hub._osu_state()["run"]["items"][0]["auto_reboot"] == "not needed"


@pytest.mark.asyncio
async def test_cluster_node_that_does_not_return_stops_the_run(monkeypatch):
    import hub_os_updates as hou
    monkeypatch.setattr(hou, "_REBOOT_RETURN_TIMEOUT_S", -1)
    hub, events = _cluster_hub(monkeypatch, [[]], back_after=99)
    await hub.osu_apply_fleet(node_keys=["agent:pve1", "agent:pve2"],
                              reboot_after=["agent:pve1", "agent:pve2"])
    for _ in range(5):
        await _drain()
    assert ("maint", "pve1", "disable") not in events  # left in maintenance
    assert not any(e[:2] == ("apply", "pve2") for e in events)
    items = hub._osu_state()["run"]["items"]
    assert items[0]["auto_reboot"].startswith("failed: did not come back")
    assert items[1]["status"] == "skipped"


@pytest.mark.asyncio
async def test_manual_deploy_to_a_cluster_node_uses_maintenance_mode(monkeypatch):
    hub, events = _cluster_hub(monkeypatch, [[]])
    await hub.osu_apply_fleet(node_keys=["agent:pve1"], actor="alice")  # no reboot_after
    for _ in range(5):
        await _drain()
    assert events == [("apply", "pve1"), ("maint", "pve1", "enable"),
                      ("reboot", "pve1", "alice"), ("maint", "pve1", "disable")]


@pytest.mark.asyncio
async def test_reboot_button_on_a_cluster_node_uses_maintenance_mode(monkeypatch):
    hub, events = _cluster_hub(monkeypatch, [["vm:100"], []])
    hub._osu_state()["run"] = None
    res = await hub.osu_reboot_node("agent:pve1", actor="alice")
    assert res["status"] == "SUCCESS"
    for _ in range(5):
        await _drain()
    assert events == [("maint", "pve1", "enable"), ("maint", "pve1", "status"),
                      ("reboot", "pve1", "alice"), ("maint", "pve1", "disable")]
    run = hub._osu_state()["run"]
    assert run["status"] == "finished"
    assert run["items"][0]["auto_reboot"] == "rebooted (cluster maintenance mode)"


# ── footer "Pending Reboot" alert ────────────────────────────────────────────

def test_pending_reboots_lists_autoreboot_nodes_due_in_this_window(monkeypatch):
    import hub_os_updates as hou
    pve = {**_node("agent", "pve1", features=("packages", "maintenance")),
           "pve_cluster": {"name": "lab"}}
    hub, _ = _hub_with([_node("spoke", "s1"), _node("spoke", "keep-up"),
                        _node("spoke", "no-updates", count=0), pve])
    for k in ("spoke:s1", "spoke:keep-up", "spoke:no-updates", "agent:pve1"):
        hub.osu_set_autopatch_node(k, True)
    hub.osu_set_autoreboot_node("spoke:keep-up", False)
    hub.osu_set_autopatch_window({"start": "01:00", "end": "05:00", "tz": "UTC"})
    monkeypatch.setattr(hou.time, "time", lambda: _ts("2026-11-02 12:00"))
    assert hub.osu_pending_reboots()["in_window"] is False
    assert hub.osu_pending_reboots()["nodes"] == []
    monkeypatch.setattr(hou.time, "time", lambda: _ts("2026-11-02 01:01"))
    got = hub.osu_pending_reboots()
    assert got["in_window"] is True
    assert [(n["key"], n["note"].startswith("may")) for n in got["nodes"]] == \
        [("spoke:s1", False), ("agent:pve1", True)]
    # Once the window's run is over nothing is pending any more.
    hub._osu_state()["autopatch_at"] = _ts("2026-11-02 01:00")
    assert hub.osu_pending_reboots()["nodes"] == []


def test_pending_reboots_follows_the_running_run():
    hub, _ = _hub_with([_node("spoke", "s1"), _node("spoke", "s2")])
    hub._osu_state()["run"] = {"status": "running", "reboot_after": ["spoke:s1", "spoke:s2"],
                               "items": [{"key": "spoke:s1", "status": "done",
                                          "auto_reboot": "scheduled"},
                                         {"key": "spoke:s2", "status": "queued"}]}
    got = hub.osu_pending_reboots()
    assert got["in_window"] and [n["key"] for n in got["nodes"]] == ["spoke:s2"]


# ── pre-patch VM snapshots ────────────────────────────────────────────────────

class _VmHub(_RecordingHub):
    """A spoke that runs in Proxmox VM 101 on pve1; its agent is the PVE host."""
    fail_snapshot = False

    def warm_get(self, ns, key):
        return {"vms": [{"unique_id": "C/pve1/101", "name": "spoke1", "vmid": 101,
                         "node": "pve1", "type": "qemu", "ips": []}]}

    def get_hypervisor_spoke(self):
        return "spoke-1"

    async def request_response(self, target, cmd, data, timeout=None):
        if cmd == "PXMX_VM_ACTION" and data["action"] == "snapshot" and self.fail_snapshot:
            self.sent.append((target, cmd, dict(data)))
            return {"payload": {"data": {"status": "ERROR", "message": "storage full"}}}
        return await super().request_response(target, cmd, data, timeout)


def _vm_hub():
    hub = _checked_hub()
    vm_hub = _VmHub(connections=hub.active_connections, agent_info=hub.agent_info,
                    module_metadata={"spoke-1": {"display_name": "Spoke One", "hostname": "spoke1",
                                                 "module_type": "hypervisor"}},
                    responses=hub._responses)
    return vm_hub


@pytest.mark.asyncio
async def test_nodes_are_linked_to_their_vm_and_pve_hosts_are_bare_metal():
    hub = _vm_hub()
    nodes = {n["kind"]: n for n in hub.osu_snapshot()["nodes"]}
    assert nodes["spoke"]["vm"]["vmid"] == 101
    assert nodes["agent"]["vm"] is None and "bare metal" in nodes["agent"]["vm_note"]


@pytest.mark.asyncio
async def test_vm_is_snapshotted_right_before_it_is_patched():
    hub = _vm_hub()
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    await hub.osu_apply_fleet(node_keys=["spoke:spoke-1"])
    await _drain()
    cmds = [(s[1], s[2].get("action")) for s in hub.sent]
    assert cmds.index(("PXMX_VM_ACTION", "snapshot")) < cmds.index(("OS_UPDATE_APPLY", None))
    item = hub._osu_state()["run"]["items"][0]
    assert item["status"] == "done" and item["snapshot"].startswith("lm-prepatch-")


@pytest.mark.asyncio
async def test_a_failed_snapshot_means_the_node_is_not_patched():
    hub = _vm_hub()
    hub.fail_snapshot = True
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    await hub.osu_apply_fleet(node_keys=["spoke:spoke-1"])
    await _drain()
    assert not [s for s in hub.sent if s[1] == "OS_UPDATE_APPLY"]
    item = hub._osu_state()["run"]["items"][0]
    assert item["status"] == "failed" and "storage full" in item["message"]


@pytest.mark.asyncio
async def test_no_snapshot_when_turned_off():
    hub = _vm_hub()
    hub.osu_set_snapshot_config(False, 2)
    await hub.osu_check_fleet(refresh=False)
    hub.sent.clear()
    await hub.osu_apply_fleet(node_keys=["spoke:spoke-1"])
    await _drain()
    assert not [s for s in hub.sent if s[1] == "PXMX_VM_ACTION"]
    assert ("spoke-1", "OS_UPDATE_APPLY", {}) in hub.sent
