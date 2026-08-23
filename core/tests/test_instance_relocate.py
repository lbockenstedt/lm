"""Coordinator-role instance pool failover (PR2) — instance_relocate.py.

Mirrors test_spoke_alert.py's harness shape: instantiate the bare mixin
directly (no full LabManagerHub) and attach the minimal fake surface its
methods actually touch (state, active_connections, spoke_module_types,
_primary_key, request_response, push_config_to_spoke).
"""
import pytest

from instance_relocate import InstanceRelocateMixin, _INSTANCE_ROLE
from _fakes import FakeState


def _hub(instances_by_key=None, active=None, module_types=None):
    m = InstanceRelocateMixin()
    gc = {"global_config": {}}
    for key, insts in (instances_by_key or {}).items():
        gc["global_config"][key] = insts
    m.state = FakeState(system_state=gc)
    m.active_connections = dict(active or {})
    m.spoke_module_types = dict(module_types or {})
    m._primary_key = lambda sid: sid
    m.load_role_calls = []
    m.unload_role_calls = []
    m.push_calls = []
    m.push_should_fail = False

    async def _request_response(spoke_id, cmd, payload, timeout=None):
        if cmd == "LOAD_ROLE":
            m.load_role_calls.append((spoke_id, payload))
            role = payload["role"]
            sub_id = f"{spoke_id}-{role}"
            module_type = {r: mt for r, mt in _INSTANCE_ROLE.values()}[role]
            m.active_connections[sub_id] = object()
            m.spoke_module_types[sub_id] = module_type
            return {"payload": {"data": {
                "status": "SUCCESS", "sub_spoke_id": sub_id, "module_type": module_type}}}
        if cmd == "UNLOAD_ROLE":
            m.unload_role_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")
    m.request_response = _request_response

    async def _push_config_to_spoke(spoke_id):
        if m.push_should_fail:
            raise RuntimeError("push failed")
        m.push_calls.append(spoke_id)
    m.push_config_to_spoke = _push_config_to_spoke

    return m


def _connect(hub, sid, module_type):
    hub.active_connections[sid] = object()
    hub.spoke_module_types[sid] = module_type


def test_instance_role_maps_the_three_products():
    assert _INSTANCE_ROLE == {
        "nac_instances": ("cppm", "nac"),
        "ipam_instances": ("netbox", "ipam"),
        "ldap_instances": ("ldap", "directory"),
    }


@pytest.mark.asyncio
async def test_healthy_instance_with_active_spoke_is_untouched():
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    _connect(hub, "spokeA-cppm", "nac")
    await hub._instance_relocate_cycle()
    assert hub.load_role_calls == []
    assert hub.unload_role_calls == []
    assert hub.state.system_state["global_config"]["nac_instances"][0]["spoke_id"] == "spokeA-cppm"


@pytest.mark.asyncio
async def test_instance_with_no_pool_is_ignored_even_if_down():
    """Plain PR1 behavior (no spoke_pool) must be completely unaffected."""
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm"}]})  # spokeA-cppm never connected
    await hub._instance_relocate_cycle()
    assert hub.load_role_calls == []
    assert hub.unload_role_calls == []


@pytest.mark.asyncio
async def test_down_instance_relocates_to_next_pool_candidate():
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    # spokeA-cppm is gone (base agent also down); spokeB is up and bare.
    _connect(hub, "spokeB", "agent")
    await hub._instance_relocate_cycle()
    assert hub.load_role_calls == [("spokeB", {"role": "cppm", "config": {}})]
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeB-cppm"
    assert hub.push_calls == ["spokeB-cppm"]


@pytest.mark.asyncio
async def test_self_heals_in_place_when_only_the_role_subconnection_died():
    """spokeA's base-agent connection is still alive; only its cppm role
    sub-connection died. Relocation should reload cppm on the SAME box
    rather than moving away, since spokeA is tried first in pool order."""
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    _connect(hub, "spokeA", "agent")  # base agent alive; spokeA-cppm is NOT in active_connections
    _connect(hub, "spokeB", "agent")
    await hub._instance_relocate_cycle()
    assert hub.load_role_calls == [("spokeA", {"role": "cppm", "config": {}})]
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeA-cppm"  # same box, reloaded — not moved to spokeB


@pytest.mark.asyncio
async def test_relocation_unloads_the_old_spoke_when_orphaned():
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    _connect(hub, "spokeA", "agent")  # old base agent is reachable for the UNLOAD_ROLE attempt
    _connect(hub, "spokeB", "agent")
    # Force selection of spokeB by making spokeA's LOAD_ROLE (self-heal) fail.
    orig = hub.request_response

    async def _flaky(spoke_id, cmd, payload, timeout=None):
        if spoke_id == "spokeA" and cmd == "LOAD_ROLE":
            raise RuntimeError("agent unreachable mid-request")
        return await orig(spoke_id, cmd, payload, timeout)
    hub.request_response = _flaky

    await hub._instance_relocate_cycle()
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeB-cppm"
    assert hub.unload_role_calls == [("spokeA", {"role": "cppm"})]


@pytest.mark.asyncio
async def test_relocation_skips_unload_when_another_instance_still_uses_old_spoke():
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM-1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeB"]},
        {"id": "i2", "name": "CPPM-2", "spoke_id": "spokeA-cppm"},  # no pool — still bound directly
    ]})
    _connect(hub, "spokeB", "agent")
    await hub._instance_relocate_cycle()
    assert hub.unload_role_calls == []  # i2 still references spokeA-cppm


@pytest.mark.asyncio
async def test_all_pool_candidates_unavailable_leaves_the_record_unchanged():
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "i1", "name": "CPPM", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    # Neither spokeA nor spokeB is connected at all.
    await hub._instance_relocate_cycle()
    assert hub.load_role_calls == []
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeA-cppm"  # unchanged — nothing viable to relocate to


@pytest.mark.asyncio
async def test_cycle_covers_all_three_products_independently():
    hub = _hub(instances_by_key={
        "nac_instances":  [{"id": "n1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeC"]}],
        "ipam_instances": [{"id": "p1", "spoke_id": "spokeA-netbox", "spoke_pool": ["spokeC"]}],
        "ldap_instances": [{"id": "l1", "spoke_id": "spokeA-ldap", "spoke_pool": ["spokeC"]}],
    })
    _connect(hub, "spokeC", "agent")
    await hub._instance_relocate_cycle()
    roles_loaded = {payload["role"] for _sid, payload in hub.load_role_calls}
    assert roles_loaded == {"cppm", "netbox", "ldap"}


# ── load-based rebalancing (PR3) ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rebalance_moves_instance_to_a_much_less_loaded_candidate():
    """spokeA is currently serving 3 instances (2 NAC-irrelevant here, but
    load counts across all 3 products); spokeB is idle. The gap (3 vs 0)
    clears the threshold, so the NAC instance on spokeA moves to spokeB."""
    hub = _hub(instances_by_key={
        "nac_instances": [
            {"id": "n1", "name": "CPPM-1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}],
        "ipam_instances": [{"id": "p1", "spoke_id": "spokeA-netbox"}],
        "ldap_instances": [{"id": "l1", "spoke_id": "spokeA-ldap"}],
    })
    _connect(hub, "spokeA-cppm", "nac")
    _connect(hub, "spokeA-netbox", "ipam")
    _connect(hub, "spokeA-ldap", "directory")
    _connect(hub, "spokeB", "agent")

    await hub._instance_rebalance_cycle()

    assert hub.load_role_calls == [("spokeB", {"role": "cppm", "config": {}})]
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeB-cppm"
    assert hub.push_calls == ["spokeB-cppm"]


@pytest.mark.asyncio
async def test_rebalance_leaves_a_small_imbalance_alone():
    """spokeA serves 1 instance, spokeB serves 0 — a gap of 1 is below the
    threshold (2), so nothing moves. Avoids thrashing on trivial imbalance."""
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "n1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    _connect(hub, "spokeA-cppm", "nac")
    _connect(hub, "spokeB", "agent")

    await hub._instance_rebalance_cycle()

    assert hub.load_role_calls == []
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeA-cppm"


@pytest.mark.asyncio
async def test_rebalance_never_touches_an_unhealthy_instance():
    """A down instance is the failover pass's job, not rebalancing's — even
    with a huge apparent load gap, rebalance must not act on it."""
    hub = _hub(instances_by_key={"nac_instances": [
        {"id": "n1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA", "spokeB"]}]})
    # spokeA-cppm is NOT connected (down) — only spokeB is up.
    _connect(hub, "spokeB", "agent")

    await hub._instance_rebalance_cycle()

    assert hub.load_role_calls == []


@pytest.mark.asyncio
async def test_rebalance_only_considers_pool_candidates_not_every_idle_spoke():
    """spokeC is idle but was never checked into this instance's pool — must
    not be used as a rebalance target."""
    hub = _hub(instances_by_key={
        "nac_instances": [{"id": "n1", "spoke_id": "spokeA-cppm", "spoke_pool": ["spokeA"]}],
        "ipam_instances": [{"id": "p1", "spoke_id": "spokeA-netbox"}],
        "ldap_instances": [{"id": "l1", "spoke_id": "spokeA-ldap"}],
    })
    _connect(hub, "spokeA-cppm", "nac")
    _connect(hub, "spokeA-netbox", "ipam")
    _connect(hub, "spokeA-ldap", "directory")
    _connect(hub, "spokeC", "agent")  # idle, but not in the pool

    await hub._instance_rebalance_cycle()

    assert hub.load_role_calls == []
    inst = hub.state.system_state["global_config"]["nac_instances"][0]
    assert inst["spoke_id"] == "spokeA-cppm"


@pytest.mark.asyncio
async def test_rebalance_runs_only_every_nth_cycle_of_the_main_loop(monkeypatch):
    """The rebalance pass shares the failover loop's tick rather than running
    on its own asyncio loop — assert it only fires every
    _REBALANCE_EVERY_N_CYCLES ticks, not every cycle. instance_relocate.py is
    a stdlib-only leaf that doesn't import asyncio itself — sync_loop.py owns
    the sleep, so that's what gets patched."""
    import asyncio
    import sync_loop
    import instance_relocate as mod

    hub = _hub(instances_by_key={"nac_instances": []})
    calls = {"relocate": 0, "rebalance": 0}

    async def _fake_relocate():
        calls["relocate"] += 1

    async def _fake_rebalance():
        calls["rebalance"] += 1
    hub._instance_relocate_cycle = _fake_relocate
    hub._instance_rebalance_cycle = _fake_rebalance

    sleeps = []

    async def _fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) >= mod._REBALANCE_EVERY_N_CYCLES + 2:
            raise asyncio.CancelledError
    monkeypatch.setattr(sync_loop.asyncio, "sleep", _fake_sleep)

    try:
        await hub.run_instance_relocate_loop()
    except asyncio.CancelledError:
        pass

    assert calls["relocate"] == mod._REBALANCE_EVERY_N_CYCLES + 1
    assert calls["rebalance"] == 1  # only fired once the tick count hit the Nth cycle
