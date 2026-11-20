"""The global learned-value approval queue is saved on every path that edits it.

A learning tenant's stable known-good is proposed into the global pending queue
by the adaptive controller; a Global Admin then approves it (published into
global_learned_values and removed from pending) or rejects it (removed from
pending). Each path edits the saved queue in one step under the store lock, so
the controller and an admin can't undo each other's edits. These tests reopen
the store from disk, so they check what was persisted, not the in-memory copy.
"""
import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations import sim_quota
from simulations.routes import register_simulations_routes
from simulations.store import SimulationsStore

_TID = "10"
_AK = "alert:dns_fail"
_QUOTA = {"sim_id": "dns_fail", "alert_type": "alert", "alert_id": "dns_fail",
          "site": "SITE-A", "count": 5, "min": 2, "max": 10,
          "learning": True, "enabled": True}
_PENDING = {_AK: {"count": 7, "floor": 6, "knobs": {}, "time_to_stable_s": 60,
                  "source_tenant": _TID, "proposed_at": 1.0}}


class _Hub:
    """Stub hub: one tenant, no cs spoke bound and no telemetry cached."""

    def __init__(self, store):
        self.simulations_store = store
        self.simulations_cache = {}
        self.active_connections = set()
        self.state = type("State", (), {
            "system_state": {},
            "tenant_state": {"tenants": {_TID: {"name": "Lab"}}}})()

    def get_client_sim_spokes(self, tenant_id):
        return []

    def get_client_sim_spoke(self, tenant_id):
        return None

    async def request_response(self, sid, cmd_type, payload, timeout=10.0):
        return {}

    async def _drain_aware_config_push(self, sid, cmd_type, payload, timeout=5.0):
        return {"status": "ok"}


def _build(tmp_path):
    """Register the simulations routes on a stub hub over a real on-disk store."""
    store = SimulationsStore(str(tmp_path))
    hub = _Hub(store)
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: {"username": "admin"},
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return app, hub, store


def _run(coro):
    """Run a coroutine on a fresh event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _saved_pending(tmp_path):
    """The pending queue as saved on disk (a fresh store reloads the file)."""
    return _run(SimulationsStore(str(tmp_path)).get_global_learned_pending())


def _seed_stable_quota(store, floor=6):
    """A learning quota whose controller has settled (stable at 7 clients)."""
    _run(store.set_central_sites_config(_TID, {"sim_quotas": [dict(_QUOTA)]}))
    _run(store.set_adaptive_state(_TID, {sim_quota.adaptive_key(_QUOTA): {
        "phase": "stable", "learned_op": 7, "target": 7, "floor": floor,
        "stable_since": 1.0}}))


def _published(tmp_path):
    """The published global learned values as saved on disk."""
    return _run(SimulationsStore(str(tmp_path)).get_global_learned_values())


def _approve(app):
    """Approve the alert's queued proposal through the route."""
    r = TestClient(app).post("/sim/api/superadmin/global-learned-pending/approve",
                             json={"alert_key": _AK})
    assert r.status_code == 200, r.text


def test_controller_saves_a_proposed_known_good(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    # Hold the state as it is, so this pass only records the known-good.
    monkeypatch.setattr(sim_quota, "adaptive_step", lambda st, *a, **k: dict(st))
    _run(hub._run_adaptive_controller())
    saved = _saved_pending(tmp_path)
    assert saved[_AK]["count"] == 7
    assert saved[_AK]["floor"] == 6
    assert saved[_AK]["source_tenant"] == _TID
    # The snapshot keeps the floor, for a proposal made when it isn't stable.
    assert _run(SimulationsStore(str(tmp_path)).get_known_good(_TID))[_AK]["floor"] == 6


def test_a_reject_during_the_sweep_is_not_undone(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    # Another alert's proposal is queued before the sweep starts.
    _run(store.propose_global_learned({"alert:other": dict(_PENDING[_AK])}))

    def _step(st, *a, **k):
        """Hold the state; meanwhile an admin rejects the other proposal."""
        store._global()["global_learned_pending"].pop("alert:other", None)
        return dict(st)

    monkeypatch.setattr(sim_quota, "adaptive_step", _step)
    _run(hub._run_adaptive_controller())
    # The sweep adds its own proposal without bringing the rejected one back.
    assert set(_saved_pending(tmp_path)) == {_AK}


def test_approve_publishes_and_removes_the_entry_from_pending(tmp_path):
    app, _hub, store = _build(tmp_path)
    _run(store.propose_global_learned(dict(_PENDING)))
    r = TestClient(app).post("/sim/api/superadmin/global-learned-pending/approve",
                             json={"alert_key": _AK})
    assert r.status_code == 200 and r.json()["approved"] == [_AK]
    assert _saved_pending(tmp_path) == {}
    published = _run(SimulationsStore(str(tmp_path)).get_global_learned_values())
    assert published[_AK]["op"] == 7


def test_reject_removes_the_entry_from_pending(tmp_path):
    app, _hub, store = _build(tmp_path)
    _run(store.propose_global_learned(dict(_PENDING)))
    r = TestClient(app).post("/sim/api/superadmin/global-learned-pending/reject",
                             json={"alert_key": _AK})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert _saved_pending(tmp_path) == {}
    # Nothing was published.
    assert _run(SimulationsStore(str(tmp_path)).get_global_learned_values()) == {}


def _seed_known_good(store, **extra):
    """The quota's known-good, saved with no proposal mark: the state left by
    the broken queue write, which saved the known-good but lost its proposal.
    With no ``floor`` in ``extra`` it has none, as snapshots had before they
    kept one."""
    kg = sim_quota.known_good_from_state(
        _QUOTA, {"phase": "stable", "learned_op": 7, "floor": 6}, {})
    _run(store.set_known_good(_TID, {_AK: dict(kg, **extra)}))


def _hold_state(monkeypatch):
    """Hold each quota's state as it is, so a pass only records known-goods."""
    monkeypatch.setattr(sim_quota, "adaptive_step", lambda st, *a, **k: dict(st))


def test_a_known_good_whose_proposal_was_lost_is_proposed(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    _seed_known_good(store)
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["count"] == 7
    assert _saved_pending(tmp_path)[_AK]["floor"] == 6


def test_a_known_good_equal_to_the_global_value_is_not_proposed(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    _seed_known_good(store)
    _run(store.set_global_learned_values({_AK: {"op": 7, "floor": 6}}))
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path) == {}


@pytest.mark.parametrize("floor", [6, None], ids=["floor", "no-floor"])
def test_a_rejected_proposal_is_not_proposed_again(tmp_path, monkeypatch, floor):
    app, hub, store = _build(tmp_path)
    _seed_stable_quota(store, floor=floor)
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    r = TestClient(app).post("/sim/api/superadmin/global-learned-pending/reject",
                             json={"alert_key": _AK})
    assert r.status_code == 200
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path) == {}


def test_reject_wins_over_a_stale_first_recovery_snapshot(tmp_path, monkeypatch):
    """Reject the same key after recovery reads its unchecked known-good."""
    _app, hub, store = _build(tmp_path)
    _seed_known_good(store)
    _run(store.propose_global_learned(dict(_PENDING)))
    propose = store.propose_global_learned
    seen = []

    async def _reject_then_propose(proposals):
        """Interleave a real rejection at the recovery queue-write boundary."""
        assert proposals[_AK]["count"] == 7
        assert await store.reject_global_learned(_AK)
        seen.append(_AK)
        await propose(proposals)

    monkeypatch.setattr(store, "propose_global_learned", _reject_then_propose)
    _run(hub._run_adaptive_controller())
    assert seen == [_AK]
    assert _saved_pending(tmp_path) == {}
    saved = _run(SimulationsStore(str(tmp_path)).get_known_good(_TID))
    assert saved[_AK]["proposal_checked"] is True


def test_rejected_pairs_survive_restart_without_blocking_other_values(tmp_path):
    """Remember every rejected count, not just the most recent one per alert."""
    store = SimulationsStore(str(tmp_path))
    for count in (7, 8):
        _run(store.propose_global_learned({_AK: dict(_PENDING[_AK], count=count)}))
        assert _run(store.reject_global_learned(_AK))
        store = SimulationsStore(str(tmp_path))

    # Neither older rejected count may return, including a string-form count.
    for count in ("7", 8):
        _run(store.propose_global_learned({_AK: dict(_PENDING[_AK], count=count)}))
        assert _saved_pending(tmp_path) == {}

    # Rejection is scoped to the alert/count pair, not all proposals.
    _run(store.propose_global_learned({
        _AK: dict(_PENDING[_AK], count=9),
        "alert:other": dict(_PENDING[_AK]),
    }))
    saved = _saved_pending(tmp_path)
    assert saved[_AK]["count"] == 9
    assert saved["alert:other"]["count"] == 7
    assert not _run(store.reject_global_learned("alert:missing"))
    assert _saved_pending(tmp_path) == saved


def test_a_failed_queue_write_is_retried_on_the_next_pass(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    _hold_state(monkeypatch)
    real = store.propose_global_learned

    async def _fail(proposals):
        """The queue write fails, as it did from Aug 6 until this fix."""
        raise OSError("disk full")

    monkeypatch.setattr(store, "propose_global_learned", _fail)
    _run(hub._run_adaptive_controller())
    monkeypatch.setattr(store, "propose_global_learned", real)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["count"] == 7


def test_a_proposal_equal_to_the_published_value_is_dropped(tmp_path):
    store = SimulationsStore(str(tmp_path))
    _run(store.set_global_learned_values({_AK: {"op": 7, "floor": 6}}))
    _run(store.propose_global_learned({
        _AK: dict(_PENDING[_AK]), "alert:other": dict(_PENDING[_AK], count=3)}))
    assert set(_saved_pending(tmp_path)) == {"alert:other"}


def test_a_value_approved_during_the_sweep_is_not_queued_again(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)

    def _step(st, *a, **k):
        """Hold the state; meanwhile an admin publishes the same count."""
        store._global()["global_learned_values"] = {_AK: {"op": 7, "floor": 6}}
        return dict(st)

    monkeypatch.setattr(sim_quota, "adaptive_step", _step)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path) == {}


def test_a_lost_proposal_is_recovered_when_its_quota_no_longer_learns(tmp_path, monkeypatch):
    _app, hub, store = _build(tmp_path)
    _run(store.set_central_sites_config(
        _TID, {"sim_quotas": [dict(_QUOTA, learning=False)]}))
    _seed_known_good(store)
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["count"] == 7
    saved = _run(SimulationsStore(str(tmp_path)).get_known_good(_TID))
    assert saved[_AK]["proposal_checked"] is True


@pytest.mark.parametrize("quotas", [[], [dict(_QUOTA, enabled=False)]],
                         ids=["no-quotas", "disabled-quota"])
def test_a_lost_proposal_is_recovered_for_a_tenant_with_nothing_adaptive(tmp_path, quotas):
    _app, hub, store = _build(tmp_path)
    _run(store.set_central_sites_config(_TID, {"sim_quotas": quotas}))
    _seed_known_good(store)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["count"] == 7


def test_a_malformed_known_good_does_not_block_the_others(tmp_path):
    _app, hub, store = _build(tmp_path)
    _seed_known_good(store)
    kg = _run(store.get_known_good(_TID))
    _run(store.set_known_good(_TID, dict(kg, **{"alert:bad": {"count": "n/a"}})))
    _run(hub._run_adaptive_controller())
    assert set(_saved_pending(tmp_path)) == {_AK}


def test_a_proposal_equal_to_the_published_value_removes_the_queued_one(tmp_path):
    store = SimulationsStore(str(tmp_path))
    _run(store.set_global_learned_values({_AK: {"op": 5, "floor": 4}}))
    _run(store.propose_global_learned(dict(_PENDING)))
    # The newest proposal for the alert is the published value: nothing to approve.
    _run(store.propose_global_learned({_AK: dict(_PENDING[_AK], count=5, floor=4)}))
    assert _saved_pending(tmp_path) == {}


def test_a_queued_entry_already_published_is_removed(tmp_path):
    store = SimulationsStore(str(tmp_path))
    _run(store.propose_global_learned({"alert:old": dict(_PENDING[_AK], count=4, floor=3)}))
    # The old approve path published the proposal but did not save its removal.
    store._global()["global_learned_values"] = {"alert:old": {"op": 4, "floor": 3}}
    _run(store._asave())
    _run(store.propose_global_learned(dict(_PENDING)))
    assert set(_saved_pending(tmp_path)) == {_AK}


def test_publishing_a_queued_count_removes_it_from_pending(tmp_path):
    app, _hub, store = _build(tmp_path)
    _run(store.propose_global_learned(
        {_AK: dict(_PENDING[_AK]), "alert:other": dict(_PENDING[_AK], count=3)}))
    r = TestClient(app).put("/sim/api/superadmin/global-learned-values",
                            json={"values": {_AK: {"op": 7, "floor": 6}}})
    assert r.status_code == 200
    assert set(_saved_pending(tmp_path)) == {"alert:other"}


@pytest.mark.parametrize("prev", [{"count": "n/a"}, {"count": None}, "n/a"],
                         ids=["text-count", "no-count", "not-a-dict"])
def test_a_malformed_known_good_of_a_stable_quota_is_replaced(tmp_path, monkeypatch, prev):
    _app, hub, store = _build(tmp_path)
    _seed_stable_quota(store)
    _run(store.set_known_good(_TID, {_AK: prev, "alert:other": {"count": 3}}))
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    # The pass replaced the bad record and still proposed every known-good.
    saved = _saved_pending(tmp_path)
    assert {ak: p["count"] for ak, p in saved.items()} == {_AK: 7, "alert:other": 3}
    assert _run(SimulationsStore(str(tmp_path)).get_known_good(_TID))[_AK]["count"] == 7


def test_a_recovered_proposal_carries_the_floor_saved_with_it(tmp_path, monkeypatch):
    app, hub, store = _build(tmp_path)
    _run(store.set_central_sites_config(
        _TID, {"sim_quotas": [dict(_QUOTA, learning=False)]}))
    _seed_known_good(store, floor=6)
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["floor"] == 6
    _approve(app)
    published = _published(tmp_path)
    assert published[_AK]["floor"] == 6
    # A consumer whose stored max (6) is below the published op (7) reaches the
    # op only when a floor is published (sim_quota.apply_adaptive_targets).
    consumer = dict(_QUOTA, learning=False, max=6)
    assert sim_quota.apply_adaptive_targets([dict(consumer)], {}, published)[0]["count"] == 7
    floorless = {_AK: dict(published[_AK], floor=None)}
    assert sim_quota.apply_adaptive_targets([dict(consumer)], {}, floorless)[0]["count"] == 6


def test_a_snapshot_saved_without_a_floor_gets_it_when_the_lab_is_stable_again(
        tmp_path, monkeypatch):
    app, hub, store = _build(tmp_path)
    _hold_state(monkeypatch)
    # Recovered while its quota doesn't learn: the floor is unknown, so the
    # approved value has none.
    _run(store.set_central_sites_config(
        _TID, {"sim_quotas": [dict(_QUOTA, learning=False)]}))
    _seed_known_good(store)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["floor"] is None
    _approve(app)
    assert _published(tmp_path)[_AK]["floor"] is None
    # The lab is stable again: the snapshot takes the floor and is proposed
    # again, as the published value lacks it.
    _seed_stable_quota(store)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path)[_AK]["floor"] == 6
    _approve(app)
    pub = _published(tmp_path)[_AK]
    assert (pub["op"], pub["floor"]) == (7, 6)
    # Once it has the floor it is not proposed again.
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path) == {}


def test_a_floor_seeded_by_a_reset_does_not_fill_a_snapshot_saved_without_one(
        tmp_path, monkeypatch):
    app, hub, store = _build(tmp_path)
    # A snapshot with no floor whose proposal was already made.
    _seed_known_good(store, proposal_checked=True)
    # Reset-to-known-good parks the quota at the snapshot's count. When the
    # hold ends the state is stable with the floor seeded from the count, and
    # no stable_since, as nothing was learned yet.
    reset = sim_quota.seed_state_to_known_good({"count": 7}, True, 0.0, hold_s=60)
    st = sim_quota.adaptive_step(reset, dict(_QUOTA), None, 120.0)
    assert (st["phase"], st["floor"], st["stable_since"]) == ("stable", 7, None)
    _run(store.set_central_sites_config(_TID, {"sim_quotas": [dict(_QUOTA)]}))
    _run(store.set_adaptive_state(_TID, {sim_quota.adaptive_key(_QUOTA): st}))
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    assert _saved_pending(tmp_path) == {}
    assert _run(store.get_known_good(_TID))[_AK].get("floor") is None


@pytest.mark.parametrize("published_floor,floor,queued", [
    (None, 6, True), (6, None, False), (6, 6, False), (6, 5, True)],
    ids=["adds-a-floor", "no-floor", "same-floor", "other-floor"])
def test_a_proposal_of_the_published_count_is_queued_only_for_its_floor(
        tmp_path, published_floor, floor, queued):
    store = SimulationsStore(str(tmp_path))
    _run(store.set_global_learned_values({_AK: {"op": 7, "floor": published_floor}}))
    _run(store.propose_global_learned({_AK: dict(_PENDING[_AK], floor=floor)}))
    assert (_AK in _saved_pending(tmp_path)) is queued


def test_a_proposal_with_no_floor_does_not_replace_a_queued_floor(tmp_path):
    store = SimulationsStore(str(tmp_path))
    _run(store.propose_global_learned(dict(_PENDING)))
    # Another tenant's snapshot of the same count, saved with no floor.
    _run(store.propose_global_learned(
        {_AK: dict(_PENDING[_AK], floor=None, source_tenant="20")}))
    assert _saved_pending(tmp_path)[_AK] == _PENDING[_AK]
    # A different count is newer, so it replaces the queued proposal.
    _run(store.propose_global_learned({_AK: dict(_PENDING[_AK], count=9, floor=None)}))
    assert _saved_pending(tmp_path)[_AK]["count"] == 9


def _seed_sites(store, states, knobs, reverse):
    """Learning quotas for the alert on SITE-A and SITE-B, both stable: each
    site's state is a stable one updated with ``states[site]``, and its knob
    learner's values are ``knobs.get(site)``. ``reverse`` lists SITE-B first."""
    rows = [dict(_QUOTA, site=s) for s in sorted(states, reverse=reverse)]
    _run(store.set_central_sites_config(_TID, {"sim_quotas": rows}))
    _run(store.set_adaptive_state(_TID, {
        sim_quota.adaptive_key(r): dict({"phase": "stable", "target": 7, "stable_since": 1.0},
                                        **states[r["site"]]) for r in rows}))
    _run(store.set_knob_learn_state(_TID, {
        sim_quota.adaptive_key(r): {"values": knobs.get(r["site"], {})} for r in rows}))


def _count_writes(monkeypatch, store):
    """Count the controller's known-good and queue writes from now on."""
    writes = []
    for name in ("set_known_good", "propose_global_learned"):

        async def _counted(*a, _real=getattr(store, name), _name=name, **k):
            """Record the write, then make it."""
            writes.append(_name)
            return await _real(*a, **k)

        monkeypatch.setattr(store, name, _counted)
    return writes


# Two sites stable on the same pass, for one alert: each site's state and knob
# values, and the snapshot the alert keeps (count, floor, the site it came from).
_SITE_CASES = {
    "higher-count": ({"SITE-A": {"learned_op": 7, "floor": 6},
                      "SITE-B": {"learned_op": 9, "floor": 8}}, {}, (9, 8, "SITE-B")),
    "learned-floor-over-none": ({"SITE-A": {"learned_op": 7, "floor": None},
                                 "SITE-B": {"learned_op": 7, "floor": 6}}, {}, (7, 6, "SITE-B")),
    # SITE-A's floor was seeded by a Reset-to-known-good, not learned.
    "learned-floor-over-reset": ({"SITE-A": {"learned_op": 7, "floor": 7, "stable_since": None},
                                  "SITE-B": {"learned_op": 7, "floor": 6}}, {}, (7, 6, "SITE-B")),
    "higher-floor": ({"SITE-A": {"learned_op": 7, "floor": 5},
                      "SITE-B": {"learned_op": 7, "floor": 6}}, {}, (7, 6, "SITE-B")),
    # Same count and floor, different knobs: the site name decides.
    "knobs-tie": ({"SITE-A": {"learned_op": 7, "floor": 6},
                   "SITE-B": {"learned_op": 7, "floor": 6}},
                  {"SITE-A": {"dns_fail_rate": 1000}, "SITE-B": {"dns_fail_rate": 1200}},
                  (7, 6, "SITE-B")),
}


@pytest.mark.parametrize("reverse", [False, True], ids=["a-first", "b-first"])
@pytest.mark.parametrize("case", list(_SITE_CASES))
def test_sites_sharing_an_alert_propose_their_best_snapshot_once(
        tmp_path, monkeypatch, case, reverse):
    """Sites that share an alert key keep one snapshot, the best of them,
    whatever their order; once rejected, it is not queued again."""
    states, knobs, (count, floor, site) = _SITE_CASES[case]
    app, hub, store = _build(tmp_path)
    _seed_sites(store, states, knobs, reverse)
    _hold_state(monkeypatch)
    _run(hub._run_adaptive_controller())
    queued = _saved_pending(tmp_path)[_AK]
    assert (queued["count"], queued["floor"], queued["knobs"]) == (count, floor, knobs.get(site, {}))
    saved = _run(SimulationsStore(str(tmp_path)).get_known_good(_TID))
    assert saved[_AK]["site"] == site
    r = TestClient(app).post("/sim/api/superadmin/global-learned-pending/reject",
                             json={"alert_key": _AK})
    assert r.status_code == 200
    # Before the fix each site replaced the other's snapshot in turn, so every
    # pass saved it unchecked and queued it again. Now an unchanged pass
    # writes nothing.
    writes = _count_writes(monkeypatch, store)
    _run(hub._run_adaptive_controller())
    _run(hub._run_adaptive_controller())
    assert writes == []
    assert _saved_pending(tmp_path) == {}
    assert _run(SimulationsStore(str(tmp_path)).get_known_good(_TID)) == saved
