"""Critical path — GitHub repo sync (System → Sync; replaces auto-update).

``test_repo_sync.py`` locks in: the config key is fixed, the interval clamps to
a 60s floor with a 900s (15 min) default, ``run_repo_sync_all`` delegates to
``perform_update`` (hub tree + spoke fan-out), records the combined status, and
the [sync-error] marker fires when ``perform_update`` raises. The disabled loop
is a no-op. Mirrors ``test_staleness_sweep.py`` (canned-relay hub stand-in).

``_is_git_repo`` is stubbed False so the ``provisioning_repos/*`` scan records
"skipped" entries without spawning a real ``git`` subprocess — this is a unit
test of the orchestration, not of git itself.
"""

import asyncio
import logging

import pytest

import repo_sync as rs
from repo_sync import RepoSyncMixin
from _fakes import FakeState


# ── config helpers ───────────────────────────────────────────────────────────

def test_cfg_key_fixed():
    assert RepoSyncMixin._REPO_SYNC_CFG_KEY == "repo_sync"


def test_interval_clamps_to_60_floor():
    m = RepoSyncMixin()
    m.state = FakeState(system_state={"global_config":
        {"repo_sync": {"interval_seconds": 10}}})
    assert m._repo_sync_interval() == 60.0          # can't hot-loop the hub
    m.state = FakeState(system_state={"global_config": {}})
    assert m._repo_sync_interval() == 900.0         # default 15 minutes


def test_default_enabled_is_true():
    # No config at all → enabled defaults True (user wants 15-min default).
    m = RepoSyncMixin()
    m.state = FakeState(system_state={"global_config": {}})
    assert m._repo_sync_cfg().get("enabled", True) is True


# ── canned-relay hub (async) ─────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = None

    async def set_repo_sync_status(self, status):
        self.recorded = status

    async def get_repo_sync_status(self):
        return dict(self.recorded or {})


class _RepoSyncHub(RepoSyncMixin):
    """Minimal hub stand-in: canned perform_update + stubbed _is_git_repo so
    the provisioning_repos scan never spawns git."""

    def __init__(self, global_config=None, perform_result=None, perform_exc=None):
        self.state = FakeState(
            system_state={"global_config": global_config or {}})
        self.simulations_store = _FakeSimulationsStore()
        self._perform_result = perform_result or {
            "status": "checked", "message": "Hub is current."}
        self._perform_exc = perform_exc
        self.perform_calls = 0

    # No real git in unit tests → every provisioning_repos subdir is "skipped".
    def _is_git_repo(self, path):
        return False

    async def perform_update(self, force=False, force_spokes=False):
        self.perform_calls += 1
        if self._perform_exc:
            raise self._perform_exc
        return self._perform_result


# ── run_repo_sync_all ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_all_delegates_to_perform_update_and_records_status():
    h = _RepoSyncHub(global_config={"repo_sync": {"enabled": True, "interval_seconds": 900}},
                    perform_result={"status": "checked", "message": "Hub is current."})
    res = await h.run_repo_sync_all()

    assert h.perform_calls == 1                     # perform_update invoked once
    assert res["hub"]["status"] == "checked"
    assert res["hub"]["message"] == "Hub is current."
    assert "last_sync_ts" in res
    # provisioning_repos scan ran but every entry is "skipped" (stubbed).
    prov = res["provisioning_repos"]
    assert isinstance(prov, list) and prov                          # scan ran
    assert all(r["status"] == "skipped" for r in prov)
    # Status persisted to the store.
    assert h.simulations_store.recorded is res                      # same dict
    assert "hub=checked" in res["message"]


@pytest.mark.asyncio
async def test_run_all_records_error_when_perform_update_raises(caplog):
    h = _RepoSyncHub(perform_exc=RuntimeError("git lock busy"))
    caplog.set_level(logging.WARNING, logger="Hub")
    res = await h.run_repo_sync_all()
    assert res["hub"]["status"] == "error"
    assert "git lock busy" in res["hub"]["message"]
    # [sync-error] marker so the cause lands in the hub log + GET_ERROR_LOGS.
    assert any("[sync-error]" in r.message and "git lock busy" in r.message
               for r in caplog.records)


# ── loop ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_loop_disabled_does_not_sync(monkeypatch):
    h = _RepoSyncHub(global_config={"repo_sync": {"enabled": False}})

    async def _boom():
        raise AssertionError("run_repo_sync_all must not run when disabled")
    h.run_repo_sync_all = _boom

    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] >= 2:
            raise asyncio.CancelledError()
    monkeypatch.setattr(rs.asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await h.run_repo_sync_loop()

# ── update-health warning dedup (item 18) ─────────────────────────────────────
# A persistent mis-config (update_sources.hub empty) would otherwise log a
# WARNING every 15-min cycle (~96/day) of the SAME advisory. The dedup logs a
# distinct warning at WARNING only on first occurrence / re-appearance after
# clearing; while it persists unchanged it emits one condensed INFO line.
class _DedupHub(_RepoSyncHub):
    """Canned check_update_health so the dedup logic is exercised in isolation."""
    def __init__(self, warnings_seq):
        super().__init__()
        self._warnings_seq = warnings_seq
        self._calls = 0

    async def check_update_health(self):
        w = self._warnings_seq[min(self._calls, len(self._warnings_seq) - 1)]
        self._calls += 1
        return {"ok": True, "checks": {}, "warnings": list(w), "errors": []}


@pytest.mark.asyncio
async def test_update_health_warning_deduped_across_cycles(caplog):
    w = ["update_sources.hub is empty/missing — falling back to the default repo URL"]
    h = _DedupHub(warnings_seq=[w, w, w])  # same warning 3 cycles
    caplog.set_level(logging.INFO, logger="Hub")
    await h.run_repo_sync_all()   # cycle 1: WARNING (first occurrence)
    await h.run_repo_sync_all()   # cycle 2: INFO summary only (deduped)
    await h.run_repo_sync_all()   # cycle 3: INFO summary only (deduped)
    warns = [r for r in caplog.records if r.levelno >= logging.WARNING
             and "update-health" in r.message and "empty/missing" in r.message]
    infos = [r for r in caplog.records if r.levelno == logging.INFO
             and "unchanged since last cycle" in r.message]
    assert len(warns) == 1, "distinct warning logged once at WARNING, then deduped"
    assert len(infos) == 2, "cycles 2+3 emit a condensed INFO summary"


@pytest.mark.asyncio
async def test_update_health_warning_re_logged_after_clearing(caplog):
    # w, then cleared, then w again → WARNING, CLEARED INFO, WARNING (re-appear).
    h = _DedupHub(warnings_seq=[["hub empty"], [], ["hub empty"]])
    caplog.set_level(logging.INFO, logger="Hub")
    await h.run_repo_sync_all()
    await h.run_repo_sync_all()
    await h.run_repo_sync_all()
    warns = [r for r in caplog.records if r.levelno >= logging.WARNING
             and "hub empty" in r.message]
    cleared = [r for r in caplog.records if r.levelno == logging.INFO
               and "CLEARED" in r.message and "hub empty" in r.message]
    assert len(warns) == 2, "re-logged at WARNING when it re-appears after clearing"
    assert len(cleared) == 1, "clearing is logged once at INFO"
