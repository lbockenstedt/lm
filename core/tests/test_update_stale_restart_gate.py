"""The "click Update, it says rebooting, it never reboots" loop
(``UpdatePipelineMixin._detect_stale_process`` + the restart gate).

Observed on the lab hub, running v0.23 with v0.25 on disk:

    Hub update: 0 file(s) changed; restart NOT needed ()
    Hub updated with no in-process code changes — skipping restart
    update-health: process is STALE: running v0.23 but on-disk is v0.25
    [update-restart] watchdog sentinel written: stale v0.23->v0.25   <- NOT force
    [watchdog] ... a user is logged in — deferring until idle or in-window

Chain: a pull lands but is judged not to need a restart, so the process stays
behind. The NEXT click force-pulls, git is ALREADY at the remote tip, the
changed-paths diff is empty, ``_paths_need_restart([])`` is False, and the
"no in-process code changes" early return fires — reporting success while the
process is never reloaded. Because that early return skips the restart block,
the FORCE sentinel is never written either; only check_update_health's later
NON-force staleness sentinel exists, which the watchdog defers indefinitely
while an operator is logged in. Every subsequent click repeats it.

The fix re-checks running-vs-disk on every path. These lock in the staleness
predicate and the gate condition that consumes it.
"""
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import update_pipeline  # noqa: E402


class _Hub:
    """Only what _detect_stale_process / _request_watchdog_restart read.

    ``_STALE_RESTART_SENTINEL`` must exist even though every test overrides it
    via the env var: the lookup is ``os.environ.get(key, self._STALE_...)`` and
    Python evaluates that default EAGERLY, so a missing attribute raises inside
    the method's blanket except and silently writes no sentinel at all.
    """
    _STALE_RESTART_SENTINEL = "/tmp/lm-test-stale-restart-requested"

    def __init__(self, startup_version=None, disk_version="0.25", boom=False,
                 startup_commit=None, disk_commit="unknown", commit_boom=False):
        if startup_version is not None:
            self._startup_version = startup_version
        self._disk_version = disk_version
        self._boom = boom
        if startup_commit is not None:
            self._startup_commit = startup_commit
        self._disk_commit = disk_commit
        self._commit_boom = commit_boom

    async def get_local_version(self):
        if self._boom:
            raise OSError("VERSION unreadable")
        return self._disk_version

    async def get_local_commit(self):
        if self._commit_boom:
            raise OSError("git unavailable")
        return self._disk_commit


def _stale(hub):
    import asyncio
    return asyncio.run(
        update_pipeline.UpdatePipelineMixin._detect_stale_process(hub))


# ── the predicate ────────────────────────────────────────────────────────────

def test_running_behind_disk_is_stale():
    """The reported case: process on 0.23, disk on 0.25."""
    assert _stale(_Hub(startup_version="0.23", disk_version="0.25")) is True


def test_running_equals_disk_is_not_stale():
    assert _stale(_Hub(startup_version="0.25", disk_version="0.25")) is False


def test_unknown_running_version_is_not_stale():
    assert _stale(_Hub(startup_version="unknown", disk_version="0.25")) is False


def test_missing_startup_version_is_not_stale():
    """Before the boot capture there is no running version to compare."""
    assert _stale(_Hub(disk_version="0.25")) is False


def test_unreadable_disk_version_never_triggers_a_restart_loop():
    assert _stale(_Hub(startup_version="0.23", boom=True)) is False


def test_empty_disk_version_is_not_stale():
    assert _stale(_Hub(startup_version="0.23", disk_version="")) is False


# ── commit-level staleness (VERSION-independent) ─────────────────────────────
# Every VERSION file is the constant 1.00, so the version compare is inert; the
# boot-commit vs on-disk-commit compare is the real stale signal for a git hub.

def test_running_behind_disk_commit_is_stale():
    """VERSION equal (both 1.00) but the boot commit trails on-disk HEAD."""
    assert _stale(_Hub(startup_version="1.00", disk_version="1.00",
                       startup_commit="aaaaaaaa", disk_commit="bbbbbbbb")) is True


def test_running_equals_disk_commit_is_not_stale():
    assert _stale(_Hub(startup_version="1.00", disk_version="1.00",
                       startup_commit="aaaaaaaa", disk_commit="aaaaaaaa")) is False


def test_unknown_commit_is_not_stale():
    assert _stale(_Hub(startup_version="1.00", disk_version="1.00",
                       startup_commit="unknown", disk_commit="bbbbbbbb")) is False


def test_missing_startup_commit_is_not_stale():
    """Tarball install / pre-boot-capture: no commit to compare, no false stale."""
    assert _stale(_Hub(startup_version="1.00", disk_version="1.00",
                       disk_commit="bbbbbbbb")) is False


def test_unreadable_disk_commit_never_triggers_a_restart_loop():
    assert _stale(_Hub(startup_version="1.00", disk_version="1.00",
                       startup_commit="aaaaaaaa", commit_boom=True)) is False


# ── the gate that consumes it ────────────────────────────────────────────────
# Mirrors `if hub_updated and not stale_reload and not _hub_needs_restart:` —
# the early return that skipped the restart.

def _skips_restart(hub_updated, stale_reload, needs_restart):
    return bool(hub_updated) and not stale_reload and not needs_restart


def test_the_exact_reported_combination_no_longer_skips():
    """hub_updated + empty diff + STALE process must NOT take the early return."""
    assert _skips_restart(hub_updated=True, stale_reload=True,
                          needs_restart=False) is False


def test_genuine_webui_only_pull_still_skips_the_restart():
    """The early return must survive for what it was written for: a pull that
    touched only static assets while the process is already current."""
    assert _skips_restart(hub_updated=True, stale_reload=False,
                          needs_restart=False) is True


def test_real_code_change_still_restarts():
    assert _skips_restart(hub_updated=True, stale_reload=False,
                          needs_restart=True) is False


# ── the force sentinel that the early return was starving ────────────────────

def test_manual_update_writes_a_force_sentinel(tmp_path, monkeypatch):
    """Reaching the restart block on a manual Update must write FORCE, so the
    watchdog acts immediately instead of deferring while a user is logged in."""
    path = tmp_path / "stale-restart-requested"
    monkeypatch.setenv("LM_STALE_RESTART_SENTINEL", str(path))
    hub = _Hub()
    update_pipeline.UpdatePipelineMixin._request_watchdog_restart(
        hub, "update->restart", force=True)
    assert path.read_text().startswith("force ")


def test_auto_update_sentinel_stays_non_force(tmp_path, monkeypatch):
    path = tmp_path / "stale-restart-requested"
    monkeypatch.setenv("LM_STALE_RESTART_SENTINEL", str(path))
    hub = _Hub()
    update_pipeline.UpdatePipelineMixin._request_watchdog_restart(
        hub, "stale v0.23->v0.25", force=False)
    assert not path.read_text().startswith("force ")


def test_non_force_never_downgrades_a_pending_force(tmp_path, monkeypatch):
    """check_update_health runs right after perform_update in the same cycle;
    its non-force staleness sentinel must not clobber the button's force."""
    path = tmp_path / "stale-restart-requested"
    monkeypatch.setenv("LM_STALE_RESTART_SENTINEL", str(path))
    hub = _Hub()
    update_pipeline.UpdatePipelineMixin._request_watchdog_restart(
        hub, "update->restart", force=True)
    update_pipeline.UpdatePipelineMixin._request_watchdog_restart(
        hub, "stale v0.23->v0.25", force=False)
    assert path.read_text().startswith("force ")
