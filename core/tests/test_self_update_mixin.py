"""Feature (b): the git self-update + rollback machinery (_run_git,
_snapshot_for_update, _is_known_bad_commit, _clear_pending_update,
_core_update_lock, _prepare_restart_with_watchdog, _perform_self_update_sync,
the recovery state dir + healthy markers, _prepare_service_restart,
_ensure_git_pull_strategy) now lives on a shared ``SelfUpdateMixin``
(``core/src/messaging/self_update.py``) consumed by BOTH ``BaseControlPlane``
(every spoke + the hub-hosting generic agent) and the device-mode ``SpokeClient``
(the dumb agent, NOT a ``BaseControlPlane`` subclass) — the sibling of the
``CodeDriftWatchdogMixin`` extraction (feature (c)).

Pins: both consumers get the 12 helpers FROM the mixin (single source of truth,
not a private copy); each consumer keeps its own per-layout hooks
(``_repo_root`` / ``_resolve_core_root`` / ``get_service_name`` /
``_flush_log_relay_sync``); and ``_spoke_state_dir`` keys the per-component
recovery dir off ``spoke_id`` (a spoke) OR ``agent_id`` (a device-mode agent) so
the agent gets its own ``/var/lib/lm/<agent_id>`` state dir without a ``spoke_id``.
"""
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging.self_update import SelfUpdateMixin  # noqa: E402
from messaging.control_plane import BaseControlPlane  # noqa: E402


_HELPERS = (
    "_ensure_git_pull_strategy",
    "_run_git",
    "_prepare_service_restart",
    "_spoke_state_dir",
    "_clear_healthy_marker",
    "_touch_healthy_marker",
    "_snapshot_for_update",
    "_is_known_bad_commit",
    "_clear_pending_update",
    "_core_update_lock",
    "_prepare_restart_with_watchdog",
    "_perform_self_update_sync",
    "_clear_stale_git_locks",
)


def test_mixin_holds_all_helpers():
    """The 12 helpers live on the mixin itself."""
    for m in _HELPERS:
        assert m in SelfUpdateMixin.__dict__, f"{m} missing from SelfUpdateMixin"


def test_base_control_plane_resolves_helpers_via_mixin():
    """BaseControlPlane no longer DEFINES the helpers — it inherits them from
    the mixin (MRO), so behavior is unchanged for every spoke + the hub-hosting
    generic agent."""
    for m in _HELPERS:
        assert m not in BaseControlPlane.__dict__, (
            f"{m} still defined on BaseControlPlane (should come from mixin)")
        assert getattr(BaseControlPlane, m) is getattr(SelfUpdateMixin, m), (
            f"{m} not resolved via SelfUpdateMixin")


class _DeviceConsumer(SelfUpdateMixin):
    """Mirrors the device-mode SpokeClient shape: NO ``spoke_id`` (it has
    ``agent_id`` instead), provides the per-layout hooks the mixin calls."""

    def __init__(self, agent_id, repo):
        self.agent_id = agent_id
        self._repo = repo
        self._draining = False
        self._spoke_update_in_progress = False

    def _repo_root(self):
        return self._repo

    def _resolve_core_root(self):
        return None

    def get_service_name(self):
        return "lm-agent"

    def _flush_log_relay_sync(self, timeout=2.0):
        pass


def test_device_consumer_resolves_helpers_via_mixin():
    """The device-mode consumer gets the 12 helpers from the mixin too (does NOT
    re-define them), and provides its OWN hooks (``_repo_root`` etc.)."""
    c = _DeviceConsumer("dev-1", "/tmp/repo")
    for m in _HELPERS:
        assert m not in type(c).__dict__, f"{m} re-defined by device consumer"
        assert getattr(type(c), m) is getattr(SelfUpdateMixin, m), (
            f"{m} not resolved via SelfUpdateMixin for device consumer")
    # hooks the mixin calls are provided by the consumer, not the mixin.
    for hook in ("_repo_root", "_resolve_core_root", "get_service_name",
                "_flush_log_relay_sync"):
        assert hook in type(c).__dict__, f"{hook} not provided by device consumer"


def test_state_dir_keys_off_spoke_id_when_present(tmp_path, monkeypatch):
    """A consumer with ``spoke_id`` (a spoke) keys the recovery dir off it."""
    class _Spoke(SelfUpdateMixin):
        def __init__(self, sid, repo):
            self.spoke_id = sid
            self._repo = repo
        def _repo_root(self):
            return self._repo

    made = []
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: made.append(str(p)))
    c = _Spoke("pxmx-1", str(tmp_path))
    c._spoke_state_dir()
    # primary path attempted with the spoke_id (the probe open() then fails →
    # fallback, but the PRIMARY makedirs call records the sid).
    assert any("pxmx-1" in p for p in made), f"spoke_id not used: {made}"


def test_state_dir_falls_back_to_agent_id_without_spoke_id(tmp_path, monkeypatch):
    """A device-mode consumer with ``agent_id`` (no ``spoke_id``) keys the
    recovery dir off ``agent_id`` — the whole point of the fallback so the agent
    gets its own /var/lib/lm/<agent_id> dir."""
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: None)
    c = _DeviceConsumer("dev-99", str(tmp_path))
    d = c._spoke_state_dir()
    # agent_id appears in the chosen dir (primary or repo-local fallback).
    assert "dev-99" in d, f"agent_id not used in state dir: {d}"


def test_state_dir_uses_component_sentinel_when_neither_id_present(tmp_path, monkeypatch):
    """A consumer exposing neither id degrades to the ``component`` sentinel
    rather than crashing — defensive."""
    monkeypatch.setattr("messaging.self_update.os.makedirs",
                        lambda p, exist_ok=False: None)
    class _Bare(SelfUpdateMixin):
        def _repo_root(self):
            return str(tmp_path)
    d = _Bare()._spoke_state_dir()
    assert "component" in d, f"sentinel not used: {d}"

# ── stale git-lock self-heal (_clear_stale_git_locks) ────────────────────────
import time as _time  # noqa: E402


class _Repo(SelfUpdateMixin):
    def __init__(self, repo):
        self._repo = repo
    def _repo_root(self):
        return self._repo


def _make_git(tmp_path):
    gd = tmp_path / ".git"
    (gd / "refs" / "heads").mkdir(parents=True)
    return gd


def _age(path, seconds):
    old = _time.time() - seconds
    os.utime(path, (old, old))


def test_clear_removes_stale_head_lock(tmp_path):
    gd = _make_git(tmp_path)
    lk = gd / "HEAD.lock"
    lk.write_text("")
    _age(lk, 300)  # 5 min old → unambiguously abandoned
    n = _Repo(str(tmp_path))._clear_stale_git_locks(str(tmp_path))
    assert n == 1
    assert not lk.exists()


def test_clear_keeps_fresh_lock(tmp_path):
    # A lock younger than the staleness window belongs to an in-flight git op
    # and must NOT be removed (avoids corrupting a concurrent writer).
    gd = _make_git(tmp_path)
    lk = gd / "index.lock"
    lk.write_text("")  # just created → fresh
    n = _Repo(str(tmp_path))._clear_stale_git_locks(str(tmp_path))
    assert n == 0
    assert lk.exists()


def test_clear_removes_stale_per_ref_lock(tmp_path):
    gd = _make_git(tmp_path)
    lk = gd / "refs" / "heads" / "main.lock"
    lk.write_text("")
    _age(lk, 300)
    n = _Repo(str(tmp_path))._clear_stale_git_locks(str(tmp_path))
    assert n == 1
    assert not lk.exists()


def test_clear_force_age_zero_removes_fresh_lock(tmp_path):
    # The reactive path (after a lock failure) passes max_age_s=0 to force-clear
    # the offending lock so the next update cycle starts clean.
    gd = _make_git(tmp_path)
    lk = gd / "HEAD.lock"
    lk.write_text("")
    n = _Repo(str(tmp_path))._clear_stale_git_locks(str(tmp_path), max_age_s=0.0)
    assert n == 1
    assert not lk.exists()


def test_clear_noop_without_git_dir(tmp_path):
    # No .git directory (or a .git file for a worktree) → nothing to do, no raise.
    n = _Repo(str(tmp_path))._clear_stale_git_locks(str(tmp_path))
    assert n == 0


# ── reactive lock self-heal in _run_git (issue #452) ─────────────────────────
# The step-1 sweep only clears locks older than max_age_s, so a lock left by a
# git that crashed MOMENTS earlier survives it, wedges `git pull --rebase`, and
# then ALSO wedges the `git reset --hard` recovery — surfacing as the opaque
# "update failed (git command exit code 1)".
import subprocess as _sp  # noqa: E402

import messaging.self_update as _su  # noqa: E402

_ISSUE_452_STDERR = (
    "error: update_ref failed for ref 'HEAD': cannot lock ref 'HEAD': Unable to "
    "create '/opt/lm/.git/HEAD.lock': File exists.\n\nAnother git process seems "
    "to be running in this repository, e.g. an editor opened by 'git commit'.\n"
    "Autostash exists; creating a new stash entry.\n"
)


def test_lock_error_detected_from_real_issue_452_output():
    assert _Repo("/x")._looks_like_git_lock_error("", _ISSUE_452_STDERR)


def test_lock_error_not_confused_with_a_real_conflict():
    # A genuine rebase conflict must NOT trigger lock removal + retry.
    conflict = ("CONFLICT (content): Merge conflict in src/app.py\n"
                "error: could not apply 1234abc... some commit\n")
    assert not _Repo("/x")._looks_like_git_lock_error("", conflict)
    assert not _Repo("/x")._looks_like_git_lock_error("", "fatal: could not resolve host")


def _fake_run_sequence(monkeypatch, results):
    """Patch subprocess.run in the mixin's module to pop from ``results``."""
    calls = []

    def _fake(cmd, **kw):
        calls.append(list(cmd))
        rc, out, err = results.pop(0)
        return _sp.CompletedProcess(cmd, rc, out, err)

    monkeypatch.setattr(_su.subprocess, "run", _fake)
    return calls


def test_run_git_clears_lock_and_retries_once(tmp_path, monkeypatch):
    gd = _make_git(tmp_path)
    lk = gd / "HEAD.lock"
    lk.write_text("")  # FRESH — the age-based sweep deliberately leaves it

    calls = _fake_run_sequence(monkeypatch, [
        (1, "", _ISSUE_452_STDERR),   # first pull dies on the lock
        (0, "Updated.", ""),          # retry succeeds once the lock is gone
    ])
    res = _Repo(str(tmp_path))._run_git(["pull", "--rebase"], cwd=str(tmp_path))

    assert res.returncode == 0
    assert not lk.exists(), "the offending lock must be force-cleared"
    assert len(calls) == 2, "exactly one retry"


def test_run_git_does_not_retry_on_non_lock_failure(tmp_path, monkeypatch):
    _make_git(tmp_path)
    calls = _fake_run_sequence(monkeypatch, [(128, "", "fatal: could not resolve host")])
    res = _Repo(str(tmp_path))._run_git(["fetch", "origin"], cwd=str(tmp_path))
    assert res.returncode == 128
    assert len(calls) == 1


def test_run_git_retries_at_most_once_when_lock_persists(tmp_path, monkeypatch):
    # No lock file on disk to remove → nothing was cleared → do NOT retry
    # (prevents hammering git when the lock is held by a live process).
    _make_git(tmp_path)
    calls = _fake_run_sequence(monkeypatch, [(1, "", _ISSUE_452_STDERR)])
    res = _Repo(str(tmp_path))._run_git(["pull", "--rebase"], cwd=str(tmp_path))
    assert res.returncode == 1
    assert len(calls) == 1


# --- _core_update_lock permission fallback (netbox [Errno 13] on the lock FILE) -
import messaging.self_update as _su  # noqa: E402


def test_core_lock_falls_back_when_lock_file_unopenable(tmp_path, monkeypatch):
    """The dir /var/lib/lm exists (makedirs succeeds) but the lock FILE was
    created by root/the hub, so this process gets [Errno 13] opening it. The
    lock must fall back to a repo-local file and still acquire — never abort
    the whole update (the netbox regression)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    real_open, real_makedirs = os.open, os.makedirs

    def _fake_open(path, *a, **k):
        if str(path).startswith("/var/lib/lm"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)

    def _fake_makedirs(path, **k):
        if str(path).startswith("/var/lib/lm"):
            return  # pretend the system dir already exists
        return real_makedirs(path, **k)

    monkeypatch.setattr(_su.os, "open", _fake_open)
    monkeypatch.setattr(_su.os, "makedirs", _fake_makedirs)

    with _Repo(str(repo))._core_update_lock(timeout=5.0) as got:
        assert got is True
    assert (repo / ".lm-state" / "core-update.lock").exists()


def test_core_lock_fail_open_when_no_writable_path(tmp_path, monkeypatch):
    """If NO candidate lock path is openable, fail OPEN (yield True, unserialized)
    rather than bricking the update channel over a perms glitch."""
    def _boom(*a, **k):
        raise PermissionError(13, "denied")
    monkeypatch.setattr(_su.os, "makedirs", lambda *a, **k: None)
    monkeypatch.setattr(_su.os, "open", _boom)
    with _Repo(str(tmp_path))._core_update_lock(timeout=5.0) as got:
        assert got is True


def test_core_lock_safe_swallows_a_raising_lock(tmp_path, monkeypatch):
    """A core lock that RAISES (the netbox `[Errno 13] Permission denied:
    '/var/lib/lm/.lm-core-update.lock'` report) must NOT unwind the update: the
    safe wrapper yields False (skip core) so the component still pulls its OWN
    repo instead of wedging on old code forever."""
    import contextlib

    @contextlib.contextmanager
    def _raises(timeout=300.0):
        raise PermissionError(13, "Permission denied",
                              "/var/lib/lm/.lm-core-update.lock")
        yield True  # pragma: no cover

    r = _Repo(str(tmp_path))
    monkeypatch.setattr(r, "_core_update_lock", _raises)
    with r._core_update_lock_safe(timeout=5.0) as got:
        assert got is False


def test_core_lock_safe_passes_through_and_releases(tmp_path, monkeypatch):
    """When the lock IS obtainable the wrapper is transparent -- it yields the
    real value and still releases on the way out."""
    real_open, real_makedirs = os.open, os.makedirs

    def _fake_open(path, *a, **k):
        if str(path).startswith("/var/lib/lm"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *a, **k)

    def _fake_makedirs(path, **k):
        if str(path).startswith("/var/lib/lm"):
            return
        return real_makedirs(path, **k)

    monkeypatch.setattr(_su.os, "open", _fake_open)
    monkeypatch.setattr(_su.os, "makedirs", _fake_makedirs)
    with _Repo(str(tmp_path))._core_update_lock_safe(timeout=5.0) as got:
        assert got is True
