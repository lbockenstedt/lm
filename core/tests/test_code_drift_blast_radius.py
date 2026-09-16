"""Blast-radius containment in the code-drift watchdog.

A role-hosting agent runs the base agent plus one ``RoleConnection`` per loaded
role in ONE process — commonly 10 control planes sharing an event loop, a
``/opt/lm`` checkout and a PID — and ``BaseControlPlane.run`` arms this watchdog
on every one of them. Live evidence from ``mipbe-lmagent``: 1766 "watchdog
armed" lines across 195 process starts (~9 per boot), and all 8 drift firings
named ``/opt/lm`` — the SHARED core repo.

That is the restart loop: ``_draining`` / ``_spoke_update_in_progress`` are
per-INSTANCE, so while one control plane pulled ``/opt/lm`` its 9 in-process
peers each saw their own flag False, observed the HEAD move that pull was
creating, and exited the process mid-``git pull`` — leaving the half-finished
rebase the next boot had to ``reset --hard`` out of.

Pins here:
  * the drain guard is process-wide (any peer updating blocks every exit),
  * it is re-checked AFTER the git read, closing the same window the await opens,
  * exactly one watchdog per directory per process polls + acts,
  * ownership is released when a watchdog stops (an unloaded role must not
    strand ``/opt/lm`` unwatched),
  * a role-scoped drift reloads just that role, and any failure there still
    falls back to the process restart (stale code never keeps serving).
"""
import asyncio
import os
import subprocess
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging import code_drift_watchdog as cdw  # noqa: E402
from messaging.code_drift_watchdog import CodeDriftWatchdogMixin  # noqa: E402


class _Consumer(CodeDriftWatchdogMixin):
    """Mirrors a BaseControlPlane peer: the two layout hooks + the drain flags."""

    def __init__(self, repo, core=None):
        self._repo = repo
        self._core = core
        self._draining = False
        self._spoke_update_in_progress = False
        self._stop = False
        self.reloaded = []
        self.role_for_dir = {}
        self.reload_result = True

    def _repo_root(self):
        return self._repo

    def _resolve_core_root(self):
        return self._core

    async def _flush_log_relay_async(self, timeout=2.0):
        pass

    def _drift_role_for_dir(self, d):
        return self.role_for_dir.get(os.path.abspath(str(d)))

    async def _reload_role_for_drift(self, role, d):
        self.reloaded.append(role)
        if isinstance(self.reload_result, Exception):
            raise self.reload_result
        return self.reload_result


@pytest.fixture(autouse=True)
def _clean_registries():
    """The registries are module-level (process-wide by design) — isolate tests."""
    cdw._DRIFT_PEERS.clear()
    cdw._DRIFT_DIR_OWNERS.clear()
    yield
    cdw._DRIFT_PEERS.clear()
    cdw._DRIFT_DIR_OWNERS.clear()


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True)


def _make_repo(path):
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q")
    _git(path, "config", "user.email", "t@t.t")
    _git(path, "config", "user.name", "t")
    (path / "f.txt").write_text("1")
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", "one")
    return path


def _commit(path, text):
    (path / "f.txt").write_text(text)
    _git(path, "add", "-A")
    _git(path, "commit", "-qm", text)


class _Exited(BaseException):
    """Models process death: derived from BaseException so it propagates past
    the loop's ``except Exception`` guard, exactly as a real ``os._exit`` would
    stop the loop dead rather than letting it fire again next cycle."""


@pytest.fixture
def exits(monkeypatch):
    """Capture os._exit instead of killing the test process."""
    seen = []

    def _fake_exit(code):
        seen.append(code)
        raise _Exited()

    monkeypatch.setattr(cdw.os, "_exit", _fake_exit)
    return seen


async def _run_cycles(consumer, repo, mutate, exits, *, interval=0.05):
    """Arm the watchdog, let it baseline, mutate the repo, let it react."""
    task = asyncio.create_task(consumer._code_drift_watchdog(interval_s=interval))
    for _ in range(100):  # wait for the baseline to be published
        if getattr(consumer, "_drift_baseline", None):
            break
        await asyncio.sleep(0.01)
    mutate()
    await asyncio.sleep(interval * 6)
    consumer._stop = True
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, _Exited, Exception):
        pass
    return exits


# ── the production failure: a peer's pull must not exit the process ──────────

@pytest.mark.asyncio
async def test_peer_update_in_flight_blocks_exit(tmp_path, exits):
    """A DIFFERENT control plane in this process is mid-update, so the HEAD move
    it is creating must not exit the process. This is the mipbe-lmagent loop."""
    repo = _make_repo(tmp_path / "core")
    watcher = _Consumer(str(repo))
    puller = _Consumer(str(repo))
    cdw._DRIFT_PEERS.add(puller)
    puller._spoke_update_in_progress = True  # the peer doing the git pull

    await _run_cycles(watcher, repo, lambda: _commit(repo, "2"), exits)
    assert exits == [], "exited the process while an in-process peer was updating"


@pytest.mark.asyncio
async def test_drift_exits_when_no_peer_is_updating(tmp_path, exits):
    """Counterpart: with no peer updating, a genuine drift still restarts —
    the guard must not have disabled the watchdog outright."""
    repo = _make_repo(tmp_path / "core")
    watcher = _Consumer(str(repo))

    await _run_cycles(watcher, repo, lambda: _commit(repo, "2"), exits)
    assert exits == [3]


@pytest.mark.asyncio
async def test_peer_draining_also_blocks_exit(tmp_path, exits):
    """``_draining`` on a peer counts too (the self-update path sets it while it
    pulls, before the restart)."""
    repo = _make_repo(tmp_path / "core")
    watcher = _Consumer(str(repo))
    peer = _Consumer(str(repo))
    cdw._DRIFT_PEERS.add(peer)
    peer._draining = True

    await _run_cycles(watcher, repo, lambda: _commit(repo, "2"), exits)
    assert exits == []


@pytest.mark.asyncio
async def test_peer_that_starts_updating_during_the_git_read_blocks_exit(
        tmp_path, exits):
    """The guard is re-checked AFTER ``git rev-parse`` awaits. Without the second
    check, a peer that begins updating during that await slips through the
    window the first check just closed.

    The peer flag is set from ``_drift_owns_dir`` — which runs INSIDE the cycle,
    after the first guard has already passed — and only once the drift exists,
    so the first guard cannot be what absorbs it."""
    repo = _make_repo(tmp_path / "core")
    watcher = _Consumer(str(repo))
    peer = _Consumer(str(repo))
    cdw._DRIFT_PEERS.add(peer)

    drift_made = False
    real_owns = watcher._drift_owns_dir

    def _own_then_start_update(key):
        got = real_owns(key)
        if drift_made:  # the peer begins its pull mid-cycle
            peer._spoke_update_in_progress = True
        return got

    watcher._drift_owns_dir = _own_then_start_update

    task = asyncio.create_task(watcher._code_drift_watchdog(interval_s=0.05))
    for _ in range(100):
        if getattr(watcher, "_drift_baseline", None):
            break
        await asyncio.sleep(0.01)
    assert peer._spoke_update_in_progress is False
    _commit(repo, "2")
    drift_made = True
    await asyncio.sleep(0.4)
    watcher._stop = True
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, _Exited, Exception):
        pass
    assert peer._spoke_update_in_progress is True, "test never armed the peer"
    assert exits == []


@pytest.mark.asyncio
async def test_no_git_reads_while_a_peer_is_updating(tmp_path, exits):
    """The pre-read guard is a LOAD control, distinct from the post-read guard
    that provides correctness: during an update wave the other ~9 watchdogs must
    not each spawn `git rev-parse` against the repo being pulled. Pinned by
    counting the per-directory work the guard is supposed to skip."""
    repo = _make_repo(tmp_path / "core")
    watcher = _Consumer(str(repo))
    peer = _Consumer(str(repo))
    cdw._DRIFT_PEERS.add(peer)
    peer._spoke_update_in_progress = True

    calls = []
    real_owns = watcher._drift_owns_dir
    watcher._drift_owns_dir = lambda k: (calls.append(k), real_owns(k))[1]

    task = asyncio.create_task(watcher._code_drift_watchdog(interval_s=0.05))
    await asyncio.sleep(0.35)  # several cycles
    watcher._stop = True
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, _Exited, Exception):
        pass
    assert calls == [], f"polled the repo {len(calls)}x during a peer's update"


# ── one checker per directory per process ────────────────────────────────────

def test_only_one_watchdog_owns_a_directory(tmp_path):
    """~10 watchdogs in one process polled the same repos and raced to exit.
    The first to claim a directory owns it; the rest skip it."""
    repo = _make_repo(tmp_path / "core")
    a, b = _Consumer(str(repo)), _Consumer(str(repo))
    key = str(repo)
    assert a._drift_owns_dir(key) is True
    assert a._drift_owns_dir(key) is True, "owner must keep its claim"
    assert b._drift_owns_dir(key) is False, "a second watchdog must not also act"


def test_ownership_is_released_when_a_watchdog_stops(tmp_path):
    """An unloaded role's watchdog must hand /opt/lm back, or the repo is left
    unwatched for the life of the process."""
    repo = _make_repo(tmp_path / "core")
    a, b = _Consumer(str(repo)), _Consumer(str(repo))
    key = str(repo)
    assert a._drift_owns_dir(key) is True
    assert b._drift_owns_dir(key) is False
    a._drift_release_dirs()
    assert b._drift_owns_dir(key) is True, "successor could not take over"


@pytest.mark.asyncio
async def test_watchdog_releases_dirs_on_cancel(tmp_path, exits):
    """The release runs in the loop's ``finally`` — cancellation is how a role
    teardown stops it."""
    repo = _make_repo(tmp_path / "core")
    a = _Consumer(str(repo))
    task = asyncio.create_task(a._code_drift_watchdog(interval_s=0.05))
    for _ in range(100):
        if getattr(a, "_drift_baseline", None):
            break
        await asyncio.sleep(0.01)
    await asyncio.sleep(0.12)
    assert cdw._DRIFT_DIR_OWNERS, "nothing was claimed"
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, _Exited, Exception):
        pass
    assert _Consumer(str(repo))._drift_owns_dir(str(repo)) is True


# ── role-scoped drift ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_role_repo_drift_reloads_only_that_role(tmp_path, exits):
    """A single role's sibling repo advancing reloads that role in place; the
    other roles in the process keep running (no exit)."""
    repo = _make_repo(tmp_path / "dnsrepo")
    c = _Consumer(str(repo))
    c.role_for_dir = {os.path.abspath(str(repo)): "dns"}

    await _run_cycles(c, repo, lambda: _commit(repo, "2"), exits)
    assert c.reloaded == ["dns"]
    assert exits == [], "reloading one role must not restart the process"


@pytest.mark.asyncio
async def test_failed_role_reload_falls_back_to_process_restart(tmp_path, exits):
    """Fail-safe: a targeted reload that does not succeed must still restart, or
    freshly-pulled code keeps being served by the old class."""
    repo = _make_repo(tmp_path / "dnsrepo")
    c = _Consumer(str(repo))
    c.role_for_dir = {os.path.abspath(str(repo)): "dns"}
    c.reload_result = False

    await _run_cycles(c, repo, lambda: _commit(repo, "2"), exits)
    assert c.reloaded == ["dns"]
    assert exits == [3]


@pytest.mark.asyncio
async def test_raising_role_reload_falls_back_to_process_restart(tmp_path, exits):
    """Same fail-safe when the reload raises rather than returning False."""
    repo = _make_repo(tmp_path / "dnsrepo")
    c = _Consumer(str(repo))
    c.role_for_dir = {os.path.abspath(str(repo)): "dns"}
    c.reload_result = RuntimeError("boom")

    await _run_cycles(c, repo, lambda: _commit(repo, "2"), exits)
    assert exits == [3]


@pytest.mark.asyncio
async def test_reloaded_role_is_not_reloaded_again_on_the_next_cycle(
        tmp_path, exits):
    """The absorbed drift re-baselines, otherwise the watchdog would reload the
    same role every cycle forever."""
    repo = _make_repo(tmp_path / "dnsrepo")
    c = _Consumer(str(repo))
    c.role_for_dir = {os.path.abspath(str(repo)): "dns"}

    task = asyncio.create_task(c._code_drift_watchdog(interval_s=0.05))
    for _ in range(100):
        if getattr(c, "_drift_baseline", None):
            break
        await asyncio.sleep(0.01)
    _commit(repo, "2")
    await asyncio.sleep(0.5)  # many cycles
    c._stop = True
    task.cancel()
    try:
        await task
    except (asyncio.CancelledError, _Exited, Exception):
        pass
    assert c.reloaded == ["dns"], f"reloaded repeatedly: {c.reloaded}"
    assert exits == []


def test_default_hooks_keep_whole_process_restart():
    """Consumers that cannot do targeted reloads (every plain spoke, the
    device-mode agent) keep the historical behaviour."""
    assert CodeDriftWatchdogMixin._drift_role_for_dir(object(), "/anything") is None
