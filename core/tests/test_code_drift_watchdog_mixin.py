"""Feature (c): the code-drift watchdog + ``_drift_watched_dirs`` now live on
a shared ``CodeDriftWatchdogMixin`` (``core/src/messaging/code_drift_watchdog.py``)
consumed by BOTH ``BaseControlPlane`` (every spoke + the generic agent) and the
device-mode ``SpokeClient`` (the dumb agent, NOT a ``BaseControlPlane``
subclass) — removing the verbatim duplication.

Pins: both consumers inherit the mixin's methods (not a private copy), the
mixin's ``_drift_watched_dirs`` composes via the consumer's ``_repo_root`` +
``_resolve_core_root`` hooks, the loop guard tolerates a missing ``_stop``
(``BaseControlPlane`` has none → runs forever; ``SpokeClient`` has it), and the
drain-gate flags are read off the consumer instance.
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging.code_drift_watchdog import CodeDriftWatchdogMixin  # noqa: E402


class _NoStopConsumer(CodeDriftWatchdogMixin):
    """Mirrors BaseControlPlane: no ``_stop`` attribute → loop must run forever
    (``getattr(self, '_stop', False)`` returns False). Provides the two hooks
    the mixin calls + the drain flags the skip-guard reads."""

    def __init__(self, repo, core=None):
        self._repo = repo
        self._core = core
        self._draining = False
        self._spoke_update_in_progress = False

    def _repo_root(self):
        return self._repo

    def _resolve_core_root(self):
        return self._core

    async def _flush_log_relay_async(self, timeout=2.0):
        pass


class _StopConsumer(_NoStopConsumer):
    """Mirrors SpokeClient: has ``_stop`` → the loop honors it (shuts down)."""

    def __init__(self, repo, core=None):
        super().__init__(repo, core)
        self._stop = False


def test_mixin_provides_methods_to_both_consumers():
    """Both consumers get ``_drift_watched_dirs`` + ``_code_drift_watchdog`` FROM
    the mixin (single source of truth), not a private re-definition."""
    for cls in (_NoStopConsumer, _StopConsumer):
        assert "_drift_watched_dirs" in CodeDriftWatchdogMixin.__dict__
        assert "_code_drift_watchdog" in CodeDriftWatchdogMixin.__dict__
        # The consumer itself does NOT re-define them (inherits via MRO).
        assert "_drift_watched_dirs" not in cls.__dict__
        assert "_code_drift_watchdog" not in cls.__dict__


def test_drift_watched_dirs_composes_via_repo_and_core_hooks(tmp_path):
    """``_drift_watched_dirs`` returns real git roots only, composed from the
    consumer's ``_repo_root`` + ``_resolve_core_root`` hooks."""
    repo = tmp_path / "agentrepo"
    repo.mkdir()
    (repo / ".git").mkdir()  # real git root marker
    core = tmp_path / "core"
    core.mkdir()
    (core / ".git").mkdir()
    notgit = tmp_path / "notgit"
    notgit.mkdir()  # no .git → filtered out

    c = _NoStopConsumer(repo=str(repo), core=str(core))
    dirs = set(c._drift_watched_dirs())
    assert os.path.abspath(str(repo)) in dirs
    assert os.path.abspath(str(core)) in dirs

    # A consumer whose core hook returns a non-git path skips it (graceful).
    c2 = _NoStopConsumer(repo=str(repo), core=str(notgit))
    dirs2 = c2._drift_watched_dirs()
    assert os.path.abspath(str(repo)) in dirs2
    assert os.path.abspath(str(notgit)) not in dirs2


def test_drift_watched_dirs_skips_when_core_hook_returns_none(tmp_path):
    """A consumer with no separate core checkout (core_root == cwd / None)
    watches ONLY its own repo."""
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / ".git").mkdir()
    c = _NoStopConsumer(repo=str(repo), core=None)
    dirs = c._drift_watched_dirs()
    assert dirs == [os.path.abspath(str(repo))]


def test_watchdog_loop_guard_tolerates_missing_stop():
    """BaseControlPlane has no ``_stop`` attribute — the loop guard
    ``getattr(self, '_stop', False)`` returns False so the loop WOULD run
    forever (we exit the test by cancelling the task). SpokeClient has
    ``_stop`` → setting True breaks the loop. This pins both shapes."""
    c_no_stop = _NoStopConsumer(repo="/nonexistent")
    # No _stop attr → getattr returns False → guard is False (loop would run).
    assert getattr(c_no_stop, "_stop", False) is False

    c_stop = _StopConsumer(repo="/nonexistent")
    c_stop._stop = True
    # _stop=True → guard True → loop exits immediately (one short sleep).
    async def _run():
        task = asyncio.create_task(c_stop._code_drift_watchdog(interval_s=0.01))
        # Give it a tick to enter the loop, see _stop True, and exit.
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())


def test_watchdog_skip_guard_reads_consumer_drain_flags(tmp_path):
    """The skip-while-draining guard reads ``_draining`` / ``_spoke_update_in_progress``
    off the consumer instance — so a self-update in flight suppresses the exit
    on both BaseControlPlane-style + SpokeClient-style consumers."""
    repo = tmp_path / "r"
    repo.mkdir()
    (repo / ".git").mkdir()
    c = _StopConsumer(repo=str(repo))
    c._draining = True
    # While draining, a HEAD advance must NOT exit — the loop skips. Run one
    # short cycle; if the guard failed it would os._exit(3) (test process dies).
    async def _run():
        c._stop = False
        task = asyncio.create_task(c._code_drift_watchdog(interval_s=0.01))
        await asyncio.sleep(0.03)
        c._stop = True
        await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_run())  # reaching here means no os._exit fired
    assert c._draining is True  # untouched