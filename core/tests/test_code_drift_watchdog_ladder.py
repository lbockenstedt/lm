"""Feature (a): the code-drift watchdog LOOP behavior — the parts the (c)
composition tests (``test_code_drift_watchdog_mixin.py``) don't drive: the
watchdog actually ``os._exit(3)``s when a watched repo's on-disk HEAD advances
AHEAD of the running process; a repo that first appears AFTER boot (a role
loaded at runtime) is BASELINED (not treated as drift + exited on); and a
self-update in flight (``_draining``) suppresses the exit. The (c) tests cover
``_drift_watched_dirs`` composition + the ``_stop`` loop guard; these cover the
remaining ladder invariants.

Driven with a fake ``git rev-parse`` (a per-dir call index over a controllable
HEAD sequence) + a fake ``asyncio.sleep`` (counts ticks, sets ``_stop`` after
``ticks``) + record-only ``os._exit`` (raises a ``BaseException`` sentinel so a
single ``asyncio.run`` progresses the whole ladder).
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging import code_drift_watchdog as cdw  # noqa: E402
from messaging.code_drift_watchdog import CodeDriftWatchdogMixin  # noqa: E402


class _Stop(BaseException):
    """Breaks the watchdog ``while not _stop`` loop — derived from
    BaseException so the loop's broad ``except Exception`` doesn't swallow it."""


class _Consumer(CodeDriftWatchdogMixin):
    """Drives the watchdog loop with a controllable set of watched git dirs.
    Mirrors a device-mode SpokeClient: has ``_stop`` (the loop honors it),
    provides the hooks, no-ops the log flush.

    ``delay_first_watch``: when True, the FIRST call to ``_drift_watched_dirs``
    (the boot baseline pass) returns [] and later calls return the full set —
    so a repo that first appears AFTER boot is baselined on its first sighting
    rather than treated as drift."""

    def __init__(self, repos, delay_first_watch=False):
        self._repos = {os.path.abspath(p): list(v) for p, v in repos.items()}
        self._stop = False
        self._draining = False
        self._spoke_update_in_progress = False
        self._delay_first_watch = delay_first_watch
        self._watch_calls = 0
        # real .git marker dirs so the mixin's _drift_watched_dirs filter keeps them
        for p in self._repos:
            os.makedirs(os.path.join(p, ".git"), exist_ok=True)

    def _repo_root(self):
        return next(iter(self._repos)) if self._repos else "/nonexistent"

    def _resolve_core_root(self):
        return None  # single-repo consumer; core composition covered by (c) tests

    def _drift_watched_dirs(self):
        self._watch_calls += 1
        if self._delay_first_watch and self._watch_calls == 1:
            return []  # boot baseline sees nothing; repo appears tick 1
        return list(self._repos)

    async def _flush_log_relay_async(self, timeout=2.0):
        pass


class _FakeProc:
    returncode = 0

    def __init__(self, out):
        self._out = out

    async def communicate(self):
        return (self._out, b"")


def _drive(c, ticks, monkeypatch, heads):
    """Run ``_code_drift_watchdog`` for ``ticks`` ticks. ``heads`` is a dict
    abspath -> list[bytes]; the baseline pass consumes index 0, tick N consumes
    index N (last value is sticky). ``os._exit`` records the code + raises
    ``_Stop`` so the loop breaks on a drift exit instead of killing the process."""
    exits = []
    idx = {d: 0 for d in heads}
    state = {"n": 0, "max": ticks}

    async def _fake_exec(*args, **kw):
        d = args[2]  # ("git", "-C", <path>, "rev-parse", "HEAD")
        i = idx[d]
        val = heads[d][i] if i < len(heads[d]) else heads[d][-1]
        idx[d] = min(i + 1, len(heads[d]) - 1)
        return _FakeProc(val)

    async def _fake_sleep(_s):
        state["n"] += 1
        if state["n"] > state["max"]:
            c._stop = True

    def _record(code):
        exits.append(code)

    def _raise_stop():
        raise _Stop()

    monkeypatch.setattr(cdw.asyncio, "create_subprocess_exec", _fake_exec)
    monkeypatch.setattr(cdw.asyncio, "sleep", _fake_sleep)
    # wait_for must return the awaitable so `await` runs the fake proc's communicate
    monkeypatch.setattr(cdw.asyncio, "wait_for", lambda aw, timeout=None: aw)
    monkeypatch.setattr(cdw.os, "_exit",
                        lambda code=0: (_record(code), _raise_stop())[1])
    try:
        asyncio.run(c._code_drift_watchdog(interval_s=0.01))
    except _Stop:
        pass
    return exits


# ── exit-on-advance (the pulled-but-not-restarted trap) ─────────────────────

def test_exit_on_head_advance(tmp_path, monkeypatch):
    """A watched repo whose HEAD advances past the baseline → os._exit(3) so
    systemd ``Restart=on-failure`` reloads the current code (the pulled-but-
    not-restarted trap the watchdog exists to close)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    c = _Consumer({str(repo): ["aaa", "aaa", "bbb"]})  # stable, then advance
    heads = {os.path.abspath(str(repo)): [b"aaa\n", b"aaa\n", b"bbb\n"]}
    exits = _drive(c, 3, monkeypatch, heads)
    assert exits == [3]                          # advanced → exited


def test_no_exit_when_head_unchanged(tmp_path, monkeypatch):
    """A stable HEAD (no advance across all ticks) → the loop keeps running,
    no exit — the watchdog only fires on an AHEAD advance."""
    repo = tmp_path / "repo"
    repo.mkdir()
    c = _Consumer({str(repo): ["aaa", "aaa", "aaa"]})
    heads = {os.path.abspath(str(repo)): [b"aaa\n", b"aaa\n", b"aaa\n"]}
    exits = _drive(c, 3, monkeypatch, heads)
    assert exits == []                            # stable → never exited


# ── newly-watched repo is baselined, not treated as drift ───────────────────

def test_newly_watched_repo_is_baselined_not_drift(tmp_path, monkeypatch):
    """A repo that first appears AFTER boot (a role loaded at runtime) is
    BASELINED on its first sighting — not treated as drift + exited on. Its
    HEAD in later ticks equals the baseline → still no exit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    # delay_first_watch: boot baseline sees []; the repo first appears tick 1.
    c = _Consumer({str(repo): ["aaa", "aaa", "aaa"]}, delay_first_watch=True)
    heads = {os.path.abspath(str(repo)): [b"aaa\n", b"aaa\n", b"aaa\n"]}
    exits = _drive(c, 3, monkeypatch, heads)
    assert exits == []                            # first-seen baselined; no drift


def test_advance_after_baseline_of_new_repo_exits(tmp_path, monkeypatch):
    """The new-repo baseline is real: a SUBSEQUENT advance on that repo (after
    it was baselined at first sighting) DOES exit — so a runtime-loaded role's
    later pull is caught, not silently absorbed by the baseline pass."""
    repo = tmp_path / "repo"
    repo.mkdir()
    c = _Consumer({str(repo): ["aaa", "aaa", "bbb"]}, delay_first_watch=True)
    heads = {os.path.abspath(str(repo)): [b"aaa\n", b"aaa\n", b"bbb\n"]}
    exits = _drive(c, 3, monkeypatch, heads)
    assert exits == [3]                           # baselined tick1, advanced tick3 → exit


# ── skip while a self-update is in flight ───────────────────────────────────

def test_skip_while_draining(tmp_path, monkeypatch):
    """A self-update in flight (``_draining``) suppresses the exit — the update
    path advances HEAD on purpose + restarts itself; don't race it with a
    second exit. A HEAD advance while draining must NOT exit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    c = _Consumer({str(repo): ["aaa", "aaa", "bbb"]})
    c._draining = True
    heads = {os.path.abspath(str(repo)): [b"aaa\n", b"aaa\n", b"bbb\n"]}
    exits = _drive(c, 3, monkeypatch, heads)
    assert exits == []                            # draining → skipped, no exit