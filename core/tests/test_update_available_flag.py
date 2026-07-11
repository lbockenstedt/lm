"""Footer version-dot "update available" flag (update_pipeline + watchdog bridge).

The footer dot used to turn yellow ONLY on ``watchdog.behind`` — the
pulled-but-not-restarted state (on-disk VERSION vs the running-version
sentinel written at startup). It did NOT turn yellow when a newer version was
detected on the REMOTE but not yet pulled (e.g. repo_sync disabled: the audit
detects remote-ahead but no pull runs → disk == running → behind=False → green).
So the dot stayed green while the sentinel had already found a new version.

Fix: ``check_update_health`` now caches ``self._update_available`` from the
local-vs-remote commit comparison (False when remote is unreachable — never
false-yellow on a network blip); ``run_watchdog_bridge_loop`` surfaces it in
``_watchdog_status``; the WebUI dot is yellow on ``behind OR update_available``.
A successful pull clears it (local then equals remote).

These tests pin the flag logic using the same git-I/O-stubbed hub stand-in as
test_update_health_empty_hub.py.
"""
import pytest

import update_pipeline as up
from update_pipeline import UpdatePipelineMixin
from _fakes import FakeState


class _HealthHub(UpdatePipelineMixin):
    """Hub stand-in with the git I/O stubbed so check_update_health's logic is
    exercised without a real checkout / network / systemctl."""

    def __init__(self, global_config, local_commit, remote_commit):
        self.state = FakeState(global_config=global_config)
        self._lc = local_commit
        self._rc = remote_commit

    async def get_local_commit(self):
        return self._lc

    async def get_remote_commit(self, hub_repo=None, branch=None):
        return self._rc

    async def get_local_version(self):
        return "v.01"

    def _is_git_repo(self, path):
        return True


def _no_systemctl(monkeypatch):
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)


_HUB_URL = "https://github.com/lbockenstedt/lm.git"


@pytest.mark.asyncio
async def test_remote_ahead_sets_update_available(monkeypatch):
    # The sentinel found a newer remote → flag True → footer dot turns yellow
    # EVEN THOUGH nothing has been pulled yet (disk == running == v.01).
    h = _HealthHub({"update_sources": {"hub": _HUB_URL}},
                   local_commit="aaa", remote_commit="bbb")
    _no_systemctl(monkeypatch)
    await h.check_update_health()
    assert h._update_available is True


@pytest.mark.asyncio
async def test_remote_equal_clears_update_available(monkeypatch):
    # Local == remote → no update pending → False (also the post-pull state).
    h = _HealthHub({"update_sources": {"hub": _HUB_URL}},
                   local_commit="aaa", remote_commit="aaa")
    _no_systemctl(monkeypatch)
    # Seed True to prove the check CLEARS it (not just leaves it unset).
    h._update_available = True
    await h.check_update_health()
    assert h._update_available is False


@pytest.mark.asyncio
async def test_remote_unreachable_never_false_yellows(monkeypatch):
    # git ls-remote failed → remote "unknown". Must NOT flag update_available
    # (a network blip must not turn the dot yellow). behind=False too → green.
    h = _HealthHub({"update_sources": {"hub": _HUB_URL}},
                   local_commit="aaa", remote_commit="unknown")
    _no_systemctl(monkeypatch)
    await h.check_update_health()
    assert h._update_available is False


@pytest.mark.asyncio
async def test_local_unknown_never_false_yellows(monkeypatch):
    # Unresolved local HEAD → can't confirm an update → False.
    h = _HealthHub({"update_sources": {"hub": _HUB_URL}},
                   local_commit="unknown", remote_commit="bbb")
    _no_systemctl(monkeypatch)
    await h.check_update_health()
    assert h._update_available is False


def test_update_available_defaults_false_before_first_check():
    # The bridge loop reads getattr(self, "_update_available", False) so a hub
    # that hasn't run check_update_health yet (just booted, repo_sync staggered
    # 30s) reports False — no false-yellow, no AttributeError.
    h = _HealthHub({"update_sources": {"hub": _HUB_URL}}, "aaa", "bbb")
    assert getattr(h, "_update_available", False) is False