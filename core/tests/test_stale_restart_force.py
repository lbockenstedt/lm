"""perform_update restart sentinel: staleness FORCES, routine auto stays GATED.

Regression for the "I keep getting stale hubs" fix. The hub's restart sentinel
(``_request_watchdog_restart``) is consumed by the root ``lm-watchdog``, which
gates a NON-force sentinel to the maintenance window (default 02:00) but
restarts immediately on a FORCE sentinel. Two behaviors must hold:

1. A STALE-reload (git current but the running process is behind on-disk
   VERSION — the recurring shape where a fix landed on disk mid-day but sat
   UNLOADED for hours) must write a FORCE sentinel so the watchdog reloads
   within one ~60s cycle, day or night. Staleness is an ERROR state, not
   planned maintenance.

2. A routine auto ``hub_updated`` (the scheduled repo_sync pulled a real hub
   change, ``force=False``) must stay NON-force — GATED to the maintenance
   window. That's the only path the gate is meant to defer, and the fix must
   NOT widen it.

A manual click (``force=True``) forces regardless (the "Update now" / "Sync
now" button does what its name says).

These drive ``perform_update`` end-to-end (git I/O + spoke fan-out stubbed)
to the restart branch and assert the sentinel's ``force`` flag per the
``force=(stale_reload or bool(force))`` expression.
"""

import pytest

import update_pipeline as up
from update_pipeline import UpdatePipelineMixin


# ── state stand-in (FakeState + ensure_admin_lockout for perform_update) ─────

class _State:
    def __init__(self, global_config):
        self.system_state = {"module_metadata": {}}
        self._gc = dict(global_config)
        self.data_dir = None   # _save_sessions reads state.data_dir pre-restart

    def ensure_admin_lockout(self):
        return False

    def get_global_config(self):
        return self._gc

    def update_global_config(self, patch):
        self._gc.update(patch)

    def save_state(self):
        pass


# ── hub stand-in ─────────────────────────────────────────────────────────────

class _RestartHub(UpdatePipelineMixin):
    """Drives perform_update to the restart branch with the git I/O, snapshot,
    self-restart helper, and watchdog sentinel stubbed. approved_modules is
    EMPTY so the spoke fan-out loop is a no-op (the restart sentinel is the
    only thing under test here)."""

    def __init__(self, *, startup_version=None, local_commit="aaa",
                 remote_commit="aaa", disk_version="v.502"):
        self.state = _State({
            "update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"},
            "global_branch": "main",
        })
        self.approved_modules = {}        # no spoke fan-out
        self.spoke_module_types = {}
        self.active_connections = {}
        self._startup_version = startup_version
        self._local_commit = local_commit
        self._remote_commit = remote_commit
        self._disk_version = disk_version
        self.restart_sentinels = []       # (reason, force) captured

    async def get_local_version(self):
        return self._disk_version

    async def get_remote_version(self):
        return self._disk_version

    async def get_local_commit(self):
        return self._local_commit

    async def get_remote_commit(self, repo_url=None, branch=None):
        # The hub's own probe (hub repo) → canned remote; spokes never ask
        # (approved_modules empty).
        return self._remote_commit

    def _is_git_repo(self, path):
        return True

    async def _git_update(self, hub_root, hub_repo, branch):
        return True   # simulate a successful git pull → hub_updated=True

    def _request_watchdog_restart(self, reason, force=False):
        self.restart_sentinels.append((reason, force))


@pytest.fixture
def _no_io(monkeypatch):
    """Stub the snapshot/recovery helpers + subprocess so perform_update's
    hub-updated path runs without touching disk, network, or systemd."""
    monkeypatch.setattr(up, "is_version_bad", lambda v: False)
    monkeypatch.setattr(up, "clear_bad_versions_older_than", lambda v: None)
    monkeypatch.setattr(up, "snapshot_code", lambda *a, **k: "/tmp/backup-dummy")
    monkeypatch.setattr(up, "write_pending", lambda *a, **k: None)
    monkeypatch.setattr(up, "clear_pending", lambda *a, **k: None)
    # The self-restart helper + lm-dns/lm-dhcp restart Popen must NOT run.
    monkeypatch.setattr(up.subprocess, "Popen", lambda *a, **k: None)


# ── stale-reload forces (the fix) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stale_reload_forces_sentinel(_no_io):
    # Git current (local==remote) → else branch → process STALE (running v.483
    # vs on-disk v.502) → stale_reload=True. force=False (auto) MUST STILL force
    # — staleness is an error state, not planned maintenance.
    hub = _RestartHub(startup_version="v.483", local_commit="aaa",
                      remote_commit="aaa", disk_version="v.502")
    await hub.perform_update(force=False)
    assert len(hub.restart_sentinels) == 1, hub.restart_sentinels
    reason, force = hub.restart_sentinels[0]
    assert reason == "stale-reload->restart"
    assert force is True, "stale-reload must FORCE (bypass the maintenance gate)"


@pytest.mark.asyncio
async def test_manual_force_on_stale_process_forces(_no_io):
    # A manual click (force=True) on a process that's stale-but-git-current:
    # force=True makes _update_available report update_available=True regardless,
    # so the git-pull branch runs (hub_updated=True), NOT the stale_reload else.
    # The sentinel is still FORCE (force=(stale_reload=False or True)=True) —
    # i.e. the "Update now" button forces the reload even when git is current.
    hub = _RestartHub(startup_version="v.483", local_commit="aaa",
                      remote_commit="aaa", disk_version="v.502")
    await hub.perform_update(force=True)
    assert len(hub.restart_sentinels) == 1, hub.restart_sentinels
    reason, force = hub.restart_sentinels[0]
    assert reason == "update->restart"
    assert force is True


# ── routine auto hub_updated stays GATED (regression guard) ─────────────────

@pytest.mark.asyncio
async def test_routine_hub_updated_auto_is_non_force_gated(_no_io):
    # Remote ahead (local!=remote) → update_available → _git_update returns
    # True → hub_updated=True, stale_reload=False, force=False (auto). The
    # sentinel MUST be NON-force so the watchdog defers to the maintenance
    # window — the gate's one intended deferral path, preserved by the fix.
    hub = _RestartHub(startup_version="v.502", local_commit="aaa",
                      remote_commit="bbb", disk_version="v.502")
    await hub.perform_update(force=False)
    assert len(hub.restart_sentinels) == 1, hub.restart_sentinels
    reason, force = hub.restart_sentinels[0]
    assert reason == "update->restart"
    assert force is False, "routine auto hub_updated must stay GATED (non-force)"


@pytest.mark.asyncio
async def test_manual_force_with_routine_hub_updated_forces(_no_io):
    # Same routine pull, but a manual click (force=True) → FORCE (the button
    # does what its name says).
    hub = _RestartHub(startup_version="v.502", local_commit="aaa",
                      remote_commit="bbb", disk_version="v.502")
    await hub.perform_update(force=True)
    assert len(hub.restart_sentinels) == 1
    reason, force = hub.restart_sentinels[0]
    assert reason == "update->restart"
    assert force is True


# ── fresh + up-to-date → NO sentinel (no restart loop) ──────────────────────

@pytest.mark.asyncio
async def test_fresh_up_to_date_writes_no_sentinel(_no_io):
    # Git current AND process current (startup == disk) → no hub_updated, no
    # stale_reload → restart branch skipped → NO sentinel. Pins the no-loop
    # half: a fresh process can't restart-loop itself.
    hub = _RestartHub(startup_version="v.502", local_commit="aaa",
                      remote_commit="aaa", disk_version="v.502")
    await hub.perform_update(force=False)
    assert hub.restart_sentinels == [], hub.restart_sentinels