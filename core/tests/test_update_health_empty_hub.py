"""check_update_health: empty update_sources.hub is LOUD, not silent.

Regression for the silent-stale-hub bug: a present-but-empty
``update_sources.hub`` made ``perform_update`` run ``git ls-remote ""`` →
``"unknown"`` → the gate returned "checked" every cycle, while the OLD
``if hub_repo:`` guard in ``check_update_health`` SKIPPED the remote probe
entirely so the box reported ``ok`` with no warning. The hub sat un-updated
at an old SHA, origin advanced, and the next-cycle backstop fix was stranded
behind the very loop it was meant to protect.

The fix resolves empty/missing ``hub`` to the default and probes REGARDLESS,
WARNing on the mis-config (so it is LOUD) while keeping updates working via
the fallback. These tests pin that behavior with the git I/O stubbed.
"""

import pytest

import update_pipeline as up
from update_pipeline import UpdatePipelineMixin
from _fakes import FakeState


class _HealthHub(UpdatePipelineMixin):
    """Hub stand-in with the git I/O stubbed so check_update_health's logic
    is exercised without a real checkout / network / systemctl."""

    def __init__(self, global_config, local_commit, remote_commit):
        # FakeState.get_global_config() returns the `global_config` ctor arg
        # (NOT system_state["global_config"]), so thread it through here.
        self.state = FakeState(global_config=global_config)
        self._lc = local_commit
        self._rc = remote_commit

    async def get_local_commit(self):
        return self._lc

    async def get_remote_commit(self, hub_repo=None, branch=None):
        # Mirrors the fix: callers pass the RESOLVED repo (default when empty),
        # so the probe runs regardless of the configured value.
        return self._rc

    async def get_local_version(self):
        return "v.01"

    def _is_git_repo(self, path):
        return True


@pytest.mark.asyncio
async def test_empty_hub_warns_misconfig_and_probes_behind(monkeypatch):
    # THE BUG: hub="" used to skip the remote probe silently (ok, no warning).
    # Now it warns on the mis-config AND still detects behind via the default.
    h = _HealthHub({"update_sources": {"hub": ""}},
                   local_commit="aaa", remote_commit="bbb")
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)  # no systemctl

    health = await h.check_update_health()
    warnings = health["warnings"]

    assert any("update_sources.hub is empty/missing" in w for w in warnings), warnings
    # The probe ran against the resolved default and saw the remote ahead.
    assert any("BEHIND" in w for w in warnings), warnings
    assert health["checks"]["remote_commit"] == "bbb"


@pytest.mark.asyncio
async def test_missing_hub_key_warns_misconfig_and_probes(monkeypatch):
    # Absent key behaves the same as empty (both fall back to default + warn).
    h = _HealthHub({"update_sources": {}}, local_commit="aaa", remote_commit="bbb")
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)

    health = await h.check_update_health()
    assert any("update_sources.hub is empty/missing" in w for w in health["warnings"])
    assert any("BEHIND" in w for w in health["warnings"])


@pytest.mark.asyncio
async def test_set_hub_does_not_warn_misconfig(monkeypatch):
    # A real URL suppresses the mis-config warning; behind is still reported.
    h = _HealthHub({"update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"}},
                   local_commit="aaa", remote_commit="bbb")
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)

    health = await h.check_update_health()
    assert not any("empty/missing" in w for w in health["warnings"]), health["warnings"]
    assert any("BEHIND" in w for w in health["warnings"])


@pytest.mark.asyncio
async def test_set_hub_up_to_date_no_warnings(monkeypatch):
    h = _HealthHub({"update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"}},
                   local_commit="aaa", remote_commit="aaa")
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)

    health = await h.check_update_health()
    assert not any("empty/missing" in w for w in health["warnings"])
    assert not any("BEHIND" in w for w in health["warnings"])


# ── stale process → FORCE watchdog sentinel (never gated to the maint window) ──
# Regression for the recurring "I keep getting stale hubs" shape: a fix lands on
# disk mid-day but the running process is behind, and the stale-restart was
# gated to the 02:00 maintenance window (non-force sentinel) → the fix sat
# UNLOADED for hours. Staleness is an ERROR state, not planned maintenance: the
# sentinel must be FORCE so the watchdog bypasses the gate and reloads within
# one ~60s cycle, day or night.

async def _disk_v502():
    return "v.502"


@pytest.mark.asyncio
async def test_stale_process_writes_force_sentinel(monkeypatch):
    h = _HealthHub({"update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"}},
                   local_commit="aaa", remote_commit="aaa")
    h._startup_version = "v.483"      # running process is BEHIND on-disk v.502
    h.get_local_version = _disk_v502  # disk version
    captured = []
    h._request_watchdog_restart = lambda reason, force=False: captured.append((reason, force))
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)  # no systemctl

    health = await h.check_update_health()

    assert any("STALE" in e for e in health["errors"]), health["errors"]
    assert len(captured) == 1, captured
    reason, force = captured[0]
    assert force is True, "stale-restart sentinel must be FORCE (bypass the gate)"
    assert "v.483" in reason and "v.502" in reason, reason


@pytest.mark.asyncio
async def test_fresh_process_writes_no_stale_sentinel(monkeypatch):
    # Running version == on-disk version → not stale → NO sentinel (so the
    # fresh process can't restart-loop). Pins the no-loop half of the fix.
    h = _HealthHub({"update_sources": {"hub": "https://github.com/lbockenstedt/lm.git"}},
                   local_commit="aaa", remote_commit="aaa")
    h._startup_version = "v.502"      # matches disk → fresh
    h.get_local_version = _disk_v502
    captured = []
    h._request_watchdog_restart = lambda reason, force=False: captured.append((reason, force))
    monkeypatch.setattr(up.shutil, "which", lambda *a: None)

    health = await h.check_update_health()

    assert not any("STALE" in e for e in health["errors"]), health["errors"]
    assert captured == [], captured