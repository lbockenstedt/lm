"""Regression: the per-spoke SPOKE_UPDATE fan-out must be gated on each
spoke's repo tip actually moving, not pushed every cycle.

Before the gate, ``perform_update`` fanned a SPOKE_UPDATE to every approved
spoke on EVERY 15-min cycle regardless of whether that spoke's repo had
changed. On the cs spoke that ran an inline ``git pull`` in its SPOKE_UPDATE
handler, the no-op pull still blocked the event loop long enough to time out
``CS_GET_USB_CONFIG`` and stall auto-provisioning — even though ``cs.git`` had
nothing new.

The fix records the remote tip SHA we last pushed to each spoke
(``global_config["spoke_update_commits"][spoke_id]``) and skips the push when
the tip hasn't moved since. ``force`` bypasses the gate; an unresolvable tip
(ls-remote failure → ``"unknown"``) falls back to push-always so a transient
network blip doesn't permanently silence a spoke.

These tests stub the I/O surface of ``perform_update`` (version/commit
fetchers, the mailbox push, the git-repo probe) and exercise just the fan-out
loop's gating decisions across cycles.
"""

import asyncio

import pytest

from update_pipeline import UpdatePipelineMixin


OPNSENSE_REPO = "https://github.com/lbockenstedt/opnsense.git"


class _State:
    def __init__(self, global_config):
        self.system_state = {
            "module_metadata": {"lm-opnsense-spoke-1": {"module_type": "firewall"}},
        }
        self._gc = dict(global_config)

    def ensure_admin_lockout(self):
        return False

    def get_global_config(self):
        return self._gc

    def update_global_config(self, patch):
        self._gc.update(patch)

    def save_state(self):
        pass


class _StubHub(UpdatePipelineMixin):
    """Drives only the fan-out loop of perform_update: hub self-update is
    held at 'up to date' (local==remote commit) so the snapshot/git-pull
    branch never runs."""

    def __init__(self, remote_tip):
        self.state = _State({
            "update_sources": {"opnsense": OPNSENSE_REPO},
            "global_branch": "main",
        })
        self.approved_modules = {"lm-opnsense-spoke-1": True}
        self.spoke_module_types = {}  # offline → persisted-fallback path
        self._remote_tip = remote_tip  # "unknown" simulates ls-remote failure
        # Connectivity gate: the marker only advances for a spoke we can deliver
        # to live. Default the spoke connected; the offline test clears it.
        self.active_connections = {"lm-opnsense-spoke-1": object()}
        self.pushes = []  # (spoke_id, repo_url, branch)

    async def get_local_version(self):
        return "v.01"

    async def get_remote_version(self):
        return "v.01"

    async def get_local_commit(self):
        return "aaa"  # == remote → hub up to date → skip hub pull

    async def get_remote_commit(self, repo_url=None, branch=None):
        # The hub's own remote_commit call passes the configured hub repo
        # (sources.hub, defaulting to lbockenstedt/lm) → "aaa" so the hub
        # reads up-to-date and the snapshot/git-pull branch is skipped. The
        # spoke fan-out calls this with the spoke's repo_url → canned tip.
        if repo_url is None or "lbockenstedt/lm" in (repo_url or ""):
            return "aaa"
        return self._remote_tip

    def _is_git_repo(self, path):
        return False

    async def _push_spoke_update(self, spoke_id, repo_url, branch,
                                 msg_type="SPOKE_UPDATE", extra_data=None):
        self.pushes.append((spoke_id, repo_url, branch))
        return None


@pytest.mark.asyncio
async def test_unchanged_tip_skips_push_after_first_cycle():
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    # First cycle: no recorded tip → push.
    assert len(hub.pushes) == 1
    assert hub.pushes[0][0] == "lm-opnsense-spoke-1"
    assert hub.state.get_global_config()["spoke_update_commits"] == {
        "lm-opnsense-spoke-1": "cccc1"}

    # Second cycle: same tip → skip (no new push, no result mutation).
    await hub.perform_update()
    assert len(hub.pushes) == 1


@pytest.mark.asyncio
async def test_moved_tip_pushes_again():
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert len(hub.pushes) == 1

    hub._remote_tip = "cccc2"  # repo moved
    await hub.perform_update()
    assert len(hub.pushes) == 2
    assert hub.state.get_global_config()["spoke_update_commits"] == {
        "lm-opnsense-spoke-1": "cccc2"}


@pytest.mark.asyncio
async def test_force_bypasses_gate():
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert len(hub.pushes) == 1

    # Same tip, but force=True → re-push anyway.
    await hub.perform_update(force=True)
    assert len(hub.pushes) == 2


@pytest.mark.asyncio
async def test_unknown_tip_falls_back_to_push_always():
    """ls-remote failed (private repo / network) → can't gate → push every
    cycle so a transient failure doesn't permanently silence the spoke."""
    hub = _StubHub(remote_tip="unknown")
    await hub.perform_update()
    assert len(hub.pushes) == 1
    # No tip recorded (we never learned it) → next cycle still can't gate.
    assert "spoke_update_commits" not in hub.state.get_global_config()
    await hub.perform_update()
    assert len(hub.pushes) == 2

@pytest.mark.asyncio
async def test_offline_spoke_is_deferred_not_falsely_marked():
    """Stranding regression: a spoke that is OFFLINE during the cycle the tip
    advances must NOT be recorded as pushed — otherwise the old per-repo marker
    said 'done' and the spoke never retried once it reconnected. It must be
    deferred (no push, no marker) and then pushed on a later connected cycle."""
    hub = _StubHub(remote_tip="cccc1")
    hub.active_connections = {}  # spoke offline
    await hub.perform_update()
    # Deferred: nothing pushed, and NO marker recorded for it (so it retries).
    assert hub.pushes == []
    assert hub.state.get_global_config().get("spoke_update_commits", {}).get(
        "lm-opnsense-spoke-1") is None

    # Spoke reconnects → next cycle delivers live and records the marker.
    hub.active_connections = {"lm-opnsense-spoke-1": object()}
    await hub.perform_update()
    assert len(hub.pushes) == 1
    assert hub.state.get_global_config()["spoke_update_commits"][
        "lm-opnsense-spoke-1"] == "cccc1"


@pytest.mark.asyncio
async def test_stale_marker_pruned_when_spoke_unapproved():
    """A marker for a spoke that's no longer approved is dropped so the map
    can't grow unbounded and a re-added spoke isn't wrongly skipped."""
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert hub.state.get_global_config()["spoke_update_commits"] == {
        "lm-opnsense-spoke-1": "cccc1"}
    # Unapprove the spoke → its marker is pruned next cycle.
    hub.approved_modules = {}
    await hub.perform_update()
    assert hub.state.get_global_config()["spoke_update_commits"] == {}
