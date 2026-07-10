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
(ls-remote failure → ``"unknown"``) still delivers a first-time push
best-effort, then defers further re-fires while the tip stays unknown (a long
backstop still nudges a genuinely-stale spoke) so a persistent GitHub
reachability failure doesn't become an update→flap→re-push storm.

These tests stub the I/O surface of ``perform_update`` (version/commit
fetchers, the mailbox push, the git-repo probe) and exercise just the fan-out
loop's gating decisions across cycles.
"""

import asyncio

import pytest

import update_pipeline
from update_pipeline import UpdatePipelineMixin


OPNSENSE_REPO = "https://github.com/lbockenstedt/opnsense.git"

_COOLDOWN_S = 600


class _Clock:
    def __init__(self, start=1_000_000.0):
        self.t = start

    def time(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def patched_clock(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(update_pipeline.time, "time", clock.time)
    return clock


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
        self.pushes = []  # list of (spoke_id, repo_url, branch, extra_data)

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
        self.pushes.append((spoke_id, repo_url, branch, extra_data))
        return None


@pytest.mark.asyncio
async def test_unchanged_tip_skips_push_after_first_cycle(patched_clock):
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert len(hub.pushes) == 1
    assert hub.pushes[0][0] == "lm-opnsense-spoke-1"
    assert hub.state.get_global_config()["spoke_update_commits"] == {
        "lm-opnsense-spoke-1": "cccc1"}
    patched_clock.advance(_COOLDOWN_S + 1)
    await hub.perform_update()
    assert len(hub.pushes) == 1


@pytest.mark.asyncio
async def test_moved_tip_pushes_again(patched_clock):
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert len(hub.pushes) == 1
    hub._remote_tip = "cccc2"  # repo moved
    patched_clock.advance(_COOLDOWN_S + 1)
    await hub.perform_update()
    assert len(hub.pushes) == 2
    assert hub.state.get_global_config()["spoke_update_commits"] == {
        "lm-opnsense-spoke-1": "cccc2"}


@pytest.mark.asyncio
async def test_force_bypasses_gate(patched_clock):
    hub = _StubHub(remote_tip="cccc1")
    await hub.perform_update()
    assert len(hub.pushes) == 1
    await hub.perform_update(force=True)
    assert len(hub.pushes) == 2


@pytest.mark.asyncio
async def test_unknown_tip_does_not_storm_while_blind(patched_clock):
    """Regression: when the remote tip is unresolvable (``ls-remote`` fails →
    ``"unknown"``), the hub must NOT blind-re-fire SPOKE_UPDATE every cooldown.
    Each re-fire restarts the spoke, dumping its pending command queue → the
    hub's CS_INGEST/GET_AGENTS timeouts (the update→flap→re-push storm). A
    first-time push goes through best-effort; subsequent cycles while the tip
    stays unknown are deferred. A long backstop still nudges a genuinely-stale
    spoke if a real update landed that the hub can't see. ``force`` bypasses."""
    blind_backstop = 6 * 3600
    hub = _StubHub(remote_tip="unknown")
    # First cycle: first-time push goes through (no pushed_ts yet).
    await hub.perform_update()
    assert len(hub.pushes) == 1
    assert hub.state.get_global_config().get("spoke_update_commits", {}).get(
        "lm-opnsense-spoke-1") is None  # tip unknown → marker not stamped
    # Cooldown window elapses but tip still unknown → deferred, NOT re-pushed.
    patched_clock.advance(_COOLDOWN_S + 1)
    await hub.perform_update()
    assert len(hub.pushes) == 1
    # Still deferred well inside the blind backstop.
    patched_clock.advance(blind_backstop // 2)
    await hub.perform_update()
    assert len(hub.pushes) == 1
    # Backstop elapses while tip still unknown → nudge a possibly-stale spoke.
    patched_clock.advance(blind_backstop)
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


@pytest.mark.asyncio
async def test_fanout_threads_core_repo_url_and_branch_into_push():
    """The hub must thread ``core_repo_url`` + ``core_branch`` into every pushed
    SPOKE_UPDATE so the spoke pulls the shared /opt/lm core alongside its own
    repo (no CLI for lm/core deploys). With ``update_sources.hub`` set, the
    payload carries the lm repo url + the configured global branch."""
    hub = _StubHub(remote_tip="cccc1")
    hub.state._gc["update_sources"] = {
        "opnsense": OPNSENSE_REPO,
        "hub": "https://github.com/lbockenstedt/lm.git",
    }
    await hub.perform_update()
    assert len(hub.pushes) == 1
    spoke_id, repo_url, branch, extra_data = hub.pushes[0]
    assert branch == "main"
    assert extra_data is not None
    assert extra_data["core_repo_url"] == "https://github.com/lbockenstedt/lm.git"
    assert extra_data["core_branch"] == "main"


@pytest.mark.asyncio
async def test_fanout_core_repo_url_none_when_hub_source_absent():
    """Air-gapped deploy with ``update_sources.hub`` blank → core_repo_url is
    None (NOT a default public URL), so the spoke skips core gracefully. The
    key is still present so the spoke can detect absence vs an old hub that
    never sent it."""
    hub = _StubHub(remote_tip="cccc1")
    # No "hub" key in update_sources (only the spoke's own source).
    await hub.perform_update()
    assert len(hub.pushes) == 1
    _, _, branch, extra_data = hub.pushes[0]
    assert extra_data is not None
    assert extra_data["core_repo_url"] is None
    assert extra_data["core_branch"] == "main"
