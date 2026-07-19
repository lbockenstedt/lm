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

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        pass

    async def save_state_now(self):
        self.save_state()


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


class _VerHub(_StubHub):
    """Stub that also reports a spoke's running .NN and the repo's latest .NN, so
    the version-evidence override (a spoke believed-current by the SHA marker but
    provably running OLD code) can be exercised deterministically."""

    def __init__(self, remote_tip, running_ver, latest_ver):
        super().__init__(remote_tip)
        self.spoke_versions = {"lm-opnsense-spoke-1": running_ver}
        self._latest_ver = latest_ver

    def latest_version_for_module(self, module_type):
        return self._latest_ver


@pytest.mark.asyncio
async def test_stale_at_tip_repushes_on_backstop_not_cooldown(patched_clock):
    """The 'delivered but never applied' strand. last_pushed[sid]==tip advances
    on DELIVERY to a connected spoke (a proxy for 'applied'). If that push never
    landed (lost mailbox msg on a hub restart, failed git pull, WS drop mid-send)
    the spoke keeps running OLD code while the hub believes it is current and
    never retries. When the spoke's reported .NN is provably older than the
    repo's latest .NN, the SHA up-to-date skip must be OVERRIDDEN — but the
    corrective re-push is rate-limited to the LONG backstop, not the 600s
    cooldown, so a genuinely broken/rolled-back update can't storm-restart it."""
    backstop = 6 * 3600
    hub = _VerHub(remote_tip="cccc1", running_ver=".10", latest_ver=".20")
    # First cycle: marker != tip -> normal push; marker recorded == tip.
    await hub.perform_update()
    assert len(hub.pushes) == 1
    assert hub.state.get_global_config()["spoke_update_commits"][
        "lm-opnsense-spoke-1"] == "cccc1"
    # Cooldown elapses; spoke STILL reports .10 (never applied). at_tip+behind ->
    # the backstop governs, so it is deferred, NOT re-pushed at the cooldown.
    patched_clock.advance(_COOLDOWN_S + 1)
    await hub.perform_update()
    assert len(hub.pushes) == 1
    # Backstop elapses -> one corrective re-push.
    patched_clock.advance(backstop)
    await hub.perform_update()
    assert len(hub.pushes) == 2


@pytest.mark.asyncio
async def test_confirmed_current_version_still_skipped(patched_clock):
    """A spoke at tip whose reported .NN MATCHES the repo's latest is genuinely
    current -> still skipped as up-to-date (the override only fires on provable
    behindness; it must never manufacture an extra push for a current spoke)."""
    hub = _VerHub(remote_tip="cccc1", running_ver=".20", latest_ver=".20")
    await hub.perform_update()
    assert len(hub.pushes) == 1  # first push (marker != tip yet)
    patched_clock.advance(_COOLDOWN_S + 1)
    await hub.perform_update()
    assert len(hub.pushes) == 1  # at_tip and not behind -> up-to-date skip


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


def test_default_repo_for_missing_update_sources_keys():
    """Regression: a module_key absent from update_sources must NOT strand its
    spokes with 'no repo configured'. The base agents + in-repo roles ('agent'
    key) resolve to the lm/hub repo; sibling keys (le, cppm) derive from the hub
    owner. This is why lm-agent / lm-svcs / lm-agent-le showed 'no repo configured'."""
    from update_pipeline import _default_repo_for_key
    hub = "https://github.com/lbockenstedt/lm.git"
    sources = {"hub": hub}
    assert _default_repo_for_key("agent", sources) == hub
    assert _default_repo_for_key("le", sources) == "https://github.com/lbockenstedt/le.git"
    assert _default_repo_for_key("cppm", sources) == "https://github.com/lbockenstedt/cppm.git"
    assert _default_repo_for_key("", sources) is None


LM_REPO = "https://github.com/lbockenstedt/lm.git"
_AGENT_UUID = "5db1754b-1234-4321-abcd-000000000001"


@pytest.mark.asyncio
async def test_agent_spokes_split_out_of_module_updates_display(patched_clock):
    """Regression: agent-typed approved spokes (generic agents — guid-armed on
    first connect so their approved_modules id is a UUID, module_type "agent")
    are fanned out here on the schedule because they need SPOKE_UPDATE with the
    full version-gate / cooldown / blind-backstop that ``update_agents_only``
    lacks. But they are NOT module spokes, so they must NOT appear in the
    ``spokes`` list (the WebUI "Module updates" card) — otherwise the card shows
    a wall of agent UUID rows (the "16 UUIDs all triggered" symptom). Agent
    result rows go to a separate ``agents`` list; the push still happens."""
    hub = _StubHub(remote_tip="cccc1")
    hub.state._gc["update_sources"] = {
        "opnsense": OPNSENSE_REPO,
        "agent": LM_REPO,
        "hub": LM_REPO,
    }
    # An approved generic agent: UUID id, module_type "agent" via the PERSISTED
    # module_metadata fallback (the live spoke_module_types map is popped on
    # disconnect, so an offline/ghost agent resolves through this — exactly
    # the path that produced the stray UUID rows).
    hub.approved_modules[_AGENT_UUID] = True
    hub.state.system_state["module_metadata"][_AGENT_UUID] = {"module_type": "agent"}
    hub.active_connections[_AGENT_UUID] = object()

    result = await hub.perform_update()

    # Both were fanned out — the agent STILL gets its scheduled SPOKE_UPDATE
    # (gating intact); only the DISPLAY is split.
    assert len(hub.pushes) == 2
    assert {p[0] for p in hub.pushes} == {"lm-opnsense-spoke-1", _AGENT_UUID}

    spokes = result.get("spokes") or []
    agents = result.get("agents") or []
    # The module spoke shows in "spokes" (Module updates).
    assert any("lm-opnsense-spoke-1" in r for r in spokes)
    # The agent does NOT pollute the module-spokes list…
    assert all(_AGENT_UUID not in r for r in spokes)
    # …it is reported in the separate "agents" list instead.
    assert any(_AGENT_UUID in r for r in agents)
    assert all("lm-opnsense-spoke-1" not in r for r in agents)


CS_REPO = "https://github.com/lbockenstedt/cs.git"
_RELAYED_CS_AGENT = "cs-svr-02-agent"


@pytest.mark.asyncio
async def test_relayed_cs_agent_without_metadata_not_fanned_out(patched_clock):
    """Regression: a relayed node-agent (pxmx per-host agent) approved via the
    WebUI ``approve_agent_under_spoke`` path is persisted in approved_modules
    with its hostname id but NO module_metadata (that path bypasses
    register_module; relayed agents guid-arm in agent_config, not
    approved_modules, so they stay hostname-keyed). Its id contains "cs" →
    without a registered-spoke guard it substring-matches the "cs" prefix →
    resolves to the cs repo → fanned out as a cs module spoke → an extra
    "cs-svr-02-agent: triggered" row in Module Updates (plus a useless
    SPOKE_UPDATE to a relayed agent it can't act on). Skip approved_modules
    ids with no module_metadata entry — a legit module spoke ALWAYS has one.
    Relayed node-agents update via their parent spoke (AGENT_UPDATE)."""
    hub = _StubHub(remote_tip="cccc1")
    hub.state._gc["update_sources"] = {
        "opnsense": OPNSENSE_REPO,
        "cs": CS_REPO,
        "hub": LM_REPO,
    }
    # Relayed CS agent: approved (hostname id), deliberately NO module_metadata.
    hub.approved_modules[_RELAYED_CS_AGENT] = True
    hub.active_connections[_RELAYED_CS_AGENT] = object()

    result = await hub.perform_update()

    pushed_ids = {p[0] for p in hub.pushes}
    # The relayed agent is SKIPPED — not fanned out, not shown anywhere.
    assert _RELAYED_CS_AGENT not in pushed_ids
    spokes = result.get("spokes") or []
    agents = result.get("agents") or []
    assert all(_RELAYED_CS_AGENT not in r for r in spokes)
    assert all(_RELAYED_CS_AGENT not in r for r in agents)
    # The legit module spoke still fans out normally.
    assert "lm-opnsense-spoke-1" in pushed_ids
