"""Feature (b): the spoke-side push path. When an agent-hosting spoke receives
``SPOKE_UPDATE`` (hub→spoke update), it forwards ``AGENT_UPDATE`` to its
connected device-mode agents BEFORE pulling its own repo + restarting — so the
Update button / auto-update / BugFixer reaches the device-mode agents too, not
just the spoke. Each agent then pulls its own repo + arms its rollback watchdog
+ ``os._exit(3)``s, symmetric with the spoke's own ``SPOKE_UPDATE``.

Pins: ``_push_agent_update_to_devices`` fans ``AGENT_UPDATE`` via
``send_raw_to_agent`` (fire-and-forget — the agent exits before responding, so
awaiting a response would time out), forwards the SAME
{repo_url, core_repo_url, core_branch} the hub sent (for an agent-hosting spoke
these point at the lm repo, which IS the device-mode agent's own repo), is a
no-op when no agents are connected or no repo_url was threaded, and never lets
one gone/erroring agent break the fan-out. The ``SPOKE_UPDATE`` intercept
forwards THEN delegates to the base (the spoke's own pull).
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402


class _Host(AgentHostingControlPlane):
    """Bypass the heavy BaseControlPlane.__init__ — set only what the push path
    touches, and record send_raw_to_agent calls instead of hitting a socket."""

    def __init__(self):
        self.connected_agents = {}
        self._sent = []  # list of (agent_id, cmd_type, payload)
        self._super_called = None
        self._draining = False
        self._spoke_update_in_progress = False

    async def send_raw_to_agent(self, agent_id, cmd_type, data):
        self._sent.append((agent_id, cmd_type, dict(data)))
        return True

    async def _super_handle(self, cmd_type, data):
        # Stand-in for BaseControlPlane.handle_system_command so the SPOKE_UPDATE
        # intercept's `super().handle_system_command(...)` doesn't run the real
        # git pull + os._exit(3). Records that it was delegated.
        self._super_called = (cmd_type, dict(data))
        return {"status": "SUCCESS", "message": "delegated to base"}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_push_fans_agent_update_to_all_connected_devices():
    """Two connected device-mode agents both receive AGENT_UPDATE with the
    forwarded repo_url/core_repo_url/core_branch."""
    h = _Host()
    h.connected_agents = {"dev-1": {"ws": object()}, "dev-2": {"ws": object()}}
    _run(h._push_agent_update_to_devices({
        "repo_url": "https://example/lm.git",
        "core_repo_url": "https://example/lm.git",
        "core_branch": "main",
    }))
    assert len(h._sent) == 2
    aids = {a for a, _, _ in h._sent}
    assert aids == {"dev-1", "dev-2"}
    for _, cmd, payload in h._sent:
        assert cmd == "AGENT_UPDATE"
        assert payload["repo_url"] == "https://example/lm.git"
        assert payload["core_repo_url"] == "https://example/lm.git"
        assert payload["core_branch"] == "main"


def test_push_is_noop_when_no_agents_connected():
    h = _Host()
    h.connected_agents = {}
    _run(h._push_agent_update_to_devices({"repo_url": "https://x/lm.git"}))
    assert h._sent == []


def test_push_is_noop_when_no_repo_url_threaded():
    """No repo_url (e.g. an older hub that didn't thread one) → don't fire a
    useless AGENT_UPDATE at the agents; leave them on current code."""
    h = _Host()
    h.connected_agents = {"dev-1": {"ws": object()}}
    _run(h._push_agent_update_to_devices({"core_repo_url": "https://x/lm.git"}))
    assert h._sent == []


def test_push_skips_a_gone_agent_without_breaking_the_fanout():
    """One agent whose send raises is skipped; the rest still receive the
    update — the fan-out is best-effort per agent, never all-or-nothing."""
    h = _Host()
    h.connected_agents = {"bad": {"ws": object()}, "good": {"ws": object()}}
    calls = []

    async def _send(agent_id, cmd_type, data):
        calls.append(agent_id)
        if agent_id == "bad":
            raise RuntimeError("agent gone")
        h._sent.append((agent_id, cmd_type, dict(data)))
        return True
    h.send_raw_to_agent = _send

    _run(h._push_agent_update_to_devices({"repo_url": "https://x/lm.git"}))
    assert set(calls) == {"bad", "good"}
    assert len(h._sent) == 1 and h._sent[0][0] == "good"


def test_spoke_update_intercept_forwards_then_delegates_to_base(monkeypatch):
    """``handle_system_command("SPOKE_UPDATE", ...)`` forwards AGENT_UPDATE to
    the device-mode agents, THEN delegates to the base class so the spoke pulls
    its own repo + restarts. Both happen on a single SPOKE_UPDATE."""
    h = _Host()
    h.connected_agents = {"dev-1": {"ws": object()}}
    # Replace the real super().handle_system_command with our stand-in so the
    # test doesn't run a real git pull + os._exit(3).
    monkeypatch.setattr(
        "messaging.control_plane.BaseControlPlane.handle_system_command",
        lambda self, cmd, data: h._super_handle(cmd, data))
    res = _run(h.handle_system_command("SPOKE_UPDATE", {
        "repo_url": "https://example/lm.git",
        "core_repo_url": "https://example/lm.git",
        "core_branch": "main",
    }))
    # AGENT_UPDATE was forwarded to the device-mode agent.
    assert len(h._sent) == 1 and h._sent[0][1] == "AGENT_UPDATE"
    # The base class (the spoke's own pull) was ALSO invoked.
    assert h._super_called is not None
    assert h._super_called[0] == "SPOKE_UPDATE"
    assert h._super_called[1]["repo_url"] == "https://example/lm.git"
    assert res["status"] == "SUCCESS"


def test_non_update_command_does_not_forward():
    """A non-SPOKE_UPDATE command must NOT trigger the AGENT_UPDATE fan-out
    (only SPOKE_UPDATE does)."""
    h = _Host()
    h.connected_agents = {"dev-1": {"ws": object()}}
    # SET_LOG_LEVEL broadcasts to agents via the existing path; it must not also
    # fan AGENT_UPDATE. Use the real super for this one — it handles
    # SET_LOG_LEVEL without git/exit (returns SUCCESS + broadcasts).
    import messaging.control_plane as cp
    # Stub the broadcast so it doesn't try to talk to sockets.
    h.broadcast_to_agents = lambda *a, **k: _noop_coro()
    res = _run(h.handle_system_command("SET_LOG_LEVEL", {"enabled": False}))
    assert h._sent == []  # no AGENT_UPDATE forwarded
    assert res["status"] == "SUCCESS"


async def _noop_coro():
    return []


def test_non_update_command_passes_through_unchanged(monkeypatch):
    """Sanity: an arbitrary command still delegates to the base unchanged."""
    h = _Host()
    monkeypatch.setattr(
        "messaging.control_plane.BaseControlPlane.handle_system_command",
        lambda self, cmd, data: h._super_handle(cmd, data))
    res = _run(h.handle_system_command("HUB_PING", {"nonce": "n"}))
    assert h._super_called[0] == "HUB_PING"
    assert h._sent == []
    assert res["status"] == "SUCCESS"