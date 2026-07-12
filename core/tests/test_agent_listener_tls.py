"""Tests for the agent-listener TLS hook + rebind (fix 2 base).

``AgentHostingControlPlane._agent_listener_tls_paths`` is the seam a subclass
(cs ``CSControlPlane``) overrides to point the ``/ws/agent`` 443 listener at the
persisted LE cert applied by ``_apply_local_cert`` — so an INSTALL_CERT covers
both the 8080 webui AND the 443 agent listener (agents dial
``wss://<spoke>:443/ws/agent``; without the override the agent leg keeps the
old/self-signed cert after a renew).

``_rebind_agent_server`` restarts the listener mid-run so a cert renewed after
serve-start is actually served (``run_agent_server`` reads the cert once at
serve-start). It mirrors the cs 8080-webui ``_rebind_api_server``.

These tests use a minimal harness that bypasses the heavy
``BaseControlPlane.__init__`` (same shape as ``test_agent_hosting_frame_decode``
``_Host``) and stubs ``_start_agent_server_task`` so no real websocket server is
bound.
"""
import asyncio
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging.agent_hosting import AgentHostingControlPlane  # noqa: E402


class _Host(AgentHostingControlPlane):
    """Bypass BaseControlPlane.__init__; record _start_agent_server_task calls."""

    def __init__(self, enabled=True):
        self._enabled = enabled
        self._agent_server_task = None
        self.started = 0

    def _agent_listener_enabled(self):
        return self._enabled

    def _start_agent_server_task(self):
        # Record instead of actually serving.
        self.started += 1
        async def _noop():
            await asyncio.Future()
        self._agent_server_task = asyncio.create_task(_noop())


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# ── _agent_listener_tls_paths (default = env) ───────────────────────────────

def test_agent_listener_tls_paths_default_reads_env(monkeypatch):
    monkeypatch.setenv("LM_TLS_CERT", "/etc/lm/tls/fullchain.pem")
    monkeypatch.setenv("LM_TLS_KEY", "/etc/lm/tls/privkey.pem")
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == "/etc/lm/tls/fullchain.pem"
    assert key == "/etc/lm/tls/privkey.pem"


def test_agent_listener_tls_paths_default_empty_when_no_env(monkeypatch):
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == ""
    assert key == ""


# ── _rebind_agent_server ────────────────────────────────────────────────────

def test_rebind_cancels_old_and_restarts_when_enabled():
    """A running listener task is cancelled and a fresh one is started so the
    new cert is served. Connected agents drop + reconnect (agent_id stable)."""
    async def _go():
        host = _Host(enabled=True)
        # Pre-existing long-running listener task simulating a live serve loop.
        async def _long():
            await asyncio.Future()
        host._agent_server_task = asyncio.create_task(_long())
        old = host._agent_server_task
        await AgentHostingControlPlane._rebind_agent_server(host)
        assert old.cancelled() or old.done()
        assert host.started == 1
        assert host._agent_server_task is not None
        assert host._agent_server_task is not old
        host._agent_server_task.cancel()
    _run(_go())


def test_rebind_noop_when_listener_not_enabled():
    """An opt-in spoke (cs without LM_CS_AGENT_LISTENER=1) never ran the
    listener → rebind must not start one."""
    async def _go():
        host = _Host(enabled=False)
        async def _long():
            await asyncio.Future()
        host._agent_server_task = asyncio.create_task(_long())
        old = host._agent_server_task
        await AgentHostingControlPlane._rebind_agent_server(host)
        assert host.started == 0
        # Old task still cancelled (clear stale state) but no new one started.
        assert host._agent_server_task is None
        assert old.cancelled() or old.done()
    _run(_go())


def test_rebind_starts_when_no_prior_task_and_enabled():
    async def _go():
        host = _Host(enabled=True)
        host._agent_server_task = None
        await AgentHostingControlPlane._rebind_agent_server(host)
        assert host.started == 1
        assert host._agent_server_task is not None
        host._agent_server_task.cancel()
    _run(_go())


def test_rebind_with_already_done_old_task_does_not_raise():
    """If the old task already exited (self-heal between cycles), rebind must
    not choke awaiting it — just start fresh."""
    async def _go():
        host = _Host(enabled=True)
        async def _quick():
            return
        t = asyncio.create_task(_quick())
        await t  # completes immediately
        host._agent_server_task = t
        await AgentHostingControlPlane._rebind_agent_server(host)
        assert host.started == 1
        host._agent_server_task.cancel()
    _run(_go())