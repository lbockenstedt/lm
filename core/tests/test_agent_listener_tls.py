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


def test_agent_listener_tls_paths_default_empty_when_no_env(monkeypatch, tmp_path):
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.delenv("LM_AGENT_LISTENER_LE_DOMAIN", raising=False)
    # Point LE discovery at an empty dir so the result is deterministic and does
    # not depend on the test host having /etc/letsencrypt/live populated.
    monkeypatch.setenv("LM_LE_LIVE_DIR", str(tmp_path))
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == ""
    assert key == ""


# ── _agent_listener_tls_paths (on-disk LE fallback) ─────────────────────────

def _make_le_cert(live_dir, domain):
    d = live_dir / domain
    d.mkdir(parents=True)
    fc = d / "fullchain.pem"
    pk = d / "privkey.pem"
    fc.write_text("CERT")
    pk.write_text("KEY")
    return str(fc), str(pk)


def test_agent_listener_tls_paths_le_fallback_discovers_cert(monkeypatch, tmp_path):
    """No LM_TLS_CERT env, but the co-located le role has a live cert on disk →
    the listener discovers it so it comes up wss instead of plaintext."""
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.delenv("LM_AGENT_LISTENER_LE_DOMAIN", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", str(tmp_path))
    fc, pk = _make_le_cert(tmp_path, "*.orange-tme.com")
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == fc
    assert key == pk


def test_agent_listener_tls_paths_env_wins_over_le(monkeypatch, tmp_path):
    """An explicitly provisioned LM_TLS_CERT takes precedence over the on-disk
    LE fallback."""
    monkeypatch.setenv("LM_TLS_CERT", "/etc/lm/tls/fullchain.pem")
    monkeypatch.setenv("LM_TLS_KEY", "/etc/lm/tls/privkey.pem")
    monkeypatch.setenv("LM_LE_LIVE_DIR", str(tmp_path))
    _make_le_cert(tmp_path, "*.orange-tme.com")
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == "/etc/lm/tls/fullchain.pem"
    assert key == "/etc/lm/tls/privkey.pem"


def test_agent_listener_tls_paths_le_domain_override(monkeypatch, tmp_path):
    """LM_AGENT_LISTENER_LE_DOMAIN pins which live cert dir is served."""
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", str(tmp_path))
    _make_le_cert(tmp_path, "*.orange-tme.com")
    fc, pk = _make_le_cert(tmp_path, "lm-agent.ext.orange-tme.com")
    monkeypatch.setenv("LM_AGENT_LISTENER_LE_DOMAIN", "lm-agent.ext.orange-tme.com")
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == fc
    assert key == pk


def test_agent_listener_tls_paths_le_incomplete_pair_ignored(monkeypatch, tmp_path):
    """A cert dir missing privkey.pem is not returned (would fail load_cert_chain)."""
    monkeypatch.delenv("LM_TLS_CERT", raising=False)
    monkeypatch.delenv("LM_TLS_KEY", raising=False)
    monkeypatch.delenv("LM_AGENT_LISTENER_LE_DOMAIN", raising=False)
    monkeypatch.setenv("LM_LE_LIVE_DIR", str(tmp_path))
    d = tmp_path / "*.orange-tme.com"
    d.mkdir(parents=True)
    (d / "fullchain.pem").write_text("CERT")  # no privkey.pem
    host = _Host()
    cert, key = AgentHostingControlPlane._agent_listener_tls_paths(host)
    assert cert == ""
    assert key == ""


def test_wss_port_default_is_443():
    """The pxmx standalone listener defaults to 443 (the NSG-allowed port), not
    8443 — hub-self and cs override this, so only pxmx is affected."""
    assert AgentHostingControlPlane.AGENT_WSS_PORT == 443


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