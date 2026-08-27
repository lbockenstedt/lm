"""Edge-proxy bind resilience on :443 (ProxySpoke._ensure_web_server).

A self-update / systemd restart can briefly overlap with the outgoing proxy
that still holds the port, so the successor's first bind can hit EADDRINUSE
(errno 98). The listener must retry a few times and come up once the
predecessor drains — instead of logging one hard error and leaving the tenant
with NO front door until the next hub poll re-triggers the ensure.
"""
import asyncio
import errno
import os
import sys

import pytest

pytest.importorskip("aiohttp")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import proxy_spoke  # noqa: E402


class _FakeRunner:
    def __init__(self, app, access_log=None):
        self.app = app

    async def setup(self):
        pass

    async def cleanup(self):
        pass


def _install_fakes(monkeypatch, fail_times):
    """Patch aiohttp web AppRunner/TCPSite so the first ``fail_times`` binds
    raise EADDRINUSE, then succeed. Returns a list recording start attempts."""
    import aiohttp.web as web
    attempts = []
    state = {"left": fail_times}

    class _FakeSite:
        def __init__(self, runner, host, port, ssl_context=None):
            self.host, self.port = host, port

        async def start(self):
            attempts.append((self.host, self.port))
            if state["left"] > 0:
                state["left"] -= 1
                raise OSError(errno.EADDRINUSE, "address already in use")

        async def stop(self):
            pass

    monkeypatch.setattr(web, "AppRunner", _FakeRunner)
    monkeypatch.setattr(web, "TCPSite", _FakeSite)
    monkeypatch.setattr(proxy_spoke, "build_proxy_app", lambda self: object())
    # Keep the retry loop instant.
    async def _nosleep(*_a, **_k):
        return None
    monkeypatch.setattr(proxy_spoke.asyncio, "sleep", _nosleep)
    return attempts


def _bare_spoke():
    sp = proxy_spoke.ProxySpoke.__new__(proxy_spoke.ProxySpoke)
    sp.web_host, sp.web_port = "0.0.0.0", 443
    sp.tls_cert = sp.tls_key = None  # → plain HTTP, no real cert needed
    sp.upstream_url = "wss://hub:443/ws/spoke"
    sp._proxy_app = sp._runner = sp._site = sp._bind = None
    return sp


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_bind_retries_then_succeeds(monkeypatch):
    # Predecessor holds :443 for the first two attempts, then releases.
    attempts = _install_fakes(monkeypatch, fail_times=2)
    sp = _bare_spoke()
    _run(sp._ensure_web_server())
    assert sp._site is not None            # recovered — front door is up
    assert sp._bind == (sp.web_host, sp.web_port, None, None)
    assert len(attempts) == 3              # 2 busy + 1 success


def test_bind_gives_up_after_max_attempts(monkeypatch):
    # Port never frees — bail after the bounded retries, leaving no site (so a
    # later hub poll re-triggers the ensure) rather than looping forever.
    attempts = _install_fakes(monkeypatch, fail_times=99)
    sp = _bare_spoke()
    _run(sp._ensure_web_server())
    assert sp._site is None
    assert len(attempts) == proxy_spoke._BIND_MAX_ATTEMPTS
