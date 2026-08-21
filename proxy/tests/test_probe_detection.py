"""Edge HTTPS-port scanner detection on the reverse proxy (proxy_app/_dispatch).

A scan of the proxy (a path we never serve) is detected at the edge, reported up
the authenticated tunnel to the hub (HTTP_PROBE_REPORT) so the hub blocks the
source centrally, and answered with a bare 404 instead of being forwarded. The
per-node ``probe_detection`` toggle can silence it.
"""
import asyncio
import os
import sys
import types

import pytest

pytest.importorskip("aiohttp")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import proxy_app  # noqa: E402
import proxy_spoke  # noqa: E402


class _FakeReq:
    def __init__(self, path, method="GET", remote="203.0.113.9", headers=None):
        self.path = path
        self.method = method
        self.remote = remote
        self.headers = headers or {}


# ── source-IP resolution ────────────────────────────────────────────────────
def test_report_source_ip_prefers_xff_origin():
    r = _FakeReq("/.env", headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"})
    assert proxy_app._report_source_ip(r) == "203.0.113.7"


def test_report_source_ip_falls_back_to_peer():
    r = _FakeReq("/.env", remote="198.51.100.4")
    assert proxy_app._report_source_ip(r) == "198.51.100.4"


# ── report emission ─────────────────────────────────────────────────────────
def test_report_edge_probe_sends_expected_frame():
    sent = {}

    async def _send_to_hub(ptype, data):
        sent["type"] = ptype
        sent["data"] = data

    cp = types.SimpleNamespace(send_to_hub=_send_to_hub)
    spoke = types.SimpleNamespace(control_plane=cp, spoke_id="proxy-7")
    r = _FakeReq("/wp-login.php", method="POST",
                 headers={"X-Forwarded-For": "203.0.113.7"})

    async def _run():
        proxy_app._report_edge_probe(spoke, r)
        await asyncio.sleep(0)  # let the fire-and-forget task run

    asyncio.run(_run())
    assert sent["type"] == "HTTP_PROBE_REPORT"
    assert sent["data"] == {"source_ip": "203.0.113.7", "path": "/wp-login.php",
                            "method": "POST", "node": "proxy-7"}


def test_report_edge_probe_noop_without_control_plane():
    spoke = types.SimpleNamespace(control_plane=None, spoke_id="proxy-7")

    async def _run():
        # Must not raise even when the tunnel back-ref is not yet wired.
        proxy_app._report_edge_probe(spoke, _FakeReq("/.env"))
        await asyncio.sleep(0)

    asyncio.run(_run())


# ── ProxySpoke config toggle ────────────────────────────────────────────────
def test_probe_detection_default_on():
    os.environ.pop("LM_PROXY_PROBE_DETECTION", None)
    s = proxy_spoke.ProxySpoke("proxy-1", {})
    assert s.probe_detection_enabled is True


def test_probe_detection_disabled_by_config():
    s = proxy_spoke.ProxySpoke("proxy-1", {"probe_detection": False})
    assert s.probe_detection_enabled is False


def test_probe_detection_env_override():
    os.environ["LM_PROXY_PROBE_DETECTION"] = "off"
    try:
        s = proxy_spoke.ProxySpoke("proxy-1", {})
        assert s.probe_detection_enabled is False
    finally:
        os.environ.pop("LM_PROXY_PROBE_DETECTION", None)


def test_apply_config_hot_toggles_probe_detection():
    s = proxy_spoke.ProxySpoke("proxy-1", {"probe_detection": True})
    assert s.probe_detection_enabled is True
    asyncio.run(s._apply_config({"probe_detection": False}))
    assert s.probe_detection_enabled is False
    asyncio.run(s._apply_config({"probe_detection": True}))
    assert s.probe_detection_enabled is True


# ── _dispatch gating ────────────────────────────────────────────────────────
def test_dispatch_404s_a_probe_and_does_not_forward():
    spoke = types.SimpleNamespace(probe_detection_enabled=True, control_plane=None,
                                  spoke_id="proxy-1", upstream_url="https://hub")
    req = _FakeReq("/phpmyadmin/index.php", headers={})
    req.app = {"spoke": spoke}
    resp = asyncio.run(proxy_app._dispatch(req))
    assert resp.status == 404


def test_dispatch_skips_detection_when_disabled():
    # Detection off → a probe path is NOT short-circuited to 404 here; it flows to
    # the upstream path (which, with no upstream configured, yields 503 — proving
    # we did not 404 it as a probe).
    spoke = types.SimpleNamespace(probe_detection_enabled=False, control_plane=None,
                                  spoke_id="proxy-1", upstream_url="")
    req = _FakeReq("/phpmyadmin/index.php", headers={})
    req.app = {"spoke": spoke}
    resp = asyncio.run(proxy_app._dispatch(req))
    assert resp.status == 503
