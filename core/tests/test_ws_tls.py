"""Hub/spoke WebSocket TLS — client SSL context + mDNS TXT advertisement.

Covers the three TLS pieces added to lm/core:

* ``BaseControlPlane._client_ssl_ctx`` — verify-OFF by default
  (``ssl._create_unverified_context()`` → ``CERT_NONE``; encrypt without
  authenticating the self-signed hub cert, the lab default) and verify-ON when
  ``LM_HUB_TLS_VERIFY=1`` + ``LM_HUB_CA_CERT`` point at a CA
  (``ssl.create_default_context(cafile=…)`` → ``CERT_REQUIRED``).
* ``BaseControlPlane._connect_and_serve`` — a ``wss://`` hub_url is handed an
  SSL context and a ``ws://`` hub_url is left plaintext (``ssl=None``).
* ``LabManagerHub._build_hub_service_info`` — the mDNS TXT advertises
  ``tls_port`` + the real ``agent_port`` when TLS is enabled, and just
  ``agent_port`` (no ``tls_port``) when it is not.
"""

import os
import ssl
import sys

# conftest puts core/src on sys.path so `main` / `security.*` import flat.
# control_plane.py uses relative imports (``from ..security.signer``) that only
# resolve when imported as ``core.src.messaging.control_plane`` — so also put the
# lm repo root (parent of core/) on sys.path for that one module (mirrors
# test_install_uuid_identity).
_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import asyncio  # noqa: E402
import pytest  # noqa: E402

import main  # noqa: E402
from core.src.messaging import control_plane as cp  # noqa: E402


# ── helpers ──────────────────────────────────────────────────────────────────

def _stub_cp(hub_url="wss://hub.example:443", verify=False, ca_cert=""):
    """A bare BaseControlPlane with just the attrs _client_ssl_ctx /
    _connect_and_serve read (avoids running the real __init__, which expects a
    full spoke environment)."""
    bc = cp.BaseControlPlane.__new__(cp.BaseControlPlane)
    bc.hub_url = hub_url
    bc._tls_verify = verify
    bc._tls_ca_cert = ca_cert
    return bc


class _BreakConnect(Exception):
    """Distinctive exception raised from the faked connect CM to break out of
    _connect_and_serve after the kwargs are captured."""


class _FakeConnectCM:
    """Records the ssl kwarg, then raises on __aenter__ so _connect_and_serve
    never enters its handshake (the retry loop lives in run(), not here, so the
    exception propagates straight out)."""
    def __init__(self, recorded, url):
        self._recorded = recorded
        self._url = url

    async def __aenter__(self):
        # __aenter__ raising means __aexit__ is never called (async-with
        # protocol) — the exception surfaces from _connect_and_serve directly.
        raise _BreakConnect()

    async def __aexit__(self, *a):
        return False


def _patch_connect(monkeypatch, recorded):
    def _fake_connect(url, **kwargs):
        recorded["url"] = url
        recorded["ssl"] = kwargs.get("ssl")
        recorded["compression"] = kwargs.get("compression")
        return _FakeConnectCM(recorded, url)
    monkeypatch.setattr(cp.websockets, "connect", _fake_connect)


# ── _client_ssl_ctx ──────────────────────────────────────────────────────────

def test_client_ssl_ctx_default_is_unverified():
    bc = _stub_cp()  # verify=False, no CA
    ctx = bc._client_ssl_ctx()

    assert isinstance(ctx, ssl.SSLContext)
    # Lab default: encrypt the link but do NOT authenticate the self-signed
    # hub cert (MITM-able on-path; hardened via LM_HUB_TLS_VERIFY+CA).
    assert ctx.verify_mode == ssl.CERT_NONE


def test_client_ssl_ctx_verify_on_with_ca(tmp_path):
    cert = tmp_path / "ca.crt"
    key = tmp_path / "ca.key"
    # Generate a throwaway self-signed CA to point the context at. Skip the
    # test if openssl is unavailable (the installers guard on it the same way).
    import subprocess
    r = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=lm-test-ca"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        pytest.skip(f"openssl unavailable or failed: {r.stderr[:200]}")

    bc = _stub_cp(verify=True, ca_cert=str(cert))
    ctx = bc._client_ssl_ctx()

    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # verify-on → authenticate


def test_client_ssl_ctx_verify_flag_without_ca_falls_back_to_unverified():
    # LM_HUB_TLS_VERIFY=1 but no CA path → can't verify, fall back to the
    # encrypt-without-auth default rather than crashing.
    bc = _stub_cp(verify=True, ca_cert="")
    ctx = bc._client_ssl_ctx()

    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE


# ── _connect_and_serve ssl ctx selection ─────────────────────────────────────

def test_connect_and_serve_passes_ssl_ctx_for_wss(monkeypatch):
    bc = _stub_cp(hub_url="wss://hub.example:443")
    recorded = {}
    _patch_connect(monkeypatch, recorded)

    with pytest.raises(_BreakConnect):
        asyncio.run(bc._connect_and_serve())

    assert recorded["url"] == "wss://hub.example:443"
    # wss:// → an SSL context is supplied (verify-off by default here).
    assert isinstance(recorded["ssl"], ssl.SSLContext)
    assert recorded["compression"] is None  # deflate still disabled


def test_connect_and_serve_no_ssl_for_ws(monkeypatch):
    bc = _stub_cp(hub_url="ws://127.0.0.1:8765")
    recorded = {}
    _patch_connect(monkeypatch, recorded)

    with pytest.raises(_BreakConnect):
        asyncio.run(bc._connect_and_serve())

    assert recorded["url"] == "ws://127.0.0.1:8765"
    # ws:// (loopback / legacy) → plaintext, no SSL context.
    assert recorded["ssl"] is None


# ── _build_hub_service_info TXT ──────────────────────────────────────────────
# A fake zeroconf is injected into sys.modules so no real mDNS stack is needed
# (mirrors test_mdns_broadcast).

class _FakeServiceInfo:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def _fake_zeroconf_module():
    mod = type(sys)("zeroconf")
    mod.ServiceInfo = _FakeServiceInfo
    mod.Zeroconf = type("Zeroconf", (), {})
    return mod


def _stub_hub(tls_enabled, tls_port=443, pxmx_agent_port=8443, port=8765):
    hub = main.LabManagerHub.__new__(main.LabManagerHub)
    hub.port = port
    hub.tls_enabled = tls_enabled
    hub.tls_port = tls_port
    hub.pxmx_agent_port = pxmx_agent_port
    return hub


def test_build_service_info_advertises_tls_when_enabled(monkeypatch):
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())
    monkeypatch.setattr(main.LabManagerHub, "_local_ipv4s", lambda self: ["10.0.0.5"])
    monkeypatch.setattr(main.LabManagerHub, "_hub_version_str", lambda self: "9.9.9")
    hub = _stub_hub(tls_enabled=True, tls_port=443, pxmx_agent_port=8443)

    info = hub._build_hub_service_info()

    assert info is not None
    props = info.kwargs["properties"]
    assert props["tls_port"] == "443"        # remote callers switch to wss://:443
    assert props["agent_port"] == "8443"     # pxmx agent listener (TLS-aware)
    assert props["version"] == "9.9.9"
    assert info.kwargs["port"] == 443        # unified srv_port = tls_port (443)


def test_build_service_info_no_tls_txt_when_disabled(monkeypatch):
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())
    monkeypatch.setattr(main.LabManagerHub, "_local_ipv4s", lambda self: ["10.0.0.5"])
    monkeypatch.setattr(main.LabManagerHub, "_hub_version_str", lambda self: "9.9.9")
    hub = _stub_hub(tls_enabled=False, pxmx_agent_port=8443)

    info = hub._build_hub_service_info()

    assert info is not None
    props = info.kwargs["properties"]
    # No tls_port → a remote caller's discovery stays ws:// (legacy, cert-less).
    assert "tls_port" not in props
    assert props["agent_port"] == "8443"


def test_build_service_info_legacy_agent_port_8766(monkeypatch):
    # A hub with no pxmx_agent_port attr (e.g. a not-yet-restarted box running
    # old code) falls back to the legacy 8766 agent-listener port.
    monkeypatch.setattr(main.LabManagerHub, "_mdns_warned", False)
    monkeypatch.setitem(sys.modules, "zeroconf", _fake_zeroconf_module())
    monkeypatch.setattr(main.LabManagerHub, "_local_ipv4s", lambda self: ["10.0.0.5"])
    monkeypatch.setattr(main.LabManagerHub, "_hub_version_str", lambda self: "9.9.9")
    hub = _stub_hub(tls_enabled=False, pxmx_agent_port=8443)
    del hub.pxmx_agent_port  # simulate the attr being absent

    info = hub._build_hub_service_info()

    assert info is not None
    props = info.kwargs["properties"]
    assert props["agent_port"] == "8766"     # getattr fallback
    assert "tls_port" not in props