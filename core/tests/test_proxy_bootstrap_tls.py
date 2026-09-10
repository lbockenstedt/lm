"""Edge proxy must serve HTTPS on :443 from the very first boot.

Port 443 is the HTTPS port, so binding it in plaintext is never right: a
browser sent to ``https://<spoke>/`` gets a TLS protocol error, which looks
like "the proxy is broken" rather than "no certificate yet". A fresh install
sits in exactly that state until the ``le`` role finishes issuing a real cert
— which may be a long time, or never if DNS-01 can't complete.

``ProxySpoke._listener_ssl`` therefore bootstraps a self-signed cert instead of
returning ``None``. These tests pin that: HTTPS comes up unattended, the
private key is not world-readable, the cert is reused rather than regenerated
across restarts, and a real CA-issued cert always wins.
"""
import importlib.util
import os
import socket
import ssl
import sys
import threading
import types
from pathlib import Path

import pytest

PROXY_SRC = Path(__file__).resolve().parents[2] / "proxy" / "src" / "proxy_spoke.py"


def _load_proxy_spoke():
    """Import proxy_spoke with its two optional deps stubbed.

    ``proxy_spoke`` tries ``from proxy_app import ...`` / ``from base_spoke
    import ...`` first and only falls back to a relative import, so seeding
    sys.modules makes the plain import succeed. aiohttp is imported lazily
    inside the bind path, so it is not needed here.
    """
    if not PROXY_SRC.exists():  # proxy module not present in this checkout
        pytest.skip("proxy/src/proxy_spoke.py not available")
    saved = {k: sys.modules.get(k) for k in ("proxy_app", "base_spoke")}
    pa = types.ModuleType("proxy_app")
    pa.build_proxy_app = lambda *a, **k: None
    bs = types.ModuleType("base_spoke")

    class _Base:  # minimal stand-in; the cert helpers don't touch it
        def __init__(self, *a, **k):
            pass

    bs.BaseSpoke = _Base
    sys.modules["proxy_app"], sys.modules["base_spoke"] = pa, bs
    try:
        spec = importlib.util.spec_from_file_location("proxy_spoke_undertest",
                                                      str(PROXY_SRC))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def _spoke(tmp_path, **over):
    """A ProxySpoke shell carrying just the attrs the cert helpers read."""
    mod = _load_proxy_spoke()
    p = mod.ProxySpoke.__new__(mod.ProxySpoke)  # skip __init__ (needs a hub)
    p._data_dir = str(tmp_path)
    p.public_host = over.get("public_host", "proxy.test.example.com")
    p.web_port = 443
    p.tls_cert = over.get("tls_cert", "")
    p.tls_key = over.get("tls_key", "")
    p._using_bootstrap_cert = False
    return p


def test_no_cert_yields_https_not_plaintext(tmp_path):
    """The regression that broke labmanager-ui: no cert must NOT mean HTTP."""
    p = _spoke(tmp_path)
    ctx = p._listener_ssl()
    assert ctx is not None, "listener fell back to plaintext on :443"
    assert p._using_bootstrap_cert is True
    assert Path(p.tls_cert).name == "selfsigned.pem"


def test_bootstrap_key_is_not_world_readable(tmp_path):
    p = _spoke(tmp_path)
    p._listener_ssl()
    mode = os.stat(p.tls_key).st_mode & 0o777
    assert mode == 0o600, f"private key mode {oct(mode)} exposes the key"


def test_bootstrap_cert_completes_a_real_tls_handshake(tmp_path):
    """Generating a file isn't enough — the context must actually serve TLS."""
    p = _spoke(tmp_path)
    ctx = p._listener_ssl()

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    result = {}

    def _serve():
        try:
            conn, _ = srv.accept()
            with ctx.wrap_socket(conn, server_side=True) as s:
                s.recv(16)
            result["ok"] = True
        except Exception as e:  # noqa: BLE001
            result["err"] = e

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    try:
        cc = ssl.create_default_context()
        cc.check_hostname = False
        cc.verify_mode = ssl.CERT_NONE  # self-signed by definition
        with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
            with cc.wrap_socket(s) as ts:
                assert ts.version().startswith("TLS")
                ts.send(b"x")
    finally:
        t.join(timeout=10)
        srv.close()
    assert result.get("ok") is True, f"server handshake failed: {result.get('err')}"


def test_bootstrap_cert_is_reused_across_restarts(tmp_path):
    """A restart must not mint a new cert — that would churn the fingerprint
    operators just clicked through in the browser."""
    first = _spoke(tmp_path)
    first._listener_ssl()
    original = Path(first.tls_cert).read_bytes()

    second = _spoke(tmp_path)
    second._listener_ssl()
    assert second.tls_cert == first.tls_cert
    assert Path(second.tls_cert).read_bytes() == original


def test_real_cert_takes_precedence_over_bootstrap(tmp_path):
    """Once the le role delivers a cert, the self-signed one must not be used."""
    boot = _spoke(tmp_path)
    boot._listener_ssl()  # create the self-signed pair on disk

    tls_dir = tmp_path / "tls"
    fc, pk = tls_dir / "fullchain.pem", tls_dir / "privkey.pem"
    fc.write_bytes(Path(boot.tls_cert).read_bytes())
    pk.write_bytes(Path(boot.tls_key).read_bytes())

    p = _spoke(tmp_path, tls_cert=str(fc), tls_key=str(pk))
    ctx = p._listener_ssl()
    assert ctx is not None
    assert p._using_bootstrap_cert is False, "real cert was flagged self-signed"
    assert p.tls_cert == str(fc)


def test_bootstrap_does_not_overwrite_le_cert_material(tmp_path):
    """The bootstrap path writes only selfsigned.*, never fullchain/privkey."""
    p = _spoke(tmp_path)
    p._listener_ssl()
    names = {q.name for q in (tmp_path / "tls").iterdir()}
    assert names == {"selfsigned.pem", "selfsigned.key"}
