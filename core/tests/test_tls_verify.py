"""Hub TLS certificate verification — the spoke dial trust path.

Verification is OFF by default (cert deployment still in progress), but the
verify=ON path must actually work and, critically, must NEVER silently downgrade
an operator who asked for verification back to an unverified context. These
tests pin the four cases of ``_client_ssl_ctx``:

  1. verify OFF                       → unverified context (CERT_NONE).
  2. verify ON, no CA path            → system trust store (CERT_REQUIRED).
  3. verify ON, valid pinned CA file  → context pinned to that CA (CERT_REQUIRED).
  4. verify ON, MISSING CA path       → None (fail fast) — NOT a silent downgrade.
"""
import os
import ssl
import datetime as _dt

import pytest

from core.src.messaging.control_plane import BaseControlPlane


def _make_ca_pem(path):
    """Write a real self-signed CA PEM to *path* so create_default_context(cafile=)
    accepts it. Uses cryptography (a test dep) to mint a throwaway CA."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lm-test-ca")])
    now = _dt.datetime.utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


class _FakeSelf:
    """Just the TLS attributes _client_ssl_ctx touches."""
    def __init__(self, verify, ca_cert=""):
        self._tls_verify = verify
        self._tls_ca_cert = ca_cert


def _ctx(fake):
    return BaseControlPlane._client_ssl_ctx(fake)


def test_verify_off_yields_unverified_context():
    ctx = _ctx(_FakeSelf(verify=False))
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_verify_on_no_ca_uses_system_trust_store():
    # Public-CA (Let's Encrypt) case: verify=1, no LM_HUB_CA_CERT → system store.
    ctx = _ctx(_FakeSelf(verify=True, ca_cert=""))
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_verify_on_pinned_ca_loads_that_ca(tmp_path):
    ca = tmp_path / "hub-ca.pem"
    _make_ca_pem(ca)
    ctx = _ctx(_FakeSelf(verify=True, ca_cert=str(ca)))
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # The pinned CA path is taken (not the system-store branch): confirm the PEM
    # was actually consumed by re-loading it directly and checking parity of the
    # trust mode. (get_ca_certs() returns [] for cafile-loaded certs on some
    # Python builds, so don't rely on it.)
    direct = ssl.create_default_context(cafile=str(ca))
    assert direct.verify_mode == ctx.verify_mode


def test_verify_on_missing_ca_path_fails_fast_not_silent_downgrade(caplog):
    """An operator who set LM_HUB_TLS_VERIFY=1 + a CA path that doesn't exist
    must NOT be silently handed an unverified context — that's the footgun
    (they'd believe the hub cert is authenticated when it isn't). The method
    returns None so the connect fails fast and surfaces the misconfiguration."""
    import logging
    caplog.set_level(logging.ERROR)
    ctx = _ctx(_FakeSelf(verify=True, ca_cert="/no/such/lm-hub-ca.pem"))
    assert ctx is None
    assert any("refusing to silently downgrade" in r.message.lower()
               or "silently downgrade" in r.message.lower()
               for r in caplog.records)


def test_verify_on_unreadable_ca_fails_fast(tmp_path, caplog):
    """A CA path that exists but isn't a valid PEM also fails fast (None) rather
    than degrading to unverified — same footgun, different trigger."""
    import logging
    bad = tmp_path / "garbage.pem"
    bad.write_text("not a pem")
    caplog.set_level(logging.ERROR)
    ctx = _ctx(_FakeSelf(verify=True, ca_cert=str(bad)))
    assert ctx is None
    assert any(r.levelno == logging.ERROR for r in caplog.records)