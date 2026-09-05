"""oci_auth.write_uploaded_private_key — shared WebUI private-key-upload path.

Both ``routes/oci_nsg.py`` and ``routes/oci_vault.py`` accept an uploaded OCI
API signing key (PEM) instead of requiring an admin to hand-copy a file onto
the hub / type a filesystem path. This module pins the shared validation +
write helper they both call: a valid unencrypted PEM key is written to
``<data_dir>/<subdir>/<filename>`` at 0600 and the resulting path is
returned; anything else (empty, oversized, garbage, or an
encrypted/passphrase-protected key) is rejected BEFORE anything touches disk.
"""
import os
import stat
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import oci_auth  # noqa: E402


def _gen_pem(*, encrypted=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    enc = (serialization.BestAvailableEncryption(b"s3cret") if encrypted
          else serialization.NoEncryption())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=enc)


class _FakeState:
    def __init__(self, data_dir):
        self.data_dir = data_dir


class _FakeHub:
    def __init__(self, data_dir):
        self.state = _FakeState(data_dir)


def test_valid_pem_is_written_at_0600_and_path_returned(tmp_path):
    hub = _FakeHub(str(tmp_path))
    pem = _gen_pem()
    path = oci_auth.write_uploaded_private_key(hub, "oci", "test-key.pem", pem)
    assert path == os.path.join(str(tmp_path), "oci", "test-key.pem")
    assert os.path.isfile(path)
    with open(path, "rb") as f:
        assert f.read() == pem
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_creates_missing_subdir(tmp_path):
    hub = _FakeHub(str(tmp_path))
    assert not os.path.isdir(os.path.join(str(tmp_path), "oci"))
    oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", _gen_pem())
    assert os.path.isdir(os.path.join(str(tmp_path), "oci"))


def test_empty_upload_rejected(tmp_path):
    hub = _FakeHub(str(tmp_path))
    with pytest.raises(oci_auth.OciAuthError, match="empty"):
        oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", b"")
    assert not os.path.isdir(os.path.join(str(tmp_path), "oci"))


def test_oversized_upload_rejected(tmp_path):
    hub = _FakeHub(str(tmp_path))
    with pytest.raises(oci_auth.OciAuthError, match="64 KB"):
        oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", b"x" * (64 * 1024 + 1))
    assert not os.path.isdir(os.path.join(str(tmp_path), "oci"))


def test_garbage_upload_rejected(tmp_path):
    hub = _FakeHub(str(tmp_path))
    with pytest.raises(oci_auth.OciAuthError, match="not a valid"):
        oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", b"not a pem key at all")
    assert not os.path.isdir(os.path.join(str(tmp_path), "oci"))


def test_encrypted_pem_rejected_since_password_is_never_prompted(tmp_path):
    hub = _FakeHub(str(tmp_path))
    with pytest.raises(oci_auth.OciAuthError, match="not a valid"):
        oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", _gen_pem(encrypted=True))
    assert not os.path.isdir(os.path.join(str(tmp_path), "oci"))


def test_write_failure_is_wrapped_as_oci_auth_error(tmp_path, monkeypatch):
    hub = _FakeHub(str(tmp_path))

    def _boom(*a, **kw):
        raise OSError("disk full")
    monkeypatch.setattr(oci_auth.os, "makedirs", _boom)
    with pytest.raises(oci_auth.OciAuthError, match="could not write"):
        oci_auth.write_uploaded_private_key(hub, "oci", "k.pem", _gen_pem())
