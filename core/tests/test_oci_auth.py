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


# ── region validation + transport-error context ─────────────────────────────
#
# Every OCI endpoint host is built by interpolating the region into
# ``<service>.<region>[.oci].oraclecloud.com``. A typo'd region therefore only
# ever surfaced as a bare ``[Errno -2] Name or service not known`` from the
# resolver — no hostname, no URL, no hint whether the region was wrong or the
# hub simply has no egress. validate_region() catches the malformed case up
# front, and _transport_error_detail() names the host for everything else.

import httpx  # noqa: E402


@pytest.mark.parametrize("region", [
    "us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1", "ap-tokyo-1",
    "uk-london-1", "sa-saopaulo-1", "me-jeddah-1", "ap-singapore-2",
])
def test_validate_region_accepts_well_formed_ids(region):
    assert oci_auth.validate_region(region) == region


def test_validate_region_normalises_case_and_whitespace():
    assert oci_auth.validate_region("  US-Ashburn-1  ") == "us-ashburn-1"


def test_validate_region_unknown_but_well_formed_is_allowed():
    """OCI adds regions regularly and OCI_REGIONS is a hand-maintained
    snapshot, so a well-formed id we don't know about must NOT be refused."""
    assert oci_auth.validate_region("xx-nowhere-9") == "xx-nowhere-9"


def test_validate_region_empty_names_the_missing_setting():
    with pytest.raises(oci_auth.OciAuthError, match="no OCI region configured"):
        oci_auth.validate_region("")


@pytest.mark.parametrize("bad", [
    "us ashburn 1",        # spaces
    "us-ashburn",          # no trailing ordinal
    "us_ashburn_1",        # underscores
    "https://us-ashburn-1",
    "iaas.us-ashburn-1.oraclecloud.com",  # whole hostname pasted in
])
def test_validate_region_rejects_malformed_and_echoes_the_value(bad):
    with pytest.raises(oci_auth.OciAuthError, match="not a valid OCI region"):
        oci_auth.validate_region(bad)


def test_transport_error_detail_names_the_host():
    msg = oci_auth._transport_error_detail(
        "https://iaas.us-ashburn-1.oraclecloud.com/20160918/x",
        httpx.ConnectError("[Errno -2] Name or service not known"))
    assert "iaas.us-ashburn-1.oraclecloud.com" in msg
    assert "DNS could not resolve" in msg


def test_transport_error_detail_non_dns_failure_mentions_egress():
    msg = oci_auth._transport_error_detail(
        "https://iaas.us-ashburn-1.oraclecloud.com/20160918/x",
        httpx.ConnectTimeout("timed out"))
    assert "iaas.us-ashburn-1.oraclecloud.com" in msg
    assert "egress" in msg
    assert "DNS could not resolve" not in msg


def _cfg():
    return oci_auth.OciAuthConfig({"region": "us-ashburn-1"})


def test_oci_request_wraps_transport_error(monkeypatch):
    import asyncio
    monkeypatch.setattr(oci_auth, "signed_headers", lambda *a, **k: {})

    class _Boom:
        async def request(self, *a, **k):
            raise httpx.ConnectError("[Errno -2] Name or service not known")

    url = "https://iaas.us-ashburn-1.oraclecloud.com/20160918/x"
    with pytest.raises(oci_auth.OciAuthError, match="could not reach OCI endpoint"):
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            oci_auth.oci_request(_cfg(), _Boom(), "GET", url))


def test_oci_request_sync_wraps_transport_error(monkeypatch):
    monkeypatch.setattr(oci_auth, "signed_headers", lambda *a, **k: {})

    class _Boom:
        def request(self, *a, **k):
            raise httpx.ConnectError("[Errno -2] Name or service not known")

    url = "https://iaas.us-ashburn-1.oraclecloud.com/20160918/x"
    with pytest.raises(oci_auth.OciAuthError, match="could not reach OCI endpoint"):
        oci_auth.oci_request_sync(_cfg(), _Boom(), "GET", url)


def test_oci_request_sync_passes_through_a_normal_response(monkeypatch):
    """The wrapper must not swallow ordinary responses (incl. HTTP errors,
    which callers inspect via status_code)."""
    monkeypatch.setattr(oci_auth, "signed_headers", lambda *a, **k: {})
    sentinel = object()

    class _Ok:
        def request(self, *a, **k):
            return sentinel

    assert oci_auth.oci_request_sync(
        _cfg(), _Ok(), "GET", "https://iaas.us-ashburn-1.oraclecloud.com/x") is sentinel


def test_list_regions_shape_and_sorting():
    regions = oci_auth.list_regions()
    assert regions and all({"id", "label"} <= set(r) for r in regions)
    assert [r["label"] for r in regions] == sorted(r["label"] for r in regions)
    ids = [r["id"] for r in regions]
    assert "us-ashburn-1" in ids
    assert len(ids) == len(set(ids)), "duplicate region ids in OCI_REGIONS"
    # Every catalogued region must itself pass validation.
    for rid in ids:
        assert oci_auth.validate_region(rid) == rid
