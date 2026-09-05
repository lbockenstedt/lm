"""Tests for the OCI 401/NotAuthenticated diagnostics.

OCI answers every bad signing credential with the same opaque
"NotAuthenticated" body, naming no field. These tests pin the local diagnosis
that turns that into an actionable message — most importantly the private
key/fingerprint comparison, which is the usual culprit when an operator has
carefully pasted five correct-looking values.
"""
import os
import sys
import hashlib

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import oci_auth  # noqa: E402
import oci_nsg  # noqa: E402
import oci_vault  # noqa: E402


@pytest.fixture(scope="module")
def keyfile(tmp_path_factory):
    """A real RSA key on disk + the fingerprint OCI would show for it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p = tmp_path_factory.mktemp("ocikey") / "api.pem"
    p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    d = hashlib.md5(der).hexdigest()
    return str(p), ":".join(d[i:i + 2] for i in range(0, len(d), 2))


def _cfg(keyfile, **over):
    path, fp = keyfile
    base = {"tenancy_ocid": "ocid1.tenancy.oc1..aaa",
            "user_ocid": "ocid1.user.oc1..bbb",
            "fingerprint": fp, "key_path": path, "region": "us-ashburn-1"}
    base.update(over)
    return oci_auth.OciAuthConfig(base)


# ── fingerprint computation ──────────────────────────────────────────────────

def test_fingerprint_matches_openssl_algorithm(keyfile):
    """OCI's fingerprint is MD5(DER SubjectPublicKeyInfo) as colon-hex."""
    path, expected = keyfile
    assert oci_auth.public_key_fingerprint(path) == expected


def test_fingerprint_is_16_colon_separated_hex_pairs(keyfile):
    fp = oci_auth.public_key_fingerprint(keyfile[0])
    assert oci_auth._FINGERPRINT_RE.match(fp)


# ── paste normalisation ──────────────────────────────────────────────────────

@pytest.mark.parametrize("raw", [
    "ocid1.tenancy.oc1..aaa\n",          # trailing newline
    " ocid1.tenancy.oc1..aaa ",           # surrounding spaces
    "ocid1.tenancy.\noc1..aaa",           # console line-wrap INSIDE the value
    "ocid1.tenancy. oc1..aaa",            # stray internal space
    "ocid1.tenancy.\toc1..aaa",           # tab
])
def test_internal_whitespace_stripped_from_ocid(keyfile, raw):
    """A wrapped paste must not silently corrupt keyId."""
    cfg = _cfg(keyfile, tenancy_ocid=raw)
    assert cfg.tenancy_ocid == "ocid1.tenancy.oc1..aaa"
    assert not any(c.isspace() for c in cfg.key_id)


def test_fingerprint_is_lowercased(keyfile):
    cfg = _cfg(keyfile, fingerprint="AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99")
    assert cfg.fingerprint == "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"


def test_key_id_is_tenancy_slash_user_slash_fingerprint(keyfile):
    """The exact keyId form OCI requires."""
    cfg = _cfg(keyfile)
    assert cfg.key_id == f"{cfg.tenancy_ocid}/{cfg.user_ocid}/{cfg.fingerprint}"
    assert cfg.key_id.count("/") == 2


# ── diagnosis ────────────────────────────────────────────────────────────────

def test_clean_config_reports_no_problems(keyfile):
    assert oci_auth.diagnose_auth(_cfg(keyfile)) == []


def test_detects_key_fingerprint_mismatch(keyfile):
    """The decisive check: uploaded key is not the one OCI knows."""
    wrong = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    problems = oci_auth.diagnose_auth(_cfg(keyfile, fingerprint=wrong))
    assert any("does NOT match" in p for p in problems)
    assert any(keyfile[1] in p for p in problems), "should name the real fingerprint"


def test_detects_tenancy_and_user_swapped(keyfile):
    problems = oci_auth.diagnose_auth(
        _cfg(keyfile, tenancy_ocid="ocid1.user.oc1..bbb"))
    assert any("ocid1.tenancy." in p for p in problems)
    assert any("identical" in p for p in problems)


def test_detects_compartment_pasted_as_user(keyfile):
    problems = oci_auth.diagnose_auth(
        _cfg(keyfile, user_ocid="ocid1.compartment.oc1..ccc"))
    assert any("ocid1.user." in p for p in problems)


def test_detects_malformed_fingerprint(keyfile):
    problems = oci_auth.diagnose_auth(_cfg(keyfile, fingerprint="not-a-fingerprint"))
    assert any("hex pairs" in p for p in problems)


def test_unreadable_key_is_reported_not_raised(keyfile):
    problems = oci_auth.diagnose_auth(_cfg(keyfile, key_path="/nonexistent/api.pem"))
    assert any("could not be loaded" in p for p in problems)


def test_help_falls_back_to_oci_side_checklist(keyfile):
    """When nothing is locally wrong, point at OCI-side causes + clock skew."""
    help_text = oci_auth.auth_failure_help(_cfg(keyfile))
    assert "ACTIVE" in help_text and "policy" in help_text
    assert "clock" in help_text


# ── wiring into the HTTP error paths ─────────────────────────────────────────

_401 = '{"code":"NotAuthenticated","message":"The required information to complete authentication was not provided or was incorrect."}'


@pytest.mark.parametrize("mod,exc", [(oci_nsg, oci_nsg.OciNsgError),
                                     (oci_vault, oci_vault.OciVaultError)])
def test_401_response_gets_diagnosis_appended(keyfile, mod, exc):
    wrong = "00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
    cfg = _cfg(keyfile, fingerprint=wrong)
    err = mod._http_error(cfg, "OCI GET thing", httpx.Response(401, text=_401))
    assert isinstance(err, exc)
    assert "HTTP 401" in str(err)
    assert "does NOT match" in str(err), "diagnosis must be appended"


@pytest.mark.parametrize("mod", [oci_nsg, oci_vault])
def test_403_also_diagnosed(keyfile, mod):
    err = mod._http_error(cfg := _cfg(keyfile), "OCI GET thing",
                          httpx.Response(403, text="NotAuthorized"))
    assert "ACTIVE" in str(err)
    assert cfg is not None


@pytest.mark.parametrize("mod", [oci_nsg, oci_vault])
def test_non_auth_status_left_alone(keyfile, mod):
    """A 404/500 must not be polluted with credential advice."""
    err = mod._http_error(_cfg(keyfile), "OCI GET thing",
                          httpx.Response(404, text="NotFound"))
    assert "HTTP 404" in str(err)
    assert "fingerprint" not in str(err)


@pytest.mark.parametrize("mod", [oci_nsg, oci_vault])
def test_diagnosis_failure_never_masks_original_error(keyfile, mod, monkeypatch):
    """If diagnosis itself blows up, the operator still gets the OCI status."""
    monkeypatch.setattr(oci_auth, "auth_failure_help",
                        lambda cfg: (_ for _ in ()).throw(RuntimeError("boom")))
    err = mod._http_error(_cfg(keyfile), "OCI GET thing",
                          httpx.Response(401, text=_401))
    assert "HTTP 401" in str(err)
