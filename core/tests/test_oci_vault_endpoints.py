"""OCI Vault endpoints: right host, right API version, right HTTP method.

"OCI Vault" is three separate services spread over three hostnames and two API
versions, and every wrong combination fails the same way — 404
``NotAuthorizedOrNotFound``, which is also what OCI returns for a deleted
resource or a policy denial. That ambiguity hid three genuine routing bugs
here: GetVault was sent to the secrets host (which has no ``/vaults`` route at
all), secret management used the retrieval service's API version, and
GetSecretBundleByName was sent as a GET when it is a POST.

The mapping below was verified against the live OCI endpoints: an
unauthenticated request to a REAL route answers ``401 NotAuthenticated``,
while a bad route answers ``404 NotAuthorizedOrNotFound``.

  KMS vault mgmt    kms.<region>.oraclecloud.com                 /20180608/vaults…
  secret mgmt       vaults.<region>.oci.oraclecloud.com          /20180608/secrets…
  secret retrieval  secrets.vaults.<region>.oci.oraclecloud.com  /20190301/secretbundles…
"""
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import oci_auth  # noqa: E402


def _vault_mod():
    try:
        import oci_vault
    except Exception as e:  # pragma: no cover
        pytest.skip(f"oci_vault unavailable: {e}")
    return oci_vault


class _Cfg:
    region = "us-ashburn-1"


# ── hostnames ────────────────────────────────────────────────────────────────

def test_kms_host_has_no_oci_label():
    """kms.<region>.oraclecloud.com — the `.oci.` label belongs only to the two
    secrets hosts."""
    base = _vault_mod()._kms_base(_Cfg())
    assert base == "https://kms.us-ashburn-1.oraclecloud.com/20180608"
    assert ".oci." not in base


def test_secret_management_host_keeps_the_oci_label():
    base = _vault_mod()._vaults_base(_Cfg())
    assert base == "https://vaults.us-ashburn-1.oci.oraclecloud.com/20180608"


def test_secret_retrieval_host_and_version():
    base = _vault_mod()._secrets_base(_Cfg())
    assert base == "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com/20190301"


def test_the_three_hosts_are_all_different():
    m = _vault_mod()
    hosts = {m._kms_base(_Cfg()), m._vaults_base(_Cfg()), m._secrets_base(_Cfg())}
    assert len(hosts) == 3


# ── the bug that produced the operator's 404 ─────────────────────────────────

@pytest.mark.asyncio
async def test_get_vault_goes_to_the_kms_host_not_the_secrets_host(monkeypatch):
    """`GET /vaults/{id}` does not exist on vaults.<region>.oci.oraclecloud.com,
    so sending it there 404s no matter how correct the credentials are."""
    m = _vault_mod()
    seen = {}

    async def _fake_request(cfg, client, method, url, json_body=None):
        seen["method"], seen["url"] = method, url

        class _R:
            status_code = 200

            @staticmethod
            def json():
                return {"lifecycleState": "ACTIVE", "id": "v", "managementEndpoint": "m"}
        return _R()

    monkeypatch.setattr(m, "_request", _fake_request)
    out = await m.test_connection(
        _Cfg(), {"vault_id": "ocid1.vault.oc1.iad.abcd",
                 "compartment_id": "ocid1.tenancy.oc1..aaaa"})
    assert seen["url"].startswith("https://kms.us-ashburn-1.oraclecloud.com/20180608/vaults/")
    assert "vaults.us-ashburn-1.oci." not in seen["url"]
    assert seen["method"] == "GET"
    assert out["lifecycle_state"] == "ACTIVE"


@pytest.mark.asyncio
async def test_get_secret_by_name_is_a_post(monkeypatch):
    """GetSecretBundleByName takes its arguments as QUERY parameters but is a
    POST; as a GET the path 404s."""
    m = _vault_mod()
    seen = {}

    async def _fake_request(cfg, client, method, url, json_body=None):
        seen["method"], seen["url"], seen["body"] = method, url, json_body

        class _R:
            status_code = 404
        return _R()

    monkeypatch.setattr(m, "_request", _fake_request)
    await m.get_secret(_Cfg(), {"vault_id": "ocid1.vault.oc1.iad.abcd",
                                "compartment_id": "ocid1.tenancy.oc1..aaaa"},
                       "my-secret")
    assert seen["method"] == "POST"
    assert "/20190301/secretbundles/actions/getByName" in seen["url"]
    assert "secretName=my-secret" in seen["url"]
    assert seen["body"] is None  # arguments ride in the query string


@pytest.mark.asyncio
async def test_secret_name_is_url_encoded(monkeypatch):
    """A name with a space or '/' would otherwise corrupt the query string —
    and, because the signature covers the request target, the signature too."""
    m = _vault_mod()
    seen = {}

    async def _fake_request(cfg, client, method, url, json_body=None):
        seen["url"] = url

        class _R:
            status_code = 404
        return _R()

    monkeypatch.setattr(m, "_request", _fake_request)
    await m.get_secret(_Cfg(), {"vault_id": "ocid1.vault.oc1.iad.abcd",
                                "compartment_id": "ocid1.tenancy.oc1..aaaa"},
                       "dns 01/he")
    assert "dns%2001%2Fhe" in seen["url"]
    assert " " not in seen["url"]


# ── signing a bodyless POST ──────────────────────────────────────────────────

def test_bodyless_post_is_signed_with_an_empty_body_not_no_body():
    """OCI requires content-length/content-type/x-content-sha256 to be signed
    on POST even when the body is empty; omitting them is NotAuthenticated."""
    assert oci_auth._body_bytes("POST", None) == b""
    assert oci_auth._body_bytes("PUT", None) == b""
    assert oci_auth._body_bytes("PATCH", None) == b""


def test_get_still_has_no_body():
    assert oci_auth._body_bytes("GET", None) is None
    assert oci_auth._body_bytes("DELETE", None) is None


def test_json_body_still_encoded_compactly():
    assert oci_auth._body_bytes("POST", {"a": 1}) == b'{"a":1}'


def test_method_case_does_not_matter():
    assert oci_auth._body_bytes("post", None) == b""


def test_empty_post_body_signs_the_content_headers(tmp_path):
    """End-to-end: the empty body must actually produce the three signed
    content headers, with the SHA-256 of the empty string."""
    import base64
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kp = tmp_path / "k.pem"
    kp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))

    cfg = oci_auth.OciAuthConfig({
        "tenancy_ocid": "ocid1.tenancy.oc1..aaaa",
        "user_ocid": "ocid1.user.oc1..bbbb",
        "fingerprint": oci_auth.public_key_fingerprint(str(kp)),
        "key_path": str(kp),
        "region": "us-ashburn-1",
    })
    headers = oci_auth.signed_headers(
        cfg, "POST",
        "https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com"
        "/20190301/secretbundles/actions/getByName?secretName=x&vaultId=y",
        oci_auth._body_bytes("POST", None))

    empty_digest = base64.b64encode(hashlib.sha256(b"").digest()).decode()
    assert headers["content-length"] == "0"
    assert headers["x-content-sha256"] == empty_digest
    assert "content-type" in headers
    for h in ("content-length", "content-type", "x-content-sha256"):
        assert h in headers["Authorization"]
