"""oci_vault.py — OCI Vault/Secrets get/set/test_connection + resolve_ref.

Covers the OCI Vault parity feature for key_vault.py: correct endpoint/verb
selection across the two OCI service surfaces (vaults control-plane vs.
secrets retrieval-plane), create-vs-update secret dispatch, base64 content
encoding/decoding, and the ``kv:<name>`` resolve_ref contract (mirrors
key_vault.resolve_ref's never-raises / inline-literal-passthrough semantics).
"""
import base64
import importlib.util
import os
import sys

import httpx
import pytest

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


oci_vault = _load_from_src("oci_vault", "oci_vault.py")


def _cfg():
    return oci_vault.OciConfig({
        "tenancy_ocid": "ocid1.tenancy.oc1..t", "user_ocid": "ocid1.user.oc1..u",
        "fingerprint": "aa:bb:cc:dd", "key_path": "/tmp/doesnotmatter.pem",
        "region": "us-ashburn-1",
    })


def _vcfg(**overrides):
    base = {"vault_id": "ocid1.vault.oc1..v", "compartment_id": "ocid1.compartment.oc1..c",
            "key_id": "ocid1.key.oc1..k"}
    base.update(overrides)
    return base


class _StubTransport(httpx.AsyncBaseTransport):
    """Records every request and returns a scripted response per call index,
    bypassing OCI request signing entirely (monkeypatched below)."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        resp = self.responses.pop(0)
        if resp.get("json") is not None:
            return httpx.Response(status_code=resp["status"], json=resp["json"], request=request)
        return httpx.Response(status_code=resp["status"], text=resp.get("text", ""), request=request)


@pytest.fixture(autouse=True)
def _no_real_signing(monkeypatch):
    """oci_vault always goes through oci_auth.oci_request(_sync); stub the
    signing step so tests don't need a real RSA key, while still exercising
    the real request-shape logic in oci_vault.py itself."""
    async def _fake_oci_request(cfg, client, method, url, *, json_body=None):
        return await client.request(method, url, json=json_body)
    monkeypatch.setattr(oci_vault._oci_auth, "oci_request", _fake_oci_request)

    def _fake_oci_request_sync(cfg, client, method, url, *, json_body=None):
        return client.request(method, url, json=json_body)
    monkeypatch.setattr(oci_vault._oci_auth, "oci_request_sync", _fake_oci_request_sync)


def _client_for(responses):
    transport = _StubTransport(responses)
    return httpx.AsyncClient(transport=transport), transport


# ── get_secret / resolve_ref ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_secret_decodes_base64_bundle_content():
    content = base64.b64encode(b"s3cr3t-value").decode()
    client, transport = _client_for([
        {"status": 200, "json": {"secretBundleContent": {"content": content}}},
    ])
    value = await oci_vault.get_secret(_cfg(), _vcfg(), "my-secret", http=client)
    assert value == "s3cr3t-value"
    req = transport.requests[0]
    # GetSecretBundleByName is a POST (its arguments ride in the query string);
    # as a GET this path 404s.
    assert req.method == "POST"
    assert "secretbundles/actions/getByName" in str(req.url)
    assert "secretName=my-secret" in str(req.url)
    assert f"vaultId={_vcfg()['vault_id']}" in str(req.url)
    assert "secrets." in str(req.url)  # retrieval plane, not vaults plane


@pytest.mark.asyncio
async def test_get_secret_returns_none_on_404():
    client, _ = _client_for([{"status": 404}])
    assert await oci_vault.get_secret(_cfg(), _vcfg(), "missing", http=client) is None


@pytest.mark.asyncio
async def test_get_secret_raises_on_other_error():
    client, _ = _client_for([{"status": 500, "text": "boom"}])
    with pytest.raises(oci_vault.OciVaultError):
        await oci_vault.get_secret(_cfg(), _vcfg(), "x", http=client)


def test_get_secret_sync_never_raises_and_returns_none_on_failure():
    """Best-effort contract for the future credential-provider integration —
    matches KeyVaultCredentialProvider's synchronous get_secret contract."""
    def _handler(request):
        return httpx.Response(status_code=500, text="boom", request=request)
    client = httpx.Client(transport=httpx.MockTransport(_handler))
    assert oci_vault.get_secret_sync(_cfg(), _vcfg(), "x", http=client) is None


@pytest.mark.asyncio
async def test_resolve_ref_inline_literal_passthrough_when_no_vault_configured():
    class _State:
        system_state = {"global_config": {}}

    class _Hub:
        state = _State()

    assert await oci_vault.resolve_ref(_Hub(), "not-a-kv-ref") == "not-a-kv-ref"
    assert await oci_vault.resolve_ref(_Hub(), "kv:something") is None
    assert await oci_vault.resolve_ref(_Hub(), None) is None


# ── set_secret (create vs update) ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_secret_creates_when_no_existing_secret_found():
    client, transport = _client_for([
        {"status": 200, "json": []},  # ListSecrets: none found
        {"status": 200, "json": {"id": "ocid1.secret.oc1..new"}},  # CreateSecret
    ])
    secret_id = await oci_vault.set_secret(_cfg(), _vcfg(), "my-secret", "value1", http=client)
    assert secret_id == "ocid1.secret.oc1..new"
    list_req, create_req = transport.requests
    assert list_req.method == "GET"
    assert "vaults." in str(list_req.url)
    assert create_req.method == "POST"
    assert str(create_req.url).endswith("/secrets")
    body = create_req.content
    assert b"my-secret" in body
    assert b"keyId" in body


@pytest.mark.asyncio
async def test_set_secret_updates_when_existing_secret_found():
    client, transport = _client_for([
        {"status": 200, "json": [{"secretName": "my-secret", "id": "ocid1.secret.oc1..existing",
                                  "lifecycleState": "ACTIVE"}]},
        {"status": 200, "json": {"id": "ocid1.secret.oc1..existing"}},  # UpdateSecret
    ])
    secret_id = await oci_vault.set_secret(_cfg(), _vcfg(), "my-secret", "value2", http=client)
    assert secret_id == "ocid1.secret.oc1..existing"
    _, update_req = transport.requests
    assert update_req.method == "PUT"
    assert update_req.url.path.endswith("/secrets/ocid1.secret.oc1..existing")


@pytest.mark.asyncio
async def test_set_secret_requires_key_id_to_create_new_secret():
    client, _ = _client_for([{"status": 200, "json": []}])
    with pytest.raises(oci_vault.OciVaultError, match="key_id"):
        await oci_vault.set_secret(_cfg(), _vcfg(key_id=""), "my-secret", "value", http=client)


def test_set_secret_requires_vault_and_compartment_ids():
    with pytest.raises(oci_vault.OciVaultError):
        import asyncio
        asyncio.new_event_loop().run_until_complete(
            oci_vault.set_secret(_cfg(), {}, "name", "value"))


# ── delete_secret ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_delete_secret_schedules_deletion_when_found():
    client, transport = _client_for([
        {"status": 200, "json": [{"secretName": "my-secret", "id": "ocid1.secret.oc1..existing",
                                  "lifecycleState": "ACTIVE"}]},
        {"status": 202, "json": {"id": "ocid1.secret.oc1..existing"}},  # scheduleDeletion
    ])
    result = await oci_vault.delete_secret(_cfg(), _vcfg(), "my-secret", http=client)
    assert result is True
    list_req, del_req = transport.requests
    assert list_req.method == "GET"
    assert del_req.method == "POST"
    assert del_req.url.path.endswith("/secrets/ocid1.secret.oc1..existing/actions/scheduleDeletion")


@pytest.mark.asyncio
async def test_delete_secret_is_idempotent_when_not_found():
    client, transport = _client_for([{"status": 200, "json": []}])  # ListSecrets: none found
    assert await oci_vault.delete_secret(_cfg(), _vcfg(), "missing", http=client) is True
    assert len(transport.requests) == 1  # never even attempts scheduleDeletion


@pytest.mark.asyncio
async def test_delete_secret_raises_on_backend_error():
    client, _ = _client_for([
        {"status": 200, "json": [{"secretName": "my-secret", "id": "ocid1.secret.oc1..existing",
                                  "lifecycleState": "ACTIVE"}]},
        {"status": 500, "text": "boom"},
    ])
    with pytest.raises(oci_vault.OciVaultError):
        await oci_vault.delete_secret(_cfg(), _vcfg(), "my-secret", http=client)


@pytest.mark.asyncio
async def test_delete_secret_empty_name_is_noop():
    client, transport = _client_for([])
    assert await oci_vault.delete_secret(_cfg(), _vcfg(), "", http=client) is True
    assert transport.requests == []


# ── test_connection ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_test_connection_returns_vault_summary():
    client, transport = _client_for([
        {"status": 200, "json": {"lifecycleState": "ACTIVE", "id": "ocid1.vault.oc1..v",
                                 "managementEndpoint": "https://x"}},
    ])
    res = await oci_vault.test_connection(_cfg(), _vcfg(), http=client)
    assert res == {"lifecycle_state": "ACTIVE", "vault_id": "ocid1.vault.oc1..v",
                   "management_endpoint": "https://x"}
    # GetVault belongs to the KMS service, NOT the secrets host — the secrets
    # host has no /vaults route and answers 404 NotAuthorizedOrNotFound.
    assert str(transport.requests[0].url).startswith(
        "https://kms.us-ashburn-1.oraclecloud.com/20180608/vaults/")


# ── endpoint hostnames ──────────────────────────────────────────────────────
#
# Pins a real user-reported bug: "Saved, but OCI apply failed: [Errno -2] Name
# or service not known". The Vault base URLs were built as
# ``vaults.<region>.oraclecloud.com`` / ``secrets.<region>.oraclecloud.com``,
# but the OCI Vault service lives under an ``.oci.`` label and the retrieval
# plane keeps the ``vaults.`` label too:
#     management: vaults.<region>.oci.oraclecloud.com
#     retrieval : secrets.vaults.<region>.oci.oraclecloud.com
# The old hostnames do not resolve AT ALL, so every Vault call died in the
# resolver before a request was ever signed or sent.

def test_vaults_base_uses_the_oci_label():
    url = oci_vault._vaults_base(_cfg())
    assert url.startswith("https://vaults.us-ashburn-1.oci.oraclecloud.com/")


def test_secrets_base_uses_the_secrets_vaults_oci_host():
    url = oci_vault._secrets_base(_cfg())
    assert url.startswith("https://secrets.vaults.us-ashburn-1.oci.oraclecloud.com/")


def test_vault_hosts_are_not_the_old_unresolvable_form():
    """Regression guard: the pre-fix hostnames must never come back."""
    vaults = oci_vault._vaults_base(_cfg())
    secrets = oci_vault._secrets_base(_cfg())
    assert "vaults.us-ashburn-1.oraclecloud.com" not in vaults
    assert "secrets.us-ashburn-1.oraclecloud.com" not in secrets
    # Both Vault planes are distinctly NOT the Core/iaas host.
    assert "iaas." not in vaults and "iaas." not in secrets


def test_management_and_retrieval_are_different_hosts():
    assert oci_vault._vaults_base(_cfg()) != oci_vault._secrets_base(_cfg())


def test_region_is_interpolated_into_both_planes():
    cfg = oci_vault.OciConfig({"region": "eu-frankfurt-1"})
    assert "eu-frankfurt-1" in oci_vault._vaults_base(cfg)
    assert "eu-frankfurt-1" in oci_vault._secrets_base(cfg)


def test_missing_region_is_a_config_error_not_a_dns_failure():
    cfg = oci_vault.OciConfig({"region": ""})
    with pytest.raises(oci_vault.OciVaultError, match="region"):
        oci_vault._vaults_base(cfg)
    with pytest.raises(oci_vault.OciVaultError, match="region"):
        oci_vault._secrets_base(cfg)


def test_malformed_region_is_rejected_before_any_network_call():
    """A typo'd region must fail as a clear config error rather than being
    interpolated into a hostname that then fails DNS with no context."""
    cfg = oci_vault.OciConfig({"region": "us ashburn 1"})
    with pytest.raises(oci_vault.OciVaultError, match="not a valid OCI region"):
        oci_vault._vaults_base(cfg)
