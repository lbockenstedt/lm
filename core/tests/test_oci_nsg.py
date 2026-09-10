"""oci_nsg.py — CIDR normalization, request signing, and NSG reconciliation.

Covers the OCI-specific pieces that have no Azure equivalent (Signature v1
signing, single-CIDR-per-rule reconciliation via bulk add/remove) plus the
CIDR-normalization helpers that mirror azure_nsg's semantics.
"""
import base64
import hashlib
import importlib.util
import json
import os
import sys

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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


oci_nsg = _load_from_src("oci_nsg", "oci_nsg.py")


# ── CIDR normalization ───────────────────────────────────────────────────────

def test_normalize_prefixes_dedupes_and_adds_default_mask():
    out = oci_nsg.normalize_prefixes(["203.0.113.5", "203.0.113.5", "203.0.113.0/24", "  "])
    assert out == ["203.0.113.5/32", "203.0.113.0/24"]


def test_normalize_prefixes_rejects_invalid_entry():
    with pytest.raises(oci_nsg.OciNsgError):
        oci_nsg.normalize_prefixes(["not-an-ip"])


def test_normalize_entries_dedupes_by_cidr_and_keeps_later_description():
    out = oci_nsg.normalize_entries([
        {"ip": "203.0.113.5", "description": ""},
        {"ip": "203.0.113.5", "description": "office VPN"},
        "198.51.100.0/24",
    ])
    assert out == [
        {"ip": "203.0.113.5/32", "description": "office VPN"},
        {"ip": "198.51.100.0/24", "description": ""},
    ]


def test_entries_to_ips_extracts_ip_field_only():
    assert oci_nsg.entries_to_ips([{"ip": "203.0.113.5/32", "description": "x"}, {"description": "no-ip"}]) == \
        ["203.0.113.5/32"]


def test_merge_live_prefixes_adds_untracked_live_cidrs():
    merged, added = oci_nsg.merge_live_prefixes(
        [{"ip": "203.0.113.5/32", "description": "known"}],
        ["203.0.113.5", "198.51.100.9"],
    )
    assert added == 1
    assert merged == [
        {"ip": "203.0.113.5/32", "description": "known"},
        {"ip": "198.51.100.9/32", "description": ""},
    ]


# ── request signing (Signature Version 1) ───────────────────────────────────

@pytest.fixture()
def rsa_keypair(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = tmp_path / "oci_api_key.pem"
    key_path.write_bytes(pem)
    return key, str(key_path)


def _cfg_for(key_path):
    return oci_nsg.OciConfig({
        "tenancy_ocid": "ocid1.tenancy.oc1..t", "user_ocid": "ocid1.user.oc1..u",
        "fingerprint": "aa:bb:cc:dd", "key_path": key_path, "region": "us-ashburn-1",
    })


def test_config_ready_requires_every_field(rsa_keypair):
    _, key_path = rsa_keypair
    assert _cfg_for(key_path).ready is True
    incomplete = oci_nsg.OciConfig({"tenancy_ocid": "t"})
    assert incomplete.ready is False


def test_signed_headers_signature_verifies_against_the_public_key(rsa_keypair, monkeypatch):
    key, key_path = rsa_keypair
    monkeypatch.setattr(oci_nsg._oci_auth, "_key_cache", {})  # avoid cross-test key-path collisions
    cfg = _cfg_for(key_path)
    body = json.dumps({"a": 1}, separators=(",", ":")).encode()
    headers = oci_nsg._signed_headers(cfg, "POST",
                                      "https://iaas.us-ashburn-1.oraclecloud.com/20160918/foo", body)

    # Reconstruct the exact signing string the way _signed_headers built it,
    # then verify the returned Authorization signature independently.
    signed_order = ["(request-target)", "date", "host", "content-length", "content-type", "x-content-sha256"]
    parts = {
        "(request-target)": "post /20160918/foo",
        "date": headers["date"],
        "host": headers["host"],
        "content-length": headers["content-length"],
        "content-type": headers["content-type"],
        "x-content-sha256": headers["x-content-sha256"],
    }
    signing_string = "\n".join(f"{h}: {parts[h]}" for h in signed_order)

    auth = headers["Authorization"]
    assert 'keyId="ocid1.tenancy.oc1..t/ocid1.user.oc1..u/aa:bb:cc:dd"' in auth
    assert 'algorithm="rsa-sha256"' in auth
    sig_b64 = auth.split('signature="')[1].rstrip('"')
    signature = base64.b64decode(sig_b64)

    key.public_key().verify(signature, signing_string.encode("ascii"),
                            padding.PKCS1v15(), hashes.SHA256())
    # content-sha256 header matches the body we actually signed for.
    assert headers["x-content-sha256"] == base64.b64encode(hashlib.sha256(body).digest()).decode()


def test_signed_headers_omits_body_headers_for_get(rsa_keypair, monkeypatch):
    _, key_path = rsa_keypair
    monkeypatch.setattr(oci_nsg._oci_auth, "_key_cache", {})
    cfg = _cfg_for(key_path)
    headers = oci_nsg._signed_headers(cfg, "GET",
                                      "https://iaas.us-ashburn-1.oraclecloud.com/20160918/foo", None)
    assert "content-length" not in headers
    assert "x-content-sha256" not in headers
    assert 'headers="(request-target) date host"' in headers["Authorization"]


def test_signed_headers_raises_when_auth_config_incomplete():
    cfg = oci_nsg.OciConfig({"tenancy_ocid": "t"})  # missing user/fingerprint/key/region
    with pytest.raises(oci_nsg.OciNsgError):
        oci_nsg._signed_headers(cfg, "GET", "https://iaas.us-ashburn-1.oraclecloud.com/20160918/foo", None)


# ── NSG reconciliation (mocked OCI API) ──────────────────────────────────────

def _managed_rule(rid, source):
    return {"id": rid, "direction": "INGRESS", "source": source,
            "description": "Managed by LM hub (lm-hub-allowlist) — do not edit by hand"}


async def _run_reconcile(cfg, occfg, ips, handler):
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return await oci_nsg.reconcile_allowlist(cfg, occfg, ips, http=client)


def test_reconcile_allowlist_adds_and_removes_to_match_desired_set(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..x", "dest_port": "443"}
    seen = {"removed": None, "added": None}

    def handler(request):
        if request.method == "GET" and request.url.path.endswith("/securityRules"):
            return httpx.Response(200, json=[
                _managed_rule("r1", "1.1.1.1/32"),
                _managed_rule("r2", "9.9.9.9/32"),
                {"id": "r3", "direction": "EGRESS", "source": "0.0.0.0/0", "description": ""},  # untouched
                {"id": "r4", "direction": "INGRESS", "source": "5.5.5.5/32", "description": "hand-made rule"},  # untouched
            ])
        if request.method == "POST" and request.url.path.endswith("/actions/removeSecurityRules"):
            seen["removed"] = json.loads(request.content)
            return httpx.Response(200, json={})
        if request.method == "POST" and request.url.path.endswith("/actions/addSecurityRules"):
            seen["added"] = json.loads(request.content)
            return httpx.Response(200, json={})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    res = asyncio.new_event_loop().run_until_complete(
        _run_reconcile(cfg, occfg, ["1.1.1.1", "2.2.2.2"], handler))

    assert res == {"applied": True, "prefixes": ["1.1.1.1/32", "2.2.2.2/32"], "added": 1, "removed": 1}
    assert seen["removed"] == {"securityRuleIds": ["r2"]}  # only the managed, no-longer-desired rule
    assert len(seen["added"]["securityRules"]) == 1
    added_rule = seen["added"]["securityRules"][0]
    assert added_rule["source"] == "2.2.2.2/32"
    assert added_rule["sourceType"] == "CIDR_BLOCK"
    assert added_rule["tcpOptions"]["destinationPortRange"] == {"min": 443, "max": 443}
    assert oci_nsg._MANAGED_MARKER in added_rule["description"]


def test_reconcile_allowlist_empty_desired_set_removes_all_managed_rules(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..x"}
    seen = {"removed": None, "added_called": False}

    def handler(request):
        if request.method == "GET" and request.url.path.endswith("/securityRules"):
            return httpx.Response(200, json=[_managed_rule("r1", "1.1.1.1/32")])
        if request.method == "POST" and request.url.path.endswith("/actions/removeSecurityRules"):
            seen["removed"] = json.loads(request.content)
            return httpx.Response(200, json={})
        if request.method == "POST" and request.url.path.endswith("/actions/addSecurityRules"):
            seen["added_called"] = True
            return httpx.Response(200, json={})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    res = asyncio.new_event_loop().run_until_complete(_run_reconcile(cfg, occfg, [], handler))

    assert res == {"applied": True, "prefixes": [], "added": 0, "removed": 1}
    assert seen["removed"] == {"securityRuleIds": ["r1"]}
    assert seen["added_called"] is False  # nothing to add — call must be skipped


def test_reconcile_allowlist_raises_when_nsg_not_found(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..missing"}

    def handler(request):
        return httpx.Response(404)

    with pytest.raises(oci_nsg.OciNsgError, match="not found"):
        asyncio.new_event_loop().run_until_complete(_run_reconcile(cfg, occfg, ["1.1.1.1"], handler))


def test_get_allowlist_returns_none_when_nsg_missing(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..missing"}
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    got = asyncio.new_event_loop().run_until_complete(oci_nsg.get_allowlist(cfg, occfg, http=client))
    assert got is None


def test_get_allowlist_returns_sorted_managed_sources(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..x"}

    def handler(request):
        return httpx.Response(200, json=[
            _managed_rule("r1", "9.9.9.9/32"),
            _managed_rule("r2", "1.1.1.1/32"),
        ])

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    got = asyncio.new_event_loop().run_until_complete(oci_nsg.get_allowlist(cfg, occfg, http=client))
    assert got == ["1.1.1.1/32", "9.9.9.9/32"]


def test_test_connection_raises_with_oci_error_body_on_failure(rsa_keypair):
    import asyncio
    _, key_path = rsa_keypair
    cfg = _cfg_for(key_path)
    occfg = {"nsg_id": "ocid1.nsg.oc1..x"}
    client = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(401, text="NotAuthenticated")))
    with pytest.raises(oci_nsg.OciNsgError, match="NotAuthenticated"):
        asyncio.new_event_loop().run_until_complete(oci_nsg.test_connection(cfg, occfg, http=client))
