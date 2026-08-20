"""Unit tests for ``instance_vault`` — the per-instance Credential Vault linkage
that overlays NAC/ClearPass, NW network-device and NetBox/IPAM secrets onto the
spoke config at push time (and keeps the plaintext out of ``global_config``).
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import cred_vault  # noqa: E402
import instance_vault as iv  # noqa: E402
from fastapi import HTTPException  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _patch_get(monkeypatch, value, *, raises=None):
    async def _fake(hub, bucket, name):
        if raises is not None:
            raise raises
        return value
    monkeypatch.setattr(cred_vault, "automation_get", _fake)


# ── has_vault_ref / normalization ────────────────────────────────────────────
def test_has_vault_ref_variants():
    assert iv.has_vault_ref({"vault_credential": {"bucket": "b", "name": "n"}}) is True
    assert iv.has_vault_ref({"vault_credential": {"bucket": " ", "name": "n"}}) is False
    assert iv.has_vault_ref({"vault_credential": {"bucket": "b"}}) is False
    assert iv.has_vault_ref({"vault_credential": "b|n"}) is False
    assert iv.has_vault_ref({}) is False


# ── overlay ─────────────────────────────────────────────────────────────────
def test_overlay_noop_without_ref_returns_same_object(monkeypatch):
    inst = {"host": "https://cppm", "client_id": "cid", "client_secret": "inline"}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out is inst  # untouched, no copy, no vault call


def test_overlay_fills_nac_client_secret(monkeypatch):
    _patch_get(monkeypatch, {"client_secret": "vaulted-secret"})
    inst = {"host": "https://cppm", "client_id": "cid",
            "vault_credential": {"bucket": "acme", "name": "cppm"}}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out["client_secret"] == "vaulted-secret"
    assert out["client_id"] == "cid"               # non-secret preserved
    assert "vault_credential" not in out           # marker never reaches spoke
    assert "vault_credential" in inst              # original untouched


def test_overlay_nac_oauth_fills_client_secret(monkeypatch):
    # An OAuth2 account secret (client_id + client_secret) backs BOTH the client
    # id and secret — grant_type=client_credentials needs both. The linked vault
    # credential is the source of truth, so its client_id overlays the inline one.
    _patch_get(monkeypatch, {"client_id": "vault-cid", "client_secret": "vaulted-secret"})
    inst = {"host": "https://cppm", "client_id": "cid",
            "vault_credential": {"bucket": "acme", "name": "cppm"}}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out["client_secret"] == "vaulted-secret"
    assert out["client_id"] == "vault-cid"         # vault-carried client_id overlaid
    assert "user" not in out and "password" not in out


def test_overlay_nac_oauth_fills_empty_inline_client_id(monkeypatch):
    # Production case: the instance's inline client_id is empty because the
    # Credential Vault OAuth secret carries it. Without sourcing client_id from
    # the vault the spoke had no client_id → client_credentials grant skipped →
    # "No OAuth2 credentials available" → ClearPass 403.
    _patch_get(monkeypatch, {"client_id": "vault-cid", "client_secret": "vaulted-secret"})
    inst = {"host": "https://cppm", "client_id": "",
            "vault_credential": {"bucket": "lrb", "name": "Clearpass API"}}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out["client_id"] == "vault-cid"
    assert out["client_secret"] == "vaulted-secret"


def test_overlay_nac_login_preserves_inline_client_id(monkeypatch):
    # A plain username/password login secret does NOT carry client_id, so an
    # inline client_id is preserved (not clobbered) — no regression for the
    # password grant.
    _patch_get(monkeypatch, {"username": "svc", "password": "pw"})
    inst = {"host": "https://cppm", "client_id": "keep-me",
            "vault_credential": {"bucket": "acme", "name": "x"}}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out["client_id"] == "keep-me"
    assert out["user"] == "svc" and out["password"] == "pw"


def test_overlay_nac_login_maps_user_password(monkeypatch):
    # A username/password login secret backs the fallback user + password
    # (password grant) — NOT the OAuth client_secret.
    _patch_get(monkeypatch, {"username": "svc", "password": "pw"})
    inst = {"vault_credential": {"bucket": "acme", "name": "x"}}
    out = _run(iv.overlay(object(), inst, "nac_instances"))
    assert out["user"] == "svc"
    assert out["password"] == "pw"
    assert "client_secret" not in out              # login secret is NOT OAuth


def test_overlay_nw_only_overlays_carried_fields(monkeypatch):
    _patch_get(monkeypatch, {"api_token": "tok"})
    dev = {"address": "10.0.0.1", "transport": "rest",
           "vault_credential": {"bucket": "acme", "name": "sw"}}
    out = _run(iv.overlay(object(), dev, "nw_devices"))
    assert out["api_token"] == "tok"
    assert "password" not in out       # secret didn't carry a password → not set
    assert out["address"] == "10.0.0.1"


def test_overlay_resolve_failure_degrades(monkeypatch):
    _patch_get(monkeypatch, None, raises=cred_vault.CredVaultError("boom"))
    dev = {"address": "10.0.0.1",
           "vault_credential": {"bucket": "acme", "name": "sw"}}
    out = _run(iv.overlay(object(), dev, "nw_devices"))
    # No crash; marker dropped; no secret overlaid.
    assert "vault_credential" not in out
    assert "password" not in out and "api_token" not in out


def test_overlay_fills_ipam_api_token_from_token_secret(monkeypatch):
    # A NetBox (IPAM) connection's API token backed by a Vault "Token" secret
    # ({token}); the non-secret URL/verify stay inline and the marker is dropped.
    _patch_get(monkeypatch, {"token": "nb-token"})
    inst = {"url": "https://netbox", "verify_ssl": True,
            "vault_credential": {"bucket": "acme", "name": "netbox"}}
    out = _run(iv.overlay(object(), inst, "ipam_instances"))
    assert out["api_token"] == "nb-token"
    assert out["url"] == "https://netbox"          # non-secret preserved
    assert "vault_credential" not in out           # marker never reaches spoke
    assert "vault_credential" in inst              # original untouched


def test_overlay_fills_ipam_api_token_from_apikey_secret(monkeypatch):
    # A Vault "API key" secret ({apikey}) also supplies the NetBox api_token.
    _patch_get(monkeypatch, {"apikey": "nb-key"})
    inst = {"url": "https://netbox",
            "vault_credential": {"bucket": "acme", "name": "netbox"}}
    out = _run(iv.overlay(object(), inst, "ipam_instances"))
    assert out["api_token"] == "nb-key"


def test_strip_drops_ipam_api_token_when_ref_present():
    inst = {"url": "https://netbox", "api_token": "inline",
            "vault_credential": {"bucket": "acme", "name": "netbox"}}
    iv.strip_inline_secrets(inst, "ipam_instances")
    assert "api_token" not in inst                  # secret dropped from config
    assert inst["url"] == "https://netbox"          # non-secret kept
    assert inst["vault_credential"] == {"bucket": "acme", "name": "netbox"}


def test_validate_ipam_unusable_secret_is_400(monkeypatch):
    _patch_get(monkeypatch, {"unrelated": "x"})  # no usable field for ipam
    with pytest.raises(HTTPException) as ei:
        _run(iv.validate_ref(object(),
                             {"vault_credential": {"bucket": "acme", "name": "n"}},
                             {"user": {"tenants": ["acme"]}}, is_admin=False,
                             storage_key="ipam_instances"))
    assert ei.value.status_code == 400


def test_overlay_many(monkeypatch):
    _patch_get(monkeypatch, {"password": "p"})
    devs = [{"address": "1", "vault_credential": {"bucket": "b", "name": "n"}},
            {"address": "2", "password": "inline"}]
    out = _run(iv.overlay_many(object(), devs, "nw_devices"))
    assert out[0]["password"] == "p"
    assert out[1]["password"] == "inline"  # no ref → untouched


# ── strip_inline_secrets ─────────────────────────────────────────────────────
def test_strip_drops_inline_secrets_when_ref_present():
    inst = {"host": "h", "client_id": "cid", "client_secret": "inline",
            "password": "inline2",
            "vault_credential": {"bucket": " acme ", "name": " cppm "}}
    iv.strip_inline_secrets(inst, "nac_instances")
    assert "client_secret" not in inst and "password" not in inst
    assert inst["client_id"] == "cid"
    assert inst["vault_credential"] == {"bucket": "acme", "name": "cppm"}  # normalized


def test_strip_noop_without_ref_keeps_inline():
    inst = {"client_secret": "inline"}
    iv.strip_inline_secrets(inst, "nac_instances")
    assert inst["client_secret"] == "inline"


# ── validate_ref ─────────────────────────────────────────────────────────────
def test_validate_noop_for_unsupported_product(monkeypatch):
    # ldap has no vault-backed secret fields → always a no-op even with a ref.
    called = {"n": 0}
    async def _fake(hub, b, n):
        called["n"] += 1
        return {}
    monkeypatch.setattr(cred_vault, "automation_get", _fake)
    _run(iv.validate_ref(object(), {"vault_credential": {"bucket": "b", "name": "n"}},
                         {"user": {"tenants": []}}, is_admin=True, storage_key="ldap_instances"))
    assert called["n"] == 0


def test_validate_noop_without_ref():
    _run(iv.validate_ref(object(), {"host": "h"}, {"user": {"tenants": []}},
                         is_admin=False, storage_key="nac_instances"))


def test_validate_reach_denies_foreign_bucket(monkeypatch):
    _patch_get(monkeypatch, {"client_secret": "s"})
    with pytest.raises(HTTPException) as ei:
        _run(iv.validate_ref(object(),
                             {"vault_credential": {"bucket": "otherT", "name": "n"}},
                             {"user": {"tenants": ["myT"]}},
                             is_admin=False, storage_key="nac_instances"))
    assert ei.value.status_code == 404


def test_validate_admin_any_bucket_ok(monkeypatch):
    _patch_get(monkeypatch, {"client_secret": "s"})
    _run(iv.validate_ref(object(),
                         {"vault_credential": {"bucket": "__admin__", "name": "n"}},
                         {"user": {"tenants": []}}, is_admin=True,
                         storage_key="nac_instances"))


def test_validate_resolve_error_is_404(monkeypatch):
    _patch_get(monkeypatch, None, raises=cred_vault.CredVaultError("nope"))
    with pytest.raises(HTTPException) as ei:
        _run(iv.validate_ref(object(),
                             {"vault_credential": {"bucket": "acme", "name": "n"}},
                             {"user": {"tenants": ["acme"]}}, is_admin=False,
                             storage_key="nac_instances"))
    assert ei.value.status_code == 404


def test_validate_unusable_secret_is_400(monkeypatch):
    _patch_get(monkeypatch, {"unrelated": "x"})  # no usable field for nac
    with pytest.raises(HTTPException) as ei:
        _run(iv.validate_ref(object(),
                             {"vault_credential": {"bucket": "acme", "name": "n"}},
                             {"user": {"tenants": ["acme"]}}, is_admin=False,
                             storage_key="nac_instances"))
    assert ei.value.status_code == 400
