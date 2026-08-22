"""Tests for the network-scan hub pieces:
  * ``routes.nw.build_scan_target_pool`` — the pure IPv4 host-IP pool builder
    (explicit IPs + expanded CIDRs, deduped, bounded).
  * ``instance_vault`` recognizes the ``nw_scan_credentials`` storage key
    (secret + non-secret field maps) so scan credential sets are vault-backed.
"""
import pytest

from routes.nw import build_scan_target_pool
import instance_vault


# ── build_scan_target_pool ───────────────────────────────────────────────────
def test_explicit_targets_only():
    ips, per = build_scan_target_pool(["10.0.0.1", "10.0.0.2"], [], 100)
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert per == {"explicit": 2}


def test_subnet_expansion():
    ips, per = build_scan_target_pool([], ["10.0.0.0/30"], 100)
    # /30 → 2 usable hosts (.1, .2)
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert per == {"subnets": 2}


def test_slash31_yields_network_address():
    ips, per = build_scan_target_pool([], ["10.0.0.0/31"], 100)
    assert ips == ["10.0.0.0"]


def test_dedup_across_sources():
    ips, per = build_scan_target_pool(["10.0.0.1"], ["10.0.0.0/30"], 100)
    # .1 from explicit is not duplicated by the subnet expansion.
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert per["explicit"] == 1
    assert per["subnets"] == 1  # only .2 was new


def test_cap_is_enforced():
    ips, per = build_scan_target_pool([], ["10.0.0.0/24"], 5)
    assert len(ips) == 5


def test_ipv4_only_and_garbage_skipped():
    ips, per = build_scan_target_pool(
        ["10.0.0.1", "not-an-ip", "::1", "", "2001:db8::1"], ["bogus/33"], 100)
    assert ips == ["10.0.0.1"]


def test_large_prefix_does_not_blow_up():
    # A /8 must expand only up to the cap, not 16M hosts.
    ips, per = build_scan_target_pool([], ["10.0.0.0/8"], 50)
    assert len(ips) == 50


# ── instance_vault: nw_scan_credentials ─────────────────────────────────────
def test_scan_creds_secret_fields_registered():
    names = instance_vault.secret_field_names("nw_scan_credentials")
    assert "password" in names
    assert "enable_secret" in names
    assert "snmp_community" in names


def test_scan_creds_strip_inline_secrets_with_vault_ref():
    rec = {
        "id": "s1", "name": "core-creds",
        "username": "admin", "password": "hunter2", "snmp_community": "public",
        "vault_credential": {"bucket": "shared", "name": "core-login"},
    }
    instance_vault.strip_inline_secrets(rec, "nw_scan_credentials")
    # Secrets dropped (a vault ref is present); username (non-secret) retained.
    assert "password" not in rec or not rec.get("password")
    assert "snmp_community" not in rec or not rec.get("snmp_community")
    assert rec.get("username") == "admin"
