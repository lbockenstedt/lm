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


# ── correlate_nw_records (cross-module NW stitch for /api/device-detail) ──────
from routes.nw import correlate_nw_records


def _cache(did, arp=None, macs=None, endpoints=None, interfaces=None):
    entry = {}
    if arp is not None:        entry["arp"] = {"status": "SUCCESS", "data": arp}
    if macs is not None:       entry["macs"] = {"status": "SUCCESS", "data": macs}
    if endpoints is not None:  entry["endpoints"] = {"status": "SUCCESS", "data": endpoints}
    if interfaces is not None: entry["interfaces"] = {"status": "SUCCESS", "data": interfaces}
    return {did: entry}


def test_correlate_matches_arp_by_ip():
    devs = [{"id": "d1", "name": "DIST-SW", "address": "172.16.1.90",
             "object_type": "aos_switch", "tenant_id": "lrb"}]
    cache = _cache("d1", arp=[{"ip": "172.16.1.16", "mac": "aa:bb:cc:dd:ee:ff",
                              "interface": "1/1/5", "vlan": "10"}])
    hits = correlate_nw_records(devs, cache, ip="172.16.1.16")
    assert len(hits) == 1
    assert hits[0]["name"] == "DIST-SW"
    assert hits[0]["is_self"] is False
    assert hits[0]["arp"][0]["interface"] == "1/1/5"


def test_correlate_matches_mac_normalized():
    devs = [{"id": "d1", "name": "SW", "address": "10.0.0.1"}]
    cache = _cache("d1", macs=[{"mac": "AABB.CCDD.EEFF", "interface": "5", "vlan": "1"}])
    hits = correlate_nw_records(devs, cache, mac="aa:bb:cc:dd:ee:ff")
    assert len(hits) == 1
    assert hits[0]["mac"][0]["interface"] == "5"


def test_correlate_is_self_when_ip_is_mgmt_address():
    devs = [{"id": "d1", "name": "DIST-SW", "address": "172.16.1.90"}]
    hits = correlate_nw_records(devs, {}, ip="172.16.1.90")
    assert len(hits) == 1 and hits[0]["is_self"] is True


def test_correlate_no_match_returns_empty():
    devs = [{"id": "d1", "name": "SW", "address": "10.0.0.1"}]
    cache = _cache("d1", arp=[{"ip": "10.0.0.9", "mac": "00:00:00:00:00:01"}])
    assert correlate_nw_records(devs, cache, ip="172.16.1.16") == []


def test_correlate_blank_mac_never_false_matches():
    devs = [{"id": "d1", "name": "SW", "address": "10.0.0.1"}]
    cache = _cache("d1", arp=[{"ip": "10.0.0.9", "mac": ""}])
    assert correlate_nw_records(devs, cache, mac="") == []
    assert correlate_nw_records(devs, cache, ip=None, mac=None) == []
