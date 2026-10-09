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


# ── targets box accepts CIDRs + ranges ───────────────────────────────────────
# Regression: a CIDR typed into the explicit "targets" box had its mask stripped
# by _add() and was scanned as the single network address, so "scan 10.0.0.0/24"
# quietly probed exactly one host. Targets now expand like subnets do.
def test_cidr_in_targets_is_expanded():
    ips, per = build_scan_target_pool(["10.0.0.0/30"], [], 100)
    assert ips == ["10.0.0.1", "10.0.0.2"]
    assert per == {"explicit": 2}


def test_host_cidr_in_targets_stays_one_host():
    # A /32 (how NetBox-style host addresses arrive) is still a single host.
    ips, per = build_scan_target_pool(["10.0.0.5/32"], [], 100)
    assert ips == ["10.0.0.5"]
    assert per == {"explicit": 1}


def test_dashed_range_in_targets_is_expanded():
    ips, per = build_scan_target_pool(["10.0.0.10-10.0.0.12"], [], 100)
    assert ips == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert per == {"explicit": 3}


def test_dashed_range_shorthand_last_octet():
    ips, _ = build_scan_target_pool(["10.0.0.10-12"], [], 100)
    assert ips == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_reversed_range_is_rejected_not_exploded():
    ips, per = build_scan_target_pool(["10.0.0.9-1"], [], 100)
    assert ips == []
    assert per == {}


def test_expanded_targets_still_respect_cap():
    ips, _ = build_scan_target_pool(["10.0.0.0/24"], [], 3)
    assert len(ips) == 3


def test_expanded_targets_dedup_against_subnets():
    ips, per = build_scan_target_pool(["10.0.0.0/30"], ["10.0.0.0/29"], 100)
    # /30 gives .1,.2; the /29 then only contributes .3-.6 (network/broadcast excluded).
    assert ips[:2] == ["10.0.0.1", "10.0.0.2"]
    assert per["explicit"] == 2
    assert per["subnets"] == 4


def test_split_leaf_and_supernets():
    from routes.nw import split_leaf_and_supernets
    leaves, supers = split_leaf_and_supernets(
        ["10.0.0.0/16", "10.0.1.0/24", "10.0.2.0/24", "192.168.1.0/24", "bogus", "fd00::/64"])
    assert [str(n) for n in supers] == ["10.0.0.0/16"]
    assert sorted(str(n) for n in leaves) == ["10.0.1.0/24", "10.0.2.0/24", "192.168.1.0/24"]


def test_split_leaf_and_supernets_dedupes_and_standalone():
    from routes.nw import split_leaf_and_supernets
    leaves, supers = split_leaf_and_supernets(["10.0.0.0/24", "10.0.0.0/24"])
    assert supers == [] and [str(n) for n in leaves] == ["10.0.0.0/24"]


def test_sweep_ranges_exclude_leaves():
    import ipaddress
    from routes.nw import sweep_ranges, split_leaf_and_supernets
    leaves, supers = split_leaf_and_supernets(["10.0.0.0/24", "10.0.1.0/24", "10.0.0.0/23"])
    # /23 contains both /24s -> nothing left to sweep
    assert sweep_ranges(supers, leaves) == []
    leaves, supers = split_leaf_and_supernets(["10.0.0.0/22", "10.0.1.0/24"])
    r = sweep_ranges(supers, leaves)
    total = sum(h - l + 1 for l, h in r)
    assert total == 1024 - 256 - 2  # /22 minus the /24 and its own net/broadcast
    # first usable host is 10.0.0.1, 10.0.1.x absent
    ips, cur, tot = __import__("routes.nw", fromlist=["sweep_take"]).sweep_take(r, 0, 5000)
    assert "10.0.1.5" not in ips and "10.0.0.1" in ips and "10.0.2.1" in ips


def test_sweep_take_cursor_and_wrap():
    from routes.nw import sweep_take
    r = [(167772161, 167772170)]  # 10.0.0.1-10.0.0.10
    ips, cur, tot = sweep_take(r, 0, 4)
    assert ips == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"] and cur == 4 and tot == 10
    ips, cur, _ = sweep_take(r, cur, 4, skip={"10.0.0.6"})
    assert ips == ["10.0.0.5", "10.0.0.7", "10.0.0.8"] and cur == 8
    ips, cur, _ = sweep_take(r, cur, 4)
    assert ips == ["10.0.0.9", "10.0.0.10"] and cur == 0


def test_wide_leaf_is_sweep_only():
    from routes.nw import split_leaf_and_supernets
    leaves, supers = split_leaf_and_supernets(["10.21.0.0/16", "172.21.0.0/24", "10.5.0.0/22"])
    assert [str(n) for n in supers] == ["10.21.0.0/16"]
    assert sorted(str(n) for n in leaves) == ["10.5.0.0/22", "172.21.0.0/24"]
