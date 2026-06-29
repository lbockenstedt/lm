"""Integration test — prefix-matching (the actual tenant-isolation logic).

``access.subnet_filter_enabled`` (covered by ``test_subnet_filter.py``) is only
the *gate*; ``simulations/tenant_filter.py`` is the matching engine that
enforces per-tenant subnet isolation server-side. These tests lock in the
documented semantics: empty prefixes → show all, concrete-IP-in-prefix → show,
concrete-IP-not-in-prefix → hide, no-concrete-IP (alias/any) → show, and the
stricter firewall two-sided rule. ``build_alias_map`` resolves OPNsense alias
names so a rule referencing ``LAN_NET`` is matched against the alias's concrete
networks.
"""

import pytest

from simulations.tenant_filter import (
    extract_addrs,
    filter_items_by_prefixes,
    filter_firewall_rules,
    firewall_rule_in_prefixes,
    build_alias_map,
)


TENANT_PREFIXES = ["10.20.0.0/16", "192.168.5.0/24"]


# ── extract_addrs ────────────────────────────────────────────────────────────

def test_extract_addrs_concrete_ip():
    assert extract_addrs("10.20.0.5") == ["10.20.0.5"]


def test_extract_addrs_cidr():
    assert extract_addrs("src 10.20.0.0/24 dst any") == ["10.20.0.0/24"]


def test_extract_addrs_alias_is_none():
    # alias names / wildcards yield None (not []) — "field had no addresses"
    assert extract_addrs("LAN_NET") is None
    assert extract_addrs("any") is None
    assert extract_addrs("") is None
    assert extract_addrs(None) is None


# ── filter_items_by_prefixes ───────────────────────────────────────────────

def test_empty_prefixes_shows_all():
    """No tenant prefixes configured → nothing to filter against → show all."""
    items = [{"ip": "10.20.0.1"}, {"ip": "8.8.8.8"}]
    out = filter_items_by_prefixes(items, [], ["ip"])
    assert out is items  # unchanged, same object


def test_keeps_in_prefix_hides_outside():
    items = [{"ip": "10.20.0.1"}, {"ip": "8.8.8.8"}, {"ip": "192.168.5.10"}]
    out = filter_items_by_prefixes(items, TENANT_PREFIXES, ["ip"])
    ips = [r["ip"] for r in out]
    assert ips == ["10.20.0.1", "192.168.5.10"]


def test_alias_field_dropped_cant_filter():
    """A record whose only IP field is an alias name (no concrete IP) is dropped
    by default — err on hiding when you can't attribute the record to a tenant.
    ``drop_no_ip=False`` restores the legacy "can't filter → show" behavior."""
    items = [{"source": "LAN_NET"}, {"source": "8.8.8.8"}]
    out = filter_items_by_prefixes(items, TENANT_PREFIXES, ["source"])
    # LAN_NET → dropped (no concrete addr, default err-on-hiding); 8.8.8.8 → hidden
    assert out == []
    # opt-in to the legacy keep-when-unattributable behavior
    out2 = filter_items_by_prefixes(items, TENANT_PREFIXES, ["source"], drop_no_ip=False)
    assert [r["source"] for r in out2] == ["LAN_NET"]


def test_envelope_dict_filtered_in_place():
    """A spoke envelope {data: [...]} is filtered in place (the list is mutated)."""
    env = {"data": [{"ip": "10.20.0.1"}, {"ip": "8.8.8.8"}], "other": "keep"}
    out = filter_items_by_prefixes(env, TENANT_PREFIXES, ["ip"])
    assert out is env
    assert [r["ip"] for r in env["data"]] == ["10.20.0.1"]
    assert env["other"] == "keep"  # non-list fields untouched


# ── firewall rules (strict two-sided) ──────────────────────────────────────

def test_firewall_global_rule_shown_both_wildcard():
    """any→any is a global policy; always shown."""
    rule = {"source": "any", "destination": "any"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is True


def test_firewall_rule_shown_when_dst_in_prefix():
    rule = {"source": "any", "destination": "10.20.0.5"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is True


def test_firewall_rule_hidden_when_both_sides_outside():
    rule = {"source": "8.8.8.8", "destination": "1.1.1.1"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_filter_rules_envelope():
    env = {"rules": [
        {"source": "any", "destination": "any"},          # global → keep
        {"source": "8.8.8.8", "destination": "1.1.1.1"},   # both outside → drop
        {"source": "any", "destination": "10.20.0.5"},     # dst in prefix → keep
    ]}
    out = filter_firewall_rules(env, TENANT_PREFIXES)
    assert len(out["rules"]) == 2


# ── alias resolution ────────────────────────────────────────────────────────

def test_build_alias_map_resolves_concrete_and_nested():
    aliases = [
        {"name": "LAN_NET", "type": "network", "content": "10.20.0.0/24\n10.20.1.0/24"},
        {"name": "WEB_SRV", "type": "host", "content": "LAN_NET\n10.20.0.50"},  # nested + concrete
        {"name": "EMPTY", "type": "urltable", "content": ""},                   # resolves to []
    ]
    amap = build_alias_map(aliases)
    assert "lan_net" in amap and "web_srv" in amap and "empty" in amap
    assert "10.20.0.0/24" in amap["lan_net"] and "10.20.1.0/24" in amap["lan_net"]
    # nested LAN_NET resolved into WEB_SRV alongside its own concrete IP
    assert "10.20.0.50" in amap["web_srv"]
    assert any("10.20" in c for c in amap["web_srv"])  # nested content pulled in
    assert amap["empty"] == []  # known alias, nothing to match


def test_alias_match_lets_firewall_rule_through():
    """A rule referencing an alias whose content is in the tenant prefix is kept
    once the alias map resolves it. Without the map the alias side is an
    unresolvable non-wildcard → dropped (err on hiding), so the map is what
    lets the tenant's own alias-based rule through."""
    aliases = [{"name": "LAN_NET", "type": "network", "content": "10.20.0.0/24"}]
    amap = build_alias_map(aliases)
    rule = {"source": "any", "destination": "LAN_NET"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES, alias_map=amap) is True
    # Without the map: dst is an unresolvable alias name (not a wildcard) → drop.
    # (Previously this leaked: both sides None → "global policy" → shown to all.)
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_rule_dropped_when_unresolvable_alias_no_map():
    """The cross-tenant leak fix: a rule whose non-wildcard side is an alias name
    we can't expand (no alias map) is NOT treated as global policy — it's
    dropped, because it can't be attributed to this tenant."""
    rule = {"source": "SOME_OTHER_TENANT_ALIAS", "destination": "any"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_rule_dropped_when_both_sides_unresolvable_interfaces():
    """Interface names (lan/opt1) aren't aliases and can't be expanded to
    concrete nets — both sides unresolvable non-wildcards → drop, not global."""
    rule = {"source": "lan", "destination": "opt1"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_global_rule_shown_both_wildcard_with_port():
    """any:443 → any is still genuine global policy (both sides wildcards)."""
    rule = {"source": "any:443", "destination": "any"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is True


def test_firewall_rule_one_side_wildcard_one_side_off_prefix_drops():
    """any → concrete-off-prefix: the concrete side is outside the tenant and the
    other side is a wildcard (not both wildcards) → drop."""
    rule = {"source": "any", "destination": "8.8.8.8"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False