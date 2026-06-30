"""Integration test — prefix-matching (the actual tenant-isolation logic).

``access.filter_enabled`` (covered by ``test_subnet_filter.py``) is only
the *gate*; ``simulations/tenant_filter.py`` is the matching engine that
enforces per-tenant subnet isolation server-side. These tests lock in the
documented semantics: empty prefixes → show all, concrete-IP-in-prefix → show,
concrete-IP-not-in-prefix → hide, no-concrete-IP → drop by default (err on
hiding; ``drop_no_ip=False`` restores the legacy keep behavior), and the
firewall either-side-qualifies rule (a rule shows when either side carries a
tenant address — concrete IP in prefix OR a tenant-owned alias; a wildcard
side is simply skipped, not a drop). ``build_alias_map`` resolves OPNsense
alias names so a rule referencing ``LAN_NET`` is matched against the alias's
concrete networks, and carries each alias's ``category`` for tenant attribution.
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


# ── alias resolution ────────────────────────────────────────────────────────

def test_build_alias_map_resolves_concrete_nested_and_category():
    aliases = [
        {"name": "LAN_NET", "type": "network", "content": "10.20.0.0/24\n10.20.1.0/24",
         "category": "Acme"},
        {"name": "WEB_SRV", "type": "host", "content": "LAN_NET\n10.20.0.50"},  # nested + concrete
        {"name": "EMPTY", "type": "urltable", "content": ""},                   # resolves to []
    ]
    amap = build_alias_map(aliases)
    assert "lan_net" in amap and "web_srv" in amap and "empty" in amap
    lan = amap["lan_net"]["nets"]
    assert "10.20.0.0/24" in lan and "10.20.1.0/24" in lan
    assert amap["lan_net"]["category"] == "Acme"  # category carried through
    # nested LAN_NET resolved into WEB_SRV alongside its own concrete IP
    web = amap["web_srv"]["nets"]
    assert "10.20.0.50" in web
    assert any("10.20" in c for c in web)  # nested content pulled in
    assert amap["empty"]["nets"] == []    # known alias, nothing to overlap
    assert amap["empty"]["category"] == ""  # no category on EMPTY


# ── firewall rules (either side qualifies) ────────────────────────────────

def test_firewall_rule_shown_when_either_side_in_prefix():
    """A rule is shown when EITHER side carries a concrete IP in the tenant's
    prefixes — src-in-prefix, dst-in-prefix, or both."""
    assert firewall_rule_in_prefixes(
        {"source": "10.20.0.5", "destination": "8.8.8.8"}, TENANT_PREFIXES) is True
    assert firewall_rule_in_prefixes(
        {"source": "8.8.8.8", "destination": "192.168.5.10"}, TENANT_PREFIXES) is True


def test_firewall_rule_wildcard_side_does_not_drop_if_other_side_in_prefix():
    """A wildcard on one side contributes nothing for that side, but does NOT
    drop the rule — the other side being in the tenant's subnet still qualifies
    it. So any→<tenant-ip> and <tenant-ip>→any both show."""
    assert firewall_rule_in_prefixes(
        {"source": "any", "destination": "10.20.0.5"}, TENANT_PREFIXES) is True
    assert firewall_rule_in_prefixes(
        {"source": "10.20.0.5", "destination": "any"}, TENANT_PREFIXES) is True
    assert firewall_rule_in_prefixes(
        {"source": "any:443", "destination": "10.20.0.5"}, TENANT_PREFIXES) is True


def test_firewall_rule_dropped_when_neither_side_belongs_to_tenant():
    """any→any (neither side contributes a tenant address) and both-sides-off-prefix
    both drop — the rule can't be attributed to this tenant."""
    assert firewall_rule_in_prefixes(
        {"source": "any", "destination": "any"}, TENANT_PREFIXES) is False
    assert firewall_rule_in_prefixes(
        {"source": "8.8.8.8", "destination": "1.1.1.1"}, TENANT_PREFIXES) is False


def test_firewall_filter_rules_envelope():
    env = {"rules": [
        {"source": "any", "destination": "any"},          # neither side → drop
        {"source": "8.8.8.8", "destination": "1.1.1.1"},    # both outside → drop
        {"source": "10.20.0.5", "destination": "8.8.8.8"},  # src in prefix → keep
        {"source": "any", "destination": "192.168.5.10"},   # dst in prefix → keep
    ]}
    out = filter_firewall_rules(env, TENANT_PREFIXES)
    assert len(out["rules"]) == 2


def test_alias_match_lets_firewall_rule_through():
    """A rule whose side is an alias resolving into the tenant prefix is kept
    once the alias map resolves it (net-overlap path). Without the map that side
    is an unresolvable alias name and the other side is off-prefix → drop."""
    aliases = [{"name": "LAN_NET", "type": "network", "content": "10.20.0.0/24"}]
    amap = build_alias_map(aliases)
    rule = {"source": "LAN_NET", "destination": "8.8.8.8"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES, alias_map=amap) is True
    # Without the map: src is an unresolvable alias name, dst is off-prefix → drop.
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_alias_category_attribution_lets_firewall_rule_through():
    """A rule referencing an alias whose OPNsense ``category`` equals the
    tenant's display name is shown to that tenant even when the alias's resolved
    networks do NOT overlap the tenant's prefixes — the alias is the tenant's
    own (admin-tagged), which is attribution enough. The same alias with no/other
    category does not qualify via category (and its off-prefix nets don't
    overlap) → the rule drops."""
    aliases = [
        {"name": "ACME_ALIAS", "type": "network", "content": "8.8.8.8", "category": "Acme"},
        {"name": "OTHER_ALIAS", "type": "network", "content": "8.8.8.8", "category": "Other"},
        {"name": "NOCAT_ALIAS", "type": "network", "content": "8.8.8.8"},
    ]
    amap = build_alias_map(aliases)
    rule = {"source": "ACME_ALIAS", "destination": "1.1.1.1"}
    # tenant_category="Acme" → ACME_ALIAS belongs to Acme → show
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES, alias_map=amap,
                                      tenant_category="Acme") is True
    # other tenant: ACME_ALIAS isn't theirs and its nets are off-prefix → drop
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES, alias_map=amap,
                                      tenant_category="Other") is False
    # no tenant_category → category path disabled; ACME_ALIAS nets off-prefix → drop
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES, alias_map=amap) is False
    # OTHER_ALIAS with tenant_category="Other" → show (it's Other's alias)
    assert firewall_rule_in_prefixes({"source": "OTHER_ALIAS", "destination": "1.1.1.1"},
                                      TENANT_PREFIXES, alias_map=amap,
                                      tenant_category="Other") is True
    # NOCAT_ALIAS: no category, nets off-prefix → drop for any tenant
    assert firewall_rule_in_prefixes({"source": "NOCAT_ALIAS", "destination": "1.1.1.1"},
                                      TENANT_PREFIXES, alias_map=amap,
                                      tenant_category="Acme") is False


def test_firewall_rule_dropped_when_unresolvable_alias_no_map():
    """A rule whose side is an alias name we can't expand (no alias map) and
    whose other side is off-prefix is dropped — it can't be attributed to
    this tenant."""
    rule = {"source": "SOME_OTHER_TENANT_ALIAS", "destination": "8.8.8.8"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_rule_dropped_when_both_sides_unresolvable_interfaces():
    """Interface names (lan/opt1) aren't aliases and can't be expanded to
    concrete nets — neither side belongs to the tenant → drop."""
    rule = {"source": "lan", "destination": "opt1"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES) is False


def test_firewall_rule_category_overrides_to_show():
    """A rule explicitly tagged with the tenant's display-name category is shown
    regardless of source/destination — the admin attribution is the escape hatch,
    and it also covers any→any that would otherwise drop."""
    rule = {"source": "any", "destination": "any", "category": "Acme"}
    assert firewall_rule_in_prefixes(rule, TENANT_PREFIXES,
                                     tenant_category="Acme") is True


def test_category_match_accepts_name_slug_id_case_insensitive():
    """The admin may tag an OPNsense record with the tenant's display name, slug,
    netbox slug, or id, in any case. The category attribution accepts any of those
    (passed as an iterable), case-insensitively, so a record categorized 'acme'
    or 'ACME' still matches a tenant whose name is 'Acme'."""
    rule_any_any = lambda cat: {"source": "any", "destination": "any", "category": cat}
    cats = ["Acme", "acme", "ACME", "acme-corp", "acme_corp", "42"]
    # tenant passes name + slug + netbox slug + id
    tenant_cats = ["Acme", "acme-corp", "acme_corp", "42"]
    for c in cats:
        # only the ones in tenant_cats (case-insensitive) qualify
        expect = c.lower() in {t.lower() for t in tenant_cats}
        assert firewall_rule_in_prefixes(rule_any_any(c), TENANT_PREFIXES,
                                         tenant_category=tenant_cats) is expect, c
    # a category that isn't any of the tenant's names/slugs/ids → drop
    assert firewall_rule_in_prefixes(rule_any_any("Other"), TENANT_PREFIXES,
                                     tenant_category=tenant_cats) is False
    # string form still works (single category, case-insensitive)
    assert firewall_rule_in_prefixes(rule_any_any("acme"), TENANT_PREFIXES,
                                     tenant_category="Acme") is True