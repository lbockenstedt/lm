"""Tests for OCI allow-list subtraction (the OCI equivalent of Azure's deny rule).

OCI network security groups — and OCI security lists — are ALLOW-only with
implicit default-deny. There is no deny rule to add, so the only way to stop
traffic that a broad allow rule currently admits is to remove the offending
address from what is permitted. Azure keeps using a real deny rule; this is the
OCI path to the same net effect.

The pathological case is a wide-open allow list: excluding a single /32 from
0.0.0.0/0 costs 32 prefixes, so the subtraction has to refuse loudly rather
than blow the NSG's 120-rule budget.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import oci_nsg  # noqa: E402


def _sub(allow, blocked, **kw):
    return oci_nsg.subtract_blocked(allow, blocked, **kw)


# ── core behaviour ───────────────────────────────────────────────────────────

def test_blocked_host_inside_trusted_range_is_excluded():
    """The case subtraction exists for: a bad host inside a trusted /16."""
    res, rep = _sub(["10.0.0.0/16"], ["10.0.5.7"])
    assert "10.0.5.7/32" in rep["removed"]
    assert not rep["truncated"]
    # the blocked address must not be covered by any remaining prefix
    import ipaddress
    tgt = ipaddress.ip_address("10.0.5.7")
    assert not any(tgt in ipaddress.ip_network(c) for c in res)


def test_remaining_addresses_in_range_still_allowed():
    """Subtraction must not over-block its neighbours."""
    import ipaddress
    res, _ = _sub(["10.0.0.0/16"], ["10.0.5.7"])
    nets = [ipaddress.ip_network(c) for c in res]
    for keep in ("10.0.5.6", "10.0.5.8", "10.0.0.1", "10.0.255.254"):
        assert any(ipaddress.ip_address(keep) in n for n in nets), keep


def test_ip_outside_allow_list_is_already_denied():
    """Default-deny already handles it — not an error, not a change."""
    res, rep = _sub(["10.0.0.0/16"], ["203.0.113.9"])
    assert rep["already_denied"] == ["203.0.113.9/32"]
    assert rep["removed"] == []
    assert res == ["10.0.0.0/16"]


def test_blocking_the_entire_allow_prefix_removes_it():
    res, rep = _sub(["10.0.0.0/16"], ["10.0.0.0/16"])
    assert res == []
    assert rep["removed"] == ["10.0.0.0/16"]


def test_allow_prefix_fully_inside_blocked_range_is_removed():
    res, _ = _sub(["10.0.5.0/24"], ["10.0.0.0/16"])
    assert res == []


def test_multiple_blocks_all_applied():
    import ipaddress
    res, rep = _sub(["10.0.0.0/16"], ["10.0.5.7", "10.0.9.9"])
    assert len(rep["removed"]) == 2
    nets = [ipaddress.ip_network(c) for c in res]
    for b in ("10.0.5.7", "10.0.9.9"):
        assert not any(ipaddress.ip_address(b) in n for n in nets)


# ── the 0.0.0.0/0 problem ────────────────────────────────────────────────────

def test_single_block_against_open_allow_costs_32_prefixes():
    """Documents the cost that makes an open allow list impractical."""
    res, rep = _sub(["0.0.0.0/0"], ["203.0.113.9"], max_prefixes=100000)
    assert len(res) == 32
    assert rep["projected"] == 32


def test_open_allow_list_refuses_rather_than_blowing_rule_budget():
    """Against 0.0.0.0/0 each blocked IP costs up to 32 prefixes, so the list
    exhausts OCI's rule budget within a handful of blocks. Refuse outright
    rather than half-apply: a partial exclusion would leave some blocked
    traffic permitted AND consume the budget."""
    blocks = ["203.0.113.9", "198.51.100.4", "192.0.2.5", "203.0.113.77",
              "8.8.8.8", "1.1.1.1"]
    res, rep = _sub(["0.0.0.0/0"], blocks)
    assert rep["truncated"] is True
    assert res == ["0.0.0.0/0"], "must not half-apply"
    assert rep["removed"] == [], "nothing was actually removed"
    assert rep["projected"] > oci_nsg.MAX_ALLOW_PREFIXES


def test_shared_parent_blocks_cost_less_than_scattered_ones():
    """Two addresses in the same /24 share most of their exclusion prefixes —
    which is why the cap is a projected-cost check, not a block count."""
    same = _sub(["0.0.0.0/0"], ["203.0.113.9", "203.0.113.77"],
                max_prefixes=100000)[1]["projected"]
    scattered = _sub(["0.0.0.0/0"], ["203.0.113.9", "8.8.8.8"],
                     max_prefixes=100000)[1]["projected"]
    assert same < scattered


def test_truncated_report_states_the_projected_cost():
    """The caller needs the number to explain WHY it refused."""
    _, rep = _sub(["0.0.0.0/0"], ["1.2.3.4", "5.6.7.8", "9.10.11.12",
                                  "13.14.15.16", "17.18.19.20"])
    assert rep["truncated"]
    assert rep["projected"] >= 100


def test_under_cap_is_applied_against_open_allow():
    """One or two blocks against 0.0.0.0/0 still fit and must work."""
    import ipaddress
    res, rep = _sub(["0.0.0.0/0"], ["203.0.113.9"])
    assert not rep["truncated"]
    assert not any(ipaddress.ip_address("203.0.113.9") in ipaddress.ip_network(c)
                   for c in res)


# ── robustness ───────────────────────────────────────────────────────────────

def test_no_blocks_is_identity():
    res, rep = _sub(["10.0.0.0/16", "192.168.1.0/24"], [])
    assert sorted(res) == ["10.0.0.0/16", "192.168.1.0/24"]
    assert not rep["truncated"]


def test_empty_allow_list_stays_empty():
    res, rep = _sub([], ["10.0.0.1"])
    assert res == []


def test_malformed_block_is_skipped_not_fatal():
    """One corrupt block record must not abort the whole allow push."""
    res, rep = _sub(["10.0.0.0/16"], ["not-an-ip", "10.0.5.7"])
    assert "10.0.5.7/32" in rep["removed"]


def test_malformed_allow_cidr_raises():
    with pytest.raises(oci_nsg.OciNsgError):
        _sub(["not-a-cidr"], ["10.0.0.1"])


def test_ipv6_blocks_do_not_touch_ipv4_prefixes():
    """Cross-family subtraction must be a no-op, not an error."""
    res, rep = _sub(["10.0.0.0/16"], ["2001:db8::1"])
    assert res == ["10.0.0.0/16"]
    assert rep["already_denied"] == ["2001:db8::1/128"]


def test_ipv6_subtraction_works():
    import ipaddress
    res, rep = _sub(["2001:db8::/32"], ["2001:db8::1"], max_prefixes=100000)
    assert rep["removed"] == ["2001:db8::1/128"]
    assert not any(ipaddress.ip_address("2001:db8::1") in ipaddress.ip_network(c)
                   for c in res)


def test_mixed_families_preserved():
    res, _ = _sub(["10.0.0.0/16", "2001:db8::/32"], ["10.0.5.7"],
                  max_prefixes=100000)
    assert any(":" in c for c in res), "IPv6 prefix must survive"


def test_no_block_path_is_an_exact_identity():
    """With nothing to subtract the allow set must be passed through UNCHANGED
    — not collapsed. The pushed prefixes are read back and folded into the
    local entry DB by merge_live_prefixes, so silently merging overlapping
    trusted entries here would rewrite the operator's configured list."""
    res, rep = _sub(["10.0.0.0/24", "10.0.0.0/25"], [])
    assert res == ["10.0.0.0/24", "10.0.0.0/25"]
    assert not rep["truncated"]


# ── operator entries must survive verbatim ───────────────────────────────────

def test_untouched_entries_are_not_collapsed():
    """Regression: the pushed prefixes are read back into the operator's entry
    DB by merge_live_prefixes. Summarising 20 configured /32s into 6 generated
    ranges would silently replace what they typed. Only prefixes that actually
    had to be SPLIT may change shape."""
    allow = [f"203.0.113.{i}/32" for i in range(1, 21)]
    res, rep = _sub(allow, ["198.51.100.99"])  # block matches nothing
    assert sorted(res) == sorted(allow)
    assert rep["already_denied"] == ["198.51.100.99/32"]


def test_blocking_an_allow_listed_host_just_drops_that_entry():
    """The target-state case: a /32 allow list where an offending IP is one of
    the allowed devices. Costs no fragmentation at all."""
    allow = [f"203.0.113.{i}/32" for i in range(1, 21)]
    res, rep = _sub(allow, ["203.0.113.7"])
    assert len(res) == 19
    assert "203.0.113.7/32" not in res
    assert rep["removed"] == ["203.0.113.7/32"]


def test_only_the_split_prefix_changes_others_verbatim():
    res, _ = _sub(["203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"],
                  ["203.0.113.55"])
    assert "198.51.100.0/24" in res, "unrelated entry must be untouched"
    assert "192.0.2.0/24" in res
    assert "203.0.113.0/24" not in res, "the split entry is replaced by fragments"
