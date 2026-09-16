"""Watchdog for a DHCP spoke that advertises the role but manages no Kea.

Production symptom this guards: a host carried a stray ``dhcp`` role with an
empty ``cluster.json`` (``members: []``) and no Kea installed. Because
``_dhcp_spoke_for_request`` falls through to ``get_spoke_by_type("dhcp")`` for a
tenantless admin — first match in ``spoke_module_types`` INSERTION order, not
the healthiest — the DHCP Diagnostics tab probed that host and reported the
entire DHCP service dead while the real HA pair was serving leases.
"""
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from routes.setup import (  # noqa: E402
    _dhcp_ha_member_count,
    _dhcp_spokes_without_cluster,
)


# ── _dhcp_ha_member_count ────────────────────────────────────────────────────
def test_an_empty_members_list_counts_as_zero():
    assert _dhcp_ha_member_count({"members": [], "enabled": False}) == 0


def test_members_are_counted_from_the_list_when_present():
    st = {"members": [{"id": "a"}, {"id": "b"}], "member_count": 99}
    assert _dhcp_ha_member_count(st) == 2


def test_members_without_an_id_are_not_counted():
    assert _dhcp_ha_member_count({"members": [{"id": "a"}, {}, "junk"]}) == 1


def test_member_count_is_used_when_there_is_no_members_list():
    assert _dhcp_ha_member_count({"member_count": 2}) == 2


def test_a_failed_relay_is_unknown_not_empty():
    # The whole point: an unreachable spoke must NOT raise the finding.
    assert _dhcp_ha_member_count(None) is None


def test_a_reply_without_any_member_field_is_unknown():
    assert _dhcp_ha_member_count({"status": "SUCCESS"}) is None


def test_a_non_numeric_member_count_is_unknown():
    assert _dhcp_ha_member_count({"member_count": "two"}) is None
    assert _dhcp_ha_member_count({"member_count": True}) is None


# ── _dhcp_spokes_without_cluster ─────────────────────────────────────────────
def test_only_the_clusterless_spoke_is_flagged():
    status = {
        "mipbe": {"members": [{"id": "svcs01"}, {"id": "svcs02"}]},
        "rsvbe": {"members": [], "mode": "hot-standby"},
    }
    assert _dhcp_spokes_without_cluster(status) == {"rsvbe"}


def test_an_unreachable_spoke_is_never_flagged():
    assert _dhcp_spokes_without_cluster({"down": None, "odd": {}}) == set()


def test_a_healthy_fleet_produces_no_finding():
    status = {"a": {"member_count": 2}, "b": {"member_count": 2}}
    assert _dhcp_spokes_without_cluster(status) == set()


def test_no_dhcp_spokes_at_all_is_quiet():
    assert _dhcp_spokes_without_cluster({}) == set()
    assert _dhcp_spokes_without_cluster(None) == set()


# ── the finding the route derives from them ──────────────────────────────────
def _default_spoke_finding(default_spoke, clusterless):
    """The route's expression, verbatim (routes/setup.py, alert_diagnostics)."""
    return {default_spoke} & clusterless if default_spoke else set()


def test_the_production_case_flags_the_default_spoke():
    # spoke_module_types insertion order put the Kea-less host first, so the
    # tenantless read path selected it.
    status = {
        "rsvbe": {"members": []},
        "mipbe": {"members": [{"id": "svcs01"}, {"id": "svcs02"}]},
    }
    clusterless = _dhcp_spokes_without_cluster(status)
    assert _default_spoke_finding("rsvbe", clusterless) == {"rsvbe"}


def test_a_clusterless_spoke_that_is_not_the_default_is_only_a_warning():
    status = {"rsvbe": {"members": []}, "mipbe": {"member_count": 2}}
    clusterless = _dhcp_spokes_without_cluster(status)
    assert clusterless == {"rsvbe"}
    assert _default_spoke_finding("mipbe", clusterless) == set()
