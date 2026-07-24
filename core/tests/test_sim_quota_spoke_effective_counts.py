"""``_reduce_spoke_effective_counts`` SUMS per-quota counts across cs spokes.

``_push_config`` apportions the tenant-total target N across a tenant's cs
spokes, so each spoke's pushed ``effective_sim_quotas`` carries its SHARE of N
(alert-tied even, e.g. 10 → 4/3/3). The reduction the hub uses to compare
against its applied count must therefore SUM the spokes' shares back to the
tenant total — NOT first-wins. First-wins picked one spoke's share (3) and
``_compute_stale_push`` compared it to the total (10), so every quota in a
multi-spoke tenant read as a perpetual "lags hub target" false positive and
the 45s reconcile-push self-heal re-pushed a no-op every tick. These pin the
sum so that can't regress.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from simulations.routes import _reduce_spoke_effective_counts  # noqa: E402


def _eff(alert_id, site, count):
    """A spoke's effective_sim_quotas entry (the shape CS_GET_SIM_QUOTA_STATE
    returns under ``data["effective"]``)."""
    return {"sim_id": "dns_fail", "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count}


def _spoke(eff):
    """A spoke reply: (sid, {"effective": [...]})."""
    return ("cs-svr-0", {"effective": eff})


def test_multi_spoke_shares_sum_to_tenant_total():
    # 3 spokes each hold their apportioned share of the 10-client target
    # (4/3/3) — the SUM is 10, not the first spoke's 4.
    results = [
        ("cs-svr-1", {"effective": [_eff("dns_fail", "MIA-PSK", 4)]}),
        ("cs-svr-2", {"effective": [_eff("dns_fail", "MIA-PSK", 3)]}),
        ("cs-svr-3", {"effective": [_eff("dns_fail", "MIA-PSK", 3)]}),
    ]
    counts = _reduce_spoke_effective_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 10}


def test_first_wins_was_the_bug_now_sums():
    # The exact false-positive from the field: hub target 10, first spoke holds
    # 3 (its share). First-wins returned 3 → perpetual "lags 10". Sum returns 10.
    results = [
        ("cs-svr-1", {"effective": [_eff("dns_fail", "MIA-PSK", 3),
                                    _eff("ssidpw_fail", "MIA-PSK", 1),
                                    _eff("assoc_fail", "MIA-ACD", 1)]}),
        ("cs-svr-2", {"effective": [_eff("dns_fail", "MIA-PSK", 3),
                                    _eff("ssidpw_fail", "MIA-PSK", 2),
                                    _eff("assoc_fail", "MIA-ACD", 1)]}),
        ("cs-svr-3", {"effective": [_eff("dns_fail", "MIA-PSK", 4),
                                    _eff("ssidpw_fail", "MIA-PSK", 2),
                                    _eff("assoc_fail", "MIA-ACD", 1)]}),
    ]
    counts = _reduce_spoke_effective_counts(results)
    # Tenant totals: dns 10, ssidpw 5, assoc 3 — matching the hub targets, so
    # _compute_stale_push sees sum == hub_count and flags NONE.
    assert counts == {"alert:dns_fail:MIA-PSK": 10,
                      "alert:ssidpw_fail:MIA-PSK": 5,
                      "alert:assoc_fail:MIA-ACD": 3}


def test_offline_spoke_drops_sum_flags_genuine_miss():
    # A spoke that didn't reply (None data) contributes 0 — its missing share
    # drops the sum below the total, so a genuine missed push still flags.
    results = [
        ("cs-svr-1", {"effective": [_eff("dns_fail", "MIA-PSK", 4)]}),
        ("cs-svr-2", None),                       # offline / no reply
        ("cs-svr-3", {"effective": [_eff("dns_fail", "MIA-PSK", 3)]}),
    ]
    counts = _reduce_spoke_effective_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 7}   # 4 + 3, the 3rd share gone


def test_quota_present_on_some_spokes_only():
    # A site-scoped quota apportioned only across the spokes that serve the site
    # — spokes it isn't on don't report the key at all. Sum the ones that do.
    results = [
        ("cs-svr-1", {"effective": [_eff("dns_fail", "MIA-PSK", 5)]}),
        ("cs-svr-2", {"effective": []}),            # serves a different site
        ("cs-svr-3", {"effective": [_eff("dns_fail", "MIA-PSK", 5)]}),
    ]
    counts = _reduce_spoke_effective_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 10}


def test_single_spoke_returns_its_count():
    results = [("cs-svr-1", {"effective": [_eff("dns_fail", "MIA-PSK", 10)]})]
    assert _reduce_spoke_effective_counts(results) == {"alert:dns_fail:MIA-PSK": 10}


def test_empty_and_malformed():
    assert _reduce_spoke_effective_counts([]) == {}
    assert _reduce_spoke_effective_counts(None) == {}
    # Non-dict data rows are skipped (a failed spoke's None payload).
    assert _reduce_spoke_effective_counts([("cs-svr-1", None), ("cs-svr-2", "oops")]) == {}
    # Non-dict quota entries inside effective are skipped.
    assert _reduce_spoke_effective_counts(
        [("cs-svr-1", {"effective": ["nope", _eff("dns_fail", "MIA-PSK", 7)]})]
    ) == {"alert:dns_fail:MIA-PSK": 7}


def test_count_missing_treated_as_zero():
    # A quota entry without a count field contributes 0, not a KeyError.
    results = [("cs-svr-1", {"effective": [
        {"sim_id": "dns_fail", "alert_type": "alert", "alert_id": "dns_fail",
         "site": "MIA-PSK"},               # no "count"
        _eff("dns_fail", "MIA-PSK", 6),
    ]})]
    assert _reduce_spoke_effective_counts(results) == {"alert:dns_fail:MIA-PSK": 6}