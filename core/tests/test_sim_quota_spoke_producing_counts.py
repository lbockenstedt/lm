"""``_reduce_spoke_producing_counts`` SUMS per-quota ACTUAL producing counts
across cs spokes — the adaptive controller's input for clamping a learned
floor to reality (see sim_quota.adaptive_step's ``producing`` param).

Same apportionment/summing rationale as
``_reduce_spoke_effective_counts``/test_sim_quota_spoke_effective_counts.py,
but reduces ``diagnostics[].producing`` (functionally-working ledger clients,
per sim_quota_engine._is_harvestable / gateway-confirmed-down on the cs side)
instead of the requested ``effective[].count``.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from simulations.routes import _reduce_spoke_producing_counts  # noqa: E402


def _diag(key, producing, target=None):
    """A spoke's quota_diagnostics() entry (the shape CS_GET_SIM_QUOTA_STATE
    returns under ``data["diagnostics"]``)."""
    return {"key": key, "sim_id": "dns_fail", "site": "MIA-PSK",
            "target": target if target is not None else producing,
            "producing": producing}


def test_multi_spoke_producing_sums_to_tenant_total():
    results = [
        ("cs-svr-1", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 4)]}),
        ("cs-svr-2", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 3)]}),
        ("cs-svr-3", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 2)]}),
    ]
    counts = _reduce_spoke_producing_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 9}


def test_producing_can_undercount_target_when_clients_are_gateway_down():
    # A quota apportioned 10 (4/3/3) but 2 of the 10 assigned clients are
    # gateway-confirmed-down on one spoke — its producing (1) is less than its
    # own share (3). The tenant-total producing (8) is what should clamp a
    # learned floor, not the requested 10.
    results = [
        ("cs-svr-1", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 4, target=4)]}),
        ("cs-svr-2", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 3, target=3)]}),
        ("cs-svr-3", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 1, target=3)]}),
    ]
    counts = _reduce_spoke_producing_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 8}


def test_offline_spoke_drops_sum():
    results = [
        ("cs-svr-1", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 4)]}),
        ("cs-svr-2", None),                       # offline / no reply
        ("cs-svr-3", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 3)]}),
    ]
    counts = _reduce_spoke_producing_counts(results)
    assert counts == {"alert:dns_fail:MIA-PSK": 7}


def test_single_spoke_returns_its_producing():
    results = [("cs-svr-1", {"diagnostics": [_diag("alert:dns_fail:MIA-PSK", 8, target=10)]})]
    assert _reduce_spoke_producing_counts(results) == {"alert:dns_fail:MIA-PSK": 8}


def test_empty_and_malformed():
    assert _reduce_spoke_producing_counts([]) == {}
    assert _reduce_spoke_producing_counts(None) == {}
    assert _reduce_spoke_producing_counts([("cs-svr-1", None), ("cs-svr-2", "oops")]) == {}
    # Non-dict / keyless diagnostics entries are skipped.
    assert _reduce_spoke_producing_counts(
        [("cs-svr-1", {"diagnostics": ["nope", _diag("alert:dns_fail:MIA-PSK", 5)]})]
    ) == {"alert:dns_fail:MIA-PSK": 5}


def test_producing_missing_treated_as_zero():
    results = [("cs-svr-1", {"diagnostics": [
        {"key": "alert:dns_fail:MIA-PSK", "sim_id": "dns_fail", "site": "MIA-PSK"},  # no "producing"
        _diag("alert:dns_fail:MIA-PSK", 6),
    ]})]
    assert _reduce_spoke_producing_counts(results) == {"alert:dns_fail:MIA-PSK": 6}
