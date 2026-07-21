"""``_compute_stale_push`` flags quotas whose spoke-side count lags the hub's.

The starkest stale-push case is a quota that is in the hub's effective set but
MISSING from the spoke's (the effective-quota push never landed). The engine
never tries to fill it, so the Quota State view reads 0/target with no
eligibility explanation — and the old ``sc is not None`` guard silently skipped
exactly that case, hiding it. These tests pin that a missing quota is now
flagged (``missing=True``, spoke_count 0) alongside the count-mismatch case,
and that a current quota + a 0/0 no-op are not flagged.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from simulations.routes import _compute_stale_push  # noqa: E402


def _q(alert_id, site, count):
    return {"sim_id": "dns_fail", "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count}


def test_missing_quota_is_flagged():
    # Hub has dns_fail@MIA-PSK at 10; the spoke's effective set doesn't include
    # it at all (spoke_counts has no key) → the push never landed.
    eff = [_q("dns_fail", "MIA-PSK", 10), _q("ssidpw_fail", "MIA-PSK", 5)]
    spoke_counts = {}  # spoke reported nothing for either
    out = _compute_stale_push(eff, spoke_counts)
    keys = {e["key"] for e in out}
    assert "alert:dns_fail:MIA-PSK" in keys
    assert "alert:ssidpw_fail:MIA-PSK" in keys
    miss = {e["key"]: e for e in out}
    assert miss["alert:dns_fail:MIA-PSK"]["missing"] is True
    assert miss["alert:dns_fail:MIA-PSK"]["spoke_count"] == 0
    assert miss["alert:dns_fail:MIA-PSK"]["hub_count"] == 10


def test_count_mismatch_is_flagged_not_missing():
    # Spoke has the quota but at a stale count (8 vs hub 10) — flagged, not missing.
    eff = [_q("dns_fail", "MIA-PSK", 10)]
    spoke_counts = {"alert:dns_fail:MIA-PSK": 8}
    out = _compute_stale_push(eff, spoke_counts)
    assert len(out) == 1
    assert out[0]["spoke_count"] == 8
    assert out[0]["hub_count"] == 10
    assert out[0]["missing"] is False


def test_current_quota_not_flagged():
    eff = [_q("dns_fail", "MIA-PSK", 10)]
    spoke_counts = {"alert:dns_fail:MIA-PSK": 10}
    assert _compute_stale_push(eff, spoke_counts) == []


def test_zero_zero_not_flagged():
    # Hub count 0 and spoke missing/0 — nothing to push, no stale flag.
    eff = [_q("dns_fail", "MIA-PSK", 0)]
    assert _compute_stale_push(eff, {}) == []
    assert _compute_stale_push(eff, {"alert:dns_fail:MIA-PSK": 0}) == []


def test_spoke_zero_hub_positive_flagged():
    # Spoke explicitly has the quota at count 0 but hub wants 5 → flagged (not
    # missing — the key is present, just 0).
    eff = [_q("ssidpw_fail", "MIA-PSK", 5)]
    spoke_counts = {"alert:ssidpw_fail:MIA-PSK": 0}
    out = _compute_stale_push(eff, spoke_counts)
    assert len(out) == 1
    assert out[0]["spoke_count"] == 0
    assert out[0]["missing"] is False


def test_empty_inputs():
    assert _compute_stale_push([], {}) == []
    assert _compute_stale_push(None, None) == []