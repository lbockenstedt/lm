"""Regression test for the shared monitored-check count evaluator (hub copy).

Pins the type-silo bug fix: in centralized mode the LM hub evaluates checks via
simulations/central_hub_poller.py, which must fire an alert-typed sim-quota on a
condition Central classifies as an INSIGHT (e.g. "DNS Server Failed to Respond"),
matched case-insensitively. check_eval is vendored byte-identical from
cs/lm-spoke/src/check_eval.py; keep this test in sync with the CS copy.
"""
from simulations.check_eval import count_for_check, normalize_counts  # noqa: E402


def test_normalize_folds_case_whitespace_and_sums():
    assert normalize_counts({" DNS Fail ": 2, "dns fail": 3}) == {"dns fail": 5}
    assert normalize_counts(None) == {}
    assert normalize_counts({"x": None}) == {"x": 0}


def test_alert_typed_check_fires_on_insight_bucket():
    check = {"id": "DNS Server Failed to Respond", "type": "alert"}
    insight_ci = normalize_counts({"dns server failed to respond": 4})
    assert count_for_check(check, normalize_counts({}), insight_ci) == 4


def test_insight_typed_check_fires_on_alert_bucket():
    check = {"id": "WPA Passphrase is Incorrect", "type": "insight"}
    alert_ci = normalize_counts({"wpa passphrase is incorrect": 6})
    assert count_for_check(check, alert_ci, normalize_counts({})) == 6


def test_case_insensitive_and_typed_bucket_wins():
    check = {"id": "DHCP Discover Timeout", "type": "alert"}
    assert count_for_check(check, normalize_counts({"dhcp discover timeout": 5}),
                           normalize_counts({"dhcp discover timeout": 9})) == 5


def test_missing_type_defaults_to_alert():
    assert count_for_check({"id": "Maximum Associations"},
                           normalize_counts({"maximum associations": 2}), {}) == 2


def test_absent_and_blank_id_are_zero():
    assert count_for_check({"id": "Nope", "type": "alert"}, normalize_counts({"x": 1}), {}) == 0
    assert count_for_check({"id": "", "type": "alert"}, {"x": 1}, {}) == 0
