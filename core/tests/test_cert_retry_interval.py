"""Configurable failed-distribution retry interval
(``global_config["certs"]["distribution_retry_hours"]``).

The hub's ``run_cert_distribution_loop`` sweeps on a configurable cadence and
re-pushes any target whose last push FAILED (the le-ledger skip-check requires
``last_status == "SUCCESS"``, so an ERROR target is never skipped). The cadence
is read by ``HubCertDistributionMixin._cert_distribution_retry_seconds`` from
``global_config["certs"]["distribution_retry_hours"]`` (default 1h, matching the
prior hard-coded 3600s). These tests pin the helper's defaults + clamping; the
loop itself just ``await asyncio.sleep(self._cert_distribution_retry_seconds())``
so the helper is the whole feature surface.

Exercised via a bare ``HubCertDistributionMixin`` instance with a fake ``state``
(no LabManagerHub construction → no at-rest-encryption pull-in), mirroring the
``_BareSpoke`` pattern in test_hub_url_push.py.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_cert_distribution import HubCertDistributionMixin  # noqa: E402


class _FakeState:
    """Minimal ``self.state``: ``get_global_config()`` returns a stored dict."""
    def __init__(self, gc=None):
        self._gc = gc or {}
    def get_global_config(self):
        return self._gc


def _mixin(gc=None):
    m = HubCertDistributionMixin()
    m.state = _FakeState(gc)
    return m


# ── _cert_distribution_retry_seconds ─────────────────────────────────────────

def test_default_is_one_hour_when_unset():
    # No certs section at all → 1h default.
    assert _mixin({})._cert_distribution_retry_seconds() == 3600.0
    # certs section present but key missing → 1h default.
    assert _mixin({"certs": {}})._cert_distribution_retry_seconds() == 3600.0


def test_default_is_one_hour_when_null():
    assert _mixin({"certs": {"distribution_retry_hours": None}})._cert_distribution_retry_seconds() == 3600.0


def test_explicit_hours_scaled_to_seconds():
    assert _mixin({"certs": {"distribution_retry_hours": 2}})._cert_distribution_retry_seconds() == 7200.0
    assert _mixin({"certs": {"distribution_retry_hours": 6}})._cert_distribution_retry_seconds() == 21600.0


def test_fractional_hours_allowed():
    # 0.5h = 30 min — above the 60s floor, so preserved.
    assert _mixin({"certs": {"distribution_retry_hours": 0.5}})._cert_distribution_retry_seconds() == 1800.0


def test_clamped_to_60s_floor():
    # A typo of 0.001h (~3.6s) must NOT turn the loop into a tight retry storm.
    assert _mixin({"certs": {"distribution_retry_hours": 0.001}})._cert_distribution_retry_seconds() == 60.0


def test_zero_or_negative_falls_back_to_default():
    assert _mixin({"certs": {"distribution_retry_hours": 0}})._cert_distribution_retry_seconds() == 3600.0
    assert _mixin({"certs": {"distribution_retry_hours": -5}})._cert_distribution_retry_seconds() == 3600.0


def test_non_numeric_falls_back_to_default():
    assert _mixin({"certs": {"distribution_retry_hours": "soon"}})._cert_distribution_retry_seconds() == 3600.0
    assert _mixin({"certs": {"distribution_retry_hours": ""}})._cert_distribution_retry_seconds() == 3600.0


def test_string_numeric_is_parsed():
    # POST /setup/config can deliver a JSON string for a numeric field; accept it.
    assert _mixin({"certs": {"distribution_retry_hours": "3"}})._cert_distribution_retry_seconds() == 10800.0