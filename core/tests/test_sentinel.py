"""In-process access sentinel (application-level tripwire, §5J-J1/J2).

Verifies the crown-jewel access contract:
  1. ``is_allowed`` — allowed caller passes, unknown caller fails, unknown
     resource is un-contracted (allowed), canary allows no one.
  2. ``guard`` OBSERVE — a contract breach reports a critical
     ``sentinel_violation`` anomaly but does NOT raise (never breaks automation).
  3. ``guard`` ENFORCE — a breach additionally raises ``SentinelViolation``.
  4. A registered canary trips on ANY access.
  5. The per-resource volume guard emits ``sentinel_rate`` on a read burst.
  6. An in-contract caller (this test module, registered) is silent.
"""
import os
import sys

import pytest

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from security import sentinel  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate():
    """Snapshot + restore the sentinel's module-level policy/state per test."""
    allow = {k: set(v) for k, v in sentinel._ALLOW.items()}
    canary = set(sentinel._CANARY)
    mode = dict(sentinel._MODE)
    rate = dict(sentinel._RATE)
    hits = dict(sentinel._hits)
    reporter = sentinel._reporter
    events = []
    sentinel.set_reporter(lambda kind, detail, ip, sev: events.append(
        {"kind": kind, "detail": detail, "ip": ip, "severity": sev}))
    sentinel._hits.clear()
    try:
        yield events
    finally:
        sentinel._ALLOW.clear(); sentinel._ALLOW.update(allow)
        sentinel._CANARY.clear(); sentinel._CANARY.update(canary)
        sentinel._MODE.clear(); sentinel._MODE.update(mode)
        sentinel._RATE.clear(); sentinel._RATE.update(rate)
        sentinel._hits.clear(); sentinel._hits.update(hits)
        sentinel.set_reporter(reporter)


def test_is_allowed_contract():
    assert sentinel.is_allowed("vault.automation_get", "henet_sync")
    assert sentinel.is_allowed("vault.automation_get", "routes.console")
    assert not sentinel.is_allowed("vault.automation_get", "evil_module")
    # An un-contracted resource is not flagged (no policy → allow).
    assert sentinel.is_allowed("something.unlisted", "whoever")


def test_canary_allows_no_one():
    sentinel.register_canary("vault.canary")
    assert not sentinel.is_allowed("vault.canary", "henet_sync")
    sentinel.guard("vault.canary", detail="decoy read")
    # (events captured via fixture)


def test_canary_reports_on_any_access(_isolate):
    sentinel.register_canary("vault.canary")
    sentinel.guard("vault.canary", detail="decoy", ip="9.9.9.9")
    hit = [e for e in _isolate if e["kind"] == "sentinel_violation"]
    assert len(hit) == 1
    assert hit[0]["severity"] == "critical"
    assert hit[0]["ip"] == "9.9.9.9"
    assert "canary" in hit[0]["detail"]


def test_observe_breach_reports_without_raising(_isolate):
    # This test module is NOT on the automation_get allow-list → breach.
    sentinel.guard("vault.automation_get", detail="b/n")  # must not raise
    viol = [e for e in _isolate if e["kind"] == "sentinel_violation"]
    assert len(viol) == 1
    assert viol[0]["severity"] == "critical"
    assert __name__.rsplit(".", 1)[-1] in viol[0]["detail"] or "test_sentinel" in viol[0]["detail"]


def test_enforce_breach_raises(_isolate):
    sentinel.set_mode("vault.automation_get", sentinel.ENFORCE)
    with pytest.raises(sentinel.SentinelViolation):
        sentinel.guard("vault.automation_get", detail="b/n")


def test_allowed_caller_is_silent(_isolate):
    # Register THIS module as an allowed caller → no violation.
    sentinel._ALLOW.setdefault("vault.automation_get", set()).add(__name__)
    sentinel.guard("vault.automation_get", detail="b/n")
    viol = [e for e in _isolate if e["kind"] == "sentinel_violation"]
    assert viol == []


def test_rate_guard_trips_on_burst(_isolate):
    sentinel._RATE["vault.automation_get"] = (3, 60.0)
    sentinel._ALLOW["vault.automation_get"].add(__name__)  # allowed → isolate rate signal
    for _ in range(5):
        sentinel.guard("vault.automation_get", detail="b/n")
    rate = [e for e in _isolate if e["kind"] == "sentinel_rate"]
    assert rate, "expected a sentinel_rate anomaly once the burst exceeds the limit"
    assert rate[0]["severity"] == "warning"
