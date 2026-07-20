"""Dongle-quarantine alert sources — ``bulk_dongle_failure`` and
``single_bus_failing`` (the ``_eval_tenant`` pull-branch).

The spoke's detection sweep (``sim_quota_engine._quarantine_sweep``) populates
``qt_state`` and relays it in the CS_TELEMETRY frame; the hub caches it in
``simulations_cache``. ``_eval_tenant`` reads it per spoke and edge-fires:
``bulk_dongle_failure`` when a host has >20% of its T2 clients never
connecting; ``single_bus_failing`` when one USB bus accumulates ≥3 fails.
Spoke decides; hub only alarms.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import alert_engine as ae  # noqa: E402
import notifications  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeStore:
    def __init__(self, rules):
        self._rules = rules

    async def get_alert_rules(self, tenant):
        return [r for r in self._rules if r.get("_tenant", tenant) == tenant]


class _FakeService:
    """SimulationsService stand-in: only ``_spokes_for_tenant`` is read by the
    qt_state branch. Returns (sid, raw_frame) tuples with a top-level qt_state."""
    def __init__(self, spokes):
        # spokes: [(sid, frame_dict)]
        self._spokes = spokes

    def _spokes_for_tenant(self, tenant_id):
        return list(self._spokes)


class _FakeHub:
    def __init__(self, rules, spokes):
        self.simulations_store = _FakeStore(rules)
        self.alert_engine = ae.AlertEngine(self)
        self._svc = _FakeService(spokes)

    # _eval_tenant receives `service` from run_alert_loop's SimulationsService;
    # here we hand our fake so the qt_state branch can read raw frames.
    def service(self):
        return self._svc


def _rule(source, recips=("noc@acme.com",), fmt="human", enabled=True):
    return {"id": "r1", "name": source, "source": source,
            "recipients": list(recips), "format": fmt, "enabled": enabled,
            "_tenant": "default"}


def _capture_send(monkeypatch):
    sent = []

    async def _send(hub, subject, body, to_emails=None, html=None, spoke_id=None):
        sent.append({"subject": subject, "body": body, "to": to_emails, "html": html})

    monkeypatch.setattr(notifications, "send_email", _send)
    return sent


def _eval(hub, tenant, needed):
    _run(ae._eval_tenant(hub.alert_engine, hub.service(), tenant, needed))


def test_bulk_dongle_failure_fires(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("bulk_dongle_failure")],
                   [("cs-spoke-1", {"spoke_name": "cs-lab",
                     "qt_state": {"bulk_hosts": ["hostA", "hostB"],
                                  "per_host": {"hostA": {"failed": 4, "total": 5}},
                                  "per_bus_fails": {}}})])
    _eval(hub, "default", {"bulk_dongle_failure"})
    assert len(sent) == 1
    assert "cs-lab" in sent[0]["subject"]
    assert "hostA" in sent[0]["body"] and "hostB" in sent[0]["body"]


def test_single_bus_failing_fires(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("single_bus_failing")],
                   [("cs-spoke-1", {"spoke_name": "cs-lab",
                     "qt_state": {"bulk_hosts": [],
                                  "per_bus_fails": {"3-1": 4, "3-2": 1}}})])
    _eval(hub, "default", {"single_bus_failing"})
    assert len(sent) == 1
    assert "3-1" in sent[0]["body"]
    assert "3-2" not in sent[0]["body"]  # below the ≥3 threshold


def test_no_qt_state_no_fire(monkeypatch):
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("bulk_dongle_failure"), _rule("single_bus_failing")],
                   [("cs-spoke-1", {"spoke_name": "cs-lab"})])  # no qt_state
    _eval(hub, "default", {"bulk_dongle_failure", "single_bus_failing"})
    assert sent == []


def test_no_service_no_fire(monkeypatch):
    """service=None (pre-startup) → branch guarded, no crash, no fire."""
    sent = _capture_send(monkeypatch)
    hub = _FakeHub([_rule("bulk_dongle_failure")], [])
    _run(ae._eval_tenant(hub.alert_engine, None, "default",
                         {"bulk_dongle_failure"}))
    assert sent == []


def test_bulk_recovery_clears_edge(monkeypatch):
    sent = _capture_send(monkeypatch)
    frame = {"spoke_name": "cs-lab",
             "qt_state": {"bulk_hosts": ["hostA"], "per_bus_fails": {}}}
    hub = _FakeHub([_rule("bulk_dongle_failure")], [("cs-spoke-1", frame)])
    # First tick: breach.
    _eval(hub, "default", {"bulk_dongle_failure"})
    assert len(sent) == 1
    # Second tick: bulk cleared → recovery.
    frame["qt_state"] = {"bulk_hosts": [], "per_bus_fails": {}}
    _eval(hub, "default", {"bulk_dongle_failure"})
    assert len(sent) == 2
    assert "OK" in sent[1]["subject"]
    # Third tick: still clear → silent.
    _eval(hub, "default", {"bulk_dongle_failure"})
    assert len(sent) == 2


def test_sources_include_dongle_alarms():
    assert "bulk_dongle_failure" in ae.SOURCES
    assert "single_bus_failing" in ae.SOURCES
    assert "Dongle" in ae._LABEL["bulk_dongle_failure"]
    assert "Dongle" in ae._LABEL["single_bus_failing"]