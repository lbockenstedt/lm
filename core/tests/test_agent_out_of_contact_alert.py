"""Relayed-agent out-of-contact alerts (``SpokeAlertMixin.get_agent_alerts``).

THE GAP: the footer MODULE STATUS dot reddens only on ``spoke_out_of_contact``
alerts, and relayed node agents are DELIBERATELY excluded from that sweep
(``_selfheal_leaked_agents`` pops them — they live under composite heartbeat
keys, not as module spokes). Observed live: every pxmx agent on the fleet went
down, all four parent cs spokes stayed connected, NOTHING raised an alert, and
the tray stayed green while four hosts were dark. A healthy spoke is not
evidence that the agents it carries are healthy.

These lock in the producer and, critically, the things it must NOT alert on —
a noisy new alert source gets muted, which would reopen the hole.
"""
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import spoke_alert_sync as sas  # noqa: E402

NOW = 2_000_000.0
WARN, ERROR = 300, 1800


class _State:
    def __init__(self, decommissioned=()):
        self._d = set(decommissioned)
        self.system_state = {}

    def is_agent_decommissioned(self, aid):
        return aid in self._d


class _HB:
    def __init__(self, last_seen=None):
        self.last_seen = last_seen or {}


class _Hub:
    """Only what get_agent_alerts touches."""

    _AGENT_ALERT_MAX_AGE_S = sas.SpokeAlertMixin._AGENT_ALERT_MAX_AGE_S
    _relayed_agent_last_seen = sas.SpokeAlertMixin._relayed_agent_last_seen
    get_agent_alerts = sas.SpokeAlertMixin.get_agent_alerts

    def __init__(self, agent_info=None, hb=None, decommissioned=()):
        self.agent_info = agent_info or {}
        self.heartbeat = _HB(hb)
        self.state = _State(decommissioned)

    def _spoke_alert_thresholds(self):
        return WARN, ERROR


def _alerts(hub, now=NOW, monkeypatch=None):
    import time
    orig = time.time
    time.time = lambda: now
    try:
        return hub.get_agent_alerts()
    finally:
        time.time = orig


# ── the reported outage ──────────────────────────────────────────────────────

def test_dead_agent_raises_an_error_alert():
    """Four agents dark for hours while their spokes stayed healthy."""
    hub = _Hub(hb={"cs-svr-01:pxmx-cs-svr-01": NOW - 4 * 3600})
    a = _alerts(hub)
    assert len(a) == 1
    assert a[0]["tier"] == "error"
    assert a[0]["spoke_id"] == "agent:pxmx-cs-svr-01"
    assert "out of contact" in a[0]["detail"]


def test_warn_tier_before_error():
    hub = _Hub(hb={"cs-1:agent-a": NOW - (WARN + 60)})
    assert _alerts(hub)[0]["tier"] == "warning"


def test_persisted_composite_key_survives_a_hub_restart():
    """agent_info is wiped on restart; the composite heartbeat key is persisted,
    and it is the ONLY thing that still knows the agent existed."""
    hub = _Hub(agent_info={}, hb={"cs-1:agent-a": NOW - 7200})
    assert _alerts(hub)[0]["spoke_id"] == "agent:agent-a"


def test_freshest_signal_wins():
    hub = _Hub(agent_info={"agent-a": {"last_seen": NOW - 10}},
               hb={"cs-1:agent-a": NOW - 9999})
    assert _alerts(hub) == []          # seen 10s ago → healthy


def test_errors_sort_before_warnings():
    hub = _Hub(hb={"cs-1:warn-agent": NOW - (WARN + 60),
                   "cs-1:dead-agent": NOW - 9999})
    assert [x["tier"] for x in _alerts(hub)] == ["error", "warning"]


# ── must NOT alert (a noisy producer gets muted, reopening the gap) ──────────

def test_healthy_agent_is_silent():
    assert _alerts(_Hub(hb={"cs-1:agent-a": NOW - 30})) == []


def test_never_seen_agent_is_silent():
    """Nothing to be out of contact FROM."""
    assert _alerts(_Hub(agent_info={"agent-a": {}}, hb={})) == []


def test_decommissioned_agent_is_silent():
    hub = _Hub(hb={"cs-1:agent-a": NOW - 9999}, decommissioned={"agent-a"})
    assert _alerts(hub) == []


def test_long_retired_agent_is_silent():
    """Older than the max age = retired hardware, not an outage."""
    hub = _Hub(hb={"cs-1:agent-a": NOW - (31 * 86400)})
    assert _alerts(hub) == []


def test_plain_spoke_heartbeat_keys_are_ignored():
    """Only COMPOSITE keys carry an agent — a bare spoke key must not be
    reported as a dead agent (it has its own producer)."""
    hub = _Hub(hb={"cs-svr-01": NOW - 9999})
    assert _alerts(hub) == []


def test_zero_and_garbage_timestamps_are_ignored():
    hub = _Hub(hb={"cs-1:a": 0, "cs-1:b": None, "cs-1:c": "nope"})
    assert _alerts(hub) == []


def test_a_broken_state_never_breaks_status():
    class _Boom(_Hub):
        def _relayed_agent_last_seen(self):
            raise RuntimeError("bad map")
    assert _Boom().get_agent_alerts() == []


def test_friendly_name_prefers_the_raw_agent_id():
    hub = _Hub(agent_info={"guid-123": {"agent_id": "pxmx-cs-svr-02",
                                        "last_seen": NOW - 9999}})
    assert _alerts(hub)[0]["name"] == "pxmx-cs-svr-02"
