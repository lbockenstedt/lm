"""Regression: deleting a spoke/agent that has an ACTIVE out-of-contact alert must
purge the alert-loop state (_spoke_alerts / _spoke_alert_tier / _spoke_absent_since).

Bug it guards: _evict_spoke() cleared every per-spoke dict EXCEPT the alert-loop
ones, and the alert loop only re-evaluates APPROVED modules — so a deleted spoke's
alert lingered forever. The header "Module Status" count (derived from the active
alerts) kept counting the orphan while the Spokes & Agents page (walks
known_modules) showed nothing out of contact. See hub_spoke_registry._evict_spoke;
the decommission route already did this cleanup.
"""
from hub_spoke_registry import SpokeRegistryMixin
from spoke_alert_sync import SpokeAlertMixin, _TIER_ERROR


class _FakeHeartbeat:
    def __init__(self):
        self.last_seen = {}


class _FakeState:
    def __init__(self):
        self.system_state = {"module_metadata": {}}

    def clear_spoke_last_seen(self, pk):
        pass


class _EvictHub(SpokeRegistryMixin, SpokeAlertMixin):
    """Minimal hub exposing the real _evict_spoke + alert-list methods."""

    def __init__(self):
        self.simulations_cache = {}
        self.spoke_telemetry = {}
        self.rate_limiters = {}
        self.spoke_events = {}
        self.spoke_recovery = {}
        self.agent_logs = {}
        self.heartbeat = _FakeHeartbeat()
        self.state = _FakeState()
        self.spoke_id_alias = {}
        self.install_uuid_index = {}
        self._spoke_alerts = {}
        self._spoke_alert_tier = {}
        self._spoke_absent_since = {}

    def _primary_key(self, spoke_id):
        return spoke_id


def test_evict_spoke_purges_out_of_contact_alert():
    hub = _EvictHub()
    pk = "spoke-guid-1"
    # Seed an ACTIVE out-of-contact alert exactly as the alert loop would.
    hub._spoke_alerts[pk] = {"tier": _TIER_ERROR, "since_ts": 1.0,
                             "duration_s": 900, "detail": "out of contact 900s"}
    hub._spoke_alert_tier[pk] = _TIER_ERROR
    hub._spoke_absent_since[pk] = 1.0
    assert len(hub.get_active_spoke_alerts()) == 1  # indicator would count it

    hub._evict_spoke(pk)

    # All three alert-loop dicts purged...
    assert pk not in hub._spoke_alerts
    assert pk not in hub._spoke_alert_tier
    assert pk not in hub._spoke_absent_since
    # ...so the header "Module Status" active-alert list (and its count) is empty.
    assert hub.get_active_spoke_alerts() == []
