"""Regression tests for relayed-agent liveness on the Dashboard's
Infrastructure Status tile (``routes/dashboard.infra_item_status``).

A relayed node agent (pxmx / cs) never joins ``active_connections`` — it dials
its PARENT SPOKE, which relays ``AGENT_RELAY_UP`` to the hub. The tile tested
every ``module_metadata`` entry with the spoke-only
``_primary_key(sid) in active_connections`` check, so an approved pxmx agent
read **offline** on the dashboard while Setup → Spokes & Agents showed the same
host ``Online`` and ``seen 6s ago``. ``spoke_alert_sync`` already fixed this
exact spoke-vs-agent confusion for the out-of-contact alerts; the dashboard tile
had not been given the same treatment.

These lock in:

* a live agent known only via ``agent_info`` reads online/green;
* a live agent known only via the persisted composite ``{spoke}:{agent}``
  heartbeat key (``agent_info`` wiped by a hub restart) also reads online;
* a genuinely dead agent still ages out through yellow to red;
* a real offline spoke (no agent record) is unchanged — still offline/red;
* a CONNECTED spoke is never reinterpreted, even when an agent key collides
  with its id (the agent branch only runs after the spoke test says offline);
* alert tiers still win: an error-tier alert is red even on a fresh agent.
"""

from routes.dashboard import (
    _AGENT_GREEN_S, _AGENT_RED_S, infra_item_status, relayed_agent_last_seen,
)


NOW = 1_000_000.0


class _FakeHeartbeat:
    def __init__(self, last_seen=None):
        self.last_seen = last_seen or {}


class _FakeHub:
    """Minimal hub: identity is a no-op (pre-arm aliases are empty → identity),
    which is exactly how a lab hub behaves before the guid migration."""

    def __init__(self, connected=(), agent_info=None, heartbeat_last=None):
        self.active_connections = {c: object() for c in connected}
        self.agent_info = agent_info or {}
        self.heartbeat = _FakeHeartbeat(heartbeat_last)

    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_primary_key(self, agent_id):
        return agent_id


def _status(hub, sid, tier="none", now=NOW):
    connected = set(hub.active_connections.keys())
    return infra_item_status(hub, sid, tier, connected,
                             relayed_agent_last_seen(hub), now)


# ── the reported bug ─────────────────────────────────────────────────────────

def test_live_agent_via_agent_info_is_online():
    """pxmx-cs-svr-04: relaying frames, not in active_connections. Was offline."""
    hub = _FakeHub(connected=["cs-svr-04"],
                   agent_info={"pxmx-cs-svr-04": {"spoke_id": "cs-svr-04",
                                                  "last_seen": NOW - 6}})
    assert _status(hub, "pxmx-cs-svr-04") == (True, "green")


def test_live_agent_via_composite_heartbeat_only():
    """agent_info is wiped on hub restart; the persisted composite key remains."""
    hub = _FakeHub(connected=["cs-svr-04"],
                   heartbeat_last={"cs-svr-04:pxmx-cs-svr-04": NOW - 30})
    assert _status(hub, "pxmx-cs-svr-04") == (True, "green")


def test_freshest_of_the_two_signals_wins():
    """A stale agent_info entry must not mask a fresh composite heartbeat."""
    hub = _FakeHub(agent_info={"pxmx-a": {"last_seen": NOW - _AGENT_RED_S - 50}},
                   heartbeat_last={"cs-1:pxmx-a": NOW - 5})
    assert _status(hub, "pxmx-a") == (True, "green")


# ── a dead agent still ages out ──────────────────────────────────────────────

def test_agent_ages_to_yellow_then_red():
    mid = _FakeHub(agent_info={"pxmx-a": {"last_seen": NOW - _AGENT_GREEN_S - 1}})
    assert _status(mid, "pxmx-a") == (True, "yellow")

    dead = _FakeHub(agent_info={"pxmx-a": {"last_seen": NOW - _AGENT_RED_S - 1}})
    assert _status(dead, "pxmx-a") == (False, "red")


def test_agent_never_seen_is_offline():
    """No agent record at all → the spoke test stands, so it stays offline."""
    assert _status(_FakeHub(), "pxmx-a") == (False, "red")


# ── no regression for spokes ─────────────────────────────────────────────────

def test_offline_spoke_unchanged():
    assert _status(_FakeHub(connected=["cs-svr-01"]), "cs-svr-02") == (False, "red")


def test_connected_spoke_unchanged():
    assert _status(_FakeHub(connected=["cs-svr-01"]), "cs-svr-01") == (True, "green")


def test_connected_spoke_not_downgraded_by_a_colliding_agent_key():
    """The agent branch runs ONLY after the spoke test says offline, so a stale
    agent record sharing the id cannot drag a live spoke to red."""
    hub = _FakeHub(connected=["cs-svr-01"],
                   agent_info={"cs-svr-01": {"last_seen": NOW - 9999}})
    assert _status(hub, "cs-svr-01") == (True, "green")


# ── alert tiers still win ────────────────────────────────────────────────────

def test_error_tier_beats_a_fresh_agent():
    hub = _FakeHub(agent_info={"pxmx-a": {"last_seen": NOW - 5}})
    assert _status(hub, "pxmx-a", tier="error") == (True, "red")


def test_warning_tier_on_a_fresh_agent():
    hub = _FakeHub(agent_info={"pxmx-a": {"last_seen": NOW - 5}})
    assert _status(hub, "pxmx-a", tier="warning") == (True, "yellow")


# ── the index itself ─────────────────────────────────────────────────────────

def test_last_seen_index_ignores_plain_spoke_heartbeat_keys():
    """Only COMPOSITE keys carry an agent; a bare spoke key must not register
    the spoke as an agent."""
    hub = _FakeHub(heartbeat_last={"cs-svr-01": NOW - 5,
                                   "cs-svr-01:pxmx-a": NOW - 5})
    assert relayed_agent_last_seen(hub) == {"pxmx-a": NOW - 5}


def test_index_degrades_to_empty_on_a_malformed_hub():
    class _Bare:
        pass
    assert relayed_agent_last_seen(_Bare()) == {}
