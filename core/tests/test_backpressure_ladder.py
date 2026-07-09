"""Backpressure escalation ladder + DDoS enforcement (main.LabManagerHub).

The graceful-degradation control loop must, deterministically:
  • classify messages (must / coalesce / skippable) with correlation-id override;
  • throttle the OFFENDING spoke first (rung 1), fleet only if still hot (rung 2);
  • DAMP release with a dwell so a throttled spoke (whose measured rate collapses
    as it coalesces) doesn't flap throttle↔release;
  • treat a per-spoke TokenBucket breach as an INSTANT offender (the 80% soft
    watermark → slow-down signal, ahead of the 10s-average mps);
  • STAND DOWN entirely under protect mode (protect's pre-parse shed is the only
    relief at a parse-bound core — running the O(spokes) ladder there is what
    took the hub unresponsive at ~800 spokes);
  • escalate a persistent flooder (keeps hard-dropping after being told to slow)
    to disconnect + quarantine — DEFAULT OFF, robust against the release race.

These exercise the decision logic directly (a lightweight object with the real
methods bound + FakeState for config) so no live hub / event loop churn is
needed. Disk-queue durability is covered separately in test_mailbox_persistence.py
(the outbound mailbox is what persists; inbound telemetry is in-memory coalesce).
"""
import asyncio
import time
import types

from _fakes import FakeState

import main

Hub = main.LabManagerHub

_BOUND = ("_apply_backpressure_ladder", "_signal_backoff", "_backpressure_params",
          "_classify_message", "_disconnect_and_quarantine", "_is_quarantined")

_CFG = {
    "per_spoke_soft_mps": 50, "per_spoke_clear_mps": 25,
    "fleet_lag_soft_s": 0.30, "fleet_lag_clear_s": 0.10, "fleet_soft_mps": 8000,
    "coalesce_min_interval_s": 2.0, "release_dwell_s": 20.0, "rl_soft_fraction": 0.8,
    "ddos_disconnect": False, "ddos_grace_s": 5.0, "ddos_min_harddrops": 20,
    "quarantine_s": 60.0,
}


class _FakeWS:
    def __init__(self):
        self.closed = None

    async def close(self, code, reason):
        self.closed = (code, reason)


class _StubHub:
    pass


def _make(bp_cfg=None):
    """A minimal object carrying just the state the ladder touches, with the
    real LabManagerHub methods bound onto it."""
    cfg = dict(_CFG)
    cfg.update(bp_cfg or {})
    h = _StubHub()
    h.state = FakeState(global_config={"backpressure": cfg})
    h.spoke_mps = {}
    h.mps = 0.0
    h.active_connections = {}
    h._backoff_signaled = {}
    h._backoff_since = {}
    h._spoke_backoff = set()
    h._fleet_backoff = False
    h._load_level = 0
    h._rl_breached = set()
    h._rl_harddrops = {}
    h._noncompliant_since = {}
    h._quarantine = {}
    h._rl_soft_frac = 0.8
    h._coalesce_pending = {}
    h._telemetry_received = h._telemetry_processed = h._telemetry_coalesced = 0
    h._probe_state = {}
    h._protect_mode = False
    h._bp_last_summary = (frozenset(), False)
    h._MSG_CLASS_DEFAULT = Hub._MSG_CLASS_DEFAULT
    h.signals = []          # (spoke_id, level) captured from send_to_spoke_command
    h.events = []           # (spoke_id, kind) captured from record_spoke_event

    async def _s2s(self, sid, ctype, data):
        self.signals.append((sid, data["level"]))

    def _rec(self, sid, kind, msg):
        self.events.append((sid, kind))

    for name in _BOUND:
        setattr(h, name, types.MethodType(getattr(Hub, name), h))
    h.send_to_spoke_command = types.MethodType(_s2s, h)
    h.record_spoke_event = types.MethodType(_rec, h)
    return h


def _ladder(h, loop_lag=0.0):
    asyncio.run(h._apply_backpressure_ladder(loop_lag))


# ── classification ──────────────────────────────────────────────────────────
def test_classification():
    h = _make()
    assert h._classify_message("HEARTBEAT", False) == "skippable"
    assert h._classify_message("CS_TELEMETRY", False) == "coalesce"
    assert h._classify_message("SPOKE_LOG", False) == "coalesce"
    assert h._classify_message("COMMAND_RESULT", False) == "must"
    assert h._classify_message("LOADTEST_PROBE", False) == "must"
    # a correlation-bearing frame is ALWAYS must-process regardless of type
    assert h._classify_message("CS_TELEMETRY", True) == "must"


# ── rung 1: offender-first ──────────────────────────────────────────────────
def test_rung1_offender_first_fleet_calm():
    h = _make()
    h.active_connections = {"loud": 1, "quiet": 1}
    h.spoke_mps = {"loud": 120.0, "quiet": 3.0}
    h.mps = 123.0
    _ladder(h, loop_lag=0.0)
    assert h.signals == [("loud", 1)]
    assert h._spoke_backoff == {"loud"} and h._load_level == 1


def test_rung1_damping_holds_then_releases():
    h = _make()
    h.active_connections = {"loud": 1}
    h.spoke_mps = {"loud": 120.0}
    h.mps = 120.0
    _ladder(h)
    assert h.signals == [("loud", 1)]
    # throttled spoke's measured rate collapses (coalescing) — must HOLD, not flap
    h.signals.clear()
    h.spoke_mps = {"loud": 0.5}
    h.mps = 0.5
    _ladder(h)
    assert h.signals == [] and h._spoke_backoff == {"loud"}   # held
    # after the dwell passes AND it's quiet → release
    h.signals.clear()
    h._backoff_since["loud"] = time.monotonic() - 100
    _ladder(h)
    assert h.signals == [("loud", 0)] and h._spoke_backoff == set() and h._load_level == 0


# ── rung 2: fleet ───────────────────────────────────────────────────────────
def test_rung2_fleet_on_loop_lag():
    h = _make()
    h.active_connections = {"a": 1, "b": 1, "c": 1}
    h.spoke_mps = {"a": 40, "b": 40, "c": 40}   # none individually an offender
    h.mps = 120
    _ladder(h, loop_lag=0.5)                     # lag over the fleet soft mark
    assert sorted(l for _, l in h.signals) == [2, 2, 2]
    assert h._fleet_backoff and h._load_level == 2
    # fleet cools + spokes quiet past dwell → full resume
    h.signals.clear()
    h.mps = 10
    h.spoke_mps = {"a": 2, "b": 2, "c": 2}
    for s in ("a", "b", "c"):
        h._backoff_since[s] = time.monotonic() - 100
    _ladder(h, loop_lag=0.05)
    assert sorted(l for _, l in h.signals) == [0, 0, 0]
    assert not h._fleet_backoff and h._load_level == 0


# ── bucket breach = instant offender (the 80% soft watermark path) ──────────
def test_bucket_breach_triggers_slowdown_under_mps_mark():
    h = _make()
    h.active_connections = {"bursty": 1, "calm": 1}
    h.spoke_mps = {"bursty": 5.0, "calm": 5.0}   # both well under 50/s
    h.mps = 10.0
    h._rl_breached = {"bursty"}                    # bursty drained its bucket
    _ladder(h)
    assert h.signals == [("bursty", 1)]
    assert h._spoke_backoff == {"bursty"}
    assert h._rl_breached == set()                 # cleared each tick


# ── protect stand-down ──────────────────────────────────────────────────────
def test_protect_stand_down_does_no_work():
    h = _make()
    h.active_connections = {"a": 1, "b": 1}
    h.spoke_mps = {"a": 999, "b": 999}
    h.mps = 2000
    h._protect_mode = True
    h._coalesce_pending = {"a": ({}, 0), "b": ({}, 0)}
    _ladder(h, loop_lag=5.0)
    assert h.signals == []                 # no signalling under protect
    assert h._coalesce_pending == {}       # buffer dropped (superseded)
    assert h._load_level >= 3


# ── DDoS enforcement (opt-in) ───────────────────────────────────────────────
def _rogue():
    h = _make({"ddos_disconnect": True})
    h.ws = _FakeWS()
    h.active_connections = {"rogue": h.ws}
    h.spoke_mps = {"rogue": 200}            # a real flooder's pre-drop mps is high
    h.mps = 200
    return h


def test_ddos_flood_within_grace_not_yet_disconnected():
    h = _rogue()
    h._rl_harddrops = {"rogue": 100}
    _ladder(h)
    assert h.ws.closed is None
    assert "rogue" in h._noncompliant_since


def test_ddos_sustained_flood_disconnects_and_quarantines():
    h = _rogue()
    h._rl_harddrops = {"rogue": 100}
    _ladder(h)                                     # start the non-compliance clock
    h._noncompliant_since["rogue"] = time.monotonic() - 10   # past ddos_grace_s
    h._rl_harddrops = {"rogue": 100}
    _ladder(h)
    assert h.ws.closed == (1013, "Flooding after slow-down — quarantined")
    assert h._is_quarantined("rogue") is True
    assert ("rogue", "ddos_quarantine") in h.events


def test_ddos_stop_flooding_clears_clock():
    h = _rogue()
    h._noncompliant_since = {"rogue": time.monotonic() - 100}
    h._rl_harddrops = {}                            # stopped flooding this tick
    _ladder(h)
    assert h.ws.closed is None
    assert "rogue" not in h._noncompliant_since


def test_ddos_disabled_by_default_never_disconnects():
    h = _make({"ddos_disconnect": False})          # default
    h.ws = _FakeWS()
    h.active_connections = {"rogue": h.ws}
    h.spoke_mps = {"rogue": 200}
    h.mps = 200
    h._rl_harddrops = {"rogue": 100}
    h._noncompliant_since = {"rogue": time.monotonic() - 100}
    _ladder(h)
    assert h.ws.closed is None


def test_quarantine_expires():
    h = _make()
    h._quarantine["x"] = time.monotonic() - 1      # already expired
    assert h._is_quarantined("x") is False
    assert "x" not in h._quarantine                # pruned on read
    h._quarantine["y"] = time.monotonic() + 60
    assert h._is_quarantined("y") is True
