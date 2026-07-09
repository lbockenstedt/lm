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
          "_classify_message", "_disconnect_and_quarantine", "_is_quarantined",
          "_protect_source_shed")

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
    h._backoff_signaled = {}; h._backoff_interval = {}; h._fleet_interval = 0.0
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
    h._spoke_recv = {}
    h._spoke_offered = {}
    h._telemetry_received = h._telemetry_processed = h._telemetry_coalesced = 0
    h._probe_state = {}
    h._protect_mode = False
    h._proc_cpu = 0.0
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
def test_rung2_fleet_on_cpu_distributed_load():
    # 3 spokes each at 30/s — none is an offender (<50/s soft mark) and mps is
    # low, but hub CPU is pegged: the fleet slow-down MUST still engage. This is
    # the distributed-load case that ground the hub at 100% with nothing throttled.
    h = _make()
    h.active_connections = {"a": 1, "b": 1, "c": 1}
    h.spoke_mps = {"a": 30, "b": 30, "c": 30}
    h.mps = 90                                    # well under fleet_soft_mps
    h._proc_cpu = 80.0                            # but the core is pegged
    _ladder(h, loop_lag=0.0)                      # and loop-lag is low
    assert sorted(l for _, l in h.signals) == [2, 2, 2]
    assert h._fleet_backoff and h._load_level == 2
    # CPU falls back below the clear mark → resume
    h.signals.clear()
    h._proc_cpu = 30.0
    h.spoke_mps = {"a": 2, "b": 2, "c": 2}
    for s in ("a", "b", "c"):
        h._backoff_since[s] = time.monotonic() - 100
    _ladder(h, loop_lag=0.0)
    assert sorted(l for _, l in h.signals) == [0, 0, 0]
    assert not h._fleet_backoff


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


# ── protect: throttle loudest, spare quiet ──────────────────────────────────
def test_protect_throttles_loudest_spares_quiet():
    # Under protect the ladder still THROTTLES the loud talkers (bounded, loudest-
    # first) — standing down entirely left them un-signalled and CPU pegged. Quiet
    # spokes (< fleet_min) are spared. The coalesce buffer is still dropped.
    h = _make()
    h.active_connections = {"loud": 1, "quiet": 1}
    h.spoke_mps = {"loud": 999, "quiet": 0.2}
    h.mps = 2000
    h._protect_mode = True
    h._spoke_offered = {}                   # nothing offered → no source-shed
    h._coalesce_pending = {"loud": ({}, 0)}
    _ladder(h, loop_lag=5.0)
    assert h.signals == [("loud", 2)]       # loudest throttled, quiet spared
    assert "quiet" not in h._spoke_backoff
    assert h._coalesce_pending == {}        # buffer dropped (superseded)
    assert h._load_level >= 3


def test_fleet_spares_quiet_spokes_and_throttles_loud():
    # The exact bug the operator hit: quiet infra spokes must NOT be fleet-
    # throttled while loud ones (40/s) must be. Fleet floor = 5/s.
    h = _make()
    h.active_connections = {"infra": 1, "loud": 1}
    h.spoke_mps = {"infra": 0.1, "loud": 40.0}
    h.mps = 90
    h._proc_cpu = 70.0                      # fleet engaged
    _ladder(h)
    assert h._fleet_backoff
    assert h.signals == [("loud", 2)]       # only the loud one; infra spared
    assert "infra" not in h._spoke_backoff


def test_protect_source_shed_disconnects_loudest_spares_quiet():
    h = _make({"protect_shed_top_k": 2, "protect_shed_min_mps": 50,
               "protect_quarantine_s": 30})
    h._protect_mode = True
    loud1, loud2, loud3, quiet = _FakeWS(), _FakeWS(), _FakeWS(), _FakeWS()
    h.active_connections = {"loud1": loud1, "loud2": loud2, "loud3": loud3, "quiet": quiet}
    # TRUE offered rates (pre-shed). quiet is a real low-rate module.
    h._spoke_offered = {"loud1": 300, "loud2": 250, "loud3": 120, "quiet": 4}
    _ladder(h, loop_lag=5.0)
    # top-K=2 loudest disconnected + quarantined; loud3 (over floor but not top-2)
    # and quiet (under floor) untouched.
    assert loud1.closed == (1013, "Hub overloaded — shedding loudest talkers")
    assert loud2.closed == (1013, "Hub overloaded — shedding loudest talkers")
    assert loud3.closed is None and quiet.closed is None
    assert h._is_quarantined("loud1") and h._is_quarantined("loud2")
    assert not h._is_quarantined("quiet")
    assert ("loud1", "protect_shed") in h.events


def test_protect_source_shed_can_be_disabled():
    h = _make({"protect_shed_source": False})
    h._protect_mode = True
    loud = _FakeWS()
    h.active_connections = {"loud": loud}
    h._spoke_offered = {"loud": 999}
    _ladder(h, loop_lag=5.0)
    assert loud.closed is None


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


def test_adaptive_fleet_interval_scales_with_cpu():
    # As CPU climbs from fleet_cpu_soft(55) toward fleet_cpu_hard(85), the slow-
    # down interval the fleet is asked to conflate to climbs from min(2) toward
    # max(15) — the hub pushes the fleet down HARDER as it heats up, and re-signals.
    h = _make()
    h.active_connections = {"a": 1}
    h.spoke_mps = {"a": 30}
    h.mps = 90
    h._proc_cpu = 55.0                       # at soft → min interval
    _ladder(h)
    assert h._fleet_backoff
    assert abs(h._fleet_interval - 2.0) < 0.6, h._fleet_interval
    # CPU spikes toward hard → interval near max → RE-SIGNAL (not a one-shot)
    h.signals.clear()
    h._proc_cpu = 85.0
    _ladder(h)
    assert h._fleet_interval >= 14.0, h._fleet_interval
    assert h.signals == [("a", 2)], h.signals
