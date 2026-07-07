"""Critical path — spoke out-of-contact alerting (forgiving 5 min / 30 min tiers).

``test_spoke_alert.py`` locks in: the config key is fixed, the warn/error
thresholds clamp (warn_s >= 60, error_s > warn_s, defaults 300/1800), the tier
mapping is right, the loop emits **only on transition** (no per-cycle log spam),
warning fires at >=300 s and error at >=1800 s, back-in-contact clears the alert +
records ``spoke_back_in_contact``, a never-seen approved spoke uses the
``_spoke_absent_since`` clock, the disabled loop is a no-op (and clears stale
alerts), and ``get_active_spoke_alerts`` shape/severity ordering. Mirrors
``test_staleness_sweep.py`` (canned hub stand-in + monkeypatched asyncio.sleep).
"""

import asyncio
import logging
import time

import pytest

import spoke_alert_sync as sa
from spoke_alert_sync import SpokeAlertMixin, _TIER_WARN, _TIER_ERROR, _TIER_NONE
from _fakes import FakeState


# ── config helpers ───────────────────────────────────────────────────────────

def test_cfg_key_and_defaults_are_fixed():
    assert SpokeAlertMixin._SPOKE_ALERT_CFG_KEY == "spoke_alert"
    assert SpokeAlertMixin._SPOKE_ALERT_DEFAULT_WARN_S == 300
    assert SpokeAlertMixin._SPOKE_ALERT_DEFAULT_ERROR_S == 1800


def test_thresholds_clamp_and_default():
    m = SpokeAlertMixin()
    # defaults
    m.state = FakeState(system_state={"global_config": {}})
    assert m._spoke_alert_thresholds() == (300, 1800)
    # warn_s floored at 60
    m.state = FakeState(system_state={"global_config":
        {"spoke_alert": {"warn_s": 10, "error_s": 120}}})
    assert m._spoke_alert_thresholds() == (60, 120)
    # error_s must exceed warn_s — bad config flips it → bumped to warn_s + 60
    m.state = FakeState(system_state={"global_config":
        {"spoke_alert": {"warn_s": 300, "error_s": 300}}})
    w, e = m._spoke_alert_thresholds()
    assert w == 300 and e > w
    # explicit sane values pass through
    m.state = FakeState(system_state={"global_config":
        {"spoke_alert": {"warn_s": 120, "error_s": 600}}})
    assert m._spoke_alert_thresholds() == (120, 600)


def test_tier_mapping():
    f = SpokeAlertMixin._spoke_alert_tier_for
    assert f(0, 300, 1800) == _TIER_NONE
    assert f(299, 300, 1800) == _TIER_NONE
    assert f(300, 300, 1800) == _TIER_WARN
    assert f(1799, 300, 1800) == _TIER_WARN
    assert f(1800, 300, 1800) == _TIER_ERROR
    assert f(99999, 300, 1800) == _TIER_ERROR


# ── canned hub stand-in ──────────────────────────────────────────────────────

class _AlertHub(SpokeAlertMixin):
    """Minimal hub stand-in: approved_modules, heartbeat.last_seen,
    active_connections, record_spoke_event, and the transient alert stores."""

    def __init__(self, global_config=None, approved=None, last_seen=None,
                 connected=None):
        self.state = FakeState(system_state={"global_config": global_config or {}})
        self.approved_modules = approved or {}
        # minimal heartbeat stand-in with just last_seen
        class _HB:
            pass
        self.heartbeat = _HB()
        self.heartbeat.last_seen = dict(last_seen or {})
        self.active_connections = dict(connected or {})
        self._spoke_alerts = {}
        self._spoke_alert_tier = {}
        self._spoke_absent_since = {}
        self.events = []  # recorded (spoke_id, event, detail)

    def record_spoke_event(self, spoke_id, event, detail=""):
        self.events.append((spoke_id, event, detail))


# ── _spoke_alert_duration ────────────────────────────────────────────────────

def test_duration_uses_last_seen_when_present():
    h = _AlertHub(approved={"s1": True}, last_seen={"s1": 1000.0})
    dur, since = h._spoke_alert_duration("s1", now=1000.0 + 400)
    assert dur == 400 and since == 1000.0


def test_duration_zero_when_connected_but_never_heartbeated():
    # last_seen None but connected → in contact, no alert (forgiving on hub restart)
    h = _AlertHub(approved={"s1": True}, connected={"s1": "ws"})
    dur, since = h._spoke_alert_duration("s1", now=1000.0)
    assert dur == 0.0 and since is None


def test_duration_seeds_absent_since_for_never_seen_disconnected():
    h = _AlertHub(approved={"s1": True})  # not connected, no last_seen
    now = 5000.0
    dur0, since0 = h._spoke_alert_duration("s1", now=now)
    assert dur0 == 0.0                       # just noticed this cycle
    assert since0 == now
    assert h._spoke_absent_since["s1"] == now
    # next cycle accrues from the seeded clock
    dur1, since1 = h._spoke_alert_duration("s1", now=now + 320)
    assert dur1 == 320 and since1 == now


# ── run_spoke_alert_loop transitions ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_warning_fires_once_at_300s_no_repeat(caplog, monkeypatch):
    h = _AlertHub(global_config={"spoke_alert": {"enabled": True}},
                  approved={"s1": True}, last_seen={"s1": 0.0})
    caplog.set_level(logging.WARNING, logger="Hub")

    # last_seen=0 → duration = now
    h._spoke_alert_duration = lambda sid, now: (max(0.0, now - 0.0), 0.0)  # type: ignore

    # The loop does: sleep(30) [stagger, call 1] → body → sleep(LOOP_S) → body → …
    # So body i runs with the clock set by sleep call i. Drive bodies with stages
    # [100 (none), 310 (warning fires), 320 (still warning — no new log)]; the
    # sleep after the last body raises to break the loop.
    stages = [100, 310, 320]
    clock = {"t": 0.0}
    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] <= len(stages):
            clock["t"] = stages[iters["n"] - 1]
            return
        raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(sa.time, "time", lambda: clock["t"])

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    warn_logs = [r for r in caplog.records if "[spoke-alert]" in r.message
                 and "warn" in r.message]
    assert len(warn_logs) == 1, "warning must emit once on transition, not per cycle"
    assert h._spoke_alert_tier["s1"] == _TIER_WARN
    assert h._spoke_alerts["s1"]["tier"] == _TIER_WARN
    # the spoke_out_of_contact event was recorded (once)
    assert sum(1 for e in h.events if e[1] == "spoke_out_of_contact") == 1


@pytest.mark.asyncio
async def test_error_escalation_at_1800s(caplog, monkeypatch):
    h = _AlertHub(global_config={"spoke_alert": {"enabled": True}},
                  approved={"s1": True}, last_seen={"s1": 0.0})
    caplog.set_level(logging.INFO, logger="Hub")
    h._spoke_alert_duration = lambda sid, now: (max(0.0, now - 0.0), 0.0)  # type: ignore

    # bodies: 310 (warning fires) → 1810 (error fires)
    stages = [310, 1810]
    clock = {"t": 0.0}
    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] <= len(stages):
            clock["t"] = stages[iters["n"] - 1]
            return
        raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(sa.time, "time", lambda: clock["t"])

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    err_logs = [r for r in caplog.records if "[spoke-alert]" in r.message
                and r.levelno == logging.ERROR]
    assert len(err_logs) == 1, "error must emit once on warning→error transition"
    assert h._spoke_alert_tier["s1"] == _TIER_ERROR
    assert h._spoke_alerts["s1"]["tier"] == _TIER_ERROR
    # since_ts preserved across escalation (onset stays at the warning onset)
    assert h._spoke_alerts["s1"]["since_ts"] == 0.0


@pytest.mark.asyncio
async def test_back_in_contact_clears_alert(monkeypatch):
    h = _AlertHub(global_config={"spoke_alert": {"enabled": True}},
                  approved={"s1": True}, last_seen={"s1": 0.0})
    h._spoke_alert_duration = lambda sid, now: (max(0.0, now - 0.0), 0.0)  # type: ignore

    # Pre-seed an active warning so we can test the clear transition.
    h._spoke_alert_tier["s1"] = _TIER_WARN
    h._spoke_alert_set("s1", _TIER_WARN, 0.0, 320.0, "out of contact 320s")

    # bodies: 310 (still warning — no transition) → 5 (back in contact → clear)
    stages = [310, 5]
    clock = {"t": 0.0}
    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] <= len(stages):
            clock["t"] = stages[iters["n"] - 1]
            return
        raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(sa.time, "time", lambda: clock["t"])

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    assert "s1" not in h._spoke_alerts
    assert h._spoke_alert_tier["s1"] == _TIER_NONE
    assert any(e[1] == "spoke_back_in_contact" for e in h.events)


@pytest.mark.asyncio
async def test_loop_disabled_is_noop_and_clears_stale(monkeypatch):
    h = _AlertHub(global_config={"spoke_alert": {"enabled": False}},
                  approved={"s1": True})
    # stale alert present from a previous enabled run
    h._spoke_alerts["s1"] = {"tier": _TIER_WARN, "since_ts": 0.0,
                             "duration_s": 320, "detail": "x"}
    h._spoke_alert_tier["s1"] = _TIER_WARN

    async def _boom():
        raise AssertionError("loop body must not run when disabled")
    h._spoke_alert_duration = _boom  # type: ignore

    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] >= 2:
            raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    # stale alerts cleared while disabled
    assert h._spoke_alerts == {}
    assert h._spoke_alert_tier == {}


@pytest.mark.asyncio
async def test_relayed_agent_ids_skipped_and_selfhealed(monkeypatch):
    """A relayed node-agent (pxmx proxmox agent) leaked into approved_modules
    must NOT be flagged out-of-contact — its liveness lives under the COMPOSITE
    heartbeat key shown in the AGENTS view, not the bare id the alert loop reads
    (bare key → None → absent_since → false "error" while the agent is online).
    The loop skips it, clears any stale alert, and self-heals it out of
    approved_modules + known_modules (mirroring /setup/diagnostics, but without
    requiring that page to be opened)."""
    h = _AlertHub(global_config={"spoke_alert": {"enabled": True}},
                  approved={"pxmx-agent": True, "s1": True},
                  last_seen={"pxmx:pxmx-agent": 0.0, "s1": 0.0})
    # Relay-agent registries: agent_config (persisted) + agent_info (in-memory).
    h.state.system_state["agent_config"] = {"pxmx-agent": {"hostname": "pxmx"}}
    h.state.system_state["known_modules"] = ["pxmx-agent", "s1"]
    h.known_modules = ["pxmx-agent", "s1"]
    h.agent_info = {"pxmx-agent": {"spoke_id": "pxmx", "last_seen": 0.0}}
    saved = {"n": 0}
    h.state.save_state = lambda: saved.__setitem__("n", saved["n"] + 1)  # type: ignore

    # One body at a large clock: s1 (last_seen 0) → error; pxmx-agent would ALSO
    # escalate if it weren't skipped (bare key absent, not in active_connections).
    stages = [2000]
    clock = {"t": 0.0}
    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] <= len(stages):
            clock["t"] = stages[iters["n"] - 1]
            return
        raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(sa.time, "time", lambda: clock["t"])

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    # pxmx-agent: skipped — no alert, popped from approved_modules, self-healed
    # out of known_modules (persisted once).
    assert "pxmx-agent" not in h._spoke_alerts
    assert "pxmx-agent" not in h.approved_modules
    assert "pxmx-agent" not in h.state.system_state["known_modules"]
    assert "pxmx-agent" not in h.known_modules
    assert saved["n"] == 1
    # s1: still evaluated — escalates to error at 2000s (last_seen 0).
    assert h._spoke_alerts["s1"]["tier"] == _TIER_ERROR


@pytest.mark.asyncio
async def test_relayed_agent_skip_is_change_gated(monkeypatch):
    """Once the leaked relay id has been self-healed out, subsequent cycles do
    NO work for it (no repeated save_state / no per-cycle write)."""
    h = _AlertHub(global_config={"spoke_alert": {"enabled": True}},
                  approved={"pxmx-agent": True, "s1": True},
                  last_seen={"pxmx:pxmx-agent": 0.0, "s1": 0.0})
    h.state.system_state["agent_config"] = {"pxmx-agent": {}}
    h.state.system_state["known_modules"] = ["pxmx-agent", "s1"]
    h.known_modules = ["pxmx-agent", "s1"]
    h.agent_info = {"pxmx-agent": {}}
    saved = {"n": 0}
    h.state.save_state = lambda: saved.__setitem__("n", saved["n"] + 1)  # type: ignore

    # Two bodies: first self-heals + saves; second finds nothing leaked → no save.
    stages = [2000, 2010]
    clock = {"t": 0.0}
    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] <= len(stages):
            clock["t"] = stages[iters["n"] - 1]
            return
        raise asyncio.CancelledError()
    monkeypatch.setattr(sa.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(sa.time, "time", lambda: clock["t"])

    with pytest.raises(asyncio.CancelledError):
        await h.run_spoke_alert_loop()

    assert saved["n"] == 1, "self-heal must persist once, not every cycle"
    assert "pxmx-agent" not in h.approved_modules


# ── get_active_spoke_alerts ──────────────────────────────────────────────────

def test_active_alerts_severity_ordering():
    h = _AlertHub(approved={})
    h._spoke_alerts = {
        "warn-spoke": {"tier": _TIER_WARN, "since_ts": 100.0,
                       "duration_s": 320, "detail": "w"},
        "err-spoke": {"tier": _TIER_ERROR, "since_ts": 200.0,
                      "duration_s": 2000, "detail": "e"},
        "ok-spoke": {"tier": _TIER_NONE, "since_ts": None,
                     "duration_s": 0, "detail": ""},
    }
    alerts = h.get_active_spoke_alerts()
    # error before warning; none excluded
    assert [a["spoke_id"] for a in alerts] == ["err-spoke", "warn-spoke"]
    assert all("spoke_id" in a and "tier" in a and "since_ts" in a
               and "duration_s" in a and "detail" in a for a in alerts)


def test_active_alerts_empty_when_none():
    h = _AlertHub(approved={})
    assert h.get_active_spoke_alerts() == []