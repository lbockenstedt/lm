"""Regression tests for spoke-recovery give-up RE-ARM (``main.LabManagerHub``).

Background: ``run_spoke_recovery_loop`` recovers approved-but-stranded spokes
(reset-failed + restart via ``lm-spoke-recover``). Before this fix, once the
loop set ``gave_up=True`` the strand was TERMINAL — the only other clear path
(``recovery_cleared``) fires on reconnect, which a stranded box can't make. So
a one-time give-up abandoned the box until a human rebooted it (the "systemd
did not revive; rebooting fixes it" outage).

The fix makes give-up re-arm after ``_RECOVERY_GIVEUP_REARM_S`` so the hub keeps
periodically retrying. ``_recovery_giveup_action`` is a pure helper the loop
calls, so the decision is unit-testable without driving the async loop.
"""

import os

from main import LabManagerHub


def _hub():
    # Bypass the heavy __init__ — the give-up helpers only read
    # os.environ + the class-level default, no instance state.
    return object.__new__(LabManagerHub)


def test_within_cooldown_skips():
    hub = _hub()
    st = {"gave_up": True, "gave_up_ts": 1000.0}
    # 100s after give-up, default 1800s cooldown -> still abandoned this cycle.
    assert hub._recovery_giveup_action(st, now=1100.0) == "skip"


def test_after_cooldown_rearms():
    hub = _hub()
    st = {"gave_up": True, "gave_up_ts": 1000.0}
    # 1801s later -> cooldown elapsed -> retry recovery.
    assert hub._recovery_giveup_action(st, now=2801.0) == "rearm"


def test_env_override_shortens_cooldown(monkeypatch):
    hub = _hub()
    monkeypatch.setenv("LM_RECOVERY_GIVEUP_REARM_S", "60")
    st = {"gave_up": True, "gave_up_ts": 1000.0}
    assert hub._recovery_giveup_action(st, now=1059.0) == "skip"
    assert hub._recovery_giveup_action(st, now=1061.0) == "rearm"


def test_rearm_disabled_is_permanent(monkeypatch):
    hub = _hub()
    monkeypatch.setenv("LM_RECOVERY_GIVEUP_REARM_S", "0")
    st = {"gave_up": True, "gave_up_ts": 1000.0}
    # 0 disables re-arm -> stays skipped no matter how much time passes.
    assert hub._recovery_giveup_action(st, now=10_000_000.0) == "skip"


def test_missing_gave_up_ts_treated_as_epoch(monkeypatch):
    hub = _hub()
    # A give-up recorded before this fix (no gave_up_ts) must not stay stranded
    # forever: gave_up_ts defaults to 0, so any real `now` is past the cooldown
    # and the box re-arms on the next cycle.
    st = {"gave_up": True}
    assert hub._recovery_giveup_action(st, now=2_000_000_000.0) == "rearm"


def test_invalid_env_falls_back_to_default(monkeypatch):
    hub = _hub()
    monkeypatch.setenv("LM_RECOVERY_GIVEUP_REARM_S", "not-an-int")
    assert hub._recovery_giveup_rearm_s() == LabManagerHub._RECOVERY_GIVEUP_REARM_S
