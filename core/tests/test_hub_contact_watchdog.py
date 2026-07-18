"""Feature (a): the hub-contact watchdog tests.

The hub-contact watchdog (``BaseControlPlane._hub_contact_watchdog``) escalates
recovery when a spoke can't reach the hub: after ``service_s`` (5m default) it
restarts the service (``os._exit(3)`` → systemd relaunches); after ``reboot_s``
(15m default) it reboots the host; after ``reboot_grace_s`` the run failed → it
sleeps ``sleep_s`` (1h) then starts another; after ``max_runs`` (3 default) it
gives up + stays offline. State persists across the restart/reboot so the
ladder is not reset by its own actions; any successful hub contact clears it.

These cover: config precedence (pushed file > env > defaults) + the persistence
helpers, the boot outage-clock reload, the escalation ladder (T1 restart / T2
reboot / T2+grace run++ + cooldown / max_runs give-up), recovery → clear,
cooldown respected, and disabled → clear + no-op. The ladder is driven with a
controllable fake clock + record-only ``os._exit`` / ``_hcw_reboot`` (the loop
is a ``while True`` of 30s sleeps; a ``BaseException`` sentinel breaks it).
"""
import asyncio
import json
import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import messaging.control_plane as cp  # noqa: E402
from messaging.control_plane import BaseControlPlane  # noqa: E402


class _Stop(BaseException):
    """Breaks the watchdog ``while True`` — derived from BaseException so the
    loop's ``except Exception`` doesn't swallow it."""


class _Spoke(BaseControlPlane):
    """Minimal harness: bypass the heavy __init__, set only what the watchdog
    touches, and no-op the log flush the escalation paths call."""

    def __init__(self, state_dir):
        self._test_state_dir = state_dir
        self._last_hub_contact = time.time()
        self._hub_ws = None
        self.spoke_id = "test-spoke-1"
        self._draining = False
        self._spoke_update_in_progress = False

    def _spoke_state_dir(self):
        return self._test_state_dir

    async def _flush_log_relay_async(self, timeout=2.0):
        pass


def _drive(c, steps, monkeypatch):
    """Run ``_hub_contact_watchdog`` through ``steps`` — each step is
    (delta_seconds, connected) applied by the fake ``asyncio.sleep`` BEFORE the
    loop body reads the clock. ``os._exit`` + ``_hcw_reboot`` are record-only so
    the ladder progresses within one run instead of killing the process."""
    clock = {"t": c._last_hub_contact}
    exits = []
    reboots = []
    it = iter(steps)
    state = {"n": 0, "max": len(steps)}

    monkeypatch.setattr(cp.time, "time", lambda: clock["t"])

    async def _fake_sleep(_s):
        state["n"] += 1
        if state["n"] > state["max"]:
            raise _Stop()
        delta, conn = next(it)
        clock["t"] += delta
        c._hub_ws = object() if conn else None

    monkeypatch.setattr(cp.asyncio, "sleep", _fake_sleep)
    monkeypatch.setattr(cp.os, "_exit", lambda code=0: exits.append(code))
    monkeypatch.setattr(c, "_hcw_reboot", lambda: _reboot_coro(reboots))
    try:
        asyncio.run(c._hub_contact_watchdog())
    except _Stop:
        pass
    return exits, reboots


async def _reboot_coro(reboots):
    reboots.append(True)


# ── config precedence + persistence helpers ───────────────────────────────

def test_config_defaults(monkeypatch, tmp_path):
    for v in ("LM_HUB_CONTACT_WATCHDOG", "LM_HUB_WATCHDOG_SERVICE_S",
             "LM_HUB_WATCHDOG_REBOOT_S", "LM_HUB_WATCHDOG_REBOOT_GRACE_S",
             "LM_HUB_WATCHDOG_SLEEP_S", "LM_HUB_WATCHDOG_MAX_RUNS"):
        monkeypatch.delenv(v, raising=False)
    c = _Spoke(str(tmp_path))
    cfg = c._hcw_config()
    assert cfg["enabled"] is False
    assert cfg["service_s"] == 300.0
    assert cfg["reboot_s"] == 900.0
    assert cfg["reboot_grace_s"] == 300.0
    assert cfg["sleep_s"] == 3600.0
    assert cfg["max_runs"] == 3


def test_config_env_overrides_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("LM_HUB_CONTACT_WATCHDOG", "1")
    monkeypatch.setenv("LM_HUB_WATCHDOG_SERVICE_S", "120")
    monkeypatch.setenv("LM_HUB_WATCHDOG_MAX_RUNS", "5")
    c = _Spoke(str(tmp_path))
    cfg = c._hcw_config()
    assert cfg["enabled"] is True
    assert cfg["service_s"] == 120.0
    assert cfg["max_runs"] == 5


def test_config_pushed_file_overrides_env(monkeypatch, tmp_path):
    """The hub-pushed config file (SPOKE_SET_WATCHDOG) wins over env — so an
    operator's WebUI enable/disable + retune isn't undone by env vars."""
    monkeypatch.setenv("LM_HUB_CONTACT_WATCHDOG", "0")
    monkeypatch.setenv("LM_HUB_WATCHDOG_SERVICE_S", "120")
    c = _Spoke(str(tmp_path))
    c._hcw_save_config({"enabled": True, "service_s": 60, "reboot_s": 200,
                        "max_runs": 7})
    cfg = c._hcw_config()
    assert cfg["enabled"] is True          # file overrode env's disabled
    assert cfg["service_s"] == 60.0        # file overrode env's 120
    assert cfg["reboot_s"] == 200.0
    assert cfg["max_runs"] == 7


def test_config_malformed_file_falls_back(monkeypatch, tmp_path):
    """A corrupted config file degrades gracefully to env/defaults (never
    crashes the watchdog tick)."""
    monkeypatch.setenv("LM_HUB_CONTACT_WATCHDOG", "1")
    c = _Spoke(str(tmp_path))
    os.makedirs(c._spoke_state_dir(), exist_ok=True)
    with open(c._hcw_config_path(), "w") as f:
        f.write("{not valid json")
    cfg = c._hcw_config()
    assert cfg["enabled"] is True         # env still honored
    assert cfg["service_s"] == 300.0       # default


def test_config_persists_across_restart(monkeypatch, tmp_path):
    """_hcw_save_config writes; a fresh spoke instance reads it back — mirrors
    a service restart/reboot where the hub is unreachable + the file must apply."""
    monkeypatch.delenv("LM_HUB_CONTACT_WATCHDOG", raising=False)
    c1 = _Spoke(str(tmp_path))
    c1._hcw_save_config({"enabled": True, "service_s": 42, "reboot_s": 99,
                          "reboot_grace_s": 10, "sleep_s": 500, "max_runs": 8})
    c2 = _Spoke(str(tmp_path))  # "restarted" — same state dir
    cfg = c2._hcw_config()
    assert cfg["enabled"] is True
    assert cfg["service_s"] == 42.0
    assert cfg["max_runs"] == 8


def test_state_save_load_roundtrip(tmp_path):
    c = _Spoke(str(tmp_path))
    st = {"run": 2, "stage": "rebooted", "run_start_at": 1234.5,
          "sleep_until": 0, "last_contact_at": 1000.0, "gave_up": False}
    c._hcw_save(st)
    assert c._hcw_load() == st


def test_state_clear_idempotent_when_absent(tmp_path):
    c = _Spoke(str(tmp_path))
    c._hcw_save({"run": 1})
    assert os.path.exists(c._hcw_state_path())
    c._hcw_clear()
    assert not os.path.exists(c._hcw_state_path())
    c._hcw_clear()  # no error on already-absent
    assert not os.path.exists(c._hcw_state_path())


# ── boot outage-clock reload ───────────────────────────────────────────────

def test_boot_reloads_older_contact_from_persisted_state(monkeypatch, tmp_path):
    """On boot the outage clock is seeded from the OLDER of (now, persisted
    last_contact_at) so an ongoing outage keeps counting across the restart/
    reboot the ladder itself triggers — not reset to "just contacted"."""
    c = _Spoke(str(tmp_path))
    fresh_now = time.time()
    c._last_hub_contact = fresh_now                 # boot seeds "now"
    older = fresh_now - 600.0                        # 10m ago — an ongoing outage
    c._hcw_save({"last_contact_at": older})

    async def _sleep_once(_s):
        raise _Stop()
    monkeypatch.setattr(cp.asyncio, "sleep", _sleep_once)
    monkeypatch.setattr(cp.time, "time", lambda: fresh_now)
    try:
        asyncio.run(c._hub_contact_watchdog())
    except _Stop:
        pass
    assert c._last_hub_contact == older             # took the older (ongoing outage)


# ── escalation ladder ──────────────────────────────────────────────────────

def _enable(c, **kw):
    kw.setdefault("enabled", True)
    kw.setdefault("reboot_grace_s", 1)
    kw.setdefault("sleep_s", 1000)
    kw.setdefault("max_runs", 3)
    c._hcw_save_config(kw)


def test_t1_triggers_service_restart(monkeypatch, tmp_path):
    """Outage >= service_s → restart the service (os._exit(3)) + stage flips to
    service_restarted."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=2, reboot_s=1000, max_runs=3)
    # 3 ticks of 1s, disconnected: outage 3 >= service_s 2 → T1.
    exits, reboots = _drive(c, [(1, False), (1, False), (1, False)], monkeypatch)
    assert exits == [3]
    assert reboots == []
    st = c._hcw_load()
    assert st["stage"] == "service_restarted"


def test_t2_triggers_reboot(monkeypatch, tmp_path):
    """From stage=service_restarted, outage >= reboot_s → reboot the host +
    stage flips to rebooted."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=1, reboot_s=3, reboot_grace_s=100, max_runs=3)
    base = c._last_hub_contact
    # Seed an in-progress run already past service_s (stage=service_restarted).
    c._hcw_save({"run_start_at": base + 1, "stage": "service_restarted",
                 "last_contact_at": base})
    # 4 ticks of 1s: outage grows 1..4; at run_outage>=3 (reboot_s) → reboot.
    exits, reboots = _drive(c, [(1, False), (1, False), (1, False), (1, False)],
                            monkeypatch)
    assert reboots == [True]
    assert 3 not in exits                 # T1 already passed before this run
    assert c._hcw_load()["stage"] == "rebooted"


def test_t2_plus_grace_bumps_run_and_cooldowns(monkeypatch, tmp_path):
    """From stage=rebooted, run_outage >= reboot_s + reboot_grace_s → the run
    failed: run += 1, sleep_until = now + sleep_s, run_start_at/stage reset."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=1, reboot_s=2, reboot_grace_s=1, sleep_s=100, max_runs=3)
    base = c._last_hub_contact
    c._hcw_save({"run_start_at": base, "stage": "rebooted",
                 "last_contact_at": base})
    # 4 ticks: run_outage grows to 4; reboot_s(2)+grace(1)=3 → at 3+ run bumps.
    _drive(c, [(1, False), (1, False), (1, False), (1, False)], monkeypatch)
    st = c._hcw_load()
    assert st["run"] == 1
    assert st["sleep_until"] > c._last_hub_contact    # cooling down
    assert st["run_start_at"] == 0
    assert st["stage"] == "started"


def test_max_runs_gives_up(monkeypatch, tmp_path):
    """run >= max_runs → gave_up=True (stop escalating; stay offline)."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=1, reboot_s=2, max_runs=2)
    # Seed one run already completed (run=1) + cooldown expired, so the next
    # tick sees run >= max_runs.
    c._hcw_save({"run": 2, "stage": "started", "run_start_at": 0,
                 "sleep_until": 0, "last_contact_at": c._last_hub_contact})
    _drive(c, [(1, False)], monkeypatch)
    st = c._hcw_load()
    assert st.get("gave_up") is True


def test_recovery_clears_ladder(monkeypatch, tmp_path):
    """Successful hub contact (connected) wipes the escalation state — full
    recovery, the ladder resets."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=10, reboot_s=20)
    c._hcw_save({"run": 1, "stage": "service_restarted", "run_start_at": 1.0,
                 "last_contact_at": 1.0})
    _drive(c, [(1, True)], monkeypatch)        # one tick, connected
    assert c._hcw_load().get("run") is None or c._hcw_load() == {} or \
        "run" not in c._hcw_load()
    # State was cleared (no armed ladder remains).
    assert not c._hcw_load().get("stage")


def test_cooldown_respected(monkeypatch, tmp_path):
    """While sleep_until is in the future, the watchdog cools down — no new run
    starts, no escalation, state untouched."""
    c = _Spoke(str(tmp_path))
    _enable(c, service_s=1, reboot_s=2, max_runs=3)
    base = c._last_hub_contact
    c._hcw_save({"run": 1, "stage": "started", "run_start_at": 0,
                 "sleep_until": base + 10000, "last_contact_at": base})
    _drive(c, [(1, False), (1, False)], monkeypatch)
    st = c._hcw_load()
    assert st["run"] == 1                       # unchanged
    assert st["run_start_at"] == 0              # no new run started


def test_disabled_clears_and_noops(monkeypatch, tmp_path):
    """When disabled (even with an armed ladder on disk), each tick wipes the
    ladder + does nothing — the task always runs but no-ops while off."""
    c = _Spoke(str(tmp_path))
    c._hcw_save_config({"enabled": False})
    c._hcw_save({"run": 1, "stage": "service_restarted", "run_start_at": 1.0,
                 "last_contact_at": 1.0})
    exits, reboots = _drive(c, [(1, False), (1, False)], monkeypatch)
    assert exits == [] and reboots == []
    assert not c._hcw_load().get("stage")       # armed ladder was wiped