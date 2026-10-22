"""The update_gate maintenance window is evaluated in a configurable timezone,
and the loopback ``/admin/ops/self-update`` deploy route no longer forces a hub
restart by default.

Both were live causes of "the hub auto-updated while I was logged in":
* The hub runs in UTC, so the default 02:00 window fired at 02:00 UTC — 9pm in
  US Central, while operators were still logged in.
* ``/admin/ops/self-update`` (scripted/agent deploys) hard-coded ``force=True``,
  bypassing the gate and restarting the hub mid-day on every deploy.
"""
import datetime as _dt
import os
import sys
import types

import pytest

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import main  # noqa: E402
from main import LabManagerHub as _MainHub  # noqa: E402


class _GateHub:
    _update_gate_config = _MainHub._update_gate_config
    _gate_allows_restart_now = _MainHub._gate_allows_restart_now

    def __init__(self, gate):
        self.state = types.SimpleNamespace(
            system_state={"global_config": {"update_gate": gate}})


class _FixedDatetime(_dt.datetime):
    """``now()`` pinned to 2026-10-22 02:30 UTC (= 21:30 America/Chicago)."""
    _UTC = _dt.datetime(2026, 10, 22, 2, 30, tzinfo=_dt.timezone.utc)

    @classmethod
    def now(cls, tz=None):
        if tz is None:
            return cls._UTC.replace(tzinfo=None)  # hub system clock is UTC
        return cls._UTC.astimezone(tz)


@pytest.fixture
def fixed_clock(monkeypatch):
    monkeypatch.setattr(main, "_dt", types.SimpleNamespace(
        datetime=_FixedDatetime, timezone=_dt.timezone))
    monkeypatch.delenv("LM_UPDATE_GATE_TZ", raising=False)
    # Window mode never consults idle, but keep it deterministic.
    import api
    monkeypatch.setattr(api, "_active_user_count", lambda *a, **k: 1)


def test_no_timezone_uses_hub_clock(fixed_clock):
    # 02:30 on the (UTC) hub clock → inside the default 02:00-04:00 window.
    assert _GateHub({})._gate_allows_restart_now() is True


def test_timezone_moves_the_window(fixed_clock):
    # Same instant is 21:30 in Chicago → outside a 02:00 Chicago window.
    hub = _GateHub({"timezone": "America/Chicago"})
    assert _update_hour(hub) == 21
    assert hub._gate_allows_restart_now() is False


def test_timezone_window_opens_at_local_2am(fixed_clock, monkeypatch):
    # 07:30 UTC == 02:30 CDT → inside the Chicago window.
    monkeypatch.setattr(_FixedDatetime, "_UTC",
                        _dt.datetime(2026, 10, 22, 7, 30, tzinfo=_dt.timezone.utc))
    assert _GateHub({"timezone": "America/Chicago"})._gate_allows_restart_now() is True


def test_env_timezone_is_the_fallback(fixed_clock, monkeypatch):
    monkeypatch.setenv("LM_UPDATE_GATE_TZ", "America/Chicago")
    assert _GateHub({})._gate_allows_restart_now() is False
    # An explicit config value wins over the env.
    assert _GateHub({"timezone": "UTC"})._gate_allows_restart_now() is True


def test_invalid_timezone_falls_back_to_hub_clock(fixed_clock):
    assert _GateHub({"timezone": "Not/AZone"})._gate_allows_restart_now() is True


def _update_hour(hub):
    return main._update_gate_local_hour(hub._update_gate_config()["timezone"])


def test_admin_ops_self_update_is_gated_by_default():
    src = open(os.path.join(_SRC, "routes", "admin_ops.py"), encoding="utf-8").read()
    start = src.index('@app.post("/admin/ops/self-update")')
    body = src[start:src.index("@app.post", start + 10)]
    assert "run_repo_sync_all(force_spokes=True, force=force)" in body
    assert "force=True)" not in body, "self-update must not hard-code a forced hub restart"
