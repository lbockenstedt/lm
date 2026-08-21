"""Spoke-level tests for the configurable auto-identify retry policy and the
first-seen (new-cable) auto-profile behaviour. Runs without pyserial/BaseSpoke.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

_bs = types.ModuleType("base_spoke")


class _BaseSpoke:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


_bs.BaseSpoke = _BaseSpoke
sys.modules.setdefault("base_spoke", _bs)

import console_spoke as cs  # noqa: E402


def _make_spoke(monkeypatch, tmp_path, config, ports):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [dict(p) for p in ports])
    sp = cs.ConsoleSpoke("console-1", dict(config))
    sp.store = cs.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def test_identify_cfg_defaults_and_overrides(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path, {"auto_identify": True}, [])
    d = sp._identify_cfg()
    assert d == {"retry_min": 300.0, "retry_max": 3600.0, "reverify": 86400.0,
                 "max_attempts": 0, "scan_interval": 30.0}
    sp.config.update({
        "console_identify_retry_secs": 60,
        "console_identify_retry_max_secs": 900,
        "console_identify_reverify_secs": 120,
        "console_identify_max_attempts": 3,
        "console_autoprobe_interval": 5,
    })
    d = sp._identify_cfg()
    assert d["retry_min"] == 60.0 and d["retry_max"] == 900.0
    assert d["reverify"] == 120.0 and d["max_attempts"] == 3 and d["scan_interval"] == 5.0


def test_identify_cfg_ignores_bad_values(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path,
                     {"auto_identify": True, "console_identify_retry_secs": "nope",
                      "console_identify_max_attempts": -1}, [])
    d = sp._identify_cfg()
    assert d["retry_min"] == 300.0        # invalid → default
    assert d["max_attempts"] == 0         # negative → default (unlimited)


def test_identify_due_new_port_is_immediately_due(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path, {"auto_identify": True}, [])
    assert sp._identify_due("never-tried") is True


def test_identify_due_stops_after_max_attempts(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path,
                     {"auto_identify": True, "console_identify_max_attempts": 2}, [])
    sp._probe_attempts["p"] = 0.0  # attempted, but backoff long-elapsed
    sp._probe_fails["p"] = 2
    assert sp._identify_due("p") is False
    # With no cap the same port is due again once its backoff elapses.
    sp.config["console_identify_max_attempts"] = 0
    assert sp._identify_due("p") is True


def test_first_seen_new_cable_is_profiled_immediately(monkeypatch, tmp_path):
    ports = [{"port_id": "usb-new", "device": "/dev/ttyUSB0"}]
    sp = _make_spoke(monkeypatch, tmp_path, {"auto_identify": True}, ports)
    called = []

    async def _fake_active(pid, dev):
        called.append((pid, dev))
        return {}

    sp._active_identify = _fake_active
    asyncio.run(sp._autoprobe_scan())
    assert called == [("usb-new", "/dev/ttyUSB0")]
    assert sp._seen_ports == {"usb-new"}


def test_replug_clears_stale_retry_state(monkeypatch, tmp_path):
    # A port that has vanished has its retry/backoff/fail state cleared so a
    # re-plugged cable starts fresh instead of inheriting a stale give-up state.
    sp = _make_spoke(monkeypatch, tmp_path, {"auto_identify": True}, [])
    sp._seen_ports = {"gone"}
    sp._probe_attempts["gone"] = 123.0
    sp._probe_delay["gone"] = 3600.0
    sp._probe_fails["gone"] = 9
    asyncio.run(sp._autoprobe_scan())
    assert "gone" not in sp._probe_attempts
    assert "gone" not in sp._probe_delay
    assert "gone" not in sp._probe_fails
    assert sp._seen_ports == set()


def test_given_up_surfaced_in_identify_status(monkeypatch, tmp_path):
    sp = _make_spoke(monkeypatch, tmp_path,
                     {"auto_identify": True, "console_identify_max_attempts": 2}, [])
    sp._probe_attempts["p"] = 1.0
    sp._probe_fails["p"] = 2
    st = sp._identify_status("p", present=True)
    assert st["given_up"] is True
    assert st["consecutive_fails"] == 2
    assert st["max_attempts"] == 2
    assert "gave up" in st["skip_reason"]
