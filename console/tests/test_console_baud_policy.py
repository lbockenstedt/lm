"""Baud-policy tests for the Console role.

The console must ALWAYS prefer 115200: it is the default rate for a port with no
saved setting, it is what an inconclusive sweep falls back to, and an operator
who pins a rate by hand must never have it silently rolled back to a detected
one (the "my session dropped to 9600 again" bug).

Runs without pyserial (a fake serial module is injected into serial_manager) and
without the real BaseSpoke (stubbed), mirroring test_console_monitor.py.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

_bs = types.ModuleType("base_spoke")


class _BaseSpoke:  # minimal stand-in
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


_bs.BaseSpoke = _BaseSpoke
sys.modules.setdefault("base_spoke", _bs)

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
from test_serial_manager import _FakeSerial  # noqa: E402


@pytest.fixture()
def spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    _FakeSerial.Serial.instances = []
    ports = [{"port_id": "good", "device": "/dev/ttyUSB0", "product": "FTDI"}]
    monkeypatch.setattr(cs, "enumerate_ports", lambda: list(ports))
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": True, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ── module defaults ───────────────────────────────────────────────────────────

def test_default_baud_is_115200():
    assert sm.DEFAULT_BAUD == 115200


def test_unconfigured_port_defaults_to_115200(tmp_path):
    """A port nobody has ever configured must open at 115200, not 9600."""
    store = sm.PortStore(path=tmp_path / "ports.json")
    assert store.settings("never-seen")["baud"] == 115200


# ── inconclusive sweeps fall back to 115200 ───────────────────────────────────

class _SilentSerial:
    """Every rate stays silent, except 9600 which emits a little line noise —
    the classic way a sweep used to 'settle' on 9600."""

    class SerialException(Exception):
        pass

    class Serial:
        def __init__(self, dev, baud, timeout=0.3):
            self.baud = baud
            self._buf = bytes([0xFF, 0x80, 0x9A, 0x41]) if baud == 9600 else b""

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def reset_input_buffer(self):
            pass

        def write(self, b):
            pass

        def flush(self):
            pass

        def read(self, n):
            out, self._buf = self._buf[:n], self._buf[n:]
            return out

        def close(self):
            pass


def test_inconclusive_sweep_falls_back_to_115200(monkeypatch):
    """No rate answered readably → report 115200, never a noise-scored guess."""
    monkeypatch.setattr(sm, "serial", _SilentSerial)
    res = sm.detect_baud("/dev/ttyUSB0", read_secs=0.3)
    assert res["confident"] is False
    assert res["baud"] == 115200


def test_priority_baud_wins_a_tied_score(monkeypatch):
    """A later rate that merely TIES 115200 must not displace it."""
    from test_serial_manager import _MapFakeSerial
    _MapFakeSerial.probed = []
    # Identical replies at 115200 and 19200: equal score, so the priority rate
    # (probed first) must stay the winner.
    _MapFakeSerial.replies = {115200: bytes([0xFF, 0x80]), 19200: bytes([0xFE, 0x81])}
    monkeypatch.setattr(sm, "serial", _MapFakeSerial)
    res = sm.detect_baud("/dev/ttyUSB0", read_secs=0.3)
    assert res["baud"] == 115200


# ── operator pin ──────────────────────────────────────────────────────────────

def test_set_settings_pins_the_operator_baud(spoke):
    res = _run(spoke.handle_command("CONSOLE_SET_SETTINGS",
                                    {"port_id": "good", "baud": 115200}))
    assert res["status"] == "SUCCESS"
    probe = spoke.store.get("good").get("probe") or {}
    assert probe["baud_pinned"] is True
    assert probe["detected_baud"] == 115200


def test_detect_baud_never_overwrites_a_pinned_port(spoke, monkeypatch):
    _run(spoke.handle_command("CONSOLE_SET_SETTINGS", {"port_id": "good", "baud": 115200}))

    async def _fake_probe(pid, fn, *a, **kw):
        return {"baud": 9600, "score": 0.9, "confident": True, "sample": "x"}

    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_probe)
    res = _run(spoke.handle_command("CONSOLE_DETECT_BAUD", {"port_id": "good"}))
    assert res["status"] == "SUCCESS"
    # Reported, but the operator's pin stands.
    assert spoke.store.settings("good")["baud"] == 115200


def test_detect_baud_does_not_persist_an_unconfident_sweep(spoke, monkeypatch):
    async def _fake_probe(pid, fn, *a, **kw):
        return {"baud": 9600, "score": 0.2, "confident": False, "sample": ""}

    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_probe)
    _run(spoke.handle_command("CONSOLE_DETECT_BAUD", {"port_id": "good"}))
    # A guess is not a lock: the port stays on the 115200 default.
    assert spoke.store.settings("good")["baud"] == 115200
    assert not (spoke.store.get("good").get("probe") or {}).get("baud_confident")


def test_detect_baud_persists_a_confident_sweep(spoke, monkeypatch):
    async def _fake_probe(pid, fn, *a, **kw):
        return {"baud": 38400, "score": 1.4, "confident": True, "sample": "Switch>"}

    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_probe)
    _run(spoke.handle_command("CONSOLE_DETECT_BAUD", {"port_id": "good"}))
    assert spoke.store.settings("good")["baud"] == 38400
    assert (spoke.store.get("good").get("probe") or {})["baud_confident"] is True


def test_boot_relock_skips_a_pinned_port(spoke, monkeypatch):
    _run(spoke.handle_command("CONSOLE_SET_SETTINGS", {"port_id": "good", "baud": 115200}))
    called = {"n": 0}

    async def _fake_probe(pid, fn, *a, **kw):
        called["n"] += 1
        return {"baud": 9600, "score": 1.4, "confident": True, "sample": "x"}

    monkeypatch_probe(spoke, _fake_probe)
    _run(spoke._relock_baud("good", "/dev/ttyUSB0"))
    assert called["n"] == 0
    assert spoke.store.settings("good")["baud"] == 115200


def monkeypatch_probe(spoke, fn):
    spoke._exclusive_probe = fn


def _boot_relock_args(spoke, score):
    """Args for _boot_maybe_relock: a garbled line, no rate-limit in the way."""
    cfg = spoke._boot_cfg()
    boot = {"relocked": False}
    return dict(pid="good", dev="/dev/ttyUSB0", score=score, cfg=cfg,
                boot=boot, now=1e9), boot


def test_auto_locked_port_can_still_re_sweep(spoke):
    """An AUTOMATIC confident lock onto the wrong rate must not be permanent —
    a garbled line has to be allowed back to 115200. Only an operator pin
    blocks the re-sweep."""
    spoke.store.update("good", settings={"baud": 9600},
                       probe={"baud_confident": True, "detected_baud": 9600})
    spoke._loop = None  # stop before dispatching the coroutine; the gate is what we test
    kwargs, boot = _boot_relock_args(spoke, score=0.1)
    spoke._boot_maybe_relock(**kwargs)
    assert boot["relocked"] is True, "auto-locked port was never allowed to re-sweep"


def test_pinned_port_is_never_re_swept_on_a_garbled_line(spoke):
    _run(spoke.handle_command("CONSOLE_SET_SETTINGS", {"port_id": "good", "baud": 115200}))
    spoke._loop = None
    kwargs, boot = _boot_relock_args(spoke, score=0.1)
    spoke._boot_maybe_relock(**kwargs)
    assert boot["relocked"] is False
