"""Spoke-level tests for offline-device name persistence: a port we've NAMED or
IDENTIFIED must keep appearing (as ``present=False``) even once its adapter is
unplugged / the target is powered off, so its name survives a reboot instead of
vanishing from the enumeration-only inventory.
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

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
from test_serial_manager import _FakeSerial  # noqa: E402


@pytest.fixture()
def spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    _FakeSerial.Serial.instances = []
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": False, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def _list(sp):
    return asyncio.run(sp.handle_command("CONSOLE_LIST_PORTS", {}))["ports"]


def test_named_offline_port_persists_as_not_present(monkeypatch, spoke):
    # A port is present and gets a human alias; its hw is remembered.
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "sw1", "device": "/dev/ttyUSB0", "kind": "usb",
         "vendor": "FTDI", "product": "FT232", "serial": "A1", "vid": "0403", "pid": "6001"},
    ])
    spoke.store.update("sw1", alias="core-switch")
    ports = _list(spoke)
    assert ports[0]["port_id"] == "sw1" and ports[0]["present"] is True

    # Device is now unplugged / powered off → not enumerated anymore.
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    ports = _list(spoke)
    assert len(ports) == 1
    p = ports[0]
    assert p["port_id"] == "sw1"
    assert p["alias"] == "core-switch"
    assert p["present"] is False
    assert p["in_use"] is False
    # hw snapshot was persisted while present → still describes the device offline.
    assert p["product"] == "FT232" and p["device"] == "/dev/ttyUSB0"


def test_identified_offline_port_persists(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "rtr1", "device": "/dev/ttyUSB1", "product": "console"},
    ])
    spoke.store.update("rtr1", probe={"identity": {"hostname": "edge-rtr"}})
    _list(spoke)  # persist hw
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    ports = _list(spoke)
    assert len(ports) == 1
    assert ports[0]["port_id"] == "rtr1" and ports[0]["present"] is False
    assert ports[0]["probe"]["identity"]["hostname"] == "edge-rtr"


def test_unnamed_offline_port_not_resurfaced(monkeypatch, spoke):
    # A port that was merely seen but never named/identified should NOT clutter
    # the list once it's gone (only meaningful, human-named ports persist).
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "tmp0", "device": "/dev/ttyUSB9", "product": "generic"},
    ])
    _list(spoke)  # persists hw only, no alias/identity
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    assert _list(spoke) == []


def test_present_flag_on_live_ports(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "a", "device": "/dev/ttyUSB0"},
        {"port_id": "b", "device": "/dev/ttyUSB1"},
    ])
    ports = _list(spoke)
    assert {p["port_id"]: p["present"] for p in ports} == {"a": True, "b": True}
