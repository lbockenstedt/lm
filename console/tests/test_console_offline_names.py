"""Spoke-level tests: a port that isn't physically enumerated right now must
NOT appear in CONSOLE_LIST_PORTS at all — no ghost/offline row.

Regression this replaces: the old behavior resurfaced a named/identified port
as a ``present=False`` row once its adapter unplugged (e.g. across a reboot).
Combined with derive_port_id's bottom-tier fallback embedding the current
``/dev/ttyUSBn`` name (unstable across a reboot when several generic
USB-serial adapters share no burned-in serial number), every reboot minted a
NEW port_id for the same physical port and left the OLD port_id's ghost row
behind forever — producing exactly the "duplicate/stale DISCONNECTED rows,
some with an empty port" symptom seen in production. The fix: a port is either
up or it isn't shown; its alias/identity data stays in PortStore and
reattaches automatically if the same DEVICE (by serial/MAC learned via
login, not the USB adapter) reappears under a different port_id — see
test_console_port_reconcile.py.
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


def test_named_port_drops_from_list_once_unplugged(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "sw1", "device": "/dev/ttyUSB0", "kind": "usb",
         "vendor": "FTDI", "product": "FT232", "serial": "A1", "vid": "0403", "pid": "6001"},
    ])
    spoke.store.update("sw1", alias="core-switch")
    ports = _list(spoke)
    assert ports[0]["port_id"] == "sw1" and ports[0]["present"] is True

    # Device is now unplugged / powered off → not enumerated anymore.
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    assert _list(spoke) == [], "an absent port must not appear at all — no ghost row"


def test_identified_port_drops_from_list_once_unplugged(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "rtr1", "device": "/dev/ttyUSB1", "product": "console"},
    ])
    spoke.store.update("rtr1", probe={"identity": {"hostname": "edge-rtr"}})
    _list(spoke)
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    assert _list(spoke) == []


def test_unnamed_offline_port_not_resurfaced(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "tmp0", "device": "/dev/ttyUSB9", "product": "generic"},
    ])
    _list(spoke)
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    assert _list(spoke) == []


def test_present_flag_on_live_ports(monkeypatch, spoke):
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "a", "device": "/dev/ttyUSB0"},
        {"port_id": "b", "device": "/dev/ttyUSB1"},
    ])
    ports = _list(spoke)
    assert {p["port_id"]: p["present"] for p in ports} == {"a": True, "b": True}


def test_alias_and_identity_survive_in_the_store_while_absent(monkeypatch, spoke):
    """The row disappears from the list, but the underlying record is NOT
    deleted — it's exactly what a reappearing device (same port_id, e.g. a
    stable uart or a real USB serial number) reattaches to automatically."""
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "sw1", "device": "/dev/ttyUSB0", "product": "FT232"},
    ])
    spoke.store.update("sw1", alias="core-switch",
                        probe={"identity": {"hostname": "core-sw", "serial": "SN123"}})
    monkeypatch.setattr(cs, "enumerate_ports", lambda: [])
    assert _list(spoke) == []
    assert spoke.store.get("sw1").get("alias") == "core-switch"

    monkeypatch.setattr(cs, "enumerate_ports", lambda: [
        {"port_id": "sw1", "device": "/dev/ttyUSB0", "product": "FT232"},
    ])
    ports = _list(spoke)
    assert ports[0]["alias"] == "core-switch"
