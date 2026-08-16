"""Spoke-level tests for the passive console monitor: keep-alive capture, passive
identity glean, faulty-port hiding, and CONSOLE_LIST_PORTS telemetry.

Runs without pyserial (a fake serial module is injected into serial_manager) and
without the real BaseSpoke (stubbed) so the console role's logic is exercised in
isolation.
"""
import asyncio
import sys
import types
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

# Stub BaseSpoke before importing the console spoke (avoids dragging in core).
_bs = types.ModuleType("base_spoke")


class _BaseSpoke:  # minimal stand-in
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


_bs.BaseSpoke = _BaseSpoke
sys.modules.setdefault("base_spoke", _bs)

import serial_manager as sm  # noqa: E402
import console_spoke as cs  # noqa: E402
from test_serial_manager import _FakeSerial  # reuse the fake serial  # noqa: E402


@pytest.fixture()
def spoke(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    _FakeSerial.Serial.instances = []
    ports = [
        {"port_id": "good", "device": "/dev/ttyUSB0", "product": "FTDI"},
        {"port_id": "bad", "device": "/dev/ttyS2-bad", "product": "onboard"},
    ]
    monkeypatch.setattr(cs, "enumerate_ports", lambda: list(ports))
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": True, "auto_identify": False})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    # Sentinels so handle_command's _ensure_*_task() see a task and don't spawn
    # real background loops during the test.
    sp._monitor_task = object()
    sp._autoprobe_task = object()
    return sp


def test_monitor_opens_good_hides_faulty(spoke):
    spoke._monitor_scan()
    # Good port is passively monitored; faulty port is flagged unopenable.
    assert spoke.sessions.channel("good") is not None
    assert spoke.sessions.channel("good").monitored is True
    assert "bad" in spoke._unopenable
    assert "input/output error" in spoke._unopenable["bad"]["error"].lower()


def test_faulty_port_hidden_from_list_but_recovers(spoke):
    spoke._monitor_scan()
    res = asyncio.run(spoke.handle_command("CONSOLE_LIST_PORTS", {}))
    pids = {p["port_id"] for p in res["ports"]}
    assert "good" in pids and "bad" not in pids
    good = next(p for p in res["ports"] if p["port_id"] == "good")
    assert good["monitoring"] is True and good["in_use"] is False
    assert "last_activity" in good and "capture_bytes" in good
    # The faulty port starts working: point it at a good device and rescan.
    spoke._clear_unopenable("bad")
    import console_spoke as _cs
    _cs.enumerate_ports = lambda: [
        {"port_id": "good", "device": "/dev/ttyUSB0"},
        {"port_id": "bad", "device": "/dev/ttyUSB1"},  # no longer "bad"
    ]
    spoke._monitor_scan()
    res2 = asyncio.run(spoke.handle_command("CONSOLE_LIST_PORTS", {}))
    assert "bad" in {p["port_id"] for p in res2["ports"]}


def test_passive_glean_fills_identity_without_login(spoke):
    spoke._monitor_scan()
    chan = spoke.sessions.channel("good")
    chan._record(b"Cisco IOS Software\r\nProcessor board ID ABC123\r\n"
                 b"Base ethernet MAC Address : 00:11:22:33:44:55\r\nSwitch#")
    spoke._passive_glean("good")
    probe = spoke.store.get("good")["probe"]
    assert probe["vendor"] == "cisco-ios"
    assert probe["identity"]["serial"] == "ABC123"
    assert probe["source"] == "passive"
    assert probe["banner"]


def test_passive_glean_never_overwrites_active(spoke):
    spoke._monitor_scan()
    # Simulate an authoritative active identify already stored.
    spoke.store.update("good", probe={
        "source": "active", "vendor": "cisco-ios",
        "identity": {"serial": "REAL123", "ip": "10.0.0.9"},
    })
    chan = spoke.sessions.channel("good")
    chan._record(b"Cisco IOS Software\r\nProcessor board ID WRONG999\r\nSwitch#")
    spoke._passive_glean("good")
    probe = spoke.store.get("good")["probe"]
    assert probe["source"] == "active"           # unchanged
    assert probe["identity"]["serial"] == "REAL123"  # active value not clobbered


def test_capture_command_returns_recent_output(spoke):
    spoke._monitor_scan()
    spoke.sessions.channel("good")._record(b"boot banner line\r\nlogin: ")
    res = asyncio.run(spoke.handle_command("CONSOLE_GET_CAPTURE", {"port_id": "good"}))
    assert res["status"] == "SUCCESS"
    assert "boot banner line" in res["capture"]
    assert res["monitoring"] is True


def test_monitor_login_scan_attempts_login_with_stored_creds(spoke):
    # Monitoring should ALSO try to log in with the stored credentials and learn
    # what it can — a silent device reveals nothing to a passive listen.
    spoke.config["auto_identify"] = True
    spoke._credentials = [{"username": "admin", "password": "x"}]
    spoke._monitor_scan()  # 'good' monitored, 'bad' hidden as unopenable
    calls = []
    spoke._identify_blocking = lambda pid, dev: calls.append(pid) or {
        "vendor": "cisco-ios", "identity": {"serial": "S1"}, "logged_in": True, "banner": "hi"}
    asyncio.run(spoke._monitor_login_scan())
    assert calls == ["good"]  # attempted the openable port; skipped the unopenable one
    probe = spoke.store.get("good")["probe"]
    assert probe["source"] == "active" and probe["identity"]["serial"] == "S1"
    # Now identified authoritatively → not attempted again.
    calls.clear()
    asyncio.run(spoke._monitor_login_scan())
    assert calls == []


def test_monitor_login_scan_skips_without_credentials(spoke):
    spoke.config["auto_identify"] = True
    spoke._credentials = []
    spoke._monitor_scan()
    called = []
    spoke._identify_blocking = lambda pid, dev: called.append(pid) or {}
    asyncio.run(spoke._monitor_login_scan())
    assert called == []  # no creds → nothing to log in with


def test_login_backs_off_after_failure(spoke):
    spoke.config["auto_identify"] = True
    spoke._credentials = [{"username": "a", "password": "b"}]
    spoke._monitor_scan()
    spoke._identify_blocking = lambda pid, dev: {"vendor": None, "identity": {}, "logged_in": False}
    asyncio.run(spoke._monitor_login_scan())
    assert spoke._probe_delay["good"] >= 300.0     # escalated backoff
    assert spoke._identify_due("good") is False     # just attempted → not due yet

