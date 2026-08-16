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


def test_diagnostics_reports_faulty_port(spoke):
    spoke._monitor_scan()  # 'bad' can't open → open failure #1; 'good' is healthy
    assert spoke._health["bad"]["open_failures"] == 1
    assert spoke._health["bad"]["currently_failing"] is True
    # Re-scanning while still faulty must NOT double-count the same episode.
    spoke._monitor_scan()
    assert spoke._health["bad"]["open_failures"] == 1
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS", {}))
    assert res["status"] == "SUCCESS"
    bad = next(d for d in res["diagnostics"] if d["port_id"] == "bad")
    assert bad["currently_failing"] is True and bad["open_failures"] == 1
    assert "input/output error" in bad["last_error"].lower()
    # A healthy port has no failure story → excluded from the report.
    assert all(d["port_id"] != "good" for d in res["diagnostics"])


def test_diagnostics_counts_recovery(spoke):
    spoke._monitor_scan()
    spoke._clear_unopenable("bad")  # simulate the port becoming openable again
    assert spoke._health["bad"]["recoveries"] == 1
    assert spoke._health["bad"]["currently_failing"] is False


def test_diagnostics_counts_disconnect(spoke):
    spoke._monitor_scan()  # 'good' is monitored
    spoke.sessions.channel("good")._reader_alive = False  # reader thread died (device pulled)
    spoke._monitor_scan()  # detect the dead reader → disconnect, then reopen
    assert spoke._health["good"]["disconnects"] == 1
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS", {}))
    good = next(d for d in res["diagnostics"] if d["port_id"] == "good")
    assert good["disconnects"] == 1




def test_llm_collect_disabled_by_default(spoke):
    res = asyncio.run(spoke.handle_command(
        "CONSOLE_LLM_COLLECT", {"port_id": "good", "commands": ["show version"]}))
    assert res["status"] == "ERROR"
    assert "disabled" in res["message"].lower()


class _ScriptedLine:
    """Login-prompt device answering one command, for the collect handler test."""
    def __init__(self, *a, **k):
        self.buf = bytearray(b"\r\ndev login: ")
        self.state = "login"
    def read(self, n=256):
        out = bytes(self.buf[:n]); del self.buf[:n]; return out
    def write(self, b):
        s = b.decode(errors="replace")
        if self.state == "login" and s.strip():
            self.state = "password"; self.buf += b"\r\nPassword: "
        elif self.state == "password" and s.strip():
            self.state = "shell"; self.buf += b"\r\ndev#"
        elif "show version" in s:
            self.buf += b"\r\nAcme NOS 1.2 SN=QQ7\r\ndev#"
        elif s.strip():
            self.buf += b"\r\ndev#"
    def close(self):
        pass


def test_llm_collect_runs_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    monkeypatch.setattr(cs, "enumerate_ports",
                        lambda: [{"port_id": "good", "device": "/dev/ttyUSB0", "product": "x"}])
    monkeypatch.setattr(cs, "open_raw", lambda *a, **k: _ScriptedLine())
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": True, "auto_identify": False,
                                       "console_llm_identify": True})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object(); sp._autoprobe_task = object()
    sp._credentials = [{"username": "a", "password": "b"}]
    res = asyncio.run(sp.handle_command(
        "CONSOLE_LLM_COLLECT",
        {"port_id": "good", "commands": ["show version", "reload"]}))
    assert res["status"] == "SUCCESS"
    assert res["logged_in"] is True
    assert "QQ7" in res["outputs"]["show version"]
    assert "reload" in res["rejected"]


def test_llm_store_persists_identity_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(sm, "serial", _FakeSerial)
    monkeypatch.setattr(cs, "enumerate_ports",
                        lambda: [{"port_id": "good", "device": "/dev/ttyUSB0", "product": "x"}])
    sp = cs.ConsoleSpoke("console-1", {"console_monitor": True, "auto_identify": False,
                                       "console_llm_identify": True})
    sp.store = sm.PortStore(path=tmp_path / "ports.json")
    sp._monitor_task = object(); sp._autoprobe_task = object()
    res = asyncio.run(sp.handle_command("CONSOLE_LLM_STORE", {
        "port_id": "good", "vendor": "juniper",
        "identity": {"serial": "JN9"}, "logged_in": True, "banner": "Junos"}))
    assert res["status"] == "SUCCESS"
    probe = sp.store.get("good").get("probe")
    assert probe["vendor"] == "juniper" and probe["identity"]["serial"] == "JN9"
    assert probe["source"] == "active" and probe["method"] == "llm"


def test_llm_store_disabled_by_default(spoke):
    res = asyncio.run(spoke.handle_command("CONSOLE_LLM_STORE",
                                           {"port_id": "good", "vendor": "x"}))
    assert res["status"] == "ERROR" and "disabled" in res["message"].lower()


def test_identify_telemetry_surfaces_in_diagnostics(spoke):
    # Simulate a login attempt that saw a login prompt but never authenticated.
    spoke._record_identify_telemetry("good", {
        "logged_in": False, "vendor": None, "identity": {},
        "diag": {"login_prompt_seen": True, "password_prompt_seen": True,
                 "shell_prompt_seen": False, "any_output": True, "bytes": 42,
                 "creds_tried": 1, "creds_available": 2,
                 "reason": "credentials rejected (re-prompted for login/password)",
                 "tail": "dev login:"}}, method="login")
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS", {}))
    row = next(d for d in res["diagnostics"] if d["port_id"] == "good")
    t = row["identify"]
    assert t["attempts"] == 1 and t["logins_ok"] == 0
    assert t["login_prompt_seen"] and t["password_prompt_seen"]
    assert "rejected" in t["reason"] and t["tail"] == "dev login:"


def test_set_llm_identify_toggles_runtime_config(spoke):
    assert spoke.config.get("console_llm_identify") in (None, False)
    res = asyncio.run(spoke.handle_command("CONSOLE_SET_LLM_IDENTIFY", {"enabled": True}))
    assert res["status"] == "SUCCESS" and res["enabled"] is True
    assert spoke.config["console_llm_identify"] is True
    res = asyncio.run(spoke.handle_command("CONSOLE_SET_LLM_IDENTIFY", {"enabled": False}))
    assert spoke.config["console_llm_identify"] is False


def test_diagnostics_purge_clears_health(spoke):
    spoke._record_identify_telemetry("good", {
        "logged_in": False, "vendor": None, "identity": {},
        "diag": {"any_output": True, "bytes": 5, "reason": "x", "tail": "y"}}, method="login")
    assert spoke._health  # something collected
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS_PURGE", {}))
    assert res["status"] == "SUCCESS" and res["purged"] >= 1
    assert spoke._health == {}


def test_effective_credentials_appends_factory_defaults(spoke):
    spoke._credentials = [{"username": "op", "password": "p"}]
    eff = spoke._effective_credentials()
    assert eff[0] == {"username": "op", "password": "p"}
    assert {"username": "admin", "password": "admin"} in eff       # factory default appended
    # extras (e.g. LLM guesses) land after operator creds, before dupes are dropped
    eff2 = spoke._effective_credentials([{"username": "guess", "password": "g"}])
    assert {"username": "guess", "password": "g"} in eff2
    # disabling factory defaults keeps only operator (+ extras)
    spoke.config["console_factory_default_creds"] = False
    assert spoke._effective_credentials() == [{"username": "op", "password": "p"}]
