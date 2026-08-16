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


def test_passive_glean_backfills_hostname_from_saved_banner(spoke):
    # An already-identified but SILENT switch (identified before the hostname
    # extraction shipped): active probe with a vendor + a saved banner that holds
    # "System Name : …", but NO hostname parsed and no NEW live output. The
    # hostname must be recovered from the saved banner without any re-probe.
    spoke._monitor_scan()  # opens the 'good' passive channel (no live bytes)
    spoke.store.update("good", probe={
        "source": "active", "vendor": "hp-procurve",
        "identity": {"type": "Switch"},
        "banner": ("MIA-SW-AOSS> show system\r\n"
                   "Status and Counters - General System Information\r\n"
                   "System Name        : MIA-SW-AOSS\r\n"),
    })
    spoke._passive_glean("good")
    probe = spoke.store.get("good")["probe"]
    assert probe["source"] == "active"                 # authoritative source kept
    assert probe["identity"]["hostname"] == "MIA-SW-AOSS"
    assert probe["identity"]["type"] == "Switch"        # existing field untouched


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


def test_banner_identified_port_not_re_probed_on_timer(spoke):
    # A device identified by BANNER (vendor + login, but no structured identity —
    # e.g. an HP-ProCurve switch) must be treated as authoritatively identified:
    # the auto-identify loops must NOT keep re-logging-into it every 30 min.
    spoke.config["auto_identify"] = True
    spoke._credentials = [{"username": "admin", "password": "x"}]
    spoke._monitor_scan()
    calls = []
    spoke._identify_blocking = lambda pid, dev: calls.append(pid) or {
        "vendor": "hp-procurve", "identity": {}, "logged_in": True, "banner": "ProCurve"}
    asyncio.run(spoke._monitor_login_scan())
    assert calls == ["good"]  # first identify happens
    probe = spoke.store.get("good")["probe"]
    assert probe["source"] == "active" and probe["vendor"] == "hp-procurve"
    # Subsequent scans (login + autoprobe) must skip it — no periodic re-verify.
    calls.clear()
    asyncio.run(spoke._monitor_login_scan())
    asyncio.run(spoke._autoprobe_scan())
    assert "good" not in calls  # identified port never re-probed on a timer
    # Diagnostics must advertise passive-only, not a re-verify countdown.
    status = spoke._identify_status("good", present=True)
    assert status["active_identity"] is True
    assert status["next_attempt_in"] == 0
    assert "no active re-probe" in status["skip_reason"]


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
    # A healthy present port now surfaces as an identify CANDIDATE (so the
    # operator can see WHY/WHEN it will be logged into) but carries no failure
    # story of its own.
    good = next((d for d in res["diagnostics"] if d["port_id"] == "good"), None)
    assert good is not None
    assert good["open_failures"] == 0 and good["currently_failing"] is False
    assert good["schedule"]["skip_reason"]


def test_diagnostics_summary_reports_login_readiness(spoke):
    # Whole-agent context: auto-identify OFF ⇒ no login is even attempted, and
    # that must be visible at the summary level (per-port rows can't show it).
    spoke.config["auto_identify"] = False
    spoke._credentials = []
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS", {}))
    s = res["summary"]
    assert s["auto_identify"] is False
    assert s["credentials_loaded"] == 0
    # Present ports carry a skip_reason explaining the disabled state.
    good = next((d for d in res["diagnostics"] if d["port_id"] == "good"), None)
    assert good and "disabled" in good["schedule"]["skip_reason"].lower()


def test_diagnostics_summary_login_enabled_with_creds(spoke):
    spoke.config["auto_identify"] = True
    spoke._credentials = [{"username": "admin", "password": "x"}]
    res = asyncio.run(spoke.handle_command("CONSOLE_DIAGNOSTICS", {}))
    s = res["summary"]
    assert s["auto_identify"] is True and s["credentials_loaded"] == 1
    assert s["login_enabled"] is True


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


def test_hostname_stability_tracked_in_telemetry(spoke):
    # A stable port: same hostname every probe → stable, no changes.
    for _ in range(3):
        spoke._record_identify_telemetry("good", {
            "logged_in": True, "vendor": "cisco-ios",
            "identity": {"hostname": "core-1"}, "hostname_source": "command",
            "diag": {}}, method="login")
    g = spoke._health["good"]["identify"]
    assert g["hostname"] == "core-1" and g["hostname_source"] == "command"
    assert g["hostname_changes"] == 0 and g["hostname_stable"] is True
    assert g["hostname_distinct"] == 1

    # A flapping port: name flips between two values → changes counted, history
    # keeps the distinct observations with their source.
    for hn, src in [("MIA-SW-AOSS", "prompt"), ("garbled", "prompt"),
                    ("MIA-SW-AOSS", "prompt")]:
        spoke._record_identify_telemetry("bad", {
            "logged_in": True, "vendor": "hp-procurve",
            "identity": {"hostname": hn}, "hostname_source": src,
            "diag": {}}, method="login")
    b = spoke._health["bad"]["identify"]
    assert b["hostname"] == "MIA-SW-AOSS"
    assert b["hostname_changes"] == 2 and b["hostname_stable"] is False
    assert b["hostname_distinct"] == 2
    assert {h["host"] for h in b["hostname_history"]} == {"MIA-SW-AOSS", "garbled"}
    assert all(h["source"] == "prompt" for h in b["hostname_history"])


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


# ── boot / wake capture ──────────────────────────────────────────────────────
class _FakeBootChan:
    """Stand-in channel exposing just what _boot_watch reads: a capture buffer."""
    def __init__(self):
        self.capture = b""

    def set(self, text: str):
        self.capture = text.encode()

    def capture_tail(self, n=None):
        return self.capture[-n:] if n else self.capture

    def snapshot(self):
        return {"monitoring": True, "last_activity": 0.0,
                "capture_bytes": len(self.capture), "pending_out": 0,
                "has_user": False, "writer": None, "baud": 9600}


def _drive_boot(spoke, pid, clock, chan, cur_bytes, dev="/dev/ttyUSB0"):
    """Invoke _boot_watch with a controlled snapshot + clock."""
    snap = {"capture_bytes": cur_bytes, "last_activity": clock[0]}
    spoke._boot_watch(pid, snap, dev)


def _install_fake_boot_chan(spoke, pid):
    chan = _FakeBootChan()
    spoke.sessions._channels[pid] = chan  # type: ignore[attr-defined]
    return chan


def test_boot_watch_booting_then_booted(spoke, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    # First tick establishes a byte baseline (no prior => no new output).
    _drive_boot(spoke, "good", clock, chan, 0)
    assert spoke._boot_info("good") is None
    # Silence passes, then a burst of boot output appears => booting.
    clock[0] += 100
    chan.set("U-Boot 2013.01\r\nStarting kernel ...\r\nLinux version 5.10\r\n")
    _drive_boot(spoke, "good", clock, chan, 60)
    info = spoke._boot_info("good")
    assert info and info["state"] == "booting"
    # A prompt appears => booted.
    clock[0] += 15
    chan.set("Linux 5.10\r\nswitch login: ")
    _drive_boot(spoke, "good", clock, chan, 90)
    info = spoke._boot_info("good")
    assert info["state"] == "booted" and info["prompt_seen"] is True


def test_boot_watch_stuck_on_fault(spoke, monkeypatch):
    clock = [2000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting...\r\nKernel panic - not syncing: VFS unable to mount root\r\n")
    _drive_boot(spoke, "good", clock, chan, 70)
    info = spoke._boot_info("good")
    assert info["state"] == "stuck" and "panic" in info["stuck_reason"].lower()


def test_boot_watch_stuck_on_timeout_no_prompt(spoke, monkeypatch):
    clock = [3000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting up, please wait ... garbled progress ...")
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"
    # Output stops; well past stuck timeout with no prompt => stuck.
    clock[0] += 40
    _drive_boot(spoke, "good", clock, chan, 50)  # no new bytes
    info = spoke._boot_info("good")
    assert info["state"] == "stuck" and info["prompt_seen"] is False


def test_boot_watch_surfaced_in_list_and_diagnostics(spoke, monkeypatch):
    clock = [4000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Starting kernel\r\nswitch login: ")
    _drive_boot(spoke, "good", clock, chan, 40)
    # CONSOLE_LIST_PORTS carries a boot block.
    res = asyncio.run(spoke.handle_command("CONSOLE_LIST_PORTS", {}))
    good = next(p for p in res["ports"] if p["port_id"] == "good")
    assert good["boot"] and good["boot"]["state"] == "booted"
    # Diagnostics rows carry it too.
    diag = spoke._diagnostics()
    row = next(r for r in diag if r["port_id"] == "good")
    assert row["boot"]["state"] == "booted"


def test_boot_watch_disabled_by_config(spoke, monkeypatch):
    clock = [5000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_watch"] = False
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("switch login: ")
    _drive_boot(spoke, "good", clock, chan, 40)
    assert spoke._boot_info("good") is None
