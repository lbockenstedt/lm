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
        self.sessions = set()  # no attached user sessions (matches a real idle monitor channel)
        self.writer = None
        self.last_user_write_at = 0.0  # no session has ever typed into this port

    def set(self, text: str):
        self.capture = text.encode()

    def capture_tail(self, n=None):
        return self.capture[-n:] if n else self.capture

    def snapshot(self):
        return {"monitoring": True, "last_activity": 0.0,
                "capture_bytes": len(self.capture), "pending_out": 0,
                "has_user": False, "last_user_write_at": self.last_user_write_at,
                "writer": None, "baud": 9600}


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


def test_boot_watch_nudge_confirms_live_prompt_not_stuck(spoke, monkeypatch):
    """A device that looks stuck only because it's repeating unrelated chatter
    (e.g. a console idle-timeout banner) must not be condemned without a
    confirming nudge — and the nudge finding a live prompt resolves it as
    booted, not stuck."""
    clock = [1_700_000_000.0]  # realistic epoch time, like real time.time()
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Console terminated due to inactivity.\r\n" * 20)
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"

    async def _fake_exclusive_probe(pid, fn, *a):
        assert fn.__func__ is cs.ConsoleSpoke._boot_liveness_blocking
        return {"responsive": True, "tail": "switch> "}
    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40  # well past stuck_secs, still no prompt in the passive tail
        _drive_boot(spoke, "good", clock, chan, 50)  # no new bytes
        # A nudge was scheduled instead of marking stuck outright.
        info = spoke._boot_info("good")
        assert info["state"] == "booting"
        assert spoke._boot_nudge_at.get("good") == clock[0]
        for _ in range(5):  # let the scheduled coroutine run to completion
            await asyncio.sleep(0)
    asyncio.run(_run())

    info = spoke._boot_info("good")
    assert info["state"] == "booted"
    assert "liveness check" in info["reason"]


@pytest.mark.parametrize("reply", ["", "Console terminated due to inactivity.\r\n" * 20,
                                   "Kernel panic\r\n" * 20,
                                   "failed to boot\r\nrommon 1 >",
                                   # Bootloader prompts with NO fault text at all:
                                   # these ANSWER the nudge and match the generic
                                   # shell-prompt shape, so liveness alone scores
                                   # them "booted" — but a device parked in
                                   # rommon/loader/u-boot never reached its OS.
                                   "loader>", "boot>", "=>", "db>",
                                   "rommon 1 >", "grub> ", "switch: "])
def test_boot_watch_nudge_confirms_genuinely_stuck(spoke, monkeypatch, reply):
    """Noise is not a prompt, a recovery prompt cannot clear a boot fault, and a
    bootloader prompt is not a booted device even with no fault text to go on."""
    clock = [1_700_000_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting up, please wait ... garbled progress ...")
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"

    async def _fake_exclusive_probe(pid, fn, *a):
        return {"responsive": cs.looks_like_prompt(reply), "tail": reply}
    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40
        _drive_boot(spoke, "good", clock, chan, 50)
        for _ in range(5):
            await asyncio.sleep(0)
    asyncio.run(_run())

    info = spoke._boot_info("good")
    assert info["state"] == "stuck" and info["prompt_seen"] is False
    if reply:
        assert spoke._health["good"]["boot"]["transcript_tail"] == cs.sanitize_console_text(reply)[-1600:]


def test_boot_watch_no_nudge_while_user_holds_port(spoke, monkeypatch):
    """Never send a confirming CR while a human/relay session is attached — a
    real operator's session is never interfered with. A session that's
    ACTIVELY BEING TYPED INTO is itself evidence the line is live, so that
    episode must NOT be condemned as stuck either: it stays "booting"
    (deferred) as long as the typing continues, e.g. a device that reprints a
    large login banner on every retry while someone works through credentials
    by hand."""
    clock = [1_700_000_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    chan.sessions = {"some-session"}
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting up, please wait ... garbled progress ...")
    _drive_boot(spoke, "good", clock, chan, 50)
    def _boom(*a, **kw):
        raise AssertionError("must not schedule a nudge while a user is typing")
    monkeypatch.setattr(spoke, "_exclusive_probe", _boom)
    monkeypatch.setattr(cs.asyncio, "run_coroutine_threadsafe", _boom)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40
        chan.last_user_write_at = clock[0]  # a keystroke just landed
        _drive_boot(spoke, "good", clock, chan, 50)
        assert spoke._boot_info("good")["state"] == "booting"
        assert "good" not in spoke._boot_nudge_at
        assert "good" not in spoke._boot_nudge_pending
        # Stays deferred as long as typing keeps refreshing last_user_write_at,
        # even well past the stuck timeout.
        clock[0] += 20
        chan.last_user_write_at = clock[0]
        chan.set("Booting up, please wait ... garbled progress ...")
        _drive_boot(spoke, "good", clock, chan, 100)
        assert spoke._boot_info("good")["state"] == "booting"
    asyncio.run(_run())


def test_boot_watch_stuck_when_session_attached_but_idle(spoke, monkeypatch):
    """A session that's merely ATTACHED — no keystroke in the recorded window
    (a stale browser tab, an abandoned relay leg) — is no evidence the device
    is actually live, so it must NOT hide a genuinely hung boot forever: this
    falls back to the same passive-stuck verdict as before a session existed
    at all (never send our own CR into any attached session, active or not)."""
    clock = [1_700_200_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    chan.sessions = {"stale-tab"}
    chan.last_user_write_at = 0.0  # never typed into
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Booting up, please wait ... garbled progress ...")
    _drive_boot(spoke, "good", clock, chan, 50)
    clock[0] += 40
    _drive_boot(spoke, "good", clock, chan, 50)  # no loop -> passive verdict
    info = spoke._boot_info("good")
    assert info["state"] == "stuck"
    assert info.get("verdict_basis") == "passive"


_SECURITY_BANNER = (
    "*" * 79 + "\n"
    "!!!WARNING!!!\n"
    "This system is solely for the use of authorized users and only for official\n"
    "purposes. Users must have express written permission to access this system.\n"
    "You have no expectation of privacy in its use and to ensure that the system\n"
    "is functioning properly, individuals using this system are subject to having\n"
    "their activities monitored and recorded at all times. Use of this system\n"
    "evidences an express consent to such monitoring and agreement that if such\n"
    "monitoring reveals evidence of possible abuse or criminal activity, the results\n"
    "of such monitoring will be supplied to the appropriate officials to be\n"
    "prosecuted to the fullest extent of both civil and criminal law.\n\n"
    "Unauthorized Access to this system is a violation of Federal Electronic\n"
    "Communication Privacy Act of 1986, and may be result in fines of $250,000\n"
    "and/or imprisonment (Title 18, USC).  All IP traffic is logged and violators\n"
    "will be prosecuted.\n" + "*" * 79 + "\n\n"
)


def test_boot_watch_no_stuck_while_user_retries_login_behind_banner(spoke, monkeypatch):
    """Real-world regression (BO-SYDm-ACSW01): a device reprints its ~1KB login
    security banner before every retry while a human at the console works
    through bad credentials ("Login incorrect" / "Maximum number of tries
    exceeded (5)"). That's a live, human-driven session (recent keystrokes) —
    never a stuck boot — so it must stay deferred exactly like the synthetic
    actively-typing case."""
    clock = [1_700_100_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    chan.sessions = {"operator-console"}
    chan.last_user_write_at = clock[0]
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.last_user_write_at = clock[0]  # still retrying credentials
    transcript = (
        "BO-SYDm-ACSW01 login: \n" + _SECURITY_BANNER +
        "BO-SYDm-ACSW01 login: ****************\n" + _SECURITY_BANNER[:200] +
        "Login incorrect\nMaximum number of tries exceeded (5)\n\n" +
        _SECURITY_BANNER +
        "BO-SYDm-ACSW01 login: ****************\n" + _SECURITY_BANNER[:150]
    )
    chan.set(transcript)
    _drive_boot(spoke, "good", clock, chan, len(transcript))

    def _boom(*a, **kw):
        raise AssertionError("must not schedule a nudge while a user is typing")
    monkeypatch.setattr(spoke, "_exclusive_probe", _boom)
    monkeypatch.setattr(cs.asyncio, "run_coroutine_threadsafe", _boom)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40
        chan.last_user_write_at = clock[0]
        _drive_boot(spoke, "good", clock, chan, len(transcript) + 1)
        assert spoke._boot_info("good")["state"] == "booting"
    asyncio.run(_run())


def test_boot_watch_user_attaches_during_pending_nudge_not_condemned(spoke, monkeypatch):
    """Race regression: _boot_maybe_confirm_stuck's synchronous check can see
    "no session" and schedule a confirming nudge — then, before that nudge's
    coroutine actually runs/finishes, an operator attaches. The old code let
    _boot_liveness_check treat the now-busy port as a probe error and
    _boot_liveness_apply converted that straight into a false "stuck" verdict
    the instant the operator connected. _boot_liveness_apply must check for an
    attached session itself (the single point that writes a verdict) so the
    race is closed regardless of where in the flow the attach happens."""
    clock = [1_700_300_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Console terminated due to inactivity.\r\n" * 20)
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"

    async def _fake_exclusive_probe(pid, fn, *a):
        # Simulate the operator attaching AND TYPING WHILE the probe is in
        # flight (the narrowest version of the race — attach mid-await, not
        # merely before the coroutine starts). A bare attach with no recent
        # keystroke would no longer be enough to defer here (see
        # test_boot_watch_stuck_when_session_attached_but_idle) — this must
        # reflect genuine activity, not just presence.
        chan.sessions.add("operator")
        chan.last_user_write_at = clock[0]
        return {"responsive": False, "tail": "", "error": "port became busy"}
    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40
        _drive_boot(spoke, "good", clock, chan, 50)
        assert spoke._boot_nudge_at.get("good") == clock[0]
        for _ in range(5):
            await asyncio.sleep(0)
    asyncio.run(_run())

    info = spoke._boot_info("good")
    assert info["state"] == "booting"
    assert "deferring" in info["reason"]


def test_boot_liveness_apply_does_not_discard_a_genuine_booted_result(spoke, monkeypatch):
    """A previous revision's race guard in _boot_liveness_apply intercepted
    EVERY attached session unconditionally, even ahead of the responsive/
    booted check — so a nudge that genuinely proved the device reached a live
    prompt had its positive verdict thrown away and the episode left stuck in
    "booting" forever just because someone happened to attach. The user-active
    defer must only ever suppress a would-be STUCK verdict, never a BOOTED
    one."""
    clock = [1_700_400_000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("Console terminated due to inactivity.\r\n" * 20)
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"

    async def _fake_exclusive_probe(pid, fn, *a):
        # An operator attaches and types WHILE the probe is in flight, AND the
        # probe itself genuinely finds a live prompt.
        chan.sessions.add("operator")
        chan.last_user_write_at = clock[0]
        return {"responsive": True, "tail": "switch> "}
    monkeypatch.setattr(spoke, "_exclusive_probe", _fake_exclusive_probe)

    async def _run():
        spoke._loop = asyncio.get_running_loop()
        clock[0] += 40
        _drive_boot(spoke, "good", clock, chan, 50)
        for _ in range(5):
            await asyncio.sleep(0)
    asyncio.run(_run())

    info = spoke._boot_info("good")
    assert info["state"] == "booted"
    assert info.get("verdict_basis") == "active"


@pytest.mark.parametrize("prompt", ["", "rommon 1 >", "loader>", "=>", "db>"])
def test_boot_fault_never_nudged_or_cleared_by_prompt(spoke, monkeypatch, prompt):
    clock = [2000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")

    def forbidden(*args, **kwargs):
        raise AssertionError("a positive boot fault must not schedule a nudge")
    monkeypatch.setattr(cs.asyncio, "run_coroutine_threadsafe", forbidden)

    async def run():
        spoke._loop = asyncio.get_running_loop()
        _drive_boot(spoke, "good", clock, chan, 0)
        for n in range(1, 4):
            clock[0] += 100
            chan.set("Kernel panic - unable to mount root\r\n" + prompt)
            _drive_boot(spoke, "good", clock, chan, n * 100)
            info = spoke._boot_info("good")
            assert info["state"] == "stuck"
            assert "panic" in info["stuck_reason"].lower()
        assert "good" not in spoke._boot_nudge_at
    asyncio.run(run())


def test_boot_nudge_cooldown_defers_new_episode(spoke, monkeypatch):
    clock = [10000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    calls = []

    async def probe(*args):
        calls.append(clock[0])
        return {"responsive": True, "tail": "switch>"}
    monkeypatch.setattr(spoke, "_exclusive_probe", probe)

    async def run():
        spoke._loop = asyncio.get_running_loop()
        _drive_boot(spoke, "good", clock, chan, 0)
        clock[0] += 100
        chan.set("Console terminated due to inactivity.\r\n")
        _drive_boot(spoke, "good", clock, chan, 50)
        clock[0] += 200
        _drive_boot(spoke, "good", clock, chan, 50)
        for _ in range(5):
            await asyncio.sleep(0)
        assert spoke._boot_info("good")["state"] == "booted"
        first = spoke._boot_nudge_at["good"]
        clock[0] += 100
        _drive_boot(spoke, "good", clock, chan, 100)
        clock[0] += 200
        _drive_boot(spoke, "good", clock, chan, 100)
        info = spoke._boot_info("good")
        assert info["state"] == "stuck"
        assert info.get("verdict_basis") == "passive"
        assert not spoke._boot_nudge_pending
        assert len(calls) == 1
        assert spoke._boot_nudge_at["good"] == first
    asyncio.run(run())


def test_boot_watch_passive_recovery_prompt_not_booted(spoke, monkeypatch):
    clock = [3000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke.config["console_boot_stuck_secs"] = 30
    spoke.config["console_boot_idle_secs"] = 5
    chan = _install_fake_boot_chan(spoke, "good")
    _drive_boot(spoke, "good", clock, chan, 0)
    clock[0] += 100
    chan.set("System Bootstrap\r\nrommon 1 > ")
    _drive_boot(spoke, "good", clock, chan, 50)
    assert spoke._boot_info("good")["state"] == "booting"
    clock[0] += 40
    _drive_boot(spoke, "good", clock, chan, 50)  # no loop -> passive verdict
    assert spoke._boot_info("good")["state"] == "stuck"


@pytest.mark.parametrize("failure", ["open", "raise", "user", "probe"])
def test_boot_nudge_failure_keeps_cooldown_and_resolves(spoke, monkeypatch, failure):
    clock = [10000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    chan = _install_fake_boot_chan(spoke, "good")
    chan.set("Booting...")
    spoke._mon_bytes["good"] = 50
    boot = {"state": "booting", "started_at": 9000.0,
            "last_output_at": 9000.0, "prompt_seen": False}
    spoke._health_rec("good")["boot"] = boot
    calls = []

    async def probe(*args):
        calls.append(1)
        if failure == "raise":
            raise RuntimeError("probe failed")
        return {"error": "open failed", "responsive": False, "tail": ""}
    monkeypatch.setattr(spoke, "_exclusive_probe", probe)

    async def run():
        spoke._loop = asyncio.get_running_loop()
        _drive_boot(spoke, "good", clock, chan, 50)
        assert "good" in spoke._boot_nudge_pending
        if failure == "user":
            # A session ATTACHES and TYPES mid-flight — after
            # _boot_maybe_confirm_stuck's synchronous check already scheduled
            # this nudge. The old race: _boot_liveness_check saw the
            # now-attached session, treated it as "port became busy", and
            # _boot_liveness_apply converted that error straight into a false
            # "stuck" verdict underneath the user the instant they connected.
            # Never condemn here — defer instead (bare attachment with no
            # keystroke would NOT be enough — see the idle-session test).
            chan.sessions.add("operator")
            chan.last_user_write_at = clock[0]
        elif failure == "probe":
            spoke._probing.add("good")
        for _ in range(5):
            await asyncio.sleep(0)
        if failure == "user":
            assert boot["state"] == "booting"
            assert "deferring" in boot["reason"]
        else:
            assert boot["state"] == "stuck"
            assert "unavailable" in boot["reason"]
        assert spoke._boot_nudge_at["good"] == 10000.0
        assert not spoke._boot_nudge_pending
        assert len(calls) == (0 if failure in ("user", "probe") else 1)
        chan.sessions.clear()
        spoke._probing.clear()
        for _ in range(3):
            clock[0] += 30
            _drive_boot(spoke, "good", clock, chan, 50)
            await asyncio.sleep(0)
        assert spoke._boot_nudge_at["good"] == 10000.0
    asyncio.run(run())


@pytest.mark.parametrize("loop_state", ["missing", "stopped", "closed"])
def test_boot_nudge_unavailable_loop_falls_back(spoke, monkeypatch, loop_state):
    loop = None if loop_state == "missing" else asyncio.new_event_loop()
    if loop_state == "closed":
        loop.close()
    spoke._loop = loop
    boot = {"state": "booting"}

    def forbidden(*args, **kwargs):
        raise AssertionError("must not schedule on an unavailable loop")
    monkeypatch.setattr(cs.asyncio, "run_coroutine_threadsafe", forbidden)
    try:
        assert spoke._boot_maybe_confirm_stuck(
            "good", "/dev/ttyUSB0", spoke._boot_cfg(), boot, 10000.0, "timeout")
        assert not spoke._boot_nudge_pending
        assert not spoke._boot_nudge_at
        assert "stuck_reason" not in boot
    finally:
        if loop is not None and not loop.is_closed():
            loop.close()


def test_user_open_cannot_race_pending_nudge(spoke, monkeypatch):
    calls = []
    monkeypatch.setattr(spoke.sessions, "open", lambda *a: calls.append(a) or {})
    spoke._boot_nudge_pending.add("good")
    with pytest.raises(RuntimeError, match="liveness check"):
        spoke._open_user_session("operator", "good", "/dev/ttyUSB0", {}, True)
    assert not calls
    spoke._boot_nudge_pending.clear()
    spoke._open_user_session("operator", "good", "/dev/ttyUSB0", {}, True)
    assert len(calls) == 1


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


def test_boot_verdict_basis_surfaced_and_active_overrides_stale_passive(spoke, monkeypatch):
    """A stuck verdict must say HOW it was reached, and a nudge that actually ran
    must overwrite a 'passive' tag left by an earlier cycle.

    _boot_maybe_confirm_stuck tags a verdict 'passive' whenever it has to fall
    back without nudging (port held, no loop, or cooldown). That tag lives on the
    boot record, so a later episode resolved by a real nudge would keep claiming
    'passive' unless the active path overwrites it — and _boot_info must actually
    project the field, or no caller can ever see it.
    """
    clock = [5000.0]
    monkeypatch.setattr(cs.time, "time", lambda: clock[0])
    spoke._health_rec("good")["boot"] = {
        "state": "booting", "started_at": clock[0] - 100,
        "last_output_at": clock[0] - 100,
        "verdict_basis": "passive",  # stale tag from an earlier, un-nudged cycle
    }
    spoke._boot_liveness_apply("good", "no prompt within boot timeout",
                               {"responsive": True, "tail": "switch> "})
    info = spoke._boot_info("good")
    assert info["state"] == "booted"
    assert info["verdict_basis"] == "active"

    # A probe that could not run at all stays honestly labelled 'passive'.
    spoke._health_rec("good")["boot"] = {
        "state": "booting", "started_at": clock[0] - 100,
        "last_output_at": clock[0] - 100,
    }
    spoke._boot_liveness_apply("good", "no prompt within boot timeout",
                               {"responsive": False, "tail": "", "error": "open failed"})
    info = spoke._boot_info("good")
    assert info["state"] == "stuck"
    assert info["verdict_basis"] == "passive"
