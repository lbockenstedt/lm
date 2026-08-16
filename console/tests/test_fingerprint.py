"""Unit tests for the Console fingerprint engine (pyserial-free)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fingerprint as fp  # noqa: E402


def test_detect_vendor():
    assert fp.detect_vendor("Cisco IOS Software, Version 15.2(4)")["name"] == "cisco-ios"
    assert fp.detect_vendor("ArubaOS-CX GL.10.08")["name"] == "aruba-cx"
    assert fp.detect_vendor("HP ProCurve Switch 2530")["name"] == "hp-procurve"
    assert fp.detect_vendor("Ubuntu 22.04 LTS\r\nhost login: ")["name"] == "linux"
    assert fp.detect_vendor("\xff\xfe random line noise") is None


def test_normalize_mac():
    assert fp.normalize_mac("0011.2233.4455") == "00:11:22:33:44:55"
    assert fp.normalize_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert fp.normalize_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert fp.normalize_mac("nope") == ""


def test_parse_identity_cisco():
    prof = fp.detect_vendor("Cisco IOS")
    outputs = {
        "terminal length 0": "Switch#",
        "show version": ("Cisco IOS Software\r\nProcessor board ID FTX1234ABCD\r\n"
                         "Base ethernet MAC Address : 0011.2233.4455\r\n"
                         "Switch uptime is 5 days\r\nCisco WS-C2960 processor\r\nVersion 15.2(4)E"),
        "show ip interface brief": "Interface   IP-Address\r\nVlan1  192.168.1.10  YES  up  up",
    }
    ident = fp.parse_identity(prof, outputs)
    assert ident["serial"] == "FTX1234ABCD"
    assert ident["mac"] == "00:11:22:33:44:55"
    assert ident["ip"] == "192.168.1.10"
    assert ident["hostname"] == "Switch"


class _FakeChan:
    """Scripted serial: pre-loaded banner + per-command responses keyed by the
    command substring seen in a write()."""
    def __init__(self, banner, responses):
        self.buf = bytearray(banner.encode())
        self.responses = list(responses)

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace")
        for i, (trig, resp) in enumerate(self.responses):
            if trig and trig in s:
                self.buf += resp.encode()
                self.responses[i] = (None, "")
                return


def test_run_identify_cisco_noauth():
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    responses = [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\n"
                         "Base ethernet MAC Address : 0011.2233.4455\r\n"
                         "Switch uptime is 1 day\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1  10.0.0.5  YES  up  up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "cisco-ios"
    assert res["logged_in"] is True
    assert res["identity"]["serial"] == "FTX9XYZ"
    assert res["identity"]["mac"] == "00:11:22:33:44:55"
    assert res["identity"]["ip"] == "10.0.0.5"


class _ConfigChan:
    """Scripted config device: an exec prompt, config-mode prompt, a running-config
    that reflects pushed lines (so post-verify passes/fails deterministically)."""
    def __init__(self, running_has=True):
        self.buf = bytearray(b"\r\nSwitch#")
        self.mode = "exec"
        self.running_has = running_has  # does 'show run' echo the pushed line?
        self.pushed = []

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace").strip()
        if s == "configure terminal":
            self.mode = "config"
            self.buf += b"\r\nSwitch(config)#"
        elif s == "end":
            self.mode = "exec"
            self.buf += b"\r\nSwitch#"
        elif s == "write memory":
            self.buf += b"\r\nBuilding configuration...\r\nOK\r\nSwitch#"
        elif s == "show running-config":
            body = "\r\n".join(self.pushed) if (self.running_has and self.pushed) else "!"
            self.buf += ("\r\n" + body + "\r\nSwitch#").encode()
        elif s in ("terminal length 0", ""):
            self.buf += b"\r\nSwitch#"
        elif self.mode == "config" and s:
            self.pushed.append(s)
            self.buf += b"\r\nSwitch(config)#"
        else:
            self.buf += b"\r\nSwitch#"


def test_push_config_success_saves():
    prof = fp.detect_vendor("Cisco IOS")
    chan = _ConfigChan(running_has=True)
    res = fp.push_config(chan.read, chan.write, prof, [], "hostname CORE-SW\nvlan 10", save=True)
    assert res["status"] == "SUCCESS"
    assert res["verify_ok"] is True
    assert res["saved"] is True
    assert res["rolled_back"] is False


def test_push_config_verify_fail_rolls_back_no_save():
    prof = fp.detect_vendor("Cisco IOS")
    chan = _ConfigChan(running_has=False)  # running-config does NOT reflect pushes
    res = fp.push_config(chan.read, chan.write, prof, [], "hostname CORE-SW", save=True, rollback="negate")
    assert res["status"] == "ERROR"
    assert res["verify_ok"] is False
    assert res["saved"] is False       # never save a failed push
    assert res["rolled_back"] is True
    assert "no hostname CORE-SW" in " ".join(chan.pushed[-3:] + [x for x in chan.pushed])


def test_run_identify_login_then_harvest():
    banner = "\r\nCisco IOS Software\r\nUsername: "
    responses = [
        ("admin", "\r\nPassword: "),
        ("secret", "\r\nSwitch#"),
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID ABC123\r\nSwitch uptime is 2 days\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.9 YES up up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [{"username": "admin", "password": "secret"}])
    assert res["logged_in"] is True
    assert res["credential_index"] == 0
    assert res["identity"]["serial"] == "ABC123"


def test_run_identify_bare_login_prompt_no_banner_until_authenticated():
    """Device shows ONLY a login prompt (no vendor banner) until you log in — the
    generic login-first path must authenticate before vendor detection can work."""
    banner = "\r\nswitch login: "
    responses = [
        ("admin", "\r\nPassword: "),
        ("secret", "\r\nCisco IOS Software, Version 15.2\r\nSwitch#"),
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID XYZ789\r\nSwitch uptime is 3 days\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.7 YES up up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [{"username": "admin", "password": "secret"}])
    assert res["logged_in"] is True
    assert res["vendor"] == "cisco-ios"
    assert res["identity"]["serial"] == "XYZ789"


def test_run_identify_bad_credentials_stops_no_rehammer():
    """Wrong credential → device re-prompts login; we stop after trying each once."""
    class _BadAuthChan:
        def __init__(self):
            self.buf = bytearray(b"\r\ndevice login: ")
            self.state = "login"
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "login" and s.strip():
                self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                self.state = "login"; self.buf += b"\r\nLogin incorrect\r\ndevice login: "
    chan = _BadAuthChan()
    res = fp.run_identify(chan.read, chan.write, [{"username": "x", "password": "y"}])
    assert res["logged_in"] is False
    assert res["identity"] == {}


# ── passive_identify: glean identity from PASSIVELY captured text (no login) ──
def test_passive_identify_cisco_show_version_scrolled_by():
    text = (
        "Cisco IOS Software, C2960 Software\r\n"
        "cisco WS-C2960-24TT-L (PowerPC405) processor\r\n"
        "Processor board ID FOC1234X56Y\r\n"
        "Base ethernet MAC Address       : 00:1a:2b:3c:4d:5e\r\n"
        "Switch#"
    )
    res = fp.passive_identify(text)
    assert res["vendor"] == "cisco-ios"
    assert res["identity"]["serial"] == "FOC1234X56Y"
    assert res["identity"]["model"] == "WS-C2960-24TT-L"
    assert res["identity"]["mac"] == "00:1a:2b:3c:4d:5e"
    assert res["identity"]["hostname"] == "Switch"  # from the prompt


def test_passive_identify_bare_prompt_gives_hostname_only():
    res = fp.passive_identify("\r\nBranch-RTR> ")
    assert res["vendor"] is None
    assert res["identity"] == {"hostname": "Branch-RTR"}


def test_passive_identify_linux_prompt_no_false_serial():
    # The linux profile's bare ^(\S+)$ field regexes must NOT be applied to
    # arbitrary scrollback (that produced a bogus serial). Only a hostname from
    # the shell prompt is safe.
    res = fp.passive_identify("\r\nubuntu-box login: \r\nadmin@ubuntu-box:~$ ")
    assert res["vendor"] == "linux"
    assert "serial" not in res["identity"]
    assert res["identity"].get("hostname") == "ubuntu-box"


def test_passive_identify_empty_and_noise():
    assert fp.passive_identify("") == {"vendor": None, "identity": {}}
    assert fp.passive_identify("random syslog line, nothing useful\r\n") == {"vendor": None, "identity": {}}


# ── read-only command allowlist (safety gate for LLM-suggested commands) ─────
def test_is_readonly_command_allows_read_verbs_and_pagers():
    ok = [
        "show version", "show running-config", "show configuration",
        "display version", "get system status", "cat /proc/cpuinfo",
        "uname -a", "hostname", "ls /etc", "terminal length 0",
        "screen-length 0 temporary", "set cli screen-length 0", "no page",
    ]
    for c in ok:
        assert fp.is_readonly_command(c) is True, c


def test_is_readonly_command_rejects_mutations_and_chaining():
    bad = [
        "", "   ", "configure terminal", "conf t", "write memory",
        "erase startup-config", "reload", "delete flash:", "clear counters",
        "copy run start", "set hostname X", "no shutdown", "reboot",
        "rm -rf /", "shutdown -h now", "request system reboot",
        "show run; reload", "show run | delete", "show ver && reboot",
        "cat x > y", "show run`reboot`", "ping 8.8.8.8", "ssh host",
        "enable", "sudo cat /etc/shadow",
    ]
    for c in bad:
        assert fp.is_readonly_command(c) is False, c


class _CmdChan:
    """Login-prompt device that answers a fixed set of commands post-login."""
    def __init__(self):
        self.buf = bytearray(b"\r\nbox login: ")
        self.state = "login"
    def read(self):
        out = bytes(self.buf[:256]); del self.buf[:256]; return out
    def write(self, b):
        s = b.decode(errors="replace")
        if self.state == "login" and s.strip():
            self.state = "password"; self.buf += b"\r\nPassword: "
        elif self.state == "password" and s.strip():
            self.state = "shell"; self.buf += b"\r\nbox#"
        elif "show version" in s:
            self.buf += b"\r\nVendorOS v9.9 serial ZZ42\r\nbox#"
        elif s.strip():
            self.buf += b"\r\nbox#"


def test_run_commands_logs_in_and_runs_only_allowlisted():
    chan = _CmdChan()
    res = fp.run_commands(chan.read, chan.write, [{"username": "a", "password": "b"}],
                          ["show version", "reload", "configure terminal"])
    assert res["logged_in"] is True
    assert "show version" in res["outputs"]
    assert "ZZ42" in res["outputs"]["show version"]
    assert "reload" in res["rejected"] and "configure terminal" in res["rejected"]


def test_run_commands_no_auth_sends_nothing():
    class _StuckLogin:
        def __init__(self): self.buf = bytearray(b"\r\nbox login: "); self.sent = []
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            self.sent.append(s)
            if s.strip():
                self.buf += b"\r\nLogin incorrect\r\nbox login: "
    chan = _StuckLogin()
    res = fp.run_commands(chan.read, chan.write, [{"username": "x", "password": "y"}],
                          ["show version"])
    assert res["logged_in"] is False
    assert res["outputs"] == {}
    assert "show version" not in " ".join(chan.sent)


# ── login telemetry (diag) for troubleshooting ──────────────────────────────
def test_run_identify_diag_silent_device():
    class _Silent:
        def read(self): return b""
        def write(self, b): pass
    ch = _Silent()
    res = fp.run_identify(ch.read, ch.write, [{"username": "a", "password": "b"}])
    d = res["diag"]
    assert d["any_output"] is False
    assert d["login_prompt_seen"] is False
    assert "no output" in d["reason"]


def test_run_identify_diag_login_prompt_no_creds():
    chan = _FakeChan("\r\nswitch login: ", [])
    res = fp.run_identify(chan.read, chan.write, [])   # no credentials
    d = res["diag"]
    assert d["login_prompt_seen"] is True
    assert d["creds_available"] == 0
    assert "no stored credentials" in d["reason"]


def test_run_identify_diag_auth_rejected():
    class _BadAuth:
        def __init__(self): self.buf = bytearray(b"\r\ndev login: "); self.state = "login"
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "login" and s.strip():
                self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                self.state = "login"; self.buf += b"\r\nLogin incorrect\r\ndev login: "
    ch = _BadAuth()
    res = fp.run_identify(ch.read, ch.write, [{"username": "x", "password": "y"}])
    d = res["diag"]
    assert d["login_prompt_seen"] and d["password_prompt_seen"]
    assert d["creds_tried"] == 1
    assert "rejected" in d["reason"]
    assert d["tail"]  # a printable tail is captured for troubleshooting
