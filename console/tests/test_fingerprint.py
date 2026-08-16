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


def test_detect_vendor_arubaos_switch():
    # ArubaOS-Switch (AOS-S) full-screen menu CLI: identifiable by its prompt and
    # its "Invalid input:" rejection of non-show commands, even through VT100 noise.
    assert fp.detect_vendor("MIA-SW-AOSS> ")["name"] == "hp-procurve"
    assert fp.detect_vendor("switch> \r\nInvalid input: get")["name"] == "hp-procurve"
    escaped = "\x1b[24;1H\x1b[24;14HMIA-SW-AOSS> \x1b[?25h\x1b[1;24rInvalid input: get"
    assert fp.detect_vendor(escaped)["name"] == "hp-procurve"


def test_sanitize_console_text_strips_vt100():
    escaped = ("\x1b[24;1H\x1b[24;14HMIA-SW-AOSS> \x1b[?25h\x1b[1;24r"
               "Invalid input: get\x1b[2K\x1b]0;title\x07\r\nMIA-SW-AOSS>")
    clean = fp.sanitize_console_text(escaped)
    assert "\x1b" not in clean
    assert "[24;1H" not in clean and "[?25h" not in clean and "[1;24r" not in clean
    assert "MIA-SW-AOSS>" in clean and "Invalid input: get" in clean
    assert fp.sanitize_console_text("") == ""


def test_prompt_hostname():
    # ArubaOS-Switch CLI prompt through VT100 noise → the switch hostname.
    assert fp.prompt_hostname("\x1b[24;1HMIA-SW-AOSS> ") == "MIA-SW-AOSS"
    assert fp.prompt_hostname("Switch1#\r\n") == "Switch1"
    assert fp.prompt_hostname("admin@edge-1:~$ ") == "edge-1"
    # last prompt wins when several are present
    assert fp.prompt_hostname("old>\r\nnew> ") == "new"
    # login/password prompts are not hostnames
    assert fp.prompt_hostname("Switch login: ") == ""
    assert fp.prompt_hostname("") == ""


def test_run_identify_arubaos_switch_prompt_hostname():
    # AOS-S rejects the profile's identity commands ("Invalid input"), so the
    # hostname must come from the device's own CLI prompt.
    lines = iter([
        b"\r\nMIA-SW-AOSS> ",           # nudge → prompt (vendor detected here)
        b"Invalid input: no page\r\nMIA-SW-AOSS> ",
        b"Invalid input: show\r\nMIA-SW-AOSS> ",
    ])

    def _read():
        try:
            return next(lines)
        except StopIteration:
            return b""

    res = fp.run_identify(_read, lambda b: None, [])
    assert res["vendor"] == "hp-procurve"
    assert res["identity"].get("hostname") == "MIA-SW-AOSS"


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


def test_generic_login_nudges_wake_silent_prompt():
    """A device that stays silent until it receives a CR should be woken by the
    Enter nudges and reveal its login prompt."""
    class _NudgeWake:
        def __init__(self): self.buf = bytearray(); self.crs = 0
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            if b"\r" in b:
                self.crs += 1
                if self.crs >= 2:              # silent on the first CRLF, wakes on the next CR
                    self.buf += b"\r\nswitch login: "
    ch = _NudgeWake()
    res = fp.run_identify(ch.read, ch.write, [])
    d = res["diag"]
    assert d["nudges"] >= 1
    assert d["login_prompt_seen"] is True


def test_merge_credentials_dedupes_preserving_order():
    a = [{"username": "op", "password": "p"}]
    b = [{"username": "op", "password": "p"}, {"username": "admin", "password": "admin"}]
    out = fp.merge_credentials(a, b)
    assert out == [{"username": "op", "password": "p"},
                   {"username": "admin", "password": "admin"}]


def test_factory_default_login_when_no_stored_creds():
    """With no operator creds, a factory-default pair (admin/admin) should log in
    once callers append FACTORY_DEFAULT_CREDENTIALS."""
    class _FactoryAuth:
        def __init__(self): self.buf = bytearray(b"\r\ndev login: "); self.state = "login"
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "login" and s.strip():
                self.user = s.strip(); self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                if getattr(self, "user", "") == "admin" and s.strip() == "admin":
                    self.state = "done"; self.buf += b"\r\ndev> "
                else:
                    self.state = "login"; self.buf += b"\r\nLogin incorrect\r\ndev login: "
    ch = _FactoryAuth()
    creds = fp.merge_credentials([], fp.FACTORY_DEFAULT_CREDENTIALS)
    res = fp.run_identify(ch.read, ch.write, creds)
    assert res["logged_in"] is True


class _RepeatChan:
    """Scripted serial whose command responses are REPEATABLE (a trigger can fire
    more than once) — needed when discovery and the profile command loop both
    send the same command (e.g. 'show version')."""
    def __init__(self, banner, responses):
        self.buf = bytearray(banner.encode())
        self.responses = list(responses)

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        s = b.decode(errors="replace")
        for trig, resp in self.responses:
            if trig and trig in s:
                self.buf += resp.encode()
                return


def test_run_identify_direct_console_discovery():
    """Live console, no login prompt, unrecognized prompt: discovery commands must
    coax out an identifying banner so the device is identified without auth."""
    banner = "\r\nmyconsole> "          # responsive, but no vendor cue and no login
    cisco = ("\r\nCisco IOS Software, Version 15.2(4)E\r\n"
             "Processor board ID FTXDIRECT1\r\n"
             "Base ethernet MAC Address : 0011.2233.4455\r\nSwitch#")
    responses = [
        ("show version", cisco),
        ("terminal length 0", "\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.42 YES up up\r\nSwitch#"),
    ]
    chan = _RepeatChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "cisco-ios"
    assert res["logged_in"] is True
    assert res["diag"].get("console_usable") is True
    assert "show version" in res["diag"].get("discovery_cmds", [])
    assert res["identity"]["serial"] == "FTXDIRECT1"


def test_read_command_output_advances_pager():
    """A --More-- pager is auto-advanced by sending space so the full output is
    captured, not just the first screen."""
    class _PagerChan:
        def __init__(self):
            self.buf = bytearray(b"line1\r\n --More-- ")
            self.stage = 0

        def read(self):
            out = bytes(self.buf[:256])
            del self.buf[:256]
            return out

        def write(self, b):
            if b == b" " and self.stage == 0:      # space advances the pager
                self.stage = 1
                self.buf += b"line2\r\nSwitch#"

    chan = _PagerChan()
    out = fp._read_command_output(chan.read, chan.write, [fp._SHELL_PROMPT], 1.0)
    assert "line1" in out and "line2" in out
    assert "More" not in out.split("line2")[-1]     # pager consumed, real prompt reached
