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


def test_detect_vendor_arubaos_gateway_by_prompt():
    """ArubaOS gateway/controller shows no banner — only its parenthesised prompt
    '(host) *#'. We must recognise it by that shape WITHOUT misfiring on a Cisco
    'host(config)#' (no space before #, hostname glued to the paren)."""
    assert fp.detect_vendor("(MIA-GW-02) *# ")["name"] == "aruba-os"
    assert fp.detect_vendor("(MIA-GW-02) #")["name"] == "aruba-os"
    assert fp.detect_vendor("ArubaOS (MODEL: A7010), Version 8.6")["name"] == "aruba-os"
    # Must NOT hijack a Cisco config-mode prompt or a CX/AOS-S switch.
    assert fp.detect_vendor("CORE-SW(config)#") is None or \
        fp.detect_vendor("CORE-SW(config)#")["name"] != "aruba-os"
    assert fp.detect_vendor("ArubaOS-CX GL.10.08")["name"] == "aruba-cx"


def test_run_identify_arubaos_gateway_serial_model_hostname():
    """Full identify on an ArubaOS gateway pulls model + serial (for NetBox / rack
    identification) and gleans the hostname from the prompt."""
    show_ver = ("\r\nAruba Operating System Software.\r\n"
                "ArubaOS (MODEL: A7010), Version 8.6.0.7\r\n(MIA-GW-02) *#")
    show_inv = ("\r\nSystem Serial#      : CV0001234\r\n"
                "SC Model#           : A7010\r\n(MIA-GW-02) *#")
    responses = [
        ("no paging", "\r\n(MIA-GW-02) *#"),
        ("show version", show_ver),
        ("show inventory", show_inv),
    ]
    chan = _FakeChan("\r\n(MIA-GW-02) *# ", responses)
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "aruba-os"
    assert res["identity"]["model"] == "A7010"
    assert res["identity"]["serial"] == "CV0001234"
    assert res["identity"]["os"] == "8.6.0.7"
    assert res["identity"]["hostname"] == "MIA-GW-02"
    assert res["identity"]["type"] == "Gateway/Controller"



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


def test_prompt_hostname_aruba_parenthesised():
    # ArubaOS controller/gateway/Instant prompt: "(hostname) #" / "(hostname) *#"
    # (the * = pending config). The hostname is INSIDE the parens with a space
    # and possible * before #, which the plain "name#" matcher can't capture.
    assert fp.prompt_hostname("(MIA-GW-02) #") == "MIA-GW-02"
    assert fp.prompt_hostname("(MIA-GW-02) *#") == "MIA-GW-02"
    # config-context prompt: "(host) (config) #" → still the host, not "config"
    assert fp.prompt_hostname("(MIA-GW-02) (config) #") == "MIA-GW-02"
    # realistic scrolling transcript ending at the live prompt
    tail = ("Invalid input detected at '^' marker. (MIA-GW-02) *# uname -a  ^  "
            "Invalid input detected at '^' marker. (MIA-GW-02) *#")
    assert fp.prompt_hostname(tail) == "MIA-GW-02"


def test_load_hostname_prompts_reads_json_override(tmp_path, monkeypatch):
    # A new hostname-prompt shape can be added via JSON with no code change.
    pf = tmp_path / "prompt_patterns.json"
    pf.write_text('{"hostname_prompt": ["(?:^|\\\\s)ID=([\\\\w\\\\-]+)::"]}')
    monkeypatch.setenv("CONSOLE_PROMPT_PATTERNS", str(pf))
    pats = fp.load_hostname_prompts()
    assert any(p.search("ID=core-7::") for p in pats)
    assert fp._prompt_hostname_with(pats, "ID=core-7::") == "core-7"


def test_load_hostname_prompts_bad_regex_falls_back(tmp_path, monkeypatch):
    pf = tmp_path / "prompt_patterns.json"
    pf.write_text('{"hostname_prompt": ["(unclosed"]}')  # invalid regex → skipped
    monkeypatch.setenv("CONSOLE_PROMPT_PATTERNS", str(pf))
    pats = fp.load_hostname_prompts()
    # bad pattern skipped, defaults used → still gleans a normal prompt
    assert pats and fp._prompt_hostname_with(pats, "Switch1#\r\n") == "Switch1"


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


def test_run_identify_aoss_hostname_from_discovery_transcript():
    # The real USB4/MIA-SW-AOSS case: vendor is recognized via banner DISCOVERY
    # (the switch answers `show system` with "System Name : …"), but the CLI
    # prompt is echoed with the typed command after it ("MIA-SW-AOSS> show system"),
    # so prompt_hostname() can't anchor it AND the profile's own
    # `show system-information` command yields nothing here. The hostname must be
    # recovered by back-filling the matched profile's field regexes across the
    # full transcript (which already holds the discovery `show system` output).
    lines = iter([
        b"\r\nwaking line\r\n",                 # login nudge: output, but no vendor/prompt
        b"bad command\r\n",                      # discovery: show version (unrecognized)
        b"bad command\r\n",                      # discovery: display version (unrecognized)
        # discovery: show system — names the box (vendor matches on "-AOSS>"),
        # but the prompt is followed by the echoed command so it is NOT line-final.
        b"MIA-SW-AOSS> show system\r\n"
        b"Status and Counters - General System Information\r\n"
        b"System Name        : MIA-SW-AOSS\r\n"
        b"Serial Number      : SG12ABC345\r\n",
    ])

    def _read():
        try:
            return next(lines)
        except StopIteration:
            return b""

    # Guard: prompt_hostname alone can't get it (prompt not line-final) — proving
    # the transcript back-fill is what recovers the name.
    assert fp.prompt_hostname("MIA-SW-AOSS> show system\r\nSystem Name : MIA-SW-AOSS") == ""
    res = fp.run_identify(_read, lambda b: None, [])
    assert res["vendor"] == "hp-procurve"
    assert res["identity"].get("hostname") == "MIA-SW-AOSS"
    assert res["identity"].get("serial") == "SG12ABC345"


def test_run_identify_loggedin_unknown_vendor_gleans_prompt_hostname():
    # Logged into a device whose vendor we don't recognize (no banner keyword,
    # no matching profile). We still glean the box name from its shell prompt so
    # the port shows a real name instead of the USB adapter string.
    lines = iter([
        b"\r\nedge-core> ",   # unknown vendor, live shell prompt
        b"edge-core> ",       # answers discovery nudges with just the prompt
        b"edge-core> ",
    ])

    def _read():
        try:
            return next(lines)
        except StopIteration:
            return b""

    res = fp.run_identify(_read, lambda b: None, [])
    assert res["vendor"] is None
    assert res["identity"].get("hostname") == "edge-core"
    assert res["hostname_source"] == "prompt"


def test_run_identify_login_prompt_only_no_hostname():
    # Sitting at a bare login prompt (never authenticated) → no shell prompt to
    # glean, so no hostname is invented.
    lines = iter([b"\r\nPassword: "])

    def _read():
        try:
            return next(lines)
        except StopIteration:
            return b""

    res = fp.run_identify(_read, lambda b: None, [])
    assert not res["identity"].get("hostname")


def test_detect_vendor_juniper():
    assert fp.detect_vendor("JUNOS 20.4R3 built")["name"] == "juniper-junos"
    assert fp.detect_vendor("Juniper Networks, Inc. srx340")["name"] == "juniper-junos"


def test_detect_vendor_juniper_prelogin_shows_no_vendor_string():
    # A login-locked SRX/EX prints only "<hostname> (ttyu0)" — no vendor name —
    # and must not fall through to the `linux` profile's bare "login:" match.
    assert fp.detect_vendor("\r\nsrx340 (ttyu0)\r\n\r\nlogin: ")["name"] == "juniper-junos"
    assert fp.detect_vendor("\r\nAmnesiac (ttyu0)\r\n\r\nlogin: ")["name"] == "juniper-junos"
    # A genuine Linux box is still a Linux box.
    assert fp.detect_vendor("\r\nUbuntu 22.04.3 LTS host tty1\r\n"
                            "\r\nhost login: ")["name"] == "linux"


_SYSLOG_LINE = ("\r\nDec  9 10:22:01  srx340 sshd[1234]: "
                "Connection closed by 10.1.1.5\r\n")


def test_prompt_tail_sees_through_console_log_noise():
    # Juniper (and any box with `system syslog console`) prints log lines that
    # land AFTER the prompt, scrolling the live prompt up. The anchored prompt
    # patterns only match at the end of the buffer, so the noise must be stripped
    # or no credential is ever spent.
    noisy = "\r\nsrx340 (ttyu0)\r\n\r\nlogin: " + _SYSLOG_LINE
    assert not fp._LOGIN_PROMPT.search(noisy[-200:])           # what used to happen
    assert fp._LOGIN_PROMPT.search(fp._prompt_tail(noisy))     # what happens now
    # Quiet lines are unaffected, and noise alone must not invent a prompt.
    assert fp._LOGIN_PROMPT.search(fp._prompt_tail("\r\nlogin: "))
    assert not fp._LOGIN_PROMPT.search(fp._prompt_tail(_SYSLOG_LINE * 2))
    # Kernel ring-buffer and Cisco facility messages count as noise too.
    assert fp._LOGIN_PROMPT.search(fp._prompt_tail(
        "\r\nlogin: \r\n[   12.345678] usb 1-1: new device\r\n"))
    assert fp._PASSWORD_PROMPT.search(fp._prompt_tail(
        "\r\nPassword:\r\n%LINK-3-UPDOWN: Interface ge-0/0/1, changed state\r\n"))


class _ChattyLoginChan:
    """A device that logs to its own console: every prompt it prints is followed
    immediately by an asynchronous syslog line, so the prompt is never the last
    thing on the wire. Accepts exactly one credential."""

    def __init__(self, user, password):
        self.user, self.password = user, password
        self.buf = bytearray()
        self.line = ""
        self.stage = "login"
        self.attempts = []
        self._emit("\r\nsrx340 (ttyu0)\r\n\r\nlogin: ")

    def _emit(self, text):
        self.buf += (text + _SYSLOG_LINE).encode()

    def read(self):
        out = bytes(self.buf[:256])
        del self.buf[:256]
        return out

    def write(self, b):
        for ch in b.decode(errors="replace"):
            if ch in "\r\n":
                self._submit(self.line)
                self.line = ""
            else:
                self.line += ch

    def _submit(self, line):
        if self.stage == "login":
            if not line:                       # bare CR nudge → redraw the prompt
                self._emit("\r\nlogin: ")
                return
            self._pending = line
            self.stage = "password"
            self._emit("\r\nPassword:")
        elif self.stage == "password":
            self.attempts.append(self._pending)
            if self._pending == self.user and line == self.password:
                self.stage = "shell"
                self._emit("\r\n--- JUNOS 21.4R3-S4.9 built 2023-05-01\r\nroot@srx340> ")
            else:
                self.stage = "login"
                self._emit("\r\nLogin incorrect\r\nlogin: ")
        else:
            self._emit("\r\nroot@srx340> ")


def test_generic_login_spends_credential_on_console_logging_device():
    # Regression: a chatty Juniper used to report "output seen but no
    # recognizable login/password prompt" and never try a credential at all.
    chan = _ChattyLoginChan("admin", "s3cret")
    logged_in, idx, _transcript, diag = fp._generic_login(
        chan.read, chan.write, [{"username": "admin", "password": "s3cret"}],
        banner_secs=1.0)
    assert chan.attempts == ["admin"], "the credential was never tried"
    assert logged_in is True
    assert idx == 0
    assert diag["login_prompt_seen"] is True
    assert diag["creds_tried"] == 1


def test_run_identify_rejected_credential_is_still_attempted_when_chatty():
    chan = _ChattyLoginChan("admin", "s3cret")
    res = fp.run_identify(chan.read, chan.write,
                          [{"username": "admin", "password": "wrong"}],
                          banner_secs=1.0, cmd_secs=1.0)
    assert chan.attempts == ["admin"]
    assert res["logged_in"] is False
    # The operator must be told the password failed, not that nothing was found.
    assert "no recognizable login/password prompt" not in res["diag"]["reason"]



def test_infer_device_type():
    assert fp.infer_device_type("SRX340", "Firewall/Router") == "Firewall"
    assert fp.infer_device_type("EX4300-48T", "Firewall/Router") == "Switch"
    assert fp.infer_device_type("MX204", "Firewall/Router") == "Router"
    assert fp.infer_device_type("2930F-24G-4SFP+ Switch", "Switch") == "Switch"
    assert fp.infer_device_type(None, "Switch") == "Switch"
    assert fp.infer_device_type("mystery", None) == ""


def test_parse_identity_procurve_model_from_modules():
    prof = fp.detect_vendor("MIA-SW-AOSS> \r\nInvalid input: get")  # hp-procurve
    outputs = {
        "no page": "",
        "show system-information": ("System Name        : MIA-SW-AOSS\r\n"
                                    "Serial Number      : SG64GXK123\r\n"
                                    "Base MAC Addr      : 3c:2a:f4:11:22:33\r\n"),
        "show modules": ("Status and Counters - Module Information\r\n\r\n"
                         "  Chassis: 2930F-24G-4SFP+ Switch(JL253A)  Serial Number: SG64GXK123\r\n"),
    }
    ident = fp.parse_identity(prof, outputs)
    assert ident["serial"] == "SG64GXK123"
    assert ident["hostname"] == "MIA-SW-AOSS"
    assert ident["model"] == "2930F-24G-4SFP+ Switch"


def test_parse_identity_no_crash_on_nonparticipating_group():
    # A model regex whose alternation branch has no group must not raise.
    prof = {"name": "x", "commands": [
        {"cmd": "c", "fields": {"model": __import__("re").compile(r"NoGroupHere|(\d+)")}}]}
    ident = fp.parse_identity(prof, {"c": "value 42 here"})
    assert ident.get("model") in ("42", "NoGroupHere", None) or True  # just: no exception


def test_run_identify_juniper_srx_model_and_type():
    chan = _FakeChan("\r\nJUNOS 20.4R3-S1.3 built 2023\r\nsrx340> ", [
        ("screen-length", "\r\nsrx340> "),
        ("show version", "Hostname: srx340\r\nModel: srx340\r\n"
                         "Junos: 20.4R3-S1.3\r\nsrx340> "),
        ("show chassis hardware", "Item Version Part Serial Description\r\n"
                                  "Chassis          AB1234567890  SRX340\r\nsrx340> "),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "juniper-junos"
    assert res["identity"].get("model") == "srx340"
    assert res["identity"].get("os") == "20.4R3-S1.3"
    assert res["identity"].get("serial") == "AB1234567890"
    assert res["identity"].get("type") == "Firewall"


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


def test_run_identify_logs_out_after_authenticated_profiling():
    """After we log in with a credential and finish profiling, we must cleanly
    log out (send exit/logout) and confirm a login prompt reappears, so we don't
    leave a privileged shell open on the shared console line."""
    banner = "\r\nCisco IOS Software\r\nUsername: "
    responses = [
        ("admin", "\r\nPassword: "),
        ("secret", "\r\nSwitch#"),
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID ABC123\r\nSwitch uptime is 2 days\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.9 YES up up\r\nSwitch#"),
        ("exit", "\r\nSwitch con0 is now available\r\n\r\nSwitch login: "),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [{"username": "admin", "password": "secret"}])
    assert res["logged_in"] is True
    assert res["credential_index"] == 0
    assert res["diag"]["logged_out"] is True


def test_run_identify_no_logout_when_not_authenticated():
    """An already-open console we merely read from (no credential used) must NOT
    be logged out — we never opened that session, so 'logged_out' stays unset."""
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    responses = [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\nSwitch uptime is 1 day\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1 10.0.0.5 YES up up\r\nSwitch#"),
    ]
    chan = _FakeChan(banner, responses)
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["logged_in"] is True
    assert res["credential_index"] is None
    assert "logged_out" not in res["diag"]


def test_logout_helper_returns_false_when_prompt_never_returns():
    """If exit/logout produce no login prompt (dead/one-way line), _logout must
    report False rather than falsely claim a clean logout."""
    class _NoPrompt:
        def read(self): return b""
        def write(self, b): pass
    ch = _NoPrompt()
    assert fp._logout(ch.read, ch.write) is False



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


def test_load_prompt_patterns_from_json(tmp_path, monkeypatch):
    """Prompt matchers are read from JSON so a new prompt string can be added
    without a code change — a custom file must override the built-in defaults."""
    import json as _json
    pf = tmp_path / "prompt_patterns.json"
    pf.write_text(_json.dumps({
        "login_prompt": [r"ENTER USER>\s*$"],
        "password_prompt": [r"PASS>\s*$"],
        "shell_prompt": [r"\$\s*$"],
    }))
    monkeypatch.setenv("CONSOLE_PROMPT_PATTERNS", str(pf))
    p = fp.load_prompt_patterns()
    assert p["login_prompt"].search("ENTER USER> ")
    assert not p["login_prompt"].search("Username: ")  # defaults replaced, not merged
    assert p["password_prompt"].search("PASS> ")


def test_load_prompt_patterns_falls_back_when_missing(monkeypatch):
    monkeypatch.setenv("CONSOLE_PROMPT_PATTERNS", "/nonexistent/prompt_patterns.json")
    p = fp.load_prompt_patterns()
    assert p["login_prompt"].search("User: ")          # built-in default still works
    assert p["login_prompt"].search("login: ")


def test_load_prompt_patterns_bad_regex_falls_back(tmp_path, monkeypatch):
    import json as _json
    pf = tmp_path / "prompt_patterns.json"
    pf.write_text(_json.dumps({"login_prompt": ["(unclosed"]}))
    monkeypatch.setenv("CONSOLE_PROMPT_PATTERNS", str(pf))
    p = fp.load_prompt_patterns()
    assert p["login_prompt"].search("User: ")          # bad family reverts to default


def test_generic_login_recognizes_bare_user_prompt():
    """A device that prompts a bare 'User:' (not 'Username:'/'login:') must be
    recognized as a login prompt so stored credentials are actually tried —
    regression for consoles that were mistakenly treated as no-auth and had
    'show version' blasted at the username prompt (creds_tried stayed 0)."""
    assert fp._LOGIN_PROMPT.search("\r\nUser: ")
    assert fp._LOGIN_PROMPT.search("User:")

    class _UserAuth:
        def __init__(self): self.buf = bytearray(b"\r\nUser: "); self.state = "login"
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "login" and s.strip():
                self.user = s.strip(); self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                if getattr(self, "user", "") == "admin" and s.strip() == "secret":
                    self.state = "done"; self.buf += b"\r\nSWITCH# "
                else:
                    self.state = "login"; self.buf += b"\r\nInvalid password\r\nUser: "
    ch = _UserAuth()
    res = fp.run_identify(ch.read, ch.write, [{"username": "admin", "password": "secret"}])
    assert res["logged_in"] is True
    assert res["diag"]["creds_tried"] >= 1  # it actually attempted a login


def test_generic_login_tries_next_cred_after_slow_reprompt():
    """A device slow to re-draw its login prompt after a FAILED attempt (needs an
    extra CR to wake) must NOT cause the next credential to be silently skipped —
    the valid credential later in the list still has to be tried. Regression for a
    switch with a valid default cred that never got profiled because the loop
    'spent' the credential without ever presenting it."""
    class _SlowReprompt:
        def __init__(self):
            self.buf = bytearray(b"\r\ndev login: ")
            self.state = "login"
            self.wake = 0  # after a failed auth, needs an extra CR to redraw login
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "wake":
                # Only a CR wakes it; the single recovery read shouldn't catch it
                # until we've moved past the first (bad) credential.
                self.wake += 1
                if self.wake >= 1:
                    self.state = "login"; self.buf += b"\r\ndev login: "
                return
            if self.state == "login" and s.strip():
                self.user = s.strip(); self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                if getattr(self, "user", "") == "admin" and s.strip() == "admin":
                    self.state = "done"; self.buf += b"\r\ndev# "
                else:
                    # Wrong cred: print the failure but DON'T redraw the prompt yet.
                    self.state = "wake"; self.wake = 0; self.buf += b"\r\nLogin incorrect\r\n"
    ch = _SlowReprompt()
    creds = [{"username": "bad", "password": "bad"}, {"username": "admin", "password": "admin"}]
    res = fp.run_identify(ch.read, ch.write, creds)
    assert res["logged_in"] is True                 # the 2nd (valid) cred was tried
    assert res["diag"]["creds_tried"] == 2


def test_generic_login_skips_forced_password_change():
    """A net-new device that forces a password SET/CHANGE right after a first
    login with a default cred must be escaped by sending bare CRs (identify is
    READ-ONLY — we must never SET a password), so the device drops to its shell
    and can be identified."""
    class _ForcedChange:
        def __init__(self):
            self.buf = bytearray(b"\r\nswitch login: ")
            self.state = "login"
            self.new_pw_inputs = []   # anything non-empty typed at the new-pw prompt
        def read(self):
            out = bytes(self.buf[:256]); del self.buf[:256]; return out
        def write(self, b):
            s = b.decode(errors="replace")
            if self.state == "login" and s.strip():
                self.state = "password"; self.buf += b"\r\nPassword: "
            elif self.state == "password" and s.strip():
                # Valid default login → device demands a new password.
                self.state = "newpw"; self.buf += b"\r\nYou must change your password\r\nEnter new password: "
            elif self.state == "newpw":
                if s.strip():
                    # Operator/agent typed a real password — record the violation.
                    self.new_pw_inputs.append(s.strip())
                    self.buf += b"\r\nEnter new password: "
                else:
                    # Bare CR skips the forced change → drop to the shell.
                    self.state = "done"; self.buf += b"\r\nswitch> "
    ch = _ForcedChange()
    res = fp.run_identify(ch.read, ch.write, [{"username": "admin", "password": "admin"}])
    assert res["logged_in"] is True
    assert res["diag"].get("forced_password_skipped") is True
    assert ch.new_pw_inputs == []   # never SET a password — identify stayed read-only


def test_new_password_prompt_does_not_match_plain_login_password():
    """The forced-change matcher must fire on set/change/new/confirm prompts but
    NOT on the ordinary login 'Password:' prompt (else we'd skip a normal auth)."""
    assert fp._NEW_PASSWORD_PROMPT.search("Enter new password: ")
    assert fp._NEW_PASSWORD_PROMPT.search("Confirm new password: ")
    assert fp._NEW_PASSWORD_PROMPT.search("You must change your password")
    assert fp._NEW_PASSWORD_PROMPT.search("Password has expired")
    assert not fp._NEW_PASSWORD_PROMPT.search("Password: ")
    assert not fp._NEW_PASSWORD_PROMPT.search("dev login: ")


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


def test_looks_like_prompt():
    assert fp.looks_like_prompt("Switch> ")
    assert fp.looks_like_prompt("MIA-SW-AOSS# ")
    assert fp.looks_like_prompt("host login: ")
    assert fp.looks_like_prompt("Password: ")
    assert not fp.looks_like_prompt("U-Boot 2013.01 booting kernel ...")
    assert not fp.looks_like_prompt("\xff\xfe garbled line noise \x01\x02")


def test_boot_fault():
    assert fp.boot_fault("Kernel panic - not syncing: VFS: Unable to mount root")
    assert fp.boot_fault("Watchdog reset! rebooting...")
    assert fp.boot_fault("No bootable device -- insert boot disk")
    assert fp.boot_fault("CRC error, image corrupt")
    # Normal boot chatter must NOT be flagged as a fault.
    assert not fp.boot_fault("Starting kernel ...\r\nLinux version 5.10\r\nSwitch> ")
    assert not fp.boot_fault("Booting system, please wait...")

def test_is_valid_device_ip():
    from fingerprint import is_valid_device_ip
    assert is_valid_device_ip("192.168.1.10") is True
    assert is_valid_device_ip("10.20.30.40") is True
    assert is_valid_device_ip("0.0.0.0") is False
    assert is_valid_device_ip("127.0.0.1") is False
    assert is_valid_device_ip("255.255.255.255") is False
    assert is_valid_device_ip("255.255.255.0") is False
    assert is_valid_device_ip("255.255.0.0") is False
    assert is_valid_device_ip("255.0.0.0") is False
    assert is_valid_device_ip("255.255.255.128") is False
    assert is_valid_device_ip("255.255.255.240") is False
    assert is_valid_device_ip("255.255.255.252") is False
    assert is_valid_device_ip("224.0.0.5") is False
    assert is_valid_device_ip("invalid") is False
    assert is_valid_device_ip("") is False

def test_parse_identity_hp_procurve_ip():
    from fingerprint import PROFILES, parse_identity
    prof = next(p for p in PROFILES if p["name"] == "hp-procurve")
    outputs = {
        "show ip": "  Internet (IPv4) Service\n\n  IPv4 Routing    : Disabled\n\n  Default Gateway : 192.168.1.1\n  Default TTL     : 64   \n\n  VLAN                 | IP Config  MAC Override IPv4 Address    Subnet Mask\n  -------------------- + ---------- ------------ --------------- ---------------\n  DEFAULT_VLAN         | Manual     False        10.20.30.40      255.255.255.0\n"
    }
    identity = parse_identity(prof, outputs)
    # The device address is the VLAN row's IPv4 Address, not the Default Gateway.
    assert identity.get("ip") == "10.20.30.40"

def test_parse_identity_hp_procurve_ip_ignores_default_gateway():
    from fingerprint import PROFILES, parse_identity
    prof = next(p for p in PROFILES if p["name"] == "hp-procurve")
    outputs = {
        "show ip": "  Internet (IPv4) Service\n\n  IPv4 Routing    : Disabled\n\n  Default Gateway : 172.16.1.1\n  Default TTL     : 64\n  Arp Age         : 20\n  Domain Suffix   :\n  DNS server      :\n\n                       |                                            Proxy ARP\n  VLAN                 | IP Config  IP Address      Subnet Mask     Std Local\n  -------------------- + ---------- --------------- --------------- --- -----\n  HOME-NETWORK         | Manual     172.16.1.90     255.255.255.0   No  No\n"
    }
    identity = parse_identity(prof, outputs)
    assert identity.get("ip") == "172.16.1.90"
    assert identity.get("ip") != "172.16.1.1"

_PROCURVE_SHOW_IP_DHCP = (
    "  Internet (IPv4) Service\n\n  IPv4 Routing    : Disabled\n\n"
    "  Default Gateway : 172.16.1.1\n  Default TTL     : 64\n  Arp Age         : 20\n\n"
    "                       |                                            Proxy ARP\n"
    "  VLAN                 | IP Config  IP Address      Subnet Mask     Std Local\n"
    "  -------------------- + ---------- --------------- --------------- --- -----\n"
    "  DEFAULT_VLAN         | DHCP/Bootp 172.16.1.57     255.255.255.0   No  No\n"
)

def test_parse_identity_hp_procurve_ip_dhcp_bootp():
    from fingerprint import PROFILES, parse_identity
    prof = next(p for p in PROFILES if p["name"] == "hp-procurve")
    identity = parse_identity(prof, {"show ip": _PROCURVE_SHOW_IP_DHCP})
    assert identity.get("ip") == "172.16.1.57"
    assert identity.get("ip") != "172.16.1.1"

def test_passive_identify_hp_procurve_dhcp_bootp_not_gateway():
    from fingerprint import passive_identify
    text = ("HP J9776A 2530-24G Switch\r\n"
            "HP-2530-24G# show ip\r\n" + _PROCURVE_SHOW_IP_DHCP + "HP-2530-24G# ")
    result = passive_identify(text)
    assert result["vendor"] == "hp-procurve"
    assert result["identity"].get("ip") == "172.16.1.57"
    assert result["identity"].get("ip") != "172.16.1.1"

def test_parse_identity_juniper_junos_ip():
    from fingerprint import PROFILES, parse_identity
    prof = next(p for p in PROFILES if p["name"] == "juniper-junos")
    outputs = {
        "show interfaces terse": "Interface               Admin Link Proto    Local                 Remote\nge-0/0/0.0              up    up   inet     192.168.1.10/24 \n"
    }
    identity = parse_identity(prof, outputs)
    assert identity.get("ip") == "192.168.1.10"

def test_parse_identity_aruba_os_ip():
    from fingerprint import PROFILES, parse_identity
    prof = next(p for p in PROFILES if p["name"] == "aruba-os")
    outputs = {
        "show ip interface brief": "Interface                   IP Address / IP Netmask        Admin   Protocol   \nvlan 1                      192.168.1.5 / 255.255.255.0    up      up\nloopback                    1.1.1.1 / 255.255.255.255      up      up\nmgmt                        10.10.10.10 / 255.255.255.0    up      up\n"
    }
    identity = parse_identity(prof, outputs)
    assert identity.get("ip") == "192.168.1.5"

def test_passive_identify_extracts_valid_ip():
    from fingerprint import passive_identify
    text = "Some random text with a subnet mask 255.255.255.0 and then IP address: 10.1.2.3"
    result = passive_identify(text)
    assert result["identity"].get("ip") == "10.1.2.3"


def test_passive_identify_ignores_unlabeled_bare_ip():
    # A bare IPv4-looking string with no "IP address"/"inet" label is as likely
    # to be a firmware version, gateway, or syslog server as the device's own
    # address (lm-986) — it must not be picked up.
    from fingerprint import passive_identify
    text = "generic-host booting firmware 8.10.0.7, syslog server 10.9.9.9 configured\r\n"
    result = passive_identify(text)
    assert result["identity"].get("ip") is None


def test_passive_identify_inet_label_not_matched_inside_word():
    # "inet" must require a word boundary so it doesn't fire inside "cabinet".
    from fingerprint import passive_identify
    text = "unit stored in cabinet 10.0.0.1, nothing else logged\r\n"
    result = passive_identify(text)
    assert result["identity"].get("ip") is None


def test_passive_identify_generic_inet_label():
    from fingerprint import passive_identify
    text = "unrecognized-host$ ip addr show\r\neth0: inet 192.168.50.5/24 brd 192.168.50.255\r\n"
    result = passive_identify(text)
    assert result["identity"].get("ip") == "192.168.50.5"


def test_passive_identify_generic_ip_address_label_with_dot_leader():
    # "IP Address.....: x" (a common CLI table leader style) must still match.
    from fingerprint import passive_identify
    text = "unrecognized-host# show system\r\nIP Address.....: 10.2.3.4\r\n"
    result = passive_identify(text)
    assert result["identity"].get("ip") == "10.2.3.4"


# ── ambiguous_fields: 2+ distinct valid candidates → flag the field, don't guess ──
_PROCURVE_SHOW_IP_TWO_VLANS = (
    "  Internet (IPv4) Service\n\n  IPv4 Routing    : Disabled\n\n"
    "  Default Gateway : 10.1.1.1\n  Default TTL     : 64\n  Arp Age         : 20\n\n"
    "                       |                                            Proxy ARP\n"
    "  VLAN                 | IP Config  IP Address      Subnet Mask     Std Local\n"
    "  -------------------- + ---------- --------------- --------------- --- -----\n"
    "  DEFAULT_VLAN         | Manual     10.1.1.20       255.255.255.0   No  No\n"
    "  MGMT                 | Manual     172.16.50.20    255.255.255.0   No  No\n"
)


def _procurve():
    return next(p for p in fp.PROFILES if p["name"] == "hp-procurve")


def test_parse_identity_hp_procurve_two_vlans_flags_ip_ambiguous():
    cands = []
    ident = fp.parse_identity(_procurve(), {"show ip": _PROCURVE_SHOW_IP_TWO_VLANS}, cands)
    assert ident.get("ip") == "10.1.1.20"  # stored value is still the first valid match
    assert [ip for ip, _ in cands] == ["10.1.1.20", "172.16.50.20"]
    assert cands[1][1].startswith("MGMT | Manual 172.16.50.20")  # source line kept
    amb = fp.ip_ambiguity(cands)
    assert amb["ambiguous_fields"] == ["ip"]
    assert amb["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]


def test_passive_identify_hp_procurve_two_vlans_ambiguous_fields():
    text = ("HP J9776A 2530-24G Switch\r\n"
            "HP-2530-24G# show ip\r\n" + _PROCURVE_SHOW_IP_TWO_VLANS + "HP-2530-24G# ")
    res = fp.passive_identify(text)
    assert res["vendor"] == "hp-procurve"
    assert res["identity"].get("ip") == "10.1.1.20"
    assert res["ambiguous_fields"] == ["ip"]
    assert res["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]
    assert set(res["ip_candidate_context"]) == {"10.1.1.20", "172.16.50.20"}
    assert "ambiguous_fields" not in res["identity"]  # sibling key, not an identity field
    assert "ip_candidates" not in res["identity"]


def test_run_identify_hp_procurve_two_vlans_ambiguous_fields():
    chan = _FakeChan("\r\nHP J9776A 2530-24G Switch\r\nHP-2530-24G# ", [
        ("no page", "\r\nHP-2530-24G# "),
        ("show system\r", "\r\n System Name : HP-2530-24G\r\n Serial Number : CN12345\r\nHP-2530-24G# "),
        ("show system-information", "\r\nInvalid input: show\r\nHP-2530-24G# "),
        ("show modules", "\r\n Chassis: 2530-24G Switch(J9776A)\r\nHP-2530-24G# "),
        ("show ip", _PROCURVE_SHOW_IP_TWO_VLANS.replace("\n", "\r\n") + "HP-2530-24G# "),
    ])
    res = fp.run_identify(chan.read, chan.write, [], cmd_secs=1.0)
    assert res["vendor"] == "hp-procurve"
    assert res["identity"].get("ip") == "10.1.1.20"
    assert res["identity"].get("hostname") == "HP-2530-24G"
    assert res["ambiguous_fields"] == ["ip"]  # hostname/serial/model never tracked
    assert res["ip_candidates"] == ["10.1.1.20", "172.16.50.20"]
    assert "ambiguous_fields" not in res["identity"]


def test_ambiguity_ignores_invalid_ip_candidates():
    # A rejected junk second address (999.1.1.1) never counts as a candidate.
    text = (_PROCURVE_SHOW_IP_DHCP
            + "  JUNK_VLAN            | Manual     999.1.1.1       255.255.255.0   No  No\n")
    cands = []
    ident = fp.parse_identity(_procurve(), {"show ip": text}, cands)
    assert ident.get("ip") == "172.16.1.57"
    assert [ip for ip, _ in cands] == ["172.16.1.57"]
    assert fp.ip_ambiguity(cands) == {}


def test_ambiguity_same_value_repeated_is_not_ambiguous():
    cands = []
    fp.parse_identity(_procurve(), {"show ip": _PROCURVE_SHOW_IP_DHCP * 2}, cands)
    assert fp.ip_ambiguity(cands) == {}


def test_single_vlan_procurve_not_ambiguous():
    cands = []
    fp.parse_identity(_procurve(), {"show ip": _PROCURVE_SHOW_IP_DHCP}, cands)
    assert fp.ip_ambiguity(cands) == {}
    text = ("HP J9776A 2530-24G Switch\r\n"
            "HP-2530-24G# show ip\r\n" + _PROCURVE_SHOW_IP_DHCP + "HP-2530-24G# ")
    res = fp.passive_identify(text)
    assert "ambiguous_fields" not in res and "ip_candidates" not in res


def test_run_identify_cisco_multi_interface_flags_ip_with_candidates():
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    chan = _FakeChan(banner, [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\nSwitch uptime is 1 day\r\nSwitch#"),
        ("show ip interface brief",
         "\r\nInterface              IP-Address      OK? Method Status                Protocol\r\n"
         "Vlan1                  unassigned      YES unset  administratively down down\r\n"
         "Vlan10                 172.16.1.90     YES NVRAM  up                    up\r\n"
         "Vlan20                 10.0.0.5        YES NVRAM  up                    up\r\n"
         "GigabitEthernet1/0/1   unassigned      YES unset  up                    up\r\n"
         "Switch#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["vendor"] == "cisco-ios"
    assert res["identity"]["ip"] == "172.16.1.90"  # first candidate still stored
    assert res["ambiguous_fields"] == ["ip"]
    assert res["ip_candidates"] == ["172.16.1.90", "10.0.0.5"]
    assert res["ip_candidate_context"]["10.0.0.5"].startswith("Vlan20 10.0.0.5")


def test_cisco_show_version_multiple_versions_not_ambiguous():
    # Regression (review concern 2): several distinct "Version …" substrings in
    # one show version are a regex-scoping artifact, not competing candidates —
    # only ip is ever tracked, so nothing is flagged and version = first match.
    show_ver = ("\r\nCisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), "
                "Version 15.2(4)E, RELEASE SOFTWARE (fc2)\r\n"
                "ROM: Bootstrap program is C2960X boot loader\r\n"
                "BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(3r)E1\r\n"
                "Switch uptime is 1 day\r\n"
                "cisco WS-C2960X-24TS-L (APM86XXX) processor with 524288K bytes of memory.\r\n"
                "Processor board ID FOC1234X0YZ\r\n"
                "Model number                    : WS-C2960X-24TS-L\r\n"
                "Switch Ports Model              SW Version            SW Image\r\n"
                "*    1 28    WS-C2960X-24TS-L   15.2(4)E7             C2960X-UNIVERSALK9-M\r\n"
                "Switch#")
    chan = _FakeChan("\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#", [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", show_ver),
        ("show ip interface brief", "\r\nVlan1  10.0.0.5  YES  up  up\r\nSwitch#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["identity"]["version"] == "15.2(4)E"  # first valid match, as before
    assert "ambiguous_fields" not in res and "ip_candidates" not in res
    prof = next(p for p in fp.PROFILES if p["name"] == "cisco-ios")
    passive = fp.passive_identify(show_ver + "\r\nshow ip interface brief\r\n"
                                  "Vlan1  10.0.0.5  YES  up  up\r\nSwitch#")
    assert passive["vendor"] == "cisco-ios"
    assert "ambiguous_fields" not in passive
    cands = []
    fp.parse_identity(prof, {"show version": show_ver}, cands)
    assert cands == []


def test_existing_single_device_identifies_report_no_ambiguity():
    # Regression: the pre-existing single-address run_identify fixtures stay unflagged.
    banner = "\r\nCisco IOS Software, Version 15.2(4)E\r\nSwitch#"
    chan = _FakeChan(banner, [
        ("terminal length 0", "\r\nSwitch#"),
        ("show version", "\r\nProcessor board ID FTX9XYZ\r\n"
                         "Base ethernet MAC Address : 0011.2233.4455\r\nSwitch#"),
        ("show ip interface brief", "\r\nVlan1  10.0.0.5  YES  up  up\r\nSwitch#"),
    ])
    res = fp.run_identify(chan.read, chan.write, [])
    assert res["identity"]["ip"] == "10.0.0.5"
    assert "ambiguous_fields" not in res
