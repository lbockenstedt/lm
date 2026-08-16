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
