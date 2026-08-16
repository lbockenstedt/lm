"""Read-only device fingerprinting for the Console role.

Auto-identify pipeline: scrape a banner, match it to a built-in vendor profile,
optionally log in with a credential list, run the profile's READ-ONLY identity
commands, and parse serial / MAC / mgmt-IP / model / hostname.

Safety: only commands from a matched profile's ``commands`` list are ever sent —
there is no free-form command path here, and every command is a read-only
``show``/``display``/``cat``. Pure helpers (:func:`detect_vendor`,
:func:`parse_identity`) import without pyserial so they are unit-testable.
"""
import logging
import re
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("ConsoleSpoke")

# A profile matches a device family by banner/prompt and defines how to log in +
# which read-only commands reveal identity. `fields` maps an identity key to a
# regex whose first group is the value. `config` (enter/exit/save/show_running)
# is consumed by the Phase G config read/push path, not the identify path.
PROFILES: List[Dict[str, Any]] = [
    {
        "name": "cisco-ios",
        "match": re.compile(r"Cisco IOS|IOS Software|IOS-XE", re.I),
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"[Uu]sername:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",  # space advances "--More--"
        "commands": [
            {"cmd": "terminal length 0"},
            {"cmd": "show version", "fields": {
                "serial": re.compile(r"[Pp]rocessor board ID\s+(\S+)"),
                "model": re.compile(r"[Cc]isco\s+(\S+).*(?:processor|chassis)", re.I),
                "mac": re.compile(r"[Bb]ase [Ee]thernet MAC Address\s*:?\s*([0-9A-Fa-f:.\-]{12,17})"),
                "version": re.compile(r"Version\s+([\w.()\-]+)"),
                "hostname": re.compile(r"^(\S+)\s+uptime is", re.M),
            }},
            {"cmd": "show ip interface brief", "fields": {
                "ip": re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b"),
            }},
        ],
        "config": {"enter": "configure terminal", "exit": "end", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        "name": "aruba-cx",
        "match": re.compile(r"ArubaOS-CX|Aruba.*CX|AOS-CX", re.I),
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"login:\s*$|[Uu]sername:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "no page"},
            {"cmd": "show system", "fields": {
                "serial": re.compile(r"Serial Number\s*:?\s*(\S+)", re.I),
                "model": re.compile(r"Product Name\s*:?\s*(.+?)\s*$", re.I | re.M),
                "mac": re.compile(r"Base MAC Address\s*:?\s*([0-9A-Fa-f:.\-]{12,17})", re.I),
                "hostname": re.compile(r"Hostname\s*:?\s*(\S+)", re.I),
            }},
            {"cmd": "show interface mgmt", "fields": {
                "ip": re.compile(r"IPv4 address\s*:?\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I),
            }},
        ],
        "config": {"enter": "configure terminal", "exit": "end", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        "name": "hp-procurve",
        "match": re.compile(r"ProCurve|HP.*Switch|Aruba.*(?:2530|2540|2930)", re.I),
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"[Uu]sername:\s*$|Login Name:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "no page"},
            {"cmd": "show system-information", "fields": {
                "serial": re.compile(r"Serial Number\s*:?\s*(\S+)", re.I),
                "model": re.compile(r"Base MAC.*|Product.*|^\s*(J\d{4}\w).*", re.I),
                "mac": re.compile(r"Base MAC Addr\s*:?\s*([0-9A-Fa-f:.\-]{12,17})", re.I),
                "hostname": re.compile(r"System Name\s*:?\s*(\S+)", re.I),
            }},
        ],
        "config": {"enter": "configure", "exit": "exit", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        "name": "linux",
        "match": re.compile(r"login:\s*$|Linux \S+ \d|Ubuntu|Debian|CentOS|localhost", re.I),
        "prompt": re.compile(r"[\w.\-]+[@:][\w.\-/~]*[#$]\s*$"),
        "login_prompt": re.compile(r"login:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": None,
        "commands": [
            {"cmd": "cat /sys/class/dmi/id/product_serial 2>/dev/null", "fields": {
                "serial": re.compile(r"^(\S+)\s*$", re.M),
            }},
            {"cmd": "hostname", "fields": {"hostname": re.compile(r"^(\S+)\s*$", re.M)}},
            {"cmd": "cat /sys/class/net/*/address 2>/dev/null | head -1", "fields": {
                "mac": re.compile(r"([0-9A-Fa-f:]{17})"),
            }},
            {"cmd": "ip -o -4 addr show scope global 2>/dev/null", "fields": {
                "ip": re.compile(r"\binet (\d{1,3}(?:\.\d{1,3}){3})"),
            }},
        ],
        "config": {"enter": None, "exit": None, "save": None, "show_running": None},
    },
]


def normalize_mac(mac: str) -> str:
    """Normalize a MAC to lower colon-separated form; '' if not 12 hex digits."""
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexs) != 12:
        return ""
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).lower()


def detect_vendor(text: str) -> Optional[Dict[str, Any]]:
    """Return the first profile whose ``match`` hits the banner/prompt text."""
    for prof in PROFILES:
        if prof["match"].search(text or ""):
            return prof
    return None


def parse_identity(profile: Dict[str, Any], outputs: Dict[str, str]) -> Dict[str, str]:
    """Apply a profile's per-command field regexes to captured command output.
    ``outputs`` maps command → its captured text. First non-empty match wins per
    field; MAC is normalized."""
    identity: Dict[str, str] = {}
    for spec in profile.get("commands", []):
        fields = spec.get("fields") or {}
        text = outputs.get(spec["cmd"], "")
        for key, rx in fields.items():
            if key in identity:
                continue
            m = rx.search(text)
            if m and m.group(1).strip():
                identity[key] = m.group(1).strip()
    if identity.get("mac"):
        identity["mac"] = normalize_mac(identity["mac"]) or identity["mac"]
    return identity


# Generic fallbacks — a hostname prompt, a MAC, or an IP scrolling by is worth
# surfacing even before we can pin a vendor. Kept conservative to avoid noise.
_GENERIC_PROMPT = re.compile(r"(?:^|\r|\n)\s*([\w][\w.\-]{1,62})[>#]\s*$")
_GENERIC_LINUX_PROMPT = re.compile(r"(?:^|\r|\n)[\w.\-]+@([\w.\-]+):[\w.\-/~]*[#$]\s*$")
_GENERIC_MAC = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")

# Vendor-agnostic prompt shapes used to log in BEFORE we know the vendor. A device
# sitting at a bare ``login:`` prompt reveals no banner/system info until you
# authenticate, so identification has to log in generically first.
_LOGIN_PROMPT = re.compile(r"(?:[Ll]ogin|[Uu]ser\s?name)\s*:\s*$")
_PASSWORD_PROMPT = re.compile(r"[Pp]assword\s*:\s*$")
_SHELL_PROMPT = re.compile(r"\S[>#$%]\s*$")

# ── Read-only command allowlist (safety gate for LLM-suggested commands) ───────
# When an LLM proposes commands to run on an unknown device, EVERY command must
# pass this gate before it touches the serial line. The guarantee we preserve:
# identify/collect only ever sends non-mutating, read-only commands.
_READONLY_VERBS = frozenset({
    # network-OS operational verbs
    "show", "display", "get", "fetch", "list",
    # unix read-only introspection
    "cat", "head", "tail", "ls", "dir", "pwd", "more", "less", "uname",
    "hostname", "id", "whoami", "uptime", "date", "env", "printenv",
    "lscpu", "lsusb", "lspci", "lsblk", "dmesg", "df", "free", "arp",
    "netstat", "version", "ver",
})
# Session-local pager/length controls — not persisted, safe to send verbatim.
_SAFE_PAGER_CMDS = frozenset({
    "terminal length 0", "terminal pager 0", "terminal pager off",
    "set terminal length 0", "set cli screen-length 0", "set cli pager off",
    "set length 0", "screen-length 0 temporary", "no page", "no paging",
    "environment no more", "no more",
})
# Any of these appearing ANYWHERE in a command → hard reject (defence in depth,
# even though chaining/redirection metacharacters are already blocked).
_MUTATION_WORDS = frozenset({
    "config", "configure", "conf", "set", "write", "wr", "erase", "delete",
    "del", "remove", "rm", "reload", "reboot", "restart", "clear", "copy",
    "cp", "mv", "format", "boot", "shutdown", "no", "commit", "rollback",
    "request", "start", "stop", "sudo", "su", "dd", "mkfs", "kill", "halt",
    "poweroff", "save", "factory-reset", "default", "add", "flush", "tftp",
    "scp", "install", "upgrade", "downgrade", "load", "import", "export",
    "tee", "renew", "release", "ping", "traceroute", "telnet", "ssh", "test",
    "debug", "enable", "disable", "power",
})
_META_TOKENS = ("\n", "\r", ";", "|", "&", "`", "$(", ">", "<", "\\", "\x00")


def is_readonly_command(cmd: str) -> bool:
    """True only if ``cmd`` is a single, non-mutating, read-only command safe to
    send to a device we're identifying. Rejects chaining/redirection/substitution
    metacharacters, any mutation keyword, and any verb not on the allowlist.
    Session-local pager controls are explicitly permitted."""
    c = (cmd or "").strip()
    if not c or any(t in c for t in _META_TOKENS):
        return False
    low = c.lower()
    if low in _SAFE_PAGER_CMDS:
        return True
    words = low.split()
    if words[0] not in _READONLY_VERBS:
        return False
    return not any(w in _MUTATION_WORDS for w in words)


def passive_identify(text: str) -> Dict[str, Any]:
    """Best-effort identity from PASSIVELY captured console text — no login, no
    commands issued. Detects the vendor from the banner/prompt, then applies that
    profile's identity field regexes across the whole capture (a human may have
    just run ``show version``; a boot banner or syslog line may reveal the rest).

    Conservative on purpose: full field extraction only for a matched vendor
    profile (avoids cross-vendor false positives); otherwise a light generic pass
    picks up a hostname prompt / MAC so the port stops showing "unknown".

    Returns ``{"vendor": <name|None>, "identity": {...}}`` (identity may be {})."""
    text = text or ""
    prof = detect_vendor(text)
    identity: Dict[str, str] = {}
    vendor = prof["name"] if prof else None
    # Full field extraction only for the LABELED network-vendor profiles (their
    # regexes anchor on strings like "Processor board ID" / "Serial Number" /
    # "Base MAC" / "IPv4 address", which are safe to match anywhere in a passive
    # capture). The linux profile's field regexes are bare ``^(\S+)$`` forms tied
    # to specific command outputs — matching those across arbitrary scrollback
    # yields garbage, so linux/unknown fall to the generic prompt pass below.
    if prof and prof["name"] != "linux":
        for spec in prof.get("commands", []):
            for key, rx in (spec.get("fields") or {}).items():
                if key in identity:
                    continue
                m = rx.search(text)
                if m and m.group(1).strip():
                    identity[key] = m.group(1).strip()
    if not identity.get("hostname"):
        # Glean a hostname from the last shell/CLI prompt we saw.
        for rx in (_GENERIC_LINUX_PROMPT, _GENERIC_PROMPT):
            for m in rx.finditer(text):
                cand = m.group(1).strip()
                if cand and cand.lower() not in ("more", "username", "password", "login"):
                    identity["hostname"] = cand
    if not identity.get("mac"):
        mm = _GENERIC_MAC.search(text)
        if mm:
            identity["mac"] = mm.group(1)
    if identity.get("mac"):
        identity["mac"] = normalize_mac(identity["mac"]) or identity["mac"]
    return {"vendor": vendor, "identity": identity}


def _read_until(read_fn: Callable[[], bytes], patterns: List[re.Pattern],
                timeout: float, idle: float = 0.4) -> str:
    """Accumulate serial output until one of ``patterns`` matches the tail, or
    ``timeout`` elapses, or the stream goes idle for ``idle`` seconds."""
    buf = b""
    deadline = time.monotonic() + timeout
    last = time.monotonic()
    while time.monotonic() < deadline:
        chunk = read_fn()
        if chunk:
            buf += chunk
            last = time.monotonic()
            tail = buf[-400:].decode("utf-8", "replace")
            if any(p.search(tail) for p in patterns):
                break
        elif time.monotonic() - last > idle:
            break
    return buf.decode("utf-8", "replace")


def _generic_login(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                   credentials: List[Dict[str, str]], banner_secs: float = 3.0,
                   step_secs: float = 4.0):
    """Vendor-agnostic login run BEFORE vendor detection.

    Nudges the line and inspects the tail: if a shell prompt is already showing we
    return logged-in with no auth; if a ``login:``/``password:`` prompt is showing
    we try each credential once (username then password) until a shell prompt
    appears. Returns ``(logged_in, credential_index, transcript, diag)`` where
    ``diag`` reports what was observed (prompt detection, bytes, creds tried) for
    troubleshooting. This is what lets a device sitting at a bare login prompt —
    which shows no banner/system info until you authenticate — be identified.
    """
    diag: Dict[str, Any] = {"login_prompt_seen": False, "password_prompt_seen": False,
                            "shell_prompt_seen": False, "creds_tried": 0,
                            "bytes": 0, "any_output": False}

    def _observe(tail: str) -> None:
        if _LOGIN_PROMPT.search(tail):
            diag["login_prompt_seen"] = True
        if _PASSWORD_PROMPT.search(tail):
            diag["password_prompt_seen"] = True
        if _SHELL_PROMPT.search(tail):
            diag["shell_prompt_seen"] = True

    write_fn(b"\r\n")
    transcript = _read_until(read_fn, [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT], banner_secs)
    diag["bytes"] = len(transcript)
    diag["any_output"] = bool(transcript.strip())
    tail = transcript[-200:]
    _observe(tail)
    at_login = bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail))
    if not at_login:
        # Already at a shell (no auth), or nothing recognizable on the line.
        return bool(_SHELL_PROMPT.search(tail)), None, transcript, diag
    if not credentials:
        return False, None, transcript, diag
    for idx, cred in enumerate(credentials):
        diag["creds_tried"] = idx + 1
        tail = transcript[-200:]
        if _LOGIN_PROMPT.search(tail):
            write_fn((cred.get("username", "") + "\r").encode())
            transcript += _read_until(read_fn, [_PASSWORD_PROMPT, _SHELL_PROMPT, _LOGIN_PROMPT], step_secs)
            tail = transcript[-200:]
            _observe(tail)
        if _PASSWORD_PROMPT.search(tail):
            write_fn((cred.get("password", "") + "\r").encode())
            transcript += _read_until(read_fn, [_SHELL_PROMPT, _LOGIN_PROMPT, _PASSWORD_PROMPT], step_secs)
            tail = transcript[-200:]
            _observe(tail)
        if _SHELL_PROMPT.search(tail) and not (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
            diag["bytes"] = len(transcript)
            return True, idx, transcript, diag
        # Auth failed → the device re-shows a login prompt; nudge and let the loop
        # try the next credential (attempt cap = len(credentials), no re-hammering).
        write_fn(b"\r")
        transcript += _read_until(read_fn, [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT], 2.0)
    diag["bytes"] = len(transcript)
    return False, None, transcript, diag


def run_identify(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                 credentials: List[Dict[str, str]], banner_secs: float = 3.0,
                 cmd_secs: float = 4.0) -> Dict[str, Any]:
    """Drive a read-only identify over an already-open serial channel.

    ``read_fn()`` returns available bytes (non-blocking-ish); ``write_fn(bytes)``
    writes. ``credentials`` is an ordered list of ``{username,password}`` tried
    once each at a login prompt (attempt cap = len(credentials); no re-hammering).
    Returns ``{banner, vendor, logged_in, credential_index, identity, outputs}``.
    Read-only: only the matched profile's commands are sent.
    """
    result: Dict[str, Any] = {"banner": "", "vendor": None, "logged_in": False,
                              "credential_index": None, "identity": {}, "outputs": {},
                              "diag": {}}
    # 1. Vendor-agnostic login FIRST. A device at a bare login prompt shows no
    #    banner/system info until authenticated, so we must log in before we can
    #    detect the vendor (and even unknown vendors get a captured post-login
    #    banner for the passive-glean / LLM-identify paths to use).
    logged_in, cred_idx, transcript, diag = _generic_login(read_fn, write_fn, credentials, banner_secs)
    result["banner"] = transcript[-4000:]
    result["logged_in"] = logged_in
    result["credential_index"] = cred_idx
    result["diag"] = _login_diag(diag, transcript, credentials)

    # 2. Detect the vendor from everything seen (pre- and post-login).
    profile = detect_vendor(transcript)
    if not profile:
        return result  # unknown vendor — the LLM-driven identify path takes over
    result["vendor"] = profile["name"]

    # If a login prompt is still showing (couldn't authenticate), stop here.
    tail = transcript[-200:]
    if not logged_in and (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
        return result

    # 3. Run the read-only identity commands + capture output.
    outputs: Dict[str, str] = {}
    for spec in profile["commands"]:
        cmd = spec["cmd"]
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_until(read_fn, [profile["prompt"]], cmd_secs)
    result["outputs"] = outputs
    result["identity"] = parse_identity(profile, outputs)
    return result


def _sanitize_tail(text: str, n: int = 240) -> str:
    """A short, printable tail of a transcript for troubleshooting telemetry —
    control bytes collapsed to spaces so it renders safely in the UI/logs."""
    tail = (text or "")[-n:]
    return re.sub(r"[^\x20-\x7e]+", " ", tail).strip()


def _login_diag(diag: Dict[str, Any], transcript: str, credentials) -> Dict[str, Any]:
    """Assemble the login telemetry block from a _generic_login diag + transcript.
    Adds a printable tail and a human ``reason`` for why login didn't complete."""
    d = dict(diag or {})
    d["creds_available"] = len(credentials or [])
    d["tail"] = _sanitize_tail(transcript)
    if d.get("shell_prompt_seen"):
        d["reason"] = "reached shell prompt"
    elif not d.get("any_output"):
        d["reason"] = "no output from device (silent line or wrong baud)"
    elif not (d.get("login_prompt_seen") or d.get("password_prompt_seen")):
        d["reason"] = "output seen but no recognizable login/password prompt"
    elif not d.get("creds_available"):
        d["reason"] = "login prompt seen but no stored credentials to try"
    elif d.get("password_prompt_seen"):
        d["reason"] = "credentials rejected (re-prompted for login/password)"
    else:
        d["reason"] = "sent username but no password prompt followed"
    return d


def run_commands(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                 credentials: List[Dict[str, str]], commands: List[str],
                 banner_secs: float = 3.0, cmd_secs: float = 4.0) -> Dict[str, Any]:
    """Log in generically, then run a caller-supplied list of READ-ONLY commands
    and capture per-command output — the primitive behind LLM-driven identify on
    devices the built-in profiles don't recognize.

    Every command is validated by :func:`is_readonly_command` before it is sent;
    anything that fails is skipped and reported in ``rejected`` (never written to
    the line). If we never authenticate (a login prompt is still showing), no
    commands are sent. Returns
    ``{banner, logged_in, credential_index, outputs, rejected, diag}``.
    """
    result: Dict[str, Any] = {"banner": "", "logged_in": False, "credential_index": None,
                              "outputs": {}, "rejected": [], "diag": {}}
    logged_in, cred_idx, transcript, diag = _generic_login(read_fn, write_fn, credentials, banner_secs)
    result["banner"] = transcript[-4000:]
    result["logged_in"] = logged_in
    result["credential_index"] = cred_idx
    result["diag"] = _login_diag(diag, transcript, credentials)
    tail = transcript[-200:]
    if not logged_in and (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
        return result  # never authenticated — don't send commands into a login prompt
    outputs: Dict[str, str] = {}
    for raw in (commands or []):
        cmd = str(raw).strip()
        if not is_readonly_command(cmd):
            result["rejected"].append(cmd)
            continue
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_until(read_fn, [_SHELL_PROMPT], cmd_secs)
    result["outputs"] = outputs
    return result


# ── Config read / transactional push (Phase G) ─────────────────────────────────

def login(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
          profile: Dict[str, Any], credentials: List[Dict[str, str]],
          sample_secs: float = 2.0):
    """Reach an exec prompt on an already-woken line. Returns (logged_in, idx).
    Tries each credential once; no re-hammering."""
    def at_exec(t: str) -> bool:
        return bool(profile["prompt"].search(t) and not (
            profile["login_prompt"].search(t) or profile["password_prompt"].search(t)))

    tail = _read_until(read_fn, [profile["login_prompt"], profile["password_prompt"],
                                 profile["prompt"]], sample_secs)[-200:]
    if at_exec(tail):
        return True, None
    if not (profile["login_prompt"].search(tail) or profile["password_prompt"].search(tail)):
        write_fn(b"\r")
        tail = _read_until(read_fn, [profile["login_prompt"], profile["password_prompt"],
                                     profile["prompt"]], sample_secs)[-200:]
        if at_exec(tail):
            return True, None
    for idx, cred in enumerate(credentials or []):
        if profile["password_prompt"].search(tail) and not profile["login_prompt"].search(tail):
            write_fn((cred.get("password", "") + "\r").encode())
        else:
            write_fn((cred.get("username", "") + "\r").encode())
            out = _read_until(read_fn, [profile["password_prompt"], profile["prompt"]], 3.0)
            if profile["password_prompt"].search(out[-200:]):
                write_fn((cred.get("password", "") + "\r").encode())
        tail = _read_until(read_fn, [profile["prompt"], profile["login_prompt"],
                                     profile["password_prompt"]], 4.0)[-200:]
        if at_exec(tail):
            return True, idx
    return False, None


def _disable_pager(read_fn, write_fn, profile, cmd_secs: float) -> None:
    """Send the profile's pure setup commands (terminal length 0 / no page) so a
    long show doesn't stall on a pager. These are the commands with no `fields`."""
    for spec in profile.get("commands", []):
        if "fields" not in spec:
            write_fn((spec["cmd"] + "\r").encode())
            _read_until(read_fn, [profile["prompt"]], cmd_secs)


def read_running_config(read_fn, write_fn, profile, credentials,
                        cmd_secs: float = 12.0) -> Dict[str, Any]:
    """Log in (if needed) and capture the device's running-config (backup/read)."""
    write_fn(b"\r\n")
    ok, _ = login(read_fn, write_fn, profile, credentials)
    if not ok:
        return {"status": "ERROR", "message": "login failed", "config": ""}
    show = (profile.get("config") or {}).get("show_running")
    if not show:
        return {"status": "ERROR", "message": "no running-config command for this device type",
                "config": ""}
    _disable_pager(read_fn, write_fn, profile, 3.0)
    write_fn((show + "\r").encode())
    cfg = _read_until(read_fn, [profile["prompt"]], cmd_secs)
    return {"status": "SUCCESS", "config": cfg}


_CFG_ERR = re.compile(r"%\s|Invalid input|Unknown command|Incomplete command|syntax error|"
                      r"not found|rejected|Error:", re.I)


def push_config(read_fn, write_fn, profile, credentials, config_text: str,
                save: bool = True, rollback: str = "negate",
                cmd_secs: float = 4.0) -> Dict[str, Any]:
    """Transactional config push (Phase G): login → backup → enter config mode →
    send lines (watch per-line errors) → exit → POST-VERIFY the pushed lines are
    in running-config → on PASS save (unless save=False); on FAIL do NOT save and
    roll back (``negate`` = ``no <line>`` in reverse, or ``reboot`` = reload the
    unsaved running-config). No post-request approval (decision: transactional).
    """
    conf = profile.get("config") or {}
    enter, exit_, save_cmd, show = (conf.get("enter"), conf.get("exit"),
                                    conf.get("save"), conf.get("show_running"))
    result: Dict[str, Any] = {"status": "ERROR", "logged_in": False, "applied": [],
                              "errors": [], "verify_ok": False, "saved": False,
                              "rolled_back": False, "baseline": "", "missing": []}
    write_fn(b"\r\n")
    ok, _ = login(read_fn, write_fn, profile, credentials)
    result["logged_in"] = ok
    if not ok:
        result["message"] = "login failed"
        return result
    if not enter:
        result["message"] = "device type has no config mode (read-only)"
        return result
    _disable_pager(read_fn, write_fn, profile, 3.0)
    if show:  # 1. pre-verify backup
        write_fn((show + "\r").encode())
        result["baseline"] = _read_until(read_fn, [profile["prompt"]], 12.0)
    lines = [l.rstrip() for l in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    # 2. enter config mode + send line-by-line
    write_fn((enter + "\r").encode())
    _read_until(read_fn, [profile["prompt"]], cmd_secs)
    for ln in lines:
        if not ln.strip():
            continue
        write_fn((ln + "\r").encode())
        out = _read_until(read_fn, [profile["prompt"]], cmd_secs)
        result["applied"].append(ln)
        if _CFG_ERR.search(out):
            result["errors"].append({"line": ln, "output": out[-160:]})
    if exit_:
        write_fn((exit_ + "\r").encode())
        _read_until(read_fn, [profile["prompt"]], cmd_secs)
    # 3. post-verify: pushed (non-comment) lines present in running-config
    running = ""
    if show:
        write_fn((show + "\r").encode())
        running = _read_until(read_fn, [profile["prompt"]], 12.0)
    check = [l.strip() for l in lines if l.strip() and not l.strip().startswith("!")]
    missing = [l for l in check if l not in running] if running else check
    result["missing"] = missing[:20]
    result["verify_ok"] = (not result["errors"]) and (not missing)
    # 4. save on pass; rollback on fail (never save a failed push)
    if result["verify_ok"]:
        if save and save_cmd:
            write_fn((save_cmd + "\r").encode())
            _read_until(read_fn, [profile["prompt"]], cmd_secs + 4)
            result["saved"] = True
        result["status"] = "SUCCESS"
    else:
        if rollback == "reboot":
            # running-config is unsaved → a reload reverts to startup.
            write_fn(b"reload\r")
            _read_until(read_fn, [re.compile(r"\[confirm\]|\[yes/no\]|\?\s*$")], 3.0)
            write_fn(b"no\r")   # 'System configuration modified. Save? [yes/no]:' → no
            write_fn(b"\r")     # confirm reload
            result["rolled_back"] = True
        elif enter:
            write_fn((enter + "\r").encode())
            _read_until(read_fn, [profile["prompt"]], cmd_secs)
            for ln in reversed(result["applied"]):
                s = ln.strip()
                if s and not s.startswith("!") and not s.lower().startswith("no "):
                    write_fn(("no " + s + "\r").encode())
                    _read_until(read_fn, [profile["prompt"]], cmd_secs)
            if exit_:
                write_fn((exit_ + "\r").encode())
                _read_until(read_fn, [profile["prompt"]], cmd_secs)
            result["rolled_back"] = True
        result["status"] = "ERROR"
        result["message"] = "verification failed — not saved; rolled back (%s)" % rollback
    return result
