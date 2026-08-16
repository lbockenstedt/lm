"""Read-only device fingerprinting for the Console role.

Auto-identify pipeline: scrape a banner, match it to a built-in vendor profile,
optionally log in with a credential list, run the profile's READ-ONLY identity
commands, and parse serial / MAC / mgmt-IP / model / hostname.

Safety: only commands from a matched profile's ``commands`` list are ever sent —
there is no free-form command path here, and every command is a read-only
``show``/``display``/``cat``. Pure helpers (:func:`detect_vendor`,
:func:`parse_identity`) import without pyserial so they are unit-testable.
"""
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("ConsoleSpoke")

# Terminal escape-sequence strippers, used to turn raw console output (which is
# full of VT100/ANSI cursor moves, scroll-region and show/hide-cursor codes on
# full-screen menu CLIs like ArubaOS-Switch) into human-readable text for the
# Capture view, the LLM identify prompt and vendor detection. The live xterm.js
# view renders escapes itself, so only the static/analysis paths sanitize.
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")      # OSC ... BEL/ST
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")               # CSI ... final
_ANSI_MISC = re.compile(r"\x1b[()#][0-9A-Za-z]|\x1b[=>78McDEHF]")  # charset/misc
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")     # keep \t \n \r


def sanitize_console_text(text: str) -> str:
    """Strip VT100/ANSI terminal escape sequences (CSI cursor moves, OSC, scroll
    regions, show/hide-cursor) and bare control bytes from raw console output so
    it is human-readable. Preserves tabs/newlines and normalizes CR/LF. Safe to
    run on partial captures. Used for the Capture view, LLM input and detection."""
    if not text:
        return ""
    s = _ANSI_OSC.sub("", text)
    s = _ANSI_CSI.sub("", s)
    s = _ANSI_MISC.sub("", s)
    s = _CTRL_CHARS.sub("", s)
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\n{3,}", "\n\n", s)


# A profile matches a device family by banner/prompt and defines how to log in +
# which read-only commands reveal identity. `fields` maps an identity key to a
# regex whose first group is the value. `config` (enter/exit/save/show_running)
# is consumed by the Phase G config read/push path, not the identify path.
PROFILES: List[Dict[str, Any]] = [
    {
        "name": "cisco-ios",
        "match": re.compile(r"Cisco IOS|IOS Software|IOS-XE", re.I),
        "family": "Switch/Router",
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"[Uu]sername:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",  # space advances "--More--"
        "commands": [
            {"cmd": "terminal length 0"},
            {"cmd": "show version", "fields": {
                "serial": re.compile(r"[Pp]rocessor board ID\s+(\S+)"),
                # "Model number : WS-C2960X-24TS-L" or "cisco WS-C3560 ... processor".
                # Require a digit in the token so the OS word ("IOS") isn't taken.
                "model": re.compile(
                    r"(?:[Mm]odel [Nn]umber\s*:?\s*|cisco\s+)([A-Za-z0-9][\w\-/+]*\d[\w\-/+]*)", re.I),
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
        "family": "Switch",
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"login:\s*$|[Uu]sername:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "no page"},
            {"cmd": "show system", "fields": {
                "serial": re.compile(r"Serial Number\s*:?\s*(\S+)", re.I),
                # "Product Name : 6300M 48-port ..." or "Chassis: JL658A 6300M".
                "model": re.compile(r"(?:Product Name|Chassis)\s*:?\s*(.+?)\s*$", re.I | re.M),
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
        "match": re.compile(
            r"ProCurve|HP.*Switch|Aruba.*(?:2530|2540|2930)|"
            r"AOS-?S\b|-AOSS[>#]|\bAOSS[>#]|Invalid input:",
            re.I),
        "family": "Switch",
        "prompt": re.compile(r"[\w.\-]+[>#]\s*$"),
        "login_prompt": re.compile(r"[Uu]sername:\s*$|Login Name:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "no page"},
            {"cmd": "show system-information", "fields": {
                "serial": re.compile(r"Serial Number\s*:?\s*(\S+)", re.I),
                "mac": re.compile(r"Base MAC Addr\S*\s*:?\s*([0-9A-Fa-f:.\-]{12,17})", re.I),
                "hostname": re.compile(r"System Name\s*:?\s*(\S+)", re.I),
            }},
            # The product/model lives in "show modules" (or "show system"), e.g.
            # "Chassis: 2930F-24G-4SFP+ Switch(JL253A)" — not in system-information.
            {"cmd": "show modules", "fields": {
                "model": re.compile(r"Chassis\s*:?\s*(.+?)\s*(?:\(|Serial|$)", re.I | re.M),
            }},
        ],
        "config": {"enter": "configure", "exit": "exit", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        "name": "juniper-junos",
        "match": re.compile(r"JUNOS|Junos:|Juniper Networks|juniper", re.I),
        "family": "Firewall/Router",
        "prompt": re.compile(r"[\w.\-]+[>#%]\s*$"),
        "login_prompt": re.compile(r"login:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "set cli screen-length 0"},
            {"cmd": "show version", "fields": {
                "model": re.compile(r"Model\s*:?\s*(\S+)", re.I),
                "os": re.compile(r"Junos:\s*(\S+)", re.I),
                "hostname": re.compile(r"Hostname\s*:?\s*(\S+)", re.I),
            }},
            {"cmd": "show chassis hardware", "fields": {
                "serial": re.compile(r"^Chassis\s+(\S+)", re.I | re.M),
            }},
        ],
        "config": {"enter": "configure", "exit": "exit", "save": "commit",
                   "show_running": "show configuration"},
    },
    {
        "name": "linux",
        "match": re.compile(r"login:\s*$|Linux \S+ \d|Ubuntu|Debian|CentOS|localhost", re.I),
        "family": "Server",
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
    """Return the first profile whose ``match`` hits the banner/prompt text.
    Escape sequences are stripped first so a full-screen menu CLI (e.g. ArubaOS-S,
    whose prompt/errors are interleaved with cursor-move codes) still matches."""
    clean = sanitize_console_text(text)
    for prof in PROFILES:
        if prof["match"].search(clean):
            return prof
    return None


# Model-number prefixes → device role. Lets us report a concrete type ("Firewall",
# "Access Point", …) rather than a vague family, once we know the model — most
# useful for Juniper, whose one OS (JunOS) spans firewalls (SRX), switches
# (EX/QFX) and routers (MX/PTX/ACX).
_TYPE_BY_MODEL: List[Tuple[Any, str]] = [
    (re.compile(r"\bSRX", re.I), "Firewall"),
    (re.compile(r"\b(?:EX|QFX)\d", re.I), "Switch"),
    (re.compile(r"\b(?:MX|PTX|ACX)\d", re.I), "Router"),
    (re.compile(r"\b(?:IAP|AP-?\d|R\d{3}|MR\d)", re.I), "Access Point"),
    (re.compile(r"\b(?:ISR|ASR|C89\d\d|C81\d\d)\b", re.I), "Router"),
    (re.compile(r"\b(?:ASA|Palo Alto|PA-\d|FortiGate|FGT)\b", re.I), "Firewall"),
]


def infer_device_type(model: Optional[str], family_default: Optional[str]) -> str:
    """Map a model string to a concrete device role (Switch/Router/Firewall/
    Access Point/…), falling back to the profile's default family. '' if neither."""
    if model:
        for rx, kind in _TYPE_BY_MODEL:
            if rx.search(model):
                return kind
    return family_default or ""


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
            if not m:
                continue
            # Use the first capturing group, but tolerate alternation branches
            # where group 1 didn't participate (returns None) — fall back to the
            # whole match so a valid hit is never dropped (or worse, crashes).
            val = ((m.group(1) if m.lastindex else None) or m.group(0) or "").strip()
            if val:
                identity[key] = val
    if identity.get("mac"):
        identity["mac"] = normalize_mac(identity["mac"]) or identity["mac"]
    return identity


# Generic fallbacks — a hostname prompt, a MAC, or an IP scrolling by is worth
# surfacing even before we can pin a vendor. Kept conservative to avoid noise.
# Generic fallbacks — a hostname prompt, a MAC, or an IP scrolling by is worth
# surfacing even before we can pin a vendor. Kept conservative to avoid noise.
# These are the built-in DEFAULTS for the hostname_prompt family; the live
# matchers are loaded from prompt_patterns.json (see load_hostname_prompts) so a
# new prompt shape can be added with NO code change. Each pattern MUST capture
# the hostname in group(1). Order = priority (first pattern that yields a
# candidate wins), so list the most specific shapes first.
def _prompt_patterns_path() -> Path:
    return Path(os.environ.get("CONSOLE_PROMPT_PATTERNS")
                or (Path(__file__).parent / "prompt_patterns.json"))


_DEFAULT_HOSTNAME_PROMPTS: List[str] = [
    # Linux shell: user@host:~$ / user@host:/path#
    r"(?:^|\r|\n)[\w.\-]+@([\w.\-]+):[\w.\-/~]*[#$]\s*$",
    # ArubaOS controller/gateway/Instant: "(hostname) #", "(hostname) *#"
    # (the * = pending config), optionally with a config-context paren:
    # "(hostname) (config) #". Hostname is the FIRST parenthesised token.
    r"(?:^|\r|\n|\s)\(([\w][\w.\-]{1,62})\)\s*(?:\([\w .\-]+\)\s*)?\*?\s*[>#]",
    # Generic vendor CLI: hostname immediately followed by > or #
    r"(?:^|\r|\n)\s*([\w][\w.\-]{1,62})[>#]\s*$",
]
_GENERIC_MAC = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
_PROMPT_HOST_SKIP = frozenset({"more", "username", "password", "login", "config"})


def load_hostname_prompts() -> List["re.Pattern"]:
    """Compile the hostname-prompt matchers (each capturing the hostname in
    group 1), reading them from prompt_patterns.json[``hostname_prompt``] when
    present and falling back to the built-in defaults. Bad file / bad regex →
    defaults, so a malformed edit can never break hostname gleaning."""
    pats: List[str] = list(_DEFAULT_HOSTNAME_PROMPTS)
    try:
        loaded = json.loads(_prompt_patterns_path().read_text())
        candidate = loaded.get("hostname_prompt")
        if isinstance(candidate, list) and candidate and all(isinstance(p, str) for p in candidate):
            pats = candidate
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001 - bad JSON → keep defaults
        logger.warning("console: invalid prompt_patterns.json hostname_prompt (%s) — using defaults", e)
    compiled: List["re.Pattern"] = []
    for p in pats:
        try:
            compiled.append(re.compile(p))
        except re.error as e:  # skip a single bad pattern, keep the rest usable
            logger.warning("console: bad hostname_prompt regex %r (%s) — skipping", p, e)
    return compiled or [re.compile(p) for p in _DEFAULT_HOSTNAME_PROMPTS]


_HOSTNAME_PROMPTS = load_hostname_prompts()


def _prompt_hostname_with(patterns: List["re.Pattern"], text: str) -> str:
    """Core of :func:`prompt_hostname`, parameterised by the compiled pattern
    list so it can be unit-tested against an arbitrary (e.g. JSON-overridden)
    pattern set. First pattern that yields a non-placeholder candidate wins;
    within a pattern the LAST (most recent) match is kept."""
    clean = sanitize_console_text(text or "")
    for rx in patterns:
        cand = ""
        for m in rx.finditer(clean):
            c = (m.group(1) or "").strip()
            if c and c.lower() not in _PROMPT_HOST_SKIP:
                cand = c
        if cand:
            return cand
    return ""


def prompt_hostname(text: str) -> str:
    """Best-effort hostname from the LAST CLI/shell prompt in ``text`` (e.g. the
    ``MIA-SW-AOSS>`` prompt of an ArubaOS-Switch, ``(MIA-GW-02) *#`` on an Aruba
    controller/gateway, or ``user@host:~$`` on Linux). Terminal escapes are
    stripped first. Returns '' if none or a placeholder."""
    return _prompt_hostname_with(_HOSTNAME_PROMPTS, text)

# Vendor-agnostic prompt shapes used to log in BEFORE we know the vendor. A device
# sitting at a bare ``login:`` prompt reveals no banner/system info until you
# authenticate, so identification has to log in generically first.
#
# These patterns are LOADED FROM prompt_patterns.json (next to this file) so a new
# prompt string a device uses — e.g. a bare ``User:`` or a vendor's oddly-worded
# password prompt — can be added by editing JSON, with NO code change. The
# hardcoded values below are the built-in defaults / fallback if the file is
# missing or malformed. Override the file location with $CONSOLE_PROMPT_PATTERNS.
_DEFAULT_PROMPT_PATTERNS: Dict[str, List[str]] = {
    "login_prompt": [r"(?:[Ll]ogin|[Uu]ser(?:\s?name)?)\s*:\s*$"],
    "password_prompt": [r"[Pp]assword\s*:\s*$"],
    "shell_prompt": [r"\S[>#$%]\s*$"],
}


def load_prompt_patterns() -> Dict[str, "re.Pattern"]:
    """Compile the login/password/shell prompt matchers, reading pattern strings
    from prompt_patterns.json when present (falling back to the built-in defaults
    per family). Each family is an OR of its listed regexes, so operators can add
    a newly-observed prompt string to the JSON without touching code."""
    data: Dict[str, List[str]] = {k: list(v) for k, v in _DEFAULT_PROMPT_PATTERNS.items()}
    path = _prompt_patterns_path()
    try:
        loaded = json.loads(path.read_text())
        for key in _DEFAULT_PROMPT_PATTERNS:
            pats = loaded.get(key)
            if isinstance(pats, list) and pats and all(isinstance(p, str) for p in pats):
                data[key] = pats
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001 - bad JSON / bad regex list → keep defaults
        logger.warning("console: invalid prompt_patterns.json (%s) — using built-in defaults", e)
    compiled: Dict[str, "re.Pattern"] = {}
    for key, pats in data.items():
        try:
            compiled[key] = re.compile("|".join(f"(?:{p})" for p in pats))
        except re.error as e:  # a bad pattern in the file → fall back for that family
            logger.warning("console: bad regex in prompt_patterns.json[%s] (%s) — using default", key, e)
            compiled[key] = re.compile("|".join(f"(?:{p})" for p in _DEFAULT_PROMPT_PATTERNS[key]))
    return compiled


_PROMPTS = load_prompt_patterns()
_LOGIN_PROMPT = _PROMPTS["login_prompt"]
_PASSWORD_PROMPT = _PROMPTS["password_prompt"]
_SHELL_PROMPT = _PROMPTS["shell_prompt"]

# Console lines are usually silent until they receive a keystroke: a device sits
# idle at a prompt and emits nothing on its own (unless it happens to be booting).
# So we actively wake the line by sending Enter (CR) — an initial CRLF plus a few
# more bare CRs — until a login/password/shell prompt appears. Many devices only
# redraw their prompt on a fresh CR, so this also turns "output but no prompt"
# into a detectable prompt without hammering (bounded attempt count).
_LOGIN_NUDGES = 4          # extra CRs after the initial CRLF banner read
_NUDGE_SECS = 1.2          # per-nudge read window

# Universal, READ-ONLY discovery commands used to coax an identifying banner out
# of a device sitting at a LIVE console that presented no login prompt and no
# recognizable vendor yet (direct-console gear, no auth). Broad vendor coverage;
# harmless/ignored where unsupported. Tried in order, stopping as soon as the
# vendor is recognized.
_DISCOVERY_COMMANDS = ("show version", "display version", "show system",
                       "get system status", "uname -a", "cat /etc/os-release")

# Pager prompts ("--More--", "---(more)---", "<--- More --->") — advanced by
# sending a space so we capture the full command output, not just one screen.
_PAGER = re.compile(r"(?i)(--+\s*more\s*--+|-{2,}\(?\s*more[^)]*\)?-{2,}|<-+\s*more\s*-+>)")

# Well-known factory-default credentials, tried (in order, once each) AFTER any
# operator-supplied credentials when a device sits at a login prompt and the
# stored credentials don't work. Deliberately short + conservative to avoid
# tripping account lockout — the most common console/network-gear defaults only.
FACTORY_DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": ""},
    {"username": "admin", "password": "password"},
    {"username": "cisco", "password": "cisco"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": ""},
    {"username": "manager", "password": "friend"},   # HPE/Aruba ProCurve
    {"username": "admin", "password": "aruba123"},    # Aruba
    {"username": "ubnt", "password": "ubnt"},          # Ubiquiti
]


def merge_credentials(*groups: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    """Concatenate credential lists, dropping duplicate ``(username, password)``
    pairs while preserving order (operator creds first, then any fallbacks)."""
    seen = set()
    out: List[Dict[str, str]] = []
    for g in groups:
        for c in (g or []):
            u, p = str(c.get("username", "")), str(c.get("password", ""))
            if (u, p) in seen:
                continue
            seen.add((u, p))
            out.append({"username": u, "password": p})
    return out

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
                if not m:
                    continue
                val = ((m.group(1) if m.lastindex else None) or m.group(0) or "").strip()
                if val:
                    identity[key] = val
    if prof and prof.get("family") and prof["name"] != "linux":
        identity["type"] = infer_device_type(identity.get("model"), prof["family"])
    if not identity.get("hostname"):
        # Glean a hostname from the last shell/CLI prompt we saw.
        hn = prompt_hostname(text)
        if hn:
            identity["hostname"] = hn
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


def _read_command_output(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                         until: List[re.Pattern], cmd_secs: float, max_pages: int = 30) -> str:
    """Read one command's output, auto-advancing pagers (``--More--``) by sending
    a space so the full output is captured instead of a single screen."""
    out = _read_until(read_fn, until, cmd_secs)
    pages = 0
    while pages < max_pages and _PAGER.search(out[-120:]):
        write_fn(b" ")
        out += _read_until(read_fn, until, cmd_secs)
        pages += 1
    return out


def _elicit_identity_banner(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                            transcript: str, cmd_secs: float = 2.5):
    """Responsive console, no vendor recognized yet and NO login prompt showing:
    send a few universal read-only discovery commands to force out an identifying
    banner. Stops as soon as :func:`detect_vendor` recognizes the device. Returns
    ``(transcript, profile, outputs)`` — a direct-console device (no auth) can be
    identified without ever seeing a login/password prompt."""
    outputs: Dict[str, str] = {}
    profile = detect_vendor(transcript)
    if profile:  # passive banner/prompt already identifies it — send nothing
        return transcript, profile, outputs
    for cmd in _DISCOVERY_COMMANDS:
        write_fn((cmd + "\r").encode())
        out = _read_command_output(read_fn, write_fn, [_SHELL_PROMPT], cmd_secs)
        outputs[cmd] = out
        transcript += "\n" + out
        profile = detect_vendor(transcript)
        if profile:
            break
    return transcript, profile, outputs


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
                            "bytes": 0, "any_output": False, "nudges": 0}

    def _observe(tail: str) -> None:
        if _LOGIN_PROMPT.search(tail):
            diag["login_prompt_seen"] = True
        if _PASSWORD_PROMPT.search(tail):
            diag["password_prompt_seen"] = True
        if _SHELL_PROMPT.search(tail):
            diag["shell_prompt_seen"] = True

    prompts = [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT]

    def _has_prompt(tail: str) -> bool:
        return bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)
                    or _SHELL_PROMPT.search(tail))

    # Wake the line. A console device typically emits nothing until it receives a
    # keystroke, so send an initial CRLF (+ banner read to catch any streaming
    # boot output), then nudge with a bare CR up to _LOGIN_NUDGES more times until
    # a prompt shows. This is what elicits a prompt from an idle, already-booted
    # device instead of sitting forever on a silent line.
    write_fn(b"\r\n")
    transcript = _read_until(read_fn, prompts, banner_secs)
    _observe(transcript[-200:])
    while diag["nudges"] < _LOGIN_NUDGES and not _has_prompt(transcript[-200:]):
        diag["nudges"] += 1
        write_fn(b"\r")
        transcript += _read_until(read_fn, prompts, _NUDGE_SECS)
        _observe(transcript[-200:])
    diag["bytes"] = len(transcript)
    diag["any_output"] = bool(transcript.strip())
    tail = transcript[-200:]
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
                              "hostname_source": "", "diag": {}}
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
    tail = transcript[-200:]
    at_login_prompt = bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail))

    # 2b. Direct-console gear shows no banner until prodded and may never present
    #     a login prompt. If we're on a LIVE line (got output, not sitting at a
    #     login/password prompt) but haven't recognized the vendor, actively run a
    #     few universal read-only discovery commands to coax out an identifying
    #     banner — i.e. try the show commands even without a username/password.
    if not profile and not at_login_prompt and diag.get("any_output"):
        transcript, profile, disc = _elicit_identity_banner(read_fn, write_fn, transcript)
        result["banner"] = transcript[-4000:]
        if any((v or "").strip() for v in disc.values()):
            # The console answered our commands → it's usable without auth.
            result["logged_in"] = True
            diag["console_usable"] = True
            diag["discovery_cmds"] = list(disc.keys())
            result["diag"] = _login_diag(diag, transcript, credentials)

    if not profile:
        # Unknown vendor, but if we reached a usable shell/CLI prompt (e.g. a
        # logged-in device or an open console) its prompt still names the box —
        # glean it so the port shows a real name instead of the USB adapter
        # string. Login/password prompts don't match, so this stays empty when
        # we never got in. The LLM-driven identify path can still add vendor/model.
        hn = prompt_hostname(transcript)
        if hn:
            result["identity"]["hostname"] = hn
            result["hostname_source"] = "prompt"
        return result
    result["vendor"] = profile["name"]
    if profile.get("family") and profile["name"] != "linux":
        # A recognized network device can report its role (Switch/…) even while
        # login-locked; refined to a concrete type once we read a model below.
        # (linux matches a bare "login:" — too weak to claim "Server" unauth'd.)
        result["identity"]["type"] = profile["family"]

    # If a login prompt is still showing (couldn't authenticate), stop here.
    tail = transcript[-200:]
    if not result["logged_in"] and (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
        return result

    # 3. Run the read-only identity commands + capture output (pager-aware).
    outputs: Dict[str, str] = {}
    for spec in profile["commands"]:
        cmd = spec["cmd"]
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_command_output(read_fn, write_fn, [profile["prompt"]], cmd_secs)
    result["outputs"] = outputs
    result["identity"] = parse_identity(profile, outputs)
    if profile.get("family"):
        # Concrete role from the model (e.g. Juniper SRX → Firewall), else the
        # profile's default family.
        result["identity"]["type"] = infer_device_type(
            result["identity"].get("model"), profile["family"])
    if result["identity"].get("hostname"):
        result["hostname_source"] = "command"  # parsed from a show/display output
    else:
        # No hostname from the identity commands (e.g. an ArubaOS-Switch that
        # rejects them) — fall back to the device's own CLI prompt name.
        hn = prompt_hostname(transcript)
        if hn:
            result["identity"]["hostname"] = hn
            result["hostname_source"] = "prompt"  # gleaned from the CLI prompt
    return result


def _sanitize_tail(text: str, n: int = 240) -> str:
    """A short, printable tail of a transcript for troubleshooting telemetry —
    terminal escapes stripped and remaining control bytes collapsed to spaces so
    it renders safely in the UI/logs."""
    tail = sanitize_console_text(text or "")[-n:]
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
        d["reason"] = ("no output after %d Enter nudge(s) — silent line, wrong "
                       "baud, or dead/one-way cable" % (int(d.get("nudges", 0)) + 1))
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
