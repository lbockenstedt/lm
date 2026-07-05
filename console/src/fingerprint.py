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
                              "credential_index": None, "identity": {}, "outputs": {}}
    # 1. Wake the line + capture the banner/prompt.
    write_fn(b"\r\n")
    banner = _read_until(read_fn, [re.compile(r"login:|[Uu]sername:|[Pp]assword:"),
                                   re.compile(r"[>#$]\s*$")], banner_secs)
    result["banner"] = banner[-4000:]
    profile = detect_vendor(banner)
    if not profile:
        return result
    result["vendor"] = profile["name"]

    # 2. Log in if a login/password prompt is showing (try each credential once).
    tail = banner[-200:]
    at_login = bool(profile["login_prompt"].search(tail) or profile["password_prompt"].search(tail))
    if at_login and credentials:
        for idx, cred in enumerate(credentials):
            write_fn((cred.get("username", "") + "\r").encode())
            out = _read_until(read_fn, [profile["password_prompt"], profile["prompt"]], 3.0)
            if profile["password_prompt"].search(out[-200:]):
                write_fn((cred.get("password", "") + "\r").encode())
                out = _read_until(read_fn, [profile["prompt"], profile["login_prompt"],
                                            profile["password_prompt"]], 4.0)
            tail2 = out[-200:]
            if profile["prompt"].search(tail2) and not (
                    profile["login_prompt"].search(tail2) or profile["password_prompt"].search(tail2)):
                result["logged_in"] = True
                result["credential_index"] = idx
                break
    else:
        # Already at an exec prompt (no auth) — treat as usable.
        result["logged_in"] = bool(profile["prompt"].search(tail))

    if not result["logged_in"] and at_login:
        return result  # couldn't authenticate; stop (no re-hammering)

    # 3. Run the read-only identity commands + capture output.
    outputs: Dict[str, str] = {}
    for spec in profile["commands"]:
        cmd = spec["cmd"]
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_until(read_fn, [profile["prompt"]], cmd_secs)
    result["outputs"] = outputs
    result["identity"] = parse_identity(profile, outputs)
    return result
