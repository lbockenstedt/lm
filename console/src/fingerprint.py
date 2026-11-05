"""Read-only device fingerprinting for the Console role.

Auto-identify pipeline: scrape a banner, match it to a built-in vendor profile,
optionally log in with a credential list, run the profile's READ-ONLY identity
commands, and parse serial / MAC / mgmt-IP / model / hostname.

Safety: only commands from a matched profile's ``commands`` list are ever sent —
there is no free-form command path here, and every command is a read-only
``show``/``display``/``cat``. Pure helpers (:func:`detect_vendor`,
:func:`parse_identity`) import without pyserial so they are unit-testable.
"""
# ipaddress: validate device IPs; json: prompt pattern file; logging.
import ipaddress
import json
import logging
# os: env overrides; re: banners, prompts and field regexes; time: read windows.
import os
import re
import time
# Path for the pattern file; typing helpers.
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# VSF stack parsing helpers for Aruba switches.
from vsf_stack import at_standby_console, parse_show_version, parse_show_vsf

# Module logger (shared with the console spoke).
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



# Juniper's internal 128.0.0.0/16 network, never a management address.
_JUNIPER_INTERNAL_NET = ipaddress.IPv4Network("128.0.0.0/16")


def is_valid_device_ip(ip: str) -> bool:
    """Return True if ip is a usable unicast IPv4 device address.

    Rejects invalid, unspecified, loopback, multicast, broadcast, Juniper internal,
    class E and netmask-shaped values.
    """
    # Must parse as IPv4.
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    # Reject special-purpose addresses.
    if addr.is_unspecified or addr.is_loopback or addr.is_multicast or addr == ipaddress.IPv4Address('255.255.255.255'):
        return False
    # Juniper's internal routing-engine network (e.g. 128.0.0.1 on em/fxp
    # internal links) is never the device's reachable management address.
    # Reject Juniper's internal network.
    if addr in _JUNIPER_INTERNAL_NET:
        return False
    # Reject 224.0.0.0 and above (multicast/reserved).
    val = int(addr)
    if val >= 0xE0000000:
        return False
    # Reject netmask-shaped values (ones followed by zeros).
    inv = (~val) & 0xFFFFFFFF
    if (inv + 1) & inv == 0:
        return False
    return True


def sanitize_console_text(text: str) -> str:
    """Strip VT100/ANSI terminal escape sequences (CSI cursor moves, OSC, scroll
    regions, show/hide-cursor) and bare control bytes from raw console output so
    it is human-readable. Preserves tabs/newlines and normalizes CR/LF. Safe to
    run on partial captures. Used for the Capture view, LLM input and detection."""
    # Nothing to clean.
    if not text:
        return ""
    # Remove OSC, CSI and other escapes, then control characters.
    s = _ANSI_OSC.sub("", text)
    s = _ANSI_CSI.sub("", s)
    s = _ANSI_MISC.sub("", s)
    s = _CTRL_CHARS.sub("", s)
    # Normalise line endings and collapse runs of blank lines.
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
        # Besides the OS name, AOS-CX has markers that it shows WITHOUT ever
        # printing "AOS-CX". We need them because CX also prints "Invalid input:",
        # which the hp-procurve profile below matches. This profile is checked
        # first, so a CX switch is not tagged as ProCurve:
        #  * the login-history line 'User "admin" has logged in 3 times in the
        #    past 30 days' (AOS-CX only);
        #  * the default banner's "register your products ... asp.arubanetworks.com"
        #    followed by a "<host> login:" prompt (ArubaOS-Switch prints a similar
        #    banner but uses "Username:"/"Press any key", never "login:");
        #  * a product string "<SKU> <CX family>", e.g. "JL725A 6200F 24G ..." or
        #    "R8N85A 6000 48G ..." (ProCurve writes "2540-24G-4SFP+ JL354A" or
        #    "5406Rzl2 J9850A": family first, then SKU);
        #  * the factory-default hostname, which is the family number ("6300 login:").
        "match": re.compile(
            r"ArubaOS-CX|Aruba.*CX|AOS-CX|"
            r"User \"[^\"]+\" has logged in \d+ times? in the past|"
            r"asp\.arubanetworks\.com[\s\S]{0,300}?\blogin:|"
            r"\b(?:JL|R[0-9A-Z]{2})\d{2,3}A\s+(?:6[0-4]\d\d|8[34]\d\d|9300|10000)[A-Z]?\b|"
            r"(?:^|\s)(?:6[0-4]00|8[34]\d0|9300)\s+login:",
            re.I),
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
            # VSF stack state. Harmless on a standalone switch (it answers
            # "Topology : Standalone"), and it is the ONLY command a stack's
            # standby member will actually answer — see vsf_stack.py.
            {"cmd": "show vsf"},
            {"cmd": "show version"},
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
            # AOS-S (2530/2540/2930/…) answers "show system"; classic ProCurve
            # answers "show system-information". Both print "System Name : <host>"
            # + serial/MAC, so we try both (first non-empty match per field wins)
            # to cover the whole family — an AOS-S box rejects the latter with
            # "Invalid input", which is why the hostname was previously missed.
            {"cmd": "show system", "fields": {
                "serial": re.compile(r"Serial Number\s*:?\s*(\S+)", re.I),
                "mac": re.compile(r"Base MAC Addr\S*\s*:?\s*([0-9A-Fa-f:.\-]{12,17})", re.I),
                "hostname": re.compile(r"System Name\s*:?\s*(\S+)", re.I),
            }},
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
            # Anchor on the VLAN row's IP Config column (Manual, or DHCP —
            # printed as "DHCP/Bootp" on ProCurve/AOS-S) so the Default
            # Gateway line is never picked. [ \t]+ keeps the match on one row.
            # With several addressed VLANs the first one listed is stored, but
            # "ip" is reported in ambiguous_fields with every address in
            # ip_candidates so the hub can ask the LLM which is the device's.
            {"cmd": "show ip", "fields": {"ip": re.compile(
                r"(?:Manual|DHCP(?:/Bootp)?)[ \t]+(?:(?:True|False)[ \t]+)?"
                r"(\d{1,3}(?:\.\d{1,3}){3})\b", re.I)}},
            # AOS-S VSF. A non-stacking model just replies "Invalid input: vsf".
            {"cmd": "show vsf"},
            {"cmd": "show version"},
        ],
        "config": {"enter": "configure", "exit": "exit", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        # Juniper Session Smart Router (SSR, formerly 128 Technology). It runs on
        # Oracle Linux, so at its OS login it looks exactly like a Linux server
        # ("Oracle Linux Server 7.9 / Kernel ... on an x86_64 / <host> login:"),
        # and once logged in as admin it shows the PCLI prompt
        # "admin@node0.<router>#". Both used to be reported as "linux" (and the
        # linux profile's bare-line field regexes then stored the PCLI prompt as
        # a serial number). No plain Linux servers sit on these console lines,
        # so an Oracle Linux banner is taken as an SSR. Checked before
        # juniper-junos, whose "juniper" match would otherwise claim SSR text.
        "name": "juniper-ssr",
        "match": re.compile(
            r"128T|Session Smart|\bSSR\s?\d{3,4}\b|Oracle Linux Server|"
            r"[\w.\-]+@node\d+\.[\w.\-]+[#>]", re.I),
        "family": "Firewall/Router",
        "prompt": re.compile(r"[\w.\-]+@[\w.\-]+(?::[\w.\-/~]*)?[#$>]\s*$"),
        "login_prompt": re.compile(r"login:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        # Identity comes from the PCLI prompt (node + router name). The version
        # is captured for the transcript/LLM path; no fields are parsed from it.
        "commands": [
            {"cmd": "show system version"},
        ],
        "config": {"enter": None, "exit": None, "save": None, "show_running": None},
    },
    {
        "name": "juniper-junos",
        # JUNOS runs on FreeBSD, and a device sitting at a bare login prompt
        # prints no vendor string at all — only "<hostname> (ttyu0)" (or
        # "Amnesiac (ttyu0)" when it has no configured hostname yet). Without
        # those markers a login-locked SRX/EX falls through to the `linux`
        # profile, whose match is a bare "login:", and the port is reported as a
        # Linux server. Keep them ahead of that catch-all.
        "match": re.compile(
            r"JUNOS|Junos:|Juniper Networks|juniper|"
            r"Amnesiac\s*\(tty|\(ttyu\d+\)|"
            # SRX chassis-cluster / EX virtual-chassis status line printed
            # above every prompt, e.g. "{primary:node0}" or "{master:0}".
            r"\{(?:primary|secondary|master|backup|linecard|hold):[\w\-]+\}", re.I),
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
                # "Hostname: xxx" from `show version` output, OR the FreeBSD tty
                # banner "FreeBSD/i386 (xxx) (ttyu0)" that a bare, never-logged-in
                # login prompt keeps reprinting (see the profile's "match"
                # comment above) — that banner is often the ONLY hostname signal
                # we ever see for a login-locked box. "Amnesiac" means the
                # device has no hostname configured, so it's excluded rather
                # than reported as a literal hostname.
                "hostname": re.compile(
                    r"(?:Hostname\s*:?\s*|FreeBSD/\S+\s+\()"
                    r"((?!Amnesiac\b)[\w.\-]+)(?=\)\s*\(tty|\s|$)", re.I),
            }},
            {"cmd": "show chassis hardware", "fields": {
                "serial": re.compile(r"^Chassis\s+(\S+)", re.I | re.M),
            }},
            {"cmd": "show interfaces terse", "fields": {"ip": re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})")}},
        ],
        "config": {"enter": "configure", "exit": "exit", "save": "commit",
                   "show_running": "show configuration"},
    },
    {
        # ArubaOS 8 Mobility Controller / Gateway (and legacy controllers). These
        # show NO vendor banner at rest — only their distinctive parenthesised
        # prompt "(hostname) #" / "(hostname) *#" (the * = pending config) — so we
        # recognise them by that prompt shape (a space before the #/> tells it
        # apart from a Cisco "host(config)#", which has no space and a hostname
        # glued to the paren). Once matched we pull model + serial so the box can
        # be found in NetBox and physically in the rack.
        # Also recognised before login: the bare "User:" login prompt (CX and
        # Junos say "login:", ProCurve and Cisco say "Username:"), and the
        # factory-default setup dialog ("Enter Option (partial string is
        # acceptable):", "Auto-provisioning is in progress").
        "name": "aruba-os",
        "match": re.compile(
            r"ArubaOS(?!-?CX)|Aruba Operating System|"
            r"(?:^|[\r\n\s])\([\w][\w.\-]{1,62}\)\s+\*?\s*[>#]|"
            r"(?:^|\s)User:\s*$|partial string is acceptable|"
            r"Auto-provisioning is in progress", re.I),
        "family": "Gateway/Controller",
        "prompt": re.compile(r"\([\w.\-]+\)\s*(?:\([\w .\-]+\)\s*)?\*?\s*[>#]\s*$"),
        "login_prompt": re.compile(r"[Uu]ser:\s*$|login:\s*$"),
        "password_prompt": re.compile(r"[Pp]assword:\s*$"),
        "pager": b" ",
        "commands": [
            {"cmd": "no paging"},
            {"cmd": "show version", "fields": {
                # "ArubaOS (MODEL: A7010), Version 8.6.0.7" — model + OS version.
                "model": re.compile(r"MODEL:\s*([\w\-]+)", re.I),
                "os": re.compile(r"ArubaOS[^\n]*?Version\s+([\w.\-]+)", re.I),
            }},
            {"cmd": "show inventory", "fields": {
                # "System Serial#      : CV0001234" (chassis serial for NetBox).
                "serial": re.compile(
                    r"(?:System Serial#|Chassis Serial#|Serial Number)\s*:?\s*([A-Za-z0-9\-]+)", re.I),
                # Fallback model if 'show version' didn't carry it: "SC Model# : A7010".
                "model": re.compile(r"(?:SC |Card )?Model#\s*:?\s*([\w\-]+)", re.I),
            }},
            {"cmd": "show ip interface brief", "fields": {"ip": re.compile(r"(?:vlan|mgmt|loopback)\s+\S*\s*(\d{1,3}(?:\.\d{1,3}){3})", re.I)}},
        ],
        "config": {"enter": "configure terminal", "exit": "exit", "save": "write memory",
                   "show_running": "show running-config"},
    },
    {
        "name": "linux",
        # Needs real Linux evidence: a distro/kernel banner or a "user@host:~$"
        # shell prompt. A bare "login:" used to be enough, but AOS-CX switches
        # (and the SSR's OS login) also show just "<host> login:", so CX
        # switches were reported as Linux servers. An unrecognised bare login
        # prompt now stays unknown until a login or banner identifies it.
        "match": re.compile(
            r"Linux \S+ \d|Ubuntu|Debian|CentOS|[\w.\-]+@[\w.\-]+:[~/][^\n]*[#$]\s*$", re.I),
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
    # Keep only hex digits; need exactly 12.
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac or "")
    if len(hexs) != 12:
        return ""
    # Lower-case pairs joined by colons.
    return ":".join(hexs[i:i + 2] for i in range(0, 12, 2)).lower()


# Words that show up where a hostname is parsed but are never a device's name:
# prompt/menu words, the echo of the linux profile's own `hostname` command, the
# AOS-CX VSF member prompt "standby#", the user part of "admin#"/"root#" and
# Junos's "Amnesiac" (no hostname configured). Live ports showed hostnames
# literally "hostname" and "standby" before these were filtered.
_PLACEHOLDER_HOSTNAMES = frozenset({
    "more", "username", "password", "login", "config", "hostname", "standby",
    "user", "admin", "root", "last", "amnesiac",
    "localhost", "none", "(none)", "unknown",
})


def is_placeholder_hostname(name: Any) -> bool:
    """True if ``name`` is empty or a word a parse glitch captures as a name."""
    # Blank or a known placeholder word.
    h = str(name or "").strip().lower()
    return not h or h in _PLACEHOLDER_HOSTNAMES


# A serial number is a single alphanumeric token. Anything else (a captured
# prompt such as "admin@node0.00900bef026b#", an error message) is junk; it
# would also become a bogus "serial:..." device key in devices.json.
_SERIAL_SHAPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9\-_./]*")


def scrub_identity(identity: Dict[str, Any]) -> Dict[str, Any]:
    """Copy of ``identity`` without values that are provably not identity: a
    placeholder hostname or a serial that is not serial-shaped. Applied to new
    results AND to identity loaded from older ports.json/devices.json records,
    so junk stored by earlier versions stops being shown and matched on."""
    # Work on a copy.
    out = dict(identity or {})
    # Drop a placeholder hostname.
    host = str(out.get("hostname") or "").strip()
    if "hostname" in out and is_placeholder_hostname(host):
        del out["hostname"]
    # Drop a serial with characters a serial cannot have.
    serial = str(out.get("serial") or "").strip()
    if serial and not _SERIAL_SHAPE.fullmatch(serial):
        del out["serial"]
    return out


# Vendor verdicts differ in strength. "linux" is the weakest (generic Linux
# text, which the SSR also shows), and "hp-procurve" can be a CX that has not
# yet printed a CX-only marker (both print "Invalid input:"). These rules stop a
# later weaker verdict from overwriting a confident one, e.g. a CX re-detected
# as "linux" from a bare login prompt.
def vendor_should_replace(current: Optional[str], candidate: Optional[str]) -> bool:
    """True if a new ``candidate`` vendor verdict should replace ``current``."""
    # No change, or nothing new.
    if not candidate or candidate == current:
        return False
    # Anything beats unknown.
    if not current:
        return True
    # Never downgrade to linux.
    if candidate == "linux":
        return False
    # Never turn aruba-cx into hp-procurve.
    if current == "aruba-cx" and candidate == "hp-procurve":
        return False
    return True


def vendor_is_upgrade(current: Optional[str], candidate: Optional[str]) -> bool:
    """True if ``candidate`` is strictly more specific than an unknown/"linux"
    ``current``, so it may correct even a logged-in (authoritative) verdict."""
    # Linux and empty never count as upgrades.
    if not candidate or candidate == "linux":
        return False
    # Only an unknown or linux verdict can be upgraded.
    return current in (None, "", "linux")


# AOS-CX evidence that cannot come from a neighbour's LLDP/CDP text: the
# device's own model is a CX product string ("JL725A 6200F 24G CL4 ..."), or the
# console shows the AOS-CX login-history line. Used to correct ports that an
# older version stored as hp-procurve (CX also prints "Invalid input:").
_CX_MODEL = re.compile(r"^\s*(?:JL|R[0-9A-Z]{2})\d{2,3}A\s+(?:6[0-4]\d\d|8[34]\d\d|9300|10000)", re.I)
# Login-history banner that only AOS-CX prints.
_CX_LOGIN_HISTORY = re.compile(r"User \"[^\"]+\" has logged in \d+ times? in the past", re.I)


def is_cx_misfiled_as_procurve(vendor: Optional[str], identity: Dict[str, Any], text: str) -> bool:
    """True if a port stored as hp-procurve (or still unknown) is in fact an
    AOS-CX switch, e.g. a CX whose model "JL725A 6200F ..." was read but whose
    vendor was never set."""
    # Only hp-procurve or unknown ports qualify.
    if vendor not in (None, "", "hp-procurve"):
        return False
    # CX model in the identity, or CX login history in the text.
    return bool(_CX_MODEL.search(str((identity or {}).get("model") or ""))
                or _CX_LOGIN_HISTORY.search(sanitize_console_text(text or "")))


def _strip_echo_and_prompts(text: str, cmd: str, prompt_rx: Optional["re.Pattern"]) -> str:
    """Command output without the echoed command line or prompt lines.

    The linux profile's fields are whole-line captures (``^(\\S+)$``), so the
    echo of ``hostname`` was stored as the hostname "hostname", and an SSR PCLI
    prompt line "admin@node0.<router>#" after a rejected ``cat`` was stored as
    the serial number."""
    # Keep each line unless it is the echoed command or a prompt.
    keep = []
    for line in (text or "").splitlines():
        s = line.strip()
        if s and (s == cmd or s.endswith(" " + cmd)):
            continue
        if s and prompt_rx is not None and prompt_rx.search(s):
            continue
        keep.append(line)
    # Rejoin the kept lines.
    return "\n".join(keep)


def detect_vendor(text: str) -> Optional[Dict[str, Any]]:
    """Return the first profile whose ``match`` hits the banner/prompt text.
    Escape sequences are stripped first so a full-screen menu CLI (e.g. ArubaOS-S,
    whose prompt/errors are interleaved with cursor-move codes) still matches."""
    # Strip escapes, then return the first profile whose pattern matches.
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
    # Return the first model rule that matches.
    if model:
        for rx, kind in _TYPE_BY_MODEL:
            if rx.search(model):
                return kind
    # Else the profile's family.
    return family_default or ""


def _ip_candidates(rx: "re.Pattern", text: str) -> List[Tuple[str, str]]:
    """Every distinct valid device IP ``rx`` yields in ``text``, in order of
    appearance, each paired with the (whitespace-collapsed) line it came from —
    e.g. ``("172.16.50.20", "MGMT | Manual 172.16.50.20 255.255.255.0 No No")``.
    Candidates must pass ``is_valid_device_ip`` (masks / junk never count).

    Only the ``ip`` field is tracked this way: 2+ distinct device addresses (a
    switch with several addressed VLANs/interfaces) is real-world ambiguity. For
    other fields multiple regex hits are a regex-scoping artifact, not competing
    candidates, so they keep plain first-valid-match behavior."""
    # Results, values already seen, and the text.
    out: List[Tuple[str, str]] = []
    seen = set()
    text = text or ""
    # Each regex match.
    for m in rx.finditer(text):
        # Same group handling as the first-match loops below.
        val = ((m.group(1) if m.lastindex else None) or m.group(0) or "").strip()
        if not val or not is_valid_device_ip(val) or val in seen:
            continue
        seen.add(val)
        # Line containing the match, whitespace collapsed and capped.
        start = text.rfind("\n", 0, m.start()) + 1
        end = text.find("\n", m.end())
        line = " ".join(text[start:end if end != -1 else len(text)].split())
        out.append((val, line[:160]))
    # All valid, distinct candidates.
    return out


def ip_ambiguity(cands: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Result keys for a multi-candidate ``ip`` (``{}`` when 0-1 candidates):
    ``ambiguous_fields: ["ip"]``, ``ip_candidates`` (the distinct values, first =
    the stored ``identity["ip"]``) and ``ip_candidate_context`` (value → source
    line) so the hub can ask the LLM which one is the device's own address."""
    # 0 or 1 candidates is not ambiguous.
    if len(cands) < 2:
        return {}
    # Flag ip as ambiguous with its candidates and source lines.
    return {"ambiguous_fields": ["ip"],
            "ip_candidates": [ip for ip, _ in cands],
            "ip_candidate_context": {ip: line for ip, line in cands}}


def _extract_profile_fields(profile: Dict[str, Any], text: str,
                            ip_candidates: Optional[List[Tuple[str, str]]] = None
                            ) -> Dict[str, str]:
    """Apply a matched vendor profile's identity-field regexes across an arbitrary
    text blob (a full identify transcript or a passive capture), returning the
    fields found. The profile's regexes anchor on specific, low-ambiguity strings
    ("Serial Number", "Base MAC Addr", "System Name", "Chassis", …), so matching
    them anywhere in a capture is safe. This is what lets us recover identity when
    the data appeared somewhere OTHER than the dedicated identity command — e.g.
    an ArubaOS-Switch that answers ``show system`` during banner discovery but
    rejects the profile's exact ``show system-information`` command. Skips the
    ``linux`` profile, whose bare ``^(\\S+)$`` field regexes would match garbage
    across arbitrary scrollback. MAC is normalized when present.

    The first valid match per field is the stored value. If ``ip_candidates``
    (a list) is passed, it is filled with every distinct valid ``ip`` candidate
    (see ``_ip_candidates``) for the regex that supplied ``found["ip"]``, so the
    caller can flag a multi-address device instead of trusting the first hit."""
    # Fields found so far.
    found: Dict[str, str] = {}
    # Skip the linux profile.
    if not profile or profile.get("name") == "linux":
        return found
    # Every field regex of every command.
    for spec in profile.get("commands", []):
        for key, rx in (spec.get("fields") or {}).items():
            # First match per field wins.
            if key in found:
                continue
            # IP: collect all valid candidates and keep the first.
            if key == "ip":
                cands = _ip_candidates(rx, text)
                if cands:
                    found[key] = cands[0][0]
                    if ip_candidates is not None:
                        ip_candidates[:] = cands
                continue
            # Other fields: first non-empty match.
            for m in rx.finditer(text or ""):
                val = ((m.group(1) if m.lastindex else None) or m.group(0) or "").strip()
                if val:
                    found[key] = val
                    break
    # Normalise the MAC.
    if found.get("mac"):
        found["mac"] = normalize_mac(found["mac"]) or found["mac"]
    return found


def parse_identity(profile: Dict[str, Any], outputs: Dict[str, str],
                   ip_candidates: Optional[List[Tuple[str, str]]] = None) -> Dict[str, str]:
    """Apply a profile's per-command field regexes to captured command output.
    ``outputs`` maps command → its captured text. First non-empty match wins per
    field; MAC is normalized. If ``ip_candidates`` (a list) is passed, it is
    filled with every distinct valid ``ip`` candidate from the command output
    that supplied ``identity["ip"]`` (see ``_extract_profile_fields``)."""
    # Fields found so far.
    identity: Dict[str, str] = {}
    # For each command, strip its echo and prompt lines from the output.
    for spec in profile.get("commands", []):
        fields = spec.get("fields") or {}
        text = _strip_echo_and_prompts(outputs.get(spec["cmd"], ""), spec["cmd"],
                                       profile.get("prompt"))
        # Apply each of the command's field regexes.
        for key, rx in fields.items():
            # First match per field wins.
            if key in identity:
                continue
            # IP: collect all valid candidates and keep the first.
            if key == "ip":
                cands = _ip_candidates(rx, text)
                if cands:
                    identity[key] = cands[0][0]
                    if ip_candidates is not None:
                        ip_candidates[:] = cands
                continue
            # Other fields: first non-empty match.
            for m in rx.finditer(text):
                # Use the first capturing group, but tolerate alternation branches
                # where group 1 didn't participate (returns None) — fall back to the
                # whole match so a valid hit is never dropped (or worse, crashes).
                val = ((m.group(1) if m.lastindex else None) or m.group(0) or "").strip()
                if val:
                    identity[key] = val
                    break
    # Normalise the MAC, then drop junk values.
    if identity.get("mac"):
        identity["mac"] = normalize_mac(identity["mac"]) or identity["mac"]
    return scrub_identity(identity)


def detect_stack(outputs: Dict[str, str], transcript: str = "") -> Dict[str, Any]:
    """Build the port's VSF stack record from its captured command output.

    A stack spans several chassis but is administered from exactly one of them
    (the conductor), so an operator needs to know which serial line is which.
    ``conductor_mac`` is the cross-reference key: the hub matches it against the
    learned MAC of every other console port to point at the conductor's port.

    Returns {} for a device that is not stacked, so the field is simply absent
    from the probe rather than carrying a misleading all-empty record.
    """
    # Use the first non-empty output from a "vsf" command.
    vsf_text = ""
    for cmd, out in (outputs or {}).items():
        if "vsf" in cmd.lower() and (out or "").strip():
            vsf_text = out
            break
    # Parse its member table.
    info = parse_show_vsf(vsf_text)
    # A bare "standby#" prompt is proof of a stack even when the reduced
    # `show vsf` was rejected or never ran.
    # A standby member's console also counts as a stack.
    standby = at_standby_console(transcript or "")
    if not info["members"] and not standby:
        return {}

    # Software version: from a version command's output, else from the transcript.
    version = ""
    for cmd, out in (outputs or {}).items():
        if "version" in cmd.lower() and (out or "").strip():
            version = parse_show_version(out)
            if version:
                break
    if not version and transcript:
        version = parse_show_version(transcript)

    # Find the conductor's MAC and this member's MAC.
    conductor_mac = ""
    local_mac = ""
    for member in info["members"]:
        if member["role"] == "conductor" and member["mac"]:
            conductor_mac = member["mac"]
        if member["member_id"] == info["local_member_id"]:
            local_mac = member["mac"]

    # The stack record.
    return {
        "is_stack": bool(info["is_stack"] or standby),
        "topology": info["topology"],
        "stack_mac": info["stack_mac"],
        "role": info["local_role"] or ("standby" if standby else ""),
        "member_id": info["local_member_id"],
        "local_mac": local_mac,
        "conductor_mac": conductor_mac,
        "sw_version": version,
        "members": [dict(m) for m in info["members"]],
    }


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
    """Return the prompt_patterns.json path (CONSOLE_PROMPT_PATTERNS env or next to this file)."""
    # Environment override, else the file next to this module.
    return Path(os.environ.get("CONSOLE_PROMPT_PATTERNS")
                or (Path(__file__).parent / "prompt_patterns.json"))


# Built-in hostname prompt regexes (group 1 is the hostname), tried in order.
_DEFAULT_HOSTNAME_PROMPTS: List[str] = [
    # Linux shell: user@host:~$ / user@host:/path#
    r"(?:^|\r|\n)[\w.\-]+@([\w.\-]+):[\w.\-/~]*[#$]\s*$",
    # JUNOS operational/config-mode prompt: "user@hostname>" / "user@hostname#"
    # / "user@hostname%" — no colon, unlike the Linux shell shape above, so it
    # needs its own pattern (the generic "host>" one below never matches: the
    # "@" isn't in its hostname character class, and there's no bare-word
    # alternative starting position once the run breaks on "@"). This is
    # often the ONLY hostname signal in a passive capture for a box that's
    # already logged in but never printed "show version" / a tty banner —
    # see e.g. BO-BOMm-CRFW01, whose scrollback carries only "show interfaces
    # terse" output and console syslog spam between prompts.
    r"(?:^|\r|\n)\s*[\w.\-]+@([\w.\-]+)[>#%]\s*$",
    # ArubaOS controller/gateway/Instant: "(hostname) #", "(hostname) *#"
    # (the * = pending config), optionally with a config-context paren:
    # "(hostname) (config) #". Hostname is the FIRST parenthesised token.
    r"(?:^|\r|\n|\s)\(([\w][\w.\-]{1,62})\)\s*(?:\([\w .\-]+\)\s*)?\*?\s*[>#]",
    # Generic vendor CLI: hostname immediately followed by > or #
    r"(?:^|\r|\n)\s*([\w][\w.\-]{1,62})[>#]\s*$",
]
# Any colon-separated MAC address.
_GENERIC_MAC = re.compile(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b")
# Generic-pass IP fallback: an unlabeled bare IPv4 anywhere in scrollback is as
# likely to be a firmware version, gateway, or syslog server as the device's
# own address, so this requires an explicit "IP address"/"IPv4 address"/"inet"
# label (any run of dots/spaces/colon between label and value, e.g.
# "IP Address.....: x"). The `\b` before "inet" keeps it from matching inside
# words like "cabinet".
_GENERIC_IP_LABEL = re.compile(
    r"\b(?:ip(?:v4)?\s*address|inet)\b[.\s]*:?[.\s]*(\d{1,3}(?:\.\d{1,3}){3})", re.I)


def load_hostname_prompts() -> List["re.Pattern"]:
    """Compile the hostname-prompt matchers (each capturing the hostname in
    group 1), reading them from prompt_patterns.json[``hostname_prompt``] when
    present and falling back to the built-in defaults. Bad file / bad regex →
    defaults, so a malformed edit can never break hostname gleaning."""
    # Start with the defaults.
    pats: List[str] = list(_DEFAULT_HOSTNAME_PROMPTS)
    # Use the file's list when it is a non-empty list of strings.
    try:
        loaded = json.loads(_prompt_patterns_path().read_text())
        candidate = loaded.get("hostname_prompt")
        if isinstance(candidate, list) and candidate and all(isinstance(p, str) for p in candidate):
            pats = candidate
    except FileNotFoundError:
        pass
    except Exception as e:  # noqa: BLE001 - bad JSON → keep defaults
        logger.warning("console: invalid prompt_patterns.json hostname_prompt (%s) — using defaults", e)
    # Compile each pattern, skipping bad ones.
    compiled: List["re.Pattern"] = []
    for p in pats:
        try:
            compiled.append(re.compile(p))
        except re.error as e:  # skip a single bad pattern, keep the rest usable
            logger.warning("console: bad hostname_prompt regex %r (%s) — skipping", p, e)
    # Fall back to the defaults if nothing compiled.
    return compiled or [re.compile(p) for p in _DEFAULT_HOSTNAME_PROMPTS]


# Compiled hostname matchers, loaded once at import.
_HOSTNAME_PROMPTS = load_hostname_prompts()


def _prompt_hostname_with(patterns: List["re.Pattern"], text: str) -> str:
    """Core of :func:`prompt_hostname`, parameterised by the compiled pattern
    list so it can be unit-tested against an arbitrary (e.g. JSON-overridden)
    pattern set. First pattern that yields a non-placeholder candidate wins;
    within a pattern the LAST (most recent) match is kept."""
    # Strip escapes first.
    clean = sanitize_console_text(text or "")
    # Try each pattern; keep its last good match.
    for rx in patterns:
        cand = ""
        for m in rx.finditer(clean):
            c = (m.group(1) or "").strip()
            if c and not is_placeholder_hostname(c):
                cand = c
        # First pattern with a match wins.
        if cand:
            return cand
    return ""


def prompt_hostname(text: str) -> str:
    """Best-effort hostname from the LAST CLI/shell prompt in ``text`` (e.g. the
    ``MIA-SW-AOSS>`` prompt of an ArubaOS-Switch, ``(MIA-GW-02) *#`` on an Aruba
    controller/gateway, or ``user@host:~$`` on Linux). Terminal escapes are
    stripped first. Returns '' if none or a placeholder."""
    return _prompt_hostname_with(_HOSTNAME_PROMPTS, text)


# "<hostname> login:" — the only name a login-locked AOS-CX switch or SSR shows
# (e.g. "BO-SYDm-ACSW02 login:", "ar30260015 login:"). Kept separate from the
# CLI-prompt patterns above and used only as a last resort, after any real
# prompt. The last occurrence wins; placeholders ("Last login:") are skipped.
_LOGIN_BANNER_HOST = re.compile(r"(?:^|\s)([A-Za-z0-9][\w.\-]{1,62})[ \t]+login:")


def login_banner_hostname(text: str) -> str:
    """Hostname from the last "<host> login:" prompt in ``text``, or ''."""
    # Strip escapes and keep the last non-placeholder match.
    clean = sanitize_console_text(text or "")
    cand = ""
    for m in _LOGIN_BANNER_HOST.finditer(clean):
        if not is_placeholder_hostname(m.group(1)):
            cand = m.group(1)
    return cand

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
    # Privilege level, read off the prompt's last character. On Cisco IOS,
    # HPE/Aruba AOS-S and most network CLIs ">" is UNPRIVILEGED (user EXEC)
    # and "#" is PRIVILEGED (enable). Most identity `show` commands need
    # privileged mode, so landing on ">" means we must send `enable` first —
    # see _escalate_privilege. Deliberately NOT "$"/"%": those are UNIX shell
    # prompts where `enable` is meaningless.
    "unpriv_prompt": [r"\S>\s*$"],
    "priv_prompt": [r"\S#\s*$"],
    # A device refusing the enable escalation, split by CAUSE because the two
    # mean very different things. "unsupported" = there is no `enable` command
    # (">" already IS the top level on some AOS-S / appliance CLIs), so retrying
    # with another secret is pointless. "denied" = enable exists but the secret
    # was wrong, so the next secret is worth trying.
    "enable_unsupported": [
        r"(?i:invalid\s+(?:input|command))",
        r"(?i:unknown\s+command)",
        r"(?i:incomplete\s+command)",
        r"(?i:command\s+not\s+found)",
        r"(?i:ambiguous\s+command)",
        r"%\s*(?:Invalid|Unknown|Incomplete)",
    ],
    "enable_denied": [
        r"(?i:invalid\s+(?:password|secret))",
        r"(?i:access\s+denied)",
        r"(?i:authentication\s+fail(?:ed|ure))",
        r"(?i:bad\s+secrets?)",
        r"(?i:permission\s+denied)",
        r"(?i:password\s+incorrect)",
        r"(?i:incorrect\s+password)",
    ],
    # A NET-NEW device (esp. after a first login with a factory-default cred)
    # often forces a password SET/CHANGE before it will drop to a shell —
    # "Enter new password:", "Confirm new password:", "You must change your
    # password", "password has expired". These also end in "password:", so this
    # family is matched BEFORE password_prompt so we never type a credential into
    # a set-password field (identify is read-only — see _skip_forced_password_change).
    "new_password_prompt": [
        r"(?i:(?:enter|set|choose|create|type)\s+(?:a\s+)?new\s+password)\s*:?\s*$",
        r"(?i:new\s+password)\s*:?\s*$",
        r"(?i:(?:re-?type|retype|confirm|verify|re-?enter)\s+(?:new\s+)?password)\s*:?\s*$",
        r"(?i:(?:must\s+|please\s+)?change\s+(?:the\s+|your\s+)?password)",
        r"(?i:password\s+(?:change\s+required|must\s+be\s+changed|has\s+expired|expired))",
    ],
}


def load_prompt_patterns() -> Dict[str, "re.Pattern"]:
    """Compile the login/password/shell prompt matchers, reading pattern strings
    from prompt_patterns.json when present (falling back to the built-in defaults
    per family). Each family is an OR of its listed regexes, so operators can add
    a newly-observed prompt string to the JSON without touching code."""
    # Start with a copy of the defaults.
    data: Dict[str, List[str]] = {k: list(v) for k, v in _DEFAULT_PROMPT_PATTERNS.items()}
    path = _prompt_patterns_path()
    # Override each family whose file entry is a non-empty list of strings.
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
    # Join each family into one alternation regex; bad patterns fall back to defaults.
    compiled: Dict[str, "re.Pattern"] = {}
    for key, pats in data.items():
        try:
            compiled[key] = re.compile("|".join(f"(?:{p})" for p in pats))
        except re.error as e:  # a bad pattern in the file → fall back for that family
            logger.warning("console: bad regex in prompt_patterns.json[%s] (%s) — using default", key, e)
            compiled[key] = re.compile("|".join(f"(?:{p})" for p in _DEFAULT_PROMPT_PATTERNS[key]))
    return compiled


# Compiled prompt families, loaded once at import.
_PROMPTS = load_prompt_patterns()
# Shortcuts to each family's regex.
_LOGIN_PROMPT = _PROMPTS["login_prompt"]
_PASSWORD_PROMPT = _PROMPTS["password_prompt"]
_SHELL_PROMPT = _PROMPTS["shell_prompt"]
_NEW_PASSWORD_PROMPT = _PROMPTS["new_password_prompt"]
_UNPRIV_PROMPT = _PROMPTS["unpriv_prompt"]
_PRIV_PROMPT = _PROMPTS["priv_prompt"]
_ENABLE_UNSUPPORTED = _PROMPTS["enable_unsupported"]
_ENABLE_DENIED = _PROMPTS["enable_denied"]

# Lines a device emits ASYNCHRONOUSLY on the console, unrelated to the prompt:
# syslog records, kernel ring-buffer messages and Cisco-style facility messages.
# Juniper (SRX/EX) logs to the console out of the box, so one of these commonly
# lands right after "login:" — see _prompt_tail.
_ASYNC_NOISE = re.compile(
    r"^(?:"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}"   # syslog "Dec  9 10:22:01"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"          # ISO-8601 timestamp
    r"|\[\s*\d+\.\d+\]"                                  # kernel "[   12.345678]"
    r"|%[A-Z][A-Z0-9_\-]*:"                              # Cisco "%LINK-3-UPDOWN:"
    r"|<\d{1,3}>"                                        # syslog priority "<30>"
    r")")

# HPE/Aruba (AOS-S) and similar CLIs print "Console terminated due to
# inactivity." whenever an unattended session's OWN idle timer fires, and can
# refire it repeatedly every few seconds if nobody types — sometimes with no
# newline between repeats, gluing straight onto the prior text/prompt. That
# makes it unlike the rest of _ASYNC_NOISE, which is matched per LINE: this one
# must be stripped as a bare trailing PHRASE regardless of line boundaries, or
# a device that's actually sitting at a live prompt (just re-terminating a
# session nobody is using) looks indistinguishable from a genuinely hung boot —
# see check_line_responsive / the boot watcher's "confirm before condemning"
# active nudge, which relies on this same _prompt_tail to see the prompt.
_TRAILING_NOISE_PHRASE = re.compile(
    r"(?:\s*Console (?:session )?terminated due to inactivity\.?)+\s*$", re.I)


def _prompt_tail(text: str) -> str:
    """The tail a prompt matcher should run against, with trailing asynchronous
    log noise removed.

    Every prompt pattern is anchored (``...\\s*$``) so it only matches the LIVE
    prompt at the end of the buffer. A device that logs to its console can print
    a syslog/kernel line immediately after ``login:``, which scrolls the prompt
    up and makes the anchored pattern miss — the probe then concludes there is no
    recognizable prompt and never spends a credential, so no login is ever
    attempted. Juniper SRX/EX do this by default, and a chatty box re-logs after
    every nudge, so retrying alone does not help.

    Dropping the trailing noise lines exposes the still-current prompt underneath.
    Blank trailing lines are dropped too, which the anchored ``\\s*$`` already
    tolerated, so behaviour is unchanged on quiet lines.
    """
    # Only the last 400 characters matter.
    joined = (text or "")[-400:]
    # Line-based stripping only pops noise that starts its OWN line; an
    # idle-timeout banner can glue directly onto the prompt/prior repeat with no
    # newline at all, so also peel any trailing run of it off as a bare phrase.
    # Iterate until stable: removing either kind of noise can expose the other.
    # Repeat until nothing more is stripped.
    while True:
        # Split into lines and drop blank or log-noise lines from the end.
        lines = re.split(r"\r\n|\r|\n", joined)
        while len(lines) > 1 and (not lines[-1].strip()
                                  or _ASYNC_NOISE.match(lines[-1].lstrip())):
            lines.pop()
        # Remove trailing "console terminated" notices.
        stripped = _TRAILING_NOISE_PHRASE.sub("", "\n".join(lines))
        # Stable: done.
        if stripped == joined:
            return stripped
        joined = stripped


def looks_like_prompt(text: str) -> bool:
    """True if the tail of ``text`` shows a login / password / shell / CLI prompt
    — i.e. the device has finished booting and is ready to talk. Used by the boot
    watcher to decide a boot cycle reached a usable prompt (vs. hung mid-boot)."""
    # Check the cleaned tail for any kind of prompt.
    tail = _prompt_tail(sanitize_console_text(text or ""))
    return bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)
                or _SHELL_PROMPT.search(tail) or _SETUP_PROMPT.search(tail)
                or prompt_hostname(text))


# Interactive prompts a fully booted OS waits at that are not login or CLI
# prompts: the ArubaOS gateway/controller factory setup dialog ("Enter Option
# (partial string is acceptable):", "Enter System name [Aruba7008]:") and the
# ArubaOS-Switch "Press any key to continue". A gateway sitting at its setup
# wizard is booted, but these were not recognised, so it aged into "stuck".
_SETUP_PROMPT = re.compile(
    r"(?:partial string is acceptable\)|Enter System name[^\n]*|"
    r"Press any key to continue)\s*:?\s*$", re.I)

# Text that only a fully booted OS prints, seen ANYWHERE in a boot episode (not
# just at the very end): login-program messages, the AOS-CX login history line,
# the ArubaOS setup/auto-provisioning dialog and its curl retry warnings, and
# "<host> login:" / "User:" prompts with whatever was typed after them. The
# watcher reads a passive capture, so the live prompt is often followed by an
# echoed username, a retry message or idle-timeout chatter that hides it from
# the end-anchored prompt check, and the port was then wrongly called "stuck".
# A switch's idle-session logout ("Console terminated due to inactivity.") is
# also proof the OS is running, even when nothing else follows it.
_OS_UP_MARKER = re.compile(
    r"Login incorrect|Login attempt timed out|Maximum number of tries exceeded|"
    r"has logged in \d+ times? in the past|Press any key to continue|"
    r"partial string is acceptable|Auto-provisioning is in progress|"
    r"Transient problem:|\S[ \t]+login:|^\s*(?:User|Username|Password)\s*:|"
    r"\(ttyu\d+\)|Console terminated due to inactivity",
    re.I | re.M)


def os_up_marker(text: str) -> str:
    """The first booted-OS marker in ``text`` (see ``_OS_UP_MARKER``), or ''."""
    # First match, trimmed.
    m = _OS_UP_MARKER.search(sanitize_console_text(text or ""))
    return m.group(0).strip() if m else ""


# Boot-time fault signatures — phrases a device prints when it FAILS to boot
# (kernel panic, watchdog reset loop, bad/missing image, memory/POST failure).
# Deliberately conservative to avoid false alarms on normal boot chatter; a hit
# during an in-progress boot flags the port as "stuck" so the UI can surface a
# likely hardware/boot problem.
_BOOT_FAULT = re.compile(
    r"kernel panic|watchdog\s+reset|boot\s*loop|rebooting\.\.\.|"
    r"unable to mount|no bootable device|no valid boot|bad magic|"
    r"image (?:signature )?(?:invalid|corrupt)|crc (?:error|mismatch)|"
    r"dram.*(?:fail|error)|memory test fail|post (?:error|fail)|"
    r"(?:machine check|unrecoverable) (?:exception|error)|"
    r"failed to boot|boot failure|system halted",
    re.I)


# Lines that REPORT why the last restart happened ("Last reboot reason:
# watchdog reset", "Reset cause: ...", "Boot reason: ...") are printed by a
# device that is booting normally (and by show-version style output). They
# contain fault words but are history, not a failure of the current boot, and
# used to flag healthy ports as "stuck". They are blanked (same length, so match
# offsets stay valid) before fault signatures are searched.
_FAULT_REPORT_LINE = re.compile(
    r"^[^\n]*(?:(?:re)?boot|reset|restart)\s+(?:reason|cause)\b[^\n]*$|"
    r"^[^\n]*\blast\s+(?:reboot|reset|restart)\b[^\n]*$", re.I | re.M)


def _fault_scan_text(text: str) -> str:
    """Sanitized ``text`` with restart-reason report lines blanked out."""
    # Strip escapes, then blank out restart-reason lines (same length).
    clean = sanitize_console_text(text or "")
    return _FAULT_REPORT_LINE.sub(lambda m: " " * len(m.group(0)), clean)


def boot_fault(text: str) -> str:
    """Return the matched boot-fault phrase found in ``text`` (a likely stuck/dead
    boot), or '' if none. Terminal escapes stripped first."""
    # First fault phrase, if any.
    m = _BOOT_FAULT.search(_fault_scan_text(text))
    return m.group(0).strip() if m else ""


# Bootloader / recovery prompts: responsive, but NOT evidence of a healthy boot.
_RECOVERY_PROMPT = re.compile(
    r"(?:rommon\s*\d*\s*>|loader>|boot>|grub>|switch:|=>|db>)\s*$", re.I)


def is_recovery_prompt(text: str) -> bool:
    """True if the tail of ``text`` is a BOOTLOADER / recovery prompt.

    Such a prompt answers a wake nudge, so :func:`looks_like_prompt` (and hence
    :func:`check_line_responsive`) reports it as responsive — ``loader>``,
    ``boot>``, ``=>`` and ``db>`` all match the generic shell-prompt shape. But
    responsive is not booted: a device sitting at its bootloader never reached
    its OS, which is precisely the condition the boot watcher exists to catch.
    Callers deciding boot HEALTH (rather than mere liveness) must consult this."""
    # Check the cleaned tail.
    return bool(_RECOVERY_PROMPT.search(_prompt_tail(sanitize_console_text(text or ""))))


def current_boot_fault(text: str) -> str:
    """Like :func:`boot_fault`, but a fault followed later in ``text`` by a
    normal (non-bootloader/recovery) prompt is treated as historical — the
    device recovered/rebooted and reached a prompt, so it's not a current fault."""
    # Cleaned text without restart-reason lines.
    clean = _fault_scan_text(text)
    # Find the last fault match.
    last = None
    for m in _BOOT_FAULT.finditer(clean):
        last = m
    # No fault.
    if last is None:
        return ""
    # A normal prompt after the fault means the device recovered.
    after = clean[last.end():]
    if looks_like_prompt(after) and not _RECOVERY_PROMPT.search(_prompt_tail(after)):
        return ""
    # Report the FIRST signature on the faulting LINE, not the last match in the
    # buffer: one fault line routinely trips several phrases ("Kernel panic -
    # unable to mount root" matches both "kernel panic" and "unable to mount"),
    # and the leading one names the actual failure. Scanning to the last match
    # above is still right for deciding WHICH fault is current; it is only the
    # reported phrase that must come from the start of that line — which is also
    # what :func:`boot_fault` reports for the same text.
    # Report the first fault on the same line as the last one.
    nl = max(clean.rfind("\n", 0, last.start()), clean.rfind("\r", 0, last.start()))
    primary = _BOOT_FAULT.search(clean, nl + 1, last.end())
    return (primary or last).group(0).strip()


# HPE/Aruba (and similar) console firmware reprints "Connected at <N> baud" plus
# its FULL startup banner on every fresh serial-line handshake (DTR toggle) —
# not only on an actual power-on/reset. Our own baud sweeps/relocks and idle
# session churn toggle that line, so a device can show several of these banner
# replays back-to-back while it was never actually stuck: each one is a fresh,
# independent boot/login cycle that reached a prompt fine on its own. Counting
# them lets the boot watcher reset its "stuck" clock per cycle instead of
# summing several genuine cycles' time into one false "stuck" verdict.
_LINE_RECONNECT = re.compile(r"Connected at\s+\d+\s+baud", re.I)


def count_line_reconnects(text: str) -> int:
    """Count of "Connected at <N> baud" banner replays seen in ``text`` — each
    one marks the start of an independent boot/login cycle (see
    ``_LINE_RECONNECT``)."""
    # Count banner replays in the cleaned text.
    return len(_LINE_RECONNECT.findall(sanitize_console_text(text or "")))


# A "stuck" boot is inferred from the passive capture alone, and a chatty device
# can defeat that: a switch stuck repeating an unrelated message (e.g. a console
# idle-timeout banner like "Console terminated due to inactivity.") looks
# identical, byte-wise, to one that's actually hung — the tail is dominated by
# the repeated noise and the live prompt underneath it never scrolls back into
# view. Rather than trust "no prompt seen in the passive tail" alone, actively
# confirm: send a single bare CR (what an operator does to wake a console) and
# see if a login/password/shell prompt answers. This is the read-only,
# no-credential half of run_identify's own "wake the line" step (see the
# ``write_fn(b"\r\n")`` / ``_LOGIN_NUDGES`` block below) — it never spends a
# credential. It establishes responsiveness, not boot health; a CR can still
# interrupt a bootloader countdown, so callers must gate it by boot timeout.
_LIVENESS_NUDGE_SECS = 3.0


def check_line_responsive(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                          nudge_secs: float = _LIVENESS_NUDGE_SECS) -> Tuple[bool, str]:
    """Send one bare CR and read back, to tell a device that's genuinely hung
    mid-boot from one already sitting at a live prompt that's merely buried
    behind unrelated console chatter. Returns ``(responsive, transcript)`` where
    ``responsive`` is True if a login/password/shell prompt answered."""
    # Press Enter once and read until a prompt.
    write_fn(b"\r")
    transcript = _read_until(read_fn, [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT,
                                       _SETUP_PROMPT], nudge_secs)
    # Responsive if the reply looks like a prompt.
    return looks_like_prompt(transcript), transcript

# Console lines are usually silent until they receive a keystroke: a device sits
# idle at a prompt and emits nothing on its own (unless it happens to be booting).
# So we actively wake the line by sending Enter (CR) — an initial CRLF plus a few
# more bare CRs — until a login/password/shell prompt appears. Many devices only
# redraw their prompt on a fresh CR, so this also turns "output but no prompt"
# into a detectable prompt without hammering (bounded attempt count).
# ── How patient the probe is ─────────────────────────────────────────────────
# Identify is NOT latency-sensitive. It runs on a background probe loop, holds
# the serial handle exclusively for one port, and the hub keeps CONSOLE_AUTOPROBE
# alive with progress frames rather than a hard 90s cut-off. Impatience is the
# expensive failure mode: a switch that simply takes a breath mid-reply gets
# written off as unresponsive and the device is reported "unknown", which costs
# an operator a manual login. Every window below is therefore sized for a slow,
# busy switch on a noisy line, not for a fast one.
#
# ``_IDLE_SECS`` is the important one: _read_until also stops when the stream
# goes quiet, and the serial handle is opened with a 0.3s read timeout, so at
# the old 0.4s a SINGLE missed poll ended the read. Sized here at several polls.
_IDLE_SECS = 1.6           # quiet gap that means "the device has finished talking"

# Global multiplier on every read window, so a deployment with unusually slow
# gear (or a test suite that wants none of this waiting) can scale the whole
# schedule from one place. See :func:`set_patience`.
_PATIENCE = 1.0


def set_patience(factor: float) -> float:
    """Scale every read/settle window in this module by ``factor``.

    ``>1`` for slow or heavily loaded gear, ``<1`` to speed up tests. Returns
    the previous value so callers can restore it. Clamped to a sane range so a
    bad config value can't wedge a probe for hours or reduce every window to
    zero."""
    global _PATIENCE
    # Remember the old value.
    prev = _PATIENCE
    # Ignore values that are not numbers.
    try:
        f = float(factor)
    except (TypeError, ValueError):
        return prev
    # Clamp between 0.01 and 10.
    _PATIENCE = min(max(f, 0.01), 10.0)
    return prev


def _t(seconds: float) -> float:
    """A read window, scaled by the configured patience."""
    # Scale by the patience factor.
    return seconds * _PATIENCE


_LOGIN_NUDGES = 5          # extra CRs after the initial CRLF banner read
_NUDGE_SECS = 2.5          # per-nudge read window

# After a FAILED credential, a device may be slow to re-draw its login prompt or
# deliberately rate-limit (a pause + fresh "login:"). Before spending the NEXT
# credential we nudge (bounded) and wait for the prompt to actually reappear, so
# a valid credential later in the list is never silently skipped just because the
# prompt hadn't redrawn yet.
_REPROMPT_NUDGES = 3       # CRs used to coax the login prompt back between creds
_REPROMPT_SECS = 5.0       # read window per re-prompt nudge (covers rate-limit delay)

# Many devices lock the console after a small number of failed attempts WITHIN
# one session (AOS-CX: "Maximum number of tries exceeded (5)"; ArubaOS-Switch
# similar). merge_credentials can hand us the operator's creds plus the full
# FACTORY_DEFAULT_CREDENTIALS list — trying all of them back-to-back with no
# gap between attempts burns through that counter in seconds and locks the
# console before a valid credential further down the list is ever tried. Pace
# failed attempts so identify never looks like a brute-force script to the
# device itself.
_CRED_RETRY_DELAY = 3.0    # seconds paused after each FAILED credential

# A net-new device often forces a password SET/CHANGE right after a first login
# with a factory-default credential. Identify is READ-ONLY, so we must NOT set a
# password — we decline by sending a few bare CRs (what an operator does to skip),
# which drops the device to its shell or bounces it back to the login prompt.
_NEW_PW_SKIP_CRS = 4       # bare CRs sent to escape a forced set/change-password flow
_NEW_PW_SKIP_SECS = 3.0    # read window per skip CR

# A prompt ending in ">" is UNPRIVILEGED (user EXEC) on Cisco IOS, HPE/Aruba
# AOS-S and most network CLIs; the identity `show` commands generally need
# PRIVILEGED ("#") mode, so we send `enable` and answer whatever it asks for.
# Two secrets are tried at an enable password prompt: the credential that just
# logged us in, then a bare Enter (many devices have no separate enable secret).
_ENABLE_DRAINS = 3         # extra passive reads for a device that pauses mid-reply
_ENABLE_ATTEMPTS = 2       # distinct enable secrets tried before giving up
_ENABLE_SECS = 6.0         # read window after each enable-flow write

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
    # Pairs already seen and the result.
    seen = set()
    out: List[Dict[str, str]] = []
    # Keep the first copy of each pair.
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
# Shell characters that could chain, redirect or substitute commands.
_META_TOKENS = ("\n", "\r", ";", "|", "&", "`", "$(", ">", "<", "\\", "\x00")


def is_readonly_command(cmd: str) -> bool:
    """True only if ``cmd`` is a single, non-mutating, read-only command safe to
    send to a device we're identifying. Rejects chaining/redirection/substitution
    metacharacters, any mutation keyword, and any verb not on the allowlist.
    Session-local pager controls are explicitly permitted."""
    # Reject empty commands and shell metacharacters.
    c = (cmd or "").strip()
    if not c or any(t in c for t in _META_TOKENS):
        return False
    # Pager settings are allowed.
    low = c.lower()
    if low in _SAFE_PAGER_CMDS:
        return True
    # First word must be a read-only verb; no word may be a mutation keyword.
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

    Returns ``{"vendor": <name|None>, "identity": {...}}`` (identity may be {}),
    plus ``ambiguous_fields: ["ip"]`` / ``ip_candidates`` / ``ip_candidate_context``
    ONLY when the profile's ip regex found 2+ distinct valid addresses (see
    ``ip_ambiguity``; the keys are omitted otherwise)."""
    # Detect the vendor and set up results.
    text = text or ""
    prof = detect_vendor(text)
    identity: Dict[str, str] = {}
    ip_cands: List[Tuple[str, str]] = []
    vendor = prof["name"] if prof else None
    # Full field extraction only for the LABELED network-vendor profiles (their
    # regexes anchor on strings like "Processor board ID" / "Serial Number" /
    # "Base MAC" / "IPv4 address", which are safe to match anywhere in a passive
    # capture). The linux profile's field regexes are bare ``^(\S+)$`` forms tied
    # to specific command outputs — matching those across arbitrary scrollback
    # yields garbage, so linux/unknown fall to the generic prompt pass below.
    # Matched vendor (not linux): pull its fields from the capture.
    if prof and prof["name"] != "linux":
        identity.update(_extract_profile_fields(prof, text, ip_cands))
    # Device type from the model or family.
    if prof and prof.get("family") and prof["name"] != "linux":
        identity["type"] = infer_device_type(identity.get("model"), prof["family"])
    # No hostname: try the prompt, then the login banner.
    if not identity.get("hostname"):
        # Glean a hostname from the last shell/CLI prompt we saw, else from a
        # "<host> login:" prompt (all a login-locked switch ever shows).
        hn = prompt_hostname(text) or login_banner_hostname(text)
        if hn:
            identity["hostname"] = hn
    # No MAC: any MAC in the text.
    if not identity.get("mac"):
        mm = _GENERIC_MAC.search(text)
        if mm:
            identity["mac"] = mm.group(1)
    # No IP: the first valid labelled address.
    if not identity.get("ip"):
        for m in _GENERIC_IP_LABEL.finditer(text):
            cand = m.group(1)
            if is_valid_device_ip(cand):
                identity["ip"] = cand
                break
    # Normalise the MAC.
    if identity.get("mac"):
        identity["mac"] = normalize_mac(identity["mac"]) or identity["mac"]
    # Result with junk removed, plus IP ambiguity info.
    res: Dict[str, Any] = {"vendor": vendor, "identity": scrub_identity(identity)}
    res.update(ip_ambiguity(ip_cands))
    return res


def _read_until(read_fn: Callable[[], bytes], patterns: List[re.Pattern],
                timeout: float, idle: Optional[float] = None) -> str:
    """Accumulate serial output until one of ``patterns`` matches the tail, or
    ``timeout`` elapses, or the stream goes idle for ``idle`` seconds.

    Both windows are scaled by the module patience (:func:`set_patience`), and
    ``idle`` defaults to ``_IDLE_SECS`` — long enough that a device pausing
    mid-reply isn't mistaken for one that has finished."""
    # Scale the windows.
    idle = _t(_IDLE_SECS if idle is None else idle)
    timeout = _t(timeout)
    # Buffer, deadline, and time of the last data.
    buf = b""
    deadline = time.monotonic() + timeout
    last = time.monotonic()
    # Read until the deadline.
    while time.monotonic() < deadline:
        chunk = read_fn()
        # Data: add it and stop if the tail matches a pattern.
        if chunk:
            buf += chunk
            last = time.monotonic()
            tail = buf[-400:].decode("utf-8", "replace")
            if any(p.search(tail) for p in patterns):
                break
        # No data for too long: stop.
        elif time.monotonic() - last > idle:
            break
    # Decode what we got.
    return buf.decode("utf-8", "replace")


def _read_command_output(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                         until: List[re.Pattern], cmd_secs: float, max_pages: int = 30) -> str:
    """Read one command's output, auto-advancing pagers (``--More--``) by sending
    a space so the full output is captured instead of a single screen."""
    # First screen.
    out = _read_until(read_fn, until, cmd_secs)
    # While a pager prompt shows, press space and read the next screen.
    pages = 0
    while pages < max_pages and _PAGER.search(out[-120:]):
        write_fn(b" ")
        out += _read_until(read_fn, until, cmd_secs)
        pages += 1
    return out


def _elicit_identity_banner(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                            transcript: str, cmd_secs: float = 4.0):
    """Responsive console, no vendor recognized yet and NO login prompt showing:
    send a few universal read-only discovery commands to force out an identifying
    banner. Stops as soon as :func:`detect_vendor` recognizes the device. Returns
    ``(transcript, profile, outputs)`` — a direct-console device (no auth) can be
    identified without ever seeing a login/password prompt."""
    # Outputs and the vendor detected so far.
    outputs: Dict[str, str] = {}
    profile = detect_vendor(transcript)
    # Already identified: send nothing.
    if profile:  # passive banner/prompt already identifies it — send nothing
        return transcript, profile, outputs
    # Send each discovery command until the vendor is recognised.
    for cmd in _DISCOVERY_COMMANDS:
        write_fn((cmd + "\r").encode())
        out = _read_command_output(read_fn, write_fn, [_SHELL_PROMPT], cmd_secs)
        outputs[cmd] = out
        transcript += "\n" + out
        profile = detect_vendor(transcript)
        if profile:
            break
    return transcript, profile, outputs


def _is_garbled(line: str) -> bool:
    """True if ``line`` is mostly undecodable/non-printable bytes (the U+FFFD
    replacement chars a wrong baud rate produces) rather than readable text."""
    # Blank lines are not garbled.
    text = line.strip()
    if not text:
        return False
    # Garbled when over 30% of characters are bad.
    bad = sum(1 for ch in text if ch == "\ufffd" or not ch.isprintable())
    return bad / len(text) > 0.3


def _generic_login(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                   credentials: List[Dict[str, str]], banner_secs: float = 6.0,
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
    # Diagnostics for troubleshooting.
    diag: Dict[str, Any] = {"login_prompt_seen": False, "password_prompt_seen": False,
                            "shell_prompt_seen": False, "creds_tried": 0,
                            "bytes": 0, "any_output": False, "nudges": 0}

    def _observe(tail: str) -> None:
        """Record which kinds of prompt appear in tail."""
        if _LOGIN_PROMPT.search(tail):
            diag["login_prompt_seen"] = True
        if _PASSWORD_PROMPT.search(tail):
            diag["password_prompt_seen"] = True
        if _SHELL_PROMPT.search(tail):
            diag["shell_prompt_seen"] = True
        if _NEW_PASSWORD_PROMPT.search(tail):
            diag["forced_password_prompt_seen"] = True

    # Prompts that end a read.
    prompts = [_LOGIN_PROMPT, _PASSWORD_PROMPT, _SHELL_PROMPT]

    def _has_prompt(tail: str) -> bool:
        """Return True if tail shows any login, password, shell or new-password prompt."""
        return bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)
                    or _SHELL_PROMPT.search(tail) or _NEW_PASSWORD_PROMPT.search(tail))

    def _last_line(t: str) -> str:
        """Return the last non-empty line of t."""
        # The current prompt is always the last non-empty line. new_password_prompt
        # has unanchored alternatives ("change your password"), so match it on the
        # last line only — otherwise a stale hint left earlier in the tail would
        # make us think we're still at a set-password prompt after reaching a shell.
        return t.replace("\r", "\n").rstrip("\n").rsplit("\n", 1)[-1]

    def _at_new_pw(t: str) -> bool:
        """Return True if the last line is a forced new-password prompt."""
        return bool(_NEW_PASSWORD_PROMPT.search(_last_line(t)))

    # Wake the line. A console device typically emits nothing until it receives a
    # keystroke, so send an initial CRLF (+ banner read to catch any streaming
    # boot output), then nudge with a bare CR up to _LOGIN_NUDGES more times until
    # a prompt shows. This is what elicits a prompt from an idle, already-booted
    # device instead of sitting forever on a silent line.
    # Send CRLF and read the banner.
    write_fn(b"\r\n")
    transcript = _read_until(read_fn, prompts, banner_secs)
    _observe(_prompt_tail(transcript))
    # Press Enter a few more times until some prompt appears.
    while diag["nudges"] < _LOGIN_NUDGES and not _has_prompt(_prompt_tail(transcript)):
        diag["nudges"] += 1
        write_fn(b"\r")
        transcript += _read_until(read_fn, prompts, _NUDGE_SECS)
        _observe(_prompt_tail(transcript))
    # Record what came back.
    diag["bytes"] = len(transcript)
    diag["any_output"] = bool(transcript.strip())
    # Is a login, password or new-password prompt showing?
    tail = _prompt_tail(transcript)
    at_login = bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)
                    or _at_new_pw(tail))
    # No login prompt: report garbled output, or logged in if a shell prompt shows.
    if not at_login:
        # Already at a shell (no auth), or nothing recognizable on the line.
        # Wrong-baud noise can end in '#' or '>' and look like a prompt; that is
        # not a login.
        if _is_garbled(_last_line(tail)):
            diag["garbled"] = True
            return False, None, transcript, diag
        return bool(_SHELL_PROMPT.search(tail)), None, transcript, diag
    # Login prompt but no credentials to try.
    if not credentials:
        return False, None, transcript, diag

    def _shell_ready(t: str) -> bool:
        """Return True if t shows a shell prompt and no login, password or new-password prompt."""
        return bool(_SHELL_PROMPT.search(t)
                    and not (_LOGIN_PROMPT.search(t) or _PASSWORD_PROMPT.search(t)
                             or _at_new_pw(t)))

    def _skip_forced_password_change() -> str:
        """A net-new device can force a password SET/CHANGE right after a first
        login with a factory-default cred ("Enter new password:" / "Confirm new
        password:" / "You must change your password"). Identify is READ-ONLY, so
        we must NEVER set a password — decline by sending a few bare CRs (what an
        operator does to skip), which drops the device to its shell or bounces it
        back to the login prompt. Returns the extended transcript."""
        # Press Enter (up to the limit) while a new-password prompt shows.
        nonlocal transcript
        sent = 0
        t = _prompt_tail(transcript)
        while sent < _NEW_PW_SKIP_CRS and _at_new_pw(t) and not _SHELL_PROMPT.search(t):
            sent += 1
            write_fn(b"\r")
            transcript += _read_until(
                read_fn, [_SHELL_PROMPT, _LOGIN_PROMPT, _NEW_PASSWORD_PROMPT, _PASSWORD_PROMPT],
                _NEW_PW_SKIP_SECS)
            t = _prompt_tail(transcript)
            _observe(t)
        # Record that we skipped it.
        if sent:
            diag["forced_password_skipped"] = True
            diag["forced_password_crs"] = sent
        return transcript

    # Try each credential in turn.
    idx = 0
    n = len(credentials)
    while idx < n:
        # Current credential and tail.
        cred = credentials[idx]
        tail = _prompt_tail(transcript)
        # Ensure a login/password prompt is actually showing before we SPEND this
        # credential. A device that rate-limits or is slow to re-draw after a
        # failed attempt may not have re-shown its prompt yet; nudge (bounded) and
        # wait so a valid credential later in the list is never silently skipped.
        # Coax the login prompt back if it is not showing.
        nudged = 0
        while not (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)
                   or _at_new_pw(tail)):
            # Already at a shell: the previous credential worked.
            if _shell_ready(tail):
                # A prior attempt actually reached a shell (its own iteration read
                # window closed before the prompt arrived) — credit that cred.
                diag["bytes"] = len(transcript)
                return True, (idx - 1 if idx > 0 else None), transcript, diag
            # Gave up waiting for the prompt.
            if nudged >= _REPROMPT_NUDGES:
                diag["bytes"] = len(transcript)   # prompt never came back — stop
                return False, None, transcript, diag
            # Press Enter and read.
            nudged += 1
            write_fn(b"\r")
            transcript += _read_until(read_fn, [_LOGIN_PROMPT, _PASSWORD_PROMPT,
                                                _NEW_PASSWORD_PROMPT, _SHELL_PROMPT], _REPROMPT_SECS)
            tail = _prompt_tail(transcript)
            _observe(tail)

        # Count this attempt.
        diag["creds_tried"] = idx + 1
        # Net-new device demanding a password SET/CHANGE (matched BEFORE the
        # ordinary password prompt so we never type a credential into a
        # set-password field): decline via CRs, then re-check for a shell.
        # Forced password change: decline it.
        if _at_new_pw(tail):
            transcript = _skip_forced_password_change()
            tail = _prompt_tail(transcript)
        # Otherwise send the username, then the password if asked.
        else:
            if _LOGIN_PROMPT.search(tail):
                write_fn((cred.get("username", "") + "\r").encode())
                transcript += _read_until(read_fn, [_NEW_PASSWORD_PROMPT, _PASSWORD_PROMPT,
                                                    _SHELL_PROMPT, _LOGIN_PROMPT], step_secs)
                tail = _prompt_tail(transcript)
                _observe(tail)
            # A forced set/change flow can appear right after the username (before
            # any password) — skip it rather than typing the credential password.
            if _at_new_pw(tail):
                transcript = _skip_forced_password_change()
                tail = _prompt_tail(transcript)
            elif _PASSWORD_PROMPT.search(tail):
                write_fn((cred.get("password", "") + "\r").encode())
                transcript += _read_until(read_fn, [_SHELL_PROMPT, _NEW_PASSWORD_PROMPT,
                                                    _LOGIN_PROMPT, _PASSWORD_PROMPT], step_secs)
                tail = _prompt_tail(transcript)
                _observe(tail)
                # Forced change AFTER a successful auth (the common net-new case).
                if _at_new_pw(tail):
                    transcript = _skip_forced_password_change()
                    tail = _prompt_tail(transcript)
        # Shell prompt: logged in with this credential.
        if _shell_ready(tail):
            diag["bytes"] = len(transcript)
            return True, idx, transcript, diag
        # Next credential, after a short pause.
        idx += 1
        if idx < n:
            # Failed credential: pace the next attempt (see _CRED_RETRY_DELAY)
            # rather than immediately spending another one.
            time.sleep(_t(_CRED_RETRY_DELAY))
    # No credential worked.
    diag["bytes"] = len(transcript)
    return False, None, transcript, diag


def _enable_secrets(credentials: List[Dict[str, str]], cred_idx) -> List[str]:
    """Enable secrets to try, in order: the password of the credential that
    just logged us in, then a bare Enter (very common — plenty of devices have
    no separate enable secret). Deduped, so a blank login password doesn't
    burn both attempts."""
    # The login password first, then blank.
    out: List[str] = []
    if isinstance(cred_idx, int) and 0 <= cred_idx < len(credentials):
        out.append((credentials[cred_idx] or {}).get("password", "") or "")
    out.append("")
    # Remove duplicates, keeping order.
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _escalate_privilege(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                        credentials: List[Dict[str, str]], cred_idx,
                        transcript: str) -> Tuple[str, Dict[str, Any]]:
    """Escalate an unprivileged console session to privileged (enable) mode.

    A prompt ending in ``>`` is UNPRIVILEGED (user EXEC) on Cisco IOS, HPE/Aruba
    AOS-S and most network CLIs — most of the identity ``show`` commands are
    rejected there ("Invalid input"), so the device would be misreported as
    unknown even though we logged in fine. Seeing ``>`` therefore means: send
    ``enable`` and answer whatever it asks for, until the prompt ends in ``#``.

    ``$`` and ``%`` prompts are deliberately NOT treated as unprivileged: those
    are UNIX shells, where ``enable`` is meaningless (and on some appliances is
    a real, state-changing command). ``_UNPRIV_PROMPT`` matches ``>`` only, so
    we never type ``enable`` into a shell.

    Read-only w.r.t. device config: ``enable`` only changes OUR session's
    privilege level, and ``_logout`` afterwards drops back out. Never raises —
    a dead line must not crash identify. Returns ``(transcript, diag)``."""
    # Diagnostics.
    diag: Dict[str, Any] = {"attempted": False, "escalated": False,
                            "secrets_tried": 0, "reason": ""}
    # Already privileged: nothing to do.
    tail = _prompt_tail(transcript)
    if _PRIV_PROMPT.search(tail):
        # Already in enable mode (or a UNIX root shell) — nothing to do.
        diag["escalated"] = True
        diag["reason"] = "already_privileged"
        return transcript, diag
    # Not a ">" prompt: leave it alone.
    if not _UNPRIV_PROMPT.search(tail):
        # Not a ">" prompt: a $/% shell, or we never reached a prompt at all.
        diag["reason"] = "not_unprivileged"
        return transcript, diag

    # Prompts that end a read during the enable flow.
    patterns = [_PRIV_PROMPT, _PASSWORD_PROMPT, _LOGIN_PROMPT, _UNPRIV_PROMPT]

    # Offset of the last thing we wrote, so each pass can tell an empty read
    # window (a line that went quiet) apart from a real refusal.
    # Transcript length when we last sent something.
    sent_at = len(transcript)

    def _send(data: str) -> bool:
        """Send data plus CR and read the reply; return False if the write fails."""
        nonlocal transcript, sent_at
        try:
            write_fn((data + "\r").encode())
        except Exception:  # noqa: BLE001 - dead line; keep what we have
            return False
        sent_at = len(transcript)
        transcript += _read_until(read_fn, patterns, _ENABLE_SECS)
        return True

    # Send "enable".
    enable_at = len(transcript)
    if not _send("enable"):
        diag["reason"] = "no_prompt"
        return transcript, diag
    diag["attempted"] = True

    # Secrets to try and how many were used.
    secrets = _enable_secrets(credentials, cred_idx)
    used = 0
    # `_read_until` also stops on a 0.4s idle gap, and real switches pause
    # between echoing `enable` and printing their post-escalation banner (the
    # AOS-S "Your previous successful login ..." notice). A couple of extra
    # passive reads let a slow device finish its reply instead of being written
    # off as unresponsive.
    # Remaining extra reads for slow devices.
    drains_left = _ENABLE_DRAINS

    def _drain() -> None:
        """Read once more from a slow device."""
        nonlocal transcript, drains_left
        drains_left -= 1
        transcript += _read_until(read_fn, patterns, _ENABLE_SECS)

    # Bounded: each pass consumes one read window and either finishes, drains
    # once more, or feeds the device one more answer, so this can never spin.
    # Bounded loop over the enable dialogue.
    for _ in range(_ENABLE_ATTEMPTS + _ENABLE_DRAINS + 2):
        tail = _prompt_tail(transcript)
        # "#" prompt: escalated.
        if _PRIV_PROMPT.search(tail):
            diag["escalated"] = True
            diag["reason"] = ""
            return transcript, diag
        # Only look at output produced SINCE we sent `enable`, so an error
        # string from earlier in the login flow can't be mistaken for a
        # refusal of this escalation.
        # Output since "enable", and whether the last send got any reply.
        since = transcript[enable_at:]
        if not transcript[sent_at:].strip():
            # Nothing at all came back. A responsive device echoes at least the
            # command, so this is a quiet line rather than a refusal — but give
            # it another read window before giving up.
            if drains_left > 0:
                _drain()
                continue
            diag["reason"] = "no_prompt"
            return transcript, diag
        # Back at ">": classify why enable failed.
        if _UNPRIV_PROMPT.search(tail):
            # Bounced back to ">". Distinguish the two causes from the error
            # text: no `enable` command at all (retrying is pointless) versus a
            # rejected secret.
            if _ENABLE_UNSUPPORTED.search(since):
                diag["reason"] = "no_enable_support"
            elif _ENABLE_DENIED.search(since) or diag["secrets_tried"]:
                diag["reason"] = "bad_secret"
            else:
                diag["reason"] = ("bad_secret" if diag["secrets_tried"]
                                  else "no_enable_support")
            return transcript, diag
        # Asked for a username: send the login username.
        if _LOGIN_PROMPT.search(tail):
            # Some devices re-ask for a username during escalation.
            user = ""
            if isinstance(cred_idx, int) and 0 <= cred_idx < len(credentials):
                user = (credentials[cred_idx] or {}).get("username", "") or ""
            if not _send(user):
                diag["reason"] = "no_prompt"
                return transcript, diag
            continue
        # Asked for a password: try the next secret, up to the limit.
        if _PASSWORD_PROMPT.search(tail):
            if used >= len(secrets) or used >= _ENABLE_ATTEMPTS:
                diag["reason"] = "bad_secret"
                return transcript, diag
            secret = secrets[used]
            used += 1
            diag["secrets_tried"] = used
            if not _send(secret):
                diag["reason"] = "no_prompt"
                return transcript, diag
            continue
        # Output arrived but it isn't a prompt yet — mid-banner. Keep reading.
        # Unrecognised output: read more, or give up.
        if drains_left > 0:
            _drain()
            continue
        diag["reason"] = "no_prompt"
        return transcript, diag

    # Ran out of loop iterations.
    diag["reason"] = "bad_secret" if diag["secrets_tried"] else "no_prompt"
    return transcript, diag


# Commands that end a session.
_LOGOUT_COMMANDS = ("exit", "logout")


def _deescalate_privilege(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                          cmd_secs: float = 3.0) -> bool:
    """Drop back from privileged ("#") to unprivileged (">") mode.

    Only used when we escalated an OPERATOR's already-open console session —
    one we did NOT authenticate and therefore won't log out. Leaving their
    shared console line sitting in enable mode would be a side effect of a
    read-only identify, so put the privilege level back. ``disable`` is the
    Cisco/AOS-S verb; ``exit`` drops a level on CLIs that lack it. Returns True
    once an unprivileged prompt is confirmed."""
    # Try each command until an unprivileged or login prompt appears.
    for cmd in ("disable", "exit"):
        try:
            write_fn((cmd + "\r").encode())
        except Exception:  # noqa: BLE001 - dead line; nothing more we can do
            return False
        out = _read_until(read_fn, [_UNPRIV_PROMPT, _LOGIN_PROMPT], cmd_secs)
        tail = _prompt_tail(out)
        if _UNPRIV_PROMPT.search(tail) or _LOGIN_PROMPT.search(tail):
            return True
    return False


def _logout(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
            profile: Optional[Dict[str, Any]] = None, cmd_secs: float = 3.0) -> bool:
    """Cleanly end an authenticated session we opened: send ``exit``/``logout``
    (or the profile's own ``logout`` override) and confirm a login/password
    prompt reappears, so profiling never leaves a privileged shell open on the
    shared console line. Read-only w.r.t. device config. Returns True once a
    login prompt is back (i.e. we are confirmed logged out)."""
    # Logout commands from the profile, else the defaults.
    cmds = list((profile or {}).get("logout") or _LOGOUT_COMMANDS)
    # Press Enter and wait for any prompt.
    try:
        write_fn(b"\r")
    except Exception:  # noqa: BLE001 - a dead line just means we can't confirm
        return False
    _read_until(read_fn, [_SHELL_PROMPT, _LOGIN_PROMPT, _PASSWORD_PROMPT], 1.0)
    # Send each logout command until a login or password prompt returns.
    for cmd in cmds:
        try:
            write_fn((cmd + "\r").encode())
        except Exception:  # noqa: BLE001
            break
        out = _read_until(read_fn, [_LOGIN_PROMPT, _PASSWORD_PROMPT], cmd_secs)
        tail = _prompt_tail(out)
        if _LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail):
            return True
    return False


def run_identify(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
                 credentials: List[Dict[str, str]], banner_secs: float = 6.0,
                 cmd_secs: float = 6.0) -> Dict[str, Any]:
    """Drive a read-only identify over an already-open serial channel.

    ``read_fn()`` returns available bytes (non-blocking-ish); ``write_fn(bytes)``
    writes. ``credentials`` is an ordered list of ``{username,password}`` tried
    once each at a login prompt (attempt cap = len(credentials); no re-hammering).
    Returns ``{banner, vendor, logged_in, credential_index, identity, outputs}``,
    plus ``ambiguous_fields: ["ip"]`` / ``ip_candidates`` / ``ip_candidate_context``
    ONLY when 2+ distinct valid device addresses were found for ``ip`` (see
    ``ip_ambiguity``; omitted otherwise, same as ``passive_identify``). The hub
    asks the LLM which candidate is the device's own address.
    Read-only: only the matched profile's commands are sent.
    """
    # Result skeleton.
    result: Dict[str, Any] = {"banner": "", "vendor": None, "logged_in": False,
                              "credential_index": None, "identity": {}, "outputs": {},
                              "hostname_source": "", "diag": {}}
    # 1. Vendor-agnostic login FIRST. A device at a bare login prompt shows no
    #    banner/system info until authenticated, so we must log in before we can
    #    detect the vendor (and even unknown vendors get a captured post-login
    #    banner for the passive-glean / LLM-identify paths to use).
    logged_in, cred_idx, transcript, diag = _generic_login(read_fn, write_fn, credentials, banner_secs)
    # 1b. A ">" prompt is UNPRIVILEGED: most identity `show` commands are
    #     rejected there ("Invalid input"), so the device would be reported as
    #     unknown even though the login worked. Escalate with `enable` BEFORE
    #     vendor detection and before any command runs. _escalate_privilege
    #     itself no-ops on a "#" prompt, on $/% UNIX shells, and at a login
    #     prompt, so this is safe to call unconditionally.
    transcript, enable_diag = _escalate_privilege(
        read_fn, write_fn, credentials, cred_idx, transcript)
    # Record login and enable results.
    diag["enable"] = enable_diag
    result["banner"] = transcript[-4000:]
    result["logged_in"] = logged_in
    result["credential_index"] = cred_idx
    result["diag"] = _login_diag(diag, transcript, credentials)

    def _finalize(res: Dict[str, Any], prof: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Log out of our own session (or de-escalate an operator's) and return res."""
        # Cleanly log out of a session WE authenticated (cred_idx set). We never
        # touch an already-open console we merely read from (console_usable path
        # leaves credential_index None), so we don't close an operator's session.
        if res.get("credential_index") is not None:
            try:
                res["diag"]["logged_out"] = _logout(read_fn, write_fn, prof)
            except Exception:  # noqa: BLE001
                res["diag"]["logged_out"] = False
        elif enable_diag.get("escalated") and enable_diag.get("attempted"):
            # We escalated an OPERATOR's already-open session and won't log it
            # out — put its privilege level back where we found it rather than
            # leaving a privileged shell on a shared console line.
            try:
                enable_diag["deescalated"] = _deescalate_privilege(read_fn, write_fn)
            except Exception:  # noqa: BLE001
                enable_diag["deescalated"] = False
        return res

    # 2. Detect the vendor from everything seen (pre- and post-login).
    # Detect the vendor and check for a login prompt.
    profile = detect_vendor(transcript)
    tail = _prompt_tail(transcript)
    at_login_prompt = bool(_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail))

    # 2b. Direct-console gear shows no banner until prodded and may never present
    #     a login prompt. If we're on a LIVE line (got output, not sitting at a
    #     login/password prompt) but haven't recognized the vendor, actively run a
    #     few universal read-only discovery commands to coax out an identifying
    #     banner — i.e. try the show commands even without a username/password.
    # No vendor and no login prompt: send discovery commands.
    if not profile and not at_login_prompt and diag.get("any_output"):
        transcript, profile, disc = _elicit_identity_banner(read_fn, write_fn, transcript)
        result["banner"] = transcript[-4000:]
        if any((v or "").strip() for v in disc.values()):
            # The console answered our commands → it's usable without auth.
            result["logged_in"] = True
            diag["console_usable"] = True
            diag["discovery_cmds"] = list(disc.keys())
            result["diag"] = _login_diag(diag, transcript, credentials)

    # Standby VSF member console: treat as aruba-cx.
    if not profile and at_standby_console(transcript):
        # A VSF standby member never prints a vendor banner and rejects the
        # usual identity commands, so detect_vendor can't place it. Its bare
        # "standby#" prompt is AOS-CX specific, so adopt that profile — this is
        # what lets us run `show vsf` and find the conductor instead of
        # reporting the port as an unknown device forever.
        profile = next((p for p in PROFILES if p["name"] == "aruba-cx"), None)

    # Still unknown: keep a hostname from the prompt and finish.
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
        return _finalize(result, None)
    # Known vendor.
    result["vendor"] = profile["name"]
    if profile.get("family") and profile["name"] != "linux":
        # A recognized network device can report its role (Switch/…) even while
        # login-locked; refined to a concrete type once we read a model below.
        # (linux matches a bare "login:" — too weak to claim "Server" unauth'd.)
        result["identity"]["type"] = profile["family"]

    # If a login prompt is still showing (couldn't authenticate), stop here.
    # Stuck at a login prompt: cannot run commands.
    tail = _prompt_tail(transcript)
    if not result["logged_in"] and (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
        return _finalize(result, profile)

    # 3. Run the read-only identity commands + capture output (pager-aware).
    # Run each profile command and parse the identity from the outputs.
    outputs: Dict[str, str] = {}
    for spec in profile["commands"]:
        cmd = spec["cmd"]
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_command_output(read_fn, write_fn, [profile["prompt"]], cmd_secs)
    result["outputs"] = outputs
    ip_cands: List[Tuple[str, str]] = []
    result["identity"] = parse_identity(profile, outputs, ip_cands)
    # Backfill any fields the dedicated identity commands didn't yield from the
    # FULL transcript: a device may answer an equivalent discovery command (e.g.
    # an ArubaOS-Switch that returns "System Name : …" for the banner-discovery
    # ``show system`` while rejecting the profile's ``show system-information``),
    # so the data is already captured — just not in this command's own output.
    # Transcript ip candidates only count if the ip was actually taken from it.
    # Fill missing fields from the whole transcript.
    backfill_ip_cands: List[Tuple[str, str]] = []
    for key, val in _extract_profile_fields(profile, transcript, backfill_ip_cands).items():
        if key not in result["identity"]:
            result["identity"][key] = val
            if key == "ip":
                ip_cands = backfill_ip_cands
    # Flag an ambiguous IP.
    result.update(ip_ambiguity(ip_cands))
    # Device type from the model.
    if profile.get("family"):
        # Concrete role from the model (e.g. Juniper SRX → Firewall), else the
        # profile's default family.
        result["identity"]["type"] = infer_device_type(
            result["identity"].get("model"), profile["family"])
    # Stack record, when stacked.
    stack = detect_stack(outputs, transcript)
    if stack:
        result["stack"] = stack
        # A standby has no hostname of its own and answers no identity command,
        # so its own stack-member MAC is the only stable key we can reconcile
        # the port against when /dev/ttyUSBn renumbers.
        if stack.get("local_mac") and not result["identity"].get("mac"):
            result["identity"]["mac"] = stack["local_mac"]

    # Drop junk values; note where the hostname came from.
    result["identity"] = scrub_identity(result["identity"])
    if result["identity"].get("hostname"):
        result["hostname_source"] = "command"  # parsed from a show/display output
    else:
        # No hostname from the identity commands (e.g. an ArubaOS-Switch that
        # rejects them) — fall back to the device's own CLI prompt name.
        hn = prompt_hostname(transcript)
        if hn:
            result["identity"]["hostname"] = hn
            result["hostname_source"] = "prompt"  # gleaned from the CLI prompt
    # Log out / de-escalate and return.
    return _finalize(result, profile)


def _sanitize_tail(text: str, n: int = 240) -> str:
    """A short, printable tail of a transcript for troubleshooting telemetry —
    terminal escapes stripped and remaining control bytes collapsed to spaces so
    it renders safely in the UI/logs."""
    # Cleaned tail; replace other characters with spaces.
    tail = sanitize_console_text(text or "")[-n:]
    return re.sub(r"[^\x20-\x7e]+", " ", tail).strip()


def _login_diag(diag: Dict[str, Any], transcript: str, credentials) -> Dict[str, Any]:
    """Assemble the login telemetry block from a _generic_login diag + transcript.
    Adds a printable tail and a human ``reason`` for why login didn't complete."""
    # Copy and add credential count and transcript tail.
    d = dict(diag or {})
    d["creds_available"] = len(credentials or [])
    d["tail"] = _sanitize_tail(transcript)
    # Privilege level reached, so an operator can tell "logged in but stuck in
    # user EXEC" apart from a plain login failure — the two look identical in
    # the output otherwise (both leave the identity commands empty).
    # Privilege level and, if enable failed, why.
    _en = d.get("enable") or {}
    if _en.get("escalated"):
        d["privilege"] = "enable"
    elif _en.get("attempted"):
        d["privilege"] = "user"
        d["enable_reason"] = {
            "no_enable_support": "device has no `enable` command (\">\" is its top level)",
            "bad_secret": "`enable` rejected the stored credential's password and a blank secret",
            "no_prompt": "`enable` sent but the device never re-prompted",
        }.get(_en.get("reason") or "", _en.get("reason") or "")
    # Main reason, most specific first.
    if d.get("garbled"):
        d["reason"] = "garbled output (likely wrong baud rate)"
    elif d.get("shell_prompt_seen"):
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
                 banner_secs: float = 6.0, cmd_secs: float = 6.0) -> Dict[str, Any]:
    """Log in generically, then run a caller-supplied list of READ-ONLY commands
    and capture per-command output — the primitive behind LLM-driven identify on
    devices the built-in profiles don't recognize.

    Every command is validated by :func:`is_readonly_command` before it is sent;
    anything that fails is skipped and reported in ``rejected`` (never written to
    the line). If we never authenticate (a login prompt is still showing), no
    commands are sent. Returns
    ``{banner, logged_in, credential_index, outputs, rejected, diag}``.
    """
    # Result skeleton.
    result: Dict[str, Any] = {"banner": "", "logged_in": False, "credential_index": None,
                              "outputs": {}, "rejected": [], "diag": {}}
    # Log in and try to escalate.
    logged_in, cred_idx, transcript, diag = _generic_login(read_fn, write_fn, credentials, banner_secs)
    # A ">" prompt is UNPRIVILEGED — escalate before running the caller's
    # commands, or a device sitting in user EXEC rejects most `show`s.
    # _escalate_privilege no-ops on "#", on $/% shells and at a login prompt.
    transcript, enable_diag = _escalate_privilege(
        read_fn, write_fn, credentials, cred_idx, transcript)
    # Record the results.
    diag["enable"] = enable_diag
    result["banner"] = transcript[-4000:]
    result["logged_in"] = logged_in
    result["credential_index"] = cred_idx
    result["diag"] = _login_diag(diag, transcript, credentials)
    # Never send commands into a login prompt.
    tail = _prompt_tail(transcript)
    if not logged_in and (_LOGIN_PROMPT.search(tail) or _PASSWORD_PROMPT.search(tail)):
        return result  # never authenticated — don't send commands into a login prompt
    # Run each read-only command; record rejected ones.
    outputs: Dict[str, str] = {}
    for raw in (commands or []):
        cmd = str(raw).strip()
        if not is_readonly_command(cmd):
            result["rejected"].append(cmd)
            continue
        write_fn((cmd + "\r").encode())
        outputs[cmd] = _read_until(read_fn, [_SHELL_PROMPT], cmd_secs)
    result["outputs"] = outputs
    # Return an operator's session to unprivileged mode.
    if enable_diag.get("escalated") and enable_diag.get("attempted") and cred_idx is None:
        # Escalated an operator's already-open session (run_commands never logs
        # out) — restore its privilege level instead of leaving enable mode on
        # a shared console line.
        try:
            enable_diag["deescalated"] = _deescalate_privilege(read_fn, write_fn)
        except Exception:  # noqa: BLE001
            enable_diag["deescalated"] = False
        result["diag"] = _login_diag(diag, transcript, credentials)
    return result

def login(read_fn: Callable[[], bytes], write_fn: Callable[[bytes], None],
          profile: Dict[str, Any], credentials: List[Dict[str, str]],
          sample_secs: float = 2.0):
    """Reach an exec prompt on an already-woken line. Returns (logged_in, idx).
    Tries each credential once; no re-hammering."""
    def at_exec(t: str) -> bool:
        """Return True if t shows the exec prompt and no login or password prompt."""
        return bool(profile["prompt"].search(t) and not (
            profile["login_prompt"].search(t) or profile["password_prompt"].search(t)))

    # Read whatever is showing.
    tail = _prompt_tail(_read_until(read_fn, [profile["login_prompt"], profile["password_prompt"],
                                              profile["prompt"]], sample_secs))
    # Already at the exec prompt.
    if at_exec(tail):
        return True, None
    # No prompt: press Enter and check again.
    if not (profile["login_prompt"].search(tail) or profile["password_prompt"].search(tail)):
        write_fn(b"\r")
        tail = _prompt_tail(_read_until(read_fn, [profile["login_prompt"], profile["password_prompt"],
                                                  profile["prompt"]], sample_secs))
        if at_exec(tail):
            return True, None
    # Try each credential once.
    for idx, cred in enumerate(credentials or []):
        # Password-only prompt: send just the password.
        if profile["password_prompt"].search(tail) and not profile["login_prompt"].search(tail):
            write_fn((cred.get("password", "") + "\r").encode())
        # Otherwise send the username, then the password if asked.
        else:
            write_fn((cred.get("username", "") + "\r").encode())
            out = _read_until(read_fn, [profile["password_prompt"], profile["prompt"]], 3.0)
            if profile["password_prompt"].search(_prompt_tail(out)):
                write_fn((cred.get("password", "") + "\r").encode())
        # Read the result; stop at the exec prompt.
        tail = _prompt_tail(_read_until(read_fn, [profile["prompt"], profile["login_prompt"],
                                                 profile["password_prompt"]], 4.0))
        if at_exec(tail):
            return True, idx
    # No credential worked.
    return False, None


def _disable_pager(read_fn, write_fn, profile, cmd_secs: float) -> None:
    """Send the profile's pure setup commands (terminal length 0 / no page) so a
    long show doesn't stall on a pager. These are the commands with no `fields`."""
    # Send each command that has no fields and wait for the prompt.
    for spec in profile.get("commands", []):
        if "fields" not in spec:
            write_fn((spec["cmd"] + "\r").encode())
            _read_until(read_fn, [profile["prompt"]], cmd_secs)


def read_running_config(read_fn, write_fn, profile, credentials,
                        cmd_secs: float = 20.0) -> Dict[str, Any]:
    """Log in (if needed) and capture the device's running-config (backup/read)."""
    # Wake the line and log in.
    write_fn(b"\r\n")
    ok, _ = login(read_fn, write_fn, profile, credentials)
    if not ok:
        return {"status": "ERROR", "message": "login failed", "config": ""}
    # The profile must define a show-running command.
    show = (profile.get("config") or {}).get("show_running")
    if not show:
        return {"status": "ERROR", "message": "no running-config command for this device type",
                "config": ""}
    # Disable the pager, send it, and capture until the prompt.
    _disable_pager(read_fn, write_fn, profile, 3.0)
    write_fn((show + "\r").encode())
    cfg = _read_until(read_fn, [profile["prompt"]], cmd_secs)
    return {"status": "SUCCESS", "config": cfg}


# Error markers in device replies to config lines.
_CFG_ERR = re.compile(r"%\s|Invalid input|Unknown command|Incomplete command|syntax error|"
                      r"not found|rejected|Error:", re.I)


def push_config(read_fn, write_fn, profile, credentials, config_text: str,
                save: bool = True, rollback: str = "negate",
                cmd_secs: float = 6.0) -> Dict[str, Any]:
    """Transactional config push (Phase G): login → backup → enter config mode →
    send lines (watch per-line errors) → exit → POST-VERIFY the pushed lines are
    in running-config → on PASS save (unless save=False); on FAIL do NOT save and
    roll back (``negate`` = ``no <line>`` in reverse, or ``reboot`` = reload the
    unsaved running-config). No post-request approval (decision: transactional).
    """
    # Config commands and the result skeleton.
    conf = profile.get("config") or {}
    enter, exit_, save_cmd, show = (conf.get("enter"), conf.get("exit"),
                                    conf.get("save"), conf.get("show_running"))
    result: Dict[str, Any] = {"status": "ERROR", "logged_in": False, "applied": [],
                              "errors": [], "verify_ok": False, "saved": False,
                              "rolled_back": False, "baseline": "", "missing": []}
    # Wake the line and log in.
    write_fn(b"\r\n")
    ok, _ = login(read_fn, write_fn, profile, credentials)
    result["logged_in"] = ok
    if not ok:
        result["message"] = "login failed"
        return result
    # Need a config mode.
    if not enter:
        result["message"] = "device type has no config mode (read-only)"
        return result
    # Disable the pager.
    _disable_pager(read_fn, write_fn, profile, 3.0)
    if show:  # 1. pre-verify backup
        write_fn((show + "\r").encode())
        result["baseline"] = _read_until(read_fn, [profile["prompt"]], 12.0)
    # Split the config into lines.
    lines = [l.rstrip() for l in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    # 2. enter config mode + send line-by-line
    # Enter config mode, send each line and record errors.
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
    # Leave config mode.
    if exit_:
        write_fn((exit_ + "\r").encode())
        _read_until(read_fn, [profile["prompt"]], cmd_secs)
    # 3. post-verify: pushed (non-comment) lines present in running-config
    # Read the running config and check every pushed line appears in it.
    running = ""
    if show:
        write_fn((show + "\r").encode())
        running = _read_until(read_fn, [profile["prompt"]], 12.0)
    check = [l.strip() for l in lines if l.strip() and not l.strip().startswith("!")]
    missing = [l for l in check if l not in running] if running else check
    result["missing"] = missing[:20]
    result["verify_ok"] = (not result["errors"]) and (not missing)
    # 4. save on pass; rollback on fail (never save a failed push)
    # Passed: save (if asked) and succeed.
    if result["verify_ok"]:
        if save and save_cmd:
            write_fn((save_cmd + "\r").encode())
            _read_until(read_fn, [profile["prompt"]], cmd_secs + 4)
            result["saved"] = True
        result["status"] = "SUCCESS"
    # Failed: roll back by reloading, or by negating each line in reverse.
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
    # Push result.
    return result
