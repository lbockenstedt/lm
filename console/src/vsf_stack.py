"""Parse HPE/Aruba VSF (Virtual Switching Framework) stack state from raw console text.

A stacked switch presents ONE logical device across several chassis, but the
console module sees each chassis as its own serial port. Without this, a stack's
standby member looks like an unidentifiable box: its CLI prompt is the bare word
``standby``, it has no hostname of its own, and most ``show`` commands are
rejected. Operators then can't tell which serial line reaches the conductor (the
only member that can actually be configured).

This module turns ``show vsf`` / ``show version`` output into a structured stack
record so the spoke can label each port with its role and so the hub can
cross-reference member MACs to point at the conductor's port.

Pure parsing: no I/O, no device interaction, stdlib only. Every function is
defensive because it is fed raw serial output that may be truncated, garbled by
line noise, or be a CLI error string.
"""

from typing import Any, Dict, List, Optional
import re

# Header labels. Anchored at line start with only an optional "VSF " prefix so
# "Base MAC Address" (the chassis MAC, a different value) can never be mistaken
# for the stack MAC, and "Split Detection Method"/"Status" never for topology.
_MAC_LABEL = re.compile(r"^[ \t]*(?:VSF[ \t]+)?MAC[ \t]+Address[ \t]*:[ \t]*(.*)$", re.I | re.M)
_TOPOLOGY_LABEL = re.compile(r"^[ \t]*(?:VSF[ \t]+)?Topology[ \t]*:[ \t]*(.*)$", re.I | re.M)
# A standby member's reduced `show vsf` omits the whole header block and instead
# names itself here. Authoritative when present.
_THIS_MBR_ID = re.compile(r"^[ \t]*This[ \t]+Mbr[ \t]+ID[ \t]*:[ \t]*(\d+)", re.I | re.M)

# A member row: optional "*" (marks the member we're attached to), then the id.
_MEMBER_ROW = re.compile(r"^[ \t]*(\*?)[ \t]*(\d+)[ \t]+(\S.*?)[ \t]*$")
_SEPARATOR_ROW = re.compile(r"^[ \t]*[-=]{2,}")

_ROLE_WORD = re.compile(r"\b(conductor|commander|standby|member)\b", re.I)
_NOT_PRESENT = re.compile(r"\bnot[ \t]+present\b", re.I)

# Trailing status/role text to peel off a member row so what remains is the
# model. Ordered longest-phrase-first; applied repeatedly because the newer
# AOS-CX table prints BOTH a Status and a Role column ("JL666A Conductor Conductor").
_TRAILING_STATUS = [
    "not present", "in other frag", "active fragment", "not ready",
    "conductor", "commander", "standby", "member", "booting", "ready", "up", "down",
]
# The AOS-S priority column. It is normally space-separated, but a long model
# name runs straight into it ("...2930F-48G-PoE+-4SFP+128"), so the glued form
# is only stripped after a "+" — a real model never ends "+<digits>".
_TRAILING_PRIORITY = re.compile(r"(?:[ \t]+\d{1,3}|(?<=\+)\d{1,3})$")

_REAL_TOPOLOGIES = {"ring", "chain", "mesh"}

# Standby-console evidence. Verified against a live AOS-CX 6300 stack: the
# standby member's post-login prompt is literally "standby#".
STANDBY_CONSOLE = re.compile(r"^[ \t]*standby[ \t]*[#>]", re.I | re.M)
# "myswitch-standby login:", "standby login:", "(standby) login:" — but never a
# plain "login:".
_STANDBY_LOGIN = re.compile(r"\bstandby\)?[ \t]+login[ \t]*:", re.I)
# An explicit banner sentence. Requires "standby" and "member" adjacent on ONE
# line so a `show vsf` table (which lists "Standby" and "Member" on separate
# rows) can't trigger it.
_STANDBY_BANNER = re.compile(r"\bstandby[ \t]+member\b", re.I)

_STANDBY_TAIL = 600

_VERSION_EXACT = re.compile(r"^[ \t]*Version[ \t]*:[ \t]*(\S+)", re.I | re.M)
_VERSION_SOFTWARE = re.compile(r"^[ \t]*Software[ \t]+Version[ \t]*:[ \t]*(\S+)", re.I | re.M)
_IMAGE_STAMP = re.compile(r"^[ \t]*Image[ \t]+stamp[ \t]*:", re.I | re.M)
_IMAGE_TOKEN = re.compile(r"^[ \t]*([A-Z]{2}\.\d+(?:\.\d+)+\w*)[ \t]*$", re.M)

_EMPTY: Dict[str, Any] = {
    "is_stack": False, "topology": "", "stack_mac": "",
    "local_role": "", "local_member_id": None, "members": [],
}


def normalize_member_mac(raw: str) -> str:
    """Reduce any MAC spelling a switch might print to one canonical form.

    VSF tables use three different notations depending on firmware
    (``8c:85:c1:4b:c7:80`` on AOS-CX, ``941882-435589`` on AOS-S, and the
    Cisco-style ``8c85.c14b.c780`` elsewhere). Cross-referencing a stack member
    against a port's learned identity is a string comparison, so they must all
    collapse to the same text.

    Returns "" for anything that is not exactly 12 hex digits — notably the
    model string ("JL662A") that occupies the MAC column of an empty stack slot.
    """
    digits = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
    if len(digits) != 12:
        return ""
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _normalize_role(word: str) -> str:
    """AOS-S says "Commander" where AOS-CX says "Conductor" for the same role."""
    role = (word or "").lower()
    return "conductor" if role == "commander" else role


def _strip_trailing_status(text: str) -> str:
    """Peel status/role columns and the priority column off a member row.

    The tables are space-aligned rather than delimited and the column set varies
    by firmware, so the model is whatever survives once the known trailing
    columns are removed from the right.
    """
    out = text.strip()
    changed = True
    while changed:
        changed = False
        low = out.lower()
        for phrase in _TRAILING_STATUS:
            if not low.endswith(phrase):
                continue
            head = out[: len(out) - len(phrase)]
            # Only strip a whole, space-separated column — never a suffix that
            # happens to sit inside a model name.
            if head and not head[-1].isspace():
                continue
            out = head.rstrip()
            changed = True
            break
        if not changed:
            stripped = _TRAILING_PRIORITY.sub("", out).rstrip()
            if stripped != out:
                out = stripped
                changed = True
    return out


def _parse_member_row(line: str) -> Optional[Dict[str, Any]]:
    """Turn one aligned member row into a member record, or None if it isn't one."""
    if _SEPARATOR_ROW.match(line):
        return None
    m = _MEMBER_ROW.match(line)
    if not m:
        return None
    marked, member_id, rest = bool(m.group(1)), int(m.group(2)), m.group(3)

    tokens = rest.split()
    mac = normalize_member_mac(tokens[0]) if tokens else ""
    body = rest[rest.index(tokens[0]) + len(tokens[0]):] if mac and tokens else rest

    present = not _NOT_PRESENT.search(rest)
    # The role is the LAST role word on the row: the newer AOS-CX table repeats
    # it in both the Status and Role columns, and a model name may contain none.
    role = ""
    if present:
        hits = _ROLE_WORD.findall(rest)
        if hits:
            role = _normalize_role(hits[-1])

    return {"member_id": member_id, "mac": mac, "model": _strip_trailing_status(body),
            "role": role, "present": present, "_marked": marked}


def parse_show_vsf(text: str) -> Dict[str, Any]:
    """Extract the stack's membership and this switch's place in it.

    Returns ``is_stack``, ``topology``, ``stack_mac``, ``local_role``,
    ``local_member_id`` and ``members``. ``local_*`` describe the chassis whose
    console we are physically attached to, which is the whole point: it is what
    lets the UI say "this cable reaches the standby, the conductor is over
    there". Never raises — a CLI rejection or line noise yields the empty result.
    """
    try:
        if not text:
            return dict(_EMPTY)

        topo_hit = _TOPOLOGY_LABEL.search(text)
        topology = topo_hit.group(1).strip() if topo_hit else ""
        mac_hit = _MAC_LABEL.search(text)
        stack_mac = normalize_member_mac(mac_hit.group(1).strip()) if mac_hit else ""

        members: List[Dict[str, Any]] = []
        marked_id: Optional[int] = None
        for line in text.splitlines():
            row = _parse_member_row(line)
            if row is None:
                continue
            if row.pop("_marked"):
                marked_id = row["member_id"]
            members.append(row)

        if not members:
            return dict(_EMPTY)

        # Precedence: the standby's explicit "This Mbr ID", then the AOS-S "*"
        # marker, then the header MAC (AOS-CX prints the local chassis' own MAC).
        local_member_id: Optional[int] = None
        this_hit = _THIS_MBR_ID.search(text)
        if this_hit:
            local_member_id = int(this_hit.group(1))
        elif marked_id is not None:
            local_member_id = marked_id
        elif stack_mac:
            for member in members:
                if member["mac"] and member["mac"] == stack_mac:
                    local_member_id = member["member_id"]
                    break

        local_role = ""
        for member in members:
            if member["member_id"] == local_member_id:
                local_role = member["role"]
                break

        present = [m for m in members if m["present"]]
        is_stack = len(present) >= 2 or topology.strip().lower() in _REAL_TOPOLOGIES
        return {"is_stack": is_stack, "topology": topology, "stack_mac": stack_mac,
                "local_role": local_role, "local_member_id": local_member_id,
                "members": members}
    except Exception:  # noqa: BLE001 - raw serial text must never crash a probe
        return dict(_EMPTY)


def parse_show_version(text: str) -> str:
    """Pull the running software image version out of ``show version``.

    Reported alongside the stack so an operator can spot a member running a
    mismatched image — the usual reason a switch refuses to join a stack.

    Matches only a line whose label is exactly ``Version``; AOS-CX also prints
    ``Service OS Version`` and ``BIOS Version``, which are different things and
    must not be returned in their place.
    """
    try:
        if not text:
            return ""
        hit = _VERSION_EXACT.search(text) or _VERSION_SOFTWARE.search(text)
        if hit:
            return hit.group(1).strip()
        # AOS-S prints the version as a bare token a few lines under "Image stamp:".
        stamp = _IMAGE_STAMP.search(text)
        if stamp:
            token = _IMAGE_TOKEN.search(text, stamp.end())
            if token:
                return token.group(1).strip()
        return ""
    except Exception:  # noqa: BLE001
        return ""


def at_standby_console(text: str) -> bool:
    """True when this serial line lands on a VSF standby member.

    This is the trigger for the whole feature: a standby answers with the bare
    prompt ``standby#`` and rejects the normal identity commands, so the port
    would otherwise stay unidentified forever. Seeing it tells the spoke to run
    ``show vsf`` and find the conductor instead of giving up.

    Only the tail is examined so that a ``show vsf`` table scrolled past earlier
    in the capture (which legitimately contains the word "Standby") cannot be
    mistaken for the prompt we are sitting at.
    """
    if not text:
        return False
    tail = text[-_STANDBY_TAIL:]
    return bool(STANDBY_CONSOLE.search(tail) or _STANDBY_LOGIN.search(tail)
                or _STANDBY_BANNER.search(tail))
