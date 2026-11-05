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

# Type hints describing the parsed stack records.
from typing import Any, Dict, List, Optional
# Regular expressions do all of the text matching below.
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
# Separator lines under a table header ("----" or "===="), which are not member rows.
_MEMBER_ROW = re.compile(r"^[ \t]*(\*?)[ \t]*(\d+)[ \t]+(\S.*?)[ \t]*$")
_SEPARATOR_ROW = re.compile(r"^[ \t]*[-=]{2,}")

# Words that name a member's role in the stack (AOS-S says commander, AOS-CX conductor).
_ROLE_WORD = re.compile(r"\b(conductor|commander|standby|member)\b", re.I)
# Phrase marking an empty stack slot.
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

# Topology values that mean a real multi-member stack (as opposed to "standalone" etc.).
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

# How many trailing characters of captured output to inspect for standby evidence.
_STANDBY_TAIL = 600

# "Version: <x>" exactly (not "BIOS Version" etc.); used by parse_show_version.
_VERSION_EXACT = re.compile(r"^[ \t]*Version[ \t]*:[ \t]*(\S+)", re.I | re.M)
# "Software Version: <x>" form used by some firmware.
_VERSION_SOFTWARE = re.compile(r"^[ \t]*Software[ \t]+Version[ \t]*:[ \t]*(\S+)", re.I | re.M)
# AOS-S "Image stamp:" label; the version token appears a few lines below it.
_IMAGE_STAMP = re.compile(r"^[ \t]*Image[ \t]+stamp[ \t]*:", re.I | re.M)
# A bare AOS-S version token such as "WC.16.10.0012" on a line of its own.
_IMAGE_TOKEN = re.compile(r"^[ \t]*([A-Z]{2}\.\d+(?:\.\d+)+\w*)[ \t]*$", re.M)

# Result returned when the text is not (or cannot be parsed as) a stack; callers copy it.
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
    # Keep only hex digits, lower-cased, so separators and case do not matter.
    digits = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
    # A MAC is exactly 6 bytes = 12 hex digits; anything else is not a MAC.
    if len(digits) != 12:
        return ""
    # Re-insert colons every two digits: "8c85c14bc780" -> "8c:85:c1:4b:c7:80".
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _normalize_role(word: str) -> str:
    """AOS-S says "Commander" where AOS-CX says "Conductor" for the same role."""
    # Lower-case it, then map the AOS-S word onto the AOS-CX one.
    role = (word or "").lower()
    return "conductor" if role == "commander" else role


def _strip_trailing_status(text: str) -> str:
    """Peel status/role columns and the priority column off a member row.

    The tables are space-aligned rather than delimited and the column set varies
    by firmware, so the model is whatever survives once the known trailing
    columns are removed from the right.
    """
    # Work on a trimmed copy; loop until a full pass removes nothing.
    out = text.strip()
    changed = True
    while changed:
        changed = False
        # Compare case-insensitively against each known trailing phrase.
        low = out.lower()
        for phrase in _TRAILING_STATUS:
            if not low.endswith(phrase):
                continue
            # Text left of the phrase.
            head = out[: len(out) - len(phrase)]
            # Only strip a whole, space-separated column — never a suffix that
            # happens to sit inside a model name.
            if head and not head[-1].isspace():
                continue
            # Remove the column and restart the scan from the longest phrases.
            out = head.rstrip()
            changed = True
            break
        # No status phrase matched: try removing a trailing priority number instead.
        if not changed:
            stripped = _TRAILING_PRIORITY.sub("", out).rstrip()
            if stripped != out:
                out = stripped
                changed = True
    return out


def _parse_member_row(line: str) -> Optional[Dict[str, Any]]:
    """Turn one aligned member row into a member record, or None if it isn't one."""
    # Table separator lines are not members.
    if _SEPARATOR_ROW.match(line):
        return None
    # Must start with an optional "*" and a numeric member id.
    m = _MEMBER_ROW.match(line)
    if not m:
        return None
    # Was it starred, its id, and the rest of the row.
    marked, member_id, rest = bool(m.group(1)), int(m.group(2)), m.group(3)

    # The first column after the id is the MAC on populated rows (a model on empty slots).
    tokens = rest.split()
    mac = normalize_member_mac(tokens[0]) if tokens else ""
    # If it was a MAC, the rest of the row after it holds model and status; otherwise keep all.
    body = rest[rest.index(tokens[0]) + len(tokens[0]):] if mac and tokens else rest

    # Empty slots say "not present".
    present = not _NOT_PRESENT.search(rest)
    # The role is the LAST role word on the row: the newer AOS-CX table repeats
    # it in both the Status and Role columns, and a model name may contain none.
    # Absent members get no role.
    role = ""
    if present:
        hits = _ROLE_WORD.findall(rest)
        if hits:
            role = _normalize_role(hits[-1])

    # "_marked" is internal; parse_show_vsf pops it before returning.
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
    # Any unexpected parsing error falls through to the empty result below.
    try:
        # Nothing captured: not a stack.
        if not text:
            return dict(_EMPTY)

        # Optional header fields: topology text and the stack MAC (canonicalised).
        topo_hit = _TOPOLOGY_LABEL.search(text)
        topology = topo_hit.group(1).strip() if topo_hit else ""
        mac_hit = _MAC_LABEL.search(text)
        stack_mac = normalize_member_mac(mac_hit.group(1).strip()) if mac_hit else ""

        # Collect member rows and remember which one (if any) carried the "*" marker.
        members: List[Dict[str, Any]] = []
        marked_id: Optional[int] = None
        # Check every line; non-member lines are skipped.
        for line in text.splitlines():
            row = _parse_member_row(line)
            if row is None:
                continue
            # Remove the internal marker flag; record the starred member's id.
            if row.pop("_marked"):
                marked_id = row["member_id"]
            members.append(row)

        # No member table at all (e.g. the command was rejected): not a stack.
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

        # Our role is whatever role our member row lists.
        local_role = ""
        for member in members:
            if member["member_id"] == local_member_id:
                local_role = member["role"]
                break

        # Two or more present members, or a ring/chain/mesh topology, means a real stack.
        present = [m for m in members if m["present"]]
        is_stack = len(present) >= 2 or topology.strip().lower() in _REAL_TOPOLOGIES
        return {"is_stack": is_stack, "topology": topology, "stack_mac": stack_mac,
                "local_role": local_role, "local_member_id": local_member_id,
                "members": members}
    # Raw serial text must never crash a probe; return "not a stack" instead.
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
    # Malformed input of any kind yields "" rather than an exception.
    try:
        if not text:
            return ""
        # Prefer an exact "Version:" line, then "Software Version:".
        hit = _VERSION_EXACT.search(text) or _VERSION_SOFTWARE.search(text)
        if hit:
            return hit.group(1).strip()
        # AOS-S prints the version as a bare token a few lines under "Image stamp:".
        stamp = _IMAGE_STAMP.search(text)
        if stamp:
            # Search for the version token only after the "Image stamp:" label.
            token = _IMAGE_TOKEN.search(text, stamp.end())
            if token:
                return token.group(1).strip()
        return ""
    # Never raise from a parser fed raw serial output.
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
    # Nothing captured means no evidence.
    if not text:
        return False
    # Only look at the most recent output (where the current prompt is).
    tail = text[-_STANDBY_TAIL:]
    # Any of the three kinds of standby evidence is enough.
    return bool(STANDBY_CONSOLE.search(tail) or _STANDBY_LOGIN.search(tail)
                or _STANDBY_BANNER.search(tail))
