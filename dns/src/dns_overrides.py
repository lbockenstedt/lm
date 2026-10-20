"""Per-client DNS response overrides, rendered as Unbound views.

An **override profile** (e.g. ``PAVO-DEVICE``) is a named set of answers that
differ from what every other client gets: fixed A/AAAA/CNAME answers for a
hostname (``*.zone`` for a whole zone, ``*`` for every name) and names that
should answer NXDOMAIN. An **assignment** binds one client IP or subnet to one
profile. Everything else the client asks resolves exactly as before.

On each resolver this renders to one ``view:`` clause per profile (with
``view-first: yes`` so names the profile does not mention fall through to the
global records and recursion) plus one ``access-control-view:`` per assignment.

Notes on Unbound semantics that shape the model:

* A client maps to at most ONE view, chosen by the longest-prefix match among
  the ``access-control*`` netblocks. Hence one profile per assignment target; a
  device inside an assigned subnet can be given a different profile with its
  own (more specific) assignment.
* A netblock that only appears in ``access-control-view`` is implicitly
  ``allow`` in Unbound (``acl_list.c``), so assigning a profile also lets that
  target query the resolver.

The coordinator (the ``dns`` spoke) owns the desired set; workers re-validate
and re-render it locally, so nothing a coordinator sends can inject arbitrary
Unbound directives (see ``validate_overrides``).
"""

import copy
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger("DNSOverrides")

DEFAULT_OVERRIDES_STATE = "/var/lib/lm-dns/overrides.json"
OVERRIDES_CONF_NAME = "lm-overrides.conf"
VIEW_PREFIX = "lm-ov-"

OVERRIDE_RECORD_TYPES = ("A", "AAAA", "CNAME")
MAX_PROFILES = 64
MAX_ENTRIES_PER_PROFILE = 500
MAX_ASSIGNMENTS = 4096
MIN_TTL = 1
MAX_TTL = 604800
DEFAULT_TTL = 300

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,46}[A-Za-z0-9])?$")
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
#: Free text never reaches the Unbound config, but it is still echoed into the
#: UI and logs, so keep it single-line and bounded.
_TEXT_BAD = re.compile(r"[\r\n\x00]")


class DnsOverrideError(ValueError):
    """An override profile/assignment failed validation."""


class DnsOverrideStateUnavailable(RuntimeError):
    """The persisted override set could not be read or written (fail closed)."""


def _text(value: Any, field: str, limit: int) -> str:
    out = str(value if value is not None else "").strip()
    if _TEXT_BAD.search(out):
        raise DnsOverrideError(f"{field} must be a single line")
    if len(out) > limit:
        raise DnsOverrideError(f"{field} must be at most {limit} characters")
    return out


def normalize_name(raw: Any, allow_wildcard: bool = True) -> str:
    """Lower-case DNS name without the trailing dot.

    ``*`` (every name) and ``*.zone`` (the zone and everything under it) are
    the only wildcard forms. Labels are restricted to letters, digits, ``-``
    and ``_`` so a name can never break out of a quoted Unbound string.
    """
    name = str(raw if raw is not None else "").strip().lower().rstrip(".")
    if not name:
        raise DnsOverrideError("name is required")
    if name == "*":
        if not allow_wildcard:
            raise DnsOverrideError("a wildcard is not allowed here")
        return name
    body = name
    if name.startswith("*."):
        if not allow_wildcard:
            raise DnsOverrideError("a wildcard is not allowed here")
        body = name[2:]
    if len(body) > 253 or not all(_LABEL_RE.match(label) for label in body.split(".")):
        raise DnsOverrideError(f"invalid DNS name: {raw!r}")
    return name


def _zone_of(name: str) -> str:
    """Wildcard name -> the Unbound zone it redirects ("" for exact names)."""
    if name == "*":
        return "."
    if name.startswith("*."):
        return name[2:]
    return ""


def _under(name: str, zone: str) -> bool:
    """True if ``name`` is ``zone`` or a name below it."""
    return name == zone or name.endswith("." + zone)


def _wild(zone: str) -> str:
    return "*" if zone == "." else f"*.{zone}"


def _validate_entry(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise DnsOverrideError("each override record must be an object")
    name = normalize_name(raw.get("name"))
    rtype = str(raw.get("type") or "A").strip().upper()
    if rtype not in OVERRIDE_RECORD_TYPES:
        raise DnsOverrideError(
            f"{name}: type must be one of {', '.join(OVERRIDE_RECORD_TYPES)}")
    value = str(raw.get("value") if raw.get("value") is not None else "").strip()
    try:
        if rtype == "A":
            value = str(ipaddress.IPv4Address(value))
        elif rtype == "AAAA":
            value = str(ipaddress.IPv6Address(value))
        else:
            value = normalize_name(value, allow_wildcard=False)
    except ValueError:
        raise DnsOverrideError(f"{name}: invalid {rtype} value {value!r}")
    try:
        ttl = int(raw.get("ttl") if raw.get("ttl") not in (None, "") else DEFAULT_TTL)
    except (TypeError, ValueError):
        raise DnsOverrideError(f"{name}: ttl must be an integer")
    if not MIN_TTL <= ttl <= MAX_TTL:
        raise DnsOverrideError(f"{name}: ttl must be between {MIN_TTL} and {MAX_TTL}")
    return {"name": name, "type": rtype, "value": value, "ttl": ttl}


def validate_profile(raw: Any) -> Dict[str, Any]:
    """Return a canonical profile or raise :class:`DnsOverrideError`."""
    if not isinstance(raw, dict):
        raise DnsOverrideError("profile must be an object")
    name = str(raw.get("name") or "").strip()
    if not _PROFILE_NAME_RE.match(name):
        raise DnsOverrideError(
            "profile name must be 1-48 characters: letters, digits, '-', '_' or "
            "'.', starting and ending with a letter or digit")
    description = _text(raw.get("description"), "description", 200)

    records_in = raw.get("records") or []
    block_in = raw.get("block") or []
    if not isinstance(records_in, list) or not isinstance(block_in, list):
        raise DnsOverrideError("records and block must be lists")
    if len(records_in) + len(block_in) > MAX_ENTRIES_PER_PROFILE:
        raise DnsOverrideError(
            f"a profile may hold at most {MAX_ENTRIES_PER_PROFILE} entries")

    records: Dict[tuple, Dict[str, Any]] = {}
    for item in records_in:
        entry = _validate_entry(item)
        records[(entry["name"], entry["type"], entry["value"])] = entry
    by_name: Dict[str, set] = {}
    for entry in records.values():
        by_name.setdefault(entry["name"], set()).add(entry["type"])
    for rname, types in by_name.items():
        if "CNAME" in types and len(types) > 1:
            raise DnsOverrideError(f"{rname}: a CNAME cannot coexist with other record types")
        if "CNAME" in types and sum(
                1 for k in records if k[0] == rname and k[1] == "CNAME") > 1:
            raise DnsOverrideError(f"{rname}: only one CNAME is allowed per name")

    block = set()
    for item in block_in:
        bname = normalize_name(item)
        # Blocking a zone already covers every name below it.
        block.add(_zone_of(bname) or bname)
    if "." in block:
        raise DnsOverrideError("blocking every name ('*') is not supported")
    answered = {(_zone_of(n) or n) for n in by_name}
    for owner in sorted(answered):
        for zone in sorted(block):
            if _under(owner, zone):
                raise DnsOverrideError(
                    f"{owner} is answered but {zone} is blocked in the same profile")
    # An Unbound redirect zone answers every name below it from its apex, so
    # an exact entry inside a wildcard's zone would be silently ignored (or,
    # at the apex itself, merged into the wildcard's answers).
    wildcard_zones = sorted({_zone_of(n) for n in by_name if _zone_of(n)})
    for rname in sorted(n for n in by_name if not _zone_of(n)):
        for zone in wildcard_zones:
            if zone == "." or _under(rname, zone):
                raise DnsOverrideError(
                    f"{rname} overlaps the wildcard {_wild(zone)} in the same "
                    f"profile; use one or the other")
    for zone in wildcard_zones:
        for other in wildcard_zones:
            if other != zone and (other == "." or _under(zone, other)):
                raise DnsOverrideError(
                    f"wildcards {_wild(zone)} and {_wild(other)} overlap in the "
                    f"same profile")

    return {
        "name": name,
        "description": description,
        "records": sorted(records.values(),
                          key=lambda r: (r["name"], r["type"], r["value"])),
        "block": sorted(block),
    }


def normalize_target(raw: Any) -> str:
    """Client IP or subnet -> canonical CIDR (a bare IP becomes /32 or /128)."""
    text = str(raw if raw is not None else "").strip()
    if not text:
        raise DnsOverrideError("target IP or subnet is required")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise DnsOverrideError(f"invalid target IP or subnet: {text!r}")
    if net.prefixlen == 0:
        raise DnsOverrideError("a /0 target would override every client; "
                               "use a narrower subnet")
    return str(net)


def validate_assignment(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise DnsOverrideError("assignment must be an object")
    return {
        "target": normalize_target(raw.get("target") or raw.get("ip")),
        "profile": str(raw.get("profile") or "").strip(),
        "label": _text(raw.get("label"), "label", 128),
    }


def validate_overrides(raw: Any) -> Dict[str, Any]:
    """Canonical ``{"profiles": [...], "assignments": [...]}`` or raise."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise DnsOverrideError("overrides must be an object")
    profiles_in = raw.get("profiles") or []
    assignments_in = raw.get("assignments") or []
    if not isinstance(profiles_in, list) or not isinstance(assignments_in, list):
        raise DnsOverrideError("profiles and assignments must be lists")
    if len(profiles_in) > MAX_PROFILES:
        raise DnsOverrideError(f"at most {MAX_PROFILES} override profiles are allowed")
    if len(assignments_in) > MAX_ASSIGNMENTS:
        raise DnsOverrideError(f"at most {MAX_ASSIGNMENTS} assignments are allowed")

    profiles: Dict[str, Dict[str, Any]] = {}
    for item in profiles_in:
        profile = validate_profile(item)
        key = profile["name"].lower()
        if key in profiles:
            raise DnsOverrideError(f"duplicate profile name {profile['name']!r}")
        profiles[key] = profile

    assignments: Dict[str, Dict[str, Any]] = {}
    for item in assignments_in:
        assignment = validate_assignment(item)
        key = assignment["profile"].lower()
        if key not in profiles:
            raise DnsOverrideError(
                f"{assignment['target']}: unknown profile {assignment['profile']!r}")
        assignment["profile"] = profiles[key]["name"]
        if assignment["target"] in assignments:
            raise DnsOverrideError(
                f"{assignment['target']} is assigned more than once")
        assignments[assignment["target"]] = assignment

    def _net_key(a):
        net = ipaddress.ip_network(a["target"])
        return (net.version, int(net.network_address), net.prefixlen)

    return {
        "profiles": sorted(profiles.values(), key=lambda p: p["name"].lower()),
        "assignments": sorted(assignments.values(), key=_net_key),
    }


def overrides_digest(clean: Dict[str, Any]) -> str:
    """Digest of the DNS-affecting content (descriptions/labels excluded so a
    cosmetic rename does not count as a different resolver config)."""
    canonical = {
        "profiles": [{k: p[k] for k in ("name", "records", "block")}
                     for p in clean.get("profiles") or []],
        "assignments": [{k: a[k] for k in ("target", "profile")}
                        for a in clean.get("assignments") or []],
    }
    raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


EMPTY_DIGEST = overrides_digest({"profiles": [], "assignments": []})


def _fqdn(name: str) -> str:
    return "." if name == "." else name + "."


def view_name(profile_name: str) -> str:
    return VIEW_PREFIX + profile_name.lower()


def render_unbound(clean: Dict[str, Any]) -> str:
    """Render a VALIDATED override set as an Unbound include file."""
    lines = ["# Managed by Lab Manager — do not edit manually\n",
             "# Per-client DNS override profiles (one view per profile).\n"]
    assignments = clean.get("assignments") or []
    if assignments:
        lines.append("server:\n")
        for a in assignments:
            lines.append(f"    access-control-view: {a['target']} {view_name(a['profile'])}\n")
    for profile in clean.get("profiles") or []:
        lines.extend(["view:\n",
                      f'    name: "{view_name(profile["name"])}"\n',
                      "    view-first: yes\n"])
        for zone in profile.get("block") or []:
            lines.append(f'    local-zone: "{_fqdn(zone)}" always_nxdomain\n')
        redirect_zones = []
        for record in profile.get("records") or []:
            zone = _zone_of(record["name"])
            if zone and zone not in redirect_zones:
                redirect_zones.append(zone)
        for zone in redirect_zones:
            lines.append(f'    local-zone: "{_fqdn(zone)}" redirect\n')
        for record in profile.get("records") or []:
            owner = _fqdn(_zone_of(record["name"]) or record["name"])
            value = record["value"]
            if record["type"] == "CNAME":
                value = value + "."
            lines.append(
                f'    local-data: "{owner} {record["ttl"]} IN {record["type"]} {value}"\n')
    return "".join(lines)


class DnsOverrideState:
    """Persisted, versioned desired override set (coordinator side)."""

    def __init__(self, state_path: str = ""):
        self.state_path = state_path
        self.version = 0
        self.data: Dict[str, Any] = {"profiles": [], "assignments": []}
        self.digest = EMPTY_DIGEST
        self.updated_at = 0.0
        self.broken = ""
        self._load()

    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path) as fh:
                raw = json.load(fh)
            clean = validate_overrides(raw.get("overrides"))
        except Exception as e:  # noqa: BLE001
            self.broken = f"override state at {self.state_path} could not be read: {e}"
            logger.error("%s — DNS override changes are blocked until it is "
                         "repaired or removed", self.broken)
            return
        if overrides_digest(clean) != raw.get("digest"):
            self.broken = (f"override state at {self.state_path} is corrupt: its "
                           f"recorded digest does not match its content")
            logger.error("%s — DNS override changes are blocked until it is "
                         "repaired or removed", self.broken)
            return
        self.version = int(raw.get("version") or 0)
        self.data = clean
        self.digest = overrides_digest(clean)
        self.updated_at = float(raw.get("updated_at") or 0.0)

    def require_usable(self) -> None:
        if self.broken:
            raise DnsOverrideStateUnavailable(self.broken)

    def persist(self, clean: Dict[str, Any], version: int) -> None:
        """Atomically write then promote in memory. Raises on failure."""
        digest = overrides_digest(clean)
        updated_at = time.time()
        if self.state_path:
            try:
                directory = os.path.dirname(self.state_path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                tmp = self.state_path + ".tmp"
                with open(tmp, "w") as fh:
                    json.dump({"version": version, "digest": digest,
                               "updated_at": updated_at, "overrides": clean}, fh)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.replace(tmp, self.state_path)
            except Exception as e:  # noqa: BLE001
                raise DnsOverrideStateUnavailable(
                    f"could not persist DNS override state to {self.state_path}: {e}")
        self.data = clean
        self.digest = digest
        self.version = version
        self.updated_at = updated_at

    def payload(self, clean: Optional[Dict[str, Any]] = None,
                version: Optional[int] = None) -> Dict[str, Any]:
        clean = self.data if clean is None else clean
        return {"version": self.version if version is None else version,
                "digest": overrides_digest(clean), "overrides": clean}


def _reply_reason(reply: Any) -> str:
    reply = reply if isinstance(reply, dict) else {}
    return str(reply.get("message") or reply.get("error") or "no response").strip()


class DnsOverrideCoordinator:
    """Pushes the override set to every resolver worker.

    A change is all-or-nothing across CONNECTED resolvers: if any connected
    worker rejects it (bad config, reload failure, a worker too old to know the
    op) the workers that already took it are put back on the previous set and
    nothing is persisted. A worker that is merely offline does not block the
    change — it is reported as ``PARTIAL`` and caught up by :meth:`reconcile`.
    """

    def __init__(self, transport, state: DnsOverrideState,
                 lock_provider: Callable[[], Any]):
        self.transport = transport
        self.state = state
        self._lock_provider = lock_provider
        #: member_id -> {"digest", "version", "at"} last confirmed by the worker
        self.reported: Dict[str, Dict[str, Any]] = {}
        #: member_id -> reason, for workers that cannot serve overrides
        self.member_errors: Dict[str, str] = {}

    # ── Read ────────────────────────────────────────────────────────────────

    def _connected_ids(self) -> List[str]:
        return [m["id"] for m in self.transport.member_links() if m.get("connected")]

    async def refresh(self, timeout: float = 10.0) -> None:
        ids = self.transport.member_ids()
        if not ids:
            return
        fan = await self.transport.fanout("DNSW_OVERRIDES_STATE", {}, timeout=timeout)
        for member_id, reply in (fan.get("results") or {}).items():
            if isinstance(reply, dict) and reply.get("status") == "SUCCESS":
                self.reported[member_id] = {"digest": reply.get("digest"),
                                            "version": reply.get("version"),
                                            "at": time.time()}
                self.member_errors.pop(member_id, None)
            else:
                self.reported.pop(member_id, None)
                self.member_errors[member_id] = _reply_reason(reply)

    def member_report(self) -> List[Dict[str, Any]]:
        out = []
        for link in self.transport.member_links():
            state = self.reported.get(link["id"]) or {}
            if not link.get("connected"):
                status = "unreachable"
            elif not state:
                status = "unknown"
            elif state.get("digest") == self.state.digest:
                status = "converged"
            else:
                status = "drifted"
            out.append({"id": link["id"],
                        "display_name": link.get("display_name") or link.get("hostname") or "",
                        "connected": bool(link.get("connected")),
                        "convergence": status,
                        "error": self.member_errors.get(link["id"], "")})
        return out

    async def snapshot(self) -> Dict[str, Any]:
        await self.refresh()
        members = self.member_report()
        out = {"status": "SUCCESS",
               "profiles": copy.deepcopy(self.state.data["profiles"]),
               "assignments": copy.deepcopy(self.state.data["assignments"]),
               "version": self.state.version, "digest": self.state.digest,
               "updated_at": self.state.updated_at, "members": members,
               "converged": bool(members) and all(
                   m["convergence"] == "converged" for m in members)}
        if self.state.broken:
            out.update({"status": "ERROR", "state_unavailable": True,
                        "message": self.state.broken})
        return out

    # ── Write ───────────────────────────────────────────────────────────────

    async def mutate(self, change: Callable[[Dict[str, Any]], Dict[str, Any]]) -> Dict[str, Any]:
        """Apply ``change(copy_of_current) -> candidate`` to every resolver."""
        async with self._lock_provider():
            self.state.require_usable()
            candidate = validate_overrides(change(copy.deepcopy(self.state.data)))
            digest = overrides_digest(candidate)
            if digest == self.state.digest:
                # Description/label-only edits still need persisting.
                if candidate != self.state.data:
                    self.state.persist(candidate, self.state.version)
                return {"status": "SUCCESS", "changed": False,
                        "version": self.state.version, **candidate}
            version = self.state.version + 1
            payload = self.state.payload(candidate, version)
            fan = await self.transport.fanout("DNSW_OVERRIDES_APPLY", payload, timeout=30.0)
            results = fan.get("results") or {}
            connected = set(self._connected_ids())
            applied, rejected, offline = [], {}, []
            for member_id in self.transport.member_ids():
                reply = results.get(member_id) or {}
                if reply.get("status") == "SUCCESS" and reply.get("digest") == digest:
                    applied.append(member_id)
                elif member_id in connected:
                    rejected[member_id] = _reply_reason(reply)
                else:
                    offline.append(member_id)

            if rejected or not applied:
                rollback = await self._rollback(applied)
                reasons = "; ".join(f"{mid}: {why}" for mid, why in rejected.items())
                message = "DNS override change was not applied"
                if reasons:
                    message += f" — rejected by {reasons}"
                elif offline:
                    message += " — no DNS Server worker is connected"
                if rollback:
                    message += "; rollback failed on " + ", ".join(rollback)
                return {"status": "ERROR", "message": message,
                        "member_errors": rejected, "members_offline": offline,
                        "rollback_failed": rollback}
            try:
                self.state.persist(candidate, version)
            except DnsOverrideStateUnavailable as e:
                rollback = await self._rollback(applied)
                return {"status": "ERROR", "message": str(e),
                        "rollback_failed": rollback}
            for member_id in applied:
                self.reported[member_id] = {"digest": digest, "version": version,
                                            "at": time.time()}
                self.member_errors.pop(member_id, None)
            out = {"status": "SUCCESS" if not offline else "PARTIAL",
                   "changed": True, "version": version,
                   "members_applied": applied, "members_offline": offline,
                   **candidate}
            if offline:
                out["message"] = ("Override saved and applied; offline resolver(s) "
                                  + ", ".join(offline)
                                  + " will be updated when they reconnect")
            return out

    async def _rollback(self, member_ids: Iterable[str]) -> List[str]:
        member_ids = list(member_ids)
        if not member_ids:
            return []
        fan = await self.transport.fanout(
            "DNSW_OVERRIDES_APPLY", self.state.payload(), timeout=30.0,
            member_ids=member_ids)
        return list(fan.get("failed") or [])

    # ── Reconcile ───────────────────────────────────────────────────────────

    async def reconcile(self) -> Dict[str, Any]:
        """Re-push the desired set to connected workers that drifted from it."""
        if not self.transport.member_ids():
            return {"status": "SKIPPED", "reason": "no workers"}
        if self.state.broken:
            return {"status": "ERROR", "message": self.state.broken}
        if self.state.version == 0:
            return {"status": "SKIPPED", "reason": "no override set committed yet"}
        async with self._lock_provider():
            await self.refresh()
            stale = [mid for mid in self._connected_ids()
                     if mid in self.reported
                     and self.reported[mid].get("digest") != self.state.digest]
            if not stale:
                return {"status": "SUCCESS", "reconciled": []}
            payload = self.state.payload()
            fan = await self.transport.fanout("DNSW_OVERRIDES_APPLY", payload,
                                              timeout=30.0, member_ids=stale)
            repaired = []
            for member_id in stale:
                reply = (fan.get("results") or {}).get(member_id) or {}
                if reply.get("status") == "SUCCESS" and reply.get("digest") == payload["digest"]:
                    repaired.append(member_id)
                    self.reported[member_id] = {"digest": payload["digest"],
                                                "version": payload["version"],
                                                "at": time.time()}
                else:
                    self.member_errors[member_id] = _reply_reason(reply)
            failed = [m for m in stale if m not in repaired]
            if repaired:
                logger.info("DNS overrides reconcile re-pushed v%s to %s",
                            payload["version"], repaired)
            return {"status": "SUCCESS" if not failed else "PARTIAL",
                    "reconciled": repaired, "failed": failed}


# ── Change builders (pure; used by the spoke's command handlers) ────────────

def upsert_profile(profile: Dict[str, Any], old_name: Optional[str] = None):
    """Return a ``change`` callable that creates/replaces/renames a profile."""
    clean = validate_profile(profile)

    def change(data):
        target = (old_name or clean["name"]).strip().lower()
        profiles = [p for p in data["profiles"] if p["name"].lower() != target]
        if old_name and len(profiles) == len(data["profiles"]):
            raise DnsOverrideError(f"profile {old_name!r} not found")
        if any(p["name"].lower() == clean["name"].lower() for p in profiles):
            raise DnsOverrideError(f"profile {clean['name']!r} already exists")
        profiles.append(clean)
        for a in data["assignments"]:
            if a["profile"].lower() == target:
                a["profile"] = clean["name"]
        data["profiles"] = profiles
        return data
    return change


def delete_profile(name: str, force: bool = False):
    key = str(name or "").strip().lower()

    def change(data):
        if not any(p["name"].lower() == key for p in data["profiles"]):
            raise DnsOverrideError(f"profile {name!r} not found")
        in_use = [a["target"] for a in data["assignments"] if a["profile"].lower() == key]
        if in_use and not force:
            raise DnsOverrideError(
                f"profile {name!r} is still assigned to {', '.join(in_use[:5])}"
                + (" …" if len(in_use) > 5 else "")
                + " — remove those assignments first")
        data["profiles"] = [p for p in data["profiles"] if p["name"].lower() != key]
        data["assignments"] = [a for a in data["assignments"] if a["profile"].lower() != key]
        return data
    return change


def assign(target: Any, profile: str, label: Any = ""):
    clean = validate_assignment({"target": target, "profile": profile, "label": label})

    def change(data):
        data["assignments"] = [a for a in data["assignments"]
                               if a["target"] != clean["target"]]
        data["assignments"].append(clean)
        return data
    return change


def unassign(target: Any):
    net = normalize_target(target)

    def change(data):
        before = len(data["assignments"])
        data["assignments"] = [a for a in data["assignments"] if a["target"] != net]
        if len(data["assignments"]) == before:
            raise DnsOverrideError(f"{net} has no override assigned")
        return data
    return change
