"""Access-control, tenant-scoping, and subnet-filter helpers for the Hub API.

These were previously nested closures defined late inside ``api.create_app()``
(``_session_user``, ``_is_admin``, ``_has_cs_access``, ``_check_tenant_access``,
``_resolve_tenant``, ``_effective_tenant*``, ``_filter_session*``,
``get_netbox_spoke``, ``get_tenant_scoping``) plus the shared leaf helpers
``_unwrap_spoke`` and ``_filter_config``. They are gathered here as
**module-level functions taking their dependencies explicitly** (the live
``_sessions`` dict, the ``hub`` handle) so the logic is importable, testable,
and — critically — no longer lives in a 5,000-line ``create_app()`` closure where
a missing typing import in a nested-def annotation can break hub startup at
app-build time (the .117→.121 regression). With ``from __future__ import
annotations`` here, annotations are strings and never evaluated at import.

``api.create_app()`` keeps thin delegating closures (``def _session_user(req):
return access.session_user(_sessions, req)``) so the ~185 routes keep calling
the same bare names (``_is_admin(sess)``, ``_filter_session(req, data, "nac",
["ip"])``, …) with zero call-site churn. The closures capture the live
``_sessions`` module global and the ``hub`` arg; everything else flows from
``access``.

This module is a **leaf**: it imports only stdlib, ``simulations.tenant_filter``
(also a leaf), and — for type hints only, under ``TYPE_CHECKING`` —
``fastapi.Request``. It MUST NOT import ``api`` or ``main`` (that would create
a cycle, since ``api`` imports this module at top). Dependency direction is
``api → access`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import time
import asyncio
import ipaddress
import logging
import os
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from simulations.tenant_filter import (filter_items_by_prefixes,
                                       filter_firewall_rules, filter_record_by_prefixes,
                                       filter_hypervisor_vms,
                                       build_alias_map, _find_list_slot)

if TYPE_CHECKING:  # annotations only — never evaluated at runtime
    from fastapi import Request

logger = logging.getLogger("Hub")

# ── Constants ───────────────────────────────────────────────────────────────

_PREFIX_CACHE_TTL = 300  # seconds — session-prefix cache TTL (was a create_app local)

# Per-module enable map for server-side subnet filtering. Modules whose data
# carries tenant IP addresses (nac, firewall, netbox, dhcp, hypervisor) default
# ON; the cs / Simulations module is scoped by tenant ID instead of subnet, so
# it defaults OFF. Admins can toggle each module in System → General.
_FILTER_MODULES = ("nac", "firewall", "netbox", "dhcp", "dns", "cs", "hypervisor", "nw")
_FILTER_DEFAULTS = {"nac": True, "firewall": True, "netbox": True,
                            "dhcp": True, "dns": False, "cs": False, "hypervisor": True, "nw": True}

# Firewall endpoint → filter spec. "rules" uses the strict source/destination
# check (with OPNsense alias expansion); the field-based endpoints filter on
# their concrete-IP columns; "aliases" filters on its ``content`` (the IPs/CIDRs
# the alias expands to). "nat" now also matches on its ``source`` (the opnsense
# spoke serializes source on NAT records) so a NAT policy whose source is in
# the tenant's subnet shows even when its target/destination aren't. NAT is
# filtered with drop_no_ip=False at the call site (see filter_fw): a typical
# port forward is source=any with an alias/hostname target, so it yields no
# concrete IP and would otherwise be dropped entirely — keeping unattributable
# NAT rules restores visibility without weakening isolation for concretely
# attributed ones. "health" carries no IP and is skipped. Field sets mirror the
# client-side itemInTenantPrefixes calls (main.js ~5078-5084).
_FW_FILTER_SPEC = {
    "rules":      ("fw", None),
    "nat":        ("fields", ["source", "internal_ip", "external_ip", "destination.network"]),
    "dns":        ("fields", ["ip", "value"]),
    "interfaces": ("fields", ["ip", "ipaddr"]),
    "dhcp":       ("fields", ["ip", "address"]),
    "aliases":    ("fields", ["content"]),
}

# OPNsense endpoints that participate in category-based tenant attribution.
# In OPNsense only ALIASES carry a `category` config field, so the record's-own
# `category` check is meaningful only for aliases. `rules` is included so the
# firewall-rule matcher still receives `tenant_category` and can attribute a
# rule that REFERENCES one of the tenant's own aliases (alias category or
# subnet overlap) — the alias categories come from the alias map
# (`build_alias_map`), not the rule record. `nat` is included for symmetry but
# NAT records carry no category, so it's a no-op there. dhcp/dns/interfaces
# don't use categories.
_FW_CATEGORY_ENDPOINTS = {"rules", "nat", "aliases"}


# Network Devices (nw) endpoint → filter spec. All nw endpoints are field-based
# (concrete-IP columns): the MAC table + ARP + interfaces views. "info" carries
# no IP list (single device summary) and is skipped. MAC/ARP are filtered with
# drop_no_ip=False (a MAC-table row with only a MAC + VLAN — no IP — should not
# be hidden; it leaks no cross-tenant IP); interfaces keep the strict default
# (an interface with no IP is still tenant-relevant only if its other fields
# match, but erring toward showing the tenant's own device interfaces is fine —
# left strict to match the firewall interfaces behavior). "devices" is the
# fleet list (no tenant IP filtering — devices are managed infra shown to all).
_NW_FILTER_SPEC = {
    "macs":      ("fields", ["ip"]),
    "arp":       ("fields", ["ip"]),
    "interfaces": ("fields", ["ip"]),
}


# ── Leaf helpers ─────────────────────────────────────────────────────────────

def unwrap_spoke(result):
    """Unwrap a spoke round-trip envelope to its data payload.

    Spoke responses come back as ``{"payload": {"data": <actual>}, ...}``; this
    returns ``<actual>`` when the envelope is present, otherwise the raw result
    (some spokes return data without an envelope). Centralizes the one-liner
    that was previously copy-pasted across ~two dozen relay handlers. See also
    ``api._normalize_cached`` (which additionally unwraps a bare ``data`` key
    and is used for cache hits).

    NOTE: the in-tree ``api._unwrap_spoke`` was briefly infinite recursion
    (``return _unwrap_spoke(result)``) introduced by the 7bc70c6 doc pass; this
    is the correct implementation restored here. Re-exported into ``api`` as
    ``_unwrap_spoke`` so the ~26 existing call sites get the fix.
    """
    if isinstance(result, dict):
        payload = result.get("payload")
        if isinstance(payload, dict):
            return payload.get("data", result)
    return result


def norm_mac(m) -> str:
    """Canonical lower-colon MAC (``aa:bb:cc:dd:ee:ff``) for dedup + payload.

    ``""`` for an absent/unknown MAC — the netbox sink tolerates a blank mac
    (it keys device matching by IP). Non-hex garbage is returned stripped lower
    so two spellings of the same MAC still dedup. Shared by the firewall and nw
    discovery syncs (and mirrored in the nw spoke's own ``_norm_mac``) so one
    canonical form flows hub → NetBox.
    """
    import re as _re
    s = str(m or "").strip().lower()
    if not s or s in ("unknown", "none", "incomplete"):
        return ""
    hexd = _re.sub(r"[^0-9a-f]", "", s)
    if len(hexd) == 12:
        return ":".join(hexd[i:i + 2] for i in range(0, 12, 2))
    return s


def filter_config(hub) -> dict:
    """Resolved per-module subnet-filter toggles (stored overrides defaults)."""
    stored = hub.state.system_state.get("subnet_filter_modules", {}) or {}
    return {m: bool(stored.get(m, _FILTER_DEFAULTS.get(m, False)))
            for m in _FILTER_MODULES}


# ── Identifier / hostname validation (defense-in-depth) ─────────────────────
# These gate user-supplied identifiers before they're stored, logged, or — for
# ``valid_hostname`` — sent to a spoke that runs ``hostname <value>`` in a shell
# (SPOKE_SET_HOSTNAME). A hostname or spoke id carrying shell metacharacters
# would be a remote command-injection vector on the spoke; a weird identifier
# (spaces, control chars, path segments) pollutes logs/state. Strict allow-lists
# keep the hub's identifier surface machine-shaped.

# A system identifier: spoke_id / agent_id / module_id / role. Alnum-first, then
# alnum + . _ -. 1–64 chars (matches the spoke ids the installers mint, e.g.
# "agent-1", "dns-spoke-1", "cs-svr-02").
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def valid_identifier(s) -> bool:
    """True if ``s`` is a safe system identifier (spoke/agent/module/role id):
    alphanumeric start, then alphanumeric + ``.`` ``_`` ``-``, 1–64 chars."""
    return bool(s) and isinstance(s, str) and bool(_IDENT_RE.fullmatch(s))


def valid_hostname(s) -> bool:
    """True if ``s`` is a safe RFC-1123-style hostname (the value sent to a
    spoke's SPOKE_SET_HOSTNAME, which the spoke applies via a shell ``hostname``
    call — so this MUST reject shell metacharacters). Each label ≤63 chars,
    alphanumeric start/end with internal ``-`` only; total ≤253 chars; dots
    separate labels. No leading/trailing dot or dash, no underscores, no
    spaces, no shell metacharacters."""
    if not s or not isinstance(s, str) or len(s) > 253:
        return False
    if s.startswith(("-", ".")) or s.endswith(("-", ".")):
        return False
    labels = s.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if not (label[0].isalnum() and label[-1].isalnum()):
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
    return True


# A human display name (module/spoke display name). Freeform-ish but NO control
# chars and NO shell metacharacters — it's stored in hub state and rendered in
# the WebUI (the WebUI escapes it on render), so the risk is storage/log
# pollution, not direct injection. Allow printable text up to 128 chars.
_BAD_DISPLAY_CHARS = set(chr(i) for i in range(0x20)) | {
    "\x7f", ";", "|", "&", "$", "`", "'", '"', "<", ">", "\\", }


def valid_display_name(s) -> bool:
    """True if ``s`` is an acceptable display name: non-empty, ≤128 chars, no
    control chars and no shell metacharacters. Most printable text passes
    (spaces, punctuation like ``(`` ``,`` ``:`` are fine)."""
    if not s or not isinstance(s, str) or len(s) > 128:
        return False
    return not any(c in _BAD_DISPLAY_CHARS for c in s)


# ── SSRF: outbound-URL safety ─────────────────────────────────────────────────
# The hub makes a small number of hub-side outbound HTTP calls to user-supplied
# destinations (notably the Aruba Central ``cluster_url`` set via the
# /sim/api/aggregate/central write path — reachable by any cs-righted tenant
# user, NOT just admins). In ``classic`` mode the hub POSTs the Aruba
# ``client_id``/``client_secret`` to ``{cluster_url}/oauth2/token``, so a
# malicious cluster_url is both SSRF (point the hub at an internal host) and
# credential exfiltration (the creds leave to the attacker). These helpers
# confine such destinations to public HTTPS endpoints.

from urllib.parse import urlsplit  # noqa: E402

# Hostnames that are always internal regardless of resolution.
_INTERNAL_HOSTNAMES = {"localhost", "metadata.google.internal", "metadata"}
# Cloud metadata service hosts (per-cloud) — a request to these from the hub
# leaks the instance identity token / IAM creds. Always block.
_METADATA_HOST_SUFFIXES = (".internal", ".local")


def is_internal_ip(ip_str: str) -> bool:
    """True if ``ip_str`` parses as a loopback / private / link-local / reserved
    / unspecified / multicast IP — i.e. an address the hub must NOT be pointed
    at over a user-supplied URL (it would be SSRF to internal services)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )


def _looks_internal_hostname(host: str) -> bool:
    host = (host or "").lower()
    if host in _INTERNAL_HOSTNAMES:
        return True
    if host.endswith(_METADATA_HOST_SUFFIXES):
        return True
    return False


def safe_external_url(s, *, require_https: bool = True) -> bool:
    """True if ``s`` is an http(s) URL whose host is NOT an internal IP literal
    or an internal-looking hostname. Pure string check (no DNS) so it is cheap
    to run on every save and importable into tests.

    ``require_https`` (default) confines hub-side outbound calls to TLS. The
    Aruba Central token exchange carries ``client_id``/``client_secret``, so
    plaintext is never acceptable for that path. Pass ``require_https=False``
    only for paths that genuinely allow plain http.

    This is the FIRST gate (rejects obvious internal destinations at save time).
    Pair with ``host_resolves_external`` for a DNS-resolution pass that blocks
    DNS-rebinding to an internal IP at the moment of save.
    """
    if not s or not isinstance(s, str):
        return False
    try:
        parts = urlsplit(s.strip())
    except Exception:
        return False
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False
    if require_https and scheme != "https":
        return False
    host = parts.hostname  # lowercased, port stripped, brackets removed
    if not host:
        return False
    if _looks_internal_hostname(host):
        return False
    # IP literal host (v4 or v6)? Reject if it's an internal range.
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if is_internal_ip(host):
            return False
    return True


def host_resolves_external(host: str) -> bool:
    """DNS-resolve ``host`` and return True only if EVERY resolved address is
    external (non-internal). A hostname that resolves to even one internal IP
    is rejected — this blocks DNS-rebinding where an attacker's DNS returns a
    public IP at save time and an internal IP (169.254.169.254, 127.0.0.1, …)
    by the time the hub makes the request. No-resolve / NXDOMAIN → True (the
    outbound call will fail anyway; the string check already gated the obvious
    cases; we don't want to add a hard DNS dependency to the save path)."""
    if not host:
        return True
    import socket
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True  # unresolvable — let the outbound call fail naturally
    addrs = {i[4][0] for i in infos}
    if not addrs:
        return True
    return not any(is_internal_ip(a) for a in addrs)


# ── Spoke / tenant scoping ────────────────────────────────────────────────────

def get_netbox_spoke(hub):
    """The connected IPAM (NetBox) spoke id, or None."""
    return hub.get_spoke_by_type("ipam")


def get_tenant_scoping(hub, tenant_id: str = None) -> dict:
    """Return the scoping config for a tenant (or the active one)."""
    try:
        tid = tenant_id or hub.state.system_state.get("active_tenant", "default") or "default"
        cfg = hub.state.get_tenant(tid) or {}
        return {
            "netbox_tenant_slug": cfg.get("netbox_tenant_slug", ""),
            "proxmox_tag":        cfg.get("proxmox_tag", ""),
            "ldap_base_dn":       cfg.get("ldap_base_dn", ""),
            "tenant_id":          tid,
        }
    except Exception:
        return {"netbox_tenant_slug": "", "proxmox_tag": "", "ldap_base_dn": "", "tenant_id": "default"}


# ── Session / auth helpers ───────────────────────────────────────────────────

# Idle timeout: a session with no activity for this long is treated as expired
# even if its absolute 8h TTL hasn't elapsed. Driven by the ``last_seen`` stamp
# the access-control middleware bumps per request. 0 disables the idle cap.
_SESSION_IDLE_TIMEOUT_S = float(os.environ.get("LM_SESSION_IDLE_TIMEOUT_S", "1800"))


def session_user(sessions: dict, request: "Request"):
    """Return the session dict for the current cookie, or None.

    Enforces both the absolute TTL (``expires``) and the idle timeout
    (``last_seen`` + ``_SESSION_IDLE_TIMEOUT_S``); an expired/idle token is
    popped from the store so the slot frees and the next persist drops it."""
    token = request.cookies.get("lm_session")
    if not token:
        return None
    sess = sessions.get(token)
    if not sess or sess["expires"] < time.time():
        sessions.pop(token, None)
        return None
    if _SESSION_IDLE_TIMEOUT_S > 0:
        last = sess.get("last_seen") or sess.get("created") or sess["expires"]
        if time.time() - float(last) > _SESSION_IDLE_TIMEOUT_S:
            sessions.pop(token, None)
            return None
    return sess


# ── RBAC: permission groups → effective permissions ────────────────────────
# Enforced right-keys — the permissions actually checked server-side. Group
# editors and the effective-permission union operate over this set (plus the
# admin flag). Kept here so the UI, routes, and resolver agree on one list.
ENFORCED_RIGHTS = ("cs", "nw", "ipam", "le", "console", "console_write")


def resolve_effective_permissions(hub, user_record: dict) -> dict:
    """Union a user's group-derived rights with their per-user overrides.

    A user belongs to zero or more permission GROUPS (``user_record["groups"]``,
    a list of group ids into ``system_state["permission_groups"]``). Effective
    permissions = the boolean-OR of every group's ``permissions`` dict, OR'd
    with the user's own ``permissions`` dict (per-user grants are additive and
    still work for pre-RBAC users who have no groups). Admin is set if ANY
    source carries ``admin`` or ``role == "admin"``; when admin, both forms are
    normalised on so every downstream check (which honours either) agrees.

    A second tier — tenant admin (``role == "tenant_admin"``) — is set if any
    source carries it. Precedence: Global admin wins over tenant admin (a user
    who is both is a Global Admin). A tenant admin is auto-granted every module
    right (see :func:`has_module_access`) but is tenant-confined
    (``check_tenant_access``/``filter_session``), so it carries no ``admin``
    flag and ``is_admin`` stays False for the tier.

    Returns a fresh flat ``{right: True}`` dict suitable to drop straight into
    ``sess["user"]["permissions"]`` — so all existing middleware/frontend gates
    keep working unchanged. Never mutates the stored record."""
    user_record = user_record or {}
    groups_store = {}
    try:
        groups_store = hub.state.system_state.get("permission_groups", {}) or {}
    except Exception:  # noqa: BLE001 — hub without state (tests) → no groups
        groups_store = {}

    eff: dict = {}
    is_adm = False
    is_tadm = False

    def _absorb(perms: dict):
        nonlocal is_adm, is_tadm
        for k, v in (perms or {}).items():
            if k == "role":
                if v == "admin":
                    is_adm = True
                elif v == "tenant_admin":
                    is_tadm = True
                continue
            if k == "admin":
                if v:
                    is_adm = True
                continue
            if k == "tenant_admin":  # flag form, symmetric with the "admin" flag
                if v:
                    is_tadm = True
                continue
            if v:  # only True grants; a False in one source never revokes another
                eff[k] = True

    # Groups first, then per-user overrides (order is immaterial for an OR).
    for gid in user_record.get("groups", []) or []:
        grp = groups_store.get(gid)
        if grp:
            _absorb(grp.get("permissions", {}))
    _absorb(user_record.get("permissions", {}))

    if is_adm:
        eff["admin"] = True
        eff["role"] = "admin"
    elif is_tadm:
        eff["role"] = "tenant_admin"
        # No "admin" flag — is_admin() stays False so every system-wide gate
        # (/setup, /admin, _ADMIN_API_PREFIXES, fleet, aggregates, user/tenant
        # mgmt) keeps blocking the tier. Tenant confinement (check_tenant_access
        # + filter_session, deny-by-default since 21d483e) does the scoping.
    return eff


def groups_for_ldap_membership(hub, member_of) -> list:
    """Map a directory user's LDAP group memberships → hub group ids.

    ``member_of`` is the list of LDAP group DNs/cns from the directory
    (``memberOf``). Returns the ids of every permission group whose
    ``ldap_group`` matches one of them (case-insensitive, exact string).

    Phase-2 hook: the storage + mapping live here now, but local ``/auth/login``
    does not consult LDAP, and ``LDAPAuthProvider.get_user_groups`` is still a
    stub — wiring this into the login flow is the remaining phase-2 step."""
    member_of = [str(m).strip().lower() for m in (member_of or []) if m]
    if not member_of:
        return []
    try:
        groups_store = hub.state.system_state.get("permission_groups", {}) or {}
    except Exception:  # noqa: BLE001
        return []
    out = []
    for gid, grp in groups_store.items():
        lg = str(grp.get("ldap_group") or "").strip().lower()
        if lg and lg in member_of:
            out.append(gid)
    return out


def is_admin(sess) -> bool:
    """True if this session belongs to a **Global Admin** (system-wide) user.

    Handles both permission formats: {"admin": True} and {"role": "admin"}.
    This is the system-wide tier — every /setup, /admin, _ADMIN_API_PREFIXES,
    fleet, aggregate, and user/tenant-management gate reads it. It is NOT
    satisfied by the tenant-admin tier (see :func:`is_tenant_admin`), which is
    tenant-confined and carries no ``admin`` flag.
    """
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get("admin") or p.get("role") == "admin")


def is_tenant_admin(sess) -> bool:
    """True if this session belongs to a **tenant-level Admin**.

    The tenant-admin tier (``role == "tenant_admin"``) is an admin *within* its
    assigned tenants only: it auto-passes the module-access gates
    (:func:`has_cs_access` / :func:`has_module_access`) and may manage its
    tenants' onboarding PSKs, users, shared-infrastructure writes, and own
    tenant records. It is **tenant-confined** — ``check_tenant_access`` and
    ``filter_session`` (deny-by-default since 21d483e) scope it to
    ``user.tenants`` — and it is **not** a Global Admin (``is_admin`` is False),
    so every system/fleet/cross-tenant gate keeps blocking it. A tenant admin
    with no tenants assigned is denied everything (the tenantless safety net).
    """
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get("role") == "tenant_admin")


def has_cs_access(sess) -> bool:
    """True if the session user may use the Simulations (cs) module.

    Global Admins and tenant Admins always pass; otherwise the user's
    permissions must carry an explicit ``cs`` right (set in User Management).
    A tenant Admin is then tenant-confined by ``check_tenant_access``/
    ``filter_session``. Mirrors the frontend ``canSeeModule`` gate in
    WebUI/main.js so nav-hiding and API/WebSocket access agree.
    """
    if is_admin(sess) or is_tenant_admin(sess):
        return True
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get("cs"))


def has_module_access(sess, right: str) -> bool:
    """True if the session user may use a permission-gated module.

    Global Admins and tenant Admins always pass; otherwise the user's
    permissions must carry an explicit ``right`` (set in User Management).
    Shared by the Network Devices (``nw``) and IPAM (``ipam``) module gates —
    mirrors ``has_cs_access`` so nav-hiding (frontend ``canSeeModule``) and API
    access agree. A tenant Admin is tenant-confined downstream.
    ``right`` is the permissions key (``"nw"`` / ``"ipam"`` / ``"cs"`` …).
    """
    if is_admin(sess) or is_tenant_admin(sess):
        return True
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get(right))


def has_nw_access(sess) -> bool:
    """Network Devices (``nw``) module access gate (see ``has_module_access``)."""
    return has_module_access(sess, "nw")


def has_ipam_access(sess) -> bool:
    """IPAM (``ipam``) module access gate (see ``has_module_access``)."""
    return has_module_access(sess, "ipam")


def has_le_access(sess) -> bool:
    """Certificate Management (``le``) module access gate (see
    ``has_module_access``). Right key is ``"le"`` (set in User Management)."""
    return has_module_access(sess, "le")


def has_console_access(sess) -> bool:
    """Console (``console``) module access gate (see ``has_module_access``).
    Right key is ``"console"`` (set in User Management)."""
    return has_module_access(sess, "console")


def has_console_write_access(sess) -> bool:
    """Console config-WRITE gate — pushing/reading device configs (Phase G) is a
    higher tier than viewing/interacting. Admins pass; otherwise the user needs
    the explicit ``console_write`` right."""
    return has_module_access(sess, "console_write")


def check_tenant_access(sess, tenant_id: str) -> bool:
    """True if the session user may access ``tenant_id``.

    Admins access everything. A non-admin must have the tenant in their
    ``user.tenants`` list — deny by default. An empty/missing ``tenants``
    list means the user has NO tenant assignment (login derives
    ``tenant_id = tenants[0]``), not "sees all tenants": the previous
    ``not allowed or tenant_id in allowed`` let an unconfigured non-admin
    (e.g. one created without a tenant_id) pass the ``?tenant=`` gate for
    ANY tenant. This now matches the deny-by-default posture of
    :func:`effective_tenant`.
    """
    if not sess:
        return False
    if is_admin(sess):
        return True
    allowed = sess.get("user", {}).get("tenants") or []
    return bool(allowed) and tenant_id in allowed


def resolve_tenant(sessions: dict, request: "Request", explicit: str = None) -> str | None:
    """Pick the tenant to scope a query to.

    Priority: explicit ?tenant= param > session user's assigned tenant_id > None
    (None lets get_tenant_scoping fall back to the hub's active_tenant).
    """
    if explicit:
        return explicit
    sess = session_user(sessions, request)
    if sess:
        return sess.get("user", {}).get("tenant_id") or None
    return None


def effective_tenant(sessions: dict, request: "Request", explicit: str = None) -> str | None:
    """The tenant a query should scope to, with non-admin escape prevention.

    Admin → the explicit ``?tenant=`` param (None = no scope, sees all).
    Non-admin → ``explicit`` only if it's in their ``user.tenants`` allowed list
    (and the list is non-empty); otherwise their session ``tenant_id``. So a
    non-admin can switch among their own tenants but can never reach another
    tenant's data via a crafted ``?tenant=``.
    """
    sess = session_user(sessions, request)
    if not sess:
        return None
    if is_admin(sess):
        return explicit
    if explicit:
        allowed = sess.get("user", {}).get("tenants") or []
        if allowed and explicit in allowed:
            return explicit
    return sess.get("user", {}).get("tenant_id") or None


def effective_tenant_slug(hub, sessions: dict, request: "Request", explicit: str = None) -> str | None:
    """NetBox tenant slug for the effective (selected) tenant, or None when the
    tenant is unbound to NetBox / unknown / unselected. None → callers treat as
    'no scope' (no-op)."""
    tid = effective_tenant(sessions, request, explicit)
    if not tid:
        return None
    return (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug") or None


# ── Prefix resolution ────────────────────────────────────────────────────────

async def fetch_tenant_prefixes(hub, tenant_id) -> list:
    """NetBox prefixes for an arbitrary tenant id (by slug). No session cache,
    no admin no-op — the raw fetch shared by ``resolve_prefixes`` (session
    tenant) and ``resolve_prefixes_for_tenant`` (selected tenant). Empty when
    the tenant is unconfigured or the NetBox spoke is down."""
    if not tenant_id:
        return []
    scoping = get_tenant_scoping(hub, tenant_id) or {}
    nb_slug = scoping.get("netbox_tenant_slug")
    if not nb_slug:
        return []
    spoke_id = get_netbox_spoke(hub)
    if not spoke_id:
        return []
    try:
        result = await hub.request_response(spoke_id, "NETBOX_GET_PREFIXES", {"tenant": nb_slug}, timeout=30.0)
        data = unwrap_spoke(result)
        return [p["prefix"] for p in (data.get("prefixes", []) if isinstance(data, dict) else []) if p.get("prefix")]
    except Exception as e:
        logger.warning(f"Failed to fetch prefixes for tenant '{tenant_id}': {e}")
        return []


async def attribute_by_prefix(hub, records: List[Dict[str, Any]]
                             ) -> Tuple[Dict[str, List[Dict[str, Any]]], int]:
    """Bucket records by tenant via IP prefix containment.

    Builds the tenant→networks map once per call (concurrent prefix fetch via
    ``fetch_tenant_prefixes``, bounded so hundreds of tenants don't stampede the
    netbox spoke), then assigns each record to the first tenant whose prefix
    contains its IP. Records with no IP, an unparseable IP, or an IP no tenant
    owns are ``dropped`` (counted) — keeps NetBox tenant-authoritative, no
    orphans. Returns ``({tenant_id: [records]}, dropped_count)``.

    Extracted from ``FwDiscoverySyncMixin._fw_attribute`` so the firewall-
    discovery sync and the realtime NAC→IPAM reverse sync share one attribution
    path. ``records`` carry an ``ip`` field (anything else is opaque to this
    helper); the caller normalizes MACs etc.
    """
    tenants = (hub.state.tenant_state or {}).get("tenants", {}) or {}
    tids = [str(tid) for tid in tenants.keys()]
    nets_by_tid: Dict[str, List[Any]] = {}
    if fetch_tenant_prefixes is not None and tids:
        sem = asyncio.Semaphore(8)

        async def _nets_for(tid: str):
            async with sem:
                try:
                    prefs = await fetch_tenant_prefixes(hub, tid)
                except Exception:
                    prefs = []
                nets: List[Any] = []
                for p in prefs or []:
                    try:
                        nets.append(ipaddress.ip_network(str(p), strict=False))
                    except Exception:
                        pass
                return tid, nets

        for tid, nets in await asyncio.gather(*(_nets_for(tid) for tid in tids)):
            nets_by_tid[tid] = nets

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    dropped = 0
    for rec in records:
        ip_s = (rec.get("ip") or "").split("/")[0].strip()
        if not ip_s:
            dropped += 1
            continue
        try:
            addr = ipaddress.ip_address(ip_s)
        except Exception:
            dropped += 1
            continue
        matched: Optional[str] = None
        for tid in tids:
            for net in nets_by_tid.get(tid) or []:
                if addr in net:
                    matched = tid
                    break
            if matched:
                break
        if matched:
            buckets.setdefault(matched, []).append(rec)
        else:
            dropped += 1
    return buckets, dropped


async def resolve_prefixes(hub, sess) -> list:
    """IP prefixes for the session user's tenant, NetBox-derived and
    session-cached (5 min). Admins and unconfigured tenants → ``[]`` (empty
    means "no filter"). Extracted from /auth/prefixes so the UI endpoint and the
    server-side filter share one source of truth.
    """
    if not sess or is_admin(sess):
        return []
    cached = sess.get("prefixes")
    if cached is not None and sess.get("prefixes_at", 0) > time.time() - _PREFIX_CACHE_TTL:
        return cached or []
    tenant_id = sess.get("user", {}).get("tenant_id")
    if not tenant_id:
        sess["prefixes"] = []
        sess["prefixes_at"] = time.time()
        return []
    prefixes = await fetch_tenant_prefixes(hub, tenant_id)
    sess["prefixes"] = prefixes
    sess["prefixes_at"] = time.time()
    return prefixes


async def resolve_prefixes_for_tenant(hub, tenant_id) -> list:
    """Prefixes for an explicit tenant id (selected tenant), used by the
    tenant-aware NAC filters so admins / multi-tenant users scope by the tenant
    they picked, not the session tenant."""
    return await fetch_tenant_prefixes(hub, tenant_id)


# ── Subnet filtering ──────────────────────────────────────────────────────────

def filter_enabled(hub, module: str) -> bool:
    return filter_config(hub).get(module, False)


async def filter_session(hub, sessions: dict, request: "Request", data, module: str, ip_fields):
    """Apply server-side subnet filtering to ``data`` for ``module``.

    No-op for admins, for disabled modules, or when the tenant has no prefixes
    (can't filter). Otherwise drops items whose concrete IPs all fall outside the
    tenant's prefixes (see simulations/tenant_filter.py).

    A non-admin with NO tenant assignment (``user.tenant_id`` absent — login
    derives it from ``tenants[0]``) is denied: returning the unfiltered
    fleet-wide set would be a cross-tenant bypass (the tenantless-bypass the
    ``?tenant=`` gate now also closes in :func:`check_tenant_access`). Such a
    user is unconfigured; admins still see everything.
    """
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return data
    if not filter_enabled(hub, module):
        return data
    if not sess.get("user", {}).get("tenant_id"):
        return [] if isinstance(data, list) else ({} if isinstance(data, dict) else data)
    prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return data
    return filter_items_by_prefixes(data, prefixes, ip_fields)


# In-process memo of per-firewall OPNsense alias maps, so the rules subnet
# filter doesn't pay an OPNSENSE_GET_ALIASES round-trip on every fetch. Keyed by
# (spoke_id, firewall_id); value is (fetched_at_monotonic, {name_lower: [nets]}).
# ~60s TTL. Best-effort: a miss/failure yields None → the matcher falls back to
# concrete-IP-only behavior (the legacy path).
_FW_ALIAS_TTL = 60.0
_FW_ALIAS_MEMO: dict = {}


async def _fw_alias_map(hub, firewall_id) -> "dict | None":
    """Best-effort OPNsense alias map for ``firewall_id`` (for the rules filter).

    Looks up the firewall's spoke, returns a memoized ``build_alias_map`` result
    or fetches ``OPNSENSE_GET_ALIASES`` and memoizes it. Returns ``None`` when
    the firewall/spoke is unavailable or the fetch fails — callers fall back to
    concrete-IP-only filtering. Never raises.
    """
    if not firewall_id:
        return None
    try:
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", []) or []
        fw = next((f for f in firewalls if isinstance(f, dict) and f.get("id") == firewall_id), None)
        if not fw:
            return None
        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in getattr(hub, "active_connections", {}):
            return None
        now = time.monotonic()
        memo = _FW_ALIAS_MEMO.get((spoke_id, firewall_id))
        if memo and (now - memo[0]) < _FW_ALIAS_TTL:
            return memo[1]
        result = await hub.request_response(spoke_id, "OPNSENSE_GET_ALIASES", {})
        data = unwrap_spoke(result)
        # OPNSENSE_GET_ALIASES → {status, data: [{name, type, content}, ...]}
        aliases = []
        if isinstance(data, dict):
            aliases = data.get("data") or []
        elif isinstance(data, list):
            aliases = data
        amap = build_alias_map(aliases)
        _FW_ALIAS_MEMO[(spoke_id, firewall_id)] = (now, amap)
        return amap
    except Exception as exc:  # noqa: BLE001
        logger.debug("fw alias map fetch failed for %s: %s", firewall_id, exc)
        return None


async def filter_fw(hub, sessions: dict, request: "Request", data, endpoint: str,
                           firewall_id=None, explicit_tenant=None):
    """Firewall-specific subnet filter: strict source/destination for ``rules``
    (with OPNsense alias resolution via ``_fw_alias_map``), field-based for
    nat/dns/interfaces/dhcp/aliases.

    Tenant-aware: when ``explicit_tenant`` resolves to a real tenant (an admin
    selecting a tenant via the switcher, or a multi-tenant user switching to an
    allowed one), scope by THAT tenant's prefixes — even for admins, who
    otherwise bypass. No explicit tenant → legacy session-tenant behavior
    (no-op for admins, session tenant for non-admins). Mirrors
    ``filter_tenant``. The ``firewall`` subnet-filter toggle gates both
    paths; an empty prefix list still means "no filter" (can't filter)."""
    spec = _FW_FILTER_SPEC.get(endpoint)
    if not spec:
        return data  # health / unknown → no IP to filter on
    mode, fields = spec
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        if not filter_enabled(hub, "firewall"):
            return data
        prefixes = await resolve_prefixes_for_tenant(hub, tid)
    else:
        sess = session_user(sessions, request)
        if not sess or is_admin(sess):
            return data
        if not filter_enabled(hub, "firewall"):
            return data
        prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return data
    # OPNsense category attribution: for rules/nat/aliases, a record whose
    # `category` belongs to the tenant is shown regardless of subnet. The admin
    # may tag a record with the tenant's display name, slug, netbox slug, or id,
    # so accept any of those, case-insensitively.
    tenant_cat = None
    if endpoint in _FW_CATEGORY_ENDPOINTS and tid:
        t = hub.state.get_tenant(tid) or {}
        cats = [t.get("name"), t.get("slug"), t.get("netbox_tenant_slug"), tid]
        tenant_cat = sorted({str(c).strip() for c in cats if c}) or None
    before = _list_len(data)
    logger.debug("DIAG filter_fw[%s] tid=%r enabled=%s prefixes=%d "
                   "items_before=%d mode=%s tenant_cat=%r", endpoint, tid, True,
                   len(prefixes), before, mode, tenant_cat)
    if mode == "fw":
        alias_map = await _fw_alias_map(hub, firewall_id) if firewall_id else None
        out = filter_firewall_rules(data, prefixes, alias_map, tenant_category=tenant_cat)
        logger.debug("DIAG filter_fw[%s] filtered %d -> %d alias_map=%s",
                       endpoint, before, _list_len(out), bool(alias_map))
        return out
    # NAT port forwards are normally public-facing (source=any) with a target
    # that may be an alias/hostname rather than a bare IP, so a typical record
    # yields no concrete IP from any field. Under the default drop_no_ip=True
    # that collapsed the whole NAT tab to empty for tenant-scoped views
    # (regression from the 2026-06-29 NAT filter extension). Keep unattributable
    # NAT rules (drop_no_ip=False): an unresolved target leaks no internal IP,
    # and a rule whose concrete IP belongs to a *different* tenant is still
    # dropped by the has_concrete branch below. dhcp/dns/interfaces keep the
    # strict default (empty/stopped rows shouldn't leak across tenants).
    drop_no_ip = endpoint != "nat"
    out = filter_items_by_prefixes(data, prefixes, fields,
                                   drop_no_ip=drop_no_ip, tenant_category=tenant_cat)
    logger.debug("DIAG filter_fw[%s] filtered %d -> %d drop_no_ip=%s",
                   endpoint, before, _list_len(out), drop_no_ip)
    return out


async def filter_nw(hub, sessions: dict, request: "Request", data, endpoint: str,
                    explicit_tenant=None):
    """Network Devices subnet filter: field-based on the concrete-IP columns of
    the MAC-table / ARP / interfaces views. Tenant-aware with the same contract
    as ``filter_fw`` — an explicit ``?tenant=`` scopes admins to that tenant's
    prefixes; no explicit tenant → legacy session-tenant behavior (no-op for
    admins, session tenant for non-admins). The ``nw`` subnet-filter toggle
    gates both paths; empty prefixes → no filter. ``devices``/``info`` carry no
    tenant-IP list and pass through unfiltered. MAC/ARP use drop_no_ip=False (a
    MAC-only row leaks no cross-tenant IP); interfaces keep the strict default.
    """
    spec = _NW_FILTER_SPEC.get(endpoint)
    if not spec:
        return data  # devices / info / unknown → no IP to filter on
    mode, fields = spec
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        if not filter_enabled(hub, "nw"):
            return data
        prefixes = await resolve_prefixes_for_tenant(hub, tid)
    else:
        sess = session_user(sessions, request)
        if not sess or is_admin(sess):
            return data
        if not filter_enabled(hub, "nw"):
            return data
        prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return data
    drop_no_ip = endpoint not in ("macs", "arp")
    before = _list_len(data)
    out = filter_items_by_prefixes(data, prefixes, fields, drop_no_ip=drop_no_ip)
    logger.debug("DIAG filter_nw[%s] tid=%r prefixes=%d filtered %d -> %d "
                   "drop_no_ip=%s", endpoint, tid, len(prefixes), before,
                   _list_len(out), drop_no_ip)
    return out


async def gate_record(hub, sessions: dict, request: "Request", record, module: str, ip_fields):
    """Gate a single-record endpoint (e.g. CPPM device-enrich): return the record
    if it may be shown, else ``None``. No-op for admins / disabled modules /
    tenants without prefixes."""
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return record
    if not filter_enabled(hub, module):
        return record
    prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return record
    return filter_record_by_prefixes(record, prefixes, ip_fields)


def _list_len(data) -> int:
    """Best-effort record count of a spoke envelope (for DIAG logging)."""
    container, key = _find_list_slot(data)
    if container is None:
        return -1
    lst = container if key is None else container[key]
    return len(lst) if isinstance(lst, list) else -1


def _template_pools(hub) -> list:
    """Configured Proxmox template pool names (VMs in these pools are visible to
    ALL tenants). Read from ``global_config.pxmx_template_pools`` (list) or
    ``pxmx_template_pool`` (string / comma-separated). Defaults to
    ``["Templates", "Template"]`` (case-insensitive match covers 'templates').
    """
    gc = hub.state.system_state.get("global_config", {}) or {}
    pools = gc.get("pxmx_template_pools")
    if pools is None:
        pools = gc.get("pxmx_template_pool")
    if not pools:
        return ["Templates", "Template"]
    if isinstance(pools, str):
        return [p.strip() for p in pools.split(",") if p.strip()]
    if isinstance(pools, list):
        return [str(p).strip() for p in pools if str(p).strip()]
    return []


def _tenant_tag_set(hub, tid) -> set:
    """Lowercased set of identifiers a VM's Proxmox tag can match to count as
    'tagged for this tenant': the tenant id, display name, slug, netbox slug,
    and proxmox_tag (the per-tenant hypervisor scope)."""
    t = hub.state.get_tenant(tid) or {}
    return {str(x).strip().lower() for x in
            [tid, t.get("name"), t.get("slug"), t.get("netbox_tenant_slug"), t.get("proxmox_tag")]
            if x}


async def filter_tenant(hub, sessions: dict, request: "Request", data, module: str, ip_fields,
                         explicit_tenant: str = None):
    """Tenant-aware filter (renamed from ``filter_session_tenant`` — it filters a
    tenant's data by subnet plus module-specific overrides, not just subnet).

    When ``explicit_tenant`` resolves to a real tenant (an admin selecting a
    tenant, or a multi-tenant user switching to an allowed one), scope by THAT
    tenant's prefixes — even for admins, who otherwise bypass the filter. No
    explicit tenant → delegate to the legacy session-tenant ``filter_session``
    (no-op for admins with nothing selected, preserving backward compatibility).

    The ``hypervisor`` module uses ``filter_hypervisor_vms`` with two overrides
    on top of the subnet match: VMs in a configured template pool are visible to
    ALL tenants (shared templates), and VMs whose Proxmox tag matches the tenant
    are shown to that tenant regardless of subnet.
    """
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        enabled = filter_enabled(hub, module)
        prefixes = await resolve_prefixes_for_tenant(hub, tid) if enabled else []
        before = _list_len(data)
        # DIAG: pinpoints where the admin-switcher filter diverges. Remove once
        # the cross-tenant leak is resolved.
        logger.debug("DIAG filter_tenant[%s] explicit=%r tid=%r enabled=%s "
                       "prefixes=%d items_before=%d ip_fields=%s", module, explicit_tenant,
                       tid, enabled, len(prefixes), before, ip_fields)
        if not enabled or not prefixes:
            return data
        if module == "hypervisor":
            out = filter_hypervisor_vms(data, prefixes,
                                        template_pools=_template_pools(hub),
                                        tenant_tags=_tenant_tag_set(hub, tid))
        else:
            out = filter_items_by_prefixes(data, prefixes, ip_fields)
        logger.debug("DIAG filter_tenant[%s] filtered %d -> %d prefixes=%s",
                       module, before, _list_len(out), prefixes)
        return out
    # Hypervisor with no explicit tenant: still apply the template-pool + tag
    # overrides for the session tenant (non-admin). Admins with no selected
    # tenant bypass (see all); a session tenant scopes by its own prefixes.
    if module == "hypervisor":
        sess = session_user(sessions, request)
        scope_tid = sess.get("user", {}).get("tenant_id") if sess and not is_admin(sess) else None
        if not scope_tid or not filter_enabled(hub, "hypervisor"):
            return data
        prefixes = await resolve_prefixes_for_tenant(hub, scope_tid)
        if not prefixes:
            return data
        return filter_hypervisor_vms(data, prefixes,
                                     template_pools=_template_pools(hub),
                                     tenant_tags=_tenant_tag_set(hub, scope_tid))
    logger.debug("DIAG filter_tenant[%s] FALLBACK legacy (explicit=%r tid=%r) "
                   "-> admin-bypass/no-op path", module, explicit_tenant, tid)
    return await filter_session(hub, sessions, request, data, module, ip_fields)


async def gate_record_tenant(hub, sessions: dict, request: "Request", record, module: str, ip_fields,
                                    explicit_tenant: str = None):
    """Tenant-aware single-record gate (device-enrich). Returns ``record`` if its
    IP is in the selected tenant's prefixes, else ``None``; no explicit tenant →
    legacy ``gate_record`` (no-op for admins)."""
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        if not filter_enabled(hub, module):
            return record
        prefixes = await resolve_prefixes_for_tenant(hub, tid)
        if not prefixes:
            return record
        return filter_record_by_prefixes(record, prefixes, ip_fields)
    return await gate_record(hub, sessions, request, record, module, ip_fields)