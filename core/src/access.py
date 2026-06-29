"""Access-control, tenant-scoping, and subnet-filter helpers for the Hub API.

These were previously nested closures defined late inside ``api.create_app()``
(``_session_user``, ``_is_admin``, ``_has_cs_access``, ``_check_tenant_access``,
``_resolve_tenant``, ``_effective_tenant*``, ``_subnet_filter*``,
``get_netbox_spoke``, ``get_tenant_scoping``) plus the shared leaf helpers
``_unwrap_spoke`` and ``_subnet_filter_config``. They are gathered here as
**module-level functions taking their dependencies explicitly** (the live
``_sessions`` dict, the ``hub`` handle) so the logic is importable, testable,
and — critically — no longer lives in a 5,000-line ``create_app()`` closure where
a missing typing import in a nested-def annotation can break hub startup at
app-build time (the .117→.121 regression). With ``from __future__ import
annotations`` here, annotations are strings and never evaluated at import.

``api.create_app()`` keeps thin delegating closures (``def _session_user(req):
return access.session_user(_sessions, req)``) so the ~185 routes keep calling
the same bare names (``_is_admin(sess)``, ``_subnet_filter(req, data, "nac",
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
import logging
from typing import TYPE_CHECKING

from simulations.tenant_filter import (filter_items_by_prefixes,
                                       filter_firewall_rules, filter_record_by_prefixes,
                                       build_alias_map)

if TYPE_CHECKING:  # annotations only — never evaluated at runtime
    from fastapi import Request

logger = logging.getLogger("Hub")

# ── Constants ───────────────────────────────────────────────────────────────

_PREFIX_CACHE_TTL = 300  # seconds — session-prefix cache TTL (was a create_app local)

# Per-module enable map for server-side subnet filtering. Modules whose data
# carries tenant IP addresses (nac, firewall, netbox, dhcp) default ON; the cs
# / Simulations module is scoped by tenant ID instead of subnet, so it defaults
# OFF. Admins can toggle each module in Setup → Simulations.
_SUBNET_FILTER_MODULES = ("nac", "firewall", "netbox", "dhcp", "cs")
_SUBNET_FILTER_DEFAULTS = {"nac": True, "firewall": True, "netbox": True,
                            "dhcp": True, "cs": False}

# Firewall endpoint → filter spec. "rules" uses the strict source/destination
# check; the others use field-based filtering; aliases/health carry no IP and
# are skipped. Mirrors the client field sets in main.js:3928-3952.
_FW_FILTER_SPEC = {
    "rules":      ("fw", None),
    "nat":        ("fields", ["internal_ip", "external_ip", "destination.network"]),
    "dns":        ("fields", ["ip", "value"]),
    "interfaces": ("fields", ["ip", "ipaddr"]),
    "dhcp":       ("fields", ["ip", "address"]),
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


def subnet_filter_config(hub) -> dict:
    """Resolved per-module subnet-filter toggles (stored overrides defaults)."""
    stored = hub.state.system_state.get("subnet_filter_modules", {}) or {}
    return {m: bool(stored.get(m, _SUBNET_FILTER_DEFAULTS.get(m, False)))
            for m in _SUBNET_FILTER_MODULES}


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

def session_user(sessions: dict, request: "Request"):
    """Return the session dict for the current cookie, or None."""
    token = request.cookies.get("lm_session")
    if not token:
        return None
    sess = sessions.get(token)
    if not sess or sess["expires"] < time.time():
        sessions.pop(token, None)
        return None
    return sess


def is_admin(sess) -> bool:
    """True if this session belongs to an admin user.

    Handles both permission formats: {"admin": True} and {"role": "admin"}.
    """
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get("admin") or p.get("role") == "admin")


def has_cs_access(sess) -> bool:
    """True if the session user may use the Simulations (cs) module.

    Admins always pass; otherwise the user's permissions must carry an explicit
    ``cs`` right (set in User Management). Mirrors the frontend ``canSeeModule``
    gate in WebUI/main.js so nav-hiding and API/WebSocket access agree.
    """
    if is_admin(sess):
        return True
    p = (sess or {}).get("user", {}).get("permissions", {})
    return bool(p.get("cs"))


def check_tenant_access(sess, tenant_id: str) -> bool:
    """True if the session user may access ``tenant_id``.

    Admins and users with no tenant restrictions can access everything.
    Otherwise the requested tenant must be in the user's tenants list.
    """
    if not sess:
        return False
    if is_admin(sess):
        return True
    allowed = sess.get("user", {}).get("tenants", [])
    return not allowed or tenant_id in allowed


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
        result = await hub.request_response(spoke_id, "NETBOX_GET_PREFIXES", {"tenant": nb_slug})
        data = unwrap_spoke(result)
        return [p["prefix"] for p in (data.get("prefixes", []) if isinstance(data, dict) else []) if p.get("prefix")]
    except Exception as e:
        logger.warning(f"Failed to fetch prefixes for tenant '{tenant_id}': {e}")
        return []


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

def subnet_filter_enabled(hub, module: str) -> bool:
    return subnet_filter_config(hub).get(module, False)


async def subnet_filter(hub, sessions: dict, request: "Request", data, module: str, ip_fields):
    """Apply server-side subnet filtering to ``data`` for ``module``.

    No-op for admins, for disabled modules, or when the tenant has no prefixes
    (can't filter). Otherwise drops items whose concrete IPs all fall outside the
    tenant's prefixes (see simulations/tenant_filter.py).
    """
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return data
    if not subnet_filter_enabled(hub, module):
        return data
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


async def subnet_filter_fw(hub, sessions: dict, request: "Request", data, endpoint: str,
                           firewall_id=None):
    """Firewall-specific subnet filter: strict source/destination for ``rules``
    (with OPNsense alias resolution via ``_fw_alias_map``), field-based for
    nat/dns/interfaces/dhcp, none for aliases."""
    spec = _FW_FILTER_SPEC.get(endpoint)
    if not spec:
        return data  # aliases / health / unknown → no IP to filter on
    mode, fields = spec
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return data
    if not subnet_filter_enabled(hub, "firewall"):
        return data
    prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return data
    if mode == "fw":
        alias_map = await _fw_alias_map(hub, firewall_id) if firewall_id else None
        return filter_firewall_rules(data, prefixes, alias_map)
    return filter_items_by_prefixes(data, prefixes, fields)


async def subnet_gate_record(hub, sessions: dict, request: "Request", record, module: str, ip_fields):
    """Gate a single-record endpoint (e.g. CPPM device-enrich): return the record
    if it may be shown, else ``None``. No-op for admins / disabled modules /
    tenants without prefixes."""
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return record
    if not subnet_filter_enabled(hub, module):
        return record
    prefixes = await resolve_prefixes(hub, sess)
    if not prefixes:
        return record
    return filter_record_by_prefixes(record, prefixes, ip_fields)


async def subnet_filter_tenant(hub, sessions: dict, request: "Request", data, module: str, ip_fields,
                               explicit_tenant: str = None):
    """Tenant-aware subnet filter. When ``explicit_tenant`` resolves to a real
    tenant (an admin selecting a tenant, or a multi-tenant user switching to an
    allowed one), scope by THAT tenant's prefixes — even for admins, who
    otherwise bypass ``subnet_filter``. No explicit tenant → delegate to the
    legacy session-tenant ``subnet_filter`` (no-op for admins with nothing
    selected, preserving backward compatibility)."""
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        if not subnet_filter_enabled(hub, module):
            return data
        prefixes = await resolve_prefixes_for_tenant(hub, tid)
        if not prefixes:
            return data
        return filter_items_by_prefixes(data, prefixes, ip_fields)
    return await subnet_filter(hub, sessions, request, data, module, ip_fields)


async def subnet_gate_record_tenant(hub, sessions: dict, request: "Request", record, module: str, ip_fields,
                                    explicit_tenant: str = None):
    """Tenant-aware single-record gate (device-enrich). Returns ``record`` if its
    IP is in the selected tenant's prefixes, else ``None``; no explicit tenant →
    legacy ``subnet_gate_record`` (no-op for admins)."""
    tid = effective_tenant(sessions, request, explicit_tenant)
    if explicit_tenant and tid:
        if not subnet_filter_enabled(hub, module):
            return record
        prefixes = await resolve_prefixes_for_tenant(hub, tid)
        if not prefixes:
            return record
        return filter_record_by_prefixes(record, prefixes, ip_fields)
    return await subnet_gate_record(hub, sessions, request, record, module, ip_fields)