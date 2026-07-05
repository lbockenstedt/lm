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
_FILTER_MODULES = ("nac", "firewall", "netbox", "dhcp", "cs", "hypervisor", "nw")
_FILTER_DEFAULTS = {"nac": True, "firewall": True, "netbox": True,
                            "dhcp": True, "cs": False, "hypervisor": True, "nw": True}

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


def has_module_access(sess, right: str) -> bool:
    """True if the session user may use a permission-gated module.

    Admins always pass; otherwise the user's permissions must carry an explicit
    ``right`` (set in User Management). Shared by the Network Devices (``nw``)
    and IPAM (``ipam``) module gates — mirrors ``has_cs_access`` so nav-hiding
    (frontend ``canSeeModule``) and API access agree. ``right`` is the
    permissions key (``"nw"`` / ``"ipam"`` / ``"cs"`` …), not a display label.
    """
    if is_admin(sess):
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
    """
    sess = session_user(sessions, request)
    if not sess or is_admin(sess):
        return data
    if not filter_enabled(hub, module):
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
    logger.warning("DIAG filter_fw[%s] tid=%r enabled=%s prefixes=%d "
                   "items_before=%d mode=%s tenant_cat=%r", endpoint, tid, True,
                   len(prefixes), before, mode, tenant_cat)
    if mode == "fw":
        alias_map = await _fw_alias_map(hub, firewall_id) if firewall_id else None
        out = filter_firewall_rules(data, prefixes, alias_map, tenant_category=tenant_cat)
        logger.warning("DIAG filter_fw[%s] filtered %d -> %d alias_map=%s",
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
    logger.warning("DIAG filter_fw[%s] filtered %d -> %d drop_no_ip=%s",
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
    logger.warning("DIAG filter_nw[%s] tid=%r prefixes=%d filtered %d -> %d "
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
        logger.warning("DIAG filter_tenant[%s] explicit=%r tid=%r enabled=%s "
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
        logger.warning("DIAG filter_tenant[%s] filtered %d -> %d prefixes=%s",
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
    logger.warning("DIAG filter_tenant[%s] FALLBACK legacy (explicit=%r tid=%r) "
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