"""Sim-Quota config foundation — hub twin of ``cs/lm-spoke/src/sim_quota.py``.

Same schema / validation / resolution + ``SIM_META`` + ``SUGGESTED_ALERT_SIM``.
The hub holds the per-tenant ``central_sites_config`` (with ``sim_quotas``) and
serves the catalog to the WebUI. In **centralized** mode it parses the tenant's
``sim_conf_content`` (raw INI text in the store); in **distributed** mode the
route forwards ``CS_GET_SIM_QUOTA_CATALOG`` to the cs spoke, which reads
``simulation.conf`` directly. Sims are pulled from the simulation config (not a
hardcoded list); the alert→sim linkage is a tenant user action; the global
catalog supplies per-sim metadata defaults + suggested linkage.

Keep this file in sync with the cs twin. The schema/validation block is
intentionally byte-identical so hub and spoke agree on the contract.
"""
from __future__ import annotations

import configparser
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("SimQuota")

# ── Schema (byte-identical to cs/lm-spoke/src/sim_quota.py) ───────────────
SIM_QUOTA_KEYS = ("alert_id", "alert_type", "sim_id", "count", "site",
                  "multi_capable", "rehome", "enabled")
ALERT_TYPES = ("alert", "insight")

SIM_META: Dict[str, Dict[str, object]] = {
    "dns_fail":    {"category": "failure", "multi_capable": False},
    "dhcp_fail":   {"category": "failure", "multi_capable": False},
    "assoc_fail":  {"category": "failure", "multi_capable": False},
    "auth_fail":   {"category": "failure", "multi_capable": False},
    "ssidpw_fail": {"category": "failure", "multi_capable": False},
    "port_flap":   {"category": "failure", "multi_capable": False},
    "ping_test":   {"category": "traffic", "multi_capable": True},
    "download":    {"category": "traffic", "multi_capable": True},
    "www_traffic": {"category": "traffic", "multi_capable": True},
    "iperf":       {"category": "traffic", "multi_capable": True},
}

SUGGESTED_ALERT_SIM: Dict[str, str] = {
    "CLIENT_DHCP_FAILURE": "dhcp_fail",
    "CLIENT_ASSOCIATION_FAILURE": "assoc_fail",
    "CLIENT_DISCONNECTED": "assoc_fail",
    "WIRELESS_CLIENT_ROAM": "assoc_fail",
    "DHCP_POOL_EXHAUSTED": "dhcp_fail",
    "CLIENT_DNS_FAILURE": "dns_fail",
}


# ── Coercion + validation (byte-identical to the cs twin) ─────────────────
def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v: Any, default: int = 1) -> int:
    try:
        n = int(str(v).strip())
        return n if n >= 1 else default
    except Exception:
        return default


def normalize_quota(raw: Any) -> Dict[str, Any]:
    """Coerce a raw quota dict to the canonical shape; drop unknown keys.

    A PRESENCE quota (``sim_id`` empty, "Clients Associated") homes N clients
    to a site and runs NO sim — it only guarantees N clients are associated to
    the site (re-homing ``wsite`` if ``rehome``). Presence quotas are ALWAYS
    multi-capable (they don't consume the client for sim purposes; other
    stackable sims may pack onto a presence-homed client)."""
    if not isinstance(raw, dict):
        return {}
    sim_id = str(raw.get("sim_id") or "").strip()
    meta = SIM_META.get(sim_id, {})
    alert_type = str(raw.get("alert_type") or "alert").strip().lower()
    if alert_type not in ALERT_TYPES:
        alert_type = "alert"
    is_presence = not sim_id
    return {
        "alert_id": str(raw.get("alert_id") or "").strip(),
        "alert_type": alert_type,
        "sim_id": sim_id,
        "count": _as_int(raw.get("count"), 1),
        "site": str(raw.get("site") or "").strip(),
        "multi_capable": True if is_presence
        else _as_bool(raw.get("multi_capable"), bool(meta.get("multi_capable", False))),
        "rehome": _as_bool(raw.get("rehome"), False),
        "enabled": _as_bool(raw.get("enabled"), False),
    }


def quota_dedup_key(q: Dict[str, Any]) -> str:
    """The dedup/identity key for a normalized quota.

    A sim quota is keyed by ``alert_type:alert_id:site``. A presence quota
    (``sim_id`` empty — "Clients Associated") has no alert, so it's keyed by
    site alone — one presence count per site, independent of the sim-quota
    namespace. The engine's ``_quota_key`` mirrors this."""
    if not q.get("sim_id"):
        return f"presence::{q.get('site', '')}"
    return f"{q.get('alert_type', 'alert')}:{q.get('alert_id', '')}:{q.get('site', '')}"


def validate_sim_quotas(
    quotas: Any, available_sims: List[str] | None = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Normalize + validate a ``sim_quotas`` list.

    A SIM quota (``sim_id`` set) requires an ``alert_id`` and its ``sim_id``
    must be in *available_sims* (when provided). A PRESENCE quota (``sim_id``
    empty — "Clients Associated") requires a ``site`` and NO ``alert_id``.
    Duplicate keys (``quota_dedup_key``) collapse last-wins."""
    clean: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen: Dict[str, Dict[str, Any]] = {}
    sim_set = set(available_sims or [])
    for i, raw in enumerate(quotas or []):
        q = normalize_quota(raw)
        if not q["sim_id"]:
            if not q["site"]:
                errors.append(f"quota #{i}: presence quota (Clients Associated) "
                              f"requires a site — dropped")
                continue
        else:
            if not q["alert_id"]:
                errors.append(f"quota #{i}: missing alert_id — dropped")
                continue
            if sim_set and q["sim_id"] not in sim_set:
                errors.append(
                    f"quota #{i} ({q['alert_id']}): sim_id '{q['sim_id']}' "
                    f"not in available sims — dropped")
                continue
        seen[quota_dedup_key(q)] = q
    clean = list(seen.values())
    return clean, errors


def resolve_effective_quotas(
    tenant_quotas: Any, available_sims: List[str] | None = None,
) -> List[Dict[str, Any]]:
    clean, _ = validate_sim_quotas(tenant_quotas, available_sims)
    return [q for q in clean if q["enabled"]]


def merge_effective_quotas(
    global_quotas: Any, tenant_quotas: Any,
) -> List[Dict[str, Any]]:
    """Merge platform-wide default quotas with a tenant's overrides.

    SIM quotas merge per ``(alert_type, alert_id)``: if the tenant declares ANY
    quota row for that alert (enabled OR disabled), the tenant OWNS that alert —
    its enabled rows are used and the global default for that alert is
    suppressed (so a tenant can explicitly turn an alert OFF by adding a
    disabled row). Alerts the tenant hasn't touched inherit the global
    default's enabled rows.

    PRESENCE quotas (``sim_id`` empty — "Clients Associated", N clients homed
    to a site, no sim) merge per SITE: a tenant presence row for a site (enabled
    OR disabled) makes the tenant own that site's presence — its enabled row is
    used and the global presence for that site is suppressed; sites the tenant
    hasn't touched inherit the global presence. So a tenant can "17 on MIA"
    globally and "10 on DFW" locally, or disable MIA to drop the global MIA
    presence.

    Both sides are validated + deduped (last-wins per ``quota_dedup_key``)
    before the merge; the result is enabled-only. The cs spoke's SimQuotaEngine
    consumes the resulting list.
    """
    g_clean, _ = validate_sim_quotas(global_quotas, list(SIM_META.keys()))
    # Tenant side is filtered against the full SIM_META primitive set (NOT the
    # bucket-derived available_sims — a sim not yet placed in any bucket is still
    # runnable via a per-client override) so a quota pointing at a non-existent
    # sim_id (typo, or a sim removed from SIM_META) is dropped here, and a
    # sim-config refresh that removes a sim re-merges cleanly without it.
    t_clean, t_errs = validate_sim_quotas(tenant_quotas, list(SIM_META.keys()))
    if t_errs:
        logger.warning("merge_effective_quotas: tenant quota errors: %s", t_errs)

    def _grp_sim(qs: List[Dict[str, Any]]) -> Dict[tuple, List[Dict[str, Any]]]:
        m: Dict[tuple, List[Dict[str, Any]]] = {}
        for q in qs:
            m.setdefault((q["alert_type"], q["alert_id"]), []).append(q)
        return m
    def _grp_site(qs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        m: Dict[str, List[Dict[str, Any]]] = {}
        for q in qs:
            m.setdefault(q["site"], []).append(q)
        return m

    g_sim = [q for q in g_clean if q["sim_id"]]
    g_pres = [q for q in g_clean if not q["sim_id"]]
    t_sim = [q for q in t_clean if q["sim_id"]]
    t_pres = [q for q in t_clean if not q["sim_id"]]

    out: List[Dict[str, Any]] = []
    # SIM quotas — ownership keyed on ALL rows (enabled+disabled) so a tenant's
    # disabled row suppresses the global default for that alert; enabled-only out.
    gmap_all, tmap_all = _grp_sim(g_sim), _grp_sim(t_sim)
    for key, rows in tmap_all.items():
        out.extend(r for r in rows if r.get("enabled"))
    for key, rows in gmap_all.items():
        if key not in tmap_all:
            out.extend(r for r in rows if r.get("enabled"))
    # PRESENCE quotas — ownership per site (a tenant presence row for a site,
    # enabled or disabled, suppresses the global presence for that site).
    gsite, tsite = _grp_site(g_pres), _grp_site(t_pres)
    for site, rows in tsite.items():
        out.extend(r for r in rows if r.get("enabled"))
    for site, rows in gsite.items():
        if site not in tsite:
            out.extend(r for r in rows if r.get("enabled"))
    return out


# ── Catalog from raw INI text (hub centralized mode) ──────────────────────
def _parse_ini(text: str) -> configparser.ConfigParser:
    p = configparser.ConfigParser()
    p.optionxform = str  # preserve key case
    if text:
        try:
            p.read_string(text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("sim_quota: parse INI failed: %s", exc)
    return p


def _bucket_sections(sim_conf: configparser.ConfigParser) -> List[str]:
    return [s for s in (sim_conf.sections() if sim_conf is not None else [])
            if s.startswith("s") and s[1:].isdigit()]


def available_sims_from_ini(sim_conf_text: str) -> List[Dict[str, Any]]:
    """Sims the Sim-Quota UI may offer, derived from the tenant's
    ``simulation.conf`` INI text (bucket sections ∩ runnable SIM_META keys)."""
    flags = list(SIM_META.keys())
    sim_conf = _parse_ini(sim_conf_text)
    bucket_flags: List[str] = []
    seen = set()
    for sec in _bucket_sections(sim_conf):
        for key in sim_conf.options(sec):
            if key in flags and key not in seen:
                seen.add(key)
                bucket_flags.append(key)
    ordered = bucket_flags + [f for f in flags if f not in seen]
    return [
        {"sim_id": f,
         "category": SIM_META.get(f, {}).get("category", "failure"),
         "multi_capable": bool(SIM_META.get(f, {}).get("multi_capable", False))}
        for f in ordered
    ]


def available_sites_from_ini(
    sim_conf_text: str, central_site_mappings: Dict[str, str] | None = None,
) -> List[str]:
    sites: set[str] = set()
    sim_conf = _parse_ini(sim_conf_text)
    for sec in _bucket_sections(sim_conf):
        w = sim_conf.get(sec, "wsite", fallback="").strip()
        if w:
            sites.add(w)
    for k, v in (central_site_mappings or {}).items():
        if k:
            sites.add(str(k))
        if v:
            sites.add(str(v))
    return sorted(sites)


def sim_quota_catalog_from_ini(
    sim_conf_text: str, central_site_mappings: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    return {
        "sims": available_sims_from_ini(sim_conf_text),
        "sites": available_sites_from_ini(sim_conf_text, central_site_mappings),
        "suggested": dict(SUGGESTED_ALERT_SIM),
        "meta": {k: dict(v) for k, v in SIM_META.items()},
    }