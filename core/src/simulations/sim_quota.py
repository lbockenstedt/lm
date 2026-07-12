"""Sim-Quota config foundation — hub twin of ``cs/lm-spoke/src/sim_quota.py``.

Same schema / validation / resolution + ``SIM_META`` + ``SUGGESTED_ALERT_SIM``.
The hub holds the per-tenant ``central_sites_config`` (with ``sim_quotas``) and
serves the catalog to the WebUI. In **centralized** mode it parses the tenant's
``sim_conf_content`` (raw INI text in the store); in **distributed** mode the
route forwards ``CS_GET_SIM_QUOTA_CATALOG`` to the cs spoke, which reads
``simulation.conf`` directly. Sims are pulled from the simulation config (not a
hardcoded list); the alert→sim marriage is a tenant user action; the global
catalog supplies per-sim metadata defaults + suggested marriages.

Keep this file in sync with the cs twin. The schema/validation block is
intentionally byte-identical so hub and spoke agree on the contract.
"""
from __future__ import annotations

import configparser
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("SimQuota")

# ── Schema (byte-identical to cs/lm-spoke/src/sim_quota.py) ───────────────
SIM_QUOTA_KEYS = ("alert_id", "alert_type", "sim_id", "count", "site", "multi_capable", "enabled")
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
    if not isinstance(raw, dict):
        return {}
    sim_id = str(raw.get("sim_id") or "").strip()
    meta = SIM_META.get(sim_id, {})
    alert_type = str(raw.get("alert_type") or "alert").strip().lower()
    if alert_type not in ALERT_TYPES:
        alert_type = "alert"
    return {
        "alert_id": str(raw.get("alert_id") or "").strip(),
        "alert_type": alert_type,
        "sim_id": sim_id,
        "count": _as_int(raw.get("count"), 1),
        "site": str(raw.get("site") or "").strip(),
        "multi_capable": _as_bool(raw.get("multi_capable"), bool(meta.get("multi_capable", False))),
        "enabled": _as_bool(raw.get("enabled"), False),
    }


def validate_sim_quotas(
    quotas: Any, available_sims: List[str] | None = None,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    clean: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen: Dict[str, Dict[str, Any]] = {}
    sim_set = set(available_sims or [])
    for i, raw in enumerate(quotas or []):
        q = normalize_quota(raw)
        if not q["alert_id"] or not q["sim_id"]:
            errors.append(f"quota #{i}: missing alert_id or sim_id — dropped")
            continue
        if sim_set and q["sim_id"] not in sim_set:
            errors.append(
                f"quota #{i} ({q['alert_id']}): sim_id '{q['sim_id']}' "
                f"not in available sims — dropped")
            continue
        seen[f"{q['alert_type']}:{q['alert_id']}:{q['site']}"] = q
    clean = list(seen.values())
    return clean, errors


def resolve_effective_quotas(
    tenant_quotas: Any, available_sims: List[str] | None = None,
) -> List[Dict[str, Any]]:
    clean, _ = validate_sim_quotas(tenant_quotas, available_sims)
    return [q for q in clean if q["enabled"]]


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