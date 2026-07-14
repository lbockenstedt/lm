"""Azure NSG allow-list hook for the LM hub.

Manages ONE named security rule (an 'alias-style' allow-list) inside an Azure
Network Security Group via the Azure Resource Manager REST API. The hub owns the
IP list; on save it reconciles the rule (PUT) so the NSG's source (Inbound) or
destination (Outbound) address set matches — one rule, many IPs, instead of a
rule per IP.

Auth reuses the Entra OIDC app registration's certificate (client-credentials
app token, scope ``https://management.azure.com/.default`` — see
``security.oidc.fetch_app_token``). The app registration must hold an ARM RBAC
role (**Network Contributor**) scoped to the NSG / resource group; without it
ARM returns 403 (surfaced verbatim).

Everything is best-effort + explicit: functions raise ``AzureNsgError`` with the
ARM response body so the route/UI can show the real reason.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

import httpx

from security.oidc import OidcConfig, fetch_app_token

logger = logging.getLogger("AzureNsg")

_API_VERSION = "2023-09-01"
_ARM_SCOPE = "https://management.azure.com/.default"
_ARM = "https://management.azure.com"


class AzureNsgError(Exception):
    """Raised for any NSG/ARM failure; message is safe to surface to the admin."""


def normalize_prefixes(ips) -> List[str]:
    """Validate + normalize a list of IPs/CIDRs to CIDR strings (bare IP → /32,
    /128 for v6). Drops blanks/dupes; raises on a genuinely invalid entry so a
    typo can't silently widen or empty the rule."""
    out: List[str] = []
    seen = set()
    for raw in (ips or []):
        s = str(raw or "").strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            cidr = str(net)
        except ValueError as e:
            raise AzureNsgError(f"invalid IP/CIDR {s!r}: {e}")
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return out


def _cfg_get(azcfg: Dict[str, Any], key: str, default: Any = "") -> Any:
    v = azcfg.get(key)
    return v if v not in (None, "") else default


def _require(azcfg: Dict[str, Any]) -> None:
    for k in ("subscription_id", "resource_group", "nsg_name"):
        if not str(azcfg.get(k) or "").strip():
            raise AzureNsgError(f"Azure NSG config incomplete: '{k}' is required")


def _nsg_base(azcfg: Dict[str, Any]) -> str:
    return (f"{_ARM}/subscriptions/{azcfg['subscription_id']}/resourceGroups/"
            f"{azcfg['resource_group']}/providers/Microsoft.Network/"
            f"networkSecurityGroups/{azcfg['nsg_name']}")


def _rule_url(azcfg: Dict[str, Any]) -> str:
    rule = _cfg_get(azcfg, "rule_name", "lm-allowlist")
    return f"{_nsg_base(azcfg)}/securityRules/{rule}?api-version={_API_VERSION}"


def _rule_properties(azcfg: Dict[str, Any], prefixes: List[str]) -> Dict[str, Any]:
    """Build the securityRule ``properties`` with the managed prefixes on the
    source (Inbound) or destination (Outbound) side; the opposite side is any."""
    direction = str(_cfg_get(azcfg, "direction", "Inbound")).capitalize()
    if direction not in ("Inbound", "Outbound"):
        direction = "Inbound"
    access = str(_cfg_get(azcfg, "access", "Allow")).capitalize()
    if access not in ("Allow", "Deny"):
        access = "Allow"
    protocol = str(_cfg_get(azcfg, "protocol", "*"))
    dports = [p.strip() for p in str(_cfg_get(azcfg, "dest_port", "*")).split(",") if p.strip()] or ["*"]
    try:
        priority = int(_cfg_get(azcfg, "priority", 300))
    except (TypeError, ValueError):
        priority = 300
    priority = max(100, min(4096, priority))
    props: Dict[str, Any] = {
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "sourcePortRange": "*",
        "description": "Managed by LM hub — do not edit by hand",
    }
    managed_key = "sourceAddressPrefixes" if direction == "Inbound" else "destinationAddressPrefixes"
    other_key = "destinationAddressPrefix" if direction == "Inbound" else "sourceAddressPrefix"
    props[managed_key] = prefixes
    props[other_key] = "*"
    if len(dports) == 1:
        props["destinationPortRange"] = dports[0]
    else:
        props["destinationPortRanges"] = dports
    return props


async def _arm_token(cfg: OidcConfig, http: Optional[httpx.AsyncClient] = None) -> str:
    return await fetch_app_token(cfg, _ARM_SCOPE, http=http)


async def test_connection(cfg: OidcConfig, azcfg: Dict[str, Any],
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET the NSG to confirm the token + RBAC + names resolve. Returns a small
    summary ({location, rules}); raises AzureNsgError with the ARM body on error."""
    _require(azcfg)
    token = await _arm_token(cfg, http=http)
    url = f"{_nsg_base(azcfg)}?api-version={_API_VERSION}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code != 200:
        raise AzureNsgError(f"ARM GET NSG failed: HTTP {resp.status_code} — {resp.text[:300]}")
    body = resp.json()
    rules = (body.get("properties", {}) or {}).get("securityRules", []) or []
    return {"location": body.get("location"), "rules": len(rules),
            "nsg_id": body.get("id")}


async def get_allowlist(cfg: OidcConfig, azcfg: Dict[str, Any],
                        http: Optional[httpx.AsyncClient] = None) -> Optional[List[str]]:
    """The prefixes currently on the managed rule in Azure (None if the rule
    doesn't exist yet) — for showing drift vs the hub's stored list."""
    _require(azcfg)
    token = await _arm_token(cfg, http=http)
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        resp = await client.get(_rule_url(azcfg), headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise AzureNsgError(f"ARM GET rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
    props = resp.json().get("properties", {}) or {}
    direction = str(props.get("direction", "Inbound"))
    key = "sourceAddressPrefixes" if direction == "Inbound" else "destinationAddressPrefixes"
    return list(props.get(key) or [])


async def reconcile_allowlist(cfg: OidcConfig, azcfg: Dict[str, Any], ips,
                              http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Make the managed NSG rule match ``ips``. Empty list → DELETE the rule (no
    allow-list) so we never PUT an empty prefixes array (which ARM rejects).
    Returns {applied, prefixes, deleted}."""
    _require(azcfg)
    prefixes = normalize_prefixes(ips)
    token = await _arm_token(cfg, http=http)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    async with (http or httpx.AsyncClient(timeout=30.0)) as client:
        if not prefixes:
            resp = await client.delete(_rule_url(azcfg), headers=headers)
            if resp.status_code not in (200, 202, 204, 404):
                raise AzureNsgError(f"ARM DELETE rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
            logger.info("Azure NSG allow-list cleared (rule deleted) on %s", azcfg.get("nsg_name"))
            return {"applied": True, "prefixes": [], "deleted": True}
        body = {"properties": _rule_properties(azcfg, prefixes)}
        resp = await client.put(_rule_url(azcfg), headers=headers, json=body)
        if resp.status_code not in (200, 201, 202):
            raise AzureNsgError(f"ARM PUT rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
    logger.info("Azure NSG allow-list reconciled: %d prefix(es) on %s/%s",
                len(prefixes), azcfg.get("nsg_name"), _cfg_get(azcfg, "rule_name", "lm-allowlist"))
    return {"applied": True, "prefixes": prefixes, "deleted": False}
