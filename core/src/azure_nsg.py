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
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# ipaddress validates IPs/CIDRs and normalises them (e.g. bare IP -> /32).
import ipaddress
# Standard-library logging for reconcile messages.
import logging
# Type hints only.
from typing import Any, Dict, List, Optional

# httpx is the async HTTP client used to call Azure Resource Manager (ARM).
import httpx

# Helper that reuses a caller's HTTP client or creates (and closes) its own.
from http_client import shared_client

# Re-exported helpers from the OCI module; both NSG backends share the entry DB shape.
from oci_nsg import entries_to_ips, merge_live_prefixes  # noqa: F401 — same entry DB shape
# OIDC config type and the helper that gets an app-only token for ARM.
from security.oidc import OidcConfig, fetch_app_token

# One named logger so Azure NSG messages can be filtered together.
logger = logging.getLogger("AzureNsg")

# ARM network API version used for every request.
_API_VERSION = "2023-09-01"
# OAuth scope meaning "all ARM permissions granted to this app".
_ARM_SCOPE = "https://management.azure.com/.default"
# ARM base URL.
_ARM = "https://management.azure.com"


class AzureNsgError(Exception):
    """Raised for any NSG/ARM failure; message is safe to surface to the admin."""


def normalize_entries(entries) -> List[Dict[str, str]]:
    """Validate + normalize the local allow-list DB: a list of ``{ip, description}``
    (bare strings accepted too). ip → CIDR (bare IP gets /32 · /128), deduped by
    ip (a later non-empty description wins). Descriptions are hub-local — Azure NSG
    rules have no per-IP description, so they never leave here. Raises on a bad ip."""
    # Normalised entries, plus an index from CIDR to position for de-duplication.
    out: List[Dict[str, str]] = []
    idx: Dict[str, int] = {}
    # Walk every stored entry.
    for e in (entries or []):
        # Bare string: it is just the IP, with no description.
        if isinstance(e, str):
            ip, desc = e, ""
        # Dict: accept "ip" or legacy "address", plus an optional description.
        elif isinstance(e, dict):
            ip = str(e.get("ip") or e.get("address") or "").strip()
            desc = str(e.get("description") or "").strip()
        # Anything else is ignored.
        else:
            continue
        # Skip blank IPs.
        if not ip:
            continue
        # Normalise to CIDR form; a typo raises so it cannot silently change the rule.
        try:
            cidr = str(ipaddress.ip_network(ip, strict=False))
        except ValueError as ex:
            raise AzureNsgError(f"invalid IP/CIDR {ip!r}: {ex}")
        # Duplicate: keep the first position but let a later non-empty description win.
        if cidr in idx:
            if desc:
                out[idx[cidr]]["description"] = desc
        # New CIDR: remember its position and add it.
        else:
            idx[cidr] = len(out)
            out.append({"ip": cidr, "description": desc})
    # Return the cleaned list.
    return out


def normalize_prefixes(ips) -> List[str]:
    """Validate + normalize a list of IPs/CIDRs to CIDR strings (bare IP → /32,
    /128 for v6). Drops blanks/dupes; raises on a genuinely invalid entry so a
    typo can't silently widen or empty the rule."""
    # Normalised CIDRs in original order, plus a set for de-duplication.
    out: List[str] = []
    seen = set()
    # Walk every supplied value.
    for raw in (ips or []):
        # Trim and skip blanks.
        s = str(raw or "").strip()
        if not s:
            continue
        # Normalise to CIDR form; strict=False accepts host bits set (e.g. 10.0.0.5/24).
        try:
            net = ipaddress.ip_network(s, strict=False)
            cidr = str(net)
        # A genuinely invalid value aborts the whole update.
        except ValueError as e:
            raise AzureNsgError(f"invalid IP/CIDR {s!r}: {e}")
        # Add each CIDR only once.
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return out


def _cfg_get(azcfg: Dict[str, Any], key: str, default: Any = "") -> Any:
    """Return ``azcfg[key]`` unless it is missing/None/empty, in which case return ``default``."""
    # Treat None and "" as "not set".
    v = azcfg.get(key)
    return v if v not in (None, "") else default


def _require(azcfg: Dict[str, Any]) -> None:
    """Raise AzureNsgError unless the settings needed to locate the NSG are filled in."""
    # Subscription, resource group and NSG name together identify the NSG in ARM.
    for k in ("subscription_id", "resource_group", "nsg_name"):
        if not str(azcfg.get(k) or "").strip():
            raise AzureNsgError(f"Azure NSG config incomplete: '{k}' is required")


def _nsg_base(azcfg: Dict[str, Any]) -> str:
    """Return the ARM resource URL of the configured NSG (without api-version)."""
    return (f"{_ARM}/subscriptions/{azcfg['subscription_id']}/resourceGroups/"
            f"{azcfg['resource_group']}/providers/Microsoft.Network/"
            f"networkSecurityGroups/{azcfg['nsg_name']}")


def _rule_url(azcfg: Dict[str, Any]) -> str:
    """Return the ARM URL of the managed security rule (default name "lm-allowlist")."""
    # The rule name is configurable.
    rule = _cfg_get(azcfg, "rule_name", "lm-allowlist")
    # The rule lives under the NSG's securityRules collection.
    return f"{_nsg_base(azcfg)}/securityRules/{rule}?api-version={_API_VERSION}"


def _rule_properties(azcfg: Dict[str, Any], prefixes: List[str]) -> Dict[str, Any]:
    """Build the securityRule ``properties`` with the managed prefixes on the
    source (Inbound) or destination (Outbound) side; the opposite side is any."""
    # Rule direction, normalised to "Inbound"/"Outbound" (anything else falls back to Inbound).
    direction = str(_cfg_get(azcfg, "direction", "Inbound")).capitalize()
    if direction not in ("Inbound", "Outbound"):
        direction = "Inbound"
    # Allow or Deny, defaulting to Allow.
    access = str(_cfg_get(azcfg, "access", "Allow")).capitalize()
    if access not in ("Allow", "Deny"):
        access = "Allow"
    # Protocol ("*" means any).
    protocol = str(_cfg_get(azcfg, "protocol", "*"))
    # Destination ports: comma-separated list, defaulting to "*" (any).
    dports = [p.strip() for p in str(_cfg_get(azcfg, "dest_port", "*")).split(",") if p.strip()] or ["*"]
    # Rule priority; fall back to 300 if the setting is not a number.
    try:
        priority = int(_cfg_get(azcfg, "priority", 300))
    except (TypeError, ValueError):
        priority = 300
    # Clamp to Azure's valid priority range 100-4096.
    priority = max(100, min(4096, priority))
    # Base rule properties common to both directions.
    props: Dict[str, Any] = {
        "priority": priority,
        "direction": direction,
        "access": access,
        "protocol": protocol,
        "sourcePortRange": "*",
        "description": "Managed by LM hub — do not edit by hand",
    }
    # Inbound rules restrict the source address; outbound rules restrict the destination.
    managed_key = "sourceAddressPrefixes" if direction == "Inbound" else "destinationAddressPrefixes"
    other_key = "destinationAddressPrefix" if direction == "Inbound" else "sourceAddressPrefix"
    # Put our IP list on the managed side and "any" on the other.
    props[managed_key] = prefixes
    props[other_key] = "*"
    # ARM uses a singular field for one port and a plural field for several.
    if len(dports) == 1:
        props["destinationPortRange"] = dports[0]
    else:
        props["destinationPortRanges"] = dports
    # Return the full rule properties for the PUT body.
    return props


async def _arm_token(cfg: OidcConfig, http: Optional[httpx.AsyncClient] = None) -> str:
    """Return an app-only access token for Azure Resource Manager."""
    # Uses the hub's Entra app certificate (client-credentials flow).
    return await fetch_app_token(cfg, _ARM_SCOPE, http=http)


async def test_connection(cfg: OidcConfig, azcfg: Dict[str, Any],
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET the NSG to confirm the token + RBAC + names resolve. Returns a small
    summary ({location, rules}); raises AzureNsgError with the ARM body on error."""
    # Fail early if the NSG location settings are incomplete.
    _require(azcfg)
    # Get an ARM token.
    token = await _arm_token(cfg, http=http)
    # URL of the NSG itself.
    url = f"{_nsg_base(azcfg)}?api-version={_API_VERSION}"
    # Read the NSG; this exercises token, RBAC role and resource names together.
    async with shared_client(http, 20.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    # Any non-200 is surfaced with ARM's reply so the admin sees the real cause.
    if resp.status_code != 200:
        raise AzureNsgError(f"ARM GET NSG failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Summarise: Azure region, number of rules and the NSG's resource id.
    body = resp.json()
    rules = (body.get("properties", {}) or {}).get("securityRules", []) or []
    return {"location": body.get("location"), "rules": len(rules),
            "nsg_id": body.get("id")}


async def get_allowlist(cfg: OidcConfig, azcfg: Dict[str, Any],
                        http: Optional[httpx.AsyncClient] = None) -> Optional[List[str]]:
    """The prefixes currently on the managed rule in Azure (None if the rule
    doesn't exist yet) — for showing drift vs the hub's stored list."""
    # Fail early if the NSG location settings are incomplete.
    _require(azcfg)
    # Get an ARM token.
    token = await _arm_token(cfg, http=http)
    # Read the managed rule.
    async with shared_client(http, 20.0) as client:
        resp = await client.get(_rule_url(azcfg), headers={"Authorization": f"Bearer {token}"})
    # Rule does not exist yet.
    if resp.status_code == 404:
        return None
    # Any other non-200 is a real error.
    if resp.status_code != 200:
        raise AzureNsgError(f"ARM GET rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Pull the address list from whichever side this rule manages.
    props = resp.json().get("properties", {}) or {}
    direction = str(props.get("direction", "Inbound"))
    key = "sourceAddressPrefixes" if direction == "Inbound" else "destinationAddressPrefixes"
    return list(props.get(key) or [])


async def reconcile_allowlist(cfg: OidcConfig, azcfg: Dict[str, Any], ips,
                              http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Make the managed NSG rule match ``ips``. Empty list → DELETE the rule (no
    allow-list) so we never PUT an empty prefixes array (which ARM rejects).
    Returns {applied, prefixes, deleted}."""
    # Fail early if the NSG location settings are incomplete.
    _require(azcfg)
    # Validate/normalise the IP list before touching Azure.
    prefixes = normalize_prefixes(ips)
    # Get an ARM token and build the request headers.
    token = await _arm_token(cfg, http=http)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    # One client for the whole reconcile, with a 30 s timeout.
    async with shared_client(http, 30.0) as client:
        # Empty list: delete the rule, since ARM rejects an empty prefix list.
        if not prefixes:
            resp = await client.delete(_rule_url(azcfg), headers=headers)
            # 404 means already deleted, which is fine.
            if resp.status_code not in (200, 202, 204, 404):
                raise AzureNsgError(f"ARM DELETE rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
            logger.info("Azure NSG allow-list cleared (rule deleted) on %s", azcfg.get("nsg_name"))
            return {"applied": True, "prefixes": [], "deleted": True}
        # Otherwise create/replace the rule with the new prefix list.
        body = {"properties": _rule_properties(azcfg, prefixes)}
        resp = await client.put(_rule_url(azcfg), headers=headers, json=body)
        # Any non-success status is surfaced with ARM's reply.
        if resp.status_code not in (200, 201, 202):
            raise AzureNsgError(f"ARM PUT rule failed: HTTP {resp.status_code} — {resp.text[:300]}")
    # Log the outcome.
    logger.info("Azure NSG allow-list reconciled: %d prefix(es) on %s/%s",
                len(prefixes), azcfg.get("nsg_name"), _cfg_get(azcfg, "rule_name", "lm-allowlist"))
    return {"applied": True, "prefixes": prefixes, "deleted": False}


async def clear_priority_slot(cfg: OidcConfig, azcfg: Dict[str, Any], *,
                              priority: int, direction: str, keep_name: str,
                              http: Optional[httpx.AsyncClient] = None) -> List[str]:
    """Delete any security rule occupying the ``priority`` + ``direction`` slot
    whose name is NOT ``keep_name`` — clearing stale/renamed managed rules that
    would otherwise collide.

    Azure keys rules by name but enforces uniqueness on (priority, direction):
    PUTing a renamed rule while the old-named one still lives at the same
    priority+direction fails with ``SecurityRuleConflict``. Deleting purely by
    the *tracked* previous name misses a rule created under any other name
    (e.g. a hand-made or older-version 'Threat-Monitor-Blocked'). This sweeps
    the slot by its real conflict key so the subsequent PUT always succeeds.

    Best-effort + idempotent: reads the NSG, deletes matching rules by name
    (404-tolerant). Returns the list of deleted rule names."""
    # Fail early if the NSG location settings are incomplete.
    _require(azcfg)
    # Normalise the requested direction (default Inbound).
    want_dir = str(direction or "Inbound").capitalize()
    if want_dir not in ("Inbound", "Outbound"):
        want_dir = "Inbound"
    # The priority must be a number; otherwise there is nothing to clear.
    try:
        want_prio = int(priority)
    except (TypeError, ValueError):
        return []
    # Get an ARM token and build the auth header.
    token = await _arm_token(cfg, http=http)
    headers = {"Authorization": f"Bearer {token}"}
    # Names of rules we delete.
    deleted: List[str] = []
    # One client for the read and all the deletes.
    async with shared_client(http, 30.0) as client:
        # Read the whole NSG to see every rule.
        resp = await client.get(f"{_nsg_base(azcfg)}?api-version={_API_VERSION}", headers=headers)
        if resp.status_code != 200:
            raise AzureNsgError(f"ARM GET NSG failed: HTTP {resp.status_code} — {resp.text[:300]}")
        # The list of security rules on the NSG.
        rules = (resp.json().get("properties", {}) or {}).get("securityRules", []) or []
        # Look for rules that collide with the slot we want.
        for r in rules:
            # Name and properties of this rule.
            name = r.get("name") or ""
            props = r.get("properties", {}) or {}
            # Skip unnamed rules and our own rule.
            if not name or name == keep_name:
                continue
            # Skip rules whose priority is not a number.
            try:
                r_prio = int(props.get("priority"))
            except (TypeError, ValueError):
                continue
            # Different priority: no conflict.
            if r_prio != want_prio:
                continue
            # Different direction: no conflict.
            if str(props.get("direction", "")).capitalize() != want_dir:
                continue
            # Conflict found: delete it by name (404 means already gone).
            del_url = f"{_nsg_base(azcfg)}/securityRules/{name}?api-version={_API_VERSION}"
            dresp = await client.delete(del_url, headers=headers)
            if dresp.status_code not in (200, 202, 204, 404):
                raise AzureNsgError(
                    f"ARM DELETE conflicting rule '{name}' failed: "
                    f"HTTP {dresp.status_code} — {dresp.text[:300]}")
            # Record and log the deletion.
            deleted.append(name)
            logger.info("Azure NSG: cleared conflicting rule '%s' at priority %d/%s on %s",
                        name, want_prio, want_dir, azcfg.get("nsg_name"))
    # Return the names of the rules we removed.
    return deleted
