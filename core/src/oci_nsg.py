"""Oracle Cloud Infrastructure (OCI) NSG allow-list hook for the LM hub.

The OCI parity feature for ``azure_nsg`` — lets a hub hosted on OCI push its
never-block / trusted-IP list onto a real OCI **Network Security Group** (NSG)
so the same IPs are also allowed at the cloud network layer, not just in the
hub's own auth logic.

Auth is a plain OCI **API signing key** (tenancy OCID + user OCID + key
fingerprint + RSA private key — see
https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm),
resolved through ``security.credential_store`` exactly like the Entra OIDC
client-cert key (``kv:<name>`` / filesystem path / bare secret name), so the
private key can live in Key Vault instead of on disk. Requests are signed
per OCI's HTTP Signature scheme via the shared ``oci_auth`` module (also used
by ``oci_vault.py`` — the OCI parity feature for ``key_vault.py``); the
Azure/Entra code doesn't need any of this, it uses an OAuth app-token instead.

IMPORTANT ASYMMETRY vs. Azure NSG: an OCI Network Security Group only supports
**ALLOW** security rules — traffic that matches no rule is denied by default;
there is no explicit DENY/block rule to reconcile onto (unlike an Azure NSG,
which layers an explicit Deny rule above a lower-priority default Allow). This
module therefore only ever implements the **allow-list** side of the
threat-monitor model (``reconcile_allow`` in ``security.threat_monitor``); the
auto-block (deny) side stays log-only when OCI is the active provider — see
that module's docstring.

A second data-model difference drives ``reconcile_allowlist``'s shape: an OCI
security rule's ``source`` is a SINGLE CIDR (unlike Azure, where one rule
carries a whole ``sourceAddressPrefixes`` list). So instead of PUTting one
rule with many prefixes, this reconciles a SET of rules — one per CIDR —
each tagged with a fixed managed-marker description, added/removed via the
NSG's bulk ``addSecurityRules`` / ``removeSecurityRules`` actions so a
reconcile only ever touches rules it created.

Only one of {Azure NSG, OCI NSG} can be ``enabled`` at a time (see
``cloud_nsg.py`` — the generic dispatcher every other part of the hub should
call instead of importing this module directly) — enforced by
``routes/azure_nsg.py`` / ``routes/oci_nsg.py`` at save time.

Everything is best-effort + explicit: functions raise ``OciNsgError`` with the
OCI response body so the route/UI can show the real reason.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

import httpx

import oci_auth as _oci_auth
from oci_auth import OciAuthConfig as OciConfig  # re-exported: same fields/shape

logger = logging.getLogger("OciNsg")

_API_VERSION = "20160918"
# Tag on every rule this module manages, so a reconcile only ever adds/removes
# rules it created — a hand-made or other-tool rule on the same NSG is never
# touched even if its CIDR happens to collide.
_MANAGED_MARKER = "lm-hub-allowlist"


class OciNsgError(Exception):
    """Raised for any NSG/OCI API failure; message is safe to surface to the admin."""


def get_oci_config(hub) -> OciConfig:
    """Read the stored OCI config from ``global_config`` (admin-set via
    ``/setup/oci-nsg``) and build an :class:`OciConfig`."""
    stored = {}
    try:
        stored = hub.state.system_state.get("global_config", {}).get("oci_nsg", {}) or {}
    except Exception:  # noqa: BLE001 — hub without state (tests)
        stored = {}
    return OciConfig(stored)


# ── entry / prefix normalization (same CIDR semantics as azure_nsg) ──────────

def normalize_entries(entries) -> List[Dict[str, str]]:
    """Validate + normalize the local allow-list DB: a list of ``{ip, description}``
    (bare strings accepted too). ip -> CIDR (bare IP gets /32 · /128), deduped by
    ip (a later non-empty description wins). Raises on a bad ip."""
    out: List[Dict[str, str]] = []
    idx: Dict[str, int] = {}
    for e in (entries or []):
        if isinstance(e, str):
            ip, desc = e, ""
        elif isinstance(e, dict):
            ip = str(e.get("ip") or e.get("address") or "").strip()
            desc = str(e.get("description") or "").strip()
        else:
            continue
        if not ip:
            continue
        try:
            cidr = str(ipaddress.ip_network(ip, strict=False))
        except ValueError as ex:
            raise OciNsgError(f"invalid IP/CIDR {ip!r}: {ex}")
        if cidr in idx:
            if desc:
                out[idx[cidr]]["description"] = desc
        else:
            idx[cidr] = len(out)
            out.append({"ip": cidr, "description": desc})
    return out


def entries_to_ips(entries) -> List[str]:
    """The CIDR list to push to OCI (the ip of each local entry)."""
    return [e["ip"] for e in (entries or []) if isinstance(e, dict) and e.get("ip")]


def merge_live_prefixes(entries: List[Dict[str, str]], live_prefixes) -> tuple:
    """Fold the prefixes CURRENTLY managed on the OCI NSG into the local DB: any
    live IP not already tracked is added with an empty description. Returns
    ``(merged, added_count)``."""
    have = {e["ip"] for e in entries if e.get("ip")}
    merged = list(entries)
    added = 0
    for p in (live_prefixes or []):
        try:
            cidr = str(ipaddress.ip_network(str(p).strip(), strict=False))
        except ValueError:
            continue
        if cidr and cidr not in have:
            have.add(cidr)
            merged.append({"ip": cidr, "description": ""})
            added += 1
    return merged, added


def normalize_prefixes(ips) -> List[str]:
    """Validate + normalize a list of IPs/CIDRs to CIDR strings (bare IP -> /32,
    /128 for v6). Drops blanks/dupes; raises on a genuinely invalid entry."""
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
            raise OciNsgError(f"invalid IP/CIDR {s!r}: {e}")
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)
    return out


def _require(occfg: Dict[str, Any]) -> None:
    if not str(occfg.get("nsg_id") or "").strip():
        raise OciNsgError("OCI NSG config incomplete: 'nsg_id' is required")


def _base_url(cfg: OciConfig) -> str:
    if not cfg.region:
        raise OciNsgError("OCI NSG config incomplete: 'region' is required")
    # Validate BEFORE interpolating: a typo'd region would otherwise only show
    # up as a context-free DNS failure once the request is attempted.
    try:
        region = _oci_auth.validate_region(cfg.region)
    except _oci_auth.OciAuthError as e:
        raise OciNsgError(str(e)) from e
    return f"https://iaas.{region}.oraclecloud.com/{_API_VERSION}"


def _rule_description() -> str:
    return f"Managed by LM hub ({_MANAGED_MARKER}) — do not edit by hand"


def _port_range(occfg: Dict[str, Any]) -> Dict[str, int]:
    raw = str(occfg.get("dest_port") or "443").strip()
    try:
        port = int(raw)
    except (TypeError, ValueError):
        port = 443
    port = max(1, min(65535, port))
    return {"min": port, "max": port}


# ── OCI request signing (Signature Version 1) ───────────────────────────────
# Shared with oci_vault.py — see oci_auth.py. Thin wrappers here just preserve
# this module's existing OciNsgError type for callers/tests.

def _signed_headers(cfg: OciConfig, method: str, url: str,
                    body: Optional[bytes]) -> Dict[str, str]:
    try:
        return _oci_auth.signed_headers(cfg, method, url, body)
    except _oci_auth.OciAuthError as e:
        raise OciNsgError(str(e)) from e


async def _oci_request(cfg: OciConfig, client: httpx.AsyncClient, method: str, url: str, *,
                       json_body: Optional[dict] = None) -> httpx.Response:
    """Issue ONE signed request on an already-open client. Callers own the
    client's lifecycle (opened once per public entry point below) — this must
    NOT close it, since a multi-request operation (e.g. reconcile_allowlist's
    list -> remove -> add) reuses the same client across several calls."""
    try:
        return await _oci_auth.oci_request(cfg, client, method, url, json_body=json_body)
    except _oci_auth.OciAuthError as e:
        raise OciNsgError(str(e)) from e


def _http_error(cfg: OciConfig, what: str, resp: httpx.Response) -> OciNsgError:
    """Build the error for a non-success OCI HTTP response.

    A 401/403 from OCI carries no indication of WHICH credential component was
    wrong, so the locally-verifiable diagnosis (OCID shapes, and whether the
    private key actually matches the configured fingerprint) is appended —
    otherwise the operator is left staring at "NotAuthenticated" with five
    correct-looking fields."""
    msg = f"{what} failed: HTTP {resp.status_code} — {resp.text[:300]}"
    if resp.status_code in (401, 403):
        try:
            msg += _oci_auth.auth_failure_help(cfg)
        except Exception:  # diagnosis must never mask the original failure
            pass
    return OciNsgError(msg)


# ── NSG operations ───────────────────────────────────────────────────────────

async def test_connection(cfg: OciConfig, occfg: Dict[str, Any],
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """GET the NSG to confirm the signing key + IAM policy + OCID resolve.
    Returns a small summary; raises OciNsgError with the OCI body on error."""
    _require(occfg)
    url = f"{_base_url(cfg)}/networkSecurityGroups/{occfg['nsg_id']}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        resp = await _oci_request(cfg, client, "GET", url)
    if resp.status_code != 200:
        raise _http_error(cfg, "OCI GET NSG", resp)
    body = resp.json()
    return {"lifecycle_state": body.get("lifecycleState"), "vcn_id": body.get("vcnId"),
            "nsg_id": body.get("id")}


async def _list_managed_rules(cfg: OciConfig, occfg: Dict[str, Any],
                              client: httpx.AsyncClient) -> Optional[List[dict]]:
    """The NSG's current INGRESS rules that carry OUR managed-marker
    description (None if the NSG itself doesn't exist). ``client`` must
    already be open — see :func:`_oci_request`."""
    url = f"{_base_url(cfg)}/networkSecurityGroups/{occfg['nsg_id']}/securityRules"
    resp = await _oci_request(cfg, client, "GET", url)
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise _http_error(cfg, "OCI GET security rules", resp)
    rules = resp.json() or []
    return [r for r in rules if r.get("direction") == "INGRESS"
            and _MANAGED_MARKER in (r.get("description") or "")]


async def get_allowlist(cfg: OciConfig, occfg: Dict[str, Any],
                        http: Optional[httpx.AsyncClient] = None) -> Optional[List[str]]:
    """The CIDRs currently on OUR managed rules in OCI (None if the NSG
    doesn't exist yet) — for showing drift vs the hub's stored list."""
    _require(occfg)
    async with (http or httpx.AsyncClient(timeout=20.0)) as client:
        rules = await _list_managed_rules(cfg, occfg, client)
    if rules is None:
        return None
    return sorted({r.get("source") for r in rules if r.get("source")})


async def reconcile_allowlist(cfg: OciConfig, occfg: Dict[str, Any], ips,
                              http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Make the managed INGRESS allow rules on the NSG match ``ips``.

    OCI security rules have a single ``source`` each (unlike Azure's
    prefix-list rule), so this reconciles a SET of rules — one per CIDR,
    tagged with the managed-marker description — via the NSG's bulk
    ``addSecurityRules`` / ``removeSecurityRules`` actions. Only rules
    carrying the marker are ever touched. Returns
    ``{applied, prefixes, added, removed}``."""
    _require(occfg)
    prefixes = normalize_prefixes(ips)
    base = f"{_base_url(cfg)}/networkSecurityGroups/{occfg['nsg_id']}"
    async with (http or httpx.AsyncClient(timeout=30.0)) as client:
        existing = await _list_managed_rules(cfg, occfg, client)
        if existing is None:
            raise OciNsgError(f"NSG {occfg['nsg_id']} not found")
        have = {r.get("source"): r.get("id") for r in existing if r.get("source")}
        to_add = [p for p in prefixes if p not in have]
        to_remove_ids = [rid for src, rid in have.items() if src not in prefixes]
        if to_remove_ids:
            resp = await _oci_request(
                cfg, client, "POST", f"{base}/actions/removeSecurityRules",
                json_body={"securityRuleIds": to_remove_ids})
            if resp.status_code not in (200, 202):
                raise _http_error(cfg, "OCI removeSecurityRules", resp)
        if to_add:
            rules = [{
                "direction": "INGRESS",
                "protocol": "6",  # TCP
                "isStateless": False,
                "source": p,
                "sourceType": "CIDR_BLOCK",
                "description": _rule_description(),
                "tcpOptions": {"destinationPortRange": _port_range(occfg)},
            } for p in to_add]
            resp = await _oci_request(
                cfg, client, "POST", f"{base}/actions/addSecurityRules",
                json_body={"securityRules": rules})
            if resp.status_code not in (200, 201, 202):
                raise _http_error(cfg, "OCI addSecurityRules", resp)
    logger.info("OCI NSG allow-list reconciled: %d prefix(es) (+%d/-%d) on %s",
                len(prefixes), len(to_add), len(to_remove_ids), occfg.get("nsg_id"))
    return {"applied": True, "prefixes": prefixes, "added": len(to_add), "removed": len(to_remove_ids)}
