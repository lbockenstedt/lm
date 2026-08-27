"""Best-effort IP origin enrichment for the Security view — reverse DNS (PTR)
plus geolocation (country / region / city / ISP / ASN) for the blocked-IP tiles
and the recent-attempt feed.

Design / safety:
  * PURELY ADVISORY. Every lookup is best-effort and NEVER raises into the
    caller: a failed PTR, a provider timeout, or a disabled lookup just yields a
    partial record. Nothing here gates a block/unblock decision.
  * Private / reserved / loopback / link-local addresses are classified LOCALLY
    (via :mod:`ipaddress`) and NEVER sent to the external provider — an internal
    LAN attempt is labelled ``private/LAN`` instead of being geolocated.
  * Reverse DNS uses the stdlib resolver (``socket.gethostbyaddr``) in a thread,
    with a short timeout so a slow PTR can't stall the event loop.
  * Geolocation calls a single configurable HTTPS provider (default
    ``ipwho.is``; the response parser also understands the ``ip-api.com`` field
    names). The only datum sent off-box is the *attacker's own public IP* — no
    hub/tenant data. Set ``LM_SECURITY_GEO=0`` to disable the external call
    entirely (PTR + local classification still work).
  * Results are cached in-process with a TTL so repeated Security-view polls and
    a busy blocked-IP list don't hammer the provider (free tiers are rate
    limited). Concurrency is bounded by a semaphore.

Leaf module: stdlib + httpx (already a core dependency).
"""
import asyncio
import ipaddress
import os
import socket
import time
from typing import Any, Dict, List, Optional

import httpx

logger_name = "SecurityGeo"
import logging  # noqa: E402
logger = logging.getLogger(logger_name)

# Provider URL template — ``{ip}`` is substituted. ipwho.is is free, keyless and
# HTTPS; override with LM_SECURITY_GEO_URL to point at ip-api.com or a paid tier.
_DEFAULT_PROVIDER = "https://ipwho.is/{ip}"
_CACHE_TTL_S = 12 * 3600      # geo/PTR facts change slowly — cache half a day
_CACHE_MAX = 4096             # bound the cache so a scan flood can't grow it forever
_HTTP_TIMEOUT_S = 4.0
_PTR_TIMEOUT_S = 2.0
_MAX_CONCURRENCY = 8

_cache: Dict[str, Dict[str, Any]] = {}   # ip -> enriched record (with _exp)
_sem = asyncio.Semaphore(_MAX_CONCURRENCY)


def _enabled() -> bool:
    """External geolocation on unless explicitly disabled. PTR + local
    classification always run regardless."""
    return os.environ.get("LM_SECURITY_GEO", "1").strip().lower() not in ("0", "false", "no", "off")


def _provider_url(ip: str) -> str:
    tmpl = os.environ.get("LM_SECURITY_GEO_URL", "").strip() or _DEFAULT_PROVIDER
    return tmpl.replace("{ip}", ip)


def _classify_local(ip: str) -> Optional[Dict[str, Any]]:
    """Return a terminal record for non-public addresses (so we never geolocate
    a LAN/loopback IP), else ``None`` for a routable public address. Also returns
    a terminal record for an unparseable string."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "scope": "invalid", "label": "invalid IP"}
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {"ip": ip, "scope": "private", "label": "private/LAN"}
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return {"ip": ip, "scope": "reserved", "label": "reserved"}
    return None


def _reverse_dns(ip: str) -> str:
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host or ""
    except (socket.herror, socket.gaierror, OSError):
        return ""
    except Exception:  # noqa: BLE001 — never let PTR failure escape
        return ""


def _parse_geo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a provider JSON body into our flat shape, understanding both
    ipwho.is and ip-api.com field names. Returns {} when the body signals
    failure (rate-limited / reserved / private range)."""
    if not isinstance(data, dict):
        return {}
    # ipwho.is uses success:bool; ip-api.com uses status:"success"|"fail".
    if data.get("success") is False or data.get("status") == "fail":
        return {}
    conn = data.get("connection") or {}  # ipwho.is nests ISP/org/ASN here
    out = {
        "country": data.get("country") or "",
        "country_code": data.get("country_code") or data.get("countryCode") or "",
        "region": data.get("region") or data.get("regionName") or "",
        "city": data.get("city") or "",
        "isp": conn.get("isp") or data.get("isp") or data.get("org") or "",
        "org": conn.get("org") or data.get("org") or "",
        "asn": (str(conn.get("asn")) if conn.get("asn") is not None else "")
               or data.get("as") or data.get("asn") or "",
    }
    flag = (data.get("flag") or {}) if isinstance(data.get("flag"), dict) else {}
    if flag.get("emoji"):
        out["flag"] = flag["emoji"]
    return {k: v for k, v in out.items() if v}


async def _geo_lookup(ip: str) -> Dict[str, Any]:
    if not _enabled():
        return {}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S,
                                     headers={"User-Agent": "lm-hub-security/1.0"}) as client:
            resp = await client.get(_provider_url(ip))
            if resp.status_code != 200:
                return {}
            return _parse_geo(resp.json())
    except Exception as e:  # noqa: BLE001 — provider down / timeout / bad JSON
        logger.debug("geo lookup failed for %s: %s", ip, e)
        return {}


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    rec = _cache.get(ip)
    if rec and rec.get("_exp", 0) > time.time():
        return {k: v for k, v in rec.items() if k != "_exp"}
    if rec:
        _cache.pop(ip, None)
    return None


def _cache_put(ip: str, rec: Dict[str, Any]) -> None:
    if len(_cache) >= _CACHE_MAX:
        # Drop the oldest ~10% by expiry to keep the map bounded.
        for old in sorted(_cache, key=lambda k: _cache[k].get("_exp", 0))[:_CACHE_MAX // 10 or 1]:
            _cache.pop(old, None)
    _cache[ip] = {**rec, "_exp": time.time() + _CACHE_TTL_S}


async def enrich(ip: str) -> Dict[str, Any]:
    """Return an origin record for ``ip`` (best-effort, cached, never raises):
    ``{ip, scope, ptr, country, country_code, region, city, isp, org, asn,
    flag, label}`` — most fields optional. ``scope`` is ``public`` |
    ``private`` | ``reserved`` | ``invalid``."""
    ip = (ip or "").strip()
    if not ip:
        return {"ip": ip, "scope": "unknown"}
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    local = _classify_local(ip)
    if local is not None:
        _cache_put(ip, local)
        return local

    async with _sem:
        cached = _cache_get(ip)  # re-check: another waiter may have filled it
        if cached is not None:
            return cached
        loop = asyncio.get_event_loop()
        try:
            ptr = await asyncio.wait_for(
                loop.run_in_executor(None, _reverse_dns, ip), _PTR_TIMEOUT_S)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            ptr = ""
        geo = await _geo_lookup(ip)
        rec: Dict[str, Any] = {"ip": ip, "scope": "public"}
        if ptr:
            rec["ptr"] = ptr
        rec.update(geo)
        _cache_put(ip, rec)
        return rec


async def enrich_many(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Enrich a list of IPs concurrently (de-duplicated, cache-backed). Returns
    ``{ip: record}``. Bounded by the module semaphore inside :func:`enrich`."""
    uniq = list(dict.fromkeys((ip or "").strip() for ip in (ips or []) if (ip or "").strip()))
    results = await asyncio.gather(*(enrich(ip) for ip in uniq), return_exceptions=True)
    out: Dict[str, Dict[str, Any]] = {}
    for ip, res in zip(uniq, results):
        out[ip] = res if isinstance(res, dict) else {"ip": ip, "scope": "unknown"}
    return out
