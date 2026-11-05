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
# asyncio: semaphore, concurrent lookups and running the blocking PTR query in a thread.
import asyncio
# ipaddress classifies private/reserved addresses locally.
import ipaddress
# os reads the LM_SECURITY_GEO* environment switches.
import os
# socket performs reverse-DNS (PTR) lookups.
import socket
# time.time() drives cache expiry.
import time
# Type hints only.
from typing import Any, Dict, List, Optional

# httpx is the async HTTP client used to call the geolocation provider.
import httpx

# Named logger for geolocation diagnostics (logging imported here, after its name).
logger_name = "SecurityGeo"
import logging  # noqa: E402
logger = logging.getLogger(logger_name)

# Provider URL template — ``{ip}`` is substituted. ipwho.is is free, keyless and
# HTTPS; override with LM_SECURITY_GEO_URL to point at ip-api.com or a paid tier.
_DEFAULT_PROVIDER = "https://ipwho.is/{ip}"
_CACHE_TTL_S = 12 * 3600      # geo/PTR facts change slowly — cache half a day
_CACHE_MAX = 4096             # bound the cache so a scan flood can't grow it forever
# Short network timeouts so a slow provider or DNS server never stalls the Security view.
_HTTP_TIMEOUT_S = 4.0
_PTR_TIMEOUT_S = 2.0
# At most 8 lookups run at once to stay polite to the free provider.
_MAX_CONCURRENCY = 8

# In-memory cache of enriched records and the semaphore that bounds concurrent lookups.
_cache: Dict[str, Dict[str, Any]] = {}   # ip -> enriched record (with _exp)
_sem = asyncio.Semaphore(_MAX_CONCURRENCY)


def _enabled() -> bool:
    """External geolocation on unless explicitly disabled. PTR + local
    classification always run regardless."""
    # Any of the usual "off" spellings disables the external call.
    return os.environ.get("LM_SECURITY_GEO", "1").strip().lower() not in ("0", "false", "no", "off")


def _provider_url(ip: str) -> str:
    """Build the provider URL for ``ip`` from the configured (or default) template."""
    # Use the operator's override URL if set, otherwise the default provider.
    tmpl = os.environ.get("LM_SECURITY_GEO_URL", "").strip() or _DEFAULT_PROVIDER
    # Insert the IP address into the template.
    return tmpl.replace("{ip}", ip)


def _classify_local(ip: str) -> Optional[Dict[str, Any]]:
    """Return a terminal record for non-public addresses (so we never geolocate
    a LAN/loopback IP), else ``None`` for a routable public address. Also returns
    a terminal record for an unparseable string."""
    # Parse the string; an unparseable address gets an "invalid" record.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "scope": "invalid", "label": "invalid IP"}
    # RFC1918 / loopback / link-local addresses are internal LAN traffic.
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return {"ip": ip, "scope": "private", "label": "private/LAN"}
    # Reserved, multicast and unspecified (0.0.0.0/::) addresses are not geolocatable.
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return {"ip": ip, "scope": "reserved", "label": "reserved"}
    # A normal public address: the caller should geolocate it.
    return None


def _reverse_dns(ip: str) -> str:
    """Return the PTR hostname for ``ip``, or "" when there is none or the lookup fails."""
    # Blocking resolver call; the caller runs it in a thread with a timeout.
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host or ""
    # "No PTR record" and resolver errors simply mean no hostname.
    except (socket.herror, socket.gaierror, OSError):
        return ""
    except Exception:  # noqa: BLE001 — never let PTR failure escape
        return ""


def _parse_geo(data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a provider JSON body into our flat shape, understanding both
    ipwho.is and ip-api.com field names. Returns {} when the body signals
    failure (rate-limited / reserved / private range)."""
    # Non-dict JSON cannot be a valid provider answer.
    if not isinstance(data, dict):
        return {}
    # ipwho.is uses success:bool; ip-api.com uses status:"success"|"fail".
    if data.get("success") is False or data.get("status") == "fail":
        return {}
    conn = data.get("connection") or {}  # ipwho.is nests ISP/org/ASN here
    # Map both providers' field names onto our flat keys, preferring the nested values.
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
    # ipwho.is includes a flag object; keep its emoji when present.
    flag = (data.get("flag") or {}) if isinstance(data.get("flag"), dict) else {}
    if flag.get("emoji"):
        out["flag"] = flag["emoji"]
    # Drop empty fields so the UI only shows what is known.
    return {k: v for k, v in out.items() if v}


async def _geo_lookup(ip: str) -> Dict[str, Any]:
    """Ask the external provider for geolocation data about a public ``ip``; {} on failure."""
    # Respect the operator's opt-out of external lookups.
    if not _enabled():
        return {}
    # Open a short-lived client with a timeout and identifying User-Agent.
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_S,
                                     headers={"User-Agent": "lm-hub-security/1.0"}) as client:
            # Fetch the record; any non-200 (e.g. rate limiting) counts as no data.
            resp = await client.get(_provider_url(ip))
            if resp.status_code != 200:
                return {}
            # Normalise the JSON body into our flat shape.
            return _parse_geo(resp.json())
    # Provider down, timeout or bad JSON: log quietly and return nothing.
    except Exception as e:  # noqa: BLE001 — provider down / timeout / bad JSON
        logger.debug("geo lookup failed for %s: %s", ip, e)
        return {}


def _cache_get(ip: str) -> Optional[Dict[str, Any]]:
    """Return a cached record for ``ip`` (without its expiry field) if still fresh, else None."""
    # Fresh entry: return a copy without the internal expiry timestamp.
    rec = _cache.get(ip)
    if rec and rec.get("_exp", 0) > time.time():
        return {k: v for k, v in rec.items() if k != "_exp"}
    # Expired entry: evict it so it is looked up again.
    if rec:
        _cache.pop(ip, None)
    return None


def _cache_put(ip: str, rec: Dict[str, Any]) -> None:
    """Store ``rec`` for ``ip`` with an expiry time, evicting old entries when full."""
    # Full cache: evict the soonest-expiring tenth (at least one) to make room.
    if len(_cache) >= _CACHE_MAX:
        # Drop the oldest ~10% by expiry to keep the map bounded.
        for old in sorted(_cache, key=lambda k: _cache[k].get("_exp", 0))[:_CACHE_MAX // 10 or 1]:
            _cache.pop(old, None)
    # Save a copy of the record plus its expiry timestamp.
    _cache[ip] = {**rec, "_exp": time.time() + _CACHE_TTL_S}


async def enrich(ip: str) -> Dict[str, Any]:
    """Return an origin record for ``ip`` (best-effort, cached, never raises):
    ``{ip, scope, ptr, country, country_code, region, city, isp, org, asn,
    flag, label}`` — most fields optional. ``scope`` is ``public`` |
    ``private`` | ``reserved`` | ``invalid``."""
    # Normalise the input; an empty string has nothing to look up.
    ip = (ip or "").strip()
    if not ip:
        return {"ip": ip, "scope": "unknown"}
    # Serve from cache when possible.
    cached = _cache_get(ip)
    if cached is not None:
        return cached

    # Private/reserved/invalid addresses are answered locally and cached.
    local = _classify_local(ip)
    if local is not None:
        _cache_put(ip, local)
        return local

    # Limit how many external lookups run concurrently.
    async with _sem:
        cached = _cache_get(ip)  # re-check: another waiter may have filled it
        if cached is not None:
            return cached
        # Run the blocking PTR lookup in a worker thread, giving up after _PTR_TIMEOUT_S.
        loop = asyncio.get_event_loop()
        try:
            ptr = await asyncio.wait_for(
                loop.run_in_executor(None, _reverse_dns, ip), _PTR_TIMEOUT_S)
        # A slow or failed PTR just means no hostname.
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            ptr = ""
        # Geolocate via the provider (empty dict when disabled or failed).
        geo = await _geo_lookup(ip)
        # Assemble the record: public scope, PTR if any, then the geo fields.
        rec: Dict[str, Any] = {"ip": ip, "scope": "public"}
        if ptr:
            rec["ptr"] = ptr
        rec.update(geo)
        # Cache and return the combined record.
        _cache_put(ip, rec)
        return rec


async def enrich_many(ips: List[str]) -> Dict[str, Dict[str, Any]]:
    """Enrich a list of IPs concurrently (de-duplicated, cache-backed). Returns
    ``{ip: record}``. Bounded by the module semaphore inside :func:`enrich`."""
    # Strip blanks and de-duplicate while preserving order.
    uniq = list(dict.fromkeys((ip or "").strip() for ip in (ips or []) if (ip or "").strip()))
    # Enrich all addresses concurrently; exceptions are returned instead of raised.
    results = await asyncio.gather(*(enrich(ip) for ip in uniq), return_exceptions=True)
    # Pair each IP with its record, substituting a placeholder if a lookup raised.
    out: Dict[str, Dict[str, Any]] = {}
    for ip, res in zip(uniq, results):
        out[ip] = res if isinstance(res, dict) else {"ip": ip, "scope": "unknown"}
    return out
