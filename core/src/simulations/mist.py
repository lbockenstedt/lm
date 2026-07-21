"""Hub-side Juniper Mist API client (centralized processing mode).

This is the hub-owned twin of the cs spoke's ``MistClient``
(``cs/lm-spoke/src/mist.py``). In **centralized** processing mode
(``processing_modes.mist_api == "centralized"``) the HUB holds the Mist API
token + org id (Setup → Mist API → ``mist_config``) and makes the calls to
Mist itself — the cs spoke is just a telemetry relay. The three
``*_from_config`` helpers below mirror ``aruba.test_central_from_config`` /
``get_central_available_from_config`` / ``browse_all_from_config`` so the
hub's Mist routes (Test / available-checks / browse) work without contacting
a spoke, identical to how centralized Aruba Central works.

Auth: Mist uses a STATIC API token (``Authorization: Token <apitoken>``) — no
OAuth/refresh dance (unlike Aruba). The org id is required; the API host is
region-scoped (``api.mist.com`` default; ``api.eu.mist.com`` / ``api.gc1.mist.com``
/ ``api.ac2.mist.com`` / ``api.ac5.mist.com`` for the other regions).

Alert-namespace note: ``alert_type_counts`` keys are the BARE Mist alarm
``type`` (e.g. ``device_down``), NOT prefixed. The ``Central:`` / ``Mist:``
prefix that disambiguates a Central ``device_down`` from a Mist one is applied
ONLY in the sim-quota catalog/picker (Setup → Sim Quotas) — see
``sim_quota`` / ``routes._alert_insight_catalog``. The dashboard Checks view and
the reports read these bare counts directly, so the prefix never leaks onto
them (per the user's "prefix only in the setup screens" rule).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict

import httpx

logger = logging.getLogger(__name__)

# Default Mist API host (Global 01). Other regions: api.eu.mist.com (EMEA),
# api.gc1.mist.com (Global 02), api.ac2.mist.com (Global 03), api.ac5.mist.com
# (APAC). The operator picks the region their org lives in at Setup → Mist API.
_DEFAULT_MIST_HOST = "api.mist.com"
_KNOWN_MIST_HOSTS = {
    "api.mist.com", "api.eu.mist.com", "api.gc1.mist.com",
    "api.ac2.mist.com", "api.ac5.mist.com",
}

# Module-level caches keyed by config_hash (like aruba.py). Caching means N
# mapped sites share 1 org-level API call per poll cycle instead of N calls.
# Value: (timestamp_float, payload).
_sites_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_alarms_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_inventory_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_ORG_CACHE_TTL = 270  # 4.5 min — just under the 5-min poll interval
_ALARMS_CACHE_TTL = 300  # 5 min — matches the poll loop
# Per-site client stats are site-scoped, so they're keyed by (config_hash, site_id).
_site_clients_cache: dict[tuple[str, str], tuple[float, list[dict[str, Any]]]] = {}
_SITE_CLIENTS_CACHE_TTL = 270

# Mist alarm types that represent a device going DOWN — surfaced into hw_devices
# so the Hardware tab + per-device monitored checks work like Aruba's AP_DOWN /
# SWITCH_DOWN / GATEWAY_DOWN. Keyed by the bare Mist alarm ``type``.
_DEVICE_DOWN_TYPES = {"ap_offline", "ap_down", "switch_down", "gateway_down", "gw_down", "device_down"}

# Fallback catalog offered when the org has no live alarms yet (mirrors Aruba's
# KNOWN_CLASSIC_ALERT_TYPES fallback so the Setup picker isn't empty on day 1).
_KNOWN_MIST_ALARM_TYPES: dict[str, str] = {
    "device_down": "Device Down",
    "ap_offline": "AP Offline",
    "switch_down": "Switch Down",
    "gateway_down": "Gateway Down",
    "rogue_ap": "Rogue AP Detected",
    "dhcp_failure": "DHCP Failure",
    "dns_failure": "DNS Failure",
    "krack_attack": "KRACK Attack",
    "ap_audio_coverage": "AP Audio Coverage",
    "weak_signal": "Weak Signal",
    "ap_version_mismatch": "AP Version Mismatch",
    "switch_non_mist": "Non-Mist Switch",
}
DEFAULT_MIST_HARDWARE_CHECKS: tuple[dict[str, str], ...] = (
    {"id": "ap_offline", "name": "APs Offline", "device_type": "ap"},
    {"id": "switch_down", "name": "Switches Down", "device_type": "switch"},
    {"id": "gateway_down", "name": "Gateways Down", "device_type": "gateway"},
)
DEFAULT_MIST_MONITORED_CHECKS: tuple[dict[str, str], ...] = (
    {"type": "alert", "id": "ap_offline", "name": "APs Offline"},
    {"type": "alert", "id": "switch_down", "name": "Switches Down"},
    {"type": "alert", "id": "gateway_down", "name": "Gateways Down"},
    {"type": "alert", "id": "rogue_ap", "name": "Rogue AP Detected"},
    {"type": "alert", "id": "CLIENT_COUNT", "name": "Connected Client Count"},
)


def _coerce_host(host: str) -> str:
    """Normalize the configured Mist API host (strip scheme/path, lower-case)."""
    h = str(host or "").strip().lower().rstrip("/")
    # Tolerate a pasted ``https://api.mist.com`` by stripping the scheme.
    if "://" in h:
        h = h.split("://", 1)[1]
    if "/" in h:
        h = h.split("/", 1)[0]
    return h or _DEFAULT_MIST_HOST


def validate_mist_host(host: str) -> str:
    """Return a normalized Mist API host, warning on an unknown region.

    Unlike Aruba's ``validate_cluster_url`` we do NOT resolve/DNS-check the host
    here — Mist's region hosts are a fixed, well-known set and the spoke's own
    SSRF guard (the hub route's validator) runs before creds are ever accepted.
    """
    h = _coerce_host(host)
    if h not in _KNOWN_MIST_HOSTS:
        logger.warning("Mist API host %s is not a known region host", h)
    return h


class MistClient:
    """Juniper Mist API client. One instance per tenant config.

    Mirrors ``aruba.ArubaClient``'s public methods so ``MistPoller`` can be a
    near-twin of ``CentralPoller``. Auth is a static token (no refresh).
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = dict(config)
        self.api_token = str(self.config.get("api_token") or "").strip()
        self.host = _coerce_host(self.config.get("host"))
        self.org_id = str(self.config.get("org_id") or "").strip()
        self._config_hash = hashlib.md5(
            json.dumps(self.config, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]

    def is_configured(self) -> bool:
        """Return ``True`` when a Mist API token + org id are present."""
        return bool(self.api_token and self.org_id)

    def _base_url(self) -> str:
        return f"https://{self.host}"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Token {self.api_token}",
                "Accept": "application/json"}

    async def _get(self, client: httpx.AsyncClient, path: str,
                  params: dict[str, Any] | None = None) -> Any:
        resp = await client.get(
            f"{self._base_url()}{path}",
            headers=self._headers(),
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    # ── severity / status helpers ───────────────────────────────────────────

    @staticmethod
    def _alarm_severity(severity: str) -> str:
        """Map a Mist alarm severity (Critical/Major/Minor/Warning/Info) to a
        UI colour, mirroring Aruba's ``_nc_alert_severity``."""
        s = str(severity or "").lower()
        if s == "critical":
            return "red"
        if s == "major":
            return "orange"
        if s in {"minor", "warning"}:
            return "yellow"
        return "info"

    @staticmethod
    def _finding_status(value: Any) -> str:
        sev = str(value or "").strip().lower()
        if sev in {"critical", "major", "red", "error"}:
            return "red"
        if sev in {"minor", "warning", "fair"}:
            return "yellow"
        if sev in {"info", "clear", "ok", "green", "resolved"}:
            return "green"
        return "yellow"

    # ── cached org-level fetchers ────────────────────────────────────────────

    async def _list_sites(self) -> list[dict[str, Any]]:
        """Return cached org sites (``GET /api/v1/orgs/:org_id/sites``). One API
        call shared across all site queries in a poll cycle."""
        cached = _sites_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _ORG_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                # Mist's list-org-sites is /sites (plural); fall back to the
                # singular /site form on 404 in case of API revision drift.
                payload: Any = None
                for path in (f"/api/v1/orgs/{self.org_id}/sites",
                             f"/api/v1/orgs/{self.org_id}/site"):
                    try:
                        payload = await self._get(http, path, params={"limit": 1000})
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                # Mist returns a bare list for these collection endpoints.
                if isinstance(payload, list):
                    result = payload
                elif isinstance(payload, dict):
                    result = payload.get("sites") or payload.get("result") or payload.get("items") or []
        except Exception as exc:  # noqa: BLE001
            # Cache ONLY on success: a fetch failure must not latch an empty
            # list for the full TTL (that would make every site vanish for
            # ~TTL). Return the last good value if we have one, else empty
            # WITHOUT caching so the next cycle re-fetches.
            logger.warning("Mist sites fetch failed [%s]: %s", self._config_hash, exc)
            return cached[1] if cached else result
        _sites_cache[self._config_hash] = (time.time(), result)
        return result

    async def _site_name_to_id(self) -> dict[str, str]:
        """Map lower-cased site NAME → site_id from the cached sites list (for
        case-insensitive lookup by name)."""
        out: dict[str, str] = {}
        for s in await self._list_sites():
            nm = str(s.get("name") or "").strip()
            sid = str(s.get("id") or s.get("site_id") or "").strip()
            if nm and sid:
                out[nm.casefold()] = sid
        return out

    async def _site_id_to_name(self) -> dict[str, str]:
        """Map site_id → ORIGINAL-CASE site name (for resolving alarm +
        inventory site_ids back to the display name). Distinct from
        ``_site_name_to_id`` which casefolds the name for lookup."""
        out: dict[str, str] = {}
        for s in await self._list_sites():
            nm = str(s.get("name") or "").strip()
            sid = str(s.get("id") or s.get("site_id") or "").strip()
            if nm and sid:
                out[sid] = nm
        return out

    async def _fetch_alarms(self, include_cleared: bool = False) -> list[dict[str, Any]]:
        """Fetch org alarms via ``GET /api/v1/orgs/:org_id/alarms/search`` and
        return ONE normalized entry per raw alarm (NOT grouped), each carrying
        its resolved site NAME, type, severity, group, device name, and active/
        cleared state. Cached 5 min.

        ``include_cleared=False`` (default) returns only ACTIVE alarms — the set
        the dashboard counts as present problems (and the input to
        ``poll_site_data``'s alert_type_counts, which counts per OCCURRENCE so
        two offline APs report ``ap_offline: 2``). ``include_cleared=True`` also
        returns acked/cleared alarms (tagged ``status``) so the Setup picker can
        offer the full universe of alarm types, not just the ones firing now.
        """
        cache_key = f"{self._config_hash}:{'all' if include_cleared else 'active'}"
        cached = _alarms_cache.get(cache_key)
        if cached and time.time() - cached[0] < _ALARMS_CACHE_TTL:
            return cached[1]

        alarms: list[dict[str, Any]] = []
        try:
            # Resolve site_id → site_name (original case) so alarms key to the
            # right site instead of falling to the global "—" bucket.
            id_to_name = await self._site_id_to_name()
            async with httpx.AsyncClient(timeout=30) as http:
                raw: list[dict[str, Any]] = []
                next_cursor: Any = None
                pages = 0
                # Bounded pagination (<=5 pages) so a looping cursor can never
                # stall browse_all (which awaits alarms + sites in parallel).
                while pages < 5:
                    params: dict[str, Any] = {"limit": 100}
                    if next_cursor:
                        params["next"] = next_cursor
                    payload = await self._get(http, f"/api/v1/orgs/{self.org_id}/alarms/search",
                                              params=params)
                    items = (payload or {}).get("results") or (payload or {}).get("alarms") or []
                    raw.extend(items)
                    pages += 1
                    next_cursor = (payload or {}).get("next")
                    if not items or not next_cursor:
                        break

            if raw:
                logger.info("Mist alarms sample keys [%s]: %s",
                            self._config_hash, sorted(raw[0].keys()))

            for item in raw:
                acked = bool(item.get("acked")) or str(item.get("state") or "").lower() in {"acked", "cleared", "resolved"}
                if acked and not include_cleared:
                    continue
                name = str(item.get("type") or item.get("key") or "alarm").strip()
                sid = str(item.get("site_id") or item.get("siteId") or "").strip()
                site = id_to_name.get(sid, "") or "—"
                alarms.append({
                    "name": name,
                    "site": site,
                    "severity": self._alarm_severity(item.get("severity", "")),
                    "category": str(item.get("group") or "").strip(),
                    "device_type": self._device_type_for(name),
                    "detail": str(item.get("note") or item.get("reason") or "").strip(),
                    "ts": item.get("timestamp") or item.get("last_seen") or None,
                    "status": "cleared" if acked else "active",
                    "device_name": self._alarm_device_name(item),
                })
        except Exception as exc:  # noqa: BLE001
            body = getattr(getattr(exc, "response", None), "text", None)
            logger.warning("Mist alarms fetch [%s]: %s%s", self._config_hash, exc,
                           f" — {body}" if body else "")
        logger.info("Mist alarms fetched [%s]: %d alarms (include_cleared=%s)",
                    self._config_hash, len(alarms), include_cleared)
        ttl_offset = 0 if alarms else (_ALARMS_CACHE_TTL - 60)
        _alarms_cache[cache_key] = (time.time() - ttl_offset, alarms)
        return alarms

    async def _list_alarms(self, include_cleared: bool = False) -> list[dict[str, Any]]:
        """Return alarms GROUPED by (type, site) for the browse view — the same
        alarm firing multiple times shows as one row with an ``N occurrences``
        detail, mirroring Aruba's ``_new_central_alerts`` grouping. Built on top
        of the cached ``_fetch_alarms`` (no extra API call)."""
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for al in await self._fetch_alarms(include_cleared=include_cleared):
            name = str(al.get("name") or "alarm").strip()
            site = str(al.get("site") or "—").strip()
            key = (name.lower(), site.lower())
            if key not in groups:
                groups[key] = {
                    "name": name,
                    "site": site,
                    "severity": al.get("severity", "info"),
                    "category": al.get("category", ""),
                    "device_type": al.get("device_type", ""),
                    "detail": al.get("detail", ""),
                    "ts": al.get("ts"),
                    "status": "cleared",
                    "count": 0,
                }
            groups[key]["count"] += 1
            if al.get("status") == "active":
                groups[key]["status"] = "active"
        out: list[dict[str, Any]] = []
        for entry in groups.values():
            cnt = entry.pop("count")
            if cnt > 1:
                entry["detail"] = f"{cnt} occurrences" + (f" — {entry['detail']}" if entry["detail"] else "")
            out.append(entry)
        return out

    @staticmethod
    def _device_type_for(alarm_type: str) -> str:
        """Infer a device_type (ap/switch/gateway) from a Mist alarm type."""
        t = str(alarm_type or "").lower()
        if t.startswith("ap_") or t == "ap_offline":
            return "ap"
        if "switch" in t:
            return "switch"
        if "gateway" in t or t.startswith("gw_"):
            return "gateway"
        return ""

    async def _site_clients(self, site_id: str) -> list[dict[str, Any]]:
        """Return cached per-site client stats (``GET /api/v1/sites/:site_id/stats/clients``)."""
        ckey = (self._config_hash, site_id)
        cached = _site_clients_cache.get(ckey)
        if cached and time.time() - cached[0] < _SITE_CLIENTS_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                payload = await self._get(http, f"/api/v1/sites/{site_id}/stats/clients",
                                          params={"limit": 1000})
                if isinstance(payload, list):
                    result = payload
                elif isinstance(payload, dict):
                    result = payload.get("clients") or payload.get("results") or payload.get("items") or []
        except Exception as exc:  # noqa: BLE001
            logger.warning("Mist site clients fetch failed [%s:%s]: %s",
                           self._config_hash, site_id, exc)
        _site_clients_cache[ckey] = (time.time(), result)
        return result

    async def _list_inventory(self) -> list[dict[str, Any]]:
        """Return cached org inventory (``GET /api/v1/orgs/:org_id/inventory``)."""
        cached = _inventory_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _ORG_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                page = 1
                while page <= 5:
                    payload = await self._get(http, f"/api/v1/orgs/{self.org_id}/inventory",
                                              params={"limit": 1000, "page": page})
                    if isinstance(payload, list):
                        items = payload
                    elif isinstance(payload, dict):
                        items = payload.get("inventory") or payload.get("result") or payload.get("items") or []
                    else:
                        items = []
                    result.extend(items)
                    if len(items) < 1000:
                        break
                    page += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("Mist inventory fetch failed [%s]: %s", self._config_hash, exc)
        _inventory_cache[self._config_hash] = (time.time(), result)
        return result

    # ── per-site poll (the poller's main input) ──────────────────────────────

    async def poll_site_data(
        self,
        site: str,
        hw_check_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Collect per-site Mist health, client counts, alarm counts, and
        hardware device names — same dict shape as ``ArubaClient.poll_site_data``
        so ``MistPoller`` can consume it identically."""
        if not self.is_configured():
            return {
                "site_health": None,
                "wireless_clients": 0,
                "wired_clients": 0,
                "client_count": 0,
                "alert_type_counts": {},
                "insight_cat_counts": {},
                "hw_devices": {},
            }

        hw_check_ids = {str(c).strip() for c in (hw_check_ids or set()) if str(c).strip()}
        alert_type_counts: dict[str, int] = {}
        insight_cat_counts: dict[str, int] = {}
        hw_devices: dict[str, dict[str, int]] = {}
        wireless_clients = 0
        wired_clients = 0

        # Resolve the configured site NAME → site_id (Mist endpoints are id-keyed).
        name_to_id = await self._site_name_to_id()
        site_id = name_to_id.get(str(site).casefold().strip(), "")
        if not site_id:
            logger.warning("Mist poll_site_data: site %r not found in org %s",
                           site, self.org_id)

        # Clients (per-site stats). Count wired vs wireless.
        if site_id:
            for cl in await self._site_clients(site_id):
                if self._client_is_wireless(cl):
                    wireless_clients += 1
                else:
                    wired_clients += 1

        # Alarms: filter the cached org alarm list by this site's name (each
        # normalized alarm carries its resolved site NAME). Count per OCCURRENCE
        # by bare type — two offline APs report ``ap_offline: 2``.
        # NOTE: alert_type_counts keys are BARE Mist alarm types (no ``Mist:``
        # prefix) — the prefix is applied only in the sim-quota catalog layer.
        alarms = await self._fetch_alarms()
        site_cf = str(site).casefold().strip()
        for al in alarms:
            al_site = str(al.get("site") or "—").strip()
            # A global (site="—") alarm counts for every site, mirroring Aruba;
            # otherwise the alarm must be pinned to THIS site.
            if al_site != "—" and al_site.casefold() != site_cf:
                continue
            atype = str(al.get("name") or "").strip()
            if not atype:
                continue
            alert_type_counts[atype] = alert_type_counts.get(atype, 0) + 1
            group = str(al.get("category") or "").strip()
            if group:
                insight_cat_counts[group] = insight_cat_counts.get(group, 0) + 1
            # Hardware (device-down) alarms → hw_devices, only for enrolled hw checks.
            if atype in _DEVICE_DOWN_TYPES and (not hw_check_ids or atype in hw_check_ids):
                device_name = str(al.get("device_name") or "").strip()
                if device_name:
                    hw_devices.setdefault(atype, {})[device_name] = (
                        hw_devices.setdefault(atype, {}).get(device_name, 0) + 1
                    )

        return {
            "site_health": None,  # TODO: SLE ap-availability score (follow-on chunk)
            "wireless_clients": wireless_clients,
            "wired_clients": wired_clients,
            "client_count": wireless_clients + wired_clients,
            "alert_type_counts": alert_type_counts,
            "insight_cat_counts": insight_cat_counts,
            "hw_devices": hw_devices,
        }

    @staticmethod
    def _client_is_wireless(cl: dict[str, Any]) -> bool:
        """Classify a Mist client as wireless vs wired. Mist stats/clients carry
        a ``type``/``connection_type`` when available; fall back to the presence
        of an SSID / band / ap_mac (wired clients have none of these)."""
        conn = str(cl.get("type") or cl.get("connection_type") or "").lower()
        if "wired" in conn:
            return False
        if "wireless" in conn or "wifi" in conn or "wlan" in conn:
            return True
        return bool(cl.get("ssid") or cl.get("band") or cl.get("ap_mac") or cl.get("bssid"))

    @staticmethod
    def _alarm_device_name(al: dict[str, Any]) -> str:
        """Pull a human-readable device name from a Mist alarm's related-device
        arrays (aps/switches/gateways/hostnames)."""
        for key in ("hostnames", "aps", "switches", "gateways", "bssids"):
            arr = al.get(key)
            if isinstance(arr, list) and arr:
                first = str(arr[0] or "").strip()
                if first:
                    return first
        return str(al.get("device_name") or al.get("detail") or "").strip()

    # ── discovery / browse / catalog (Setup → Mist API tab) ──────────────────

    async def list_sites(self) -> list[dict[str, Any]]:
        """Return normalized Mist sites for hub auto-discovery (same shape as
        ``ArubaClient.list_sites``: ``{name, site_id, health_score,
        wireless_clients}``)."""
        if not self.is_configured():
            return []
        sites: dict[str, dict[str, Any]] = {}
        for item in await self._list_sites():
            nm = str(item.get("name") or "").strip()
            if not nm:
                continue
            sites[nm.casefold()] = {
                "name": nm,
                "site_id": item.get("id") or item.get("site_id") or "",
                "health_score": item.get("health") or item.get("health_score"),
                "wireless_clients": item.get("num_clients") or item.get("client_count"),
            }
        return sorted(sites.values(), key=lambda i: i["name"].casefold())

    async def list_clients(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return normalized clients across the org's sites (same shape as
        ``ArubaClient.list_clients``). Gathers per-site stats/clients (Mist has
        no confirmed org-wide clients endpoint) — cached per site."""
        if not self.is_configured():
            return []
        out: list[dict[str, Any]] = []
        id_to_name = await self._site_id_to_name()
        for sid, nm in id_to_name.items():
            for cl in await self._site_clients(sid):
                out.append({
                    "mac": cl.get("mac") or cl.get("mac_address") or "—",
                    "ip": cl.get("ip_address") or cl.get("ip") or "—",
                    "hostname": cl.get("hostname") or cl.get("name") or "—",
                    "username": cl.get("username") or cl.get("user") or "",
                    "site": nm or "—",
                    "ap": cl.get("ap_name") or cl.get("ap_mac") or "—",
                    "ssid": cl.get("ssid") or cl.get("essid") or "—",
                    "status": "connected" if cl.get("connected") is not False else "—",
                    "os": cl.get("os") or cl.get("device_type") or "—",
                    "vlan": str(cl.get("vlan_id") or cl.get("vlan") or "—"),
                    "connection_type": "wireless" if self._client_is_wireless(cl) else "wired",
                })
            if len(out) >= limit:
                break
        return out[:limit]

    async def browse_all(self) -> dict[str, Any]:
        """Fetch all Mist sites, alarms, clients, and devices for the browse
        view — same shape as ``ArubaClient.browse_all``."""
        if not self.is_configured():
            return {"sites": [], "alerts": [], "insights": [], "clients": [],
                    "devices_by_site": {}, "clients_by_site": {}}

        sites, all_alarms, all_inventory = await asyncio.gather(
            self.list_sites(),
            self._list_alarms(include_cleared=True),
            self._list_inventory(),
            return_exceptions=True,
        )
        if isinstance(sites, Exception):
            raise sites
        if isinstance(all_alarms, Exception):
            all_alarms = []
        if isinstance(all_inventory, Exception):
            all_inventory = []

        # Inventory → devices_by_site (group by site name).
        id_to_name = await self._site_id_to_name()
        devices_by_site: dict[str, list[dict[str, Any]]] = {}
        for dev in all_inventory:
            sid = str(dev.get("site_id") or "").strip()
            sn = id_to_name.get(sid, "—") or "—"
            devices_by_site.setdefault(sn, []).append({
                "name": dev.get("name") or dev.get("serial") or "—",
                "type": dev.get("type") or "",
                "model": dev.get("model") or "",
                "status": "up" if dev.get("connected") else (dev.get("status") or ""),
                "serial": dev.get("serial") or dev.get("id") or "",
                "ip": dev.get("ip") or dev.get("ip_address") or "",
                "firmware": dev.get("fwversion") or dev.get("firmware") or "",
                "last_seen": dev.get("last_seen") or "",
            })

        # Clients → clients_by_site + normalized clients list (gather per site).
        clients_by_site: dict[str, dict[str, Any]] = {}
        normalized_clients: list[dict[str, Any]] = []
        for sid, nm in id_to_name.items():
            for cl in await self._site_clients(sid):
                sn = nm or "—"
                entry = clients_by_site.setdefault(sn, {"total": 0, "wired": 0, "wireless": 0})
                entry["total"] += 1
                if self._client_is_wireless(cl):
                    entry["wireless"] += 1
                else:
                    entry["wired"] += 1
                normalized_clients.append({
                    "mac": cl.get("mac") or "—",
                    "ip": cl.get("ip_address") or cl.get("ip") or "—",
                    "hostname": cl.get("hostname") or cl.get("name") or "—",
                    "username": cl.get("username") or cl.get("user") or "",
                    "site": sn,
                    "ap": cl.get("ap_name") or cl.get("ap_mac") or "—",
                    "ssid": cl.get("ssid") or "—",
                    "status": "connected" if cl.get("connected") is not False else "—",
                    "os": cl.get("os") or "—",
                    "vlan": str(cl.get("vlan_id") or "—"),
                    "connection_type": "wireless" if self._client_is_wireless(cl) else "wired",
                })

        return {
            "sites": sites,
            "alerts": list(all_alarms),
            "insights": [],  # TODO: SLE site insights (follow-on chunk)
            "clients": normalized_clients,
            "devices_by_site": devices_by_site,
            "clients_by_site": clients_by_site,
        }

    async def available_checks(self) -> dict[str, Any]:
        """Return the Mist alarm + hardware catalogs for the Setup picker (same
        shape as ``ArubaClient.available_checks``). Live alarm types are sourced
        from the org's recent alarms; if none, the known-type fallback is shown
        so the picker isn't empty on day 1."""
        if not self.is_configured():
            return {"alerts": [], "insights": [], "hardware": [], "warning": "Mist not configured."}

        alert_types: dict[str, str] = {}
        warnings: list[str] = []
        try:
            for al in await self._list_alarms(include_cleared=True):
                aid = str(al.get("name") or "").strip()
                if not aid:
                    continue
                alert_types[aid] = str(al.get("name") or aid.replace("_", " ").title())
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"Network error fetching Mist alarms: {exc}")

        using_fallback = False
        if not alert_types:
            alert_types = dict(_KNOWN_MIST_ALARM_TYPES)
            using_fallback = True
        if using_fallback:
            warnings.append("No live alarms returned by Mist — showing standard Mist alarm types.")

        hardware_catalog = [
            dict(item) for item in DEFAULT_MIST_HARDWARE_CHECKS
            if item.get("id") in alert_types or item.get("id") in _DEVICE_DOWN_TYPES
        ]
        return {
            "alerts": [{"id": k, "name": v} for k, v in sorted(alert_types.items())],
            "insights": [],  # TODO: SLE metrics (follow-on chunk)
            "hardware": hardware_catalog,
            "warning": "; ".join(dict.fromkeys(warnings)) if warnings else None,
        }

    async def test_connection(self) -> dict[str, Any]:
        """Best-effort connectivity check for the Setup → Mist API "Test" button.
        Mirrors Aruba's ``test_central`` single-spoke shape."""
        if not self.is_configured():
            return {"status": "SUCCESS", "spokes": [{
                "spoke_id": "", "spoke_name": "",
                "token_state": None, "token_valid": False,
                "status": "Mist not configured.",
            }]}
        try:
            async with httpx.AsyncClient(timeout=15) as http:
                await self._get(http, f"/api/v1/orgs/{self.org_id}")
            return {"status": "SUCCESS", "spokes": [{
                "spoke_id": "", "spoke_name": "",
                "token_state": {"api_token": "***", "host": self.host, "org_id": self.org_id},
                "token_valid": True, "status": "Connected.",
            }]}
        except Exception as exc:  # noqa: BLE001
            return {"status": "SUCCESS", "spokes": [{
                "spoke_id": "", "spoke_name": "",
                "token_state": {"api_token": "***", "host": self.host, "org_id": self.org_id},
                "token_valid": False, "status": f"Connection failed: {exc}",
            }]}


# ── hub-side from_config helpers (centralized processing mode) ──────────────
# Mirror aruba.test_central_from_config / get_central_available_from_config /
# browse_all_from_config so the hub's Mist routes (Test / available-checks /
# browse) work without contacting a spoke when mist_api is centralized.

async def test_mist_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Run a single hub-side probe against the Mist API using the hub's stored
    ``mist_config`` creds. Returns one ``spokes`` entry (the same shape the cs
    spoke's ``mist_poller.test_connection`` returns) so the ``/sim/api/{tenant}/
    test-mist`` UI renders it identically.

    ``token_state`` is a short string ("present"/"missing"), NOT the raw token,
    so the API token is never shipped to the browser."""
    client = MistClient(cfg)
    if not client.is_configured():
        logger.info("test_mist [hub/%s]: Mist not configured (no api_token/org_id)", spoke_id)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "missing", "token_valid": False,
                "status": "Mist not configured."}
    chash = client._config_hash
    try:
        async with httpx.AsyncClient(timeout=20) as http:
            await client._get(http, f"/api/v1/orgs/{client.org_id}")
        logger.info("test_mist [hub/%s] cfg=%s: connected to Mist", spoke_id, chash)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "present", "token_valid": True,
                "status": "Connected."}
    except Exception as exc:  # noqa: BLE001 — surface any transport error
        logger.warning("test_mist [hub/%s] cfg=%s FAILED: %r", spoke_id, chash, exc)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "missing", "token_valid": False,
                "status": f"Connection failed: {exc}"}


async def get_mist_available_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Hub-side check-catalog fetch for centralized Mist processing mode.
    Mirrors the cs spoke's ``mist_poller.available_checks()`` so the Mist API
    editor's monitored-check picker works without contacting the spoke. Returns
    the same ``{alerts, insights, hardware, warning}`` shape."""
    client = MistClient(cfg)
    try:
        return await client.available_checks()
    except Exception as exc:  # noqa: BLE001
        logger.warning("get_mist_available [hub/%s] FAILED: %r", spoke_id, exc)
        return {"alerts": [], "insights": [], "hardware": [],
                "warning": f"Mist catalog fetch failed: {exc}"}


async def browse_mist_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Hub-side FULL Mist inventory (sites/alerts/insights/clients/devices) for
    centralized processing mode — mirrors the cs spoke's ``mist_poller.browse()``
    so the Mist -> Sites/Alerts/Clients tabs work without contacting a spoke.
    Returns the same shape ``browse_all`` produces, or an empty set + warning on
    misconfig/error. Named ``browse_mist_`` (not ``browse_all_``) to avoid a
    collision with ``aruba.browse_all_from_config`` when both are imported."""
    client = MistClient(cfg)
    if not client.is_configured():
        return {"status": "SUCCESS", "sites": [], "alerts": [], "insights": [],
                "clients": [], "devices_by_site": {}, "clients_by_site": {},
                "warning": "Mist not configured."}
    try:
        data = await client.browse_all()
        return {"status": "SUCCESS", **data}
    except Exception as exc:  # noqa: BLE001
        logger.warning("browse_all_mist [hub/%s] FAILED: %r", spoke_id, exc)
        return {"status": "ERROR", "message": str(exc), "sites": [], "alerts": [],
                "insights": [], "clients": [], "devices_by_site": {}, "clients_by_site": {}}