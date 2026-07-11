"""Hub-side Aruba Central token client (centralized processing mode).

This is the hub-owned subset of the cs spoke's ``ArubaClient``
(``cs/lm-spoke/src/aruba.py``, itself vendored from
``solutions-hpe/webui-hub/app/aruba.py``). In **centralized** processing mode
(``processing_modes.central_api == "centralized"``) the HUB holds the Aruba
Central cluster credentials (Setup → Central API → ``central_config``) and
makes the call to Central itself — the cs spoke is just a telemetry relay.
The hub historically had no Aruba client at all, so its "Test Connection"
button only echoed cached relayed spoke telemetry and could never validate
the creds the operator typed into the hub form. This client gives the hub
the same token-exchange path the spoke uses, so ``test_central`` can run a
real probe from the hub.

Only the token logic is ported (``__init__`` / ``is_configured`` /
``_token_state`` / ``_new_central_token_url`` / ``_ensure_token``) — the
polling/caching surface is intentionally NOT vendored here; if centralized
mode later needs hub-side polling, port the full ``ArubaClient`` from the
cs spoke instead of growing this file.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx

from access import safe_external_url

logger = logging.getLogger(__name__)

_NEW_CENTRAL_TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2"
_GLP_TOKEN_URL_TEMPLATE = "https://global.api.greenlake.hpe.com/authorization/v2/oauth2/{workspace_id}/token"

# Check catalogs mirrored from the cs spoke's aruba.py so the hub can serve the
# Central API editor's monitored-check picker directly in centralized mode.
DEFAULT_NEW_CENTRAL_MONITORED_CHECKS = (
    {"type": "alert", "id": "SITE_HEALTH", "name": "Site Health Score (0–100)"},
    {"type": "alert", "id": "AP_DOWN", "name": "APs Down / Offline"},
    {"type": "alert", "id": "SWITCH_DOWN", "name": "Switches Down / Offline"},
    {"type": "alert", "id": "GATEWAY_DOWN", "name": "Gateways Down / Offline"},
    {"type": "alert", "id": "CLIENT_COUNT", "name": "Connected Client Count"},
)
DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS = (
    {"id": "AP_DOWN", "name": "APs Down / Offline", "device_type": "ap"},
    {"id": "SWITCH_DOWN", "name": "Switches Down / Offline", "device_type": "switch"},
    {"id": "GATEWAY_DOWN", "name": "Gateways Down / Offline", "device_type": "gateway"},
)
KNOWN_CLASSIC_ALERT_TYPES = {
    "AP_DOWN": "AP Down", "AP_UP": "AP Up", "ACCESS_POINT_DOWN": "Access Point Down",
    "CLIENT_ASSOCIATION_FAILURE": "Client Association Failure",
    "CLIENT_DHCP_FAILURE": "Client DHCP Failure", "CLIENT_DISCONNECTED": "Client Disconnected",
    "DHCP_POOL_EXHAUSTED": "DHCP Pool Exhausted", "IDS_AP_SPOOFED": "IDS AP Spoofed",
    "PORTAL_DOWN": "Portal Down", "RADIO_INTERFERENCE": "Radio Interference",
    "ROGUE_AP_DETECTED": "Rogue AP Detected", "SWITCH_DOWN": "Switch Down",
    "SWITCH_PORT_DOWN": "Switch Port Down", "TUNNEL_DOWN": "Tunnel Down",
    "UPLINK_FAILURE": "Uplink Failure", "VPN_TUNNEL_DOWN": "VPN Tunnel Down",
    "WIRELESS_CLIENT_ROAM": "Wireless Client Roam", "WIRELESS_INTERFERENCE": "Wireless Interference",
}
KNOWN_CLASSIC_INSIGHT_CATEGORIES = {
    "CONNECTIVITY": "Connectivity", "PERFORMANCE": "Performance",
    "RELIABILITY": "Reliability", "SECURITY": "Security",
}

# Module-level caches for new_central global endpoints.
# Caching means 9 sites share 1 API call instead of 27 calls per poll cycle.
# Key: config_hash, Value: (timestamp_float, payload_dict_or_list)
_insights_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_INSIGHTS_CACHE_TTL = 900  # 15 minutes

_alerts_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_ALERTS_CACHE_TTL = 300   # 5 minutes

_sites_health_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_devices_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_nc_clients_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_NC_GLOBAL_CACHE_TTL = 270  # 4.5 min — just under the 5-min poll interval
_KNOWN_CENTRAL_GATEWAY_SUFFIXES = (".api.central.arubanetworks.com", ".api.central.arubanetworks.com.cn")


@dataclass
class ArubaFinding:
    site_name: str
    check_name: str
    status: str  # "red" | "yellow" | "green"
    source: str  # "alert" | "insight"
    raw: dict[str, Any] = field(default_factory=dict)


class ArubaClient:
    """Minimal hub-side Aruba Central client — token exchange only.

    Behavior mirrors ``cs/lm-spoke/src/aruba.py:ArubaClient`` so a creds test
    run on the hub yields the same result the spoke would have produced.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = dict(config or {})
        # SSRF belt-and-suspenders: the save path (/sim/api/aggregate/central)
        # already confines cluster_url to a public https URL with a DNS-rebind
        # check, but a value stored BEFORE that guard existed (or written by a
        # spoke/restore) could still be internal. Neutralize it here so neither
        # the classic token exchange (POST client_id/client_secret to
        # {cluster_url}/oauth2/token) nor the monitoring GETs ever reach an
        # internal host. new_central mode uses a fixed HPE token URL and never
        # touches cluster_url, so clearing it is safe for that mode too.
        raw_cluster_url = (self.config.get("cluster_url") or "").strip().rstrip("/")
        self.cluster_url = raw_cluster_url if safe_external_url(raw_cluster_url) else ""
        # stored central_config carries api_version (new_central|classic) set
        # by the Setup UI (csSaveCentralConn); fall back to classic.
        self.api_version = (self.config.get("api_version")
                            or ("new_central" if self.config.get("mode") == "central" else "classic")
                            ).strip()
        self._config_hash = hashlib.md5(
            json.dumps(self.config, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]
        self._token_cache: Dict[str, Dict[str, Any]] = {self._config_hash: {}}

    def is_configured(self) -> bool:
        return bool(self.cluster_url) or self.api_version == "new_central"

    def _token_state(self) -> Dict[str, Any]:
        return self._token_cache.setdefault(self._config_hash, {})

    def _new_central_token_url(self) -> str:
        workspace_id = str(self.config.get("workspace_id") or "").strip()
        if workspace_id:
            return _GLP_TOKEN_URL_TEMPLATE.format(workspace_id=workspace_id)
        return _NEW_CENTRAL_TOKEN_URL

    async def _ensure_token(self, client: httpx.AsyncClient) -> str:
        now = time.time()
        token_state = self._token_state()
        if token_state.get("access_token") and token_state.get("expires_at", 0) > now + 60:
            return token_state["access_token"]

        if self.api_version == "new_central":
            # Static access token — use directly, no OAuth exchange.
            static_token = str(self.config.get("access_token") or "").strip()
            if static_token:
                token_state.clear()
                token_state.update({"access_token": static_token, "expires_at": now + 7200})
                return static_token

            workspace_id = str(self.config.get("workspace_id") or "").strip()
            resp = await client.post(
                self._new_central_token_url(),
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.config.get("client_id", ""),
                    "client_secret": self.config.get("client_secret", ""),
                },
                timeout=15,
            )
            resp.raise_for_status()
            payload = resp.json()
            if "access_token" not in payload:
                raise ValueError(
                    f"Token endpoint returned no access_token. Response: {json.dumps(payload)[:300]}"
                )
            token_state.clear()
            token_state.update(
                {
                    "access_token": payload["access_token"],
                    "expires_at": now + int(payload.get("expires_in", 900 if workspace_id else 7200)),
                }
            )
            return token_state["access_token"]

        access_token = self.config.get("access_token")
        refresh_token = self.config.get("refresh_token")

        if access_token and not refresh_token:
            token_state.clear()
            token_state.update({"access_token": access_token, "expires_at": now + 3600})
            return access_token

        if not refresh_token:
            raise ValueError(
                "Aruba Central credentials incomplete — need access_token or refresh_token"
            )

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.config.get("client_id", ""),
            "client_secret": self.config.get("client_secret", ""),
        }
        if self.config.get("customer_id"):
            data["customer_id"] = self.config["customer_id"]

        resp = await client.post(f"{self.cluster_url}/oauth2/token", data=data, timeout=15)
        resp.raise_for_status()
        payload = resp.json()
        token_state.clear()
        token_state.update(
            {
                "access_token": payload["access_token"],
                "refresh_token": payload.get("refresh_token", refresh_token),
                "expires_at": now + int(payload.get("expires_in", 3600)),
            }
        )
        return token_state["access_token"]

    def _headers(self, token: str) -> Dict[str, str]:
        headers = {"Authorization": f"Bearer {token}"}
        if self.config.get("customer_id"):
            headers["X-Customer-ID"] = str(self.config["customer_id"])
        return headers

    async def _get(self, client: "httpx.AsyncClient", path: str, params: Dict[str, Any] | None = None) -> Any:
        token = await self._ensure_token(client)
        resp = await client.get(
            f"{self.cluster_url}{path}",
            headers=self._headers(token),
            params=params or {},
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()

    async def available_checks(self) -> Dict[str, Any]:
        """Return the Aruba Central alert/insight/hardware catalog — mirrors the
        cs spoke's ``ArubaClient.available_checks`` so centralized mode can serve
        the Central API editor's monitored-check picker without contacting the
        spoke. ``new_central`` returns a static default catalog (no API call);
        ``classic`` live-fetches alert/insight types from the cluster gateway,
        falling back to the known standard types when Central returns nothing."""
        if not self.is_configured():
            return {"alerts": [], "insights": [], "hardware": [],
                    "warning": "Central not configured."}

        if self.api_version == "new_central":
            return {
                "alerts": [dict(item) for item in DEFAULT_NEW_CENTRAL_MONITORED_CHECKS],
                "insights": [],
                "hardware": [dict(item) for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS],
                "warning": None,
            }

        alert_types: Dict[str, str] = {}
        insight_categories: Dict[str, str] = {}
        warnings: list = []
        thirty_days_ago = int(time.time()) - 30 * 86400

        async with httpx.AsyncClient(timeout=30) as client:
            for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts", "/aiops/v2/alerts"):
                try:
                    payload = await self._get(client, alerts_path,
                                              params={"limit": 1000, "from_timestamp": thirty_days_ago})
                    for alert in payload.get("alerts") or payload.get("items") or []:
                        alert_id = str(alert.get("alert_type") or alert.get("type") or "").strip()
                        if not alert_id:
                            continue
                        alert_types[alert_id] = str(
                            alert.get("alert_type_name") or alert.get("name")
                            or alert_id.replace("_", " ").title()
                        )
                    if alert_types:
                        break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    warnings.append(f"Alerts endpoint returned HTTP {exc.response.status_code}.")
                    break
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"Network error fetching alerts: {exc}")
                    break

            for insights_path in ("/aiops/v1/insights", "/aiops/v2/insights"):
                try:
                    payload = await self._get(client, insights_path,
                                              params={"limit": 1000, "from_timestamp": thirty_days_ago})
                    for insight in payload.get("insights") or payload.get("items") or []:
                        category = str(insight.get("category") or insight.get("type") or "").strip()
                        if not category:
                            continue
                        insight_categories[category] = str(
                            insight.get("category_name") or insight.get("name")
                            or category.replace("_", " ").title()
                        )
                    if insight_categories:
                        break
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    warnings.append(f"Insights endpoint returned HTTP {exc.response.status_code}.")
                    break
                except Exception as exc:  # noqa: BLE001
                    warnings.append(f"Network error fetching insights: {exc}")
                    break

        using_fallback = False
        if not alert_types:
            alert_types = dict(KNOWN_CLASSIC_ALERT_TYPES)
            using_fallback = True
        if not insight_categories:
            insight_categories = dict(KNOWN_CLASSIC_INSIGHT_CATEGORIES)
            using_fallback = True
        if using_fallback:
            warnings.append("No live checks returned by Central — showing standard Aruba Central check types.")

        hardware_catalog = [
            dict(item) for item in DEFAULT_NEW_CENTRAL_HARDWARE_CHECKS
            if item.get("id") in alert_types or item.get("id") in {"AP_DOWN", "SWITCH_DOWN", "GATEWAY_DOWN"}
        ]
        return {
            "alerts": [{"id": key, "name": value} for key, value in sorted(alert_types.items())],
            "insights": [{"id": key, "name": value} for key, value in sorted(insight_categories.items())],
            "hardware": hardware_catalog,
            "warning": "; ".join(dict.fromkeys(warnings)) if warnings else None,
        }

    @staticmethod
    def _finding_status(value: Any) -> str:
        sev = str(value or "").strip().lower()
        if sev in {"critical", "major", "red", "open", "error"}:
            return "red"
        if sev in {"clear", "closed", "normal", "ok", "green", "resolved"}:
            return "green"
        return "yellow"

    async def poll_alerts_and_insights(self, site_filter: Optional[str] = None) -> list[ArubaFinding]:
        """Collect Aruba alerts and insights across the supported API variants for a tenant."""
        if not self.is_configured():
            return []

        findings: list[ArubaFinding] = []
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                try:
                    data = await self._get(client, "/network-monitoring/v1alpha1/sites-health")
                    for item in data.get("items") or []:
                        site = (item.get("name") or item.get("siteName") or item.get("site_name") or "unknown").strip() or "unknown"
                        if site_filter and site.lower() != site_filter.lower():
                            continue
                        good_pct = next(
                            (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                            item.get("healthScore", item.get("health_score", 100)),
                        )
                        findings.append(
                            ArubaFinding(
                                site_name=site,
                                check_name="SITE_HEALTH",
                                status="green" if int(good_pct or 0) >= 80 else "yellow",
                                source="alert",
                                raw=item,
                            )
                        )
                except Exception as exc:
                    logger.warning("Aruba sites-health fetch failed [%s]: %s", self._config_hash, exc)
                # For new_central: insights are fetched on-demand via _new_central_insights()
                # (which has a 15-min cache). Skip the aiops endpoints here to avoid 429s
                # from background polling burning the rate-limit quota.
                return findings

            params: dict[str, Any] = {"limit": 1000}
            if site_filter:
                params["site"] = site_filter

            try:
                alerts_payload = None
                for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts", "/aiops/v2/alerts"):
                    try:
                        alerts_payload = await self._get(client, alerts_path, params=params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for alert in (alerts_payload or {}).get("alerts") or (alerts_payload or {}).get("items") or []:
                    site = (alert.get("site_name") or alert.get("site") or alert.get("group") or "unknown").strip() or "unknown"
                    name = (
                        alert.get("name")
                        or alert.get("alert_name")
                        or alert.get("rule")
                        or alert.get("alert_type")
                        or "alert"
                    )
                    status = self._finding_status(alert.get("severity") or alert.get("status"))
                    findings.append(ArubaFinding(site_name=site, check_name=str(name), status=status, source="alert", raw=alert))
            except Exception as exc:
                logger.warning("Aruba alerts fetch failed [%s]: %s", self._config_hash, exc)

            insight_params = dict(params)
            if site_filter:
                insight_params["site_name"] = site_filter
                insight_params.pop("site", None)
            try:
                insights_payload = None
                for insights_path in ("/aiops/v1/insights", "/aiops/v2/insights"):
                    try:
                        insights_payload = await self._get(client, insights_path, params=insight_params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for insight in (insights_payload or {}).get("insights") or (insights_payload or {}).get("items") or []:
                    site = (insight.get("site_name") or insight.get("site") or insight.get("group") or "unknown").strip() or "unknown"
                    name = (
                        insight.get("name")
                        or insight.get("insight_name")
                        or insight.get("rule")
                        or insight.get("category")
                        or "insight"
                    )
                    status = self._finding_status(insight.get("severity") or insight.get("status"))
                    findings.append(ArubaFinding(site_name=site, check_name=str(name), status=status, source="insight", raw=insight))
            except Exception as exc:
                logger.warning("Aruba insights fetch failed [%s]: %s", self._config_hash, exc)

        return findings

    async def poll_site_data(
        self,
        site: str,
        hw_check_ids: set[str] | None = None,
    ) -> dict[str, Any]:
        """Collect per-site Aruba Central health, counts, and hardware device names."""
        if not self.is_configured():
            return {
                "site_health": None,
                "wireless_clients": 0,
                "client_count": 0,
                "alert_type_counts": {},
                "insight_cat_counts": {},
                "hw_devices": {},
            }

        hw_check_ids = {str(check_id).strip() for check_id in (hw_check_ids or set()) if str(check_id).strip()}
        site_health: int | None = None
        wireless_clients = 0
        wired_clients = 0
        alert_type_counts: dict[str, int] = {}
        insight_cat_counts: dict[str, int] = {}
        hw_devices: dict[str, dict[str, int]] = {}

        if self.api_version == "new_central":
            # Use cached global fetchers — 9 sites share 1 API call per endpoint
            site_id: str | None = None
            for item in await self._nc_sites_health():
                site_name = (item.get("name") or item.get("siteName") or item.get("site_name") or "").strip()
                if site_name.lower() != site.lower():
                    continue
                site_id = str(item.get("id") or item.get("siteId") or item.get("site_id") or "").strip() or None
                good_pct = next(
                    (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                    item.get("healthScore", item.get("health_score", 0)),
                )
                site_health = int(good_pct or 0)
                break

            DEVICE_ALERT = {"ACCESS_POINT": "AP_DOWN", "SWITCH": "SWITCH_DOWN", "GATEWAY": "GATEWAY_DOWN"}
            for device in await self._nc_devices():
                dev_site_id = str(device.get("siteId") or device.get("site_id") or "").strip()
                if site_id and dev_site_id and dev_site_id != site_id:
                    continue
                device_type = str(device.get("deviceType") or "").upper()
                status = str(device.get("status") or "").upper()
                if status in {"UP", "ONLINE"}:
                    continue
                alert_id = DEVICE_ALERT.get(device_type)
                if not alert_id:
                    continue
                alert_type_counts[alert_id] = alert_type_counts.get(alert_id, 0) + 1
                if not hw_check_ids or alert_id in hw_check_ids:
                    device_name = (
                        device.get("deviceName") or device.get("name")
                        or device.get("serialNumber") or device.get("serial") or ""
                    ).strip()
                    if device_name:
                        hw_devices.setdefault(alert_id, {})[device_name] = hw_devices.setdefault(alert_id, {}).get(device_name, 0) + 1

            # Count all clients (wired + wireless) for the site from the global clients list
            for cl in await self._nc_clients():
                cl_site_id = str(cl.get("siteId") or cl.get("site_id") or "").strip()
                matches = (site_id and cl_site_id and cl_site_id == site_id) or (not site_id)
                if not matches:
                    continue
                conn_type = str(cl.get("clientConnectionType") or cl.get("connection_type") or "").lower()
                if conn_type == "wired":
                    wired_clients += 1
                else:
                    wireless_clients += 1

            # Count insights per site so MONITORED insight checks (enrolled from
            # the Central -> Insights tab) evaluate on the dashboard. Keyed
            # name||category to match the WebUI monitored-check id. Insights carry
            # a site NAME (or "All Sites" for global); _new_central_insights is
            # cached so this adds no extra API call within the TTL.
            for ins in await self._new_central_insights():
                ins_site = str(ins.get("site") or "").strip()
                if ins_site and ins_site.lower() not in (site.lower(), "all sites"):
                    continue
                cat = str(ins.get("name") or ins.get("category") or "").strip()
                if cat:
                    insight_cat_counts[cat] = insight_cat_counts.get(cat, 0) + 1

            # Count network-notifications alerts by name so MONITORED alert checks
            # (Central -> Alerts Monitor button) evaluate on the dashboard. Alerts
            # aren't reliably site-scoped, so an active alert counts for EVERY
            # monitored site; key name||category = the WebUI monitored-check id.
            for al in await self._new_central_alerts():
                al_site = str(al.get("site") or "").strip()
                # Count an alert for THIS site when it is pinned here (name match)
                # or has no site ("-" = global -> every site). Enables per-site
                # alert monitoring; the monitored check id is name||category.
                if al_site and al_site not in ("-", "—") and al_site.lower() != site.lower():
                    continue
                nm = str(al.get("name") or al.get("category") or "").strip()
                if nm:
                    alert_type_counts[nm] = alert_type_counts.get(nm, 0) + 1

            return {
                "site_health": site_health,
                "wireless_clients": wireless_clients,
                "wired_clients": wired_clients,
                "client_count": wireless_clients + wired_clients,
                "alert_type_counts": alert_type_counts,
                "insight_cat_counts": insight_cat_counts,
                "hw_devices": hw_devices,
            }

        async with httpx.AsyncClient(timeout=30) as client:

            params: dict[str, Any] = {"site": site, "limit": 1000}
            try:
                alerts_payload = None
                for alerts_path in ("/monitoring/v1/alerts", "/monitoring/v2/alerts"):
                    try:
                        alerts_payload = await self._get(client, alerts_path, params=params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for alert in (alerts_payload or {}).get("alerts") or (alerts_payload or {}).get("items") or []:
                    alert_type = str(alert.get("alert_type") or alert.get("type") or "").strip()
                    if not alert_type:
                        continue
                    alert_type_counts[alert_type] = alert_type_counts.get(alert_type, 0) + 1
                    if hw_check_ids and alert_type in hw_check_ids:
                        device_name = (
                            alert.get("device_name")
                            or alert.get("hostname")
                            or alert.get("name")
                            or ""
                        ).strip()
                        if device_name:
                            hw_devices.setdefault(alert_type, {})[device_name] = hw_devices.setdefault(alert_type, {}).get(device_name, 0) + 1
            except Exception as exc:
                logger.warning("Aruba alerts fetch failed [%s:%s]: %s", self._config_hash, site, exc)

            insight_params = {"site_name": site, "limit": 1000}
            try:
                insights_payload = None
                for insights_path in ("/aiops/v1/insights", "/aiops/v2/insights"):
                    try:
                        insights_payload = await self._get(client, insights_path, params=insight_params)
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                for insight in (insights_payload or {}).get("insights") or (insights_payload or {}).get("items") or []:
                    category = str(insight.get("category") or insight.get("type") or "").strip()
                    if category:
                        insight_cat_counts[category] = insight_cat_counts.get(category, 0) + 1
            except Exception as exc:
                logger.warning("Aruba insights fetch failed [%s:%s]: %s", self._config_hash, site, exc)

            fetched_wireless = False
            for clients_path in ("/monitoring/v2/clients/wireless", "/monitoring/v1/clients/wireless"):
                for site_param in ("site", "site_name"):
                    try:
                        payload = await self._get(client, clients_path, params={site_param: site, "limit": 1})
                        wireless_clients = int(payload.get("total") or payload.get("count") or 0)
                        fetched_wireless = True
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                    except Exception as exc:
                        logger.warning("Aruba wireless clients fetch failed [%s:%s]: %s", self._config_hash, site, exc)
                        break
                if fetched_wireless:
                    break

            fetched_wired = False
            for clients_path in ("/monitoring/v2/clients/wired", "/monitoring/v1/clients/wired"):
                for site_param in ("site", "site_name"):
                    try:
                        payload = await self._get(client, clients_path, params={site_param: site, "limit": 1})
                        wired_clients = int(payload.get("total") or payload.get("count") or 0)
                        fetched_wired = True
                        break
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code == 404:
                            continue
                        raise
                    except Exception as exc:
                        logger.warning("Aruba wired clients fetch failed [%s:%s]: %s", self._config_hash, site, exc)
                        break
                if fetched_wired:
                    break

        return {
            "site_health": site_health,
            "wireless_clients": wireless_clients,
            "wired_clients": wired_clients,
            "client_count": wireless_clients + wired_clients,
            "alert_type_counts": alert_type_counts,
            "insight_cat_counts": insight_cat_counts,
            "hw_devices": hw_devices,
        }

    async def list_sites(self) -> list[dict[str, Any]]:
        """Return normalized Aruba Central sites for hub auto-discovery."""
        if not self.is_configured():
            return []

        sites: dict[str, dict[str, Any]] = {}
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                data = await self._get(client, "/network-monitoring/v1alpha1/sites-health")
                for item in data.get("items") or []:
                    site_name = (item.get("name") or item.get("siteName") or item.get("site_name") or "").strip()
                    if not site_name:
                        continue
                    key = site_name.casefold()
                    sites[key] = {
                        "name": site_name,
                        "site_id": item.get("id") or item.get("siteId") or item.get("site_id") or "",
                        "health_score": next(
                            (g.get("value", 0) for g in (item.get("health") or {}).get("groups", []) if g.get("name") == "Good"),
                            item.get("healthScore", item.get("health_score")),
                        ),
                        "wireless_clients": (item.get("clients") or {}).get("count") or item.get("clientCount") or item.get("client_count"),
                    }
                return sorted(sites.values(), key=lambda item: item["name"].casefold())

        try:
            findings = await self.poll_alerts_and_insights()
        except Exception as exc:
            logger.warning("Aruba classic site discovery failed [%s]: %s", self._config_hash, exc)
            findings = []
        for finding in findings:
            site_name = str(finding.site_name or "").strip()
            if not site_name:
                continue
            sites.setdefault(site_name.casefold(), {"name": site_name})
        return sorted(sites.values(), key=lambda item: item["name"].casefold())

    async def list_clients(self, limit: int = 500) -> list[dict[str, Any]]:
        """Return normalized wireless clients from Central API."""
        if not self.is_configured():
            return []
        async with httpx.AsyncClient(timeout=30) as client:
            if self.api_version == "new_central":
                try:
                    data = await self._get(client, "/network-monitoring/v1alpha1/clients", params={"limit": limit})
                    return [
                        {
                            "mac": item.get("macAddress") or item.get("mac_address") or item.get("mac") or "—",
                            "ip": item.get("ipv4") or item.get("ipv4Address") or item.get("ip_address") or item.get("ip") or "—",
                            "hostname": item.get("name") or item.get("clientName") or item.get("deviceName") or item.get("hostname") or "—",
                            "username": item.get("userName") or item.get("username") or item.get("associatedUser") or item.get("auth_username") or "",
                            "site": item.get("siteName") or item.get("site_name") or "—",
                            "ap": item.get("associatedDeviceName") or item.get("associatedDevice") or item.get("ap_name") or "—",
                            "ssid": item.get("ssid") or item.get("essid") or "—",
                            "status": item.get("status") or "—",
                            "os": item.get("osType") or item.get("os_type") or "—",
                            "vlan": str(item.get("vlan") or "—"),
                            "connection_type": item.get("clientConnectionType") or "",
                        }
                        for item in (data.get("items") or [])
                    ]
                except Exception as exc:
                    logger.warning("list_clients new_central failed [%s]: %s", self._config_hash, exc)
                    return []
            for path in ("/monitoring/v2/clients/wireless", "/monitoring/v1/clients/wireless"):
                try:
                    data = await self._get(client, path, params={"limit": limit})
                    return [
                        {
                            "mac": item.get("macaddr") or item.get("mac_address") or item.get("mac") or "—",
                            "ip": item.get("ip_address") or item.get("ip") or "—",
                            "hostname": item.get("name") or item.get("hostname") or "—",
                            "username": item.get("username") or item.get("userName") or "",
                            "site": item.get("site") or item.get("site_name") or "—",
                            "ap": item.get("associated_device_name") or item.get("ap_name") or "—",
                            "ssid": item.get("ssid") or "—",
                            "status": item.get("status") or "connected",
                            "os": item.get("os_type") or "—",
                            "vlan": str(item.get("vlan_id") or item.get("vlan") or "—"),
                        }
                        for item in (data.get("clients") or data.get("items") or [])
                    ]
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 404:
                        continue
                    logger.warning("list_clients classic failed [%s] %s: %s", self._config_hash, path, exc)
                    return []
                except Exception as exc:
                    logger.warning("list_clients classic failed [%s] %s: %s", self._config_hash, path, exc)
                    return []
            return []

    async def _new_central_device_alerts(self) -> list[dict[str, Any]]:
        """Fetch device-level alerts (down APs/switches/gateways) for new_central browse view."""
        DEVICE_TYPE_ALERT = {"ACCESS_POINT": "AP Down", "SWITCH": "Switch Down", "GATEWAY": "Gateway Down"}
        alerts: list[dict[str, Any]] = []
        try:
            devices = await self._nc_devices()
            for device in devices:
                status = str(device.get("status") or "").upper()
                if status in {"UP", "ONLINE", ""}:
                    continue
                device_type = str(device.get("deviceType") or device.get("type") or "").upper()
                alert_name = DEVICE_TYPE_ALERT.get(device_type) or f"{device_type} Down"
                site = (
                    device.get("siteName") or device.get("site_name") or device.get("site") or "—"
                ).strip() or "—"
                device_name = (
                    device.get("deviceName") or device.get("name") or device.get("serialNumber") or device.get("id") or "—"
                ).strip()
                alerts.append({
                    "name": alert_name,
                    "site": site,
                    "severity": "error",
                    "detail": device_name,
                    "device_name": device_name,
                    "status": status,
                    "ts": None,
                })
        except Exception as exc:
            logger.warning("new_central device alerts fetch failed [%s]: %s", self._config_hash, exc)
        return alerts

    # ── new_central cached global fetchers ────────────────────────────────────

    async def _nc_sites_health(self) -> list[dict[str, Any]]:
        """Return cached sites-health list; one API call shared across all site queries."""
        cached = _sites_health_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _NC_GLOBAL_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                data = await self._get(http, "/network-monitoring/v1alpha1/sites-health")
                result = data.get("items") or []
        except Exception as exc:
            logger.warning("new_central sites-health cache fetch [%s]: %s", self._config_hash, exc)
        _sites_health_cache[self._config_hash] = (time.time(), result)
        return result

    async def _nc_devices(self) -> list[dict[str, Any]]:
        """Return cached devices list from /network-monitoring/v1/devices (paginated)."""
        cached = _devices_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _NC_GLOBAL_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                params: dict[str, Any] = {"limit": 1000}
                while True:
                    data = await self._get(http, "/network-monitoring/v1/devices", params=params)
                    items = data.get("items") or []
                    result.extend(items)
                    nxt = data.get("next")
                    if not nxt or len(items) < 1000:
                        break
                    params["next"] = nxt
        except Exception as exc:
            logger.warning("new_central devices cache fetch [%s]: %s", self._config_hash, exc)
        _devices_cache[self._config_hash] = (time.time(), result)
        return result

    async def _nc_clients(self) -> list[dict[str, Any]]:
        """Return cached clients list from /network-monitoring/v1/clients (paginated)."""
        cached = _nc_clients_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _NC_GLOBAL_CACHE_TTL:
            return cached[1]
        result: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                params: dict[str, Any] = {"limit": 1000}
                while True:
                    data = await self._get(http, "/network-monitoring/v1/clients", params=params)
                    items = data.get("items") or []
                    result.extend(items)
                    nxt = data.get("next")
                    if not nxt or len(items) < 1000:
                        break
                    params["next"] = nxt
        except Exception as exc:
            logger.warning("new_central clients cache fetch [%s]: %s", self._config_hash, exc)
        if result:
            logger.info("new_central client fields sample [%s]: %s", self._config_hash, list(result[0].keys()))
        _nc_clients_cache[self._config_hash] = (time.time(), result)
        return result

    # Reason-code → human-readable alert name mapping for new_central sites-health.
    # Codes follow the pattern: <device>_<metric>_<severity> e.g. AP_CHANNEL_UTILIZATION_5GHZ_FAIR
    _REASON_NAMES: dict[str, str] = {
        "DEVICE_OFFLINE": "Device Offline",
        "AP_OFFLINE": "AP Offline",
        "SWITCH_OFFLINE": "Switch Offline",
        "GW_OFFLINE": "Gateway Offline",
        "AP_CHANNEL_UTILIZATION_5GHZ_FAIR": "AP 5GHz Channel Utilization",
        "AP_CHANNEL_UTILIZATION_5GHZ_POOR": "AP 5GHz Channel Utilization",
        "AP_CHANNEL_UTILIZATION_24GHZ_FAIR": "AP 2.4GHz Channel Utilization",
        "AP_CHANNEL_UTILIZATION_24GHZ_POOR": "AP 2.4GHz Channel Utilization",
        "AP_CHANNEL_UTILIZATION_FAIR": "AP Channel Utilization",
        "AP_CHANNEL_UTILIZATION_POOR": "AP Channel Utilization",
        "GW_TUNNEL_FLAP_FAIR": "Gateway Tunnel Flap",
        "GW_TUNNEL_FLAP_POOR": "Gateway Tunnel Flap",
        "GW_UPLINK_UTIL_FAIR": "Gateway Uplink Utilization",
        "GW_UPLINK_UTIL_POOR": "Gateway Uplink Utilization",
        "AP_UPLINK_UTIL_FAIR": "AP Uplink Utilization",
        "AP_UPLINK_UTIL_POOR": "AP Uplink Utilization",
        "AP_DOWNLINK_PKT_DROP_FAIR": "Downlink Packet Drops",
        "AP_DOWNLINK_PKT_DROP_POOR": "Downlink Packet Drops",
        "AP_DOWNLINK_PACKET_DROPS_FAIR": "Downlink Packet Drops",
        "AP_DOWNLINK_PACKET_DROPS_POOR": "Downlink Packet Drops",
        "AP_UPLINK_PKT_DROP_FAIR": "Uplink Packet Drops",
        "AP_UPLINK_PKT_DROP_POOR": "Uplink Packet Drops",
        "CLIENT_COUNT_FAIR": "High Client Count",
        "CLIENT_COUNT_POOR": "High Client Count",
        "AP_CLIENT_COUNT_FAIR": "AP High Client Count",
        "AP_CLIENT_COUNT_POOR": "AP High Client Count",
        "MEMORY_USAGE_FAIR": "Memory Usage",
        "MEMORY_USAGE_POOR": "Memory Usage",
        "CPU_USAGE_FAIR": "CPU Usage",
        "CPU_USAGE_POOR": "CPU Usage",
        "AP_NOISE_5GHZ_FAIR": "AP 5GHz Noise Floor",
        "AP_NOISE_5GHZ_POOR": "AP 5GHz Noise Floor",
        "AP_NOISE_24GHZ_FAIR": "AP 2.4GHz Noise Floor",
        "AP_NOISE_24GHZ_POOR": "AP 2.4GHz Noise Floor",
        "EMPTY_SITE": "Empty Site",
    }

    @classmethod
    def _reason_to_alert_name(cls, reason_code: str) -> str:
        """Convert a sites-health reason code to a human-readable alert name."""
        name = cls._REASON_NAMES.get(reason_code)
        if name:
            return name
        # Fallback: clean up the code e.g. AP_DOWNLINK_PKT_DROP_FAIR → "AP Downlink Pkt Drop"
        clean = reason_code.replace("_FAIR", "").replace("_POOR", "")
        return " ".join(w.capitalize() for w in clean.split("_"))

    @classmethod
    def _reason_severity(cls, health: str) -> str:
        """Map a sites-health reason health value to a severity string."""
        h = str(health or "").lower()
        if h == "poor":
            return "red"
        if h == "fair":
            return "yellow"
        return "green"

    @classmethod
    def _reason_category(cls, reason_code: str) -> str:
        """Infer alert category from the reason code prefix."""
        code = reason_code.upper()
        # Check specific metrics before generic prefixes
        if "CHANNEL" in code or "NOISE" in code or "PKT_DROP" in code or "PACKET_DROP" in code:
            return "LAN"
        if "TUNNEL" in code or "UPLINK_UTIL" in code:
            return "WAN"
        if "CLIENT" in code:
            return "Client"
        if "OFFLINE" in code:
            return "Device"
        if code.startswith("AP_") or code.startswith("SWITCH_") or code.startswith("GW_"):
            return "Device"
        return ""

    @staticmethod
    def _nc_alert_severity(severity: str) -> str:
        """Map new_central alert severity (Critical/Major/Minor/Info) to UI colour."""
        s = str(severity or "").lower()
        if s == "critical":
            return "red"
        if s == "major":
            return "orange"
        if s == "minor":
            return "yellow"
        return "info"

    async def _new_central_alerts(self) -> list[dict[str, Any]]:
        """Fetch active alerts from /network-notifications/v1/alerts.

        This is the real individual-alert endpoint (returned 404 on old paths like
        /monitoring/v1/alerts).  Each alert has name, site, severity, category,
        deviceType, summary and createdAt.  Results are grouped by (name, site) so
        the same alert firing multiple times shows as one row with a count.
        Cache TTL: 5 minutes.
        """
        cached = _alerts_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _ALERTS_CACHE_TTL:
            return cached[1]
        alerts: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                # Fetch all active alerts (max 100 per page, follow pagination).
                # NOTE: OData filter parameter is "$filter" (with $), not "filter".
                # "sort" is not a supported query param on this endpoint.
                # network-notifications/v1/alerts — VERIFIED against Aruba's own
                # SDK reference (aruba/central-python-workflows msp-tenant-monitoring
                # + pycentral): NUMERIC "next" page starting at 1, NO OData $filter
                # (the old $filter=status eq 'Active' returned nothing), items under
                # "items", ~10-page safety cap. Alert fields per Aruba map_alert:
                # name/summary/severity/status/category/deviceType/createdAt/clearedReason.
                raw_alerts: list[dict[str, Any]] = []
                next_page: Any = 1
                pages = 0
                seen: set = set()
                # Bounded: <=5 pages, stop on an empty page or a non-advancing
                # "next" — so slow/looping alert pagination can NEVER stall
                # browse_all (which awaits alerts + insights + sites in parallel).
                while next_page is not None and pages < 5 and next_page not in seen:
                    seen.add(next_page)
                    payload = await self._get(http, "/network-notifications/v1/alerts",
                                              params={"limit": 100, "next": next_page})
                    if isinstance(payload, dict) and isinstance(payload.get("msg"), dict):
                        payload = payload["msg"]  # some responses wrap the body under "msg"
                    items = (payload or {}).get("items") or []
                    raw_alerts.extend(items)
                    pages += 1
                    next_page = (payload or {}).get("next")
                    if not items:
                        break

                # Diagnostic: log the first alert's field names once (values NOT logged).
                if raw_alerts:
                    logger.info("new_central alerts sample keys [%s]: %s",
                                self._config_hash, sorted(raw_alerts[0].keys()))

                # Resolve a site for each alert. The payload may carry a site by
                # NAME (siteName/site/groupName) or only a siteId — build an
                # id->name map from the cached sites-health so alerts key to the
                # right site instead of falling to the global "-" bucket.
                site_id_to_name: dict[str, str] = {}
                try:
                    for s in await self._nc_sites_health():
                        _sid = str(s.get("id") or s.get("siteId") or s.get("site_id") or "").strip()
                        _nm = str(s.get("name") or s.get("siteName") or s.get("site_name") or "").strip()
                        if _sid and _nm:
                            site_id_to_name[_sid] = _nm
                except Exception:  # noqa: BLE001
                    pass

                # Group by (name, site). Keep only non-cleared alerts (the demo's
                # expected errors that should be PRESENT).
                groups: dict[tuple[str, str], dict[str, Any]] = {}
                for item in raw_alerts:
                    status = str(item.get("status") or "").strip().lower()
                    if status in ("cleared", "closed", "resolved") or item.get("clearedReason"):
                        continue
                    name = str(item.get("name") or item.get("summary") or "Alert").strip()
                    site = (str(item.get("siteName") or item.get("site_name")
                                or item.get("site") or item.get("groupName") or "").strip()
                            or site_id_to_name.get(str(item.get("siteId")
                                or item.get("site_id") or "").strip(), "")
                            or "—")
                    key = (name.lower(), site.lower())
                    if key not in groups:
                        groups[key] = {
                            "name": name,
                            "site": site,
                            "severity": self._nc_alert_severity(item.get("severity", "")),
                            "category": str(item.get("category") or "").strip(),
                            "device_type": str(item.get("deviceType") or "").strip(),
                            "detail": str(item.get("summary") or item.get("description") or "").strip(),
                            "ts": item.get("createdAt") or item.get("updatedAt") or None,
                            "count": 0,
                        }
                    groups[key]["count"] += 1

                for entry in groups.values():
                    cnt = entry.pop("count")
                    if cnt > 1:
                        entry["detail"] = f"{cnt} occurrences" + (f" — {entry['detail']}" if entry["detail"] else "")
                    alerts.append(entry)

        except Exception as exc:
            body = getattr(getattr(exc, "response", None), "text", None)
            logger.warning("new_central alerts fetch [%s]: %s%s", self._config_hash, exc, f" — {body}" if body else "")
        logger.info("new_central alerts fetched [%s]: %d alert groups from /network-notifications/v1/alerts", self._config_hash, len(alerts))
        ttl_offset = 0 if alerts else (_ALERTS_CACHE_TTL - 60)
        _alerts_cache[self._config_hash] = (time.time() - ttl_offset, alerts)
        return alerts

    async def _new_central_insights(self) -> list[dict[str, Any]]:
        """Fetch AI-powered insights from /network-notifications/v1/insights.

        Each insight is global (siteId="-1") or site-specific and contains an
        impactedSites list.  Results are cached for 15 minutes.
        """
        cached = _insights_cache.get(self._config_hash)
        if cached and time.time() - cached[0] < _INSIGHTS_CACHE_TTL:
            return cached[1]

        insights: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                payload = await self._get(http, "/network-notifications/v1/insights", params={"limit": 100})
                raw_list = payload.get("items") or []
                for item in raw_list:
                    title = str(item.get("title") or item.get("name") or item.get("category") or "Insight").strip()
                    category = str(item.get("category") or "").strip()
                    description = str(item.get("description") or "").strip()
                    ts = item.get("timestamp") or item.get("createdAt") or None
                    # Convert epoch-ms timestamp to ISO string if needed
                    if ts and str(ts).isdigit() and len(str(ts)) == 13:
                        import datetime
                        ts = datetime.datetime.utcfromtimestamp(int(ts) / 1000).strftime("%Y-%m-%dT%H:%M:%SZ")

                    impacted = item.get("impactedSites") or []
                    if impacted:
                        for s in impacted:
                            site_name = str(s.get("siteName") or s.get("name") or "").strip() or "All Sites"
                            insights.append({
                                "name": title,
                                "site": site_name,
                                "category": category,
                                "severity": "info",
                                "description": description,
                                "device_count": s.get("impactedDeviceCount") or 0,
                                "client_count": s.get("impactedClientCount") or 0,
                                "ts": ts,
                            })
                    else:
                        insights.append({
                            "name": title,
                            "site": "All Sites",
                            "category": category,
                            "severity": "info",
                            "description": description,
                            "device_count": 0,
                            "client_count": 0,
                            "ts": ts,
                        })
        except Exception as exc:
            logger.warning("new_central insights fetch [%s]: %s", self._config_hash, exc)
        logger.info("new_central insights fetched [%s]: %d insights from /network-notifications/v1/insights", self._config_hash, len(insights))
        ttl = _INSIGHTS_CACHE_TTL if insights else 120
        _insights_cache[self._config_hash] = (time.time() - (_INSIGHTS_CACHE_TTL - ttl), insights)
        return insights

    async def browse_all(self) -> dict[str, Any]:
        """Fetch all Central sites, alerts, insights, clients, and devices for the browse view."""
        import asyncio

        if self.api_version == "new_central":
            sites, all_devices, all_clients, nc_insights, nc_alerts = await asyncio.gather(
                self.list_sites(),
                self._nc_devices(),
                self._nc_clients(),
                self._new_central_insights(),
                self._new_central_alerts(),
                return_exceptions=True,
            )
            if isinstance(sites, Exception):
                # Re-raise so _refresh_central_browse preserves the existing cache
                raise sites
            if isinstance(all_devices, Exception):
                all_devices = []
            if isinstance(all_clients, Exception):
                all_clients = []
            if isinstance(nc_insights, Exception):
                nc_insights = []
            if isinstance(nc_alerts, Exception):
                nc_alerts = []

            # Build devices_by_site: {siteName: [device, ...]}
            devices_by_site: dict[str, list[dict[str, Any]]] = {}
            for dev in all_devices:
                sn = (dev.get("siteName") or dev.get("site_name") or "—").strip() or "—"
                devices_by_site.setdefault(sn, []).append({
                    "name": dev.get("deviceName") or dev.get("name") or dev.get("serialNumber") or "—",
                    "type": dev.get("deviceType") or "",
                    "model": dev.get("model") or "",
                    "status": dev.get("status") or "",
                    "serial": dev.get("serialNumber") or dev.get("id") or "",
                    "ip": dev.get("ipv4") or dev.get("ipv6") or "",
                    "firmware": dev.get("firmwareVersion") or "",
                    "last_seen": dev.get("lastSeenAt") or "",
                })

            # Build clients_by_site: {siteName: {total, wired, wireless}}
            clients_by_site: dict[str, dict[str, Any]] = {}
            normalized_clients: list[dict[str, Any]] = []
            for cli in all_clients:
                sn = (cli.get("siteName") or cli.get("site_name") or "—").strip() or "—"
                entry = clients_by_site.setdefault(sn, {"total": 0, "wired": 0, "wireless": 0})
                entry["total"] += 1
                conn_type = str(cli.get("clientConnectionType") or "").lower()
                if conn_type == "wired":
                    entry["wired"] += 1
                elif conn_type == "wireless":
                    entry["wireless"] += 1
                normalized_clients.append({
                    "mac": cli.get("macAddress") or cli.get("mac_address") or cli.get("mac") or "—",
                    "ip": cli.get("ipv4") or cli.get("ipv4Address") or cli.get("ip_address") or cli.get("ip") or "—",
                    "hostname": cli.get("name") or cli.get("clientName") or cli.get("deviceName") or cli.get("hostname") or "—",
                    "username": cli.get("userName") or cli.get("username") or cli.get("associatedUser") or cli.get("auth_username") or "",
                    "site": sn,
                    "ap": cli.get("associatedDeviceName") or cli.get("associatedDevice") or cli.get("ap_name") or "—",
                    "ssid": cli.get("ssid") or cli.get("essid") or "—",
                    "status": cli.get("status") or "—",
                    "os": cli.get("osType") or cli.get("os_type") or "—",
                    "vlan": str(cli.get("vlan") or "—"),
                    "connection_type": cli.get("clientConnectionType") or "",
                })

            return {
                "sites": sites,
                "alerts": list(nc_alerts),
                "insights": list(nc_insights),
                "clients": normalized_clients,
                "devices_by_site": devices_by_site,
                "clients_by_site": clients_by_site,
            }

        sites, findings, clients = await asyncio.gather(
            self.list_sites(),
            self.poll_alerts_and_insights(),
            self.list_clients(),
            return_exceptions=True,
        )
        if isinstance(sites, Exception):
            raise sites
        if isinstance(findings, Exception):
            findings = []
        if isinstance(clients, Exception):
            clients = []
        alerts = [
            {"name": f.check_name, "site": f.site_name, "severity": f.status, "detail": "", "ts": None}
            for f in findings
            if isinstance(f, ArubaFinding) and f.source == "alert"
        ]
        insights = [
            {"name": f.check_name, "site": f.site_name, "severity": f.status, "category": "", "ts": None}
            for f in findings
            if isinstance(f, ArubaFinding) and f.source == "insight"
        ]
        return {"sites": sites, "alerts": alerts, "insights": insights, "clients": clients}


async def test_central_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Run a single hub-side token-exchange probe against Aruba Central using
    the hub's stored ``central_config`` creds. Returns one ``spokes`` entry
    (the same shape the cs spoke's ``central_poller.test_connection`` returns)
    so the ``/sim/api/{tenant}/test-central`` UI renders it identically.

    ``token_state`` is a short string ("present"/"missing"), NOT the raw token
    dict, so the access token is never shipped to the browser.
    """
    client = ArubaClient(cfg)
    if not client.is_configured():
        logger.info("test_central [hub/%s]: Central not configured (no cluster_url)",
                    spoke_id)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "missing", "token_valid": False,
                "status": "Central not configured."}
    mode = client.api_version
    chash = client._config_hash
    try:
        import httpx as _httpx
        async with _httpx.AsyncClient(timeout=20) as http:
            await client._ensure_token(http)
        logger.info("test_central [hub/%s] mode=%s cfg=%s: connected to Central",
                    spoke_id, mode, chash)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "present", "token_valid": True,
                "status": "Connected."}
    except Exception as exc:  # noqa: BLE001 — surface any token/transport error
        logger.warning("test_central [hub/%s] mode=%s cfg=%s FAILED: %r",
                       spoke_id, mode, chash, exc)
        return {"spoke_id": spoke_id, "spoke_name": "Hub (centralized)",
                "token_state": "missing", "token_valid": False,
                "status": f"Connection failed: {exc}"}


async def get_central_available_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Hub-side check-catalog fetch for centralized processing mode. Mirrors the
    cs spoke's ``central_poller.available_checks()`` so the Central API editor's
    monitored-check picker works without contacting the spoke. Returns the same
    ``{alerts, insights, hardware, warning}`` shape the spoke returns."""
    client = ArubaClient(cfg)
    try:
        return await client.available_checks()
    except Exception as exc:  # noqa: BLE001 — surface any token/transport error
        logger.warning("get_central_available [hub/%s] FAILED: %r", spoke_id, exc)
        return {"alerts": [], "insights": [], "hardware": [],
                "warning": f"Central catalog fetch failed: {exc}"}


async def browse_all_from_config(cfg: Dict[str, Any], spoke_id: str = "hub") -> Dict[str, Any]:
    """Hub-side FULL Central inventory (sites/alerts/insights/clients/devices)
    for centralized processing mode — mirrors the cs spoke's
    ``central_poller.browse()`` so the Central -> Sites/Alerts/Clients tabs work
    without contacting a spoke. Returns the same shape browse_all produces, or an
    empty set + warning on misconfig/error."""
    client = ArubaClient(cfg)
    if not client.is_configured():
        return {"status": "SUCCESS", "sites": [], "alerts": [], "insights": [],
                "clients": [], "devices_by_site": {}, "clients_by_site": {},
                "warning": "Central not configured."}
    try:
        data = await client.browse_all()
        return {"status": "SUCCESS", **data}
    except Exception as exc:  # noqa: BLE001
        logger.warning("browse_all [hub/%s] FAILED: %r", spoke_id, exc)
        return {"status": "ERROR", "message": str(exc), "sites": [], "alerts": [],
                "insights": [], "clients": [], "devices_by_site": {}, "clients_by_site": {}}