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
from typing import Any, Dict

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