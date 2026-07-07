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

logger = logging.getLogger(__name__)

_NEW_CENTRAL_TOKEN_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2"
_GLP_TOKEN_URL_TEMPLATE = "https://global.api.greenlake.hpe.com/authorization/v2/oauth2/{workspace_id}/token"


class ArubaClient:
    """Minimal hub-side Aruba Central client — token exchange only.

    Behavior mirrors ``cs/lm-spoke/src/aruba.py:ArubaClient`` so a creds test
    run on the hub yields the same result the spoke would have produced.
    """

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = dict(config or {})
        self.cluster_url = (self.config.get("cluster_url") or "").rstrip("/")
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