"""Hub-side Aruba Central poller for CENTRALIZED processing mode.

In centralized mode the HUB holds the Central creds (Setup -> Central API ->
``central_config``) and the cs spoke has no Aruba client, so the spoke-side
``CentralPoller`` (``cs/lm-spoke/src/central_poller.py``) never runs and the
Simulations Checks / Hardware / Client-Count and Central tabs would stay empty
(they render ``spoke.central_status`` relayed via CS_TELEMETRY, which a
credential-less spoke never produces).

This loop is the hub-side equivalent: for every tenant whose
``processing_modes.central_api == "centralized"`` with a configured
``central_config``, it polls Central using the hub's full ``ArubaClient``
(``aruba.py``) and writes the SAME ``central_status`` shape the spoke relays
into ``hub.central_hub_status[tenant_id]``. ``SimulationsService`` then injects
that as a synthetic "Hub (centralized)" spoke so the dashboards populate
identically to distributed mode.

Mirrors ``central_poller.py``'s ``_poll_once`` + ``_client_count_entry`` (the
rolling 1h client-count average / drop%% baseline) — keep the two in sync.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict

from .aruba import ArubaClient

logger = logging.getLogger("CentralHubPoller")

_POLL_INTERVAL_S = 300  # 5 min — matches the spoke poller + aruba.py cache TTLs

# Rolling client-count baseline (identical to central_poller.py): last hour of
# per-site counts → current + hourly_avg + drop%%; DEGRADED when the live count
# is >=25%% below the hour's average.
_CLIENT_WINDOW_SECS = 3600
_CLIENT_MIN_SAMPLES = 3
_CLIENT_DROP_PCT = 25.0


class CentralHubPoller:
    """Polls Aruba Central hub-side for every centralized-mode tenant on a
    5-minute loop, writing ``hub.central_hub_status[tenant_id]`` in the shape the
    Simulations service / sim-views.js Checks/Hardware/Client-Count/Central tabs
    expect. See the module docstring."""

    def __init__(self, hub) -> None:
        self.hub = hub
        # Rolling per-(tenant, wsite) client-count samples [(ts, count), ...].
        self._client_samples: Dict[str, Dict[str, list]] = {}

    @property
    def _store(self):
        return self.hub.simulations_store

    def _client_count_entry(self, tenant_id: str, wsite: str,
                            central_site: str, current: int) -> Dict[str, Any]:
        """Rolling 1h window → {current, hourly_avg, drop_pct, status}. DEGRADED
        when the live count is >=25%% below the hour's average (needs
        _CLIENT_MIN_SAMPLES first → NO_DATA). Mirrors
        central_poller.CentralPoller._client_count_entry, keyed per tenant."""
        now = time.time()
        samples = self._client_samples.setdefault(tenant_id, {}).setdefault(wsite, [])
        samples.append((now, current))
        cutoff = now - _CLIENT_WINDOW_SECS
        while samples and samples[0][0] < cutoff:
            samples.pop(0)
        if len(samples) >= _CLIENT_MIN_SAMPLES:
            avg = sum(s[1] for s in samples) / len(samples)
            drop_pct = max(0.0, (avg - current) / avg * 100.0) if avg >= 1 else 0.0
            status = "DEGRADED" if drop_pct >= _CLIENT_DROP_PCT else "OK"
        else:
            avg, drop_pct, status = float(current), 0.0, "NO_DATA"
        return {"site_name": central_site, "current": current,
                "hourly_avg": round(avg, 1), "drop_pct": round(drop_pct, 1),
                "status": status, "ts": now}

    async def _centralized_tenants(self) -> list:
        """(tenant_id, central_config) for every tenant in centralized central_api
        mode with a non-empty central_config. Skips tenants with no creds."""
        out = []
        for tid in self._store.tenant_ids():
            try:
                modes = await self._store.get_processing_modes(tid)
                if modes.get("central_api") != "centralized":
                    continue
                cc = await self._store.get_central_config(tid)
                if cc:
                    out.append((tid, cc))
            except Exception:  # noqa: BLE001 — one bad tenant never blocks the rest
                continue
        return out

    async def _poll_tenant(self, tenant_id: str, central_config: Dict[str, Any]) -> None:
        # ArubaClient maps central_config's ``mode`` -> api_version itself.
        client = ArubaClient(central_config)
        if not client.is_configured():
            self.hub.central_hub_status.pop(tenant_id, None)
            self._client_samples.pop(tenant_id, None)
            return
        sites_cfg = await self._store.get_central_sites_config(tenant_id)
        site_mappings: Dict[str, str] = sites_cfg.get("site_mappings") or {}
        monitored: list = sites_cfg.get("monitored_checks") or []
        hw_checks: list = sites_cfg.get("hardware_checks") or []
        hw_check_ids = {str(h.get("id")) for h in hw_checks if h.get("id")}
        hw_names = {str(h.get("id")): h for h in hw_checks if h.get("id")}

        status: Dict[str, Any] = {}
        client_count_status: Dict[str, Any] = {}
        central_clients_by_site: Dict[str, int] = {}
        hw_totals: Dict[str, int] = {}

        for wireless_site, central_site in site_mappings.items():
            try:
                data = await client.poll_site_data(central_site, hw_check_ids)
            except Exception as exc:  # noqa: BLE001
                status[wireless_site] = {"poll_error": {"status": "error", "message": str(exc)}}
                continue
            alert_counts = data.get("alert_type_counts") or {}
            insight_counts = data.get("insight_cat_counts") or {}
            checks: Dict[str, Any] = {}
            for chk in monitored:
                cid = str(chk.get("id") or "")
                if not cid:
                    continue
                counts = alert_counts if (chk.get("type") or "alert") == "alert" else insight_counts
                n = int(counts.get(cid, 0) or 0)
                checks[cid] = {"status": "ok" if n == 0 else "error",
                               "message": f"{n} active" if n else "No active alerts"}
            if not checks and data.get("site_health") is not None:
                checks["site_health"] = {
                    "status": "ok" if (data.get("site_health") or 0) >= 80 else "warning",
                    "message": f"Site health {data.get('site_health')}",
                }
            status[wireless_site] = checks
            current = int(data.get("client_count", 0) or 0)
            client_count_status[wireless_site] = self._client_count_entry(
                tenant_id, wireless_site, central_site, current)
            central_clients_by_site[wireless_site] = current
            for alert_id, devices in (data.get("hw_devices") or {}).items():
                hw_totals[alert_id] = hw_totals.get(alert_id, 0) + sum(devices.values())

        hardware_alerts = [
            {"id": aid, "name": (hw_names.get(aid) or {}).get("name", aid),
             "device_type": (hw_names.get(aid) or {}).get("device_type", ""),
             "total": total}
            for aid, total in hw_totals.items()
        ]
        self.hub.central_hub_status[tenant_id] = {
            "status": status,
            "hardware_alerts": hardware_alerts,
            "client_count_status": client_count_status,
            "central_clients_by_site": central_clients_by_site,
            "site_mappings": site_mappings,
            "token_valid": True,
            "fetched_at": time.time(),
        }

    async def _poll_once(self) -> None:
        tenants = await self._centralized_tenants()
        # Drop cached status for tenants that left centralized mode / cleared creds
        # so the UI stops showing a stale synthetic hub spoke.
        live = {tid for tid, _ in tenants}
        for stale in [t for t in list(self.hub.central_hub_status.keys()) if t not in live]:
            self.hub.central_hub_status.pop(stale, None)
            self._client_samples.pop(stale, None)
        for tid, cc in tenants:
            try:
                await self._poll_tenant(tid, cc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Central hub poll failed for tenant %s: %s", tid, exc)

    async def run_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Central hub poll loop error: %s", exc)
            await asyncio.sleep(_POLL_INTERVAL_S)
