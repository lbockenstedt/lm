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
import json
import logging
import os
import time
from typing import Any, Dict

from .aruba import ArubaClient

logger = logging.getLogger("CentralHubPoller")

_POLL_INTERVAL_S = 300  # 5 min — matches the spoke poller + aruba.py cache TTLs

# Client-count baseline constants — ported verbatim from the source webui-spoke
# (server.py). The alarm baseline is a 7-DAY rolling average of hourly snapshots
# (NOT the 1h average), so a prolonged client drop stays flagged instead of the
# baseline sagging to match it.
_CC_WINDOW = 3600          # seconds of raw samples kept (the "current hourly")
_CC_MIN_SAMPLES = 3        # minimum live samples before flagging
_CC_WARN_PCT = 20.0        # >20% below the hour average -> WARNING
_CC_ERROR_PCT = 50.0       # >50% below -> ERROR        # percent drop below baseline that flags DEGRADED
_CC_7DAY_WINDOW = 7 * 86400
_CC_SNAPSHOT_INTERVAL = 3600  # append one hourly snapshot to the 7-day history / hr
_CC_KEYSEP = "\x1f"        # composite (tenant, wsite) key separator


class ClientCountTracker:
    """Per-(scope, wsite) client-count baseline + drop detection, ported
    faithfully from the source webui-spoke (server.py ``_client_count_payload`` /
    ``_save_client_count_baseline`` / ``hourly_baseline_saver``).

    Monitoring a site means watching its client count for a sustained DROP: 1h of
    raw samples gives the smoothed "current hourly" average, and a 7-DAY history
    of hourly snapshots is the STABLE alarm baseline. ``drop_pct = (baseline -
    hourly_avg) / baseline`` and the site goes DEGRADED at >=25%. Because the
    baseline spans 7 days, a prolonged drop does NOT suppress the alarm. Both the
    last-hour baseline and the 7-day history persist to disk so a restart keeps
    the reference instead of showing NO_DATA for an hour. ``scope`` is the
    tenant_id on the hub (a single fixed key on the distributed spoke)."""

    def __init__(self, baseline_path: str, sevenday_path: str) -> None:
        self._baseline_path = baseline_path
        self._sevenday_path = sevenday_path
        self._samples: Dict[str, list] = {}    # key -> [(ts, count), ...] (1h)
        self._hourly: Dict[str, list] = {}      # key -> [(ts, hourly_avg), ...] (7d)
        self._baseline: Dict[str, dict] = {}    # key -> {hourly_avg, recorded_at}
        # Match the source: wait one full hour before the first snapshot write.
        self._last_snapshot = time.time()
        self._load()

    @staticmethod
    def _key(scope: str, wsite: str) -> str:
        return f"{scope}{_CC_KEYSEP}{wsite}"

    def _load(self) -> None:
        now = time.time()
        try:
            with open(self._baseline_path, encoding="utf-8") as f:
                self._baseline = json.load(f) or {}
            # Seed synthetic samples from the saved average so the UI surfaces a
            # reference immediately on restart (they age out as live data arrives).
            for key, saved in self._baseline.items():
                avg = round(saved.get("hourly_avg", 0))
                self._samples[key] = [
                    (now - (_CC_MIN_SAMPLES - i) * 60, avg) for i in range(_CC_MIN_SAMPLES)
                ]
        except Exception:  # noqa: BLE001 — absent/corrupt baseline → start empty
            self._baseline = {}
        try:
            with open(self._sevenday_path, encoding="utf-8") as f:
                raw = json.load(f) or {}
            cutoff = now - _CC_7DAY_WINDOW
            self._hourly = {
                k: [(float(ts), float(v)) for ts, v in entries if float(ts) >= cutoff]
                for k, entries in raw.items()
            }
        except Exception:  # noqa: BLE001
            self._hourly = {}

    def record(self, scope: str, wsite: str, current: int) -> None:
        """Append a raw sample and trim to the 1-hour window."""
        now = time.time()
        key = self._key(scope, wsite)
        samples = self._samples.setdefault(key, [])
        samples.append((now, int(current)))
        cutoff = now - _CC_WINDOW
        self._samples[key] = [s for s in samples if s[0] >= cutoff]

    def entry(self, scope: str, wsite: str, central_site: str) -> Dict[str, Any]:
        """Per-site client-count status. Baseline = the AVERAGE over the last hour;
        the site goes WARNING when the current count is >20%% below that hourly
        average and ERROR when >50%% below (needs _CC_MIN_SAMPLES first -> no_data).
        Detects sim-client die-off within the last hour (the demo's failure mode).
        Status values (ok/warning/error/no_data) double as dashboard CHECK statuses."""
        now = time.time()
        key = self._key(scope, wsite)
        samples = self._samples.get(key, [])
        if not samples:
            return {"site_name": central_site, "current": 0, "hourly_avg": 0,
                    "drop_pct": 0.0, "status": "no_data", "ts": now}
        current = samples[-1][1]
        hourly_avg = sum(s[1] for s in samples) / len(samples)
        if len(samples) < _CC_MIN_SAMPLES:
            drop_pct, status = 0.0, "no_data"
        elif hourly_avg >= 1:
            drop_pct = max(0.0, (hourly_avg - current) / hourly_avg * 100.0)
            if drop_pct > _CC_ERROR_PCT:
                status = "error"
            elif drop_pct > _CC_WARN_PCT:
                status = "warning"
            else:
                status = "ok"
        else:
            drop_pct, status = 0.0, "ok"
        return {"site_name": central_site, "current": current,
                "hourly_avg": round(hourly_avg, 1), "drop_pct": round(drop_pct, 1),
                "status": status, "ts": samples[-1][0]}

    def maybe_snapshot(self) -> None:
        """Once per hour: append each site's current hourly average to the 7-day
        history and persist both files. Mirrors source hourly_baseline_saver +
        _save_client_count_baseline."""
        now = time.time()
        if now - self._last_snapshot < _CC_SNAPSHOT_INTERVAL:
            return
        self._last_snapshot = now
        cutoff = now - _CC_7DAY_WINDOW
        snapshot: Dict[str, dict] = {}
        for key, samples in self._samples.items():
            if len(samples) < _CC_MIN_SAMPLES:
                continue
            avg = sum(s[1] for s in samples) / len(samples)
            snapshot[key] = {"hourly_avg": round(avg, 1), "recorded_at": now}
            hist = self._hourly.setdefault(key, [])
            hist.append((now, avg))
            self._hourly[key] = [(ts, v) for ts, v in hist if ts >= cutoff]
        if snapshot:
            self._baseline.update(snapshot)
            self._persist(self._baseline_path, self._baseline)
        if self._hourly:
            self._persist(self._sevenday_path, {k: list(v) for k, v in self._hourly.items()})

    def forget(self, scope: str) -> None:
        """Drop all state for a scope (tenant left centralized mode / cleared creds)."""
        prefix = f"{scope}{_CC_KEYSEP}"
        for store in (self._samples, self._hourly, self._baseline):
            for k in [k for k in store if k.startswith(prefix)]:
                store.pop(k, None)

    @staticmethod
    def _persist(path: str, data: dict) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            logger.warning("ClientCountTracker: persist failed (%s): %s", path, exc)


class CentralHubPoller:
    """Polls Aruba Central hub-side for every centralized-mode tenant on a
    5-minute loop, writing ``hub.central_hub_status[tenant_id]`` in the shape the
    Simulations service / sim-views.js Checks/Hardware/Client-Count/Central tabs
    expect. See the module docstring."""

    def __init__(self, hub) -> None:
        self.hub = hub
        ddir = getattr(getattr(hub, "state", None), "data_dir", ".") or "."
        self._cc = ClientCountTracker(
            os.path.join(ddir, "client_count_baseline.json"),
            os.path.join(ddir, "client_count_7day.json"),
        )

    @property
    def _store(self):
        return self.hub.simulations_store

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
            self._cc.forget(tenant_id)
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
                # Per-site monitoring: a check pinned to a site evaluates ONLY on
                # that site (central_site); an empty/absent site = global (every
                # mapped site). Lets you monitor an insight/alert at one site.
                chk_site = str(chk.get("site") or "").strip().lower()
                if chk_site and chk_site not in (str(central_site).lower(), str(wireless_site).lower(), "all sites"):
                    continue
                counts = alert_counts if (chk.get("type") or "alert") == "alert" else insight_counts
                n = int(counts.get(cid, 0) or 0)
                # INVERTED semantics: this is a demo/simulation platform that is
                # SUPPOSED to be generating these alerts/insights. A monitored check
                # is HEALTHY (ok) when its error IS present, and FAILING (error) when
                # the expected error is NOT detected — the sim stopped producing it.
                # Monitor-for-absence: notify when the expected error goes missing.
                checks[cid] = {"status": "ok" if n > 0 else "error",
                               "message": f"{n} active (as expected)" if n else "Expected error NOT detected"}
            status[wireless_site] = checks
            current = int(data.get("client_count", 0) or 0)
            self._cc.record(tenant_id, wireless_site, current)
            cc_entry = self._cc.entry(tenant_id, wireless_site, central_site)
            client_count_status[wireless_site] = cc_entry
            # Surface the site's client-count monitor as a CHECK so "everything
            # monitored" shows on the dashboard Checks view. Direct (NOT inverted)
            # semantics: a DROP in clients means the sim clients died -> warning
            # (>20% below the hour average) / error (>50%). See ClientCountTracker.
            checks["Steady Client Count 1hr Average"] = {
                "status": cc_entry["status"],
                "message": f"{cc_entry['current']} clients vs {cc_entry['hourly_avg']} hr-avg (down {cc_entry['drop_pct']}%)",
            }
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
            self._cc.forget(stale)
        for tid, cc in tenants:
            try:
                await self._poll_tenant(tid, cc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Central hub poll failed for tenant %s: %s", tid, exc)
        # Append the hourly snapshot to the 7-day baseline history (self-gated to
        # once per hour) and persist — the alarm baseline that flags sustained drops.
        self._cc.maybe_snapshot()

    async def run_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Central hub poll loop error: %s", exc)
            await asyncio.sleep(_POLL_INTERVAL_S)
