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
from .check_eval import count_for_check, normalize_counts

logger = logging.getLogger("CentralHubPoller")

_POLL_INTERVAL_S = 300  # 5 min — default; matches the spoke poller + aruba.py cache TTLs
_POLL_INTERVAL_FLOOR_S = 60  # min allowed per-tenant interval (protect the Central API)

# Client-count baseline constants — ported verbatim from the source webui-spoke
# (server.py). The alarm baseline is a 7-DAY rolling average of hourly snapshots
# (NOT the 1h average), so a prolonged client drop stays flagged instead of the
# baseline sagging to match it.
_CC_WINDOW = 3600          # seconds of raw samples kept (the "current hourly")
_CC_MIN_SAMPLES = 3        # minimum live samples before flagging
_CC_WARN_PCT = 20.0        # >20% below the hour average -> WARNING
_CC_ERROR_PCT = 50.0       # >50% below -> ERROR        # percent drop below baseline that flags DEGRADED
_CC_7DAY_WINDOW = 7 * 86400
_CC_30DAY_WINDOW = 30 * 86400   # long-run history retention (the 7-day is a subset)
_CC_SNAPSHOT_INTERVAL = 3600  # append one hourly snapshot to the history / hr
# Severe sustained die-off: the current hour is < 20% of the rolling PEAK
# (max hourly-avg) over the window → ERROR. Gated on a meaningful peak so a
# quiet/low-traffic site can't error on noise.
_CC_MAX_FRACTION = 0.20
_CC_MAX_MIN_PEAK = 5
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

    def __init__(self, baseline_path: str, sevenday_path: str,
                 samples_path: str = "") -> None:
        self._baseline_path = baseline_path
        self._sevenday_path = sevenday_path
        # Raw 1h samples persist here too (every poll cycle) so a restart within
        # the first hour restores the ACTUAL reference, not just the synthetic
        # seed from the (hourly-written) baseline.
        self._samples_path = samples_path or (
            baseline_path.replace("baseline", "samples") if "baseline" in baseline_path
            else baseline_path + ".samples")
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
            cutoff = now - _CC_30DAY_WINDOW
            self._hourly = {
                k: [(float(ts), float(v)) for ts, v in entries if float(ts) >= cutoff]
                for k, entries in raw.items()
            }
        except Exception:  # noqa: BLE001
            self._hourly = {}
        # Restore the ACTUAL last-hour raw samples (trimmed to the 1h window),
        # overriding the synthetic seed above so the reference is exact on restart
        # — including within the first hour before any baseline was ever written.
        try:
            with open(self._samples_path, encoding="utf-8") as f:
                raw_s = json.load(f) or {}
            scut = now - _CC_WINDOW
            for key, entries in raw_s.items():
                kept = [(float(ts), int(v)) for ts, v in entries if float(ts) >= scut]
                if kept:
                    self._samples[key] = kept
        except Exception:  # noqa: BLE001 — absent/corrupt → keep synthetic seed
            pass

    def record(self, scope: str, wsite: str, current: int) -> None:
        """Append a raw sample and trim to the 1-hour window."""
        now = time.time()
        key = self._key(scope, wsite)
        samples = self._samples.setdefault(key, [])
        samples.append((now, int(current)))
        cutoff = now - _CC_WINDOW
        self._samples[key] = [s for s in samples if s[0] >= cutoff]

    def entry(self, scope: str, wsite: str, central_site: str) -> Dict[str, Any]:
        """Per-site client-count status (doubles as a dashboard CHECK). Tiered:
          - WITHIN-HOUR drop (current vs the last-hour average): WARNING at >20%
            below, ERROR at >50% below — catches sim-client die-off inside the hour.
          - SUSTAINED die-off: the current hour < 20% (``_CC_MAX_FRACTION``) of the
            7-DAY or 30-DAY rolling PEAK (max hourly-avg) → ERROR. Gated on a peak
            of at least ``_CC_MAX_MIN_PEAK`` so a quiet site can't false-trigger.
        The 7d/30d peaks are recorded for display regardless of status."""
        now = time.time()
        key = self._key(scope, wsite)
        samples = self._samples.get(key, [])
        hist = self._hourly.get(key, [])
        # Rolling peaks over each window (include the live hour so a fresh spike counts).
        vals_7d = [v for ts, v in hist if ts >= now - _CC_7DAY_WINDOW]
        vals_30d = [v for ts, v in hist if ts >= now - _CC_30DAY_WINDOW]
        if not samples:
            return {"site_name": central_site, "current": 0, "hourly_avg": 0,
                    "drop_pct": 0.0, "max_7day": round(max(vals_7d or [0]), 1),
                    "max_30day": round(max(vals_30d or [0]), 1),
                    "status": "no_data", "ts": now}
        current = samples[-1][1]
        hourly_avg = sum(s[1] for s in samples) / len(samples)
        max_7day = round(max(vals_7d + [hourly_avg]), 1)
        max_30day = round(max(vals_30d + [hourly_avg]), 1)
        if len(samples) < _CC_MIN_SAMPLES:
            drop_pct, status = 0.0, "no_data"
        else:
            if hourly_avg >= 1:
                drop_pct = max(0.0, (hourly_avg - current) / hourly_avg * 100.0)
            else:
                drop_pct = 0.0
            # Within-hour tier.
            if drop_pct > _CC_ERROR_PCT:
                status = "error"
            elif drop_pct > _CC_WARN_PCT:
                status = "warning"
            else:
                status = "ok"
            # Sustained die-off vs the 7d/30d peak → hard ERROR (overrides warn/ok).
            if ((max_7day >= _CC_MAX_MIN_PEAK and hourly_avg < _CC_MAX_FRACTION * max_7day)
                    or (max_30day >= _CC_MAX_MIN_PEAK and hourly_avg < _CC_MAX_FRACTION * max_30day)):
                status = "error"
        return {"site_name": central_site, "current": current,
                "hourly_avg": round(hourly_avg, 1), "drop_pct": round(drop_pct, 1),
                "max_7day": max_7day, "max_30day": max_30day,
                "status": status, "ts": samples[-1][0]}

    def maybe_snapshot(self) -> None:
        """Once per hour: append each site's current hourly average to the 7-day
        history and persist both files. Mirrors source hourly_baseline_saver +
        _save_client_count_baseline."""
        now = time.time()
        if now - self._last_snapshot < _CC_SNAPSHOT_INTERVAL:
            return
        self._last_snapshot = now
        cutoff = now - _CC_30DAY_WINDOW
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

    def save_samples(self) -> None:
        """Persist the raw 1h samples (trimmed to the window) every poll cycle so
        a restart restores the exact reference. Best-effort; small dict."""
        now = time.time()
        cutoff = now - _CC_WINDOW
        trimmed = {
            k: [(ts, c) for ts, c in v if ts >= cutoff]
            for k, v in self._samples.items()
        }
        trimmed = {k: v for k, v in trimmed.items() if v}
        self._persist(self._samples_path, trimmed)

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


_HEALTH_IDX = {"ok": 0, "warning": 1, "error": 2}  # else (no_data/pending/unknown) -> 3


class CheckHealthHistory:
    """Rolling 30-day status history for every dashboard check, in HOURLY buckets.

    Each poll records one status sample per (tenant, site, check) into the current
    hour's bucket as counts ``[ok, warning, error, other]`` (green/yellow/red/grey).
    ``summary`` rolls the hourly buckets up to 30 DAILY buckets for the at-a-glance
    health strip; ``hourly`` returns the raw hourly buckets for the on-hover
    breakdown. Persisted to one JSON file in the data dir (not sensitive)."""

    def __init__(self, path: str) -> None:
        self._path = path
        # key = tenant\x1fsite\x1fcheck -> {hour_ts(int): [o, w, e, n]}
        self._h: Dict[str, Dict[int, list]] = {}
        self._load()

    @staticmethod
    def _key(tenant: str, site: str, check_id: str) -> str:
        return f"{tenant}{_CC_KEYSEP}{site}{_CC_KEYSEP}{check_id}"

    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as f:
                raw = json.load(f) or {}
            cutoff = time.time() - _CC_30DAY_WINDOW
            self._h = {
                k: {int(b): list(v) for b, v in buckets.items() if int(b) >= cutoff}
                for k, buckets in raw.items()
            }
        except Exception:  # noqa: BLE001 — absent/corrupt → start empty
            self._h = {}

    def record(self, tenant: str, site: str, check_id: str, status: str) -> None:
        now = time.time()
        buckets = self._h.setdefault(self._key(tenant, site, check_id), {})
        bucket = int(now // 3600 * 3600)
        cell = buckets.get(bucket)
        if cell is None:
            cell = [0, 0, 0, 0]
            buckets[bucket] = cell
        cell[_HEALTH_IDX.get(str(status).strip().lower(), 3)] += 1
        cutoff = now - _CC_30DAY_WINDOW
        for b in [b for b in buckets if b < cutoff]:
            del buckets[b]

    def save(self) -> None:
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({k: {str(b): v for b, v in bk.items()}
                           for k, bk in self._h.items()}, f, default=str)
            os.replace(tmp, self._path)
        except Exception:  # noqa: BLE001 — never let persistence kill the poll
            pass

    def summary(self, tenant: str) -> Dict[str, Any]:
        """{site: {check_id: [{d, o, w, e, n} ... up to 30 daily]}} for the tenant."""
        now = time.time()
        floor = int(now // 86400 * 86400) - 29 * 86400
        prefix = f"{tenant}{_CC_KEYSEP}"
        out: Dict[str, Any] = {}
        for key, buckets in self._h.items():
            if not key.startswith(prefix):
                continue
            parts = key.split(_CC_KEYSEP, 2)
            if len(parts) != 3:
                continue
            _, site, check_id = parts
            days: Dict[int, list] = {}
            for b, cell in buckets.items():
                d = int(b // 86400 * 86400)
                if d < floor:
                    continue
                acc = days.setdefault(d, [0, 0, 0, 0])
                for i in range(4):
                    acc[i] += cell[i]
            out.setdefault(site, {})[check_id] = [
                {"d": d, "o": v[0], "w": v[1], "e": v[2], "n": v[3]}
                for d, v in sorted(days.items())
            ]
        return out

    def hourly(self, tenant: str, site: str, check_id: str) -> list:
        """Raw hourly buckets [{h, o, w, e, n}] (last 30 days) for one check."""
        buckets = self._h.get(self._key(tenant, site, check_id), {})
        return [{"h": b, "o": v[0], "w": v[1], "e": v[2], "n": v[3]}
                for b, v in sorted(buckets.items())]


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
            os.path.join(ddir, "client_count_samples.json"),
        )
        # 30-day per-check status history (green/yellow/red) for the health graphs.
        self._health = CheckHealthHistory(os.path.join(ddir, "check_health_history.json"))
        # Per-tenant last-poll timestamps + the next loop sleep. The Central poll
        # interval is configurable per tenant (Setup → Central API → Connection);
        # tenants are gated by their own interval and the loop wakes on the
        # shortest configured one.
        self._last_poll: Dict[str, float] = {}
        self._next_sleep_s: float = _POLL_INTERVAL_S

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
                # Central API defaults to CENTRALIZED — only explicit 'distributed'
                # (a spoke owns the creds) opts out. So a hub with a Central config
                # and no spoke still gets polled and its checks show.
                if not self._store.central_api_is_centralized(modes):
                    continue
                cc = await self._store.get_central_config(tid)
                if cc:
                    out.append((tid, cc))
            except Exception:  # noqa: BLE001 — one bad tenant never blocks the rest
                continue
        return out

    @staticmethod
    def _interval_for(central_config: Dict[str, Any]) -> int:
        """This tenant's Central poll interval in seconds — ``poll_interval_s`` from
        its central_config (Setup → Central API → Connection), defaulting to 5 min
        and clamped to the floor so a misconfig can't hammer the Central API."""
        try:
            iv = int((central_config or {}).get("poll_interval_s") or _POLL_INTERVAL_S)
        except (TypeError, ValueError):
            iv = _POLL_INTERVAL_S
        return max(_POLL_INTERVAL_FLOOR_S, iv)

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
            # Match case-insensitively AND across BOTH the alert and insight
            # buckets. The dashboard's alert/insight query is merged, so a check
            # must fire whether Central classifies the named condition as an alert
            # or an insight — e.g. "DNS Server Failed to Respond" comes back as an
            # INSIGHT, but its quota is typed "alert". Reading only the typed
            # bucket (case-sensitively) reported a live condition as absent, so the
            # adaptive controller ramped forever and exhausted the client pool.
            # Typed bucket wins; fall back to the other. Shared with the three CS
            # deployments via check_eval (single source of truth for this match).
            alert_ci, insight_ci = normalize_counts(alert_counts), normalize_counts(insight_counts)
            # DIAG: what the engine looks for vs what Central actually returned for
            # this site. A monitored id absent from BOTH lists = a site-drop or a
            # name diff; present = should fire.
            logger.info("central-check diag [%s→%s]: monitored=%s alert_keys=%s insight_keys=%s",
                        wireless_site, central_site,
                        [str(c.get("id")) for c in monitored if isinstance(c, dict) and c.get("id")],
                        sorted(alert_ci), sorted(insight_ci))
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
                n = count_for_check(chk, alert_ci, insight_ci)
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
            # Break out wired vs wireless (Central reports both; total = their sum).
            cc_entry["wired"] = int(data.get("wired_clients", 0) or 0)
            cc_entry["wireless"] = int(data.get("wireless_clients", 0) or 0)
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

        # Per-device hardware monitoring: look each monitored hardware device up in
        # the live device list and add a check on its pinned site — DOWN = error
        # (a monitored switch/AP/gateway is offline). new_central only; best-effort.
        if hw_checks:
            try:
                all_devices = await client._nc_devices()
            except Exception:  # noqa: BLE001
                all_devices = []
            dev_by_key: Dict[str, dict] = {}
            for d in all_devices:
                for k in (d.get("serialNumber"), d.get("serial"), d.get("deviceName"), d.get("name")):
                    if k:
                        dev_by_key[str(k)] = d
            for hc in hw_checks:
                hid = str(hc.get("id") or "")
                if not hid:
                    continue
                hsite = str(hc.get("site") or "").strip().lower()
                dev = dev_by_key.get(hid)
                up = str((dev or {}).get("status") or "").upper() in ("UP", "ONLINE")
                label = str(hc.get("name") or hid)
                for wsite, csite in site_mappings.items():
                    if hsite and hsite not in (str(csite).lower(), str(wsite).lower(), "all sites"):
                        continue
                    status.setdefault(wsite, {})[label] = {
                        "status": "ok" if up else "error",
                        "message": "up" if up else "DOWN",
                    }

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
        # Record each check's status into the 30-day health history (hourly bucket).
        for wsite, checks_map in status.items():
            if not isinstance(checks_map, dict):
                continue
            for cid, info in checks_map.items():
                st = (info.get("status") if isinstance(info, dict) else info) or "no_data"
                self._health.record(tenant_id, wsite, cid, st)

    async def _poll_once(self) -> None:
        tenants = await self._centralized_tenants()
        # Drop cached status for tenants that left centralized mode / cleared creds
        # so the UI stops showing a stale synthetic hub spoke.
        live = {tid for tid, _ in tenants}
        for stale in [t for t in list(self.hub.central_hub_status.keys()) if t not in live]:
            self.hub.central_hub_status.pop(stale, None)
            self._cc.forget(stale)
            self._last_poll.pop(stale, None)
        now = time.time()
        # Gate each tenant by its own configured interval; wake on the shortest.
        intervals = [self._interval_for(cc) for _, cc in tenants]
        self._next_sleep_s = min(intervals) if intervals else _POLL_INTERVAL_S
        for tid, cc in tenants:
            iv = self._interval_for(cc)
            if now - self._last_poll.get(tid, 0.0) < iv:
                continue  # not due yet
            self._last_poll[tid] = now
            try:
                await self._poll_tenant(tid, cc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Central hub poll failed for tenant %s: %s", tid, exc)
        # Append the hourly snapshot to the 7-day baseline history (self-gated to
        # once per hour) and persist — the alarm baseline that flags sustained drops.
        self._cc.maybe_snapshot()
        # Persist the raw 1h samples EVERY cycle so a restart (even within the
        # first hour, before any hourly baseline is written) restores the actual
        # last-hour reference instead of showing NO_DATA for ~15 min while it
        # rebuilds. Cheap (small dict); best-effort.
        self._cc.save_samples()
        # Persist the per-check health history off-thread (bounded once-per-cycle write).
        try:
            await asyncio.to_thread(self._health.save)
        except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
            logger.debug("check health persist skipped: %s", exc)
        # Warm-start persistence for the whole per-tenant dashboard status. Off the
        # event loop — a bounded write once per 5-min cycle can't starve the WS.
        save = getattr(self.hub, "_save_central_hub_status", None)
        if save:
            try:
                await asyncio.to_thread(save)
            except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
                logger.debug("central_hub_status persist skipped: %s", exc)

    async def run_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Central hub poll loop error: %s", exc)
            await asyncio.sleep(max(_POLL_INTERVAL_FLOOR_S, self._next_sleep_s))
