"""Hub-side Juniper Mist poller for CENTRALIZED processing mode.

In centralized mode the HUB holds the Mist creds (Setup -> Mist API ->
``mist_config``) and the cs spoke has no Mist client, so the spoke-side
``MistPoller`` (``cs/lm-spoke/src/mist_poller.py``) never runs and the
Simulations Checks / Hardware / Client-Count and Mist tabs would stay empty
(they render ``spoke.mist_status`` relayed via CS_TELEMETRY, which a
credential-less spoke never produces).

This loop is the hub-side equivalent: for every tenant whose
``processing_modes.mist_api == "centralized"`` with a configured
``mist_config``, it polls Mist using the hub's full ``MistClient``
(``mist.py``) and writes the SAME ``mist_status`` shape the spoke relays
into ``hub.mist_hub_status[tenant_id]``. ``SimulationsService`` then injects
that as a synthetic "Hub (centralized)" spoke so the dashboards populate
identically to distributed mode.

The client-count / health-history / poll-window trackers are Central's
(``central_hub_poller``), subclassed only to keep Mist's state in its own files.

Mirrors ``mist_poller.py``'s ``_poll_once`` + ``_client_count_entry`` (the
rolling 1h client-count average / drop%% baseline) — keep the two in sync.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict

from .mist import MistClient
from .check_eval import count_for_check, normalize_counts

logger = logging.getLogger("MistHubPoller")


from .central_hub_poller import (  # the Mist poller shares Central's trackers
    _POLL_INTERVAL_FLOOR_S, _POLL_INTERVAL_S, CheckHealthHistory, CheckPollWindow,
    ClientCountTracker, _cc_site_floor, _cc_thresholds, _cc_worst,
    _classify_poll_status, min_client_check,
)


# Same trackers as Central; only the shard filenames differ, so Mist state is
# never mixed with Central's (same pattern as the Central On-Prem subclasses).
class MistClientCountTracker(ClientCountTracker):
    _BASELINE = "mist_client_count_baseline.json"
    _SEVENDAY = "mist_client_count_7day.json"
    _SAMPLES = "mist_client_count_samples.json"


class MistCheckHealthHistory(CheckHealthHistory):
    _NAME = "mist_check_health_history.json"


class MistCheckPollWindow(CheckPollWindow):
    _NAME = "mist_check_poll_window.json"


class MistHubPoller:
    """Polls Juniper Mist hub-side for every centralized-mode tenant on a
    5-minute loop, writing ``hub.mist_hub_status[tenant_id]`` in the shape the
    Simulations service / sim-views.js Checks/Hardware/Client-Count/Mist tabs
    expect. See the module docstring."""

    def __init__(self, hub) -> None:
        self.hub = hub
        ddir = getattr(getattr(hub, "state", None), "data_dir", ".") or "."
        self._cc = MistClientCountTracker(ddir)
        # 30-day per-check status history (green/yellow/red) for the health graphs.
        self._health = MistCheckHealthHistory(ddir)
        # Rolling 1h PASS/FAIL window per check → the last-hour verdict override
        # (a check can't read OK if any poll failed within the hour).
        self._cpw = MistCheckPollWindow(ddir)
        # Per-tenant last-poll timestamps + the next loop sleep. The Mist poll
        # interval is configurable per tenant (Setup → Mist API → Connection);
        # tenants are gated by their own interval and the loop wakes on the
        # shortest configured one.
        self._last_poll: Dict[str, float] = {}
        self._next_sleep_s: float = _POLL_INTERVAL_S

    @property
    def _store(self):
        return self.hub.simulations_store

    async def _centralized_tenants(self) -> list:
        """(tenant_id, mist_config) for every tenant in centralized mist_api mode
        with a non-empty mist_config. Skips tenants with no creds."""
        out = []
        for tid in self._store.tenant_ids():
            try:
                modes = await self._store.get_processing_modes(tid)
                # Mist API defaults to CENTRALIZED — only explicit 'distributed'
                # (a spoke owns the creds) opts out. So a hub with a Mist config
                # and no spoke still gets polled and its checks show.
                if not self._store.mist_api_is_centralized(modes):
                    continue
                mc = await self._store.get_mist_config(tid)
                if mc:
                    out.append((tid, mc))
            except Exception:  # noqa: BLE001 — one bad tenant never blocks the rest
                continue
        return out

    @staticmethod
    def _interval_for(mist_config: Dict[str, Any]) -> int:
        """This tenant's Mist poll interval in seconds — ``poll_interval_s`` from
        its mist_config (Setup → Mist API → Connection), defaulting to 5 min and
        clamped to the floor so a misconfig can't hammer the Mist API."""
        try:
            iv = int((mist_config or {}).get("poll_interval_s") or _POLL_INTERVAL_S)
        except (TypeError, ValueError):
            iv = _POLL_INTERVAL_S
        return max(_POLL_INTERVAL_FLOOR_S, iv)

    async def _poll_tenant(self, tenant_id: str, mist_config: Dict[str, Any]) -> None:
        client = MistClient(mist_config)
        if not client.is_configured():
            self.hub.mist_hub_status.pop(tenant_id, None)
            self._cc.forget(tenant_id)
            self._cpw.forget(tenant_id)
            return
        cc_thresh = _cc_thresholds(mist_config)
        sites_cfg = await self._store.get_mist_sites_config(tenant_id)
        site_mappings: Dict[str, str] = sites_cfg.get("site_mappings") or {}
        monitored: list = sites_cfg.get("monitored_checks") or []
        hw_checks: list = sites_cfg.get("hardware_checks") or []
        # Per-site minimum client count threshold (site name -> int). When set,
        # the poller raises a "Minimum Client Threshold" check (direct semantics:
        # below the floor = error) IN ADDITION to the drop-based client-count
        # check — some sites should always have at least N clients (a floor),
        # independent of the % drop from the rolling average.
        site_min_clients: Dict[str, int] = {
            str(k): int(v) for k, v in (sites_cfg.get("site_min_clients") or {}).items()
            if isinstance(v, (int, float)) and int(v) > 0
        }
        hw_check_ids = {str(h.get("id")) for h in hw_checks if h.get("id")}
        hw_names = {str(h.get("id")): h for h in hw_checks if h.get("id")}

        status: Dict[str, Any] = {}
        client_count_status: Dict[str, Any] = {}
        mist_clients_by_site: Dict[str, int] = {}
        hw_totals: Dict[str, int] = {}

        for wireless_site, mist_site in site_mappings.items():
            try:
                data = await client.poll_site_data(mist_site, hw_check_ids)
            except Exception as exc:  # noqa: BLE001
                status[wireless_site] = {"poll_error": {"status": "error", "message": str(exc)}}
                continue
            alert_counts = data.get("alert_type_counts") or {}
            insight_counts = data.get("insight_cat_counts") or {}
            # Match case-insensitively AND across BOTH the alert and insight
            # buckets (same rationale as the Central poller; shared match logic
            # lives in check_eval). Typed bucket wins; fall back to the other.
            alert_ci, insight_ci = normalize_counts(alert_counts), normalize_counts(insight_counts)
            logger.debug("mist-check diag [%s→%s]: monitored=%s alert_keys=%s insight_keys=%s",
                         wireless_site, mist_site,
                         [str(c.get("id")) for c in monitored if isinstance(c, dict) and c.get("id")],
                         sorted(alert_ci), sorted(insight_ci))
            # GLOBAL SIM CATALOG: record every alert/insight NAME observed on this
            # tenant/site into the hub-wide history shared by ALL tenants, tagged
            # source="mist" so the Sim-Quota picker builds a Mist library
            # automatically from live polling. Best-effort: the store writes only
            # when a NEW type appears, so a steady poll adds no I/O, and a failure
            # here can never break the poll cycle.
            try:
                _cat_items = (
                    [{"type": "alert", "id": k, "name": k, "site": mist_site,
                      "source": "mist"}
                     for k in (alert_counts or {})]
                    + [{"type": "insight", "id": k, "name": k, "site": mist_site,
                        "source": "mist"}
                       for k in (insight_counts or {})]
                )
                if _cat_items:
                    await self._store.record_alert_insight_seen(_cat_items)
            except Exception:  # noqa: BLE001 — cataloguing must never break the poll
                pass
            checks: Dict[str, Any] = {}
            for chk in monitored:
                cid = str(chk.get("id") or "")
                if not cid:
                    continue
                # Per-site monitoring: a check pinned to a site evaluates ONLY on
                # that site (mist_site); an empty/absent site = global (every
                # mapped site). Lets you monitor an alert/insight at one site.
                chk_site = str(chk.get("site") or "").strip().lower()
                if chk_site and chk_site not in (str(mist_site).lower(), str(wireless_site).lower(), "all sites"):
                    continue
                n = count_for_check(chk, alert_ci, insight_ci)
                # INVERTED semantics: this is a demo/simulation platform that is
                # SUPPOSED to be generating these alerts/insights. A monitored check
                # is HEALTHY (ok) when its error IS present, and FAILING (error) when
                # the expected error is NOT detected — the sim stopped producing it.
                # Monitor-for-absence: notify when the expected error goes missing.
                if n > 0:
                    checks[cid] = {"status": "ok", "message": f"{n} active (as expected)"}
                else:
                    # Surface WHY the expected error is absent (mirrors central twin):
                    # site returned NOTHING → site dropped / name mismatch; vs the
                    # site reporting other conditions → sim not firing THIS alert.
                    _seen = len(alert_ci) + len(insight_ci)
                    _cc = int(data.get("client_count", 0) or 0)
                    if _seen == 0:
                        _msg = (f"Expected error NOT detected — site returned no "
                                f"alerts/insights ({_cc} clients; site dropped or "
                                f"name mismatch?)")
                    else:
                        _msg = (f"Expected error NOT detected — sim not firing "
                                f"(0 seen; {_seen} other condition(s) at site, "
                                f"{_cc} clients)")
                    checks[cid] = {"status": "error", "message": _msg}
            status[wireless_site] = checks
            current = int(data.get("client_count", 0) or 0)
            wired = int(data.get("wired_clients", 0) or 0)
            wireless = int(data.get("wireless_clients", 0) or 0)
            # Track total, wired, and wireless as SEPARATE series so each is
            # evaluated on its own baseline/peak with the same thresholds — a
            # wired-only or wireless-only die-off is caught even when the total is
            # masked (e.g. wired collapses while wireless spikes).
            self._cc.record(tenant_id, wireless_site, current)
            self._cc.record(tenant_id, wireless_site, wired, kind="wired")
            self._cc.record(tenant_id, wireless_site, wireless, kind="wireless")
            # Per-site FLOOR, resolved here because entry() only sees thresholds.
            # Absent/0 disables the floor rule for THIS site alone.
            cc_thresh = dict(cc_thresh or {})
            cc_thresh["floor"] = _cc_site_floor(sites_cfg, wireless_site, mist_site)
            cc_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh)
            w_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh, kind="wired")
            wl_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh, kind="wireless")
            cc_entry["wired"] = wired
            cc_entry["wireless"] = wireless
            cc_entry["wired_status"] = w_entry["status"]
            cc_entry["wired_drop_pct"] = w_entry["drop_pct"]
            cc_entry["wireless_status"] = wl_entry["status"]
            cc_entry["wireless_drop_pct"] = wl_entry["drop_pct"]
            # Overall = worst of total/wired/wireless.
            cc_entry["status"] = _cc_worst(cc_entry["status"], w_entry["status"], wl_entry["status"])
            client_count_status[wireless_site] = cc_entry
            # Surface the site's client-count monitor as a CHECK so "everything
            # monitored" shows on the dashboard Checks view. Direct (NOT inverted)
            # semantics: a DROP in clients means the sim clients died -> warning / error.
            checks["Steady Client Count 1hr Average"] = {
                "status": cc_entry["status"],
                "message": (f"{cc_entry['current']} clients vs {cc_entry['hourly_avg']} hr-avg "
                            f"(down {cc_entry['drop_pct']}%) · wired {wired} (down {w_entry['drop_pct']}%) "
                            f"· wireless {wireless} (down {wl_entry['drop_pct']}%)"),
            }
            # Per-site minimum client floor. Direct semantics: current below the
            # configured min = error (clients died below an absolute floor, not
            # just a relative drop). Only emitted when a min is set for THIS site
            # — sites without a threshold are unchanged. The floor lookup matches
            # on the wireless site name OR the mist site name so a threshold saved
            # against either form applies.
            min_floor = site_min_clients.get(wireless_site) or site_min_clients.get(mist_site)
            _mc = min_client_check(current, min_floor)
            if _mc:
                checks["Minimum Client Threshold"] = _mc
            mist_clients_by_site[wireless_site] = current
            for alert_id, devices in (data.get("hw_devices") or {}).items():
                hw_totals[alert_id] = hw_totals.get(alert_id, 0) + sum(devices.values())

        # Per-device hardware monitoring: look each monitored hardware device up in
        # the live org inventory and add a check on its pinned site — DOWN = error
        # (a monitored AP/switch/gateway is offline). Mirrors the Central poller's
        # new_central per-device section, but adapted for Mist's inventory. Mist
        # hardware checks are TYPE-based by default (ap_offline / switch_down /
        # gateway_down) and are already surfaced as monitored checks + hardware
        # totals above; a hw check whose id is NOT an actual device serial/name is
        # SKIPPED here so a type-based check is never spuriously marked DOWN.
        if hw_checks:
            try:
                all_devices = await client._list_inventory()
            except Exception:  # noqa: BLE001
                all_devices = []
            dev_by_key: Dict[str, dict] = {}
            for d in all_devices:
                for k in (d.get("serial"), d.get("name"), d.get("id"), d.get("mac")):
                    if k:
                        dev_by_key[str(k)] = d
            for hc in hw_checks:
                hid = str(hc.get("id") or "")
                if not hid:
                    continue
                dev = dev_by_key.get(hid)
                if dev is None:
                    # id is a type/alias, not a real device → covered elsewhere.
                    continue
                hsite = str(hc.get("site") or "").strip().lower()
                up = bool(dev.get("connected")) or str(dev.get("status") or "").upper() in ("UP", "ONLINE", "CONNECTED")
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
        self.hub.mist_hub_status[tenant_id] = {
            "status": status,
            "hardware_alerts": hardware_alerts,
            "client_count_status": client_count_status,
            "mist_clients_by_site": mist_clients_by_site,
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
                # Rolling 1h verdict: a check must NOT read OK if any poll FAILED
                # in the last hour. Classify this poll (INVERTED sim semantics —
                # a client-drop "warning" or a missing-alert "error" both = a
                # FAILED poll), record it, then OVERRIDE the stored status with
                # the aggregate verdict. Because mist_hub_status[...]["status"]
                # holds this SAME dict by reference, rewriting info["status"]
                # flows into the persisted block and to the dashboard. no_data/
                # other → ignore (verdict stays None) → leave as-is.
                is_pass = _classify_poll_status(st)
                if is_pass is None or not isinstance(info, dict):
                    continue
                self._cpw.record(tenant_id, wsite, cid, is_pass)
                verdict = self._cpw.verdict(tenant_id, wsite, cid)
                if verdict is not None:
                    info["status"] = verdict
                    passes, total = self._cpw.counts(tenant_id, wsite, cid)
                    info["message"] = f"{info.get('message', '')} · {passes}/{total} polls OK in last 1h"

    async def _poll_once(self) -> None:
        tenants = await self._centralized_tenants()
        # Drop cached status for tenants that left centralized mode / cleared creds
        # so the UI stops showing a stale synthetic hub spoke.
        live = {tid for tid, _ in tenants}
        for stale in [t for t in list(self.hub.mist_hub_status.keys()) if t not in live]:
            self.hub.mist_hub_status.pop(stale, None)
            self._cc.forget(stale)
            self._cpw.forget(stale)
            self._last_poll.pop(stale, None)
        now = time.time()
        # Gate each tenant by its own configured interval; wake on the shortest.
        intervals = [self._interval_for(mc) for _, mc in tenants]
        self._next_sleep_s = min(intervals) if intervals else _POLL_INTERVAL_S
        for tid, mc in tenants:
            iv = self._interval_for(mc)
            if now - self._last_poll.get(tid, 0.0) < iv:
                continue  # not due yet
            self._last_poll[tid] = now
            try:
                await self._poll_tenant(tid, mc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Mist hub poll failed for tenant %s: %s", tid, exc)
        # Append the hourly snapshot to the 7-day baseline history (self-gated to
        # once per hour) and persist — the alarm baseline that flags sustained drops.
        self._cc.maybe_snapshot()
        # Persist the raw 1h samples EVERY cycle so a restart (even within the
        # first hour, before any hourly baseline is written) restores the actual
        # last-hour reference instead of showing NO_DATA for ~15 min while it
        # rebuilds. Cheap (small dict); best-effort.
        # Off the event loop (bounded per-tenant shard writes once per cycle) so
        # they can't starve the WS loop — same discipline as _health.save below.
        try:
            await asyncio.to_thread(self._cc.save_samples)
        except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
            logger.debug("mist client-count samples persist skipped: %s", exc)
        # Persist the rolling 1h PASS/FAIL window too so the last-hour verdict
        # survives a hub restart within the hour.
        try:
            await asyncio.to_thread(self._cpw.save_samples)
        except Exception as exc:  # noqa: BLE001
            logger.debug("mist check poll window persist skipped: %s", exc)
        # Persist the per-check health history off-thread (bounded once-per-cycle write).
        try:
            await asyncio.to_thread(self._health.save)
        except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
            logger.debug("mist check health persist skipped: %s", exc)
        # Warm-start persistence for the whole per-tenant dashboard status. Off the
        # event loop — a bounded write once per 5-min cycle can't starve the WS.
        save = getattr(self.hub, "_save_mist_hub_status", None)
        if save:
            try:
                await asyncio.to_thread(save)
            except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
                logger.debug("mist_hub_status persist skipped: %s", exc)

    async def run_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Mist hub poll loop error: %s", exc)
            await asyncio.sleep(max(_POLL_INTERVAL_FLOOR_S, self._next_sleep_s))