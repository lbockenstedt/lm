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
# Postponed annotations: type hints are not evaluated at runtime.
from __future__ import annotations

# asyncio for the polling loop and for moving disk writes off the event loop.
import asyncio
# Standard-library logging for poll failures and diagnostics.
import logging
# Wall-clock timestamps for fetched_at and per-tenant poll gating.
import time
# Type hints only.
from typing import Any, Dict

# The hub's full Juniper Mist API client.
from .mist import MistClient
# Shared helpers that match monitored checks against alert/insight counts.
from .check_eval import count_for_check, normalize_counts

# One named logger for the hub-side Mist poller.
logger = logging.getLogger("MistHubPoller")


# Reuse Central's poll intervals, trackers and client-count helpers so both behave alike.
from .central_hub_poller import (  # the Mist poller shares Central's trackers
    _POLL_INTERVAL_FLOOR_S, _POLL_INTERVAL_S, CheckHealthHistory, CheckPollWindow,
    ClientCountTracker, _cc_site_floor, _cc_thresholds, _cc_worst,
    _classify_poll_status, min_client_check,
)


# Same trackers as Central; only the shard filenames differ, so Mist state is
# never mixed with Central's (same pattern as the Central On-Prem subclasses).
class MistClientCountTracker(ClientCountTracker):
    """Client-count tracker that stores Mist samples/baselines in Mist-specific files."""
    _BASELINE = "mist_client_count_baseline.json"
    _SEVENDAY = "mist_client_count_7day.json"
    _SAMPLES = "mist_client_count_samples.json"


class MistCheckHealthHistory(CheckHealthHistory):
    """Check health history that stores Mist data in its own file."""
    _NAME = "mist_check_health_history.json"


class MistCheckPollWindow(CheckPollWindow):
    """Rolling 1h pass/fail window that stores Mist data in its own file."""
    _NAME = "mist_check_poll_window.json"


class MistHubPoller:
    """Polls Juniper Mist hub-side for every centralized-mode tenant on a
    5-minute loop, writing ``hub.mist_hub_status[tenant_id]`` in the shape the
    Simulations service / sim-views.js Checks/Hardware/Client-Count/Mist tabs
    expect. See the module docstring."""

    def __init__(self, hub) -> None:
        """Set up the trackers, using the hub's data directory for their files."""
        # Keep the hub so the poller can read the store and write status.
        self.hub = hub
        # Directory where tracker state files live (current dir if the hub has none).
        ddir = getattr(getattr(hub, "state", None), "data_dir", ".") or "."
        # Rolling client-count averages and baselines per site.
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
        """Shortcut to the hub's simulations store (tenant config and modes)."""
        return self.hub.simulations_store

    async def _centralized_tenants(self) -> list:
        """(tenant_id, mist_config) for every tenant in centralized mist_api mode
        with a non-empty mist_config. Skips tenants with no creds."""
        # Collected (tenant_id, mist_config) pairs.
        out = []
        # Check every tenant the store knows about.
        for tid in self._store.tenant_ids():
            try:
                modes = await self._store.get_processing_modes(tid)
                # Mist API defaults to CENTRALIZED — only explicit 'distributed'
                # (a spoke owns the creds) opts out. So a hub with a Mist config
                # and no spoke still gets polled and its checks show.
                if not self._store.mist_api_is_centralized(modes):
                    continue
                # Only tenants that actually have Mist credentials can be polled.
                mc = await self._store.get_mist_config(tid)
                if mc:
                    out.append((tid, mc))
            # A broken tenant config is skipped so the others still poll.
            except Exception:  # noqa: BLE001 — one bad tenant never blocks the rest
                continue
        return out

    @staticmethod
    def _interval_for(mist_config: Dict[str, Any]) -> int:
        """This tenant's Mist poll interval in seconds — ``poll_interval_s`` from
        its mist_config (Setup → Mist API → Connection), defaulting to 5 min and
        clamped to the floor so a misconfig can't hammer the Mist API."""
        # Read the configured interval, defaulting to 5 minutes.
        try:
            iv = int((mist_config or {}).get("poll_interval_s") or _POLL_INTERVAL_S)
        # A non-numeric value falls back to the default.
        except (TypeError, ValueError):
            iv = _POLL_INTERVAL_S
        # Never poll faster than the floor.
        return max(_POLL_INTERVAL_FLOOR_S, iv)

    async def _poll_tenant(self, tenant_id: str, mist_config: Dict[str, Any]) -> None:
        """Poll Mist once for one tenant and store the resulting dashboard status on the hub."""
        # Build a Mist API client from this tenant's credentials.
        client = MistClient(mist_config)
        # Credentials incomplete: clear any old status and tracker state for this tenant.
        if not client.is_configured():
            self.hub.mist_hub_status.pop(tenant_id, None)
            self._cc.forget(tenant_id)
            self._cpw.forget(tenant_id)
            return
        # Client-count warning/error thresholds from the tenant's config.
        cc_thresh = _cc_thresholds(mist_config)
        # Site mappings plus the checks the tenant wants monitored.
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
        # Hardware check ids, and a lookup of each hardware check by id for naming.
        hw_check_ids = {str(h.get("id")) for h in hw_checks if h.get("id")}
        hw_names = {str(h.get("id")): h for h in hw_checks if h.get("id")}

        # Accumulators for the per-site results built below.
        status: Dict[str, Any] = {}
        client_count_status: Dict[str, Any] = {}
        mist_clients_by_site: Dict[str, int] = {}
        hw_totals: Dict[str, int] = {}

        # Poll each mapped site (WebUI site name -> Mist site).
        for wireless_site, mist_site in site_mappings.items():
            try:
                # Fetch alerts, insights, client counts and hardware data for the site.
                data = await client.poll_site_data(mist_site, hw_check_ids)
            # A site that fails to poll gets a single poll_error check and is skipped.
            except Exception as exc:  # noqa: BLE001
                status[wireless_site] = {"poll_error": {"status": "error", "message": str(exc)}}
                continue
            # Raw alert-type and insight-category counts reported for the site.
            alert_counts = data.get("alert_type_counts") or {}
            insight_counts = data.get("insight_cat_counts") or {}
            # Match case-insensitively AND across BOTH the alert and insight
            # buckets (same rationale as the Central poller; shared match logic
            # lives in check_eval). Typed bucket wins; fall back to the other.
            alert_ci, insight_ci = normalize_counts(alert_counts), normalize_counts(insight_counts)
            # Debug trace of which checks are monitored and which names Mist returned.
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
                # Build catalog entries for every alert and insight name seen at this site.
                _cat_items = (
                    [{"type": "alert", "id": k, "name": k, "site": mist_site,
                      "source": "mist"}
                     for k in (alert_counts or {})]
                    + [{"type": "insight", "id": k, "name": k, "site": mist_site,
                        "source": "mist"}
                       for k in (insight_counts or {})]
                )
                # Write them only when there is something to record.
                if _cat_items:
                    await self._store.record_alert_insight_seen(_cat_items)
            # Cataloguing is optional; any failure is ignored.
            except Exception:  # noqa: BLE001 — cataloguing must never break the poll
                pass
            # Evaluate each monitored check for this site.
            checks: Dict[str, Any] = {}
            for chk in monitored:
                # Skip checks without an id.
                cid = str(chk.get("id") or "")
                if not cid:
                    continue
                # Per-site monitoring: a check pinned to a site evaluates ONLY on
                # that site (mist_site); an empty/absent site = global (every
                # mapped site). Lets you monitor an alert/insight at one site.
                chk_site = str(chk.get("site") or "").strip().lower()
                if chk_site and chk_site not in (str(mist_site).lower(), str(wireless_site).lower(), "all sites"):
                    continue
                # How many matching alerts/insights are active for this check.
                n = count_for_check(chk, alert_ci, insight_ci)
                # INVERTED semantics: this is a demo/simulation platform that is
                # SUPPOSED to be generating these alerts/insights. A monitored check
                # is HEALTHY (ok) when its error IS present, and FAILING (error) when
                # the expected error is NOT detected — the sim stopped producing it.
                # Monitor-for-absence: notify when the expected error goes missing.
                # The expected condition is present, so the simulation is working.
                if n > 0:
                    checks[cid] = {"status": "ok", "message": f"{n} active (as expected)"}
                else:
                    # Surface WHY the expected error is absent (mirrors central twin):
                    # site returned NOTHING → site dropped / name mismatch; vs the
                    # site reporting other conditions → sim not firing THIS alert.
                    # Count of all other conditions and the site's client count, for the message.
                    _seen = len(alert_ci) + len(insight_ci)
                    _cc = int(data.get("client_count", 0) or 0)
                    # Nothing at all came back from the site.
                    if _seen == 0:
                        _msg = (f"Expected error NOT detected — site returned no "
                                f"alerts/insights ({_cc} clients; site dropped or "
                                f"name mismatch?)")
                    # The site reported other things, just not this alert.
                    else:
                        _msg = (f"Expected error NOT detected — sim not firing "
                                f"(0 seen; {_seen} other condition(s) at site, "
                                f"{_cc} clients)")
                    # Mark the check as failing with the explanatory message.
                    checks[cid] = {"status": "error", "message": _msg}
            # Store this site's check results.
            status[wireless_site] = checks
            # Current total, wired and wireless client counts for the site.
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
            # Copy the thresholds and add this site's floor.
            cc_thresh = dict(cc_thresh or {})
            cc_thresh["floor"] = _cc_site_floor(sites_cfg, wireless_site, mist_site)
            # Evaluate total, wired and wireless client counts against their baselines.
            cc_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh)
            w_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh, kind="wired")
            wl_entry = self._cc.entry(tenant_id, wireless_site, mist_site, cc_thresh, kind="wireless")
            # Attach the wired/wireless details to the total entry for display.
            cc_entry["wired"] = wired
            cc_entry["wireless"] = wireless
            cc_entry["wired_status"] = w_entry["status"]
            cc_entry["wired_drop_pct"] = w_entry["drop_pct"]
            cc_entry["wireless_status"] = wl_entry["status"]
            cc_entry["wireless_drop_pct"] = wl_entry["drop_pct"]
            # Overall = worst of total/wired/wireless.
            cc_entry["status"] = _cc_worst(cc_entry["status"], w_entry["status"], wl_entry["status"])
            # Save the combined client-count entry for this site.
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
            # Look up the site's minimum client floor under either site name.
            min_floor = site_min_clients.get(wireless_site) or site_min_clients.get(mist_site)
            # Build the minimum-client check (None when no floor is set).
            _mc = min_client_check(current, min_floor)
            if _mc:
                checks["Minimum Client Threshold"] = _mc
            # Remember the current client count per site.
            mist_clients_by_site[wireless_site] = current
            # Add this site's hardware alert device counts to the tenant totals.
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
            # Load the org inventory; failures leave it empty so no device is marked down.
            try:
                all_devices = await client._list_inventory()
            except Exception:  # noqa: BLE001
                all_devices = []
            # Index devices by serial, name, id and MAC so a check id can match any of them.
            dev_by_key: Dict[str, dict] = {}
            for d in all_devices:
                for k in (d.get("serial"), d.get("name"), d.get("id"), d.get("mac")):
                    if k:
                        dev_by_key[str(k)] = d
            # Evaluate each hardware check that names a real device.
            for hc in hw_checks:
                # Skip checks without an id.
                hid = str(hc.get("id") or "")
                if not hid:
                    continue
                dev = dev_by_key.get(hid)
                if dev is None:
                    # id is a type/alias, not a real device → covered elsewhere.
                    continue
                # Site the check is pinned to (empty = every site).
                hsite = str(hc.get("site") or "").strip().lower()
                # The device is up if Mist says it is connected or reports an up-like status.
                up = bool(dev.get("connected")) or str(dev.get("status") or "").upper() in ("UP", "ONLINE", "CONNECTED")
                # Display name for the check row.
                label = str(hc.get("name") or hid)
                # Add the up/down check to every site it applies to.
                for wsite, csite in site_mappings.items():
                    if hsite and hsite not in (str(csite).lower(), str(wsite).lower(), "all sites"):
                        continue
                    status.setdefault(wsite, {})[label] = {
                        "status": "ok" if up else "error",
                        "message": "up" if up else "DOWN",
                    }

        # Summarise hardware alert totals with their display names and device types.
        hardware_alerts = [
            {"id": aid, "name": (hw_names.get(aid) or {}).get("name", aid),
             "device_type": (hw_names.get(aid) or {}).get("device_type", ""),
             "total": total}
            for aid, total in hw_totals.items()
        ]
        # Publish the tenant's status in the same shape a spoke would relay.
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
        # Walk every site/check result produced this cycle.
        for wsite, checks_map in status.items():
            # Skip error placeholders that are not check maps.
            if not isinstance(checks_map, dict):
                continue
            # Record each check's status for the 30-day history.
            for cid, info in checks_map.items():
                # Accept both dict entries and bare status strings.
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
                # Classify this poll as pass/fail; skip unknown states and non-dict entries.
                is_pass = _classify_poll_status(st)
                if is_pass is None or not isinstance(info, dict):
                    continue
                # Record the poll and read back the rolling last-hour verdict.
                self._cpw.record(tenant_id, wsite, cid, is_pass)
                verdict = self._cpw.verdict(tenant_id, wsite, cid)
                # Override the status with the hourly verdict and append the pass ratio to the
                # message.
                if verdict is not None:
                    info["status"] = verdict
                    passes, total = self._cpw.counts(tenant_id, wsite, cid)
                    info["message"] = f"{info.get('message', '')} · {passes}/{total} polls OK in last 1h"

    async def _poll_once(self) -> None:
        """Run one poll cycle: poll every due tenant and persist tracker state."""
        # Tenants currently in centralized Mist mode with credentials.
        tenants = await self._centralized_tenants()
        # Drop cached status for tenants that left centralized mode / cleared creds
        # so the UI stops showing a stale synthetic hub spoke.
        # Set of tenants still active, used to drop stale ones.
        live = {tid for tid, _ in tenants}
        # Forget status and tracker state for tenants no longer active.
        for stale in [t for t in list(self.hub.mist_hub_status.keys()) if t not in live]:
            self.hub.mist_hub_status.pop(stale, None)
            self._cc.forget(stale)
            self._cpw.forget(stale)
            self._last_poll.pop(stale, None)
        # Snapshot the time once for interval gating.
        now = time.time()
        # Gate each tenant by its own configured interval; wake on the shortest.
        intervals = [self._interval_for(mc) for _, mc in tenants]
        self._next_sleep_s = min(intervals) if intervals else _POLL_INTERVAL_S
        # Poll each tenant whose own interval has elapsed.
        for tid, mc in tenants:
            # This tenant's interval.
            iv = self._interval_for(mc)
            if now - self._last_poll.get(tid, 0.0) < iv:
                continue  # not due yet
            # Stamp the poll time before polling so a failure still waits a full interval.
            self._last_poll[tid] = now
            # Poll the tenant; failures are logged and the next tenant continues.
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
        # The hub may provide a function to persist the dashboard status.
        save = getattr(self.hub, "_save_mist_hub_status", None)
        if save:
            try:
                await asyncio.to_thread(save)
            except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
                logger.debug("mist_hub_status persist skipped: %s", exc)

    async def run_loop(self) -> None:
        """Run poll cycles forever, sleeping the shortest tenant interval between them."""
        # Loop until the task is cancelled at shutdown.
        while True:
            try:
                await self._poll_once()
            # Cancellation (hub shutdown) must propagate to stop the loop.
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Mist hub poll loop error: %s", exc)
            await asyncio.sleep(max(_POLL_INTERVAL_FLOOR_S, self._next_sleep_s))