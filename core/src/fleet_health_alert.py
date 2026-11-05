"""Fleet-availability alerting for the Hub — a dashboard operational alert when a
tenant's client-simulation fleet health drops (too few clients actually working).

Companion to ``SpokeAlertMixin`` (spoke out-of-contact). Where that watches a
single spoke's contact, this watches the AGGREGATE:
``SimulationsService._fleet_health`` per tenant = working clients / eligible
(registered − exclusive), status ok ≥75 / warning 50–74 / critical <50. The user
wants a blinking badge AND a real alert when the fleet runs degraded (e.g. only
40 of 100 clients simulating), so this raises an operator-facing alert that rides
the SAME ``/status`` active-alerts channel the spoke alerts use (header badge — no
new polling).

Forgiving like the spoke alerts: a transient dip (a clone batch rebooting, a sim
rotation, the ~20% USB-dongle churn floor) must not fire, so a warning/critical
status must PERSIST ≥ ``debounce_s`` (default 5 min) before the alert is raised;
it clears the moment health recovers.

Leaf module: stdlib + SimulationsService only; must NOT import ``main``/``api``
(that would cycle — ``main`` imports this to pull in the mixin).
"""
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# Standard-library logging for alert raise/clear messages.
import logging
# time.time() provides the epoch timestamps used by the debounce clock.
import time
# Type hints only.
from typing import Any, Dict, List

# Shared helper that runs a periodic loop with stagger, guard and error handling.
from sync_loop import run_sync_loop  # sibling leaf

# Use the hub's main logger so fleet alerts appear alongside other hub messages.
logger = logging.getLogger("Hub")

# Alert tiers: "none" means healthy / no alert.
_TIER_NONE = "none"
# "warning" tier: fleet is degraded (50-74% working).
_TIER_WARN = "warning"
# "error" tier: fleet is critical (<50% working).
_TIER_ERROR = "error"


class FleetHealthAlertMixin:
    """Per-tenant fleet-availability alerting → the dashboard ``/status`` channel.

    Config (``global_config["fleet_health_alert"]``): ``enabled`` (bool, default
    True), ``debounce_s`` (default 300 — how long a degraded status must persist
    before firing; read fresh each cycle). State (transient, in-memory on the hub,
    never persisted — re-derives within one cycle after a restart):
      - ``_fleet_alerts``     : {tenant_id: {tier, since_ts, duration_s, detail}}
        — the active-alert store, surfaced via ``get_fleet_alerts`` into /status.
      - ``_fleet_alert_tier`` : {tenant_id: last emitted tier} — transition-only log.
      - ``_fleet_bad_since``  : {tenant_id: epoch the degraded status began} — the
        debounce clock.
    """

    # global_config key holding this feature's settings.
    _FLEET_ALERT_CFG_KEY = "fleet_health_alert"
    # Default debounce: a degraded status must last 5 minutes before alerting.
    _FLEET_ALERT_DEFAULT_DEBOUNCE_S = 300
    # How often (seconds) the loop re-evaluates fleet health while enabled.
    _FLEET_ALERT_LOOP_S = 60.0

    # ── config ───────────────────────────────────────────────────────────────
    def _fleet_alert_cfg(self) -> Dict[str, Any]:
        """Return this feature's settings from global_config (empty dict if unset)."""
        # Read global_config[fleet_health_alert]; "or {}" guards against a stored None.
        return (self.state.system_state.get("global_config", {})
                .get(self._FLEET_ALERT_CFG_KEY, {})) or {}

    def _fleet_alert_enabled(self) -> bool:
        # Default ON: the user explicitly asked the fleet-availability drop to fire
        # an alert, and the debounce keeps a healthy (~80%) fleet from tripping.
        """Return whether fleet-availability alerting is switched on (default True)."""
        return bool(self._fleet_alert_cfg().get("enabled", True))

    def _fleet_alert_debounce_s(self) -> int:
        """Return the configured debounce in seconds, never less than 30."""
        # Read the configured value; fall back to the default if it is not a number.
        try:
            v = int(self._fleet_alert_cfg().get(
                "debounce_s", self._FLEET_ALERT_DEFAULT_DEBOUNCE_S))
        # Bad config value (e.g. a string); use the default instead of crashing.
        except (TypeError, ValueError):
            v = self._FLEET_ALERT_DEFAULT_DEBOUNCE_S
        # Enforce a 30 s floor so a tiny value cannot make alerts flap.
        return max(30, v)

    @staticmethod
    def _fleet_tier_for(status: str) -> str:
        """Map a fleet-health status string to an alert tier."""
        # Critical health raises an error-tier alert.
        if status == "critical":
            return _TIER_ERROR
        # Warning health raises a warning-tier alert.
        if status == "warning":
            return _TIER_WARN
        # Anything else (ok / no_data) means no alert.
        return _TIER_NONE

    # ── active-alert store (surfaced via /status) ────────────────────────────
    def get_fleet_alerts(self) -> List[Dict[str, Any]]:
        """Active fleet alerts as a list, most-severe first — SAME shape as
        ``get_active_spoke_alerts`` so the /status header badge + the System→Sync
        list render them uniformly. ``spoke_id`` is a synthetic ``fleet:<tenant>``
        key (harmless to the per-spoke infra-status tiles, which key by real id)
        and ``name`` gives the badge a readable label."""
        # Sort key: errors before warnings.
        order = {_TIER_ERROR: 0, _TIER_WARN: 1}
        # Collected alerts in the /status shape.
        out: List[Dict[str, Any]] = []
        # Walk the active-alert store (may not exist yet before the loop starts).
        for tid, a in (getattr(self, "_fleet_alerts", {}) or {}).items():
            # Only report entries that are actually in an alerting tier.
            if a.get("tier") in (_TIER_WARN, _TIER_ERROR):
                out.append({
                    "spoke_id": f"fleet:{tid}",
                    "name": f"Fleet · {tid}",
                    "tier": a.get("tier"),
                    "since_ts": a.get("since_ts"),
                    "duration_s": int(a.get("duration_s", 0) or 0),
                    "detail": a.get("detail", ""),
                })
        # Most severe first, then oldest first within a tier.
        out.sort(key=lambda e: (order.get(e["tier"], 9), e.get("since_ts") or 0))
        return out

    async def _eval_fleet_health(self, service, tid: str, now: float,
                                 debounce: int) -> None:
        """Raise/clear a fleet-availability alert for one tenant. Degraded status
        must persist >= debounce; transition-only log; clears on recovery."""
        # Fetch this tenant's client data, which includes the computed fleet_health.
        try:
            data = await service.get_clients_data(tid)
        # A failing tenant is skipped quietly so it cannot stop the other tenants' checks.
        except Exception as e:  # noqa: BLE001 — one tenant never sinks the loop
            logger.debug("[fleet-alert] %s health read failed: %s", tid, e)
            return
        # Pull the fleet_health block out of the reply (empty if missing).
        fh = (data or {}).get("fleet_health") or {}
        # The status label, e.g. ok / warning / critical / no_data.
        status = str(fh.get("status") or "no_data")
        # Which alert tier this status calls for.
        target = self._fleet_tier_for(status)
        # Which tier we last emitted for this tenant.
        current = self._fleet_alert_tier.get(tid, _TIER_NONE)
        # Healthy: reset the debounce clock.
        if target == _TIER_NONE:
            self._fleet_bad_since.pop(tid, None)
            # Was alerting before: clear the alert and log the recovery once.
            if current != _TIER_NONE:
                self._fleet_alerts.pop(tid, None)
                self._fleet_alert_tier[tid] = _TIER_NONE
                logger.info("[fleet-alert] %s fleet health recovered (%s%%)",
                            tid, fh.get("pct"))
            return
        # When did the degraded status start? Start the clock now if this is the first bad cycle.
        since = self._fleet_bad_since.get(tid)
        if since is None:
            since = now
            self._fleet_bad_since[tid] = since
        # How long the fleet has been degraded so far.
        dur = now - since
        # Human-readable summary shown in the dashboard badge.
        detail = (f"{fh.get('working', 0)}/{fh.get('eligible', 0)} clients "
                  f"working ({fh.get('pct')}%) — {status}")
        if dur < debounce:
            return                                      # degraded but not persistent yet
        # Record or refresh the active alert (duration keeps growing while it persists).
        self._fleet_alerts[tid] = {"tier": target, "since_ts": since,
                                   "duration_s": dur, "detail": detail}
        # Only log when the tier changes, so a lasting alert does not spam the log.
        if current != target:
            # ERROR (critical) surfaces in the error-log feed / ab; WARNING
            # is dashboard/log only.
            (logger.error if target == _TIER_ERROR else logger.warning)(
                "[fleet-alert] %s fleet availability %s: %s (persisted %.0fs)",
                tid, target, detail, dur)
            # Remember the tier we just emitted.
            self._fleet_alert_tier[tid] = target

    # ── loop ─────────────────────────────────────────────────────────────────
    async def run_fleet_health_alert_loop(self):
        """Every ~60s, evaluate each tenant's fleet health and raise/clear a
        dashboard alert on TRANSITION only. A degraded (warning/critical) status
        must persist ≥ ``debounce_s`` before it fires (forgiving of a transient
        dip); it clears immediately on recovery. Disabled → clear + idle. Staggered
        45 s after startup so a hub restart doesn't fire before spokes report."""
        # Imported lazily to avoid an import cycle at module load time.
        from simulations.service import SimulationsService
        # Service that computes each tenant's client/fleet data.
        service = SimulationsService(self)
        # Store that knows which tenants exist.
        store = self.simulations_store

        def _guard() -> bool:
            """Return whether the loop should run this cycle, clearing alerts when disabled."""
            # Read the current on/off setting each cycle so changes apply without a restart.
            fleet_on = self._fleet_alert_enabled()
            # Clear the store the moment the feature is disabled so the UI drops
            # its alerts.
            if not fleet_on and getattr(self, "_fleet_alerts", {}):
                self._fleet_alerts.clear()
                self._fleet_alert_tier.clear()
                self._fleet_bad_since.clear()
            return fleet_on

        async def _body():
            """One loop cycle: evaluate fleet health for every tenant."""
            # Common timestamp and debounce value for the whole cycle.
            now = time.time()
            debounce = self._fleet_alert_debounce_s()
            fleet_on = self._fleet_alert_enabled()
            # List the tenants; a failure here just means nothing to check this cycle.
            try:
                tids = list(store.tenant_ids())
            except Exception:  # noqa: BLE001
                tids = []
            # Evaluate each tenant while the feature is on.
            for tid in tids:
                if fleet_on:
                    await self._eval_fleet_health(service, tid, now, debounce)

        # Run the loop: start 45 s after boot, every 60 s when enabled, 120 s when idle.
        await run_sync_loop(
            stagger=45, guard=_guard, body=_body,
            delay=lambda: (self._FLEET_ALERT_LOOP_S
                           if self._fleet_alert_enabled() else 120),
            on_error=lambda e: logger.warning("[fleet-alert] loop cycle failed: %s", e))
