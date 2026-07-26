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
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List

from sync_loop import run_sync_loop  # sibling leaf

logger = logging.getLogger("Hub")

_TIER_NONE = "none"
_TIER_WARN = "warning"
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

    _FLEET_ALERT_CFG_KEY = "fleet_health_alert"
    _FLEET_ALERT_DEFAULT_DEBOUNCE_S = 300
    _FLEET_ALERT_LOOP_S = 60.0

    # ── config ───────────────────────────────────────────────────────────────
    def _fleet_alert_cfg(self) -> Dict[str, Any]:
        return (self.state.system_state.get("global_config", {})
                .get(self._FLEET_ALERT_CFG_KEY, {})) or {}

    def _fleet_alert_enabled(self) -> bool:
        # Default ON: the user explicitly asked the fleet-availability drop to fire
        # an alert, and the debounce keeps a healthy (~80%) fleet from tripping.
        return bool(self._fleet_alert_cfg().get("enabled", True))

    def _fleet_alert_debounce_s(self) -> int:
        try:
            v = int(self._fleet_alert_cfg().get(
                "debounce_s", self._FLEET_ALERT_DEFAULT_DEBOUNCE_S))
        except (TypeError, ValueError):
            v = self._FLEET_ALERT_DEFAULT_DEBOUNCE_S
        return max(30, v)

    @staticmethod
    def _fleet_tier_for(status: str) -> str:
        if status == "critical":
            return _TIER_ERROR
        if status == "warning":
            return _TIER_WARN
        return _TIER_NONE

    # ── active-alert store (surfaced via /status) ────────────────────────────
    def get_fleet_alerts(self) -> List[Dict[str, Any]]:
        """Active fleet alerts as a list, most-severe first — SAME shape as
        ``get_active_spoke_alerts`` so the /status header badge + the System→Sync
        list render them uniformly. ``spoke_id`` is a synthetic ``fleet:<tenant>``
        key (harmless to the per-spoke infra-status tiles, which key by real id)
        and ``name`` gives the badge a readable label."""
        order = {_TIER_ERROR: 0, _TIER_WARN: 1}
        out: List[Dict[str, Any]] = []
        for tid, a in (getattr(self, "_fleet_alerts", {}) or {}).items():
            if a.get("tier") in (_TIER_WARN, _TIER_ERROR):
                out.append({
                    "spoke_id": f"fleet:{tid}",
                    "name": f"Fleet · {tid}",
                    "tier": a.get("tier"),
                    "since_ts": a.get("since_ts"),
                    "duration_s": int(a.get("duration_s", 0) or 0),
                    "detail": a.get("detail", ""),
                })
        out.sort(key=lambda e: (order.get(e["tier"], 9), e.get("since_ts") or 0))
        return out

    # ── loop ─────────────────────────────────────────────────────────────────
    async def run_fleet_health_alert_loop(self):
        """Every ~60s, evaluate each tenant's fleet health and raise/clear a
        dashboard alert on TRANSITION only. A degraded (warning/critical) status
        must persist ≥ ``debounce_s`` before it fires (forgiving of a transient
        dip); it clears immediately on recovery. Disabled → clear + idle. Staggered
        45 s after startup so a hub restart doesn't fire before spokes report."""
        from simulations.service import SimulationsService
        service = SimulationsService(self)
        store = self.simulations_store

        def _guard() -> bool:
            if not self._fleet_alert_enabled():
                if getattr(self, "_fleet_alerts", {}):
                    self._fleet_alerts.clear()
                    self._fleet_alert_tier.clear()
                    self._fleet_bad_since.clear()
                return False
            return True

        async def _body():
            now = time.time()
            debounce = self._fleet_alert_debounce_s()
            try:
                tids = list(store.tenant_ids())
            except Exception:  # noqa: BLE001
                tids = []
            for tid in tids:
                try:
                    data = await service.get_clients_data(tid)
                except Exception as e:  # noqa: BLE001 — one tenant never sinks the loop
                    logger.debug("[fleet-alert] %s health read failed: %s", tid, e)
                    continue
                fh = (data or {}).get("fleet_health") or {}
                status = str(fh.get("status") or "no_data")
                target = self._fleet_tier_for(status)
                current = self._fleet_alert_tier.get(tid, _TIER_NONE)

                if target == _TIER_NONE:
                    # Healthy / no_data → clear the debounce clock + any alert.
                    self._fleet_bad_since.pop(tid, None)
                    if current != _TIER_NONE:
                        self._fleet_alerts.pop(tid, None)
                        self._fleet_alert_tier[tid] = _TIER_NONE
                        logger.info("[fleet-alert] %s fleet health recovered (%s%%)",
                                    tid, fh.get("pct"))
                    continue

                # Degraded — start / continue the debounce clock.
                since = self._fleet_bad_since.get(tid)
                if since is None:
                    since = now
                    self._fleet_bad_since[tid] = since
                dur = now - since
                detail = (f"{fh.get('working', 0)}/{fh.get('eligible', 0)} clients "
                          f"working ({fh.get('pct')}%) — {status}")
                if dur < debounce:
                    continue                            # degraded but not persistent yet
                # Persisted → raise (keep since_ts at the degraded onset).
                self._fleet_alerts[tid] = {"tier": target, "since_ts": since,
                                           "duration_s": dur, "detail": detail}
                if current != target:
                    # ERROR (critical) surfaces in the error-log feed / bugfixer;
                    # WARNING is dashboard/log only.
                    (logger.error if target == _TIER_ERROR else logger.warning)(
                        "[fleet-alert] %s fleet availability %s: %s (persisted %.0fs)",
                        tid, target, detail, dur)
                    self._fleet_alert_tier[tid] = target

        await run_sync_loop(
            stagger=45, guard=_guard, body=_body,
            delay=lambda: (self._FLEET_ALERT_LOOP_S
                           if self._fleet_alert_enabled() else 120),
            on_error=lambda e: logger.warning("[fleet-alert] loop cycle failed: %s", e))
