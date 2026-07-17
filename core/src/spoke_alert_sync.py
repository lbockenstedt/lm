"""Spoke out-of-contact alerting for the Hub.

A self-contained subsystem gathered here as a **mixin** (same pattern as
``staleness_sweep.py``) so the Hub class body shrinks with zero call-site change.
``api.py`` reads ``hub.get_active_spoke_alerts()`` and the loop is launched from
``main.py start()`` — both resolve via inheritance once ``SpokeAlertMixin`` is added
to ``LabManagerHub`` bases.

The hub already has a realtime liveness traffic-light (``HeartbeatManager``:
GREEN <120 s, YELLOW 120–300 s, RED ≥300 s) and a recovery watchdog that acts on
RED@300 s. That traffic-light flips YELLOW/RED on a momentary blip (spoke restart,
WAN jitter, a 300 ms-latency leg), which reads as an "alert" far too eagerly on a
distributed deployment. The user wants the **system to stay realtime** (the
traffic-light keeps updating immediately) but **alerts to be forgiving**: warn only
after a spoke has been **out of contact ≥5 min** (warning) and escalate to **error
after ≥30 min**.

This loop is deliberately **decoupled from the watchdog**: it computes the
out-of-contact duration straight from ``heartbeat.last_seen`` against independent
``warn_s`` / ``error_s`` thresholds and NEVER consults ``HeartbeatManager.get_status``
— so the watchdog's load-bearing 300 s RED boundary
(``main.py run_spoke_recovery_loop`` + ``heartbeat.py`` tripwire) stays untouched.

Alerts surface three ways (no new polling): folded into ``/status``
(``active_alert_count`` → header badge) and ``/setup/diagnostics``
(``alert_tier``/``alert_since`` per spoke → diagnostics badge), plus a dedicated
``GET /setup/spoke-alerts`` route (→ the System → Sync active-alerts list). The
ERROR tier is emitted at ``logger.error`` so it matches the ``collect_error_logs``
regex and lands in GET_ERROR_LOGS / the Error Log tab / bugfixer; the WARNING tier
is ``logger.warning`` (hub log + UI only — deliberately NOT in the error-log feed,
to avoid noise).

This module is a **leaf**: it imports only stdlib and must NOT import ``main`` or
``api`` (no back-import — that would cycle, since ``main`` imports this module to
pull in the mixin). Dependency direction is ``main → spoke_alert_sync`` only.

Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("Hub")

# Tier names used in the store + API + WebUI.
_TIER_NONE = "none"
_TIER_WARN = "warning"
_TIER_ERROR = "error"


class SpokeAlertMixin:
    """Forgiving out-of-contact alerting, decoupled from the recovery watchdog.

    Config (``global_config["spoke_alert"]``): ``enabled`` (bool, default False),
    ``warn_s`` (default 300 = 5 min), ``error_s`` (default 1800 = 30 min). Read
    fresh each cycle so a WebUI change takes effect without a restart.

    State (transient, in-memory on the hub — never persisted/committed; re-derives
    within one cycle after a hub restart):
      - ``_spoke_alerts``      : {spoke_id: {tier, since_ts, duration_s, detail}}
        — the active-alert store surfaced via the API.
      - ``_spoke_alert_tier``  : {spoke_id: "none"|"warning"|"error"} — last emitted
        tier, so we emit only on TRANSITION (no log spam every 30 s cycle).
      - ``_spoke_absent_since``: {spoke_id: epoch} — for an approved spoke that has
        never sent a heartbeat, the moment the loop first noticed it absent. Gives a
        defensible "out of contact since" clock so a never-seen spoke still alerts at
        5/30 min (per user) instead of silently never clocking.
    """

    _SPOKE_ALERT_CFG_KEY = "spoke_alert"
    _SPOKE_ALERT_DEFAULT_WARN_S = 300
    _SPOKE_ALERT_DEFAULT_ERROR_S = 1800
    _SPOKE_ALERT_MIN_WARN_S = 60
    _SPOKE_ALERT_LOOP_S = 30.0

    # ── config helpers ──────────────────────────────────────────────────────

    def _spoke_alert_cfg(self) -> Dict[str, Any]:
        """Read the alert config fresh (enabled/warn_s/error_s)."""
        return (self.state.system_state.get("global_config", {})
                .get(self._SPOKE_ALERT_CFG_KEY, {})) or {}

    def _spoke_alert_thresholds(self) -> Tuple[int, int]:
        """Return ``(warn_s, error_s)`` clamped to sane bounds.

        ``warn_s`` ≥ 60 (can't hot-loop / can't be usefully below the loop cadence).
        ``error_s`` > ``warn_s`` (error must be a stricter threshold than warning);
        if a bad config flips that, error_s is bumped to warn_s + 60. Defaults
        300 / 1800.
        """
        cfg = self._spoke_alert_cfg()

        def _pos(key: str, default: int) -> int:
            try:
                v = int(cfg.get(key, default))
            except (TypeError, ValueError):
                v = default
            return max(1, v)

        warn_s = max(self._SPOKE_ALERT_MIN_WARN_S, _pos("warn_s", self._SPOKE_ALERT_DEFAULT_WARN_S))
        error_s = _pos("error_s", self._SPOKE_ALERT_DEFAULT_ERROR_S)
        if error_s <= warn_s:
            error_s = warn_s + 60
        return warn_s, error_s

    @staticmethod
    def _spoke_alert_tier_for(duration: float, warn_s: int, error_s: int) -> str:
        """Map a continuous out-of-contact duration to a tier."""
        if duration >= error_s:
            return _TIER_ERROR
        if duration >= warn_s:
            return _TIER_WARN
        return _TIER_NONE

    # ── active-alert store (surfaced via the API) ───────────────────────────

    def get_active_spoke_alerts(self) -> List[Dict[str, Any]]:
        """Active alerts (tier != none) as a list, most-severe first (error before
        warning), then by ``since_ts`` ascending. Each entry is
        ``{spoke_id, tier, since_ts, duration_s, detail}``."""
        order = {_TIER_ERROR: 0, _TIER_WARN: 1}
        out: List[Dict[str, Any]] = []
        for sid, a in (getattr(self, "_spoke_alerts", {}) or {}).items():
            if a.get("tier") in (_TIER_WARN, _TIER_ERROR):
                out.append({
                    "spoke_id": sid,
                    "tier": a.get("tier"),
                    "since_ts": a.get("since_ts"),
                    "duration_s": int(a.get("duration_s", 0) or 0),
                    "detail": a.get("detail", ""),
                })
        out.sort(key=lambda e: (order.get(e["tier"], 9), e.get("since_ts") or 0))
        return out

    # ── per-spoke evaluation ────────────────────────────────────────────────

    def _spoke_alert_duration(self, sid: str, now: float
                              ) -> Tuple[float, Optional[float]]:
        """Continuous out-of-contact duration for ``sid`` and the ``since_ts`` to
        report (the out-of-contact start), or ``(0.0, None)`` when the spoke is in
        contact.

        - ``last_seen`` present → duration = now - last_seen (covers the common
          "was up, went down" case: last_seen stays set after disconnect).
        - ``last_seen`` None but the spoke is currently connected → 0.0 (connected,
          heartbeat imminent; forgiving on a fresh hub start where last_seen is
          empty until the first frame).
        - ``last_seen`` None and not connected (approved but never seen, or wiped on
          hub restart) → the ``_spoke_absent_since`` clock, seeded on first
          observation so a never-seen spoke still accrues toward the thresholds.
        """
        last = self.heartbeat.last_seen.get(sid)
        if last is not None:
            return max(0.0, now - last), last
        if sid in getattr(self, "active_connections", {}):
            return 0.0, None
        absent_since = self._spoke_absent_since.get(sid)
        if absent_since is None:
            absent_since = now
            self._spoke_absent_since[sid] = absent_since
        return max(0.0, now - absent_since), absent_since

    def _spoke_alert_set(self, sid: str, tier: str, since_ts: Optional[float],
                         duration: float, detail: str) -> None:
        self._spoke_alerts[sid] = {
            "tier": tier,
            "since_ts": since_ts,
            "duration_s": duration,
            "detail": detail,
        }

    def _spoke_alert_clear(self, sid: str) -> None:
        self._spoke_alerts.pop(sid, None)

    def _schedule_alert_email(self, sid: str, tier: str, detail: str,
                              since_ts: Optional[float], duration: float) -> None:
        """Fire-and-forget an email on a tier TRANSITION (not every cycle).
        ``notifications`` is a leaf module like this one; the import is lazy so
        a notifications-module failure can never break the alert loop, and the
        dispatch is wrapped so a send error never escapes into the loop."""
        try:
            import notifications as _n  # leaf; lazy import keeps the loop robust
            subject = f"[LM Hub] Spoke {sid} out of contact ({tier})"
            body = (f"Spoke: {sid}\nTier: {tier}\n"
                    f"Out-of-contact: {int(duration)}s\n"
                    f"Since: {since_ts}\nDetail: {detail}\n"
                    f"Hub time: {time.time()}")
            # ensure_future → non-blocking; a slow SMTP/API send never stalls
            # the 30s loop. send_email itself swallows errors (logs at error).
            # spoke_id=sid so send_email resolves THIS spoke's tenant and uses
            # that tenant's recipients (cs tenant Notifications card) instead
            # of the hub's global list.
            asyncio.ensure_future(_n.send_email(self, subject, body, spoke_id=sid))
        except Exception as e:  # noqa: BLE001
            logger.warning("[spoke-alert] email dispatch failed: %s", e)

    # ── loop ────────────────────────────────────────────────────────────────

    async def run_spoke_alert_loop(self):
        """Every ~30 s, evaluate each approved spoke's out-of-contact duration
        against the configured warn/error thresholds and emit alerts **on
        transition only** (so a spoke that sits at warning for an hour logs once,
        not 120×). Decoupled from the recovery watchdog — never calls
        ``get_status()``. Disabled → short sleep + re-check. Staggered ~30 s after
        startup so a hub restart doesn't fire a burst before spokes reconnect.
        """
        await asyncio.sleep(30)  # let spokes connect before first evaluation
        while True:
            try:
                cfg = self._spoke_alert_cfg()
                if not cfg.get("enabled", False):
                    # Still clear any stale active alerts so the UI doesn't show
                    # alerts while the feature is off.
                    if getattr(self, "_spoke_alerts", {}):
                        self._spoke_alerts.clear()
                        self._spoke_alert_tier.clear()
                    await asyncio.sleep(60)
                    continue

                warn_s, error_s = self._spoke_alert_thresholds()
                now = time.time()
                approved = {s for s, a in self.approved_modules.items() if a}

                # Relayed node-agents (pxmx proxmox agents) are tracked under
                # COMPOSITE heartbeat keys ("{parent_spoke}:{agent_id}") and in
                # ``agent_info``, and are surfaced via /api/pxmx/agents — NOT as
                # spokes. They leak into approved_modules (a known issue; the
                # /setup/diagnostics route self-heals them out, but only when
                # that page is opened). Evaluating them here reads
                # ``heartbeat.last_seen[bare_id]`` → None (the real key is the
                # composite) → not in active_connections (that's for spokes) →
                # clocks absent_since → escalates to "error" out-of-contact for
                # agents that are actually connected and fresh (the AGENTS view
                # reads the composite key and shows them online — the exact
                # "module out of contact but agent online" false positive).
                # Skip them here, clear any stale alert already recorded, and
                # self-heal them out of approved_modules (mirrors
                # setup_admin.py:349-367 so the cleanup does not depend on the
                # Diagnostics page being open).
                relay_ids = {k.split(":", 1)[1] for k in self.heartbeat.last_seen
                             if ":" in k}
                relay_ids |= set((self.state.system_state.get("agent_config", {})
                                  or {}).keys())
                relay_ids |= set(getattr(self, "agent_info", {}).keys())
                leaked = sorted(s for s in approved if s in relay_ids)
                if leaked:
                    for sid in leaked:
                        self.approved_modules.pop(sid, None)
                        self._spoke_alert_clear(sid)
                        self._spoke_absent_since.pop(sid, None)
                    # Persisted self-heal: drop from known_modules too so a hub
                    # restart doesn't re-leak them. Change-gated → no per-cycle
                    # write once clean.
                    known = list(self.state.system_state.get("known_modules", [])
                                 or [])
                    cleaned = [m for m in known if m not in relay_ids]
                    if cleaned != known:
                        self.state.system_state["known_modules"] = cleaned
                        self.known_modules = cleaned
                        try:
                            self.state._mark_dirty()
                        except Exception as e:
                            logger.debug("[spoke-alert] self-heal save failed: %s", e)
                    logger.info("[spoke-alert] skipped relayed agent id(s) "
                                "leaked into approved_modules: %s", leaked)
                    approved -= set(leaked)

                for sid in sorted(approved):
                    duration, since_ts = self._spoke_alert_duration(sid, now)
                    tier = self._spoke_alert_tier_for(duration, warn_s, error_s)
                    current = self._spoke_alert_tier.get(sid, _TIER_NONE)

                    if tier == current:
                        # No transition — just keep the live duration fresh for the
                        # UI ("out of contact 642 s") without re-logging.
                        if tier != _TIER_NONE:
                            self._spoke_alert_set(sid, tier, since_ts, duration,
                                                   self._spoke_alerts.get(sid, {}).get("detail", ""))
                        continue

                    # --- transition ---
                    if tier == _TIER_NONE:
                        # Back in contact (from warning or error).
                        prev = self._spoke_alerts.get(sid, {})
                        prev_dur = int(prev.get("duration_s", 0) or 0)
                        self._spoke_alert_clear(sid)
                        self._spoke_absent_since.pop(sid, None)
                        self.record_spoke_event(sid, "spoke_back_in_contact",
                                                f"reconnected after {prev_dur}s")
                        logger.info("[spoke-alert] %s back in contact (was out %ds)",
                                    sid, prev_dur)
                    elif tier == _TIER_WARN:
                        # none → warning (first alert).
                        detail = f"out of contact {int(duration)}s (warn {warn_s}s)"
                        self._spoke_alert_set(sid, _TIER_WARN, since_ts, duration, detail)
                        self.record_spoke_event(sid, "spoke_out_of_contact", detail)
                        # WARNING level: hub log + UI only (NOT the error-log feed —
                        # avoids noise; the forgiving warning is for the dashboard).
                        logger.warning("[spoke-alert] %s out of contact %ds "
                                       "(warn threshold %ds exceeded)",
                                       sid, int(duration), warn_s)
                        self._schedule_alert_email(sid, "warning", detail,
                                                   since_ts, duration)
                    else:  # tier == _TIER_ERROR (escalation from warning)
                        # Preserve the original onset since_ts (the out-of-contact
                        # start), don't reset it at escalation.
                        detail = f"escalated to error at {int(duration)}s (error {error_s}s)"
                        prev_since = self._spoke_alerts.get(sid, {}).get("since_ts", since_ts)
                        self._spoke_alert_set(sid, _TIER_ERROR, prev_since, duration, detail)
                        self.record_spoke_event(sid, "spoke_out_of_contact", detail)
                        # ERROR level: matches the collect_error_logs regex
                        # (\berror\b) → surfaces in GET_ERROR_LOGS / Error Log tab /
                        # bugfixer so a 30-min outage is actionable, not just visual.
                        logger.error("[spoke-alert] %s out of contact %ds "
                                     "(error threshold %ds exceeded)",
                                     sid, int(duration), error_s)
                        self._schedule_alert_email(sid, "error", detail,
                                                   prev_since, duration)

                    self._spoke_alert_tier[sid] = tier

                await asyncio.sleep(self._SPOKE_ALERT_LOOP_S)
            except Exception as e:
                logger.warning("[spoke-alert] loop cycle failed: %s", e)
                await asyncio.sleep(60)