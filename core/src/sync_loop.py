"""Shared skeleton for the hub's periodic background sync loops.

Eleven hub loops (vm/endpoint/fw/nw-discovery/nw-import/dns-dhcp/spoke-alert/
staleness/realtime-NAC/repo/cert-distribution) shared the same hand-rolled
while-True / startup-stagger / enable-guard / body / schedule-sleep / except
shape, and four of them additionally duplicated the "daily HH:MM vs interval,
clamp >= 60" schedule helper verbatim. ``run_sync_loop`` +
``next_schedule_delay`` are the single copies; each mixin's ``run_*_loop``
supplies its guard/body/delay closures so per-loop enable-flag and interval
semantics are unchanged.

A leaf: stdlib only. MUST NOT import ``main`` or ``api`` (dependency direction
is ``main → sync_loop`` only). Audience: Hub developers.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Union

logger = logging.getLogger("Hub")


async def run_sync_loop(*, stagger: float,
                        body: Callable[[], Awaitable[Any]],
                        delay: Callable[[], float],
                        guard: Optional[Callable[[], bool]] = None,
                        error_label: str = "sync loop failed",
                        error_delay: Union[float, Callable[[], float]] = 60.0,
                        on_error: Optional[Callable[[Exception], None]] = None,
                        ) -> None:
    """Run one periodic sync loop forever. Never returns; never raises.

    - ``stagger``: one-time startup sleep so the heavy loops don't
      simultaneous-fire when the hub boots (each loop keeps its historic
      offset).
    - ``guard``: evaluated fresh each cycle (enable flag + spokes-up). False
      skips the body but still sleeps ``delay()`` — the delay closure is
      responsible for returning the short disabled re-check interval, exactly
      like the old inline shape. May carry side effects (e.g. spoke-alert
      clears stale alerts while disabled). ``None`` → always run the body.
    - ``body``: one cycle. Per-cycle inner try/excepts stay with the body.
    - ``delay``: seconds until the next cycle, evaluated AFTER the body so a
      WebUI config change takes effect without a restart.
    - on an escaped exception: ``on_error(e)`` if given (else WARNING
      ``[sync-error] <error_label>: e``), then sleep ``error_delay`` — a float,
      or a callable evaluated defensively (falls back to 60 s if it raises).
    """
    await asyncio.sleep(stagger)
    while True:
        try:
            if guard is None or guard():
                await body()
            await asyncio.sleep(delay())
        except Exception as e:  # noqa: BLE001 — the loop must survive anything
            if on_error is not None:
                try:
                    on_error(e)
                except Exception:  # noqa: BLE001 — reporting must not kill the loop
                    logger.warning("[sync-error] %s: %s", error_label, e)
            else:
                logger.warning("[sync-error] %s: %s", error_label, e)
            d: Any = error_delay
            if callable(d):
                try:
                    d = float(d())
                except Exception:  # noqa: BLE001 — bad config must not kill the loop
                    d = 60.0
            await asyncio.sleep(d)


def next_schedule_delay(cfg: Dict[str, Any], *,
                        default_daily_time: str = "02:00",
                        default_interval: int = 3600,
                        log_name: str = "sync") -> float:
    """Seconds to sleep before the next scheduled sync, per the config mode.

    ``mode`` is ``"daily"`` (run once a day at ``daily_time`` "HH:MM", 24h
    local) or anything else (interval mode → every ``interval_seconds``).
    Always clamped to >= 60 s so a bad config can't hot-loop the hub.
    Previously duplicated verbatim across the vm/endpoint/fw/nw sync mixins
    (identical apart from the default daily time + debug-log prefix).
    """
    mode = str(cfg.get("mode", "interval")).strip().lower()
    if mode == "daily":
        hhmm = str(cfg.get("daily_time", default_daily_time)).strip()
        try:
            hh, mm = (int(p) for p in hhmm.split(":")[:2])
            now = _dt.datetime.now()
            target = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if target <= now:
                target += _dt.timedelta(days=1)
            return max(60.0, (target - now).total_seconds())
        except Exception:  # noqa: BLE001 — bad HH:MM falls back to interval mode
            logger.debug("%s: bad daily_time %r — falling back to interval",
                         log_name, hhmm)
    interval = default_interval
    try:
        interval = int(cfg.get("interval_seconds", default_interval))
    except (TypeError, ValueError):
        interval = default_interval
    return max(60.0, float(interval))
