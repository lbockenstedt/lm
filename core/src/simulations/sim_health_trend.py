"""Trend-based Sim Health tracker — Fleet Health's *second* metric.

Fleet Health has two very different questions:

  1. **API check-in** (``service._fleet_health``) — "is the client alive on the
     backend?" The heartbeat rides a network independent of any sim SSID, so
     EVERY sim VM must check in; this should sit at ~100% and drives the
     never-reporting reclone. Easy and reliable to measure.

  2. **Sim health** (this module) — "is the sim actually DOING ITS JOB on the
     wire?" Much harder, and deliberately cross-referenced against Aruba Central
     rather than a local gateway ping (a failure sim never gets a gateway *by
     design*, so gateway reachability can't tell "failing correctly" from
     "broken").

Why a TREND and not a point-in-time check
-----------------------------------------
Central's per-cycle view is noisy: a client that IS generating a failure
(auth_fail, port_flap, ssidpw_fail, …) is frequently NOT flagged in Central at
any given instant. A single "is the error present right now?" read would flap
wildly and mislabel healthy failure-sims as broken.

So we accumulate observations over a rolling window (default 1 hour). For a
FAILURE sim a client counts as **working** as long as its expected error was
observed AT LEAST ONCE inside the window. Only a client that goes a FULL window
with no observed error is "not working". A client first seen less than a window
ago is given grace (too new to have had a fair hour) and counts as working.

How the caller feeds it (per the design)
-----------------------------------------
Once per cycle the caller pulls the set of devices/clients currently in each
error state from Central ONCE (bulk, into memory) and, for every client that is
currently *expected* to be failing, calls :meth:`observe` with whether that
client was a member of the error set this cycle. We NEVER query Central
per-device. The key is opaque — a client id/MAC for per-client tracking, or a
site/quota key for a per-site rollup; the caller chooses the granularity.

Per-tenant rollup: :meth:`rollup` scores the caller's current active-key set and
returns the working/total/pct/status the Fleet Health badge shows alongside the
API-check-in number.

Persistence: ``first_seen`` + ``last_fail`` per (tenant, key) are held on disk so
a hub restart doesn't reset every client's hour to zero.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

logger = logging.getLogger("SimHealthTrend")

_DEFAULT_WINDOW_S = 3600.0          # 1 hour trend window (the design's period)
_PRUNE_AFTER_S = 2 * _DEFAULT_WINDOW_S  # forget a key untouched this long
_STATE_FILE = "sim_health_trend.json"


class SimHealthTrend:
    """Rolling per-(tenant, key) trend of "was the expected error observed?"."""

    def __init__(self, data_dir: str, window_s: float = _DEFAULT_WINDOW_S) -> None:
        self.window_s = float(window_s)
        self._path = Path(data_dir) / _STATE_FILE
        # {tenant_id: {key: {"first_seen": ts, "last_fail": ts|0}}}
        self._state: Dict[str, Dict[str, Dict[str, float]]] = self._load()

    # ── persistence ─────────────────────────────────────────────────────────
    def _load(self) -> Dict[str, Dict[str, Dict[str, float]]]:
        try:
            if self._path.exists():
                d = json.loads(self._path.read_text())
                if isinstance(d, dict):
                    out: Dict[str, Dict[str, Dict[str, float]]] = {}
                    for tid, keys in d.items():
                        if not isinstance(keys, dict):
                            continue
                        out[str(tid)] = {}
                        for k, rec in keys.items():
                            if not isinstance(rec, dict):
                                continue
                            out[str(tid)][str(k)] = {
                                "first_seen": float(rec.get("first_seen") or 0),
                                "last_fail": float(rec.get("last_fail") or 0),
                            }
                    return out
        except Exception:  # noqa: BLE001 — a corrupt file must not kill the hub
            pass
        return {}

    def save(self) -> None:
        try:
            self._path.write_text(json.dumps(self._state))
        except Exception as e:  # noqa: BLE001
            logger.debug("sim-health-trend: state save failed: %s", e)

    # ── observation ─────────────────────────────────────────────────────────
    def observe(self, tenant_id: str, key: str, seen_failing: bool,
                now: Optional[float] = None) -> None:
        """Record one cycle's observation for a client currently EXPECTED to be
        failing. ``seen_failing`` = was it a member of Central's error set this
        cycle. Stamps ``first_seen`` once (starts the grace/trend clock) and
        refreshes ``last_fail`` whenever the error is observed."""
        if not tenant_id or not key:
            return
        now = time.time() if now is None else now
        rec = self._state.setdefault(str(tenant_id), {}).setdefault(
            str(key), {"first_seen": now, "last_fail": 0.0})
        if not rec.get("first_seen"):
            rec["first_seen"] = now
        if seen_failing:
            rec["last_fail"] = now

    def is_working(self, tenant_id: str, key: str,
                   now: Optional[float] = None) -> bool:
        """Working iff the error was observed within the window, OR the key is
        still inside its first-window grace (too new to judge)."""
        now = time.time() if now is None else now
        rec = self._state.get(str(tenant_id), {}).get(str(key))
        if not rec:
            return False
        if rec.get("last_fail") and (now - rec["last_fail"]) <= self.window_s:
            return True
        first = rec.get("first_seen") or 0
        return bool(first and (now - first) < self.window_s)

    # ── rollup + housekeeping ───────────────────────────────────────────────
    def rollup(self, tenant_id: str, active_keys: Iterable[str],
               now: Optional[float] = None) -> Dict[str, Any]:
        """Per-tenant Sim Health over the caller's CURRENT active fail-sim keys.

        ``active_keys`` is this cycle's set of clients expected to be failing (so
        a client that stopped running the sim, or vanished, drops out of both
        numerator and denominator). Returns the badge shape:
        ``{working, total, pct, status}`` with ``pct``/``status`` None/"no_data"
        when there's nothing to judge."""
        now = time.time() if now is None else now
        keys = list(dict.fromkeys(str(k) for k in active_keys if k))
        total = len(keys)
        working = sum(1 for k in keys if self.is_working(tenant_id, k, now))
        if total <= 0:
            return {"working": 0, "total": 0, "pct": None, "status": "no_data"}
        pct = round(100.0 * working / total, 1)
        if pct >= 90:
            status = "ok"
        elif pct >= 75:
            status = "warning"
        else:
            status = "critical"
        return {"working": working, "total": total, "pct": pct, "status": status}

    def prune(self, now: Optional[float] = None) -> None:
        """Forget keys not observed for a while (client gone) so the map can't
        grow without bound. Uses the latest of first_seen/last_fail as touch."""
        now = time.time() if now is None else now
        for tid in list(self._state.keys()):
            keys = self._state[tid]
            for k in list(keys.keys()):
                rec = keys[k]
                touched = max(rec.get("first_seen") or 0, rec.get("last_fail") or 0)
                if touched and (now - touched) > _PRUNE_AFTER_S:
                    del keys[k]
            if not keys:
                del self._state[tid]
