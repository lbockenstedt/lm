"""90-day uptime history for the status page.

Each STATUS_SNAPSHOT the hub pushes carries the current per-component status.
We fold those into per-component, per-DAY buckets (each day keeps the WORST
status seen that day — the cloud-provider convention), keep 90 days, and persist
to a small JSON file so the history survives a restart.

Status vocabulary matches the hub's buckets, normalized to three tones:
  operational  (ok/pass/up/healthy)
  degraded     (warning/degraded/unknown/no_data/pending)
  down         (error/fail/down/critical)
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger("StatusPageSpoke")

_RANK = {"operational": 0, "degraded": 1, "down": 2}
_DAY = 86400
_KEEP_DAYS = 90


def _day_key(ts: float) -> str:
    """UTC day bucket 'YYYY-MM-DD' from an epoch timestamp (no Date.now use —
    time.gmtime is deterministic given ts)."""
    tm = time.gmtime(ts)
    return "%04d-%02d-%02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday)


class UptimeHistory:
    def __init__(self, path: Path):
        self.path = Path(path)
        # {component_name: {day_key: "operational"|"degraded"|"down"}}
        self._data: Dict[str, Dict[str, str]] = {}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                self._data = json.loads(self.path.read_text()) or {}
        except Exception as e:  # noqa: BLE001
            logger.debug("uptime history load failed: %s", e)
            self._data = {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data))
            tmp.replace(self.path)
        except Exception as e:  # noqa: BLE001
            logger.debug("uptime history save failed: %s", e)

    def record(self, components: List[Dict[str, Any]], now: float = None) -> None:
        """Fold a snapshot's component statuses into today's bucket, keeping the
        worst status per component per day. Prunes buckets older than 90 days."""
        now = now if now is not None else time.time()
        day = _day_key(now)
        cutoff = _day_key(now - _KEEP_DAYS * _DAY)
        for comp in components or []:
            name = str(comp.get("name") or "").strip()
            if not name:
                continue
            tone = str(comp.get("status") or "degraded").lower()
            if tone not in _RANK:
                tone = "degraded"
            buckets = self._data.setdefault(name, {})
            prev = buckets.get(day)
            # Worst-of-day: only overwrite if the new tone is worse (higher rank).
            if prev is None or _RANK[tone] > _RANK.get(prev, 0):
                buckets[day] = tone
            # Prune old days for this component.
            for d in [d for d in buckets if d < cutoff]:
                buckets.pop(d, None)
        self._save()

    def bars(self, now: float = None) -> Dict[str, Any]:
        """Return, per component, an ordered list of the last 90 daily statuses
        (oldest→newest) plus an uptime % (share of days operational). Days with
        no sample are 'nodata'."""
        now = now if now is not None else time.time()
        days = [_day_key(now - (_KEEP_DAYS - 1 - i) * _DAY) for i in range(_KEEP_DAYS)]
        out: Dict[str, Any] = {}
        for name, buckets in self._data.items():
            series = [buckets.get(d, "nodata") for d in days]
            observed = [s for s in series if s != "nodata"]
            up = sum(1 for s in observed if s == "operational")
            pct = round(100.0 * up / len(observed), 2) if observed else None
            out[name] = {"days": days, "series": series, "uptime_pct": pct}
        return out
