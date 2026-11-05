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
# json reads and writes the history file.
import json
# Standard-library logging for load/save problems.
import logging
# time supplies the current epoch time and converts it to UTC dates.
import time
# Path locates the history file.
from pathlib import Path
# Type hints only; they document the shapes of snapshots and results.
from typing import Any, Dict, List

# Shares the status-page spoke's logger so messages appear together.
logger = logging.getLogger("StatusPageSpoke")

# Severity order of the three tones; higher is worse (used for worst-of-day).
_RANK = {"operational": 0, "degraded": 1, "down": 2}
# Seconds in one day, and how many days of history to keep.
_DAY = 86400
_KEEP_DAYS = 90


def _day_key(ts: float) -> str:
    """UTC day bucket 'YYYY-MM-DD' from an epoch timestamp (no Date.now use —
    time.gmtime is deterministic given ts)."""
    # Convert the timestamp to UTC calendar fields and format them as YYYY-MM-DD.
    tm = time.gmtime(ts)
    return "%04d-%02d-%02d" % (tm.tm_year, tm.tm_mon, tm.tm_mday)


class UptimeHistory:
    """Per-component daily status history, persisted to a JSON file."""
    def __init__(self, path: Path):
        """Open (or start) the history stored at path.

        Args:
            path: JSON file where the history is kept.
        """
        # Normalise to a Path so str inputs work too.
        self.path = Path(path)
        # {component_name: {day_key: "operational"|"degraded"|"down"}}
        self._data: Dict[str, Dict[str, str]] = {}
        # Read any history already saved on disk.
        self._load()

    def _load(self) -> None:
        """Load saved history from disk; start empty if the file is missing or corrupt."""
        # Read the file only if it exists; "null" content becomes an empty dict.
        try:
            if self.path.exists():
                self._data = json.loads(self.path.read_text()) or {}
        # Corrupt/unreadable file: log quietly and start fresh rather than crash.
        except Exception as e:  # noqa: BLE001
            logger.debug("uptime history load failed: %s", e)
            self._data = {}

    def _save(self) -> None:
        """Write history to disk atomically; failures are logged and ignored."""
        # Make sure the folder exists, write to a temp file, then rename over the real file
        # so a crash never leaves a half-written history.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data))
            tmp.replace(self.path)
        # Disk errors are not fatal; the in-memory history stays intact.
        except Exception as e:  # noqa: BLE001
            logger.debug("uptime history save failed: %s", e)

    def record(self, components: List[Dict[str, Any]], now: float = None) -> None:
        """Fold a snapshot's component statuses into today's bucket, keeping the
        worst status per component per day. Prunes buckets older than 90 days."""
        # Default to the current time when the caller does not supply one (tests pass one).
        now = now if now is not None else time.time()
        # Today's bucket key and the oldest day key that is still kept.
        day = _day_key(now)
        cutoff = _day_key(now - _KEEP_DAYS * _DAY)
        # Process each component in the snapshot (None is treated as empty).
        for comp in components or []:
            # Skip components without a usable name.
            name = str(comp.get("name") or "").strip()
            if not name:
                continue
            # Normalise the status; anything unrecognised counts as "degraded".
            tone = str(comp.get("status") or "degraded").lower()
            if tone not in _RANK:
                tone = "degraded"
            # Get (or create) this component's day buckets and today's current value.
            buckets = self._data.setdefault(name, {})
            prev = buckets.get(day)
            # Worst-of-day: only overwrite if the new tone is worse (higher rank).
            if prev is None or _RANK[tone] > _RANK.get(prev, 0):
                buckets[day] = tone
            # Prune old days for this component.
            for d in [d for d in buckets if d < cutoff]:
                buckets.pop(d, None)
        # Persist the updated history.
        self._save()

    def bars(self, now: float = None) -> Dict[str, Any]:
        """Return, per component, an ordered list of the last 90 daily statuses
        (oldest→newest) plus an uptime % (share of days operational). Days with
        no sample are 'nodata'."""
        # Default to the current time when the caller does not supply one.
        now = now if now is not None else time.time()
        # Build the list of the last 90 day keys, oldest first.
        days = [_day_key(now - (_KEEP_DAYS - 1 - i) * _DAY) for i in range(_KEEP_DAYS)]
        # Result: one entry per component.
        out: Dict[str, Any] = {}
        # Build each component's series and uptime percentage.
        for name, buckets in self._data.items():
            # Status for each day, "nodata" where nothing was recorded.
            series = [buckets.get(d, "nodata") for d in days]
            # Uptime % is operational days over days that have data (None if no data at all).
            observed = [s for s in series if s != "nodata"]
            up = sum(1 for s in observed if s == "operational")
            pct = round(100.0 * up / len(observed), 2) if observed else None
            # Store the days, series and uptime for this component.
            out[name] = {"days": days, "series": series, "uptime_pct": pct}
        return out
