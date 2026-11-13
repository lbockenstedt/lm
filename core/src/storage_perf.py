"""7 days of 5-minute performance averages, per device, for any module.

Storage (truenas) and firewall (opnsense) spokes average their own samples,
keep 7 days on their own disk, and push each average as ``STORAGE_PERF_SAMPLE``
``{module, samples: [{device_id, ts, samples, metrics}]}``. The hub keeps this
copy (keyed ``<module>:<device_id>``, persisted to
``<cache_dir>/storage_perf.json``) so the default 7-day chart loads instantly
and survives the spoke being offline; other ranges are read from the spoke,
with any bucket the spoke lacks filled in from this copy (``merge_rows``).
Not tied to Zabbix or to any one device type.

A leaf: stdlib + cache_core only.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from cache_core import JsonCacheFile

KEEP_S = 7 * 86400

# Modules that push STORAGE_PERF_SAMPLE -> the global_config list holding their
# devices. The hub ignores samples from any other module.
PERF_DEVICE_LISTS = {"truenas": "truenas_appliances", "opnsense": "firewalls"}


def merge_rows(spoke_rows: Any, hub_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The spoke's rows plus any bucket only the hub's copy has, oldest first.

    The spoke is the store of record, so its row wins a bucket both have; the
    hub's copy fills buckets the spoke lost (a restart before a save, or the
    file overwritten)."""
    by_ts = {r["ts"]: r for r in hub_rows if isinstance(r, dict) and "ts" in r}
    for r in spoke_rows if isinstance(spoke_rows, list) else []:
        if isinstance(r, dict) and "ts" in r:
            by_ts[r["ts"]] = r
    return [by_ts[t] for t in sorted(by_ts)]


class StoragePerfStore:
    """Per-device lists of ``{ts, samples, metrics}``, oldest first."""

    def __init__(self, cache_dir_fn):
        self.series: Dict[str, List[Dict[str, Any]]] = {}
        self._file = JsonCacheFile(
            "storage perf", lambda: os.path.join(cache_dir_fn(), "storage_perf.json"),
            lambda: {"series": self.series})

    def load(self) -> None:
        data = self._file.load() or {}
        series = data.get("series")
        if isinstance(series, dict):
            self.series = {k: v for k, v in series.items() if isinstance(v, list)}

    async def flush_now(self) -> None:
        await self._file.flush_now()

    def add(self, module: str, samples: Any, now: float = None) -> int:
        """Store pushed averages; returns how many were kept. A repeat of an
        existing bucket replaces it (a spoke re-sends after a lost ack)."""
        now = time.time() if now is None else now
        new: Dict[str, Dict[int, Dict[str, Any]]] = {}
        for s in samples if isinstance(samples, list) else []:
            if not isinstance(s, dict) or not s.get("device_id"):
                continue
            ts, metrics = s.get("ts"), s.get("metrics")
            if not isinstance(ts, (int, float)) or not isinstance(metrics, dict):
                continue
            if ts < now - KEEP_S or ts > now + 600:
                continue
            new.setdefault(f"{module}:{s['device_id']}", {})[int(ts)] = {
                "ts": int(ts), "samples": s.get("samples"),
                "metrics": {k: v for k, v in metrics.items()
                            if isinstance(v, (int, float)) and not isinstance(v, bool)}}
        for key, rows in new.items():
            merged = {r["ts"]: r for r in self.series.get(key, [])}
            merged.update(rows)
            self.series[key] = [merged[t] for t in sorted(merged) if t >= now - KEEP_S]
        if new:
            self._file.schedule_save()
        return sum(len(rows) for rows in new.values())

    def get(self, module: str, device_id: str, start: float = None, end: float = None,
            now: float = None) -> List[Dict[str, Any]]:
        """The device's averages with ``start <= ts <= end`` (default: the
        last 7 days), oldest first."""
        now = time.time() if now is None else now
        start = now - KEEP_S if start is None else start
        end = now if end is None else end
        return [r for r in self.series.get(f"{module}:{device_id}", [])
                if start <= r["ts"] <= end]
