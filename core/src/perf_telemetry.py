"""In-memory performance telemetry for the hub: slow HTTP routes and slow
spoke commands. Served to AppBuilder through ``GET_HEALTH_REPORT`` so it can
spot a slow page or a slow spoke command and file a fix, without anyone
grepping logs. Counters are per process (reset on restart) and bounded."""

import logging
import os
import shutil
import threading
import time
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("hub.perf")

SLOW_ROUTE_S = float(os.getenv("LM_SLOW_ROUTE_S", "3"))
SLOW_COMMAND_S = float(os.getenv("LM_SLOW_COMMAND_S", "5"))
_MAX_KEYS = 400
_LOG_EVERY_S = 60.0


class _Stat:
    __slots__ = ("count", "total", "max", "slow", "last_slow_ts")

    def __init__(self) -> None:
        self.count = 0
        self.total = 0.0
        self.max = 0.0
        self.slow = 0
        self.last_slow_ts = 0.0

    def add(self, secs: float, slow_at: float) -> bool:
        self.count += 1
        self.total += secs
        self.max = max(self.max, secs)
        if secs >= slow_at:
            self.slow += 1
            self.last_slow_ts = time.time()
            return True
        return False

    def row(self, key: Any) -> Dict[str, Any]:
        return {"key": key, "count": self.count, "avg_s": round(self.total / max(self.count, 1), 2),
                "max_s": round(self.max, 2), "slow": self.slow, "last_slow_ts": self.last_slow_ts}


class PerfTelemetry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._routes: Dict[str, _Stat] = {}
        self._commands: Dict[Tuple[str, str], _Stat] = {}
        self._last_log: Dict[str, float] = {}

    def _stat(self, table: Dict, key: Any) -> _Stat:
        st = table.get(key)
        if st is None:
            if len(table) >= _MAX_KEYS:
                return _Stat()
            st = table[key] = _Stat()
        return st

    def _maybe_log(self, key: str, line: str) -> None:
        now = time.time()
        if now - self._last_log.get(key, 0.0) >= _LOG_EVERY_S:
            self._last_log[key] = now
            logger.warning(line)

    def record_route(self, method: str, route: str, secs: float, status: int = 200) -> None:
        key = f"{method} {route}"
        with self._lock:
            slow = self._stat(self._routes, key).add(secs, SLOW_ROUTE_S)
        if slow:
            self._maybe_log(key, f"[perf] SLOW REQUEST {key} took {secs:.1f}s (status {status})")

    def record_command(self, spoke: str, command: str, secs: float, ok: bool = True) -> None:
        with self._lock:
            slow = self._stat(self._commands, (spoke, command)).add(secs, SLOW_COMMAND_S)
        if slow:
            self._maybe_log(f"{spoke}:{command}",
                            f"[perf] SLOW COMMAND {command} to {spoke} took {secs:.1f}s")

    def snapshot(self, top: int = 15) -> Dict[str, Any]:
        with self._lock:
            routes = [s.row(k) for k, s in self._routes.items()]
            cmds = [dict(s.row(k[1]), spoke=k[0]) for k, s in self._commands.items()]
        by_slow = lambda r: (r["slow"], r["max_s"])  # noqa: E731
        return {"slow_route_s": SLOW_ROUTE_S, "slow_command_s": SLOW_COMMAND_S,
                "routes": sorted(routes, key=by_slow, reverse=True)[:top],
                "commands": sorted(cmds, key=by_slow, reverse=True)[:top]}


TELEMETRY = PerfTelemetry()


def host_stats() -> Dict[str, Any]:
    """Load, memory and disk of the hub host (best effort, Linux)."""
    out: Dict[str, Any] = {}
    try:
        out["load"] = [round(x, 2) for x in os.getloadavg()]
        out["cpus"] = os.cpu_count() or 1
    except OSError:
        pass
    try:
        mem = {}
        with open("/proc/meminfo") as fh:
            for ln in fh:
                k, _, v = ln.partition(":")
                if k in ("MemTotal", "MemAvailable"):
                    mem[k] = int(v.split()[0])
        if mem.get("MemTotal"):
            out["mem_used_pct"] = round(100 - 100.0 * mem.get("MemAvailable", 0) / mem["MemTotal"], 1)
    except (OSError, ValueError):
        pass
    try:
        du = shutil.disk_usage("/")
        out["disk_used_pct"] = round(100.0 * du.used / du.total, 1)
    except OSError:
        pass
    return out


def build_report(hub: Any) -> Dict[str, Any]:
    """Everything AppBuilder's health check needs in one reply."""
    report: Dict[str, Any] = {"generated": time.time(), "host": host_stats(),
                              "perf": TELEMETRY.snapshot()}
    report["timeouts_total"] = getattr(hub, "_request_timeouts_total", 0)
    report["timeouts_by_spoke"] = {
        str(sid): dict(cmds) for sid, cmds in
        (getattr(hub, "_request_timeouts_by_spoke", {}) or {}).items()}
    report["loop_lag_s"] = round(float(getattr(hub, "_loop_lag", 0.0) or 0.0), 2)
    try:
        report["spoke_names"] = {sid: hub._spoke_label(sid) for sid in report["timeouts_by_spoke"]}
    except Exception:  # noqa: BLE001
        report["spoke_names"] = {}
    return report
