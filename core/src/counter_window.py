"""Hour/day/week/month totals for counters that only grow until a restart.

Unbound and Kea both report lifetime counters (queries, DHCP packets) that
reset when the service restarts. A background sampler snapshots them; the
total for a window is the sum of the increases between snapshots. Used by the
DNS and DHCP workers, so both Overview pages window their stats the same way.

A snapshot is ``{"t": epoch, "up": uptime_s, "c": {counter: value}}`` with an
optional ``"types": {name: count}`` breakdown. ``up`` is optional (Kea has no
uptime); a restart is also detected by any tracked counter going down.
"""
import json
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# The selectable windows, by name, in seconds.
RANGE_SECONDS = {"hour": 3600, "day": 86400, "week": 7 * 86400, "month": 30 * 86400}

# Sample every 5 min; never closer than 1 min apart. Samples older than 26 h
# are thinned to one per hour, and nothing older than 31 days is kept.
SAMPLE_INTERVAL_S = 300
MIN_SAMPLE_GAP_S = 60
FINE_RETENTION_S = 26 * 3600
COARSE_STEP_S = 3600
HISTORY_MAX_S = 31 * 86400
PERSIST_INTERVAL_S = 300


def range_seconds(name) -> int:
    """Seconds for a window name ("hour"/"day"/"week"/"month"), or None."""
    return RANGE_SECONDS.get(str(name or "").strip().lower())


def counter_delta(prev: dict, cur: dict, keys) -> dict:
    """Increase of each counter from ``prev`` to ``cur``.

    After a restart (uptime went back, or any of ``keys`` went down) the
    counters started again from zero, so ``cur`` itself is the increase.
    """
    restarted = cur.get("up", 0) < prev.get("up", 0) or any(
        cur["c"].get(k, 0) < prev["c"].get(k, 0) for k in keys)
    out = {"c": {}, "types": {}}
    for k in set(prev["c"]) | set(cur["c"]):
        a, b = prev["c"].get(k, 0), cur["c"].get(k, 0)
        out["c"][k] = b if restarted else max(0, b - a)
    prev_types, cur_types = prev.get("types") or {}, cur.get("types") or {}
    for t in set(prev_types) | set(cur_types):
        a, b = prev_types.get(t, 0), cur_types.get(t, 0)
        d = b if restarted else max(0, b - a)
        if d:
            out["types"][t] = d
    return out


def merge_member_windows(replies, window_s: int) -> dict:
    """Combined ``window`` for a cluster whose members each windowed their own
    counters. Partial if any member's is, or a member sent no window (an older
    worker that returned lifetime totals)."""
    ok = [r for r in replies if isinstance(r, dict) and r.get("status") == "SUCCESS"]
    wins = [r["window"] for r in ok if isinstance(r.get("window"), dict)]
    return {
        "seconds": window_s,
        "covered_seconds": min((int(w.get("covered_seconds") or 0) for w in wins), default=0),
        "partial": len(wins) < len(ok) or any(w.get("partial") for w in wins),
        "unsupported_members": len(ok) - len(wins),
    }


class CounterHistory:
    """Snapshot history for one service's counters, optionally saved as JSON."""

    def __init__(self, path, keys, name: str):
        """
        Args:
            path: JSON file to keep history in, or None for memory only.
            keys: Counter names whose drop means the service restarted.
            name: Short label for logs and the sampler thread ("dns", "dhcp").
        """
        self.path = path
        self.keys = tuple(keys)
        self.name = name
        self.lock = threading.Lock()
        self.persisted_at = 0.0
        self.sampler = None
        self.samples = self.load()

    def load(self) -> list:
        """Saved snapshots, or [] when there is no path, no file or bad JSON."""
        if not self.path:
            return []
        try:
            with open(self.path) as f:
                data = json.load(f)
            samples = data.get("samples") if isinstance(data, dict) else None
            return [s for s in samples or [] if isinstance(s, dict) and "t" in s and "c" in s]
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.warning("%s stats history %s unreadable, starting fresh: %s",
                           self.name, self.path, e)
            return []

    def persist(self, now: float, force: bool = False) -> None:
        """Save to disk at most every PERSIST_INTERVAL_S (atomic replace)."""
        if not self.path or (not force and now - self.persisted_at < PERSIST_INTERVAL_S):
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"samples": self.samples}, f, separators=(",", ":"))
            os.replace(tmp, self.path)
            self.persisted_at = now
        except Exception as e:
            logger.warning("%s stats history persist to %s failed: %s", self.name, self.path, e)

    def record(self, snap: dict, force: bool = False) -> None:
        """Add a snapshot, thin old ones, and save if due."""
        with self.lock:
            hist = self.samples
            if not force and hist and snap["t"] - hist[-1]["t"] < MIN_SAMPLE_GAP_S:
                return
            hist.append(snap)
            now = snap["t"]
            # Drop samples past the max age; keep one per hour past fine retention.
            kept, last_slot = [], None
            for s in hist:
                age = now - s["t"]
                if age > HISTORY_MAX_S:
                    continue
                if age > FINE_RETENTION_S:
                    slot = int(s["t"] // COARSE_STEP_S)
                    if slot == last_slot:
                        continue
                    last_slot = slot
                kept.append(s)
            self.samples = kept
            self.persist(now)

    def window(self, current: dict, window_s: int) -> dict:
        """Counter increases over the ``window_s`` seconds ending at ``current``.

        The baseline is the newest sample at or before the window start. If
        history doesn't reach that far but the service started inside the
        window (known only when ``up`` is reported), its lifetime counters are
        the window. Otherwise the result is ``partial`` and ``covered_seconds``
        says how much of the window it covers.
        """
        now = current["t"]
        start = now - window_s
        up = current.get("up", 0)
        with self.lock:
            hist = [s for s in self.samples if s["t"] < now]
        base_idx = None
        for i, s in enumerate(hist):
            if s["t"] <= start:
                base_idx = i
        zero = {"t": start, "up": 0, "c": {}, "types": {}}
        partial = False
        if base_idx is not None:
            # History covers the whole window.
            chain = hist[base_idx:]
            covered = window_s
        elif up and now - up >= start and (not hist or hist[0]["t"] >= now - up):
            # The service started inside the window: count from zero.
            chain = [zero] + hist
            covered = window_s
        elif hist:
            # History is shorter than the window.
            chain = hist
            covered = int(now - hist[0]["t"])
            partial = True
        else:
            # No history: lifetime counters are the best available.
            chain = [zero]
            covered = min(window_s, int(up))
            partial = covered < window_s
        chain = chain + [current]
        tot = {"c": {k: 0 for k in self.keys}, "types": {}}
        for a, b in zip(chain, chain[1:]):
            d = counter_delta(a, b, self.keys)
            for k, v in d["c"].items():
                tot["c"][k] = tot["c"].get(k, 0) + v
            for t, v in d["types"].items():
                tot["types"][t] = tot["types"].get(t, 0) + v
        tot["covered_seconds"] = covered
        tot["partial"] = partial
        return tot

    def start_sampler(self, sample, interval: int = SAMPLE_INTERVAL_S):
        """Run ``sample()`` every ``interval`` seconds on a daemon thread so
        windows have baselines even when nobody views the page. Idempotent."""
        if self.sampler and self.sampler.is_alive():
            return self.sampler

        def run():
            """Sample forever; one failed pass never stops the loop."""
            while True:
                try:
                    sample()
                except Exception as e:  # noqa: BLE001
                    logger.warning("%s stats sampler pass failed: %s", self.name, e)
                time.sleep(interval)

        self.sampler = threading.Thread(target=run, name=f"{self.name}-stats-sampler", daemon=True)
        self.sampler.start()
        logger.info("%s stats sampler started (every %ss, history=%s, %d samples loaded)",
                    self.name, interval, self.path or "memory", len(self.samples))
        return self.sampler
