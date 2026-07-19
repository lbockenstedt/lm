"""Hub-side Aruba Central poller for CENTRALIZED processing mode.

In centralized mode the HUB holds the Central creds (Setup -> Central API ->
``central_config``) and the cs spoke has no Aruba client, so the spoke-side
``CentralPoller`` (``cs/lm-spoke/src/central_poller.py``) never runs and the
Simulations Checks / Hardware / Client-Count and Central tabs would stay empty
(they render ``spoke.central_status`` relayed via CS_TELEMETRY, which a
credential-less spoke never produces).

This loop is the hub-side equivalent: for every tenant whose
``processing_modes.central_api == "centralized"`` with a configured
``central_config``, it polls Central using the hub's full ``ArubaClient``
(``aruba.py``) and writes the SAME ``central_status`` shape the spoke relays
into ``hub.central_hub_status[tenant_id]``. ``SimulationsService`` then injects
that as a synthetic "Hub (centralized)" spoke so the dashboards populate
identically to distributed mode.

Mirrors ``central_poller.py``'s ``_poll_once`` + ``_client_count_entry`` (the
rolling 1h client-count average / drop%% baseline) — keep the two in sync.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from typing import Any, Dict, Optional

from .aruba import ArubaClient
from .check_eval import count_for_check, normalize_counts
from tenant_sharded import migrate_legacy, shard_load, shard_save

logger = logging.getLogger("CentralHubPoller")


def min_client_check(current: int, min_floor: Optional[int]) -> Optional[Dict[str, Any]]:
    """Build the per-site ``Minimum Client Threshold`` check, or ``None`` when no
    floor is set. Direct semantics: ``current`` below ``min_floor`` is an error
    (an absolute client-count floor — some sites should always have at least N
    clients), IN ADDITION to the % drop check. A floor of ``None``/``0`` means
    "monitor for change only" and emits no check (the site behaves as before)."""
    if not min_floor or min_floor <= 0:
        return None
    if current < min_floor:
        return {"status": "error", "message": f"{current} clients — below minimum {min_floor}"}
    return {"status": "ok", "message": f"{current} clients (min {min_floor}) — OK"}

_POLL_INTERVAL_S = 300  # 5 min — default; matches the spoke poller + aruba.py cache TTLs
_POLL_INTERVAL_FLOOR_S = 60  # min allowed per-tenant interval (protect the Central API)

# Client-count baseline constants — ported verbatim from the source webui-spoke
# (server.py). The alarm baseline is a 7-DAY rolling average of hourly snapshots
# (NOT the 1h average), so a prolonged client drop stays flagged instead of the
# baseline sagging to match it.
_CC_WINDOW = 3600          # seconds of raw samples kept (the "current hourly")
_CC_MIN_SAMPLES = 3        # minimum live samples before flagging
_CC_WARN_PCT = 20.0        # >20% below the hour average -> WARNING
_CC_ERROR_PCT = 50.0       # >50% below -> ERROR        # percent drop below baseline that flags DEGRADED
_CC_7DAY_WINDOW = 7 * 86400
_CC_30DAY_WINDOW = 30 * 86400   # long-run history retention (the 7-day is a subset)
_CC_SNAPSHOT_INTERVAL = 3600  # append one hourly snapshot to the history / hr
# Severe sustained die-off: the current hour is < 20% of the rolling PEAK
# (max hourly-avg) over the window → ERROR. Gated on a meaningful peak so a
# quiet/low-traffic site can't error on noise.
_CC_MAX_FRACTION = 0.20
_CC_MAX_MIN_PEAK = 5
_CC_KEYSEP = "\x1f"        # composite (tenant, wsite) key separator


def _cc_thresholds(central_config):
    """Per-tenant client-count CHECK thresholds, read from
    ``central_config['cc_thresholds']`` (Setup → Central API) with the module
    defaults as fallback and clamped to sane ranges. Keys: ``warn_pct`` /
    ``error_pct`` = amber/red when the count is that % below the recent hourly
    average; ``die_off_pct`` = red when the hourly average falls below that % of
    the rolling 7/30-day peak (0 disables the die-off rule); ``min_peak`` = the
    peak floor that arms the die-off rule. Returns resolved values with the
    die-off as a 0-1 fraction; ``error_pct`` is coerced up to ``warn_pct`` so red
    can never trip before amber. Mirror of the cs central_poller copy."""
    t = (central_config or {}).get("cc_thresholds") or {}

    def _num(val, dflt, lo, hi):
        try:
            x = float(val)
        except (TypeError, ValueError):
            return dflt
        return max(lo, min(hi, x))

    warn = _num(t.get("warn_pct"), _CC_WARN_PCT, 0.0, 100.0)
    err = _num(t.get("error_pct"), _CC_ERROR_PCT, 0.0, 100.0)
    if err < warn:
        err = warn
    die = _num(t.get("die_off_pct"), _CC_MAX_FRACTION * 100.0, 0.0, 100.0) / 100.0
    peak = int(_num(t.get("min_peak"), _CC_MAX_MIN_PEAK, 1, 1_000_000))
    return {"warn_pct": warn, "error_pct": err, "die_off_frac": die, "min_peak": peak}


_CC_SEVERITY = {"error": 3, "warning": 2, "ok": 1}  # else (no_data/pending/…) -> 0


def _cc_worst(*statuses):
    """Worst (most severe) of a set of client-count statuses — for the overall
    site check when wired + wireless are tracked separately (error > warning >
    ok > no_data). So a wired-only or wireless-only die-off reddens the site even
    if the other half is healthy. All-empty → the first status (usually
    no_data). Mirror of the cs central_poller copy."""
    worst, rank = None, -1
    for s in statuses:
        r = _CC_SEVERITY.get(s, 0)
        if r > rank:
            rank, worst = r, s
    return worst or "ok"


class ClientCountTracker:
    """Per-(scope, wsite) client-count baseline + drop detection, ported
    faithfully from the source webui-spoke (server.py ``_client_count_payload`` /
    ``_save_client_count_baseline`` / ``hourly_baseline_saver``).

    Monitoring a site means watching its client count for a sustained DROP: 1h of
    raw samples gives the smoothed "current hourly" average, and a 7-DAY history
    of hourly snapshots is the STABLE alarm baseline. ``drop_pct = (baseline -
    hourly_avg) / baseline`` and the site goes DEGRADED at >=25%. Because the
    baseline spans 7 days, a prolonged drop does NOT suppress the alarm. Both the
    last-hour baseline and the 7-day history persist to disk so a restart keeps
    the reference instead of showing NO_DATA for an hour. ``scope`` is the
    tenant_id on the hub (a single fixed key on the distributed spoke)."""

    def __init__(self, baseline_path: str, sevenday_path: str,
                 samples_path: str = "") -> None:
        self._baseline_path = baseline_path
        self._sevenday_path = sevenday_path
        # Raw 1h samples persist here too (every poll cycle) so a restart within
        # the first hour restores the ACTUAL reference, not just the synthetic
        # seed from the (hourly-written) baseline.
        self._samples_path = samples_path or (
            baseline_path.replace("baseline", "samples") if "baseline" in baseline_path
            else baseline_path + ".samples")
        self._samples: Dict[str, list] = {}    # key -> [(ts, count), ...] (1h)
        self._hourly: Dict[str, list] = {}      # key -> [(ts, hourly_avg), ...] (7d)
        self._baseline: Dict[str, dict] = {}    # key -> {hourly_avg, recorded_at}
        # Match the source: wait one full hour before the first snapshot write.
        self._last_snapshot = time.time()
        self._load()

    @staticmethod
    def _key(scope: str, wsite: str, kind: str = "") -> str:
        base = f"{scope}{_CC_KEYSEP}{wsite}"
        return f"{base}{_CC_KEYSEP}{kind}" if kind else base

    def _load(self) -> None:
        now = time.time()
        try:
            with open(self._baseline_path, encoding="utf-8") as f:
                self._baseline = json.load(f) or {}
            # Seed synthetic samples from the saved average so the UI surfaces a
            # reference immediately on restart (they age out as live data arrives).
            for key, saved in self._baseline.items():
                avg = round(saved.get("hourly_avg", 0))
                self._samples[key] = [
                    (now - (_CC_MIN_SAMPLES - i) * 60, avg) for i in range(_CC_MIN_SAMPLES)
                ]
        except Exception:  # noqa: BLE001 — absent/corrupt baseline → start empty
            self._baseline = {}
        try:
            with open(self._sevenday_path, encoding="utf-8") as f:
                raw = json.load(f) or {}
            cutoff = now - _CC_30DAY_WINDOW
            self._hourly = {
                k: [(float(ts), float(v)) for ts, v in entries if float(ts) >= cutoff]
                for k, entries in raw.items()
            }
        except Exception:  # noqa: BLE001
            self._hourly = {}
        # Restore the ACTUAL last-hour raw samples (trimmed to the 1h window),
        # overriding the synthetic seed above so the reference is exact on restart
        # — including within the first hour before any baseline was ever written.
        try:
            with open(self._samples_path, encoding="utf-8") as f:
                raw_s = json.load(f) or {}
            scut = now - _CC_WINDOW
            for key, entries in raw_s.items():
                kept = [(float(ts), int(v)) for ts, v in entries if float(ts) >= scut]
                if kept:
                    self._samples[key] = kept
        except Exception:  # noqa: BLE001 — absent/corrupt → keep synthetic seed
            pass

    def record(self, scope: str, wsite: str, current: int, kind: str = "") -> None:
        """Append a raw sample and trim to the 1-hour window."""
        now = time.time()
        key = self._key(scope, wsite, kind)
        samples = self._samples.setdefault(key, [])
        samples.append((now, int(current)))
        cutoff = now - _CC_WINDOW
        self._samples[key] = [s for s in samples if s[0] >= cutoff]

    def entry(self, scope: str, wsite: str, central_site: str, thresholds=None, kind: str = "") -> Dict[str, Any]:
        """Per-site client-count status (doubles as a dashboard CHECK). Tiered:
          - WITHIN-HOUR drop (current vs the last-hour average): WARNING / ERROR
            at ``warn_pct`` / ``error_pct`` below — catches sim-client die-off
            inside the hour.
          - SUSTAINED die-off: the current hour < ``die_off_frac`` of the 7-DAY or
            30-DAY rolling PEAK (max hourly-avg) → ERROR. Gated on a peak of at
            least ``min_peak`` so a quiet site can't false-trigger; die_off_frac=0
            disables it.
        ``thresholds`` (from _cc_thresholds → central_config) overrides the module
        defaults per tenant. The 7d/30d peaks are recorded regardless of status."""
        _t = thresholds or {}
        warn_pct = _t.get("warn_pct", _CC_WARN_PCT)
        error_pct = _t.get("error_pct", _CC_ERROR_PCT)
        die_off_frac = _t.get("die_off_frac", _CC_MAX_FRACTION)
        min_peak = _t.get("min_peak", _CC_MAX_MIN_PEAK)
        now = time.time()
        key = self._key(scope, wsite, kind)
        samples = self._samples.get(key, [])
        hist = self._hourly.get(key, [])
        # Rolling peaks over each window (include the live hour so a fresh spike counts).
        vals_7d = [v for ts, v in hist if ts >= now - _CC_7DAY_WINDOW]
        vals_30d = [v for ts, v in hist if ts >= now - _CC_30DAY_WINDOW]
        if not samples:
            return {"site_name": central_site, "current": 0, "hourly_avg": 0,
                    "drop_pct": 0.0, "max_7day": round(max(vals_7d or [0]), 1),
                    "max_30day": round(max(vals_30d or [0]), 1),
                    "status": "no_data", "ts": now}
        current = samples[-1][1]
        hourly_avg = sum(s[1] for s in samples) / len(samples)
        max_7day = round(max(vals_7d + [hourly_avg]), 1)
        max_30day = round(max(vals_30d + [hourly_avg]), 1)
        if len(samples) < _CC_MIN_SAMPLES:
            drop_pct, status = 0.0, "no_data"
        else:
            if hourly_avg >= 1:
                drop_pct = max(0.0, (hourly_avg - current) / hourly_avg * 100.0)
            else:
                drop_pct = 0.0
            # Within-hour tier.
            if drop_pct > error_pct:
                status = "error"
            elif drop_pct > warn_pct:
                status = "warning"
            else:
                status = "ok"
            # Sustained die-off vs the 7d/30d peak → hard ERROR (overrides warn/ok);
            # die_off_frac=0 disables this rule.
            if (die_off_frac > 0
                    and ((max_7day >= min_peak and hourly_avg < die_off_frac * max_7day)
                         or (max_30day >= min_peak and hourly_avg < die_off_frac * max_30day))):
                status = "error"
        return {"site_name": central_site, "current": current,
                "hourly_avg": round(hourly_avg, 1), "drop_pct": round(drop_pct, 1),
                "max_7day": max_7day, "max_30day": max_30day,
                "status": status, "ts": samples[-1][0]}

    def maybe_snapshot(self) -> None:
        """Once per hour: append each site's current hourly average to the 7-day
        history and persist both files. Mirrors source hourly_baseline_saver +
        _save_client_count_baseline."""
        now = time.time()
        if now - self._last_snapshot < _CC_SNAPSHOT_INTERVAL:
            return
        self._last_snapshot = now
        cutoff = now - _CC_30DAY_WINDOW
        snapshot: Dict[str, dict] = {}
        for key, samples in self._samples.items():
            if len(samples) < _CC_MIN_SAMPLES:
                continue
            avg = sum(s[1] for s in samples) / len(samples)
            snapshot[key] = {"hourly_avg": round(avg, 1), "recorded_at": now}
            hist = self._hourly.setdefault(key, [])
            hist.append((now, avg))
            self._hourly[key] = [(ts, v) for ts, v in hist if ts >= cutoff]
        if snapshot:
            self._baseline.update(snapshot)
            self._persist(self._baseline_path, self._baseline)
        if self._hourly:
            self._persist(self._sevenday_path, {k: list(v) for k, v in self._hourly.items()})

    def save_samples(self) -> None:
        """Persist the raw 1h samples (trimmed to the window) every poll cycle so
        a restart restores the exact reference. Best-effort; small dict."""
        now = time.time()
        cutoff = now - _CC_WINDOW
        trimmed = {
            k: [(ts, c) for ts, c in v if ts >= cutoff]
            for k, v in self._samples.items()
        }
        trimmed = {k: v for k, v in trimmed.items() if v}
        self._persist(self._samples_path, trimmed)

    def forget(self, scope: str) -> None:
        """Drop all state for a scope (tenant left centralized mode / cleared creds)."""
        prefix = f"{scope}{_CC_KEYSEP}"
        for store in (self._samples, self._hourly, self._baseline):
            for k in [k for k in store if k.startswith(prefix)]:
                store.pop(k, None)

    @staticmethod
    def _persist(path: str, data: dict) -> None:
        try:
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, path)
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            logger.warning("ClientCountTracker: persist failed (%s): %s", path, exc)


_HEALTH_IDX = {"ok": 0, "warning": 1, "error": 2}  # else (no_data/pending/unknown) -> 3


class CheckHealthHistory:
    """Rolling 30-day status history for every dashboard check, in HOURLY buckets.

    Each poll records one status sample per (tenant, site, check) into the current
    hour's bucket as counts ``[ok, warning, error, other]`` (green/yellow/red/grey).
    ``summary`` rolls the hourly buckets up to 30 DAILY buckets for the at-a-glance
    health strip; ``hourly`` returns the raw hourly buckets for the on-hover
    breakdown. Persisted to one JSON file in the data dir (not sensitive)."""

    def __init__(self, path: str) -> None:
        self._path = path
        # key = tenant\x1fsite\x1fcheck -> {hour_ts(int): [o, w, e, n]}
        self._h: Dict[str, Dict[int, list]] = {}
        self._load()

    @staticmethod
    def _key(tenant: str, site: str, check_id: str) -> str:
        return f"{tenant}{_CC_KEYSEP}{site}{_CC_KEYSEP}{check_id}"

    def _load(self) -> None:
        try:
            with open(self._path, encoding="utf-8") as f:
                raw = json.load(f) or {}
            cutoff = time.time() - _CC_30DAY_WINDOW
            self._h = {
                k: {int(b): list(v) for b, v in buckets.items() if int(b) >= cutoff}
                for k, buckets in raw.items()
            }
        except Exception:  # noqa: BLE001 — absent/corrupt → start empty
            self._h = {}

    def record(self, tenant: str, site: str, check_id: str, status: str) -> None:
        now = time.time()
        buckets = self._h.setdefault(self._key(tenant, site, check_id), {})
        bucket = int(now // 3600 * 3600)
        cell = buckets.get(bucket)
        if cell is None:
            cell = [0, 0, 0, 0]
            buckets[bucket] = cell
        cell[_HEALTH_IDX.get(str(status).strip().lower(), 3)] += 1
        cutoff = now - _CC_30DAY_WINDOW
        for b in [b for b in buckets if b < cutoff]:
            del buckets[b]

    def save(self) -> None:
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({k: {str(b): v for b, v in bk.items()}
                           for k, bk in self._h.items()}, f, default=str)
            os.replace(tmp, self._path)
        except Exception:  # noqa: BLE001 — never let persistence kill the poll
            pass

    def summary(self, tenant: str) -> Dict[str, Any]:
        """{site: {check_id: [{d, o, w, e, n} ... up to 30 daily]}} for the tenant."""
        now = time.time()
        floor = int(now // 86400 * 86400) - 29 * 86400
        prefix = f"{tenant}{_CC_KEYSEP}"
        out: Dict[str, Any] = {}
        for key, buckets in self._h.items():
            if not key.startswith(prefix):
                continue
            parts = key.split(_CC_KEYSEP, 2)
            if len(parts) != 3:
                continue
            _, site, check_id = parts
            days: Dict[int, list] = {}
            for b, cell in buckets.items():
                d = int(b // 86400 * 86400)
                if d < floor:
                    continue
                acc = days.setdefault(d, [0, 0, 0, 0])
                for i in range(4):
                    acc[i] += cell[i]
            out.setdefault(site, {})[check_id] = [
                {"d": d, "o": v[0], "w": v[1], "e": v[2], "n": v[3]}
                for d, v in sorted(days.items())
            ]
        return out

    def hourly(self, tenant: str, site: str, check_id: str) -> list:
        """Raw hourly buckets [{h, o, w, e, n}] (last 30 days) for one check."""
        buckets = self._h.get(self._key(tenant, site, check_id), {})
        return [{"h": b, "o": v[0], "w": v[1], "e": v[2], "n": v[3]}
                for b, v in sorted(buckets.items())]


_CPW_WINDOW = 3600  # seconds — the rolling 1-hour PASS/FAIL verdict window


_POLL_PASS_STATES = ("ok", "pass", "passed", "green", "up", "healthy", "online")
# Only genuinely-absent samples are IGNORED (don't count toward the verdict).
# Everything that isn't a pass or an ignore is a FAIL — see below.
_POLL_IGNORE_STATES = ("", "no_data", "nodata", "unknown", "pending", "n/a", "none", "-", "—")


def _classify_poll_status(status: Any) -> Optional[bool]:
    """Classify one per-poll check status into PASS / FAIL / IGNORE for the
    rolling 1h verdict. INVERTED sim semantics are already baked into the
    per-poll status (a per-poll ``"error"`` = the expected alert/insight is
    MISSING, a ``"warning"`` = clients dropped — both FAILED polls).

    Returns ``True`` (PASS) for ok-like states, ``None`` (IGNORE — don't record,
    don't count) only for genuinely-absent states (``no_data``/``unknown``/blank),
    and ``False`` (FAIL) for EVERYTHING ELSE — ``warning``/``error`` but also
    ``critical``/``fail``/``down``/``degraded``/… . Defaulting unknown states to
    FAIL (not ignore) is deliberate: a failure state the classifier didn't
    recognize used to be silently dropped, so a green last poll could win the
    verdict even though the hour had failures."""
    s = str(status or "").strip().lower()
    if s in _POLL_PASS_STATES:
        return True
    if s in _POLL_IGNORE_STATES:
        return None
    return False


class CheckPollWindow:
    """Rolling 1-hour PASS/FAIL window per (tenant, site, check) enforcing the
    operator rule: a dashboard check must NOT read OK if ANY poll FAILED in the
    last hour.

      - every poll in the last hour PASSED            → verdict ``"ok"``     (green)
      - any failure but ≤50% of polls failed          → verdict ``"warning"`` (yellow)
      - MORE THAN 50% of polls in the last hour failed → verdict ``"error"``   (red)
      - no pass/fail samples yet (only no_data/absent) → verdict ``None`` (leave as-is)

    Mirrors ``ClientCountTracker``'s persistence pattern: ``self._samples`` maps
    ``tenant\\x1fsite\\x1fcheck`` (via ``_CC_KEYSEP``) to ``[(ts, is_pass), ...]``
    trimmed to a 3600s window on every ``record``, and persisted atomically to a
    single JSON file in the data dir (``save_samples``), restored (trimmed) on
    init so a verdict survives a hub restart within the hour."""

    _MODULE = "simulations"
    _NAME = "check_poll_window.json"

    def __init__(self, data_dir: str) -> None:
        # Sharded per tenant under <data_dir>/tenants/<tenant>/simulations/. One
        # migrate-on-first-boot split of any legacy shared file, then load shards.
        self._data_dir = data_dir
        self._samples: Dict[str, list] = {}    # key -> [(ts, is_pass: bool), ...]
        self._dirty: set = set()               # tenants changed since last save
        migrate_legacy(data_dir, self._MODULE, self._NAME)
        self._load()

    @staticmethod
    def _key(tenant: str, site: str, check: str) -> str:
        return f"{tenant}{_CC_KEYSEP}{site}{_CC_KEYSEP}{check}"

    def _load(self) -> None:
        cutoff = time.time() - _CPW_WINDOW
        raw = shard_load(self._data_dir, self._MODULE, self._NAME)
        trimmed = {
            k: [(float(ts), bool(p)) for ts, p in entries if float(ts) >= cutoff]
            for k, entries in raw.items()
        }
        self._samples = {k: v for k, v in trimmed.items() if v}

    def record(self, tenant: str, site: str, check: str, is_pass: bool) -> None:
        """Append a PASS/FAIL sample and trim to the 1-hour window."""
        now = time.time()
        key = self._key(tenant, site, check)
        samples = self._samples.setdefault(key, [])
        samples.append((now, bool(is_pass)))
        cutoff = now - _CPW_WINDOW
        self._samples[key] = [s for s in samples if s[0] >= cutoff]
        self._dirty.add(str(tenant))

    def _window(self, tenant: str, site: str, check: str) -> list:
        cutoff = time.time() - _CPW_WINDOW
        return [p for ts, p in self._samples.get(self._key(tenant, site, check), [])
                if ts >= cutoff]

    def verdict(self, tenant: str, site: str, check: str) -> Optional[str]:
        """Aggregate 1h verdict — ``"ok"``/``"warning"``/``"error"`` per the rule
        above, or ``None`` when there are no PASS/FAIL samples in the window."""
        samples = self._window(tenant, site, check)
        if not samples:
            return None
        total = len(samples)
        passes = sum(1 for p in samples if p)
        if passes == total:
            return "ok"                     # every poll in the window passed → green
        fails = total - passes
        if fails * 2 > total:               # MORE THAN 50% of polls failed → red
            return "error"
        return "warning"                    # any failure, up to 50% → yellow

    def counts(self, tenant: str, site: str, check: str) -> tuple:
        """``(passes, total)`` over the last hour — for the operator message hint."""
        samples = self._window(tenant, site, check)
        return sum(1 for p in samples if p), len(samples)

    def save_samples(self) -> None:
        """Persist the window (trimmed) per tenant so a restart within the hour
        restores the verdict. Writes only tenants that changed since the last save
        (recorded a sample OR had one trimmed away). Best-effort."""
        cutoff = time.time() - _CPW_WINDOW
        dirty = set(self._dirty)
        new: Dict[str, list] = {}
        for k, v in self._samples.items():
            kept = [(ts, p) for ts, p in v if ts >= cutoff]
            if len(kept) != len(v):
                dirty.add(k.split(_CC_KEYSEP, 1)[0])   # trimmed → this tenant changed
            if kept:
                new[k] = kept
        self._samples = new
        shard_save(self._data_dir, self._MODULE, self._NAME, self._samples,
                   dirty=(dirty or None))
        self._dirty = set()

    def forget(self, tenant: str) -> None:
        """Drop all in-memory state for a tenant (left centralized mode) and mark
        it dirty so the next save removes its now-empty shard file."""
        prefix = f"{tenant}{_CC_KEYSEP}"
        for k in [k for k in self._samples if k.startswith(prefix)]:
            self._samples.pop(k, None)
        self._dirty.add(str(tenant))


class CentralHubPoller:
    """Polls Aruba Central hub-side for every centralized-mode tenant on a
    5-minute loop, writing ``hub.central_hub_status[tenant_id]`` in the shape the
    Simulations service / sim-views.js Checks/Hardware/Client-Count/Central tabs
    expect. See the module docstring."""

    def __init__(self, hub) -> None:
        self.hub = hub
        ddir = getattr(getattr(hub, "state", None), "data_dir", ".") or "."
        self._cc = ClientCountTracker(
            os.path.join(ddir, "client_count_baseline.json"),
            os.path.join(ddir, "client_count_7day.json"),
            os.path.join(ddir, "client_count_samples.json"),
        )
        # 30-day per-check status history (green/yellow/red) for the health graphs.
        self._health = CheckHealthHistory(os.path.join(ddir, "check_health_history.json"))
        # Rolling 1h PASS/FAIL window per check → the last-hour verdict override
        # (a check can't read OK if any poll failed within the hour).
        self._cpw = CheckPollWindow(ddir)
        # Per-tenant last-poll timestamps + the next loop sleep. The Central poll
        # interval is configurable per tenant (Setup → Central API → Connection);
        # tenants are gated by their own interval and the loop wakes on the
        # shortest configured one.
        self._last_poll: Dict[str, float] = {}
        self._next_sleep_s: float = _POLL_INTERVAL_S

    @property
    def _store(self):
        return self.hub.simulations_store

    async def _centralized_tenants(self) -> list:
        """(tenant_id, central_config) for every tenant in centralized central_api
        mode with a non-empty central_config. Skips tenants with no creds."""
        out = []
        for tid in self._store.tenant_ids():
            try:
                modes = await self._store.get_processing_modes(tid)
                # Central API defaults to CENTRALIZED — only explicit 'distributed'
                # (a spoke owns the creds) opts out. So a hub with a Central config
                # and no spoke still gets polled and its checks show.
                if not self._store.central_api_is_centralized(modes):
                    continue
                cc = await self._store.get_central_config(tid)
                if cc:
                    out.append((tid, cc))
            except Exception:  # noqa: BLE001 — one bad tenant never blocks the rest
                continue
        return out

    @staticmethod
    def _interval_for(central_config: Dict[str, Any]) -> int:
        """This tenant's Central poll interval in seconds — ``poll_interval_s`` from
        its central_config (Setup → Central API → Connection), defaulting to 5 min
        and clamped to the floor so a misconfig can't hammer the Central API."""
        try:
            iv = int((central_config or {}).get("poll_interval_s") or _POLL_INTERVAL_S)
        except (TypeError, ValueError):
            iv = _POLL_INTERVAL_S
        return max(_POLL_INTERVAL_FLOOR_S, iv)

    async def _poll_tenant(self, tenant_id: str, central_config: Dict[str, Any]) -> None:
        # ArubaClient maps central_config's ``mode`` -> api_version itself.
        client = ArubaClient(central_config)
        if not client.is_configured():
            self.hub.central_hub_status.pop(tenant_id, None)
            self._cc.forget(tenant_id)
            self._cpw.forget(tenant_id)
            return
        cc_thresh = _cc_thresholds(central_config)
        sites_cfg = await self._store.get_central_sites_config(tenant_id)
        site_mappings: Dict[str, str] = sites_cfg.get("site_mappings") or {}
        monitored: list = sites_cfg.get("monitored_checks") or []
        hw_checks: list = sites_cfg.get("hardware_checks") or []
        # Per-site minimum client count threshold (site name -> int). When set,
        # the poller raises a "Minimum Client Threshold" check (direct semantics:
        # below the floor = error) IN ADDITION to the drop-based client-count
        # check — some sites should always have at least N clients (a floor),
        # independent of the % drop from the rolling average.
        site_min_clients: Dict[str, int] = {
            str(k): int(v) for k, v in (sites_cfg.get("site_min_clients") or {}).items()
            if isinstance(v, (int, float)) and int(v) > 0
        }
        hw_check_ids = {str(h.get("id")) for h in hw_checks if h.get("id")}
        hw_names = {str(h.get("id")): h for h in hw_checks if h.get("id")}

        status: Dict[str, Any] = {}
        client_count_status: Dict[str, Any] = {}
        central_clients_by_site: Dict[str, int] = {}
        hw_totals: Dict[str, int] = {}

        for wireless_site, central_site in site_mappings.items():
            try:
                data = await client.poll_site_data(central_site, hw_check_ids)
            except Exception as exc:  # noqa: BLE001
                status[wireless_site] = {"poll_error": {"status": "error", "message": str(exc)}}
                continue
            alert_counts = data.get("alert_type_counts") or {}
            insight_counts = data.get("insight_cat_counts") or {}
            # Match case-insensitively AND across BOTH the alert and insight
            # buckets. The dashboard's alert/insight query is merged, so a check
            # must fire whether Central classifies the named condition as an alert
            # or an insight — e.g. "DNS Server Failed to Respond" comes back as an
            # INSIGHT, but its quota is typed "alert". Reading only the typed
            # bucket (case-sensitively) reported a live condition as absent, so the
            # adaptive controller ramped forever and exhausted the client pool.
            # Typed bucket wins; fall back to the other. Shared with the three CS
            # deployments via check_eval (single source of truth for this match).
            alert_ci, insight_ci = normalize_counts(alert_counts), normalize_counts(insight_counts)
            # DIAG: what the engine looks for vs what Central actually returned for
            # this site. A monitored id absent from BOTH lists = a site-drop or a
            # name diff; present = should fire.
            logger.info("central-check diag [%s→%s]: monitored=%s alert_keys=%s insight_keys=%s",
                        wireless_site, central_site,
                        [str(c.get("id")) for c in monitored if isinstance(c, dict) and c.get("id")],
                        sorted(alert_ci), sorted(insight_ci))
            # GLOBAL SIM CATALOG: record every alert/insight NAME observed on this
            # tenant/site into the hub-wide history shared by ALL tenants, so the
            # Sim-Quota "Alert / Insight ID" picker builds a library automatically
            # from live polling — no need to stage the condition in a monitored
            # site first. Use the properly-cased pre-normalize count keys
            # (alert_ci/insight_ci are lowercased for matching only). Best-effort:
            # the store writes only when a NEW type appears, so a steady poll adds
            # no I/O, and a failure here can never break the poll cycle.
            try:
                _cat_items = (
                    [{"type": "alert", "id": k, "name": k, "site": central_site}
                     for k in (alert_counts or {})]
                    + [{"type": "insight", "id": k, "name": k, "site": central_site}
                       for k in (insight_counts or {})]
                )
                if _cat_items:
                    await self._store.record_alert_insight_seen(_cat_items)
            except Exception:  # noqa: BLE001 — cataloguing must never break the poll
                pass
            checks: Dict[str, Any] = {}
            for chk in monitored:
                cid = str(chk.get("id") or "")
                if not cid:
                    continue
                # Per-site monitoring: a check pinned to a site evaluates ONLY on
                # that site (central_site); an empty/absent site = global (every
                # mapped site). Lets you monitor an insight/alert at one site.
                chk_site = str(chk.get("site") or "").strip().lower()
                if chk_site and chk_site not in (str(central_site).lower(), str(wireless_site).lower(), "all sites"):
                    continue
                n = count_for_check(chk, alert_ci, insight_ci)
                # INVERTED semantics: this is a demo/simulation platform that is
                # SUPPOSED to be generating these alerts/insights. A monitored check
                # is HEALTHY (ok) when its error IS present, and FAILING (error) when
                # the expected error is NOT detected — the sim stopped producing it.
                # Monitor-for-absence: notify when the expected error goes missing.
                checks[cid] = {"status": "ok" if n > 0 else "error",
                               "message": f"{n} active (as expected)" if n else "Expected error NOT detected"}
            status[wireless_site] = checks
            current = int(data.get("client_count", 0) or 0)
            wired = int(data.get("wired_clients", 0) or 0)
            wireless = int(data.get("wireless_clients", 0) or 0)
            # Track total, wired, and wireless as SEPARATE series so each is
            # evaluated on its own baseline/peak with the same thresholds — a
            # wired-only or wireless-only die-off is caught even when the total is
            # masked (e.g. wired collapses while wireless spikes).
            self._cc.record(tenant_id, wireless_site, current)
            self._cc.record(tenant_id, wireless_site, wired, kind="wired")
            self._cc.record(tenant_id, wireless_site, wireless, kind="wireless")
            cc_entry = self._cc.entry(tenant_id, wireless_site, central_site, cc_thresh)
            w_entry = self._cc.entry(tenant_id, wireless_site, central_site, cc_thresh, kind="wired")
            wl_entry = self._cc.entry(tenant_id, wireless_site, central_site, cc_thresh, kind="wireless")
            cc_entry["wired"] = wired
            cc_entry["wireless"] = wireless
            cc_entry["wired_status"] = w_entry["status"]
            cc_entry["wired_drop_pct"] = w_entry["drop_pct"]
            cc_entry["wireless_status"] = wl_entry["status"]
            cc_entry["wireless_drop_pct"] = wl_entry["drop_pct"]
            # Overall = worst of total/wired/wireless.
            cc_entry["status"] = _cc_worst(cc_entry["status"], w_entry["status"], wl_entry["status"])
            client_count_status[wireless_site] = cc_entry
            # Surface the site's client-count monitor as a CHECK so "everything
            # monitored" shows on the dashboard Checks view. Direct (NOT inverted)
            # semantics: a DROP in clients means the sim clients died -> warning / error.
            checks["Steady Client Count 1hr Average"] = {
                "status": cc_entry["status"],
                "message": (f"{cc_entry['current']} clients vs {cc_entry['hourly_avg']} hr-avg "
                            f"(down {cc_entry['drop_pct']}%) · wired {wired} (down {w_entry['drop_pct']}%) "
                            f"· wireless {wireless} (down {wl_entry['drop_pct']}%)"),
            }
            # Per-site minimum client floor. Direct semantics: current below the
            # configured min = error (clients died below an absolute floor, not
            # just a relative drop). Only emitted when a min is set for THIS site
            # — sites without a threshold are unchanged. The floor lookup matches
            # on the wireless site name OR the central site name so a threshold
            # saved against either form applies.
            min_floor = site_min_clients.get(wireless_site) or site_min_clients.get(central_site)
            _mc = min_client_check(current, min_floor)
            if _mc:
                checks["Minimum Client Threshold"] = _mc
            central_clients_by_site[wireless_site] = current
            for alert_id, devices in (data.get("hw_devices") or {}).items():
                hw_totals[alert_id] = hw_totals.get(alert_id, 0) + sum(devices.values())

        # Per-device hardware monitoring: look each monitored hardware device up in
        # the live device list and add a check on its pinned site — DOWN = error
        # (a monitored switch/AP/gateway is offline). new_central only; best-effort.
        if hw_checks:
            try:
                all_devices = await client._nc_devices()
            except Exception:  # noqa: BLE001
                all_devices = []
            dev_by_key: Dict[str, dict] = {}
            for d in all_devices:
                for k in (d.get("serialNumber"), d.get("serial"), d.get("deviceName"), d.get("name")):
                    if k:
                        dev_by_key[str(k)] = d
            for hc in hw_checks:
                hid = str(hc.get("id") or "")
                if not hid:
                    continue
                hsite = str(hc.get("site") or "").strip().lower()
                dev = dev_by_key.get(hid)
                up = str((dev or {}).get("status") or "").upper() in ("UP", "ONLINE")
                label = str(hc.get("name") or hid)
                for wsite, csite in site_mappings.items():
                    if hsite and hsite not in (str(csite).lower(), str(wsite).lower(), "all sites"):
                        continue
                    status.setdefault(wsite, {})[label] = {
                        "status": "ok" if up else "error",
                        "message": "up" if up else "DOWN",
                    }

        hardware_alerts = [
            {"id": aid, "name": (hw_names.get(aid) or {}).get("name", aid),
             "device_type": (hw_names.get(aid) or {}).get("device_type", ""),
             "total": total}
            for aid, total in hw_totals.items()
        ]
        self.hub.central_hub_status[tenant_id] = {
            "status": status,
            "hardware_alerts": hardware_alerts,
            "client_count_status": client_count_status,
            "central_clients_by_site": central_clients_by_site,
            "site_mappings": site_mappings,
            "token_valid": True,
            "fetched_at": time.time(),
        }
        # Record each check's status into the 30-day health history (hourly bucket).
        for wsite, checks_map in status.items():
            if not isinstance(checks_map, dict):
                continue
            for cid, info in checks_map.items():
                st = (info.get("status") if isinstance(info, dict) else info) or "no_data"
                self._health.record(tenant_id, wsite, cid, st)
                # Rolling 1h verdict: a check must NOT read OK if any poll FAILED
                # in the last hour. Classify this poll (INVERTED sim semantics —
                # a client-drop "warning" or a missing-alert "error" both = a
                # FAILED poll), record it, then OVERRIDE the stored status with the
                # aggregate verdict. Because central_hub_status[...]["status"] holds
                # this SAME dict by reference, rewriting info["status"] flows into
                # the persisted block and to the dashboard. no_data/other → ignore
                # (verdict stays None) → leave the instantaneous status as-is.
                is_pass = _classify_poll_status(st)
                if is_pass is None or not isinstance(info, dict):
                    continue
                self._cpw.record(tenant_id, wsite, cid, is_pass)
                verdict = self._cpw.verdict(tenant_id, wsite, cid)
                if verdict is not None:
                    info["status"] = verdict
                    passes, total = self._cpw.counts(tenant_id, wsite, cid)
                    info["message"] = f"{info.get('message', '')} · {passes}/{total} polls OK in last 1h"

    async def _poll_once(self) -> None:
        tenants = await self._centralized_tenants()
        # Drop cached status for tenants that left centralized mode / cleared creds
        # so the UI stops showing a stale synthetic hub spoke.
        live = {tid for tid, _ in tenants}
        for stale in [t for t in list(self.hub.central_hub_status.keys()) if t not in live]:
            self.hub.central_hub_status.pop(stale, None)
            self._cc.forget(stale)
            self._cpw.forget(stale)
            self._last_poll.pop(stale, None)
        now = time.time()
        # Gate each tenant by its own configured interval; wake on the shortest.
        intervals = [self._interval_for(cc) for _, cc in tenants]
        self._next_sleep_s = min(intervals) if intervals else _POLL_INTERVAL_S
        for tid, cc in tenants:
            iv = self._interval_for(cc)
            if now - self._last_poll.get(tid, 0.0) < iv:
                continue  # not due yet
            self._last_poll[tid] = now
            try:
                await self._poll_tenant(tid, cc)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Central hub poll failed for tenant %s: %s", tid, exc)
        # Append the hourly snapshot to the 7-day baseline history (self-gated to
        # once per hour) and persist — the alarm baseline that flags sustained drops.
        self._cc.maybe_snapshot()
        # Persist the raw 1h samples EVERY cycle so a restart (even within the
        # first hour, before any hourly baseline is written) restores the actual
        # last-hour reference instead of showing NO_DATA for ~15 min while it
        # rebuilds. Cheap (small dict); best-effort.
        # Off the event loop (bounded per-tenant shard writes once per cycle) so
        # they can't starve the WS loop — same discipline as _health.save below.
        try:
            await asyncio.to_thread(self._cc.save_samples)
        except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
            logger.debug("client-count samples persist skipped: %s", exc)
        # Persist the rolling 1h PASS/FAIL window too so the last-hour verdict
        # survives a hub restart within the hour.
        try:
            await asyncio.to_thread(self._cpw.save_samples)
        except Exception as exc:  # noqa: BLE001
            logger.debug("check poll window persist skipped: %s", exc)
        # Persist the per-check health history off-thread (bounded once-per-cycle write).
        try:
            await asyncio.to_thread(self._health.save)
        except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
            logger.debug("check health persist skipped: %s", exc)
        # Warm-start persistence for the whole per-tenant dashboard status. Off the
        # event loop — a bounded write once per 5-min cycle can't starve the WS.
        save = getattr(self.hub, "_save_central_hub_status", None)
        if save:
            try:
                await asyncio.to_thread(save)
            except Exception as exc:  # noqa: BLE001 — never let persistence kill the poll
                logger.debug("central_hub_status persist skipped: %s", exc)

    async def run_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — never let a bad poll kill the loop
                logger.warning("Central hub poll loop error: %s", exc)
            await asyncio.sleep(max(_POLL_INTERVAL_FLOOR_S, self._next_sleep_s))
