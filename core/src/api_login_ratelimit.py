"""Login throttling for the LM Hub WebUI/API — failed-attempt lockout plus a
per-IP spray limiter.

Extracted verbatim from ``api.py`` (no FastAPI/request objects; the caller in
``routes/auth.py`` computes the client IP via ``api._client_ip`` and passes it
in, and passes the ``hub`` for state-dir persistence + threat-monitor hooks).
Imported back into ``api.py`` so ``from api import _login_check`` etc. (used by
``routes/auth.py``) keeps resolving and behavior is unchanged.

No HTTP rate-limit library is used; this is a compact in-process throttle. The
per-username counters (lockout state) are persisted to login_attempts.json so a
targeted brute-force survives a hub restart; the per-IP spray window is
in-memory only (resets on restart — acceptable). Tunable via env.
"""

# json reads/writes the persisted lockout counters file.
import json
# Standard-library logging for persistence warnings.
import logging
# os is used for env-var tunables and file paths/permissions.
import os
# time.time() provides the timestamps used for windows and lockouts.
import time

# Share the hub's main logger so these messages appear with other hub output.
logger = logging.getLogger("Hub")

# Failed logins allowed for one username before lockout starts (env-tunable, default 5).
_LOGIN_MAX_FAILS = int(os.environ.get("LM_LOGIN_MAX_FAILS", "5"))
# First lockout length in seconds; it doubles for each further failure.
_LOGIN_BASE_LOCKOUT_S = float(os.environ.get("LM_LOGIN_BASE_LOCKOUT_S", "30"))
# Upper bound on any single lockout (1 hour) so accounts are never locked forever.
_LOGIN_MAX_LOCKOUT_S = float(os.environ.get("LM_LOGIN_MAX_LOCKOUT_S", "3600"))
# Length of the per-IP sliding window in seconds (5 minutes).
_LOGIN_IP_WINDOW_S = float(os.environ.get("LM_LOGIN_IP_WINDOW_S", "300"))
# Max login attempts from one IP inside that window before the IP is throttled.
_LOGIN_IP_MAX = int(os.environ.get("LM_LOGIN_IP_MAX", "20"))
# Cap on the number of distinct source IPs tracked in the spray window. A
# spoofed-XFF rotation (or a large fleet behind one proxy) would otherwise grow
# ``_login_ip_attempts`` without limit; past this cap the oldest buckets are
# evicted. Per-username lockout remains the real defense; this is memory hygiene.
_LOGIN_IP_TRACKED_MAX = int(os.environ.get("LM_LOGIN_IP_TRACKED_MAX", "4096"))
# Per-username lockout state; persisted to disk.
_login_attempts: dict = {}    # {username: {count, locked_until, first_fail}}
# Per-IP list of recent attempt timestamps; memory only.
_login_ip_attempts: dict = {}  # {ip: [ts,...]} (in-memory, not persisted)


def _login_attempts_file(hub) -> str:
    """Return the path of the JSON file that stores per-username lockout state."""
    # The file lives in the hub's data directory so it survives restarts.
    return os.path.join(hub.state.data_dir, "login_attempts.json")


def _save_login_attempts(hub) -> None:
    """Persist the per-username lockout counters (not the in-memory IP window)."""
    # Any disk problem is logged, never raised, so login handling keeps working.
    try:
        # Work out where the file goes and make sure its directory exists.
        path = _login_attempts_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Write to a temp file first so a crash mid-write never leaves a half-written file.
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_login_attempts, f)
        # Owner-only permissions: the file reveals which usernames are being attacked.
        os.chmod(tmp, 0o600)
        # Atomically swap the finished temp file into place.
        os.replace(tmp, path)
    # Persistence failed (disk full, permissions); warn and carry on with in-memory state.
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_attempts persist failed: %s", exc)


def _load_login_attempts(hub) -> None:
    """Rehydrate persisted per-username lockout counters on startup."""
    # A missing or corrupt file is non-fatal; we just start with empty counters.
    try:
        # Locate the file; nothing to load if it is absent or empty.
        path = _login_attempts_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        # Read the saved counters.
        with open(path) as f:
            data = json.load(f)
        # Only accept the expected dict shape, then merge into the in-memory table.
        if isinstance(data, dict):
            _login_attempts.update(data)
    # Unreadable/corrupt file: warn and continue with empty counters.
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:  # noqa: BLE001
        logger.warning("login_attempts load failed: %s", exc)


def _lockout_key(user_id: str) -> str:
    """Case-folded lockout key for a username. Pass this (not the raw username)
    to ``_login_check`` / ``_login_fail`` / ``_login_success`` so case-variant
    brute force ("admin", "Admin", "ADMIN", …) shares ONE counter and trips the
    throttle after N total tries instead of N tries × (case permutations).
    The raw username is still used for the case-sensitive user-store lookup."""
    # casefold() is a stronger lower() that also handles non-ASCII case variants.
    return (user_id or "").casefold()


def _login_check(user_id: str, ip: str):
    """Return ``(allowed, retry_after_seconds)`` for a login attempt.

    Blocks (with a Retry-After) when the username is in lockout OR the source IP
    has exceeded the spray window. ``retry_after_seconds`` is 0 when allowed."""
    # math.ceil rounds the retry-after value up to whole seconds.
    import math as _math
    # Current time used for both the IP window and the lockout check.
    now = time.time()
    # Per-IP spray window (credential stuffing across many usernames).
    ip_hits = [ts for ts in _login_ip_attempts.get(ip, [])
               if ts > now - _LOGIN_IP_WINDOW_S]
    # Store the trimmed list so old timestamps do not accumulate.
    if ip_hits:
        _login_ip_attempts[ip] = ip_hits
    else:
        # Drop an empty bucket so the dict doesn't retain a key per spoofed IP.
        _login_ip_attempts.pop(ip, None)
    # Too many attempts from this IP: block until the oldest hit falls out of the window.
    if len(ip_hits) >= _LOGIN_IP_MAX:
        return False, max(1, int(_math.ceil((ip_hits[0] + _LOGIN_IP_WINDOW_S) - now)))
    # Bound the number of tracked IPs (memory hygiene under XFF rotation).
    if len(_login_ip_attempts) > _LOGIN_IP_TRACKED_MAX:
        _prune_ip_buckets(_LOGIN_IP_TRACKED_MAX)
    # Per-username lockout.
    # Look up this username's lockout record, if any.
    rec = _login_attempts.get(user_id)
    # Still inside a lockout period: block and say how long to wait.
    if rec and rec.get("locked_until", 0) > now:
        return False, max(1, int(_math.ceil(rec["locked_until"] - now)))
    # Neither limit hit, so the attempt may proceed.
    return True, 0


def _prune_ip_buckets(max_keep: int) -> None:
    """Evict the oldest per-IP spray buckets past ``max_keep`` (by the newest
    timestamp in each bucket) so ``_login_ip_attempts`` can't grow unbounded
    under a spoofed-XFF rotation or a large fleet behind one proxy."""
    # Already within the limit; nothing to evict.
    if len(_login_ip_attempts) <= max_keep:
        return
    # Score each IP by its most recent attempt (0 for an empty bucket).
    scored = [(max(b) if b else 0, ip) for ip, b in _login_ip_attempts.items()]
    # Newest first, so the entries past max_keep are the stalest ones.
    scored.sort(reverse=True)
    # Drop every bucket beyond the keep limit.
    for _ts, ip in scored[max_keep:]:
        _login_ip_attempts.pop(ip, None)


def _login_fail(hub, user_id: str, ip: str, meta: dict = None) -> int:
    """Record a failed attempt; engage/extend exponential lockout when over the
    threshold. Returns the remaining lockout seconds (0 if not yet locked).

    ``meta`` is optional structured evidence (e.g. user-agent) forwarded to the
    threat monitor so the operator can drill into the attempt."""
    # math.ceil rounds the remaining lockout up to whole seconds.
    import math as _math
    # Timestamp of this failure.
    now = time.time()
    # IP spray accounting.
    _login_ip_attempts.setdefault(ip, []).append(now)
    # Keep the per-IP list bounded (don't grow without limit between prunes).
    _login_ip_attempts[ip] = _login_ip_attempts[ip][-(_LOGIN_IP_MAX * 4):]
    # Username lockout with exponential backoff, capped.
    # Fetch (or start) this username's failure record.
    rec = _login_attempts.get(user_id, {"count": 0, "locked_until": 0,
                                        "first_fail": now})
    # Count this failure.
    rec["count"] = int(rec.get("count", 0)) + 1
    # Past the threshold: lock for base * 2^(extra failures), but never above the max.
    if rec["count"] >= _LOGIN_MAX_FAILS:
        growth = min(_LOGIN_BASE_LOCKOUT_S *
                     (2 ** (rec["count"] - _LOGIN_MAX_FAILS)), _LOGIN_MAX_LOCKOUT_S)
        rec["locked_until"] = now + growth
    # Store the updated record and persist it so a restart does not reset the lockout.
    _login_attempts[user_id] = rec
    _save_login_attempts(hub)
    # Tell the threat monitor about the failure so repeated attacks can be flagged.
    try:
        hub.threat_monitor.record_failure(ip, "login", username=user_id, meta=meta)
    # The monitor is best-effort; a failure there must not break the login response.
    except Exception:  # noqa: BLE001 - the monitor must never break login handling
        pass
    # Return how many seconds the account stays locked (0 if not locked).
    return max(0, int(_math.ceil(rec.get("locked_until", 0) - now)))


def _login_success(hub, user_id: str, ip: str = None) -> None:
    """Clear a username's lockout counters (and its per-IP spray bucket) on a
    successful login — persisted (the username record) so a restart doesn't
    re-lock an account that just succeeded. The IP bucket is in-memory only."""
    # Tracks whether the persisted file needs rewriting.
    changed = False
    # Forget any failure history for this username after a good login.
    if user_id in _login_attempts:
        _login_attempts.pop(user_id, None)
        changed = True
    # Also clear this IP's spray bucket (memory only, so no save needed).
    if ip and ip in _login_ip_attempts:
        _login_ip_attempts.pop(ip, None)
    # Only touch the disk when the username record actually changed.
    if changed:
        _save_login_attempts(hub)
    # Let the threat monitor know this IP authenticated successfully.
    try:
        if ip:
            hub.threat_monitor.record_success(ip)
    # The monitor is best-effort; ignore any failure there.
    except Exception:  # noqa: BLE001
        pass
