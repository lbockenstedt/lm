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

import json
import logging
import os
import time

logger = logging.getLogger("Hub")

_LOGIN_MAX_FAILS = int(os.environ.get("LM_LOGIN_MAX_FAILS", "5"))
_LOGIN_BASE_LOCKOUT_S = float(os.environ.get("LM_LOGIN_BASE_LOCKOUT_S", "30"))
_LOGIN_MAX_LOCKOUT_S = float(os.environ.get("LM_LOGIN_MAX_LOCKOUT_S", "3600"))
_LOGIN_IP_WINDOW_S = float(os.environ.get("LM_LOGIN_IP_WINDOW_S", "300"))
_LOGIN_IP_MAX = int(os.environ.get("LM_LOGIN_IP_MAX", "20"))
# Cap on the number of distinct source IPs tracked in the spray window. A
# spoofed-XFF rotation (or a large fleet behind one proxy) would otherwise grow
# ``_login_ip_attempts`` without limit; past this cap the oldest buckets are
# evicted. Per-username lockout remains the real defense; this is memory hygiene.
_LOGIN_IP_TRACKED_MAX = int(os.environ.get("LM_LOGIN_IP_TRACKED_MAX", "4096"))
_login_attempts: dict = {}    # {username: {count, locked_until, first_fail}}
_login_ip_attempts: dict = {}  # {ip: [ts,...]} (in-memory, not persisted)


def _login_attempts_file(hub) -> str:
    return os.path.join(hub.state.data_dir, "login_attempts.json")


def _save_login_attempts(hub) -> None:
    """Persist the per-username lockout counters (not the in-memory IP window)."""
    try:
        path = _login_attempts_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_login_attempts, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_attempts persist failed: %s", exc)


def _load_login_attempts(hub) -> None:
    """Rehydrate persisted per-username lockout counters on startup."""
    try:
        path = _login_attempts_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            _login_attempts.update(data)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:  # noqa: BLE001
        logger.warning("login_attempts load failed: %s", exc)


def _lockout_key(user_id: str) -> str:
    """Case-folded lockout key for a username. Pass this (not the raw username)
    to ``_login_check`` / ``_login_fail`` / ``_login_success`` so case-variant
    brute force ("admin", "Admin", "ADMIN", …) shares ONE counter and trips the
    throttle after N total tries instead of N tries × (case permutations).
    The raw username is still used for the case-sensitive user-store lookup."""
    return (user_id or "").casefold()


def _login_check(user_id: str, ip: str):
    """Return ``(allowed, retry_after_seconds)`` for a login attempt.

    Blocks (with a Retry-After) when the username is in lockout OR the source IP
    has exceeded the spray window. ``retry_after_seconds`` is 0 when allowed."""
    import math as _math
    now = time.time()
    # Per-IP spray window (credential stuffing across many usernames).
    ip_hits = [ts for ts in _login_ip_attempts.get(ip, [])
               if ts > now - _LOGIN_IP_WINDOW_S]
    if ip_hits:
        _login_ip_attempts[ip] = ip_hits
    else:
        # Drop an empty bucket so the dict doesn't retain a key per spoofed IP.
        _login_ip_attempts.pop(ip, None)
    if len(ip_hits) >= _LOGIN_IP_MAX:
        return False, max(1, int(_math.ceil((ip_hits[0] + _LOGIN_IP_WINDOW_S) - now)))
    # Bound the number of tracked IPs (memory hygiene under XFF rotation).
    if len(_login_ip_attempts) > _LOGIN_IP_TRACKED_MAX:
        _prune_ip_buckets(_LOGIN_IP_TRACKED_MAX)
    # Per-username lockout.
    rec = _login_attempts.get(user_id)
    if rec and rec.get("locked_until", 0) > now:
        return False, max(1, int(_math.ceil(rec["locked_until"] - now)))
    return True, 0


def _prune_ip_buckets(max_keep: int) -> None:
    """Evict the oldest per-IP spray buckets past ``max_keep`` (by the newest
    timestamp in each bucket) so ``_login_ip_attempts`` can't grow unbounded
    under a spoofed-XFF rotation or a large fleet behind one proxy."""
    if len(_login_ip_attempts) <= max_keep:
        return
    scored = [(max(b) if b else 0, ip) for ip, b in _login_ip_attempts.items()]
    scored.sort(reverse=True)
    for _ts, ip in scored[max_keep:]:
        _login_ip_attempts.pop(ip, None)


def _login_fail(hub, user_id: str, ip: str) -> int:
    """Record a failed attempt; engage/extend exponential lockout when over the
    threshold. Returns the remaining lockout seconds (0 if not yet locked)."""
    import math as _math
    now = time.time()
    # IP spray accounting.
    _login_ip_attempts.setdefault(ip, []).append(now)
    # Keep the per-IP list bounded (don't grow without limit between prunes).
    _login_ip_attempts[ip] = _login_ip_attempts[ip][-(_LOGIN_IP_MAX * 4):]
    # Username lockout with exponential backoff, capped.
    rec = _login_attempts.get(user_id, {"count": 0, "locked_until": 0,
                                        "first_fail": now})
    rec["count"] = int(rec.get("count", 0)) + 1
    if rec["count"] >= _LOGIN_MAX_FAILS:
        growth = min(_LOGIN_BASE_LOCKOUT_S *
                     (2 ** (rec["count"] - _LOGIN_MAX_FAILS)), _LOGIN_MAX_LOCKOUT_S)
        rec["locked_until"] = now + growth
    _login_attempts[user_id] = rec
    _save_login_attempts(hub)
    try:
        hub.threat_monitor.record_failure(ip, "login", username=user_id)
    except Exception:  # noqa: BLE001 - the monitor must never break login handling
        pass
    return max(0, int(_math.ceil(rec.get("locked_until", 0) - now)))


def _login_success(hub, user_id: str, ip: str = None) -> None:
    """Clear a username's lockout counters (and its per-IP spray bucket) on a
    successful login — persisted (the username record) so a restart doesn't
    re-lock an account that just succeeded. The IP bucket is in-memory only."""
    changed = False
    if user_id in _login_attempts:
        _login_attempts.pop(user_id, None)
        changed = True
    if ip and ip in _login_ip_attempts:
        _login_ip_attempts.pop(ip, None)
    if changed:
        _save_login_attempts(hub)
    try:
        if ip:
            hub.threat_monitor.record_success(ip)
    except Exception:  # noqa: BLE001
        pass
