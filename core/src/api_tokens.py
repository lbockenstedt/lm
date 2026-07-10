"""User API tokens — Bearer access tokens + refresh tokens.

Separate from the WebUI cookie sessions (``api.py`` ``_sessions``): these are for
PROGRAMMATIC API access. Design:

- **Access token** (``Authorization: Bearer <token>``) — short-lived (4h). It
  resolves via ``bearer_session()`` to a session-shaped dict so every existing
  ``access.*`` gate (is_admin / has_*_access / tenant) works unchanged.
- **Refresh token** — longer-lived (30d). ``refresh()`` consumes it and issues a
  brand-new access+refresh pair in the same "family" (SEAMLESS rotation — the
  client swaps in the new access token, no re-login).
- **Reuse detection** — a refresh token can be used ONCE; presenting an
  already-rotated one revokes the whole family (a theft signal).

Tokens are stored HASHED (sha256), so the persisted file (0600) never holds a
usable credential. Persisted like sessions so tokens survive a hub restart.
User permissions travel as a snapshot (secret fields stripped); a
password/permission/role change calls ``invalidate_user`` to drop the user's
tokens, mirroring ``_invalidate_user_sessions``.
"""
import hashlib
import json
import logging
import os
import secrets
import time
from typing import Optional, Tuple

logger = logging.getLogger("APITokens")

ACCESS_TTL_S = 4 * 3600            # 4 hours (per requirement)
REFRESH_TTL_S = 30 * 24 * 3600    # 30 days
MAX_TOKENS_PER_USER = 20          # live families per user
_ROTATED_KEEP_S = 24 * 3600       # keep a rotated refresh this long for reuse detection

# sha256(token) -> record. Access rec: {user_id, user, expires, created, family,
# name}. Refresh rec: same + {rotated: bool}.
_access: dict = {}
_refresh: dict = {}

_SECRET_KEYS = ("password", "password_hash", "hash", "pw", "secret")


def _hash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def _tokens_file(hub) -> str:
    return os.path.join(hub.state.data_dir, "api_tokens.json")


def _snapshot(user: dict) -> dict:
    """Copy the user record for the token, stripping any secret-ish field so the
    0600 token file never holds a password hash."""
    return {k: v for k, v in (user or {}).items() if k.lower() not in _SECRET_KEYS}


def _issue(hub, user_id, user_snapshot, family, name) -> Tuple[str, str, int]:
    now = time.time()
    access = secrets.token_urlsafe(32)
    refresh_tok = secrets.token_urlsafe(32)
    _access[_hash(access)] = {"user_id": user_id, "user": user_snapshot,
                              "expires": now + ACCESS_TTL_S, "created": now,
                              "family": family, "name": name}
    _refresh[_hash(refresh_tok)] = {"user_id": user_id, "user": user_snapshot,
                                    "expires": now + REFRESH_TTL_S, "created": now,
                                    "family": family, "name": name, "rotated": False}
    return access, refresh_tok, ACCESS_TTL_S


def issue_pair(hub, user_id: str, user: dict, name: str = "") -> Tuple[str, str, int]:
    """Mint a new access+refresh pair for ``user_id``. Returns
    (access_token, refresh_token, access_expires_in_seconds)."""
    _enforce_cap(user_id)
    access, refresh_tok, ttl = _issue(hub, user_id, _snapshot(user),
                                      secrets.token_hex(8), name or "api token")
    _save(hub)
    return access, refresh_tok, ttl


def refresh(hub, refresh_token: str) -> Optional[Tuple[str, str, int]]:
    """Rotate a refresh token into a NEW access+refresh pair (same family).
    Returns the new pair, or None (invalid / expired / reuse-detected)."""
    h = _hash(refresh_token)
    rec = _refresh.get(h)
    now = time.time()
    if not rec or rec.get("expires", 0) < now:
        if rec:
            _refresh.pop(h, None); _save(hub)
        return None
    if rec.get("rotated"):
        # A rotated refresh presented again → likely stolen → revoke the family.
        logger.warning("API refresh-token REUSE (user %s) — revoking token family",
                       rec.get("user_id"))
        _revoke_families({rec.get("family")}); _save(hub)
        return None
    rec["rotated"] = True                    # keep briefly for reuse detection
    rec["rotated_at"] = now
    fam = rec.get("family")
    for ah in [k for k, r in _access.items() if r.get("family") == fam]:
        _access.pop(ah, None)                # invalidate the old access token
    access, new_refresh, ttl = _issue(hub, rec["user_id"], rec.get("user", {}), fam,
                                      rec.get("name", "api token"))
    _save(hub)
    return access, new_refresh, ttl


def bearer_session(request):
    """Resolve an ``Authorization: Bearer <access>`` header to a session-shaped
    dict (same keys as api.py ``_sessions``) or None. Marked ``api_token``."""
    auth = (request.headers.get("Authorization")
            or request.headers.get("authorization") or "")
    if not auth.startswith("Bearer "):
        return None
    tok = auth[7:].strip()
    if not tok:
        return None
    rec = _access.get(_hash(tok))
    if not rec or rec.get("expires", 0) < time.time():
        return None
    return {"user_id": rec.get("user_id"), "user": rec.get("user", {}),
            "expires": rec.get("expires"), "created": rec.get("created"),
            "last_seen": time.time(), "sid": rec.get("family"), "api_token": True}


def list_tokens(user_id: str) -> list:
    """Metadata for a user's live token families (no secrets)."""
    now = time.time()
    fam: dict = {}
    for r in _refresh.values():
        if (r.get("user_id") == user_id and not r.get("rotated")
                and r.get("expires", 0) > now):
            fam[r.get("family")] = {"id": r.get("family"), "name": r.get("name", ""),
                                    "created": r.get("created"), "expires": r.get("expires")}
    return sorted(fam.values(), key=lambda x: x.get("created") or 0)


def revoke(hub, user_id: str, family_id: str) -> bool:
    """Revoke one token family owned by ``user_id``."""
    owned = {r.get("family") for r in _refresh.values()
             if r.get("user_id") == user_id and r.get("family") == family_id}
    owned |= {r.get("family") for r in _access.values()
              if r.get("user_id") == user_id and r.get("family") == family_id}
    if not owned:
        return False
    _revoke_families(owned); _save(hub)
    return True


def _revoke_families(families: set) -> None:
    families = {f for f in families if f}
    if not families:
        return
    for h in [k for k, r in _access.items() if r.get("family") in families]:
        _access.pop(h, None)
    for h in [k for k, r in _refresh.items() if r.get("family") in families]:
        _refresh.pop(h, None)


def invalidate_user(hub, user_id: str) -> int:
    """Drop ALL of a user's tokens — called on password / permission / role
    change (mirrors _invalidate_user_sessions). Returns families dropped."""
    fams = {r.get("family") for r in _refresh.values() if r.get("user_id") == user_id}
    fams |= {r.get("family") for r in _access.values() if r.get("user_id") == user_id}
    fams = {f for f in fams if f}
    if fams:
        _revoke_families(fams); _save(hub)
    return len(fams)


def _enforce_cap(user_id) -> None:
    now = time.time()
    live = {}
    for r in _refresh.values():
        if (r.get("user_id") == user_id and not r.get("rotated")
                and r.get("expires", 0) > now):
            live[r.get("family")] = r.get("created", 0)
    if len(live) >= MAX_TOKENS_PER_USER:
        oldest = sorted(live.items(), key=lambda kv: kv[1])
        _revoke_families({f for f, _ in oldest[:len(live) - MAX_TOKENS_PER_USER + 1]})


def _save(hub) -> None:
    """Atomically persist (hashes + metadata only), pruning expired + stale
    rotated. Best-effort; never raises."""
    try:
        now = time.time()
        acc = {h: r for h, r in _access.items() if r.get("expires", 0) > now}
        ref = {h: r for h, r in _refresh.items()
               if r.get("expires", 0) > now
               and not (r.get("rotated") and now - r.get("rotated_at", 0) > _ROTATED_KEEP_S)}
        path = _tokens_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"access": acc, "refresh": ref}, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("api-token persist failed: %s", exc)


def load(hub) -> None:
    """Rehydrate the token stores on startup (best-effort; drops expired)."""
    try:
        path = _tokens_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        now = time.time()
        for h, r in (data.get("access") or {}).items():
            if isinstance(r, dict) and r.get("expires", 0) > now:
                _access[h] = r
        for h, r in (data.get("refresh") or {}).items():
            if isinstance(r, dict) and r.get("expires", 0) > now:
                _refresh[h] = r
        if _access or _refresh:
            logger.info("Restored %d API access + %d refresh token(s) from disk",
                        len(_access), len(_refresh))
    except Exception as exc:  # noqa: BLE001
        logger.warning("api-token load failed: %s", exc)
