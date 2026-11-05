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
# hashlib hashes tokens so only their sha256 digests are stored.
import hashlib
# json reads/writes the persisted token file.
import json
# Standard-library logging for persistence and reuse-detection messages.
import logging
# os builds file paths and sets owner-only permissions on the token file.
import os
# secrets generates cryptographically strong random tokens and family ids.
import secrets
# time.time() supplies creation/expiry timestamps.
import time
# Type hints only.
from typing import Optional, Tuple

# One named logger so API-token messages can be filtered together.
logger = logging.getLogger("APITokens")

# Lifetime of an access token in seconds.
ACCESS_TTL_S = 4 * 3600            # 4 hours (per requirement)
# Lifetime of a refresh token in seconds.
REFRESH_TTL_S = 30 * 24 * 3600    # 30 days
# Max simultaneous token families per user; the oldest is revoked when exceeded.
MAX_TOKENS_PER_USER = 20          # live families per user
# How long a used refresh token is remembered so a replay of it can be detected.
_ROTATED_KEEP_S = 24 * 3600       # keep a rotated refresh this long for reuse detection

# sha256(token) -> record. Access rec: {user_id, user, expires, created, family,
# name}. Refresh rec: same + {rotated: bool}.
# Live access tokens keyed by hash.
_access: dict = {}
# Live (and recently rotated) refresh tokens keyed by hash.
_refresh: dict = {}

# Field names that look like secrets and must never be copied into a token record.
_SECRET_KEYS = ("password", "password_hash", "hash", "pw", "secret")


def _hash(tok: str) -> str:
    """Return the sha256 hex digest of a token; this is the lookup key, not the token itself."""
    # Hash the UTF-8 bytes; storing only the digest means a leaked file grants no access.
    return hashlib.sha256(tok.encode()).hexdigest()


def _tokens_file(hub) -> str:
    """Return the path of the JSON file holding persisted token records."""
    # Lives in the hub's data directory so tokens survive a restart.
    return os.path.join(hub.state.data_dir, "api_tokens.json")


def _snapshot(user: dict) -> dict:
    """Copy the user record for the token, stripping any secret-ish field so the
    0600 token file never holds a password hash."""
    # Keep every field except those whose (lower-cased) name looks secret.
    return {k: v for k, v in (user or {}).items() if k.lower() not in _SECRET_KEYS}


def _issue(hub, user_id, user_snapshot, family, name) -> Tuple[str, str, int]:
    """Create one access+refresh token pair in ``family`` and record both; returns (access,
    refresh, ttl).
    """
    # Single timestamp so both tokens share the same creation time.
    now = time.time()
    # 32 random bytes, URL-safe base64, for each token.
    access = secrets.token_urlsafe(32)
    refresh_tok = secrets.token_urlsafe(32)
    # Record the access token (by hash) with its owner, expiry and family.
    _access[_hash(access)] = {"user_id": user_id, "user": user_snapshot,
                              "expires": now + ACCESS_TTL_S, "created": now,
                              "family": family, "name": name}
    # Record the refresh token (by hash); "rotated" flips to True once it is used.
    _refresh[_hash(refresh_tok)] = {"user_id": user_id, "user": user_snapshot,
                                    "expires": now + REFRESH_TTL_S, "created": now,
                                    "family": family, "name": name, "rotated": False}
    # Return the raw tokens to the caller; they are never stored in raw form.
    return access, refresh_tok, ACCESS_TTL_S


def issue_pair(hub, user_id: str, user: dict, name: str = "") -> Tuple[str, str, int]:
    """Mint a new access+refresh pair for ``user_id``. Returns
    (access_token, refresh_token, access_expires_in_seconds)."""
    # Make room first if the user already has the maximum number of token families.
    _enforce_cap(user_id)
    # Issue the pair under a brand-new random family id with a default display name.
    access, refresh_tok, ttl = _issue(hub, user_id, _snapshot(user),
                                      secrets.token_hex(8), name or "api token")
    # Persist so the new tokens survive a hub restart.
    _save(hub)
    return access, refresh_tok, ttl


def refresh(hub, refresh_token: str) -> Optional[Tuple[str, str, int]]:
    """Rotate a refresh token into a NEW access+refresh pair (same family).
    Returns the new pair, or None (invalid / expired / reuse-detected)."""
    # Look the presented token up by its hash.
    h = _hash(refresh_token)
    rec = _refresh.get(h)
    # Current time for expiry checks.
    now = time.time()
    # Unknown or expired token: reject (and drop an expired record from the store).
    if not rec or rec.get("expires", 0) < now:
        if rec:
            _refresh.pop(h, None); _save(hub)
        return None
    # Already-used refresh token presented again.
    if rec.get("rotated"):
        # A rotated refresh presented again → likely stolen → revoke the family.
        logger.warning("API refresh-token REUSE (user %s) — revoking token family",
                       rec.get("user_id"))
        _revoke_families({rec.get("family")}); _save(hub)
        return None
    # Mark this refresh token as used, remembering when, so a replay can be caught later.
    rec["rotated"] = True                    # keep briefly for reuse detection
    rec["rotated_at"] = now
    # The new pair stays in the same family as the old one.
    fam = rec.get("family")
    # Remove the family's previous access token so only the newest one works.
    for ah in [k for k, r in _access.items() if r.get("family") == fam]:
        _access.pop(ah, None)                # invalidate the old access token
    # Issue the replacement pair using the stored user snapshot and token name.
    access, new_refresh, ttl = _issue(hub, rec["user_id"], rec.get("user", {}), fam,
                                      rec.get("name", "api token"))
    # Persist the rotation.
    _save(hub)
    return access, new_refresh, ttl


def bearer_session(request):
    """Resolve an ``Authorization: Bearer <access>`` header to a session-shaped
    dict (same keys as api.py ``_sessions``) or None. Marked ``api_token``."""
    # Read the Authorization header (checking both capitalisations).
    auth = (request.headers.get("Authorization")
            or request.headers.get("authorization") or "")
    # Only "Bearer <token>" headers are API tokens; anything else is not ours.
    if not auth.startswith("Bearer "):
        return None
    # Strip the "Bearer " prefix (7 characters) and whitespace to get the raw token.
    tok = auth[7:].strip()
    # Empty token after the prefix: reject.
    if not tok:
        return None
    # Look the token up by hash; reject unknown or expired tokens.
    rec = _access.get(_hash(tok))
    if not rec or rec.get("expires", 0) < time.time():
        return None
    # Build a dict shaped like a WebUI session so existing permission checks work unchanged.
    return {"user_id": rec.get("user_id"), "user": rec.get("user", {}),
            "expires": rec.get("expires"), "created": rec.get("created"),
            "last_seen": time.time(), "sid": rec.get("family"), "api_token": True}


def list_tokens(user_id: str) -> list:
    """Metadata for a user's live token families (no secrets)."""
    # Current time for expiry checks.
    now = time.time()
    # One entry per family, keyed by family id.
    fam: dict = {}
    # Only live (unused, unexpired) refresh tokens represent active families.
    for r in _refresh.values():
        if (r.get("user_id") == user_id and not r.get("rotated")
                and r.get("expires", 0) > now):
            fam[r.get("family")] = {"id": r.get("family"), "name": r.get("name", ""),
                                    "created": r.get("created"), "expires": r.get("expires")}
    # Oldest first.
    return sorted(fam.values(), key=lambda x: x.get("created") or 0)


def revoke(hub, user_id: str, family_id: str) -> bool:
    """Revoke one token family owned by ``user_id``."""
    # Families matching this id that belong to this user (refresh side)...
    owned = {r.get("family") for r in _refresh.values()
             if r.get("user_id") == user_id and r.get("family") == family_id}
    # ...plus the access side, so a family is found even if only one half remains.
    owned |= {r.get("family") for r in _access.values()
              if r.get("user_id") == user_id and r.get("family") == family_id}
    # Not this user's family (or does not exist): refuse.
    if not owned:
        return False
    # Revoke and persist.
    _revoke_families(owned); _save(hub)
    return True


def _revoke_families(families: set) -> None:
    """Remove every access and refresh token belonging to any of the given families."""
    # Ignore empty/None family ids.
    families = {f for f in families if f}
    # Nothing to revoke.
    if not families:
        return
    # Drop the families' access tokens.
    for h in [k for k, r in _access.items() if r.get("family") in families]:
        _access.pop(h, None)
    # Drop the families' refresh tokens.
    for h in [k for k, r in _refresh.items() if r.get("family") in families]:
        _refresh.pop(h, None)


def invalidate_user(hub, user_id: str) -> int:
    """Drop ALL of a user's tokens — called on password / permission / role
    change (mirrors _invalidate_user_sessions). Returns families dropped."""
    # Every family this user owns, from both stores.
    fams = {r.get("family") for r in _refresh.values() if r.get("user_id") == user_id}
    fams |= {r.get("family") for r in _access.values() if r.get("user_id") == user_id}
    # Ignore empty/None family ids.
    fams = {f for f in fams if f}
    # Revoke them all and persist, if there were any.
    if fams:
        _revoke_families(fams); _save(hub)
    return len(fams)


def _enforce_cap(user_id) -> None:
    """Revoke the user's oldest token families so a new one fits under MAX_TOKENS_PER_USER."""
    # Current time for expiry checks.
    now = time.time()
    # Map of live family id -> creation time for this user.
    live = {}
    # A family is live while its current refresh token is unused and unexpired.
    for r in _refresh.values():
        if (r.get("user_id") == user_id and not r.get("rotated")
                and r.get("expires", 0) > now):
            live[r.get("family")] = r.get("created", 0)
    # At (or over) the cap: revoke enough of the oldest families to leave room for one more.
    if len(live) >= MAX_TOKENS_PER_USER:
        oldest = sorted(live.items(), key=lambda kv: kv[1])
        _revoke_families({f for f, _ in oldest[:len(live) - MAX_TOKENS_PER_USER + 1]})


def _save(hub) -> None:
    """Atomically persist (hashes + metadata only), pruning expired + stale
    rotated. Best-effort; never raises."""
    # Persistence is best-effort; a disk problem is logged, never raised.
    try:
        # Only keep unexpired access tokens.
        now = time.time()
        acc = {h: r for h, r in _access.items() if r.get("expires", 0) > now}
        # Keep unexpired refresh tokens, but drop rotated ones older than the reuse-detection
        # window.
        ref = {h: r for h, r in _refresh.items()
               if r.get("expires", 0) > now
               and not (r.get("rotated") and now - r.get("rotated_at", 0) > _ROTATED_KEEP_S)}
        # Make sure the data directory exists.
        path = _tokens_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Write to a temp file first so a crash cannot leave a half-written file.
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"access": acc, "refresh": ref}, f)
        # Owner-only permissions, then atomically replace the old file.
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    # Disk full / permission problems: warn and keep running with in-memory tokens.
    except Exception as exc:  # noqa: BLE001
        logger.warning("api-token persist failed: %s", exc)


def load(hub) -> None:
    """Rehydrate the token stores on startup (best-effort; drops expired)."""
    # Loading is best-effort; a bad file just means starting with no tokens.
    try:
        # Nothing to load if the file is absent or empty.
        path = _tokens_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        # Read the saved stores.
        with open(path) as f:
            data = json.load(f)
        # Ignore a file with an unexpected shape.
        if not isinstance(data, dict):
            return
        # Current time for expiry checks.
        now = time.time()
        # Restore only unexpired, well-formed access records.
        for h, r in (data.get("access") or {}).items():
            if isinstance(r, dict) and r.get("expires", 0) > now:
                _access[h] = r
        # Restore only unexpired, well-formed refresh records.
        for h, r in (data.get("refresh") or {}).items():
            if isinstance(r, dict) and r.get("expires", 0) > now:
                _refresh[h] = r
        # Log how many tokens were restored.
        if _access or _refresh:
            logger.info("Restored %d API access + %d refresh token(s) from disk",
                        len(_access), len(_refresh))
    # Corrupt/unreadable file: warn and continue.
    except Exception as exc:  # noqa: BLE001
        logger.warning("api-token load failed: %s", exc)
