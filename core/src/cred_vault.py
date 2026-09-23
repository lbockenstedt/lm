"""Per-tenant + admin-slot credential vault (hub-side, Key Vault-backed).

A general-purpose secret locker that lets a **tenant-admin** store/retrieve their
OWN tenant's named credentials, plus a special non-tenant **admin slot**
(``__admin__``) for infrastructure credentials (e.g. the Hurricane Electric DNS
account) that belong to no tenant. Built on :mod:`cloud_vault`, the generic
Azure/OCI Vault dispatcher — so no code here ever knows or cares WHICH cloud
vault backend is active; it just calls ``cloud_vault.get_secret`` /
``set_secret`` / ``delete_secret`` and whichever provider is currently
``enabled`` (Azure Key Vault or OCI Vault) handles the request.

Storage backend is transparent: when a cloud vault is configured/enabled the
encrypted ciphertext is stored there; on a standalone/vault-less deployment
(the hub running as a plain local VM, or one with neither vault enabled) it
falls back to an encrypted-blob map in hub state. The ciphertext is
Fernet-encrypted either way, so the vault is *used when available* but never
*required*.

Security model (decided with the operator)
------------------------------------------
* **Reach = role, decrypt = PSK.** Which buckets a caller can *reach* is decided
  by role (tenant-admin → their own bucket; Global Admin → any bucket + the
  ``__admin__`` slot). Whether they can actually *decrypt* is decided by a
  per-bucket **PSK** (pass-phrase) the caller must supply. The PSK is verified
  against a stored scrypt verifier before any read/write.
* **Per-secret mode — the automation opt-in.** Each secret is stored in one of
  two modes:

  - ``psk`` (default, strongest): the value is encrypted with a key *derived
    from the bucket PSK* (scrypt). Neither the hub nor the cloud vault backend
    can read it without the PSK — a human must supply it for every reveal. No
    unattended access.
  - ``hub`` (automation-readable): the value is encrypted with the hub's
    at-rest Fernet key (:data:`security.encryption.hub_encryption`). The hub can
    decrypt it unattended, so tooling (e.g. a cert-renewal run pulling the HE
    account, or the console auto-identify loop) can fetch it with no human in the
    loop. Interactive reveal STILL requires the PSK; only :func:`automation_get`
    bypasses it, and only for ``hub``-mode secrets.

At rest the ciphertext lives in whichever cloud vault is currently enabled
(Azure Key Vault or OCI Vault — each provider's own encryption + RBAC/IAM)
under an opaque ``cred-<uuid>`` name; the hub keeps only non-secret
**metadata** (names, mode, type, description, timestamps, per-secret salt,
PSK verifier) in the Fernet-encrypted hub state — never a plaintext value.
"""
from __future__ import annotations

import base64
import copy
import hmac
import json
import logging
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import httpx
import asyncio

import cloud_vault as _cv
from security.encryption import hub_encryption
from security import sentinel

logger = logging.getLogger("CredVault")

_AUTOMATION_CACHE: Dict[Tuple[str, str, str], Tuple[float, Any]] = {}
_AUTOMATION_CACHE_TTL: float = 60.0  # seconds

def _cache_key(bucket: str, name: str, updated_at: str) -> Tuple[str, str, str]:
    return (bucket, name, str(updated_at or ""))

def _cache_get(key: Tuple[str, str, str]) -> Optional[Any]:
    """Return a copy of the cached value, never the stored object itself —
    callers may freely mutate what they get back without poisoning the shared
    60s-TTL cache entry for every other reader in that window."""
    entry = _AUTOMATION_CACHE.get(key)
    if entry is not None and (time.time() - entry[0]) < _AUTOMATION_CACHE_TTL:
        return copy.deepcopy(entry[1])
    if entry is not None:
        _AUTOMATION_CACHE.pop(key, None)
    return None

def _cache_set(key: Tuple[str, str, str], value: Any) -> None:
    _AUTOMATION_CACHE[key] = (time.time(), value)

def _cache_invalidate(bucket: str, name: Optional[str] = None) -> None:
    to_del = [k for k in _AUTOMATION_CACHE if k[0] == bucket and (name is None or k[1] == name)]
    for k in to_del:
        _AUTOMATION_CACHE.pop(k, None)

ADMIN_BUCKET = "__admin__"          # the non-tenant "Global Admin slot"
_KV_PREFIX = "cred-"                # opaque cloud-vault secret-name prefix
# Canary / honeytoken secret name (§5J-J1). A decoy secret provisioned under this
# name is NEVER read by any legitimate code path, so ANY read of it — via any
# vault entry point — is malicious by definition and trips the sentinel canary.
CANARY_SECRET = "__canary__"
sentinel.register_canary("vault.canary")
_MODE_PSK = "psk"
_MODE_HUB = "hub"
_MODES = (_MODE_PSK, _MODE_HUB)
_STORE_KV = "kv"                    # ciphertext lives in the active cloud vault
_STORE_LOCAL = "local"             # ciphertext lives in hub state (no-KV deploy)

# scrypt work factors (N,r,p) — ~16 MiB memory, interactive-fast.
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1


class CredVaultError(Exception):
    """Raised for any credential-vault failure; message is safe to surface."""


class CredVaultEngineError(CredVaultError):
    """Raised when the PSK crypto engine (scrypt) fails at runtime — as opposed
    to a genuine pass-phrase mismatch.

    Kept distinct so a transient crypto/resource failure (e.g. an allocation or
    OpenSSL-backend error deriving the ~16 MiB scrypt hash) is never silently
    reported as ``"incorrect pass-phrase"`` for every bucket/tenant at once.
    Subclasses :class:`CredVaultError` so existing handlers still catch it, but
    the route layer maps it to HTTP 503 (server error) rather than 400."""


# ── low-level crypto helpers ────────────────────────────────────────────────
def _scrypt(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R,
                  p=_SCRYPT_P).derive(password.encode("utf-8"))


def _psk_fernet(psk: str, salt: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_scrypt(psk, salt)))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(txt: str) -> bytes:
    return base64.b64decode(txt.encode("ascii"))


def _now() -> int:
    return int(time.time())


# ── metadata (hub state) ────────────────────────────────────────────────────
def _meta(hub) -> Dict[str, Any]:
    """The persistent metadata blob under ``global_config["cred_vault"]``.

    Shape: ``{"buckets": {bucket: {"psk": {salt,hash}, "created_at": ...}},
    "secrets": {bucket: {name: {mode,type,description,kv_name,salt,store,...}}},
    "blobs": {kv_name: ciphertext}}``. Plaintext is NEVER stored here. When a
    cloud vault (Azure Key Vault or OCI Vault) is enabled the ciphertext lives
    there; on a vault-less deployment it falls back to the encrypted ``blobs``
    map (the ciphertext is already Fernet-encrypted, exactly like the other
    at-rest encrypted blobs in hub state)."""
    gc = hub.state.system_state.setdefault("global_config", {})
    cv = gc.setdefault("cred_vault", {})
    cv.setdefault("buckets", {})
    cv.setdefault("secrets", {})
    cv.setdefault("blobs", {})
    return cv


def _save(hub) -> None:
    hub.state._mark_dirty()


def _vault_available(hub) -> bool:
    """True when a cloud vault (Azure Key Vault or OCI Vault) is enabled.
    Standalone hubs deployed as a plain VM without a vault — or with neither
    provider enabled — return False and transparently use the local
    encrypted-blob store instead."""
    try:
        return _cv.active_provider(hub) is not None
    except Exception:  # noqa: BLE001
        return False


# ── storage backend (cloud vault when configured, else local hub state) ─────
def _secret_store(sm: Dict[str, Any]) -> str:
    """Which backend a stored secret lives in (``kv`` for pre-existing records
    without an explicit marker — they were vault-only before this fallback)."""
    return sm.get("store") or _STORE_KV


async def _store_put(hub, kv_name: str, token: str, store: str) -> None:
    if store == _STORE_LOCAL:
        _meta(hub)["blobs"][kv_name] = token
    else:
        await _cv.set_secret(hub, kv_name, token)


async def _store_get(hub, kv_name: str, store: str, http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    if store == _STORE_LOCAL:
        return _meta(hub)["blobs"].get(kv_name)
    return await _cv.get_secret(hub, kv_name, http=http)


async def _store_del(hub, kv_name: str, store: str) -> None:
    if store == _STORE_LOCAL:
        _meta(hub)["blobs"].pop(kv_name, None)
        return
    # Best-effort: metadata removal proceeds even if the vault delete
    # 404s/soft-deletes/fails — cloud_vault.delete_secret already swallows
    # backend-specific errors and returns False rather than raising.
    await _cv.delete_secret(hub, kv_name)


# ── bucket / PSK management ─────────────────────────────────────────────────
def bucket_has_psk(hub, bucket: str) -> bool:
    return bool(_meta(hub)["buckets"].get(bucket, {}).get("psk"))


def verify_psk(hub, bucket: str, psk: str) -> bool:
    rec = _meta(hub)["buckets"].get(bucket, {}).get("psk")
    if not rec or not psk:
        return False
    try:
        expect = _unb64(rec["hash"])
        got = _scrypt(psk, _unb64(rec["salt"]))
    except Exception as exc:  # noqa: BLE001
        # A failure HERE is a crypto-engine / resource error (scrypt derivation
        # or verifier decode), NOT a wrong pass-phrase. Silently returning False
        # would make a transient failure look like a fleet-wide "incorrect
        # pass-phrase" for EVERY bucket/tenant, with no trace in the logs. Log it
        # loudly and raise a distinct error so it is diagnosable and surfaced.
        logger.error(
            "PSK verification ENGINE FAILURE for bucket %r: %s: %s — this is a "
            "server crypto/resource error, NOT a wrong pass-phrase (check hub "
            "memory and the OpenSSL/cryptography backend)",
            bucket, type(exc).__name__, exc, exc_info=True)
        raise CredVaultEngineError(
            "pass-phrase check failed due to a server crypto error (not a wrong "
            "pass-phrase) — check the hub logs and retry") from exc
    return hmac.compare_digest(expect, got)


def _require_psk(hub, bucket: str, psk: str) -> None:
    if not bucket_has_psk(hub, bucket):
        raise CredVaultError("this bucket has no pass-phrase set yet — set one before storing secrets")
    if not verify_psk(hub, bucket, psk):
        raise CredVaultError("incorrect pass-phrase")


async def set_bucket_psk(hub, bucket: str, new_psk: str, old_psk: Optional[str] = None) -> None:
    """Set or rotate a bucket's PSK. Rotating re-encrypts every ``psk``-mode
    secret in the bucket under the new key (``hub``-mode secrets are unaffected —
    they're keyed on the hub Fernet key, not the PSK)."""
    new_psk = (new_psk or "").strip()
    if len(new_psk) < 8:
        raise CredVaultError("pass-phrase must be at least 8 characters")
    cv = _meta(hub)
    existing = cv["buckets"].get(bucket, {}).get("psk")
    if existing:
        if not verify_psk(hub, bucket, old_psk or ""):
            raise CredVaultError("incorrect current pass-phrase")
        await _rekey_bucket(hub, bucket, old_psk or "", new_psk)
    salt = secrets.token_bytes(16)
    cv["buckets"].setdefault(bucket, {})
    cv["buckets"][bucket]["psk"] = {"salt": _b64(salt), "hash": _b64(_scrypt(new_psk, salt))}
    cv["buckets"][bucket].setdefault("created_at", _now())
    cv["buckets"][bucket]["updated_at"] = _now()
    _save(hub)


async def _rekey_bucket(hub, bucket: str, old_psk: str, new_psk: str) -> None:
    cv = _meta(hub)
    for name, sm in list(cv["secrets"].get(bucket, {}).items()):
        if sm.get("mode") != _MODE_PSK:
            continue
        value = await _fetch_and_decrypt(hub, bucket, name, psk=old_psk)
        salt = secrets.token_bytes(16)
        token = _psk_fernet(new_psk, salt).encrypt(json.dumps(value).encode("utf-8")).decode("ascii")
        await _store_put(hub, sm["kv_name"], token, _secret_store(sm))
        sm["salt"] = _b64(salt)
        sm["updated_at"] = _now()
    _save(hub)


def count_psk_secrets(hub, bucket: str) -> int:
    """How many secrets in ``bucket`` are encrypted UNDER THE BUCKET PSK, and
    are therefore unrecoverable if the pass-phrase is lost. ``hub``-mode secrets
    are keyed on the hub Fernet key instead, so they survive a lost pass-phrase
    (and keep working for automation) — they are not counted here."""
    return sum(1 for sm in (_meta(hub)["secrets"].get(bucket, {}) or {}).values()
               if sm.get("mode", _MODE_PSK) == _MODE_PSK)


async def reset_bucket_psk(hub, bucket: str, new_psk: str, *,
                           destroy_psk_secrets: bool = False,
                           actor: str = "") -> Dict[str, Any]:
    """Forgotten-pass-phrase escape hatch for a bucket (Global-Admin only —
    the caller MUST enforce that).

    ``set_bucket_psk`` can only ROTATE a pass-phrase, because it verifies the
    old one first. That is correct for a rotation but left a lost pass-phrase
    with no recovery at all: the bucket became permanently unusable through the
    UI even when nothing in it was actually encrypted under that pass-phrase.

    This resets the verifier WITHOUT the old pass-phrase:

    * ``hub``-mode secrets are untouched and keep working — they are encrypted
      with the hub Fernet key, never with the PSK. A bucket holding only
      ``hub``-mode secrets therefore resets with **zero** data loss.
    * ``psk``-mode secrets are already undecryptable (their key died with the
      pass-phrase), so they can only be discarded. That is refused unless the
      caller explicitly passes ``destroy_psk_secrets``, so the destructive case
      is always a deliberate, acknowledged act.

    Returns a summary of what happened for the audit log / UI.
    """
    new_psk = (new_psk or "").strip()
    if len(new_psk) < 8:
        raise CredVaultError("pass-phrase must be at least 8 characters")
    cv = _meta(hub)
    doomed = [n for n, sm in (cv["secrets"].get(bucket, {}) or {}).items()
              if sm.get("mode", _MODE_PSK) == _MODE_PSK]
    if doomed and not destroy_psk_secrets:
        raise CredVaultError(
            f"{len(doomed)} secret(s) in this bucket are encrypted with the lost "
            f"pass-phrase and CANNOT be recovered: {', '.join(sorted(doomed))}. "
            "Re-run the reset with confirmation to discard them and set a new "
            "pass-phrase.")
    for name in doomed:
        sm = cv["secrets"][bucket][name]
        try:
            await _store_del(hub, sm["kv_name"], _secret_store(sm))
        except Exception as exc:  # noqa: BLE001 — the blob is unreadable anyway
            logger.warning("cred-vault: reset could not delete blob for %s/%s: %s",
                           bucket, name, exc)
        del cv["secrets"][bucket][name]
        _cache_invalidate(bucket, name)
    salt = secrets.token_bytes(16)
    cv["buckets"].setdefault(bucket, {})
    cv["buckets"][bucket]["psk"] = {"salt": _b64(salt), "hash": _b64(_scrypt(new_psk, salt))}
    cv["buckets"][bucket].setdefault("created_at", _now())
    cv["buckets"][bucket]["updated_at"] = _now()
    _save(hub)
    kept = len(cv["secrets"].get(bucket, {}) or {})
    logger.warning("cred-vault: pass-phrase RESET (no old pass-phrase) for bucket "
                   "%s by %s — %d psk-mode secret(s) discarded, %d hub-mode "
                   "secret(s) kept", bucket, actor or "?", len(doomed), kept)
    return {"bucket": bucket, "destroyed": sorted(doomed), "kept": kept}


async def move_secret(hub, bucket: str, name: str, to_bucket: str, *,
                      psk: str = "", to_psk: str = "", actor: str = "") -> Dict[str, Any]:
    """Move one secret to another bucket, keeping its Key Vault blob.

    The at-rest blob name is a random id, not derived from the bucket, so a move
    is a metadata re-point rather than a copy-and-delete — there is no window
    where the credential exists twice or not at all.

    * ``hub``-mode secrets are encrypted with the hub Fernet key, which does not
      depend on the bucket, so no pass-phrase is needed for either side. The
      payload is re-encrypted purely to refresh its embedded ``_bucket`` marker.
    * ``psk``-mode secrets are keyed on the SOURCE bucket's pass-phrase, so both
      ``psk`` and ``to_psk`` must be supplied and the value is re-encrypted
      under the destination bucket's key.

    This is the rescue path for a credential stranded in an orphaned bucket:
    move it somewhere tenant-scoped code can actually reference, then delete the
    orphan.
    """
    to_bucket = (to_bucket or "").strip()
    if not to_bucket:
        raise CredVaultError("destination bucket is required")
    if to_bucket == bucket:
        raise CredVaultError("source and destination buckets are the same")
    cv = _meta(hub)
    sm = cv["secrets"].get(bucket, {}).get(name)
    if not sm:
        raise CredVaultError(f"secret '{name}' not found")
    if cv["secrets"].get(to_bucket, {}).get(name):
        raise CredVaultError(
            f"'{to_bucket}' already has a secret named '{name}' — rename or "
            "remove it first (a move must never silently overwrite a credential)")
    if not bucket_has_psk(hub, to_bucket):
        raise CredVaultError("the destination bucket has no pass-phrase set yet")

    mode = sm.get("mode", _MODE_PSK)
    if mode == _MODE_HUB:
        value = await _fetch_and_decrypt(hub, bucket, name, psk=None)
        payload = dict(value)
        payload["_bucket"], payload["_name"] = to_bucket, name
        token = hub_encryption.encrypt(json.dumps(payload)).decode("ascii")
        salt = ""
    else:
        _require_psk(hub, bucket, psk)
        _require_psk(hub, to_bucket, to_psk)
        value = await _fetch_and_decrypt(hub, bucket, name, psk=psk)
        payload = dict(value)
        payload["_bucket"], payload["_name"] = to_bucket, name
        salt_bytes = secrets.token_bytes(16)
        token = _psk_fernet(to_psk, salt_bytes).encrypt(
            json.dumps(payload).encode("utf-8")).decode("ascii")
        salt = _b64(salt_bytes)

    await _store_put(hub, sm["kv_name"], token, _secret_store(sm))
    moved = dict(sm)
    moved["salt"] = salt
    moved["updated_at"] = _now()
    moved["updated_by"] = actor
    cv["secrets"].setdefault(to_bucket, {})[name] = moved
    del cv["secrets"][bucket][name]
    _save(hub)
    _cache_invalidate(bucket, name)
    _cache_invalidate(to_bucket, name)
    logger.info("cred-vault: moved secret %s from bucket %s to %s by %s",
                name, bucket, to_bucket, actor or "?")
    return {"name": name, "from": bucket, "to": to_bucket, "mode": mode}


async def delete_bucket(hub, bucket: str, *, confirm_destroy: bool = False,
                        actor: str = "") -> Dict[str, Any]:
    """Remove a bucket entirely — its pass-phrase record and any secrets left in
    it (Global-Admin only; the caller MUST enforce that and MUST refuse buckets
    that belong to a live tenant).

    This exists because a bucket could be created by typing a free-text name,
    but never removed: ``list_buckets`` derives from the pass-phrase records
    UNION the secret records, so an unwanted bucket lingered in every Global
    Admin's picker forever. An orphaned bucket matches no tenant, so nothing
    tenant-scoped can reference it and no tenant-admin can reach it — it is a
    dead end that only invites credentials being stored somewhere unusable.

    Deleting secrets is destructive and irreversible, so it is refused unless
    ``confirm_destroy`` is passed. Move anything worth keeping out first with
    :func:`move_secret`.
    """
    if bucket == ADMIN_BUCKET:
        raise CredVaultError(
            "the Global Admin slot is infrastructure and cannot be deleted")
    cv = _meta(hub)
    names = sorted((cv["secrets"].get(bucket) or {}).keys())
    if names and not confirm_destroy:
        raise CredVaultError(
            f"this bucket still holds {len(names)} secret(s): {', '.join(names)}. "
            "Move them to another bucket first, or confirm the deletion to "
            "destroy them.")
    if not names and not cv["buckets"].get(bucket):
        raise CredVaultError(f"bucket '{bucket}' not found")
    for name in names:
        sm = cv["secrets"][bucket][name]
        try:
            await _store_del(hub, sm["kv_name"], _secret_store(sm))
        except Exception as exc:  # noqa: BLE001 — never strand the metadata
            logger.warning("cred-vault: delete-bucket could not remove blob for "
                           "%s/%s: %s", bucket, name, exc)
        _cache_invalidate(bucket, name)
    cv["secrets"].pop(bucket, None)
    cv["buckets"].pop(bucket, None)
    _save(hub)
    logger.warning("cred-vault: bucket %s DELETED by %s (%d secret(s) destroyed)",
                   bucket, actor or "?", len(names))
    return {"bucket": bucket, "destroyed": names}


# ── secret storage ──────────────────────────────────────────────────────────
def list_buckets(hub) -> List[Dict[str, Any]]:
    cv = _meta(hub)
    out = []
    names = set(cv["buckets"]) | set(cv["secrets"])
    for b in sorted(names):
        out.append({"bucket": b, "has_psk": bucket_has_psk(hub, b),
                    "secret_count": len(cv["secrets"].get(b, {}))})
    return out


def list_secrets(hub, bucket: str) -> List[Dict[str, Any]]:
    """Names + non-secret metadata for a bucket — NEVER the values."""
    cv = _meta(hub)
    out = []
    for name, sm in sorted(cv["secrets"].get(bucket, {}).items()):
        out.append({
            "name": name, "type": sm.get("type", "generic"), "mode": sm.get("mode", _MODE_PSK),
            "description": sm.get("description", ""), "fields": sm.get("fields", []),
            "automation": sm.get("mode") == _MODE_HUB, "store": _secret_store(sm),
            "created_at": sm.get("created_at"), "updated_at": sm.get("updated_at"),
            "last_accessed_at": sm.get("last_accessed_at"),
        })
    return out


async def put_secret(hub, bucket: str, name: str, value: Dict[str, Any], *,
                     mode: str = _MODE_PSK, sec_type: str = "generic",
                     description: str = "", psk: str = "", actor: str = "") -> Dict[str, Any]:
    """Create/replace a secret. Writing ALWAYS requires the bucket PSK (so only a
    holder of the pass-phrase can add or change secrets); ``mode`` then selects
    the at-rest key: ``psk`` (PSK-derived, human-only) or ``hub`` (hub Fernet key,
    automation-readable)."""
    name = (name or "").strip()
    if not name:
        raise CredVaultError("secret name is required")
    if mode not in _MODES:
        raise CredVaultError(f"invalid mode {mode!r}")
    if not isinstance(value, dict) or not value:
        raise CredVaultError("secret value must be a non-empty object")
    _require_psk(hub, bucket, psk)

    cv = _meta(hub)
    existing = cv["secrets"].setdefault(bucket, {}).get(name)
    kv_name = existing["kv_name"] if existing else _KV_PREFIX + uuid.uuid4().hex
    # Keep a replaced secret in its original backend; otherwise pick Key Vault
    # when configured, else the local encrypted-blob store (vault-less deploy).
    store = _secret_store(existing) if existing else (_STORE_KV if _vault_available(hub) else _STORE_LOCAL)
    payload = dict(value)
    payload["_bucket"] = bucket
    payload["_name"] = name
    plain = json.dumps(payload).encode("utf-8")

    if mode == _MODE_HUB:
        token = hub_encryption.encrypt(json.dumps(payload)).decode("ascii")
        salt = ""
    else:
        salt_bytes = secrets.token_bytes(16)
        token = _psk_fernet(psk, salt_bytes).encrypt(plain).decode("ascii")
        salt = _b64(salt_bytes)

    await _store_put(hub, kv_name, token, store)
    now = _now()
    cv["secrets"][bucket][name] = {
        "mode": mode, "type": sec_type, "description": description,
        "fields": sorted(k for k in value if not k.startswith("_")),
        "kv_name": kv_name, "salt": salt, "store": store,
        "created_at": existing["created_at"] if existing else now,
        "created_by": existing["created_by"] if existing else actor,
        "updated_at": now, "updated_by": actor,
        "last_accessed_at": existing.get("last_accessed_at") if existing else None,
    }
    _save(hub)
    _cache_invalidate(bucket, name)
    return {"bucket": bucket, "name": name, "mode": mode, "store": store}


async def _fetch_and_decrypt(hub, bucket: str, name: str, *, psk: Optional[str], http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    if name == CANARY_SECRET:
        sentinel.guard("vault.canary", detail=f"{bucket}/{name} (honeytoken read)")
    sm = _meta(hub)["secrets"].get(bucket, {}).get(name)
    if not sm:
        raise CredVaultError(f"secret '{name}' not found")
    token = await _store_get(hub, sm["kv_name"], _secret_store(sm), http=http)
    if token is None:
        raise CredVaultError(f"secret '{name}' is missing from the vault")
    try:
        if sm.get("mode") == _MODE_HUB:
            raw = hub_encryption.decrypt(token.encode("ascii"))
        else:
            raw = _psk_fernet(psk or "", _unb64(sm["salt"])).decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise CredVaultError("could not decrypt secret (wrong pass-phrase or corrupted data)")
    data = json.loads(raw)
    data.pop("_bucket", None)
    data.pop("_name", None)
    return data


async def reveal_secret(hub, bucket: str, name: str, *, psk: str, actor: str = "") -> Dict[str, Any]:
    """Interactive reveal — ALWAYS requires the bucket PSK, regardless of mode."""
    sentinel.guard("vault.reveal_secret", detail=f"{bucket}/{name} actor={actor}")
    _require_psk(hub, bucket, psk)
    value = await _fetch_and_decrypt(hub, bucket, name, psk=psk)
    sm = _meta(hub)["secrets"][bucket][name]
    sm["last_accessed_at"] = _now()
    sm["last_accessed_by"] = actor
    _save(hub)
    return value


async def automation_get(hub, bucket: str, name: str) -> Dict[str, Any]:
    """Unattended retrieval for tooling — NO pass-phrase. Only works for
    ``hub``-mode (automation-readable) secrets; ``psk``-mode secrets raise."""
    sentinel.guard("vault.automation_get", detail=f"{bucket}/{name}")
    sm = _meta(hub)["secrets"].get(bucket, {}).get(name)
    if not sm:
        raise CredVaultError(f"secret '{name}' not found")
    if sm.get("mode") != _MODE_HUB:
        raise CredVaultError(f"secret '{name}' is pass-phrase-only and cannot be read unattended")
    value = await _fetch_and_decrypt(hub, bucket, name, psk=None)
    sm["last_accessed_at"] = _now()
    sm["last_accessed_by"] = "automation"
    _save(hub)
    return value


async def automation_list_by_type(hub, sec_type,
                                  buckets: Optional[List[str]] = None
                                  ) -> List[Dict[str, Any]]:
    """Unattended bulk retrieval for tooling — return every AUTOMATION-READABLE
    (``hub``-mode) secret of a given ``type`` in the requested ``buckets`` (or
    all buckets when ``buckets`` is None), decrypted. NO pass-phrase.

    ``sec_type`` may be a single type string OR an iterable of type strings
    (e.g. ``("console", "login")``) — a secret matches when its type is in the
    requested set. This lets the console resolver accept ordinary ``login``
    secrets as device-console logins, not only the dedicated ``console`` type.

    Each item is ``{"bucket","name","value"}``. Unreadable / pass-phrase-only /
    wrong-type secrets are skipped silently — this is a best-effort scan used by
    the console-credential resolver, so it must never raise on a bad record.

    Unlike :func:`automation_get` it does NOT stamp ``last_accessed_*`` (a seed
    can run on every spoke connect, so we avoid churning hub state on each scan)."""
    want_types = ({sec_type} if isinstance(sec_type, str) else set(sec_type))
    sentinel.guard("vault.automation_list_by_type",
                   detail=f"type={','.join(sorted(want_types))}")
    want = set(buckets) if buckets is not None else None
    out: List[Dict[str, Any]] = []
    to_fetch = []
    for bucket, secrets in (_meta(hub)["secrets"] or {}).items():
        if want is not None and bucket not in want:
            continue
        for name, sm in (secrets or {}).items():
            if sm.get("type") not in want_types or sm.get("mode") != _MODE_HUB:
                continue
            val = _cache_get(_cache_key(bucket, name, sm.get("updated_at", "")))
            if val is not None and name != CANARY_SECRET:
                out.append({"bucket": bucket, "name": name, "value": val})
            else:
                to_fetch.append((bucket, name, sm))
    
    if to_fetch:
        async with httpx.AsyncClient(timeout=20.0) as shared_http:
            tasks = [
                _fetch_and_decrypt(hub, b, n, psk=None, http=shared_http)
                for b, n, sm in to_fetch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for (b, n, sm), res in zip(to_fetch, results):
                if isinstance(res, Exception):
                    continue
                _cache_set(_cache_key(b, n, sm.get("updated_at", "")), res)
                out.append({"bucket": b, "name": n, "value": res})
    return out


async def delete_secret(hub, bucket: str, name: str, *, psk: str, actor: str = "") -> None:
    _require_psk(hub, bucket, psk)
    cv = _meta(hub)
    sm = cv["secrets"].get(bucket, {}).get(name)
    if not sm:
        raise CredVaultError(f"secret '{name}' not found")
    await _store_del(hub, sm["kv_name"], _secret_store(sm))
    del cv["secrets"][bucket][name]
    _save(hub)
    _cache_invalidate(bucket, name)
