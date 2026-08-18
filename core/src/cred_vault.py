"""Per-tenant + admin-slot credential vault (hub-side, Azure Key Vault-backed).

A general-purpose secret locker that lets a **tenant-admin** store/retrieve their
OWN tenant's named credentials, plus a special non-tenant **admin slot**
(``__admin__``) for infrastructure credentials (e.g. the Hurricane Electric DNS
account) that belong to no tenant. Built on the existing pure-REST Key Vault
broker (:mod:`key_vault`) — the same SSO-app-certificate auth as the DR kit — so
no new Azure config is required beyond the vault URL already set under
``global_config["key_vault"]``.

Storage backend is transparent: when a Key Vault URL is configured the encrypted
ciphertext is stored in the vault; on a standalone/vault-less deployment (the hub
running as a plain local VM) it falls back to an encrypted-blob map in hub state.
The ciphertext is Fernet-encrypted either way, so the vault is *used when
available* but never *required*.

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
    from the bucket PSK* (scrypt). Neither the hub nor Azure can read it without
    the PSK — a human must supply it for every reveal. No unattended access.
  - ``hub`` (automation-readable): the value is encrypted with the hub's
    at-rest Fernet key (:data:`security.encryption.hub_encryption`). The hub can
    decrypt it unattended, so tooling (e.g. a cert-renewal run pulling the HE
    account, or the console auto-identify loop) can fetch it with no human in the
    loop. Interactive reveal STILL requires the PSK; only :func:`automation_get`
    bypasses it, and only for ``hub``-mode secrets.

At rest the ciphertext lives in Key Vault (Azure's own encryption + RBAC) under
an opaque ``cred-<uuid>`` name; the hub keeps only non-secret **metadata**
(names, mode, type, description, timestamps, per-secret salt, PSK verifier) in
the Fernet-encrypted hub state — never a plaintext value.
"""
from __future__ import annotations

import base64
import hmac
import json
import logging
import secrets
import time
import uuid
from typing import Any, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import key_vault as _kv
from security.encryption import hub_encryption
from security.oidc import get_oidc_config

logger = logging.getLogger("CredVault")

ADMIN_BUCKET = "__admin__"          # the non-tenant "Global Admin slot"
_KV_PREFIX = "cred-"                # opaque Key Vault secret-name prefix
_MODE_PSK = "psk"
_MODE_HUB = "hub"
_MODES = (_MODE_PSK, _MODE_HUB)
_STORE_KV = "kv"                    # ciphertext lives in Azure Key Vault
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
    "blobs": {kv_name: ciphertext}}``. Plaintext is NEVER stored here. When
    Azure Key Vault is configured the ciphertext lives in the vault; on a
    vault-less deployment it falls back to the encrypted ``blobs`` map (the
    ciphertext is already Fernet-encrypted, exactly like the other at-rest
    encrypted blobs in hub state)."""
    gc = hub.state.system_state.setdefault("global_config", {})
    cv = gc.setdefault("cred_vault", {})
    cv.setdefault("buckets", {})
    cv.setdefault("secrets", {})
    cv.setdefault("blobs", {})
    return cv


def _save(hub) -> None:
    hub.state._mark_dirty()


def _oidc(hub):
    return get_oidc_config(hub)


def _vault_available(hub) -> bool:
    """True when Azure Key Vault is configured (a vault URL is set). Standalone
    hubs deployed as a plain VM without a vault return False and transparently
    use the local encrypted-blob store instead."""
    try:
        return bool(str((_kv.get_config(hub) or {}).get("vault_url") or "").strip())
    except Exception:  # noqa: BLE001
        return False


def _vault_url(hub) -> str:
    url = str((_kv.get_config(hub) or {}).get("vault_url") or "").strip()
    if not url:
        raise CredVaultError("Azure Key Vault is not configured (set the vault URL in Setup → Azure → Key Vault)")
    return url


# ── storage backend (Key Vault when configured, else local hub state) ────────
def _secret_store(sm: Dict[str, Any]) -> str:
    """Which backend a stored secret lives in (``kv`` for pre-existing records
    without an explicit marker — they were vault-only before this fallback)."""
    return sm.get("store") or _STORE_KV


async def _store_put(hub, kv_name: str, token: str, store: str) -> None:
    if store == _STORE_LOCAL:
        _meta(hub)["blobs"][kv_name] = token
    else:
        await _kv.set_secret(_oidc(hub), _vault_url(hub), kv_name, token)


async def _store_get(hub, kv_name: str, store: str) -> Optional[str]:
    if store == _STORE_LOCAL:
        return _meta(hub)["blobs"].get(kv_name)
    return await _kv.get_secret(_oidc(hub), _vault_url(hub), kv_name)


async def _store_del(hub, kv_name: str, store: str) -> None:
    if store == _STORE_LOCAL:
        _meta(hub)["blobs"].pop(kv_name, None)
        return
    try:
        await _kv.delete_secret(_oidc(hub), _vault_url(hub), kv_name)
    except _kv.KeyVaultError:
        pass  # metadata removal proceeds even if the vault delete 404s/soft-deletes


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
    return {"bucket": bucket, "name": name, "mode": mode, "store": store}


async def _fetch_and_decrypt(hub, bucket: str, name: str, *, psk: Optional[str]) -> Dict[str, Any]:
    sm = _meta(hub)["secrets"].get(bucket, {}).get(name)
    if not sm:
        raise CredVaultError(f"secret '{name}' not found")
    token = await _store_get(hub, sm["kv_name"], _secret_store(sm))
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


async def automation_list_by_type(hub, sec_type: str,
                                  buckets: Optional[List[str]] = None
                                  ) -> List[Dict[str, Any]]:
    """Unattended bulk retrieval for tooling — return every AUTOMATION-READABLE
    (``hub``-mode) secret of a given ``type`` in the requested ``buckets`` (or
    all buckets when ``buckets`` is None), decrypted. NO pass-phrase.

    Each item is ``{"bucket","name","value"}``. Unreadable / pass-phrase-only /
    wrong-type secrets are skipped silently — this is a best-effort scan used by
    the console-credential resolver, so it must never raise on a bad record.

    Unlike :func:`automation_get` it does NOT stamp ``last_accessed_*`` (a seed
    can run on every spoke connect, so we avoid churning hub state on each scan)."""
    want = set(buckets) if buckets is not None else None
    out: List[Dict[str, Any]] = []
    for bucket, secrets in (_meta(hub)["secrets"] or {}).items():
        if want is not None and bucket not in want:
            continue
        for name, sm in (secrets or {}).items():
            if sm.get("type") != sec_type or sm.get("mode") != _MODE_HUB:
                continue
            try:
                value = await _fetch_and_decrypt(hub, bucket, name, psk=None)
            except Exception:  # noqa: BLE001 — skip unreadable/corrupt records
                continue
            out.append({"bucket": bucket, "name": name, "value": value})
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
