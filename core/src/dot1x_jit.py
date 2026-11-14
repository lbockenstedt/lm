"""JIT 802.1X accounts for simulated clients (hub broker).

The cs SimQuotaEngine places clients on SSID cells (Config → Engine → SSID
matrix). A 1X cell may name an *account location* (``dot1x_account``):

  * ``entra``     — Entra ID user via Graph (``cloud_nac``; the global Cloud NAC
                    app + UPN domain);
  * ``ldap``      — local user in the tenant's directory OU (LDAP spoke);
  * ``clearpass`` — Policy Manager local user (CPPM spoke).

When the engine moves a client onto such a cell, the spoke sends
``CS_DOT1X_PROVISION``; the hub creates the account for the client's sim
username with a random password, stores the password (active cloud vault —
Azure Key Vault / OCI Vault — else the Fernet-encrypted hub state) and delivers
it back to that spoke as ``CS_DOT1X_CREDENTIAL`` (the client's engine-owned
``dot1x_password`` override). Several hostnames can share one username, so an
account lives until its last hostname is released (``CS_DOT1X_RELEASE`` — the
engine no longer has the client on the cell, or the client is gone).
``CS_DOT1X_SYNC`` is the spoke's periodic keep-alive: it refreshes
``last_active``, releases hostnames the spoke no longer reports (missed
releases) and re-delivers a credential the client never received.

The hourly :func:`run_sweep_loop` rotates passwords older than ``rotate_days``,
retries failed deletes and, every ``cleanup_interval_days``, deletes accounts
not active for ``unused_days``. Passwords never leave the hub except toward the
owning cs spoke — the My Users API lists / resets / deletes, never reveals.
"""
# Postpone evaluation of type hints so annotations are never evaluated at runtime.
from __future__ import annotations

# asyncio provides per-account locks and the sweep loop's sleeps.
import asyncio
# Standard-library logging.
import logging
# re validates usernames.
import re
# time stamps creation, rotation and activity.
import time
# uuid generates vault secret names and self-test usernames.
import uuid
# Type hints only.
from typing import Any, Dict, Iterable, List, Optional

# Spoke reply unwrapping and tenant/LDAP slug helpers.
import access
# Entra ID user management via Graph, and password generation.
import cloud_nac
# Hub-generated secret storage (cloud vault when enabled, else encrypted hub state).
import hub_secret_store

# Dedicated logger for this feature.
logger = logging.getLogger("Dot1xJit")

# Supported account locations and their display names.
BACKENDS = ("entra", "ldap", "clearpass")
BACKEND_LABELS = {"entra": "Entra ID", "ldap": "LDAP", "clearpass": "ClearPass"}
# Hub-state keys: account index, local password blobs, sweep metadata, and config.
STATE_KEY = "dot1x_jit_accounts"
SECRETS_KEY = "dot1x_jit_secrets"
META_KEY = "dot1x_jit_meta"
CFG_KEY = "dot1x_jit"
# Command that delivers a password (or revocation) to a cs spoke.
CREDENTIAL_CMD = "CS_DOT1X_CREDENTIAL"
# Spoke message types this module handles.
MESSAGE_TYPES = ("CS_DOT1X_PROVISION", "CS_DOT1X_RELEASE", "CS_DOT1X_SYNC")

# Prefix for vault secret names.
_KV_PREFIX = "dot1x-"
# Seconds per day.
_DAY = 86400.0
# Allowed usernames: lower-case, starts with a letter/digit, max 64 chars.
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
# Config defaults.
_DEFAULTS = {"rotate_days": 30, "unused_days": 30, "cleanup_interval_days": 30,
             "cppm_role": "[Employee]"}

# One asyncio lock per account key, so operations on the same account never overlap.
_locks: Dict[str, asyncio.Lock] = {}


class Dot1xJitError(Exception):
    """Provisioning/backend failure; the message is safe to surface."""


# ── config / state ───────────────────────────────────────────────────────────

def get_config(hub) -> Dict[str, Any]:
    """Return the effective JIT config: stored values over defaults, day counts clamped to >= 1."""
    # Stored config overlays the defaults (blank values ignored).
    gc = hub.state.system_state.get("global_config", {}) or {}
    cfg = dict(_DEFAULTS)
    cfg.update({k: v for k, v in (gc.get(CFG_KEY) or {}).items() if v not in (None, "")})
    # Day counts must be positive integers; fall back to the default otherwise.
    for k in ("rotate_days", "unused_days", "cleanup_interval_days"):
        try:
            cfg[k] = max(1, int(cfg[k]))
        except (TypeError, ValueError):
            cfg[k] = _DEFAULTS[k]
    # ClearPass role for created users.
    cfg["cppm_role"] = str(cfg.get("cppm_role") or _DEFAULTS["cppm_role"])
    return cfg


def set_config(hub, incoming: Dict[str, Any]) -> Dict[str, Any]:
    """Update the stored config with known keys from ``incoming``; returns the normalised config."""
    # Copy the current stored config.
    gc = hub.state.system_state.setdefault("global_config", {})
    cur = dict(gc.get(CFG_KEY) or {})
    # Take only known keys from the input.
    for k in _DEFAULTS:
        if k in (incoming or {}):
            cur[k] = incoming[k]
    # Store, then normalise and store the normalised version.
    gc[CFG_KEY] = cur
    cfg = get_config(hub)
    gc[CFG_KEY] = cfg
    # Mark state for saving.
    hub.state._mark_dirty()
    return cfg


def _index(hub) -> Dict[str, Dict[str, Any]]:
    """Return the account index in hub state (created if missing)."""
    return hub.state.system_state.setdefault(STATE_KEY, {})


def _blobs(hub) -> Dict[str, str]:
    """Return the local (non-vault) encrypted-password map in hub state."""
    return hub.state.system_state.setdefault(SECRETS_KEY, {})


def _meta(hub) -> Dict[str, Any]:
    """Return the sweep metadata dict in hub state (e.g. last cleanup time)."""
    return hub.state.system_state.setdefault(META_KEY, {})


def _dirty(hub) -> None:
    """Mark hub state dirty so it is saved on the next flush."""
    hub.state._mark_dirty()


async def _persist(hub) -> None:
    """Save hub state now if possible; otherwise mark it dirty."""
    # Use the immediate saver if the state has one.
    saver = getattr(hub.state, "save_state_now", None)
    if callable(saver):
        try:
            await saver()
            return
        # Save failed: fall back to the normal deferred save.
        except Exception as e:  # noqa: BLE001
            logger.warning("dot1x_jit: immediate state save failed (%s); marked dirty", e)
    _dirty(hub)


def account_key(tenant_id: str, backend: str, username: str) -> str:
    """Return the index key for an account: "tenant|backend|username"."""
    return f"{tenant_id}|{backend}|{username}"


def normalize_username(username: Any) -> str:
    """Return ``username`` lower-cased and validated; raises Dot1xJitError if invalid."""
    # Normalise, then validate.
    u = str(username or "").strip().lower()
    if not _USERNAME_RE.match(u):
        raise Dot1xJitError(f"invalid 802.1X username {username!r}")
    return u


def normalize_backend(backend: Any) -> str:
    """Return ``backend`` lower-cased and validated; raises Dot1xJitError if unknown."""
    # Normalise, then check it is supported.
    b = str(backend or "").strip().lower()
    if b not in BACKENDS:
        raise Dot1xJitError(f"unknown account location {backend!r}")
    return b


def _lock(key: str) -> asyncio.Lock:
    """Return the lock for account ``key``, creating it on first use."""
    lk = _locks.get(key)
    if lk is None:
        lk = _locks[key] = asyncio.Lock()
    return lk


# ── password storage (cloud vault when enabled, else encrypted hub state) ────

def _vault_on(hub) -> bool:
    """Return True if a cloud vault is enabled."""
    return hub_secret_store.vault_on(hub)


async def _secret_put(hub, key: str, rec: Dict[str, Any], password: str) -> None:
    """Encrypt and store ``password`` for account ``key``, updating ``rec``'s storage fields."""
    await hub_secret_store.put(hub, _blobs(hub), key, rec, password, _KV_PREFIX)


async def _secret_get(hub, key: str, rec: Dict[str, Any]) -> Optional[str]:
    """Return the decrypted password for account ``key``, or None if missing/unreadable."""
    return await hub_secret_store.get(hub, _blobs(hub), key, rec)


async def _secret_del(hub, key: str, rec: Dict[str, Any]) -> None:
    """Delete the stored password for account ``key`` (local copy and any vault copy)."""
    await hub_secret_store.delete(hub, _blobs(hub), key, rec)


# ── backends ─────────────────────────────────────────────────────────────────

async def _rr(hub, spoke_id: Optional[str], cmd: str, payload: Dict[str, Any],
              timeout: float = 30.0) -> Dict[str, Any]:
    """Send ``cmd`` to a spoke and return its data dict; raises Dot1xJitError on error replies."""
    # No spoke to talk to.
    if not spoke_id:
        raise Dot1xJitError(f"no spoke connected for {cmd}")
    # Send and unwrap.
    res = await hub.request_response(spoke_id, cmd, payload, timeout=timeout)
    data = access.unwrap_spoke(res) if isinstance(res, dict) else res
    # Either the envelope or the payload may report an error.
    for d in (res, data):
        if isinstance(d, dict) and str(d.get("status", "")).upper() == "ERROR":
            raise Dot1xJitError(str(d.get("message") or f"{cmd} failed"))
    # Some spokes nest the result one level deeper under "data".
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    return data if isinstance(data, dict) else {}


def _nac_spoke(hub, tenant_id: str) -> Optional[str]:
    """Same resolution as routes/cppm.py ``_nac_spoke_for_request`` for a
    known tenant: the tenant's own ``nac_instances`` spoke, else a nac spoke
    bound to the tenant (or the shared-tenant spoke)."""
    # The tenant's own NAC instance, if connected.
    instances = (hub.state.system_state.get("global_config", {}) or {}).get("nac_instances", []) or []
    inst = next((i for i in instances if isinstance(i, dict) and i.get("tenant_id") == tenant_id), None)
    sid = (inst or {}).get("spoke_id") or ""
    if sid and hub._primary_key(sid) in hub.active_connections:
        return sid
    # Otherwise the shared or tenant-bound ClearPass spoke.
    return (hub.get_cppm_spoke_for_shared() if access.tenant_is_shared(tenant_id)
            else hub.get_cppm_spoke_for_tenant(tenant_id))


def _entra_cfg(hub):
    """Return (Cloud NAC config, OIDC config) for Entra; raises if Cloud NAC is not set up."""
    # Cloud NAC must be enabled with a UPN domain.
    cfg = cloud_nac.get_config(hub.state.system_state)
    if not cfg.get("enabled") or not cfg.get("domain"):
        raise Dot1xJitError("Entra account location needs Cloud NAC configured "
                            "(Settings → Cloud → Cloud NAC: enabled + UPN domain)")
    # Imported lazily: OIDC config (Graph credentials).
    from security.oidc import get_oidc_config
    return cfg, get_oidc_config(hub)


def _ldap_target(hub, tenant_id: str):
    """Return (directory spoke, tenant OU slug) for LDAP; raises if the tenant has no slug."""
    # The tenant's OU slug is required.
    slug = access.ldap_tenant_slug(hub, tenant_id)
    if not slug:
        raise Dot1xJitError("tenant has no directory OU slug")
    return hub.get_directory_spoke_for_tenant(tenant_id), slug


def _is_already_exists(msg: str) -> bool:
    """Return True if an error message says the object already exists."""
    m = (msg or "").lower()
    return "already exists" in m or "already_exists" in m


def _is_no_such(msg: str) -> bool:
    """Return True if an error message says the object was not found."""
    m = (msg or "").lower()
    return "no such object" in m or "no_such_object" in m or "not found" in m


async def _backend_upsert(hub, rec: Dict[str, Any], password: str, *, owned: bool) -> None:
    """Create the account (``owned=False``) or set its password (``owned`` —
    already in our index). Never takes over a pre-existing LDAP/ClearPass
    account we didn't create."""
    # Account identity.
    tid, backend, username = rec["tenant_id"], rec["backend"], rec["username"]
    # Entra: create or update the user via Graph.
    if backend == "entra":
        cfg, oidc = _entra_cfg(hub)
        try:
            res = await cloud_nac.provision_user(oidc, cfg["domain"], username, password=password,
                oid=rec.get("oid") if owned else None)
        except cloud_nac.CloudNacError as e:
            raise Dot1xJitError(str(e)) from e
        # Remember the user's UPN and object id.
        rec["upn"], rec["oid"] = res.get("upn"), res.get("oid")
        # New users are added to the configured group (failure only warns).
        if cfg.get("group_id") and res.get("oid") and not owned:
            try:
                await cloud_nac.add_user_to_group(oidc, cfg["group_id"], res["oid"])
            except cloud_nac.CloudNacError as e:
                logger.warning("dot1x_jit: Entra group add for %s failed: %s", rec.get("upn"), e)
        return
    # LDAP: user lives in the tenant's OU.
    if backend == "ldap":
        spoke, slug = _ldap_target(hub, tid)
        rec["upn"] = f"{username}@{slug}"
        # Existing account: just set the password (fall through to create if it vanished).
        if owned:
            try:
                await _rr(hub, spoke, "LDAP_SET_PASSWORD",
                          {"tenant_slug": slug, "uid": username, "password": password})
                return
            except Dot1xJitError as e:
                if not _is_no_such(str(e)):
                    raise
        # Make sure the tenant OU exists, then create the user.
        await _rr(hub, spoke, "LDAP_PROVISION_TENANT_OU", {"tenant_slug": slug}, timeout=60.0)
        try:
            await _rr(hub, spoke, "LDAP_CREATE_USER", {
                "tenant_slug": slug, "uid": username, "auth_mode": "local",
                "password": password,
                "attrs": {"cn": username, "sn": username,
                          "displayName": f"{username} (LM simulation 802.1X)"}})
        # An existing user we did not create is never taken over.
        except Dot1xJitError as e:
            if _is_already_exists(str(e)):
                raise Dot1xJitError(f"LDAP user {username!r} already exists in the tenant "
                                    "OU and was not created by LM — refusing to take it over") from e
            raise
        return
    # ClearPass: create (or update) the local user with the configured role.
    spoke = _nac_spoke(hub, tid)
    await _rr(hub, spoke, "CPPM_CREATE_LOCAL_USER", {
        "user_id": username, "password": password,
        "role_name": get_config(hub)["cppm_role"]})
    rec["upn"] = username


async def _backend_delete(hub, rec: Dict[str, Any]) -> None:
    """Delete the account from its backend (an already-missing LDAP user is not an error)."""
    # Account identity.
    tid, backend, username = rec["tenant_id"], rec["backend"], rec["username"]
    # Entra: delete via Graph.
    if backend == "entra":
        _cfg, oidc = _entra_cfg(hub)
        try:
            await cloud_nac.delete_user(oidc, rec.get("oid") or rec.get("upn"))
        except cloud_nac.CloudNacError as e:
            raise Dot1xJitError(str(e)) from e
        return
    # LDAP: delete, ignoring "no such object".
    if backend == "ldap":
        spoke, slug = _ldap_target(hub, tid)
        try:
            await _rr(hub, spoke, "LDAP_DELETE_USER", {"tenant_slug": slug, "uid": username})
        except Dot1xJitError as e:
            if not _is_no_such(str(e)):
                raise
        return
    # ClearPass: delete the local user.
    await _rr(hub, _nac_spoke(hub, tid), "CPPM_DELETE_LOCAL_USER", {"user_id": username})


# ── credential delivery to cs spokes ─────────────────────────────────────────

def _by_spoke(rec: Dict[str, Any], only: Optional[Iterable[str]] = None) -> Dict[str, List[str]]:
    """Group ``rec``'s hostnames by spoke id (optionally only those in ``only``)."""
    # Optional hostname filter.
    only = set(only) if only is not None else None
    out: Dict[str, List[str]] = {}
    # Skip hostnames outside the filter or without a spoke.
    for h, m in (rec.get("hostnames") or {}).items():
        if only is not None and h not in only:
            continue
        sid = (m or {}).get("spoke_id")
        if sid:
            out.setdefault(sid, []).append(h)
    return out


async def _deliver(hub, rec: Dict[str, Any], password: Optional[str], *,
                   only: Optional[Iterable[str]] = None, revoke: bool = False,
                   targets: Optional[Dict[str, List[str]]] = None) -> int:
    """Send the password (or a revocation) to each spoke's hostnames; returns hostnames reached."""
    # Count of hostnames delivered to.
    sent = 0
    # One message per spoke covering its hostnames.
    for sid, hs in (targets if targets is not None else _by_spoke(rec, only)).items():
        payload = {"username": rec["username"], "backend": rec["backend"],
                   "hostnames": sorted(hs), "version": rec.get("rotated_at") or 0}
        # Revoke, or include the password.
        if revoke:
            payload["revoke"] = True
        else:
            payload["password"] = password
        # Send; a failure is logged (the spoke asks again via SYNC).
        try:
            await _rr(hub, sid, CREDENTIAL_CMD, payload, timeout=20.0)
            sent += len(hs)
        except Exception as e:  # noqa: BLE001 — spoke re-requests via SYNC
            logger.warning("dot1x_jit: %s %s → %s %s failed: %s", CREDENTIAL_CMD,
                           rec["username"], sid, hs, e)
    return sent


# ── account lifecycle ────────────────────────────────────────────────────────

def _entra_conflict(hub, tenant_id: str, username: str) -> Optional[str]:
    """Return the other tenant already using this Entra username, or None."""
    # Entra usernames are global, so the same name in two tenants would collide.
    for r in _index(hub).values():
        if r.get("backend") == "entra" and r.get("username") == username and r.get("tenant_id") != tenant_id:
            return r.get("tenant_id")
    return None


async def provision(hub, tenant_id: str, spoke_id: str, hostname: str,
                    username: str, backend: str, cell: str = "") -> Dict[str, Any]:
    """Ensure the account exists for (tenant, backend, username), map
    ``hostname`` to it and deliver the password to ``spoke_id``. A password
    younger than ``rotate_days`` is reused (several hostnames share one
    account); otherwise a fresh one is set. Returns the public record."""
    # Validate inputs.
    if not tenant_id:
        raise Dot1xJitError("spoke has no tenant")
    username, backend = normalize_username(username), normalize_backend(backend)
    hostname = str(hostname or "").strip()
    if not hostname:
        raise Dot1xJitError("missing hostname")
    # Serialise all work on this account.
    key = account_key(tenant_id, backend, username)
    async with _lock(key):
        # Current record, if any.
        now = time.time()
        idx = _index(hub)
        rec = idx.get(key)
        password = None
        # Reuse the stored password while it is younger than rotate_days.
        if rec is not None and not rec.get("pending_delete"):
            age = now - float(rec.get("rotated_at") or 0)
            if age < get_config(hub)["rotate_days"] * _DAY:
                password = await _secret_get(hub, key, rec)
        # Need a new password (new account, too old, or unreadable).
        if password is None:
            # Refuse an Entra username already used by another tenant.
            if backend == "entra" and rec is None:
                other = _entra_conflict(hub, tenant_id, username)
                if other:
                    raise Dot1xJitError(f"Entra user {username!r} is already JIT-provisioned "
                                        f"for tenant {other!r}")
            # Work on a copy so a failure leaves the stored record unchanged.
            new = rec is None
            work = dict(rec or {"tenant_id": tenant_id, "backend": backend, "username": username,
                                "hostnames": {}, "created_at": now})
            work.pop("pending_delete", None)
            # Generate a password and create/update the backend account.
            password = cloud_nac.gen_password()
            try:
                await _backend_upsert(hub, work, password, owned=not new)
            except Dot1xJitError as e:
                # Remember the error on the existing record, then re-raise.
                if rec is not None:
                    rec["last_error"] = str(e)
                    _dirty(hub)
                raise
            # Store the password; if that fails, undo a newly created account.
            try:
                await _secret_put(hub, key, work, password)
            except Exception as e:  # noqa: BLE001
                if new:
                    try:
                        await _backend_delete(hub, work)
                    except Exception as de:  # noqa: BLE001
                        logger.warning("dot1x_jit: rollback delete of %s failed: %s", key, de)
                raise Dot1xJitError(f"password vault write failed: {e}") from e
            # Success: stamp rotation and save the record.
            work["rotated_at"] = now
            work.pop("last_error", None)
            rec = idx[key] = work
            logger.info("dot1x_jit: %s %s account %r for tenant %s (store=%s)",
                        "created" if new else "re-keyed", BACKEND_LABELS[backend],
                        username, tenant_id, rec.get("store"))
        # Map this hostname to the account and note activity.
        rec.setdefault("hostnames", {})[hostname] = {"spoke_id": spoke_id, "cell": cell,
                                                     "last_active": now}
        rec["last_active_at"] = now
        # Save, deliver the password to this hostname's spoke, and return the public view.
        await _persist(hub)
        await _deliver(hub, rec, password, only=[hostname])
        return public_record(rec)


async def _delete_locked(hub, key: str, rec: Dict[str, Any], *, revoke: bool) -> None:
    """Delete account ``rec`` (lock held): backend, password and index; optionally revoke
    clients.
    """
    # Remember which spokes to notify before the record goes away.
    targets = _by_spoke(rec)
    # Delete from the backend; on failure mark it for the sweep to retry.
    try:
        await _backend_delete(hub, rec)
    except Exception as e:  # noqa: BLE001 — retried by the sweep
        rec["pending_delete"] = True
        rec["last_error"] = f"delete failed: {e}"
        _dirty(hub)
        raise Dot1xJitError(rec["last_error"]) from e
    # Remove the password and index entry, then save.
    await _secret_del(hub, key, rec)
    _index(hub).pop(key, None)
    await _persist(hub)
    logger.info("dot1x_jit: deleted %s account %r (tenant %s)",
                BACKEND_LABELS.get(rec.get("backend"), rec.get("backend")),
                rec.get("username"), rec.get("tenant_id"))
    # Tell clients the credential is gone, if requested.
    if revoke and targets:
        await _deliver(hub, rec, None, revoke=True, targets=targets)


async def release(hub, tenant_id: str, hostname: str, username: str, backend: str) -> bool:
    """Unmap ``hostname``; delete the account once no hostname uses it.
    Returns True if the account was deleted."""
    # Validate inputs.
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    # Serialise work on this account.
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            return False
        # Unmap the hostname.
        (rec.get("hostnames") or {}).pop(str(hostname or "").strip(), None)
        _dirty(hub)
        # Other hostnames still use it: keep the account.
        if rec.get("hostnames"):
            return False
        # Last one gone: delete the account (the sweep retries on failure).
        try:
            await _delete_locked(hub, key, rec, revoke=False)
        except Dot1xJitError as e:
            logger.warning("dot1x_jit: release delete of %s failed (sweep will retry): %s", key, e)
            return False
        return True


async def rotate(hub, tenant_id: str, backend: str, username: str) -> Dict[str, Any]:
    """New random password → backend → vault → push to every mapped client.
    If the vault write fails the backend is reverted to the old password."""
    # Validate inputs.
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    # Serialise work on this account.
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            raise Dot1xJitError("no such account")
        # Keep the old password in case we need to revert.
        old = await _secret_get(hub, key, rec)
        # Set a new password in the backend.
        password = cloud_nac.gen_password()
        try:
            await _backend_upsert(hub, rec, password, owned=True)
        except Dot1xJitError as e:
            rec["last_error"] = f"rotate failed: {e}"
            _dirty(hub)
            raise
        # Store it; if that fails, put the old password back in the backend.
        try:
            await _secret_put(hub, key, rec, password)
        except Exception as e:  # noqa: BLE001
            if old:
                try:
                    await _backend_upsert(hub, rec, old, owned=True)
                except Exception as re_:  # noqa: BLE001
                    logger.error("dot1x_jit: %s backend now holds an unstored password "
                                 "(revert failed: %s)", key, re_)
            rec["last_error"] = f"vault write failed: {e}"
            _dirty(hub)
            raise Dot1xJitError(rec["last_error"]) from e
        # Success: stamp rotation, save, and push to all mapped clients.
        rec["rotated_at"] = time.time()
        rec.pop("last_error", None)
        await _persist(hub)
        logger.info("dot1x_jit: rotated %s password for %r (tenant %s)",
                    BACKEND_LABELS[backend], username, tenant_id)
        await _deliver(hub, rec, password)
        return public_record(rec)


async def delete(hub, tenant_id: str, backend: str, username: str) -> None:
    """Operator delete (My Users). Revokes the client's credential; if the
    engine still has the client on a JIT cell it re-provisions on its next pass."""
    # Validate inputs.
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    # Serialise work on this account, then delete and revoke.
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            raise Dot1xJitError("no such account")
        await _delete_locked(hub, key, rec, revoke=True)


async def sync(hub, tenant_id: str, spoke_id: str, active: List[Dict[str, Any]]) -> Dict[str, int]:
    """Spoke keep-alive. ``active`` = [{hostname, username, backend, cell,
    version}] — every client the spoke's engine currently holds on a JIT cell."""
    # Current time, hostnames reported, and counters.
    now = time.time()
    seen = set()
    stats = {"touched": 0, "provisioned": 0, "redelivered": 0, "released": 0}
    # Process each client the spoke reports.
    for item in active or []:
        # Skip invalid usernames/backends.
        try:
            username = normalize_username(item.get("username"))
            backend = normalize_backend(item.get("backend"))
        except Dot1xJitError:
            continue
        # Skip entries without a hostname.
        hostname = str(item.get("hostname") or "").strip()
        if not hostname:
            continue
        # Remember this (account, hostname) as still active.
        key = account_key(tenant_id, backend, username)
        seen.add((key, hostname))
        # Unknown or unmapped: provision it now.
        rec = _index(hub).get(key)
        if rec is None or rec.get("pending_delete") or hostname not in (rec.get("hostnames") or {}):
            try:
                await provision(hub, tenant_id, spoke_id, hostname, username, backend,
                                str(item.get("cell") or ""))
                stats["provisioned"] += 1
            except Dot1xJitError as e:
                logger.warning("dot1x_jit: sync provision %s/%s failed: %s", key, hostname, e)
            continue
        # Known: refresh activity and cell.
        hm = rec["hostnames"][hostname]
        hm.update({"spoke_id": spoke_id, "last_active": now})
        if item.get("cell"):
            hm["cell"] = str(item["cell"])
        rec["last_active_at"] = now
        stats["touched"] += 1
        # Client's credential version (rotated_at it last received).
        try:
            ver = float(item.get("version") or 0)
        except (TypeError, ValueError):
            ver = 0.0
        # Client has an older password: deliver the current one.
        if ver < float(rec.get("rotated_at") or 0) - 1:
            pw = await _secret_get(hub, key, rec)
            if pw:
                await _deliver(hub, rec, pw, only=[hostname])
                stats["redelivered"] += 1
    # Release hostnames on this spoke the spoke no longer reports (missed releases).
    for key, rec in list(_index(hub).items()):
        if rec.get("tenant_id") != tenant_id:
            continue
        for h, m in list((rec.get("hostnames") or {}).items()):
            if (m or {}).get("spoke_id") == spoke_id and (key, h) not in seen:
                await release(hub, tenant_id, h, rec["username"], rec["backend"])
                stats["released"] += 1
    # Mark state for saving and return the counts.
    _dirty(hub)
    return stats


# ── spoke messages ───────────────────────────────────────────────────────────

async def handle_spoke_message(hub, spoke_id: str, msg_type: str, data: Dict[str, Any]) -> None:
    """Entry point for CS_DOT1X_* frames from a cs spoke. Never raises."""
    # Resolve the spoke's tenant; spokes without one are ignored.
    data = data or {}
    try:
        tenant_id = hub.state.get_spoke_tenant(hub._primary_key(spoke_id))
    except Exception:  # noqa: BLE001
        tenant_id = None
    if not tenant_id:
        logger.warning("dot1x_jit: %s from %s ignored — spoke has no tenant", msg_type, spoke_id)
        return
    # Dispatch by message type; errors are logged, never raised.
    try:
        if msg_type == "CS_DOT1X_PROVISION":
            await provision(hub, tenant_id, spoke_id, data.get("hostname"), data.get("username"),
                            data.get("backend"), str(data.get("cell") or ""))
        elif msg_type == "CS_DOT1X_RELEASE":
            await release(hub, tenant_id, data.get("hostname"), data.get("username"),
                          data.get("backend"))
        elif msg_type == "CS_DOT1X_SYNC":
            stats = await sync(hub, tenant_id, spoke_id, data.get("active") or [])
            if any(v for k, v in stats.items() if k != "touched"):
                logger.info("dot1x_jit: sync from %s (tenant %s): %s", spoke_id, tenant_id, stats)
    except Dot1xJitError as e:
        logger.warning("[sync-error] dot1x_jit %s from %s (tenant %s) host=%s user=%s: %s",
                       msg_type, spoke_id, tenant_id, data.get("hostname"),
                       data.get("username"), e)
    except Exception:  # noqa: BLE001
        logger.exception("dot1x_jit: %s from %s failed", msg_type, spoke_id)


# ── sweep (rotation + cleanup) ───────────────────────────────────────────────

async def sweep(hub, now: Optional[float] = None, force_cleanup: bool = False) -> Dict[str, int]:
    """Rotate old passwords, retry pending deletes, and periodically delete unused accounts."""
    # Current time, config, metadata and counters.
    now = now or time.time()
    cfg = get_config(hub)
    meta = _meta(hub)
    out = {"rotated": 0, "deleted": 0, "errors": 0}
    # Cleanup runs every cleanup_interval_days (or when forced).
    cleanup = force_cleanup or (now - float(meta.get("last_cleanup") or 0)
                                >= cfg["cleanup_interval_days"] * _DAY)
    # Hostnames/accounts inactive since before this are unused.
    cutoff = now - cfg["unused_days"] * _DAY
    # Process each account.
    for key, rec in list(_index(hub).items()):
        tid, backend, username = rec.get("tenant_id"), rec.get("backend"), rec.get("username")
        try:
            # During cleanup, drop hostnames inactive too long.
            hs = rec.setdefault("hostnames", {})
            if cleanup:
                for h, m in list(hs.items()):
                    if float((m or {}).get("last_active") or 0) < cutoff:
                        hs.pop(h, None)
            # Account inactive too long?
            stale = float(rec.get("last_active_at") or rec.get("created_at") or 0) < cutoff
            # Delete accounts marked for delete, or (during cleanup) unused with no hostnames.
            if rec.get("pending_delete") or (cleanup and not hs and stale):
                async with _lock(key):
                    # Re-check under the lock that the record was not replaced meanwhile.
                    if _index(hub).get(key) is rec:
                        await _delete_locked(hub, key, rec, revoke=bool(hs))
                out["deleted"] += 1
                continue
            # Rotate passwords older than rotate_days.
            if now - float(rec.get("rotated_at") or 0) >= cfg["rotate_days"] * _DAY:
                await rotate(hub, tid, backend, username)
                out["rotated"] += 1
        # One account's failure does not stop the sweep.
        except Exception as e:  # noqa: BLE001
            out["errors"] += 1
            logger.warning("dot1x_jit: sweep %s failed: %s", key, e)
    # Record when cleanup last ran.
    if cleanup:
        meta["last_cleanup"] = now
    _dirty(hub)
    # Log only if something happened.
    if out["rotated"] or out["deleted"] or out["errors"]:
        logger.info("dot1x_jit sweep: %s (cleanup=%s)", out, cleanup)
    return out


async def run_sweep_loop(hub, tick_s: float = 3600.0, initial_delay_s: float = 300.0) -> None:
    """Run the sweep every ``tick_s`` seconds, after an initial delay, until cancelled."""
    # Let the hub settle first.
    await asyncio.sleep(initial_delay_s)
    while True:
        # Errors are logged; cancellation stops the loop.
        try:
            await sweep(hub)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("dot1x_jit sweep failed")
        await asyncio.sleep(tick_s)


# ── My Users (listing never includes a password) ─────────────────────────────

def public_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Return the account fields safe to show in My Users (never the password)."""
    # Mapped hostnames and last rotation time.
    hosts = rec.get("hostnames") or {}
    rotated = float(rec.get("rotated_at") or 0)
    # Public summary with a derived status.
    return {
        "tenant_id": rec.get("tenant_id"),
        "backend": rec.get("backend"),
        "backend_label": BACKEND_LABELS.get(rec.get("backend"), rec.get("backend")),
        "username": rec.get("username"),
        "identity": rec.get("upn") or rec.get("username"),
        "hostnames": sorted(hosts),
        "cells": sorted({(m or {}).get("cell") for m in hosts.values() if (m or {}).get("cell")}),
        "created_at": rec.get("created_at"),
        "rotated_at": rotated or None,
        "last_active_at": rec.get("last_active_at"),
        "password_store": "vault" if rec.get("store") == "kv" else "local",
        "status": "pending_delete" if rec.get("pending_delete") else ("error" if rec.get("last_error") else "active"),
        "last_error": rec.get("last_error") or "",
    }


def list_accounts(hub, tenant_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return public records for all accounts (or one tenant's), with next rotation time."""
    # Config and result rows.
    cfg = get_config(hub)
    rows = []
    # Filter by tenant if requested.
    for rec in _index(hub).values():
        if tenant_id and rec.get("tenant_id") != tenant_id:
            continue
        row = public_record(rec)
        # Add when the next rotation is due.
        if row["rotated_at"]:
            row["next_rotation_at"] = row["rotated_at"] + cfg["rotate_days"] * _DAY
        rows.append(row)
    # Sort by tenant, username, backend.
    rows.sort(key=lambda r: (str(r.get("tenant_id")), r["username"], r["backend"]))
    return rows


async def selftest(hub, tenant_id: str,
                   backends: Iterable[str] = BACKENDS) -> List[Dict[str, Any]]:
    """Operator check (/admin/ops/dot1x-jit-selftest): for each backend run the
    real lifecycle on a throwaway account — provision, rotate, delete.

    The test hostname has no spoke, so no credential is delivered anywhere.
    Delete is always attempted once provisioning succeeded, so a failed rotate
    never leaves a test account behind. Returns one row per backend:
    ``{backend, username, ok, steps: [{step, ok, error?}]}``.
    """
    # One result row per backend.
    out: List[Dict[str, Any]] = []
    for backend in backends:
        # Validate and pick a throwaway username.
        backend = normalize_backend(backend)
        username = f"lmjit-selftest-{uuid.uuid4().hex[:8]}"
        steps: List[Dict[str, Any]] = []

        async def _step(name, coro):
            """Await ``coro``, recording step ``name`` as ok or failed; returns True on success."""
            try:
                await coro
                steps.append({"step": name, "ok": True})
                return True
            except Exception as e:  # noqa: BLE001 — reported, not raised
                steps.append({"step": name, "ok": False, "error": str(e)})
                return False

        # Provision; if it worked, rotate and then always delete.
        if await _step("provision", provision(hub, tenant_id, "", "lmjit-selftest",
                                              username, backend)):
            await _step("rotate", rotate(hub, tenant_id, backend, username))
            await _step("delete", delete(hub, tenant_id, backend, username))
        # Record and log the backend's result.
        out.append({"backend": backend, "username": username,
                    "ok": all(s["ok"] for s in steps), "steps": steps})
        logger.info("dot1x_jit: selftest tenant=%s backend=%s ok=%s %s",
                    tenant_id, backend, out[-1]["ok"],
                    [s for s in steps if not s["ok"]])
    return out
