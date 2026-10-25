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
from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional

import access
import cloud_nac
import cloud_vault
from security.encryption import hub_encryption

logger = logging.getLogger("Dot1xJit")

BACKENDS = ("entra", "ldap", "clearpass")
BACKEND_LABELS = {"entra": "Entra ID", "ldap": "LDAP", "clearpass": "ClearPass"}
STATE_KEY = "dot1x_jit_accounts"
SECRETS_KEY = "dot1x_jit_secrets"
META_KEY = "dot1x_jit_meta"
CFG_KEY = "dot1x_jit"
CREDENTIAL_CMD = "CS_DOT1X_CREDENTIAL"
MESSAGE_TYPES = ("CS_DOT1X_PROVISION", "CS_DOT1X_RELEASE", "CS_DOT1X_SYNC")

_KV_PREFIX = "dot1x-"
_DAY = 86400.0
_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DEFAULTS = {"rotate_days": 30, "unused_days": 30, "cleanup_interval_days": 30,
             "cppm_role": "[Employee]"}

_locks: Dict[str, asyncio.Lock] = {}


class Dot1xJitError(Exception):
    """Provisioning/backend failure; the message is safe to surface."""


# ── config / state ───────────────────────────────────────────────────────────

def get_config(hub) -> Dict[str, Any]:
    gc = hub.state.system_state.get("global_config", {}) or {}
    cfg = dict(_DEFAULTS)
    cfg.update({k: v for k, v in (gc.get(CFG_KEY) or {}).items() if v not in (None, "")})
    for k in ("rotate_days", "unused_days", "cleanup_interval_days"):
        try:
            cfg[k] = max(1, int(cfg[k]))
        except (TypeError, ValueError):
            cfg[k] = _DEFAULTS[k]
    cfg["cppm_role"] = str(cfg.get("cppm_role") or _DEFAULTS["cppm_role"])
    return cfg


def set_config(hub, incoming: Dict[str, Any]) -> Dict[str, Any]:
    gc = hub.state.system_state.setdefault("global_config", {})
    cur = dict(gc.get(CFG_KEY) or {})
    for k in _DEFAULTS:
        if k in (incoming or {}):
            cur[k] = incoming[k]
    gc[CFG_KEY] = cur
    cfg = get_config(hub)
    gc[CFG_KEY] = cfg
    hub.state._mark_dirty()
    return cfg


def _index(hub) -> Dict[str, Dict[str, Any]]:
    return hub.state.system_state.setdefault(STATE_KEY, {})


def _blobs(hub) -> Dict[str, str]:
    return hub.state.system_state.setdefault(SECRETS_KEY, {})


def _meta(hub) -> Dict[str, Any]:
    return hub.state.system_state.setdefault(META_KEY, {})


def _dirty(hub) -> None:
    hub.state._mark_dirty()


async def _persist(hub) -> None:
    saver = getattr(hub.state, "save_state_now", None)
    if callable(saver):
        try:
            await saver()
            return
        except Exception as e:  # noqa: BLE001
            logger.warning("dot1x_jit: immediate state save failed (%s); marked dirty", e)
    _dirty(hub)


def account_key(tenant_id: str, backend: str, username: str) -> str:
    return f"{tenant_id}|{backend}|{username}"


def normalize_username(username: Any) -> str:
    u = str(username or "").strip().lower()
    if not _USERNAME_RE.match(u):
        raise Dot1xJitError(f"invalid 802.1X username {username!r}")
    return u


def normalize_backend(backend: Any) -> str:
    b = str(backend or "").strip().lower()
    if b not in BACKENDS:
        raise Dot1xJitError(f"unknown account location {backend!r}")
    return b


def _lock(key: str) -> asyncio.Lock:
    lk = _locks.get(key)
    if lk is None:
        lk = _locks[key] = asyncio.Lock()
    return lk


# ── password storage (cloud vault when enabled, else encrypted hub state) ────

def _vault_on(hub) -> bool:
    try:
        return cloud_vault.active_provider(hub) is not None
    except Exception:  # noqa: BLE001
        return False


async def _secret_put(hub, key: str, rec: Dict[str, Any], password: str) -> None:
    token = hub_encryption.encrypt(password).decode("ascii")
    old_kv = rec.get("kv_name") if rec.get("store") == "kv" else None
    if _vault_on(hub):
        name = old_kv or (_KV_PREFIX + uuid.uuid4().hex)
        await cloud_vault.set_secret(hub, name, token)
        _blobs(hub).pop(key, None)
        rec["store"], rec["kv_name"] = "kv", name
    else:
        _blobs(hub)[key] = token
        rec["store"] = "local"
        rec.pop("kv_name", None)
        if old_kv:
            await cloud_vault.delete_secret(hub, old_kv)


async def _secret_get(hub, key: str, rec: Dict[str, Any]) -> Optional[str]:
    try:
        if rec.get("store") == "kv":
            token = await cloud_vault.get_secret(hub, rec.get("kv_name") or "")
        else:
            token = _blobs(hub).get(key)
        if not token:
            return None
        return hub_encryption.decrypt(token.encode("ascii"))
    except Exception as e:  # noqa: BLE001
        logger.warning("dot1x_jit: secret read for %s failed: %s", key, e)
        return None


async def _secret_del(hub, key: str, rec: Dict[str, Any]) -> None:
    _blobs(hub).pop(key, None)
    if rec.get("store") == "kv" and rec.get("kv_name"):
        await cloud_vault.delete_secret(hub, rec["kv_name"])


# ── backends ─────────────────────────────────────────────────────────────────

async def _rr(hub, spoke_id: Optional[str], cmd: str, payload: Dict[str, Any],
              timeout: float = 30.0) -> Dict[str, Any]:
    if not spoke_id:
        raise Dot1xJitError(f"no spoke connected for {cmd}")
    res = await hub.request_response(spoke_id, cmd, payload, timeout=timeout)
    data = access.unwrap_spoke(res) if isinstance(res, dict) else res
    for d in (res, data):
        if isinstance(d, dict) and str(d.get("status", "")).upper() == "ERROR":
            raise Dot1xJitError(str(d.get("message") or f"{cmd} failed"))
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        data = data["data"]
    return data if isinstance(data, dict) else {}


def _nac_spoke(hub, tenant_id: str) -> Optional[str]:
    """Same resolution as routes/cppm.py ``_nac_spoke_for_request`` for a
    known tenant: the tenant's own ``nac_instances`` spoke, else a nac spoke
    bound to the tenant (or the shared-tenant spoke)."""
    instances = (hub.state.system_state.get("global_config", {}) or {}).get("nac_instances", []) or []
    inst = next((i for i in instances if isinstance(i, dict) and i.get("tenant_id") == tenant_id), None)
    sid = (inst or {}).get("spoke_id") or ""
    if sid and hub._primary_key(sid) in hub.active_connections:
        return sid
    return (hub.get_cppm_spoke_for_shared() if access.tenant_is_shared(tenant_id)
            else hub.get_cppm_spoke_for_tenant(tenant_id))


def _entra_cfg(hub):
    cfg = cloud_nac.get_config(hub.state.system_state)
    if not cfg.get("enabled") or not cfg.get("domain"):
        raise Dot1xJitError("Entra account location needs Cloud NAC configured "
                            "(Settings → Cloud → Cloud NAC: enabled + UPN domain)")
    from security.oidc import get_oidc_config
    return cfg, get_oidc_config(hub)


def _ldap_target(hub, tenant_id: str):
    slug = access.ldap_tenant_slug(hub, tenant_id)
    if not slug:
        raise Dot1xJitError("tenant has no directory OU slug")
    return hub.get_directory_spoke_for_tenant(tenant_id), slug


def _is_already_exists(msg: str) -> bool:
    m = (msg or "").lower()
    return "already exists" in m or "already_exists" in m


def _is_no_such(msg: str) -> bool:
    m = (msg or "").lower()
    return "no such object" in m or "no_such_object" in m or "not found" in m


async def _backend_upsert(hub, rec: Dict[str, Any], password: str, *, owned: bool) -> None:
    """Create the account (``owned=False``) or set its password (``owned`` —
    already in our index). Never takes over a pre-existing LDAP/ClearPass
    account we didn't create."""
    tid, backend, username = rec["tenant_id"], rec["backend"], rec["username"]
    if backend == "entra":
        cfg, oidc = _entra_cfg(hub)
        try:
            res = await cloud_nac.provision_user(oidc, cfg["domain"], username, password=password)
        except cloud_nac.CloudNacError as e:
            raise Dot1xJitError(str(e)) from e
        rec["upn"], rec["oid"] = res.get("upn"), res.get("oid")
        if cfg.get("group_id") and res.get("oid") and not owned:
            try:
                await cloud_nac.add_user_to_group(oidc, cfg["group_id"], res["oid"])
            except cloud_nac.CloudNacError as e:
                logger.warning("dot1x_jit: Entra group add for %s failed: %s", rec.get("upn"), e)
        return
    if backend == "ldap":
        spoke, slug = _ldap_target(hub, tid)
        rec["upn"] = f"{username}@{slug}"
        if owned:
            try:
                await _rr(hub, spoke, "LDAP_SET_PASSWORD",
                          {"tenant_slug": slug, "uid": username, "password": password})
                return
            except Dot1xJitError as e:
                if not _is_no_such(str(e)):
                    raise
        await _rr(hub, spoke, "LDAP_PROVISION_TENANT_OU", {"tenant_slug": slug}, timeout=60.0)
        try:
            await _rr(hub, spoke, "LDAP_CREATE_USER", {
                "tenant_slug": slug, "uid": username, "auth_mode": "local",
                "password": password,
                "attrs": {"cn": username, "sn": username,
                          "displayName": f"{username} (LM simulation 802.1X)"}})
        except Dot1xJitError as e:
            if _is_already_exists(str(e)):
                raise Dot1xJitError(f"LDAP user {username!r} already exists in the tenant "
                                    "OU and was not created by LM — refusing to take it over") from e
            raise
        return
    spoke = _nac_spoke(hub, tid)
    await _rr(hub, spoke, "CPPM_CREATE_LOCAL_USER", {
        "user_id": username, "password": password,
        "role_name": get_config(hub)["cppm_role"],
        "tenant_slug": access.ldap_tenant_slug(hub, tid) or tid})
    rec["upn"] = username


async def _backend_delete(hub, rec: Dict[str, Any]) -> None:
    tid, backend, username = rec["tenant_id"], rec["backend"], rec["username"]
    if backend == "entra":
        _cfg, oidc = _entra_cfg(hub)
        try:
            await cloud_nac.delete_user(oidc, rec.get("oid") or rec.get("upn"))
        except cloud_nac.CloudNacError as e:
            raise Dot1xJitError(str(e)) from e
        return
    if backend == "ldap":
        spoke, slug = _ldap_target(hub, tid)
        try:
            await _rr(hub, spoke, "LDAP_DELETE_USER", {"tenant_slug": slug, "uid": username})
        except Dot1xJitError as e:
            if not _is_no_such(str(e)):
                raise
        return
    await _rr(hub, _nac_spoke(hub, tid), "CPPM_DELETE_LOCAL_USER", {"user_id": username})


# ── credential delivery to cs spokes ─────────────────────────────────────────

def _by_spoke(rec: Dict[str, Any], only: Optional[Iterable[str]] = None) -> Dict[str, List[str]]:
    only = set(only) if only is not None else None
    out: Dict[str, List[str]] = {}
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
    sent = 0
    for sid, hs in (targets if targets is not None else _by_spoke(rec, only)).items():
        payload = {"username": rec["username"], "backend": rec["backend"],
                   "hostnames": sorted(hs), "version": rec.get("rotated_at") or 0}
        if revoke:
            payload["revoke"] = True
        else:
            payload["password"] = password
        try:
            await _rr(hub, sid, CREDENTIAL_CMD, payload, timeout=20.0)
            sent += len(hs)
        except Exception as e:  # noqa: BLE001 — spoke re-requests via SYNC
            logger.warning("dot1x_jit: %s %s → %s %s failed: %s", CREDENTIAL_CMD,
                           rec["username"], sid, hs, e)
    return sent


# ── account lifecycle ────────────────────────────────────────────────────────

def _entra_conflict(hub, tenant_id: str, username: str) -> Optional[str]:
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
    if not tenant_id:
        raise Dot1xJitError("spoke has no tenant")
    username, backend = normalize_username(username), normalize_backend(backend)
    hostname = str(hostname or "").strip()
    if not hostname:
        raise Dot1xJitError("missing hostname")
    key = account_key(tenant_id, backend, username)
    async with _lock(key):
        now = time.time()
        idx = _index(hub)
        rec = idx.get(key)
        password = None
        if rec is not None and not rec.get("pending_delete"):
            age = now - float(rec.get("rotated_at") or 0)
            if age < get_config(hub)["rotate_days"] * _DAY:
                password = await _secret_get(hub, key, rec)
        if password is None:
            if backend == "entra" and rec is None:
                other = _entra_conflict(hub, tenant_id, username)
                if other:
                    raise Dot1xJitError(f"Entra user {username!r} is already JIT-provisioned "
                                        f"for tenant {other!r}")
            new = rec is None
            work = dict(rec or {"tenant_id": tenant_id, "backend": backend, "username": username,
                                "hostnames": {}, "created_at": now})
            work.pop("pending_delete", None)
            password = cloud_nac.gen_password()
            try:
                await _backend_upsert(hub, work, password, owned=not new)
            except Dot1xJitError as e:
                if rec is not None:
                    rec["last_error"] = str(e)
                    _dirty(hub)
                raise
            try:
                await _secret_put(hub, key, work, password)
            except Exception as e:  # noqa: BLE001
                if new:
                    try:
                        await _backend_delete(hub, work)
                    except Exception as de:  # noqa: BLE001
                        logger.warning("dot1x_jit: rollback delete of %s failed: %s", key, de)
                raise Dot1xJitError(f"password vault write failed: {e}") from e
            work["rotated_at"] = now
            work.pop("last_error", None)
            rec = idx[key] = work
            logger.info("dot1x_jit: %s %s account %r for tenant %s (store=%s)",
                        "created" if new else "re-keyed", BACKEND_LABELS[backend],
                        username, tenant_id, rec.get("store"))
        rec.setdefault("hostnames", {})[hostname] = {"spoke_id": spoke_id, "cell": cell,
                                                     "last_active": now}
        rec["last_active_at"] = now
        await _persist(hub)
        await _deliver(hub, rec, password, only=[hostname])
        return public_record(rec)


async def _delete_locked(hub, key: str, rec: Dict[str, Any], *, revoke: bool) -> None:
    targets = _by_spoke(rec)
    try:
        await _backend_delete(hub, rec)
    except Exception as e:  # noqa: BLE001 — retried by the sweep
        rec["pending_delete"] = True
        rec["last_error"] = f"delete failed: {e}"
        _dirty(hub)
        raise Dot1xJitError(rec["last_error"]) from e
    await _secret_del(hub, key, rec)
    _index(hub).pop(key, None)
    await _persist(hub)
    logger.info("dot1x_jit: deleted %s account %r (tenant %s)",
                BACKEND_LABELS.get(rec.get("backend"), rec.get("backend")),
                rec.get("username"), rec.get("tenant_id"))
    if revoke and targets:
        await _deliver(hub, rec, None, revoke=True, targets=targets)


async def release(hub, tenant_id: str, hostname: str, username: str, backend: str) -> bool:
    """Unmap ``hostname``; delete the account once no hostname uses it.
    Returns True if the account was deleted."""
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            return False
        (rec.get("hostnames") or {}).pop(str(hostname or "").strip(), None)
        _dirty(hub)
        if rec.get("hostnames"):
            return False
        try:
            await _delete_locked(hub, key, rec, revoke=False)
        except Dot1xJitError as e:
            logger.warning("dot1x_jit: release delete of %s failed (sweep will retry): %s", key, e)
            return False
        return True


async def rotate(hub, tenant_id: str, backend: str, username: str) -> Dict[str, Any]:
    """New random password → backend → vault → push to every mapped client.
    If the vault write fails the backend is reverted to the old password."""
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            raise Dot1xJitError("no such account")
        old = await _secret_get(hub, key, rec)
        password = cloud_nac.gen_password()
        try:
            await _backend_upsert(hub, rec, password, owned=True)
        except Dot1xJitError as e:
            rec["last_error"] = f"rotate failed: {e}"
            _dirty(hub)
            raise
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
    username, backend = normalize_username(username), normalize_backend(backend)
    key = account_key(tenant_id, backend, username)
    async with _lock(key):
        rec = _index(hub).get(key)
        if rec is None:
            raise Dot1xJitError("no such account")
        await _delete_locked(hub, key, rec, revoke=True)


async def sync(hub, tenant_id: str, spoke_id: str, active: List[Dict[str, Any]]) -> Dict[str, int]:
    """Spoke keep-alive. ``active`` = [{hostname, username, backend, cell,
    version}] — every client the spoke's engine currently holds on a JIT cell."""
    now = time.time()
    seen = set()
    stats = {"touched": 0, "provisioned": 0, "redelivered": 0, "released": 0}
    for item in active or []:
        try:
            username = normalize_username(item.get("username"))
            backend = normalize_backend(item.get("backend"))
        except Dot1xJitError:
            continue
        hostname = str(item.get("hostname") or "").strip()
        if not hostname:
            continue
        key = account_key(tenant_id, backend, username)
        seen.add((key, hostname))
        rec = _index(hub).get(key)
        if rec is None or rec.get("pending_delete") or hostname not in (rec.get("hostnames") or {}):
            try:
                await provision(hub, tenant_id, spoke_id, hostname, username, backend,
                                str(item.get("cell") or ""))
                stats["provisioned"] += 1
            except Dot1xJitError as e:
                logger.warning("dot1x_jit: sync provision %s/%s failed: %s", key, hostname, e)
            continue
        hm = rec["hostnames"][hostname]
        hm.update({"spoke_id": spoke_id, "last_active": now})
        if item.get("cell"):
            hm["cell"] = str(item["cell"])
        rec["last_active_at"] = now
        stats["touched"] += 1
        try:
            ver = float(item.get("version") or 0)
        except (TypeError, ValueError):
            ver = 0.0
        if ver < float(rec.get("rotated_at") or 0) - 1:
            pw = await _secret_get(hub, key, rec)
            if pw:
                await _deliver(hub, rec, pw, only=[hostname])
                stats["redelivered"] += 1
    for key, rec in list(_index(hub).items()):
        if rec.get("tenant_id") != tenant_id:
            continue
        for h, m in list((rec.get("hostnames") or {}).items()):
            if (m or {}).get("spoke_id") == spoke_id and (key, h) not in seen:
                await release(hub, tenant_id, h, rec["username"], rec["backend"])
                stats["released"] += 1
    _dirty(hub)
    return stats


# ── spoke messages ───────────────────────────────────────────────────────────

async def handle_spoke_message(hub, spoke_id: str, msg_type: str, data: Dict[str, Any]) -> None:
    """Entry point for CS_DOT1X_* frames from a cs spoke. Never raises."""
    data = data or {}
    try:
        tenant_id = hub.state.get_spoke_tenant(hub._primary_key(spoke_id))
    except Exception:  # noqa: BLE001
        tenant_id = None
    if not tenant_id:
        logger.warning("dot1x_jit: %s from %s ignored — spoke has no tenant", msg_type, spoke_id)
        return
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
    now = now or time.time()
    cfg = get_config(hub)
    meta = _meta(hub)
    out = {"rotated": 0, "deleted": 0, "errors": 0}
    cleanup = force_cleanup or (now - float(meta.get("last_cleanup") or 0)
                                >= cfg["cleanup_interval_days"] * _DAY)
    cutoff = now - cfg["unused_days"] * _DAY
    for key, rec in list(_index(hub).items()):
        tid, backend, username = rec.get("tenant_id"), rec.get("backend"), rec.get("username")
        try:
            hs = rec.setdefault("hostnames", {})
            if cleanup:
                for h, m in list(hs.items()):
                    if float((m or {}).get("last_active") or 0) < cutoff:
                        hs.pop(h, None)
            stale = float(rec.get("last_active_at") or rec.get("created_at") or 0) < cutoff
            if rec.get("pending_delete") or (cleanup and not hs and stale):
                async with _lock(key):
                    if _index(hub).get(key) is rec:
                        await _delete_locked(hub, key, rec, revoke=bool(hs))
                out["deleted"] += 1
                continue
            if now - float(rec.get("rotated_at") or 0) >= cfg["rotate_days"] * _DAY:
                await rotate(hub, tid, backend, username)
                out["rotated"] += 1
        except Exception as e:  # noqa: BLE001
            out["errors"] += 1
            logger.warning("dot1x_jit: sweep %s failed: %s", key, e)
    if cleanup:
        meta["last_cleanup"] = now
    _dirty(hub)
    if out["rotated"] or out["deleted"] or out["errors"]:
        logger.info("dot1x_jit sweep: %s (cleanup=%s)", out, cleanup)
    return out


async def run_sweep_loop(hub, tick_s: float = 3600.0, initial_delay_s: float = 300.0) -> None:
    await asyncio.sleep(initial_delay_s)
    while True:
        try:
            await sweep(hub)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            logger.exception("dot1x_jit sweep failed")
        await asyncio.sleep(tick_s)


# ── My Users (listing never includes a password) ─────────────────────────────

def public_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    hosts = rec.get("hostnames") or {}
    rotated = float(rec.get("rotated_at") or 0)
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
    cfg = get_config(hub)
    rows = []
    for rec in _index(hub).values():
        if tenant_id and rec.get("tenant_id") != tenant_id:
            continue
        row = public_record(rec)
        if row["rotated_at"]:
            row["next_rotation_at"] = row["rotated_at"] + cfg["rotate_days"] * _DAY
        rows.append(row)
    rows.sort(key=lambda r: (str(r.get("tenant_id")), r["username"], r["backend"]))
    return rows
