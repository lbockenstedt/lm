"""Azure Key Vault hook (hub broker) — disaster-recovery kit off-box.

Pushes to an Azure Key Vault, authenticated with the SAME SSO app certificate
(``security.oidc.fetch_app_token`` → ``https://vault.azure.net/.default``):

  * the local **admin password** (rotated on a schedule — break-glass: after
    rotation it exists ONLY in the vault),
  * the config **Fernet key** (``LM_FERNET_KEY`` — needed to decrypt a backup),
  * rolling **min backups** (gzip+base64), keeping the most recent ``retain``
    daily copies. A min backup is NOT the full config (that's >25 KB — it lives in
    the real backup source) — it's just enough to bring a fresh hub back online:
    users/logins, the OIDC + Azure connection config, the OIDC cert/key, and the
    Fernet key. Restore it → the hub can auth to Azure and let admins log in →
    then restore the full backup from source.

The app registration needs the **Key Vault Secrets Officer** RBAC role (or a Set
secret access policy) on the vault. Key Vault secrets are capped at 25 KB, so a
min backup that exceeds that (many local users) is refused with a clear error.

Pure REST (no azure SDK). Errors carry the vault response body.
"""
from __future__ import annotations

import base64
import gzip
import logging
import secrets
import string
from typing import Any, Dict, List, Optional

import httpx

from security.oidc import OidcConfig, fetch_app_token

logger = logging.getLogger("KeyVault")

_SCOPE = "https://vault.azure.net/.default"
_API = "7.4"
_MAX_SECRET_BYTES = 25 * 1024  # Key Vault hard limit on secret value size


class KeyVaultError(Exception):
    """Raised for any Key Vault failure; message is safe to surface."""


def gen_password(n: int = 24) -> str:
    """Random password meeting complexity (all four classes), length ``n``."""
    lo, up, dg = string.ascii_lowercase, string.ascii_uppercase, string.digits
    sy = "!@#$%^&*()-_=+"
    n = max(12, n)
    pw = [secrets.choice(lo), secrets.choice(up), secrets.choice(dg), secrets.choice(sy)]
    allc = lo + up + dg + sy
    pw += [secrets.choice(allc) for _ in range(n - 4)]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def encode_config_secret(raw: bytes) -> str:
    """gzip + base64 the (already-encrypted) state bytes for a Key Vault secret;
    raise if the result exceeds the 25 KB secret limit."""
    blob = base64.b64encode(gzip.compress(raw)).decode()
    if len(blob) > _MAX_SECRET_BYTES:
        raise KeyVaultError(
            f"config backup is {len(blob)} bytes compressed — over Key Vault's "
            f"{_MAX_SECRET_BYTES}-byte secret limit; use Azure Blob Storage for backups")
    return blob


def decode_config_secret(blob: str) -> bytes:
    return gzip.decompress(base64.b64decode(blob))


def _base(vault_url: str) -> str:
    return str(vault_url or "").rstrip("/")


async def _token(cfg: OidcConfig, http: Optional[httpx.AsyncClient] = None) -> str:
    return await fetch_app_token(cfg, _SCOPE, http=http)


async def set_secret(cfg: OidcConfig, vault_url: str, name: str, value: str,
                     http: Optional[httpx.AsyncClient] = None) -> str:
    """PUT a secret (new version). Returns the secret id."""
    if not vault_url:
        raise KeyVaultError("Key Vault URL not configured")
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.put(url, headers={"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"},
                           json={"value": value})
    if resp.status_code not in (200, 201):
        raise KeyVaultError(f"Key Vault PUT {name} failed: HTTP {resp.status_code} — {resp.text[:300]}")
    return resp.json().get("id", "")


async def get_secret(cfg: OidcConfig, vault_url: str, name: str,
                     http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise KeyVaultError(f"Key Vault GET {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return resp.json().get("value")


async def list_secret_names(cfg: OidcConfig, vault_url: str, prefix: str = "",
                            http: Optional[httpx.AsyncClient] = None) -> List[str]:
    """All secret names (optionally prefix-filtered), paged."""
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets?api-version={_API}"
    out: List[str] = []
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        while url:
            resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                raise KeyVaultError(f"Key Vault list failed: HTTP {resp.status_code} — {resp.text[:200]}")
            body = resp.json()
            for item in body.get("value", []):
                sid = item.get("id", "")
                nm = sid.rsplit("/", 1)[-1]
                if nm and (not prefix or nm.startswith(prefix)):
                    out.append(nm)
            url = body.get("nextLink")
    return out


async def delete_secret(cfg: OidcConfig, vault_url: str, name: str,
                        http: Optional[httpx.AsyncClient] = None) -> bool:
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.delete(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code not in (200, 204, 404):
        raise KeyVaultError(f"Key Vault DELETE {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


async def test_connection(cfg: OidcConfig, vault_url: str,
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """List secrets to confirm the token + RBAC + URL resolve. Returns a count."""
    names = await list_secret_names(cfg, vault_url, http=http)
    return {"ok": True, "secret_count": len(names)}


# ---------------------------------------------------------------------------
# Hub-level operations (shared by the WebUI routes and the 7-day scheduler).
# These touch hub state and the api helpers; api is imported lazily to avoid a
# circular import at module load (api imports the route modules).
# ---------------------------------------------------------------------------

import datetime as _dt
import json as _json
import os as _os
import time as _time

CFG_FIELDS = ("enabled", "vault_url", "admin_secret", "fernet_secret",
              "backup_prefix", "retain", "rotate_days")
DEFAULTS = {"enabled": False, "vault_url": "", "admin_secret": "lm-admin-password",
            "fernet_secret": "lm-fernet-key", "backup_prefix": "lm-min-backup-",
            "retain": 7, "rotate_days": 7}


def get_config(hub) -> dict:
    c = dict(DEFAULTS)
    c.update((hub.state.system_state.get("global_config", {}) or {}).get("key_vault", {}) or {})
    return c


def save_config(hub, cfg: dict) -> None:
    gc = hub.state.system_state.get("global_config", {})
    gc["key_vault"] = cfg
    hub.state.system_state["global_config"] = gc
    hub.state._mark_dirty()


def admin_uid(hub) -> Optional[str]:
    users = hub.state.system_state.get("users", {}) or {}
    for uid, u in users.items():
        if isinstance(u, dict) and u.get("protected"):
            return uid
    return next(iter(users), None)


def build_min_backup(hub) -> bytes:
    """Bootstrap bundle: enough to bring a fresh hub online (Azure connection +
    logins + Fernet key + a pointer to the real backup source). NOT the full
    config (that's >25 KB — it lives in the backup source)."""
    from security.oidc import get_oidc_config
    from security.credential_store import resolve_private_key_material
    ss = hub.state.system_state
    gc = ss.get("global_config", {}) or {}
    oidc_cfg = get_oidc_config(hub)

    def _read(p):
        try:
            b = resolve_private_key_material(p) if p else None
            return b.decode() if b else ""
        except Exception:  # noqa: BLE001
            return ""

    bundle = {
        "kind": "lm-min-backup", "version": 1,
        "created": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "users": ss.get("users", {}),
        "permission_groups": ss.get("permission_groups", {}),
        # Azure connection + the backup SOURCE (self_backup = where the full
        # backup lives), so a recovered hub can call home to Azure, let admins
        # in, and knows where to pull the real backup from.
        "global_config": {k: gc.get(k) for k in
                          ("oidc", "key_vault", "azure_nsg", "cloud_nac", "self_backup") if k in gc},
        "tenants": (ss.get("tenant_state", {}) or {}).get("tenants", {}),
        "oidc_cert_pem": _read(getattr(oidc_cfg, "cert_path", "")),
        "oidc_key_pem": _read(getattr(oidc_cfg, "key_path", "")),
        "fernet_key": _os.environ.get("LM_FERNET_KEY", ""),
    }
    return _json.dumps(bundle).encode()


async def do_rotate_admin(hub) -> Dict[str, Any]:
    """Rotate the local admin password → push to the vault FIRST → then set the
    local hash + invalidate sessions. Break-glass: after this the password lives
    only in the vault. Raises KeyVaultError on vault failure (no local change)."""
    from api import _hash_password, _invalidate_user_sessions
    from security.oidc import get_oidc_config
    cfg = get_config(hub)
    if not cfg.get("vault_url"):
        raise KeyVaultError("Key Vault URL not configured")
    uid = admin_uid(hub)
    if not uid:
        raise KeyVaultError("no local admin account found")
    pw = gen_password()
    await set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["admin_secret"], pw)
    hub.state.system_state["users"][uid]["password_hash"] = _hash_password(pw)
    hub.state.system_state["users"][uid]["updated_at"] = _time.time()
    cfg["last_rotate"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_config(hub, cfg)
    try:
        _invalidate_user_sessions(hub, uid)
    except Exception as e:  # noqa: BLE001
        logger.warning("Key Vault: session invalidation for '%s' failed: %s", uid, e)
    logger.info("Key Vault: rotated admin '%s' password → secret '%s'", uid, cfg["admin_secret"])
    return {"admin_user": uid, "secret": cfg["admin_secret"]}


async def do_push_fernet(hub) -> Dict[str, Any]:
    from security.oidc import get_oidc_config
    cfg = get_config(hub)
    fk = _os.environ.get("LM_FERNET_KEY", "").strip()
    if not fk:
        raise KeyVaultError("LM_FERNET_KEY is not set in the hub environment")
    await set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["fernet_secret"], fk)
    return {"secret": cfg["fernet_secret"]}


async def do_backup_min(hub) -> Dict[str, Any]:
    """Push a min backup as ``<prefix><YYYYMMDD>`` and prune to the newest
    ``retain`` daily copies."""
    from security.oidc import get_oidc_config
    cfg = get_config(hub)
    if not cfg.get("vault_url"):
        raise KeyVaultError("Key Vault URL not configured")
    oidc = get_oidc_config(hub)
    blob = encode_config_secret(build_min_backup(hub))
    day = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d")
    name = f"{cfg['backup_prefix']}{day}"
    await set_secret(oidc, cfg["vault_url"], name, blob)
    names = sorted(await list_secret_names(oidc, cfg["vault_url"], prefix=cfg["backup_prefix"]))
    retain = max(1, int(cfg.get("retain", 7) or 7))
    pruned = names[:-retain] if len(names) > retain else []
    for old in pruned:
        await delete_secret(oidc, cfg["vault_url"], old)
    cfg["last_backup"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
    save_config(hub, cfg)
    logger.info("Key Vault: min backup '%s' pushed (%d bytes), pruned %d old", name, len(blob), len(pruned))
    return {"secret": name, "size": len(blob), "pruned": pruned}


def apply_min_backup(hub, bundle: dict) -> Dict[str, Any]:
    """Restore a min bootstrap bundle onto THIS hub: replace users, permission
    groups, the bootstrap global_config subset and tenants, and write the OIDC
    cert/key back to disk so SSO/Azure work again. Returns a summary including
    the Fernet key + the backup-source pointer so the operator can then pull the
    full backup. Does NOT swap LM_FERNET_KEY (that's an env var / process-level)."""
    if not isinstance(bundle, dict) or bundle.get("kind") != "lm-min-backup":
        raise KeyVaultError("not a Lab Manager min backup (missing kind=lm-min-backup)")
    from security.oidc import get_oidc_config
    ss = hub.state.system_state
    if isinstance(bundle.get("users"), dict):
        ss["users"] = bundle["users"]
    if isinstance(bundle.get("permission_groups"), dict):
        ss["permission_groups"] = bundle["permission_groups"]
    gc = ss.setdefault("global_config", {})
    for k, v in (bundle.get("global_config") or {}).items():
        gc[k] = v
    if isinstance(bundle.get("tenants"), dict):
        ts = ss.setdefault("tenant_state", {})
        ts["tenants"] = bundle["tenants"]
    wrote = []
    oidc_cfg = get_oidc_config(hub)
    for pem_key, path_attr in (("oidc_cert_pem", "cert_path"), ("oidc_key_pem", "key_path")):
        pem = bundle.get(pem_key)
        path = getattr(oidc_cfg, path_attr, "")
        if pem and path:
            try:
                _os.makedirs(_os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(pem)
                if path_attr == "key_path":
                    _os.chmod(path, 0o600)
                wrote.append(path)
            except Exception as e:  # noqa: BLE001
                logger.warning("Key Vault restore: could not write %s: %s", path, e)
    hub.state.save_state()
    logger.info("Key Vault: restored min backup (users=%d, wrote %d cert files)",
                len(bundle.get("users", {}) or {}), len(wrote))
    self_backup = (bundle.get("global_config") or {}).get("self_backup") or {}
    return {
        "users": len(bundle.get("users", {}) or {}),
        "permission_groups": len(bundle.get("permission_groups", {}) or {}),
        "tenants": len(bundle.get("tenants", {}) or {}),
        "cert_files": wrote,
        "fernet_key_present": bool(bundle.get("fernet_key")),
        "fernet_key": bundle.get("fernet_key", ""),
        "backup_source": {k: self_backup.get(k) for k in
                          ("ssh_host", "ssh_user", "ssh_path", "ssh_port")
                          if k in self_backup},
        "created": bundle.get("created", ""),
    }


def _iso_age_days(iso: str) -> float:
    """Days since an ISO timestamp; a large number if unparseable/empty."""
    if not iso:
        return 1e9
    try:
        t = _dt.datetime.fromisoformat(iso)
        if t.tzinfo is None:
            t = t.replace(tzinfo=_dt.timezone.utc)
        return (_dt.datetime.now(_dt.timezone.utc) - t).total_seconds() / 86400.0
    except Exception:  # noqa: BLE001
        return 1e9


class KeyVaultSchedulerMixin:
    """Drives the DR automation: rotate the admin password every ``rotate_days``
    and push a min backup daily. Mixed into the hub; started from startup."""

    async def run_key_vault_loop(self):
        # Stagger well past boot syncs; the cadence is day-scale so a ~10 min
        # poll is plenty responsive to a config change.
        await __import__("asyncio").sleep(180)
        asyncio = __import__("asyncio")
        while True:
            try:
                cfg = get_config(self)
                if not cfg.get("enabled", False) or not cfg.get("vault_url"):
                    await asyncio.sleep(600)
                    continue
                rotate_days = max(1, int(cfg.get("rotate_days", 7) or 7))
                if _iso_age_days(cfg.get("last_rotate", "")) >= rotate_days:
                    try:
                        await do_rotate_admin(self)
                    except Exception as e:  # noqa: BLE001
                        logger.warning("Key Vault: scheduled admin rotation failed: %s", e)
                # Daily min backup (the prefix carries a per-day name, so a repeat
                # within the same day just overwrites that day's secret).
                if _iso_age_days(cfg.get("last_backup", "")) >= 1.0:
                    try:
                        await do_backup_min(self)
                    except Exception as e:  # noqa: BLE001
                        logger.warning("Key Vault: scheduled min backup failed: %s", e)
                await asyncio.sleep(600)
            except Exception as e:  # noqa: BLE001
                logger.warning("[sync-error] key-vault loop cycle failed: %s", e)
                await asyncio.sleep(120)
