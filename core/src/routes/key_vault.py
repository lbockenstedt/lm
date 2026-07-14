"""Azure Key Vault DR admin routes (Setup → Azure → Key Vault).

Config + manual operations for the disaster-recovery kit stored in Azure Key
Vault (see ``key_vault.py``): rotate the local admin password (break-glass), push
the Fernet key, and push a rolling **min backup** (bootstrap bundle). The 7-day
automation runs on a schedule (wired in main); these routes drive/test it by hand.

Under ``/setup/`` so the access-control middleware gates them to admins.
"""
from __future__ import annotations

import datetime
import json
import os
import time

from api import HTTPException, Request, logger, _hash_password, _invalidate_user_sessions
from security.oidc import get_oidc_config
from security.credential_store import resolve_private_key_material
import key_vault as _kv

_CFG_FIELDS = ("enabled", "vault_url", "admin_secret", "fernet_secret",
               "backup_prefix", "retain", "rotate_days")
_DEFAULTS = {"enabled": False, "vault_url": "", "admin_secret": "lm-admin-password",
             "fernet_secret": "lm-fernet-key", "backup_prefix": "lm-min-backup-",
             "retain": 7, "rotate_days": 7}


def register(app, hub, ctx):
    def _cfg() -> dict:
        c = dict(_DEFAULTS)
        c.update((hub.state.system_state.get("global_config", {}) or {}).get("key_vault", {}) or {})
        return c

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["key_vault"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state.save_state()

    def _admin_uid():
        users = hub.state.system_state.get("users", {}) or {}
        for uid, u in users.items():
            if isinstance(u, dict) and u.get("protected"):
                return uid
        return next(iter(users), None)

    def _build_min_backup() -> bytes:
        """The bootstrap bundle: enough to bring a fresh hub online (Azure conn +
        logins + Fernet key). Deliberately small — NOT the full config."""
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
            "users": ss.get("users", {}),
            "permission_groups": ss.get("permission_groups", {}),
            # Azure connection + the backup SOURCE (self_backup = where the full
            # backup lives), so a recovered hub can call home to Azure, let admins
            # in, and knows where to pull the real backup from.
            "global_config": {k: gc.get(k) for k in
                              ("oidc", "key_vault", "azure_nsg", "cloud_nac", "self_backup") if k in gc},
            "tenants": (ss.get("tenant_state", {}) or {}).get("tenants", {}),
            "oidc_cert_pem": _read(oidc_cfg.cert_path),
            "oidc_key_pem": _read(oidc_cfg.key_path),
            "fernet_key": os.environ.get("LM_FERNET_KEY", ""),
        }
        return json.dumps(bundle).encode()

    @app.get("/setup/key-vault")
    async def get_key_vault():
        cfg = _cfg()
        status = {"backups": [], "warning": ""}
        if cfg.get("vault_url"):
            try:
                names = await _kv.list_secret_names(get_oidc_config(hub), cfg["vault_url"],
                                                    prefix=cfg["backup_prefix"])
                status["backups"] = sorted(names)
            except Exception as e:  # noqa: BLE001
                status["warning"] = str(e)
        return {"config": cfg, "status": status,
                "admin_user": _admin_uid()}

    @app.post("/setup/key-vault")
    async def set_key_vault(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _cfg()
        for k in _CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        cur["enabled"] = bool(cur.get("enabled", False))
        for k in ("retain", "rotate_days"):
            try:
                cur[k] = max(1, int(cur[k]))
            except (TypeError, ValueError):
                cur[k] = _DEFAULTS[k]
        cur["vault_url"] = str(cur.get("vault_url") or "").strip()
        _save({k: cur[k] for k in _CFG_FIELDS})
        return {"status": "ok", "config": cur}

    @app.post("/setup/key-vault/test")
    async def test_key_vault(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _cfg())
        try:
            res = await _kv.test_connection(get_oidc_config(hub), cfg["vault_url"])
            return {"status": "ok", **res}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    @app.post("/setup/key-vault/rotate-admin")
    async def rotate_admin(request: Request):
        """Rotate the local admin password, push the new one to the vault, and
        invalidate that admin's sessions. BREAK-GLASS: the new password then lives
        ONLY in the vault — retrieve it from there to log in."""
        cfg = _cfg()
        if not cfg.get("vault_url"):
            raise HTTPException(status_code=400, detail="set the Key Vault URL first")
        uid = _admin_uid()
        if not uid:
            raise HTTPException(status_code=409, detail="no local admin account found")
        pw = _kv.gen_password()
        try:
            await _kv.set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["admin_secret"], pw)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=502, detail=str(e))
        # Only change the local password AFTER the vault write succeeds, so a vault
        # failure can't lock the admin out with a password nobody has.
        hub.state.system_state["users"][uid]["password_hash"] = _hash_password(pw)
        hub.state.system_state["users"][uid]["updated_at"] = time.time()
        cfg["last_rotate"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _save(cfg)
        _invalidate_user_sessions(hub, uid)
        logger.info("Key Vault: rotated admin '%s' password → secret '%s'", uid, cfg["admin_secret"])
        return {"status": "ok", "admin_user": uid, "secret": cfg["admin_secret"]}

    @app.post("/setup/key-vault/push-fernet")
    async def push_fernet(request: Request):
        cfg = _cfg()
        fk = os.environ.get("LM_FERNET_KEY", "").strip()
        if not fk:
            raise HTTPException(status_code=409, detail="LM_FERNET_KEY is not set in the hub environment")
        try:
            await _kv.set_secret(get_oidc_config(hub), cfg["vault_url"], cfg["fernet_secret"], fk)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=502, detail=str(e))
        return {"status": "ok", "secret": cfg["fernet_secret"]}

    @app.post("/setup/key-vault/backup")
    async def backup_min(request: Request):
        """Push a min (bootstrap) backup as ``<prefix><YYYYMMDD>`` and prune to the
        newest ``retain`` daily copies."""
        cfg = _cfg()
        if not cfg.get("vault_url"):
            raise HTTPException(status_code=400, detail="set the Key Vault URL first")
        oidc = get_oidc_config(hub)
        try:
            blob = _kv.encode_config_secret(_build_min_backup())
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=413, detail=str(e))
        day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
        name = f"{cfg['backup_prefix']}{day}"
        try:
            await _kv.set_secret(oidc, cfg["vault_url"], name, blob)
            names = sorted(await _kv.list_secret_names(oidc, cfg["vault_url"], prefix=cfg["backup_prefix"]))
            pruned = names[:-int(cfg["retain"])] if len(names) > int(cfg["retain"]) else []
            for old in pruned:
                await _kv.delete_secret(oidc, cfg["vault_url"], old)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=502, detail=str(e))
        cfg["last_backup"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _save(cfg)
        logger.info("Key Vault: min backup '%s' pushed (%d bytes), pruned %d old",
                    name, len(blob), len(pruned))
        return {"status": "ok", "secret": name, "size": len(blob), "pruned": pruned}
