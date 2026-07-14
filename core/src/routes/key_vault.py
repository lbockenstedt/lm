"""Azure Key Vault DR admin routes (Setup → Azure → Key Vault).

Config + manual operations for the disaster-recovery kit stored in Azure Key
Vault (see ``key_vault.py``): rotate the local admin password (break-glass), push
the Fernet key, and push a rolling **min backup** (bootstrap bundle). The 7-day
automation runs on a schedule (``KeyVaultSchedulerMixin.run_key_vault_loop``);
these routes drive/test the same operations by hand.

Under ``/setup/`` so the access-control middleware gates them to admins.
"""
from __future__ import annotations

from api import HTTPException, Request, logger
from security.oidc import get_oidc_config
import key_vault as _kv


def register(app, hub, ctx):
    @app.get("/setup/key-vault")
    async def get_key_vault():
        cfg = _kv.get_config(hub)
        status = {"backups": [], "warning": ""}
        if cfg.get("vault_url"):
            try:
                names = await _kv.list_secret_names(get_oidc_config(hub), cfg["vault_url"],
                                                    prefix=cfg["backup_prefix"])
                status["backups"] = sorted(names)
            except Exception as e:  # noqa: BLE001
                status["warning"] = str(e)
        return {"config": cfg, "status": status, "admin_user": _kv.admin_uid(hub)}

    @app.post("/setup/key-vault")
    async def set_key_vault(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _kv.get_config(hub)
        for k in _kv.CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        cur["enabled"] = bool(cur.get("enabled", False))
        for k in ("retain", "rotate_days"):
            try:
                cur[k] = max(1, int(cur[k]))
            except (TypeError, ValueError):
                cur[k] = _kv.DEFAULTS[k]
        cur["vault_url"] = str(cur.get("vault_url") or "").strip()
        _kv.save_config(hub, {k: cur[k] for k in _kv.CFG_FIELDS})
        return {"status": "ok", "config": cur}

    @app.post("/setup/key-vault/test")
    async def test_key_vault(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _kv.get_config(hub))
        try:
            res = await _kv.test_connection(get_oidc_config(hub), cfg["vault_url"])
            return {"status": "ok", **res}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}

    @app.post("/setup/key-vault/rotate-admin")
    async def rotate_admin(request: Request):
        """Rotate the local admin password, push it to the vault, and invalidate
        that admin's sessions. BREAK-GLASS: afterwards it lives ONLY in the vault."""
        try:
            res = await _kv.do_rotate_admin(hub)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=502, detail=str(e))
        return {"status": "ok", **res}

    @app.post("/setup/key-vault/push-fernet")
    async def push_fernet(request: Request):
        try:
            res = await _kv.do_push_fernet(hub)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=502, detail=str(e))
        return {"status": "ok", **res}

    @app.post("/setup/key-vault/backup")
    async def backup_min(request: Request):
        """Push a min (bootstrap) backup as ``<prefix><YYYYMMDD>`` and prune to the
        newest ``retain`` daily copies."""
        try:
            res = await _kv.do_backup_min(hub)
        except _kv.KeyVaultError as e:
            code = 413 if "limit" in str(e) else 502
            raise HTTPException(status_code=code, detail=str(e))
        return {"status": "ok", **res}
