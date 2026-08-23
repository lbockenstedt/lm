"""Azure Key Vault DR admin routes (Setup → Azure → Key Vault).

Config + manual operations for the disaster-recovery kit stored in Azure Key
Vault (see ``key_vault.py``): rotate the local admin password (break-glass), push
the Fernet key, and push a rolling **min backup** (bootstrap bundle). The 7-day
automation runs on a schedule (``KeyVaultSchedulerMixin.run_key_vault_loop``);
these routes drive/test the same operations by hand.

Under ``/setup/`` so the access-control middleware gates them to admins.
"""
from __future__ import annotations

import json
import os

from cryptography.fernet import Fernet
from fastapi import Response

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

    @app.post("/setup/key-vault/test-fernet-tier1")
    async def test_fernet_tier1(request: Request):
        """Diagnostic for the Tier-1 Fernet-key-from-Key-Vault boot path
        (security/encryption.py's ``_resolve_primary_key``) — a DIFFERENT
        auth mechanism than every other route in this file (which all use the
        SSO app-cert token via ``security.oidc``). Tier-1 uses
        ``security.credential_store``'s ``DefaultAzureCredential`` (managed
        identity / az-cli / env chain), driven by the SAME raw env vars the
        hub reads at boot (``LM_KEYVAULT_URL``, ``LM_FERNET_KEY_KV_SECRET``,
        optional ``LM_KEYVAULT_CLIENT_ID``) — deliberately NOT
        ``global_config``, since at real boot time config isn't decryptable
        yet (it's encrypted with the very key being resolved). Reads exactly
        those env vars so a "PASS" here means a restart would actually work.

        Never returns the secret's VALUE — only whether it was found and
        whether it parses as a valid Fernet key — so this diagnostic can't
        become a way to exfiltrate the master encryption key over the API."""
        from security.credential_store import get_credential_provider

        secret_name = (os.getenv("LM_FERNET_KEY_KV_SECRET") or "").strip()
        vault_url = (os.getenv("LM_KEYVAULT_URL") or "").strip()
        diag = {"kv_secret_env_set": bool(secret_name), "vault_url_env_set": bool(vault_url)}
        if not secret_name:
            return {"status": "error",
                    "message": "LM_FERNET_KEY_KV_SECRET is not set on this hub process — "
                              "nothing to test yet. Set it in .env and restart before testing.",
                    **diag}
        try:
            provider = get_credential_provider()
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": f"could not build a credential provider: {e}", **diag}
        diag["provider"] = getattr(provider, "name", "")
        diag["ready"] = bool(getattr(provider, "ready", False))
        if diag["provider"] != "keyvault":
            return {"status": "error",
                    "message": "Resolved provider is 'env', not 'keyvault' — check LM_KEYVAULT_URL "
                              "and that azure-identity/azure-keyvault-secrets are installed.",
                    **diag}
        if not diag["ready"]:
            return {"status": "error",
                    "message": "Key Vault provider is not ready (missing SDK or invalid vault URL).",
                    **diag}
        try:
            value = provider.get_secret(secret_name)
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": f"get_secret raised: {e}", **diag}
        diag["secret_found"] = bool(value)
        if not value:
            return {"status": "error",
                    "message": f"Secret '{secret_name}' was not found in the vault (or the fetch "
                              f"failed — check the hub log for a 'Key Vault fetch' warning).",
                    **diag}
        try:
            Fernet(value.encode())
            diag["valid_fernet_key"] = True
        except Exception:
            diag["valid_fernet_key"] = False
        if not diag["valid_fernet_key"]:
            return {"status": "error",
                    "message": f"Secret '{secret_name}' was fetched but is NOT a valid Fernet key.",
                    **diag}
        return {"status": "ok",
                "message": f"Secret '{secret_name}' fetched from Key Vault and is a valid Fernet "
                          f"key — a restart with only LM_FERNET_KEY_KV_SECRET set would boot on it.",
                **diag}

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

    @app.get("/setup/key-vault/download-min")
    async def download_min():
        """Download the current min bootstrap bundle as a JSON file — the offline
        DR seed (keep it somewhere safe / off this hub). Upload it back via
        /restore on a fresh hub to bring logins + Azure + the backup source up."""
        raw = _kv.build_min_backup(hub)
        return Response(content=raw, media_type="application/json", headers={
            "Content-Disposition": 'attachment; filename="lm-min-backup.json"'})

    @app.post("/setup/key-vault/restore")
    async def restore_min(request: Request):
        """Restore a min bootstrap bundle. Body is either an uploaded bundle
        ({"bundle": {...}}) or {"from_vault": "<secret-name>"} to pull it from
        the vault. Applies users/logins + Azure config + OIDC cert/key, and
        returns the Fernet key + backup-source pointer for the full restore."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        bundle = (body or {}).get("bundle")
        secret = (body or {}).get("from_vault")
        if not bundle and secret:
            cfg = _kv.get_config(hub)
            if not cfg.get("vault_url"):
                raise HTTPException(status_code=400, detail="set the Key Vault URL first")
            try:
                blob = await _kv.get_secret(get_oidc_config(hub), cfg["vault_url"], secret)
            except _kv.KeyVaultError as e:
                raise HTTPException(status_code=502, detail=str(e))
            if not blob:
                raise HTTPException(status_code=404, detail=f"secret '{secret}' not found in the vault")
            try:
                bundle = json.loads(_kv.decode_config_secret(blob).decode())
            except Exception as e:  # noqa: BLE001
                raise HTTPException(status_code=422, detail=f"could not decode backup: {e}")
        if not isinstance(bundle, dict):
            raise HTTPException(status_code=400, detail="no bundle provided (upload a file or set from_vault)")
        try:
            res = _kv.apply_min_backup(hub, bundle)
        except _kv.KeyVaultError as e:
            raise HTTPException(status_code=400, detail=str(e))
        logger.warning("Key Vault: min backup RESTORED via WebUI (users=%s)", res.get("users"))
        return {"status": "ok", **res}
