"""Hub notifications config routes (Setup → Notifications).

Config + a send-test for the platform-level email channel (see
``notifications.py``): provider dropdown (Azure ACS / Gmail / Yahoo /
Office 365 / Generic), transport (ACS API default, SMTP fallback), sender +
recipients. ACS creds are auto-pulled from Key Vault at send time, so no
password is stored for ACS; non-ACS passwords are Fernet-encrypted at rest and
never echoed back to the UI (a ``has_password`` flag is returned instead).

Under ``/setup/`` so the access-control middleware gates it to admins.
"""
from __future__ import annotations

from api import Request
import notifications as _n
from security.encryption import hub_encryption


def register(app, hub, ctx):

    @app.get("/setup/notifications")
    async def get_notifications():
        cfg = _n.get_config(hub)
        has_password = bool(cfg.get("smtp_password_enc"))
        safe = {k: v for k, v in cfg.items() if k != "smtp_password_enc"}
        safe["has_password"] = has_password
        return {"config": safe}

    @app.post("/setup/notifications")
    async def set_notifications(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        cur = _n.get_config(hub)
        for k in _n.CFG_FIELDS:
            if k in incoming:
                cur[k] = incoming[k]
        cur["enabled"] = bool(cur.get("enabled", False))
        try:
            cur["smtp_port"] = int(cur.get("smtp_port") or _n.DEFAULTS["smtp_port"])
        except (TypeError, ValueError):
            cur["smtp_port"] = _n.DEFAULTS["smtp_port"]
        # recipients: accept list or comma/whitespace string → flat list
        cur["to_emails"] = _n._normalize_recipients(cur.get("to_emails"))
        cur["provider"] = str(cur.get("provider") or "azure_acs")
        cur["transport"] = str(cur.get("transport") or "api")
        cur["from_email"] = str(cur.get("from_email") or "").strip()
        cur["smtp_host"] = str(cur.get("smtp_host") or "").strip()
        cur["smtp_user"] = str(cur.get("smtp_user") or "").strip()
        cur["acs_kv_secret_name"] = str(cur.get("acs_kv_secret_name") or
                                        _n.DEFAULTS["acs_kv_secret_name"]).strip()
        cur["vault_url"] = str(cur.get("vault_url") or "").strip()

        if cur["provider"] == "azure_acs":
            # ACS creds live in Key Vault — never store a password here.
            cur["smtp_password_enc"] = ""
        else:
            # Incoming plaintext password (if any) → Fernet-encrypt at rest.
            # An empty/absent submission preserves the existing ciphertext so
            # the UI can save other fields without re-entering the password.
            new_pw = str(incoming.get("smtp_password") or "")
            if new_pw:
                cur["smtp_password_enc"] = hub_encryption.encrypt(new_pw).decode()
            elif "smtp_password" in incoming and incoming.get("smtp_password") == "":
                # Explicit clear.
                cur["smtp_password_enc"] = ""
            # else: keep whatever was already in cur["smtp_password_enc"]

        _n.save_config(hub, {k: cur.get(k) for k in _n.CFG_FIELDS})
        return {"status": "ok",
                "config": {k: cur[k] for k in _n.CFG_FIELDS if k != "smtp_password_enc"},
                "has_password": bool(cur.get("smtp_password_enc"))}

    @app.post("/setup/notifications/test")
    async def test_notifications(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        # Merge the posted form over the saved config so Test validates unsaved
        # edits (e.g. a freshly-typed password) without persisting.
        override = {}
        for k in _n.CFG_FIELDS:
            if k in incoming:
                override[k] = incoming[k]
        if incoming.get("smtp_password"):
            override["smtp_password"] = incoming["smtp_password"]
        try:
            res = await _n.send_test(hub, cfg_override=override or None)
            return res
        except _n.NotificationsError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            return {"status": "error", "message": str(e)}