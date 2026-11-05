"""OCI Vault credential-store admin routes (Setup → OCI Vault).

Manage the hub's OCI Vault/Secrets connection — the OCI parity feature for
``routes/key_vault.py``. Auth is an OCI API signing key (see ``oci_vault`` /
``OciConfig``); the user backing the key needs an IAM policy granting
``manage secret-family`` (to create/update secrets) and ``manage vaults``
(read-only use is enough for the connectivity test) in the vault's
compartment.

Config lives in ``global_config['oci_vault']`` (admin-set), a SEPARATE
auth/config block from ``oci_nsg`` — see ``oci_vault.py``'s module docstring
for why. All routes are under ``/setup/`` so the access-control middleware
already gates them to admins.

Scope note: unlike ``routes/key_vault.py``, there is no OCI equivalent of the
Azure-only disaster-recovery scheduler (admin-password rotation, min-backup
bundles) — that automation stays Azure-specific; this route only exposes the
core connection config + get/set/test operations that ``cloud_vault.py``
needs.
"""
# Postponed evaluation of annotations so type hints stay plain strings at runtime.
from __future__ import annotations

# Shared OCI auth helpers: validating and writing the uploaded API signing key.
import oci_auth
# Request/exception types and the shared logger from the main API module.
from api import HTTPException, Request, logger
# The OCI Vault client (config lookup, connection test); aliased to keep route code short.
import oci_vault as _kv

# Whitelisted, persisted config fields. Auth (tenancy_ocid/user_ocid/
# fingerprint/key_path) is never a secret VALUE here — key_path is itself a
# credential_store reference (kv:<name> / path), same as Entra's key_path.
_FIELDS = ("enabled", "tenancy_ocid", "user_ocid", "fingerprint", "key_path",
          "region", "compartment_id", "vault_id", "key_id")

# Sub-directory and file name (under the hub's data dir) for the uploaded vault signing key.
# Fixed on-box path the uploaded OCI API signing key is written to (0600) via
# oci_auth.write_uploaded_private_key — a SEPARATE file from oci_nsg's own
# key (each OCI feature owns its own auth block; see the module docstring).
_KEY_UPLOAD_SUBDIR = "oci"
_KEY_UPLOAD_FILENAME = "oci-vault-api-key.pem"


def register(app, hub, ctx):
    """Attach the OCI Vault setup routes to the web app.

    Args: app is the web application, hub is the running LM hub, ctx carries shared route helpers
    (unused here).
    """
    def _cfg() -> dict:
        """Return a copy of the stored OCI Vault config (empty dict when never configured)."""
        # Copy so callers can modify the result without changing the live state by accident.
        return dict(hub.state.system_state.get("global_config", {}).get("oci_vault", {}) or {})

    def _save(cfg: dict) -> None:
        """Store the OCI Vault config in global_config and flag the state for saving to disk."""
        # Replace the oci_vault block inside global_config and write global_config back.
        gc = hub.state.system_state.get("global_config", {})
        gc["oci_vault"] = cfg
        hub.state.system_state["global_config"] = gc
        # Mark the state dirty so the hub's persistence loop writes it out.
        hub.state._mark_dirty()

    @app.get("/setup/oci-vault")
    async def get_oci_vault_cfg():
        """Return the stored OCI Vault config for the Setup page."""
        return {"config": _cfg()}

    @app.post("/setup/oci-vault")
    async def set_oci_vault(request: Request):
        """Save the OCI Vault config posted from the Setup page (only whitelisted fields are kept).
        """
        # Read the JSON body; a missing or broken body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Accept either {"config": {...}} or the bare config object.
        incoming = (body or {}).get("config", body) or {}
        # Keep only the known fields so arbitrary keys can never be stored.
        clean = {}
        for k in _FIELDS:
            if k in incoming:
                clean[k] = incoming[k]
        # Coerce "enabled" to a real boolean (it defaults to off).
        clean["enabled"] = bool(clean.get("enabled", False))
        # Only one cloud vault provider may be active at a time, so refuse to enable OCI while Azure
        # Key Vault is on.
        if clean["enabled"]:
            import cloud_vault
            if cloud_vault.other_provider_enabled(hub, "oci"):
                raise HTTPException(status_code=400,
                                    detail="Azure Key Vault is currently enabled — disable it before enabling OCI Vault")
        # Persist and echo back what was actually saved.
        _save(clean)
        return {"status": "ok", "config": clean}

    @app.post("/setup/oci-vault/upload-key")
    async def upload_oci_vault_key(request: Request):
        """Accept an OCI API signing private key (PEM) uploaded via the WebUI
        and write it to a fixed on-box path (0600), persisting that path into
        ``oci_vault.key_path`` immediately -- no more hand-copying the key
        onto the hub / typing a path. Multipart form field ``file``; falls
        back to a raw body. Validates the upload actually parses as an
        unencrypted PEM private key BEFORE writing anything."""
        # Work out whether this is a multipart form upload or a raw body.
        ctype = (request.headers.get("content-type") or "").lower()
        # Read the uploaded key bytes from the form's "file" field or, failing that, the raw request
        # body.
        try:
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                data = await up.read()
            else:
                data = await request.body()
        # Our own 400 for a missing field passes straight through.
        except HTTPException:
            raise
        # Any other read failure is reported to the user as a bad upload.
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        # Validate the key and write it to disk; an invalid/encrypted key becomes a 400 with the
        # reason.
        try:
            path = oci_auth.write_uploaded_private_key(
                hub, _KEY_UPLOAD_SUBDIR, _KEY_UPLOAD_FILENAME, data)
        except oci_auth.OciAuthError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # Point the stored config at the newly written key file right away.
        cfg = _cfg()
        cfg["key_path"] = path
        _save(cfg)
        return {"status": "ok", "key_path": path}

    @app.post("/setup/oci-vault/test")
    async def test_oci_vault(request: Request):
        """Test the signing key + vault reachability (GET the vault). Uses the
        posted config if present, else the stored one, so an admin can test
        before saving."""
        # Read the optional posted config; a missing or broken body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Prefer the posted (unsaved) config, otherwise test the saved one.
        cfg = ((body or {}).get("config") or _cfg())
        # Try to reach the vault and return its summary details on success.
        try:
            summary = await _kv.test_connection(_kv.get_oci_config(hub), cfg)
            return {"status": "ok", **summary}
        # Expected vault errors (auth, not found, ...) are shown as a friendly error message.
        except _kv.OciVaultError as e:
            return {"status": "error", "message": str(e)}
        # Unexpected errors are logged with a traceback and also reported back to the UI.
        except Exception as e:  # noqa: BLE001
            logger.exception("oci-vault test failed")
            return {"status": "error", "message": str(e)}
