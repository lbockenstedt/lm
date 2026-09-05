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
from __future__ import annotations

from api import HTTPException, Request, logger
import oci_vault as _kv

# Whitelisted, persisted config fields. Auth (tenancy_ocid/user_ocid/
# fingerprint/key_path) is never a secret VALUE here — key_path is itself a
# credential_store reference (kv:<name> / path), same as Entra's key_path.
_FIELDS = ("enabled", "tenancy_ocid", "user_ocid", "fingerprint", "key_path",
          "region", "compartment_id", "vault_id", "key_id")


def register(app, hub, ctx):
    def _cfg() -> dict:
        return dict(hub.state.system_state.get("global_config", {}).get("oci_vault", {}) or {})

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["oci_vault"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    @app.get("/setup/oci-vault")
    async def get_oci_vault_cfg():
        return {"config": _cfg()}

    @app.post("/setup/oci-vault")
    async def set_oci_vault(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        clean = {}
        for k in _FIELDS:
            if k in incoming:
                clean[k] = incoming[k]
        clean["enabled"] = bool(clean.get("enabled", False))
        if clean["enabled"]:
            import cloud_vault
            if cloud_vault.other_provider_enabled(hub, "oci"):
                raise HTTPException(status_code=400,
                                    detail="Azure Key Vault is currently enabled — disable it before enabling OCI Vault")
        _save(clean)
        return {"status": "ok", "config": clean}

    @app.post("/setup/oci-vault/test")
    async def test_oci_vault(request: Request):
        """Test the signing key + vault reachability (GET the vault). Uses the
        posted config if present, else the stored one, so an admin can test
        before saving."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _cfg())
        try:
            summary = await _kv.test_connection(_kv.get_oci_config(hub), cfg)
            return {"status": "ok", **summary}
        except _kv.OciVaultError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("oci-vault test failed")
            return {"status": "error", "message": str(e)}
