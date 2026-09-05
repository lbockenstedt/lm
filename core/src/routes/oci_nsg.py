"""OCI NSG allow-list admin routes (Setup → OCI NSG).

Manage a set of managed 'allow' rules in an Oracle Cloud Infrastructure
Network Security Group from the hub — the OCI parity feature for
``routes/azure_nsg.py``. Auth is an OCI API signing key (see ``oci_nsg`` /
``OciConfig``); the user backing the key needs an IAM policy granting
``manage security-lists`` (or the narrower ``use network-security-groups``)
in the NSG's compartment.

Config lives in ``global_config['oci_nsg']`` (admin-set). All routes are
under ``/setup/`` so the access-control middleware already gates them to
admins.

NOTE: unlike Azure NSG, OCI NSGs support ALLOW rules only — there is no
`deny`/`priority`/`direction`/`access` equivalent to reconcile, so this route
carries no ``priority`` ordering guard against the threat-monitor block
config (see ``oci_nsg.py``'s module docstring for the full explanation).
"""
from __future__ import annotations

from api import HTTPException, Request, logger
import oci_nsg as _nsg

# Whitelisted, persisted config fields. Auth (tenancy_ocid/user_ocid/
# fingerprint/key_path) is never a secret VALUE here — key_path is itself a
# credential_store reference (kv:<name> / path), same as Entra's key_path.
_FIELDS = ("enabled", "tenancy_ocid", "user_ocid", "fingerprint", "key_path",
          "region", "nsg_id", "dest_port", "entries")


def register(app, hub, ctx):
    def _cfg() -> dict:
        return dict(hub.state.system_state.get("global_config", {}).get("oci_nsg", {}) or {})

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["oci_nsg"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    @app.get("/setup/oci-nsg")
    async def get_oci_nsg():
        cfg = _cfg()
        cfg["entries"] = _nsg.normalize_entries(cfg.get("entries") or [])
        # Read the CIDRs currently on our managed rules and import any we
        # don't track yet into the local DB (empty description). Persist
        # when something new was found.
        live = None
        warning = ""
        if cfg.get("nsg_id") and cfg.get("region"):
            try:
                live = await _nsg.get_allowlist(_nsg.get_oci_config(hub), cfg)
                merged, added = _nsg.merge_live_prefixes(cfg["entries"], live)
                if added:
                    cfg["entries"] = merged
                    _save(cfg)
            except Exception as e:  # noqa: BLE001
                warning = str(e)
        return {"config": cfg, "live_prefixes": live, "warning": warning}

    @app.post("/setup/oci-nsg")
    async def set_oci_nsg(request: Request):
        """Persist the config and reconcile the NSG's managed allow rules to
        match ``ips`` (unless disabled). Returns the applied prefixes or a
        warning if OCI refused."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        clean = {}
        for k in _FIELDS:
            if k in incoming:
                clean[k] = incoming[k]
        try:
            clean["entries"] = _nsg.normalize_entries(clean.get("entries") or [])
        except _nsg.OciNsgError as e:
            raise HTTPException(status_code=400, detail=str(e))
        clean["enabled"] = bool(clean.get("enabled", False))
        _save(clean)
        applied = None
        warning = ""
        if clean["enabled"] and clean.get("nsg_id") and clean.get("region"):
            try:
                applied = await _nsg.reconcile_allowlist(
                    _nsg.get_oci_config(hub), clean, _nsg.entries_to_ips(clean["entries"]))
            except Exception as e:  # noqa: BLE001
                logger.warning("oci-nsg reconcile failed: %s", e)
                warning = str(e)
        return {"status": "ok", "config": clean, "applied": applied, "warning": warning}

    @app.post("/setup/oci-nsg/test")
    async def test_oci_nsg(request: Request):
        """Test the signing key + NSG reachability (GET the NSG). Uses the
        posted config if present, else the stored one, so an admin can test
        before saving."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _cfg())
        try:
            summary = await _nsg.test_connection(_nsg.get_oci_config(hub), cfg)
            return {"status": "ok", **summary}
        except _nsg.OciNsgError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("oci-nsg test failed")
            return {"status": "error", "message": str(e)}
