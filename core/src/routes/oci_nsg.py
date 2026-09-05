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

import oci_auth
from api import HTTPException, Request, logger
import oci_nsg as _nsg

# Whitelisted, persisted config fields. Auth (tenancy_ocid/user_ocid/
# fingerprint/key_path) is never a secret VALUE here — key_path is itself a
# credential_store reference (kv:<name> / path), same as Entra's key_path.
_FIELDS = ("enabled", "tenancy_ocid", "user_ocid", "fingerprint", "key_path",
          "region", "nsg_id", "dest_port", "entries")

# Fixed on-box path the uploaded OCI API signing key is written to (0600) via
# oci_auth.write_uploaded_private_key. Not vault-backed: the OCI Vault
# credential-store backend needs its OWN resolvable private key just to
# authenticate to OCI in the first place, so it can't be the bootstrap
# target for THIS key without a chicken-and-egg problem. A plain,
# tightly-permissioned file is what ``key_path`` already supports
# (``resolve_private_key_material``'s filesystem-path branch), so an admin
# who uploads instead of hand-typing a path gets the same end state.
_KEY_UPLOAD_SUBDIR = "oci"
_KEY_UPLOAD_FILENAME = "oci-nsg-api-key.pem"


def register(app, hub, ctx):
    def _cfg() -> dict:
        return dict(hub.state.system_state.get("global_config", {}).get("oci_nsg", {}) or {})

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["oci_nsg"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    @app.get("/setup/oci-regions")
    async def get_oci_regions():
        """The OCI region catalog for the Region dropdown (shared by the OCI NSG
        and OCI Vault tiles).

        There is no unauthenticated OCI API to list regions — ``ListRegions``
        itself needs a working signing key AND a bootstrap region host, which is
        exactly what an operator hasn't configured yet. So this serves the
        curated catalog in ``oci_auth.OCI_REGIONS``, the same approach the
        official OCI SDK and Terraform provider take.

        A dropdown (rather than a free-text box) is the point: a typo'd region
        is otherwise only discoverable as a DNS failure once a call is made."""
        return {"regions": oci_auth.list_regions()}

    @app.get("/setup/oci-nsg")
    async def get_oci_nsg():
        cfg = _cfg()
        cfg["entries"] = _nsg.normalize_entries(cfg.get("entries") or [])
        # Read the CIDRs currently on our managed rules and import any we
        # don't track yet into the local DB (empty description). Persist
        # when something new was found.
        live = None
        unmanaged = None
        warning = ""
        if cfg.get("nsg_id") and cfg.get("region"):
            try:
                split = await _nsg.get_live_prefixes(_nsg.get_oci_config(hub), cfg)
                if split is not None:
                    live = split["managed"]
                    unmanaged = split["unmanaged"]
                    # Only OUR rules are folded into the local list. An
                    # unmanaged rule is shown but never adopted — importing it
                    # would make the next apply create a duplicate, tagged rule
                    # for the same CIDR alongside the operator's own.
                    merged, added = _nsg.merge_live_prefixes(cfg["entries"], live)
                    if added:
                        cfg["entries"] = merged
                        _save(cfg)
            except Exception as e:  # noqa: BLE001
                warning = str(e)
        return {"config": cfg, "live_prefixes": live,
                "unmanaged_prefixes": unmanaged, "warning": warning}

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
        if clean["enabled"]:
            import cloud_nsg
            if cloud_nsg.other_provider_enabled(hub, "oci"):
                raise HTTPException(status_code=400,
                                    detail="Azure NSG is currently enabled — disable it before enabling OCI NSG")
        _save(clean)
        applied = None
        warning = ""
        # Pre-flight the credentials BEFORE attempting any OCI call. A wrong
        # OCID shape or a private key that doesn't match the fingerprint is
        # detectable locally, and saying so at save time is far better than
        # letting it surface as an opaque 401 from the apply below (or worse,
        # staying silent because the apply was skipped for another reason).
        try:
            _problems = oci_auth.diagnose_auth(_nsg.get_oci_config(hub))
        except Exception:  # noqa: BLE001 — diagnosis must never block a save
            _problems = []
        if _problems:
            warning = " ".join(_problems)
        if clean["enabled"] and clean.get("nsg_id") and clean.get("region"):
            try:
                applied = await _nsg.reconcile_allowlist(
                    _nsg.get_oci_config(hub), clean, _nsg.entries_to_ips(clean["entries"]))
            except Exception as e:  # noqa: BLE001
                logger.warning("oci-nsg reconcile failed: %s", e)
                warning = str(e)
        return {"status": "ok", "config": clean, "applied": applied, "warning": warning}

    @app.post("/setup/oci-nsg/upload-key")
    async def upload_oci_nsg_key(request: Request):
        """Accept an OCI API signing private key (PEM) uploaded via the WebUI
        and write it to a fixed on-box path (0600), persisting that path into
        ``oci_nsg.key_path`` immediately -- no more hand-copying the key onto
        the hub / typing a path. Multipart form field ``file``; falls back to
        a raw body. Validates the upload actually parses as an unencrypted PEM
        private key BEFORE writing anything, so a bad paste/upload can't
        silently brick the integration or leave garbage on disk."""
        ctype = (request.headers.get("content-type") or "").lower()
        try:
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                data = await up.read()
            else:
                data = await request.body()
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        try:
            path = oci_auth.write_uploaded_private_key(
                hub, _KEY_UPLOAD_SUBDIR, _KEY_UPLOAD_FILENAME, data)
        except oci_auth.OciAuthError as e:
            raise HTTPException(status_code=400, detail=str(e))
        cfg = _cfg()
        cfg["key_path"] = path
        _save(cfg)
        return {"status": "ok", "key_path": path}

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
