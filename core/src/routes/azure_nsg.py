"""Azure NSG allow-list admin routes (Setup → Azure NSG).

Manage a single 'alias-style' allow rule in an Azure Network Security Group from
the hub. Auth reuses the Entra OIDC app cert (see ``azure_nsg`` /
``security.oidc.fetch_app_token``) — the app registration needs an ARM
**Network Contributor** role on the NSG / resource group.

Config lives in ``global_config['azure_nsg']`` (admin-set). All routes are under
``/setup/`` so the access-control middleware already gates them to admins.
"""
from __future__ import annotations

from api import HTTPException, Request, logger
from security.oidc import get_oidc_config
import azure_nsg as _nsg

# Whitelisted, persisted config fields (never any secret — auth is the OIDC cert).
_FIELDS = ("enabled", "subscription_id", "resource_group", "nsg_name",
           "rule_name", "priority", "direction", "access", "protocol",
           "dest_port", "ips")


def register(app, hub, ctx):
    def _cfg() -> dict:
        return dict(hub.state.system_state.get("global_config", {}).get("azure_nsg", {}) or {})

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["azure_nsg"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state.save_state()

    @app.get("/setup/azure-nsg")
    async def get_azure_nsg():
        cfg = _cfg()
        # Best-effort live read of what's currently on the NSG rule, so the UI can
        # show drift between the hub's stored list and Azure. Never fatal.
        live = None
        warning = ""
        if cfg.get("subscription_id") and cfg.get("nsg_name"):
            try:
                live = await _nsg.get_allowlist(get_oidc_config(hub), cfg)
            except Exception as e:  # noqa: BLE001
                warning = str(e)
        return {"config": cfg, "live_prefixes": live, "warning": warning}

    @app.post("/setup/azure-nsg")
    async def set_azure_nsg(request: Request):
        """Persist the config and reconcile the NSG rule to match ``ips`` (unless
        disabled). Returns the applied prefixes or a warning if ARM refused."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        clean = {}
        for k in _FIELDS:
            if k in incoming:
                clean[k] = incoming[k]
        # Normalize the IP list early so a typo is rejected before we persist.
        try:
            clean["ips"] = _nsg.normalize_prefixes(clean.get("ips") or [])
        except _nsg.AzureNsgError as e:
            raise HTTPException(status_code=400, detail=str(e))
        clean["enabled"] = bool(clean.get("enabled", False))
        _save(clean)
        # Reconcile to Azure only when enabled + configured. A failure here is
        # returned as a warning (config is still saved) so the admin can fix RBAC.
        applied = None
        warning = ""
        if clean["enabled"] and clean.get("subscription_id") and clean.get("nsg_name"):
            try:
                applied = await _nsg.reconcile_allowlist(get_oidc_config(hub), clean, clean["ips"])
            except Exception as e:  # noqa: BLE001
                logger.warning("azure-nsg reconcile failed: %s", e)
                warning = str(e)
        return {"status": "ok", "config": clean, "applied": applied, "warning": warning}

    @app.post("/setup/azure-nsg/test")
    async def test_azure_nsg(request: Request):
        """Test ARM auth + reachability (GET the NSG). Uses the posted config if
        present, else the stored one, so an admin can test before saving."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _cfg())
        try:
            summary = await _nsg.test_connection(get_oidc_config(hub), cfg)
            return {"status": "ok", **summary}
        except _nsg.AzureNsgError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("azure-nsg test failed")
            return {"status": "error", "message": str(e)}
