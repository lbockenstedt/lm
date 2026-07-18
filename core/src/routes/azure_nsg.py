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
# ``entries`` is the local allow-list DB: [{ip, description}].
_FIELDS = ("enabled", "subscription_id", "resource_group", "nsg_name",
           "rule_name", "priority", "direction", "access", "protocol",
           "dest_port", "entries")


def register(app, hub, ctx):
    def _cfg() -> dict:
        cfg = dict(hub.state.system_state.get("global_config", {}).get("azure_nsg", {}) or {})
        # Migrate the legacy bare-IP list to {ip, description} entries.
        if "entries" not in cfg and cfg.get("ips"):
            cfg["entries"] = [{"ip": ip, "description": ""} for ip in cfg.get("ips") or []]
            cfg.pop("ips", None)
        return cfg

    def _save(cfg: dict) -> None:
        gc = hub.state.system_state.get("global_config", {})
        gc["azure_nsg"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    @app.get("/setup/azure-nsg")
    async def get_azure_nsg():
        cfg = _cfg()
        cfg["entries"] = _nsg.normalize_entries(cfg.get("entries") or [])
        # Read the prefixes CURRENTLY on the Azure rule and IMPORT any we don't
        # track yet into the local DB (empty description), so existing NSG entries
        # are captured and can be annotated. Persist when something new was found.
        live = None
        warning = ""
        if cfg.get("subscription_id") and cfg.get("nsg_name"):
            try:
                live = await _nsg.get_allowlist(get_oidc_config(hub), cfg)
                merged, added = _nsg.merge_live_prefixes(cfg["entries"], live)
                if added:
                    cfg["entries"] = merged
                    _save(cfg)
            except Exception as e:  # noqa: BLE001
                warning = str(e)
        # Surface the threat-monitor DENY rule's priority/name so the NSG tile can
        # display + edit BOTH priorities (single source of truth with Security).
        deny = {}
        tm = getattr(hub, "threat_monitor", None)
        if tm is not None:
            try:
                tcfg = tm.config()
                deny = {"priority": tcfg.get("block_priority"),
                        "rule_name": tcfg.get("block_rule_name")}
            except Exception:  # noqa: BLE001
                deny = {}
        return {"config": cfg, "live_prefixes": live, "warning": warning, "deny": deny}

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
        # Accept legacy bare-IP `ips` too; validate/normalize the entries early so
        # a typo is rejected before we persist.
        raw = clean.get("entries")
        if raw is None and isinstance(incoming.get("ips"), list):
            raw = incoming["ips"]
        try:
            clean["entries"] = _nsg.normalize_entries(raw or [])
        except _nsg.AzureNsgError as e:
            raise HTTPException(status_code=400, detail=str(e))
        clean["enabled"] = bool(clean.get("enabled", False))
        # Enforce the allow/deny priority ordering guard when the ALLOW priority is
        # being changed: validate the incoming allow against the CURRENT
        # threat-monitor deny priority (allow < deny < 1000). Reject before persist.
        if "priority" in clean:
            from security.threat_monitor import validate_nsg_priorities
            tm = getattr(hub, "threat_monitor", None)
            if tm is not None:
                block = tm.config().get("block_priority")
                ok, message = validate_nsg_priorities(clean.get("priority"), block)
                if not ok:
                    raise HTTPException(status_code=400, detail=message)
        _save(clean)
        # Reconcile to Azure only when enabled + configured. A failure here is
        # returned as a warning (config is still saved) so the admin can fix RBAC.
        applied = None
        warning = ""
        if clean["enabled"] and clean.get("subscription_id") and clean.get("nsg_name"):
            try:
                applied = await _nsg.reconcile_allowlist(
                    get_oidc_config(hub), clean, _nsg.entries_to_ips(clean["entries"]))
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
