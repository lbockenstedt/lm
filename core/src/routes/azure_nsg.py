"""Azure NSG allow-list admin routes (Setup → Azure NSG).

Manage a single 'alias-style' allow rule in an Azure Network Security Group from
the hub. Auth reuses the Entra OIDC app cert (see ``azure_nsg`` /
``security.oidc.fetch_app_token``) — the app registration needs an ARM
**Network Contributor** role on the NSG / resource group.

Config lives in ``global_config['azure_nsg']`` (admin-set). All routes are under
``/setup/`` so the access-control middleware already gates them to admins.
"""
# Postpone evaluation of type hints (lets hints like "dict" stay cheap at import time).
from __future__ import annotations

# Shared Hub helpers: HTTP error type, request object and the hub logger.
from api import HTTPException, Request, logger
# Entra OIDC app config; its certificate is what authenticates to Azure Resource Manager.
from security.oidc import get_oidc_config
# Azure NSG client: read/merge/reconcile the allow rule and validate entries.
import azure_nsg as _nsg

# Whitelisted, persisted config fields (never any secret — auth is the OIDC cert).
# ``entries`` is the local allow-list DB: [{ip, description}].
_FIELDS = ("enabled", "subscription_id", "resource_group", "nsg_name",
           "rule_name", "priority", "direction", "access", "protocol",
           "dest_port", "entries")


def register(app, hub, ctx):
    """Register the Setup -> Azure NSG admin routes on the Hub app."""
    def _cfg() -> dict:
        """Return a copy of the stored Azure NSG config, migrating the legacy IP list."""
        cfg = dict(hub.state.system_state.get("global_config", {}).get("azure_nsg", {}) or {})
        # Migrate the legacy bare-IP list to {ip, description} entries.
        if "entries" not in cfg and cfg.get("ips"):
            cfg["entries"] = [{"ip": ip, "description": ""} for ip in cfg.get("ips") or []]
            cfg.pop("ips", None)
        # Hand back the (possibly migrated) copy.
        return cfg

    def _save(cfg: dict) -> None:
        """Store ``cfg`` as the Azure NSG config and mark hub state for saving."""
        gc = hub.state.system_state.get("global_config", {})
        gc["azure_nsg"] = cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()

    # Read the Azure NSG config plus what is live on the Azure rule.
    @app.get("/setup/azure-nsg")
    async def get_azure_nsg():
        """Return the config, the live rule prefixes, any warning and the deny-rule settings."""
        # Load the config and normalise its allow-list entries.
        cfg = _cfg()
        cfg["entries"] = _nsg.normalize_entries(cfg.get("entries") or [])
        # Read the prefixes CURRENTLY on the Azure rule and IMPORT any we don't
        # track yet into the local DB (empty description), so existing NSG entries
        # are captured and can be annotated. Persist when something new was found.
        # Live prefixes and any Azure error; only query Azure when it is configured.
        live = None
        warning = ""
        if cfg.get("subscription_id") and cfg.get("nsg_name"):
            # Read the live rule and import any prefixes we don't track yet (then save).
            try:
                live = await _nsg.get_allowlist(get_oidc_config(hub), cfg)
                merged, added = _nsg.merge_live_prefixes(cfg["entries"], live)
                if added:
                    cfg["entries"] = merged
                    _save(cfg)
            # Azure errors don't fail the page; they are shown as a warning.
            except Exception as e:  # noqa: BLE001
                warning = str(e)
        # Surface the threat-monitor DENY rule's priority/name so the NSG tile can
        # display + edit BOTH priorities (single source of truth with Security).
        # Ask the threat monitor (if running) for its deny-rule priority and name.
        deny = {}
        tm = getattr(hub, "threat_monitor", None)
        if tm is not None:
            try:
                tcfg = tm.config()
                deny = {"priority": tcfg.get("block_priority"),
                        "rule_name": tcfg.get("block_rule_name")}
            except Exception:  # noqa: BLE001
                deny = {}
        # Return everything the NSG tile needs.
        return {"config": cfg, "live_prefixes": live, "warning": warning, "deny": deny}

    # Save the Azure NSG config and push it to Azure.
    @app.post("/setup/azure-nsg")
    async def set_azure_nsg(request: Request):
        """Persist the config and reconcile the NSG rule to match ``ips`` (unless
        disabled). Returns the applied prefixes or a warning if ARM refused."""
        # Read the JSON body (defaulting to {}); accept {"config": {...}} or a bare config.
        try:
            body = await request.json()
        except Exception:
            body = {}
        incoming = (body or {}).get("config", body) or {}
        # Keep only the whitelisted config fields.
        clean = {}
        for k in _FIELDS:
            if k in incoming:
                clean[k] = incoming[k]
        # Accept legacy bare-IP `ips` too; validate/normalize the entries early so
        # a typo is rejected before we persist.
        # Use the entries list, or a legacy "ips" list if that's what was sent.
        raw = clean.get("entries")
        if raw is None and isinstance(incoming.get("ips"), list):
            raw = incoming["ips"]
        # Validate/normalise the entries; a bad entry is a 400 before anything is saved.
        try:
            clean["entries"] = _nsg.normalize_entries(raw or [])
        except _nsg.AzureNsgError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # Store enabled as a real bool.
        clean["enabled"] = bool(clean.get("enabled", False))
        # Only one cloud NSG provider may be enabled at a time.
        if clean["enabled"]:
            import cloud_nsg
            if cloud_nsg.other_provider_enabled(hub, "azure"):
                raise HTTPException(status_code=400,
                                    detail="OCI NSG is currently enabled — disable it before enabling Azure NSG")
        # Enforce the allow/deny priority ordering guard when the ALLOW priority is
        # being changed: validate the incoming allow against the CURRENT
        # threat-monitor deny priority (allow < deny < 1000). Reject before persist.
        # Check the allow priority is below the threat monitor's deny priority.
        if "priority" in clean:
            from security.threat_monitor import validate_nsg_priorities
            tm = getattr(hub, "threat_monitor", None)
            if tm is not None:
                block = tm.config().get("block_priority")
                ok, message = validate_nsg_priorities(clean.get("priority"), block)
                if not ok:
                    raise HTTPException(status_code=400, detail=message)
        # Persist the cleaned config.
        _save(clean)
        # Reconcile to Azure only when enabled + configured. A failure here is
        # returned as a warning (config is still saved) so the admin can fix RBAC.
        # Push the allow-list to Azure only when enabled and fully configured.
        applied = None
        warning = ""
        if clean["enabled"] and clean.get("subscription_id") and clean.get("nsg_name"):
            try:
                applied = await _nsg.reconcile_allowlist(
                    get_oidc_config(hub), clean, _nsg.entries_to_ips(clean["entries"]))
            except Exception as e:  # noqa: BLE001
                logger.warning("azure-nsg reconcile failed: %s", e)
                warning = str(e)
        # Return the saved config, what was applied, and any warning.
        return {"status": "ok", "config": clean, "applied": applied, "warning": warning}

    # Test the Azure connection with the posted or stored config.
    @app.post("/setup/azure-nsg/test")
    async def test_azure_nsg(request: Request):
        """Test ARM auth + reachability (GET the NSG). Uses the posted config if
        present, else the stored one, so an admin can test before saving."""
        # Read the JSON body (defaulting to {}); fall back to the stored config.
        try:
            body = await request.json()
        except Exception:
            body = {}
        cfg = ((body or {}).get("config") or _cfg())
        # Try fetching the NSG; known and unexpected errors are both reported as "error".
        try:
            summary = await _nsg.test_connection(get_oidc_config(hub), cfg)
            return {"status": "ok", **summary}
        except _nsg.AzureNsgError as e:
            return {"status": "error", "message": str(e)}
        except Exception as e:  # noqa: BLE001
            logger.exception("azure-nsg test failed")
            return {"status": "error", "message": str(e)}
