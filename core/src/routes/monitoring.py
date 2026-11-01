"""Monitoring routes (admin only).

The monitoring spoke is vendor-neutral (module_type "monitoring"); these routes
only relay MON_STATUS / MON_SYNC / MON_REBUILD to it. Tenants never see the
backend — the LM WebUI is the only front end.
"""
from api import HTTPException, Request, logger


async def inventory_devices(hub):
    """LM inventory as monitoring devices, with each SNMP community resolved
    from the credential vault (the credential the network scan found to work)."""
    import instance_vault
    inv = (hub.state.system_state.get("global_config", {}).get("nw_devices", []) or [])
    inv = await instance_vault.overlay_many(
        hub, [d for d in inv if isinstance(d, dict) and d.get("name") and d.get("address")],
        "nw_devices")
    return [{"tenant": d.get("tenant") or d.get("tenant_id") or "default",
             "name": d.get("name"), "type": d.get("type") or d.get("model") or "",
             "ip": str(d.get("address") or "").split("/")[0],
             "snmp": bool(d.get("snmp_community")) or d.get("transport") == "snmp",
             "snmp_community": d.get("snmp_community") or ""}
            for d in inv]


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _admin_spoke(request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        sid = hub.get_spoke_by_type("monitoring")
        if not sid:
            raise HTTPException(status_code=503, detail="Monitoring spoke not connected")
        return sid

    async def _relay(sid, command, payload=None):
        try:
            return await hub.request_response(sid, command, payload or {}, timeout=300.0)
        except Exception as e:
            logger.exception("monitoring %s failed", command)
            raise HTTPException(status_code=502, detail=str(e))

    @app.get("/api/monitoring/status")
    async def monitoring_status(request: Request):
        return await _relay(_admin_spoke(request), "MON_STATUS")

    @app.post("/api/monitoring/sync")
    async def monitoring_sync(request: Request):
        sid = _admin_spoke(request)
        return await _relay(sid, "MON_SYNC", await _payload(request))

    @app.post("/api/monitoring/rebuild")
    async def monitoring_rebuild(request: Request):
        sid = _admin_spoke(request)
        return await _relay(sid, "MON_REBUILD", await _payload(request))

    async def _payload(request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return {"devices": await inventory_devices(hub),
                "dry_run": bool((body or {}).get("dry_run"))}
