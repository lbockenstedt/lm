"""Security / threat-monitor routes — the auth-failure audit log, blocked-IP
tiles (permanent / temporary / manual), config, manual block/unblock, and the
never-block allow list. ALL ADMIN-ONLY (on top of the /api/* session gate)."""
from api import HTTPException, Request


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _guard(request: Request):
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    @app.get("/api/security/overview")
    async def security_overview(request: Request):
        """Snapshot for the Security view: config + blocked-IP tiles (permanent /
        temporary / manual) + never-block list + recent auth-failure events."""
        _guard(request)
        return hub.threat_monitor.snapshot()

    @app.put("/api/security/config")
    async def security_config(request: Request):
        """Update policy: enabled, auto_block, threshold (>N fails), window_s,
        ttl_s, permanent_after, success_grace_s, block_rule_name, block_priority."""
        _guard(request)
        body = await request.json()
        return {"status": "ok", "config": hub.threat_monitor.set_config(body or {})}

    @app.post("/api/security/block")
    async def security_block(request: Request):
        """Manually block an IP (optionally permanent). Body: {ip, reason, permanent}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.block_manual(
            (body.get("ip") or "").strip(), body.get("reason", ""),
            permanent=bool(body.get("permanent")))

    @app.post("/api/security/unblock")
    async def security_unblock(request: Request):
        """Remove a block (temporary, permanent, or manual). Body: {ip}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.unblock((body.get("ip") or "").strip())

    @app.post("/api/security/never-block")
    async def security_never_add(request: Request):
        """Add an IP/CIDR to the never-block allow list. Body: {cidr}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.add_never((body.get("cidr") or "").strip())

    @app.delete("/api/security/never-block")
    async def security_never_remove(request: Request):
        """Remove an IP/CIDR from the never-block allow list. Body: {cidr}."""
        _guard(request)
        body = await request.json()
        return hub.threat_monitor.remove_never((body.get("cidr") or "").strip())

    @app.post("/api/security/reconcile")
    async def security_reconcile(request: Request):
        """Force a push of the current blocked-IP set onto the Azure NSG deny
        rule (e.g. after enabling auto-block or editing Azure config)."""
        _guard(request)
        hub.threat_monitor._nsg_dirty = True
        return await hub.threat_monitor.reconcile_nsg()
