"""LDAP directory (OU/user/group) routes."""
from api import (
    HTTPException, Request, _invalidate_user_sessions, logger,
)


def register(app, hub, ctx):
    """Register ldap routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    # ── Per-tenant OU scoping ────────────────────────────────────────────────
    # The directory is one shared tree; each tenant is confined to its own OU
    # subtree via the tenant's ``ldap_base_dn`` (set in the tenant config). A
    # tenant-admin may read + write ONLY entries within that subtree; a Global
    # Admin is unconfined. WRITES are OU-scoped (fail-closed) and READS are
    # filtered to the subtree on the hub side (reliable regardless of whether the
    # directory spoke honors a base filter). Writes are tenant-admin tier — the
    # middleware already required it; here we bind them to the tenant's own OU.
    _LDAP_DN_FIELDS = ("dn", "parent_dn", "parent", "ou", "ou_dn", "base",
                       "base_dn", "group_dn", "user_dn", "target_dn", "member_dn")

    def _tenant_ldap_base(sess):
        tid = (sess or {}).get("user", {}).get("tenant_id") or ""
        t = hub.state.get_tenant(tid) or {}
        return str(t.get("ldap_base_dn") or "").strip()

    def _dn_in_base(dn, base) -> bool:
        d = str(dn or "").strip().lower()
        b = str(base or "").strip().lower()
        return bool(b) and bool(d) and (d == b or d.endswith("," + b))

    def _assert_ldap_write(request, data):
        """Global Admin → any. Otherwise (tenant-admin) EVERY DN-like field in the
        payload must sit within the caller's tenant OU subtree; a write carrying no
        resolvable in-OU DN is refused (fail-closed — a tenant-admin cannot touch
        another tenant's OU, and a username-only password reset must be done by an
        admin or carry the full dn)."""
        sess = _session_user(request)
        if _is_admin(sess):
            return
        base = _tenant_ldap_base(sess)
        if not base:
            raise HTTPException(status_code=403,
                detail="No directory OU (ldap_base_dn) is configured for your tenant")
        dns = [data.get(f) for f in _LDAP_DN_FIELDS if data.get(f)]
        if not dns:
            raise HTTPException(status_code=403,
                detail="Specify a target DN within your tenant's OU")
        for d in dns:
            if not _dn_in_base(d, base):
                raise HTTPException(status_code=403,
                    detail="You may only manage directory entries within your tenant's OU")

    def _scope_ldap_list(request, result):
        """Filter a LIST_* result to entries within the caller's tenant OU (admin
        sees all). Handles a bare list or a dict wrapping list values."""
        sess = _session_user(request)
        if _is_admin(sess):
            return result
        base = _tenant_ldap_base(sess)

        def _keep(entry):
            return isinstance(entry, dict) and _dn_in_base(entry.get("dn"), base)
        if isinstance(result, list):
            return [e for e in result if _keep(e)]
        if isinstance(result, dict):
            return {k: ([e for e in v if _keep(e)] if isinstance(v, list) else v)
                    for k, v in result.items()}
        return result

    async def get_ldap_spoke(hub):
        spoke_id = hub.get_spoke_by_type("directory")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        return spoke_id

    @app.get("/api/ldap/ous")
    async def get_ldap_ous(request: Request):
        """List LDAP OUs from the directory spoke (tenant-OU scoped for non-admins)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/ous")
        try:
            result = await hub.request_response(spoke_id, "LIST_OUS", {})
            return _scope_ldap_list(request, result.get("data", result) if isinstance(result, dict) else result)
        except Exception as e:
            logger.exception("get_ldap_ous failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/ous")
    async def create_ldap_ou(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_OU", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/ous")
    async def update_ldap_ou(request: Request):
        """Rename an OU (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "UPDATE_OU", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_ou failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/users")
    async def get_ldap_users(request: Request):
        """List LDAP users from the directory spoke (tenant-OU scoped for non-admins)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/users")
        try:
            result = await hub.request_response(spoke_id, "LIST_USERS", {})
            return _scope_ldap_list(request, result.get("data", result) if isinstance(result, dict) else result)
        except Exception as e:
            logger.exception("get_ldap_users failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_USER", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        """Update a user's attributes (first/last/email) and optionally rename uid."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn"):
                raise HTTPException(status_code=400, detail="dn is required")
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "UPDATE_USER", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/ldap/groups")
    async def get_ldap_groups(request: Request):
        """List LDAP groups from the directory spoke (tenant-OU scoped for non-admins)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        logger.debug("relay GET /api/ldap/groups")
        try:
            result = await hub.request_response(spoke_id, "LIST_GROUPS", {})
            return _scope_ldap_list(request, result.get("data", result) if isinstance(result, dict) else result)
        except Exception as e:
            logger.exception("get_ldap_groups failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_GROUP", data)
            return result
        except Exception as e:
            logger.exception("create_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/groups")
    async def update_ldap_group(request: Request):
        """Rename a group (dn + new name → modrdn on the spoke)."""
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            if not data.get("dn") or not data.get("name"):
                raise HTTPException(status_code=400, detail="dn and name are required")
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "UPDATE_GROUP", data)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/group")
    async def add_ldap_user_to_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "ADD_USER_TO_GROUP", data)
            return result
        except Exception as e:
            logger.exception("add_ldap_user_to_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users/group")
    async def remove_ldap_user_from_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "REMOVE_USER_FROM_GROUP", data)
            return result
        except Exception as e:
            logger.exception("remove_ldap_user_from_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/entity")
    async def delete_ldap_entity(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "DELETE_ENTITY", data)
            return result
        except Exception as e:
            logger.exception("delete_ldap_entity failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/password")
    async def set_ldap_user_password(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "SET_PASSWORD", data)
            # The directory password changed → any hub session minted for this
            # directory user must be revoked so the old credential can't keep
            # authorizing API calls until its TTL. Best-effort: the spoke already
            # accepted the reset; a miss here only means a stale cookie lingers.
            uid = data.get("username") or data.get("user_id") or data.get("uid")
            if uid:
                _invalidate_user_sessions(hub, uid)
            return result
        except Exception as e:
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox setup config ───────────────────────────────────────────────────

    # Shims delegating to access.* — bodies live in access.py (importable,
    # testable, free of the nested-def annotation trap). Routes keep calling
