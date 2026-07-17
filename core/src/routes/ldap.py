"""LDAP directory (OU/user/group) routes."""
from api import (
    HTTPException, Request, _invalidate_user_sessions, get_spoke_or_503, logger,
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
    # DN-valued fields — must all sit within the caller's OU subtree. Includes
    # move targets (new_superior/new_parent) so an in-OU entry can't be relocated
    # OUT of the OU, and member DN fields.
    _LDAP_DN_FIELDS = ("dn", "parent_dn", "parent", "ou", "ou_dn", "base",
                       "base_dn", "group_dn", "user_dn", "target_dn", "member_dn",
                       "new_superior", "newsuperior", "new_parent", "new_parent_dn")
    # BARE identity fields the directory spoke may key on INSTEAD of the validated
    # dn — each must match the RDN value of an in-OU dn in the same payload, else a
    # tenant-admin could send their own dn + a foreign username and act on a user
    # outside their OU (e.g. reset ANY user's password).
    _LDAP_BARE_ID_FIELDS = ("username", "uid", "user_id", "userid", "cn",
                            "sam_account_name", "samaccountname")

    def _tenant_ldap_base(sess):
        tid = (sess or {}).get("user", {}).get("tenant_id") or ""
        t = hub.state.get_tenant(tid) or {}
        return str(t.get("ldap_base_dn") or "").strip()

    def _dn_in_base(dn, base) -> bool:
        d = str(dn or "").strip().lower()
        b = str(base or "").strip().lower()
        return bool(b) and bool(d) and (d == b or d.endswith("," + b))

    def _rdn_value(dn) -> str:
        # Leftmost RDN value, e.g. "uid=alice,ou=t,dc=x" -> "alice".
        first = str(dn or "").strip().split(",", 1)[0]
        return first.split("=", 1)[1].strip().lower() if "=" in first else ""

    def _assert_ldap_write(request, data):
        """Global Admin → any. Otherwise (tenant-admin) EVERY DN-like field must sit
        within the caller's tenant OU subtree, and every BARE identity field must
        match the RDN of an in-OU DN in the same payload. A write carrying no
        resolvable in-OU DN is refused (fail-closed) — a tenant-admin cannot touch
        another tenant's OU, cannot relocate an entry out of it, and cannot smuggle
        a foreign uid/username past an in-OU dn."""
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
        rdns = {_rdn_value(d) for d in dns if _rdn_value(d)}
        for f in _LDAP_BARE_ID_FIELDS:
            v = data.get(f)
            if v and str(v).strip().lower() not in rdns:
                raise HTTPException(status_code=403,
                    detail="Identity fields must match a DN within your tenant's OU")

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
        return get_spoke_or_503(hub, "directory", "LDAP")

    async def _ldap_warm(hub, cmd):
        """Warm-cached LDAP list read: cache the raw (scope-independent) result
        and serve last-known (stale) on spoke-down / error / overrun so the
        Directory page renders instantly instead of blocking/503-ing. Per-reader
        OU scoping (_scope_ldap_list) is applied by the caller after."""
        spoke_id = hub.get_spoke_by_type("directory")
        if not spoke_id:
            cached = hub.warm_get(cmd.lower(), "_all_")
            if cached is not None:
                return cached
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        try:
            result = await hub.request_response(spoke_id, cmd, {}, timeout=20.0)
            data = result.get("data", result) if isinstance(result, dict) else result
            await hub.warm_set(cmd.lower(), "_all_", data)
            return data
        except HTTPException:
            raise
        except Exception:
            cached = hub.warm_get(cmd.lower(), "_all_")
            if cached is not None:
                return cached
            raise

    @app.get("/api/ldap/ous")
    async def get_ldap_ous(request: Request):
        """List LDAP OUs from the directory spoke (tenant-OU scoped for non-admins)."""
        hub = app.state.hub
        logger.debug("relay GET /api/ldap/ous")
        return _scope_ldap_list(request, await _ldap_warm(hub, "LIST_OUS"))

    @app.post("/api/ldap/ous")
    async def create_ldap_ou(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_OU", data)
            return result
        except HTTPException:
            raise
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
        logger.debug("relay GET /api/ldap/users")
        return _scope_ldap_list(request, await _ldap_warm(hub, "LIST_USERS"))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_USER", data)
            return result
        except HTTPException:
            raise
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
        logger.debug("relay GET /api/ldap/groups")
        return _scope_ldap_list(request, await _ldap_warm(hub, "LIST_GROUPS"))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        hub = app.state.hub
        spoke_id = await get_ldap_spoke(hub)
        try:
            data = await request.json()
            _assert_ldap_write(request, data)
            result = await hub.request_response(spoke_id, "CREATE_GROUP", data)
            return result
        except HTTPException:
            raise
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
        except HTTPException:
            raise
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
        except HTTPException:
            raise
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
        except HTTPException:
            raise
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
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox setup config ───────────────────────────────────────────────────

    # Shims delegating to access.* — bodies live in access.py (importable,
    # testable, free of the nested-def annotation trap). Routes keep calling
