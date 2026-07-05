"""Auth routes: login, me, logout, first-run setup, session prefixes."""
from api import (
    HTTPException, JSONResponse, Request, _SESSION_TTL, _hash_password, _save_sessions,
    _start_cache_for_tenant, _stop_cache_for_tenant, _verify_password, get_netbox_spoke,
    get_tenant_scoping, logger, secrets, time,
)


def register(app, hub, ctx):
    """Register auth routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_prefixes = ctx._resolve_prefixes
    _effective_tenant = ctx._effective_tenant
    _resolve_prefixes_for_tenant = ctx._resolve_prefixes_for_tenant

    @app.post("/auth/login")
    async def local_login(request: Request):
        """Authenticate a local user and set the ``lm_session`` cookie.

        Verifies the password against the stored hash, mints a 32-byte session
        token (8h TTL, persisted via ``_save_sessions`` so it survives a hub
        restart), and kicks background cache preload for each tenant the user
        belongs to. Returns the user record (user_id, permissions, tenants) with
        HTTP 200; 401 on bad credentials, 400 on missing fields."""
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("username", "").strip()
            password = data.get("password", "")
            if not user_id or not password:
                raise HTTPException(status_code=400, detail="username and password required")
            users = hub.state.system_state.get("users", {})
            user = users.get(user_id)
            if not user or not user.get("password_hash"):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            if not _verify_password(password, user["password_hash"]):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            # Always read the live record so migrations/admin changes take effect on next login
            perms   = user.get("permissions", {})
            tenants = user.get("tenants", [])
            protected = user.get("protected", False)
            # Protected accounts have no tenant assignment regardless of stored value
            if protected:
                tenants = []
            tenant_id = tenants[0] if tenants else None
            token = secrets.token_urlsafe(32)
            user_data = {
                "user_id":    user_id,
                "auth_type":  user.get("auth_type", "local"),
                "permissions": perms,
                "tenants":    tenants,
                "tenant_id":  tenant_id,
                "protected":  protected,
            }
            _sessions[token] = {
                "user_id": user_id,
                "expires": time.time() + _SESSION_TTL,
                "user":    user_data,
            }
            _save_sessions(hub)
            resp = JSONResponse({"status": "ok", **user_data})
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
            )
            # Kick off background cache preload for every tenant this user belongs to
            for tid in tenants:
                _start_cache_for_tenant(hub, tid)
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("local_login failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/auth/me")
    async def auth_me(request: Request):
        """Return the current user, or 401 ``{first_run}`` when unauthenticated.

        Re-reads the live user record each call so permission/tenant changes
        made after login take effect without a re-login, and keeps the session
        in sync. ``first_run=true`` (no users defined yet) tells the WebUI to
        show the initial setup flow instead of the login form."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            users = hub.state.system_state.get("users", {})
            return JSONResponse(
                status_code=401,
                content={"authenticated": False, "first_run": len(users) == 0},
            )
        # Always read permissions and tenants from the live user record so that
        # changes made after login (migrations, admin edits) are reflected immediately
        # without requiring a logout/login cycle.
        user_id = sess.get("user_id") or sess["user"].get("user_id")
        live = hub.state.system_state.get("users", {}).get(user_id, {})
        merged = {
            **sess["user"],
            "permissions": live.get("permissions", sess["user"].get("permissions", {})),
            "tenants":     live.get("tenants",     sess["user"].get("tenants", [])),
            "tenant_id":   live.get("tenants", [sess["user"].get("tenant_id")])[0]
                           if live.get("tenants") else None,
            "protected":   live.get("protected", False),
        }
        # Keep session in sync so middleware checks stay consistent
        sess["user"] = merged
        return {"status": "ok", **merged}

    @app.post("/auth/logout")
    async def auth_logout(request: Request):
        """Drop the ``lm_session`` token, clear the cookie, and stop the
        background cache task for the user's tenant when no other sessions
        for it remain. Persists the session store so the revocation survives
        a restart."""
        token = request.cookies.get("lm_session")
        sess = _sessions.pop(token, None)
        tenant_id = (sess or {}).get("user", {}).get("tenant_id")
        _save_sessions(app.state.hub)
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie("lm_session")
        if tenant_id:
            _stop_cache_for_tenant(tenant_id)
        return resp

    @app.post("/auth/setup")
    async def first_run_setup(request: Request):
        """Create the first admin account. Only works when no users exist."""
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if users:
            raise HTTPException(status_code=403, detail="Setup already complete — log in with an existing account")
        try:
            data = await request.json()
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                raise HTTPException(status_code=400, detail="username and password required")
            if len(password) < 8:
                raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
            entry = {
                "auth_type": "local",
                "password_hash": _hash_password(password),
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "protected": True,  # anti-lockout: this account cannot be deleted or demoted
                "updated_at": time.time(),
            }
            hub.state.system_state.setdefault("users", {})[username] = entry
            hub.state.save_state()
            token = secrets.token_urlsafe(32)
            _sessions[token] = {
                "user_id": username,
                "expires": time.time() + _SESSION_TTL,
                "user": {
                    "user_id": username,
                    "auth_type": "local",
                    "permissions": {"role": "admin", "admin": True},
                    "tenants": [],
                    "tenant_id": None,
                    "protected": True,
                },
            }
            _save_sessions(hub)
            resp = JSONResponse({
                "status": "ok",
                "user_id": username,
                "auth_type": "local",
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "tenant_id": None,
                "protected": True,
            })
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
            )
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("first_run_setup failed")
            raise HTTPException(status_code=500, detail=str(e))

    # _PREFIX_CACHE_TTL moved to access.py (access._PREFIX_CACHE_TTL); the
    # session-prefix cache TTL is now owned by access.resolve_prefixes.

    @app.get("/auth/prefixes")
    async def get_session_prefixes(request: Request, tenant: str = None):
        """Return the IP prefixes for the current session user's tenant.

        NetBox-derived and session-cached (5 min). Used by the UI to filter all
        module views (firewall rules, NAC sessions, etc.) AND by the server-side
        subnet filter — both share prefix resolution so the UI and the API
        enforcement agree. ``?tenant=`` scopes prefixes to the selected tenant
        (an admin acting as a tenant via the switcher, or a multi-tenant user
        switching to an allowed one); without it, the session tenant is used
        (admins get [] so the client-side filter stays a no-op for them).
        """
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        hub = app.state.hub
        if tenant:
            tid = _effective_tenant(request, tenant)
            prefixes = await _resolve_prefixes_for_tenant(hub, tid) if tid else []
        else:
            tid = sess.get("user", {}).get("tenant_id")
            prefixes = await _resolve_prefixes(hub, sess)
        resp = {"prefixes": prefixes}
        # Surface why a non-admin might have no prefixes (helps debugging the
        # "tenant sees everything" symptom). Admins get [] intentionally.
        if not prefixes and not _is_admin(sess):
            if not tid:
                resp["warning"] = "No tenant assigned to this user"
            elif not get_tenant_scoping(hub, tid).get("netbox_tenant_slug"):
                resp["warning"] = "No NetBox tenant slug configured for this tenant"
            elif not get_netbox_spoke(hub):
                resp["warning"] = "NetBox spoke not connected"
        return resp

    # ── Admin: per-module subnet-filter toggle ──────────────────────────────
    # Middleware already 403s non-admins on /admin/* (api.py:274); the explicit
    # _is_admin check is defense-in-depth and matches the other /admin routes.
