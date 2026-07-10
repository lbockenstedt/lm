"""Auth routes: login, me, logout, first-run setup, session prefixes."""
from api import (
    HTTPException, JSONResponse, Request, _SESSION_TTL, _client_ip,
    _cookie_secure, _hash_password, _lockout_key, _login_check, _login_fail,
    _login_success, _record_session, _save_sessions, _sessions,
    _start_cache_for_tenant, _stop_cache_for_tenant, _verify_password,
    get_netbox_spoke, get_tenant_scoping, logger, os, secrets, time,
)
from access import resolve_effective_permissions
from security.credential_store import resolve_password_hash


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
        token (8h absolute TTL, 30m idle timeout, persisted via ``_save_sessions``
        so it survives a hub restart), enforces failed-attempt lockout + per-IP
        spray limiting, and kicks background cache preload for each tenant the
        user belongs to. Returns the user record (user_id, permissions, tenants)
        with HTTP 200; 401 on bad credentials, 429 (Retry-After) when throttled,
        400 on missing fields."""
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("username", "").strip()
            password = data.get("password", "")
            # Real client IP for the per-IP spray limiter. Behind an Azure
            # front end the TCP peer is the proxy; _client_ip recovers the real
            # client from X-Forwarded-For ONLY when the peer is a configured
            # trusted proxy (LM_TRUSTED_PROXIES), walking right-to-left past
            # trusted hops — so XFF can't be spoofed to bypass the cap.
            ip = _client_ip(request)
            # Lockout key is case-folded so case-variant brute force ("admin",
            # "Admin", "ADMIN", …) can't get _LOGIN_MAX_FAILS tries PER variant.
            lkey = _lockout_key(user_id)
            # Throttle BEFORE the field/password checks so a locked-out IP can't
            # even probe, AND so a flood of malformed (empty-username) requests
            # still counts against the per-IP spray window (was: the 400 fired
            # before _login_check → unthrottled). ``_login_check`` covers both
            # per-username lockout and per-IP spray windows.
            allowed, retry_after = _login_check(lkey, ip)
            if not allowed:
                raise HTTPException(
                    status_code=429,
                    detail="Too many login attempts. Try again later.",
                    headers={"Retry-After": str(retry_after)},
                )
            if not user_id or not password:
                # Malformed, but still abuse — count it against the IP window so
                # an empty-field flood fills the bucket and trips the throttle
                # above on the next request.
                _login_fail(hub, lkey, ip)
                raise HTTPException(status_code=400, detail="username and password required")
            users = hub.state.system_state.get("users", {})
            user = users.get(user_id)
            # The hash to verify is normally the stored password_hash; a record
            # with a password_hash_ref instead resolves its hash from the
            # credential store (break-glass admin hash in Key Vault).
            pw_hash = resolve_password_hash(user) if user else None
            # Same 401 message for "no such user" and "wrong password" to avoid
            # username enumeration; both increment the lockout/spray counters.
            if not user or not pw_hash or \
               not _verify_password(password, pw_hash):
                _login_fail(hub, lkey, ip)
                raise HTTPException(status_code=401, detail="Invalid credentials")
            _login_success(hub, lkey, ip)
            # Always read the live record so migrations/admin changes take effect on next login.
            # Effective perms = group-derived rights unioned with per-user overrides (RBAC).
            perms   = resolve_effective_permissions(hub, user)
            tenants = user.get("tenants", [])
            protected = user.get("protected", False)
            # Protected accounts have no tenant assignment regardless of stored value
            if protected:
                tenants = []
            tenant_id = tenants[0] if tenants else None
            user_data = {
                "user_id":    user_id,
                "auth_type":  user.get("auth_type", "local"),
                "permissions": perms,
                "tenants":    tenants,
                "tenant_id":  tenant_id,
                "protected":  protected,
            }
            token = _record_session(hub, user_data)
            resp = JSONResponse({"status": "ok", **user_data})
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
                secure=_cookie_secure(),
            )
            # Kick off background cache preload for every tenant this user belongs to
            for tid in tenants:
                _start_cache_for_tenant(hub, tid)
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("local_login failed")
            raise HTTPException(status_code=500, detail="Login request failed")

    def _user_snapshot(hub, user_id, user):
        """Build the same session-shaped user dict login uses, so an API token
        carries identical effective permissions/tenants."""
        perms = resolve_effective_permissions(hub, user)
        tenants = [] if user.get("protected") else user.get("tenants", [])
        return {"user_id": user_id, "auth_type": user.get("auth_type", "local"),
                "permissions": perms, "tenants": tenants,
                "tenant_id": tenants[0] if tenants else None,
                "protected": user.get("protected", False)}

    @app.post("/auth/token")
    async def issue_api_token(request: Request):
        """Mint an API token pair (Bearer access + refresh). Authenticate EITHER
        with an active WebUI session (mint for yourself) OR username+password.
        Returns {token_type:'Bearer', access_token, refresh_token, expires_in}.
        The access token is 4h; use /auth/token/refresh to rotate seamlessly."""
        import api_tokens
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        name = str(data.get("name") or "api token")[:64]
        sess = _session_user(request)
        if sess and not sess.get("api_token"):   # a cookie session mints for itself
            user_id = sess.get("user_id")
            snap = sess.get("user") or {}
            snap.setdefault("user_id", user_id)
        else:                                      # username + password (throttled, like login)
            user_id = str(data.get("username") or "").strip()
            password = str(data.get("password") or "")
            ip = _client_ip(request)
            lkey = _lockout_key(user_id)  # case-folded: case variants share one lockout
            allowed, retry_after = _login_check(lkey, ip)
            if not allowed:
                raise HTTPException(status_code=429, detail="Too many attempts",
                                    headers={"Retry-After": str(retry_after)})
            users = hub.state.system_state.get("users", {})
            user = users.get(user_id)
            pw_hash = resolve_password_hash(user) if user else None
            if (not user_id or not password or not user
                    or not pw_hash
                    or not _verify_password(password, pw_hash)):
                _login_fail(hub, lkey, ip)
                raise HTTPException(status_code=401, detail="Invalid credentials")
            _login_success(hub, lkey, ip)
            snap = _user_snapshot(hub, user_id, user)
        if not user_id:
            raise HTTPException(status_code=401, detail="Not authenticated")
        access, refresh, ttl = api_tokens.issue_pair(hub, user_id, snap, name)
        logger.info("Issued API token '%s' for user %s", name, user_id)
        return JSONResponse({"token_type": "Bearer", "access_token": access,
                             "refresh_token": refresh, "expires_in": ttl})

    @app.post("/auth/token/refresh")
    async def refresh_api_token(request: Request):
        """Rotate a refresh token into a NEW access+refresh pair (seamless, no
        re-login). A refresh token is single-use; reuse revokes the family."""
        import api_tokens
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        rt = str(data.get("refresh_token") or "").strip()
        if not rt:
            raise HTTPException(status_code=400, detail="refresh_token required")
        pair = api_tokens.refresh(hub, rt)
        if not pair:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        access, refresh, ttl = pair
        return JSONResponse({"token_type": "Bearer", "access_token": access,
                             "refresh_token": refresh, "expires_in": ttl})

    @app.get("/auth/tokens")
    async def list_api_tokens(request: Request):
        """List the caller's live API token families (metadata only, no secrets)."""
        import api_tokens
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return {"tokens": api_tokens.list_tokens(sess.get("user_id"))}

    @app.post("/auth/token/revoke")
    async def revoke_api_token(request: Request):
        """Revoke one of the caller's API token families by id."""
        import api_tokens
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        try:
            data = await request.json()
        except Exception:
            data = {}
        tid = str(data.get("id") or "").strip()
        if not tid:
            raise HTTPException(status_code=400, detail="token id required")
        ok = api_tokens.revoke(hub, sess.get("user_id"), tid)
        return {"status": "ok" if ok else "not_found"}

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
        # /auth/me is the WebUI's recurring session-validation poll and is in
        # _PUBLIC, so access_control_middleware short-circuits BEFORE its
        # last_seen bump. Bump here so an active user polling /auth/me isn't
        # falsely idle-logged-out (last_seen would only advance on gated
        # requests, which a parked-on-the-dashboard user may not make).
        if isinstance(sess, dict):
            sess["last_seen"] = time.time()
        live = hub.state.system_state.get("users", {}).get(user_id, {})
        # Re-derive effective (group + per-user) perms live so group membership
        # or group-permission edits take effect without a re-login.
        _eff_perms = (resolve_effective_permissions(hub, live) if live
                      else sess["user"].get("permissions", {}))
        merged = {
            **sess["user"],
            "permissions": _eff_perms,
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
        """Create the first admin account. Only works when no users exist.

        When ``LM_SETUP_TOKEN`` is set (the install flag — generated by
        ``install_all.sh`` into ``.env``), the request MUST carry a matching
        ``X-Setup-Token`` header. This closes the first-run race where anyone who
        could reach the hub before the operator created the first account could
        plant the bootstrap admin. The token is consumed implicitly: once the
        first user exists this route 403s regardless, so the token need not be
        rotated after setup. ``--no-setup-token`` in the installer leaves the env
        unset, restoring the old open-first-run behavior (dev/loopback only)."""
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if users:
            raise HTTPException(status_code=403, detail="Setup already complete — log in with an existing account")
        setup_token = os.environ.get("LM_SETUP_TOKEN", "").strip()
        if setup_token:
            supplied = (request.headers.get("X-Setup-Token") or "").strip()
            if not supplied or not secrets.compare_digest(supplied, setup_token):
                raise HTTPException(status_code=403, detail="Setup token required")
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
            user_data = {
                "user_id": username,
                "auth_type": "local",
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "tenant_id": None,
                "protected": True,
            }
            token = _record_session(hub, user_data)
            resp = JSONResponse({
                "status": "ok",
                **user_data,
            })
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
                secure=_cookie_secure(),
            )
            return resp
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("first_run_setup failed")
            raise HTTPException(status_code=500, detail="Setup request failed")

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
