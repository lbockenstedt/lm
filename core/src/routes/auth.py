"""Auth routes: login, me, logout, first-run setup, session prefixes."""
# Shared Hub helpers: HTTP/JSON types, session store and TTL, login throttling and
# lockout, password hashing, cookie settings, cache warm-up and misc stdlib modules.
from api import (
    HTTPException, JSONResponse, Request, _SESSION_TTL, _client_ip,
    _cookie_secure, _end_impersonation, _hash_password, _lockout_key, _login_check, _login_fail,
    _login_success, _record_session, _save_sessions, _sessions,
    _verify_password, cache_kick_login,
    get_netbox_spoke, get_tenant_scoping, logger, os, secrets, time,
)
# Tenant access checks and RBAC (group + per-user) effective-permission resolution.
from access import check_tenant_access, resolve_effective_permissions
# One-time RSA key exchange so the browser never sends the password in clear text.
from security import login_crypto
# Resolves a user's password hash, including hashes held in the credential store.
from security.credential_store import resolve_password_hash


def register(app, hub, ctx):
    """Register auth routes on the Hub app."""
    # Pull the session lookup helper from the shared route context.
    _session_user = ctx._session_user

    def _login_ev_meta(request, reason):
        """Structured evidence for a failed-login threat event so the operator
        can drill into who/what attempted it from the Security UI."""
        # Build the evidence dict from request headers; fall back to just the reason on error.
        try:
            return {
                "method": request.method,
                "path": request.url.path,
                "user_agent": request.headers.get("user-agent") or "",
                "referer": request.headers.get("referer") or "",
                "x_forwarded_for": request.headers.get("x-forwarded-for") or "",
                "reason": reason,
            }
        except Exception:  # noqa: BLE001
            return {"reason": reason}

    # More shared helpers: admin check and tenant/prefix resolution for sessions.
    _is_admin = ctx._is_admin
    _resolve_prefixes = ctx._resolve_prefixes
    _effective_tenant = ctx._effective_tenant
    _resolve_prefixes_for_tenant = ctx._resolve_prefixes_for_tenant

    # Public key endpoint used by the login page before submitting credentials.
    @app.get("/auth/login/key")
    async def login_key():
        """One-time RSA-OAEP key the login page encrypts the password with, so
        the clear-text password never appears in the browser's network log."""
        # Issue a fresh key; "no-store" stops the browser or proxies caching it.
        return JSONResponse(login_crypto.issue(), headers={"Cache-Control": "no-store"})

    # Local username/password login.
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
        # Read the submitted username (trimmed) and password.
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
            # The login page sends an encrypted password; decrypt it with the one-time key.
            # An expired/unknown key counts as a failed attempt.
            if data.get("password_enc"):
                try:
                    password = login_crypto.decrypt(data.get("key_id"), data.get("password_enc"))
                except ValueError as exc:
                    _login_fail(hub, lkey, ip, meta=_login_ev_meta(request, str(exc)))
                    raise HTTPException(status_code=400, detail="Login expired, please try again")
            if not user_id or not password:
                # Malformed, but still abuse — count it against the IP window so
                # an empty-field flood fills the bucket and trips the throttle
                # above on the next request.
                _login_fail(hub, lkey, ip, meta=_login_ev_meta(request, "missing username/password"))
                raise HTTPException(status_code=400, detail="username and password required")
            # Look up the user record.
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
                _login_fail(hub, lkey, ip, meta=_login_ev_meta(request, "invalid credentials"))
                raise HTTPException(status_code=401, detail="Invalid credentials")
            # Credentials are good: reset the failure counters for this user/IP.
            _login_success(hub, lkey, ip)
            # Always read the live record so migrations/admin changes take effect on next login.
            # Effective perms = group-derived rights unioned with per-user overrides (RBAC).
            perms   = resolve_effective_permissions(hub, user)
            # The user's tenants and whether it is a protected (built-in) account.
            tenants = user.get("tenants", [])
            protected = user.get("protected", False)
            # Protected accounts have no tenant assignment regardless of stored value
            if protected:
                tenants = []
            # The first tenant is the session's initial tenant; build the session's user record.
            tenant_id = tenants[0] if tenants else None
            user_data = {
                "user_id":    user_id,
                "auth_type":  user.get("auth_type", "local"),
                "permissions": perms,
                "tenants":    tenants,
                "tenant_id":  tenant_id,
                "protected":  protected,
            }
            # Add the user's saved default tenant (if still valid) and create the session token.
            user_data["default_tenant"] = _default_tenant(hub, user, user_data)
            token = _record_session(hub, user_data, bind_ip=_client_ip(request))
            # Reply with the user record and set the session cookie (HttpOnly, SameSite=Lax).
            resp = JSONResponse({"status": "ok", **user_data})
            resp.set_cookie(
                key="lm_session", value=token,
                httponly=True, samesite="lax",
                max_age=_SESSION_TTL,
                secure=_cookie_secure(),
            )
            # Refresh this user's cached data now; pages then serve from cache.
            cache_kick_login(hub, user_data)
            return resp
        # Our own HTTP errors pass through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("local_login failed")
            raise HTTPException(status_code=500, detail="Login request failed")

    def _default_tenant(hub, record, user_data):
        """The user's saved default tenant while it still exists and they may
        still view it; otherwise None (the WebUI falls back to its usual pick)."""
        # No saved default: nothing to return.
        tenant = (record or {}).get("default_tenant")
        if not tenant:
            return None
        # The tenant must still exist (the built-in "default" always does).
        if tenant != "default" and tenant not in hub.state.tenant_state.get("tenants", {}):
            return None
        # And the user must still be allowed to view it.
        return tenant if check_tenant_access({"user": user_data}, tenant) else None

    def _user_snapshot(hub, user_id, user):
        """Build the same session-shaped user dict login uses, so an API token
        carries identical effective permissions/tenants."""
        # Effective permissions; protected accounts never carry tenants.
        perms = resolve_effective_permissions(hub, user)
        tenants = [] if user.get("protected") else user.get("tenants", [])
        # Same shape as the login session's user record.
        return {"user_id": user_id, "auth_type": user.get("auth_type", "local"),
                "permissions": perms, "tenants": tenants,
                "tenant_id": tenants[0] if tenants else None,
                "protected": user.get("protected", False)}

    # Mint an API access/refresh token pair.
    @app.post("/auth/token")
    async def issue_api_token(request: Request):
        """Mint an API token pair (Bearer access + refresh). Authenticate EITHER
        with an active WebUI session (mint for yourself) OR username+password.
        Returns {token_type:'Bearer', access_token, refresh_token, expires_in}.
        The access token is 4h; use /auth/token/refresh to rotate seamlessly."""
        # API token store (imported lazily); read the JSON body, defaulting to {}.
        import api_tokens
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Human label for the token, capped at 64 characters.
        name = str(data.get("name") or "api token")[:64]
        # An impersonating admin may not mint tokens as the impersonated user.
        sess = _session_user(request)
        if sess and sess.get("impersonator"):
            raise HTTPException(status_code=403, detail="Not allowed while impersonating a user")
        # A real cookie session mints a token for its own user, reusing its user record.
        if sess and not sess.get("api_token"):   # a cookie session mints for itself
            user_id = sess.get("user_id")
            snap = sess.get("user") or {}
            snap.setdefault("user_id", user_id)
        # Otherwise authenticate with username + password, with the same throttling as login.
        else:                                      # username + password (throttled, like login)
            user_id = str(data.get("username") or "").strip()
            password = str(data.get("password") or "")
            ip = _client_ip(request)
            lkey = _lockout_key(user_id)  # case-folded: case variants share one lockout
            allowed, retry_after = _login_check(lkey, ip)
            if not allowed:
                raise HTTPException(status_code=429, detail="Too many attempts",
                                    headers={"Retry-After": str(retry_after)})
            # Verify the password; any failure is one generic 401 that counts toward lockout.
            users = hub.state.system_state.get("users", {})
            user = users.get(user_id)
            pw_hash = resolve_password_hash(user) if user else None
            if (not user_id or not password or not user
                    or not pw_hash
                    or not _verify_password(password, pw_hash)):
                _login_fail(hub, lkey, ip, meta=_login_ev_meta(request, "invalid credentials"))
                raise HTTPException(status_code=401, detail="Invalid credentials")
            # Success: reset counters and build the user snapshot the token will carry.
            _login_success(hub, lkey, ip)
            snap = _user_snapshot(hub, user_id, user)
        # Defensive: a token must belong to a user.
        if not user_id:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Issue the token pair, log it (name and user only, never the token) and return it.
        access, refresh, ttl = api_tokens.issue_pair(hub, user_id, snap, name)
        logger.info("Issued API token '%s' for user %s", name, user_id)
        return JSONResponse({"token_type": "Bearer", "access_token": access,
                             "refresh_token": refresh, "expires_in": ttl})

    # Rotate a refresh token into a new token pair.
    @app.post("/auth/token/refresh")
    async def refresh_api_token(request: Request):
        """Rotate a refresh token into a NEW access+refresh pair (seamless, no
        re-login). A refresh token is single-use; reuse revokes the family."""
        # Token store (lazy import); read the JSON body, defaulting to {}.
        import api_tokens
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        # A refresh token is required.
        rt = str(data.get("refresh_token") or "").strip()
        if not rt:
            raise HTTPException(status_code=400, detail="refresh_token required")
        # Rotate it; None means invalid, expired or already used.
        pair = api_tokens.refresh(hub, rt)
        if not pair:
            raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
        # Return the new pair in the standard OAuth-style shape.
        access, refresh, ttl = pair
        return JSONResponse({"token_type": "Bearer", "access_token": access,
                             "refresh_token": refresh, "expires_in": ttl})

    # List the caller's own API tokens.
    @app.get("/auth/tokens")
    async def list_api_tokens(request: Request):
        """List the caller's live API token families (metadata only, no secrets)."""
        # Token store (lazy import); the caller must be signed in.
        import api_tokens
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Only the caller's own token families are listed.
        return {"tokens": api_tokens.list_tokens(sess.get("user_id"))}

    # Revoke one of the caller's API tokens.
    @app.post("/auth/token/revoke")
    async def revoke_api_token(request: Request):
        """Revoke one of the caller's API token families by id."""
        # Token store (lazy import); the caller must be signed in.
        import api_tokens
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Read the JSON body (defaulting to {}); a token id is required.
        try:
            data = await request.json()
        except Exception:
            data = {}
        tid = str(data.get("id") or "").strip()
        if not tid:
            raise HTTPException(status_code=400, detail="token id required")
        # An impersonating admin may not revoke the impersonated user's tokens.
        if sess.get("impersonator"):
            raise HTTPException(status_code=403, detail="Not allowed while impersonating a user")
        # Revoke only within the caller's own tokens; report whether it was found.
        ok = api_tokens.revoke(hub, sess.get("user_id"), tid)
        return {"status": "ok" if ok else "not_found"}

    # Who am I? Used by the WebUI on every page load.
    @app.get("/auth/me")
    async def auth_me(request: Request):
        """Return the current user, or 401 ``{first_run}`` when unauthenticated.

        Re-reads the live user record each call so permission/tenant changes
        made after login take effect without a re-login, and keeps the session
        in sync. ``first_run=true`` (no users defined yet) tells the WebUI to
        show the initial setup flow instead of the login form."""
        # Not signed in: 401, telling the WebUI whether this is a first run (no users yet).
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
        # Record activity now (see the note above).
        if isinstance(sess, dict):
            sess["last_seen"] = time.time()
        # Fetch the live user record (empty if the user was deleted).
        live = hub.state.system_state.get("users", {}).get(user_id, {})
        # Re-derive effective (group + per-user) perms live so group membership
        # or group-permission edits take effect without a re-login.
        _eff_perms = (resolve_effective_permissions(hub, live) if live
                      else sess["user"].get("permissions", {}))
        # Friendly display name — for Entra users user_id is the oid GUID, so
        # prefer the record's name/email (captured from the id_token) and fall
        # back to the user_id (which IS the username for local accounts).
        _name = str(live.get("name") or sess["user"].get("name") or "")
        _email = str(live.get("email") or sess["user"].get("email") or "")
        # Session record refreshed with live permissions, tenants, protection and names.
        merged = {
            **sess["user"],
            "permissions": _eff_perms,
            "tenants":     live.get("tenants",     sess["user"].get("tenants", [])),
            "tenant_id":   live.get("tenants", [sess["user"].get("tenant_id")])[0]
                           if live.get("tenants") else None,
            "protected":   live.get("protected", False),
            "name":        _name,
            "email":       _email,
            "display_name": _name or _email or user_id,
        }
        # Add the saved default tenant if it is still valid for this user.
        merged["default_tenant"] = _default_tenant(hub, live, merged)
        # Keep session in sync so middleware checks stay consistent
        sess["user"] = merged
        # Build the reply; while impersonating, also say who the real admin is.
        out = {"status": "ok", **merged}
        imp = sess.get("impersonator")
        if imp:
            out["impersonator"] = {"user_id": imp.get("user_id"),
                                   "display_name": imp.get("display_name") or imp.get("user_id"),
                                   "started": imp.get("started")}
        return out

    # Save the caller's default tenant.
    @app.put("/auth/default-tenant")
    async def set_default_tenant(request: Request):
        """Save the tenant the WebUI opens on for the caller (``{"tenant_id": null}``
        clears it). Self-service: any signed-in user, but only for an existing
        tenant they are allowed to view."""
        # The caller must be signed in.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Read the JSON body (defaulting to {}) and the requested tenant ("" clears it).
        try:
            data = await request.json()
        except Exception:
            data = {}
        tenant = str((data or {}).get("tenant_id") or "").strip()
        # Find the caller's stored user record.
        user_id = sess.get("user_id") or sess["user"].get("user_id")
        user = hub.state.system_state.get("users", {}).get(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User record not found")
        # Setting a tenant: it must exist and the caller must be allowed to view it.
        if tenant:
            known = tenant == "default" or tenant in hub.state.tenant_state.get("tenants", {})
            if not known:
                raise HTTPException(status_code=404, detail=f"Unknown tenant '{tenant}'")
            if not check_tenant_access(sess, tenant):
                raise HTTPException(status_code=403, detail="You do not have access to that tenant")
            user["default_tenant"] = tenant
        # Clearing: remove the saved default.
        else:
            user.pop("default_tenant", None)
        # Persist the change now and reflect it in the live session.
        await hub.state.save_state_now()
        sess["user"]["default_tenant"] = tenant or None
        return {"status": "ok", "default_tenant": tenant or None}

    # Start impersonating another user (Global Admin only).
    @app.post("/auth/impersonate")
    async def impersonate_start(request: Request):
        """Global Admin only: switch the caller's session to act as another
        registered user (``{"user_id": ...}``). The session takes the target's
        effective permissions and tenants; the admin identity is kept under
        ``impersonator`` so ``/auth/impersonate/stop`` can restore it."""
        # Need a real browser session (not an API token), not already impersonating, and admin.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or sess.get("api_token"):
            raise HTTPException(status_code=401, detail="Not authenticated")
        if sess.get("impersonator"):
            raise HTTPException(status_code=409, detail="Already impersonating; stop first")
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin access required")
        # Read the JSON body (defaulting to {}): the target user id is required.
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = str((data or {}).get("user_id") or "").strip()
        admin_id = sess.get("user_id") or sess["user"].get("user_id")
        if not target:
            raise HTTPException(status_code=400, detail="user_id required")
        # Impersonating yourself makes no sense.
        if target == admin_id:
            raise HTTPException(status_code=400, detail="You cannot impersonate yourself")
        # The target must be a registered user.
        record = hub.state.system_state.get("users", {}).get(target)
        if not record:
            raise HTTPException(status_code=404, detail=f"Unknown user '{target}'")
        # Build the target's session record, including names and default tenant.
        snap = _user_snapshot(hub, target, record)
        snap["name"] = str(record.get("name") or "")
        snap["email"] = str(record.get("email") or "")
        snap["display_name"] = snap["name"] or snap["email"] or target
        snap["default_tenant"] = _default_tenant(hub, record, snap)
        # Save the admin's own identity so it can be restored when impersonation stops.
        admin_user = sess.get("user") or {}
        sess["impersonator"] = {
            "user_id": admin_id,
            "display_name": admin_user.get("display_name") or admin_id,
            "user": admin_user,
            "started": time.time(),
        }
        # Switch the session to the target and drop cached prefixes (they were the admin's).
        sess["user_id"] = target
        sess["user"] = snap
        sess.pop("prefixes", None)
        sess.pop("prefixes_at", None)
        # Persist, audit-log the switch, and warm the target's cached data.
        _save_sessions(hub)
        logger.warning("IMPERSONATION start: admin=%s target=%s ip=%s sid=%s",
                       admin_id, target, _client_ip(request), sess.get("sid"))
        cache_kick_login(hub, snap)
        # Return the new identity plus who is impersonating.
        return {"status": "ok", **snap,
                "impersonator": {"user_id": admin_id,
                                 "display_name": sess["impersonator"]["display_name"],
                                 "started": sess["impersonator"]["started"]}}

    # Stop impersonating and return to the admin's own identity.
    @app.post("/auth/impersonate/stop")
    async def impersonate_stop(request: Request):
        """End an impersonation and restore the admin's own identity."""
        # The caller must be signed in and currently impersonating.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        imp = sess.get("impersonator")
        if not imp:
            raise HTTPException(status_code=400, detail="Not impersonating")
        # Remember who was impersonated, restore the admin, persist and audit-log it.
        target = sess.get("user_id")
        _end_impersonation(sess)
        _save_sessions(hub)
        logger.warning("IMPERSONATION stop: admin=%s target=%s ip=%s sid=%s",
                       sess.get("user_id"), target, _client_ip(request), sess.get("sid"))
        return {"status": "ok", "user_id": sess.get("user_id")}

    # Sign out.
    @app.post("/auth/logout")
    async def auth_logout(request: Request):
        """Drop the ``lm_session`` token, clear the cookie, and stop the
        background cache task for the user's tenant when no other sessions
        for it remain. Persists the session store so the revocation survives
        a restart."""
        # Remove the session token server-side and persist the store.
        token = request.cookies.get("lm_session")
        _sessions.pop(token, None)
        _save_sessions(app.state.hub)
        # Clear the browser's session cookie.
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie("lm_session")
        return resp

    # First-run creation of the bootstrap admin account.
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
        # Refuse once any user exists.
        hub = app.state.hub
        users = hub.state.system_state.get("users", {})
        if users:
            raise HTTPException(status_code=403, detail="Setup already complete — log in with an existing account")
        # If the installer set a setup token, the request must present it (constant-time compare).
        setup_token = os.environ.get("LM_SETUP_TOKEN", "").strip()
        if setup_token:
            supplied = (request.headers.get("X-Setup-Token") or "").strip()
            if not supplied or not secrets.compare_digest(supplied, setup_token):
                raise HTTPException(status_code=403, detail="Setup token required")
        # Read and validate the username and password (minimum 8 characters).
        try:
            data = await request.json()
            username = data.get("username", "").strip()
            password = data.get("password", "")
            if not username or not password:
                raise HTTPException(status_code=400, detail="username and password required")
            if len(password) < 8:
                raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
            # The first account is a protected local admin with no tenant.
            entry = {
                "auth_type": "local",
                "password_hash": _hash_password(password),
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "protected": True,  # anti-lockout: this account cannot be deleted or demoted
                "updated_at": time.time(),
            }
            # Store the account and persist immediately.
            hub.state.system_state.setdefault("users", {})[username] = entry
            await hub.state.save_state_now()
            # Sign the new admin in straight away: build the session record and token.
            user_data = {
                "user_id": username,
                "auth_type": "local",
                "permissions": {"role": "admin", "admin": True},
                "tenants": [],
                "tenant_id": None,
                "protected": True,
            }
            token = _record_session(hub, user_data, bind_ip=_client_ip(request))
            # Reply and set the session cookie, same settings as normal login.
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
        # Our own HTTP errors pass through; anything else is logged and returned as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("first_run_setup failed")
            raise HTTPException(status_code=500, detail="Setup request failed")

    # _PREFIX_CACHE_TTL moved to access.py (access._PREFIX_CACHE_TTL); the
    # session-prefix cache TTL is now owned by access.resolve_prefixes.

    # IP prefixes that scope what the caller's tenant can see.
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
        # The caller must be signed in.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        hub = app.state.hub
        # An explicit tenant (after access checks) wins; otherwise use the session's tenant.
        if tenant:
            tid = _effective_tenant(request, tenant)
            prefixes = await _resolve_prefixes_for_tenant(hub, tid) if tid else []
        else:
            tid = sess.get("user", {}).get("tenant_id")
            prefixes = await _resolve_prefixes(hub, sess)
        # Build the reply.
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
