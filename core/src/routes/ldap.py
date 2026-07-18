"""Directory (LDAP/Entra) routes — tenant-scoped user/group management.

The directory is one OpenLDAP mirror partitioned per tenant: TENANT == OU (1:1),
``ou=<tenant_slug>,<base_dn>``. A **tenant-admin** manages ONLY their own
tenant's users + groups; a **Global Admin** may pick any tenant. Every relayed
``LDAP_*`` command carries a ``tenant_slug`` that is derived SERVER-SIDE from the
session (:func:`access.resolve_directory_tenant`) — a tenant-admin can NEVER pass
another tenant's slug (the cross-tenant guard, enforced here and matched
case-insensitively so case can't bypass it). Reads are warm-cached per tenant.

The middleware (api.py) already gates ``/api/ldap/*``: GET requires the ``ldap``
right (or admin); writes require the tenant-admin tier (``_can_edit_shared``).
This module adds the per-tenant slug injection + guard on top.
"""
from api import (
    HTTPException, Request, _invalidate_user_sessions, access,
    get_spoke_or_503, logger,
)


def register(app, hub, ctx):
    """Register directory (LDAP) routes on the Hub app."""
    _session_user = ctx._session_user

    def _directory_slug(request: Request, data=None) -> str:
        """Resolve the tenant OU slug this request acts on, enforcing the
        cross-tenant guard. The requested tenant is read from the body
        (``tenant_id``/``tenant``) OR the ``?tenant=`` query — a tenant-admin
        cannot smuggle a foreign tenant through EITHER, since
        :func:`access.resolve_directory_tenant` validates it against their own
        tenants case-insensitively. Returns the canonical OU slug (never the
        client-supplied casing)."""
        sess = _session_user(request)
        is_adm = access.is_admin(sess)
        acting = (sess or {}).get("user", {}).get("tenants") or []
        requested = ""
        if isinstance(data, dict):
            requested = str(data.get("tenant_id") or data.get("tenant") or "").strip()
        if not requested:
            requested = str(request.query_params.get("tenant") or "").strip()
        tid, status, detail = access.resolve_directory_tenant(is_adm, acting, requested)
        if status:
            raise HTTPException(status_code=status, detail=detail)
        return access.ldap_tenant_slug(hub, tid)

    async def _relay(cmd: str, payload: dict):
        """Relay an LDAP_* command to the directory spoke and unwrap its data.

        SURFACES spoke-side failures: if the spoke returns an ERROR envelope
        (e.g. slapd unreachable → SERVER_DOWN) this raises 502 with the message
        instead of returning the envelope with a 200 — otherwise the WebUI shows
        a false 'created' toast for an op that actually failed."""
        spoke_id = get_spoke_or_503(hub, "directory", "LDAP")
        result = await hub.request_response(spoke_id, cmd, payload, timeout=20.0)
        if isinstance(result, dict) and str(result.get("status", "")).upper() == "ERROR":
            raise HTTPException(status_code=502,
                                detail=result.get("message") or f"{cmd} failed on the LDAP server")
        return result.get("data", result) if isinstance(result, dict) else result

    async def _relay_list(cmd: str, slug: str):
        """Warm-cached LIST read (per tenant slug): serve last-known (stale) on
        spoke-down / error so the Directory page renders instead of 503-ing."""
        spoke_id = hub.get_spoke_by_type("directory")
        key = cmd.lower()
        if not spoke_id:
            cached = hub.warm_get(key, slug)
            if cached is not None:
                return cached
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        try:
            result = await hub.request_response(spoke_id, cmd, {"tenant_slug": slug},
                                                timeout=20.0)
            # Don't cache/return an ERROR envelope as if it were data (a
            # SERVER_DOWN would otherwise poison the warm cache with junk and
            # hide the outage) — fall through to stale cache / raise.
            if isinstance(result, dict) and str(result.get("status", "")).upper() == "ERROR":
                raise RuntimeError(result.get("message") or f"{cmd} failed on the LDAP server")
            data = result.get("data", result) if isinstance(result, dict) else result
            await hub.warm_set(key, slug, data)
            return data
        except HTTPException:
            raise
        except Exception:  # noqa: BLE001
            cached = hub.warm_get(key, slug)
            if cached is not None:
                return cached
            raise

    # ── Tenant picker (feeds the WebUI Directory tenant dropdown) ─────────────
    @app.get("/api/ldap/tenants")
    async def ldap_tenants(request: Request):
        """Tenants the caller may manage in the Directory: a Global Admin sees
        all, a tenant-admin/viewer only their own. Each carries the OU slug the
        spoke keys on so the UI shows what OU it will touch."""
        sess = _session_user(request)
        all_t = hub.state.tenant_state.get("tenants", {}) or {}
        if access.is_admin(sess):
            ids = list(all_t.keys())
        else:
            ids = [t for t in ((sess or {}).get("user", {}).get("tenants") or []) if t]
        out = []
        for tid in ids:
            cfg = all_t.get(tid, {}) or {}
            out.append({"id": tid, "name": cfg.get("name") or tid,
                        "slug": access.ldap_tenant_slug(hub, tid)})
        return {"tenants": out}

    # ── Users ────────────────────────────────────────────────────────────────
    @app.get("/api/ldap/users")
    async def get_ldap_users(request: Request):
        slug = _directory_slug(request)
        logger.debug("relay LDAP_LIST_USERS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_USERS", slug)

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            auth_mode = "entra" if str(data.get("auth_mode")) == "entra" else "local"
            payload = {"tenant_slug": slug, "uid": uid, "auth_mode": auth_mode,
                       "attrs": data.get("attrs") or {}}
            if auth_mode == "entra":
                upn = str(data.get("upn") or "").strip()
                if not upn:
                    raise HTTPException(status_code=400,
                                        detail="upn is required for an Entra-backed user")
                payload["upn"] = upn
            else:
                # Local: optional password (spoke auto-generates + returns one when blank).
                if data.get("password"):
                    payload["password"] = data.get("password")
            return await _relay("LDAP_CREATE_USER", payload)
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            return await _relay("LDAP_UPDATE_USER",
                                {"tenant_slug": slug, "uid": uid,
                                 "attrs": data.get("attrs") or {}})
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users")
    async def delete_ldap_user(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            result = await _relay("LDAP_DELETE_USER", {"tenant_slug": slug, "uid": uid})
            _invalidate_user_sessions(hub, uid)  # kill any live hub session for it
            return result
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/users/password")
    async def set_ldap_user_password(request: Request):
        """Reset a LOCAL directory user's password (Entra users authenticate
        against Entra — no local password)."""
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            uid = str(data.get("uid") or "").strip()
            password = data.get("password")
            if not uid or not password:
                raise HTTPException(status_code=400, detail="uid and password are required")
            result = await _relay("LDAP_SET_PASSWORD",
                                  {"tenant_slug": slug, "uid": uid, "password": password})
            # The directory credential changed → revoke any live hub session
            # minted for this user so the old password can't keep authorizing.
            _invalidate_user_sessions(hub, uid)
            return result
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Groups ───────────────────────────────────────────────────────────────
    @app.get("/api/ldap/groups")
    async def get_ldap_groups(request: Request):
        slug = _directory_slug(request)
        logger.debug("relay LDAP_LIST_GROUPS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_GROUPS", slug)

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            return await _relay("LDAP_CREATE_GROUP",
                                {"tenant_slug": slug, "cn": cn,
                                 "attrs": data.get("attrs") or {}})
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("create_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/groups")
    async def delete_ldap_group(request: Request):
        # NOTE: LDAP_DELETE_GROUP is not in the minimal shared-contract list but
        # is required by the Directory UI ("create/delete group") and follows the
        # same LDAP_* + tenant_slug convention; needs the matching spoke handler.
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            return await _relay("LDAP_DELETE_GROUP", {"tenant_slug": slug, "cn": cn})
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups/members")
    async def add_ldap_member(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            return await _relay("LDAP_ADD_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid})
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("add_ldap_member failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/groups/members")
    async def remove_ldap_member(request: Request):
        try:
            data = await request.json()
            slug = _directory_slug(request, data)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            return await _relay("LDAP_REMOVE_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid})
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("remove_ldap_member failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── OU provisioning (single tenant; backfill lives in tenants_users) ──────
    @app.post("/api/ldap/provision-ou")
    async def provision_ou(request: Request):
        """(Re)provision the caller's tenant OU on the directory mirror. Uses the
        session-derived slug (cross-tenant guard applies), so a tenant-admin can
        only (re)build their OWN OU."""
        try:
            data = await request.json() if request.method == "POST" else {}
        except Exception:  # noqa: BLE001 — empty body is fine
            data = {}
        slug = _directory_slug(request, data if isinstance(data, dict) else {})
        return await _relay("LDAP_PROVISION_TENANT_OU", {"tenant_slug": slug})
