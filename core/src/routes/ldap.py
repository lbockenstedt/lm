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
    logger,
)

_DEFAULT_LDAP_SERVER_URL = "ldap://localhost:389"


# ── Setup → Directory (LDAP) SERVER connection config — pure helpers ──────────
# A Global Admin sets the directory SERVER connection (base DN + admin account +
# server URL + mirror peers) from the WebUI instead of relying on install flags /
# defaults. Stored under ``global_config["ldap"]``; ``_ldap_config_for_spoke``
# (main.py) PREFERS these over the legacy ``ldap_instances`` entry (and the
# dc=example,dc=org install default) via :func:`merge_ldap_connection`, and Save
# re-pushes through ``hub.push_ldap_config_all()`` so the mirror gets it at once.
# NOTE: TENANT == OU is unchanged — this is the SERVER config, not per-tenant.

def merge_ldap_connection(gldap, inst):
    """Precedence merge for the four LDAP_* connection fields the directory spoke
    consumes. A non-empty Setup value (``global_config["ldap"]`` = ``gldap``) WINS
    over the install-time ``ldap_instances`` entry (``inst``), which wins over
    nothing. Returns the UPDATE_CONFIG field dict (``LDAP_SERVER_URL`` /
    ``LDAP_BASE_DN`` / ``LDAP_ADMIN_DN`` / ``LDAP_ADMIN_PW``). Pure — unit-tested
    for the precedence contract."""
    gldap = gldap or {}
    inst = inst or {}

    def pick(gkey, ikey):
        gv = gldap.get(gkey)
        if isinstance(gv, str):
            gv = gv.strip()
        return gv if gv else inst.get(ikey)

    return {
        "LDAP_SERVER_URL": pick("server_url", "server_url"),
        "LDAP_BASE_DN": pick("base_dn", "base_dn"),
        "LDAP_ADMIN_DN": pick("admin_dn", "admin_dn"),
        "LDAP_ADMIN_PW": pick("admin_pw", "admin_pw"),
    }


def normalize_mirror_peers(raw):
    """Coerce a stored/submitted mirror-peer list into the spoke's contract shape
    — a list of ``{"server_id", "url"}`` dicts. Accepts a list of URL strings OR
    a list of dicts; blanks are dropped. Pure."""
    peers = []
    for p in raw or []:
        if isinstance(p, dict):
            url = str(p.get("url") or "").strip()
            if url:
                peers.append({"server_id": str(p.get("server_id") or ""), "url": url})
        elif isinstance(p, str) and p.strip():
            peers.append({"server_id": "", "url": p.strip()})
    return peers


def parse_mirror_peers_input(raw):
    """Parse the WebUI Mirror-Peers field — a comma/newline separated list of peer
    URLs — into a list of URL strings. A list is passed through (stripped); a
    string is split on commas/newlines. Pure."""
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    out = []
    for chunk in str(raw or "").replace(",", "\n").splitlines():
        s = chunk.strip()
        if s:
            out.append(s)
    return out


def mask_ldap_config(gldap):
    """Shape the stored ``global_config["ldap"]`` for the GET response — never
    echo the admin password (report ``admin_pw_set`` bool instead), mirroring how
    ``/setup/oidc-config`` withholds secrets. Pure."""
    gldap = gldap or {}
    return {
        "base_dn": gldap.get("base_dn") or "",
        "admin_dn": gldap.get("admin_dn") or "",
        "server_url": gldap.get("server_url") or "",
        "server_id": gldap.get("server_id") or "",
        "mirror_peers": normalize_mirror_peers(gldap.get("mirror_peers")),
        "admin_pw_set": bool(gldap.get("admin_pw")),
    }


def register(app, hub, ctx):
    """Register directory (LDAP) routes on the Hub app."""
    _session_user = ctx._session_user

    def _directory_resolve(request: Request, data=None, write: bool = False):
        """Resolve the tenant this request acts on, enforce the cross-tenant
        guard, AND classify the read/write scope (defense-in-depth, mirroring
        firewall/nw — see ``_authz_firewall`` / ``_authz_nw_device``). Returns
        ``(tenant_id, ou_slug, scope)``.

        ``resolve_directory_tenant`` picks the tenant (an admin may name any; a
        non-admin only their own — case-insensitively) and 403s a foreign
        tenant. ``read_scope``/``write_scope`` then re-check the TIER (a write
        needs edit access) and give the single canonical deny point the other
        modules have. For an admin both return ``"full"`` for any tenant, so the
        all-OU admin view is preserved. ``scope`` is returned for callers that
        need to narrow shared-tenant writes (none today — own-tenant only — but
        the contract matches the other modules)."""
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
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(
                status_code=403,
                detail="You do not have access to this tenant's directory")
        return tid, access.ldap_tenant_slug(hub, tid), scope

    async def _relay(cmd: str, payload: dict, spoke_id: str):
        """Relay an LDAP_* command to the directory spoke and unwrap its data.
        ``spoke_id`` is resolved tenant-aware by the caller via
        ``hub.get_directory_spoke_for_tenant(tid)`` — never the first connected
        directory spoke blindly (that could land a tenant's OU op on another
        tenant's spoke in a multi-spoke deploy).

        SURFACES spoke-side failures: if the spoke returns an ERROR envelope
        (e.g. slapd unreachable → SERVER_DOWN) this raises 502 with the message
        instead of returning the envelope with a 200 — otherwise the WebUI shows
        a false 'created' toast for an op that actually failed."""
        result = await hub.request_response(spoke_id, cmd, payload, timeout=20.0)
        if isinstance(result, dict) and str(result.get("status", "")).upper() == "ERROR":
            raise HTTPException(status_code=502,
                                detail=result.get("message") or f"{cmd} failed on the LDAP server")
        return result.get("data", result) if isinstance(result, dict) else result

    async def _relay_list(cmd: str, slug: str, spoke_id: str):
        """Warm-cached LIST read (per tenant slug): serve last-known (stale) on
        spoke-down / error so the Directory page renders instead of 503-ing.
        ``spoke_id`` is resolved tenant-aware by the caller."""
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

    def _directory_spoke(tid: str) -> str:
        """Resolve the tenant-aware directory spoke or 503. Mirrors the
        ``get_spoke_or_503`` shape the old single-instance relay had, but routes
        through ``hub.get_directory_spoke_for_tenant(tid)`` so a tenant's OU op
        never lands on another tenant's spoke."""
        sid = hub.get_directory_spoke_for_tenant(tid)
        if not sid:
            raise HTTPException(status_code=503, detail="LDAP spoke not connected")
        return sid

    # ── Server + Entra health (Directory page status icons) ────────────────
    @app.get("/api/ldap/health")
    async def ldap_health(request: Request):
        """Two status dots for the Directory page header: is the LDAP server
        (slapd) bindable from the directory spoke, and are the hub's Entra
        (OIDC) app creds live-valid. Returns ``{"ldap": {...}, "entra": {...}}``
        with each ``status`` ∈ ``healthy`` / ``degraded`` / ``down``.

        LDAP: relays ``LIST_OUS`` (binds + a one-level OU search) to the
        connected directory spoke — a FRESH bind check each poll, not stale
        heartbeat state. No spoke connected → ``down`` (not a 503) so the icon
        still renders and tells the admin the role isn't loaded.
        Entra: a real client-credentials token mint via the cert
        ``client_assertion`` (``fetch_app_graph_token``); not-configured →
        ``degraded`` (yellow), cred/network failure → ``down`` (red)."""
        import time
        from security.oidc import (OidcError, fetch_app_graph_token,
                                   get_oidc_config)

        # ── LDAP server ──
        ldap = {"status": "down", "detail": "no directory spoke connected"}
        spoke_id = hub.get_spoke_by_type("directory")
        if spoke_id:
            try:
                result = await hub.request_response(spoke_id, "LIST_OUS",
                                                    {}, timeout=5.0)
                if isinstance(result, dict) and \
                        str(result.get("status", "")).upper() == "ERROR":
                    ldap = {"status": "down",
                            "detail": (result.get("message")
                                       or "LDAP command failed")[:160]}
                else:
                    ldap = {"status": "healthy", "detail": "OpenLDAP online"}
            except Exception as e:  # noqa: BLE001 — spoke unreachable / timeout
                ldap = {"status": "down", "detail": str(e)[:160]}

        # ── Entra ID ──
        entra = {"status": "down", "detail": "OIDC config error"}
        try:
            cfg = get_oidc_config(hub)
            if not cfg.ready():
                entra = {"status": "degraded", "detail": "not configured"}
            else:
                try:
                    await fetch_app_graph_token(cfg)
                    entra = {"status": "healthy", "detail": "Entra online"}
                except OidcError as e:
                    entra = {"status": "down", "detail": str(e)[:160]}
                except Exception as e:  # noqa: BLE001 — network / crypto
                    entra = {"status": "down", "detail": str(e)[:160]}
        except Exception as e:  # noqa: BLE001 — OIDC config unreadable
            entra = {"status": "down", "detail": f"OIDC config error: {e}"[:160]}

        return {"ldap": ldap, "entra": entra, "checked_at": time.time()}

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
        tid, slug, _ = _directory_resolve(request)
        logger.debug("relay LDAP_LIST_USERS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_USERS", slug, _directory_spoke(tid))

    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
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
            return await _relay("LDAP_CREATE_USER", payload, _directory_spoke(tid))
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            return await _relay("LDAP_UPDATE_USER",
                                {"tenant_slug": slug, "uid": uid,
                                 "attrs": data.get("attrs") or {}},
                                _directory_spoke(tid))
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/users")
    async def delete_ldap_user(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            result = await _relay("LDAP_DELETE_USER", {"tenant_slug": slug, "uid": uid},
                                  _directory_spoke(tid))
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
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            password = data.get("password")
            if not uid or not password:
                raise HTTPException(status_code=400, detail="uid and password are required")
            result = await _relay("LDAP_SET_PASSWORD",
                                  {"tenant_slug": slug, "uid": uid, "password": password},
                                  _directory_spoke(tid))
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
        tid, slug, _ = _directory_resolve(request)
        logger.debug("relay LDAP_LIST_GROUPS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_GROUPS", slug, _directory_spoke(tid))

    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            return await _relay("LDAP_CREATE_GROUP",
                                {"tenant_slug": slug, "cn": cn,
                                 "attrs": data.get("attrs") or {}},
                                _directory_spoke(tid))
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
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            return await _relay("LDAP_DELETE_GROUP", {"tenant_slug": slug, "cn": cn},
                                _directory_spoke(tid))
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/ldap/groups/members")
    async def add_ldap_member(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            return await _relay("LDAP_ADD_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid},
                                _directory_spoke(tid))
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("add_ldap_member failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/ldap/groups/members")
    async def remove_ldap_member(request: Request):
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            return await _relay("LDAP_REMOVE_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid},
                                _directory_spoke(tid))
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
        tid, slug, _ = _directory_resolve(request, data if isinstance(data, dict) else {},
                                          write=True)
        return await _relay("LDAP_PROVISION_TENANT_OU", {"tenant_slug": slug},
                            _directory_spoke(tid))

    # ── Admin: Directory (LDAP) SERVER connection config (mirror oidc route) ──
    # ``/setup/*`` is Global-Admin-only via the access-control middleware, so no
    # extra gate is needed here. GET masks the admin password (reports whether
    # one is set, like ``/setup/oidc-config`` does for secrets). POST validates
    # (base DN + admin DN non-empty), stores under ``global_config["ldap"]``,
    # persists, then re-pushes to every connected directory spoke so the values
    # reach the mirror immediately (not only on the next reconnect).
    @app.get("/setup/ldap-config")
    async def get_ldap_config_route():
        gldap = hub.state.system_state.get("global_config", {}).get("ldap", {}) or {}
        try:
            connected = len(hub.get_all_spokes_by_type("directory") or [])
        except Exception:  # noqa: BLE001
            connected = 0
        return {"config": mask_ldap_config(gldap), "spokes_connected": connected}

    @app.post("/setup/ldap-config")
    async def update_ldap_config_route(request: Request):
        try:
            data = await request.json()
        except Exception:  # noqa: BLE001
            data = {}
        config = (data or {}).get("config", {}) or {}
        base_dn = str(config.get("base_dn") or "").strip()
        admin_dn = str(config.get("admin_dn") or "").strip()
        if not base_dn:
            raise HTTPException(status_code=400, detail="Base DN is required")
        if not admin_dn:
            raise HTTPException(status_code=400, detail="Admin DN is required")
        gc = hub.state.system_state.setdefault("global_config", {})
        prev = dict(gc.get("ldap", {}) or {})
        clean = {
            "base_dn": base_dn,
            "admin_dn": admin_dn,
            "server_url": (str(config.get("server_url") or "").strip()
                           or _DEFAULT_LDAP_SERVER_URL),
            "server_id": str(config.get("server_id") or "").strip(),
            "mirror_peers": normalize_mirror_peers(
                parse_mirror_peers_input(config.get("mirror_peers"))),
        }
        # Admin password: a submitted value REPLACES; blank KEEPS the stored one
        # (mirrors the netbox-sso "leave blank to keep" secret handling). The
        # state file is Fernet-encrypted at rest, so the plaintext pw lives only
        # inside the encrypted blob — same as ldap_instances / cloud_nac secrets.
        submitted_pw = config.get("admin_pw")
        if submitted_pw:
            clean["admin_pw"] = str(submitted_pw)
        elif prev.get("admin_pw"):
            clean["admin_pw"] = prev["admin_pw"]
        gc["ldap"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Re-push the full LDAP + Entra config to every connected directory spoke
        # so the Setup values reach the mirror now (not on the next reconnect).
        pushed = 0
        try:
            pushed = len(hub.get_all_spokes_by_type("directory") or [])
            await hub.push_ldap_config_all()
        except Exception:  # noqa: BLE001 — best-effort; reconnect re-pushes
            logger.debug("update_ldap_config: spoke re-push skipped", exc_info=True)
        return {"status": "ok", "pushed_to_spokes": pushed,
                "admin_pw_set": bool(clean.get("admin_pw"))}

    @app.post("/setup/ldap-config/push")
    async def push_ldap_config_route():
        """Re-push the stored LDAP config to every connected directory spoke
        WITHOUT changing values (the "Push to spokes now" button)."""
        try:
            spokes = hub.get_all_spokes_by_type("directory") or []
        except Exception:  # noqa: BLE001
            spokes = []
        try:
            await hub.push_ldap_config_all()
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"push failed: {e}")
        return {"status": "ok", "pushed_to_spokes": len(spokes)}
