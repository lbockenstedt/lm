"""Directory (LDAP/Entra) routes — tenant-scoped user/group management.

The directory is one OpenLDAP mirror partitioned per tenant: TENANT == OU (1:1),
``ou=<tenant_slug>,<base_dn>``. A **tenant-admin** manages ONLY their own
tenant's users + groups; a **Global Admin** may pick any tenant. Every relayed
``LDAP_*`` command carries a ``tenant_slug`` that is derived SERVER-SIDE from the
session (:func:`access.resolve_directory_tenant`) — a tenant-admin can NEVER pass
another tenant's slug (the cross-tenant guard, enforced here and matched
case-insensitively so case can't bypass it). User/group LISTS are served from
the hub data cache per tenant OU (warm_cache.cache_read; writes refresh them).

The middleware (api.py) already gates ``/api/ldap/*``: GET requires the ``ldap``
right (or admin); writes require the tenant-admin tier (``_can_edit_shared``).
This module adds the per-tenant slug injection + guard on top.
"""
import asyncio
import time

# Shared Hub helpers: HTTP error type, request, session invalidation, tenant access, logger.
from api import (
    HTTPException, Request, _invalidate_user_sessions, access,
    logger,
)
# Every tenant id (for the background cache feed).
from access import all_tenant_ids
# Hub data-cache job description.
from warm_cache import CacheJob

# The list commands whose results are cached (users and groups).
LDAP_LIST_CMDS = ("LDAP_LIST_USERS", "LDAP_LIST_GROUPS")

# Directory health check: reuse a result this long (s); give the spoke this long.
HEALTH_TTL_S = 15
HEALTH_TIMEOUT_S = 15

# Server URL used when none is set.
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
        """Return the Setup value for ``gkey`` if non-blank, else the install value for ``ikey``."""
        gv = gldap.get(gkey)
        if isinstance(gv, str):
            gv = gv.strip()
        return gv if gv else inst.get(ikey)

    # Pick each of the four fields.
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
    # Keep dict entries with a URL and non-blank strings, in the {server_id, url} shape.
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
    # A list is just tidied; a string is split on commas and newlines.
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
    # The saved values, with the password reported only as set/not set.
    gldap = gldap or {}
    return {
        "base_dn": gldap.get("base_dn") or "",
        "admin_dn": gldap.get("admin_dn") or "",
        "server_url": gldap.get("server_url") or "",
        "server_id": gldap.get("server_id") or "",
        "mirror_peers": normalize_mirror_peers(gldap.get("mirror_peers")),
        "admin_pw_set": bool(gldap.get("admin_pw")),
    }


def canonicalize_user_attrs(attrs):
    """Map the WebUI's friendly user-attribute keys to the canonical LDAP
    attribute names the directory spoke writes.

    The spoke's READ side (``list_users_scoped``) already emits friendly keys
    (``givenName``→``first_name``, ``sn``→``last_name``, ``mail``→``email``), so
    the WebUI speaks ``first_name``/``last_name``/``email`` on the way in too —
    but the spoke's WRITE side (``create_user_scoped``/``update_user_scoped``)
    only reads the canonical LDAP names. Without this translation a created or
    updated user silently loses its name/email (``cn``/``sn`` fall back to the
    uid) and shows up blank in the list, looking as though nothing was saved.

    Translates the friendly keys, derives a ``cn``/``displayName`` from the
    name parts when one isn't supplied, and passes any already-canonical keys
    through untouched (forward-compatible). Pure."""
    # Read the name and email from either friendly or LDAP keys, and drop the friendly ones.
    attrs = attrs or {}
    out = dict(attrs)
    first = str(attrs.get("first_name") or attrs.get("givenName") or "").strip()
    last = str(attrs.get("last_name") or attrs.get("sn") or "").strip()
    email = str(attrs.get("email") or attrs.get("mail") or "").strip()
    for friendly in ("first_name", "last_name", "email"):
        out.pop(friendly, None)
    # Write them under the LDAP names.
    if first:
        out["givenName"] = first
    if last:
        out["sn"] = last
    if email:
        out["mail"] = email
    # Build a full name for cn/displayName if those weren't given.
    full = " ".join(p for p in (first, last) if p)
    if full and not out.get("cn"):
        out["cn"] = full
    if full and not out.get("displayName"):
        out["displayName"] = full
    return out


def register(app, hub, ctx):
    """Register directory (LDAP) routes on the Hub app."""
    # Session lookup from the shared route context.
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
        # Who is asking, and which tenant they asked for (body, else ?tenant=).
        sess = _session_user(request)
        is_adm = access.is_admin(sess)
        acting = (sess or {}).get("user", {}).get("tenants") or []
        requested = ""
        if isinstance(data, dict):
            requested = str(data.get("tenant_id") or data.get("tenant") or "").strip()
        if not requested:
            requested = str(request.query_params.get("tenant") or "").strip()
        # Resolve the tenant; a foreign tenant is refused.
        tid, status, detail = access.resolve_directory_tenant(is_adm, acting, requested)
        if status:
            raise HTTPException(status_code=status, detail=detail)
        # Check the caller's read/write scope for that tenant.
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
        # Send the command and unwrap the reply (spoke errors become a 502).
        result = await hub.request_response(spoke_id, cmd, payload, timeout=20.0)
        data = _ldap_unwrap(result, cmd)
        # Every _relay command is a write: refresh this OU's cached lists now
        # so the page shows the change (readers briefly wait for it).
        slug = (payload or {}).get("tenant_slug")
        if slug and hasattr(hub, "cache_refresh"):
            for list_cmd in LDAP_LIST_CMDS:
                ns = list_cmd.lower()
                keys = tuple(k for k in (hub.warm_cache.get(ns) or {})
                             if k.endswith(f"|{slug}"))
                if keys:
                    hub.cache_refresh(ns, keys, exact=True)
        return data

    def _ldap_unwrap(result, cmd):
        """Spoke reply → the spoke's own result, raising 502 on an ERROR.

        ``request_response`` returns the whole reply frame
        (``{"header", "payload": {"data": <spoke result>}}``), so the spoke's
        ``status`` is inside ``payload.data``. Checking only the top level
        missed it: lists came back as the raw frame (the WebUI showed "no
        users") and a failed write showed a false "created" toast.

        A spoke result of ``{"status", "data": [...]}`` (lists) returns the
        inner ``data``; one without ``data`` (create → ``dn``/``password``)
        returns the result itself."""
        # Unwrap the reply frame; a spoke ERROR is a 502.
        body = access.unwrap_spoke(result)
        if not isinstance(body, dict):
            return body
        if str(body.get("status", "")).upper() == "ERROR":
            raise HTTPException(status_code=502,
                                detail=body.get("message") or f"{cmd} failed on the LDAP server")
        data = body.get("data")
        # `is not None`: an empty-but-real payload ({}, []) is data.
        return data if data is not None else body

    def ldap_cache_job(cmd: str, tid: str, slug: str) -> CacheJob:
        """Hub-cache job for a directory LIST (users or groups) of one tenant
        OU. Namespace ``ldap_list_users`` / ``ldap_list_groups``, key =
        ``<tenant id>|<OU slug>``. The directory spoke is resolved
        tenant-aware at FETCH time."""
        async def fetch():
            """Fetch the list from this tenant's directory spoke (503 if none)."""
            spoke_id = hub.get_directory_spoke_for_tenant(tid)
            if not spoke_id:
                raise HTTPException(status_code=503, detail="No spoke connected")
            result = await hub.request_response(spoke_id, cmd, {"tenant_slug": slug},
                                                timeout=20.0)
            # Never cache an ERROR as data (a SERVER_DOWN would hide the
            # outage behind junk) — _ldap_unwrap raises so last-known data is kept.
            return _ldap_unwrap(result, cmd)
        # Key = "<tenant id>|<OU slug>": the fetch goes to THIS tenant's
        # directory spoke, so two tenants that happen to map to the same OU
        # slug must never share an entry.
        return CacheJob(cmd.lower(), f"{tid or ''}|{slug}", fetch,
                        (tid,) if tid else None, lane="ldap")

    def ldap_cache_feed(_hub):
        """Feed: users + groups for every tenant that has a directory spoke."""
        # Each tenant with a directory spoke and an OU: its users and groups lists.
        for tid in all_tenant_ids(hub):
            if hub.get_directory_spoke_for_tenant(tid):
                slug = access.ldap_tenant_slug(hub, tid)
                if slug:
                    for cmd in LDAP_LIST_CMDS:
                        yield ldap_cache_job(cmd, tid, slug)

    # Register the feed with the hub data cache (if this hub has one).
    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("ldap", ldap_cache_feed)

    async def _relay_list(cmd: str, tid: str, slug: str):
        """Directory LIST served from the hub data cache (last-known data on
        spoke-down / error, so the Directory page renders instead of 503-ing)."""
        # Read through the cache and add the cache info.
        job = ldap_cache_job(cmd, tid, slug)
        data = await hub.cache_read(job.ns, job.key, job.fetch, tenants=job.tenants,
                                    lane=job.lane)
        return hub.cache_annotate(data, job.ns, job.key)

    def _directory_spoke(tid: str) -> str:
        """Resolve the tenant-aware directory spoke or 503. Mirrors the
        ``get_spoke_or_503`` shape the old single-instance relay had, but routes
        through ``hub.get_directory_spoke_for_tenant(tid)`` so a tenant's OU op
        never lands on another tenant's spoke."""
        # Find the spoke; none is a 503.
        sid = hub.get_directory_spoke_for_tenant(tid)
        if not sid:
            raise HTTPException(status_code=503, detail="No spoke connected")
        return sid

    # ── Server + Entra health (Directory page status icons) ────────────────
    # Every open Directory page polls this every 10s. One check is shared by all
    # pollers and reused for HEALTH_TTL_S, so pages never pile LIST_OUS calls onto
    # the directory spoke (it runs only a few commands at a time, and a backlog
    # there delays the user/group lists).
    health = {"result": None, "at": 0.0, "task": None}

    async def _ldap_server_health():
        """Is slapd bindable from the directory spoke (a fresh LIST_OUS)?"""
        spoke_id = hub.get_spoke_by_type("directory")
        if not spoke_id:
            return {"status": "down", "detail": "no directory spoke connected"}
        try:
            result = await hub.request_response(spoke_id, "LIST_OUS", {},
                                                timeout=HEALTH_TIMEOUT_S)
            result = access.unwrap_spoke(result)
            if isinstance(result, dict) and str(result.get("status", "")).upper() == "ERROR":
                return {"status": "down",
                        "detail": (result.get("message") or "LDAP command failed")[:160]}
            return {"status": "healthy", "detail": "OpenLDAP online"}
        except Exception as e:  # noqa: BLE001 — spoke unreachable / timeout
            return {"status": "down", "detail": (str(e) or type(e).__name__)[:160]}

    async def _entra_health():
        """Are the hub's Entra (OIDC) app creds live-valid?"""
        from security.oidc import OidcError, fetch_app_graph_token, get_oidc_config
        try:
            cfg = get_oidc_config(hub)
            if not cfg.ready:
                return {"status": "degraded", "detail": "not configured"}
            # Reuse a token up to 5 min old: still proves the cert and app
            # registration work, without minting one every poll.
            await fetch_app_graph_token(cfg, max_age=300)
            return {"status": "healthy", "detail": "Entra online"}
        except OidcError as e:
            return {"status": "down", "detail": str(e)[:160]}
        except Exception as e:  # noqa: BLE001 — config / network / crypto
            return {"status": "down", "detail": str(e)[:160]}

    async def _check_health():
        """Run both checks together and remember the result."""
        ldap, entra = await asyncio.gather(_ldap_server_health(), _entra_health())
        health["result"] = {"ldap": ldap, "entra": entra, "checked_at": time.time()}
        health["at"] = time.time()
        return health["result"]

    @app.get("/api/ldap/health")
    async def ldap_health(request: Request):
        """Two status dots for the Directory page header: is the LDAP server
        (slapd) bindable from the directory spoke, and are the hub's Entra
        (OIDC) app creds live-valid. Returns ``{"ldap": {...}, "entra": {...}}``
        with each ``status`` ∈ ``healthy`` / ``degraded`` / ``down``.
        No spoke connected → ``down`` (not a 503) so the icon still renders;
        Entra not configured → ``degraded``."""
        if health["result"] and time.time() - health["at"] < HEALTH_TTL_S:
            return health["result"]
        if health["task"] is None or health["task"].done():
            health["task"] = asyncio.ensure_future(_check_health())
        return await asyncio.shield(health["task"])

    # ── Tenant picker (feeds the WebUI Directory tenant dropdown) ─────────────
    # List the tenants the caller may manage.
    @app.get("/api/ldap/tenants")
    async def ldap_tenants(request: Request):
        """Tenants the caller may manage in the Directory: a Global Admin sees
        all, a tenant-admin/viewer only their own. Each carries the OU slug the
        spoke keys on so the UI shows what OU it will touch."""
        # Admins get every tenant; others only their own.
        sess = _session_user(request)
        all_t = hub.state.tenant_state.get("tenants", {}) or {}
        if access.is_admin(sess):
            ids = list(all_t.keys())
        else:
            ids = [t for t in ((sess or {}).get("user", {}).get("tenants") or []) if t]
        # Return each with its name and OU slug.
        out = []
        for tid in ids:
            cfg = all_t.get(tid, {}) or {}
            out.append({"id": tid, "name": cfg.get("name") or tid,
                        "slug": access.ldap_tenant_slug(hub, tid)})
        return {"tenants": out}

    # ── Users ────────────────────────────────────────────────────────────────
    # List users.
    @app.get("/api/ldap/users")
    async def get_ldap_users(request: Request):
        """List the users in the caller's tenant OU (from the cache)."""
        # Resolve the tenant and read the cached list.
        tid, slug, _ = _directory_resolve(request)
        logger.debug("relay LDAP_LIST_USERS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_USERS", tid, slug)

    # Create a user.
    @app.post("/api/ldap/users")
    async def create_ldap_user(request: Request):
        """Create a user (local or Entra-backed) in the tenant OU."""
        # Read the body and resolve the tenant (a write); uid is required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            # Build the request; Entra users need a UPN.
            auth_mode = "entra" if str(data.get("auth_mode")) == "entra" else "local"
            payload = {"tenant_slug": slug, "uid": uid, "auth_mode": auth_mode,
                       "attrs": canonicalize_user_attrs(data.get("attrs"))}
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
            # Send it to the directory spoke.
            return await _relay("LDAP_CREATE_USER", payload, _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("create_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Update a user.
    @app.put("/api/ldap/users")
    async def update_ldap_user(request: Request):
        """Update a user's attributes."""
        # Read the body and resolve the tenant (a write); uid is required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            # Send the update to the directory spoke.
            return await _relay("LDAP_UPDATE_USER",
                                {"tenant_slug": slug, "uid": uid,
                                 "attrs": canonicalize_user_attrs(data.get("attrs"))},
                                _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("update_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Delete a user.
    @app.delete("/api/ldap/users")
    async def delete_ldap_user(request: Request):
        """Delete a user and end their hub sessions."""
        # Read the body and resolve the tenant (a write); uid is required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            if not uid:
                raise HTTPException(status_code=400, detail="uid is required")
            # Delete it on the directory spoke.
            result = await _relay("LDAP_DELETE_USER", {"tenant_slug": slug, "uid": uid},
                                  _directory_spoke(tid))
            _invalidate_user_sessions(hub, uid)  # kill any live hub session for it
            return result
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_ldap_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Reset a user's password.
    @app.post("/api/ldap/users/password")
    async def set_ldap_user_password(request: Request):
        """Reset a LOCAL directory user's password (Entra users authenticate
        against Entra — no local password)."""
        # Read the body and resolve the tenant (a write); uid and password are required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            uid = str(data.get("uid") or "").strip()
            password = data.get("password")
            if not uid or not password:
                raise HTTPException(status_code=400, detail="uid and password are required")
            # Set it on the directory spoke.
            result = await _relay("LDAP_SET_PASSWORD",
                                  {"tenant_slug": slug, "uid": uid, "password": password},
                                  _directory_spoke(tid))
            # The directory credential changed → revoke any live hub session
            # minted for this user so the old password can't keep authorizing.
            _invalidate_user_sessions(hub, uid)
            return result
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("set_ldap_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Groups ───────────────────────────────────────────────────────────────
    # List groups.
    @app.get("/api/ldap/groups")
    async def get_ldap_groups(request: Request):
        """List the groups in the caller's tenant OU (from the cache)."""
        # Resolve the tenant and read the cached list.
        tid, slug, _ = _directory_resolve(request)
        logger.debug("relay LDAP_LIST_GROUPS tenant=%s", slug)
        return await _relay_list("LDAP_LIST_GROUPS", tid, slug)

    # Create a group.
    @app.post("/api/ldap/groups")
    async def create_ldap_group(request: Request):
        """Create a group in the tenant OU."""
        # Read the body and resolve the tenant (a write); a name is required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            # Send it to the directory spoke.
            return await _relay("LDAP_CREATE_GROUP",
                                {"tenant_slug": slug, "cn": cn,
                                 "attrs": data.get("attrs") or {}},
                                _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("create_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Delete a group.
    @app.delete("/api/ldap/groups")
    async def delete_ldap_group(request: Request):
        """Delete a group from the tenant OU."""
        # NOTE: LDAP_DELETE_GROUP is not in the minimal shared-contract list but
        # is required by the Directory UI ("create/delete group") and follows the
        # same LDAP_* + tenant_slug convention; needs the matching spoke handler.
        try:
            # Read the body and resolve the tenant (a write); a name is required.
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("name") or "").strip()
            if not cn:
                raise HTTPException(status_code=400, detail="cn is required")
            # Delete it on the directory spoke.
            return await _relay("LDAP_DELETE_GROUP", {"tenant_slug": slug, "cn": cn},
                                _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("delete_ldap_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Add a user to a group.
    @app.post("/api/ldap/groups/members")
    async def add_ldap_member(request: Request):
        """Add a user to a group."""
        # Read the body and resolve the tenant (a write); group and user are required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            # Send it to the directory spoke.
            return await _relay("LDAP_ADD_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid},
                                _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("add_ldap_member failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Remove a user from a group.
    @app.delete("/api/ldap/groups/members")
    async def remove_ldap_member(request: Request):
        """Remove a user from a group."""
        # Read the body and resolve the tenant (a write); group and user are required.
        try:
            data = await request.json()
            tid, slug, _ = _directory_resolve(request, data, write=True)
            cn = str(data.get("cn") or data.get("group") or "").strip()
            uid = str(data.get("uid") or data.get("member") or "").strip()
            if not cn or not uid:
                raise HTTPException(status_code=400, detail="cn and uid are required")
            # Send it to the directory spoke.
            return await _relay("LDAP_REMOVE_MEMBER",
                                {"tenant_slug": slug, "cn": cn, "uid": uid},
                                _directory_spoke(tid))
        # Pass HTTP errors through; anything else is logged and a 500.
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("remove_ldap_member failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── OU provisioning (single tenant; backfill lives in tenants_users) ──────
    # (Re)build the tenant's OU.
    @app.post("/api/ldap/provision-ou")
    async def provision_ou(request: Request):
        """(Re)provision the caller's tenant OU on the directory mirror. Uses the
        session-derived slug (cross-tenant guard applies), so a tenant-admin can
        only (re)build their OWN OU."""
        # Read the body (an empty one is fine).
        try:
            data = await request.json() if request.method == "POST" else {}
        except Exception:  # noqa: BLE001 — empty body is fine
            data = {}
        # Resolve the tenant (a write) and ask the spoke to build its OU.
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
    # Read the directory server settings.
    @app.get("/setup/ldap-config")
    async def get_ldap_config_route():
        """Return the settings (password masked) and how many directory spokes are connected."""
        # Read the saved settings and count the directory spokes.
        gldap = hub.state.system_state.get("global_config", {}).get("ldap", {}) or {}
        try:
            connected = len(hub.get_all_spokes_by_type("directory") or [])
        except Exception:  # noqa: BLE001
            connected = 0
        return {"config": mask_ldap_config(gldap), "spokes_connected": connected}

    # Save the directory server settings.
    @app.post("/setup/ldap-config")
    async def update_ldap_config_route(request: Request):
        """Save the directory server settings and push them to the spokes."""
        # Read the JSON body (defaulting to {}).
        try:
            data = await request.json()
        except Exception:  # noqa: BLE001
            data = {}
        # Base DN and admin DN are required.
        config = (data or {}).get("config", {}) or {}
        base_dn = str(config.get("base_dn") or "").strip()
        admin_dn = str(config.get("admin_dn") or "").strip()
        if not base_dn:
            raise HTTPException(status_code=400, detail="Base DN is required")
        if not admin_dn:
            raise HTTPException(status_code=400, detail="Admin DN is required")
        # Build the clean settings (URL defaulted, peers parsed).
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
        # Save them.
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

    # Re-push the saved settings to the spokes.
    @app.post("/setup/ldap-config/push")
    async def push_ldap_config_route():
        """Re-push the stored LDAP config to every connected directory spoke
        WITHOUT changing values (the "Push to spokes now" button)."""
        # Count the directory spokes, then push (a failure is a 502).
        try:
            spokes = hub.get_all_spokes_by_type("directory") or []
        except Exception:  # noqa: BLE001
            spokes = []
        try:
            await hub.push_ldap_config_all()
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"push failed: {e}")
        return {"status": "ok", "pushed_to_spokes": len(spokes)}

    # ── Setup → Directory: one-form setup (domain + admin account) ───────────
    # The hub discovers the ldap-server nodes itself, resets their admin
    # password, wires replication between them and points the Directory spoke
    # at all of them (ldap_cluster.py). /setup/* is Global-Admin only (api.py).
    # Read the one-form directory setup.
    @app.get("/setup/ldap-directory")
    async def get_ldap_directory_route():
        """Return the saved setup, where its password lives in the vault, and the found servers."""
        # Local imports: the credential vault and the cluster setup logic.
        import cred_vault as _cv
        import ldap_cluster
        # Read the saved setup, find the servers, and count the directory spokes.
        stored = ldap_cluster.stored_setup(hub)
        servers = await ldap_cluster.discover(hub)
        try:
            connected = len(hub.get_all_spokes_by_type("directory") or [])
        except Exception:  # noqa: BLE001
            connected = 0
        # Return it all (password reported only as set/not set).
        return {
            "domain": stored.get("domain", ""),
            "admin_user": stored.get("admin_user", ""),
            "base_dn": stored.get("base_dn", ""),
            "admin_dn": stored.get("admin_dn", ""),
            "server_url": stored.get("server_url", ""),
            "admin_pw_set": bool(stored.get("admin_pw")),
            "vault_secret": f"{_cv.ADMIN_BUCKET}/{ldap_cluster.VAULT_SECRET}",
            "vault_psk_required": _cv.bucket_has_psk(hub, _cv.ADMIN_BUCKET),
            "servers": servers,
            "spokes_connected": connected,
        }

    # Apply the one-form directory setup.
    @app.post("/setup/ldap-directory")
    async def apply_ldap_directory_route(request: Request):
        """Set up the directory: domain, admin account, replication and the spoke."""
        # Cluster setup logic.
        import ldap_cluster
        # Read the JSON body (defaulting to {}).
        try:
            data = await request.json()
        except Exception:  # noqa: BLE001
            data = {}
        data = data or {}
        # Who is doing it (for the log).
        sess = _session_user(request) or {}
        actor = (sess.get("user", {}) or {}).get("username", "?")
        # Run the setup; a setup error is a 400.
        try:
            return {"status": "ok", **await ldap_cluster.apply_setup(
                hub, str(data.get("domain") or ""), str(data.get("admin_user") or ""),
                admin_pw=str(data.get("admin_pw") or ""), psk=str(data.get("psk") or ""),
                actor=actor)}
        except ldap_cluster.LdapSetupError as e:
            raise HTTPException(status_code=400, detail=str(e))
