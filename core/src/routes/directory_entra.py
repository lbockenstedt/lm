"""Directory → Entra routes: a tenant's Entra accounts and groups.

``/api/ldap/entra*`` so the Directory middleware gate in api.py applies (reads
need the ``ldap`` right or admin, writes the tenant-admin tier). Every route
resolves the tenant with :func:`routes.ldap.directory_resolve` (a tenant admin
only ever acts on their own tenant), then touches only:

  * groups registered on that tenant (``directory_entra_groups``), and
  * accounts that are DIRECT members of that tenant's base group
    (``LM-<tenant>-Users``; never the users of a group nested in it),

and only Entra object ids (GUIDs) ever reach a Graph path.

The model and the Graph calls live in :mod:`directory_entra`. The account and
group list is served from the hub cache (refreshed in the background, and at
once after a write).
"""
# Postpone evaluation of type hints.
from __future__ import annotations

# One lock per tenant around group-registry changes.
import asyncio

# Shared Hub helpers: HTTP error type, request object and the hub logger.
from api import HTTPException, Request, logger
# Every tenant id (for the background cache feed).
from access import all_tenant_ids
# Hub data-cache job description.
from warm_cache import CacheJob
# The shared Directory tenant resolver (tenant guard + read/write scope).
from routes.ldap import directory_resolve
# Graph transport errors (timeouts, refused connections).
import httpx

# Entra OIDC app config (the Graph calls use its app cert) and token errors.
from security.oidc import OidcError, get_oidc_config
# Graph error type.
from cloud_nac import CloudNacError
# Entra accounts and groups for the Directory.
import directory_entra as de

# Cache namespace for a tenant's Entra accounts and groups (key = tenant id).
CACHE_NS = "ldap_entra"
# Background refresh floor for that list (Graph is slow-moving; fleet rule 4.8).
REFRESH_S = 300


def register(app, hub, ctx):
    """Register the Directory → Entra routes on the Hub app."""
    _session_user = ctx._session_user
    # Per-tenant locks so two first writes never create two base groups.
    locks: dict = {}

    def _resolve(request: Request, data=None, write: bool = False) -> str:
        """The tenant id this request acts on (guarded and scope-checked)."""
        tid, _slug, _scope = directory_resolve(hub, _session_user(request), request,
                                               data, write)
        return tid

    def _tenant(tid: str) -> dict:
        """The tenant record (the live one, so changes persist), or 404."""
        tenant = hub.state.get_tenant(tid)
        if not isinstance(tenant, dict):
            raise HTTPException(status_code=404, detail="Unknown tenant")
        return tenant

    def _cfg():
        """The Entra app config, or 503 when Entra is not set up."""
        cfg = get_oidc_config(hub)
        if not cfg.ready:
            raise HTTPException(status_code=503, detail="Entra is not configured "
                                "(Settings → Single sign-on)")
        return cfg

    async def _graph(coro):
        """Await a Graph call, turning its errors into HTTP errors: a Graph
        refusal, an app-token failure or an unreachable Graph is a 502, never
        an unhandled 500 that would skip a caller's rollback."""
        try:
            return await coro
        except de.EntraConflict as e:
            raise HTTPException(status_code=409, detail=str(e))
        except (CloudNacError, OidcError) as e:
            raise HTTPException(status_code=502, detail=str(e))
        except httpx.HTTPError as e:
            raise HTTPException(status_code=502, detail=f"Entra unreachable: {e}")

    def _oid_arg(value, field: str) -> str:
        """An Entra object id from the request, or 400. Only a GUID may go
        into a Graph path (a crafted "../users/x#" would hit another object)."""
        try:
            return de.object_id_arg(value)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"{field} must be an Entra object id")

    def _group(tenant: dict, group_id, *, tenant_group: bool = False) -> dict:
        """A group registered on the tenant (404 if not). ``tenant_group``
        also refuses the base group, whose membership is the tenant's account
        list and changes only by creating or deleting an account."""
        group_id = _oid_arg(group_id, "group_id")
        g = next((g for g in de.registered_groups(tenant) if g["id"] == group_id), None)
        if not g:
            raise HTTPException(status_code=404, detail="Not one of this tenant's Entra groups")
        if tenant_group and g.get("base"):
            raise HTTPException(status_code=400, detail="The base group changes only "
                                "by creating or deleting an account")
        return g

    async def _require_account(cfg, tenant: dict, user_id) -> str:
        """The user id, if the user is one of the tenant's Entra accounts
        (a direct member of its base group); 404 otherwise."""
        user_id = _oid_arg(user_id, "user_id")
        base = de.base_group(tenant)
        if not base or not await _graph(de.is_member(cfg, base["id"], user_id)):
            raise HTTPException(status_code=404, detail="Not one of this tenant's Entra accounts")
        return user_id

    async def _ensure_base(cfg, tid: str, tenant: dict) -> dict:
        """The tenant's base group, created and registered on first use."""
        base = de.base_group(tenant)
        if base:
            return base
        name = de.display_name(tenant.get("name") or tid, de.BASE_NAME)
        base = {**await _graph(de.create_group(cfg, name)), "base": True}
        await _register(cfg, tenant, base)
        logger.info("Directory: created Entra base group %s for tenant %s", name, tid)
        return base

    async def _register(cfg, tenant: dict, group: dict) -> None:
        """Record a just-created Entra group on the tenant and save at once
        (an unrecorded group would be an orphan in Entra). If the save fails,
        drop the record and delete the group again, then re-raise."""
        tenant.setdefault(de.TENANT_KEY, []).append(group)
        try:
            await hub.state.save_state_now()
        except BaseException:
            tenant[de.TENANT_KEY] = [g for g in de.registered_groups(tenant)
                                     if g["id"] != group["id"]]
            try:
                await de.delete_group(cfg, group["id"])
            except Exception as e:
                logger.warning("Directory: could not remove unrecorded Entra group %s: %s",
                               group.get("name"), e)
            raise

    def _refresh(tid: str) -> None:
        """After a write, refresh the tenant's cached list now."""
        if hasattr(hub, "cache_refresh"):
            hub.cache_refresh(CACHE_NS, (tid,), exact=True)

    def entra_cache_job(tid: str) -> CacheJob:
        """Cache job for one tenant's Entra accounts and groups."""
        async def fetch():
            """Read the tenant's groups' members from Graph (raises on error,
            so an outage keeps the last list instead of showing none)."""
            cfg = _cfg()
            registered = de.registered_groups(hub.state.get_tenant(tid))
            # The base group first: its members are the tenant's accounts.
            base = next((g for g in registered if g.get("base")), None)
            users = await _graph(de.list_group_users(cfg, base["id"])) if base else []
            own = {u["id"] for u in users}
            groups = [{"id": base["id"], "name": base.get("name") or "", "base": True,
                       "member_count": len(users)}] if base else []
            # Tenant groups show only the tenant's own accounts: a user added
            # to one by hand in Entra (from outside the tenant) stays hidden.
            for g in registered:
                if g.get("base"):
                    continue
                members = await _graph(de.list_group_users(cfg, g["id"]))
                groups.append({"id": g["id"], "name": g.get("name") or "", "base": False,
                               "members": [m for m in members if m["id"] in own]})
            return {"groups": groups, "users": users}
        return CacheJob(CACHE_NS, tid, fetch, (tid,), lane="entra", refresh_s=REFRESH_S)

    def entra_cache_feed(_hub):
        """Feed: every tenant with registered Entra groups, once Entra is set up."""
        if not get_oidc_config(hub).ready:
            return
        for tid in all_tenant_ids(hub):
            if de.registered_groups(hub.state.get_tenant(tid)):
                yield entra_cache_job(tid)

    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("ldap_entra", entra_cache_feed)

    # ── Read ────────────────────────────────────────────────────────────────
    @app.get("/api/ldap/entra")
    async def get_entra(request: Request):
        """The tenant's Entra accounts (base-group members) and groups, from
        the cache. ``configured`` is false when Entra is not set up; a tenant
        with no Entra groups yet gets empty lists without asking Graph."""
        tid = _resolve(request)
        configured = get_oidc_config(hub).ready
        if not configured or not de.registered_groups(_tenant(tid)):
            return {"configured": configured, "groups": [], "users": []}
        job = entra_cache_job(tid)
        data = await hub.cache_read(job.ns, job.key, job.fetch, tenants=job.tenants,
                                    lane=job.lane)
        return hub.cache_annotate({"configured": True, **data}, job.ns, job.key)

    # ── Accounts ────────────────────────────────────────────────────────────
    @app.post("/api/ldap/entra/users")
    async def create_entra_user(request: Request):
        """Create an Entra account for the tenant: it joins the base group and
        any of the tenant's groups in ``group_ids``. The password is the one
        typed, or a generated one returned ONCE (never stored or logged)."""
        # Resolve the tenant (a write) and validate the request.
        data = await request.json()
        tid = _resolve(request, data, write=True)
        tenant = _tenant(tid)
        try:
            upn = de.upn_arg(data.get("upn"))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        name = str(data.get("name") or "").strip()[:128]
        password = str(data.get("password") or "")
        groups = [_group(tenant, g, tenant_group=True) for g in data.get("group_ids") or []]
        # Make sure the base group exists, then create the account.
        cfg = _cfg()
        async with locks.setdefault(tid, asyncio.Lock()):
            base = await _ensure_base(cfg, tid, tenant)
        user = await _graph(de.create_user(cfg, upn, name, password))
        # Join the groups. If one fails, delete the account again: outside the
        # base group it would be invisible to the tenant, an orphan in Entra.
        try:
            for g in [base, *groups]:
                await _graph(de.add_member(cfg, g["id"], user["id"]))
        except BaseException:
            # Any failure (including a cancelled request): undo, then re-raise
            # the original error. A failed undo is only logged.
            try:
                await de.delete_user(cfg, user["id"])
            except Exception as e:
                logger.warning("Directory: could not remove half-created Entra account "
                               "%s: %s", upn, e)
            raise
        # Refresh the cached list; return the generated password only.
        _refresh(tid)
        logger.info("Directory: created Entra account %s for tenant %s", upn, tid)
        out = {"id": user["id"], "upn": user["upn"], "name": user["name"]}
        if user["generated"]:
            out["password"] = user["password"]
        return out

    @app.delete("/api/ldap/entra/users")
    async def delete_entra_user(request: Request):
        """Delete one of the tenant's Entra accounts (a base-group member)."""
        data = await request.json()
        tid = _resolve(request, data, write=True)
        cfg = _cfg()
        user_id = await _require_account(cfg, _tenant(tid), data.get("id"))
        await _graph(de.delete_user(cfg, user_id))
        _refresh(tid)
        logger.info("Directory: deleted Entra account %s for tenant %s", user_id, tid)
        return {"status": "deleted"}

    # ── Groups ──────────────────────────────────────────────────────────────
    @app.post("/api/ldap/entra/groups")
    async def create_entra_group(request: Request):
        """Create a tenant group ``LM-<tenant>-<name>`` in Entra and register
        it on the tenant (creating the base group first if needed)."""
        # Resolve the tenant (a write) and validate the name.
        data = await request.json()
        tid = _resolve(request, data, write=True)
        tenant = _tenant(tid)
        try:
            name = de.group_name_arg(data.get("name"))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        display = de.display_name(tenant.get("name") or tid, name)
        cfg = _cfg()
        # Under the tenant lock: refuse a duplicate, make sure the base group
        # exists, then create and record the new group.
        async with locks.setdefault(tid, asyncio.Lock()):
            if any(g.get("name", "").lower() == display.lower()
                   for g in de.registered_groups(tenant)):
                raise HTTPException(status_code=409, detail=f"{display} already exists")
            await _ensure_base(cfg, tid, tenant)
            group = {**await _graph(de.create_group(cfg, display)), "base": False}
            await _register(cfg, tenant, group)
        # Refresh the cached list and report.
        _refresh(tid)
        logger.info("Directory: created Entra group %s for tenant %s", display, tid)
        return group

    @app.delete("/api/ldap/entra/groups")
    async def delete_entra_group(request: Request):
        """Delete one of the tenant's groups in Entra and unregister it. The
        base group can't be deleted (it is the tenant's account list)."""
        data = await request.json()
        tid = _resolve(request, data, write=True)
        tenant = _tenant(tid)
        cfg = _cfg()
        async with locks.setdefault(tid, asyncio.Lock()):
            group = _group(tenant, data.get("id"), tenant_group=True)
            await _graph(de.delete_group(cfg, group["id"]))
            # Unregister it. If the save fails, keep the record so the delete
            # can simply be retried (deleting an already-deleted group is OK).
            before = list(de.registered_groups(tenant))
            tenant[de.TENANT_KEY] = [g for g in before if g["id"] != group["id"]]
            try:
                await hub.state.save_state_now()
            except BaseException:
                tenant[de.TENANT_KEY] = before
                raise
        _refresh(tid)
        logger.info("Directory: deleted Entra group %s for tenant %s", group.get("name"), tid)
        return {"status": "deleted"}

    @app.post("/api/ldap/entra/groups/members")
    async def add_entra_member(request: Request):
        """Add one of the tenant's accounts to one of its groups."""
        data = await request.json()
        tid = _resolve(request, data, write=True)
        tenant = _tenant(tid)
        group = _group(tenant, data.get("group_id"), tenant_group=True)
        cfg = _cfg()
        user_id = await _require_account(cfg, tenant, data.get("user_id"))
        await _graph(de.add_member(cfg, group["id"], user_id))
        _refresh(tid)
        return {"status": "added"}

    @app.delete("/api/ldap/entra/groups/members")
    async def remove_entra_member(request: Request):
        """Remove a member from one of the tenant's groups. Any member may be
        removed (one added in Entra by hand too): it only ever narrows the
        tenant's own group."""
        data = await request.json()
        tid = _resolve(request, data, write=True)
        group = _group(_tenant(tid), data.get("group_id"), tenant_group=True)
        user_id = _oid_arg(data.get("user_id"), "user_id")
        await _graph(de.remove_member(_cfg(), group["id"], user_id))
        _refresh(tid)
        return {"status": "removed"}
