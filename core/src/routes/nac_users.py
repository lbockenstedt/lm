"""NAC → My Users: the tenant's JIT 802.1X accounts created by the simulation
engine (see dot1x_jit.py). List / reset password / delete — passwords are
never returned. Under ``/api/cppm/`` so the NAC-right gate in api.py applies;
mutations additionally require write scope on the account's tenant."""
# Postponed evaluation of annotations, so type hints are never evaluated at import time.
from __future__ import annotations

# Tenant/role permission helpers (admin check, per-tenant write scope).
import access
# Shared FastAPI-style request/exception types and the app-wide logger from the API module.
from api import HTTPException, Request, logger
# The JIT 802.1X account store that actually lists, rotates and deletes accounts.
import dot1x_jit


def register(app, hub, ctx):
    """Attach the "My Users" NAC routes to the web app.

    Args: app is the web application, hub is the running LM hub (holds state), ctx carries shared
    route helpers (session lookup, tenant resolution).
    """
    # Pull the shared helpers out of ctx once so the route handlers below can use them as closures.
    _session_user = ctx._session_user
    _effective_tenant = ctx._effective_tenant

    @app.get("/api/cppm/my-users")
    async def list_my_users(request: Request, tenant: str = None):
        """List the JIT 802.1X accounts belonging to the caller's tenant (passwords are never
        included).
        """
        # Identify the logged-in user and the tenant this request is scoped to.
        sess = _session_user(request)
        tid = _effective_tenant(request, tenant)
        # A non-admin with no tenant has nothing to see; return an empty list rather than an error.
        if not tid and not access.is_admin(sess):
            return {"users": [], "tenant": None}
        # Return the tenant's accounts (admins without a tenant see every tenant) plus the
        # auto-rotation period so the UI can show when passwords change.
        return {"users": dot1x_jit.list_accounts(hub, tid or None), "tenant": tid,
                "rotate_days": dot1x_jit.get_config(hub)["rotate_days"]}

    async def _target(request: Request):
        """Parse and authorise a mutation request, returning (tenant, backend, username, session).

        Raises HTTPException 400 for missing/invalid input and 403 when the caller cannot edit the
        tenant.
        """
        # Read the JSON body; a missing or malformed body is treated as empty so the validation
        # below reports what is missing.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # The body may be JSON null; normalise it to an empty dict.
        body = body or {}
        # Work out which tenant is targeted: admins may name any tenant, everyone else is forced to
        # their effective tenant.
        sess = _session_user(request)
        requested = str(body.get("tenant_id") or request.query_params.get("tenant") or "").strip()
        tid = requested if access.is_admin(sess) else _effective_tenant(request, requested or None)
        # Every account belongs to a tenant, so a tenant is mandatory.
        if not tid:
            raise HTTPException(status_code=400, detail="tenant_id required")
        # Only users with write access to the tenant may reset or delete its accounts.
        if access.write_scope(sess, tid) == "deny":
            raise HTTPException(status_code=403, detail="Edit access to this tenant is required")
        # Validate the backend and username; the JIT module raises Dot1xJitError for bad values,
        # which becomes a 400.
        try:
            backend = dot1x_jit.normalize_backend(body.get("backend"))
            username = dot1x_jit.normalize_username(body.get("username"))
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=400, detail=str(e))
        # Hand the validated values back to the calling route.
        return tid, backend, username, sess

    @app.post("/api/cppm/my-users/reset")
    async def reset_my_user(request: Request):
        """Generate a new password for one JIT 802.1X account (the new password is not returned)."""
        # Validate and authorise the request first.
        tid, backend, username, sess = await _target(request)
        # Rotate the password; "no such" errors mean the account does not exist (404), anything else
        # is a backend failure (502).
        try:
            rec = await dot1x_jit.rotate(hub, tid, backend, username)
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=404 if "no such" in str(e) else 502, detail=str(e))
        # Audit-log who reset which account.
        logger.info("dot1x_jit: password reset for %s/%s (tenant %s) by %s", backend, username,
                    tid, (sess or {}).get("user", {}).get("username"))
        # Return the updated account record (without its password).
        return {"status": "ok", "user": rec}

    @app.post("/api/cppm/my-users/delete")
    async def delete_my_user(request: Request):
        """Delete one JIT 802.1X account from the tenant's NAC backend."""
        # Validate and authorise the request first.
        tid, backend, username, sess = await _target(request)
        # Delete the account; "no such" errors mean it was already gone (404), anything else is a
        # backend failure (502).
        try:
            await dot1x_jit.delete(hub, tid, backend, username)
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=404 if "no such" in str(e) else 502, detail=str(e))
        # Audit-log who deleted which account.
        logger.info("dot1x_jit: account %s/%s (tenant %s) deleted by %s", backend, username,
                    tid, (sess or {}).get("user", {}).get("username"))
        # Confirm the deletion to the UI.
        return {"status": "ok", "deleted": username}
