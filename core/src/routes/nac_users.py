"""NAC → My Users: the tenant's JIT 802.1X accounts created by the simulation
engine (see dot1x_jit.py). List / reset password / delete — passwords are
never returned. Under ``/api/cppm/`` so the NAC-right gate in api.py applies;
mutations additionally require write scope on the account's tenant."""
from __future__ import annotations

import access
from api import HTTPException, Request, logger
import dot1x_jit


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _effective_tenant = ctx._effective_tenant

    @app.get("/api/cppm/my-users")
    async def list_my_users(request: Request, tenant: str = None):
        sess = _session_user(request)
        tid = _effective_tenant(request, tenant)
        if not tid and not access.is_admin(sess):
            return {"users": [], "tenant": None}
        return {"users": dot1x_jit.list_accounts(hub, tid or None), "tenant": tid,
                "rotate_days": dot1x_jit.get_config(hub)["rotate_days"]}

    async def _target(request: Request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body or {}
        sess = _session_user(request)
        requested = str(body.get("tenant_id") or request.query_params.get("tenant") or "").strip()
        tid = requested if access.is_admin(sess) else _effective_tenant(request, requested or None)
        if not tid:
            raise HTTPException(status_code=400, detail="tenant_id required")
        if access.write_scope(sess, tid) == "deny":
            raise HTTPException(status_code=403, detail="Edit access to this tenant is required")
        try:
            backend = dot1x_jit.normalize_backend(body.get("backend"))
            username = dot1x_jit.normalize_username(body.get("username"))
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return tid, backend, username, sess

    @app.post("/api/cppm/my-users/reset")
    async def reset_my_user(request: Request):
        tid, backend, username, sess = await _target(request)
        try:
            rec = await dot1x_jit.rotate(hub, tid, backend, username)
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=404 if "no such" in str(e) else 502, detail=str(e))
        logger.info("dot1x_jit: password reset for %s/%s (tenant %s) by %s", backend, username,
                    tid, (sess or {}).get("user", {}).get("username"))
        return {"status": "ok", "user": rec}

    @app.post("/api/cppm/my-users/delete")
    async def delete_my_user(request: Request):
        tid, backend, username, sess = await _target(request)
        try:
            await dot1x_jit.delete(hub, tid, backend, username)
        except dot1x_jit.Dot1xJitError as e:
            raise HTTPException(status_code=404 if "no such" in str(e) else 502, detail=str(e))
        logger.info("dot1x_jit: account %s/%s (tenant %s) deleted by %s", backend, username,
                    tid, (sess or {}).get("user", {}).get("username"))
        return {"status": "ok", "deleted": username}
