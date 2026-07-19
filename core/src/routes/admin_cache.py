"""Auth/admin cache-status + session admin + cache config routes."""
from api import (
    HTTPException, Request, _DEFAULT_CACHE_CONFIG, _FW_MODULES, _cache_status, _cache_tasks,
    _fetch_module, _get_cache_config, _get_max_concurrent, _preload_all_parallel,
    _save_sessions, _sessions, _start_cache_for_tenant, _tenant_cache, asyncio, time,
)


def register(app, hub, ctx):
    """Register admin_cache routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    @app.get("/auth/cache-status")
    async def get_my_cache_status(request: Request):
        """Returns cache loading status for the current session's tenant (used by footer indicator)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        tenant_id = sess.get("user", {}).get("tenant_id")
        if not tenant_id:
            return {"status": {}, "all_ready": True, "tenant_id": None}
        config = _get_cache_config(hub)
        status = _cache_status.get(tenant_id, {})
        enabled_modules = {k for k, v in config.items() if v.get("enabled", True)}
        loading = [k for k, v in status.items() if v == "loading"]
        all_ready = not loading and bool(status)
        return {
            "status": status,
            "loading": loading,
            "all_ready": all_ready,
            "tenant_id": tenant_id,
            "labels": {k: _DEFAULT_CACHE_CONFIG[k.split(":")[0]]["label"]
                       for k in status if k.split(":")[0] in _DEFAULT_CACHE_CONFIG},
        }

    @app.get("/admin/sessions")
    async def admin_get_sessions(request: Request):
        now = time.time()
        active = []
        pruned = False
        for token, sess in list(_sessions.items()):
            if sess["expires"] < now:
                _sessions.pop(token, None)
                pruned = True
                continue
            u = sess.get("user", {})
            p = u.get("permissions", {})
            _uid = sess.get("user_id", u.get("user_id", "?"))
            # Friendly display name — for an Entra user the user_id is the oid GUID,
            # so surface the human name and fall back to the id only if nothing set.
            _name = (u.get("name") or u.get("display_name") or u.get("full_name")
                     or u.get("username") or u.get("email") or _uid)
            active.append({
                "user_id":    _uid,
                "name":       _name,
                "is_admin":   bool(p.get("admin") or p.get("role") == "admin"),
                "tenants":    u.get("tenants", []),
                "expires_in": int(sess["expires"] - now),
                # Non-secret revocation id (NOT the cookie token prefix). The old
                # ``token_hint: token[:8]`` leaked 8 chars of the session cookie
                # to the admin UI and matched revocation by prefix — a hostile
                # admin (or anyone reading the listing) could narrow a session
                # token. ``sid`` is an opaque per-session id with no relationship
                # to the cookie, so the listing/revocation surface is safe to
                # expose and revocation is exact, not prefix-based.
                "sid":        sess.get("sid") or "",
            })
        if pruned:
            _save_sessions(app.state.hub)
        active.sort(key=lambda s: str(s.get("name") or s["user_id"]).lower())
        return {"sessions": active, "count": len(active)}

    @app.delete("/admin/sessions/{sid}")
    async def admin_revoke_session(sid: str, request: Request):
        for token in list(_sessions.keys()):
            if _sessions[token].get("sid") == sid:
                _sessions.pop(token, None)
                _save_sessions(app.state.hub)
                return {"status": "ok", "message": "Session revoked"}
        raise HTTPException(status_code=404, detail="Session not found")

    @app.get("/admin/cache/config")
    async def admin_get_cache_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        cfg = _get_cache_config(hub)
        return {
            "config": cfg,
            "max_concurrent_tenants": _get_max_concurrent(hub),
            "labels": {k: v["label"] for k, v in _DEFAULT_CACHE_CONFIG.items()},
        }

    @app.put("/admin/cache/config")
    async def admin_update_cache_config(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        data = await request.json()
        stored = hub.state.system_state.get("cache_config", {})
        for key, vals in data.get("config", {}).items():
            stored.setdefault(key, {}).update({k: v for k, v in vals.items() if k in ("enabled", "interval")})
        if "max_concurrent_tenants" in data:
            stored["max_concurrent_tenants"] = int(data["max_concurrent_tenants"])
        hub.state.system_state["cache_config"] = stored
        hub.state._mark_dirty()
        return {"status": "ok"}

    @app.post("/admin/cache/purge")
    async def admin_purge_cache(request: Request, tenant: str = None):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        if tenant:
            _tenant_cache.pop(tenant, None)
            _cache_status.pop(tenant, None)
            task = _cache_tasks.pop(tenant, None)
            if task: task.cancel()
            _start_cache_for_tenant(hub, tenant)
        else:
            tenants_to_rewarm = list(_tenant_cache.keys())
            _tenant_cache.clear()
            _cache_status.clear()
            for tid, task in list(_cache_tasks.items()):
                task.cancel()
            _cache_tasks.clear()
            for tid in tenants_to_rewarm:
                _start_cache_for_tenant(hub, tid)
        return {"status": "ok", "tenant": tenant or "all"}

    @app.post("/admin/state/reset")
    async def admin_reset_derived_state(request: Request, tenant: str = None):
        """Corruption recovery: wipe DERIVED/cache/history JSON (sharded files +
        in-memory dicts) globally or for one tenant (all its modules). Preserves
        config/identity (tenant registration, spoke PSKs, users, sessions) — a
        reset never orphans a spoke or logs anyone out; the derived data
        regenerates from the next poll/telemetry. Global-Admin only + audited."""
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        who = (sess.get("user", {}) or {}).get("user_id") or sess.get("user_id") or "?"
        try:
            result = hub.reset_derived_cache(tenant or None)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"reset failed: {e}")
        try:
            audit = getattr(hub, "audit_event", None) or getattr(hub, "audit", None)
            if callable(audit):
                audit("state_reset", user=who,
                      detail=f"derived-cache reset scope={tenant or 'ALL'} "
                             f"files={result.get('files_removed')}")
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass
        return result

    @app.get("/admin/cache/status")
    async def admin_cache_status(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        summary = {}
        for tid, modules in _cache_status.items():
            summary[tid] = {
                "modules": modules,
                "fetched_at": {k: _tenant_cache.get(tid, {}).get(k, {}).get("fetched_at")
                               for k in modules},
                "task_alive": tid in _cache_tasks and not _cache_tasks[tid].done(),
            }
        return {"tenants": summary, "max_concurrent": _get_max_concurrent(hub)}

    @app.post("/auth/cache/refresh")
    async def refresh_my_cache(request: Request, module: str = None):
        """Any authenticated user can trigger a refresh of their tenant's cache modules."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        tenant_id = sess.get("user", {}).get("tenant_id")
        if not tenant_id:
            return {"status": "ok", "message": "No tenant assigned"}
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        if module:
            base = module.split(":")[0]
            if base in _FW_MODULES:
                tasks = [_fetch_module(hub, tenant_id, base, fw_id=fw["id"]) for fw in firewalls]
            else:
                tasks = [_fetch_module(hub, tenant_id, base)]
            await asyncio.gather(*tasks, return_exceptions=True)
        else:
            await _preload_all_parallel(hub, tenant_id)
        return {"status": "ok", "tenant_id": tenant_id}
