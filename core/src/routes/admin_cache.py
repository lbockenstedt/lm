"""Hub data cache status/refresh/purge routes + session admin routes.

Every module page is served from ONE hub data cache (``warm_cache.py``). These
routes only LOOK at it or nudge it — there is nothing to configure:

* ``GET  /admin/cache/status``   — admin: every cached namespace/entry, its age,
  error, whether it is kept warm (feed) and on the fast (active) cycle.
* ``POST /admin/cache/refresh``  — admin: refresh one namespace (or all) now.
* ``POST /admin/cache/purge``    — admin: drop cached data (all, or one
  tenant's) and refetch it.
* ``GET  /auth/cache-status``    — any user: footer "Caching: …" indicator.
* ``POST /auth/cache/refresh``   — any user: refresh one module for the
  caller's own tenants (the per-page refresh buttons).
"""
from api import (
    HTTPException, Request, _legacy_cache_namespaces, _save_sessions,
    _session_cache_scopes, _sessions, time,
)

# Friendly names for the footer indicator.
_NS_LABELS = {
    "nb_racks": "Racks", "nb_devices": "Devices", "nb_ips": "IP Addresses",
    "nb_prefixes": "Prefixes",
    "list_endpoints": "Device Database", "cppm_get_access_tracker": "Access Tracker",
    "pxmx_vms": "Virtual Machines", "pxmx_nodes": "Hypervisor Nodes",
    "fw_rules": "Firewall Rules", "fw_nat": "NAT Policies", "fw_dhcp": "DHCP Leases",
    "fw_dns": "DNS Records", "fw_interfaces": "Interfaces",
    "ldap_list_users": "Directory Users", "ldap_list_groups": "Directory Groups",
}


def _visible(entry_tenants, scopes: set) -> bool:
    """Can a session with ``scopes`` see a cache entry owned by
    ``entry_tenants``? None = shared data (anyone)."""
    if not entry_tenants:
        return True
    return bool(set(entry_tenants) & scopes)


def register(app, hub, ctx):
    """Register admin_cache routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        return sess

    @app.get("/auth/cache-status")
    async def get_my_cache_status(request: Request):
        """Footer indicator: which of the caller's modules are being fetched
        for the FIRST time (no cached data yet). Everything else is served
        from cache instantly, so ``loading`` is normally empty."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        scopes = _session_cache_scopes(sess)
        loading = set()
        for (ns, key), task in list(getattr(hub, "_cache_inflight", {}).items()):
            if task.done() or key in hub.warm_cache.get(ns, {}):
                continue
            job = hub._cache_read_jobs.get((ns, key))
            if job is None or _visible(job.tenants, scopes):
                loading.add(_NS_LABELS.get(ns, ns))
        return {
            "loading": sorted(loading),
            "all_ready": not loading,
            "tenant_id": (sess.get("user", {}) or {}).get("tenant_id"),
        }

    @app.post("/auth/cache/refresh")
    async def refresh_my_cache(request: Request, module: str = None):
        """Refresh one module (legacy key, e.g. ``cppm_devices``) — only the
        entries the caller can see — and wait briefly so the page reload
        right after shows the new data."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        if not module:
            return {"status": "ok", "refreshed": 0}
        scopes = _session_cache_scopes(sess)
        n = 0
        for ns in _legacy_cache_namespaces(module):
            keys = tuple(k for k, e in (hub.warm_cache.get(ns) or {}).items()
                         if isinstance(e, dict) and _visible(e.get("tenants"), scopes))
            if keys:
                n += hub.cache_refresh(ns, keys, exact=True)
        await hub.cache_wait_idle(timeout=15.0)
        return {"status": "ok", "refreshed": n}

    @app.get("/admin/cache/status")
    async def admin_cache_status(request: Request):
        _require_admin(request)
        return hub.cache_status()

    @app.post("/admin/cache/refresh")
    async def admin_cache_refresh(request: Request, namespace: str = None):
        """Refresh one namespace (or every namespace) now."""
        _require_admin(request)
        namespaces = [namespace] if namespace else list(hub.warm_cache)
        n = sum(hub.cache_refresh(ns) for ns in namespaces)
        return {"status": "ok", "refreshed": n}

    @app.post("/admin/cache/purge")
    async def admin_purge_cache(request: Request, tenant: str = None):
        """Drop cached data (all, or what one tenant can see) and refetch it.
        Pages keep working: the next read fetches live."""
        _require_admin(request)
        n = hub.cache_purge(tenant or None)
        return {"status": "ok", "tenant": tenant or "all", "dropped": n}

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

    @app.post("/admin/state/reset")
    async def admin_reset_derived_state(request: Request, tenant: str = None):
        """Corruption recovery: wipe DERIVED/cache/history JSON (sharded files +
        in-memory dicts) globally or for one tenant (all its modules). Preserves
        config/identity (tenant registration, spoke PSKs, users, sessions) — a
        reset never orphans a spoke or logs anyone out; the derived data
        regenerates from the next poll/telemetry. Global-Admin only + audited."""
        sess = _require_admin(request)
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
