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
# Shared Hub helpers: HTTP error type, request object, cache/session state and
# helpers, and the time module (all re-exported by the main api module).
from api import (
    HTTPException, Request, _legacy_cache_namespaces, _save_sessions,
    _session_cache_scopes, _sessions, time,
)

# Maps internal cache namespace keys to the labels users see in the UI footer.
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
    # No owning tenants means the entry is shared data that every session may see.
    if not entry_tenants:
        return True
    # Otherwise the session needs at least one tenant scope in common with the entry.
    return bool(set(entry_tenants) & scopes)


def register(app, hub, ctx):
    """Register admin_cache routes on the Hub app."""
    # Pull the session/permission helpers out of the shared route context once.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _require_admin(request):
        """Return the caller's session, or raise 403 unless they are an admin."""
        # Look up the session from the request cookie; reject anonymous or non-admin callers.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        # Hand the session back so callers can use it (e.g. for audit user names).
        return sess

    # Footer "Caching: ..." indicator, available to any signed-in user.
    @app.get("/auth/cache-status")
    async def get_my_cache_status(request: Request):
        """Footer indicator: which of the caller's modules are being fetched
        for the FIRST time (no cached data yet). Everything else is served
        from cache instantly, so ``loading`` is normally empty."""
        # Only signed-in users may ask about cache state.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # Tenants this session may see, and the set of module labels still loading.
        scopes = _session_cache_scopes(sess)
        loading = set()
        # Walk every in-flight cache fetch (copied to a list so it can't change under us).
        for (ns, key), task in list(getattr(hub, "_cache_inflight", {}).items()):
            # Skip fetches that already finished or whose data is already cached.
            if task.done() or key in hub.warm_cache.get(ns, {}):
                continue
            # Show the fetch only if it is shared data or belongs to one of the caller's tenants.
            job = hub._cache_read_jobs.get((ns, key))
            if job is None or _visible(job.tenants, scopes):
                loading.add(_NS_LABELS.get(ns, ns))
        # Sorted labels for a stable UI; all_ready tells the footer to hide the indicator.
        return {
            "loading": sorted(loading),
            "all_ready": not loading,
            "tenant_id": (sess.get("user", {}) or {}).get("tenant_id"),
        }

    # Per-page refresh buttons: refresh one module, limited to the caller's own tenants.
    @app.post("/auth/cache/refresh")
    async def refresh_my_cache(request: Request, module: str = None):
        """Refresh one module (legacy key, e.g. ``cppm_devices``) — only the
        entries the caller can see — and wait briefly so the page reload
        right after shows the new data."""
        # Only signed-in users may trigger a refresh.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not authenticated")
        # No module named means nothing to refresh; report zero rather than erroring.
        if not module:
            return {"status": "ok", "refreshed": 0}
        # Caller's visible tenant scopes, and a counter of refreshed entries.
        scopes = _session_cache_scopes(sess)
        n = 0
        # A legacy module key can map to several cache namespaces; handle each one.
        for ns in _legacy_cache_namespaces(module):
            # Collect only the cache keys in this namespace that the caller is allowed to see.
            keys = tuple(k for k, e in (hub.warm_cache.get(ns) or {}).items()
                         if isinstance(e, dict) and _visible(e.get("tenants"), scopes))
            # Refresh exactly those keys (not the whole namespace) and count them.
            if keys:
                n += hub.cache_refresh(ns, keys, exact=True)
        # Wait up to 15 s for the refreshes so the page reload shows fresh data.
        await hub.cache_wait_idle(timeout=15.0)
        return {"status": "ok", "refreshed": n}

    # Admin view of every cache namespace/entry with age, errors and warm status.
    @app.get("/admin/cache/status")
    async def admin_cache_status(request: Request):
        """Return the full hub cache status (admin only)."""
        # Enforce admin, then return the hub's own status report.
        _require_admin(request)
        return hub.cache_status()

    # Admin: force a refresh of one namespace, or all of them.
    @app.post("/admin/cache/refresh")
    async def admin_cache_refresh(request: Request, namespace: str = None):
        """Refresh one namespace (or every namespace) now."""
        # Admin only; with no namespace given, refresh every cached namespace.
        _require_admin(request)
        namespaces = [namespace] if namespace else list(hub.warm_cache)
        # Each refresh call returns how many entries it queued; total them for the reply.
        n = sum(hub.cache_refresh(ns) for ns in namespaces)
        return {"status": "ok", "refreshed": n}

    # Admin: drop cached data and let it be refetched on the next read.
    @app.post("/admin/cache/purge")
    async def admin_purge_cache(request: Request, tenant: str = None):
        """Drop cached data (all, or what one tenant can see) and refetch it.
        Pages keep working: the next read fetches live."""
        # Admin only; purge everything, or only one tenant's entries when given.
        _require_admin(request)
        n = hub.cache_purge(tenant or None)
        return {"status": "ok", "tenant": tenant or "all", "dropped": n}

    # Admin: list every live login session.
    @app.get("/admin/sessions")
    async def admin_get_sessions(request: Request):
        """List active sessions for the admin UI, pruning expired ones as we go."""
        # Current time, the output list, and a flag noting whether we removed anything.
        now = time.time()
        active = []
        pruned = False
        # Iterate a copy of the session table because expired entries are removed in the loop.
        for token, sess in list(_sessions.items()):
            # Expired session: delete it and remember to persist the change.
            if sess["expires"] < now:
                _sessions.pop(token, None)
                pruned = True
                continue
            # Pull the user record, its permissions and the user id for display.
            u = sess.get("user", {})
            p = u.get("permissions", {})
            _uid = sess.get("user_id", u.get("user_id", "?"))
            # Friendly display name — for an Entra user the user_id is the oid GUID,
            # so surface the human name and fall back to the id only if nothing set.
            _name = (u.get("name") or u.get("display_name") or u.get("full_name")
                     or u.get("username") or u.get("email") or _uid)
            # Build the row the admin UI shows for this session.
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
        # Persist the session table only if expired entries were actually removed.
        if pruned:
            _save_sessions(app.state.hub)
        # Sort by display name (case-insensitive) so the list is easy to scan.
        active.sort(key=lambda s: str(s.get("name") or s["user_id"]).lower())
        return {"sessions": active, "count": len(active)}

    # Admin: revoke one session by its opaque sid.
    @app.delete("/admin/sessions/{sid}")
    async def admin_revoke_session(sid: str, request: Request):
        """Revoke the session whose opaque ``sid`` matches; 404 if none does."""
        # Find the cookie token whose session has this sid (exact match, not prefix).
        for token in list(_sessions.keys()):
            if _sessions[token].get("sid") == sid:
                # Remove it, persist the session table and confirm.
                _sessions.pop(token, None)
                _save_sessions(app.state.hub)
                return {"status": "ok", "message": "Session revoked"}
        # No session carried that sid.
        raise HTTPException(status_code=404, detail="Session not found")

    # Admin: corruption recovery that wipes derived/cached state.
    @app.post("/admin/state/reset")
    async def admin_reset_derived_state(request: Request, tenant: str = None):
        """Corruption recovery: wipe DERIVED/cache/history JSON (sharded files +
        in-memory dicts) globally or for one tenant (all its modules). Preserves
        config/identity (tenant registration, spoke PSKs, users, sessions) — a
        reset never orphans a spoke or logs anyone out; the derived data
        regenerates from the next poll/telemetry. Global-Admin only + audited."""
        # Admin only; work out who is doing this so it can be audited.
        sess = _require_admin(request)
        who = (sess.get("user", {}) or {}).get("user_id") or sess.get("user_id") or "?"
        # Run the reset; any failure is reported to the caller as a 500 with the reason.
        try:
            result = hub.reset_derived_cache(tenant or None)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"reset failed: {e}")
        # Record an audit event if the hub provides an audit function (either name).
        try:
            audit = getattr(hub, "audit_event", None) or getattr(hub, "audit", None)
            if callable(audit):
                audit("state_reset", user=who,
                      detail=f"derived-cache reset scope={tenant or 'ALL'} "
                             f"files={result.get('files_removed')}")
        # Auditing must never make a successful reset look like a failure.
        except Exception:  # noqa: BLE001 — audit is best-effort
            pass
        # Return the hub's summary of what was removed.
        return result
