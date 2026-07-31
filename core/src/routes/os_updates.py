"""Fleet OS updates — inventory + approve-and-deploy, from the WebUI.

The hub is the module: it collects pending-update state from every spoke and
agent and, on explicit Global-Admin approval, sends the apply commands. Nodes
never decide to update themselves.

Security posture (mirrors Remote Console):
  * Global-Admin ONLY.
  * Applying is an explicit POST carrying the approval; checking is read-only.
  * Every approval and every per-node outcome is audit-logged at WARNING with
    the operator's identity.
Commands reach a node as an HMAC-signed OS_UPDATE_* frame (control_plane), so a
spoke trusts them exactly like SPOKE_UPDATE.

Behaviour is fixed by design, not exposed as knobs: dist-upgrade (everything —
security, regular, dependency transitions), NEVER auto-reboot, rolling one node
at a time, hub last. See hub_os_updates.py for why.
"""
from api import HTTPException, Request, logger


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _who(sess):
        return ((sess or {}).get("user_id") or (sess or {}).get("username")
                or (sess or {}).get("user") or "?")

    def _require_admin(request):
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin required")
        return sess

    @app.get("/api/os-updates")
    async def os_updates_snapshot(request: Request):
        """Last known fleet state. Cheap — serves the cache, probes nothing."""
        _require_admin(request)
        return hub.osu_snapshot()

    @app.post("/api/os-updates/check")
    async def os_updates_check(request: Request):
        """Re-probe every node (apt-get update + list upgradable). Read-only."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        refresh = bool((body or {}).get("refresh", True))
        return await hub.osu_check_fleet(refresh=refresh)

    @app.post("/api/os-updates/apply")
    async def os_updates_apply(request: Request):
        """Approve + deploy. Returns immediately; poll the snapshot for progress.

        ``nodes`` (optional) restricts the roll to specific ``kind:id`` keys;
        omitted means every eligible node with pending updates.
        """
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        keys = (body or {}).get("nodes") or None
        if keys is not None and not isinstance(keys, list):
            raise HTTPException(status_code=400, detail="'nodes' must be a list")
        actor = _who(sess)
        logger.warning("[os-updates] APPLY approved by %s — nodes=%s",
                       actor, keys if keys else "ALL eligible")
        res = await hub.osu_apply_fleet(node_keys=keys, actor=actor)
        if res.get("status") == "ERROR":
            raise HTTPException(status_code=409, detail=res.get("message", "cannot apply"))
        return res
