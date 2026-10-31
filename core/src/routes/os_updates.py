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

Behaviour: rolling one node at a time, hub last; a manual apply never reboots. An apply
is a full dist-upgrade by default, or narrowed to chosen nodes, chosen packages
per node, or security updates only. Rebooting is its own explicit, audited
action per node, and a running roll can be cancelled (the current node
finishes). See hub_os_updates.py for why.

Checking IS on a configurable schedule though: the panel auto-checks the fleet
every ``interval_hours`` (default 6, ``/api/os-updates/auto-check``) so its
status stays fresh without an operator remembering to click "Check for
updates" — see ``run_os_updates_check_loop`` in ``hub_os_updates.py``.

Auto-patch (``/api/os-updates/auto-patch``) is the one scheduled apply and is
approved PER NODE (none by default) and only runs inside its maintenance window
(default 01:00-05:00): once per window it re-checks the fleet and deploys what
was found on the approved nodes, through the same rolling hub-last roll,
audit-logged as "auto-patch". It never installs a package on the operator's
exclude list (names or globs). Auto-reboot (per node, on by default for an
auto-patch node) reboots the nodes that installed something, hub last,
audit-logged as "auto-reboot".

``/api/os-updates/fix-access`` takes a root/sudo login typed once for a node
blocked by missing privileges; the password is relayed to that node only and
never stored or logged.

``/api/os-updates/cves?q=`` answers "who is affected by this CVE?" from the
installed packages each node reports with its check (see ``os_cve.py``);
``/api/os-updates/cves/fleet`` lists just the CVEs affecting the fleet, for the
search box's suggestions.
"""
import re

from api import HTTPException, Request, logger

_CVE_QUERY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]*$")


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

    @app.get("/api/os-updates/cves")
    async def os_updates_cves(request: Request, q: str = ""):
        """Who is affected: ``?q=CVE-2026-1234`` lists the nodes running a
        vulnerable package (and those already patched); ``?q=php`` lists the
        open CVEs of matching packages and their nodes. Matches the installed
        packages reported at the last check against Debian's security
        tracker — probes nothing."""
        _require_admin(request)
        q = (q or "").strip()
        if not (2 <= len(q) <= 64) or not _CVE_QUERY_RE.match(q):
            raise HTTPException(status_code=400,
                                detail="enter a CVE id (CVE-2026-1234) or a package name")
        return await hub.osu_cve_search(q)

    @app.get("/api/os-updates/pending-reboots")
    async def os_updates_pending_reboots(request: Request):
        """Nodes auto-reboot will restart in the current maintenance window
        (footer "Pending Reboot" alert): ``{in_window, window, nodes}``."""
        _require_admin(request)
        return hub.osu_pending_reboots()

    @app.get("/api/os-updates/cves/fleet")
    async def os_updates_fleet_cves(request: Request):
        """CVEs that affect at least one node now (``[{cve, description,
        urgency, nodes}]``) — the suggestions for the who-is-affected box."""
        _require_admin(request)
        return await hub.osu_fleet_cves()

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

    @app.get("/api/os-updates/auto-check")
    async def os_updates_autocheck_get(request: Request):
        """Current auto-check schedule: ``{enabled, interval_hours}``. Runs the
        scheduled twin of the "Check for updates" button — see
        ``run_os_updates_check_loop`` in ``hub_os_updates.py``."""
        _require_admin(request)
        return hub.osu_autocheck_config()

    @app.post("/api/os-updates/auto-check")
    async def os_updates_autocheck_set(request: Request):
        """Update the auto-check schedule. ``interval_hours`` is clamped >= 1
        (server-side) so a fat-fingered '0' can't hot-loop probing the whole
        fleet. Takes effect on the loop's NEXT cycle — no restart needed."""
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        enabled = bool((body or {}).get("enabled", True))
        interval_hours = (body or {}).get("interval_hours", 6)
        cfg = hub.osu_set_autocheck_config(enabled, interval_hours)
        logger.info("[os-updates] auto-check config updated by %s: enabled=%s "
                   "interval_hours=%g", _who(sess), cfg["enabled"], cfg["interval_hours"])
        return cfg

    @app.get("/api/os-updates/auto-patch")
    async def os_updates_autopatch_get(request: Request):
        """Auto-patch config: ``{security_only, nodes, exclude, reboot_nodes, window}``."""
        _require_admin(request)
        return hub.osu_autopatch_config()

    @app.post("/api/os-updates/auto-patch")
    async def os_updates_autopatch_set(request: Request):
        """Approve one node: ``{"node": "kind:id", "enabled": bool}``, set
        ``{"security_only": bool}`` for every auto-patched node, and/or replace
        ``{"exclude": ["pkg", "linux-image-*", ...]}`` — packages auto-patch
        never installs. ``{"node": "kind:id", "auto_reboot": bool}`` turns
        auto-reboot on/off for an auto-patch node (approving a node turns it on).
        ``{"window": {"start": "01:00", "end": "05:00", "tz": "America/Chicago"}}``
        sets the maintenance window auto-patch (and auto-reboot) runs in."""
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        body = body or {}
        actor = _who(sess)
        cfg = hub.osu_autopatch_config()
        if "security_only" in body:
            cfg = hub.osu_set_autopatch_security_only(bool(body["security_only"]))
            logger.warning("[os-updates] auto-patch security_only=%s set by %s",
                           cfg["security_only"], actor)
        if "exclude" in body:
            exclude = body["exclude"]
            if not isinstance(exclude, list) or not all(isinstance(p, str) for p in exclude):
                raise HTTPException(status_code=400, detail="'exclude' must be a list of package names")
            cfg = hub.osu_set_autopatch_exclude(exclude)
            logger.warning("[os-updates] auto-patch exclude=%s set by %s",
                           cfg["exclude"], actor)
        if "window" in body:
            if not isinstance(body["window"], dict):
                raise HTTPException(status_code=400, detail="'window' must be {start, end, tz}")
            try:
                cfg = hub.osu_set_autopatch_window(body["window"])
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"bad maintenance window: {exc}")
            logger.warning("[os-updates] auto-patch window=%s set by %s", cfg["window"], actor)
        key = body.get("node")
        if key is not None:
            if not isinstance(key, str) or not key:
                raise HTTPException(status_code=400, detail="'node' must be a kind:id key")
            if "auto_reboot" in body:
                try:
                    cfg = hub.osu_set_autoreboot_node(key, bool(body["auto_reboot"]))
                except ValueError as exc:
                    raise HTTPException(status_code=409, detail=str(exc))
                logger.warning("[os-updates] auto-reboot %s for %s by %s",
                               "ON" if key in cfg["reboot_nodes"] else "off", key, actor)
            else:
                cfg = hub.osu_set_autopatch_node(key, bool(body.get("enabled", False)))
                logger.warning("[os-updates] auto-patch %s for %s by %s",
                               "APPROVED" if key in cfg["nodes"] else "withdrawn", key, actor)
        return cfg

    @app.post("/api/os-updates/fix-access")
    async def os_updates_fix_access(request: Request):
        """``{"node": "kind:id", "username": "root", "password": "..."}`` —
        one-time login used by the node to install its update helper."""
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        body = body or {}
        key = body.get("node")
        password = body.get("password")
        if not isinstance(key, str) or not key:
            raise HTTPException(status_code=400, detail="'node' (kind:id) is required")
        if not isinstance(password, str) or not password:
            raise HTTPException(status_code=400, detail="'password' is required")
        username = str(body.get("username") or "root")
        res = await hub.osu_fix_access(key, username, password, actor=_who(sess))
        if res.get("status") == "ERROR":
            raise HTTPException(status_code=409, detail=res.get("message", "fix failed"))
        return res

    @app.post("/api/os-updates/apply")
    async def os_updates_apply(request: Request):
        """Approve + deploy. Returns immediately; poll the snapshot for progress.

        Body (all optional):
          * ``nodes`` — restrict the roll to these ``kind:id`` keys; omitted
            means every eligible node with pending updates.
          * ``packages`` — ``{"kind:id": ["pkg", ...]}``: upgrade only those
            packages on that node.
          * ``security_only`` — nodes without an explicit package list get
            only their pending security packages.
        """
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        keys = (body or {}).get("nodes") or None
        if keys is not None and not isinstance(keys, list):
            raise HTTPException(status_code=400, detail="'nodes' must be a list")
        packages = (body or {}).get("packages") or None
        if packages is not None and not (
                isinstance(packages, dict)
                and all(isinstance(v, list) and all(isinstance(p, str) for p in v)
                        for v in packages.values())):
            raise HTTPException(status_code=400,
                                detail="'packages' must map node key -> list of package names")
        security_only = bool((body or {}).get("security_only", False))
        actor = _who(sess)
        logger.warning("[os-updates] APPLY approved by %s — nodes=%s packages=%s security_only=%s",
                       actor, keys if keys else "ALL eligible",
                       {k: len(v) for k, v in (packages or {}).items()} or "all",
                       security_only)
        res = await hub.osu_apply_fleet(node_keys=keys, actor=actor,
                                        packages=packages, security_only=security_only)
        if res.get("status") == "ERROR":
            raise HTTPException(status_code=409, detail=res.get("message", "cannot apply"))
        return res

    @app.post("/api/os-updates/cancel")
    async def os_updates_cancel(request: Request):
        """Stop the running roll after the node currently applying."""
        sess = _require_admin(request)
        res = hub.osu_cancel_run(actor=_who(sess))
        if res.get("status") == "ERROR":
            raise HTTPException(status_code=409, detail=res.get("message", "cannot cancel"))
        return res

    @app.post("/api/os-updates/reboot")
    async def os_updates_reboot(request: Request):
        """Reboot ONE node (``{"node": "kind:id"}``) in one minute. Never
        automatic — this endpoint is the only way LM reboots a host."""
        sess = _require_admin(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        key = (body or {}).get("node")
        if not isinstance(key, str) or not key:
            raise HTTPException(status_code=400, detail="'node' (kind:id) is required")
        actor = _who(sess)
        logger.warning("[os-updates] REBOOT requested by %s — node=%s", actor, key)
        res = await hub.osu_reboot_node(key, actor=actor)
        if res.get("status") == "ERROR":
            raise HTTPException(status_code=409, detail=res.get("message", "cannot reboot"))
        return res
