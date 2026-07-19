"""Remote Client Debug Mode — flip a single cs client into debug mode from the
WebUI and stream its logs up to the hub for remote troubleshooting.

The flow (every hop already existed — this module is the hub-side control +
read surface; see the full design in ``.claude/plans/precious-napping-seahorse.md``):

  WebUI ─POST /api/cs/clients/{host}/debug─▶ here
       └─ hub.request_response(cs_spoke, "CS_QUEUE_COMMAND",
           {target:host, action:"debug_mode", args:{enabled, level}})
              └─ cs spoke _handle_queue_command → /ws/client push
                   └─ agent.sh writes debug-mode.flag + starts the Python tailer
                        └─ tailer sends {"type":"debug_log", payload:{lines, level}}
                             └─ cs spoke /ws/client → _relay_client_debug_log_to_hub
                                  └─ send_to_hub("CS_DEBUG_LOG", {hostname, level, lines})
                                       └─ hub._handle_cs_debug_log → client_debug_logs[(t,host)]
                                            └─ GET /api/cs/clients/{host}/debug-logs ◀─ WebUI panel

Authz mirrors the directory/firewall modules (``access.read_scope`` /
``write_scope``): a Global-Admin gets ``full`` for any tenant; a tenant write
user gets ``full`` for their own tenant; everyone else 403s. The buffer is
ephemeral (same contract as ``agent_logs`` / ``SPOKE_LOG``) — lost on hub
restart. A 30-min auto-off is enforced BOTH client-side (the tailer's flag
deadline) AND hub-side (``_handle_cs_debug_log`` drops frames past
``enabled_at``), so a client that drops and re-streams past the window can't
keep filling memory.
"""
import time

import access
from api import HTTPException, Request, logger

# Hub-side auto-off window — must match the client tailer's deadline
# (agent.sh writes `deadline = now + 30*60` into debug-mode.flag) and the
# hub-side drop guard in _handle_cs_debug_log.
_DEBUG_WINDOW_S = 30 * 60


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _resolve_tenant = ctx._resolve_tenant
    _check_tenant_access = ctx._check_tenant_access

    def _resolve(request: Request, write: bool):
        """Resolve + authorize the tenant this debug request acts on.

        Honors ``?tenant=`` (admin naming any; non-admin gated by
        ``check_tenant_access`` so a foreign tenant 403s before the scope check),
        falling back to the session's tenant_id. ``read_scope``/``write_scope``
        then re-check the TIER — a write needs edit access — giving the single
        canonical deny point the other modules have. Returns ``(tid, scope)``."""
        sess = _session_user(request)
        explicit = str(request.query_params.get("tenant") or "").strip()
        tid = explicit or _resolve_tenant(request)
        if tid and explicit and not _check_tenant_access(sess, tid):
            raise HTTPException(status_code=403,
                                detail=f"Not authorized for tenant '{explicit}'")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(
                status_code=403,
                detail="You do not have access to this tenant's client debug")
        return tid, scope

    @app.post("/api/cs/clients/{hostname}/debug")
    async def cs_client_debug_set(request: Request, hostname: str):
        """Toggle debug mode on one cs client (immediate, non-persistent).

        Body ``{enabled: bool, level: "basic"|"advanced"}``. Relays to the
        tenant's cs spoke as a ``CS_QUEUE_COMMAND`` (the same path kill_switch /
        reboot / update_now use), which enqueues a ``debug_mode`` action the
        client's agent.sh picks up on its persistent /ws/client. Records
        ``enabled_at`` on the hub so the auto-off window + the WebUI "active
        until" indicator work even though the flag itself lives on the client."""
        tid, _scope = _resolve(request, write=True)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        if not isinstance(body, dict):
            body = {}
        enabled = bool(body.get("enabled"))
        level = str(body.get("level") or "basic").strip().lower()
        if level not in ("basic", "advanced"):
            level = "basic"

        cs_spoke = hub.get_client_sim_spoke(tid) if hasattr(hub, "get_client_sim_spoke") else None
        if not cs_spoke:
            raise HTTPException(status_code=503,
                                detail="Client-Sim spoke not connected")
        try:
            await hub.request_response(
                cs_spoke, "CS_QUEUE_COMMAND",
                {"target": hostname, "action": "debug_mode",
                 "args": {"enabled": enabled, "level": level}, "type": None},
                timeout=15.0)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502,
                                detail=f"debug_mode relay failed: {exc}")

        key = (tid or "default", str(hostname))
        if enabled:
            hub.client_debug_sessions[key] = {
                "enabled_at": time.time(), "level": level}
            _u = _session_user(request) or {}
            logger.info("[client-debug] enabled host=%s tenant=%s level=%s by user=%s",
                        hostname, tid, level,
                        _u.get("user_id") or _u.get("username") or "?")
        else:
            hub.client_debug_sessions.pop(key, None)
            logger.info("[client-debug] disabled host=%s tenant=%s",
                        hostname, tid)
        return {"status": "ok", "hostname": hostname, "enabled": enabled,
                "level": level}

    @app.get("/api/cs/clients/{hostname}/debug-logs")
    async def cs_client_debug_logs(request: Request, hostname: str):
        """Read the per-host debug-log ring buffer (tenant-scoped).

        Returns ``{logs, active, level, enabled_at, active_until}``. ``active``
        reflects whether the session is still inside the 30-min auto-off window
        (a client that cleared its flag but whose session record is still live
        reports ``active=false``). The deque is ephemeral — empty after a hub
        restart (acceptable for troubleshooting; on-disk persistence is a
        documented follow-up)."""
        tid, _scope = _resolve(request, write=False)
        key = (tid or "default", str(hostname))
        ring = hub.client_debug_logs.get(key)
        logs = list(ring) if ring else []
        sess = hub.client_debug_sessions.get(key) or {}
        enabled_at = sess.get("enabled_at")
        active = False
        active_until = None
        if isinstance(enabled_at, (int, float)):
            active_until = enabled_at + _DEBUG_WINDOW_S
            active = (time.time() - float(enabled_at)) < _DEBUG_WINDOW_S
            if not active:
                # Window elapsed — stop accepting new frames for this host too
                # (the client tailer already self-stopped; this clears the
                # stale session record so the UI flips to inactive permanently).
                hub.client_debug_sessions.pop(key, None)
        return {"logs": logs, "active": active, "level": sess.get("level"),
                "enabled_at": enabled_at, "active_until": active_until}

    @app.delete("/api/cs/clients/{hostname}/debug")
    async def cs_client_debug_stop(request: Request, hostname: str):
        """Stop debug mode on one cs client (sends ``enabled:false``)."""
        tid, _scope = _resolve(request, write=True)
        cs_spoke = hub.get_client_sim_spoke(tid) if hasattr(hub, "get_client_sim_spoke") else None
        if cs_spoke:
            try:
                await hub.request_response(
                    cs_spoke, "CS_QUEUE_COMMAND",
                    {"target": hostname, "action": "debug_mode",
                     "args": {"enabled": False, "level": "basic"}, "type": None},
                    timeout=15.0)
            except Exception as exc:  # noqa: BLE001 — best-effort stop
                logger.info("[client-debug] stop relay failed for %s: %s", hostname, exc)
        hub.client_debug_sessions.pop((tid or "default", str(hostname)), None)
        return {"status": "ok", "hostname": hostname, "enabled": False}