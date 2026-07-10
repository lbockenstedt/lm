"""Remote Console — run a diagnostic (allowlist) or, when Debug/shell mode is on,
an arbitrary command on the hub or any connected spoke, from the WebUI.

Security posture (matches how the feature was requested):
  * OFF by default — every route 403s until a Global-Admin flips
    ``remote_exec.enabled`` in Setup → Remote Console.
  * Global-Admin ONLY (checked here AND via _ADMIN_API_PREFIXES in api.py).
  * ``allow_shell`` (the "Debug (shell)" knob) is what unlocks arbitrary
    commands; without it the shared command_runner enforces its allowlist.
  * Every config change and every invocation is audit-logged (user + target +
    command + rc) to the hub log at WARNING.
Commands reach a spoke as a HMAC-signed RUN_COMMAND (control_plane), so a spoke
trusts them exactly like SPOKE_UPDATE; the hub runs "hub" targets locally.
"""
import asyncio
from api import HTTPException, Request, logger

try:
    from command_runner import run_local_command
except ImportError:  # test/bare-package path
    from core.src.command_runner import run_local_command  # type: ignore


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _cfg():
        return (hub.state.get_global_config() or {}).get("remote_exec", {}) or {}

    def _who(sess):
        return (sess or {}).get("user_id") or (sess or {}).get("username") or (sess or {}).get("user") or "?"

    def _require_admin(request):
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin required")
        return sess

    @app.get("/api/exec/config")
    async def get_exec_config(request: Request):
        _require_admin(request)
        c = _cfg()
        return {"enabled": bool(c.get("enabled", False)),
                "allow_shell": bool(c.get("allow_shell", False))}

    @app.post("/api/exec/config")
    async def set_exec_config(request: Request):
        sess = _require_admin(request)
        data = await request.json()
        gc = hub.state.get_global_config()
        cur = dict(gc.get("remote_exec", {}) or {})
        if "enabled" in data:
            cur["enabled"] = bool(data["enabled"])
        if "allow_shell" in data:
            cur["allow_shell"] = bool(data["allow_shell"])
        # Fail safe: disabling the feature also drops shell mode, so re-enabling
        # never silently comes back with arbitrary-shell already unlocked.
        if not cur.get("enabled"):
            cur["allow_shell"] = False
        gc["remote_exec"] = cur
        hub.state.system_state["global_config"] = gc
        hub.state.save_state()
        logger.warning("[remote-exec] config changed by %s → enabled=%s allow_shell=%s",
                       _who(sess), cur.get("enabled"), cur.get("allow_shell"))
        return {"status": "ok", "enabled": bool(cur.get("enabled")),
                "allow_shell": bool(cur.get("allow_shell"))}

    @app.get("/api/exec/targets")
    async def get_exec_targets(request: Request):
        _require_admin(request)
        # hub + every connected spoke (generic agents + role sub-spokes connect
        # as spokes, so this list covers them by spoke_id).
        targets = [{"id": "hub", "label": "Hub (this box)", "kind": "hub"}]
        for sid in sorted(getattr(hub, "active_connections", {}) or {}):
            targets.append({"id": sid, "label": sid, "kind": "spoke"})
        return {"targets": targets}

    @app.post("/api/exec")
    async def run_exec(request: Request):
        sess = _require_admin(request)
        c = _cfg()
        if not c.get("enabled"):
            raise HTTPException(status_code=403,
                                detail="Remote Console is disabled — enable it in Setup → Remote Console")
        data = await request.json()
        target = (data.get("target") or "hub").strip()
        command = (data.get("command") or "").strip()
        allow_shell = bool(c.get("allow_shell", False))
        if not command:
            raise HTTPException(status_code=400, detail="command is required")
        who = _who(sess)
        # AUDIT — before running, unconditionally.
        logger.warning("[remote-exec] RUN user=%s target=%s shell=%s cmd=%r",
                       who, target, allow_shell, command[:500])
        try:
            if target == "hub":
                res = await asyncio.to_thread(run_local_command, command, allow_shell, 30.0)
            else:
                if target not in (getattr(hub, "active_connections", {}) or {}):
                    raise HTTPException(status_code=404, detail=f"spoke '{target}' not connected")
                resp = await hub.request_response(
                    target, "RUN_COMMAND",
                    {"command": command, "allow_shell": allow_shell, "timeout": 30.0},
                    timeout=40.0)
                # Unwrap {"payload":{"data":{"status","result"}}} → the runner dict.
                payload = (resp or {}).get("payload", {}) or {}
                inner = payload.get("data", resp) or {}
                res = inner.get("result") if isinstance(inner, dict) else None
                if not isinstance(res, dict):
                    res = {"ok": False, "rc": None, "stdout": "", "stderr": "",
                           "truncated": False, "error": "no result from spoke (offline / timed out?)"}
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.error("[remote-exec] user=%s target=%s FAILED: %s", who, target, e)
            raise HTTPException(status_code=500, detail=str(e))
        logger.warning("[remote-exec] DONE user=%s target=%s rc=%s error=%s",
                       who, target, res.get("rc"), res.get("error") or "")
        return res
