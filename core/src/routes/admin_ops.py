"""Loopback-only hub operations API (``/admin/ops/*``).

Purpose: give an operator (or an automation running *on the hub box itself*) a
programmatic way to drive the same fleet actions the WebUI exposes —
triggering a fleet self-update, approving a pending relayed node-agent, and
reading live agent/connection telemetry — without a browser session. This
unblocks debugging the "approve → back to pending" agent flap: the fix can be
driven and watched from a hub shell instead of round-tripping through a human
clicking the UI.

Security posture — TWO independent gates, both required on every route:
  1. **Loopback peer only.** The app binds ``0.0.0.0:443`` with NO reverse
     proxy in front (main.py build_server), so ``request.client.host`` is the
     true TCP peer. We accept ONLY loopback (127.0.0.1 / ::1 / ::ffff:127.0.0.1)
     and deliberately ignore X-Forwarded-* — a remote caller can neither reach
     these routes nor spoof the peer address at the TCP layer.
  2. **Root-minted bearer token.** A random token is minted once and persisted
     0600 under the hub data dir (readable only by the hub's service user /
     root). Callers present it as ``X-LM-Admin-Token``; compared with
     ``secrets.compare_digest``. The token VALUE is never logged (only its
     path), so it can't leak into hub.log.

These are privileged, side-effecting operations, so they are intentionally NOT
session/cookie gated (no CSRF surface — there's no browser session) and NOT
reachable off-box.
"""
import asyncio
import os
import re
import time
import stat
import secrets

from api import HTTPException, Request, logger

# Argument-shape guard for the diagnostic bundle's unit / repo / log / lines
# parameters. Deliberately strict: letters, digits, and the handful of path /
# unit punctuation we need — NO shell metacharacters (the command_runner
# allowlist re-checks, but validating here keeps a malformed value from ever
# reaching a spoke). ``re.fullmatch`` so the WHOLE value must match.
_DIAG_ARG_RE = re.compile(r"^[A-Za-z0-9._/@:-]{1,200}$")
# The curated read-only diagnostic bundle. Each entry is (key, argv-template).
# Every binary is already in command_runner.ALLOWED_BINARIES and no template
# contains a shell metacharacter, so the whole bundle runs in allowlist mode
# (allow_shell is NEVER set on this path). ``{unit}``/``{repo}``/``{log}``/
# ``{lines}`` are substituted from the (validated) request body.
_DIAG_BUNDLE = (
    ("is_active",     "systemctl is-active {unit}"),
    ("service_state", "systemctl show {unit} -p ActiveState -p SubState "
                      "-p NRestarts -p ExecMainStatus -p ActiveEnterTimestamp"),
    ("git_head",      "git -C {repo} rev-parse --short HEAD"),
    ("uptime",        "uptime"),
    ("journal",       "journalctl -u {unit} -n {lines} --no-pager"),
    ("log_tail",      "tail -n {lines} {log}"),
)

# Loopback peers we accept. IPv4, IPv6, and the IPv4-mapped-IPv6 form uvicorn
# may report. Nothing else — and X-Forwarded-* is ignored on purpose.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

_ADMIN_TOKEN_HEADER = "x-lm-admin-token"
_ADMIN_TOKEN_ENV = "LM_ADMIN_OPS_TOKEN"


def _token_path(hub) -> str:
    return os.path.join(hub.state.data_dir, "admin_ops_token")


def _load_or_mint_token(hub) -> str:
    """Return the admin-ops token, minting+persisting one (0600) on first use.

    An explicit ``LM_ADMIN_OPS_TOKEN`` env var wins (lets an operator inject a
    known token); otherwise we read the on-disk token, or mint a new random one
    and write it 0600 so only the hub service user / root can read it. Only the
    PATH is logged, never the value."""
    env = os.environ.get(_ADMIN_TOKEN_ENV)
    if env:
        return env.strip()
    path = _token_path(hub)
    try:
        with open(path, "r") as fh:
            tok = fh.read().strip()
        if tok:
            return tok
    except FileNotFoundError:
        pass
    except Exception:  # noqa: BLE001 — unreadable/corrupt → re-mint below
        logger.warning("admin_ops: existing token at %s unreadable — re-minting", path)
    tok = secrets.token_urlsafe(32)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Write with 0600 from the start (open + restrictive mode), then chmod
        # defensively in case a prior umask widened it.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, tok.encode())
        finally:
            os.close(fd)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        logger.warning("admin_ops: minted new loopback admin-ops token at %s (0600)", path)
    except Exception:  # noqa: BLE001
        logger.exception("admin_ops: could not persist token to %s — using in-memory only", path)
    return tok


def _peer_is_loopback(request: Request) -> bool:
    client = request.client
    host = client.host if client else None
    return host in _LOOPBACK_HOSTS


def register(app, hub, ctx):
    # Mint/load once at registration so the token exists on disk immediately
    # (an operator can `cat` it right after the hub starts).
    _token = _load_or_mint_token(hub)

    def _guard(request: Request):
        """Both gates: loopback peer AND a matching root-minted token."""
        if not _peer_is_loopback(request):
            peer = request.client.host if request.client else "unknown"
            logger.warning("admin_ops: rejected non-loopback peer %s for %s",
                           peer, request.url.path)
            raise HTTPException(status_code=403, detail="loopback only")
        supplied = request.headers.get(_ADMIN_TOKEN_HEADER, "")
        if not supplied or not secrets.compare_digest(supplied, _token):
            raise HTTPException(status_code=403, detail="invalid admin token")

    @app.get("/admin/ops/ping")
    async def admin_ops_ping(request: Request):
        """Liveness + auth check. Confirms both gates pass and the hub is up."""
        _guard(request)
        return {"status": "ok", "time": time.time(),
                "hub_pid": os.getpid()}

    @app.get("/admin/ops/connections")
    async def admin_ops_connections(request: Request):
        """Hub-side connection telemetry (no spoke fan-out, always instant):
        which spokes hold a live WebSocket right now, plus the approved-module
        map and each spoke's module type. Enough to see whether the agent's
        owning spoke is currently connected."""
        _guard(request)
        active = sorted(hub.active_connections.keys())
        approved = dict(hub.state.system_state.get("approved_modules", {}) or {})
        md = hub.state.system_state.get("module_metadata", {}) or {}
        spoke_types = {sid: (m or {}).get("module_type") for sid, m in md.items()}
        return {"active_connections": active,
                "active_count": len(active),
                "approved_modules": approved,
                "spoke_module_types": spoke_types}

    @app.get("/admin/ops/agents")
    async def admin_ops_agents(request: Request):
        """Live agent roster (connected + pending + offline-relayed) — the same
        GET_AGENTS fan-out the WebUI Agents tile uses, so the pending agent's
        ``agent_id`` and owning ``spoke_id`` are visible for approve-agent."""
        _guard(request)
        # Imported lazily to avoid any import-order coupling at module load.
        from routes.pxmx import _maybe_refresh_agents, _offline_relay_agents
        agent_spokes = list(dict.fromkeys(
            hub.get_all_spokes_by_type("hypervisor") + hub.get_all_spokes_by_type("simulation")
        ))
        if not agent_spokes:
            live = {"agents": [], "pending_agents": [], "spoke_connected": False}
        else:
            live = await _maybe_refresh_agents(hub, agent_spokes, force=True) \
                or {"agents": [], "pending_agents": [], "spoke_connected": True}
        live_ids = {a.get("agent_id") for a in live.get("agents", []) if a.get("agent_id")}
        live_ids |= {a.get("agent_id") for a in live.get("pending_agents", []) if a.get("agent_id")}
        out = dict(live)
        out["offline_agents"] = _offline_relay_agents(hub, live_ids)
        out["agent_spokes"] = agent_spokes
        return out

    @app.post("/admin/ops/approve-agent")
    async def admin_ops_approve_agent(request: Request):
        """Approve a pending relayed node-agent — identical logic to the WebUI
        approve button (persist the approved flag + durably relay
        APPROVAL_SUCCESS through the mailbox so it survives the owning spoke's
        reconnect flap). Body: {"spoke_id": ..., "agent_id": ...}. ``spoke_id``
        is a hint; the real owner is resolved from the agent index and used if
        found. Idempotent — safe to retry."""
        _guard(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        agent_id = (body or {}).get("agent_id")
        spoke_id = (body or {}).get("spoke_id")
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id required")
        from routes.setup import _perform_agent_approval, _bust_spokes_cache
        try:
            summary = await _perform_agent_approval(hub, spoke_id, agent_id)
        except Exception as e:
            logger.exception("admin_ops: approve-agent failed for %s", agent_id)
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            _bust_spokes_cache()
        logger.warning("admin_ops: approve-agent driven via loopback for agent=%s → %s",
                       agent_id, summary)
        return {"status": "ok", **summary}

    @app.post("/admin/ops/self-update")
    async def admin_ops_self_update(request: Request):
        """Trigger the fleet self-update (the Setup → Sync 'Sync now' action):
        pull the hub's provisioning repos, run the version-gated hub pull, and
        fan ``SPOKE_UPDATE`` out to every approved spoke so they self-pull and
        restart on a version change. ``force=True`` bypasses the maintenance
        window (operator-initiated). Use this to push new agent/spoke code
        (e.g. the agent-secret mint) out to cs-svr-06 before approving."""
        _guard(request)
        try:
            result = await hub.run_repo_sync_all(force_spokes=True, force=True)
        except Exception as e:
            logger.exception("admin_ops: self-update failed")
            raise HTTPException(status_code=500, detail=str(e))
        logger.warning("admin_ops: self-update driven via loopback")
        return {"status": "ok", "result": result}

    # ── Diagnostics fan-out ──────────────────────────────────────────────────
    # Run a READ-ONLY diagnostic on the hub, any connected spoke, or a relayed
    # node-agent, from the hub box itself. Reuses the same HMAC-signed
    # RUN_COMMAND / AGENT_RUN_COMMAND relay the WebUI Remote Console uses, but
    # exposed on the loopback+token surface so this can be driven from a hub
    # shell — and, unlike Remote Console, ``allow_shell`` is ALWAYS False here,
    # so only command_runner's ALLOWED_BINARIES (systemctl, journalctl, tail,
    # git, ip, ss, …) can run and shell metacharacters are rejected. Three gates
    # therefore hold on every call: loopback peer, root-minted token, and the
    # spoke-side command allowlist. It never requires the ``remote_exec``
    # feature toggle (that toggle only gates the browser/arbitrary-shell path).
    def _unwrap_run_result(resp) -> dict:
        """{"payload":{"data":{"result": {...}}}} → the command_runner dict."""
        payload = (resp or {}).get("payload", {}) or {}
        inner = payload.get("data", resp) or {}
        r = inner.get("result") if isinstance(inner, dict) else None
        if not isinstance(r, dict):
            return {"ok": False, "rc": None, "stdout": "", "stderr": "",
                    "truncated": False, "error": "no result (offline / timed out?)"}
        return r

    async def _relay_exec(target: str, command: str, timeout: float) -> dict:
        """Run one ALLOWLISTED command on ``target`` and return the runner dict.

        ``target`` is ``hub``, a connected ``spoke_id``, or
        ``agent:<owning_spoke_id>:<agent_id>``. ``allow_shell`` is never set."""
        conns = getattr(hub, "active_connections", {}) or {}
        if target == "hub":
            try:
                from command_runner import run_local_command
            except ImportError:  # test/bare-package path
                from core.src.command_runner import run_local_command  # type: ignore
            return await asyncio.to_thread(run_local_command, command, False, timeout)
        if target.startswith("agent:"):
            _, _, rest = target.partition(":")
            sid, _, aid = rest.partition(":")
            if not sid or not aid:
                raise HTTPException(status_code=400, detail="bad agent target (want agent:<spoke>:<agent_id>)")
            if hub._primary_key(sid) not in conns:
                raise HTTPException(status_code=404, detail=f"agent's spoke '{sid}' not connected")
            resp = await hub.request_response(
                sid, "AGENT_RUN_COMMAND",
                {"agent_id": aid, "command": command, "allow_shell": False, "timeout": timeout},
                timeout=timeout + 20.0)
            return _unwrap_run_result(resp)
        if hub._primary_key(target) not in conns:
            raise HTTPException(status_code=404, detail=f"spoke '{target}' not connected")
        resp = await hub.request_response(
            target, "RUN_COMMAND",
            {"command": command, "allow_shell": False, "timeout": timeout},
            timeout=timeout + 10.0)
        return _unwrap_run_result(resp)

    @app.post("/admin/ops/exec")
    async def admin_ops_exec(request: Request):
        """Run a single READ-ONLY (allowlisted) command on a target and return
        the command_runner result ``{ok, rc, stdout, stderr, truncated, error}``.

        Body: ``{"target": "hub"|"<spoke_id>"|"agent:<spoke>:<agent_id>",
        "command": "<allowlisted cmd>", "timeout": <sec, optional>}``. The
        command must use a binary in command_runner.ALLOWED_BINARIES and contain
        no shell metacharacters — otherwise the spoke rejects it. Use this to
        query live log/service state from any connected spoke during this
        session (e.g. ``journalctl -u lm-agent -n 60 --no-pager``)."""
        _guard(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        target = str((body or {}).get("target") or "hub").strip()
        command = str((body or {}).get("command") or "").strip()
        if not command:
            raise HTTPException(status_code=400, detail="command required")
        try:
            timeout = float((body or {}).get("timeout") or 30.0)
        except (TypeError, ValueError):
            timeout = 30.0
        timeout = max(1.0, min(timeout, 120.0))
        logger.warning("admin_ops: exec via loopback target=%s cmd=%r", target, command[:300])
        try:
            res = await _relay_exec(target, command, timeout)
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            logger.exception("admin_ops: exec failed for target=%s", target)
            raise HTTPException(status_code=500, detail=str(e))
        return {"status": "ok", "target": target, "result": res}

    @app.post("/admin/ops/spoke-diag")
    async def admin_ops_spoke_diag(request: Request):
        """Run the curated read-only diagnostic BUNDLE on a target and return a
        per-check map — the service state (is-active / NRestarts), running git
        HEAD, uptime, recent journal, and a log tail — in one round-trip.

        Body: ``{"target": "hub"|"<spoke_id>"|"agent:<spoke>:<agent_id>",
        "unit": "lm-agent", "repo": "/opt/lm", "log": "/var/log/lm/lm-agent.log",
        "lines": 40}``. ``unit``/``repo``/``log`` are validated to a strict
        charset (no shell metacharacters); ``lines`` is clamped to 1..200. Each
        bundled command runs in allowlist mode, so this is safe to fan at a
        flapping spoke to see WHY it is restarting without opening a shell."""
        _guard(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        target = str((body or {}).get("target") or "hub").strip()
        unit = str((body or {}).get("unit") or "lm-agent").strip()
        repo = str((body or {}).get("repo") or "/opt/lm").strip()
        log = str((body or {}).get("log") or "/var/log/lm/lm-agent.log").strip()
        try:
            lines = int((body or {}).get("lines") or 40)
        except (TypeError, ValueError):
            lines = 40
        lines = max(1, min(lines, 200))
        for label, val in (("unit", unit), ("repo", repo), ("log", log)):
            if not _DIAG_ARG_RE.fullmatch(val):
                raise HTTPException(status_code=400,
                                    detail=f"invalid {label!r}: letters, digits, and . _ / @ : - only")
        subs = {"unit": unit, "repo": repo, "log": log, "lines": str(lines)}
        logger.warning("admin_ops: spoke-diag via loopback target=%s unit=%s", target, unit)
        checks: dict = {}
        for key, tmpl in _DIAG_BUNDLE:
            command = tmpl.format(**subs)
            try:
                checks[key] = await _relay_exec(target, command, 30.0)
            except HTTPException:
                # Target unreachable — surface once and stop (every check would
                # 404 the same way).
                raise
            except Exception as e:  # noqa: BLE001
                checks[key] = {"ok": False, "rc": None, "stdout": "", "stderr": "",
                               "truncated": False, "error": str(e)}
        return {"status": "ok", "target": target, "unit": unit,
                "repo": repo, "log": log, "lines": lines, "checks": checks}
