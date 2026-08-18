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
import os
import time
import stat
import secrets

from api import HTTPException, Request, logger

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

    @app.get("/admin/ops/le-diag")
    async def admin_ops_le_diag(request: Request):
        """TEMPORARY diagnostic: report the runtime shared-tenant id, the le
        filter flag, and per-cert-domain tenant ownership / visibility for a
        synthesized ADMIN and NON-admin session — all in the RUNNING process,
        so it reflects the live _SHARED_TENANT_ID and hub state. Used to root
        cause why assigned tenants don't surface on GET /api/le/certs."""
        _guard(request)
        import access
        import le_cert_access as lca

        def _extract_certs(env):
            if not isinstance(env, dict):
                return []
            if isinstance(env.get("certs"), list):
                return env["certs"]
            inner = env.get("data")
            if isinstance(inner, dict) and isinstance(inner.get("certs"), list):
                return inner["certs"]
            return []

        env = hub.le_cache_get("certs")
        certs = _extract_certs(env)
        domains = [c.get("domain") for c in certs if isinstance(c, dict)]

        admin_sess = {"user": {"permissions": {"admin": True}, "tenants": []}}
        non_admin_sess = {"user": {"permissions": {}, "tenants": ["lrb"]}}

        gc = hub.state.system_state.get("global_config", {}) or {}
        store = gc.get(getattr(lca, "STORE_KEY", "le_cert_tenants"), {}) or {}

        per_domain = {}
        for d in domains:
            per_domain[d] = {
                "owners": lca.get_tenants(hub, d),
                "meta_admin": lca.meta(hub, admin_sess, d),
                "visible_admin": lca.visible_to(hub, admin_sess, d, []),
                "visible_nonadmin_lrb": lca.visible_to(hub, non_admin_sess, d, ["lrb"]),
                "is_shared": lca.is_shared(hub, d),
            }

        return {
            "shared_tenant_id_runtime": access.shared_tenant_id(),
            "le_filter_enabled": access.filter_enabled(hub, "le"),
            "cert_domains": domains,
            "store_keys": sorted(store.keys()),
            "per_domain": per_domain,
        }

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
