"""Setup admin: debug-mode, docs, appearance, logs, diagnostics, recovery, bug reports."""
import asyncio
from api import (
    HTTPException, Request, logger, os, re, set_log_level, time,
)
from update_pipeline import _version_behind

# ── /setup/diagnostics cache (stale-while-revalidate) ───────────────────────
# The Diagnostics card + the Spokes & Agents page poll /setup/diagnostics on
# every load/tick; the handler gathers system metrics + the local version, then
# per-spoke iterates events/log_events/heartbeat/recovery/version. Mirror the
# /api/pxmx/agents SWR cache (routes/pxmx.py): instant serve from a fresh
# cache, one background refresh at the fresh-TTL boundary, a forced refresh
# only when there's no servable cache. One hub per process → module-level.
_DIAG_CACHE: dict = {"data": None, "ts": 0.0, "refreshing": False}
_DIAG_FRESH_S = 5.0    # serve cached payload verbatim while younger than this
_DIAG_STALE_S = 30.0   # still servable (background refresh kicks in here)
# Per-loop lock (verbatim mirror of pxmx._agents_lock — see there for why a
# module-level asyncio.Lock() breaks across asyncio.run()/loop recreation).
_diag_locks: dict = {}


def _diag_lock() -> "asyncio.Lock":
    loop = asyncio.get_running_loop()
    lk = _diag_locks.get(id(loop))
    if lk is None:
        lk = asyncio.Lock()
        _diag_locks[id(loop)] = lk
    return lk


async def _maybe_refresh_diagnostics(hub, force=False):
    """Under ``_diag_lock``: serve the cached payload if fresh (unless
    ``force``); otherwise recompute via ``_aggregate_diagnostics`` and store.
    Serializes concurrent first-loaders into a single recompute. Returns the
    served payload (fresh, recomputed, or stale-on-failure). Mirrors
    pxmx._maybe_refresh_agents; ``force`` does not bypass a genuinely-fresh
    result (a concurrent refresh while this one waited is served as-is)."""
    async with _diag_lock():
        cached = _DIAG_CACHE["data"]
        age = (time.time() - _DIAG_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _DIAG_FRESH_S:
            return cached
        _DIAG_CACHE["refreshing"] = True
        try:
            result = await _aggregate_diagnostics(hub)
            _DIAG_CACHE["data"] = result
            _DIAG_CACHE["ts"] = time.time()
            return result
        except Exception:
            logger.exception("diagnostics cache refresh failed")
            return cached  # serve stale rather than blanking the card
        finally:
            _DIAG_CACHE["refreshing"] = False


def _bust_diag_cache():
    """Debounced invalidation of the diagnostics cache. Called from setup
    mutation endpoints (approve/revoke/delete/purge/ack/metadata rename +
    recovery pause). Rather than cold-busting (ts=0), which forced a BLOCKING
    full recompute on the next GET and — under admin churn — made every poll
    bypass the SWR cache, this DEMOTES the cache to "just past fresh": the next
    GET serves instantly and kicks a single background refresh, reflecting the
    mutation within the fresh-TTL window without thrash. A cold cache (data is
    None) still forced-refreshes on the next GET."""
    if _DIAG_CACHE.get("data") is not None:
        _DIAG_CACHE["ts"] = min(_DIAG_CACHE["ts"], time.time() - _DIAG_FRESH_S)
    else:
        _DIAG_CACHE["ts"] = 0.0


async def _compute_mtls_readiness(hub) -> dict:
    """Delegate to ``hub.mtls_readiness()`` (HubCertDistributionMixin) so the
    route, the enable guard, and the auto-enable loop share ONE implementation.
    See ``GET /setup/mtls-readiness`` for the rationale (primary spokes only,
    offline spokes don't block, ready = hub CA + server cert + every connected
    primary spoke has materials)."""
    return await hub.mtls_readiness()

async def _aggregate_diagnostics(hub):
    """Per-spoke + hub diagnostic snapshot (compute fn for the
    /setup/diagnostics SWR cache). Assembles, for each known
    spoke: connection status, heartbeat age + RED flag, watchdog/
    recovery state, flapping detection, version skew vs the hub,
    and CS telemetry presence; plus hub-side metrics. Module-level
    (not a route closure) so it depends only on ``hub`` and is
    unit-testable with a stub hub. Includes the leaked relay-agent
    self-heal (run on every fresh recompute so stale serves inherit
    a cleaned state)."""
    metrics = await hub.get_system_metrics()
    diagnostics = []
    known_spokes = hub.state.system_state.get("known_modules", [])

    # Resolved up-front so per-spoke version_skew can be computed in the loop.
    hub_version = await hub.get_local_version()
    now = time.time()

    # version_skew now means "not on the per-repo .NN numbering" — see the
    # per-spoke comment in the loop. Each repo's .NN is an independent
    # counter, so a spoke .NN ≠ hub .NN is normal; this flags only stale
    # X.Y.Z / v-tag / pre-reset values.
    import re as _re
    def _is_nn(v) -> bool:
        return bool(_re.match(r"^\.\d+$", str(v).strip()))

    # Relayed node agents (pxmx) connect THROUGH their hypervisor spoke, not
    # directly to the hub, so the hub has no WebSocket for the bare agent
    # id. The old approve flow leaked agent ids into known_modules /
    # approved_modules; a leaked id renders here as a bogus OFFLINE spoke
    # row (the footer module-status then shows it offline while the
    # Diagnostics → Agents table — fed by /api/pxmx/agents — shows it
    # online), AND the recovery watchdog would resolve the leaked id to the
    # parent spoke's unit (pxmx-cs-svr-02 -> lm-pxmx) and restart a healthy
    # pxmx spoke every cycle. Identify relayed agent ids from the composite
    # heartbeat keys ("{spoke}:{agent}") plus the agent_config registry, skip
    # them below, and self-heal the persisted registries so the watchdog
    # stops considering them. Mirrors the client-side filter in
    # loadDiagnostics (WebUI/main.js).
    agent_cfg_keys = set((hub.state.system_state.get("agent_config", {}) or {}).keys())
    relay_ids = {k.split(":", 1)[1] for k in hub.heartbeat.last_seen if ":" in k}
    relay_ids |= agent_cfg_keys
    # B2: agent_config / composite keys are guid-keyed post-arm, but a leaked
    # id in known_modules from the pre-guid approve flow is a raw NAME — include
    # the raw names (agent_info[guid]["agent_id"]) so those still match + clean.
    for _aid, _info in (getattr(hub, "agent_info", {}) or {}).items():
        _raw = (_info or {}).get("agent_id")
        if _raw:
            relay_ids.add(_raw)
    if relay_ids:
        known = list(hub.state.system_state.get("known_modules", []))
        leaked = [m for m in known if m in relay_ids]
        if leaked:
            cleaned = [m for m in known if m not in relay_ids]
            hub.state.system_state["known_modules"] = cleaned
            hub.known_modules = cleaned
            for aid in leaked:
                hub.approved_modules.pop(aid, None)
            hub.state._mark_dirty()
            logger.info("[diag] removed leaked relay-agent id(s) from "
                        "known_modules/approved_modules: %s", leaked)

    for sid in known_spokes:
        if sid in relay_ids:
            continue  # relayed node agent — surfaced via /api/pxmx/agents, not here
        ws = hub.active_connections.get(hub._primary_key(sid))
        telemetry = hub.spoke_telemetry.get(hub._primary_key(sid), {})
        events = hub.get_spoke_events(sid, limit=50)
        log_events = hub.get_spoke_log_events(sid, limit=30)

        # Flapping detector: count connect/close cycles in the last 5 min.
        # A "flap" is a connection_closed / connection_error / auth_failed
        # event — i.e. the spoke reached the hub then dropped. Many of
        # these in a short window with intervening auth_attempt/connected
        # events is the flapping signature (spoke process is alive and
        # retrying, but never holds the connection).
        recent = [e for e in events if now - e["ts"] <= 300]
        flap_drops = sum(1 for e in recent if e["event"] in
                         ("connection_closed", "connection_error",
                          "auth_failed", "mutual_auth_failed", "mutual_auth_timeout"))
        flapping = flap_drops >= 3

        # Heartbeat age: seconds since the last inbound heartbeat frame, or
        # None if the spoke has never heartbeated. get_status() already
        # classifies GREEN/YELLOW/RED from this; surfacing the raw age lets
        # the UI show "last seen 312s ago" rather than just a colored dot.
        last_seen = hub.heartbeat.last_seen.get(sid)
        heartbeat_age_s = None
        if isinstance(last_seen, (int, float)):
            heartbeat_age_s = max(0, int(now - last_seen))

        # Watchdog recovery state (run_spoke_recovery_loop). Empty dict when
        # the spoke has never been stranded/recovered. The WebUI renders a
        # badge + attempt counter + last action/error from this; bugfixer
        # also reads it via GET_SPOKE_STATUS to suppress/escalate.
        rec = hub.spoke_recovery.get(hub._primary_key(sid), {}) or {}

        # Out-of-contact alert (SpokeAlertMixin) — separate from the realtime
        # heartbeat_status traffic-light above. tier is "warning" (>=5 min out
        # of contact) or "error" (>=30 min); absent when the spoke is in
        # contact. Drives the diagnostics badge.
        alert = (getattr(hub, "_spoke_alerts", {}) or {}).get(sid, {}) or {}

        spoke_version = hub.spoke_versions.get(hub._primary_key(sid), "unknown")
        # version_skew: True when a connected spoke reports a version that
        # is NOT in the new per-repo ".NN" numbering (e.g. a stale X.Y.Z /
        # v-tag / pre-reset value). Each repo has an INDEPENDENT .NN
        # counter, so a spoke's .NN differing from the hub's .NN is normal
        # and NOT a mismatch — the flag now points at un-migrated
        # components. "unknown" / disconnected spokes are not skewed (we
        # just don't know). _is_nn is defined up-front above the loop.
        version_skew = (
            spoke_version not in ("unknown", None, "")
            and not _is_nn(spoke_version)
        )

        # version_behind: a GENUINE "this spoke is older than the latest
        # build of ITS OWN repo" signal. Each repo has an INDEPENDENT .NN
        # counter, so this compares the spoke's .NN to the latest .NN the hub
        # can resolve LOCALLY for the repo backing this module_type (the lm
        # repo for dns/dhcp/console/agent; a sibling checkout for the rest).
        # latest_version is None when the hub can't determine it (unknown
        # module_type or no local checkout) → version_behind stays False so
        # we NEVER false-positive. This is orthogonal to version_skew, which
        # flags a stale non-.NN reported version. Both mean "out of date".
        module_type = hub.spoke_module_types.get(hub._primary_key(sid), "")
        latest_version = hub.latest_version_for_module(module_type)
        version_behind = _version_behind(spoke_version, latest_version)

        diagnostics.append({
            "spoke_id": sid,
            "display_name": hub.state.get_module_name(sid),
            "authenticated": hub._primary_key(sid) in hub.active_connections,
            # Grace-based display status: connected now OR seen within the
            # grace window. The WebUI header dots use this so a transient
            # stall / brief reconnect doesn't flip a module offline.
            "in_contact": hub.is_spoke_in_contact(sid),
            "approved": hub.approved_modules.get(hub._primary_key(sid), False),
            "heartbeat_status": hub.heartbeat.get_status(sid),
            "heartbeat_age_s": heartbeat_age_s,
            # Forgiving out-of-contact alert (separate from heartbeat_status):
            # warning >=5 min, error >=30 min. None when in contact.
            "alert_tier": alert.get("tier"),
            "alert_since": alert.get("since_ts"),
            "alert_duration_s": int(alert.get("duration_s", 0) or 0) if alert else 0,
            "connection_state": ws.state if ws else "OFFLINE",
            "version": spoke_version,
            "version_skew": version_skew,
            "version_behind": version_behind,
            "latest_version": latest_version,
            "hub_version": hub_version,
            "last_attempt": telemetry.get("last_attempt"),
            "last_status": telemetry.get("status", "UNKNOWN"),
            "last_error": telemetry.get("error"),
            "flapping": flapping,
            "recent_drops": flap_drops,
            # The full events(50)+log_events(30) arrays are NOT sent in the LIST
            # payload (heavy: 80 objects × every spoke on every poll). Only the
            # total count for the "N events ▾" badge ships here; the WebUI lazily
            # fetches the arrays from GET /setup/diagnostics/{spoke_id} on
            # row-expand (see get_diagnostics_detail below + toggleSpokeEvents in
            # WebUI/main.js). ``events`` is still computed above for flapping.
            "event_count": len(events) + len(log_events),
            "cpu_util": telemetry.get("cpu_util"),
            "mem_util": telemetry.get("mem_util"),
            # Watchdog recovery (see run_spoke_recovery_loop). in_progress =
            # hub is actively restarting the unit (backoff); gave_up = a
            # restart structurally can't fix it (e.g. venv missing) and
            # bugfixer has/will be handed off; manual_pause = admin paused.
            "recovery": {
                "attempts": rec.get("attempts", 0),
                "in_progress": bool(rec.get("in_progress", False)),
                "gave_up": bool(rec.get("gave_up", False)),
                "manual_pause": bool(rec.get("manual_pause", False)),
                "last_action": rec.get("last_action", ""),
                "last_error": rec.get("last_error", ""),
                "last_crash_sig": rec.get("last_crash_sig", ""),
                "next_retry_ts": rec.get("next_retry_ts", 0),
                "last_attempt_ts": rec.get("last_attempt_ts", 0),
            },
            # Client-Sim combined spoke: module type, tenant binding, and
            # whether the latest CS_TELEMETRY frame is cached.
            "module_type": module_type,
            "tenant_id": hub.state.get_spoke_tenant(sid),
            "cs_telemetry_cached": sid in hub.simulations_cache,
            "cs_telemetry_ts": (hub.simulations_cache.get(sid, {}) or {}).get("timestamp"),
        })

    webui_version = "unknown"
    try:
        # The WebUI lives at lm/WebUI (not lm/ui). Resolve from core/src →
        # lm/WebUI/VERSION; the autobump bumps this in lockstep with the
        # other lm VERSION files so "WebUI .NN" tracks the hub's .NN.
        version_path = os.path.join(os.path.dirname(__file__), "../../WebUI/VERSION")
        if not os.path.exists(version_path):
            version_path = os.path.join(os.path.dirname(__file__), "../../../GitHub/webui/VERSION")
        with open(version_path, "r") as f:
            webui_version = f.read().strip()
    except Exception:
        pass

    return {
        "spokes": diagnostics,
        "hub_version": hub_version,
        "webui_version": webui_version,
        "system": metrics
    }



def register(app, hub, ctx):
    """Register setup_admin routes on the Hub app."""

    @app.get("/setup/debug-mode")
    async def get_debug_mode():
        hub = app.state.hub
        enabled = hub.state.get_global_config().get("debug_mode", False)
        return {"enabled": enabled}

    @app.post("/setup/debug-mode")
    async def toggle_debug_mode(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            enabled = data.get("enabled", False)

            global_config = hub.state.get_global_config()
            global_config["debug_mode"] = enabled
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Flip the HUB's own root + named loggers (not just the broadcast
            # targets) so the hub's logger.debug(...) lines actually emit.
            set_log_level(enabled)
            await hub.broadcast_log_level(enabled)

            return {"status": "ok", "enabled": enabled}
        except Exception as e:
            logger.exception("toggle_debug_mode failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/docs/{section}")
    async def get_docs(section: str):
        try:
            readme_path = next(
                (r for r in (
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../README.md")),
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../README.md")),
                ) if os.path.exists(r)),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../README.md")))
            if not os.path.exists(readme_path):
                raise HTTPException(status_code=404, detail="README.md documentation not found")

            with open(readme_path, "r") as f:
                content = f.read()

            marker = "### \U0001f4d6 Help:"
            sections = content.split(marker)

            for s in sections[1:]:
                lines = s.split('\n')
                header = lines[0].strip()
                if header == section:
                    body = '\n'.join(lines[1:]).strip()
                    return {"content": body}

            raise HTTPException(status_code=404, detail=f"Help section '{section}' not found in documentation.")
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading documentation section {section}: {e}")
            raise HTTPException(status_code=500, detail=f"Error retrieving documentation: {str(e)}")

    # ── Canonical documentation (single source of truth) ─────────────────────
    # The WebUI in-app Help drawer pulls from ``lm/docs/*.md`` — the SAME
    # canonical, hand-authored docs referenced everywhere else (per-repo copies
    # are downstream mirrors). No second doc set: the tooltip/help panel renders
    # these files directly. ``/docs`` lists them; ``/docs/{name}`` returns one.
    # docs/ lives at the lm repo ROOT (/opt/lm/docs), i.e. ../../../docs from
    # core/src/routes/. The old ../../docs resolved to core/docs (nonexistent) →
    # every Help fetch 404'd. Probe the canonical path first, then a legacy
    # fallback, so a future layout change can't silently break the Help drawer.
    _DOCS_DIR = next(
        (d for d in (
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../docs")),
        ) if os.path.isdir(d)),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../docs")))

    def _safe_doc_path(name: str) -> str:
        """Resolve ``name`` to a .md file strictly inside _DOCS_DIR (no traversal)."""
        stem = (name or "").strip().lower()
        if stem.endswith(".md"):
            stem = stem[:-3]
        # Canonical doc names are kebab-case ascii; reject anything else outright.
        if not stem or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", stem):
            raise HTTPException(status_code=400, detail="Invalid document name.")
        path = os.path.abspath(os.path.join(_DOCS_DIR, f"{stem}.md"))
        if os.path.dirname(path) != _DOCS_DIR or not os.path.isfile(path):
            raise HTTPException(status_code=404, detail=f"Document '{stem}' not found.")
        return path

    @app.get("/docs")
    async def list_docs():
        """List the canonical docs (name + first-heading title) for the Help index."""
        out = []
        try:
            for fn in sorted(os.listdir(_DOCS_DIR)):
                if not fn.endswith(".md"):
                    continue
                name = fn[:-3]
                title = name
                try:
                    with open(os.path.join(_DOCS_DIR, fn), "r", encoding="utf-8") as f:
                        for line in f:
                            if line.startswith("# "):
                                title = line[2:].strip()
                                break
                except Exception:  # noqa: BLE001
                    pass
                out.append({"name": name, "title": title})
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Docs directory not found.")
        return {"docs": out}

    @app.get("/docs/{name}")
    async def get_doc(name: str):
        """Return one canonical doc as raw markdown (rendered client-side)."""
        path = _safe_doc_path(name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                markdown = f.read()
        except Exception as e:  # noqa: BLE001
            logger.error(f"Error reading doc {name}: {e}")
            raise HTTPException(status_code=500, detail="Error reading document.")
        title = os.path.basename(path)[:-3]
        for line in markdown.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        return {"name": os.path.basename(path)[:-3], "title": title, "markdown": markdown}

    @app.get("/setup/mtls-readiness")
    async def get_mtls_readiness():
        """mTLS readiness: is the system safe to enable mutual TLS without
        orphaning a spoke/agent? Reports the master switch, the hub's cert
        materials, AND each connected PRIMARY spoke's mTLS materials (queried
        via SPOKE_GET_MTLS_STATUS) so the card renders a per-spoke green/amber
        dot and the operator can see exactly which spoke isn't ready before
        enabling. Role sub-spokes are excluded — they share their parent
        agent's process + cert, so the parent's dot covers them.

        ``ready`` = hub has the CA + server cert AND every connected primary
        spoke has the CA + client cert/key. Offline spokes do NOT block —
        distribution is mailbox-durable, so a spoke temporarily mid-reconnect
        gets its materials on reconnect (and is shown amber, not red)."""
        return await _compute_mtls_readiness(app.state.hub)

    @app.post("/setup/mtls-enable")
    async def set_mtls_enable(request: Request):
        from security import mtls
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        enable = bool(data.get("enabled"))
        # Guard: refuse to enable if not ready (would orphan a spoke), unless
        # the caller explicitly forces it. Readiness now covers the per-spoke
        # deep-check (hub CA + server cert AND every connected primary spoke has
        # its materials), not just the hub's own files.
        if enable and not bool(data.get("force")):
            rdy = await _compute_mtls_readiness(hub)
            if not rdy["ready"]:
                raise HTTPException(status_code=409,
                    detail="System not ready for mTLS — "
                           + "; ".join(rdy["blockers"])
                           + " (or pass force=true).")
        gc = hub.state.system_state.get("global_config", {})
        gc["mtls_enabled"] = enable
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        mtls.set_runtime_enabled(enable)  # applies to new SSL contexts (reconnects)
        return {"status": "ok", "enabled": enable,
                "message": ("mTLS enabled — verification arms on the next "
                            "reconnect of each leg." if enable
                            else "mTLS disabled (encrypted, unverified).")}

    @app.post("/setup/mtls-auto-provision")
    async def set_mtls_auto_provision(request: Request):
        """Toggle ``global_config["mtls"]["auto_provision"]`` — the master
        switch for auto-deploying the LE wildcard + CA bundle to the hub + every
        primary spoke (and auto-enabling mTLS once the fleet is ready). When ON,
        the cert-distribution loop + the LE_CERT_RENEWED event path fan the
        mTLS materials out to every primary spoke; when OFF, distribution and
        auto-enable are both inert (the manual Enable button + 409 guard still
        behave as before)."""
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        enabled = bool(data.get("enabled"))
        gc = hub.state.system_state.get("global_config", {})
        mtls_cfg = gc.get("mtls", {}) or {}
        mtls_cfg["auto_provision"] = enabled
        gc["mtls"] = mtls_cfg
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "auto_provision": enabled,
                "message": ("mTLS auto-provision ON — the hub will distribute the "
                             "LE wildcard + CA bundle to every spoke and enable "
                             "mTLS once the fleet is ready."
                             if enabled
                             else "mTLS auto-provision OFF — distribution + "
                                  "auto-enable are inert; use the manual Enable "
                                  "button.")}

    @app.get("/setup/session-timeout")
    async def get_session_timeout():
        """Idle session timeout (minutes) — a user with no requests for this long
        is logged out. 0 = disabled. Default 60 minutes."""
        import access
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        mins = gc.get("session_idle_timeout_minutes")
        if mins is None:
            mins = int(round(access.get_session_idle_timeout() / 60))
        return {"minutes": int(mins)}

    @app.post("/setup/session-timeout")
    async def set_session_timeout(request: Request):
        import access
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        try:
            mins = int(data.get("minutes"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="minutes must be an integer")
        if mins < 0 or mins > 43200:  # cap at 30 days
            raise HTTPException(status_code=400, detail="minutes out of range (0–43200)")
        gc = hub.state.system_state.get("global_config", {})
        gc["session_idle_timeout_minutes"] = mins
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        access.set_session_idle_timeout(mins * 60)  # apply live
        return {"status": "ok", "minutes": mins,
                "message": ("Idle timeout disabled." if mins == 0
                            else f"Users are logged out after {mins} idle minute(s).")}

    @app.get("/setup/appearance")
    async def get_appearance():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("appearance", {
            "primary_color": "#01A982",
            "navy_color": "#263040",
            "logo_url": "hpe-svg",
            "logo_url_right": "hpe-svg",
            "show_logo_left": True,
            "show_logo_right": True
        })
        return {"config": config}

    @app.post("/setup/appearance")
    async def update_appearance(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["appearance"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            return {"status": "ok", "message": "Appearance settings updated."}
        except Exception as e:
            logger.exception("update_appearance failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/toast-config")
    async def get_toast_config():
        hub = app.state.hub
        seconds = hub.state.system_state.get("toast_duration_s", 10)
        return {"toast_duration_s": seconds}

    @app.post("/setup/toast-config")
    async def update_toast_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            # Clamp to a sane range — 0/negative would make toasts vanish
            # instantly (effectively hiding errors) and there is no reason to
            # keep one on screen for more than 5 minutes.
            seconds = max(1, min(300, int(data.get("toast_duration_s", 10))))
            hub.state.system_state["toast_duration_s"] = seconds
            hub.state._mark_dirty()
            return {"status": "ok", "toast_duration_s": seconds}
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="toast_duration_s must be a number")
        except Exception as e:
            logger.exception("update_toast_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/logs/all")
    async def get_all_logs():
        hub = app.state.hub
        # collect_all_logs does os.listdir + per-file open + deque over
        # /var/log/lm then an inline json.dumps binary search to fit the
        # payload — off the hub loop so BugFixer's periodic poll can't stall
        # heartbeats / request_response (the in-code comment notes a prior
        # version "stalled the event loop on every BugFixer poll").
        return await asyncio.to_thread(hub.collect_all_logs)

    @app.get("/setup/logs")
    async def get_hub_logs():
        hub = app.state.hub
        try:
            log_path = "/var/log/lm/hub.log"
            if os.path.exists(log_path):
                # deque(f, maxlen=500) caps memory: readlines() loads the WHOLE
                # file (hub.log can be many MB) before slicing the last 500.
                from collections import deque
                with open(log_path, "r") as f:
                    tail = deque(f, maxlen=500)
                return {"logs": [l.strip() for l in tail]}
            # No file — fall back to in-memory deque (deques don't support slicing)
            mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
            return {"logs": [str(l) for l in mem_logs]}
        except Exception as e:
            logger.error(f"Error reading hub logs: {e}")
            try:
                mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
                return {"logs": [str(l) for l in mem_logs]}
            except Exception:
                return {"logs": []}

    @app.get("/setup/logs/{module}")
    async def get_module_logs(module: str):
        hub = app.state.hub
        try:
            if module == "errors":
                # Error Log tab: every error-level line across all sources
                # (hub deque, agent_logs, /var/log/lm/*.log), one list.
                # Off the hub loop — same I/O reason as get_all_logs.
                return await asyncio.to_thread(hub.collect_error_logs)

            if module == "agents":
                flat = []
                for agent_id, logs in hub.agent_logs.items():
                    # B2: agent_logs is guid-keyed for relayed agents; label with
                    # the raw name (guid→name via agent_info). Spoke-namespace
                    # keys (SPOKE_LOG, guid-keyed) fall back to the key itself.
                    label = hub._agent_relay_name(agent_id)
                    for line in logs:
                        flat.append(f"[{label}] {line}")
                return {"logs": flat[-500:]}

            # This module's spoke(s) run on a SEPARATE box from the hub in any
            # real (non-all-in-one) deployment, so /var/log/lm/<module>.log
            # below is a HUB-local path that only ever exists for a spoke
            # co-located on the hub's own machine — for cs/pxmx/opnsense/etc.
            # running elsewhere it 404s every time ("no logs" in the WebUI)
            # even though the spoke has been dutifully relaying its own log
            # lines up via SPOKE_LOG the whole time (_handle_spoke_log stores
            # them in hub.agent_logs[spoke_id], same buffer the "agents"
            # branch above already reads). Prefer that live relay, scoped to
            # this module's spoke(s), before ever touching the local file.
            module_type_map = {
                "opn": "firewall", "pxmx": "hypervisor", "cppm": "nac",
                "cs": "simulation", "ldap": "directory", "netbox": "ipam",
                "dns": "dns", "dhcp": "dhcp", "nw": "nw", "le": "certificates",
            }
            mtype = module_type_map.get(module)
            matching_sids = set()
            if mtype:
                matching_sids.update(
                    sid for sid, mt in hub.spoke_module_types.items() if mt == mtype)
            # Prefix fallback catches a spoke whose module_type isn't live
            # right now (disconnected — popped from spoke_module_types) but
            # whose buffered logs from while it WAS connected are still held.
            matching_sids.update(
                sid for sid in hub.agent_logs if sid == module or sid.startswith(module + "-"))

            if matching_sids:
                flat = []
                for sid in matching_sids:
                    for line in hub.agent_logs.get(sid, []):
                        flat.append(f"[{sid}] {line}")
                # Hub-side cert-distribution activity (the le.distribution logger
                # — per-target push outcomes, hub self-install, LE_GET_CERT
                # failures) lives on the HUB, not the le spoke, so it isn't in
                # agent_logs; merge it into the same Certificates view so an
                # operator sees issue + distribution + install in one place.
                if module == "le":
                    flat.extend(hub.cert_dist_logs)
                # Hub-side CS-bridge activity (the "CSBridge" logger — per-agent
                # ACTIVE/SKIP decisions, relay re-queue/give-up/ack-failed
                # outcomes, cycle heartbeat) runs ON THE HUB, so it isn't in
                # agent_logs; merge it into the same Simulations view so an
                # operator sees the cs spoke's relayed logs + the bridge's
                # per-agent decisions in one place (mirrors le/cert above).
                if module == "cs":
                    flat.extend(hub.cs_bridge_logs)
                if flat:
                    return {"logs": flat[-500:]}

            # No connected le spoke right now — still surface the hub-side
            # distribution buffer (issue/distribute outcomes) under Certificates.
            if module == "le" and hub.cert_dist_logs:
                return {"logs": list(hub.cert_dist_logs)[-500:]}

            # No connected cs spoke right now — still surface the hub-side
            # CS-bridge buffer (per-agent decisions + relay outcomes) under
            # Simulations so the bridge's view is never empty just because the
            # cs spoke momentarily disconnected.
            if module == "cs" and hub.cs_bridge_logs:
                return {"logs": list(hub.cs_bridge_logs)[-500:]}

            # Map WebUI module keys → actual log filenames under /var/log/lm/
            log_name_map = {
                "opn":    "lm-opnsense",
                "pxmx":   "lm-pxmx",
                "cppm":   "lm-cppm",
                "cs":     "lm-cs",
                "ldap":   "lm-ldap",
                "netbox": "lm-netbox-spoke",
                "dns":    "lm-dns",
                "dhcp":   "lm-dhcp",
            }
            filename = log_name_map.get(module, f"lm-{module}")

            log_path = f"/var/log/lm/{filename}.log"
            if not os.path.exists(log_path):
                raise HTTPException(status_code=404, detail=f"Log file for {module} not found at {log_path}.")

            with open(log_path, "r") as f:
                # deque caps memory — readlines() loads the whole file first.
                from collections import deque
                logs = deque(f, maxlen=500)

            return {"logs": [log.strip() for log in logs]}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading logs for {module}: {e}")
            raise HTTPException(status_code=500, detail=f"Permission or I/O error reading {log_path}: {str(e)}")

    @app.post("/setup/logs/clear")
    async def clear_all_logs(request: Request):
        """Clear Logs button in the Logs view. Wipes every log source the Hub
        Log UI can show: the hub's in-memory deque, every relayed agent/spoke
        deque (``agent_logs``), and the on-disk ``/var/log/lm/*.log`` files on
        the hub box; then broadcasts ``CLEAR_LOGS`` to every connected spoke so
        each remote box truncates its own on-disk logs. Admin-only — the
        ``/setup/*`` middleware already gates admin, this is belt-and-suspenders
        (mirrors ``reset_rate_limit_drops``). The clear is destructive and
        fleet-wide, hence the explicit re-check + a [diag] audit line."""
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        result = await hub.clear_all_logs()
        logger.warning("[diag] Clear Logs by %s: hub %d + agent/spoke %d lines, "
                       "%d on-disk file(s), broadcast to %d spoke(s)",
                       (sess.get("username") if isinstance(sess, dict) else "?"),
                       result.get("hub_lines", 0), result.get("agent_lines", 0),
                       len(result.get("disk_files_truncated", [])),
                       result.get("spokes_broadcast", 0))
        return result

    @app.get("/setup/api-probe")
    async def probe_spoke_api(spoke_id: str, path: str):
        hub = app.state.hub
        if hub._primary_key(spoke_id) not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Spoke {spoke_id} not connected")

        try:
            result = await hub.request_response(spoke_id, "PROBE_API", {"path": path})
            return result
        except Exception as e:
            logger.exception("probe_api failed (spoke=%s path=%s)", spoke_id, path)
            raise HTTPException(status_code=500, detail=f"Probe failed: {str(e)}")


    # ── Diagnostics + bug-report (/setup/diagnostics, /api/bug-report/*) ───────
    @app.get("/setup/diagnostics")
    async def get_diagnostics():
        """Per-spoke + hub diagnostic snapshot for the WebUI Diagnostics
        card. Serves a stale-while-revalidate cache (``_DIAG_CACHE``):
        fresh within ``_DIAG_FRESH_S`` (instant serve), servable-stale
        until ``_DIAG_STALE_S`` (instant serve + one background refresh),
        and a forced refresh only when there is no servable cache. The
        compute (``_aggregate_diagnostics``) runs the leaked relay-agent
        self-heal on every fresh recompute."""
        hub = app.state.hub

        cached = _DIAG_CACHE["data"]
        age = (time.time() - _DIAG_CACHE["ts"]) if cached is not None else None

        # Inside the stale window → serve instantly; past fresh-TTL,
        # kick ONE background refresh (the ``not refreshing`` guard
        # avoids a pile-up).
        if cached is not None and age is not None and age < _DIAG_STALE_S:
            if age >= _DIAG_FRESH_S and not _DIAG_CACHE["refreshing"]:
                asyncio.create_task(_maybe_refresh_diagnostics(hub))
            return cached

        # No servable cache → forced refresh. The lock serializes
        # concurrent first-loaders into a single recompute.
        result = await _maybe_refresh_diagnostics(hub, force=True)
        return result or {"spokes": [], "hub_version": "", "webui_version": "unknown", "system": {}}

    @app.get("/setup/diagnostics/{spoke_id}")
    async def get_diagnostics_detail(spoke_id: str):
        """Per-spoke lifecycle events + relayed WARNING/ERROR log lines, fetched
        lazily by the WebUI when an admin expands a spoke's events panel. Split
        out of the /setup/diagnostics LIST payload (which now carries only an
        ``event_count`` badge) so the polled list stays light — these arrays are
        only needed for the one spoke the operator actually expanded. Cheap
        hub-local reads (in-memory deques), admin-gated by the /setup/ prefix."""
        hub = app.state.hub
        return {
            "spoke_id": spoke_id,
            "events": hub.get_spoke_events(spoke_id, limit=50),
            "log_events": hub.get_spoke_log_events(spoke_id, limit=30),
        }

    @app.post("/setup/spoke/{spoke_id}/recovery")
    async def set_spoke_recovery_pause(spoke_id: str, request: Request):
        """Manual override for the spoke-recovery watchdog.

        Body: {"pause": true|false}. Pausing sets manual_pause so the watchdog
        stops restart attempts for this spoke (one of the give-up triggers);
        resuming clears it so recovery resumes. This is the "Manual override
        flag" surfaced as a per-row Pause/Resume button in the Diagnostics view.
        Admin-gated automatically by the /setup/ prefix in access_control_middleware.
        """
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        pause = bool(data.get("pause", False))

        st = hub.spoke_recovery.setdefault(hub._primary_key(spoke_id), {"attempts": 0})
        if pause:
            st["manual_pause"] = True
            st["in_progress"] = False
            action, event = "paused", "recovery_paused"
            hub.record_spoke_event(spoke_id, "recovery_paused", "manual pause set via WebUI")
            logger.info(f"[recovery] spoke_id={spoke_id} action=paused reason=manual_override")
        else:
            st["manual_pause"] = False
            # Resume: reset attempts/backoff so recovery fires on the next tick
            # rather than waiting out a stale next_retry_ts.
            st["attempts"] = 0
            st["next_retry_ts"] = 0
            st["gave_up"] = False
            action, event = "resumed", "recovery_resumed"
            hub.record_spoke_event(spoke_id, "recovery_resumed", "manual pause cleared via WebUI")
            logger.info(f"[recovery] spoke_id={spoke_id} action=resumed reason=manual_override")
        _bust_diag_cache()
        return {"status": "ok", "spoke_id": spoke_id, "paused": pause}

    @app.post("/api/bug-report")
    async def file_bug_report(request: Request):
        """File a Bug from the WebUI footer button.

        Body: {explanation, severity, console_logs, html, screenshot, context}.
        The hub stores the full artifacts (console/HTML/screenshot) under
        data_dir/bugs/<id>/ and logs a short greppable [bug-report] marker so
        bugfixer's scan_bugs finds it. The marker line carries only the id +
        a summary — the large payloads never go into the hub log. Any
        authenticated user can file (the /api/ prefix is auth-gated but not
        admin-only, unlike /setup/). bugfixer later files a clean-body GitHub
        issue and pulls these artifacts from the hub for fix context.
        """
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        if not isinstance(data, dict) or not str(data.get("explanation") or "").strip():
            raise HTTPException(status_code=400, detail="Missing explanation")

        try:
            explanation = str(data.get("explanation") or "")
            # Capture-integrity receipt line (before store): shows whether the
            # WebUI actually captured console/html/screenshot, so a "no issue in
            # GitHub" trace can rule out a missing payload upstream of storage.
            shot = data.get("screenshot")
            if isinstance(shot, str) and shot.startswith("data:"):
                shot_kind = "png" if "image/png" in shot.split(",", 1)[0] else "jpg"
            else:
                shot_kind = "none"
            logger.info(
                f"[bug-report] received explanation={len(explanation)} chars "
                f"console={len(str(data.get('console_logs') or ''))} "
                f"html={len(str(data.get('html') or ''))} screenshot={shot_kind}"
            )
            rid = await asyncio.to_thread(hub._store_bug_report, data)
            if not rid:
                logger.error("bug-report: _store_bug_report returned no id (data keys=%s)", list(data.keys()))
                raise HTTPException(status_code=500, detail="Failed to store bug report")
            sev = str(data.get("severity") or "medium")
            rtype = str(data.get("type") or "bug").strip().lower() or "bug"
            ctx = data.get("context") or {}
            view = ctx.get("currentView") if isinstance(ctx, dict) else ""
            # Short marker — flows through HubLogHandler -> self.logs ->
            # /var/log/lm/hub.log -> GET_LOGS -> bugfixer scan_bugs. No base64.
            logger.info(
                f"[bug-report] id={rid} type={rtype} severity={sev} view={view} "
                f"summary={explanation[:80]!r}"
            )
            return {"status": "ok", "id": rid}
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"[bug-report] /api/bug-report failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    # Bug Reports log view (admin-only, like the rest of /setup/): lists filed
    # reports and serves the full artifacts (console/HTML/screenshot) for an
    # expandable detail modal. Reuses the hub's _list_bug_reports /
    # _get_bug_report helpers so the UI and bugfixer see the same data.
    @app.get("/setup/bug-reports")
    async def list_bug_reports():
        hub = app.state.hub
        reports = hub._list_bug_reports()
        reports.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return {"reports": reports}

    @app.get("/setup/bug-reports/{rid}")
    async def get_bug_report(rid: str):
        hub = app.state.hub
        rep = await asyncio.to_thread(hub._get_bug_report, rid)
        if not rep:
            raise HTTPException(status_code=404, detail="Bug report not found")
        return rep

    @app.delete("/setup/bug-reports/{rid}")
    async def delete_bug_report(rid: str):
        """Delete a stored bug report (admin-only, like the rest of /setup/).
        Removes the in-memory index entry + the on-disk artifacts
        (console/HTML/screenshot) under data_dir/bugs/<id>/. The public GitHub
        issue bugfixer may already have filed is NOT touched — only the hub's
        local copy of the captured artifacts."""
        hub = app.state.hub
        ok = await asyncio.to_thread(hub._delete_bug_report, rid)
        if not ok:
            raise HTTPException(status_code=404, detail="Bug report not found")
        return {"status": "ok", "id": rid}

    # ── LDAP relay (/api/ldap/*) ──────────────────────────────────────────────
