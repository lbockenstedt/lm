"""Setup admin: debug-mode, docs, appearance, logs, diagnostics, recovery, bug reports."""
# asyncio provides the per-event-loop lock for the diagnostics cache.
import asyncio
# Hub-wide helpers: HTTP errors, logger, os/re/time and the log-level setter.
from api import (
    HTTPException, Request, logger, os, re, set_log_level, time,
)
# Compares a spoke's version with the latest one for its repo.
from update_pipeline import _version_behind
# Ids of spokes that connect directly to the hub (not relayed through another spoke).
from spoke_alert_sync import direct_module_ids as _direct_module_ids
# GitHub helpers that turn recently merged PRs/commits into "What's New" items.
from whats_new_prs import (
    _WHATS_NEW_REPOS, fetch_recent_merged_prs, merged_prs_to_items, recent_commit_items,
)

# Parses YAML front matter in docs.
from . import frontmatter

# Cap for the WebUI "What's New" popover (GET /api/whats-new).
_WHATS_NEW_LIMIT = 30
# Only surface updates merged within this many days ("the last 2 weeks").
_WHATS_NEW_DAYS = 14


def _committed_features(reports: list, *, now: float = None,
                        within_days: int = _WHATS_NEW_DAYS) -> list:
    """Recently merged bug fixes AND features for the "What's New" popover.

    An item qualifies when it's a bug-store report AppBuilder has built &
    closed — its MARK_BUG_FIXED cascade sets ``status=="fixed"`` + a
    ``fixed_at`` epoch — of ``type`` bug or feature (an untyped legacy report
    counts as a bug, matching the WebUI's ``r.type || 'bug'`` convention), with
    a non-empty ``summary``, fixed within the last ``within_days`` days.
    Newest-first by ``fixed_at`` (falls back to ``ts``), capped at
    ``_WHATS_NEW_LIMIT``. Each item carries a ``type`` so the UI can badge
    "Bug fix" vs "Feature". Pure function (inject ``now`` in tests)."""
    # Default to the current time; tests pass a fixed one.
    if now is None:
        now = time.time()
    # Oldest fix time still shown.
    cutoff = now - within_days * 86400
    # Collect qualifying items.
    items = []
    for r in reports or []:
        # Only bug and feature reports (untyped counts as bug).
        rtype = str(r.get("type") or "bug").lower()
        if rtype not in ("bug", "feature"):
            continue
        # Only reports marked fixed.
        if str(r.get("status") or "").lower() != "fixed":
            continue
        # Skip reports without a summary.
        summary = str(r.get("summary") or "").strip()
        if not summary:
            continue
        # Skip reports with no time or older than the cutoff.
        when = r.get("fixed_at") or r.get("ts") or 0
        if not when or when < cutoff:
            continue
        # Keep just the fields the popover needs.
        items.append({
            "id": r.get("id"),
            "summary": summary,
            "type": "feature" if rtype == "feature" else "bug",
            "fixed_at": when,
            "issue_url": r.get("issue_url") or "",
        })
    # Newest first, capped.
    items.sort(key=lambda x: x.get("fixed_at") or 0, reverse=True)
    return items[:_WHATS_NEW_LIMIT]


def _dedupe_and_cap(items: list, limit: int = _WHATS_NEW_LIMIT) -> list:
    """Merge step for the "What's New" popover's two sources. Drops a later item
    whose summary (whitespace/case normalized) duplicates an earlier one -
    callers pass the bug-store items first so a curated summary wins over a
    PR-derived one describing the same change - then sorts newest-first by
    ``fixed_at`` and caps at ``limit``. Pure; does not touch ``_committed_features``."""
    # Track normalised summaries already seen.
    seen = set()
    deduped = []
    # Keep only the first item for each summary.
    for it in items:
        # Compare summaries ignoring case and extra whitespace.
        key = " ".join(str(it.get("summary") or "").lower().split())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(it)
    # Newest first, capped at the limit.
    deduped.sort(key=lambda x: x.get("fixed_at") or 0, reverse=True)
    return deduped[:limit]

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
    """Return the diagnostics lock for the current event loop, creating it on first use."""
    # Key the lock by the running loop so each loop gets its own.
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
    # Only one refresh runs at a time.
    async with _diag_lock():
        # Serve the cache if it is fresh enough.
        cached = _DIAG_CACHE["data"]
        age = (time.time() - _DIAG_CACHE["ts"]) if cached is not None else None
        if cached is not None and age is not None and age < _DIAG_FRESH_S:
            return cached
        # Recompute and store the new payload.
        _DIAG_CACHE["refreshing"] = True
        try:
            result = await _aggregate_diagnostics(hub)
            _DIAG_CACHE["data"] = result
            _DIAG_CACHE["ts"] = time.time()
            return result
        except Exception:
            logger.exception("diagnostics cache refresh failed")
            return cached  # serve stale rather than blanking the card
        # Always clear the refreshing flag.
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
    # Keep data but mark it just past fresh, so the next GET refreshes in the background.
    if _DIAG_CACHE.get("data") is not None:
        _DIAG_CACHE["ts"] = min(_DIAG_CACHE["ts"], time.time() - _DIAG_FRESH_S)
    # No cached data: force a refresh on the next GET.
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
    # Hub-wide system metrics, the result list and the known spokes.
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
        """Return True if ``v`` uses the ".NN" or "MAJOR.MINOR" version scheme."""
        # Accept BOTH the legacy ".NN" counter and the new "MAJOR.MINOR" scheme
        # (e.g. "1.02", "2.14"). SKEW flags only versions on NEITHER (stale
        # X.Y.Z / v-tag / pre-reset). Mirrors _isNN in WebUI/main.js.
        s = str(v).strip()
        return bool(_re.match(r"^\.\d+$", s) or _re.match(r"^\d+\.\d+$", s))

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
    # Collect relayed agent ids from agent_config and "{spoke}:{agent}" heartbeat keys.
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
    # Spokes that connect directly are never treated as relayed agents.
    direct_module_ids = _direct_module_ids(hub.state.system_state)
    # Remove relay agent ids that leaked into known_modules/approved_modules.
    if relay_ids:
        known = list(hub.state.system_state.get("known_modules", []))
        leaked = [
            m for m in known
            if m in relay_ids and m not in direct_module_ids
        ]
        if leaked:
            cleaned = [m for m in known if m not in leaked]
            hub.state.system_state["known_modules"] = cleaned
            hub.known_modules = cleaned
            for aid in leaked:
                hub.approved_modules.pop(aid, None)
            hub.state._mark_dirty()
            logger.info("[diag] removed leaked relay-agent id(s) from "
                        "known_modules/approved_modules: %s", leaked)

    # Build one diagnostics row per known spoke.
    for sid in known_spokes:
        # Skip relayed node agents.
        if sid in relay_ids and sid not in direct_module_ids:
            continue  # relayed node agent — surfaced via /api/pxmx/agents, not here
        # Live socket, telemetry and recent events for this spoke.
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
                          "auth_failed", "mutual_auth_failed", "mutual_auth_timeout",
                          # Spoke-side refusal of the Hub's identity proof
                          # (stale/rotated-out hub_secret + TLS verify off) —
                          # counts toward flapping the same as the other
                          # mutual-auth failure events above, since a spoke
                          # stuck in this loop reconnects/refuses on the same
                          # 5-300s backoff cadence.
                          "hub_identity_rejected"))
        # Three or more drops in 5 minutes counts as flapping.
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
        # badge + attempt counter + last action/error from this; ab
        # also reads it via GET_SPOKE_STATUS to suppress/escalate.
        rec = hub.spoke_recovery.get(hub._primary_key(sid), {}) or {}

        # Out-of-contact alert (SpokeAlertMixin) — separate from the realtime
        # heartbeat_status traffic-light above. tier is "warning" (>=5 min out
        # of contact) or "error" (>=30 min); absent when the spoke is in
        # contact. Drives the diagnostics badge.
        alert = (getattr(hub, "_spoke_alerts", {}) or {}).get(sid, {}) or {}

        # The version this spoke last reported.
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

        # Parent agent of a role sub-spoke, and whether it is connected right
        # now. Both stay None/False for an ordinary top-level spoke. getattr:
        # the diagnostics compute serves STALE on any exception, so an
        # AttributeError here would silently blank the whole card.
        parent_sid = (getattr(hub, "spoke_parent_map", None) or {}).get(
            hub._primary_key(sid)) or None
        parent_online = bool(
            parent_sid and hub._primary_key(parent_sid) in hub.active_connections)

        # Add this spoke's diagnostics row.
        diagnostics.append({
            "spoke_id": sid,
            "display_name": hub.state.get_module_name(sid),
            "authenticated": hub._primary_key(sid) in hub.active_connections,
            # Grace-based display status: connected now OR seen within the
            # grace window. The WebUI header dots use this so a transient
            # stall / brief reconnect doesn't flip a module offline.
            "in_contact": hub.is_spoke_in_contact(sid),
            "approved": hub.approved_modules.get(hub._primary_key(sid), False),
            # Soft-retire flag (decommission_module): kept record, suppressed
            # out-of-contact alerting, reversible. UI badged grey + offers
            # Restore / Force-Delete instead of the normal Delete.
            "decommissioned": hub.state.is_module_decommissioned(hub._primary_key(sid)),
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
            # Role sub-spokes of a generic agent ({base}-{role}) share ONE
            # process with the base agent, so "this role is down" almost never
            # means systemd failed to revive a unit — the role has no unit of
            # its own. Ship the parent's live connection state so the UI can
            # say "parent agent online, role reloading" instead of blaming
            # systemd (see spokeStatusMessage in WebUI/main.js).
            "parent_spoke_id": parent_sid,
            "parent_online": parent_online,
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
            # ab has/will be handed off; manual_pause = admin paused.
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

    # Read the WebUI version file; stays "unknown" if it cannot be read.
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

    # Return per-spoke rows plus hub-wide versions and metrics.
    return {
        "spokes": diagnostics,
        "hub_version": hub_version,
        "webui_version": webui_version,
        "system": metrics
    }



async def store_bug_report(hub, ctx, request, data: dict) -> str:
    """Store one WebUI bug/feature report (shared by /api/bug-report and the
    Request Assistant submit route) and log the greppable ``[bug-report]``
    marker ab's scan_bugs keys on. Returns the report id; raises HTTPException.
    The tenant is resolved server-side and overrides whatever the browser sent."""
    # Any unexpected failure becomes a 500.
    try:
        explanation = str(data.get("explanation") or "")
        # Capture-integrity receipt line (before store): shows whether the
        # WebUI actually captured console/html/screenshot, so a "no issue in
        # GitHub" trace can rule out a missing payload upstream of storage.
        # Note the screenshot format (png/jpg) or "none" for the receipt log.
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
        # Attribute the report to the filer's tenant (authoritative, server-
        # side) so the read-only tenant-admin view can scope to it. Prefer the
        # session tenant; for a Global Admin with no active tenant, fall back
        # to the header tenant picker carried in context.currentTenant.
        try:
            _tid = ctx._resolve_tenant(request) or ""
        except Exception:  # noqa: BLE001
            _tid = ""
        # No session tenant: use the tenant picked in the WebUI header.
        if not _tid:
            _c = data.get("context") or {}
            if isinstance(_c, dict):
                _tid = str(_c.get("currentTenant") or "").strip()
        # 'default' is the WebUI's no-tenant sentinel, not a real tenant —
        # store it as untagged (Global-Admin-only) rather than a bogus tenant.
        if _tid == "default":
            _tid = ""
        # Save the report off the event loop; an empty id means it failed.
        data["tenant_id"] = _tid
        rid = await asyncio.to_thread(hub._store_bug_report, data)
        if not rid:
            logger.error("bug-report: _store_bug_report returned no id (data keys=%s)", list(data.keys()))
            raise HTTPException(status_code=500, detail="Failed to store bug report")
        # Gather the fields for the marker log line.
        sev = str(data.get("severity") or "medium")
        rtype = str(data.get("type") or "bug").strip().lower() or "bug"
        bctx = data.get("context") or {}
        view = bctx.get("currentView") if isinstance(bctx, dict) else ""
        summary = str(data.get("title") or "") or explanation
        # Short marker — flows through HubLogHandler -> self.logs ->
        # /var/log/lm/hub.log -> GET_LOGS -> ab scan_bugs. No base64.
        logger.info(
            f"[bug-report] id={rid} type={rtype} severity={sev} view={view} "
            f"summary={summary[:80]!r}"
        )
        return rid
    # Let HTTP errors through unchanged; wrap anything else as a 500.
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[bug-report] store failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def register(app, hub, ctx):
    """Register setup_admin routes on the Hub app."""

    @app.get("/setup/debug-mode")
    async def get_debug_mode():
        """Return whether debug logging is enabled."""
        # Read the debug flag from the global config.
        hub = app.state.hub
        enabled = hub.state.get_global_config().get("debug_mode", False)
        return {"enabled": enabled}

    @app.post("/setup/debug-mode")
    async def toggle_debug_mode(request: Request):
        """Turn debug logging on or off for the hub and all spokes.

        Expects JSON {"enabled": bool}.
        """
        hub = app.state.hub
        try:
            # Read the requested setting.
            data = await request.json()
            enabled = data.get("enabled", False)

            # Store it in the global config and mark state for saving.
            global_config = hub.state.get_global_config()
            global_config["debug_mode"] = enabled
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Flip the HUB's own root + named loggers (not just the broadcast
            # targets) so the hub's logger.debug(...) lines actually emit.
            set_log_level(enabled)
            await hub.broadcast_log_level(enabled)

            return {"status": "ok", "enabled": enabled}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("toggle_debug_mode failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/docs/{section}")
    async def get_docs(section: str):
        """Return one "Help:" section of README.md by its header name (404 if missing)."""
        try:
            # Find README.md in either possible layout, falling back to the first path.
            readme_path = next(
                (r for r in (
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../README.md")),
                    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../README.md")),
                ) if os.path.exists(r)),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../README.md")))
            # The README must exist.
            if not os.path.exists(readme_path):
                raise HTTPException(status_code=404, detail="README.md documentation not found")

            # Read the whole README.
            with open(readme_path, "r") as f:
                content = f.read()

            # Help sections start with this marker; split the README on it.
            marker = "### \U0001f4d6 Help:"
            sections = content.split(marker)

            # Return the body of the section whose header matches.
            for s in sections[1:]:
                lines = s.split('\n')
                header = lines[0].strip()
                if header == section:
                    body = '\n'.join(lines[1:]).strip()
                    return {"content": body}

            raise HTTPException(status_code=404, detail=f"Help section '{section}' not found in documentation.")
        # Let HTTP errors through unchanged; wrap anything else as a 500.
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
        # Normalise the name and drop any .md extension.
        stem = (name or "").strip().lower()
        if stem.endswith(".md"):
            stem = stem[:-3]
        # Canonical doc names are kebab-case ascii; reject anything else outright.
        if not stem or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", stem):
            raise HTTPException(status_code=400, detail="Invalid document name.")
        # Build the path and make sure it is a real file directly in the docs folder.
        path = os.path.abspath(os.path.join(_DOCS_DIR, f"{stem}.md"))
        if os.path.dirname(path) != _DOCS_DIR or not os.path.isfile(path):
            raise HTTPException(status_code=404, detail=f"Document '{stem}' not found.")
        return path

    @app.get("/docs")
    async def list_docs():
        """List the canonical docs (name + first-heading title) for the Help index."""
        # Collect one entry per doc.
        out = []
        try:
            # Look at every .md file in the docs folder, in name order.
            for fn in sorted(os.listdir(_DOCS_DIR)):
                if not fn.endswith(".md"):
                    continue
                # Default the title to the file name.
                name = fn[:-3]
                title = name
                summary = ""
                # Read the start of the file for its front matter summary and first heading.
                try:
                    with open(os.path.join(_DOCS_DIR, fn), "r", encoding="utf-8") as f:
                        head = f.read(2048)
                    meta, body = frontmatter.split(head)
                    summary = str(meta.get("summary") or "")
                    for line in body.splitlines():
                        if line.startswith("# "):
                            title = line[2:].strip()
                            break
                # An unreadable doc keeps its default title.
                except Exception:  # noqa: BLE001
                    pass
                out.append({"name": name, "title": title, "summary": summary})
        # The docs folder itself is missing.
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Docs directory not found.")
        return {"docs": out}

    @app.get("/docs/{name}")
    async def get_doc(name: str):
        """Return one canonical doc as raw markdown (rendered client-side)."""
        # Validate the name and read the file.
        path = _safe_doc_path(name)
        try:
            with open(path, "r", encoding="utf-8") as f:
                markdown = f.read()
        # Read failures are logged and reported as a 500.
        except Exception as e:  # noqa: BLE001
            logger.error(f"Error reading doc {name}: {e}")
            raise HTTPException(status_code=500, detail="Error reading document.")
        # Strip the metadata header before it reaches the client. The client-side
        # renderer turns '---' into <hr>, so an unstripped block renders as a
        # rule followed by raw YAML at the top of every document.
        meta, markdown = frontmatter.split(markdown)
        # Default the title to the file name, then use the first "# " heading if any.
        title = os.path.basename(path)[:-3]
        for line in markdown.splitlines():
            if line.startswith("# "):
                title = line[2:].strip()
                break
        # Return the doc with its title, summary and markdown body.
        return {"name": os.path.basename(path)[:-3], "title": title,
                "summary": str(meta.get("summary") or ""), "markdown": markdown}

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
        """Turn mutual TLS on or off (Global Admin only).

        Enabling is refused with 409 if the fleet is not ready, unless "force" is true.
        """
        # mtls holds the runtime mTLS switch.
        from security import mtls
        hub = app.state.hub
        # Only Global Admins may change this.
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the requested state.
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
        # Save the flag in the global config and mark state for saving.
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
        # Only Global Admins may change this.
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the requested state.
        data = await request.json()
        enabled = bool(data.get("enabled"))
        # Save it under global_config["mtls"] and mark state for saving.
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
        # access holds the live idle-timeout setting.
        import access
        hub = app.state.hub
        # Use the stored value, or the current live default.
        gc = hub.state.system_state.get("global_config", {}) or {}
        mins = gc.get("session_idle_timeout_minutes")
        if mins is None:
            mins = int(round(access.get_session_idle_timeout() / 60))
        return {"minutes": int(mins)}

    @app.post("/setup/session-timeout")
    async def set_session_timeout(request: Request):
        """Set the idle session timeout in minutes (Global Admin only, 0 disables, max 30 days)."""
        # access holds the live idle-timeout setting.
        import access
        hub = app.state.hub
        # Only Global Admins may change this.
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read and validate the number of minutes.
        data = await request.json()
        try:
            mins = int(data.get("minutes"))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="minutes must be an integer")
        if mins < 0 or mins > 43200:  # cap at 30 days
            raise HTTPException(status_code=400, detail="minutes out of range (0–43200)")
        # Save it in the global config and mark state for saving.
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
        """Return the WebUI colour/logo settings, or the HPE defaults when unset."""
        # Read the stored appearance, with HPE defaults.
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
        """Save the WebUI colour/logo settings.

        Expects JSON {"config": {...}}.
        """
        # Read the new settings.
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            # Store them in the global config and mark state for saving.
            global_config = hub.state.system_state.get("global_config", {})
            global_config["appearance"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            return {"status": "ok", "message": "Appearance settings updated."}
        # Any failure is reported as a 500.
        except Exception as e:
            logger.exception("update_appearance failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/toast-config")
    async def get_toast_config():
        """Return how long WebUI toast messages stay on screen (seconds, default 10)."""
        # Read the stored duration.
        hub = app.state.hub
        seconds = hub.state.system_state.get("toast_duration_s", 10)
        return {"toast_duration_s": seconds}

    @app.post("/setup/toast-config")
    async def update_toast_config(request: Request):
        """Set how long WebUI toast messages stay on screen (1-300 seconds)."""
        # Read the requested duration.
        hub = app.state.hub
        try:
            data = await request.json()
            # Clamp to a sane range — 0/negative would make toasts vanish
            # instantly (effectively hiding errors) and there is no reason to
            # keep one on screen for more than 5 minutes.
            seconds = max(1, min(300, int(data.get("toast_duration_s", 10))))
            # Store it and mark state for saving.
            hub.state.system_state["toast_duration_s"] = seconds
            hub.state._mark_dirty()
            return {"status": "ok", "toast_duration_s": seconds}
        # A non-number value is a bad request.
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="toast_duration_s must be a number")
        except Exception as e:
            logger.exception("update_toast_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/logs/all")
    async def get_all_logs():
        """Return logs from every source (hub, spokes, agents) in one payload."""
        hub = app.state.hub
        # collect_all_logs does os.listdir + per-file open + deque over
        # /var/log/lm then an inline json.dumps binary search to fit the
        # payload — off the hub loop so AppBuilder's periodic poll can't stall
        # heartbeats / request_response (the in-code comment notes a prior
        # version "stalled the event loop on every AppBuilder poll").
        return await asyncio.to_thread(hub.collect_all_logs)

    @app.get("/setup/logs")
    async def get_hub_logs():
        """Return the last 500 lines of the hub log (file, or in-memory buffer as fallback)."""
        # Any read error falls back to the in-memory buffer below.
        hub = app.state.hub
        try:
            # Prefer the hub log file when it exists.
            log_path = "/var/log/lm/hub.log"
            if os.path.exists(log_path):
                # deque(f, maxlen=500) caps memory: readlines() loads the WHOLE
                # file (hub.log can be many MB) before slicing the last 500.
                # deque keeps only the last N lines in memory.
                from collections import deque
                with open(log_path, "r") as f:
                    tail = deque(f, maxlen=500)
                return {"logs": [l.strip() for l in tail]}
            # No file — fall back to in-memory deque (deques don't support slicing)
            mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
            return {"logs": [str(l) for l in mem_logs]}
        # On error, log it and try the in-memory buffer; return no lines if that fails too.
        except Exception as e:
            logger.error(f"Error reading hub logs: {e}")
            try:
                mem_logs = list(hub.logs)[-500:] if hasattr(hub, "logs") else []
                return {"logs": [str(l) for l in mem_logs]}
            except Exception:
                return {"logs": []}

    @app.get("/setup/logs/{module}")
    async def get_module_logs(module: str):
        """Return the logs for one module, the error log, console logs or agent logs.

        ``module`` is a short module name (e.g. "dns") or one of "errors", "console", "agents".
        """
        # Any failure is handled at the end of this function.
        hub = app.state.hub
        try:
            if module == "errors":
                # Error Log tab: every error-level line across all sources
                # (hub deque, agent_logs, /var/log/lm/*.log), one list.
                # Off the hub loop — same I/O reason as get_all_logs.
                return await asyncio.to_thread(hub.collect_error_logs)

            if module == "console":
                # Console module is hub-native (VNC/serial relay, credential
                # handling, learn/identify) with no spoke — its "Console" logger
                # feeds hub.console_logs directly (see main.py ConsoleLogHandler).
                return {"logs": list(hub.console_logs)[-500:]}

            # Agent logs: every agent's lines, labelled with a readable name.
            if module == "agents":
                # Flatten all agents' lines into one list.
                flat = []
                for agent_id, logs in hub.agent_logs.items():
                    # B2: agent_logs is guid-keyed for relayed agents; label with
                    # the raw name (guid→name via agent_info). Spoke-namespace
                    # keys (SPOKE_LOG, guid-keyed) fall back to the key itself —
                    # so when the relay name is still a bare guid, resolve it to
                    # the registered display name / hostname instead of a UUID.
                    label = hub._agent_relay_name(agent_id)
                    if label == agent_id:
                        label = hub._log_source_label(agent_id)
                    # Prefix each line with its source.
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
            # Map short module names to the spoke module types.
            module_type_map = {
                "opn": "firewall", "pxmx": "hypervisor", "cppm": "nac",
                "cs": "simulation", "ldap": "directory", "netbox": "ipam",
                "dns": "dns", "dhcp": "dhcp", "henet": "henet", "nw": "nw", "le": "certificates",
            }
            # Collect spoke ids of this module's type.
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

            # When spokes relayed lines, return those, labelled by source.
            if matching_sids:
                flat = []
                for sid in matching_sids:
                    label = hub._log_source_label(sid)
                    for line in hub.agent_logs.get(sid, []):
                        flat.append(f"[{label}] {line}")
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
                # Return the newest 500 lines if anything was found.
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
                "henet":  "lm-henet",
                "dhcp":   "lm-dhcp",
            }
            # Unknown modules use the "lm-<module>" naming convention.
            filename = log_name_map.get(module, f"lm-{module}")

            # The log file must exist on the hub.
            log_path = f"/var/log/lm/{filename}.log"
            if not os.path.exists(log_path):
                raise HTTPException(status_code=404, detail=f"Log file for {module} not found at {log_path}.")

            # Read the last 500 lines of the file.
            with open(log_path, "r") as f:
                # deque caps memory — readlines() loads the whole file first.
                from collections import deque
                logs = deque(f, maxlen=500)

            return {"logs": [log.strip() for log in logs]}
        # Let HTTP errors through unchanged; report anything else as a 500.
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error reading logs for {module}: {e}")
            raise HTTPException(status_code=500, detail=f"Permission or I/O error reading {log_path}: {str(e)}")

    @app.post("/setup/log-analysis")
    async def run_log_analysis(request: Request):
        """AI Log Analysis: gather this module's logs (same lines the Logs UI shows)
        and delegate to the ab spoke's LLM. The hub has no LLM of its own.
        Blocks until the analysis returns (long — the LLM can be slow); admin-gated
        by the /setup/* middleware."""
        # A missing or invalid JSON body is treated as empty.
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Which module to analyse; hub, recovery and all mean the hub log.
        module = (body or {}).get("module") or "hub"
        is_hub = module in ("hub", "recovery", "all", "")
        # Reuse the log routes above; any failure means no lines.
        try:
            resp = await (get_hub_logs() if is_hub else get_module_logs(module))
        except HTTPException:
            resp = {"logs": []}
        except Exception:
            resp = {"logs": []}
        # Sources (get_hub_logs / get_module_logs) are oldest→newest, which _window_log_lines
        # expects. Send the LLM only the recent window (configured interval, default 15 min)
        # — not the whole tail. Quiet module (nothing in-window) → "no recent activity".
        lines = [str(l) for l in ((resp or {}).get("logs", []) if isinstance(resp, dict) else [])]
        # Window length in minutes from settings (default 30).
        win = int(hub.state.get_global_config().get("log_analysis_interval_min", 30) or 30)
        windowed = hub._window_log_lines(lines, win)
        # Send at most the last 400 lines.
        log_text = "\n".join(windowed[-400:])
        # Label the logs for the LLM prompt.
        label = f"Lab Manager (hub) logs (last {win} min)" if is_hub else f"{module} logs (last {win} min)"
        return await hub.analyze_logs_via_ab(module, log_text, label)

    @app.get("/setup/log-analysis")
    async def get_log_analysis(module: str = "hub"):
        """Return the cached (pre-computed or last-run) Log Analysis for a module."""
        # Look up the cached result for this module.
        hub = app.state.hub
        cache = getattr(hub, "_log_analysis_cache", {}) or {}
        cached = cache.get(module or "hub")
        if cached:
            return cached
        # Nothing cached yet: return an empty placeholder.
        return {"ok": None, "running": False, "module": module or "hub",
                "analysis": "", "verdict": None, "error": None, "at": None}

    @app.get("/setup/log-analysis/config")
    async def get_log_analysis_config():
        """Log-sentinel settings + last-sweep generation-time metric for the UI."""
        # Read the settings from the global config.
        hub = app.state.hub
        gc = hub.state.get_global_config()
        return {
            "auto": gc.get("log_analysis_auto", True),
            "interval_min": int(gc.get("log_analysis_interval_min", 30) or 30),
            "metric": getattr(hub, "_log_sentinel_metric", {}) or {},
            "ab_online": bool(hub.get_spoke_by_type("ab")),
        }

    @app.post("/setup/log-analysis/config")
    async def set_log_analysis_config(request: Request):
        """Enable/disable the unattended sentinel + set its target interval (minutes).
        The loop self-throttles so the effective gap is never shorter than a sweep takes."""
        # A missing or invalid JSON body is treated as empty.
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Update only the fields that were sent; a bad interval is ignored.
        gc = hub.state.get_global_config()
        if "auto" in data:
            gc["log_analysis_auto"] = bool(data.get("auto"))
        if "interval_min" in data:
            try:
                gc["log_analysis_interval_min"] = max(1, int(data.get("interval_min")))
            except (TypeError, ValueError):
                pass
        # Store the config and mark state for saving.
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"ok": True, "auto": gc.get("log_analysis_auto", True),
                "interval_min": int(gc.get("log_analysis_interval_min", 30) or 30)}

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
        # Re-check Global Admin, since the action is destructive and fleet-wide.
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not sess or not ctx._is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Clear every log source, then write an audit line.
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
        """Ask a connected spoke to call one of its own API paths and return the raw result (debug
           tool).
        """
        # The spoke must be connected.
        hub = app.state.hub
        if hub._primary_key(spoke_id) not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Spoke {spoke_id} not connected")

        # Relay the probe; any failure is a 500.
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
        # Read the cached payload and its age.
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
        # Read the in-memory event and log buffers for this spoke.
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
        # A missing or invalid JSON body is treated as empty.
        hub = app.state.hub
        try:
            data = await request.json()
        except Exception:
            data = {}
        pause = bool(data.get("pause", False))

        # Get (or create) this spoke's recovery state.
        st = hub.spoke_recovery.setdefault(hub._primary_key(spoke_id), {"attempts": 0})
        # Pause: stop restart attempts and record the event.
        if pause:
            st["manual_pause"] = True
            st["in_progress"] = False
            action, event = "paused", "recovery_paused"
            hub.record_spoke_event(spoke_id, "recovery_paused", "manual pause set via WebUI")
            logger.info(f"[recovery] spoke_id={spoke_id} action=paused reason=manual_override")
        # Resume: clear the pause.
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
        # Make the Diagnostics view refresh soon to show the change.
        _bust_diag_cache()
        return {"status": "ok", "spoke_id": spoke_id, "paused": pause}

    @app.post("/api/bug-report")
    async def file_bug_report(request: Request):
        """File a Bug from the WebUI footer button.

        Body: {explanation, severity, console_logs, html, screenshot, context}.
        The hub stores the full artifacts (console/HTML/screenshot) under
        data_dir/bugs/<id>/ and logs a short greppable [bug-report] marker so
        ab's scan_bugs finds it. The marker line carries only the id +
        a summary — the large payloads never go into the hub log. Any
        authenticated user can file (the /api/ prefix is auth-gated but not
        admin-only, unlike /setup/). ab later files a clean-body GitHub
        issue and pulls these artifacts from the hub for fix context.
        """
        hub = app.state.hub
        # The body must be valid JSON with a non-empty explanation.
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        if not isinstance(data, dict) or not str(data.get("explanation") or "").strip():
            raise HTTPException(status_code=400, detail="Missing explanation")

        # Store the report and return its id.
        return {"status": "ok", "id": await store_bug_report(hub, ctx, request, data)}

    @app.get("/api/whats-new")
    async def whats_new():
        """List recently merged bug fixes + features for the "What's New" popover.

        Merges THREE independent sources:
        1. bug-store reports ab has built & closed — its MARK_BUG_FIXED cascade
           flips the report to status=="fixed" with a fixed_at epoch + the closed
           issue_url — of type bug or feature (see _committed_features). This is
           the only source that existed before; it's empty for a PR that was
           merged directly and never went through the WebUI "File a Bug" flow.
        2. this hub's own recently-merged GitHub pull requests (whats_new_prs),
           classified from the PR's HEAD BRANCH NAME (feat/feature/perf -> feature,
           fix/hotfix/bugfix -> bug; an unrecognised prefix is skipped, not
           guessed). ``promote/*`` and ``backmerge/*`` branches (and matching
           title prefixes) are excluded as release-flow noise — the real PR they
           carry already appears on its own.
        3. the commits on this hub's own checkout (whats_new_prs.recent_commit_items).
           Most work reaches main as direct commits carried by those excluded
           promote/* PRs, so without this source it never showed up.

        The lists are merged, deduped by normalized summary (bug-store first,
        then PRs, then commits — the first wins), sorted newest-first by
        fixed_at, and capped at 30 (_dedupe_and_cap). Each item carries a
        ``type`` so the UI can badge "Bug fix" vs "Feature". Readable by ANY
        authenticated user: the /api/ prefix is session-gated but not
        admin-only (unlike /setup/bug-reports, which is global-admin gated).
        _list_bug_reports is an in-memory read, so no to_thread; the PR fetch
        is wrapped so a GitHub outage never turns this into a 500 — it just
        falls back to the bug-store-only result.
        """
        hub = app.state.hub
        # Source 1: fixed reports from the bug store.
        bug_items = _committed_features(hub._list_bug_reports())
        # Source 2: merged PRs; any failure leaves this list empty.
        pr_items = []
        try:
            # Repos to read from settings (default list), as (owner, name) pairs.
            gc = hub.state.system_state.get("global_config", {}) or {}
            repos = gc.get("whats_new_repos") or list(_WHATS_NEW_REPOS)
            slugs = [(o, n) for o, _, n in (str(r or "").partition("/") for r in repos) if o and n]
            if slugs:
                # Fetch all repos in parallel; a failing repo is logged and skipped.
                fetched = await asyncio.gather(
                    *(fetch_recent_merged_prs(o, n, within_days=_WHATS_NEW_DAYS) for o, n in slugs),
                    return_exceptions=True,
                )
                prs = []
                for result in fetched:
                    if isinstance(result, Exception):
                        logger.warning("whats-new: PR fetch failed: %s", result)
                        continue
                    prs.extend(result)
                # Turn PRs into popover items.
                pr_items = merged_prs_to_items(prs, within_days=_WHATS_NEW_DAYS)
        except Exception as e:  # noqa: BLE001 — PR source must never break the popover
            logger.warning("whats-new: PR source failed: %s", e)
            pr_items = []
        # Source 3: recent commits on this hub's checkout, read off the event loop.
        commit_items = []
        try:
            commit_items = await asyncio.to_thread(
                recent_commit_items, _WHATS_NEW_DAYS,
                repo_url=f"https://github.com/{_WHATS_NEW_REPOS[0]}")
        except Exception as e:  # noqa: BLE001 — never break the popover
            logger.warning("whats-new: commit source failed: %s", e)
        # Merge, dedupe and cap the three sources.
        return {"features": _dedupe_and_cap(bug_items + pr_items + commit_items)}

    # Bug Reports log view (admin-only, like the rest of /setup/): lists filed
    # reports and serves the full artifacts (console/HTML/screenshot) for an
    # expandable detail modal. Reuses the hub's _list_bug_reports /
    # _get_bug_report helpers so the UI and ab see the same data.
    @app.get("/setup/bug-reports")
    async def list_bug_reports():
        """List all filed bug reports and feature requests, newest first."""
        # Read the stored reports and sort newest first.
        hub = app.state.hub
        reports = hub._list_bug_reports()
        reports.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return {"reports": reports}

    @app.get("/setup/bug-reports/{rid}")
    async def get_bug_report(rid: str):
        """Return one bug report with its artifacts, or 404."""
        # Read the report off the event loop.
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
        issue ab may already have filed is NOT touched — only the hub's
        local copy of the captured artifacts."""
        # Delete off the event loop; False means it did not exist.
        hub = app.state.hub
        ok = await asyncio.to_thread(hub._delete_bug_report, rid)
        if not ok:
            raise HTTPException(status_code=404, detail="Bug report not found")
        return {"status": "ok", "id": rid}

    @app.post("/setup/bug-reports/{rid}/approve")
    async def approve_bug_report(rid: str):
        """Admin approves a feature request (admin-only, like the rest of /setup/).
        Marks it 'approved' so GET_BUG_REPORTS exposes it to ab, which then
        files the GitHub issue and works the feature. Bugs never need this gate."""
        # Mark it approved off the event loop; False means it did not exist.
        hub = app.state.hub
        ok = await asyncio.to_thread(hub._approve_bug_report, rid)
        if not ok:
            raise HTTPException(status_code=404, detail="Bug report not found")
        return {"status": "ok", "id": rid, "state": "approved"}

    # ── Tenant-admin READ-ONLY view (/tenant/bug-reports) ─────────────────────
    # A tenant admin sees Bug Reports + Feature Requests filed under their own
    # tenant(s) — never any other tenant's, and never the mutate actions
    # (approve/delete stay Global-Admin-only under /setup/). The /tenant/* prefix
    # is gated to tenant-admins + Global Admins by the access-control middleware;
    # per-report ownership is enforced here (anti cross-tenant IDOR).
    def _bug_acting_tenants(sess):
        """Return the tenant ids assigned to the session's user."""
        return (sess or {}).get("user", {}).get("tenants") or []

    def _bug_report_tenant(r):
        """The tenant a report is attributed to. Prefer the authoritative,
        server-resolved top-level ``tenant_id`` (set at file time, browser can't
        spoof it); fall back to the tenant captured in the report's
        ``context.currentTenant`` so LEGACY reports — filed before tenant_id was
        recorded — still scope by the tenant that's already in the bug."""
        # Use the stored tenant_id when set.
        r = r or {}
        tid = str(r.get("tenant_id") or "").strip()
        if tid:
            return tid
        # Otherwise fall back to the tenant recorded in the report's context.
        cmeta = r.get("context") or {}
        if isinstance(cmeta, dict):
            ctid = str(cmeta.get("currentTenant") or "").strip()
            # 'default' is the WebUI no-tenant sentinel, not a real tenant.
            return "" if ctid == "default" else ctid
        return ""

    def _bug_report_visible(sess, r):
        """Global Admin → every report; tenant-admin → only reports attributed
        to one of their tenants (top-level tenant_id, else the tenant in the
        report's context). Untagged reports stay Global-Admin-only, so a tenant
        admin never sees a report not attributed to their tenant (mirrors
        tenant_devices._owns)."""
        # Global Admins see everything.
        if ctx._is_admin(sess):
            return True
        # Others see only reports tagged with one of their tenants.
        tid = _bug_report_tenant(r)
        return bool(tid) and tid in _bug_acting_tenants(sess)

    @app.get("/tenant/bug-reports")
    async def tenant_list_bug_reports(request: Request):
        """Tenant-scoped, read-only mirror of /setup/bug-reports. Returns only
        reports filed under one of the caller's tenants (Global Admin sees all)."""
        # Keep only reports this caller may see, newest first.
        hub = app.state.hub
        sess = ctx._session_user(request)
        reports = [r for r in hub._list_bug_reports() if _bug_report_visible(sess, r)]
        reports.sort(key=lambda r: r.get("ts", 0), reverse=True)
        return {"reports": reports}

    @app.get("/tenant/bug-reports/{rid}")
    async def tenant_get_bug_report(request: Request, rid: str):
        """Tenant-scoped detail. A report the caller's tenant doesn't own is
        reported as 404 (never 403) so existence never leaks across tenants."""
        # Read the report and hide it unless the caller may see it.
        hub = app.state.hub
        sess = ctx._session_user(request)
        rep = await asyncio.to_thread(hub._get_bug_report, rid)
        if not rep or not _bug_report_visible(sess, rep):
            raise HTTPException(status_code=404, detail="Bug report not found")
        return rep

    # ── LDAP relay (/api/ldap/*) ──────────────────────────────────────────────
