"""Syslog routes (``/api/syslog/*``), all tenant-scoped (docs/syslog.md).

The hub never carries message traffic: devices send syslog to their tenant's
collectors, and these routes only relay commands to the tenant's logging
spokes (``hub.get_logging_spokes_for_tenant``) and merge the answers. Another
tenant's collectors are never asked. The overview renders from the hub cache
(``SyslogCacheMixin``); settings and the archive live in ``syslog_archive``.
"""

import asyncio
from typing import Any, Dict, List, Optional

import access
import syslog_archive as sa
from api import HTTPException, Request, logger

# Query limits and fan-out bounds.
QUERY_DEFAULT_LIMIT = 500
QUERY_MAX_LIMIT = 5000
QUERY_TIMEOUT_S = 45.0
PREVIEW_TIMEOUT_S = 60.0
DIAG_TIMEOUT_S = 60.0
FANOUT = 8
# SYSLOG_QUERY fields relayed as given (after type checks).
_QUERY_TEXT_FIELDS = ("host", "program", "text")


def _float_or_none(body, key) -> Optional[float]:
    """``body[key]`` as a float, None when absent; ValueError when not a number."""
    val = body.get(key)
    if val is None or val == "":
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be a number") from None


def build_query(body) -> Dict[str, Any]:
    """Validate a query body into the SYSLOG_QUERY payload (no ``collector``)."""
    if not isinstance(body, dict):
        raise ValueError("body must be an object")
    q: Dict[str, Any] = {}
    # Time range and live-tail cursor.
    for key in ("start", "end", "after_ts"):
        val = _float_or_none(body, key)
        if val is not None:
            q[key] = val
    # Text filters.
    for key in _QUERY_TEXT_FIELDS:
        if body.get(key) not in (None, ""):
            q[key] = str(body[key])[:500]
    # Severity ceiling 0..7.
    if body.get("severity_max") not in (None, ""):
        try:
            sev = int(body["severity_max"])
        except (TypeError, ValueError):
            raise ValueError("severity_max must be 0-7") from None
        if not 0 <= sev <= 7:
            raise ValueError("severity_max must be 0-7")
        q["severity_max"] = sev
    # Result limit, capped.
    try:
        limit = int(body.get("limit") or QUERY_DEFAULT_LIMIT)
    except (TypeError, ValueError):
        raise ValueError("limit must be a number") from None
    q["limit"] = max(1, min(limit, QUERY_MAX_LIMIT))
    return q


def merge_results(rows: List[Dict[str, Any]], limit: int) -> Dict[str, Any]:
    """Merge per-collector query replies newest-first and cut to ``limit``.

    ``rows`` are ``{"collector", "reply", "error"}``. Returns the route body:
    ``{"messages", "sources", "errors", "truncated"}``."""
    messages, sources, errors, truncated = [], {}, [], False
    for row in rows:
        # A collector that could not be asked is an error, not "no data".
        if row.get("error"):
            errors.append({"collector": row["collector"], "error": row["error"]})
            continue
        reply = row.get("reply") or {}
        src = str(reply.get("source") or "local")
        sources[src] = sources.get(src, 0) + 1
        truncated = truncated or bool(reply.get("truncated"))
        # A partial answer carries its own error (archive unreachable).
        if reply.get("error"):
            errors.append({"collector": row["collector"], "error": str(reply["error"])})
        for m in reply.get("messages") or []:
            if isinstance(m, dict):
                messages.append({**m, "collector": row["collector"]})
    # Newest first, then cut.
    messages.sort(key=lambda m: float(m.get("ts") or 0), reverse=True)
    if len(messages) > limit:
        messages, truncated = messages[:limit], True
    return {"messages": messages, "sources": sources, "errors": errors, "truncated": truncated}


def archive_cutoff(collectors: List[Dict[str, Any]], sids: List[str]) -> Optional[float]:
    """The newest "oldest local message" across the asked collectors (from the
    overview cache), or None when none is known. Every collector holds local
    data from this point on, so local answers [cut-off, end] and the archive
    answers the time before it."""
    asked = set(sids)
    oldest = [(c.get("collector") or {}).get("oldest_ts") for c in collectors
              if c.get("spoke_id") in asked]
    known = [float(o) for o in oldest if o is not None]
    return max(known) if known else None


def register(app, hub, ctx):
    """Register the /api/syslog routes."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin

    def _scope(request: Request, *, manage: bool = False):
        """``(sess, tenant, is_global_admin)`` for the request, or raise.

        Read: Global Admin or a member of the tenant. ``manage`` (settings,
        archive, diagnostics): Global Admin or a tenant admin of the tenant.
        Syslog has no per-tenant slice, so the shared tenant's collectors are
        only visible to its own members (no "filtered" shared view)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Not logged in")
        tenant = access.request_effective_tenant(sess, request)
        if not tenant:
            raise HTTPException(status_code=400, detail="Select a tenant first")
        is_ga = _is_admin(sess)
        member = tenant in ((sess.get("user") or {}).get("tenants") or [])
        if not is_ga and not member:
            raise HTTPException(status_code=403, detail="No access to this tenant's syslog")
        if manage and not is_ga and not _is_tenant_admin(sess):
            raise HTTPException(status_code=403, detail="Tenant admin required")
        return sess, tenant, is_ga

    def _spokes(tenant, collector: Optional[str] = None) -> List[str]:
        """The tenant's logging spokes, optionally only the named collector."""
        sids = sa.logging_spokes(hub, tenant)
        if collector:
            sids = [s for s in sids if sa.collector_name(hub, s) == collector]
            if not sids:
                raise HTTPException(status_code=404,
                                    detail=f"Collector '{collector}' is not connected")
        return sids

    async def _fan_out(tenant, sids, cmd, data, timeout, label) -> List[Dict[str, Any]]:
        """Send ``cmd`` to each collector (bounded); one ``{collector, reply,
        error}`` row each. Errors are logged with the collector name.
        ``data`` may be a function of the collector's index for per-collector payloads."""
        sem = asyncio.Semaphore(FANOUT)

        async def one(i, sid):
            """Ask one collector."""
            name = sa.collector_name(hub, sid)
            payload = data(i) if callable(data) else data
            async with sem:
                try:
                    reply = sa.unwrap(await hub.request_response(sid, cmd, payload, timeout=timeout))
                    err = sa.reply_error(reply)
                except Exception as e:  # noqa: BLE001 - one collector must not fail the rest
                    reply, err = None, str(e) or type(e).__name__
            if err:
                logger.warning("syslog: %s for tenant %s: collector %s: error %s",
                               label, tenant, name, err)
            return {"collector": name, "reply": None if err else reply, "error": err}

        return list(await asyncio.gather(*(one(i, s) for i, s in enumerate(sids))))

    # ── overview ─────────────────────────────────────────────────────────────

    @app.get("/api/syslog/overview")
    async def syslog_overview(request: Request):
        """Collectors, merged sources and the archive, from the hub cache."""
        _sess, tenant, is_ga = _scope(request)
        entry = hub.syslog_cache_get(tenant)
        # First visit for this tenant: fill the cache once, live.
        if entry is None and sa.logging_spokes(hub, tenant):
            entry = await hub.refresh_syslog_tenant(tenant)
        entry = entry or {}
        archive = sa.public_archive(sa.get_archive(hub, tenant), include_ui=is_ga)
        if archive is not None and entry.get("archive_host"):
            archive["host_status"] = entry["archive_host"]
        collectors = [{k: v for k, v in c.items() if k != "spoke_id"}
                      for c in entry.get("collectors") or []]
        return {"collectors": collectors, "archive": archive,
                "sources": entry.get("sources") or [], "cached_at": entry.get("fetched_at"),
                "stale": hub.syslog_policy.is_stale(entry.get("fetched_at"))}

    # ── query ────────────────────────────────────────────────────────────────

    @app.post("/api/syslog/query")
    async def syslog_query(request: Request):
        """Search the tenant's collectors (and, through them, the archive)."""
        _sess, tenant, _ga = _scope(request)
        body = await request.json()
        try:
            q = build_query(body)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        sids = _spokes(tenant, (body or {}).get("collector") or None)
        # One local/archive cut-off for every collector, so their parts neither
        # overlap nor leave a gap; only the first also searches the shared
        # archive, so archive rows are not duplicated.
        cached = (hub.syslog_cache_get(tenant) or {}).get("collectors") or []
        cut = archive_cutoff(cached, sids)
        extra = {"archive_before": cut} if cut is not None else {}
        rows = await _fan_out(tenant, sids, "SYSLOG_QUERY",
                              lambda i: {**q, **extra, "use_archive": i == 0}, QUERY_TIMEOUT_S, "query")
        return merge_results(rows, q["limit"])

    # ── settings ─────────────────────────────────────────────────────────────

    @app.get("/api/syslog/settings")
    async def syslog_settings_get(request: Request):
        """The tenant's drop rules, retention and size cap."""
        _sess, tenant, _ga = _scope(request)
        return {"settings": sa.get_settings(hub, tenant),
                "limits": {"max_drop_rules": sa.MAX_DROP_RULES, "fields": list(sa.RULE_FIELDS),
                           "ops": list(sa.RULE_OPS)}}

    @app.put("/api/syslog/settings")
    async def syslog_settings_put(request: Request):
        """Validate + save the tenant's settings and push them to its collectors."""
        _sess, tenant, _ga = _scope(request, manage=True)
        body = await request.json()
        try:
            settings = sa.validate_settings(body, sa.get_settings(hub, tenant))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        sa.save_settings(hub, tenant, settings)
        logger.info("syslog: settings saved for tenant %s (%d drop rule(s), %sh, %s MB)",
                    tenant, len(settings["drop_rules"]), settings["retention_hours"],
                    settings["max_mb"])
        results = await sa.push_to_tenant(hub, tenant, settings, reason="settings saved")
        return {"settings": settings, "results": _public_results(results)}

    @app.post("/api/syslog/drop-preview")
    async def syslog_drop_preview(request: Request):
        """How many of the last hour's messages the given rules would drop."""
        _sess, tenant, _ga = _scope(request)
        body = await request.json()
        try:
            rules = sa.validate_drop_rules((body or {}).get("drop_rules"))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        rows = await _fan_out(tenant, _spokes(tenant), "SYSLOG_DROP_PREVIEW",
                              {"drop_rules": rules}, PREVIEW_TIMEOUT_S, "drop preview")
        return sum_previews(rows, len(rules))

    # ── archive ──────────────────────────────────────────────────────────────

    @app.put("/api/syslog/archive")
    async def syslog_archive_put(request: Request):
        """Connect (or update) an external archive server for the tenant."""
        sess, tenant, is_ga = _scope(request, manage=True)
        body = await request.json()
        try:
            results = await sa.save_external_archive(hub, tenant, body, sess, is_admin=is_ga)
        except sa.ArchiveConflict as e:
            raise HTTPException(status_code=409, detail=str(e))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"archive": sa.public_archive(sa.get_archive(hub, tenant), include_ui=is_ga),
                "results": _public_results(results)}

    @app.delete("/api/syslog/archive")
    async def syslog_archive_delete(request: Request):
        """Disconnect the tenant's external archive (409 for an LM-installed one)."""
        _sess, tenant, _ga = _scope(request, manage=True)
        try:
            results = await sa.delete_external_archive(hub, tenant)
        except sa.ArchiveConflict as e:
            raise HTTPException(status_code=409, detail=str(e))
        return {"archive": None, "results": _public_results(results)}

    # ── diagnostics ──────────────────────────────────────────────────────────

    @app.get("/api/syslog/diagnostics")
    async def syslog_diagnostics(request: Request, collector: str = ""):
        """Relay SYSLOG_DIAG to one of the tenant's collectors (troubleshooting)."""
        _sess, tenant, _ga = _scope(request, manage=True)
        if not collector:
            raise HTTPException(status_code=400, detail="collector is required")
        sid = _spokes(tenant, collector)[0]
        logger.info("syslog: diagnostics requested for collector %s (tenant %s)",
                    collector, tenant)
        rows = await _fan_out(tenant, [sid], "SYSLOG_DIAG", {}, DIAG_TIMEOUT_S, "diagnostics")
        if rows[0]["error"]:
            raise HTTPException(status_code=502,
                                detail=f"Collector {collector}: {rows[0]['error']}")
        return {"collector": collector, "diag": rows[0]["reply"]}


def _public_results(results) -> List[Dict[str, Any]]:
    """Push results without spoke ids (names only in the UI)."""
    return [{k: v for k, v in r.items() if k != "spoke_id"} for r in results or []]


def sum_previews(rows: List[Dict[str, Any]], n_rules: int) -> Dict[str, Any]:
    """Add up per-collector SYSLOG_DROP_PREVIEW replies."""
    out = {"scanned": 0, "dropped": 0, "per_rule": [0] * n_rules, "errors": []}
    for row in rows:
        if row.get("error"):
            out["errors"].append({"collector": row["collector"], "error": row["error"]})
            continue
        reply = row.get("reply") or {}
        out["scanned"] += int(reply.get("scanned") or 0)
        out["dropped"] += int(reply.get("dropped") or 0)
        for i, n in enumerate((reply.get("per_rule") or [])[:n_rules]):
            out["per_rule"][i] += int(n or 0)
    return out
