"""ClearPass (CPPM/NAC) device/session/enrichment routes."""
# Runs the per-spoke fan-out queries in parallel.
import asyncio
import datetime as _dt
# Hash the NAC ownership settings into the cache keys.
import hashlib
import json

# Every tenant id (for the background cache feed).
from access import all_tenant_ids
# Shared Hub helpers: HTTP error type, request, spoke-reply unwrap, tenant access and logger.
from api import (
    HTTPException, Request, _unwrap_spoke, access, get_tenant_scoping, logger,
)
# The NAC records that configure a spoke, the legacy single ClearPass config,
# and what a spoke holds once it is sent a record.
from hub_spoke_registry import _nac_spoke_records, nac_legacy_record, nac_push_key
# Marker that tags a tenant's own-CPPM records so the subnet filter skips them.
from simulations import tenant_filter
# Hub data-cache job description, the "all tenants" scope, and the error a
# read raises while a failed query's refresh floor holds.
from warm_cache import ALL_SCOPE, CacheFloorError, CacheJob

ACCESS_TRACKER_LOOKBACK_HOURS = 24
ACCESS_TRACKER_FETCH_PAGE_SIZE = 1000
ACCESS_TRACKER_MAX_PAGES = 10
# Part of the cache key; bump it when the cached query or its result shape
# changes, so startup drops the old entries instead of serving them.
ACCESS_TRACKER_CACHE_VERSION = 3
# Hard floor between 24-hour history queries for one scope: each one pages
# through ClearPass, so page reads, login kicks and the refresh button honour
# it, failed queries included.
ACCESS_TRACKER_MIN_INTERVAL_S = 300.0
# The one Access Tracker query: the feed and the page read share its entry.
ACCESS_TRACKER_QUERY = {"limit": ACCESS_TRACKER_FETCH_PAGE_SIZE, "offset": 0,
                        "lookback_hours": ACCESS_TRACKER_LOOKBACK_HOURS}

# NAC datasets kept warm by the hub data cache: (spoke command, list field,
# default payload). The default payload is what the WebUI requests, so the
# feed refreshes exactly the entry the page reads.
NAC_FEED_READS = (
    ("LIST_ENDPOINTS", "devices", {}),
    ("CPPM_GET_ACCESS_TRACKER", "sessions", ACCESS_TRACKER_QUERY),
)

# ClearPass roles offered as per-device overrides (one list for every tenant).
ROLE_OVERRIDE_PREFIX = "SSPLM-"
ROLE_OVERRIDE_NS = "nac_role_overrides"

# Every hub cache namespace holding data read from a ClearPass: the fed
# lists (namespace = the lower-cased command), each spoke's status and the
# role list.
NAC_CACHE_NAMESPACES = tuple(cmd.lower() for cmd, _, _ in NAC_FEED_READS) + (
    "cppm_get_nac_status", ROLE_OVERRIDE_NS)


def nac_cache_fingerprint(hub) -> str:
    """A short hash of the saved settings that decide which ClearPass answers
    for whom. Every NAC cache key ends in ``src=<fingerprint>``, so an entry
    cached under other settings is never read again, even when the drop that
    follows a change was lost to a crash or a restart.

    It covers each NAC record's tenant and host (or the legacy single
    ClearPass host), each NAC spoke's tenant binding, and which tenants are
    shared or have a shared-access mode other than ``auto``. It leaves out
    the spoke a record is on: moving a record to another spoke keeps its
    tenant and ClearPass, so its cached data stays valid
    (``instance_relocate``). The status key names the spoke's ClearPass for
    that reason (``nac_status_key``). Only saved settings count, never which
    spokes are connected, so the caches stay warm across a restart."""
    gc = hub.state.get_global_config() or {}
    # Each NAC record's tenant and host, or the legacy single ClearPass.
    records = [r for r in gc.get("nac_instances") or [] if isinstance(r, dict)]
    legacy = nac_legacy_record(gc)
    hosts = sorted((access._norm_tenant_id(r.get("tenant_id")), str(r.get("host") or "").strip())
                   for r in records + ([legacy] if legacy else []))
    # Each NAC spoke's tenant binding.
    meta = (getattr(hub.state, "system_state", None) or {}).get("module_metadata") or {}
    bindings = sorted((sid, access._norm_tenant_id(m.get("tenant_id")))
                      for sid, m in meta.items()
                      if isinstance(m, dict) and access.spoke_module_type(hub, sid) == "nac")
    # The shared tenant and every tenant that does not use the default
    # (auto) shared access; plain tenants do not change who reads what.
    sharing = []
    tenants = (getattr(hub.state, "tenant_state", None) or {}).get("tenants") or {}
    for tid, cfg in tenants.items():
        if not isinstance(cfg, dict):
            continue
        mode = str(cfg.get("shared_access") or "auto").strip().lower()
        if cfg.get("shared") or mode != "auto":
            sharing.append((access._norm_tenant_id(tid), bool(cfg.get("shared")), mode))
    blob = json.dumps([hosts, bindings, sorted(sharing)])
    return hashlib.sha1(blob.encode()).hexdigest()[:12]


def _refuse_if_nac_changed(hub, fp: str) -> None:
    """Refuse a NAC fetch whose cache key was made under other NAC settings
    than the current ones (``nac_cache_fingerprint``): the ClearPass that
    answers now may not be the one the key names, so nothing may be stored
    under it. The next read or feed pass makes its key from the current
    settings."""
    if nac_cache_fingerprint(hub) != fp:
        raise HTTPException(status_code=503, detail="NAC settings changed; retry")


def nac_payload_sig(cmd: str, payload: dict, fp: str) -> str:
    """The part of a NAC list's cache key after its scope: the request
    payload, the Access Tracker snapshot version, and the ownership
    fingerprint ``fp`` (``nac_cache_fingerprint``)."""
    parts = [f"{k}={v}" for k, v in sorted((payload or {}).items())]
    if cmd == "CPPM_GET_ACCESS_TRACKER" and (payload or {}).get("lookback_hours"):
        # Do not reuse first-page entries from the pre-snapshot query.
        parts.append(f"snapshot={ACCESS_TRACKER_CACHE_VERSION}")
    parts.append(f"src={fp}")
    return ",".join(parts)


def nac_status_key(hub, spoke_id: str, fp: str = None) -> str:
    """The cache key of one NAC spoke's status (its ClearPass's totals): the
    spoke, the ClearPass the hub sends it (``nac_push_key`` of its first
    record, as the push sends) and the ownership fingerprint. The
    fingerprint leaves out which spoke a record is on, so the key names the
    ClearPass itself: a record moved onto or off the spoke never serves the
    totals of the ClearPass the spoke held before."""
    records = _nac_spoke_records(hub, spoke_id)
    held = (nac_push_key(records[0]) if records else None) or ""
    return f"{spoke_id}|{held}|src={fp or nac_cache_fingerprint(hub)}"


def drop_nac_caches(hub) -> int:
    """Drop every cached NAC entry after a change to which ClearPass answers
    for whom: a NAC instance added, changed, moved or deleted, a NAC spoke
    bound to another tenant, a new legacy config, or a sharing change. The
    keys already carry the ownership fingerprint (``nac_cache_fingerprint``),
    so no entry cached before the change is read again even without this.
    The drop frees those entries now and detaches the fetches still running
    under the old settings. Returns the entries dropped."""
    if not hasattr(hub, "warm_drop"):
        return 0
    n = sum(hub.warm_drop(ns, ("",)) for ns in NAC_CACHE_NAMESPACES)
    if n:
        logger.info("NAC: dropped %d cached NAC entries after a NAC ownership change", n)
    return n


def drop_orphan_nac_caches(hub, fp: str) -> int:
    """Drop the NAC cache keys no current read uses, so they do not pile up
    in memory and in the saved cache: keys made under another ownership
    fingerprint than ``fp`` (a change whose drop a crash or restart lost, or
    a change no drop follows, such as a new NAC spoke), and Access Tracker
    keys from earlier cache shapes (the admin fan-out, the global scope,
    per-page and older-snapshot keys). Each key goes with its entry, read
    job, failure floor and running fetch (``warm_drop``). Keys are matched
    exactly, because a current key starts with an older one. Returns the
    keys dropped."""
    tracker_sig = nac_payload_sig("CPPM_GET_ACCESS_TRACKER", ACCESS_TRACKER_QUERY, fp)

    def current(ns, key):
        """Whether a current read or the feed uses ``key`` in ``ns``."""
        if ns == "cppm_get_access_tracker":
            # Only each tenant's full-history snapshot is read today.
            return (key.startswith("_all_:") and not key.startswith("_all_:_global_|")
                    and key.split("|", 1)[1:] == [tracker_sig])
        if ns == "cppm_get_nac_status":
            return key == nac_status_key(hub, key.split("|", 1)[0], fp)
        return key.endswith(f"src={fp}")

    # Drop the rest, namespace by namespace.
    dropped = 0
    for ns in NAC_CACHE_NAMESPACES:
        orphans = tuple(k for k in hub.cache_keys(ns) if not current(ns, k))
        if orphans:
            hub.warm_drop(ns, orphans, exact=True)
            logger.info("NAC: dropped %d %s cache keys no current read uses", len(orphans), ns)
            dropped += len(orphans)
    return dropped


def _access_tracker_sort_key(session):
    """Sort normalized ClearPass timestamps chronologically, including offsets."""
    if not isinstance(session, dict) or not session.get("start_time"):
        return float("-inf")
    try:
        value = str(session["start_time"]).replace("Z", "+00:00")
        timestamp = _dt.datetime.fromisoformat(value)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=_dt.timezone.utc)
        return timestamp.timestamp()
    except (OverflowError, OSError, TypeError, ValueError):
        return float("-inf")


def register(app, hub, ctx):
    """Register cppm routes on the Hub app."""
    # Session, admin and tenant-filter helpers from the shared route context.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _effective_tenant = ctx._effective_tenant
    _effective_tenant_slug = ctx._effective_tenant_slug
    _filter_session = ctx._filter_session
    _filter_tenant = ctx._filter_tenant
    _gate_record_tenant = ctx._gate_record_tenant

    # ── tenant-aware spoke resolution ───────────────────────────────────────
    # Multiple ``nac`` spokes may be connected, each bound to a different
    # tenant (a tenant runs their own ClearPass appliance). Tenant requests
    # resolve through their own/shared spoke set; global requests use only an
    # unassigned or configured shared spoke, never an arbitrary tenant spoke.
    def _nac_spoke_for_request(request: Request, tenant: str = None):
        """The nac spoke that should answer THIS request, for reads whose
        rows the caller subnet-filters (device detail, sessions, logs) and
        the admin-only diagnostics. ``hub.get_cppm_spoke_for_scope``: the
        tenant's own ClearPass, else the shared one when the tenant may use
        it, so a tenant on the shared ClearPass reads its own rows the way
        the Access Tracker does; never another tenant's spoke. An admin with
        no tenant or ADMIN selected gets only the global/shared source; the
        all-tenant NAC page uses ``_nac_merge_fanout`` instead."""
        return hub.get_cppm_spoke_for_scope(_effective_tenant(request, tenant))

    def _nac_own_spoke_for_request(request: Request, tenant: str = None):
        """The nac spoke for an appliance-wide read (the NAC totals, the role
        list): the tenant's own ClearPass, the shared one for the shared
        tenant, the global source for an admin with no tenant selected.
        These answers cover every tenant on the appliance and have no rows
        to subnet-filter, so a tenant that only uses the shared ClearPass
        gets a 403 instead of other tenants' totals. No spoke at all is the
        usual 503."""
        # Resolve as before this change: own, shared tenant, or global.
        tid = _effective_tenant(request, tenant)
        if not tid:
            spoke = hub.get_cppm_spoke_for_global()
        elif access.tenant_is_shared(tid):
            spoke = hub.get_cppm_spoke_for_shared()
        else:
            spoke = hub.get_cppm_spoke_for_tenant(tid)
        if spoke:
            return spoke
        # Only the shared ClearPass serves this tenant: refuse, don't say "no spoke".
        if tid and hub.get_cppm_spoke_for_scope(tid):
            raise HTTPException(
                status_code=403,
                detail="This tenant uses the shared ClearPass, whose totals and "
                       "roles cover every tenant.")
        raise HTTPException(status_code=503, detail="No spoke connected")

    def _nac_fanout_tag(sid) -> str:
        """The tenant the admin fan-out labels a NAC spoke's rows with
        (``_tenant``): the tenant whose ClearPass the spoke serves
        (``hub.get_nac_spoke_owner``), so tenant A's record moved onto a
        spoke bound to tenant B keeps A's label. The shared ClearPass gets
        the shared tenant's label, as its binding gave before; an unassigned
        or admin-only ClearPass gets none."""
        owner = hub.get_nac_spoke_owner(sid)
        if owner and owner != access.ADMIN_ONLY_OWNER:
            return owner
        # None: the shared or an unassigned ClearPass. Label only the shared one.
        serves_shared = owner is None and (
            access.tenant_is_shared(hub.state.get_spoke_tenant(sid))
            or any(access.tenant_is_shared(r.get("tenant_id"))
                   for r in _nac_spoke_records(hub, sid)))
        return (access.shared_tenant_id() or "") if serves_shared else ""

    async def _nac_merge_fanout(cmd: str, payload: dict, list_key: str, request: Request):
        """Admin, no tenant selected: fan ``cmd`` out to EVERY usable nac spoke
        (``hub.get_nac_usable_spokes``: connected, approved, not stale and
        configured), tag each returned record with the tenant whose
        ClearPass answered (``_tenant``, see ``_nac_fanout_tag``), and merge
        into one combined list — 'combine the
        data at the hub' instead of only ever seeing whichever spoke happened
        to connect first. ``list_key`` is the response dict key holding the
        record list (e.g. "devices", "sessions"). A tenant-scoped caller
        never reaches this — see the ``tid`` check at each call site."""
        # Every usable nac spoke; none is a 503.
        spokes = hub.get_nac_usable_spokes()
        if not spokes:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Label each spoke now, with the settings that picked the spokes.
        tags = {sid: _nac_fanout_tag(sid) for sid in spokes}

        async def _one(sid):
            """Query one spoke; return its records tagged with its tenant (None on failure)."""
            try:
                result = await hub.request_response(sid, cmd, payload or {}, timeout=20.0)
                data = _cppm_unwrap(result)
            except Exception as e:  # noqa: BLE001 — one bad/offline spoke must not fail the merge
                logger.debug("nac merge fanout: %s failed: %s", sid, e)
                return None
            recs = data.get(list_key) if isinstance(data, dict) else None
            if not isinstance(recs, list):
                return None
            return [{**r, "_tenant": tags[sid]} if isinstance(r, dict) else r for r in recs]

        # Query them all at once.
        results = await asyncio.gather(*[_one(s) for s in spokes])
        if all(r is None for r in results):
            # Every spoke failed: raise rather than return an empty list, so
            # the hub cache keeps (and badges) the last-known data instead of
            # replacing it with nothing.
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Flatten into one list.
        merged = [r for recs in results if recs for r in recs]
        return {list_key: merged, "total": len(merged)}

    async def _nac_gather_merge(spokes, cmd: str, payload: dict, list_key: str,
                                own_spoke=None):
        """Query every spoke in ``spokes`` with ``cmd``, merging each response's
        ``list_key`` list into one combined list — used for a SINGLE tenant's
        combined view (their own dedicated CPPM + the shared CPPM, if any;
        see ``hub.get_cppm_spokes_for_tenant``), unlike ``_nac_merge_fanout``
        which fans out across EVERY tenant's spoke for the admin view. A spoke
        that errors is skipped rather than failing the whole call — one bad/
        offline source must not blank the other's data. Returns ``None`` only
        when every spoke fails.

        Records from ``own_spoke`` (the tenant's OWN dedicated CPPM) are
        stamped with the ``OWN_SOURCE_MARKER`` so the downstream subnet filter
        shows them all — that appliance is entirely the tenant's equipment.
        Only records merged in from a SHARED CPPM stay subject to the subnet
        filter. A spoke the hub knows has no ClearPass configured
        (``hub._nac_unconfigured_spokes``) is not queried at all."""
        # Skip spokes known to have no ClearPass configured.
        unconfigured = getattr(hub, "_nac_unconfigured_spokes", None) or set()
        spokes = [s for s in spokes if s not in unconfigured]
        if not spokes:
            return None

        async def _one(sid):
            """Query one spoke; return (sid, data), with None data on failure."""
            try:
                result = await hub.request_response(sid, cmd, payload or {}, timeout=20.0)
                return sid, _cppm_unwrap(result)
            except Exception as e:  # noqa: BLE001 — one bad/offline spoke must not fail the merge
                logger.debug("nac combine: %s failed: %s", sid, e)
                return sid, None
        # Query them all, then merge the lists, marking the tenant's own records.
        results = await asyncio.gather(*[_one(s) for s in spokes])
        merged = []
        any_ok = False
        source_error = False
        recent_window_complete = bool(payload.get("lookback_hours"))
        more_available = False
        page_limit = payload.get("limit")
        page_offset = payload.get("offset", 0)
        for sid, d in results:
            if isinstance(d, dict) and isinstance(d.get(list_key), list):
                any_ok = True
                if recent_window_complete and not d.get("window_start"):
                    recent_window_complete = False
                recs = d[list_key]
                total = d.get("total")
                if payload.get("lookback_hours"):
                    if type(total) is int:
                        more_available |= page_offset + len(recs) < total
                    elif type(page_limit) is int:
                        more_available |= len(recs) >= page_limit
                if own_spoke and sid == own_spoke:
                    recs = [{**r, tenant_filter.OWN_SOURCE_MARKER: True}
                            if isinstance(r, dict) else r for r in recs]
                merged.extend(recs)
            else:
                source_error = True
        if not any_ok:
            return None
        data = {list_key: merged, "total": len(merged)}
        if payload.get("lookback_hours"):
            data["recent_window_complete"] = recent_window_complete and not source_error
            data["source_error"] = source_error
            data["more_available"] = more_available
            data["window_end"] = payload.get("window_end")
        return data

    async def _nac_access_tracker_history(fetch_page, payload: dict,
                                          list_key: str) -> dict:
        """Gather a bounded snapshot before caching one tenant-scoped result."""
        query_payload = dict(payload)
        if not query_payload.get("window_end"):
            query_payload["window_end"] = _dt.datetime.now(
                _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        window_end = query_payload["window_end"]
        sessions = []
        recent_window_complete = True
        source_error = False
        more_available = False
        truncated = False
        # Drain source pages inside the cache fetch; the UI reads one cache key.
        for page in range(ACCESS_TRACKER_MAX_PAGES):
            page_payload = dict(query_payload)
            page_payload["offset"] = page * ACCESS_TRACKER_FETCH_PAGE_SIZE
            page_payload["window_end"] = window_end
            data = await fetch_page(page_payload)
            if not isinstance(data, dict):
                raise HTTPException(status_code=502, detail="Invalid CPPM Access Tracker response")
            if page == 0:
                window_end = data.get("window_end") or window_end
            page_sessions = data.get(list_key)
            if isinstance(page_sessions, list):
                sessions.extend(page_sessions)
            source_error |= data.get("source_error") is True
            window_complete = data.get("recent_window_complete")
            if window_complete is None:
                window_complete = bool(data.get("window_start"))
            recent_window_complete &= window_complete is True
            page_more = data.get("more_available")
            if page_more is None:
                page_more = data.get("has_more")
            if page_more is None:
                total = data.get("total")
                page_more = (type(total) is int
                             and page_payload["offset"] + len(page_sessions or []) < total)
            more_available = page_more is True
            if not more_available:
                break
            if page == ACCESS_TRACKER_MAX_PAGES - 1:
                truncated = True
        return {
            list_key: sessions,
            "total": len(sessions),
            "recent_window_complete": recent_window_complete and not source_error,
            "source_error": source_error,
            "more_available": more_available,
            "total_is_lower_bound": more_available or truncated or source_error,
            "recent_window_truncated": truncated,
            "window_end": window_end,
        }

    def nac_cache_job(cmd: str, list_key: str, tid, payload: dict = None, *,
                      fanout: bool = False, detail: bool = False,
                      fp: str = None) -> CacheJob:
        """How to fetch one NAC list for one scope — shared by the page reads
        and the background feed so both use the same cache entry.

        Scopes (namespace = ``cmd.lower()``):
          * ``tid`` set   → key ``_all_:<tid>``: the tenant's own CPPM merged
            with the shared CPPM (``get_cppm_spokes_for_tenant``).
          * ``fanout``    → key ``_fanout_``: admin, no tenant selected — every
            connected nac spoke merged, each record tagged ``_tenant``.
          * neither       → key ``_all_:_global_``: the single global nac spoke.
        The key ends in the payload and the ownership fingerprint ``fp``
        (``nac_payload_sig``; computed when not given, the feed passes it
        once per pass). The cache holds the RAW merged list; callers filter."""
        # Work out the cache key and tenant scope for this job.
        payload = dict(payload or {})
        fp = fp or nac_cache_fingerprint(hub)
        if fanout:
            base, tenants = "_fanout_", (ALL_SCOPE,)
        elif tid:
            base, tenants = f"_all_:{tid}", (tid,)
        else:
            base, tenants = "_all_:_global_", None
        key = f"{base}|{nac_payload_sig(cmd, payload, fp)}"

        async def fetch():
            """Fetch the list for this job's scope (raises 503 when no spoke answers)."""
            query_payload = dict(payload)
            if query_payload.get("lookback_hours") and not query_payload.get("window_end"):
                query_payload["window_end"] = _dt.datetime.now(
                    _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            async def fetch_page(page_payload):
                """Fetch one raw page from this cache job's source scope."""
                # Checked on every page, so a history scan never mixes pages
                # that two different owners' settings picked.
                _refuse_if_nac_changed(hub, fp)
                if fanout:
                    return await _nac_merge_fanout(cmd, page_payload, list_key, None)
                if tid:
                    spokes = hub.get_cppm_spokes_for_tenant(tid)
                    if not spokes:
                        raise HTTPException(status_code=503, detail="No spoke connected")
                    # The tenant's dedicated appliance is not subnet-filtered:
                    # only the resolver's own spoke, never the shared one.
                    data = await _nac_gather_merge(spokes, cmd, page_payload, list_key,
                                                   own_spoke=hub.get_cppm_spoke_for_tenant(tid))
                    if data is None:
                        raise HTTPException(status_code=503, detail="No spoke connected")
                    return data
                # Global: ask only the configured global/shared NAC source.
                spoke = hub.get_cppm_spoke_for_global()
                if not spoke:
                    raise HTTPException(status_code=503, detail="No spoke connected")
                return _cppm_unwrap(await hub.request_response(
                    spoke, cmd, page_payload, timeout=20.0))

            if cmd == "CPPM_GET_ACCESS_TRACKER" and query_payload.get("lookback_hours"):
                # The spoke performs each ClearPass query; the hub bounds page
                # orchestration because tenant filtering happens after merging
                # shared-source rows and is hub policy.
                return await _nac_access_tracker_history(fetch_page, query_payload, list_key)
            return await fetch_page(query_payload)

        # Build the job (namespace is the lower-cased command).
        min_interval_s = (ACCESS_TRACKER_MIN_INTERVAL_S
                          if cmd == "CPPM_GET_ACCESS_TRACKER" and payload.get("lookback_hours")
                          else 0)
        return CacheJob(cmd.lower(), key, fetch, tenants, lane="nac", detail=detail,
                        min_interval_s=min_interval_s)

    def _nac_job_for(request: Request, tenant, cmd: str, list_key: str,
                     payload: dict = None, detail: bool = False) -> CacheJob:
        """Pick the tenant, admin-fanout or global scope for a NAC list read."""
        tid = _effective_tenant(request, tenant)
        sess = _session_user(request)
        fanout = not tid and bool(sess and _is_admin(sess))
        return nac_cache_job(cmd, list_key, tid, payload, fanout=fanout, detail=detail)

    async def _nac_read(job: CacheJob):
        """Read the job's list through the hub data cache (fetching on a miss)."""
        return await hub.cache_read(job.ns, job.key, job.fetch, tenants=job.tenants,
                                    lane=job.lane, detail=job.detail,
                                    min_interval_s=job.min_interval_s)

    def role_override_job(fp: str = None) -> CacheJob:
        """The SSPLM- role list from the global ClearPass, cached for everyone
        under ``_|src=<fingerprint>``."""
        fp = fp or nac_cache_fingerprint(hub)

        async def fetch():
            """Fetch the role list from the global ClearPass."""
            _refuse_if_nac_changed(hub, fp)
            spoke = hub.get_cppm_spoke_for_global()
            if not spoke:
                raise HTTPException(status_code=503, detail="No spoke connected")
            data = _cppm_unwrap(await hub.request_response(
                spoke, "LIST_ROLES", {"prefix": ROLE_OVERRIDE_PREFIX}, timeout=30.0))
            if not isinstance(data, dict) or data.get("status") == "ERROR":
                raise HTTPException(status_code=502, detail=str((data or {}).get("message") or "LIST_ROLES failed"))
            return data
        return CacheJob(ROLE_OVERRIDE_NS, f"_|src={fp}", fetch, None, lane="nac")

    def _role_override_response(data, key: str) -> dict:
        """Role names starting with the prefix, sorted, with the cache badge
        fields of entry ``key``."""
        # Older cppm spokes ignore "prefix", so filter here too.
        names = sorted({str(r.get("name") or "") for r in (data or {}).get("roles") or []
                        if isinstance(r, dict) and str(r.get("name") or "").startswith(ROLE_OVERRIDE_PREFIX)})
        return hub.cache_annotate({"prefix": ROLE_OVERRIDE_PREFIX, "roles": names},
                                  ROLE_OVERRIDE_NS, key)

    @app.get("/api/cppm/role-overrides")
    async def get_role_overrides(request: Request):
        """ClearPass roles a device can be overridden to (cached, refreshed on a schedule)."""
        if not _session_user(request):
            raise HTTPException(status_code=401, detail="Not authenticated")
        job = role_override_job()
        return _role_override_response(await _nac_read(job), job.key)

    @app.post("/api/cppm/role-overrides/refresh")
    async def refresh_role_overrides(request: Request):
        """Re-read the role list from ClearPass now (e.g. right after adding a role)."""
        if not _session_user(request):
            raise HTTPException(status_code=401, detail="Not authenticated")
        job = role_override_job()
        data = await hub.cache_fetch_now(job.ns, job.key, job.fetch, lane=job.lane)
        return _role_override_response(data, job.key)

    def nac_cache_feed(_hub):
        """Feed devices and tenant-scoped sessions, plus roles, into the
        cache, every key made with this pass's ownership fingerprint. First
        drop the NAC entries no current key reads (``drop_orphan_nac_caches``):
        at startup those loaded from disk, later those a NAC change left."""
        fp = nac_cache_fingerprint(hub)
        try:
            drop_orphan_nac_caches(hub, fp)
        except Exception as e:  # noqa: BLE001 - cleanup must not stop the feed
            logger.warning("NAC: dropping orphan cache entries failed: %s", e)
        yield role_override_job(fp)
        # Feed the device admin view and each tenant's dataset into the cache.
        for cmd, list_key, payload in NAC_FEED_READS:
            # Access Tracker history contains tenant authentication identities;
            # do not build an unselected-admin all-tenant cache entry.
            if cmd != "CPPM_GET_ACCESS_TRACKER":
                yield nac_cache_job(cmd, list_key, None, payload, fanout=True, fp=fp)
            for tid in all_tenant_ids(hub):
                try:
                    if hub.get_cppm_spokes_for_tenant(tid):
                        yield nac_cache_job(cmd, list_key, tid, payload, fp=fp)
                except Exception:  # noqa: BLE001
                    continue

    # Register the feed with the hub data cache (if this hub has one). Its
    # first pass drops the entries loaded from disk that no key reads now.
    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("nac", nac_cache_feed)

    # Ask the nac spoke to refresh its ClearPass cache.
    @app.get("/cppm/refresh")
    async def refresh_cppm_cache(request: Request, tenant: str = None):
        """Refresh the spoke's ClearPass cache and drop our cached NAC status."""
        hub = app.state.hub
        logger.info("API: Triggering CPPM cache refresh")
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected for refresh")
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Refresh it and invalidate the cached status; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_REFRESH_CACHE", {}, timeout=20.0)
            hub.cache_refresh("cppm_get_nac_status", (nac_status_key(hub, cppm_spoke),),
                              exact=True)
            tid = _effective_tenant(request, tenant)
            if tid:
                history_job = nac_cache_job(
                    "CPPM_GET_ACCESS_TRACKER", "sessions", tid, ACCESS_TRACKER_QUERY)
                hub.cache_refresh(history_job.ns, (history_job.key,), exact=True)
            return result
        except Exception as e:
            logger.error(f"API: Error refreshing CPPM cache: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # Test the spoke's ClearPass login.
    @app.get("/api/cppm/test-auth")
    async def test_cppm_auth(request: Request, tenant: str = None):
        """Run the spoke's ClearPass auth test and return its result."""
        hub = app.state.hub
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Run the test; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "TEST_AUTH", {})
            data = _unwrap_spoke(result)
            return data
        except Exception as e:
            logger.exception("test_cppm_auth failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Call an arbitrary ClearPass API path through the spoke (debug).
    @app.get("/api/cppm/probe")
    async def probe_cppm(request: Request, path: str, method: str = "GET", tenant: str = None):
        """Have the spoke call ClearPass ``path`` with ``method`` and return the result."""
        hub = app.state.hub
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Run the call; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "PROBE_API", {"path": path, "method": method})
            data = _unwrap_spoke(result)
            return data
        except Exception as e:
            logger.exception("probe_cppm failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ClearPass system health.
    @app.get("/cppm/health")
    async def get_cppm_health(request: Request, tenant: str = None):
        """Return the ClearPass system health from the spoke."""
        hub = app.state.hub
        logger.info("API: Requesting CPPM health")
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Fetch and unwrap the health data; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_SYSTEM_HEALTH", {}, timeout=20.0)
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM health: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM health: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _device_tenant(d: dict) -> str:
        """A device's tenant = its NetBox_Tenant_ID endpoint attribute (the LM
        tenant id the endpoint sync writes). Empty when untagged."""
        attrs = (d.get("attributes") if isinstance(d, dict) else None) or {}
        return attrs.get("NetBox_Tenant_ID") or ""

    def _filter_devices_by_tenant(data, scope: str):
        """Tag-based tenant filter for the Device Database list. Keeps only
        devices tagged with this tenant id (the logged-in user's tenant).
        More authoritative than the subnet filter — a device tagged for tenant
        X belongs to X regardless of its IP — so a non-admin sees only their own
        tenant's devices. No scope (admin, or tenant not bound to NetBox) →
        unchanged. Preserves the response shape (status/devices/total)."""
        # Nothing to filter without a scope or a devices list.
        if not scope:
            return data
        if not isinstance(data, dict):
            return data
        devices = data.get("devices")
        if not isinstance(devices, list):
            return data
        # Keep the scope's devices and fix up the total.
        kept = [d for d in devices if isinstance(d, dict) and _device_tenant(d) == scope]
        out = dict(data)
        out["devices"] = kept
        out["total"] = len(kept)
        return out

    # ── CPPM / NAC: devices, sessions, logs, roles (/api/cppm/*) ─────────────
    # ClearPass REST ``filter`` is exact-equality only (no SQL-LIKE), so the
    # device/session list handlers do an exact MAC/IP filter first then a bounded
    # client-side substring scan (see cppm/src/queries.py SEARCH_SCAN_CAP).
    # List ClearPass devices for the caller's tenant.
    @app.get("/api/cppm/devices")
    async def get_cppm_devices(request: Request, tenant: str = None):
        """Return the ClearPass device list, filtered to the caller's tenant."""
        hub = app.state.hub
        # see _netbox_list_get (variant: admin/multi-tenant live path runs FIRST,
        # then non-admin cache path; _filter_tenant + tag filter — inline).
        # Relay trace (DEBUG so polled reads don't flood INFO): records the
        # tenant scope + that we entered the relay. Established convention —
        # every relay GET (CPPM, NetBox, pxmx, DNS, DHCP, LDAP, firewall
        # live-fetch) carries this one-liner so a slow/failed spoke round-trip
        # is traceable from logs even on the happy path (error paths already log).
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        sess = _session_user(request)
        # Tag-based tenant filter: keep only devices tagged with the effective
        # tenant's id (NetBox_Tenant_ID). The effective tenant is the selected
        # one (?tenant=) for admins / multi-tenant switches — clamped for
        # non-admins — falling back to the session tenant when nothing is
        # selected. scope=None (admin, no selection, or tenant not bound to
        # NetBox so its endpoints are never tagged) → no-op; the subnet filter
        # is the backstop.
        tid = _effective_tenant(request, tenant) if tenant or (sess and not _is_admin(sess)) else None
        bound = tid and (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
        scope = tid if bound else None
        # Filter function that applies that scope.
        tf = lambda d: _filter_devices_by_tenant(d, scope)

        # Served from the hub data cache for every user (see nac_cache_job
        # for the scope). Filters are re-applied on every read.
        job = _nac_job_for(request, tenant, "LIST_ENDPOINTS", "devices")
        data = tf(await _nac_read(job))
        # Then apply the subnet filter (selected tenant, else the session's tenant).
        if tenant and _effective_tenant(request, tenant):
            data = await _filter_tenant(request, data, "nac", ["ip"], tenant)
        else:
            data = await _filter_session(request, data, "nac", ["ip"])
        return hub.cache_annotate(data, job.ns, job.key)

    # List endpoints that aren't tagged to any tenant.
    @app.get("/api/cppm/unknown-devices")
    async def get_cppm_unknown_devices(request: Request, tenant: str = None):
        """Endpoints not assigned to any tenant (no NetBox_Tenant_ID
        attribute) — the 'Unknown Devices' tab. Subnet-scoped by the
        selected tenant so a tenant sees untagged devices on their own network;
        an admin with no tenant selected sees every untagged endpoint."""
        hub = app.state.hub
        # Admin, no tenant selected: the fan-out entry combines every connected
        # nac spoke's endpoints before filtering to untagged ones.
        # Same cached LIST_ENDPOINTS entry as the devices page.
        job = _nac_job_for(request, tenant, "LIST_ENDPOINTS", "devices")
        data = await _nac_read(job)
        # Keep only untagged endpoints (assigned to no tenant).
        if isinstance(data, dict) and isinstance(data.get("devices"), list):
            untagged = [d for d in data["devices"] if isinstance(d, dict) and not _device_tenant(d)]
            data = {**data, "devices": untagged, "total": len(untagged)}
        elif isinstance(data, list):
            data = [d for d in data if isinstance(d, dict) and not _device_tenant(d)]
        # Apply the tenant subnet filter and add the cache info.
        return hub.cache_annotate(await _filter_tenant(request, data, "nac", ["ip"], tenant),
                                  job.ns, job.key)

    def _norm_mac(m: str) -> str:
        """Return a MAC lower-cased with all separators removed ("" if empty)."""
        return m.lower().replace(":", "").replace("-", "").replace(".", "") if m else ""

    # Look up one device across every module (admins only).
    @app.get("/api/device-detail")
    async def get_device_detail(request: Request, q: str = None, mac: str = None, ip: str = None, hostname: str = None, serial: str = None, port_id: str = None, device: str = None):
        """Fan-out device lookup across all modules by MAC, IP, or hostname.

        Queries every connected spoke type (CPPM endpoints/sessions, NetBox IPs,
        OPNsense DHCP leases + firewall rules, pxmx VMs) for a match, de-dupes,
        and returns the merged record. Consumer: the WebUI device dashboard
        (``showDeviceDashboard`` in ``WebUI/main.js``). NOTE: the inner OPNsense
        loop sets ``rules_data`` from a lease-IP match even when the rules call
        itself failed — the success condition is intentionally tied to finding a
        DHCP lease, so read that block twice before changing it.

        SECURITY: admin-only. This aggregates cross-tenant recon (NAC + NetBox +
        OPNsense + Proxmox) AND a directory user search (LDAP SEARCH_USERS) by
        MAC/IP/hostname, so a non-admin caller could read another tenant's
        device record and enumerate directory users — the latter bypasses the
        ``/api/ldap/*`` admin gate. Gate the whole route behind admin to match."""
        # Local imports: parallel lookups and the query-type patterns.
        import asyncio as _asyncio, re as _re
        hub = app.state.hub
        # Must be logged in as an admin.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not _is_admin(sess):
            raise HTTPException(status_code=403,
                                detail="Admin only — cross-system device detail is admin-gated")

        # Treat blank query values as missing.
        mac = (mac or "").strip() or None
        ip = (ip or "").strip() or None
        hostname = (hostname or "").strip() or None
        serial = (serial or "").strip() or None
        port_id = (port_id or "").strip() or None
        device = (device or "").strip() or None

        # A free-text query is read as a MAC, an IP, or else a hostname.
        if q and not (mac or ip or hostname or serial):
            q = q.strip()
            if _re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', q):
                mac = q
            elif _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', q):
                ip = q
            else:
                hostname = q

        async def safe(coro):
            """Await ``coro``, turning any error into {"error": ...}."""
            try:
                return await coro
            except Exception as e:
                return {"error": str(e)}

        async def req(spoke, cmd, data):
            """Send ``cmd`` to ``spoke`` and unwrap the reply (None if there is no spoke)."""
            if not spoke:
                return None
            r = await hub.request_response(spoke, cmd, data)
            d = _unwrap_spoke(r)
            return d

        # Admin-only cross-system search (gated above) uses the global/shared
        # NAC source. It does not fan out across tenant ClearPass appliances.
        spoke_nac  = hub.get_cppm_spoke_for_global()
        fw_spokes  = hub.get_all_spokes_by_type("firewall") or []
        spoke_ipam = hub.get_spoke_by_type("ipam")
        spoke_pxmx = hub.get_hypervisor_spoke()
        spoke_ldap = hub.get_spoke_by_type("directory")

        # Queue a lookup for each module that is connected and has something to search on.
        tasks: dict = {}
        search_q = serial or mac or ip or hostname or ""

        if spoke_nac:
            if mac:
                tasks["nac_ep"]   = safe(req(spoke_nac, "GET_ENDPOINT_DETAIL", {"mac": mac}))
                tasks["nac_sess"] = safe(req(spoke_nac, "GET_DEVICE_SESSIONS", {"mac": mac}))
            elif ip or hostname:
                tasks["nac_sess"] = safe(req(spoke_nac, "SEARCH_SESSIONS", {"q": ip or hostname}))

        for fw in fw_spokes:
            tasks["dhcp"] = safe(req(fw, "OPNSENSE_GET_DHCP_LEASES", {}))
            break

        if spoke_ipam and search_q:
            tasks["netbox"] = safe(req(spoke_ipam, "NETBOX_SEARCH", {"q": search_q}))
            # A record is often keyed on another identifier (name vs IP vs serial):
            # search each one we were given and merge below.
            for extra_key, extra in (("netbox_host", hostname), ("netbox_ip", ip), ("netbox_serial", serial)):
                if extra and extra != search_q:
                    tasks[extra_key] = safe(req(spoke_ipam, "NETBOX_SEARCH", {"q": extra}))
        if spoke_pxmx and (ip or hostname):
            tasks["proxmox"] = safe(req(spoke_pxmx, "SEARCH_VMS", {"q": ip or hostname}))
        if spoke_ldap and (hostname or ip):
            tasks["ldap"] = safe(req(spoke_ldap, "SEARCH_USERS", {"q": hostname or ip}))

        # Run them all at once and key the results by name.
        gathered = await _asyncio.gather(*tasks.values())
        data = dict(zip(tasks.keys(), gathered))

        # What we know about the device so far; filled in from the results below.
        identity = {"mac": mac, "ip": ip, "hostname": hostname, "serial": serial}

        # Process DHCP — find lease by MAC or IP
        dhcp_result = None
        if "dhcp" in data and isinstance(data["dhcp"], list):
            norm_mac = _norm_mac(mac) if mac else None
            for lease in data["dhcp"]:
                if norm_mac and _norm_mac(lease.get("mac", "")) == norm_mac:
                    dhcp_result = lease
                    break
                if ip and lease.get("ip") == ip:
                    dhcp_result = lease
                    break
            if dhcp_result:
                identity["ip"]       = identity["ip"] or (dhcp_result.get("ip") if dhcp_result.get("ip") != "unknown" else None)
                identity["mac"]      = identity["mac"] or (dhcp_result.get("mac") if dhcp_result.get("mac") != "unknown" else None)
                identity["hostname"] = identity["hostname"] or (dhcp_result.get("hostname") if dhcp_result.get("hostname") not in ("unknown", "") else None)

        # Process NAC
        nac_result = None
        nac_ep = data.get("nac_ep") or {}
        nac_sess = data.get("nac_sess") or {}
        if isinstance(nac_ep, dict) and nac_ep.get("status") == "SUCCESS":
            nac_result = {**nac_ep, "sessions": nac_sess.get("sessions", []) if isinstance(nac_sess, dict) else []}
            identity["ip"]       = identity["ip"] or nac_ep.get("ip") or None
            identity["hostname"] = identity["hostname"] or nac_ep.get("hostname") or None
        elif isinstance(nac_sess, dict) and nac_sess.get("sessions"):
            nac_result = {"sessions": nac_sess["sessions"]}

        # NetBox, Proxmox and LDAP matches (empty if their lookups failed).
        nb_results = []
        _nb_seen = set()
        for _k in ("netbox", "netbox_host", "netbox_ip", "netbox_serial"):
            _v = data.get(_k)
            for _r in ((_v or {}).get("results", []) if isinstance(_v, dict) else []):
                _id = (_r.get("type"), _r.get("id"), _r.get("name"), _r.get("ip"))
                if _id not in _nb_seen:
                    _nb_seen.add(_id)
                    nb_results.append(_r)
        px_results  = (data.get("proxmox") or {}).get("results", []) if isinstance(data.get("proxmox"), dict) else []
        ld_results  = (data.get("ldap") or {}).get("results", []) if isinstance(data.get("ldap"), dict) else []

        # Console leg: find serial-console port(s) whose identified device
        # matches this record so the dashboard can offer a direct connect. Match
        # precisely on hostname/alias/IP (not a loose substring) to avoid pairing
        # the wrong device. Admin-only route → the tenant-scoped lister returns
        # the global view. Best-effort: never fail device-detail on a slow fleet.
        console_results = []
        try:
            from routes.console import console_port_result
            lister = getattr(app.state, "console_list_visible_ports", None)
            if lister:
                cdata = await lister(request)
                h = (identity.get("hostname") or "").strip().lower()
                cip = (identity.get("ip") or "").strip()
                cser = (identity.get("serial") or "").strip().lower()
                cpid = (port_id or "").strip().lower()
                for p in (cdata.get("ports") or []):
                    probe = p.get("probe") or {}
                    pident = probe.get("identity") or {}
                    phost = str(pident.get("hostname") or "").strip().lower()
                    palias = str(p.get("alias") or "").strip().lower()
                    pip = str(pident.get("ip") or "").strip()
                    pser = str(pident.get("serial") or probe.get("serial") or "").strip().lower()
                    ppid = str(p.get("port_id") or "").strip().lower()
                    if (
                        (h and (h == phost or h == palias))
                        or (cip and cip == pip)
                        or (cser and cser == pser)
                        or (cpid and cpid == ppid)
                    ):
                        console_results.append(console_port_result(p))
        except Exception as e:
            logger.warning(f"device-detail: console leg failed: {e}")

        # NW module leg: stitch in where this ip/mac lives on the switched
        # network (which switch/gateway, on what port/VLAN). Reads the hub's
        # own nw_devices config + per-device cache (no spoke round-trip), so a
        # searched IP is linked to the NW module the same way it is to
        # NAC/DHCP/NetBox/Proxmox. Best-effort: never fail device-detail on it.
        nw_results = []
        try:
            from routes.nw import correlate_nw_records
            nw_devices = (hub.state.system_state.get("global_config", {})
                          .get("nw_devices", []) or [])
            nw_results = correlate_nw_records(
                nw_devices, getattr(hub, "nw_device_cache", {}) or {},
                ip=identity.get("ip") or ip, mac=identity.get("mac") or mac)
        except Exception as e:
            logger.warning(f"device-detail: nw leg failed: {e}")

        # Monitoring (Zabbix) and DNS legs: matched on the identity gathered above
        # (name or IP), so a device found by MAC still resolves its host/records.
        def _short(n):
            return str(n or "").strip().lower().split(".", 1)[0]
        want_names = {x for x in (_short(identity.get("hostname")), _short(hostname)) if x}
        want_ip = (identity.get("ip") or ip or "").strip()
        for nb in nb_results:
            if nb.get("type") == "device" and nb.get("name"):
                want_names.add(_short(nb["name"]))
        # NetBox gives the device's primary IP as "a.b.c.d/nn".
        want_ips = {want_ip} if want_ip else set()
        for nb in nb_results:
            if nb.get("type") == "device" and nb.get("ip"):
                want_ips.add(str(nb["ip"]).split("/", 1)[0])
        want_ips.discard("")

        monitoring_results = []
        try:
            spoke_mon = hub.get_spoke_by_type("monitoring")
            if spoke_mon and (want_names or want_ips):
                mon = await safe(req(spoke_mon, "MON_HOSTS", {}))
                for h in ((mon or {}).get("hosts") or []) if isinstance(mon, dict) else []:
                    if _short(h.get("name")) in want_names or str(h.get("ip") or "") in want_ips:
                        monitoring_results.append(h)
        except Exception as e:
            logger.warning(f"device-detail: monitoring leg failed: {e}")

        dns_results = []
        try:
            _dns_seen = set()
            for dns_sp in (hub.get_all_spokes_by_type("dns") or []):
                if not (want_names or want_ips):
                    break
                recs = await safe(req(dns_sp, "DNS_LIST", {}))
                for r in ((recs or {}).get("records") or []) if isinstance(recs, dict) else []:
                    if _short(r.get("name")) in want_names or str(r.get("value") or "") in want_ips:
                        key = (r.get("name"), r.get("type"), r.get("value"))
                        if key not in _dns_seen:
                            _dns_seen.add(key)
                            dns_results.append(r)
        except Exception as e:
            logger.warning(f"device-detail: dns leg failed: {e}")

        # Return everything we found.
        return {
            "monitoring": monitoring_results,
            "dns":      dns_results,
            "identity": identity,
            "nac":      nac_result,
            "dhcp":     dhcp_result,
            "netbox":   nb_results,
            "proxmox":  px_results,
            "ldap":     ld_results,
            "console":  console_results,
            "nw":       nw_results,
        }

    # One ClearPass endpoint, with missing IP/hostname filled from DHCP leases.
    @app.get("/api/cppm/device-enrich")
    async def get_cppm_device_enrich(request: Request, mac: str, tenant: str = None):
        """Fetch CPPM endpoint detail and enrich missing fields from DHCP leases."""
        hub = app.state.hub
        # Pick the nac spoke and the firewall spokes.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        fw_spokes = hub.get_all_spokes_by_type("firewall") or []

        # Fetch the endpoint from ClearPass (best effort).
        ep: dict = {}
        if cppm_spoke:
            try:
                raw = await hub.request_response(cppm_spoke, "GET_ENDPOINT_DETAIL", {"mac": mac})
                ep = _cppm_unwrap(raw) if isinstance(raw, dict) else {}
            except Exception:
                pass

        # Record where each field came from.
        sources: dict = {}
        if ep.get("ip"):
            sources["ip"] = "ClearPass"
        if ep.get("hostname"):
            sources["hostname"] = "ClearPass"

        # Fill gaps from DHCP leases. Ask every firewall at once with a short
        # timeout: one at a time, a slow firewall held the modal for a minute.
        norm_target = _norm_mac(mac)

        async def _leases(spoke_id):
            """One firewall's DHCP leases, or [] on error/timeout."""
            try:
                raw = await hub.request_response(spoke_id, "OPNSENSE_GET_DHCP_LEASES", {}, timeout=10.0)
                data = raw.get("payload", {}).get("data", []) if isinstance(raw, dict) else []
                return data if isinstance(data, list) else []
            except Exception:  # noqa: BLE001
                return []

        need_dhcp = not (ep.get("ip") and ep.get("hostname"))
        all_leases = await asyncio.gather(*(_leases(s) for s in fw_spokes)) if need_dhcp else []
        for leases in all_leases:
            try:
                lease = next((l for l in leases if _norm_mac(l.get("mac", "")) == norm_target), None)
                if lease:
                    if not ep.get("ip") and lease.get("ip") and lease["ip"] != "unknown":
                        ep["ip"] = lease["ip"]
                        sources["ip"] = "DHCP"
                    if not ep.get("hostname") and lease.get("hostname") and lease["hostname"] not in ("unknown", ""):
                        ep["hostname"] = lease["hostname"]
                        sources["hostname"] = "DHCP"
                    if ep.get("ip") and ep.get("hostname"):
                        break
            except Exception:
                pass

        ep["sources"] = sources
        # Gate the single endpoint record by tenant subnet (returns {} if the
        # resolved IP is concrete and off the tenant's prefixes). Honors the
        # selected tenant for admins / multi-tenant switches.
        return await _gate_record_tenant(request, ep, "nac", ["ip"], tenant,
                                         spoke_id=cppm_spoke) or {}

    # Sessions for one device (by MAC).
    @app.get("/api/cppm/device-sessions")
    async def get_cppm_device_sessions(request: Request, mac: str, tenant: str = None):
        """Return a device's ClearPass sessions, filtered to the caller's tenant."""
        hub = app.state.hub
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Fetch and tenant-filter the sessions; our HTTP errors pass through, others are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "GET_DEVICE_SESSIONS", {"mac": mac})
            return await _filter_tenant(request, _cppm_unwrap(result), "nac", ["ip"], tenant,
                                        spoke_id=cppm_spoke)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_device_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))

    # List ClearPass roles.
    @app.get("/api/cppm/roles")
    async def get_cppm_roles(request: Request, tenant: str = None):
        """List ClearPass roles from the NAC spoke (unfiltered relay)."""
        hub = app.state.hub
        logger.debug("relay GET /api/cppm/roles")
        logger.info("API: Requesting CPPM roles")
        # The caller's own ClearPass; shared-only is a 403, none a 503.
        cppm_spoke = _nac_own_spoke_for_request(request, tenant)
        # Fetch the roles; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ROLES", {})
            data = _unwrap_spoke(result)
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    # ClearPass audit logs for a time range.
    @app.get("/api/cppm/logs")
    async def get_cppm_logs(request: Request, start: str, end: str, tenant: str = None):
        """Fetch ClearPass audit logs between start/end; subnet-filtered per tenant."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        logger.info(f"API: Requesting CPPM logs from {start} to {end}")
        # Pick the nac spoke for this caller; none is a 503.
        cppm_spoke = _nac_spoke_for_request(request, tenant)
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Fetch and tenant-filter the logs; errors are a 500.
        try:
            result = await hub.request_response(cppm_spoke, "GET_LOGS", {"start": start, "end": end}, timeout=20.0)
            data = _unwrap_spoke(result)
            return await _filter_tenant(request, data, "nac", ["ip", "nas_ip_address"], tenant,
                                        spoke_id=cppm_spoke)
        except Exception as e:
            logger.error(f"API: Error fetching CPPM logs: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _cppm_unwrap(result):
        """Extract spoke payload data and raise HTTPException if spoke reported an error."""
        # Unwrap; a spoke-reported ERROR becomes a 502.
        data = _unwrap_spoke(result)
        if isinstance(data, dict) and data.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=data.get("message", "CPPM API error"))
        return data

    # List access-tracker sessions.
    @app.get("/api/cppm/sessions")
    async def get_cppm_sessions(request: Request, limit: int = 200, offset: int = 0,
                                tenant: str = None):
        """List tenant-scoped ClearPass authentications from the hub cache."""
        hub = app.state.hub
        tid = _effective_tenant(request, tenant)
        # Every viewer must select a tenant before viewing authentication identities.
        if not tid:
            raise HTTPException(status_code=400, detail="Select a tenant to view Access Tracker.")
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        visible_limit = max(1, min(limit, ACCESS_TRACKER_FETCH_PAGE_SIZE))
        visible_offset = max(0, offset)
        first_job = _nac_job_for(
            request, tenant, "CPPM_GET_ACCESS_TRACKER", "sessions", ACCESS_TRACKER_QUERY)
        # The feed and page share one warm cache entry containing the bounded scan.
        try:
            data = await _nac_read(first_job)
        except HTTPException:
            raise
        except CacheFloorError as e:
            # Nothing cached yet and the last query failed inside the floor.
            raise HTTPException(status_code=503, detail=str(e),
                                headers={"Retry-After": str(e.retry_after)})
        except Exception as e:
            logger.exception("get_cppm_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Apply the tenant filter to the cached raw set before counting or slicing.
        data = await _filter_tenant(request, data, "nac", ["ip"], tid)
        if not isinstance(data, dict):
            data = {}
        sessions = data.get("sessions")
        if not isinstance(sessions, list):
            sessions = []
        sessions = sorted(sessions, key=_access_tracker_sort_key, reverse=True)
        recent_window_complete = data.get("recent_window_complete") is True
        truncated = data.get("recent_window_truncated") is True
        # A lower-bound total is explicit when the page scan stopped before all
        # ClearPass source records were exhausted.
        total_is_lower_bound = data.get("total_is_lower_bound") is True
        result = {
            "sessions": sessions[visible_offset:visible_offset + visible_limit],
            "total": len(sessions),
            "total_is_lower_bound": total_is_lower_bound,
            "recent_window_complete": recent_window_complete,
            "source_error": data.get("source_error") is True,
            "recent_window_truncated": truncated,
        }
        return hub.cache_annotate(result, first_job.ns, first_job.key)

    # NAC landing-page status.
    @app.get("/api/cppm/nac-status")
    async def get_cppm_nac_status(request: Request, tenant: str = None):
        """NAC landing page status, served from the hub data cache per nac
        spoke (the request picks the spoke, so tenant scoping is unchanged)."""
        hub = app.state.hub
        # The caller's own ClearPass; shared-only is a 403, none a 503.
        cppm_spoke = _nac_own_spoke_for_request(request, tenant)
        # The tenant this cache entry belongs to (all tenants when none).
        tid = _effective_tenant(request, tenant)
        # Keyed by the spoke and the ClearPass the hub gives it (nac_status_key).
        key = nac_status_key(hub, cppm_spoke)

        async def fetch():
            """Fetch the NAC status from the chosen spoke, unless the
            ClearPass its key names has changed since (``nac_status_key``)."""
            if nac_status_key(hub, cppm_spoke) != key:
                raise HTTPException(status_code=503, detail="NAC settings changed; retry")
            return _cppm_unwrap(await hub.request_response(
                cppm_spoke, "CPPM_GET_NAC_STATUS", {}, timeout=20.0))

        # Read it through the cache; errors other than ours are a 500.
        job = CacheJob("cppm_get_nac_status", key, fetch,
                       (tid,) if tid else (ALL_SCOPE,), lane="nac")
        try:
            return hub.cache_annotate(await _nac_read(job), job.ns, job.key)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_nac_status failed")
            raise HTTPException(status_code=500, detail=str(e))
