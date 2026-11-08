"""NetBox (IPAM) config + sites/racks/devices/prefixes/IPs routes."""
# asyncio runs the follow-up DHCP sync as a background task.
import asyncio
# os reads environment overrides and handles the rack-import scratch files.
import os
# secrets gives a constant-time compare for the rack-import download token.
import secrets

# The Admin tenant id and the list of every tenant id.
from access import ADMIN_TENANT_ID, all_tenant_ids
# Request/exception types plus hub helpers from the main API module: message building, cache
# refresh, NetBox reply unwrapping, spoke lookup and tenant-to-NetBox scoping, and the logger.
from api import (
    HTTPException, Request, _hub_msg,
    _refresh_module_all_tenants, _unwrap_netbox,
    get_netbox_spoke, get_spoke_or_503, get_tenant_scoping, logger,
    netbox_tenant_scope, tenant_netbox_slugs,
)
# Background warm-cache job type, and the marker meaning "visible to every admin".
from warm_cache import ALL_SCOPE, CacheJob

# Which spoke command fetches each NetBox list dataset.
# NetBox list datasets held in the hub data cache. Namespace = "nb_<module>",
# key = the resolved NetBox scope key (tenant slug, "group:<slug>", or "_all_")
# plus "|<slice>" for a site/rack/prefix/device-filtered read.
NB_LIST_CMDS = {
    "netbox_racks":    "NETBOX_GET_RACKS",
    "netbox_devices":  "NETBOX_GET_DEVICES",
    "netbox_ips":      "NETBOX_GET_IPS",
    "netbox_prefixes": "NETBOX_GET_PREFIXES",
}


def nb_cache_job(hub, module_key: str, scope: dict, slice_query: dict = None) -> CacheJob:
    """The one definition of "how to fetch a NetBox list for a scope", shared
    by the page read, the ownership guard and the background feed so all three
    cache under the same (namespace, key) and send the same spoke payload."""
    # Copy the slice filters and turn them into a stable "k=v,k=v" signature (sorted, empty values
    # dropped).
    slice_query = dict(slice_query or {})
    slice_sig = ",".join(f"{k}={v}" for k, v in sorted(slice_query.items()) if v)
    # The cache key starts from the scope key; owner is the hub tenant the scope belongs to.
    base = scope["key"]
    owner = scope.get("tenant_id")
    if base == "_all_" and owner:
        # A tenant with no NetBox slug gets an unscoped list. Key it by the
        # hub tenant anyway: two slug-less tenants must NEVER share an entry
        # (the write ownership guard trusts this list).
        base = f"_all_:{owner}"
    # Add the slice signature (if any) so filtered reads get their own cache entry.
    key = f"{base}|{slice_sig}" if slice_sig else base
    # The spoke payload is the slice filters plus the tenant scoping.
    payload = dict(slice_query)
    # Exactly one of these is set: a plain tenant sends ``tenant``, a NetBox
    # tenant group sends ``tenant_group`` (NetBox's tree-aware union filter).
    payload["tenant"] = scope["tenant"]
    payload["tenant_group"] = scope["tenant_group"]
    # The spoke command for this dataset.
    cmd = NB_LIST_CMDS[module_key]

    async def fetch():
        """Fetch this list live from the NetBox spoke (used on a cache miss or refresh)."""
        # No NetBox spoke connected means nothing can be fetched.
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # 20s: a large NetBox can be slow; the cache covers an overrun.
        return _unwrap_netbox(await hub.request_response(spoke_id, cmd, payload, timeout=20.0))

    # Who may see this entry: its hub tenant, or every admin for "_all_".
    tenants = (owner,) if owner else (ALL_SCOPE,)
    # Namespace "nb_devices" etc. (module key without its "netbox_" prefix).
    ns = "nb_" + module_key[len("netbox_"):] if module_key.startswith("netbox_") else f"nb_{module_key}"
    # Slice-filtered reads are "detail" jobs; full lists are the regular feed.
    return CacheJob(ns, key, fetch, tenants, lane="netbox", detail=bool(slice_sig))


def filter_autorack_report(res: dict, scope: dict) -> dict:
    """Limit an auto-rack sweep result to one tenant scope: a concrete tenant or
    group sees only its own devices; the unscoped admin view sees everything."""
    scoped = bool(scope.get("tenant") or scope.get("tenant_group"))
    slugs = {str(s).lower() for s in scope.get("slugs") or []}

    def keep(x):
        return not scoped or str(x.get("tenant") or "").lower() in slugs

    conflicts = [x for x in res.get("conflicts") or [] if keep(x)]
    cannot = [x for x in res.get("cannot") or [] if keep(x)]
    return {"status": "SUCCESS", "ts": res.get("ts"), "scope": scope.get("key"),
            "conflicts": conflicts, "cannot": cannot,
            "mismatches": [x for x in cannot if x.get("mismatch")],
            "summary": {"conflicts": len(conflicts), "cannot": len(cannot),
                        "racked": None if scoped else res.get("racked"),
                        "named": None if scoped else res.get("named")}}


def nb_cache_feed(hub):
    """Feed: every tenant's (and the admin view's) four NetBox lists."""
    # (namespace, key) pairs already yielded, so shared entries are produced once.
    seen = set()
    # None stands for the admin (all tenants) view, then every tenant.
    for tid in [None] + all_tenant_ids(hub):
        # Resolve the tenant's NetBox scope; a tenant that cannot be resolved is skipped.
        try:
            scope = netbox_tenant_scope(hub, tid)
        except Exception:  # noqa: BLE001
            continue
        # One job per list dataset for this scope.
        for module_key in NB_LIST_CMDS:
            job = nb_cache_job(hub, module_key, scope)
            if (job.ns, job.key) not in seen:   # tenants sharing a slug share one entry
                seen.add((job.ns, job.key))
                yield job


def register(app, hub, ctx):
    """Register netbox routes on the Hub app."""
    # Pull the shared session/tenant helpers out of ctx once for the route closures below.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    # Fall back to plain tenant resolution if this build has no acting-tenant helper.
    _acting_tenant = getattr(ctx, "_acting_tenant", lambda request: _resolve_tenant(request, None))
    _filter_session = ctx._filter_session
    _trigger_endpoint_sync_after_ipam_edit = ctx._trigger_endpoint_sync_after_ipam_edit

    def _trigger_dhcp_sync_after_prefix_edit():
        """Apply a successful NetBox prefix change to Kea immediately."""
        async def _sync():
            """Run the DHCP sync, logging (not raising) any failure."""
            try:
                await hub.sync_dhcp_from_netbox()
            except Exception as exc:  # noqa: BLE001
                logger.warning("DHCP sync after NetBox prefix edit failed: %s", exc)
        # Fire and forget so the HTTP response is not held up by the DHCP sync.
        asyncio.create_task(_sync())

    # The tenant cache stores each NetBox list module as the spoke's REPLY
    # ENVELOPE -- {"status": "SUCCESS", "prefixes": [...]} -- not a bare list.
    # _normalize_cached only unwraps a "data"/"payload" key, and these replies
    # have neither, so the rows live one level down under a per-module key.
    _NB_ROW_KEY = {
        "netbox_prefixes": "prefixes",
        "netbox_devices": "devices",
        "netbox_ips": "ip_addresses",
        "netbox_racks": "racks",
    }

    def _nb_rows(cached, module_key):
        """The row list inside a cached NetBox list module, or None.

        None means "shape not recognised" and the caller must FAIL CLOSED --
        never guess. Returning a wrong list here would hand a non-admin a
        cross-tenant mutation, which is the exact thing _verify_owns exists to
        prevent.
        """
        # Not a dict: unknown shape, fail closed.
        if not isinstance(cached, dict):
            return None
        data = cached.get("data")
        if isinstance(data, list):          # already-unwrapped shape
            return data
        # Envelope shape: the rows are under the per-module key (e.g. "prefixes").
        if isinstance(data, dict):
            rows = data.get(_NB_ROW_KEY.get(module_key))
            if isinstance(rows, list):
                return rows
        # Anything else: unknown shape, fail closed.
        return None

    async def _verify_owns(request, module_key, obj_id, id_field="id"):
        """Cross-tenant guard for NetBox path-ID mutation routes (DELETE/PUT).

        A non-admin ipam user may only mutate objects that exist in THEIR
        tenant's NetBox cache (or live list), so enumerating another tenant's
        sequential integer IDs (device_id/prefix_id/ip_id) is fail-closed
        rather than a cross-tenant destroy/modify. Admin bypasses (returns
        None). Returns the caller's tenant_id on success; raises 401/403 on
        failure. The hub data cache is the fast path; on a miss the tenant's
        list is fetched live once (``cache_fetch_now``) and re-checked, so a
        legit delete of a just-created object isn't false-denied. Spoke down
        on a miss → 403 (fail closed: ownership can't be verified).

        A user with several tenants owns an object if ANY of them holds it —
        checking only the session's primary ``tenant_id`` denied edits made
        while working in a secondary tenant."""
        # Admins may mutate anything; no session means 401.
        sess = _session_user(request)
        if sess and _is_admin(sess):
            return None
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Every tenant the user belongs to (primary included), de-duplicated in order.
        user = sess.get("user", {}) or {}
        tids = list(dict.fromkeys(
            t for t in (user.get("tenants") or []) + [user.get("tenant_id")] if t))
        # A user with no tenant cannot own anything.
        if not tids:
            raise HTTPException(status_code=403, detail="No tenant context for this user")
        # Compare ids as strings since path ids arrive as text.
        sid = str(obj_id)

        def _in(data):
            """True when the cached list data contains an object with this id."""
            rows = _nb_rows({"data": data}, module_key)
            return any(isinstance(it, dict) and str(it.get(id_field)) == sid
                       for it in (rows or []))

        # One cache job per distinct scope (tenants sharing a NetBox slug share a job).
        jobs = {}
        for tid in tids:
            job = nb_cache_job(hub, module_key, netbox_tenant_scope(hub, tid))
            jobs.setdefault((job.ns, job.key), (tid, job))
        # Fast path: check each tenant's cached list.
        for tid, job in jobs.values():
            if _in(hub.warm_get(job.ns, job.key)):
                return tid
        # Not in any cached list (new object, or cache older than the
        # object) → fetch each tenant's list live once and re-check.
        for tid, job in jobs.values():
            try:
                fresh = await hub.cache_fetch_now(job.ns, job.key, job.fetch,
                                                  tenants=job.tenants, lane=job.lane)
            # A failed live fetch for one tenant is logged and the next tenant is tried.
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox ownership refresh [%s][%s] %s failed: %s",
                               tid, module_key, sid, e)
                continue
            if _in(fresh):
                return tid
        # Not found in any of the user's tenants: deny.
        raise HTTPException(status_code=403,
                            detail="Object not found in your tenant (cross-tenant mutation denied)")

    def _enforce_body_tenant(request, data):
        """For NetBox add routes (racks/devices/prefixes/ips): clamp the body
        ``tenant`` slug to one of the caller's OWN tenants for non-admins. A
        non-admin passing another tenant's slug → 403; passing their own →
        unchanged; passing none → none (unassigned create stays allowed, it
        just can't target another tenant). Admins may target any tenant.
        Mirrors claim-device's tenant guard so the plain add routes can't be
        used to plant a resource in another tenant's scope by forwarding
        body.tenant verbatim. Returns the slug to send to the spoke.

        A caller assigned to a NetBox tenant GROUP is allowed to create into any
        MEMBER tenant of that group (tenant_netbox_slugs expands it) — but never
        into the group itself, which is not a real NetBox tenant and cannot own
        an object."""
        # The slug the body asked for (None when blank).
        requested_slug = (str(data.get("tenant") or "").strip()) or None
        # No session means 401.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Admins may target any tenant.
        if _is_admin(sess):
            if requested_slug is not None:
                return requested_slug
            # Resolve the selected tenant's configured NetBox slug, defaulting to "default" for the
            # Admin tenant.
            # No explicit tenant in the body — this is the normal shape for the
            # WebUI's "currently selected tenant" create forms when that tenant
            # is the built-in Admin tenant (id "default"): every other tenant
            # is 1:1 with its own NetBox slug and gets stamped into the body
            # directly, but 'default' is excluded there (it also doubles as
            # the unscoped/global sentinel). LM's own tenant list ALWAYS
            # labels this tenant "ADMIN" in the UI (hardcoded in
            # /setup/tenants, not a user rename) — NetBox has no tenant
            # actually named/slugged "admin"; the matching NetBox tenant is
            # the one literally slugged "default". Resolve the caller's
            # selected tenant context (``?tenant=`` query param, the same
            # convention every read route uses) through that tenant's
            # ``netbox_tenant_slug`` config first (an explicit override always
            # wins), and fall back to the literal "default" slug for the
            # built-in Admin tenant specifically when nothing is configured —
            # so the created object lands in NetBox's real "default" tenant
            # out of the box, with no manual linking step required.
            ctx_tid = request.query_params.get("tenant")
            if ctx_tid:
                slug = get_tenant_scoping(hub, ctx_tid).get("netbox_tenant_slug") or None
                if not slug and ctx_tid == ADMIN_TENANT_ID:
                    slug = ADMIN_TENANT_ID
                return slug
            return None
        # Non-admin from here on.
        if requested_slug is None:
            return None  # unassigned create is allowed; just can't target another tenant
        # The user's tenants (falling back to the single primary tenant id).
        user = sess.get("user", {}) or {}
        allowed_ids = user.get("tenants") or []
        if not allowed_ids and user.get("tenant_id"):
            allowed_ids = [user.get("tenant_id")]
        # Expand them into every NetBox slug they may create into (group members included).
        allowed = set()
        for tid in allowed_ids:
            allowed.update(tenant_netbox_slugs(hub, tid))
        # Refuse a slug outside that set.
        if requested_slug not in allowed:
            raise HTTPException(status_code=403,
                                detail="Not authorized to create into that tenant")
        return requested_slug


    async def _netbox_write(request, cmd, refresh_keys, *, log_name,
                            id_field=None, obj_id=None, verify_key=None,
                            tenant_mode="always", sync_body=None, timeout=None,
                            sync_dhcp=False):
        """Shared body of the 12 NetBox write (POST/PUT/DELETE) handlers:
        spoke-check → ownership verify → body/id build → tenant-enforce →
        relay → cache-refresh → optional endpoint-sync trigger → unwrap
        (mirrors net_services._relay_spoke). Shapes:

        - create (``tenant_mode="always"``): body = JSON; tenant always clamped
          via _enforce_body_tenant.
        - update (``tenant_mode="if_present"``): body = JSON + ``{id_field:
          obj_id}``; tenant clamped only when the body carries one.
        - delete (``tenant_mode=None``): no body — payload ``{id_field:
          obj_id}``.

        ``sync_body`` drives _trigger_endpoint_sync_after_ipam_edit: "data"
        (pass the written body), "null" (pass None), None (no trigger).
        ``verify_key`` runs the cross-tenant ownership gate against that cache
        module BEFORE the mutation (unchanged order: spoke 503 first)."""
        # Find the NetBox spoke (503 if none) and, when asked, check the caller owns the object
        # first.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        if verify_key:
            await _verify_owns(request, verify_key, obj_id)
        # Relay errors become a logged 500; HTTPExceptions pass through.
        try:
            # Delete: the payload is only the object id.
            if tenant_mode is None:
                data = {id_field: obj_id}
            # Create/update: the payload is the JSON body (plus the id for updates).
            else:
                data = await request.json()
                if id_field is not None:
                    data[id_field] = obj_id
                # Clamp the tenant slug to the caller's allowed tenants.
                if tenant_mode == "always" or "tenant" in data:
                    data["tenant"] = _enforce_body_tenant(request, data)
            # Send the command (with a custom timeout if given) and unwrap the reply.
            kw = {"timeout": timeout} if timeout else {}
            result = await hub.request_response(spoke_id, cmd, data, **kw)
            response = _unwrap_netbox(result)
            # Refresh the cached lists the change affects for every tenant.
            for key in refresh_keys:
                _refresh_module_all_tenants(hub, key)
            # Optionally trigger an endpoint sync with the written data (or with none).
            if sync_body == "data":
                _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            elif sync_body == "null":
                _trigger_endpoint_sync_after_ipam_edit(hub, request, None)
            # Optionally push prefix changes to Kea DHCP.
            if sync_dhcp:
                _trigger_dhcp_sync_after_prefix_edit()
            return response
        # Our own HTTP errors (403, 503, ...) pass straight through.
        except HTTPException:
            raise
        # Anything else is logged with a traceback and reported as a 500.
        except Exception as e:
            logger.exception("%s failed", log_name)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/netbox-config")
    async def get_netbox_config():
        """Return the stored NetBox connection config (admin only via /setup/)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("netbox", {})
        return {"config": config}

    @app.post("/setup/netbox-config")
    async def update_netbox_config(request: Request):
        """Save the NetBox connection config and push the URL/token to the NetBox spoke."""
        # Any failure is logged and reported as a 500.
        hub = app.state.hub
        try:
            # Read the posted config and store it in global_config, flagging state for saving.
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["netbox"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            # Push the new URL/token to the spoke if connected; otherwise report a partial success.
            spoke_id = get_netbox_spoke(hub)
            if spoke_id:
                msg = _hub_msg(spoke_id, "UPDATE_CONFIG", {"netbox_url": config.get("url"), "api_token": config.get("api_token"), "netbox_verify_ssl": config.get("verify_ssl")})
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Config saved and pushed to NetBox spoke.", "pushed": True}
            return {"status": "partial_success", "message": "Config saved; NetBox spoke not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_netbox_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── NetBox data API ────────────────────────────────────────────────────────

    async def _netbox_list_get(request, tenant, cache_key, cmd, slice_query, subnet_fields, route_name):
        """Serve a NetBox list (racks/devices/prefixes/ips) from the hub data
        cache — for every user, admin included; the page never waits on the
        spoke except the very first read of a scope.

        The entry is keyed by the resolved NetBox scope (tenant slug,
        ``group:<slug>`` or ``_all_``) plus any slice params, and holds the RAW
        spoke list; ``subnet_fields`` (e.g. ``["prefix"]``) re-applies the
        caller's subnet filter on every read. ``cmd`` must match
        ``NB_LIST_CMDS[cache_key]`` (kept in the signature for readability)."""
        # Resolve the caller's NetBox scope and the cache job for this list/slice.
        hub = app.state.hub
        scope = netbox_tenant_scope(hub, _resolve_tenant(request, tenant))
        job = nb_cache_job(hub, cache_key, scope, slice_query)
        # Read from the cache (fetching live only on a first read); our HTTP errors pass through,
        # others become a logged 500.
        try:
            data = await hub.cache_read(job.ns, job.key, job.fetch, tenants=job.tenants,
                                        lane=job.lane, detail=job.detail)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception(route_name + " failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Re-apply the caller's subnet restrictions when this list has subnet fields.
        if subnet_fields:
            data = await _filter_session(request, data, "netbox", subnet_fields)
        # Add cache age/freshness info for the UI.
        return hub.cache_annotate(data, job.ns, job.key)

    # Register the background feed that keeps every tenant's NetBox lists warm (if this hub supports
    # it).
    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("netbox", nb_cache_feed)

    @app.get("/api/netbox/health")
    async def netbox_health():
        """NetBox spoke reachability + API-token validity probe (10s timeout)."""
        # Find the NetBox spoke (503 if none).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        # Ask the spoke to probe NetBox; our HTTP errors pass through, others become a logged 500.
        try:
            result = await hub.request_response(spoke_id, "NETBOX_HEALTH", {}, timeout=10.0)
            return _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_health failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/tenants")
    async def netbox_get_tenants(request: Request):
        """Full NetBox tenant list (id/name/slug) — for the Migrate Data picker.
        Admin-only: it exposes every tenant, and its only consumer is the
        admin-gated migrate action below."""
        # Admins only.
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        # Fetch the tenant list from NetBox (up to a minute for big installs).
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        result = await hub.request_response(spoke_id, "NETBOX_GET_TENANTS", {}, timeout=60.0)
        return _unwrap_netbox(result)

    @app.post("/api/netbox/migrate-tenant")
    async def netbox_migrate_tenant(request: Request):
        """Migrate Data to new Tenant — reassign every NetBox object owned by the
        SOURCE tenant to the TARGET tenant, then (by default) delete the source.
        ADMIN-ONLY: this is a destructive cross-tenant operation. Body:
        ``{source, target, delete_source=true, create_target=false}`` where
        source/target are a tenant id, slug, or name."""
        # Admins only.
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        # Both a source and a target tenant are required.
        body = await request.json()
        source = body.get("source")
        target = body.get("target")
        if not source or not target:
            raise HTTPException(status_code=400, detail="source and target are required")
        # Find the NetBox spoke and audit-log who started the migration.
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        logger.info("netbox migrate-tenant: %s -> %s (delete_source=%s) by %s",
                    source, target, body.get("delete_source", True),
                    (sess.get("user", {}) or {}).get("username"))
        # Run the migration on the spoke; allow 5 minutes for large tenants.
        result = await hub.request_response(
            spoke_id, "NETBOX_MIGRATE_TENANT",
            {"source": source, "target": target,
             "delete_source": body.get("delete_source", True),
             "create_target": body.get("create_target", False)},
            timeout=300.0)
        out = _unwrap_netbox(result)
        # Refresh every cached NetBox list; a failed refresh is harmless (the cache catches up
        # later).
        # A big reassignment stales every cached NetBox list across tenants.
        for mk in ("netbox_devices", "netbox_prefixes", "netbox_ips", "netbox_racks"):
            try:
                _refresh_module_all_tenants(hub, mk)
            except Exception:  # noqa: BLE001
                pass
        return out

    @app.get("/api/netbox/sites")
    async def netbox_get_sites():
        """List NetBox sites (admin sees all; unfiltered spoke round-trip)."""
        # Find the NetBox spoke (503 if none).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        # Fetch the sites; our HTTP errors pass through, others become a logged 500.
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_SITES", {})
            return _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_get_sites failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/seed-catalog")
    async def netbox_seed_catalog(request: Request):
        """Seed NetBox with the bundled Aruba/HPE/Juniper device-type catalog
        (manufacturers + device types + interface/console/power templates).
        ADMIN-ONLY: creates many objects. Idempotent — re-runs upsert device
        types and add missing templates, never erroring on an existing type
        (safe to re-run after editing the catalog). Bypasses _netbox_write
        (not a tenant-scoped CRUD object; no body / no tenant clamp)."""
        # Admins only.
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        # Find the NetBox spoke and audit-log who started the seed.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        logger.info("netbox seed-catalog by %s",
                    (sess.get("user", {}) or {}).get("username"))
        # Our HTTP errors pass through, others become a logged 500.
        try:
            # Long-running: 45+ device types × interface/console/power templates.
            result = await hub.request_response(spoke_id, "NETBOX_SEED_CATALOG",
                                                {}, timeout=300.0)
            # New/changed device types alter the device form-options picklist.
            try:
                _refresh_module_all_tenants(hub, "netbox_devices")
            except Exception:  # noqa: BLE001
                pass
            return _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_seed_catalog failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ─── Excel rack-layout import (admin-only, two-step URL relay) ────────────
    #
    # Mirrors the template-refresh relay: the hub saves the uploaded .xlsx to a
    # scratch dir, mints a one-time download token, and hands the spoke a
    # download_url + token. The spoke HTTP-GETs the file for BOTH steps (detect
    # → user maps columns → commit), so the workbook isn't inlined over the WS
    # (16 MiB frame cap). The scratch file + token live until the commit
    # completes (or the hub restarts). Bypasses _netbox_write — the importer
    # resolves tenant itself from the body's tenant_slug (admin-gated).

    # Scratch directory for uploaded workbooks (overridable via LM_RACK_IMPORT_DIR).
    _RACK_IMPORT_DIR = os.environ.get("LM_RACK_IMPORT_DIR", "/var/lib/lm/imports")
    _RACK_IMPORT_MAX = 64 * 1024 * 1024  # 64 MB xlsx cap

    def _rack_imports():
        """In-memory upload_id → {path, token, filename, ts}. Lost on hub
        restart (imports are short-lived; the user re-uploads)."""
        # Create the dict on first use.
        if not getattr(hub, "rack_imports", None):
            hub.rack_imports = {}
        return hub.rack_imports

    def _rack_import_download_url(request, upload_id):
        """URL the spoke uses to download an uploaded workbook from the hub."""
        # Prefer the configured public hub URL; otherwise use the URL this request came in on.
        base = (os.environ.get("LM_HUB_PUBLIC_URL") or str(request.base_url)).rstrip("/")
        return f"{base}/api/netbox/racks/import-xlsx/{upload_id}"

    @app.post("/api/netbox/racks/import-xlsx")
    async def netbox_rack_import_xlsx(request: Request):
        """Step 1: accept an .xlsx upload, save it to scratch, relay
        NETBOX_IMPORT_RACK_DETECT to the spoke (it fetches the file via the
        token-gated download_url, parses with openpyxl, returns detected rack
        sheets + guessed column maps). Also fetches device form-options
        (sites/device_types/roles/tenants) so the WebUI can render the mapping
        UI + defaults in one round trip. ADMIN-ONLY."""
        # uuid for upload ids, secrets for the download token, time for the upload timestamp.
        import uuid as _uuid, secrets as _secrets, time as _time
        # Path, to create the scratch directory.
        from pathlib import Path
        # Admins only.
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        # Find the NetBox spoke and work out how the file was sent.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        ctype = (request.headers.get("content-type") or "").lower()
        data = b""
        filename = ""
        # Read the file from the multipart "file" field, or from the raw body.
        try:
            if "multipart/form-data" in ctype:
                form = await request.form()
                up = form.get("file")
                if up is None:
                    raise HTTPException(status_code=400, detail="no 'file' field in the upload")
                filename = getattr(up, "filename", "") or "rack.xlsx"
                data = await up.read()
            else:
                data = await request.body()
                filename = "rack.xlsx"
        # Our own 400 for a missing field passes straight through.
        except HTTPException:
            raise
        # Any other read failure is reported as a bad upload.
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        # Reject empty, oversized (over 64 MB) and non-.xlsx uploads.
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _RACK_IMPORT_MAX:
            raise HTTPException(status_code=413, detail="upload exceeds 64 MB limit")
        if not filename.lower().endswith(".xlsx"):
            raise HTTPException(status_code=400, detail="file must be .xlsx")

        # Random upload id and a 32-byte one-time download token for the spoke.
        upload_id = _uuid.uuid4().hex
        token = _secrets.token_urlsafe(32)
        # Save the workbook into the scratch directory; a failure is logged and reported as a 500.
        try:
            Path(_RACK_IMPORT_DIR).mkdir(parents=True, exist_ok=True)
            path = os.path.join(_RACK_IMPORT_DIR, f"{upload_id}.xlsx")
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:  # noqa: BLE001
            logger.exception("netbox rack import: failed to save upload")
            raise HTTPException(status_code=500, detail=f"could not save upload: {e}")
        # Remember the upload so step 2 and the download endpoint can find it.
        _rack_imports()[upload_id] = {"path": path, "token": token,
                                      "filename": filename, "ts": _time.time()}
        # Audit-log the upload.
        logger.info("netbox rack import-xlsx by %s (upload_id=%s, %d bytes)",
                    (sess.get("user", {}) or {}).get("username"), upload_id, len(data))
        # Relay errors: our HTTP errors pass through, others become a logged 500.
        try:
            # Ask the spoke to download and parse the workbook (allow 3 minutes).
            download_url = _rack_import_download_url(request, upload_id)
            detect = await hub.request_response(spoke_id, "NETBOX_IMPORT_RACK_DETECT",
                                                {"download_url": download_url, "token": token},
                                                timeout=180.0)
            detect = _unwrap_netbox(detect)
            # Parsing failed on the spoke.
            if detect.get("status") != "SUCCESS":
                # parse failed on the spoke (e.g. openpyxl missing) → clean up.
                _rack_imports().pop(upload_id, None)
                try: os.remove(path)
                except OSError: pass
                raise HTTPException(status_code=502, detail=detect.get("message") or "detect failed")
            # Best effort: without picklists the UI still works, just with empty defaults.
            # form-options for the mapping UI + defaults (parallel picklist read).
            try:
                fo = await hub.request_response(spoke_id, "NETBOX_GET_DEVICE_FORM_OPTIONS",
                                                {}, timeout=60.0)
                fo = _unwrap_netbox(fo)
                form_options = fo if fo.get("status") == "SUCCESS" else {}
            except Exception:  # noqa: BLE001
                form_options = {}
            # Return the upload id, the detected rack sheets and the picklists.
            return {"upload_id": upload_id, "racks": detect.get("racks", []),
                    "form_options": form_options}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox rack import-xlsx relay failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/racks/import-commit")
    async def netbox_rack_import_commit(request: Request):
        """Step 2: apply the user's column maps + selections. Body::
        ``{upload_id, sheets:[{sheet, rack_name, site_slug, u_height,
        tenant_slug, shape, column_map, default_role_slug, default_status}],
        dry_run}``. Relays NETBOX_IMPORT_RACK_COMMIT (the spoke re-GETs the file,
        re-parses the selected sheets with full device rows, then creates/updates
        racks + devices + mgmt iface/IP). Deletes the scratch file after.
        ADMIN-ONLY. Bypasses _netbox_write (importer resolves tenant itself)."""
        # Admins only.
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        # Find the NetBox spoke (503 if none).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        # The body must be valid JSON.
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        # The upload must still be known and its file still on disk.
        upload_id = str(body.get("upload_id") or "")
        rec = _rack_imports().get(upload_id)
        if not rec or not os.path.isfile(rec["path"]):
            raise HTTPException(status_code=404, detail="upload not found (expired or already committed)")
        # At least one sheet must be selected.
        sheets = body.get("sheets") or []
        if not sheets:
            raise HTTPException(status_code=400, detail="no sheets selected")
        # Dry run only reports what would change; audit-log the commit either way.
        dry_run = bool(body.get("dry_run"))
        logger.info("netbox rack import-commit by %s (upload_id=%s, %d sheets, dry_run=%s)",
                    (sess.get("user", {}) or {}).get("username"), upload_id, len(sheets), dry_run)
        # Relay errors: our HTTP errors pass through, others become a logged 500.
        try:
            # Ask the spoke to download the file again and apply the selected sheets (allow 10
            # minutes).
            download_url = _rack_import_download_url(request, upload_id)
            result = await hub.request_response(spoke_id, "NETBOX_IMPORT_RACK_COMMIT",
                                                {"download_url": download_url,
                                                 "token": rec["token"],
                                                 "sheets": sheets, "dry_run": dry_run},
                                                timeout=600.0)
            result = _unwrap_netbox(result)
            # Clean up the scratch file + token regardless of outcome.
            _rack_imports().pop(upload_id, None)
            try: os.remove(rec["path"])
            except OSError: pass
            # Invalidate rack + device picklist caches (creates/updates both).
            if not dry_run:
                try:
                    _refresh_module_all_tenants(hub, "netbox_racks")
                    _refresh_module_all_tenants(hub, "netbox_devices")
                except Exception:  # noqa: BLE001
                    pass
            # Return the spoke's import summary.
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox rack import-commit relay failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/racks/import-xlsx/{upload_id}")
    async def netbox_rack_import_download(upload_id: str, request: Request):
        """Token-gated file download for the spoke (middleware-exempt: the spoke
        authenticates with the one-time bearer token, not a user session).
        Mirrors the template-refresh download endpoint."""
        # Streams the workbook file back as the HTTP response.
        from fastapi.responses import FileResponse
        # Unknown upload id: 404.
        rec = _rack_imports().get(upload_id)
        if not rec:
            raise HTTPException(status_code=404, detail="upload not found")
        # Take the token from an "Authorization: Bearer" header, or the ?token= query parameter.
        auth = request.headers.get("authorization") or ""
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        token = token or request.query_params.get("token") or ""
        # Compare in constant time so the token cannot be guessed via timing.
        if not token or not secrets.compare_digest(token, rec["token"]):
            raise HTTPException(status_code=403, detail="invalid download token")
        # The file may have been removed already.
        if not os.path.isfile(rec["path"]):
            raise HTTPException(status_code=404, detail="upload file missing on disk")
        # Serve the workbook with the Excel MIME type.
        return FileResponse(rec["path"], media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            filename=rec.get("filename") or "rack.xlsx")

    @app.get("/api/netbox/racks")
    async def netbox_get_racks(request: Request, site: str = None, tenant: str = None):
        """List NetBox racks, optionally scoped by site; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_racks", "NETBOX_GET_RACKS",
                                      {"site": site}, None, "netbox_get_racks")

    @app.get("/api/netbox/autorack")
    async def netbox_autorack_report(request: Request, tenant: str = None, refresh: bool = False):
        """Rack-placement dashboard data: devices whose name asks for a rack slot
        that is in conflict, cannot be used, or differs from where NetBox has them
        (from the NetBox spoke's last auto-rack sweep), limited to the caller's
        tenant scope. ``refresh`` (admin) re-evaluates now with a read-only run."""
        hub = app.state.hub
        scope = netbox_tenant_scope(hub, _resolve_tenant(request, tenant))
        sess = _session_user(request)
        admin = bool(sess and _is_admin(sess))
        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        payload = {"report": True}
        if refresh and admin:
            payload = {"dry_run": True}
        try:
            res = _unwrap_netbox(await hub.request_response(
                spoke_id, "NETBOX_AUTORACK_SWEEP", payload, timeout=120.0))
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_autorack_report failed")
            raise HTTPException(status_code=500, detail=str(e))
        if not isinstance(res, dict) or res.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=str((res or {}).get("message") or "autorack unavailable"))
        return filter_autorack_report(res, scope)

    @app.post("/api/netbox/racks")
    async def netbox_add_rack(request: Request):
        """Create a NetBox rack; invalidates the racks cache on success."""
        # Shared write path: create with the tenant clamped to the caller's own tenants.
        return await _netbox_write(request, "NETBOX_ADD_RACK", ["netbox_racks"],
                                   log_name="netbox_add_rack")

    @app.put("/api/netbox/racks/{rack_id}")
    async def netbox_update_rack(rack_id: int, request: Request):
        """Update a NetBox rack; invalidates the racks cache on success."""
        # Shared write path: ownership check first, tenant clamped only if the body sets one.
        return await _netbox_write(request, "NETBOX_UPDATE_RACK", ["netbox_racks"],
                                   log_name="netbox_update_rack",
                                   id_field="rack_id", obj_id=rack_id,
                                   verify_key="netbox_racks",
                                   tenant_mode="if_present")

    @app.delete("/api/netbox/racks/{rack_id}")
    async def netbox_delete_rack(rack_id: int, request: Request):
        """Delete a NetBox rack; invalidates the racks cache on success."""
        # Shared write path: ownership check, then delete by id.
        return await _netbox_write(request, "NETBOX_DELETE_RACK", ["netbox_racks"],
                                   log_name="netbox_delete_rack",
                                   id_field="rack_id", obj_id=rack_id,
                                   verify_key="netbox_racks", tenant_mode=None)

    @app.get("/api/netbox/racks/{rack_id}/elevation")
    async def netbox_get_rack_elevation(rack_id: int, request: Request):
        """Front+rear rack elevation render model for the WebUI "View" button
        (mirrors NetBox's rack-elevation view). Read-only, but non-admins are
        ownership-gated against their tenant's racks cache (same cross-tenant
        guard as the PUT/DELETE routes) so a user can't enumerate another
        tenant's rack layout by guessing the sequential rack_id; admins bypass.
        Relays ``NETBOX_GET_RACK_ELEVATION`` to the ipam spoke."""
        # Make sure a non-admin owns this rack before revealing its layout.
        await _verify_owns(request, "netbox_racks", rack_id, id_field="id")
        # Find the NetBox spoke and fetch the elevation (up to a minute).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        result = await hub.request_response(
            spoke_id, "NETBOX_GET_RACK_ELEVATION", {"rack_id": rack_id}, timeout=60.0)
        return _unwrap_netbox(result)

    @app.get("/api/netbox/devices")
    async def netbox_get_devices(request: Request, site: str = None, rack: str = None, tenant: str = None):
        """List NetBox devices, optionally scoped by site/rack; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        # Served from the cache, filtered by site/rack.
        return await _netbox_list_get(request, tenant, "netbox_devices", "NETBOX_GET_DEVICES",
                                      {"site": site, "rack": rack}, None, "netbox_get_devices")

    @app.post("/api/netbox/devices")
    async def netbox_add_device(request: Request):
        """Create a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        # Shared write path, then sync endpoints with the new device data.
        return await _netbox_write(request, "NETBOX_ADD_DEVICE", ["netbox_devices"],
                                   log_name="netbox_add_device", sync_body="data")

    @app.get("/api/netbox/claim-device/options")
    async def netbox_claim_device_options(request: Request):
        """Picklists (sites, device types, device roles, tenants) for the
        Claim-an-unknown-device form. Non-admins see only their own allowed
        tenants in the tenant list; admins see all."""
        # Find the NetBox spoke (503 if none).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        # Relay errors: our HTTP errors pass through, others become a logged 500.
        try:
            # Fetch the picklists from NetBox.
            result = await hub.request_response(spoke_id, "NETBOX_GET_DEVICE_FORM_OPTIONS", {})
            out = _unwrap_netbox(result)
            # Non-admins: trim the tenant picklist to their own tenants' NetBox slugs.
            sess = _session_user(request)
            if sess and not _is_admin(sess) and isinstance(out, dict):
                user = sess.get("user", {}) or {}
                allowed_ids = user.get("tenants") or []
                if not allowed_ids and user.get("tenant_id"):
                    allowed_ids = [user.get("tenant_id")]
                allowed = set()
                for tid in allowed_ids:
                    s = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
                    if s:
                        allowed.add(s)
                # Copy before modifying so the spoke's reply object is left untouched.
                out = dict(out)
                out["tenants"] = [t for t in (out.get("tenants") or []) if t.get("slug") in allowed]
            return out
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_claim_device_options failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/claim-device")
    async def netbox_claim_device(request: Request):
        """Claim a CPPM unknown (untagged) endpoint into NetBox: create a
        tenant-owned device and attach the endpoint's IP as its primary IPv4.
        The spoke does the create; on success we invalidate the device caches
        and trigger an endpoint sync so the matching ClearPass endpoint is
        tagged with the tenant and leaves 'Unknown Devices'.

        Security: a non-admin may only claim into one of their own tenants
        (matched by NetBox tenant slug); any other slug → 403. Admins may claim
        into any tenant."""
        # Find the NetBox spoke (503 if none).
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        # The body must be valid JSON.
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        # The tenant slug the device should belong to (None when blank).
        requested_slug = (str(data.get("tenant") or "").strip()) or None

        # Non-admins: build the set of their tenants' NetBox slugs and refuse anything else
        # (including no slug).
        sess = _session_user(request)
        if sess and not _is_admin(sess):
            user = sess.get("user", {}) or {}
            allowed_ids = user.get("tenants") or []
            if not allowed_ids and user.get("tenant_id"):
                allowed_ids = [user.get("tenant_id")]
            allowed = set()
            for tid in allowed_ids:
                s = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
                if s:
                    allowed.add(s)
            if not requested_slug or requested_slug not in allowed:
                raise HTTPException(status_code=403, detail="Not authorized to claim into that tenant")

        # Only these fields are passed to the spoke, with safe defaults.
        payload = {
            "name": data.get("name", ""),
            "device_type": data.get("device_type", ""),
            "role": data.get("role", ""),
            "site": data.get("site", ""),
            "tenant": requested_slug or "",
            "status": data.get("status", "active"),
            "description": data.get("description", ""),
            "ip": data.get("ip", ""),
            "mac": data.get("mac", ""),
            "dns_name": data.get("dns_name", ""),
        }
        # Ask the spoke to create the device; our HTTP errors pass through, others become a logged
        # 500.
        try:
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_DEVICE", payload)
            result = _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_claim_device failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Only refresh caches and resync endpoints when the claim actually succeeded.
        if isinstance(result, dict) and result.get("status") == "SUCCESS":
            # Refresh (drop + background re-fetch), not invalidate-only, so a
            # non-admin viewer sees the claimed device appear / re-attribute
            # immediately. claim-device also re-tags the CPPM endpoint, so
            # refresh cppm_devices too (the endpoint sync below is best-effort
            # and async; this guarantees the cache is dropped now).
            _refresh_module_all_tenants(hub, "netbox_devices")
            _refresh_module_all_tenants(hub, "cppm_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, {"tenant": requested_slug} if requested_slug else None)
        # Return the spoke's result either way.
        return result

    @app.delete("/api/netbox/devices/{device_id}")
    async def netbox_delete_device(device_id: int, request: Request):
        """Delete a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        # Shared write path: ownership check, delete, then resync endpoints.
        return await _netbox_write(request, "NETBOX_DELETE_DEVICE", ["netbox_devices"],
                                   log_name="netbox_delete_device",
                                   id_field="device_id", obj_id=device_id,
                                   verify_key="netbox_devices", tenant_mode=None,
                                   sync_body="null")

    @app.put("/api/netbox/devices/{device_id}")
    async def netbox_update_device(device_id: int, request: Request):
        """Update a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        # Shared write path: ownership check, update, then resync endpoints.
        return await _netbox_write(request, "NETBOX_UPDATE_DEVICE", ["netbox_devices"],
                                   log_name="netbox_update_device",
                                   id_field="device_id", obj_id=device_id,
                                   verify_key="netbox_devices",
                                   tenant_mode="if_present", sync_body="data")

    @app.get("/api/netbox/prefixes")
    async def netbox_get_prefixes(request: Request, site: str = None, tenant: str = None):
        """List NetBox prefixes (subnet-filtered), optionally scoped by site;
        non-admins get the tenant cache, admins go live (see _netbox_list_get)."""
        # Served from the cache and filtered to the caller's allowed subnets.
        return await _netbox_list_get(request, tenant, "netbox_prefixes", "NETBOX_GET_PREFIXES",
                                      {"site": site}, ["prefix"], "netbox_get_prefixes")

    @app.post("/api/netbox/prefixes")
    async def netbox_allocate_prefix(request: Request):
        """Allocate a NetBox prefix; invalidates the prefix + IP caches (30s timeout)."""
        # Shared write path, then refresh prefix/IP caches and push to Kea DHCP.
        return await _netbox_write(request, "NETBOX_ALLOCATE_PREFIX",
                                   ["netbox_prefixes", "netbox_ips"],
                                   log_name="netbox_allocate_prefix", timeout=30.0,
                                   sync_dhcp=True)

    @app.put("/api/netbox/prefixes/{prefix_id}")
    async def netbox_update_prefix(prefix_id: int, request: Request):
        """Update a NetBox prefix; invalidates the prefix cache on success."""
        # Shared write path: ownership check, update, then push to Kea DHCP.
        return await _netbox_write(request, "NETBOX_UPDATE_PREFIX", ["netbox_prefixes"],
                                   log_name="netbox_update_prefix",
                                   id_field="prefix_id", obj_id=prefix_id,
                                   verify_key="netbox_prefixes",
                                   tenant_mode="if_present", sync_dhcp=True)

    @app.delete("/api/netbox/prefixes/{prefix_id}")
    async def netbox_delete_prefix(prefix_id: int, request: Request):
        """Delete a NetBox prefix; invalidates the prefix + IP caches on success."""
        # Shared write path: ownership check, delete, then push to Kea DHCP.
        return await _netbox_write(request, "NETBOX_DELETE_PREFIX",
                                   ["netbox_prefixes", "netbox_ips"],
                                   log_name="netbox_delete_prefix",
                                   id_field="prefix_id", obj_id=prefix_id,
                                   verify_key="netbox_prefixes", tenant_mode=None,
                                   sync_dhcp=True)

    @app.get("/api/netbox/available-subnets")
    async def netbox_find_available_subnets(request: Request, near: str = None,
                                             prefix_length: int = None,
                                             hosts: int = None, count: int = 20,
                                             exact: str = None):
        """Find the closest free subnets of a requested size to ``near``.

        Free = no tenant-assigned NetBox prefix overlaps it; search is RFC1918.
        Size may be given as ``prefix_length`` or as ``hosts`` (host count →
        smallest mask that fits). ``exact`` is tried first when given. Response
        is only free CIDRs (no other tenants' data), so it is safe for non-admins."""
        # Find the NetBox spoke and require a "near" CIDR.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        if not near:
            raise HTTPException(status_code=400, detail="'near' CIDR is required")
        # Relay errors: our HTTP errors pass through, others become a logged 500.
        try:
            # Build the search request.
            payload: dict = {"near": near, "count": int(count)}
            # An explicit prefix length must be /22 to /30.
            if prefix_length is not None:
                prefix_length = int(prefix_length)
                if not 22 <= prefix_length <= 30:
                    raise HTTPException(status_code=400,
                                        detail="subnet size must be between /22 and /30 (up to a /22)")
                payload["prefix_length"] = prefix_length
            # Otherwise size by host count.
            elif hosts is not None:
                payload["hosts"] = int(hosts)
            # A specific subnet to try first.
            if exact:
                payload["exact"] = exact
            # Ask the spoke to search (up to a minute).
            result = await hub.request_response(spoke_id, "NETBOX_FIND_AVAILABLE_PREFIXES",
                                                 payload, timeout=60.0)
            return _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_find_available_subnets failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/netbox/subnet-assign")
    async def netbox_assign_subnet(request: Request):
        """Assign a chosen free subnet to a tenant (the picker "Assign" action).

        Tenant is enforced server-side: a non-admin can only assign to their
        own tenant (any ``tenant`` in the body is ignored); an admin may target
        any tenant or leave it unassigned. Forwards NETBOX_CLAIM_PREFIX, which
        reassigns an existing unassigned prefix or creates a new one.

        ``custom_fields`` (e.g. ``dhcp_enabled``/``gateway``/``dns_servers``)
        is forwarded same as the Allocate Subnet modal — before this, "Add
        Prefix" was the one creation path that silently dropped the DHCP
        options a caller supplied, and never applied them to Kea either (no
        DHCP sync was triggered on this route at all)."""
        # Find the NetBox spoke and require a logged-in user.
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # Relay errors: our HTTP errors pass through, others become a logged 500.
        try:
            # A prefix is required.
            body = await request.json()
            prefix = body.get("prefix")
            if not prefix:
                raise HTTPException(status_code=400, detail="'prefix' is required")
            # Admins choose the tenant; everyone else gets their acting tenant's NetBox slug.
            if _is_admin(sess):
                tenant = body.get("tenant")
            else:
                tenant = get_tenant_scoping(hub, _acting_tenant(request))["netbox_tenant_slug"] or None
            # Payload for the claim, including any DHCP custom fields.
            payload = {
                "prefix": prefix,
                "tenant": tenant,
                "description": body.get("description", ""),
                "site": body.get("site"),
                "status": body.get("status", "active"),
                "custom_fields": body.get("custom_fields"),
            }
            # Ask the spoke to claim/create the prefix.
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_PREFIX", payload, timeout=60.0)
            data = _unwrap_netbox(result)
            # On success refresh the prefix/IP caches and push the change to Kea DHCP.
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                _refresh_module_all_tenants(hub, "netbox_prefixes")
                _refresh_module_all_tenants(hub, "netbox_ips")
                _trigger_dhcp_sync_after_prefix_edit()
            return data
        except HTTPException:
            raise
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_assign_subnet failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/netbox/ips")
    async def netbox_get_ips(request: Request, prefix: str = None, device: str = None, tenant: str = None):
        """List NetBox IP addresses (subnet-filtered), optionally scoped by
        prefix/device; non-admins get the tenant cache, admins go live
        (see _netbox_list_get)."""
        # Served from the cache and filtered to the caller's allowed subnets.
        return await _netbox_list_get(request, tenant, "netbox_ips", "NETBOX_GET_IPS",
                                      {"prefix": prefix, "device": device}, ["address"], "netbox_get_ips")

    @app.post("/api/netbox/ips")
    async def netbox_allocate_ip(request: Request):
        """Allocate a NetBox IP address; invalidates the IP cache and triggers an endpoint sync (30s timeout)."""
        # Shared write path, then sync endpoints with the new IP data.
        return await _netbox_write(request, "NETBOX_ALLOCATE_IP", ["netbox_ips"],
                                   log_name="netbox_allocate_ip",
                                   sync_body="data", timeout=30.0)

    @app.delete("/api/netbox/ips/{ip_id}")
    async def netbox_release_ip(ip_id: int, request: Request):
        """Release a NetBox IP back to the pool; invalidates the IP cache and triggers an endpoint sync."""
        # Shared write path: ownership check, release, then resync endpoints.
        return await _netbox_write(request, "NETBOX_RELEASE_IP", ["netbox_ips"],
                                   log_name="netbox_release_ip",
                                   id_field="ip_id", obj_id=ip_id,
                                   verify_key="netbox_ips", tenant_mode=None,
                                   sync_body="null")

    @app.put("/api/netbox/ips/{ip_id}")
    async def netbox_update_ip(ip_id: int, request: Request):
        """Update a NetBox IP address; invalidates the IP cache and triggers an endpoint sync."""
        # Shared write path: ownership check, update, then resync endpoints.
        return await _netbox_write(request, "NETBOX_UPDATE_IP_ADDR", ["netbox_ips"],
                                   log_name="netbox_update_ip",
                                   id_field="ip_id", obj_id=ip_id,
                                   verify_key="netbox_ips",
                                   tenant_mode="if_present", sync_body="data")

    # ── Update trigger + module install (/setup/update, /setup/modules/*) ─────
