"""TrueNAS (storage) routes + per-tenant appliance CRUD.

Mirrors routes/nw.py: tenant-scoped fleet list, per-appliance live relay with
offline-cache fallback, _authz_truenas_appliance (read_scope/write_scope),
per-tenant appliance CRUD (each record tenant-stamped + spoke_id-bound), and a
poll-now endpoint that folds the rich poll into the cache twin.
"""
# Request/error types, the hub message builder, spoke-reply unwrapping, tenant access rules,
# logger and uuid (for new appliance ids), all re-exported by the api module.
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access,
    logger, uuid,
)
import time

import instance_vault
from storage_perf import merge_rows
from warm_cache import ALL_SCOPE, CacheJob


def register(app, hub, ctx):
    """Register truenas routes on the Hub app."""
    # Pull the session and role-check helpers off the shared context once for all routes.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin

    def _enforce_tenant_bind(request, cfg, kind):
        """Shared add/edit gate for tenant-scoped appliance creation. A
        tenant-admin may bind ``cfg`` ONLY to a spoke in their own tenant (via
        ``cfg['spoke_id']``) and the record is bound to that tenant; Global
        Admin is unrestricted (record tenant defaults to the spoke's tenant).
        Plain users are rejected. Mutates ``cfg['tenant_id']`` in place. Raises
        403 on violation. Mirrors routes/nw.py:_enforce_tenant_bind."""
        # Who is acting and which spoke the record should be bound to.
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        # Non-admins must be tenant-admins binding to a spoke of their own tenant.
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403,
                                    detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            # The record's tenant always follows the bound spoke for a tenant-admin.
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        # Admins may set any tenant; if they left it blank, default to the bound spoke's tenant.
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _truenas_appliances_for_spoke(hub, spoke_id: str):
        """The appliance slice a spoke should receive (bound-to-it, else unbound)."""
        # All configured appliances from global_config.
        appliances = (hub.state.system_state.get("global_config", {})
                      .get("truenas_appliances", []) or [])
        # Appliances explicitly bound to this spoke.
        pk = hub._primary_key(spoke_id)
        mine = [a for a in appliances if isinstance(a, dict)
                and hub._primary_key(a.get("spoke_id") or "") == pk]
        # If none are bound to it, this spoke manages the unbound appliances instead.
        if not mine:
            mine = [a for a in appliances if isinstance(a, dict) and not a.get("spoke_id")]
        return mine

    def _project_truenas_appliances_for_push(appliances):
        """Copy appliance dicts for the spoke payload (creds retained — runtime
        only). Mirrors routes/nw.py:_project_nw_devices_for_push."""
        # deepcopy so later edits to stored records cannot alter a payload already queued.
        import copy
        return [copy.deepcopy(a) for a in appliances if isinstance(a, dict)]

    async def _truenas_push_fleet(hub, spoke_id: str):
        """Re-push the bound appliance slice to a connected truenas spoke."""
        # Only push to a spoke that is connected right now.
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        # Payload: this spoke's appliances, the shared tenant id, and the default poll interval.
        # Vault-backed API keys are resolved onto copies here, never stored.
        payload = {"appliances": await instance_vault.overlay_many(
                        hub, _project_truenas_appliances_for_push(
                            _truenas_appliances_for_spoke(hub, spoke_id)),
                        "truenas_appliances"),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   "default_poll_interval":
                       (hub.state.system_state.get("global_config", {}) or {})
                       .get("truenas_poll_default_interval")}
        # Wrap in a hub UPDATE_CONFIG message and send it.
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _shared_truenas_hidden(request):
        """The viewer's tenant has its own storage spoke, so shared appliances
        and the shared truenas spoke are hidden from it."""
        # The tenant the viewer is acting as.
        tid = access.request_effective_tenant(_session_user(request), request)
        # True when that tenant has opted out of shared storage by having its own spoke.
        return access.tenant_left_shared(app.state.hub, tid, "storage")

    def _authz_truenas_appliance(request, appliance_id, write=False):
        """Authorize + classify a per-appliance truenas op by the appliance's
        OWNING tenant. Returns ``(appliance, scope, spoke_id)``. Raises 404 /
        403. Mirrors routes/nw.py:_authz_nw_device. ``scope`` folds the caller's
        tier with the appliance's tenancy (read_scope/write_scope): ``"full"``
        (admin or own-tenant-dedicated), ``"filtered"`` (shared → own slice),
        ``"deny"`` → 403. ``spoke_id`` resolves from the record's ``spoke_id``
        (per-tenant spokes), falling back to the tenant/shared resolver."""
        # Find the appliance record by id; unknown ids are 404.
        hub = app.state.hub
        appliances = (hub.state.system_state.get("global_config", {}) or {}) \
            .get("truenas_appliances", []) or []
        app_ = next((a for a in appliances if isinstance(a, dict) and a.get("id") == appliance_id), None)
        if not app_:
            raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
        # Work out the caller's access level for the appliance's owning tenant.
        sess = _session_user(request)
        tid = app_.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        # Deny outright, or deny shared/limited access when this tenant hides shared storage.
        if scope == "deny" or (scope in ("filtered", "constrained") and _shared_truenas_hidden(request)):
            raise HTTPException(status_code=403,
                                detail="You do not have access to this TrueNAS appliance")
        return app_, scope, _truenas_spoke_for(app_)

    def _truenas_spoke_for(app_):
        """The connected spoke serving an appliance, or "" (callers use the cache)."""
        hub = app.state.hub
        tid = app_.get("tenant_id", "")
        # Use the appliance's bound spoke when it is connected.
        spoke_id = app_.get("spoke_id") or ""
        # Otherwise fall back to the shared or tenant storage spoke.
        if (not spoke_id
                or hub._primary_key(spoke_id) not in hub.active_connections):
            spoke_id = (hub.get_truenas_spoke_for_shared()
                        if access.tenant_is_shared(tid)
                        else hub.get_truenas_spoke_for_tenant(tid)) or ""
        # A resolved spoke that is not connected is treated as none.
        if spoke_id and hub._primary_key(spoke_id) not in hub.active_connections:
            spoke_id = ""
        return spoke_id

    # ── fleet list (tenant-scoped, offline-cache fallback) ─────────────────────
    # List the TrueNAS appliances the caller may see.
    @app.get("/api/truenas/appliances")
    async def truenas_list_appliances(request: Request, tenant: str = None):
        """List the truenas fleet, tenant-scoped. Admin → the whole fleet.
        Non-admin → own-tenant + shared appliances only. The hub config
        (``truenas_appliances``, tenant-stamped) is the visibility gate; status
        and version come from the spoke's last background poll."""
        # Who is asking and whether they are an admin.
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        # All configured appliances, and whether shared ones should be hidden from this viewer.
        all_apps = (hub.state.system_state.get("global_config", {}) or {}) \
            .get("truenas_appliances", []) or []
        hide_shared = not is_admin and _shared_truenas_hidden(request)

        def _app_visible(tid):
            """Return True if an appliance owned by tenant ``tid`` should be shown to this caller.
            """
            # Hide shared and unowned appliances when the tenant opted out of shared storage.
            if hide_shared and (access.tenant_is_shared(tid) or not str(tid or "").strip()):
                return False
            # Admins see everything; others see their own and shared tenants' appliances.
            return is_admin or access.spoke_visible_to_session(sess, tid)

        # Configured appliances visible to the caller.
        visible = [a for a in all_apps if isinstance(a, dict) and _app_visible(a.get("tenant_id", ""))]

        # Rows come from the hub config + the spoke's background poll (no live
        # round-trip), so the list is instant and shows the last-polled state.
        rows = []
        for a in visible:
            entry = hub.truenas_appliance_cache.get(a.get("id")) or {}
            info = (entry.get("info") or {}).get("data") or {}
            rows.append({
                "id": a.get("id"), "name": a.get("name"), "host": a.get("host"),
                "object_type": a.get("object_type", "truenas"),
                "verify_ssl": a.get("verify_ssl"), "tenant_id": a.get("tenant_id", ""),
                "info": info if isinstance(info, dict) else {},
                # None = never polled yet (shown as "—").
                "reachable": entry.get("reachable"),
                "polled_at": entry.get("polled_at"),
            })
        return {"status": "SUCCESS", "data": rows, "message": f"{len(rows)} appliance(s)"}

    # ── per-appliance live relay (with offline-cache fallback) ────────────────
    # Read live appliance data, falling back to cache when the spoke is offline.
    @app.get("/api/truenas/{appliance_id}/{endpoint}")
    async def truenas_get_appliance_data(request: Request, appliance_id: str,
                                         endpoint: str, tenant: str = None):
        """Live per-appliance truenas data
        (info|pools|datasets|disks|shares|alerts|services|capacity|performance),
        tenant-gated. ``_authz_truenas_appliance`` resolves the appliance
        record + scope + spoke. Caches the raw envelope on every live fetch +
        serves it (marked ``stale``) when the spoke is offline."""
        hub = app.state.hub
        # URL endpoint name -> spoke command.
        command_map = {
            "info":      "TRUENAS_PROBE",
            "pools":     "TRUENAS_GET_POOLS",
            "datasets":  "TRUENAS_GET_DATASETS",
            "disks":     "TRUENAS_GET_DISKS",
            "shares":    "TRUENAS_GET_SHARES",
            "alerts":    "TRUENAS_GET_ALERTS",
            "services":  "TRUENAS_GET_SERVICES",
            "capacity":  "TRUENAS_GET_CAPACITY",
            "performance": "TRUENAS_GET_PERFORMANCE",
        }
        # Unknown endpoints are rejected.
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400,
                                detail=f"Endpoint {endpoint} not supported by truenas module")
        logger.debug("relay GET /api/truenas/%s/%s tenant=%s", appliance_id, endpoint, tenant)
        # Authorize, then build the relay payload with the appliance id and its tenant.
        app_, scope, spoke_id = _authz_truenas_appliance(request, appliance_id)
        tid = app_.get("tenant_id", "")
        relay_payload = {"appliance_id": appliance_id}
        # For shares, the "tenant" query value is reused as the share kind (smb by default).
        if endpoint == "shares":
            relay_payload["kind"] = (tenant if tenant else "smb")
        if tid:
            relay_payload["tenant"] = tid
        # capacity/poll fan several WS calls on the spoke — give them room.
        timeout = 45.0 if endpoint == "capacity" else 20.0
        # Serve the background poll's cached data first (like Firewall): pages
        # load instantly; the spoke refreshes it every poll interval.
        # Performance is a live per-second sample, so it skips the cache while
        # the spoke is connected (the cache is only the fallback).
        cached = hub.truenas_cache_get_appliance(appliance_id, endpoint)
        if cached is not None and not (endpoint == "performance" and spoke_id):
            out = dict(cached) if isinstance(cached, dict) else cached
            if isinstance(out, dict) and not spoke_id:
                out["stale"] = True
            return out
        # Nothing cached and no connected spoke: 503.
        if not spoke_id:
            raise HTTPException(status_code=503,
                                detail="No spoke connected")
        # Live fetch; cache the result for offline fallback and return it.
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.truenas_cache_set_appliance(appliance_id, endpoint, data)
            return data
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Live fetch failed: fall back to cached data (marked stale) if any.
        except Exception as e:
            cached = hub.truenas_cache_get_appliance(appliance_id, endpoint)
            if cached is not None:
                logger.warning("truenas_get_appliance_data live fetch failed (%s/%s: %s)"
                               " — serving cached", appliance_id, endpoint, e)
                filtered = dict(cached) if isinstance(cached, dict) else cached
                if isinstance(filtered, dict):
                    filtered["stale"] = True
                return filtered
            # Nothing cached: log and report 500.
            logger.exception("truenas_get_appliance_data failed (%s/%s)", appliance_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    # ── performance trend (5-minute averages kept by the spoke) ──────────────
    PERF_RECENT_S = 3600  # the Overview's default range, kept warm by the hub

    async def _perf_history(app_, start, end):
        """5-minute averages for ``start``..``end`` from the spoke that stores
        them, gaps filled from the hub's pushed copy; only the hub's copy when
        the spoke is offline or fails."""
        hub = app.state.hub
        appliance_id = app_.get("id")
        spoke_id = _truenas_spoke_for(app_)
        if spoke_id:
            payload = {"appliance_id": appliance_id, "start": start, "end": end}
            if app_.get("tenant_id"):
                payload["tenant"] = app_["tenant_id"]
            try:
                res = access.unwrap_spoke(await hub.request_response(
                    spoke_id, "TRUENAS_GET_PERF_HISTORY", payload, timeout=20.0))
                if isinstance(res, dict) and res.get("status") == "SUCCESS":
                    return {"status": "SUCCESS", "interval": 300, "source": "spoke",
                            "data": merge_rows(res.get("data"), hub.storage_perf.get(
                                "truenas", appliance_id, start, end))}
                logger.warning("truenas perf history %s from spoke: %s", appliance_id,
                               (res or {}).get("message") if isinstance(res, dict) else res)
            except Exception as e:  # noqa: BLE001 — fall back to the hub copy
                logger.warning("truenas perf history %s from spoke failed: %s", appliance_id, e)
        rows = hub.storage_perf.get("truenas", appliance_id, start, end)
        return {"status": "SUCCESS", "interval": 300, "source": "hub", "data": rows}

    def _perf_recent_job(app_):
        """Warm-cache job: the appliance's last hour of averages."""
        tid = app_.get("tenant_id", "")

        async def fetch():
            now = time.time()
            return await _perf_history(app_, now - PERF_RECENT_S, now)

        tenants = (tid,) if tid and not access.tenant_is_shared(tid) else (ALL_SCOPE,)
        return CacheJob("truenas_perf_recent", app_.get("id"), fetch, tenants, lane="truenas")

    def truenas_cache_feed(_hub):
        """Feed: every appliance's last hour, so the Overview opens instantly."""
        appliances = (app.state.hub.state.system_state.get("global_config", {}) or {}) \
            .get("truenas_appliances", []) or []
        for a in appliances:
            if isinstance(a, dict) and a.get("id"):
                yield _perf_recent_job(a)

    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("truenas", truenas_cache_feed)

    @app.get("/api/truenas/{appliance_id}/performance/history")
    async def truenas_performance_history(request: Request, appliance_id: str,
                                          start: float = None, end: float = None):
        """The appliance's 5-minute performance averages. No range = the last
        hour, served from the hub's warm cache; a ``start``/``end`` range
        (epoch seconds) is read from the spoke, which stores 7 days (the hub's
        copy if the spoke is offline)."""
        hub = app.state.hub
        app_, _scope, _spoke = _authz_truenas_appliance(request, appliance_id)
        if start is None:
            job = _perf_recent_job(app_)
            data = await hub.cache_read(job.ns, job.key, job.fetch,
                                        tenants=job.tenants, lane=job.lane)
            return hub.cache_annotate(data, job.ns, job.key)
        return await _perf_history(app_, start, end if end is not None else time.time())

    # ── poll now (admin) ───────────────────────────────────────────────────────
    @app.post("/api/truenas/{appliance_id}/poll")
    async def truenas_poll_appliance(appliance_id: str, request: Request):
        """POLL NOW for one TrueNAS appliance (admin-only): run a full poll on
        the spoke + fold the rich result into the per-appliance cache."""
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Authorize and resolve the spoke; a poll needs a live spoke.
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Run the full poll (60s), cache the rich result, and return it.
        try:
            result = await hub.request_response(spoke_id, "TRUENAS_POLL",
                                                {"appliance_id": appliance_id,
                                                 "tenant": app_.get("tenant_id", "")},
                                                timeout=60.0)
            data = access.unwrap_spoke(result)
            if isinstance(data, dict):
                await hub.truenas_cache_set_poll(appliance_id, data)
            return data
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:
            logger.exception("truenas_poll_appliance failed (%s)", appliance_id)
            raise HTTPException(status_code=500, detail=str(e))

    # ── write / management (gated by write_scope) ─────────────────────────────
    # Create a ZFS dataset on an appliance.
    @app.post("/api/truenas/{appliance_id}/dataset")
    async def truenas_create_dataset(appliance_id: str, request: Request):
        """Create dataset ``name`` in ``pool`` on the appliance (requires write access)."""
        # Authorize for writing; a write needs a live spoke.
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Use the body only when it is a JSON object; anything else is treated as empty.
        d = data or {} if isinstance(data, dict) else {}
        # Pool and dataset name are required.
        if not d.get("pool") or not d.get("name"):
            raise HTTPException(status_code=400, detail="pool and name required")
        # Relay the create and return the spoke's reply.
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_DATASET",
                                            {"appliance_id": appliance_id,
                                             "pool": d["pool"], "name": d["name"],
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=60.0)
        return access.unwrap_spoke(result)

    # Delete a ZFS dataset on an appliance.
    @app.delete("/api/truenas/{appliance_id}/dataset")
    async def truenas_delete_dataset(appliance_id: str, request: Request):
        """Delete a dataset (by ``dataset`` or ``dataset_id``) on the appliance (requires write
           access).
        """
        # Authorize for writing; a write needs a live spoke.
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Use the body only when it is a JSON object; anything else is treated as empty.
        d = data or {} if isinstance(data, dict) else {}
        # Accept either field name for the dataset; it is required.
        dataset = d.get("dataset") or d.get("dataset_id")
        if not dataset:
            raise HTTPException(status_code=400, detail="dataset required")
        # Relay the delete and return the spoke's reply.
        result = await hub.request_response(spoke_id, "TRUENAS_DELETE_DATASET",
                                            {"appliance_id": appliance_id,
                                             "dataset": dataset,
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=60.0)
        return access.unwrap_spoke(result)

    # Create an SMB or NFS share on an appliance.
    @app.post("/api/truenas/{appliance_id}/share")
    async def truenas_create_share(appliance_id: str, request: Request):
        """Create an SMB/NFS share for ``dataset`` on the appliance (requires write access)."""
        # Authorize for writing; a write needs a live spoke.
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Use the body only when it is a JSON object; anything else is treated as empty.
        d = data or {} if isinstance(data, dict) else {}
        # Share kind defaults to SMB and must be SMB or NFS.
        kind = (d.get("kind") or "smb").lower()
        if kind not in ("smb", "nfs"):
            raise HTTPException(status_code=400, detail="kind must be smb or nfs")
        # The dataset to share is required.
        if not d.get("dataset"):
            raise HTTPException(status_code=400, detail="dataset required")
        # Relay the create and return the spoke's reply.
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_SHARE",
                                            {"appliance_id": appliance_id,
                                             "kind": kind, "dataset": d["dataset"],
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=60.0)
        return access.unwrap_spoke(result)

    # Snapshot a dataset on an appliance.
    @app.post("/api/truenas/{appliance_id}/snapshot")
    async def truenas_create_snapshot(appliance_id: str, request: Request):
        """Create a ZFS snapshot of ``dataset`` on the appliance (requires write access)."""
        # Authorize for writing; a write needs a live spoke.
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Use the body only when it is a JSON object; anything else is treated as empty.
        d = data or {} if isinstance(data, dict) else {}
        # The dataset to snapshot is required.
        if not d.get("dataset"):
            raise HTTPException(status_code=400, detail="dataset required")
        # Relay the snapshot (name optional; the spoke picks one if blank) and return the reply.
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_SNAPSHOT",
                                            {"appliance_id": appliance_id,
                                             "dataset": d["dataset"], "name": d.get("name", ""),
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=60.0)
        return access.unwrap_spoke(result)

    # Start a pool scrub (integrity check) on an appliance.
    @app.post("/api/truenas/{appliance_id}/scrub")
    async def truenas_run_scrub(appliance_id: str, request: Request):
        """Start a scrub of pool ``pool_id`` on the appliance (requires write access)."""
        # Authorize for writing; a write needs a live spoke.
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="No spoke connected")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Use the body only when it is a JSON object; anything else is treated as empty.
        d = data or {} if isinstance(data, dict) else {}
        # Accept either field name for the pool; it is required.
        pool_id = d.get("pool_id") or d.get("pool")
        if not pool_id:
            raise HTTPException(status_code=400, detail="pool_id required")
        # pool.scrub.start is a long job — generous window.
        result = await hub.request_response(spoke_id, "TRUENAS_RUN_SCRUB",
                                            {"appliance_id": appliance_id,
                                             "pool_id": str(pool_id),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=300.0)
        return access.unwrap_spoke(result)

    # ── Setup config (per-tenant appliance CRUD + module poll cadence) ────────
    # List configured appliances for the Setup page.
    @app.get("/setup/truenas-appliances")
    async def get_truenas_appliances(request: Request):
        """Return the appliance records the caller may see, with API keys removed."""
        # All configured appliances.
        hub = app.state.hub
        appliances = hub.state.system_state.get("global_config", {}) \
            .get("truenas_appliances", [])
        # Non-admins only see appliances of their own and shared tenants.
        sess = _session_user(request)
        if not _is_admin(sess):
            appliances = [a for a in appliances
                          if access.spoke_visible_to_session(
                              sess, (a or {}).get("tenant_id", ""))]
        # Strip the api_key from the response (it's a secret; the UI only needs
        # to know whether one is set).
        out = []
        # Copy each record and swap the secret key for a "key is set" flag.
        for a in appliances:
            if not isinstance(a, dict):
                continue
            aa = dict(a)
            aa["api_key_set"] = bool(aa.get("api_key")) or instance_vault.has_vault_ref(aa)
            aa.pop("api_key", None)
            out.append(aa)
        return {"truenas_appliances": out}

    # Read the default TrueNAS poll interval.
    @app.get("/setup/truenas-poll-config")
    async def get_truenas_poll_config(request: Request):
        """Return the module-wide default poll interval (None means the spoke's built-in default).
        """
        # Read it from global_config.
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("truenas_poll_default_interval")}

    # Change the default TrueNAS poll interval.
    @app.post("/setup/truenas-poll-config")
    async def set_truenas_poll_config(request: Request):
        """Set the module-wide default poll interval (admin only) and push it to storage spokes."""
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Read the new value; blank/null clears it, anything else must be an integer.
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400,
                                detail="default_poll_interval must be an integer or null")
        # Save it in global_config and mark state for saving.
        gc = hub.state.system_state.get("global_config", {})
        gc["truenas_poll_default_interval"] = val
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Re-push config to every storage spoke so they pick up the new interval; count successes.
        pushed = 0
        for sid in (hub.get_all_spokes_by_type("storage") or []):
            if await _truenas_push_fleet(hub, sid):
                pushed += 1
        return {"status": "ok", "default_poll_interval": val, "pushed": pushed}

    # Add an appliance.
    @app.post("/setup/truenas-appliances")
    async def add_truenas_appliance(request: Request):
        """Add a TrueNAS appliance record, bound to a spoke in the caller's tenant."""
        # Any unexpected failure below becomes a 500; our own HTTP errors pass through.
        hub = app.state.hub
        try:
            # Read the new record from the body; name and host are required.
            data = await request.json()
            new_app = data.get("appliance", {})
            if not new_app.get("name") or not new_app.get("host"):
                raise HTTPException(status_code=400, detail="Missing appliance name or host")
            # Check the spoke binding and stamp the record's tenant.
            _enforce_tenant_bind(request, new_app, "TrueNAS appliance")
            # With the Credential Vault on, the API key must come from it; the
            # inline key is never persisted once a reference is set.
            sess = _session_user(request)
            await instance_vault.validate_ref(
                hub, new_app, sess, is_admin=_is_admin(sess), storage_key="truenas_appliances")
            instance_vault.strip_inline_secrets(new_app, "truenas_appliances")
            # Give it an id if none was supplied, and mark its object type.
            if "id" not in new_app:
                new_app["id"] = str(uuid.uuid4())
            new_app.setdefault("object_type", "truenas")
            # Append to the stored list and mark state for saving.
            global_config = hub.state.system_state.get("global_config", {})
            appliances = global_config.get("truenas_appliances", [])
            appliances.append(new_app)
            global_config["truenas_appliances"] = appliances
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            # Push the updated slice to the bound spoke, if any.
            spoke_id = new_app.get("spoke_id")
            pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
            return {"status": "ok", "appliance": new_app, "pushed": pushed}
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:
            logger.exception("add_truenas_appliance failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Edit an appliance.
    @app.put("/setup/truenas-appliances/{appliance_id}")
    async def update_truenas_appliance(appliance_id: str, request: Request):
        """Merge changes into an appliance record and re-push its spoke's config."""
        # Any unexpected failure below becomes a 500; our own HTTP errors pass through.
        hub = app.state.hub
        try:
            # Read the changes and find the record's index in the stored list.
            data = await request.json()
            update_data = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            appliances = global_config.get("truenas_appliances", [])
            idx = next((i for i, a in enumerate(appliances)
                        if isinstance(a, dict) and a.get("id") == appliance_id), None)
            # Unknown id.
            if idx is None:
                raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
            # Sentinel-merge the api_key: an empty/absent key keeps the stored one
            # (so a re-save of host/verify_ssl doesn't wipe the key).
            if "api_key" in update_data and update_data["api_key"] in (None, ""):
                update_data["api_key"] = appliances[idx].get("api_key", "")
            # Apply the changes and mark state for saving.
            appliances[idx].update(update_data)
            sess = _session_user(request)
            await instance_vault.validate_ref(
                hub, appliances[idx], sess, is_admin=_is_admin(sess), storage_key="truenas_appliances")
            instance_vault.strip_inline_secrets(appliances[idx], "truenas_appliances")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            # Push to the bound spoke; "partial_success" means saved but not pushed.
            spoke_id = appliances[idx].get("spoke_id")
            pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
            return {"status": "ok" if pushed else "partial_success",
                    "message": ("Appliance updated and pushed to spoke." if pushed
                                else "Configuration saved, but associated spoke is not connected."),
                    "pushed": pushed}
        # Re-raise our own HTTP errors unchanged.
        except HTTPException:
            raise
        # Anything else is logged and reported as 500.
        except Exception as e:
            logger.exception("update_truenas_appliance failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Delete an appliance.
    @app.delete("/setup/truenas-appliances/{appliance_id}")
    async def delete_truenas_appliance(appliance_id: str):
        """Remove an appliance record and re-push its spoke's (now smaller) config."""
        # Load the stored list and remember the record being removed (for its spoke).
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        appliances = global_config.get("truenas_appliances", [])
        victim = next((a for a in appliances if isinstance(a, dict) and a.get("id") == appliance_id), None)
        # Filter it out in place; an unchanged length means the id was unknown.
        original_len = len(appliances)
        appliances[:] = [a for a in appliances if not (isinstance(a, dict) and a.get("id") == appliance_id)]
        if len(appliances) == original_len:
            raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
        # Mark state for saving.
        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Re-push the slice so the spoke stops polling the deleted appliance.
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"TrueNAS appliance {appliance_id} deleted.",
                "pushed": pushed}

    # ── TrueNAS → NetBox inventory-discovery sync ─────────────────────────────
    # Mirrors routes/setup.py's nw-discovery-sync routes. Config lives in
    # global_config["truenas_discovery_sync"] (enabled/source/mode/interval/
    # daily_time/concurrency/defaults); the background loop runs in
    # TruenasDiscoverySyncMixin.run_truenas_discovery_sync_loop.

    # Read the discovery-sync settings and the available data sources.
    @app.get("/setup/truenas-discovery-sync")
    async def get_truenas_discovery_sync(request: Request):
        """Return the TrueNAS -> NetBox sync config, its sources, and whether NetBox is connected.
        """
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Stored config (or {}).
        cfg = hub.state.system_state.get("global_config", {}).get("truenas_discovery_sync", {}) or {}
        # Config plus each source's label, module type and connection state.
        return {"config": cfg,
                "sources": [{"name": n, "label": se.get("label", n),
                              "module_type": se.get("module_type", ""),
                              "connected": bool(hub.get_all_spokes_by_type(se.get("module_type", "")))}
                             for n, se in hub.TRUENAS_DISCOVERY_SOURCES.items()],
                "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    # Save the discovery-sync settings.
    @app.post("/setup/truenas-discovery-sync")
    async def set_truenas_discovery_sync(request: Request):
        """Merge the posted settings into the TrueNAS -> NetBox sync config (admin only)."""
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Parse the body; a bad body becomes {}.
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Take the "config" object from the body.
        cfg = (data or {}).get("config", {}) if isinstance(data, dict) else {}
        # Read the current global config.
        gc = hub.state.system_state.get("global_config", {}) or {}
        # Sentinel-merge: keep defaults if the caller omitted them.
        old = gc.get("truenas_discovery_sync", {}) or {}
        merged = {**old, **cfg}
        # Save the merged config and mark state for saving.
        gc["truenas_discovery_sync"] = merged
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "config": merged}

    @app.post("/setup/truenas-discovery-sync/run")
    async def run_truenas_discovery_sync(request: Request):
        """On-demand TrueNAS → NetBox inventory sync ('Sync now'). Body
        optional: ``{"tenant_id": "<id>"}`` to sync one tenant; absent → all."""
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Parse the body; an empty or bad body means "sync all tenants".
        try:
            data = await request.json()
        except Exception:
            data = {}
        # Optional single tenant to sync.
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        # One tenant: sync just that one.
        if target:
            results = [await hub.sync_tenant_truenas_devices(target)]
        # All tenants: run the full sync and collect per-tenant results.
        else:
            agg = await hub.run_truenas_discovery_sync_all()
            results = list((agg.get("per_tenant") or {}).values())
        # Totals across all synced tenants.
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        # Return per-tenant results plus a summary.
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results)}}

    @app.get("/setup/truenas-discovery-sync/status")
    async def truenas_discovery_sync_status(request: Request):
        """Per-tenant last truenas-discovery-sync status."""
        # Admin only.
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        # Stored last-run status per tenant.
        statuses = hub.simulations_store.get_all_truenas_discovery_sync_status()
        tenants = []
        # One row per tenant, with defaults for missing counters.
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "discovered_total": st.get("discovered_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        # Return the rows for the status table.
        return {"tenants": tenants}