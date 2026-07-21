"""TrueNAS (storage) routes + per-tenant appliance CRUD.

Mirrors routes/nw.py: tenant-scoped fleet list, per-appliance live relay with
offline-cache fallback, _authz_truenas_appliance (read_scope/write_scope),
per-tenant appliance CRUD (each record tenant-stamped + spoke_id-bound), and a
poll-now endpoint that folds the rich poll into the cache twin.
"""
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, get_spoke_or_503,
    logger, uuid,
)


def register(app, hub, ctx):
    """Register truenas routes on the Hub app."""
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
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403,
                                    detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _get_truenas_spoke(hub):
        """The connected truenas spoke id, or raise 503 (single-instance resolver)."""
        return get_spoke_or_503(hub, "storage", "TrueNAS")

    def _truenas_appliances_for_spoke(hub, spoke_id: str):
        """The appliance slice a spoke should receive (bound-to-it, else unbound)."""
        appliances = (hub.state.system_state.get("global_config", {})
                      .get("truenas_appliances", []) or [])
        mine = [a for a in appliances if isinstance(a, dict) and a.get("spoke_id") == spoke_id]
        if not mine:
            mine = [a for a in appliances if isinstance(a, dict) and not a.get("spoke_id")]
        return mine

    def _project_truenas_appliances_for_push(appliances):
        """Copy appliance dicts for the spoke payload (creds retained — runtime
        only). Mirrors routes/nw.py:_project_nw_devices_for_push."""
        import copy
        return [copy.deepcopy(a) for a in appliances if isinstance(a, dict)]

    async def _truenas_push_fleet(hub, spoke_id: str):
        """Re-push the bound appliance slice to a connected truenas spoke."""
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        payload = {"appliances": _project_truenas_appliances_for_push(
                        _truenas_appliances_for_spoke(hub, spoke_id)),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   "default_poll_interval":
                       (hub.state.system_state.get("global_config", {}) or {})
                       .get("truenas_poll_default_interval")}
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _authz_truenas_appliance(request, appliance_id, write=False):
        """Authorize + classify a per-appliance truenas op by the appliance's
        OWNING tenant. Returns ``(appliance, scope, spoke_id)``. Raises 404 /
        403. Mirrors routes/nw.py:_authz_nw_device. ``scope`` folds the caller's
        tier with the appliance's tenancy (read_scope/write_scope): ``"full"``
        (admin or own-tenant-dedicated), ``"filtered"`` (shared → own slice),
        ``"deny"`` → 403. ``spoke_id`` resolves from the record's ``spoke_id``
        (per-tenant spokes), falling back to the tenant/shared resolver."""
        hub = app.state.hub
        appliances = (hub.state.system_state.get("global_config", {}) or {}) \
            .get("truenas_appliances", []) or []
        app_ = next((a for a in appliances if isinstance(a, dict) and a.get("id") == appliance_id), None)
        if not app_:
            raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
        sess = _session_user(request)
        tid = app_.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(status_code=403,
                                detail="You do not have access to this TrueNAS appliance")
        spoke_id = app_.get("spoke_id") or ""
        if (not spoke_id
                or hub._primary_key(spoke_id) not in hub.active_connections):
            spoke_id = (hub.get_truenas_spoke_for_shared()
                        if access.tenant_is_shared(tid)
                        else hub.get_truenas_spoke_for_tenant(tid)) or ""
        if spoke_id and hub._primary_key(spoke_id) not in hub.active_connections:
            spoke_id = ""
        return app_, scope, spoke_id

    # ── fleet list (tenant-scoped, offline-cache fallback) ─────────────────────
    @app.get("/api/truenas/appliances")
    async def truenas_list_appliances(request: Request, tenant: str = None):
        """List the truenas fleet, tenant-scoped. Admin → the whole fleet (all
        connected truenas spokes). Non-admin → own-tenant + shared appliances
        only. The hub config (``truenas_appliances``, tenant-stamped) is the
        AUTHORITATIVE visibility gate. Caches the whole-fleet (admin) fetch +
        serves it tenant-filtered when no relevant spoke is connected."""
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        all_apps = (hub.state.system_state.get("global_config", {}) or {}) \
            .get("truenas_appliances", []) or []
        visible = [a for a in all_apps if isinstance(a, dict)
                   and (is_admin or access.spoke_visible_to_session(sess, a.get("tenant_id", "")))]
        visible_ids = {a.get("id") for a in visible if a.get("id")}

        if is_admin:
            spokes = [s for s in (hub.get_all_spokes_by_type("storage") or [])
                      if s in hub.active_connections
                      and hub.approved_modules.get(s, False)]
            spoke_to_tid = {s: "" for s in spokes}
        else:
            spoke_to_tid = {}
            for t in ((sess or {}).get("user", {}).get("tenants") or []):
                s = hub.get_truenas_spoke_for_tenant(t)
                if s:
                    spoke_to_tid[s] = t
            shared_tid = access.shared_tenant_id()
            if shared_tid:
                s = hub.get_truenas_spoke_for_shared()
                if s:
                    spoke_to_tid[s] = shared_tid
            spoke_to_tid = {s: t for s, t in spoke_to_tid.items()
                            if s in hub.active_connections
                            and hub.approved_modules.get(s, False)}
            spokes = list(spoke_to_tid)

        if not spokes:
            cached = hub.truenas_cache_get_fleet_filtered(
                lambda r: is_admin
                or access.spoke_visible_to_session(sess, r.get("tenant_id", "")))
            if cached:
                out = dict((cached.get("appliances") or {}))
                out["stale"] = True
                out["fetched_at"] = cached.get("fetched_at")
                out["message"] = (out.get("message") or
                                 "TrueNAS spoke offline — showing last-known data")
                return out
            raise HTTPException(status_code=503,
                                detail="TrueNAS spoke not connected")

        merged, seen = [], set()
        for sid in spokes:
            tid = spoke_to_tid.get(sid, "")
            payload = {"tenant": tid} if tid else {}
            try:
                result = await hub.request_response(sid, "TRUENAS_LIST_APPLIANCES",
                                                    payload, timeout=20.0)
                env = access.unwrap_spoke(result)
                rows = env.get("data") if isinstance(env, dict) else None
                if isinstance(rows, list):
                    for r in rows:
                        if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                            seen.add(r["id"])
                            merged.append(r)
            except Exception as e:
                logger.warning("truenas_list_appliances: spoke %s fetch failed: %s", sid, e)

        if visible_ids:
            merged = [r for r in merged if r.get("id") in visible_ids]
        env = {"status": "SUCCESS", "data": merged,
               "message": f"{len(merged)} appliance(s)"}
        if is_admin:
            try:
                await hub.truenas_cache_set_fleet(env)
            except Exception:
                logger.debug("truenas_list_appliances: cache set failed", exc_info=True)
        return env

    # ── per-appliance live relay (with offline-cache fallback) ────────────────
    @app.get("/api/truenas/{appliance_id}/{endpoint}")
    async def truenas_get_appliance_data(request: Request, appliance_id: str,
                                         endpoint: str, tenant: str = None):
        """Live per-appliance truenas data
        (info|pools|datasets|disks|shares|alerts|services|capacity),
        tenant-gated. ``_authz_truenas_appliance`` resolves the appliance
        record + scope + spoke. Caches the raw envelope on every live fetch +
        serves it (marked ``stale``) when the spoke is offline."""
        hub = app.state.hub
        command_map = {
            "info":      "TRUENAS_PROBE",
            "pools":     "TRUENAS_GET_POOLS",
            "datasets":  "TRUENAS_GET_DATASETS",
            "disks":     "TRUENAS_GET_DISKS",
            "shares":    "TRUENAS_GET_SHARES",
            "alerts":    "TRUENAS_GET_ALERTS",
            "services":  "TRUENAS_GET_SERVICES",
            "capacity":  "TRUENAS_GET_CAPACITY",
        }
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400,
                                detail=f"Endpoint {endpoint} not supported by truenas module")
        logger.debug("relay GET /api/truenas/%s/%s tenant=%s", appliance_id, endpoint, tenant)
        app_, scope, spoke_id = _authz_truenas_appliance(request, appliance_id)
        tid = app_.get("tenant_id", "")
        relay_payload = {"appliance_id": appliance_id}
        if endpoint == "shares":
            relay_payload["kind"] = (tenant if tenant else "smb")
        if tid:
            relay_payload["tenant"] = tid
        # capacity/poll fan several WS calls on the spoke — give them room.
        timeout = 45.0 if endpoint == "capacity" else 20.0
        if not spoke_id:
            cached = hub.truenas_cache_get_appliance(appliance_id, endpoint)
            if cached is not None:
                filtered = dict(cached) if isinstance(cached, dict) else cached
                if isinstance(filtered, dict):
                    filtered["stale"] = True
                return filtered
            raise HTTPException(status_code=503,
                                detail="TrueNAS spoke not connected")
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.truenas_cache_set_appliance(appliance_id, endpoint, data)
            return data
        except HTTPException:
            raise
        except Exception as e:
            cached = hub.truenas_cache_get_appliance(appliance_id, endpoint)
            if cached is not None:
                logger.warning("truenas_get_appliance_data live fetch failed (%s/%s: %s)"
                               " — serving cached", appliance_id, endpoint, e)
                filtered = dict(cached) if isinstance(cached, dict) else cached
                if isinstance(filtered, dict):
                    filtered["stale"] = True
                return filtered
            logger.exception("truenas_get_appliance_data failed (%s/%s)", appliance_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    # ── poll now (admin) ───────────────────────────────────────────────────────
    @app.post("/api/truenas/{appliance_id}/poll")
    async def truenas_poll_appliance(appliance_id: str, request: Request):
        """POLL NOW for one TrueNAS appliance (admin-only): run a full poll on
        the spoke + fold the rich result into the per-appliance cache."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "TRUENAS_POLL",
                                                {"appliance_id": appliance_id,
                                                 "tenant": app_.get("tenant_id", "")},
                                                timeout=60.0)
            data = access.unwrap_spoke(result)
            if isinstance(data, dict):
                await hub.truenas_cache_set_poll(appliance_id, data)
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("truenas_poll_appliance failed (%s)", appliance_id)
            raise HTTPException(status_code=500, detail=str(e))

    # ── write / management (gated by write_scope) ─────────────────────────────
    @app.post("/api/truenas/{appliance_id}/dataset")
    async def truenas_create_dataset(appliance_id: str, request: Request):
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            data = await request.json()
        except Exception:
            data = {}
        d = data or {} if isinstance(data, dict) else {}
        if not d.get("pool") or not d.get("name"):
            raise HTTPException(status_code=400, detail="pool and name required")
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_DATASET",
                                            {"appliance_id": appliance_id,
                                             "pool": d["pool"], "name": d["name"],
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=30.0)
        return access.unwrap_spoke(result)

    @app.delete("/api/truenas/{appliance_id}/dataset")
    async def truenas_delete_dataset(appliance_id: str, request: Request):
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            data = await request.json()
        except Exception:
            data = {}
        d = data or {} if isinstance(data, dict) else {}
        dataset = d.get("dataset") or d.get("dataset_id")
        if not dataset:
            raise HTTPException(status_code=400, detail="dataset required")
        result = await hub.request_response(spoke_id, "TRUENAS_DELETE_DATASET",
                                            {"appliance_id": appliance_id,
                                             "dataset": dataset,
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=30.0)
        return access.unwrap_spoke(result)

    @app.post("/api/truenas/{appliance_id}/share")
    async def truenas_create_share(appliance_id: str, request: Request):
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            data = await request.json()
        except Exception:
            data = {}
        d = data or {} if isinstance(data, dict) else {}
        kind = (d.get("kind") or "smb").lower()
        if kind not in ("smb", "nfs"):
            raise HTTPException(status_code=400, detail="kind must be smb or nfs")
        if not d.get("dataset"):
            raise HTTPException(status_code=400, detail="dataset required")
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_SHARE",
                                            {"appliance_id": appliance_id,
                                             "kind": kind, "dataset": d["dataset"],
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=30.0)
        return access.unwrap_spoke(result)

    @app.post("/api/truenas/{appliance_id}/snapshot")
    async def truenas_create_snapshot(appliance_id: str, request: Request):
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            data = await request.json()
        except Exception:
            data = {}
        d = data or {} if isinstance(data, dict) else {}
        if not d.get("dataset"):
            raise HTTPException(status_code=400, detail="dataset required")
        result = await hub.request_response(spoke_id, "TRUENAS_CREATE_SNAPSHOT",
                                            {"appliance_id": appliance_id,
                                             "dataset": d["dataset"], "name": d.get("name", ""),
                                             "options": d.get("options"),
                                             "tenant": app_.get("tenant_id", "")},
                                            timeout=30.0)
        return access.unwrap_spoke(result)

    @app.post("/api/truenas/{appliance_id}/scrub")
    async def truenas_run_scrub(appliance_id: str, request: Request):
        hub = app.state.hub
        app_, _scope, spoke_id = _authz_truenas_appliance(request, appliance_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503, detail="TrueNAS spoke not connected")
        try:
            data = await request.json()
        except Exception:
            data = {}
        d = data or {} if isinstance(data, dict) else {}
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
    @app.get("/setup/truenas-appliances")
    async def get_truenas_appliances(request: Request):
        hub = app.state.hub
        appliances = hub.state.system_state.get("global_config", {}) \
            .get("truenas_appliances", [])
        sess = _session_user(request)
        if not _is_admin(sess):
            appliances = [a for a in appliances
                          if access.spoke_visible_to_session(
                              sess, (a or {}).get("tenant_id", ""))]
        # Strip the api_key from the response (it's a secret; the UI only needs
        # to know whether one is set).
        out = []
        for a in appliances:
            if not isinstance(a, dict):
                continue
            aa = dict(a)
            if "api_key" in aa:
                aa["api_key_set"] = bool(aa.get("api_key"))
                del aa["api_key"]
            out.append(aa)
        return {"truenas_appliances": out}

    @app.get("/setup/truenas-poll-config")
    async def get_truenas_poll_config(request: Request):
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("truenas_poll_default_interval")}

    @app.post("/setup/truenas-poll-config")
    async def set_truenas_poll_config(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400,
                                detail="default_poll_interval must be an integer or null")
        gc = hub.state.system_state.get("global_config", {})
        gc["truenas_poll_default_interval"] = val
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        pushed = 0
        for sid in (hub.get_all_spokes_by_type("storage") or []):
            if await _truenas_push_fleet(hub, sid):
                pushed += 1
        return {"status": "ok", "default_poll_interval": val, "pushed": pushed}

    @app.post("/setup/truenas-appliances")
    async def add_truenas_appliance(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_app = data.get("appliance", {})
            if not new_app.get("name") or not new_app.get("host"):
                raise HTTPException(status_code=400, detail="Missing appliance name or host")
            _enforce_tenant_bind(request, new_app, "TrueNAS appliance")
            if "id" not in new_app:
                new_app["id"] = str(uuid.uuid4())
            new_app.setdefault("object_type", "truenas")
            global_config = hub.state.system_state.get("global_config", {})
            appliances = global_config.get("truenas_appliances", [])
            appliances.append(new_app)
            global_config["truenas_appliances"] = appliances
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            spoke_id = new_app.get("spoke_id")
            pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
            return {"status": "ok", "appliance": new_app, "pushed": pushed}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("add_truenas_appliance failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/truenas-appliances/{appliance_id}")
    async def update_truenas_appliance(appliance_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            appliances = global_config.get("truenas_appliances", [])
            idx = next((i for i, a in enumerate(appliances)
                        if isinstance(a, dict) and a.get("id") == appliance_id), None)
            if idx is None:
                raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
            # Sentinel-merge the api_key: an empty/absent key keeps the stored one
            # (so a re-save of host/verify_ssl doesn't wipe the key).
            if "api_key" in update_data and update_data["api_key"] in (None, ""):
                update_data["api_key"] = appliances[idx].get("api_key", "")
            appliances[idx].update(update_data)
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            spoke_id = appliances[idx].get("spoke_id")
            pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
            return {"status": "ok" if pushed else "partial_success",
                    "message": ("Appliance updated and pushed to spoke." if pushed
                                else "Configuration saved, but associated spoke is not connected."),
                    "pushed": pushed}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_truenas_appliance failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/truenas-appliances/{appliance_id}")
    async def delete_truenas_appliance(appliance_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        appliances = global_config.get("truenas_appliances", [])
        victim = next((a for a in appliances if isinstance(a, dict) and a.get("id") == appliance_id), None)
        original_len = len(appliances)
        appliances[:] = [a for a in appliances if not (isinstance(a, dict) and a.get("id") == appliance_id)]
        if len(appliances) == original_len:
            raise HTTPException(status_code=404, detail="TrueNAS appliance not found")
        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _truenas_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"TrueNAS appliance {appliance_id} deleted.",
                "pushed": pushed}