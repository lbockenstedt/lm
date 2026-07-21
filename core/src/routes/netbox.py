"""NetBox (IPAM) config + sites/racks/devices/prefixes/IPs routes."""
import os
import secrets
from api import (
    HTTPException, Request, _cache_entry, _fetch_module, _hub_msg,
    _refresh_module_all_tenants, _unwrap_netbox,
    get_netbox_spoke, get_spoke_or_503, get_tenant_scoping, logger,
)


def register(app, hub, ctx):
    """Register netbox routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    _filter_session = ctx._filter_session
    _trigger_endpoint_sync_after_ipam_edit = ctx._trigger_endpoint_sync_after_ipam_edit

    async def _verify_owns(request, module_key, obj_id, id_field="id"):
        """Cross-tenant guard for NetBox path-ID mutation routes (DELETE/PUT).

        A non-admin ipam user may only mutate objects that exist in THEIR
        tenant's NetBox cache (or live list), so enumerating another tenant's
        sequential integer IDs (device_id/prefix_id/ip_id) is fail-closed
        rather than a cross-tenant destroy/modify. Admin bypasses (returns
        None). Returns the caller's tenant_id on success; raises 401/403 on
        failure. The cache is the fast path; a stale/empty cache (e.g. after
        the 300s TTL) is refreshed via the canonical ``_fetch_module`` GET +
        re-checked, so a legit delete isn't false-denied. Spoke-down → 503
        (can't verify ownership without the live list)."""
        sess = _session_user(request)
        if sess and _is_admin(sess):
            return None
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        tid = _resolve_tenant(request, None) or (sess.get("user", {}) or {}).get("tenant_id")
        if not tid:
            raise HTTPException(status_code=403, detail="No tenant context for this user")
        sid = str(obj_id)

        def _in(items):
            return any(isinstance(it, dict) and str(it.get(id_field)) == sid
                       for it in (items or []))

        cached = _cache_entry(tid, module_key)
        if cached and _in(cached.get("data")):
            return tid
        # Stale/empty cache → live-refresh the tenant's list and re-check.
        try:
            await _fetch_module(hub, tid, module_key)
        except Exception as e:  # noqa: BLE001
            logger.warning("netbox ownership refresh [%s][%s] %s failed: %s",
                           tid, module_key, sid, e)
        cached = _cache_entry(tid, module_key)
        if cached and _in(cached.get("data")):
            return tid
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
        body.tenant verbatim. Returns the slug to send to the spoke."""
        requested_slug = (str(data.get("tenant") or "").strip()) or None
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if _is_admin(sess):
            return requested_slug
        if requested_slug is None:
            return None  # unassigned create is allowed; just can't target another tenant
        user = sess.get("user", {}) or {}
        allowed_ids = user.get("tenants") or []
        if not allowed_ids and user.get("tenant_id"):
            allowed_ids = [user.get("tenant_id")]
        allowed = set()
        for tid in allowed_ids:
            s = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug")
            if s:
                allowed.add(s)
        if requested_slug not in allowed:
            raise HTTPException(status_code=403,
                                detail="Not authorized to create into that tenant")
        return requested_slug


    async def _netbox_write(request, cmd, refresh_keys, *, log_name,
                            id_field=None, obj_id=None, verify_key=None,
                            tenant_mode="always", sync_body=None, timeout=None):
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
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        if verify_key:
            await _verify_owns(request, verify_key, obj_id)
        try:
            if tenant_mode is None:
                data = {id_field: obj_id}
            else:
                data = await request.json()
                if id_field is not None:
                    data[id_field] = obj_id
                if tenant_mode == "always" or "tenant" in data:
                    data["tenant"] = _enforce_body_tenant(request, data)
            kw = {"timeout": timeout} if timeout else {}
            result = await hub.request_response(spoke_id, cmd, data, **kw)
            for key in refresh_keys:
                _refresh_module_all_tenants(hub, key)
            if sync_body == "data":
                _trigger_endpoint_sync_after_ipam_edit(hub, request, data)
            elif sync_body == "null":
                _trigger_endpoint_sync_after_ipam_edit(hub, request, None)
            return _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("%s failed", log_name)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/netbox-config")
    async def get_netbox_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("netbox", {})
        return {"config": config}

    @app.post("/setup/netbox-config")
    async def update_netbox_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["netbox"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
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
        """Cache→spoke→offline GET for the NetBox list handlers (racks/devices/
        prefixes/ips). Non-admin cache hit (when no slice param or tenant is
        selected) → cached data; spoke down → offline cache fallback; otherwise a
        live spoke round-trip with the resolved tenant slug. ``slice_query`` is the
        dict of non-tenant slice params (site/rack/prefix/device); ``subnet_fields``
        is None for raw data or a list like ``["prefix"]`` to apply the subnet
        filter to both cached and live data. Handlers that can't share this
        helper (get_firewall_data, get_cppm_devices/sessions, get_pxmx_vms)
        inline the same cache→spoke→offline shape with a
        ``# see _netbox_list_get (variant: …)`` cross-ref."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s %s", request.method, request.url.path, tenant, slice_query)
        sess = _session_user(request)
        cache_bypass = bool(tenant) or any(v for v in slice_query.values())
        if not cache_bypass and sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            if tid:
                cached = _cache_entry(tid, cache_key)
                if cached:
                    data = cached["data"]
                    if subnet_fields:
                        return await _filter_session(request, data, "netbox", subnet_fields)
                    return data
        # Warm-cache scope key: the resolved tenant slug (admins acting all-
        # tenants → "_all_"), so cached data is only ever served back to the same
        # scope (tenant isolation preserved). Slice params vary the key so a
        # site/rack-filtered read doesn't serve an unfiltered snapshot.
        scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
        slug = scoping["netbox_tenant_slug"] or "_all_"
        slice_sig = ",".join(f"{k}={v}" for k, v in sorted(slice_query.items()) if v)
        warm_key = f"{slug}|{slice_sig}" if slice_sig else slug

        async def _warm_or_raise(exc):
            cached = hub.warm_get(f"nb_{cache_key}", warm_key)
            if cached is not None:
                out = cached
                if subnet_fields:
                    out = await _filter_session(request, cached, "netbox", subnet_fields)
                if isinstance(out, dict):
                    out = dict(out); out["stale"] = True
                return out
            raise exc

        spoke_id = get_netbox_spoke(hub)
        if not spoke_id:
            if sess:
                tid = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tid, cache_key) if tid else None
                if cached:
                    data = cached["data"]
                    if subnet_fields:
                        return await _filter_session(request, data, "netbox", subnet_fields)
                    return data
            return await _warm_or_raise(
                HTTPException(status_code=503, detail="NetBox spoke not connected"))
        try:
            payload = dict(slice_query)
            payload["tenant"] = scoping["netbox_tenant_slug"] or None
            # 20s (was the 5s relay default) — a large NetBox can be slow; the
            # warm cache covers an overrun so the page still renders.
            result = await hub.request_response(spoke_id, cmd, payload, timeout=20.0)
            data = _unwrap_netbox(result)
            await hub.warm_set(f"nb_{cache_key}", warm_key, data)  # cache raw
            if subnet_fields:
                return await _filter_session(request, data, "netbox", subnet_fields)
            return data
        except HTTPException as e:
            return await _warm_or_raise(e)
        except Exception as e:
            logger.exception(route_name + " failed")
            return await _warm_or_raise(HTTPException(status_code=500, detail=str(e)))

    @app.get("/api/netbox/health")
    async def netbox_health():
        """NetBox spoke reachability + API-token validity probe (10s timeout)."""
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
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
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        result = await hub.request_response(spoke_id, "NETBOX_GET_TENANTS", {}, timeout=15.0)
        return _unwrap_netbox(result)

    @app.post("/api/netbox/migrate-tenant")
    async def netbox_migrate_tenant(request: Request):
        """Migrate Data to new Tenant — reassign every NetBox object owned by the
        SOURCE tenant to the TARGET tenant, then (by default) delete the source.
        ADMIN-ONLY: this is a destructive cross-tenant operation. Body:
        ``{source, target, delete_source=true, create_target=false}`` where
        source/target are a tenant id, slug, or name."""
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        body = await request.json()
        source = body.get("source")
        target = body.get("target")
        if not source or not target:
            raise HTTPException(status_code=400, detail="source and target are required")
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        logger.info("netbox migrate-tenant: %s -> %s (delete_source=%s) by %s",
                    source, target, body.get("delete_source", True),
                    (sess.get("user", {}) or {}).get("username"))
        result = await hub.request_response(
            spoke_id, "NETBOX_MIGRATE_TENANT",
            {"source": source, "target": target,
             "delete_source": body.get("delete_source", True),
             "create_target": body.get("create_target", False)},
            timeout=300.0)
        out = _unwrap_netbox(result)
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
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
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
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        logger.info("netbox seed-catalog by %s",
                    (sess.get("user", {}) or {}).get("username"))
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

    _RACK_IMPORT_DIR = os.environ.get("LM_RACK_IMPORT_DIR", "/var/lib/lm/imports")
    _RACK_IMPORT_MAX = 64 * 1024 * 1024  # 64 MB xlsx cap

    def _rack_imports():
        """In-memory upload_id → {path, token, filename, ts}. Lost on hub
        restart (imports are short-lived; the user re-uploads)."""
        if not getattr(hub, "rack_imports", None):
            hub.rack_imports = {}
        return hub.rack_imports

    def _rack_import_download_url(request, upload_id):
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
        import uuid as _uuid, secrets as _secrets, time as _time
        from pathlib import Path
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        ctype = (request.headers.get("content-type") or "").lower()
        data = b""
        filename = ""
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
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not read upload: {e}")
        if not data:
            raise HTTPException(status_code=400, detail="empty upload")
        if len(data) > _RACK_IMPORT_MAX:
            raise HTTPException(status_code=413, detail="upload exceeds 64 MB limit")
        if not filename.lower().endswith(".xlsx"):
            raise HTTPException(status_code=400, detail="file must be .xlsx")

        upload_id = _uuid.uuid4().hex
        token = _secrets.token_urlsafe(32)
        try:
            Path(_RACK_IMPORT_DIR).mkdir(parents=True, exist_ok=True)
            path = os.path.join(_RACK_IMPORT_DIR, f"{upload_id}.xlsx")
            with open(path, "wb") as f:
                f.write(data)
        except Exception as e:  # noqa: BLE001
            logger.exception("netbox rack import: failed to save upload")
            raise HTTPException(status_code=500, detail=f"could not save upload: {e}")
        _rack_imports()[upload_id] = {"path": path, "token": token,
                                      "filename": filename, "ts": _time.time()}
        logger.info("netbox rack import-xlsx by %s (upload_id=%s, %d bytes)",
                    (sess.get("user", {}) or {}).get("username"), upload_id, len(data))
        try:
            download_url = _rack_import_download_url(request, upload_id)
            detect = await hub.request_response(spoke_id, "NETBOX_IMPORT_RACK_DETECT",
                                                {"download_url": download_url, "token": token},
                                                timeout=180.0)
            detect = _unwrap_netbox(detect)
            if detect.get("status") != "SUCCESS":
                # parse failed on the spoke (e.g. openpyxl missing) → clean up.
                _rack_imports().pop(upload_id, None)
                try: os.remove(path)
                except OSError: pass
                raise HTTPException(status_code=502, detail=detect.get("message") or "detect failed")
            # form-options for the mapping UI + defaults (parallel picklist read).
            try:
                fo = await hub.request_response(spoke_id, "NETBOX_GET_DEVICE_FORM_OPTIONS",
                                                {}, timeout=20.0)
                fo = _unwrap_netbox(fo)
                form_options = fo if fo.get("status") == "SUCCESS" else {}
            except Exception:  # noqa: BLE001
                form_options = {}
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
        sess = _session_user(request)
        if not (sess and _is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")
        upload_id = str(body.get("upload_id") or "")
        rec = _rack_imports().get(upload_id)
        if not rec or not os.path.isfile(rec["path"]):
            raise HTTPException(status_code=404, detail="upload not found (expired or already committed)")
        sheets = body.get("sheets") or []
        if not sheets:
            raise HTTPException(status_code=400, detail="no sheets selected")
        dry_run = bool(body.get("dry_run"))
        logger.info("netbox rack import-commit by %s (upload_id=%s, %d sheets, dry_run=%s)",
                    (sess.get("user", {}) or {}).get("username"), upload_id, len(sheets), dry_run)
        try:
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
        from fastapi.responses import FileResponse
        rec = _rack_imports().get(upload_id)
        if not rec:
            raise HTTPException(status_code=404, detail="upload not found")
        auth = request.headers.get("authorization") or ""
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
        token = token or request.query_params.get("token") or ""
        if not token or not secrets.compare_digest(token, rec["token"]):
            raise HTTPException(status_code=403, detail="invalid download token")
        if not os.path.isfile(rec["path"]):
            raise HTTPException(status_code=404, detail="upload file missing on disk")
        return FileResponse(rec["path"], media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            filename=rec.get("filename") or "rack.xlsx")

    @app.get("/api/netbox/racks")
    async def netbox_get_racks(request: Request, site: str = None, tenant: str = None):
        """List NetBox racks, optionally scoped by site; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_racks", "NETBOX_GET_RACKS",
                                      {"site": site}, None, "netbox_get_racks")

    @app.post("/api/netbox/racks")
    async def netbox_add_rack(request: Request):
        """Create a NetBox rack; invalidates the racks cache on success."""
        return await _netbox_write(request, "NETBOX_ADD_RACK", ["netbox_racks"],
                                   log_name="netbox_add_rack")

    @app.put("/api/netbox/racks/{rack_id}")
    async def netbox_update_rack(rack_id: int, request: Request):
        """Update a NetBox rack; invalidates the racks cache on success."""
        return await _netbox_write(request, "NETBOX_UPDATE_RACK", ["netbox_racks"],
                                   log_name="netbox_update_rack",
                                   id_field="rack_id", obj_id=rack_id,
                                   verify_key="netbox_racks",
                                   tenant_mode="if_present")

    @app.delete("/api/netbox/racks/{rack_id}")
    async def netbox_delete_rack(rack_id: int, request: Request):
        """Delete a NetBox rack; invalidates the racks cache on success."""
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
        await _verify_owns(request, "netbox_racks", rack_id, id_field="id")
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        result = await hub.request_response(
            spoke_id, "NETBOX_GET_RACK_ELEVATION", {"rack_id": rack_id}, timeout=30.0)
        return _unwrap_netbox(result)

    @app.get("/api/netbox/devices")
    async def netbox_get_devices(request: Request, site: str = None, rack: str = None, tenant: str = None):
        """List NetBox devices, optionally scoped by site/rack; non-admins get the
        tenant cache, admins/multi-tenant switches go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_devices", "NETBOX_GET_DEVICES",
                                      {"site": site, "rack": rack}, None, "netbox_get_devices")

    @app.post("/api/netbox/devices")
    async def netbox_add_device(request: Request):
        """Create a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        return await _netbox_write(request, "NETBOX_ADD_DEVICE", ["netbox_devices"],
                                   log_name="netbox_add_device", sync_body="data")

    @app.get("/api/netbox/claim-device/options")
    async def netbox_claim_device_options(request: Request):
        """Picklists (sites, device types, device roles, tenants) for the
        Claim-an-unknown-device form. Non-admins see only their own allowed
        tenants in the tenant list; admins see all."""
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_DEVICE_FORM_OPTIONS", {})
            out = _unwrap_netbox(result)
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
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")
        requested_slug = (str(data.get("tenant") or "").strip()) or None

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
        try:
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_DEVICE", payload)
            result = _unwrap_netbox(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("netbox_claim_device failed")
            raise HTTPException(status_code=500, detail=str(e))
        if isinstance(result, dict) and result.get("status") == "SUCCESS":
            # Refresh (drop + background re-fetch), not invalidate-only, so a
            # non-admin viewer sees the claimed device appear / re-attribute
            # immediately. claim-device also re-tags the CPPM endpoint, so
            # refresh cppm_devices too (the endpoint sync below is best-effort
            # and async; this guarantees the cache is dropped now).
            _refresh_module_all_tenants(hub, "netbox_devices")
            _refresh_module_all_tenants(hub, "cppm_devices")
            _trigger_endpoint_sync_after_ipam_edit(hub, request, {"tenant": requested_slug} if requested_slug else None)
        return result

    @app.delete("/api/netbox/devices/{device_id}")
    async def netbox_delete_device(device_id: int, request: Request):
        """Delete a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        return await _netbox_write(request, "NETBOX_DELETE_DEVICE", ["netbox_devices"],
                                   log_name="netbox_delete_device",
                                   id_field="device_id", obj_id=device_id,
                                   verify_key="netbox_devices", tenant_mode=None,
                                   sync_body="null")

    @app.put("/api/netbox/devices/{device_id}")
    async def netbox_update_device(device_id: int, request: Request):
        """Update a NetBox device; invalidates the device cache and triggers an endpoint sync."""
        return await _netbox_write(request, "NETBOX_UPDATE_DEVICE", ["netbox_devices"],
                                   log_name="netbox_update_device",
                                   id_field="device_id", obj_id=device_id,
                                   verify_key="netbox_devices",
                                   tenant_mode="if_present", sync_body="data")

    @app.get("/api/netbox/prefixes")
    async def netbox_get_prefixes(request: Request, site: str = None, tenant: str = None):
        """List NetBox prefixes (subnet-filtered), optionally scoped by site;
        non-admins get the tenant cache, admins go live (see _netbox_list_get)."""
        return await _netbox_list_get(request, tenant, "netbox_prefixes", "NETBOX_GET_PREFIXES",
                                      {"site": site}, ["prefix"], "netbox_get_prefixes")

    @app.post("/api/netbox/prefixes")
    async def netbox_allocate_prefix(request: Request):
        """Allocate a NetBox prefix; invalidates the prefix + IP caches (30s timeout)."""
        return await _netbox_write(request, "NETBOX_ALLOCATE_PREFIX",
                                   ["netbox_prefixes", "netbox_ips"],
                                   log_name="netbox_allocate_prefix", timeout=30.0)

    @app.put("/api/netbox/prefixes/{prefix_id}")
    async def netbox_update_prefix(prefix_id: int, request: Request):
        """Update a NetBox prefix; invalidates the prefix cache on success."""
        return await _netbox_write(request, "NETBOX_UPDATE_PREFIX", ["netbox_prefixes"],
                                   log_name="netbox_update_prefix",
                                   id_field="prefix_id", obj_id=prefix_id,
                                   verify_key="netbox_prefixes",
                                   tenant_mode="if_present")

    @app.delete("/api/netbox/prefixes/{prefix_id}")
    async def netbox_delete_prefix(prefix_id: int, request: Request):
        """Delete a NetBox prefix; invalidates the prefix + IP caches on success."""
        return await _netbox_write(request, "NETBOX_DELETE_PREFIX",
                                   ["netbox_prefixes", "netbox_ips"],
                                   log_name="netbox_delete_prefix",
                                   id_field="prefix_id", obj_id=prefix_id,
                                   verify_key="netbox_prefixes", tenant_mode=None)

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
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        if not near:
            raise HTTPException(status_code=400, detail="'near' CIDR is required")
        try:
            payload: dict = {"near": near, "count": int(count)}
            if prefix_length is not None:
                prefix_length = int(prefix_length)
                if not 22 <= prefix_length <= 30:
                    raise HTTPException(status_code=400,
                                        detail="subnet size must be between /22 and /30 (up to a /22)")
                payload["prefix_length"] = prefix_length
            elif hosts is not None:
                payload["hosts"] = int(hosts)
            if exact:
                payload["exact"] = exact
            result = await hub.request_response(spoke_id, "NETBOX_FIND_AVAILABLE_PREFIXES",
                                                 payload, timeout=30.0)
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
        reassigns an existing unassigned prefix or creates a new one."""
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        try:
            body = await request.json()
            prefix = body.get("prefix")
            if not prefix:
                raise HTTPException(status_code=400, detail="'prefix' is required")
            if _is_admin(sess):
                tenant = body.get("tenant")
            else:
                tenant = get_tenant_scoping(hub, _resolve_tenant(request, None))["netbox_tenant_slug"] or None
            payload = {
                "prefix": prefix,
                "tenant": tenant,
                "description": body.get("description", ""),
                "site": body.get("site"),
                "status": body.get("status", "active"),
            }
            result = await hub.request_response(spoke_id, "NETBOX_CLAIM_PREFIX", payload, timeout=30.0)
            data = _unwrap_netbox(result)
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                _refresh_module_all_tenants(hub, "netbox_prefixes")
                _refresh_module_all_tenants(hub, "netbox_ips")
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
        return await _netbox_list_get(request, tenant, "netbox_ips", "NETBOX_GET_IPS",
                                      {"prefix": prefix, "device": device}, ["address"], "netbox_get_ips")

    @app.post("/api/netbox/ips")
    async def netbox_allocate_ip(request: Request):
        """Allocate a NetBox IP address; invalidates the IP cache and triggers an endpoint sync (30s timeout)."""
        return await _netbox_write(request, "NETBOX_ALLOCATE_IP", ["netbox_ips"],
                                   log_name="netbox_allocate_ip",
                                   sync_body="data", timeout=30.0)

    @app.delete("/api/netbox/ips/{ip_id}")
    async def netbox_release_ip(ip_id: int, request: Request):
        """Release a NetBox IP back to the pool; invalidates the IP cache and triggers an endpoint sync."""
        return await _netbox_write(request, "NETBOX_RELEASE_IP", ["netbox_ips"],
                                   log_name="netbox_release_ip",
                                   id_field="ip_id", obj_id=ip_id,
                                   verify_key="netbox_ips", tenant_mode=None,
                                   sync_body="null")

    @app.put("/api/netbox/ips/{ip_id}")
    async def netbox_update_ip(ip_id: int, request: Request):
        """Update a NetBox IP address; invalidates the IP cache and triggers an endpoint sync."""
        return await _netbox_write(request, "NETBOX_UPDATE_IP_ADDR", ["netbox_ips"],
                                   log_name="netbox_update_ip",
                                   id_field="ip_id", obj_id=ip_id,
                                   verify_key="netbox_ips",
                                   tenant_mode="if_present", sync_body="data")

    # ── Update trigger + module install (/setup/update, /setup/modules/*) ─────
