"""Network-devices routes + multi-instance product CRUD (_instance_crud)."""
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, get_spoke_or_503,
    logger, uuid,
)


def register(app, hub, ctx):
    """Register nw routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_nw = ctx._filter_nw

    def _enforce_tenant_bind(request, cfg, kind):
        """Shared add/edit gate for tenant-scoped device/instance creation. A
        tenant-admin may bind ``cfg`` ONLY to a spoke in their own tenant (via
        ``cfg['spoke_id']``) and the record is bound to that tenant; Global Admin
        is unrestricted (record tenant defaults to the spoke's tenant). Plain
        users are rejected. Mutates ``cfg['tenant_id']`` in place. Raises 403 on
        violation."""
        sess = _session_user(request)
        spoke_id = cfg.get("spoke_id")
        if not _is_admin(sess):
            if not _is_tenant_admin(sess):
                raise HTTPException(status_code=403, detail=f"Tenant-admin access required to add a {kind}")
            if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                raise HTTPException(status_code=403,
                                    detail=f"You can only bind a {kind} to a spoke assigned to your tenant")
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
        elif spoke_id and not cfg.get("tenant_id"):
            cfg["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

    def _get_nw_spoke(hub):
        """The connected nw spoke id, or raise 503 (single-instance resolver)."""
        return get_spoke_or_503(hub, "nw", "Network Devices")

    def _nw_devices_for_spoke(hub, spoke_id: str):
        """The device slice a spoke should receive (bound-to-it, else unbound)."""
        devices = (hub.state.system_state.get("global_config", {})
                   .get("nw_devices", []) or [])
        mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
        if not mine:
            mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
        return mine

    def _project_nw_devices_for_push(devices):
        """Copy device dicts for the spoke payload (creds retained — runtime
        only). Mirrors main.py ``_project_nw_devices``."""
        import copy
        return [copy.deepcopy(d) for d in devices if isinstance(d, dict)]

    async def _nw_push_fleet(hub, spoke_id: str):
        """Re-push the bound device slice to a connected nw spoke."""
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        payload = {"devices": _project_nw_devices_for_push(_nw_devices_for_spoke(hub, spoke_id)),
                   "shared_tenant_id": access.shared_tenant_id() or "",
                   "default_poll_interval":
                       (hub.state.system_state.get("global_config", {}) or {})
                       .get("nw_poll_default_interval")}
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _authz_nw_device(request, device_id, write=False):
        """Authorize + classify a per-device nw op by the device's OWNING
        tenant. Returns ``(dev, scope, spoke_id)``. Raises 404 (unknown id) /
        403 (no access). Mirrors ``_authz_firewall`` (firewall.py:17-46).

        ``scope`` folds the caller's tier with the device's tenancy
        (access.read_scope / write_scope): ``"full"`` (admin, or a device
        DEDICATED to the caller's own tenant → whole device), ``"filtered"``
        (a SHARED device → only the caller's tenant subnet slice via
        ``_filter_nw``), ``"deny"`` → 403. ``spoke_id`` resolves from the
        RECORD's ``spoke_id`` (per-tenant spokes), falling back to
        ``get_nw_spoke_for_tenant`` / ``get_nw_spoke_for_shared`` — never an
        unassigned fallback (no cross-tenant leak). Empty ``spoke_id`` → the
        caller raises 503 (device's spoke not connected)."""
        hub = app.state.hub
        devices = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        dev = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        if not dev:
            raise HTTPException(status_code=404, detail="Network device not found")
        sess = _session_user(request)
        tid = dev.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(status_code=403,
                                detail="You do not have access to this network device")
        # Resolve the spoke from the record's spoke_id (per-tenant); if it's
        # unset/disconnected, fall back to the tenant/shared resolver (which
        # returns only a connected, approved, tenant-bound spoke — or None).
        spoke_id = dev.get("spoke_id") or ""
        if (not spoke_id
                or hub._primary_key(spoke_id) not in hub.active_connections):
            spoke_id = (hub.get_nw_spoke_for_shared()
                        if access.tenant_is_shared(tid)
                        else hub.get_nw_spoke_for_tenant(tid)) or ""
        if spoke_id and hub._primary_key(spoke_id) not in hub.active_connections:
            spoke_id = ""
        return dev, scope, spoke_id

    async def _filter_nw_optional(scope, request, data, endpoint, tenant):
        """Apply the nw subnet filter ONLY when the reader is scoped or
        acting-as. A ``"full"``-scope reader (admin, or a device DEDICATED to
        the caller's own tenant) with no explicit ``?tenant=`` gets the whole
        device — preserves admin/own-tenant behavior. ``"filtered"`` (shared
        device) or an explicit ``?tenant=`` (admin acting-as) applies
        ``_filter_nw`` (shared → the viewer's session-tenant slice; acting-as
        → the named tenant's slice)."""
        if scope == "full" and not tenant:
            return data
        return await _filter_nw(request, data, endpoint, tenant)

    @app.get("/api/nw/devices")
    async def nw_list_devices(request: Request, tenant: str = None):
        """List the nw fleet, tenant-scoped. Admin → the whole fleet (all
        connected nw spokes). Non-admin → own-tenant + shared devices only
        (the shared-tenant-flag invariant); other-tenant / unassigned devices
        are admin-only. The hub config (``nw_devices``, tenant-stamped) is the
        AUTHORITATIVE visibility gate: live spoke rows are intersected with the
        reader's visible config set so a stale/leaky spoke can't surface a
        device the reader can't see (the cross-tenant leak this closes).

        Caches the whole-fleet (admin) fetch and serves it tenant-filtered
        (``nw_cache_get_fleet_filtered``) when no relevant spoke is connected,
        so a spoke outage still seeds the Network Devices table without
        cross-tenant leak. ``?tenant=`` is accepted for signature compat (the
        fleet list is inventory, no IP to subnet-filter on)."""
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        # Authoritative visibility: the hub config is the source of truth for
        # the device list (addresses/creds/tenant_id); the spoke adds live
        # reachability. A row is visible iff its tenant_id is admin / shared /
        # the reader's own (spoke_visible_to_session).
        all_devs = (hub.state.system_state.get("global_config", {}) or {}).get("nw_devices", []) or []
        visible = [d for d in all_devs if isinstance(d, dict)
                   and (is_admin or access.spoke_visible_to_session(sess, d.get("tenant_id", "")))]
        visible_ids = {d.get("id") for d in visible if d.get("id")}

        # Resolve the connected, approved nw spoke(s) to query for live data.
        # Admin → every connected nw spoke (whole fleet per spoke, no tenant
        # filter). Non-admin → the spoke(s) bound to the reader's own tenant(s)
        # + the shared-tenant spoke (shared devices live there); the spoke-side
        # tenant filter returns own+shared from each. No shared tenant → no
        # shared spoke (never the global fallback, which would leak the fleet).
        if is_admin:
            spokes = [s for s in (hub.get_all_spokes_by_type("nw") or [])
                      if s in hub.active_connections
                      and hub.approved_modules.get(s, False)]
            spoke_to_tid = {s: "" for s in spokes}
        else:
            spoke_to_tid = {}
            for t in ((sess or {}).get("user", {}).get("tenants") or []):
                s = hub.get_nw_spoke_for_tenant(t)
                if s:
                    spoke_to_tid[s] = t
            shared_tid = access.shared_tenant_id()
            if shared_tid:
                s = hub.get_nw_spoke_for_shared()
                if s:
                    spoke_to_tid[s] = shared_tid
            spoke_to_tid = {s: t for s, t in spoke_to_tid.items()
                            if s in hub.active_connections
                            and hub.approved_modules.get(s, False)}
            spokes = list(spoke_to_tid)

        if not spokes:
            # No live spoke for the reader's slice → serve the cached fleet,
            # tenant-filtered (the leak fix: never serve the whole global cache
            # to a non-admin). Admin predicate is all-True (whole cache).
            cached = hub.nw_cache_get_fleet_filtered(
                lambda r: is_admin
                or access.spoke_visible_to_session(sess, r.get("tenant_id", "")))
            if cached:
                out = dict((cached.get("devices") or {}))
                out["stale"] = True
                out["fetched_at"] = cached.get("fetched_at")
                out["message"] = (out.get("message") or
                                  "Network Devices spoke offline — showing last-known data")
                return out
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")

        # Fan out NW_LIST_DEVICES (admin: {} = whole fleet per spoke; non-admin:
        # {"tenant": tid} = own+shared from that spoke) + merge rows by id.
        merged, seen = [], set()
        for sid in spokes:
            tid = spoke_to_tid.get(sid, "")
            payload = {"tenant": tid} if tid else {}
            try:
                result = await hub.request_response(sid, "NW_LIST_DEVICES", payload,
                                                    timeout=20.0)
                env = access.unwrap_spoke(result)
                rows = env.get("data") if isinstance(env, dict) else None
                if isinstance(rows, list):
                    for r in rows:
                        if isinstance(r, dict) and r.get("id") and r["id"] not in seen:
                            seen.add(r["id"])
                            merged.append(r)
            except Exception as e:
                logger.warning("nw_list_devices: spoke %s fetch failed: %s", sid, e)

        # Authoritative gate: drop any row not in the reader's visible config
        # set (defense-in-depth against a stale/leaky spoke).
        if visible_ids:
            merged = [r for r in merged if r.get("id") in visible_ids]

        env = {"status": "SUCCESS", "data": merged,
               "message": f"{len(merged)} device(s)"}
        # The global cache holds the WHOLE fleet (last admin fetch) so the
        # offline path serves a complete, filterable snapshot — only update it
        # from a whole-fleet (admin) fetch, never a non-admin subset.
        if is_admin:
            try:
                await hub.nw_cache_set_fleet(env)
            except Exception:
                logger.debug("nw_list_devices: cache set failed", exc_info=True)
        return env

    @app.get("/api/nw/{device_id}/{endpoint}")
    async def nw_get_device_data(request: Request, device_id: str, endpoint: str,
                                 tenant: str = None):
        """Live per-device nw data (info|macs|arp|interfaces|endpoints|vlans),
        tenant-gated. ``_authz_nw_device`` resolves the device record, classifies
        the read scope, and resolves the spoke from the record's ``spoke_id``
        (per-tenant) — 404 unknown, 403 other-tenant/unassigned, 503 spoke down.

        ``endpoint`` selects the device sub-resource → the NW_GET_<X> command.
        Results are subnet-filtered via ``_filter_nw`` ONLY when the reader is
        scoped (shared device → ``"filtered"``) or acting-as (``?tenant=``); a
        ``"full"``-scope reader (admin, or a device dedicated to the caller's
        own tenant) with no explicit tenant gets the whole device (preserves
        admin/own-tenant behavior). MAC/ARP/interfaces carry IPs; info does not.

        Caches the raw per-device endpoint envelope on every live fetch and
        serves it (marked ``stale``, scope-filtered) when the spoke is offline.
        The cache is gated by the same ``_authz_nw_device`` check, so a
        non-admin can't fetch another tenant's device cache."""
        hub = app.state.hub
        command_map = {
            "info":       "NW_GET_DEVICE_INFO",
            "macs":       "NW_GET_MAC_TABLE",
            "arp":        "NW_GET_ARP",
            "interfaces": "NW_GET_INTERFACES",
            "endpoints":  "NW_GET_ENDPOINTS",  # fused ARP+MAC unique IP/MAC list
            "vlans":      "NW_GET_VLANS",       # per-VLAN rollup
        }
        spoke_cmd = command_map.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported by nw module")
        logger.debug("relay GET /api/nw/%s/%s tenant=%s", device_id, endpoint, tenant)
        dev, scope, spoke_id = _authz_nw_device(request, device_id)
        tid = dev.get("tenant_id", "")
        # Defense-in-depth: re-check on the spoke via the tenant filter (the
        # spoke rejects a device whose tenant_id is neither the passed tenant
        # nor the shared tenant — Stage 1).
        relay_payload = {"device_id": device_id}
        if tid:
            relay_payload["tenant"] = tid
        # endpoints/vlans run three sequential SSH gathers (arp+mac+interfaces)
        # on the spoke, so the 5s default relay timeout is far too short — give
        # them room; the single-datum views get a comfortable margin too.
        timeout = 45.0 if endpoint in ("endpoints", "vlans") else 20.0
        if not spoke_id:
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, spoke_cmd, relay_payload,
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_device(device_id, endpoint, data)
            return await _filter_nw_optional(scope, request, data, endpoint, tenant)
        except HTTPException:
            raise
        except Exception as e:
            # A slow/timed-out live fetch shouldn't blank the tab — serve the
            # last-known cached value (marked stale, scope-filtered) if we have
            # one, so a heavy gateway that occasionally overruns still shows data.
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                logger.warning("nw_get_device_data live fetch failed (%s/%s: %s)"
                               " — serving cached", device_id, endpoint, e)
                filtered = await _filter_nw_optional(scope, request, cached, endpoint, tenant)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            logger.exception("nw_get_device_data failed (%s/%s)", device_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/config")
    async def nw_run_config(device_id: str, request: Request):
        """Apply a CLI/REST config snippet to a device (admin-only). Body:
        ``{"commands": ["...", ...]}``. Returns the spoke's applied/errors lists.

        Resolves the spoke from the device record's ``spoke_id`` (per-tenant)
        via ``_authz_nw_device`` rather than the single global resolver, so a
        config push lands on the spoke that owns the device."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        commands = (data or {}).get("commands", []) if isinstance(data, dict) else []
        if not isinstance(commands, list):
            raise HTTPException(status_code=400, detail="commands must be a list")
        dev, _scope, spoke_id = _authz_nw_device(request, device_id, write=True)
        if not spoke_id:
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NW_RUN_CONFIG",
                                                {"device_id": device_id,
                                                 "commands": commands,
                                                 "tenant": dev.get("tenant_id", "")})
            return access.unwrap_spoke(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_run_config failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/poll")
    async def nw_poll_device(device_id: str, request: Request):
        """POLL NOW for one network device (admin-only): run a full
        probe+info+interfaces+arp+mac poll on the spoke, then upsert the device
        + its interfaces into NetBox via ``NETBOX_SYNC_NW_DEVICE``. Returns the
        poll results + a NetBox push summary. Driven by the WebUI "Poll Now"
        button on the Devices table."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            result = await hub.poll_nw_device(device_id)
            # Fold the poll's rich result into the per-device cache so a later
            # page load (spoke offline) still reflects the last probe.
            if isinstance(result, dict):
                await hub.nw_cache_set_poll(device_id, result)
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_poll_device failed (%s)", device_id)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/nw-devices")
    async def get_nw_devices(request: Request):
        hub = app.state.hub
        devices = hub.state.system_state.get("global_config", {}).get("nw_devices", [])
        # Tenant-scope the device list (shared + own visible; other/unassigned
        # admin-only). Object-level IP filtering + the write gate are unchanged.
        sess = _session_user(request)
        if not _is_admin(sess):
            devices = [d for d in devices
                       if access.spoke_visible_to_session(sess, (d or {}).get("tenant_id", ""))]
        return {"nw_devices": devices}

    @app.get("/setup/nw-poll-config")
    async def get_nw_poll_config(request: Request):
        """Module-level nw poll cadence. ``default_poll_interval`` (seconds) is
        the fallback each nw spoke applies to any device that doesn't set its own
        (device-level always wins). null/absent → the spoke's built-in 15m."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"default_poll_interval": gc.get("nw_poll_default_interval")}

    @app.post("/setup/nw-poll-config")
    async def set_nw_poll_config(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        raw = data.get("default_poll_interval")
        try:
            val = None if raw in (None, "", "null") else int(raw)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="default_poll_interval must be an integer or null")
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_poll_default_interval"] = val
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        # Re-push every connected nw spoke so the new module default takes effect.
        pushed = 0
        for sid in (hub.get_all_spokes_by_type("nw") or []):
            if await _nw_push_fleet(hub, sid):
                pushed += 1
        return {"status": "ok", "default_poll_interval": val, "pushed": pushed}

    @app.get("/setup/nw-netbox-import")
    async def get_nw_netbox_import(request: Request):
        """NetBox→NW import config (NetBox = fleet source of truth): which NetBox
        device roles get imported into the nw fleet, object_type mapping, cadence."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"nw_netbox_import": gc.get("nw_netbox_import", {}) or {}}

    @app.post("/setup/nw-netbox-import")
    async def set_nw_netbox_import(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        cfg = data.get("config", data) or {}
        roles = cfg.get("roles")
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        clean = {
            "enabled": bool(cfg.get("enabled", False)),
            "roles": [str(r).strip() for r in (roles or []) if str(r).strip()],
            "object_type_map": dict(cfg.get("object_type_map") or {}),
            "default_object_type": str(cfg.get("default_object_type") or "gateway"),
            "interval": int(cfg.get("interval") or 900),
            "spoke_id": str(cfg.get("spoke_id") or "").strip(),
        }
        gc = hub.state.system_state.get("global_config", {})
        gc["nw_netbox_import"] = clean
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "nw_netbox_import": clean}

    @app.post("/setup/nw-netbox-import/run")
    async def run_nw_netbox_import(request: Request):
        """On-demand 'Import now' — run one NetBox→NW import cycle."""
        hub = app.state.hub
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            return await hub.run_nw_netbox_import_all()
        except Exception as e:
            logger.exception("run_nw_netbox_import failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/nw-devices")
    async def add_nw_device(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_dev = data.get("device", {})
            if not new_dev.get("name") or not new_dev.get("object_type"):
                raise HTTPException(status_code=400, detail="Missing device name or object_type")
            if new_dev.get("object_type") not in ("aos_switch", "cx_switch",
                                                   "ex_switch", "gateway"):
                raise HTTPException(status_code=400, detail="Invalid object_type")
            _enforce_tenant_bind(request, new_dev, "network device")
            if "id" not in new_dev:
                new_dev["id"] = str(uuid.uuid4())
            # A manually-added device is nw-owned (not a NetBox import) — tag it so
            # the NetBox→NW import loop never prunes it as a stale netbox record.
            new_dev.setdefault("source", "manual")

            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            devices.append(new_dev)
            global_config["nw_devices"] = devices
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # New device → push the bound slice so the spoke knows about it now.
            spoke_id = new_dev.get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False

            # NetBox is the fleet source of truth: write a manually-added device
            # back to NetBox (dcim.device) so it stays complete. Best-effort — a
            # NetBox miss must not fail the add. Skipped for netbox-imported rows.
            netbox_pushed = False
            if new_dev.get("source") != "netbox":
                try:
                    push, _errs, _slug = await hub.push_nw_device_inventory(new_dev, {}, [])
                    netbox_pushed = str((push or {}).get("status", "")).upper() in ("SUCCESS", "PARTIAL")
                except Exception as e:
                    logger.debug("add_nw_device NetBox write-back skipped: %s", e)
            return {"status": "ok", "device": new_dev, "pushed": pushed,
                    "netbox_pushed": netbox_pushed}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("add_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/nw-devices/{device_id}")
    async def update_nw_device(device_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            idx = next((i for i, d in enumerate(devices)
                        if isinstance(d, dict) and d.get("id") == device_id), None)
            if idx is None:
                raise HTTPException(status_code=404, detail="Network device not found")

            devices[idx].update(update_data)
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            spoke_id = devices[idx].get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
            if pushed:
                return {"status": "ok",
                        "message": "Network device updated and pushed to spoke.",
                        "pushed": True}
            return {"status": "partial_success",
                    "message": "Configuration saved, but associated spoke is not connected.",
                    "pushed": False}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("update_nw_device failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/nw-devices/{device_id}")
    async def delete_nw_device(device_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        devices = global_config.get("nw_devices", [])
        victim = next((d for d in devices if isinstance(d, dict) and d.get("id") == device_id), None)
        original_len = len(devices)
        devices[:] = [d for d in devices if not (isinstance(d, dict) and d.get("id") == device_id)]
        if len(devices) == original_len:
            raise HTTPException(status_code=404, detail="Network device not found")

        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Re-push so the spoke drops the deleted device from its fleet.
        spoke_id = victim.get("spoke_id") if isinstance(victim, dict) else None
        pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
        return {"status": "ok", "message": f"Network device {device_id} deleted.",
                "pushed": pushed}

    # ─── Multi-instance product connections (mirror firewalls) ────────────────
    # NAC / IPAM / LDAP / DNS / DHCP each manage a LIST of connection instances
    # (one per bound spoke) instead of a single config object, so the Setup
    # page can show a table with Add / Edit / Delete like Firewalls.

    async def _push_instance_config(hub, instance: dict, payload_fn):
        """Send UPDATE_CONFIG to the instance's bound spoke, if connected.
        `payload_fn(instance)` returns the spoke-side config dict (or None for
        save-only products like DNS/DHCP). Returns True when a message was sent."""
        if not payload_fn:
            return False
        spoke_id = instance.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return False
        payload = payload_fn(instance)
        if not payload:
            return False
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    def _instance_crud(route_prefix: str, storage_key: str, payload_fn=None,
                       legacy_key: str = None, legacy_to_instance=None):
        """Register GET/POST/PUT/DELETE /setup/<route_prefix>[/id] for one
        multi-instance product, mirroring the firewalls CRUD. Each instance is
        a dict with an `id` and `spoke_id`; on add/update the config is pushed
        to the bound spoke when `payload_fn` is provided and the spoke is up.

        ``legacy_key``/``legacy_to_instance`` perform a one-shot migration of a
        pre-multi-instance single config (e.g. global_config.cppm / .netbox)
        into the instance list so deployments that configured CPPM/NetBox
        before the refactor still see their server on Setup → Security/NAC /
        IPAM. The migrated entry is deduped by host/url and persisted so it
        becomes a normal editable instance."""
        hub = app.state.hub
        op = route_prefix.replace("-", "_")

        @app.get(f"/setup/{route_prefix}", operation_id=f"list_{op}")
        async def list_instances(request: Request):
            """List instances for this product (NAC/IPAM/Directory); folds in any legacy single-instance config."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = list(global_config.get(storage_key, []))
            if legacy_key and legacy_to_instance:
                legacy = global_config.get(legacy_key)
                if isinstance(legacy, dict) and legacy:
                    inst = legacy_to_instance(legacy)
                    ident = inst.get("host") or inst.get("url") or inst.get("server_url")
                    already = any(
                        (inst.get("host") and i.get("host") == inst.get("host")) or
                        (inst.get("url") and i.get("url") == inst.get("url"))
                        for i in instances if isinstance(i, dict)
                    )
                    if ident and not already:
                        instances.append(inst)
                        global_config[storage_key] = instances
                        # Clear the legacy single-config so deleting the migrated
                        # instance doesn't re-migrate it on the next page load.
                        global_config[legacy_key] = {}
                        hub.state.system_state["global_config"] = global_config
                        hub.state._mark_dirty()
            # Tenant-scope the LIST: a non-admin sees only instances in the shared
            # tenant or their own tenant(s); other-tenant / unassigned instances
            # are admin-only. Object-level filtering + the add/write gates are
            # separate. Admins see all.
            sess = _session_user(request)
            if not _is_admin(sess):
                instances = [i for i in instances
                             if isinstance(i, dict) and access.spoke_visible_to_session(sess, i.get("tenant_id", ""))]
            return {"instances": instances}

        @app.post(f"/setup/{route_prefix}", operation_id=f"add_{op}")
        async def add_instance(request: Request):
            """Add an instance and push its config to the bound spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                new_inst = data.get("instance", {})
                if not new_inst.get("name"):
                    raise HTTPException(status_code=400, detail="Missing instance name")
                _enforce_tenant_bind(request, new_inst, route_prefix.split("-")[0])
                if "id" not in new_inst:
                    new_inst["id"] = str(uuid.uuid4())
                global_config = hub.state.system_state.get("global_config", {})
                instances = global_config.get(storage_key, [])
                instances.append(new_inst)
                global_config[storage_key] = instances
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                pushed = await _push_instance_config(hub, new_inst, payload_fn)
                status = "ok" if pushed else "partial_success"
                msg = "Instance added and pushed to spoke." if pushed else "Instance added; spoke not connected."
                return {"status": status, "message": msg, "pushed": pushed, "instance": new_inst}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("add_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.put(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"update_{op}")
        async def update_instance(instance_id: str, request: Request):
            """Update an instance and push to its spoke (partial_success + pushed=False when the spoke is down)."""
            try:
                data = await request.json()
                update_data = data.get("config", {})
                global_config = hub.state.system_state.get("global_config", {})
                instances = global_config.get(storage_key, [])
                idx = next((i for i, x in enumerate(instances) if x.get("id") == instance_id), None)
                if idx is None:
                    raise HTTPException(status_code=404, detail="Instance not found")
                instances[idx].update(update_data)
                hub.state.system_state["global_config"] = global_config
                hub.state._mark_dirty()
                pushed = await _push_instance_config(hub, instances[idx], payload_fn)
                if pushed:
                    return {"status": "ok", "message": "Instance updated and pushed to spoke.", "pushed": True}
                return {"status": "partial_success", "message": "Instance saved; associated spoke not connected.", "pushed": False}
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("update_instance failed")
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete(f"/setup/{route_prefix}/{{instance_id}}", operation_id=f"delete_{op}")
        async def delete_instance(instance_id: str):
            """Delete an instance; the spoke keeps its last config until re-pushed."""
            global_config = hub.state.system_state.get("global_config", {})
            instances = global_config.get(storage_key, [])
            before = len(instances)
            instances[:] = [x for x in instances if x.get("id") != instance_id]
            if len(instances) == before:
                raise HTTPException(status_code=404, detail="Instance not found")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()
            return {"status": "ok", "message": f"Instance {instance_id} deleted."}

    _instance_crud(
        "nac-instances", "nac_instances",
        lambda inst: {
            "host": inst.get("host"),
            "client_id": inst.get("client_id"),
            "client_secret": inst.get("client_secret"),
            "user": inst.get("user"),
            "password": inst.get("password"),
        },
        legacy_key="cppm",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": c.get("host") or "ClearPass",
            "spoke_id": "",
            "host": c.get("host"),
            "client_id": c.get("client_id"),
            "client_secret": c.get("client_secret"),
            "user": c.get("user"),
            "password": c.get("password"),
        },
    )
    _instance_crud(
        "ipam-instances", "ipam_instances",
        lambda inst: {"netbox_url": inst.get("url"), "api_token": inst.get("api_token"), "netbox_verify_ssl": inst.get("verify_ssl")},
        legacy_key="netbox",
        legacy_to_instance=lambda c: {
            "id": str(uuid.uuid4()),
            "name": "NetBox",
            "spoke_id": "",
            "url": c.get("url") or c.get("netbox_url"),
            "api_token": c.get("api_token") or c.get("token"),
        },
    )

    @app.post("/setup/ipam/apply-schema", operation_id="ipam_apply_schema")
    async def ipam_apply_schema():
        """Apply the Lab Manager custom-field schema to the connected NetBox.

        Backs the "Apply schema changes" button on the Setup/IPAM NetBox
        instance modal. Sends NETBOX_PROVISION_CUSTOM_FIELDS to the connected
        ipam spoke, which runs the engine's idempotent _ensure_custom_fields
        (force=True) over the shared CUSTOM_FIELDS_SPEC — the same spec
        install.sh provisions on a fresh install, so a manual apply and a
        reinstall produce identical schemas. Re-runnable: never errors when the
        fields are already present (the engine get-or-creates + verifies each
        attachment). Returns the spoke's report
        (status/total/present/created/attached/already_attached/warnings).
        """
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "ipam", "NetBox")
        try:
            # NETBOX_PROVISION_CUSTOM_FIELDS runs _ensure_custom_fields(force=True)
            # over the full CUSTOM_FIELDS_SPEC — get-or-creating each field then
            # verifying/attaching content_types. That is many NetBox API calls
            # (17+ fields × create+attach) and routinely exceeds the 5s default
            # request_response timeout, surfacing as "Timed out waiting for spoke
            # response". Give it a generous window; the UI fires-and-forgets with
            # a "started" toast and shows "completed" when this resolves.
            result = await hub.request_response(spoke_id,
                                                "NETBOX_PROVISION_CUSTOM_FIELDS", {},
                                                timeout=120.0)
            data = _unwrap_spoke(result)
            if data.get("status") not in ("SUCCESS", "PARTIAL"):
                raise HTTPException(status_code=502,
                                    detail=data.get("message", "NetBox provisioning error"))
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ipam_apply_schema failed")
            raise HTTPException(status_code=500, detail=str(e))
    _instance_crud(
        "ldap-instances", "ldap_instances",
        lambda inst: {
            "LDAP_SERVER_URL": inst.get("server_url"),
            "LDAP_BASE_DN": inst.get("base_dn"),
            "LDAP_ADMIN_DN": inst.get("admin_dn"),
            "LDAP_ADMIN_PW": inst.get("admin_pw"),
        },
    )
    _instance_crud("dns-instances", "dns_instances", None)
    _instance_crud("dhcp-instances", "dhcp_instances", None)
