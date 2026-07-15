"""Network-devices routes + multi-instance product CRUD (_instance_crud)."""
from api import (
    HTTPException, Request, _hub_msg, _unwrap_spoke, access, logger, uuid,
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
        spoke_id = hub.get_spoke_by_type("nw")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="Network Devices spoke not connected")
        return spoke_id

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
        if not spoke_id or spoke_id not in hub.active_connections:
            return False
        payload = {"devices": _project_nw_devices_for_push(_nw_devices_for_spoke(hub, spoke_id))}
        msg = _hub_msg(spoke_id, "UPDATE_CONFIG", payload)
        await hub.send_to_spoke(msg)
        return True

    @app.get("/api/nw/devices")
    async def nw_list_devices(request: Request, tenant: str = None):
        """List the nw fleet from the spoke (admin) — unfiltered (devices are
        managed infra shown to all). Tenant scoping has no IP to filter on.

        Caches the last-known fleet (``nw_cache``) on every live fetch and
        serves it (marked ``stale``) when the nw spoke is offline, so a hub
        restart / spoke outage still seeds the Network Devices table."""
        logger.debug("relay GET /api/nw/devices tenant=%s", tenant)
        hub = app.state.hub
        # Gated by the ``nw`` module right in the middleware; the fleet list is
        # managed-infra inventory (no per-device IPs) shown to nw-right users.
        spoke_id = hub.get_spoke_by_type("nw")
        if not spoke_id:
            cached = hub.nw_cache_get_fleet()
            if cached:
                out = dict(cached.get("devices") or {})
                out["stale"] = True
                out["fetched_at"] = cached.get("fetched_at")
                out["message"] = (out.get("message") or
                                  "Network Devices spoke offline — showing last-known data")
                return out
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NW_LIST_DEVICES", {})
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_fleet(data)
            return data
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("nw_list_devices failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/nw/{device_id}/{endpoint}")
    async def nw_get_device_data(request: Request, device_id: str, endpoint: str,
                                 tenant: str = None):
        """Live per-device nw data (info|macs|arp|interfaces).

        ``endpoint`` selects the device sub-resource → the NW_GET_<X> command.
        Results are tenant-prefix-filtered via ``_filter_nw`` before return
        (MAC/ARP/interfaces carry IPs; info does not). ``?tenant=`` scopes the
        filter to the selected tenant so an admin acting as a tenant sees only
        that tenant's subnet data — without it, admins bypass the filter (see
        access.filter_nw).

        Caches the raw per-device endpoint envelope (``nw_cache``) on every live
        fetch and serves it (marked ``stale``, tenant-filtered) when the nw
        spoke is offline, so a hub restart / spoke outage still seeds the
        device sub-views. The cache stores the *raw* envelope so the tenant
        subnet filter is re-applied per-reader from the same cached data."""
        hub = app.state.hub
        # Gated by the ``nw`` module right in the middleware; per-device rows are
        # subnet-filtered for non-admins via _filter_nw (mac/arp/interfaces). The
        # ``info`` endpoint carries no tenant IP, so it is device metadata shown to
        # nw-right users. Live-data reads only; nw device CONFIG (with tenant
        # binding) is managed under /tenant/devices/nw-devices.
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
        spoke_id = hub.get_spoke_by_type("nw")
        if not spoke_id:
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                filtered = await _filter_nw(request, cached, endpoint, tenant)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            raise HTTPException(status_code=503,
                                detail="Network Devices spoke not connected")
        # endpoints/vlans run three sequential SSH gathers (arp+mac+interfaces)
        # on the spoke, so the 5s default relay timeout is far too short — give
        # them room; the single-datum views get a comfortable margin too.
        timeout = 45.0 if endpoint in ("endpoints", "vlans") else 20.0
        try:
            result = await hub.request_response(spoke_id, spoke_cmd,
                                                {"device_id": device_id},
                                                timeout=timeout)
            data = access.unwrap_spoke(result)
            await hub.nw_cache_set_device(device_id, endpoint, data)
            return await _filter_nw(request, data, endpoint, tenant)
        except HTTPException:
            raise
        except Exception as e:
            # A slow/timed-out live fetch shouldn't blank the tab — serve the
            # last-known cached value (marked stale) if we have one, so a heavy
            # gateway that occasionally overruns still shows data.
            cached = hub.nw_cache_get_device(device_id, endpoint)
            if cached is not None:
                logger.warning("nw_get_device_data live fetch failed (%s/%s: %s)"
                               " — serving cached", device_id, endpoint, e)
                filtered = await _filter_nw(request, cached, endpoint, tenant)
                if isinstance(filtered, dict):
                    filtered = dict(filtered)
                    filtered["stale"] = True
                return filtered
            logger.exception("nw_get_device_data failed (%s/%s)", device_id, endpoint)
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/nw/{device_id}/config")
    async def nw_run_config(device_id: str, request: Request):
        """Apply a CLI/REST config snippet to a device (admin-only). Body:
        ``{"commands": ["...", ...]}``. Returns the spoke's applied/errors lists."""
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
        spoke_id = _get_nw_spoke(hub)
        try:
            result = await hub.request_response(spoke_id, "NW_RUN_CONFIG",
                                                {"device_id": device_id, "commands": commands})
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

            global_config = hub.state.system_state.get("global_config", {})
            devices = global_config.get("nw_devices", [])
            devices.append(new_dev)
            global_config["nw_devices"] = devices
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            # New device → push the bound slice so the spoke knows about it now.
            spoke_id = new_dev.get("spoke_id")
            pushed = await _nw_push_fleet(hub, spoke_id) if spoke_id else False
            return {"status": "ok", "device": new_dev, "pushed": pushed}
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
            hub.state.save_state()

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
        hub.state.save_state()
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
        if not spoke_id or spoke_id not in hub.active_connections:
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
                        hub.state.save_state()
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
                hub.state.save_state()
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
                hub.state.save_state()
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
            hub.state.save_state()
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
        spoke_id = hub.get_spoke_by_type("ipam")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
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
