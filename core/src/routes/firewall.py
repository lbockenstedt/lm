"""Firewall (OPNsense) data + rule/alias/NAT/DNS CRUD routes."""
import access
from api import (
    HTTPException, Request, _FW_FETCH_TIMEOUTS, _FW_FETCH_TIMEOUT_DEFAULT, _FW_MODULES,
    _FW_WRITE_TIMEOUT, _cache_entry, _fetch_module, _hub_msg, _invalidate_module_all_tenants,
    _invalidate_tenant_module, _tenant_cache, asyncio, logger, uuid,
)


def register(app, hub, ctx):
    """Register firewall routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_fw = ctx._filter_fw

    def _authz_firewall(request, firewall_id, write=False):
        """Authorize + classify a firewall op by the firewall's OWNING tenant.
        Returns ``(fw, scope)``. Raises 404 (unknown id) / 403 (no access).

        The tenant boundary for the ENTIRE ``/api/firewall/*`` surface — reads
        (data/refresh) AND writes (rules/aliases/NAT/DNS). ``scope`` folds the
        caller's tier with the firewall's tenancy (see access.read_scope /
        write_scope):

          * read  → ``"full"`` (Global Admin, or the firewall is DEDICATED to the
            caller's own tenant → whole device) or ``"filtered"`` (the SHARED
            firewall → only the caller's tenant slice; ``_filter_fw`` narrows it).
          * write → ``"full"`` (admin, or own-dedicated by a write-user+ → mutate
            anything) or ``"constrained"`` (SHARED, tenant-admin → only rules
            attributable to the caller's tenant; the write handler validates each
            payload via access.fw_rule_in_tenant_scope).

        ``"deny"`` → 403. 404-before-403 is intentional parity with the CRUD
        handlers; ids are server-issued UUIDs, so no meaningful existence leak."""
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f.get("id") == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        sess = _session_user(request)
        tid = fw.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        if scope == "deny":
            raise HTTPException(status_code=403, detail="You do not have access to this firewall")
        return fw, scope

    async def _authz_fw_write(request, firewall_id, endpoint, payload=None, uuid=None):
        """Write-authorize a firewall mutation and, on a SHARED firewall
        (scope=='constrained'), enforce that the target is within the caller's
        tenant slice. ADD/EDIT validate the submitted ``payload``; DELETE (only a
        ``uuid``) fetches the current records for ``endpoint`` and checks the
        matching record's attribution. 403 if the op falls outside the slice.
        Returns the fw dict."""
        hub = app.state.hub
        fw, scope = _authz_firewall(request, firewall_id, write=True)
        if scope != "constrained":
            return fw  # 'full' — admin or own-dedicated write-user; unrestricted
        sess = _session_user(request)
        # Both the NEW body (add/edit) AND the EXISTING record (edit/delete, by
        # uuid) must be in the caller's slice. Validating only the new payload on
        # an EDIT let a tenant-admin overwrite ANOTHER tenant's rule by uuid with a
        # body in their own subnet — so an edit must also attribute the target it
        # replaces. ADD → new only; DELETE → existing only; EDIT → both.
        targets = []
        if payload is not None:
            targets.append(payload)
        if uuid is not None:
            targets.append(await _fw_record_by_uuid(request, fw, endpoint, uuid))
        if not targets:
            raise HTTPException(status_code=403, detail="Nothing to authorize")
        for t in targets:
            if t is None or not await access.fw_rule_in_tenant_scope(hub, sess, endpoint, firewall_id, t):
                raise HTTPException(
                    status_code=403,
                    detail="On shared infrastructure you may only modify entries within your tenant's scope")
        return fw

    async def _fw_record_by_uuid(request, fw, endpoint, uuid):
        """Fetch the current records for ``endpoint`` from the firewall's spoke and
        return the one whose uuid matches (or None). Used to attribute a
        constrained delete/edit on a shared firewall."""
        hub = app.state.hub
        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            return None
        cmd = {"rules": "OPNSENSE_GET_ALL_RULES", "nat": "OPNSENSE_GET_NAT_POLICIES",
               "dns": "OPNSENSE_GET_DNS_RECORDS", "aliases": "OPNSENSE_GET_ALIASES"}.get(endpoint)
        if not cmd:
            return None
        try:
            result = await hub.request_response(spoke_id, cmd, {}, timeout=_FW_WRITE_TIMEOUT)
        except Exception:  # noqa: BLE001
            return None
        rows = result.get("payload", result) if isinstance(result, dict) else result
        if isinstance(rows, dict):
            rows = rows.get("data", rows)
        items = rows if isinstance(rows, list) else (rows.get(endpoint) if isinstance(rows, dict) else None)
        for r in (items or []):
            if isinstance(r, dict) and (r.get("uuid") == uuid or r.get("id") == uuid):
                return r
        return None

    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str, request: Request):
        hub = app.state.hub
        _authz_firewall(request, firewall_id)
        logger.info(f"API: Triggering cache refresh for firewall {firewall_id}")
        success = await hub.poll_opnsense_rules(firewall_id=firewall_id)
        if not success:
            logger.error(f"API: Cache refresh failed for firewall {firewall_id}")
            raise HTTPException(status_code=503, detail=f"Failed to refresh cache for firewall {firewall_id} (Spoke not connected or API error)")

        return {"status": "ok", "message": f"Cache for firewall {firewall_id} refreshed successfully!"}

    @app.get("/api/firewall/{firewall_id}/{endpoint}")
    # ── Firewall: data + CRUD (/api/firewall/*) ──────────────────────────────
    # get_firewall_data serves from tenant cache (non-admin) / offline cache /
    # a live spoke round-trip; the CRUD handlers below mutate and refresh.
    async def get_firewall_data(request: Request, firewall_id: str, endpoint: str, tenant: str = None):
        """Live + cached firewall data (rules/interfaces/services/virtual-ip).

        Three return paths: tenant cache hit for non-admins, offline cache when
        the spoke is down, and a live ``request_response`` round-trip. The
        ``endpoint`` arg selects the firewall sub-resource. Results are
        tenant-prefix-filtered via ``_filter_fw`` before return. ``?tenant=``
        scopes the filter to the selected tenant so an admin acting as a tenant
        (via the switcher) sees only that tenant's subnet data across every tab —
        without it, admins bypass the filter (see access.filter_fw)."""
        # see _netbox_list_get (variant: per-model command map + fw_id-scoped cache
        # keys + _filter_fw filter — enough variation to stay inline).
        hub = app.state.hub
        logger.debug("relay %s %s firewall=%s endpoint=%s tenant=%s", request.method, request.url.path, firewall_id, endpoint, tenant)

        # Tenant boundary + read scope: refuse a firewall the caller doesn't own
        # (admin any; else own/shared tenant). scope 'full' = whole device (admin
        # or own-dedicated); 'filtered' = shared, narrowed to the caller's slice.
        _fw0, _rscope = _authz_firewall(request, firewall_id)

        async def _scoped(payload):
            # 'full' = whole device (Global Admin, or an owner of a DEDICATED
            # firewall). But an explicit ?tenant= is a deliberate "scope me to this
            # tenant" request (the admin tenant switcher), so still apply the subnet
            # filter when it is present — otherwise an admin acting-as-tenant would
            # regress to seeing the whole device instead of that tenant's slice
            # (filter_fw honors explicit_tenant even for admins).
            if _rscope == "full" and not tenant:
                return payload
            return await _filter_fw(request, payload, endpoint, firewall_id, tenant)

        # Serve from tenant cache for non-admin users (if module is cached)
        sess = _session_user(request)
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id and endpoint in _FW_MODULES:
                cached = _cache_entry(tenant_id, f"{endpoint}:{firewall_id}")
                if cached:
                    return await _scoped(cached["data"])

        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")

        model = fw.get("model", "opnsense").lower()
        # Only OPNsense has a spoke that handles these commands. The UI model
        # dropdown also offers pfsense/juniper/fortigate, but no spokes exist
        # for those yet, so an unknown model falls back to the OPNsense command
        # set (parity with the previous behavior for pfsense/fortigate). The
        # former "juniper" entry mapped to JUNIPER_GET_* commands no spoke
        # handles — dead, removed.
        command_map = {
            "opnsense": {
                "rules": "OPNSENSE_GET_ALL_RULES",
                "interfaces": "GET_INTERFACE_STATUS",
                "health": "GET_SYSTEM_HEALTH",
                "dhcp": "OPNSENSE_GET_DHCP_LEASES",
                "nat": "OPNSENSE_GET_NAT_POLICIES",
                "dns": "OPNSENSE_GET_DNS_RECORDS",
                "aliases": "OPNSENSE_GET_ALIASES",
            },
        }

        model_commands = command_map.get(model, command_map.get("opnsense", {}))
        spoke_cmd = model_commands.get(endpoint)
        if not spoke_cmd:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported for model {model}")

        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            # Spoke offline — serve last known cache for any authenticated user
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                if tenant_id:
                    cached = _cache_entry(tenant_id, f"{endpoint}:{firewall_id}")
                    if cached:
                        return await _scoped(cached["data"])
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")

        try:
            result = await hub.request_response(
                spoke_id, spoke_cmd, {},
                timeout=_FW_FETCH_TIMEOUTS.get(endpoint, _FW_FETCH_TIMEOUT_DEFAULT))
            # A spoke ERROR (e.g. OPNsense < 26.1 with no NAT MVC API, or an API
            # key lacking the module scope) must surface to the UI rather than
            # degrade to an empty list — otherwise the tab silently shows
            # "No <things> found" with no clue as to why.
            if isinstance(result, dict) and result.get("status") == "ERROR":
                raise HTTPException(status_code=502,
                                    detail=result.get("message", "Firewall spoke error"))
            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    data = result
            else:
                data = result
            return await _scoped(data)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error fetching {endpoint} for firewall {firewall_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    async def _fw_spoke_cmd(hub, firewall_id: str, command: str, data: dict):
        """Helper: resolve firewall spoke and send a command, return result."""
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        spoke_id = fw.get("spoke_id")
        if not spoke_id or spoke_id not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")
        try:
            result = await hub.request_response(spoke_id, command, data, timeout=_FW_WRITE_TIMEOUT)
            if isinstance(result, dict):
                payload = result.get("payload", result)
                if isinstance(payload, dict) and "data" in payload:
                    return payload
                return result
            return result
        except Exception as e:
            logger.exception("_fw_spoke_cmd failed")
            raise HTTPException(status_code=500, detail=str(e))

    async def _fw_write(hub, firewall_id: str, command: str, data: dict, module_key: str):
        """Send a firewall write command and refresh the affected module in all tenant caches."""
        result = await _fw_spoke_cmd(hub, firewall_id, command, data)
        for tid in list(_tenant_cache):
            _invalidate_tenant_module(tid, f"{module_key}:{firewall_id}")
            asyncio.create_task(_fetch_module(hub, tid, module_key, fw_id=firewall_id))
        return result

    @app.post("/api/firewall/{firewall_id}/rules")
    async def add_firewall_rule(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        rule = data.get("rule", data)
        await _authz_fw_write(request, firewall_id, "rules", payload=rule)
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_RULE", {"rule": rule}, "rules")

    @app.delete("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def delete_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        await _authz_fw_write(request, firewall_id, "rules", uuid=rule_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_RULE", {"rule_id": rule_id}, "rules")

    @app.put("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def edit_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        rule = data.get("rule", data)
        await _authz_fw_write(request, firewall_id, "rules", payload=rule, uuid=rule_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_RULE", {"uuid": rule_id, "rule": rule}, "rules")

    @app.post("/api/firewall/{firewall_id}/aliases")
    async def add_firewall_alias(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "aliases", payload=data)
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_ADD_ALIAS", data)

    @app.delete("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def delete_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        hub = app.state.hub
        await _authz_fw_write(request, firewall_id, "aliases", uuid=alias_id)
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_DEL_ALIAS", {"uuid": alias_id})

    @app.put("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def edit_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "aliases", payload=data, uuid=alias_id)
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_EDIT_ALIAS", {"uuid": alias_id, **data})

    @app.post("/api/firewall/{firewall_id}/nat")
    async def add_nat_rule(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "nat", payload=data)
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_NAT_RULE", data, "nat")

    @app.delete("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def delete_nat_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        await _authz_fw_write(request, firewall_id, "nat", uuid=rule_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_NAT_RULE", {"nat_type": "d_nat", "uuid": rule_id}, "nat")

    @app.put("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def edit_nat_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "nat", payload=data, uuid=rule_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_NAT_RULE", {"uuid": rule_id, **data}, "nat")

    @app.post("/api/firewall/{firewall_id}/dns")
    async def add_dns_record(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "dns", payload=data)
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_DNS_RECORD", data, "dns")

    @app.delete("/api/firewall/{firewall_id}/dns/{record_id}")
    async def delete_dns_record(firewall_id: str, record_id: str, request: Request):
        hub = app.state.hub
        await _authz_fw_write(request, firewall_id, "dns", uuid=record_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_DNS_RECORD", {"uuid": record_id}, "dns")

    @app.put("/api/firewall/{firewall_id}/dns/{record_id}")
    async def edit_dns_record(firewall_id: str, record_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "dns", payload=data, uuid=record_id)
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_DNS_RECORD", {"uuid": record_id, **data}, "dns")

    @app.post("/setup/firewalls")
    async def add_firewall(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_fw = data.get("firewall", {})
            if not new_fw.get("name") or not new_fw.get("model"):
                raise HTTPException(status_code=400, detail="Missing firewall name or model")

            # Tenant-scoped add: a tenant-admin may bind a firewall ONLY to a
            # firewall spoke assigned to their own tenant, and the device is bound
            # to that tenant. Global Admin is unrestricted (device tenant defaults
            # to the bound spoke's tenant). Plain users cannot add.
            sess = _session_user(request)
            spoke_id = new_fw.get("spoke_id")
            if not _is_admin(sess):
                if not _is_tenant_admin(sess):
                    raise HTTPException(status_code=403, detail="Tenant-admin access required to add a firewall")
                if not spoke_id or not access.can_bind_spoke(hub, sess, spoke_id):
                    raise HTTPException(status_code=403,
                                        detail="You can only bind a firewall to a spoke assigned to your tenant")
                new_fw["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""
            elif spoke_id and not new_fw.get("tenant_id"):
                new_fw["tenant_id"] = hub.state.get_spoke_tenant(spoke_id) or ""

            if "id" not in new_fw:
                new_fw["id"] = str(uuid.uuid4())

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])
            firewalls.append(new_fw)
            global_config["firewalls"] = firewalls
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "ok", "firewall": new_fw}
        except HTTPException:
            raise  # 400/403 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("add_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.put("/setup/firewalls/{firewall_id}")
    async def update_firewall(firewall_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            update_data = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])

            fw_index = next((i for i, fw in enumerate(firewalls) if fw["id"] == firewall_id), None)
            if fw_index is None:
                raise HTTPException(status_code=404, detail="Firewall not found")

            firewalls[fw_index].update(update_data)
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            spoke_id = firewalls[fw_index].get("spoke_id")
            if spoke_id and spoke_id in hub.active_connections:
                msg = _hub_msg(spoke_id, "UPDATE_CONFIG", firewalls[fw_index])
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Firewall configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but associated spoke is not connected.", "pushed": False}
        except HTTPException:
            raise  # 4xx/503 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("update_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/firewalls/{firewall_id}")
    async def delete_firewall(firewall_id: str):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        firewalls = global_config.get("firewalls", [])

        original_len = len(firewalls)
        firewalls[:] = [fw for fw in firewalls if fw["id"] != firewall_id]

        if len(firewalls) == original_len:
            raise HTTPException(status_code=404, detail="Firewall not found")

        hub.state.system_state["global_config"] = global_config
        hub.state.save_state()
        # Drop orphaned per-firewall cache entries ({rules,nat,dhcp,dns,
        # interfaces}:{firewall_id}) from every tenant's cache so a deleted
        # firewall doesn't leave stale data that would render until the 300s
        # tick (and would never be re-fetched — the firewall no longer exists).
        for _fw_mod in _FW_MODULES:
            _invalidate_module_all_tenants(f"{_fw_mod}:{firewall_id}")
        return {"status": "ok", "message": f"Firewall {firewall_id} deleted."}

    # ── Network Devices: data + CRUD (/api/nw/*, /setup/nw-devices) ───────────
    # A single nw spoke manages a FLEET of switches + gateways (AOS-S / AOS-CX /
    # Juniper EX / Aruba-HPE gateway). global_config["nw_devices"] is the
    # hub-owned fleet list; each device binds to a spoke via spoke_id (unbound
    # devices fall to whatever nw spoke is connected — single-product deploy).
    # On edit/delete the bound spoke is re-pushed UPDATE_CONFIG with its
    # projected device slice (no creds stripped — system.json is runtime-only,
    # never committed). See access.filter_nw for the subnet filter contract.
