"""Firewall (OPNsense) data + rule/alias/NAT/DNS CRUD routes."""
from api import (
    HTTPException, Request, _FW_FETCH_TIMEOUTS, _FW_FETCH_TIMEOUT_DEFAULT, _FW_MODULES,
    _FW_WRITE_TIMEOUT, _cache_entry, _fetch_module, _hub_msg, _invalidate_module_all_tenants,
    _invalidate_tenant_module, _tenant_cache, asyncio, logger, uuid,
)


def register(app, hub, ctx):
    """Register firewall routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _filter_fw = ctx._filter_fw

    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str):
        hub = app.state.hub
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

        # Serve from tenant cache for non-admin users (if module is cached)
        sess = _session_user(request)
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id and endpoint in _FW_MODULES:
                cached = _cache_entry(tenant_id, f"{endpoint}:{firewall_id}")
                if cached:
                    return await _filter_fw(request, cached["data"], endpoint, firewall_id, tenant)

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
                        return await _filter_fw(request, cached["data"], endpoint, firewall_id, tenant)
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
            return await _filter_fw(request, data, endpoint, firewall_id, tenant)
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
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_RULE", {"rule": data.get("rule", data)}, "rules")

    @app.delete("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def delete_firewall_rule(firewall_id: str, rule_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_RULE", {"rule_id": rule_id}, "rules")

    @app.put("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def edit_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_RULE", {"uuid": rule_id, "rule": data.get("rule", data)}, "rules")

    @app.post("/api/firewall/{firewall_id}/aliases")
    async def add_firewall_alias(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_ADD_ALIAS", data)

    @app.delete("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def delete_firewall_alias(firewall_id: str, alias_id: str):
        hub = app.state.hub
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_DEL_ALIAS", {"uuid": alias_id})

    @app.put("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def edit_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_EDIT_ALIAS", {"uuid": alias_id, **data})

    @app.post("/api/firewall/{firewall_id}/nat")
    async def add_nat_rule(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_NAT_RULE", data, "nat")

    @app.delete("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def delete_nat_rule(firewall_id: str, rule_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_NAT_RULE", {"nat_type": "d_nat", "uuid": rule_id}, "nat")

    @app.put("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def edit_nat_rule(firewall_id: str, rule_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_NAT_RULE", {"uuid": rule_id, **data}, "nat")

    @app.post("/api/firewall/{firewall_id}/dns")
    async def add_dns_record(firewall_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_DNS_RECORD", data, "dns")

    @app.delete("/api/firewall/{firewall_id}/dns/{record_id}")
    async def delete_dns_record(firewall_id: str, record_id: str):
        hub = app.state.hub
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_DNS_RECORD", {"uuid": record_id}, "dns")

    @app.put("/api/firewall/{firewall_id}/dns/{record_id}")
    async def edit_dns_record(firewall_id: str, record_id: str, request: Request):
        hub = app.state.hub
        data = await request.json()
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_DNS_RECORD", {"uuid": record_id, **data}, "dns")

    @app.post("/setup/firewalls")
    async def add_firewall(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            new_fw = data.get("firewall", {})
            if not new_fw.get("name") or not new_fw.get("model"):
                raise HTTPException(status_code=400, detail="Missing firewall name or model")

            if "id" not in new_fw:
                new_fw["id"] = str(uuid.uuid4())

            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])
            firewalls.append(new_fw)
            global_config["firewalls"] = firewalls
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            return {"status": "ok", "firewall": new_fw}
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
