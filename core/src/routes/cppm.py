"""ClearPass (CPPM/NAC) device/session/enrichment routes."""
from api import (
    HTTPException, Request, _cache_entry, get_tenant_scoping, logger,
)


def register(app, hub, ctx):
    """Register cppm routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _effective_tenant = ctx._effective_tenant
    _effective_tenant_slug = ctx._effective_tenant_slug
    _filter_session = ctx._filter_session
    _filter_tenant = ctx._filter_tenant
    _gate_record_tenant = ctx._gate_record_tenant

    @app.get("/cppm/refresh")
    async def refresh_cppm_cache():
        hub = app.state.hub
        logger.info("API: Triggering CPPM cache refresh")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected for refresh")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_REFRESH_CACHE", {})
            return result
        except Exception as e:
            logger.error(f"API: Error refreshing CPPM cache: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/test-auth")
    async def test_cppm_auth():
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "TEST_AUTH", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.exception("test_cppm_auth failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/probe")
    async def probe_cppm(path: str, method: str = "GET"):
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "PROBE_API", {"path": path, "method": method})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.exception("probe_cppm failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/cppm/health")
    async def get_cppm_health():
        hub = app.state.hub
        logger.info("API: Requesting CPPM health")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_SYSTEM_HEALTH", {})
            data = result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
            logger.info(f"API: Received CPPM health: {data}")
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM health: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _device_tenant_slug(d: dict) -> str:
        """A device's tenant = its NetBox_Tenant_Slug (or Tenant_Slug) endpoint
        attribute — the value the endpoint sync writes. Empty when untagged."""
        attrs = (d.get("attributes") if isinstance(d, dict) else None) or {}
        return attrs.get("NetBox_Tenant_Slug") or attrs.get("Tenant_Slug") or ""

    def _filter_devices_by_tenant(data, scope: str):
        """Tag-based tenant filter for the Device Database list. Keeps only
        devices tagged with this IPAM scope (the logged-in user's tenant).
        More authoritative than the subnet filter — a device tagged for tenant
        X belongs to X regardless of its IP — so a non-admin sees only their own
        tenant's devices. No scope (admin, or tenant not bound to NetBox) →
        unchanged. Preserves the response shape (status/devices/total)."""
        if not scope:
            return data
        if not isinstance(data, dict):
            return data
        devices = data.get("devices")
        if not isinstance(devices, list):
            return data
        kept = [d for d in devices if isinstance(d, dict) and _device_tenant_slug(d) == scope]
        out = dict(data)
        out["devices"] = kept
        out["total"] = len(kept)
        return out

    # ── CPPM / NAC: devices, sessions, logs, roles (/api/cppm/*) ─────────────
    # ClearPass REST ``filter`` is exact-equality only (no SQL-LIKE), so the
    # device/session list handlers do an exact MAC/IP filter first then a bounded
    # client-side substring scan (see cppm/src/queries.py SEARCH_SCAN_CAP).
    @app.get("/api/cppm/devices")
    async def get_cppm_devices(request: Request, tenant: str = None):
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
        # tenant's IPAM scope (NetBox_Tenant_Slug / Tenant_Slug). The effective
        # tenant is the selected one (?tenant=) for admins / multi-tenant
        # switches — clamped for non-admins — falling back to the session tenant
        # when nothing is selected. scope=None (admin, no selection, or tenant
        # not bound to NetBox) → no-op; the subnet filter is the backstop.
        if tenant and _effective_tenant(request, tenant):
            scope = _effective_tenant_slug(request, tenant)
        elif sess and not _is_admin(sess):
            tid = sess.get("user", {}).get("tenant_id")
            scope = (get_tenant_scoping(hub, tid) or {}).get("netbox_tenant_slug") or None if tid else None
        else:
            scope = None
        tf = lambda d: _filter_devices_by_tenant(d, scope)

        if tenant and _effective_tenant(request, tenant):
            cppm_spoke = hub.get_spoke_by_type("nac")
            if not cppm_spoke:
                raise HTTPException(status_code=503, detail="No CPPM spoke connected")
            try:
                result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
                return await _filter_tenant(request, tf(_cppm_unwrap(result)), "nac", ["ip"], tenant)
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"API: Error fetching CPPM devices: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=str(e))
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id:
                cached = _cache_entry(tenant_id, "cppm_devices")
                if cached:
                    return await _filter_session(request, tf(cached["data"]), "nac", ["ip"])
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tenant_id, "cppm_devices") if tenant_id else None
                if cached:
                    return await _filter_session(request, tf(cached["data"]), "nac", ["ip"])
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
            return await _filter_session(request, tf(_cppm_unwrap(result)), "nac", ["ip"])
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"API: Error fetching CPPM devices: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/unknown-devices")
    async def get_cppm_unknown_devices(request: Request, tenant: str = None):
        """Endpoints not assigned to any tenant (no NetBox_Tenant_Slug /
        Tenant_Slug attribute) — the 'Unknown Devices' tab. Subnet-scoped by the
        selected tenant so a tenant sees untagged devices on their own network;
        an admin with no tenant selected sees every untagged endpoint."""
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ENDPOINTS", {})
            data = _cppm_unwrap(result)
            # Keep only untagged endpoints (assigned to no tenant).
            if isinstance(data, dict) and isinstance(data.get("devices"), list):
                untagged = [d for d in data["devices"] if isinstance(d, dict) and not _device_tenant_slug(d)]
                data = {**data, "devices": untagged, "total": len(untagged)}
            elif isinstance(data, list):
                data = [d for d in data if isinstance(d, dict) and not _device_tenant_slug(d)]
            return await _filter_tenant(request, data, "nac", ["ip"], tenant)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"API: Error fetching CPPM unknown devices: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _norm_mac(m: str) -> str:
        return m.lower().replace(":", "").replace("-", "").replace(".", "") if m else ""

    @app.get("/api/device-detail")
    async def get_device_detail(q: str = None, mac: str = None, ip: str = None, hostname: str = None):
        """Fan-out device lookup across all modules by MAC, IP, or hostname.

        Queries every connected spoke type (CPPM endpoints/sessions, NetBox IPs,
        OPNsense DHCP leases + firewall rules, pxmx VMs) for a match, de-dupes,
        and returns the merged record. Consumer: the WebUI device dashboard
        (``showDeviceDashboard`` in ``WebUI/main.js``). NOTE: the inner OPNsense
        loop sets ``rules_data`` from a lease-IP match even when the rules call
        itself failed — the success condition is intentionally tied to finding a
        DHCP lease, so read that block twice before changing it."""
        import asyncio as _asyncio, re as _re
        hub = app.state.hub

        mac = (mac or "").strip() or None
        ip = (ip or "").strip() or None
        hostname = (hostname or "").strip() or None

        if q and not (mac or ip or hostname):
            q = q.strip()
            if _re.match(r'^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$', q):
                mac = q
            elif _re.match(r'^\d{1,3}(\.\d{1,3}){3}$', q):
                ip = q
            else:
                hostname = q

        async def safe(coro):
            try:
                return await coro
            except Exception as e:
                return {"error": str(e)}

        async def req(spoke, cmd, data):
            if not spoke:
                return None
            r = await hub.request_response(spoke, cmd, data)
            d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
            return d

        spoke_nac  = hub.get_spoke_by_type("nac")
        fw_spokes  = hub.get_all_spokes_by_type("firewall") or []
        spoke_ipam = hub.get_spoke_by_type("ipam")
        spoke_pxmx = hub.get_hypervisor_spoke()
        spoke_ldap = hub.get_spoke_by_type("directory")

        tasks: dict = {}
        search_q = mac or ip or hostname or ""

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
        if spoke_pxmx and (ip or hostname):
            tasks["proxmox"] = safe(req(spoke_pxmx, "SEARCH_VMS", {"q": ip or hostname}))
        if spoke_ldap and (hostname or ip):
            tasks["ldap"] = safe(req(spoke_ldap, "SEARCH_USERS", {"q": hostname or ip}))

        gathered = await _asyncio.gather(*tasks.values())
        data = dict(zip(tasks.keys(), gathered))

        identity = {"mac": mac, "ip": ip, "hostname": hostname}

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

        nb_results  = (data.get("netbox") or {}).get("results", []) if isinstance(data.get("netbox"), dict) else []
        px_results  = (data.get("proxmox") or {}).get("results", []) if isinstance(data.get("proxmox"), dict) else []
        ld_results  = (data.get("ldap") or {}).get("results", []) if isinstance(data.get("ldap"), dict) else []

        return {
            "identity": identity,
            "nac":      nac_result,
            "dhcp":     dhcp_result,
            "netbox":   nb_results,
            "proxmox":  px_results,
            "ldap":     ld_results,
        }

    @app.get("/api/cppm/device-enrich")
    async def get_cppm_device_enrich(request: Request, mac: str, tenant: str = None):
        """Fetch CPPM endpoint detail and enrich missing fields from DHCP leases."""
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        fw_spokes = hub.get_all_spokes_by_type("firewall") or []

        ep: dict = {}
        if cppm_spoke:
            try:
                raw = await hub.request_response(cppm_spoke, "GET_ENDPOINT_DETAIL", {"mac": mac})
                ep = _cppm_unwrap(raw) if isinstance(raw, dict) else {}
            except Exception:
                pass

        sources: dict = {}
        if ep.get("ip"):
            sources["ip"] = "ClearPass"
        if ep.get("hostname"):
            sources["hostname"] = "ClearPass"

        norm_target = _norm_mac(mac)
        for spoke_id in fw_spokes:
            try:
                dhcp_raw = await hub.request_response(spoke_id, "OPNSENSE_GET_DHCP_LEASES", {})
                leases = dhcp_raw.get("payload", {}).get("data", []) if isinstance(dhcp_raw, dict) else []
                if not isinstance(leases, list):
                    continue
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
        return await _gate_record_tenant(request, ep, "nac", ["ip"], tenant) or {}

    @app.get("/api/cppm/device-sessions")
    async def get_cppm_device_sessions(request: Request, mac: str, tenant: str = None):
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "GET_DEVICE_SESSIONS", {"mac": mac})
            return await _filter_tenant(request, _cppm_unwrap(result), "nac", ["ip"], tenant)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_device_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/roles")
    async def get_cppm_roles():
        """List ClearPass roles from the NAC spoke (unfiltered relay)."""
        hub = app.state.hub
        logger.debug("relay GET /api/cppm/roles")
        logger.info("API: Requesting CPPM roles")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "LIST_ROLES", {})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return data
        except Exception as e:
            logger.error(f"API: Error fetching CPPM roles: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/logs")
    async def get_cppm_logs(request: Request, start: str, end: str, tenant: str = None):
        """Fetch ClearPass audit logs between start/end; subnet-filtered per tenant."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        logger.info(f"API: Requesting CPPM logs from {start} to {end}")
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            logger.error("API: No CPPM spoke connected")
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "GET_LOGS", {"start": start, "end": end})
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return await _filter_tenant(request, data, "nac", ["ip", "nas_ip_address"], tenant)
        except Exception as e:
            logger.error(f"API: Error fetching CPPM logs: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))

    def _cppm_unwrap(result):
        """Extract spoke payload data and raise HTTPException if spoke reported an error."""
        data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        if isinstance(data, dict) and data.get("status") == "ERROR":
            raise HTTPException(status_code=502, detail=data.get("message", "CPPM API error"))
        return data

    @app.get("/api/cppm/sessions")
    async def get_cppm_sessions(request: Request, limit: int = 200, offset: int = 0,
                                tenant: str = None):
        """List ClearPass access-tracker sessions; admin/multi-tenant switches go
        live, non-admins get the tenant cache; spoke-down falls back to cache."""
        hub = app.state.hub
        logger.debug("relay %s %s tenant=%s", request.method, request.url.path, tenant)
        sess = _session_user(request)
        # see _netbox_list_get (variant: admin/multi-tenant live path FIRST, then
        # non-admin cache; _filter_tenant — inline, mirrors get_cppm_devices).
        # Admin / multi-tenant switch: scope by the selected tenant's prefixes
        # (explicit_tenant). Without a selection, non-admins keep session-tenant
        # scoping via the cache path below.
        if tenant and _effective_tenant(request, tenant):
            cppm_spoke = hub.get_spoke_by_type("nac")
            if not cppm_spoke:
                raise HTTPException(status_code=503, detail="No CPPM spoke connected")
            try:
                result = await hub.request_response(cppm_spoke, "CPPM_GET_ACCESS_TRACKER", {"limit": limit, "offset": offset})
                return await _filter_tenant(request, _cppm_unwrap(result), "nac", ["ip"], tenant)
            except HTTPException:
                raise
            except Exception as e:
                logger.exception("get_cppm_sessions failed")
                raise HTTPException(status_code=500, detail=str(e))
        if sess and not _is_admin(sess):
            tenant_id = sess.get("user", {}).get("tenant_id")
            if tenant_id:
                cached = _cache_entry(tenant_id, "cppm_sessions")
                if cached:
                    return await _filter_session(request, cached["data"], "nac", ["ip"])
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            if sess:
                tenant_id = sess.get("user", {}).get("tenant_id")
                cached = _cache_entry(tenant_id, "cppm_sessions") if tenant_id else None
                if cached:
                    return await _filter_session(request, cached["data"], "nac", ["ip"])
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_ACCESS_TRACKER", {"limit": limit, "offset": offset})
            return await _filter_session(request, _cppm_unwrap(result), "nac", ["ip"])
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_sessions failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/cppm/nac-status")
    async def get_cppm_nac_status():
        hub = app.state.hub
        cppm_spoke = hub.get_spoke_by_type("nac")
        if not cppm_spoke:
            raise HTTPException(status_code=503, detail="No CPPM spoke connected")
        try:
            result = await hub.request_response(cppm_spoke, "CPPM_GET_NAC_STATUS", {})
            return _cppm_unwrap(result)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("get_cppm_nac_status failed")
            raise HTTPException(status_code=500, detail=str(e))
