"""Firewall (OPNsense) data + rule/alias/NAT/DNS CRUD routes."""
# asyncio for background/parallel work; access for tenant checks; instance_vault for stored secrets.
import asyncio
import access
import instance_vault
# Shared Hub helpers: errors, request, firewall timeouts and module list, messages, logger, uuid.
from api import (
    HTTPException, Request, _FW_FETCH_TIMEOUTS, _FW_FETCH_TIMEOUT_DEFAULT, _FW_MODULES,
    _FW_WRITE_TIMEOUT, _hub_msg, logger, uuid,
)
# Hub data-cache job description.
from warm_cache import CacheJob

# Firewall read endpoints → OPNsense spoke command. Only OPNsense has a spoke;
# the UI model dropdown also offers pfsense/juniper/fortigate, which fall back
# to this command set (the former JUNIPER_GET_* map had no handler — removed).
FW_READ_CMDS = {
    "rules": "OPNSENSE_GET_ALL_RULES",
    "interfaces": "GET_INTERFACE_STATUS",
    "health": "GET_SYSTEM_HEALTH",
    "overview": "OPNSENSE_GET_OVERVIEW",
    "dhcp": "OPNSENSE_GET_DHCP_LEASES",
    "nat": "OPNSENSE_GET_NAT_POLICIES",
    "dns": "OPNSENSE_GET_DNS_RECORDS",
    "aliases": "OPNSENSE_GET_ALIASES",
    "impair": "OPNSENSE_GET_IMPAIRMENTS",
}


def _fw_record(hub, firewall_id):
    """Return the configured firewall with this id (None if there isn't one)."""
    firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
    return next((f for f in firewalls if f.get("id") == firewall_id), None)


def fw_cache_job(hub, firewall_id: str, endpoint: str) -> CacheJob:
    """Hub-cache job for one firewall endpoint. Namespace ``fw_<endpoint>``,
    key = firewall id: a firewall's data is stored ONCE no matter how many
    tenants share it; ``_filter_fw`` narrows it per reader. The five list
    modules (``_FW_MODULES``) are kept warm by the feed; health/aliases are
    cached on first open. Lane per firewall so one slow box can't starve the
    others."""
    async def fetch():
        """Fetch this endpoint's data from the firewall's spoke."""
        # The firewall must exist and its spoke must be connected.
        fw = _fw_record(hub, firewall_id)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        spoke_id = fw.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")
        # Ask the spoke for the data.
        result = await hub.request_response(
            spoke_id, FW_READ_CMDS[endpoint], {},
            timeout=_FW_FETCH_TIMEOUTS.get(endpoint, _FW_FETCH_TIMEOUT_DEFAULT))
        # A spoke ERROR (e.g. OPNsense < 26.1 with no NAT MVC API, or an API
        # key lacking the module scope) must surface rather than be cached as
        # an empty list.
        reply = result.get("payload", result) if isinstance(result, dict) else result
        if isinstance(reply, dict) and reply.get("status") == "ERROR":
            raise HTTPException(status_code=502,
                                detail=reply.get("message", "Firewall spoke error"))
        # Return the data part of the reply.
        if isinstance(result, dict):
            if "data" in result:
                return result["data"]
            if isinstance(result.get("payload"), dict):
                return result["payload"].get("data", {})
        return result

    # Build the job (list modules are warm; others are "detail" entries).
    return CacheJob(f"fw_{endpoint}", firewall_id, fetch, None,
                    lane=f"fw:{firewall_id}", detail=endpoint not in _FW_MODULES)


def fw_cache_feed(hub):
    """Feed: the five list modules for every configured firewall."""
    # Each list module of each firewall that has an id.
    for fw in hub.state.system_state.get("global_config", {}).get("firewalls", []) or []:
        if fw.get("id"):
            for endpoint in sorted(_FW_MODULES):
                yield fw_cache_job(hub, fw["id"], endpoint)


def register(app, hub, ctx):
    """Register firewall routes on the Hub app."""
    # Session, admin and filter helpers from the shared route context.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _is_tenant_admin = ctx._is_tenant_admin
    _filter_fw = ctx._filter_fw

    def _redeploy_certs_soon(hub, spoke_id):
        """A firewall was added/re-pointed on ``spoke_id``: push its LE certs
        (and let the spoke activate them on the WebGUI) once UPDATE_CONFIG has
        landed, instead of waiting for the next renewal."""
        async def _run():
            """Wait for the config to land, then push the firewall's certs (best effort)."""
            await asyncio.sleep(5)
            try:
                await hub._redeploy_certs_to_target("firewall", spoke_id)
            except Exception as e:  # noqa: BLE001 — hourly sweep / manual deploy remain
                logger.warning("[cert] firewall/%s re-deploy after config change failed: %s", spoke_id, e)
        # Run it in the background.
        asyncio.create_task(_run())

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
        # Find the firewall; unknown is a 404.
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f.get("id") == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        # Work out the caller's read or write scope for this firewall's tenant.
        sess = _session_user(request)
        tid = fw.get("tenant_id", "")
        scope = access.write_scope(sess, tid) if write else access.read_scope(sess, tid)
        # A shared firewall hidden from this tenant, or no access, is a 403.
        if scope in ("filtered", "constrained") and _shared_fw_hidden(request, fw):
            scope = "deny"
        if scope == "deny":
            raise HTTPException(status_code=403, detail="You do not have access to this firewall")
        return fw, scope

    def _shared_fw_hidden(request, fw):
        """A shared firewall is hidden from a tenant that has its own."""
        # A tenant-owned firewall is never hidden.
        if access.firewall_owner_tenant(app.state.hub, fw.get("id")):
            return False
        # Hidden if the caller's tenant has its own firewall.
        tid = access.request_effective_tenant(_session_user(request), request)
        return access.tenant_left_shared(app.state.hub, tid, "firewall")

    async def _authz_fw_write(request, firewall_id, endpoint, payload=None, uuid=None):
        """Write-authorize a firewall mutation and, on a SHARED firewall
        (scope=='constrained'), enforce that the target is within the caller's
        tenant slice. ADD/EDIT validate the submitted ``payload``; DELETE (only a
        ``uuid``) fetches the current records for ``endpoint`` and checks the
        matching record's attribution. 403 if the op falls outside the slice.
        Returns the fw dict."""
        # Check write access; full scope may change anything.
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
        # The spoke must be connected.
        hub = app.state.hub
        spoke_id = fw.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            return None
        # Pick the list command for this endpoint (unknown endpoints give None).
        cmd = {"rules": "OPNSENSE_GET_ALL_RULES", "nat": "OPNSENSE_GET_NAT_POLICIES",
               "dns": "OPNSENSE_GET_DNS_RECORDS", "aliases": "OPNSENSE_GET_ALIASES",
               "impair": "OPNSENSE_GET_IMPAIRMENTS"}.get(endpoint)
        if not cmd:
            return None
        # Fetch the list (None on failure).
        try:
            result = await hub.request_response(spoke_id, cmd, {}, timeout=_FW_WRITE_TIMEOUT)
        except Exception:  # noqa: BLE001
            return None
        # Unwrap the reply into a list of records.
        rows = result.get("payload", result) if isinstance(result, dict) else result
        if isinstance(rows, dict):
            rows = rows.get("data", rows)
        items = rows if isinstance(rows, list) else (rows.get(endpoint) if isinstance(rows, dict) else None)
        # Return the record whose uuid (or id) matches.
        for r in (items or []):
            if isinstance(r, dict) and (r.get("uuid") == uuid or r.get("id") == uuid):
                return r
        return None

    # Refresh one firewall's cached data.
    @app.get("/api/firewall/{firewall_id}/refresh")
    async def refresh_firewall_cache(firewall_id: str, request: Request):
        """Re-poll one firewall (with access check); 503 if it fails."""
        hub = app.state.hub
        # Check read access, then re-poll it.
        _authz_firewall(request, firewall_id)
        logger.info(f"API: Triggering cache refresh for firewall {firewall_id}")
        success = await hub.poll_opnsense_rules(firewall_id=firewall_id)
        if not success:
            logger.error(f"API: Cache refresh failed for firewall {firewall_id}")
            raise HTTPException(status_code=503, detail=f"Failed to refresh cache for firewall {firewall_id} (Spoke not connected or API error)")

        return {"status": "ok", "message": f"Cache for firewall {firewall_id} refreshed successfully!"}

    # Refresh several firewalls at once.
    @app.post("/api/firewall/refresh")
    async def refresh_firewalls_bulk(request: Request):
        """Batch cache-refresh: refresh many firewalls in ONE call (the UI's
        "Refresh cache" across all configured firewalls) instead of one GET per
        firewall. Each is authorized + refreshed independently and concurrently;
        returns a per-firewall ok list so one failure doesn't sink the rest."""
        hub = app.state.hub
        # Read the JSON body (defaulting to {}).
        try:
            body = await request.json()
        except Exception:
            body = {}
        # A non-empty list of firewall ids is required.
        ids = (body or {}).get("firewall_ids") or []
        if not isinstance(ids, list) or not ids:
            raise HTTPException(status_code=400, detail="firewall_ids must be a non-empty list")
        import asyncio as _asyncio

        async def _one(fid):
            """Check access to and re-poll one firewall; report ok or the error."""
            try:
                _authz_firewall(request, fid)
                ok = await hub.poll_opnsense_rules(firewall_id=fid)
                return {"id": fid, "ok": bool(ok)}
            except HTTPException as he:
                return {"id": fid, "ok": False, "error": str(he.detail)}
            except Exception as e:  # noqa: BLE001
                return {"id": fid, "ok": False, "error": str(e)}

        # Run them all at once and return the per-firewall results with totals.
        results = await _asyncio.gather(*[_one(fid) for fid in ids])
        return {"results": results,
                "ok": sum(1 for r in results if r.get("ok")),
                "total": len(results)}

    # Read one kind of firewall data.
    @app.get("/api/firewall/{firewall_id}/{endpoint}")
    # ── Firewall: data + CRUD (/api/firewall/*) ──────────────────────────────
    # get_firewall_data serves from the hub data cache (fw_cache_job); the CRUD
    # handlers below mutate and then cache_refresh the affected module.
    async def get_firewall_data(request: Request, firewall_id: str, endpoint: str, tenant: str = None):
        """Cached firewall data (rules/interfaces/nat/dhcp/dns/health/aliases).

        The RAW per-firewall payload comes from the hub data cache (one entry
        per firewall, shared by every tenant; first open of an uncached
        endpoint fetches live). Authorization (``_authz_firewall``) and the
        tenant-prefix filter (``_filter_fw``) run on EVERY read. ``?tenant=``
        scopes the filter to the selected tenant so an admin acting as a
        tenant (via the switcher) sees only that tenant's subnet data — without
        it, admins bypass the filter (see access.filter_fw). Responses carry
        ``cached_at`` (+ ``stale``)."""
        hub = app.state.hub
        logger.debug("relay %s %s firewall=%s endpoint=%s tenant=%s", request.method, request.url.path, firewall_id, endpoint, tenant)

        # Tenant boundary + read scope: refuse a firewall the caller doesn't own
        # (admin any; else own/shared tenant). scope 'full' = whole device (admin
        # or own-dedicated); 'filtered' = shared, narrowed to the caller's slice.
        _fw0, _rscope = _authz_firewall(request, firewall_id)

        async def _scoped(payload):
            """Apply the caller's tenant filter to ``payload`` (unless they see it all)."""
            # 'full' = whole device (Global Admin, or an owner of a DEDICATED
            # firewall). But an explicit ?tenant= is a deliberate "scope me to this
            # tenant" request (the admin tenant switcher), so still apply the subnet
            # filter when it is present — otherwise an admin acting-as-tenant would
            # regress to seeing the whole device instead of that tenant's slice
            # (filter_fw honors explicit_tenant even for admins).
            if _rscope == "full" and not tenant:
                return payload
            return await _filter_fw(request, payload, endpoint, firewall_id, tenant)

        # Unknown firewall is a 404; unsupported endpoint is a 400.
        if not _fw_record(hub, firewall_id):
            raise HTTPException(status_code=404, detail="Firewall not found")
        if endpoint not in FW_READ_CMDS:
            raise HTTPException(status_code=400, detail=f"Endpoint {endpoint} not supported")
        # Read through the cache; our HTTP errors pass through, others are a 500.
        job = fw_cache_job(hub, firewall_id, endpoint)
        try:
            data = await hub.cache_read(job.ns, job.key, job.fetch, tenants=job.tenants,
                                        lane=job.lane, detail=job.detail)
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error fetching {endpoint} for firewall {firewall_id}: {e}", exc_info=True)
            raise HTTPException(status_code=500, detail=str(e))
        # Filter for the caller and add the cache info.
        return hub.cache_annotate(await _scoped(data), job.ns, job.key)

    # Register the firewall feed with the hub data cache (if this hub has one).
    if hasattr(hub, "cache_register_feed"):
        hub.cache_register_feed("firewall", fw_cache_feed)

    async def _fw_spoke_cmd(hub, firewall_id: str, command: str, data: dict):
        """Helper: resolve firewall spoke and send a command, return result."""
        # Find the firewall; unknown is a 404, a disconnected spoke is a 503.
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        if not fw:
            raise HTTPException(status_code=404, detail="Firewall not found")
        spoke_id = fw.get("spoke_id")
        if not spoke_id or hub._primary_key(spoke_id) not in hub.active_connections:
            raise HTTPException(status_code=503, detail=f"Firewall spoke {spoke_id} not connected")
        # Send the command and unwrap the reply.
        try:
            result = await hub.request_response(spoke_id, command, data, timeout=_FW_WRITE_TIMEOUT)
            if isinstance(result, dict):
                payload = result.get("payload", result)
                if isinstance(payload, dict) and "data" in payload:
                    return payload
                return result
            return result
        # Any failure is logged and a 500.
        except Exception as e:
            logger.exception("_fw_spoke_cmd failed")
            raise HTTPException(status_code=500, detail=str(e))

    async def _fw_write(hub, firewall_id: str, command: str, data: dict, module_key: str):
        """Send a firewall write command, then refresh that firewall's cached
        ``module_key`` data now (readers briefly wait for it — see
        ``warm_cache.cache_refresh``)."""
        # Send the command, then refresh the cached module.
        result = await _fw_spoke_cmd(hub, firewall_id, command, data)
        hub.cache_refresh(f"fw_{module_key}", (firewall_id,), exact=True)
        return result

    # Add a firewall rule.
    @app.post("/api/firewall/{firewall_id}/rules")
    async def add_firewall_rule(firewall_id: str, request: Request):
        """Add a rule (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Read the rule and check the caller may write it.
        data = await request.json()
        rule = data.get("rule", data)
        await _authz_fw_write(request, firewall_id, "rules", payload=rule)
        # Send it and refresh the cached rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_RULE", {"rule": rule}, "rules")

    # Delete a firewall rule.
    @app.delete("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def delete_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        """Delete a rule (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Check the caller may change this rule.
        await _authz_fw_write(request, firewall_id, "rules", uuid=rule_id)
        # Send it and refresh the cached rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_RULE", {"rule_id": rule_id}, "rules")

    # Edit a firewall rule.
    @app.put("/api/firewall/{firewall_id}/rules/{rule_id}")
    async def edit_firewall_rule(firewall_id: str, rule_id: str, request: Request):
        """Replace a rule (old and new versions checked against the tenant scope)."""
        hub = app.state.hub
        # Read the new rule and check the caller may write both versions.
        data = await request.json()
        rule = data.get("rule", data)
        await _authz_fw_write(request, firewall_id, "rules", payload=rule, uuid=rule_id)
        # Send it and refresh the cached rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_RULE", {"uuid": rule_id, "rule": rule}, "rules")

    # Add a firewall alias.
    @app.post("/api/firewall/{firewall_id}/aliases")
    async def add_firewall_alias(firewall_id: str, request: Request):
        """Add an alias (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Read the alias and check the caller may write it.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "aliases", payload=data)
        # Send it to the spoke.
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_ADD_ALIAS", data)

    # Delete a firewall alias.
    @app.delete("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def delete_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        """Delete an alias (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Check the caller may change this alias.
        await _authz_fw_write(request, firewall_id, "aliases", uuid=alias_id)
        # Send it to the spoke.
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_DEL_ALIAS", {"uuid": alias_id})

    # Edit a firewall alias.
    @app.put("/api/firewall/{firewall_id}/aliases/{alias_id}")
    async def edit_firewall_alias(firewall_id: str, alias_id: str, request: Request):
        """Update an alias (old and new versions checked against the tenant scope)."""
        hub = app.state.hub
        # Read the new alias and check the caller may write both versions.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "aliases", payload=data, uuid=alias_id)
        # Send it to the spoke.
        return await _fw_spoke_cmd(hub, firewall_id, "OPNSENSE_EDIT_ALIAS", {"uuid": alias_id, **data})

    # Add a NAT rule.
    @app.post("/api/firewall/{firewall_id}/nat")
    async def add_nat_rule(firewall_id: str, request: Request):
        """Add a NAT rule (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Read the rule and check the caller may write it.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "nat", payload=data)
        # Send it and refresh the cached NAT rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_NAT_RULE", data, "nat")

    # Delete a NAT rule.
    @app.delete("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def delete_nat_rule(firewall_id: str, rule_id: str, request: Request):
        """Delete a destination-NAT rule (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Check the caller may change this rule.
        await _authz_fw_write(request, firewall_id, "nat", uuid=rule_id)
        # Send it and refresh the cached NAT rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_NAT_RULE", {"nat_type": "d_nat", "uuid": rule_id}, "nat")

    # Edit a NAT rule.
    @app.put("/api/firewall/{firewall_id}/nat/{rule_id}")
    async def edit_nat_rule(firewall_id: str, rule_id: str, request: Request):
        """Update a NAT rule (old and new versions checked against the tenant scope)."""
        hub = app.state.hub
        # Read the new rule and check the caller may write both versions.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "nat", payload=data, uuid=rule_id)
        # Send it and refresh the cached NAT rules.
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_NAT_RULE", {"uuid": rule_id, **data}, "nat")

    # Add a DNS record.
    @app.post("/api/firewall/{firewall_id}/dns")
    async def add_dns_record(firewall_id: str, request: Request):
        """Add a DNS record (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Read the record and check the caller may write it.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "dns", payload=data)
        # Send it and refresh the cached DNS records.
        return await _fw_write(hub, firewall_id, "OPNSENSE_ADD_DNS_RECORD", data, "dns")

    # Delete a DNS record.
    @app.delete("/api/firewall/{firewall_id}/dns/{record_id}")
    async def delete_dns_record(firewall_id: str, record_id: str, request: Request):
        """Delete a DNS record (checked against the caller's tenant scope)."""
        hub = app.state.hub
        # Check the caller may change this record.
        await _authz_fw_write(request, firewall_id, "dns", uuid=record_id)
        # Send it and refresh the cached DNS records.
        return await _fw_write(hub, firewall_id, "OPNSENSE_DEL_DNS_RECORD", {"uuid": record_id}, "dns")

    # Edit a DNS record.
    @app.put("/api/firewall/{firewall_id}/dns/{record_id}")
    async def edit_dns_record(firewall_id: str, record_id: str, request: Request):
        """Update a DNS record (old and new versions checked against the tenant scope)."""
        hub = app.state.hub
        # Read the new record and check the caller may write both versions.
        data = await request.json()
        await _authz_fw_write(request, firewall_id, "dns", payload=data, uuid=record_id)
        # Send it and refresh the cached DNS records.
        return await _fw_write(hub, firewall_id, "OPNSENSE_EDIT_DNS_RECORD", {"uuid": record_id, **data}, "dns")

    # ── Network impairment (latency / loss for a host or subnet) ─────────────
    async def _impair_authz(request, firewall_id, payload=None, uuid=None):
        """Usual firewall write check, plus: on a SHARED firewall the target
        must lie INSIDE one of the caller's prefixes (the generic check only
        needs an overlap, which would let a tenant impair a whole /8)."""
        # Run the usual write check, then (shared firewalls only) the inside-a-subnet check.
        import ipaddress
        await _authz_fw_write(request, firewall_id, "impair", payload=payload, uuid=uuid)
        _fw, scope = _authz_firewall(request, firewall_id, write=True)
        if scope != "constrained" or payload is None:
            return
        # Is the target inside one of the caller's prefixes? A bad address counts as no.
        try:
            target = ipaddress.ip_network(str(payload.get("target", "")).strip(), strict=False)
            owned = [ipaddress.ip_network(p, strict=False)
                     for p in await access.resolve_owned_prefixes(app.state.hub, _session_user(request))]
            inside = any(target.version == n.version and target.subnet_of(n) for n in owned)
        except ValueError:
            inside = False
        if not inside:
            raise HTTPException(status_code=403,
                                detail="On shared infrastructure the target must be inside your tenant's subnets")

    async def _impair_write(firewall_id, command, data):
        """Send an impairment change; a spoke ERROR becomes a 400."""
        result = await _fw_write(app.state.hub, firewall_id, command, data, "impair")
        reply = result.get("payload", result) if isinstance(result, dict) else result
        if isinstance(reply, dict) and reply.get("status") == "ERROR":
            raise HTTPException(status_code=400, detail=reply.get("message", "Firewall spoke error"))
        return result

    # Add a network impairment.
    @app.post("/api/firewall/{firewall_id}/impair")
    async def add_impairment(firewall_id: str, request: Request):
        """Add an impairment (latency/loss) for a host or subnet."""
        # Read it, check the caller may add it, and send it.
        data = await request.json()
        await _impair_authz(request, firewall_id, payload=data)
        return await _impair_write(firewall_id, "OPNSENSE_ADD_IMPAIRMENT", data)

    # Edit a network impairment.
    @app.put("/api/firewall/{firewall_id}/impair/{impair_id}")
    async def edit_impairment(firewall_id: str, impair_id: str, request: Request):
        """Update an impairment."""
        # Read it, check the caller may change it, and send it.
        data = await request.json()
        await _impair_authz(request, firewall_id, payload=data, uuid=impair_id)
        return await _impair_write(firewall_id, "OPNSENSE_EDIT_IMPAIRMENT", {**data, "uuid": impair_id})

    # Delete a network impairment.
    @app.delete("/api/firewall/{firewall_id}/impair/{impair_id}")
    async def delete_impairment(firewall_id: str, impair_id: str, request: Request):
        """Delete an impairment."""
        # Check the caller may delete it, and send it.
        await _impair_authz(request, firewall_id, uuid=impair_id)
        return await _impair_write(firewall_id, "OPNSENSE_DEL_IMPAIRMENT", {"uuid": impair_id})

    # Add a firewall to the setup.
    @app.post("/setup/firewalls")
    async def add_firewall(request: Request):
        """Save a new firewall and push its config to its spoke."""
        hub = app.state.hub
        # Read it; a name and model are required, and OPNsense needs API credentials.
        try:
            data = await request.json()
            new_fw = data.get("firewall", {})
            if not new_fw.get("name") or not new_fw.get("model"):
                raise HTTPException(status_code=400, detail="Missing firewall name or model")
            # A Credential Vault reference supplies api_key/api_secret at push
            # time, so the "both required" inline check only applies when no
            # vault_credential is present.
            if (new_fw.get("model") == "opnsense"
                    and not instance_vault.has_vault_ref(new_fw)
                    and not (new_fw.get("api_key") and new_fw.get("api_secret"))):
                raise HTTPException(status_code=400, detail="OPNsense needs both an API key and an API secret")

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

            # Vault-reference validation + strip: when a vault_credential is
            # present it must resolve (reach + automation-readable + usable);
            # either way the inline api_key/api_secret are never persisted once
            # a reference is set (strip_inline_secrets is a no-op otherwise).
            # Also enforces the hub's "vault available → no inline secrets"
            # policy (instance_vault._vault_only_violation).
            await instance_vault.validate_ref(
                hub, new_fw, sess, is_admin=_is_admin(sess), storage_key="firewalls")
            instance_vault.strip_inline_secrets(new_fw, "firewalls")

            # Give it an id if it has none.
            if "id" not in new_fw:
                new_fw["id"] = str(uuid.uuid4())

            # Add it to the saved firewall list.
            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])
            firewalls.append(new_fw)
            global_config["firewalls"] = firewalls
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Deliver the connection (host + API creds) to the bound spoke now;
            # otherwise it stays "No firewall configured" until it reconnects.
            # The vault-resolved api_key/api_secret are overlaid onto a COPY
            # just before the push — the plaintext never touches global_config.
            pushed = False
            new_spoke = new_fw.get("spoke_id")
            if new_spoke and hub._primary_key(new_spoke) in hub.active_connections:
                try:
                    push_fw = await instance_vault.overlay(hub, new_fw, "firewalls")
                    await hub.send_to_spoke(_hub_msg(new_spoke, "UPDATE_CONFIG", push_fw))
                    pushed = True
                    _redeploy_certs_soon(hub, new_spoke)
                except Exception as e:  # noqa: BLE001 — saved; reconnect re-push covers it
                    logger.warning("add_firewall: config push to %s failed: %s", new_spoke, e)

            return {"status": "ok", "firewall": new_fw, "pushed": pushed}
        except HTTPException:
            raise  # 400/403 must propagate as-is, not be re-wrapped as 500
        # Anything else is logged and a 500.
        except Exception as e:
            logger.exception("add_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Change a firewall's setup.
    @app.put("/setup/firewalls/{firewall_id}")
    async def update_firewall(firewall_id: str, request: Request):
        """Update a firewall's config and push it to its spoke."""
        hub = app.state.hub
        # Read the changes.
        try:
            data = await request.json()
            update_data = data.get("config", {})

            # Find the firewall; unknown is a 404.
            global_config = hub.state.system_state.get("global_config", {})
            firewalls = global_config.get("firewalls", [])

            fw_index = next((i for i, fw in enumerate(firewalls) if fw["id"] == firewall_id), None)
            if fw_index is None:
                raise HTTPException(status_code=404, detail="Firewall not found")

            # OPNsense still needs API credentials after the change.
            merged = {**firewalls[fw_index], **update_data}
            if (merged.get("model") == "opnsense"
                    and not instance_vault.has_vault_ref(merged)
                    and not (merged.get("api_key") and merged.get("api_secret"))):
                raise HTTPException(status_code=400, detail="OPNsense needs both an API key and an API secret")
            # Apply the changes, check any vault reference, drop inline secrets, and save.
            firewalls[fw_index].update(update_data)
            sess = _session_user(request)
            await instance_vault.validate_ref(
                hub, firewalls[fw_index], sess, is_admin=_is_admin(sess), storage_key="firewalls")
            instance_vault.strip_inline_secrets(firewalls[fw_index], "firewalls")
            hub.state.system_state["global_config"] = global_config
            hub.state._mark_dirty()

            # Push to the spoke if connected (redeploying certs if the connection changed).
            spoke_id = firewalls[fw_index].get("spoke_id")
            if spoke_id and hub._primary_key(spoke_id) in hub.active_connections:
                push_fw = await instance_vault.overlay(hub, firewalls[fw_index], "firewalls")
                msg = _hub_msg(spoke_id, "UPDATE_CONFIG", push_fw)
                await hub.send_to_spoke(msg)
                if {"host", "port", "api_key", "api_secret", "vault_credential", "credential_ref", "spoke_id"} & set(update_data):
                    _redeploy_certs_soon(hub, spoke_id)
                return {"status": "ok", "message": "Firewall configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but associated spoke is not connected.", "pushed": False}
        except HTTPException:
            raise  # 4xx/503 must propagate as-is, not be re-wrapped as 500
        # Anything else is logged and a 500.
        except Exception as e:
            logger.exception("update_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    # Remove a firewall from the setup.
    @app.delete("/setup/firewalls/{firewall_id}")
    async def delete_firewall(firewall_id: str):
        """Delete a firewall and its cached data."""
        # Remove it from the saved list; unknown is a 404.
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        firewalls = global_config.get("firewalls", [])

        original_len = len(firewalls)
        firewalls[:] = [fw for fw in firewalls if fw["id"] != firewall_id]

        if len(firewalls) == original_len:
            raise HTTPException(status_code=404, detail="Firewall not found")

        # Save.
        hub.state.system_state["global_config"] = global_config
        hub.state._mark_dirty()
        # Drop the deleted firewall's cached data (every fw_<endpoint>
        # namespace, exact key) so it isn't served or persisted any more.
        for _ep in FW_READ_CMDS:
            entries = hub.warm_cache.get(f"fw_{_ep}") or {}
            if firewall_id in entries:
                hub.warm_drop(f"fw_{_ep}", (firewall_id,))
        return {"status": "ok", "message": f"Firewall {firewall_id} deleted."}

    # ── Network Devices: data + CRUD (/api/nw/*, /setup/nw-devices) ───────────
    # A single nw spoke manages a FLEET of switches + gateways (AOS-S / AOS-CX /
    # Juniper EX / Aruba-HPE gateway). global_config["nw_devices"] is the
    # hub-owned fleet list; each device binds to a spoke via spoke_id (unbound
    # devices fall to whatever nw spoke is connected — single-product deploy).
    # On edit/delete the bound spoke is re-pushed UPDATE_CONFIG with its
    # projected device slice (no creds stripped — system.json is runtime-only,
    # never committed). See access.filter_nw for the subnet filter contract.
