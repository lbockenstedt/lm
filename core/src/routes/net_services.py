"""DNS/LE/DHCP spoke-relay routes and shared spoke helpers."""
from api import (
    HTTPException, Request, _spoke_payload_or_raise, access, logger,
)
from cert_distribution import build_available_targets


def register(app, hub, ctx):
    """Register net_services routes on the Hub app."""
    _filter_session = ctx._filter_session
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    async def _constrain_shared_write(request, record, fields, kind):
        """Constrained-write gate for the SHARED DNS/DHCP servers. Global Admin →
        unrestricted. Otherwise (a tenant-admin — the middleware already required
        can_edit_shared) the record's IP must fall within the caller's tenant
        subnets (access.record_in_tenant_scope); else 403. So a tenant-admin may
        only add/edit/delete records addressed within their own prefixes."""
        sess = _session_user(request)
        if _is_admin(sess):
            return
        if not await access.record_in_tenant_scope(hub, sess, record, fields):
            raise HTTPException(
                status_code=403,
                detail=f"On the shared DNS/DHCP server you may only modify a {kind} whose address is in your tenant's subnets")

    def _get_dns_spoke(hub):
        spoke_id = hub.get_spoke_by_type("dns")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="DNS spoke not connected")
        return spoke_id

    def _get_le_spoke(hub):
        spoke_id = hub.get_spoke_by_type("certificates")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="Certificate spoke not connected")
        return spoke_id

    async def _relay_spoke(spoke_id, command, payload=None, log_name="", timeout=None):
        """Relay ``command`` to a spoke and return its SUCCESS payload.

        Shared core of every DNS/DHCP relay handler (10 routes were near-
        identical get-spoke → request_response → unwrap → except→500 blocks).
        The spoke contract is ``{status: "SUCCESS", ...}`` / ``{status:
        "ERROR", message|error}``; previously the hub passed an ERROR payload
        back at HTTP 200, which was the last residual hold-out from the API
        error-contract migration (every other spoke-relay group raises on
        spoke-down). An upstream that responded with an error is now translated
        to HTTP 502 (Bad Gateway) carrying the spoke's message as ``detail``,
        matching the NetBox/CPPM relay contract. The success body — the spoke's
        full SUCCESS dict — is returned verbatim so existing field access
        (``data["records"]`` / ``data["subnets"]`` …) is unchanged. Spoke-down
        (503) is raised by the ``_get_*_spoke`` caller before we run.

        ``timeout`` overrides the request_response default (5s) for long-running
        spoke commands — e.g. LE certbot issuance/renewal/revoke, which can run
        certbot for up to ~180s.
        """
        hub = app.state.hub
        try:
            kw = {"timeout": timeout} if timeout else {}
            result = await hub.request_response(spoke_id, command, payload or {}, **kw)
            data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return _spoke_payload_or_raise(data)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("%s relay failed", log_name or command)
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/dns/records")
    async def dns_list_records(request: Request):
        """List DNS records from the Unbound spoke, subnet-filtered per the
        caller's tenant when the ``dns`` subnet-filter module is enabled.

        Unfiltered by default (DNS is largely a shared single-view Unbound, and
        records can be non-IP CNAME/TXT that the IP-prefix filter would hide).
        A multi-tenant deployment enables the ``dns`` subnet-filter toggle so a
        non-admin sees only A/PTR records whose value (IP) is in their own
        tenant's NetBox prefixes (mirrors /api/dhcp/leases). Admins always see
        all records."""
        logger.debug("relay GET /api/dns/records")
        data = await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_LIST", log_name="dns_list_records")
        return await _filter_session(request, data, "dns", ["value", "ip"])

    @app.post("/api/dns/record")
    async def dns_add_record(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_ADD", body, log_name="dns_add_record")

    @app.delete("/api/dns/record")
    async def dns_delete_record(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_DELETE", body, log_name="dns_delete_record")

    @app.put("/api/dns/record")
    async def dns_update_record(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_UPDATE", body, log_name="dns_update_record")

    @app.get("/api/dns/status")
    async def dns_status():
        """Unbound service status / health from the DNS spoke."""
        logger.debug("relay GET /api/dns/status")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_STATUS", log_name="dns_status")

    @app.get("/api/dns/stats")
    async def dns_stats():
        """Unbound query statistics (total/cache-hit/recursion + per-type) for
        the DNS analytics panel."""
        logger.debug("relay GET /api/dns/stats")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_STATS", log_name="dns_stats")

    @app.get("/api/dns/forwarders")
    async def dns_forwarders():
        """Configured upstream forwarders (per-zone upstream servers)."""
        logger.debug("relay GET /api/dns/forwarders")
        return await _relay_spoke(_get_dns_spoke(app.state.hub), "DNS_FORWARDERS", log_name="dns_forwarders")

    @app.post("/api/dns/sync")
    async def dns_sync_from_netbox():
        """
        Fetch all IPs with a dns_name from NetBox and sync them to Unbound.
        Requires both NetBox spoke and DNS spoke to be connected. Delegates to
        the shared DnsDhcpSyncMixin helper so the manual button and the periodic
        auto-sync loop build the identical payload.
        """
        hub = app.state.hub
        result = await hub.sync_dns_from_netbox()
        if result.get("status") == "skipped":
            raise HTTPException(status_code=503, detail=result.get("reason", "spoke not connected"))
        if result.get("status") == "error":
            raise HTTPException(status_code=500, detail=result.get("error", "sync failed"))
        return result

    @app.get("/api/dns-dhcp/sync-status")
    async def dns_dhcp_sync_status():
        """Last-run status + config for the NetBox→Unbound/Kea auto-sync loop
        (fuels the DNS/DHCP status tiles). Read-only, authed (under /api/)."""
        hub = app.state.hub
        gc = hub.state.system_state.get("global_config", {}) or {}
        cfg = gc.get("dns_dhcp_sync", {}) or {}
        return {
            "status": hub.dns_dhcp_sync_status,
            "config": {
                "enabled":  bool(cfg.get("enabled", True)),
                "interval": int(cfg.get("interval", 300) or 300),
            },
        }

    # ─── Certificate Management (le) API ──────────────────────────────────────
    # Relays LE_* commands to the certificates spoke via _relay_spoke (same
    # SUCCESS/ERROR contract + 502-on-spoke-error as DNS/DHCP). The le spoke
    # owns certbot (issue/renew/revoke) + the cert ledger; the HUB is the
    # transport for cert material from le to each cert's target spokes — issue
    # and renew inline-trigger hub._distribute_one_cert (LE_GET_CERT →
    # INSTALL_CERT per target → LE_MARK_DISTRIBUTED), and a background
    # run_cert_distribution_loop re-pushes stale targets hourly.

    # Hub-side wait for a certbot ACME run. The le spoke caps certbot at 180s
    # (acme._run timeout), so 200s gives margin; the request_response default
    # (5s) timed out long before certbot finished — "Issue failed: Timed out
    # waiting for spoke response" even though issuance was still running.
    _LE_CERTBOT_TIMEOUT = 200.0

    def _le_inner(payload):
        """The le spoke returns nested {status, data:{...}}; pull out data."""
        if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
            return payload["data"]
        return payload if isinstance(payload, dict) else {}

    async def _le_request(command, body, timeout=None):
        """Relay command to the le spoke; return (hub, le_sid, payload) with the
        SUCCESS payload (raises 502/503/500 on spoke error/down). ``timeout``
        overrides the request_response default (5s) for long-running certbot
        commands (issue/renew/revoke — certbot can run up to ~180s)."""
        hub = app.state.hub
        le_sid = _get_le_spoke(hub)
        try:
            kw = {"timeout": timeout} if timeout else {}
            result = await hub.request_response(le_sid, command, body or {}, **kw)
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("%s relay failed", command)
            raise HTTPException(status_code=500, detail=str(e))
        ret = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
        return hub, le_sid, _spoke_payload_or_raise(ret)

    @app.post("/api/le/he-config")
    async def le_set_he_login(request: Request):
        """Store the Hurricane Electric account-login knob on the le spoke, so the
        email/password is reused for every he-login issue/renew instead of typed
        each time. Admin-only (shared-infra write); the spoke persists it 0600."""
        _hub, _sid, payload = await _le_request("LE_SET_HE_LOGIN", await request.json())
        return payload

    @app.get("/api/le/he-config")
    async def le_get_he_login():
        """Whether the HE account-login knob is configured (never returns the
        password) — drives the Setup knob's 'configured' state."""
        _hub, _sid, payload = await _le_request("LE_GET_HE_LOGIN", {})
        return payload

    # ── Per-tenant multi-provider DNS-01 credential store ────────────────────
    # Each tenant manages its OWN named DNS credentials (HE / Cloudflare /
    # rfc2136 / route53). tenant_id is derived from the session and injected into
    # the le command — NEVER taken from the request body — so one tenant can't
    # read or write another's creds.
    def _le_tenant(request):
        sess = _session_user(request)
        return ((sess.get("user", {}).get("tenant_id") if sess else None) or "default")

    @app.get("/api/le/dns-credentials")
    async def le_list_dns_creds(request: Request):
        """This tenant's saved DNS-01 credentials (names + providers; NO secrets),
        plus the provider field catalog for the editor."""
        _hub, _sid, payload = await _le_request(
            "LE_LIST_DNS_CREDS", {"tenant_id": _le_tenant(request)})
        return payload

    @app.post("/api/le/dns-credentials")
    async def le_set_dns_cred(request: Request):
        """Add/update one of THIS tenant's DNS-01 credentials. Empty secret fields
        keep the stored value (sentinel-merge)."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        body["tenant_id"] = _le_tenant(request)  # server-derived; ignore any client value
        _hub, _sid, payload = await _le_request("LE_SET_DNS_CRED", body)
        return payload

    @app.delete("/api/le/dns-credentials")
    async def le_delete_dns_cred(request: Request):
        """Delete one of this tenant's DNS-01 credentials by name."""
        body = await request.json()
        name = (body.get("name") if isinstance(body, dict) else None)
        _hub, _sid, payload = await _le_request(
            "LE_DELETE_DNS_CRED", {"tenant_id": _le_tenant(request), "name": name})
        return payload

    @app.get("/api/le/certs")
    async def le_list_certs():
        """List managed certificates from the le spoke."""
        logger.debug("relay GET /api/le/certs")
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_LIST_CERTS",
                                  log_name="le_list_certs")

    @app.get("/api/le/inflight")
    async def le_inflight():
        """Targets the hub is currently pushing INSTALL_CERT to (waiting on
        deployment confirmation). Hub-side — not relayed to the le spoke. The
        WebUI merges this onto the cert target badges (yellow + elapsed timer)
        so the operator can see what's in flight, since we can't predict how
        fast a cert will transfer or install (hypervisor pveproxy restart can
        take many minutes). Cleared the moment a push returns."""
        hub = app.state.hub
        items = list(getattr(hub, "cert_dist_inflight", {}).values())
        return {"status": "SUCCESS", "inflight": items}

    @app.get("/api/le/status")
    async def le_status():
        """le spoke module status (version, certbot present, cert count)."""
        logger.debug("relay GET /api/le/status")
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_GET_STATUS",
                                  log_name="le_status")

    @app.post("/api/le/issue")
    async def le_issue_cert(request: Request):
        """Issue a cert via the le spoke, then hub-broker the new material to
        its targets. Returns the spoke result with an added ``distribution``
        per-target summary. Injects the session tenant so a named DNS credential
        (``dns_credential``) resolves against THIS tenant's store."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        body["tenant_id"] = _le_tenant(request)  # server-derived; scopes dns_credential
        hub, le_sid, payload = await _le_request("LE_ISSUE_CERT", body,
                                                  timeout=_LE_CERTBOT_TIMEOUT)
        inner = _le_inner(payload)
        domain = inner.get("domain")
        targets = inner.get("targets") or []
        dist = []
        # Always invoke distribution (even with no targets) so the no-targets
        # skip is logged under Certificates — otherwise a freshly-issued cert
        # with no targets is a silent no-op and the operator can't tell why
        # nothing deployed. distribute_cert_to_targets handles the empty case.
        if domain:
            try:
                dist = await hub._distribute_one_cert(le_sid, domain, targets,
                                                      material_hash=inner.get("material_hash"))
            except Exception as e:
                logger.warning("cert distribution after issue failed: %s", e)
                dist = [{"status": "ERROR", "message": str(e)}]
        inner["distribution"] = dist
        return payload

    @app.post("/api/le/renew")
    async def le_renew_cert(request: Request):
        """Renew one (body.domain) or all managed certs via the le spoke, then
        hub-broker renewed material to each renewed cert's targets. Returns the
        spoke result with per-cert + aggregate ``distribution`` summaries."""
        hub, le_sid, payload = await _le_request("LE_RENEW_CERT", await request.json(),
                                                  timeout=_LE_CERTBOT_TIMEOUT)
        inner = _le_inner(payload)
        agg = []
        for r in inner.get("renewed") or []:
            if r.get("renewed") and r.get("domain") and r.get("targets"):
                try:
                    d = await hub._distribute_one_cert(le_sid, r["domain"], r["targets"],
                                                       material_hash=r.get("material_hash"))
                    r["distribution"] = d
                    agg.extend(d)
                except Exception as e:
                    logger.warning("cert distribution after renew failed for %s: %s",
                                   r.get("domain"), e)
                    r["distribution"] = [{"status": "ERROR", "message": str(e)}]
                    agg.extend(r["distribution"])
        inner["distribution"] = agg
        return payload

    @app.post("/api/le/revoke")
    async def le_revoke_cert(request: Request):
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_REVOKE_CERT",
                                  await request.json(), log_name="le_revoke_cert",
                                  timeout=_LE_CERTBOT_TIMEOUT)

    @app.post("/api/le/distribute")
    async def le_distribute():
        """Re-push any stale cert material to its targets now (no certbot
        invocation — just LE_GET_CERT → INSTALL_CERT for targets whose
        last_pushed_hash differs). Returns the refreshed cert list (for the
        table) with an added ``distribution`` per-target summary so the UI can
        show a per-target toast — mirrors /api/le/issue. Without the summary,
        Distribute now gave the UI zero feedback (results were only in
        Logs/Certificates, which needs a manual refresh)."""
        hub = app.state.hub
        le_sid = _get_le_spoke(hub)
        try:
            dist = await hub._distribute_all_certs(le_sid)
        except Exception as e:
            logger.exception("le_distribute failed")
            raise HTTPException(status_code=500, detail=str(e))
        payload = await _relay_spoke(le_sid, "LE_LIST_CERTS", log_name="le_distribute")
        _le_inner(payload)["distribution"] = dist or []
        return payload

    @app.post("/api/le/certs/{domain}/distribute")
    async def le_distribute_target(domain: str, request: Request):
        """Re-push cert material for ``domain`` to ONE target only — the
        per-target click-to-deploy in the LE table (click a spoke/agent badge
        → deploy this cert to that target). Mirrors /api/le/issue's
        single-cert distribution but narrows to a single target so the operator
        can re-deploy to a failed node without re-pushing every target. The
        target dict is built WITHOUT ``last_pushed_hash``/``last_status``, so
        ``distribute_cert_to_targets``' skip-check never short-circuits — a
        click is an explicit re-deploy, even on an already-green target. Returns
        a one-entry per-target summary."""
        body = await request.json()
        if not isinstance(body, dict) or not body.get("module_type"):
            raise HTTPException(status_code=400, detail="module_type required")
        target = {"module_type": body["module_type"],
                  "identifier": body.get("identifier") or ""}
        hub = app.state.hub
        le_sid = _get_le_spoke(hub)
        try:
            dist = await hub._distribute_one_cert(le_sid, domain, [target])
        except Exception as e:
            logger.exception("le_distribute_target failed")
            raise HTTPException(status_code=500, detail=str(e))
        return {"status": "SUCCESS", "distribution": dist or []}

    @app.get("/api/le/targets/available")
    async def le_available_targets():
        """All connected spokes/agents this cert could be distributed to — the
        click-to-add list in the LE targets modal ("list all available targets
        so I can click and add that agent/module"). One entry per cert-capable
        connected spoke (by module_type), EXCEPT agent-hosting types
        (hypervisor/simulation) which list EACH connected pxmx agent as a
        per-node target (identifier = agent_id) plus an "all nodes" broadcast
        entry per connected spoke of those types. Offline / non-cert-capable
        spokes are omitted — they'd only ERROR on distribute. Returns
        {targets: [{module_type, identifier, label, spoke_id?}]}. The per-node
        agent list reuses the /api/pxmx/agents stale-while-revalidate cache so
        opening the modal doesn't block on a fresh GET_AGENTS fan-out. List
        shaping is in cert_distribution.build_available_targets (pure, tested)."""
        hub = app.state.hub
        agent_spokes = list(dict.fromkeys(
            hub.get_all_spokes_by_type("hypervisor")
            + hub.get_all_spokes_by_type("simulation")))
        agents: list = []
        if agent_spokes:
            try:
                from routes import pxmx as _pxmx
                agg = await _pxmx._maybe_refresh_agents(hub, agent_spokes)
                agents = (agg or {}).get("agents", []) or []
            except Exception as e:  # noqa: BLE001 - modal still usable w/o agents
                logger.debug("le_available_targets: agents gather failed: %s", e)
        module_names = hub.state.system_state.get("module_names", {}) or {}
        return {"targets": build_available_targets(
            dict(hub.spoke_module_types), hub.active_connections,
            module_names, hub.CERT_CAPABLE_MODULES, agents,
            netbox_server_agents=set(getattr(hub, "netbox_server_agents", set())))}

    # ── per-cert distribution targets ──────────────────────────────────────────
    # Each target = {module_type, identifier?} describing which spoke/device a
    # cert should be installed on. The hub resolves the spoke by module_type and
    # pushes INSTALL_CERT; the target spoke applies the cert to its own device.

    @app.get("/api/le/certs/{domain}/targets")
    async def le_list_targets(domain: str):
        payload = await _relay_spoke(_get_le_spoke(app.state.hub), "LE_LIST_CERTS",
                                     log_name="le_list_targets")
        for c in _le_inner(payload).get("certs") or []:
            if c.get("domain") == domain:
                return {"status": "SUCCESS", "targets": c.get("targets", [])}
        raise HTTPException(status_code=404, detail=f"no managed cert for {domain}")

    @app.post("/api/le/certs/{domain}/targets")
    async def le_add_target(domain: str, request: Request):
        body = await request.json()
        if not isinstance(body, dict) or not body.get("module_type"):
            raise HTTPException(status_code=400, detail="module_type required")
        hub = app.state.hub
        mt = str(body.get("module_type") or "").strip()
        # Defense-in-depth: reject a target the UI would never offer. The UI
        # dropdown is fed by /api/le/targets/available (installed + has-device),
        # but the API is open — enforce at least "cert-capable + installed" here
        # so a stale UI / direct API call can't store a target that can only
        # ERROR at distribute time. The hub self-install target ("hub") is always
        # allowed (the hub is always installed). The "has a device" half for
        # agent-hosting types is enforced by the UI (live agents list).
        if mt not in hub.CERT_CAPABLE_MODULES:
            raise HTTPException(
                status_code=400,
                detail=f"module type '{mt}' does not support cert install")
        if mt != "hub" and not hub.get_spoke_by_type(mt):
            raise HTTPException(
                status_code=400,
                detail=f"no connected '{mt}' spoke — install/connect it first")
        # One cert per target: a module/agent already assigned to ANOTHER managed
        # cert is ineligible (a device serves a single TLS cert per endpoint).
        # Reject naming the owning domain so the operator removes it there first.
        ident = str(body.get("identifier") or "")
        try:
            all_certs = _le_inner(await _relay_spoke(
                _get_le_spoke(hub), "LE_LIST_CERTS", log_name="le_add_target_conflict")).get("certs") or []
        except HTTPException:
            raise
        except Exception as e:  # noqa: BLE001 — don't block add if the ledger read fails
            all_certs = []
            logger.debug("le_add_target: conflict pre-check skipped: %s", e)
        for c in all_certs:
            if c.get("domain") == domain:
                continue
            for t in c.get("targets") or []:
                if str(t.get("module_type") or "") == mt and str(t.get("identifier") or "") == ident:
                    tgt_label = f"{mt}{('/' + ident) if ident else ''}"
                    raise HTTPException(
                        status_code=409,
                        detail=f"{tgt_label} is already assigned to the cert for "
                               f"'{c.get('domain')}'. A target can host only one cert — "
                               f"remove it there first.")
        return await _relay_spoke(_get_le_spoke(hub), "LE_ADD_TARGET",
                                  {"domain": domain, "target": body},
                                  log_name="le_add_target")

    @app.delete("/api/le/certs/{domain}/targets/{idx}")
    async def le_remove_target(domain: str, idx: int):
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_REMOVE_TARGET",
                                  {"domain": domain, "idx": idx},
                                  log_name="le_remove_target")

    # ─── DHCP API ─────────────────────────────────────────────────────────────

    def _get_dhcp_spoke(hub):
        spoke_id = hub.get_spoke_by_type("dhcp")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="DHCP spoke not connected")
        return spoke_id

    @app.get("/api/dhcp/subnets")
    async def dhcp_list_subnets(request: Request):
        """List DHCP subnets configured on the Kea spoke, subnet-filtered per
        the caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). The subnet's ``subnet`` field is a CIDR; the
        filter matches it against the tenant's NetBox prefixes by overlap, so a
        non-admin sees only their own tenant's subnets. Admins always see all.
        Unfiltered when the subnet-filter toggle is off (shared single-view Kea)."""
        logger.debug("relay GET /api/dhcp/subnets")
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_SUBNETS", log_name="dhcp_list_subnets")
        return await _filter_session(request, data, "dhcp", ["subnet"])

    @app.get("/api/dhcp/leases")
    async def dhcp_list_leases(request: Request, subnet: str = None):
        """List DHCP leases (optionally per-subnet); subnet-filtered before return."""
        logger.debug("relay %s %s subnet=%s", request.method, request.url.path, subnet)
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_LEASES", {"subnet": subnet}, log_name="dhcp_list_leases")
        return await _filter_session(request, data, "dhcp", ["ip", "address"])

    @app.post("/api/dhcp/reservation")
    async def dhcp_add_reservation(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_ADD_RES", body, log_name="dhcp_add_reservation")

    @app.get("/api/dhcp/reservations")
    async def dhcp_list_reservations(request: Request):
        """List DHCP reservations from the Kea spoke, subnet-filtered per the
        caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). A reservation's ``ip`` is matched against
        the tenant's NetBox prefixes, so a non-admin sees only their own
        tenant's reservations (hostname/MAC/client-id are tenant-identifying).
        Admins always see all. Unfiltered when the toggle is off."""
        logger.debug("relay GET /api/dhcp/reservations")
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_RES", log_name="dhcp_list_reservations")
        return await _filter_session(request, data, "dhcp", ["ip"])

    @app.put("/api/dhcp/reservation")
    async def dhcp_update_reservation(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_UPDATE_RES", body, log_name="dhcp_update_reservation")

    @app.delete("/api/dhcp/reservation")
    async def dhcp_delete_reservation(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_DEL_RES", body, log_name="dhcp_delete_reservation")

    @app.get("/api/dhcp/status")
    async def dhcp_status():
        """Kea DHCP4 service status / health from the DHCP spoke."""
        logger.debug("relay GET /api/dhcp/status")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_STATUS", log_name="dhcp_status")

    @app.get("/api/dhcp/stats")
    async def dhcp_stats():
        """Kea DHCP4 statistics — global + per-subnet pool utilization and the
        headline packet counters for the DHCP analytics panel."""
        logger.debug("relay GET /api/dhcp/stats")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_STATS", log_name="dhcp_stats")

    @app.post("/api/dhcp/sync")
    async def dhcp_sync_from_netbox():
        """
        Fetch NetBox prefixes and IP-to-MAC reservations, sync to Kea DHCP4.
        Delegates to the shared DnsDhcpSyncMixin helper so the manual button and
        the periodic auto-sync loop build the identical payload.
        """
        hub = app.state.hub
        result = await hub.sync_dhcp_from_netbox()
        if result.get("status") == "skipped":
            raise HTTPException(status_code=503, detail=result.get("reason", "spoke not connected"))
        if result.get("status") == "error":
            raise HTTPException(status_code=500, detail=result.get("error", "sync failed"))
        return result

    # ── Cache management (/admin/cache/*, /setup/cache-config) ───────────────
