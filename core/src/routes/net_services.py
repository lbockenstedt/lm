"""DNS/LE/DHCP spoke-relay routes and shared spoke helpers."""
from api import (
    HTTPException, Request, _spoke_payload_or_raise, access, get_spoke_or_503,
    logger,
)
from cert_distribution import build_available_targets


def register(app, hub, ctx):
    """Register net_services routes on the Hub app."""
    _filter_session = ctx._filter_session
    # Explicit-tenant filter (scopes even admins by the selected tenant; delegates
    # to _filter_session when no tenant is passed). Used by DNS/DHCP so the pages
    # honor the global tenant picker like nw/ipam/firewall already do.
    _filter_tenant = ctx._filter_tenant
    # Resolves the tenant-picker selection to a tenant_id WITH an access check
    # (admin → any; multi-tenant user → owned only; None if not allowed). Used by
    # the bespoke le cert filter to scope by an explicitly-selected tenant.
    _effective_tenant = ctx._effective_tenant
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
        return get_spoke_or_503(hub, "dns", "DNS")

    def _get_le_spoke(hub):
        return get_spoke_or_503(hub, "certificates", "Certificate")

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
    async def dns_list_records(request: Request, tenant: str = None):
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
        return await _filter_tenant(request, data, "dns", ["value", "ip"], tenant)

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

    async def _dns_hosts(nets):
        """A/AAAA hostnames from BOTH DNS sources — the DNS module (Unbound spoke)
        AND every connected OPNsense firewall's Unbound host-overrides. ``nets`` =
        list of ip_network to keep (only hosts whose IP is in one), or None to keep
        ALL hosts. Returns (hostnames:set, any_source_reachable:bool)."""
        import ipaddress

        def _in(ip):
            try:
                a = ipaddress.ip_address(str(ip).strip())
            except (ValueError, AttributeError):
                return False
            return any(a in n for n in (nets or []))

        hosts = set()
        any_source = False

        def _collect(records, name_keys, ip_keys):
            for r in records if isinstance(records, list) else []:
                if not isinstance(r, dict):
                    continue
                if str(r.get("type", "A")).upper() not in ("A", "AAAA"):
                    continue
                name = ""
                for k in name_keys:
                    name = str(r.get(k) or "").strip().rstrip(".").lower()
                    if name:
                        break
                ip = next((r.get(k) for k in ip_keys if r.get(k)), None)
                if name and (nets is None or (ip and _in(ip))):
                    hosts.add(name)

        try:
            dns_data = await _relay_spoke(_get_dns_spoke(hub), "DNS_LIST", log_name="le_dns_hosts")
            any_source = True
            _collect((dns_data or {}).get("records") or [], ("name",), ("value", "ip"))
        except Exception:  # noqa: BLE001 — DNS module down; try the firewalls
            pass
        try:
            firewalls = (hub.state.system_state.get("global_config", {}) or {}).get("firewalls", []) or []
        except Exception:  # noqa: BLE001
            firewalls = []
        for sid in {fw.get("spoke_id") for fw in firewalls if fw.get("spoke_id")}:
            if hub._primary_key(sid) not in getattr(hub, "active_connections", {}):
                continue
            try:
                fres = await hub.request_response(sid, "OPNSENSE_GET_DNS_RECORDS", {}, timeout=10.0)
                any_source = True
                recs = (fres or {}).get("data") or (fres or {}).get("dns_records") \
                    or (fres or {}).get("records") or (fres if isinstance(fres, list) else [])
                _collect(recs, ("hostname", "host", "name"), ("ip", "value", "server"))
            except Exception:  # noqa: BLE001 — one bad firewall never blocks the rest
                continue
        return hosts, any_source

    async def _filter_le_certs(request, data, tenant=None):
        """Tenant subnet-filter the cert list. Certs have no IP column, so a cert is
        attributed to a tenant by resolving its SANs through the internal DNS A/AAAA
        records: a non-admin sees a cert only if one of its SANs maps to a hostname
        whose DNS IP is in the tenant's prefixes. A wildcard SAN (``*.d``) matches any
        A-record host under that domain. TWO DNS sources are consulted: the DNS
        module (Unbound spoke) AND every connected firewall's Unbound host-overrides
        (OPNsense). If BOTH DNS sources are unreachable → fail OPEN (don't hide certs
        on an outage). The cache stores the UNFILTERED list; this runs per request.

        Tenant scoping: an EXPLICIT tenant (the picker) scopes by THAT tenant's
        prefixes even for admins (matches nw/ipam/firewall); with none selected, an
        admin sees all and a session-tenant user is scoped by their own prefixes."""
        if not isinstance(data, dict) or not access.filter_enabled(hub, "le"):
            return data
        sess = _session_user(request)
        tid = _effective_tenant(request, tenant) if tenant else None
        if tenant and tid:
            # Explicit tenant selected → scope by its prefixes (admins included).
            prefixes = await access.resolve_prefixes_for_tenant(hub, tid)
            if not prefixes:
                return {**data, "certs": []}   # fail CLOSED for an explicit tenant
        else:
            if not sess or _is_admin(sess):
                return data
            prefixes = await access.resolve_prefixes(hub, sess)
            if not prefixes:
                return data
        import ipaddress
        nets = []
        for p in prefixes:
            try:
                nets.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                continue
        tenant_hosts, any_source = await _dns_hosts(nets)
        if not any_source:
            return data  # both DNS sources unreachable → fail open
        if not tenant_hosts:
            return {**data, "certs": []}

        def _match(cert):
            for san in (cert.get("domains") or []):
                s = str(san).strip().rstrip(".").lower()
                if not s:
                    continue
                if s.startswith("*."):
                    apex, suffix = s[2:], s[1:]  # "acme.com", ".acme.com"
                    if any(h == apex or h.endswith(suffix) for h in tenant_hosts):
                        return True
                elif s in tenant_hosts:
                    return True
            return False

        return {**data, "certs": [c for c in (data.get("certs") or []) if _match(c)]}

    def _bugfixer_pinned():
        """The set of DNS names designated as BugFixer certs (H1) —
        ``global_config['bugfixer_cert_identities']``. The HUB_REQUEST channel
        is gated to a connection presenting one of these over mTLS."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        # Lower-cased: le_set_bugfixer stores lowercase, and DNS names are
        # case-insensitive — so match case-insensitively (a cert whose domain
        # carries any uppercase would otherwise never show as tagged).
        return {str(n).strip().lower() for n in (gc.get("bugfixer_cert_identities") or [])}

    def _tag_bugfixer(data):
        """Tag each cert with ``bugfixer: bool`` (its domain / any SAN is in the
        pinned BugFixer list) so the LE-module UI can show the BugFixer toggle's
        state. Runs on both live + cached-stale paths."""
        if not isinstance(data, dict):
            return data
        pinned = _bugfixer_pinned()
        certs = data.get("certs") or []
        tagged = []
        for c in certs:
            if not isinstance(c, dict):
                tagged.append(c)
                continue
            names = {str(c.get("domain") or "").strip().lower()}
            for san in (c.get("domains") or []):
                names.add(str(san or "").strip().lower())
            is_bf = any(n and n in pinned for n in names)
            tagged.append({**c, "bugfixer": is_bf})
        return {**data, "certs": tagged}

    @app.get("/api/le/certs")
    async def le_list_certs(request: Request, tenant: str = None):
        """List managed certificates from the le spoke.

        Warm-cached (``le_cache``): serves last-known certs (marked ``stale``)
        when the le spoke is offline or a live fetch overruns, so the
        Certificates page renders instantly instead of blocking/503-ing. A
        successful live fetch refreshes + persists the cache. Tenant subnet
        filtering (``_filter_le_certs``) runs per request on the UNFILTERED cache.
        Each cert is also tagged ``bugfixer: bool`` (H1) from the pinned
        ``global_config['bugfixer_cert_identities']`` list."""
        logger.debug("relay GET /api/le/certs")
        hub = app.state.hub
        le_sid = hub.get_spoke_by_type("certificates")
        if not le_sid:
            cached = hub.le_cache_get("certs")
            if cached is not None:
                out = dict(cached) if isinstance(cached, dict) else {"certs": cached}
                out["stale"] = True
                return await _filter_le_certs(request, _tag_bugfixer(out), tenant)
            raise HTTPException(status_code=503, detail="Certificate spoke not connected")
        try:
            data = await _relay_spoke(le_sid, "LE_LIST_CERTS", log_name="le_list_certs")
            await hub.le_cache_set("certs", data)
            return await _filter_le_certs(request, _tag_bugfixer(data), tenant)
        except HTTPException:
            cached = hub.le_cache_get("certs")
            if cached is not None:
                out = dict(cached) if isinstance(cached, dict) else {"certs": cached}
                out["stale"] = True
                return await _filter_le_certs(request, _tag_bugfixer(out), tenant)
            raise

    @app.get("/api/le/eligible-domains")
    async def le_eligible_domains(request: Request):
        """Domains the caller can issue a cert for and still SEE it under the ``le``
        subnet filter: the A/AAAA hostnames from their tenant's DNS (both the DNS
        module and firewalls), plus a derived ``*.<domain>`` wildcard per parent
        domain. Non-admin with the filter ON → only hostnames in their prefixes;
        admin or filter OFF → all DNS hostnames. Feeds the issue-cert domain dropdown."""
        sess = _session_user(request)
        nets = None
        if sess and not _is_admin(sess) and access.filter_enabled(hub, "le"):
            import ipaddress
            nets = []
            for p in (await access.resolve_prefixes(hub, sess)) or []:
                try:
                    nets.append(ipaddress.ip_network(p, strict=False))
                except ValueError:
                    continue
        hosts, _src = await _dns_hosts(nets)
        wildcards = sorted({f"*.{h.split('.', 1)[1]}" for h in hosts if "." in h})
        return {"hosts": sorted(hosts), "wildcards": wildcards}

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
        # Refresh the hub's le_cache so a FAILED issue's new ledger entry
        # (last_issue_error) + any deploy last_status are hub-visible promptly
        # → the Certificates list + the cert-failure alert pull-branch see them
        # within the 60s alert tick (vs. up to 1h for the next distro sweep).
        if le_sid:
            asyncio.create_task(hub._le_refresh_certs_cache(le_sid))
        return payload

    @app.post("/api/le/certs/{domain}/clientauth")
    async def le_set_clientauth(domain: str, request: Request):
        """Toggle the clientAuth EKU on a managed cert and re-issue now. The ACME
        'classic'-style profile carries serverAuth+clientAuth; the default profile
        is server-only. Needed for mTLS CLIENT certs (BugFixer, the mTLS wildcard) —
        certs that don't need it stay server-only. Re-distributes the freshly-issued
        material to the cert's targets, like /api/le/issue."""
        body = await request.json()
        enabled = bool(body.get("enabled", body.get("client_auth", False))) if isinstance(body, dict) else False
        data = {"domain": domain, "client_auth": enabled, "tenant_id": _le_tenant(request)}
        hub, le_sid, payload = await _le_request("LE_SET_CLIENTAUTH", data,
                                                  timeout=_LE_CERTBOT_TIMEOUT)
        inner = _le_inner(payload)
        d = inner.get("domain") or domain
        targets = inner.get("targets") or []
        if d and le_sid:
            try:
                inner["distribution"] = await hub._distribute_one_cert(
                    le_sid, d, targets, material_hash=inner.get("material_hash"))
            except Exception as e:
                logger.warning("cert distribution after clientauth toggle failed: %s", e)
                inner["distribution"] = [{"status": "ERROR", "message": str(e)}]
            asyncio.create_task(hub._le_refresh_certs_cache(le_sid))
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
        # Refresh le_cache so on-demand renew results (last_error / deploy
        # last_status) are hub-visible promptly for the cert-failure alert
        # pull-branch + the Certificates list.
        if le_sid:
            asyncio.create_task(hub._le_refresh_certs_cache(le_sid))
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
            netbox_server_agents=set(getattr(hub, "netbox_server_agents", set())),
            ldap_server_agents=set(getattr(hub, "ldap_server_agents", set())))}

    @app.get("/api/le/wildcard/eligibility")
    async def le_wildcard_eligibility():
        """Coverage of the 'Fan wildcard → all spokes' feature: which spokes WOULD
        receive a wildcard cert (eligible) and which would NOT (ineligible + why),
        so the operator sees the reach before/while using fan-out. Mirrors exactly
        what distribute_wildcard_to_all_spokes does: every connected cert-capable
        spoke (by spoke_id) + the hub; a netbox-server host counts via its
        capability even though its base module_type is 'agent'."""
        hub = app.state.hub
        capable = hub.CERT_CAPABLE_MODULES
        known = hub.state.system_state.get("known_modules", []) or []
        module_names = hub.state.system_state.get("module_names", {}) or {}
        module_metadata = hub.state.system_state.get("module_metadata", {}) or {}
        nb_servers = set(getattr(hub, "netbox_server_agents", set()))

        def _mt(sid):
            return (hub.spoke_module_types.get(hub._primary_key(sid))
                    or (module_metadata.get(sid, {}) or {}).get("module_type"))

        eligible = [{"spoke_id": "hub", "module_type": "hub",
                     "label": "hub (LM WebUI)", "connected": True}]
        ineligible = []
        for sid in known:
            mt = _mt(sid)
            connected = hub._primary_key(sid) in hub.active_connections
            label = module_names.get(sid, sid) or sid
            is_nb_server = hub._primary_key(sid) in nb_servers
            eff_mt = "netbox-server" if (is_nb_server and mt not in capable) else mt
            eff_capable = (mt in capable) or is_nb_server
            entry = {"spoke_id": sid, "module_type": eff_mt or mt or "—",
                     "label": label, "connected": connected}
            if not connected:
                ineligible.append({**entry, "reason": "offline (not connected)"})
            elif not eff_capable:
                ineligible.append({**entry,
                                   "reason": f"module type '{mt or '—'}' does not support cert install"})
            else:
                eligible.append(entry)
        return {"enabled": hub._wildcard_all_spokes_enabled(),
                "eligible": eligible, "ineligible": ineligible,
                "eligible_count": len(eligible), "ineligible_count": len(ineligible)}

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

    @app.post("/api/le/certs/{domain}/bugfixer")
    async def le_set_bugfixer(domain: str, request: Request):
        """H1: label a managed cert as the BugFixer cert. Toggles membership of
        ``domain`` in ``global_config['bugfixer_cert_identities']`` — the pinned
        list the HUB_REQUEST channel authorizes on (a connection must present one
        of these certs over mTLS, see ``LabManagerHub._hub_request_authorized``).
        ``enabled:true`` adds the domain (dedup, order-stable); ``false`` removes
        it. Admin-only. The cert itself is issued/managed via the normal LE flow;
        this just records which domain's cert is the BugFixer identity."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        data = await request.json()
        enabled = bool(data.get("enabled")) if isinstance(data, dict) else False
        domain = (domain or "").strip().lower()
        if not domain:
            raise HTTPException(status_code=400, detail="domain required")
        gc = hub.state.system_state.get("global_config", {}) or {}
        pinned = [str(n).strip().lower() for n in (gc.get("bugfixer_cert_identities") or [])]
        if enabled:
            if domain not in pinned:
                pinned.append(domain)
        else:
            pinned = [n for n in pinned if n != domain]
        gc["bugfixer_cert_identities"] = pinned
        hub.state.system_state["global_config"] = gc
        await hub.state.save_state_now()
        logger.info("[H1] BugFixer cert label for %s -> %s (pinned=%s)",
                    domain, enabled, pinned)
        return {"status": "ok", "domain": domain, "bugfixer": enabled,
                "pinned": pinned}

    @app.get("/api/mtls/trust-diag")
    async def mtls_trust_diag(request: Request):
        """H1 debug: what the hub's mTLS client-verify path trusts, and whether it
        would ACCEPT each pinned BugFixer cert. Surfaces (a) the LM_MTLS_CA chain in
        full, (b) the combined-bundle cert count + any same-subject collisions (the
        real-vs-private 'ISRG Root X1' hazard), and (c) an openssl verify of every
        pinned cert's live chain (pulled from the le spoke) against that bundle — so
        an operator sees from the WebUI exactly why a cert is rejected. Admin-only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            from security import mtls as _mtls
        except Exception as e:  # noqa: BLE001
            return {"error": f"mtls module unavailable: {e}"}
        diag = _mtls.trust_diagnostics()
        # Test-verify each pinned BugFixer cert's live chain against the hub trust.
        gc = hub.state.system_state.get("global_config", {}) or {}
        pinned = [str(n).strip() for n in (gc.get("bugfixer_cert_identities") or []) if str(n).strip()]
        le_sid = hub.get_spoke_by_type("certificates")
        checks = []
        for domain in pinned:
            entry = {"domain": domain}
            if not le_sid:
                entry.update({"ok": False, "detail": "certificate spoke not connected"})
                checks.append(entry)
                continue
            try:
                mat = await _relay_spoke(le_sid, "LE_GET_CERT", {"domain": domain},
                                        log_name="mtls_trust_diag")
                inner = mat.get("data") if isinstance(mat, dict) and isinstance(mat.get("data"), dict) else mat
                fullchain = (inner or {}).get("fullchain") or ""
                if not fullchain:
                    entry.update({"ok": False, "detail": "le returned no fullchain for this domain"})
                else:
                    ok, detail = _mtls.verify_chain(fullchain)
                    entry.update({"ok": ok, "detail": detail})
            except Exception as e:  # noqa: BLE001
                entry.update({"ok": False, "detail": f"lookup/verify failed: {e}"})
            checks.append(entry)
        diag["pinned_cert_checks"] = checks
        return diag

    @app.get("/api/le/certs/{domain}/devices")
    async def le_target_devices(domain: str, module_type: str = "", identifier: str = ""):
        """Drill-down device list for a fleet spoke target. For nw it pulls the
        LIVE fleet from the spoke (so every switch/gateway shows even before any
        distribution) and merges each device's last cert-install status, so the
        UI can render a per-device Deploy button + status. Falls back to the
        stashed distribution report if the live fetch fails."""
        hub = app.state.hub
        rep = hub.cert_device_report(domain, module_type, identifier)
        stashed = {}
        for d in (rep.get("devices") or []):
            k = str(d.get("device_id") or d.get("name") or "")
            if k:
                stashed[k] = d
        devices = []
        if module_type == "nw":
            try:
                spoke_id = hub.get_spoke_by_type("nw")
                if spoke_id:
                    res = await hub.request_response(spoke_id, "NW_LIST_DEVICES", {}, timeout=15.0)
                    data = access.unwrap_spoke(res) or {}
                    fleet = data.get("devices") if isinstance(data, dict) else data
                    for dv in (fleet or []):
                        did = str(dv.get("id") or dv.get("device_id") or "")
                        ot = (dv.get("object_type") or "").strip().lower()
                        st = stashed.get(did) or {}
                        # cx_switch (AOS-CX REST) + gateway (ArubaOS PKCS#12/SCP)
                        # can import an external LE cert; aos_switch/ex_switch can't.
                        capable = ot in ("cx_switch", "gateway")
                        devices.append({
                            "device_id": did, "name": dv.get("name") or did,
                            "ip": dv.get("address") or dv.get("ip") or "",
                            "object_type": ot, "cert_capable": capable,
                            "status": st.get("status") or ("" if capable else "SKIPPED"),
                            "message": st.get("message") or ("" if capable
                                       else f"cert install not supported for '{ot or 'unknown'}'"),
                        })
            except Exception as e:  # noqa: BLE001 — fall back to the stash
                logger.debug("le_target_devices: live nw fleet fetch failed: %s", e)
        if not devices:
            devices = rep.get("devices") or []
        return {"status": "SUCCESS", "domain": domain, "module_type": module_type,
                "identifier": identifier, "devices": devices,
                "message": rep.get("message", ""), "aggregate_status": rep.get("status", ""),
                "at": rep.get("at", "")}

    @app.post("/api/le/certs/{domain}/devices/{device_id}/deploy")
    async def le_deploy_device(domain: str, device_id: str, request: Request):
        """Deploy a managed cert to ONE nw device (switch/gateway). Pulls the
        material from le and sends INSTALL_CERT to the nw spoke with the device's
        id, then records that device's per-device status."""
        hub = app.state.hub
        spoke_id = get_spoke_or_503(hub, "nw", "Network Devices")
        le_spoke = _get_le_spoke(hub)
        mat = await hub.request_response(le_spoke, "LE_GET_CERT", {"domain": domain}, timeout=15.0)
        m = access.unwrap_spoke(mat) or {}
        if not (isinstance(m, dict) and m.get("status") == "SUCCESS"):
            raise HTTPException(status_code=502, detail=(m or {}).get("message", "LE_GET_CERT failed"))
        cert = m.get("data") or {}
        try:
            res = await hub.request_response(spoke_id, "INSTALL_CERT", {
                "domain": domain, "fullchain": cert.get("fullchain", ""),
                "privkey": cert.get("privkey", ""), "chain": cert.get("chain", ""),
                "identifier": device_id, "module_type": "nw"}, timeout=120.0)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"deploy failed: {e}")
        r = access.unwrap_spoke(res) or {}
        hub.update_cert_device_status(domain, "nw", "", device_id, r)
        return {"status": "ok", "device_id": device_id,
                "result_status": r.get("status", ""), "message": r.get("message", "")}

    @app.delete("/api/le/certs/{domain}/targets/{idx}")
    async def le_remove_target(domain: str, idx: int):
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_REMOVE_TARGET",
                                  {"domain": domain, "idx": idx},
                                  log_name="le_remove_target")

    # ─── DHCP API ─────────────────────────────────────────────────────────────

    def _get_dhcp_spoke(hub):
        return get_spoke_or_503(hub, "dhcp", "DHCP")

    @app.get("/api/dhcp/subnets")
    async def dhcp_list_subnets(request: Request, tenant: str = None):
        """List DHCP subnets configured on the Kea spoke, subnet-filtered per
        the caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). The subnet's ``subnet`` field is a CIDR; the
        filter matches it against the tenant's NetBox prefixes by overlap, so a
        non-admin sees only their own tenant's subnets. Admins always see all.
        Unfiltered when the subnet-filter toggle is off (shared single-view Kea)."""
        logger.debug("relay GET /api/dhcp/subnets")
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_SUBNETS", log_name="dhcp_list_subnets")
        return await _filter_tenant(request, data, "dhcp", ["subnet"], tenant)

    @app.get("/api/dhcp/leases")
    async def dhcp_list_leases(request: Request, subnet: str = None, tenant: str = None):
        """List DHCP leases (optionally per-subnet); subnet-filtered before return."""
        logger.debug("relay %s %s subnet=%s", request.method, request.url.path, subnet)
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_LEASES", {"subnet": subnet}, log_name="dhcp_list_leases")
        return await _filter_tenant(request, data, "dhcp", ["ip", "address"], tenant)

    @app.post("/api/dhcp/reservation")
    async def dhcp_add_reservation(request: Request):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_ADD_RES", body, log_name="dhcp_add_reservation")

    @app.get("/api/dhcp/reservations")
    async def dhcp_list_reservations(request: Request, tenant: str = None):
        """List DHCP reservations from the Kea spoke, subnet-filtered per the
        caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). A reservation's ``ip`` is matched against
        the tenant's NetBox prefixes, so a non-admin sees only their own
        tenant's reservations (hostname/MAC/client-id are tenant-identifying).
        Admins always see all. Unfiltered when the toggle is off."""
        logger.debug("relay GET /api/dhcp/reservations")
        data = await _relay_spoke(_get_dhcp_spoke(app.state.hub), "DHCP_LIST_RES", log_name="dhcp_list_reservations")
        return await _filter_tenant(request, data, "dhcp", ["ip"], tenant)

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
