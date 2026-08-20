"""DNS/LE/DHCP spoke-relay routes and shared spoke helpers."""
import asyncio
import time
from api import (
    HTTPException, Request, _spoke_payload_or_raise, access, get_spoke_or_503,
    logger, spoke_or_503,
)
from cert_distribution import build_available_targets, target_owner_tenant
import le_cert_access as _lca


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

    # ── tenant-aware DNS spoke resolution ───────────────────────────────────
    # Multiple ``dns`` spokes may be connected, each bound to a different
    # tenant (a tenant runs their own Unbound server). Every DNS route below
    # used to resolve via ``_get_dns_spoke`` — the first connected dns spoke,
    # full stop — so with more than one dns spoke connected, EVERY tenant's
    # request silently hit whichever spoke connected first. DNS is commonly
    # deployed as ONE shared Unbound server (see the record-level subnet
    # filtering below, which stays the primary isolation for that case) —
    # this resolver only changes behavior once a SECOND dns spoke connects.
    def _dns_spoke_for_request(request: Request, tenant: str = None):
        """The dns spoke that should answer THIS request, or a 503 (matches
        the ``get_spoke_or_503``/``_get_dns_spoke`` contract every caller here
        already relies on — ``_relay_spoke`` itself does NOT check for a
        falsy spoke_id, it trusts the resolver already raised). Prefers the
        caller's effective tenant's own ``dns_instances`` record (a tenant-
        admin's self-configured DNS connection via
        ``/tenant/devices/dns-instances``), falling back to a spoke bound to
        that tenant by module_type, then the shared-tenant spoke. Admin with
        no tenant selected keeps the legacy global-first-connected-spoke
        behavior — see ``_dns_merge_fanout`` for the admin combined view."""
        hub = app.state.hub
        tid = _effective_tenant(request, tenant)
        if not tid:
            return spoke_or_503(hub.get_spoke_by_type("dns"), "DNS")
        instances = (hub.state.system_state.get("global_config", {}) or {}).get("dns_instances", []) or []
        inst = next((i for i in instances if isinstance(i, dict) and i.get("tenant_id") == tid), None)
        spoke_id = (inst or {}).get("spoke_id") or ""
        if spoke_id and hub._primary_key(spoke_id) in hub.active_connections:
            return spoke_id
        resolved = (hub.get_dns_spoke_for_shared()
                   if access.tenant_is_shared(tid)
                   else hub.get_dns_spoke_for_tenant(tid))
        return spoke_or_503(resolved, "DNS")

    async def _dns_merge_fanout(cmd: str, payload: dict, list_key: str):
        """Admin, no tenant selected: fan ``cmd`` out to EVERY connected,
        approved dns spoke, tag each returned record with its spoke's owning
        tenant (``_tenant``), and merge — 'combine the data at the hub'
        instead of only ever seeing whichever spoke happened to connect
        first. Mirrors cppm.py's ``_nac_merge_fanout``."""
        hub = app.state.hub
        spokes = [s for s in (hub.get_all_spokes_by_type("dns") or [])
                  if s in hub.active_connections and hub.approved_modules.get(s, False)]
        if not spokes:
            raise HTTPException(status_code=503, detail="No spoke connected")

        async def _one(sid):
            try:
                result = await hub.request_response(sid, cmd, payload or {})
                data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
                data = _spoke_payload_or_raise(data)
            except Exception as e:  # noqa: BLE001 — one bad/offline spoke must not fail the merge
                logger.debug("dns merge fanout: %s failed: %s", sid, e)
                return []
            recs = data.get(list_key) if isinstance(data, dict) else None
            if not isinstance(recs, list):
                return []
            tid = hub.state.get_spoke_tenant(sid) or ""
            return [{**r, "_tenant": tid} if isinstance(r, dict) else r for r in recs]

        merged = [r for recs in await asyncio.gather(*[_one(s) for s in spokes]) for r in recs]
        return {list_key: merged, "total": len(merged)}

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
        all records.

        Admin with no tenant selected AND 2+ dns spokes connected: records
        are combined across every spoke (tagged _tenant) rather than only
        ever the first-connected one — see _dns_merge_fanout."""
        logger.debug("relay GET /api/dns/records tenant=%s", tenant)
        sess = _session_user(request)
        tid = _effective_tenant(request, tenant)
        if not tid and sess and _is_admin(sess) and len(hub.get_all_spokes_by_type("dns") or []) > 1:
            data = await _dns_merge_fanout("DNS_LIST", {}, "records")
        else:
            data = await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_LIST", log_name="dns_list_records")
        return await _filter_tenant(request, data, "dns", ["value", "ip"], tenant)

    @app.post("/api/dns/record")
    async def dns_add_record(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_ADD", body, log_name="dns_add_record")

    @app.delete("/api/dns/record")
    async def dns_delete_record(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_DELETE", body, log_name="dns_delete_record")

    @app.put("/api/dns/record")
    async def dns_update_record(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "value"], "DNS record")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_UPDATE", body, log_name="dns_update_record")

    @app.get("/api/dns/status")
    async def dns_status(request: Request, tenant: str = None):
        """Unbound service status / health from the DNS spoke."""
        logger.debug("relay GET /api/dns/status")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_STATUS", log_name="dns_status")

    @app.get("/api/dns/stats")
    async def dns_stats(request: Request, tenant: str = None):
        """Unbound query statistics (total/cache-hit/recursion + per-type) for
        the DNS analytics panel."""
        logger.debug("relay GET /api/dns/stats")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_STATS", log_name="dns_stats")

    @app.get("/api/dns/forwarders")
    async def dns_forwarders(request: Request, tenant: str = None):
        """Configured upstream forwarders (per-zone upstream servers)."""
        logger.debug("relay GET /api/dns/forwarders")
        return await _relay_spoke(_dns_spoke_for_request(request, tenant), "DNS_FORWARDERS", log_name="dns_forwarders")

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
            raise HTTPException(status_code=503, detail=result.get("reason", "No spoke connected"))
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

    # ─── Hurricane Electric (HE.NET) public-DNS API ───────────────────────────
    # The public-address-space analogue of the DNS (Unbound) routes above:
    # relays HENET_* commands to the ``henet`` spoke via _relay_spoke (same
    # SUCCESS/ERROR + 502-on-spoke-error contract). The HE DDNS key is a secret
    # and is NEVER held on the spoke — it lives in the hub Credential Vault; the
    # write routes resolve a ``henet_vault_credential`` {bucket,name} reference
    # unattended via cred_vault.automation_get and inject ``ddns_key`` into the
    # relayed command, mirroring LE's _le_resolve_vault_dns_cred.
    #
    # Per-tenant model: each record now carries an explicit ``tenant_id`` —
    # "" for a Global-Admin-managed (shared/global) record, or the owning
    # tenant's id. A tenant may configure its OWN default DDNS credential
    # (global_config['henet']['tenant_credentials'][tenant_id], a sibling of
    # the existing global 'vault_credential' slot) and add/edit/delete only
    # its own records; Global Admin sees + manages everything (global + every
    # tenant's), optionally acting "as" one tenant via an explicit ``tenant``
    # field/param. SYNC (bulk replace-the-managed-set) and IMPORT (scrape the
    # whole HE.NET account) have no per-object scope and stay Global-Admin-only
    # (see api.py _ADMIN_INFRA_WRITE_PREFIXES) — replacing/importing the WHOLE
    # set would blow away other tenants' records if opened up per-tenant.
    def _get_henet_spoke(hub):
        return get_spoke_or_503(hub, "henet", "HE.NET")

    def _henet_update_cfg(hub, **fields):
        """Merge-safe update of global_config['henet'].

        ``hub.state.update_global_config()`` only shallow-replaces the WHOLE
        top-level key it's given — passing ``{"henet": {"tenant_credentials":
        {...}}}`` would silently wipe the sibling ``vault_credential`` (and
        vice versa). Read-modify-write the full sub-dict here instead."""
        gc = hub.state.get_global_config() or {}
        henet_cfg = dict(gc.get("henet") or {})
        henet_cfg.update(fields)
        hub.state.update_global_config({"henet": henet_cfg})

    def _henet_get_assigned_cred(hub, tenant_id=None):
        """The assigned HE DDNS credential reference for ``tenant_id`` (a
        non-secret ``{bucket, name}`` vault reference), or the module-level
        GLOBAL one when ``tenant_id`` is falsy. Persisted in global config
        under ``henet.tenant_credentials[tenant_id]`` / ``henet.vault_credential``
        respectively, so add/sync don't have to re-pick the credential on
        every write."""
        gc = hub.state.get_global_config() or {}
        henet_cfg = gc.get("henet") or {}
        if tenant_id:
            ref = (henet_cfg.get("tenant_credentials") or {}).get(tenant_id)
        else:
            ref = henet_cfg.get("vault_credential")
        if isinstance(ref, dict) and (ref.get("bucket") or "").strip() and (ref.get("name") or "").strip():
            return {"bucket": ref["bucket"].strip(), "name": ref["name"].strip()}
        return None

    def _henet_tenant_scope(sess, explicit_tenant=None):
        """Server-authoritative tenant scope for a HE.NET record/credential.

        A non-admin's OWN tenant always wins — never client-choosable, exactly
        like LE's ``_le_tenant`` — so one tenant can't read or write another's
        records by passing a different id. Global Admin may explicitly target
        ONE tenant (managing on its behalf) via ``explicit_tenant``, or omit it
        for the global/shared scope (``""``)."""
        if not _is_admin(sess):
            return (sess.get("user", {}) or {}).get("tenant_id") or "default"
        return (explicit_tenant or "").strip()

    async def _henet_find_record(hub, name, rtype):
        """The existing managed record matching (name, type), or None. Used to
        determine ownership before an add/update/delete touches it — there's no
        per-record GET, so this reads the full list (spoke-local, cheap)."""
        r = await _relay_spoke(_get_henet_spoke(hub), "HENET_LIST", log_name="henet_owner_check")
        rt = (rtype or "").upper()
        for rec in (r or {}).get("records") or []:
            if rec.get("name") == name and (not rt or str(rec.get("type") or "").upper() == rt):
                return rec
        return None

    async def _henet_assert_can_write(hub, sess, name, rtype):
        """Verify the caller may add/update/delete this (name, type) record.

        Returns the record's EXISTING ``tenant_id`` to preserve across the
        write (``None`` if it doesn't exist yet — a brand-new record). A
        non-admin whose tenant doesn't match the existing owner gets a 404,
        never a 403 — a record belonging to another tenant must be
        indistinguishable from a genuinely absent one, same convention as
        tenant_devices.py."""
        existing = await _henet_find_record(hub, name, rtype)
        if existing is None:
            return None
        owner = existing.get("tenant_id") or ""
        if not _is_admin(sess) and owner != _henet_tenant_scope(sess):
            raise HTTPException(status_code=404, detail="record not found")
        return owner

    # Field names, in priority order, from which the dyndns update password may
    # be pulled. This lets ONE Hurricane Electric vault secret serve BOTH the LE
    # module (DNS-01) and this External-DNS module: whether the operator stored
    # it as an ``henet`` DDNS key (``ddns_key``) or as an LE DNS-01 "Hurricane
    # Electric (account login)" secret (``he_password``), the module reformats
    # it to the single push password HE's dyndns API expects — the operator
    # never keeps two copies of the same credential.
    _HENET_KEY_FIELDS = ("ddns_key", "he_password", "password", "secret", "key", "value")

    def _henet_extract_ddns_key(val):
        """Pull the HE dyndns update password out of a resolved vault secret,
        tolerating the several shapes an identical HE credential can be stored in
        (see :data:`_HENET_KEY_FIELDS`). Returns the key string or ``None``."""
        if not isinstance(val, dict):
            return None
        for f in _HENET_KEY_FIELDS:
            v = val.get(f)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None

    async def _henet_resolve_vault_cred(request: Request, body: dict, tenant_id=""):
        """Resolve the HE DDNS key into ``body['ddns_key']`` unattended.

        Precedence: an explicit ``henet_vault_credential`` {bucket,name} in the
        request wins; otherwise the credential assigned for ``tenant_id``
        (:func:`_henet_get_assigned_cred` — that tenant's own slot, or the
        global slot when ``tenant_id`` is falsy) is used. NO cross-fallback: a
        tenant with no credential of its own does not silently borrow the
        global one. The secret VALUE is read via :func:`cred_vault.automation_get`
        and injected as ``ddns_key`` — it is never returned to the browser.
        Reach is enforced on an EXPLICIT override: a tenant-admin may only
        reference buckets for their own tenants; a Global Admin, any bucket
        (including the ``__admin__`` infra slot where the HE account key
        belongs). Raises 400 when neither an explicit nor an assigned
        credential exists.

        The stored secret may be an ``henet`` DDNS key OR a shared LE DNS-01
        "Hurricane Electric" secret — :func:`_henet_extract_ddns_key` reformats
        either shape into the single dyndns push password::

            {"ddns_key": "..."}   # henet secret
            {"provider": "he-login", "he_username": "...", "he_password": "..."}
        """
        ref = body.pop("henet_vault_credential", None)
        explicit = isinstance(ref, dict)
        if not explicit:
            ref = _henet_get_assigned_cred(app.state.hub, tenant_id or None)
        if not isinstance(ref, dict):
            raise HTTPException(
                status_code=400,
                detail="No HE.NET DDNS credential assigned. Assign one under "
                       "DNS → External DNS → HE.NET (a Credential Vault secret "
                       "of type 'HE.NET DDNS key', or a shared Let's Encrypt "
                       "'Hurricane Electric' DNS-01 secret).")
        bucket = (ref.get("bucket") or "").strip()
        name = (ref.get("name") or "").strip()
        if not bucket or not name:
            raise HTTPException(status_code=400,
                                detail="henet_vault_credential requires bucket + name")
        sess = _session_user(request) or {}
        if explicit and not _is_admin(sess):
            reach = set((sess.get("user", {}) or {}).get("tenants") or [])
            if bucket not in reach:
                # Indistinguishable from missing so bucket existence never leaks.
                raise HTTPException(status_code=404, detail="vault credential not found")
        import cred_vault as _cv
        try:
            val = await _cv.automation_get(app.state.hub, bucket, name)
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("henet: vault credential resolve failed: %s", e)
            raise HTTPException(status_code=502,
                                detail=f"could not resolve vault credential: {e}")
        key = _henet_extract_ddns_key(val)
        if not key:
            raise HTTPException(status_code=404,
                                detail="vault credential not found, not automation-readable, "
                                       "or missing a usable HE DDNS key / password")
        body["ddns_key"] = key

    async def _henet_resolve_account_login(request: Request):
        """Resolve the HE **account** login (email + password) for reading the
        dns.he.net web panel — the import path needs the full web login, not the
        per-record dyndns key. Precedence mirrors :func:`_henet_resolve_vault_cred`:
        the module-level assigned credential (a ``dns`` "Hurricane Electric
        (account login)" vault secret with ``he_username``/``he_password``).

        Returns ``(username, password)``. Raises 400 when no credential is
        assigned, 404 when the secret can't be read, and 422 when the assigned
        secret is only a bare DDNS key (no account login to scrape with)."""
        ref = _henet_get_assigned_cred(app.state.hub)
        if not isinstance(ref, dict):
            raise HTTPException(
                status_code=400,
                detail="No HE.NET credential assigned. Assign the Credential Vault "
                       "'Hurricane Electric (account login)' secret (email + password) "
                       "under DNS → External DNS → HE.NET.")
        bucket = (ref.get("bucket") or "").strip()
        name = (ref.get("name") or "").strip()
        sess = _session_user(request) or {}
        if not _is_admin(sess):
            reach = set((sess.get("user", {}) or {}).get("tenants") or [])
            if bucket not in reach:
                raise HTTPException(status_code=404, detail="vault credential not found")
        import cred_vault as _cv
        try:
            val = await _cv.automation_get(app.state.hub, bucket, name)
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("henet: account-login resolve failed: %s", e)
            raise HTTPException(status_code=502,
                                detail=f"could not resolve vault credential: {e}")
        if not isinstance(val, dict):
            raise HTTPException(status_code=404, detail="vault credential not found")
        username = (val.get("he_username") or val.get("username") or val.get("email") or "").strip()
        password = val.get("he_password") or val.get("password") or ""
        if not username or not password:
            raise HTTPException(
                status_code=422,
                detail="the assigned HE.NET credential has no account login — importing "
                       "existing records needs a 'Hurricane Electric (account login)' "
                       "vault secret (email + password), not a bare DDNS key.")
        return username, password

    @app.get("/api/henet/credential")
    async def henet_get_credential(request: Request):
        """The assigned HE DDNS credential reference (or null). A non-secret
        {bucket,name} — the value is never returned.

        Non-admin: always their OWN tenant's slot (never client-choosable).
        Global Admin: pass ``?tenant=<id>`` to read one tenant's slot; omitted,
        returns the merged overview — the global slot under ``credential`` PLUS
        every tenant that has assigned one under ``tenants`` — mirroring the
        Sim-Quota admin-overview shape (global + every tenant, side by side)."""
        sess = _session_user(request) or {}
        hub = app.state.hub
        if _is_admin(sess):
            want_tenant = request.query_params.get("tenant")
            if want_tenant is not None:
                tid = want_tenant.strip() or None
                return {"status": "SUCCESS", "credential": _henet_get_assigned_cred(hub, tid)}
            gc = hub.state.get_global_config() or {}
            tenant_creds = {
                tid: ref for tid, ref in ((gc.get("henet") or {}).get("tenant_credentials") or {}).items()
                if isinstance(ref, dict) and (ref.get("bucket") or "").strip() and (ref.get("name") or "").strip()
            }
            return {"status": "SUCCESS", "credential": _henet_get_assigned_cred(hub),
                    "tenants": tenant_creds}
        return {"status": "SUCCESS", "credential": _henet_get_assigned_cred(hub, _henet_tenant_scope(sess))}

    @app.post("/api/henet/credential")
    async def henet_set_credential(request: Request):
        """Assign a HE DDNS credential — the caller's own tenant slot, or (Global
        Admin only) the global slot / an explicit tenant's slot via
        ``{"tenant": "<id>"}``. Validates the reference resolves to an
        automation-readable secret carrying a usable HE DDNS key / password (an
        ``henet`` DDNS key OR a shared LE DNS-01 "Hurricane Electric" secret)
        before persisting it, so a bad reference is rejected up-front rather than
        at first push."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        bucket = (body.get("bucket") or "").strip()
        name = (body.get("name") or "").strip()
        if not bucket or not name:
            raise HTTPException(status_code=400, detail="bucket and name are required")
        sess = _session_user(request) or {}
        if _is_admin(sess):
            tenant_id = (body.get("tenant") or "").strip()
        else:
            tenant_id = _henet_tenant_scope(sess)
            reach = set((sess.get("user", {}) or {}).get("tenants") or [])
            if bucket not in reach:
                raise HTTPException(status_code=404, detail="vault credential not found")
        import cred_vault as _cv
        try:
            val = await _cv.automation_get(app.state.hub, bucket, name)
        except Exception as e:  # noqa: BLE001 — vault/network
            raise HTTPException(status_code=502, detail=f"could not resolve vault credential: {e}")
        if not _henet_extract_ddns_key(val):
            raise HTTPException(status_code=404,
                                detail="vault credential not found, not automation-readable, "
                                       "or missing a usable HE DDNS key / password")
        hub = app.state.hub
        if tenant_id:
            gc = hub.state.get_global_config() or {}
            tenant_creds = dict((gc.get("henet") or {}).get("tenant_credentials") or {})
            tenant_creds[tenant_id] = {"bucket": bucket, "name": name}
            _henet_update_cfg(hub, tenant_credentials=tenant_creds)
        else:
            _henet_update_cfg(hub, vault_credential={"bucket": bucket, "name": name})
        await hub.state.save_state_now()
        logger.info("henet: DDNS credential assigned -> %s/%s (tenant=%s)",
                    bucket, name, tenant_id or "global")
        return {"status": "SUCCESS", "credential": {"bucket": bucket, "name": name},
                "tenant": tenant_id or None}

    @app.delete("/api/henet/credential")
    async def henet_clear_credential(request: Request):
        """Clear an assigned HE DDNS credential — the caller's own tenant slot,
        or (Global Admin only) the global slot / an explicit ``?tenant=`` slot."""
        sess = _session_user(request) or {}
        hub = app.state.hub
        if _is_admin(sess):
            tenant_id = (request.query_params.get("tenant") or "").strip()
        else:
            tenant_id = _henet_tenant_scope(sess)
        if tenant_id:
            gc = hub.state.get_global_config() or {}
            tenant_creds = dict((gc.get("henet") or {}).get("tenant_credentials") or {})
            tenant_creds.pop(tenant_id, None)
            _henet_update_cfg(hub, tenant_credentials=tenant_creds)
        else:
            _henet_update_cfg(hub, vault_credential=None)
        await hub.state.save_state_now()
        logger.info("henet: DDNS credential assignment cleared (tenant=%s)", tenant_id or "global")
        return {"status": "SUCCESS", "credential": None}

    @app.get("/api/henet/records")
    async def henet_list_records(request: Request):
        """List the HE.NET records this module manages (from spoke-local state).

        Global Admin sees every record (global + every tenant's, each tagged
        with its ``tenant_id`` so the WebUI can group them). A non-admin sees
        ONLY records whose ``tenant_id`` matches their own tenant — never the
        global set nor another tenant's — filtered here, not just hidden client-
        side, since the spoke itself has no tenant concept."""
        logger.debug("relay GET /api/henet/records")
        result = await _relay_spoke(_get_henet_spoke(app.state.hub), "HENET_LIST",
                                    log_name="henet_list_records")
        sess = _session_user(request) or {}
        if _is_admin(sess):
            return result
        scope = _henet_tenant_scope(sess)
        records = [r for r in (result or {}).get("records") or [] if (r.get("tenant_id") or "") == scope]
        out = dict(result or {})
        out["records"] = records
        return out

    @app.get("/api/henet/status")
    async def henet_status(request: Request):
        """HE dyndns endpoint reachability + managed-record count (fleet-wide —
        the endpoint/reachability figure isn't per-tenant data)."""
        logger.debug("relay GET /api/henet/status")
        return await _relay_spoke(_get_henet_spoke(app.state.hub), "HENET_STATUS",
                                  log_name="henet_status")

    @app.post("/api/henet/record")
    async def henet_add_record(request: Request):
        """Add (or re-push) a record. Tenant-owned: a non-admin's new record is
        auto-tagged with their own tenant; re-adding an EXISTING name they don't
        own 404s (see _henet_assert_can_write). Global Admin may target a
        specific tenant via ``{"tenant": "<id>"}``, else the record is global."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        sess = _session_user(request) or {}
        hub = app.state.hub
        name = str(body.get("name") or "").strip().rstrip(".")
        rtype = str(body.get("type") or "A").upper()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        existing_owner = await _henet_assert_can_write(hub, sess, name, rtype)
        tenant_id = existing_owner if existing_owner is not None else \
            _henet_tenant_scope(sess, body.get("tenant") if _is_admin(sess) else None)
        body["tenant_id"] = tenant_id
        await _henet_resolve_vault_cred(request, body, tenant_id)
        return await _relay_spoke(_get_henet_spoke(hub), "HENET_ADD", body,
                                  log_name="henet_add_record")

    @app.put("/api/henet/record")
    async def henet_update_record(request: Request):
        """Re-push an existing record with a new IP. Must already own it (or be
        admin) — 404 otherwise, see _henet_assert_can_write."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        sess = _session_user(request) or {}
        hub = app.state.hub
        name = str(body.get("name") or "").strip().rstrip(".")
        rtype = str(body.get("type") or "A").upper()
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        existing_owner = await _henet_assert_can_write(hub, sess, name, rtype)
        # Global Admin may re-home an existing record to another tenant (or back
        # to global) by sending an explicit ``tenant``; otherwise the record
        # keeps its current owner. A non-admin is always pinned to their own.
        if _is_admin(sess) and "tenant" in body:
            tenant_id = _henet_tenant_scope(sess, body.get("tenant"))
        else:
            tenant_id = existing_owner if existing_owner is not None else _henet_tenant_scope(sess)
        body["tenant_id"] = tenant_id
        await _henet_resolve_vault_cred(request, body, tenant_id)
        return await _relay_spoke(_get_henet_spoke(hub), "HENET_UPDATE", body,
                                  log_name="henet_update_record")

    @app.delete("/api/henet/record")
    async def henet_delete_record(request: Request):
        """Remove a record from local management (no HE credential needed — HE's
        dyndns API has no delete verb, so the zone entry itself is left as-is).
        Must already own it (or be admin) — 404 otherwise."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        sess = _session_user(request) or {}
        hub = app.state.hub
        name = str(body.get("name") or "").strip().rstrip(".")
        rtype = str(body.get("type") or "").strip()
        await _henet_assert_can_write(hub, sess, name, rtype)
        return await _relay_spoke(_get_henet_spoke(hub), "HENET_DELETE", body,
                                  log_name="henet_delete_record")

    @app.post("/api/henet/record/tenant")
    async def henet_set_record_tenant(request: Request):
        """Re-home a managed record to a tenant WITHOUT re-pushing to HE.

        Metadata only: the HE zone entry + last-push status are untouched — this
        just moves the record onto another tenant's tab/scope. Global Admin only
        (moving a record between tenants is an admin operation); ``tenant`` "" or
        omitted moves it back to the Global/admin scope. No DDNS key needed, so
        it works even while the dyndns endpoint is unreachable."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        sess = _session_user(request) or {}
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        name = str(body.get("name") or "").strip().rstrip(".")
        if not name:
            raise HTTPException(status_code=400, detail="name is required")
        payload = {"name": name, "type": body.get("type"),
                   "tenant_id": _henet_tenant_scope(sess, body.get("tenant"))}
        return await _relay_spoke(_get_henet_spoke(app.state.hub), "HENET_SET_TENANT",
                                  payload, log_name="henet_set_record_tenant")

    @app.post("/api/henet/sync")
    async def henet_sync(request: Request):
        """Replace the managed set and push every A/AAAA record to HE.NET.

        HE authenticates each dyndns push with the record's OWN per-record DDNS
        key — the account login is NOT a valid push password. So an explicit
        ``ddns_key`` in the body (the shared key the operator set on their HE
        records, entered in the Sync-all dialog) is used verbatim as the push
        password for every record; only when none is supplied do we fall back to
        the assigned credential (which works when that credential is itself a
        real shared DDNS key). Sending the account-login password as the key is
        exactly what made Sync all report "badauth" for every record."""
        body = await request.json()
        body = dict(body) if isinstance(body, dict) else {}
        typed_key = str(body.get("ddns_key") or "").strip()
        if typed_key:
            body["ddns_key"] = typed_key  # operator-supplied shared key wins, no vault lookup
        else:
            body.pop("ddns_key", None)
            await _henet_resolve_vault_cred(request, body)
        return await _relay_spoke(_get_henet_spoke(app.state.hub), "HENET_SYNC", body,
                                  log_name="henet_sync")

    @app.post("/api/henet/import")
    async def henet_import(request: Request):
        """Import the records that already exist in the HE.NET zone into local
        management, so records added directly at dns.he.net (not by LM) become
        visible + manageable.

        HE's dyndns API cannot list records, so the hub logs into the dns.he.net
        **web panel** with the assigned account-login credential (resolved from
        the Credential Vault — the SAME HE account the certificate DNS-01 flow
        uses) and reads each zone's record table. The scrape runs on the HUB (it
        has outbound access to dns.he.net and the vault key); the discovered
        A/AAAA records are then handed to the henet spoke via HENET_IMPORT to
        merge into its managed state WITHOUT re-pushing them. Non-A/AAAA records
        are reported as skipped (HE dyndns can only manage A/AAAA).

        Optional body ``{"zone": "example.com"}`` restricts the import to one
        zone; omitted, every zone on the account is imported."""
        hub = app.state.hub
        spoke_id = _get_henet_spoke(hub)  # 503 early if the spoke is offline
        try:
            body = await request.json()
        except Exception:
            body = {}
        zone_filter = (body or {}).get("zone") if isinstance(body, dict) else None
        username, password = await _henet_resolve_account_login(request)

        import henet_scrape
        scraper = henet_scrape.HENetScraper()
        result = await asyncio.to_thread(scraper.import_all, username, password, zone_filter)
        if result.get("status") != "SUCCESS":
            raise HTTPException(status_code=502,
                                detail=result.get("message") or "HE.NET import failed")

        records = result.get("records", [])
        merged = await _relay_spoke(spoke_id, "HENET_IMPORT", {"records": records},
                                    log_name="henet_import")
        return {
            "status": "SUCCESS",
            "imported": merged.get("imported", 0),
            "skipped_existing": merged.get("skipped", 0),
            "discovered": len(records),
            "zones": [z.get("name") for z in result.get("zones", [])],
            "skipped_types": result.get("skipped_types", {}),
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

    def _le_vault_enabled():
        """True when the Credential Vault (Azure Key Vault) is configured. When
        on, LE credentials belong in the vault; any raw creds still held on the
        le spoke should be migrated there manually (we never auto-drop them)."""
        try:
            import cred_vault as _cv
            return bool(_cv._vault_available(app.state.hub))
        except Exception:  # noqa: BLE001
            return False

    _LE_MIGRATE_WARNING = (
        "The credential vault is enabled but this LE credential is still stored "
        "locally on the hub/spoke. Migrate it into the Credential Vault manually; "
        "raw LE passwords can no longer be created here.")

    # certbot plugin aliases (mirror of WebUI LE_DNS_PROVIDER_ALIAS): a vault
    # secret may name a friendly provider that maps to a real certbot plugin.
    _LE_DNS_PLUGIN_ALIAS = {"he": "rfc2136"}

    async def _le_resolve_vault_dns_cred(request: Request, body: dict):
        """Resolve a ``dns_vault_credential`` {bucket,name} reference in-place to
        the inline spoke DNS-cred shape (``dns_provider`` + ``dns_creds`` INI, or
        HE-login user/pass). The secret VALUE is read unattended via
        :func:`cred_vault.automation_get` and forwarded to the le spoke — it is
        never returned to the browser. Reach is enforced: a tenant-admin may only
        reference buckets for their own tenants; a Global Admin, any bucket.

        Expected vault secret value (hub-mode, type ``dns``)::

            {"provider": "cloudflare", "dns_creds": "<certbot INI text>"}
            {"provider": "he-login", "he_username": "...", "he_password": "..."}
        """
        ref = body.get("dns_vault_credential")
        if not isinstance(ref, dict):
            body.pop("dns_vault_credential", None)
            return
        bucket = (ref.get("bucket") or "").strip()
        name = (ref.get("name") or "").strip()
        if not bucket or not name:
            raise HTTPException(status_code=400,
                                detail="dns_vault_credential requires bucket + name")
        sess = _session_user(request) or {}
        if not _is_admin(sess):
            reach = set((sess.get("user", {}) or {}).get("tenants") or [])
            if bucket not in reach:
                # Indistinguishable from missing so bucket existence never leaks.
                raise HTTPException(status_code=404, detail="vault credential not found")
        import cred_vault as _cv
        try:
            val = await _cv.automation_get(app.state.hub, bucket, name)
        except Exception as e:  # noqa: BLE001 — vault/network
            logger.warning("le: vault dns credential resolve failed: %s", e)
            raise HTTPException(status_code=502,
                                detail=f"could not resolve vault credential: {e}")
        if not isinstance(val, dict):
            raise HTTPException(status_code=404,
                                detail="vault credential not found or not automation-readable")
        provider = (val.get("provider") or "").strip()
        if not provider:
            raise HTTPException(status_code=400,
                                detail="vault credential is missing a 'provider' field")
        body.pop("dns_credential", None)  # vault ref supersedes any named cred
        body["dns_provider"] = _LE_DNS_PLUGIN_ALIAS.get(provider, provider)
        if provider == "he-login":
            if val.get("he_username"):
                body["he_username"] = val["he_username"]
            if val.get("he_password"):
                body["he_password"] = val["he_password"]
        else:
            body["dns_creds"] = val.get("dns_creds") or val.get("ini") or ""
        # Keep a normalized (secret-free) reference in the body so the spoke can
        # persist it on its ledger and the hub can re-resolve it on renew / after
        # a spoke reinstall. Only {bucket,name} — never the resolved secret.
        body["dns_vault_credential"] = {"bucket": bucket, "name": name}

    def _le_store_vault_ref(domain, ref):
        """Persist a secret-free {bucket,name} vault DNS-01 reference for ``domain``
        in hub state so it survives a spoke reinstall (re-pushed on reconnect)."""
        if not (domain and isinstance(ref, dict)):
            return
        b = (ref.get("bucket") or "").strip()
        n = (ref.get("name") or "").strip()
        if not (b and n):
            return
        gc = app.state.hub.state.system_state.setdefault("global_config", {})
        refs = gc.setdefault("le_vault_dns_creds", {})
        refs[domain] = {"bucket": b, "name": n}

    def _le_forget_vault_ref(domain):
        gc = app.state.hub.state.system_state.get("global_config", {}) or {}
        refs = gc.get("le_vault_dns_creds")
        if isinstance(refs, dict) and domain in refs:
            refs.pop(domain, None)
            return True
        return False

    @app.post("/api/le/he-config")
    async def le_set_he_login(request: Request):
        """DISABLED — storing a raw Hurricane Electric account email/password knob
        on the le spoke is no longer allowed. Store the HE account login in the
        Credential Vault (add a ``DNS-01`` secret, provider *Hurricane Electric
        (account login)*, automation-readable) and select it when issuing a
        certificate; the hub resolves it unattended. Existing spoke-stored knobs
        are left untouched (no migration, no auto-delete)."""
        raise HTTPException(
            status_code=409,
            detail=("Storing a Hurricane Electric account login in the LE module is "
                    "disabled. Add it to the Credential Vault (DNS-01 secret, "
                    "provider 'Hurricane Electric (account login)') and pick it "
                    "when issuing a certificate."))

    @app.get("/api/le/he-config")
    async def le_get_he_login():
        """Whether the HE account-login knob is configured (never returns the
        password) — drives the Setup knob's 'configured' state."""
        _hub, _sid, payload = await _le_request("LE_GET_HE_LOGIN", {})
        if isinstance(payload, dict):
            vault_on = _le_vault_enabled()
            data = _le_inner(payload)
            configured = bool(data.get("configured", payload.get("configured")))
            payload["vault_enabled"] = vault_on
            payload["local_passwords_present"] = configured
            payload["migrate_warning"] = _LE_MIGRATE_WARNING if (vault_on and configured) else ""
        return payload

    # ── Per-tenant multi-provider DNS-01 credential store ────────────────────
    # Each tenant manages its OWN named DNS credentials (HE / Cloudflare /
    # rfc2136 / route53). tenant_id is derived from the session and injected into
    # the le command — NEVER taken from the request body — so one tenant can't
    # read or write another's creds.
    def _le_tenant(request):
        sess = _session_user(request)
        return ((sess.get("user", {}).get("tenant_id") if sess else None) or "default")

    # ── Per-cert tenant ownership + shared-tenant deploy authorization ────────
    # A managed cert carries an explicit owner-tenant list in
    # global_config['le_cert_tenants'][domain] (see le_cert_access). Change ops
    # (renew/revoke/targets/tenant-edit) require ownership; a shared cert is
    # deployable by any user to their own devices but not changeable.
    def _le_guard_change(request, domain):
        """403 unless the caller may CHANGE this cert (admin, an owner, or a
        legacy ownerless cert). Shared-but-not-owned → deploy only, so blocked."""
        sess = _session_user(request)
        if not _lca.can_change(hub, sess, domain):
            raise HTTPException(
                status_code=403,
                detail="This certificate belongs to another tenant. You can "
                       "deploy a shared certificate to your own devices, but not "
                       "change it.")

    async def _le_persist(context):
        try:
            await app.state.hub.state.save_state_now()
        except Exception as e:  # noqa: BLE001
            logger.warning("persist le cert tenants (%s) failed: %s", context, e)

    def _le_target_tenant(module_type, identifier, spoke_id=None):
        """The owning tenant_id of a cert install TARGET, or "" if it has none
        (shared / unattributable). Thin hub-backed wrapper over the pure
        cert_distribution.target_owner_tenant (see there for the resolution
        rules): the hub target is shared (""); an agent-hosting per-node target
        honors the node's OWN pinned tenant (agent_config → client_simulation
        .tenant_id, same source the VM console + per-agent Tenant button use),
        falling back to its owning spoke; otherwise the identifier/spoke_id IS
        the spoke, and its module_metadata tenant is the target's tenant."""
        def _agent_tenant(aid):
            try:
                ac = (hub.state.system_state.get("agent_config", {}) or {}).get(
                    hub._agent_primary_key(aid), {}) or {}
                return str((ac.get("client_simulation") or {}).get("tenant_id") or "").strip()
            except Exception:  # noqa: BLE001 — fail-open to spoke-tenant fallback
                return ""
        return target_owner_tenant(
            {"module_type": module_type, "identifier": identifier,
             "spoke_id": spoke_id},
            lambda sid: hub.state.get_spoke_tenant(hub._primary_key(sid)) or "",
            lambda aid: hub.get_spoke_for_agent(aid, fallback_hypervisor=False) or "",
            _agent_tenant)

    def _le_guard_target(request, module_type, identifier, spoke_id=None):
        """403 unless the caller may deploy to this install TARGET. A Global Admin
        may target anything (incl. the hub + shared spokes). A tenant-admin may
        target ONLY a spoke/agent bound to one of their own tenants — never the
        hub and never another tenant's (or an unattributable/shared) target."""
        sess = _session_user(request)
        if _is_admin(sess):
            return
        ttid = _le_target_tenant(module_type, identifier, spoke_id)
        mine = set(_lca.user_tenants(sess)) | {_lca.current_tenant(sess)}
        if not ttid or ttid not in mine:
            raise HTTPException(
                status_code=403,
                detail="You can only deploy this certificate to targets in your "
                       "own tenant. The hub and shared infrastructure are managed "
                       "by a Global Admin.")

    def _nw_device_tenant(device_id):
        """The owning tenant_id of an nw device (from global_config.nw_devices),
        used to authorize a shared-cert deploy to the caller's own device."""
        gc = app.state.hub.state.system_state.get("global_config", {}) or {}
        for d in gc.get("nw_devices", []) or []:
            if isinstance(d, dict) and str(d.get("id")) == str(device_id):
                return (d.get("tenant_id") or "").strip()
        return ""

    def _tenant_exists(tid):
        tenants = (getattr(app.state.hub.state, "tenant_state", {}) or {}).get("tenants", {}) or {}
        return tid in tenants

    @app.get("/api/le/certs/{domain}/tenants")
    async def le_get_cert_tenants(domain: str, request: Request):
        """The cert's explicit owner-tenant list + the caller's rights."""
        sess = _session_user(request)
        meta = _lca.meta(hub, sess, domain)
        logger.info("LE-CERT-TENANTS GET domain=%r -> meta=%r store_keys=%r",
                    domain, meta, _le_cert_tenant_store_keys())
        return {"status": "ok", "domain": domain, **meta}

    def _le_cert_tenant_store_keys():
        """The domains that currently have an explicit owner-tenant list stored,
        for troubleshooting a save that 'doesn't stick' (a key mismatch between
        the stored domain and the cert-list domain is the usual culprit)."""
        gc = app.state.hub.state.system_state.get("global_config", {}) or {}
        m = gc.get(_lca.STORE_KEY) or {}
        return sorted(m.keys()) if isinstance(m, dict) else []

    async def _le_apply_cert_tenants(request, domain, want):
        """Shared core for the cert owner-tenant replace op: authorize, validate,
        set + durably persist, and return the tagging meta. Raises HTTPException
        (400/403/500) on any failure so the caller never reports a false
        success."""
        sess = _session_user(request)
        u = (sess or {}).get("user", {}) if isinstance(sess, dict) else {}
        logger.info(
            "LE-CERT-TENANTS SET request domain=%r want=%r caller(tenant_id=%r "
            "tenants=%r admin=%s)", domain, want, u.get("tenant_id"),
            u.get("tenants"), _is_admin(sess))
        if not (isinstance(domain, str) and domain.strip()):
            logger.warning("LE-CERT-TENANTS SET rejected: empty/invalid domain %r", domain)
            raise HTTPException(status_code=400, detail="'domain' is required")
        domain = domain.strip()
        _le_guard_change(request, domain)
        if not isinstance(want, list):
            logger.warning("LE-CERT-TENANTS SET rejected: 'tenants' not a list: %r", want)
            raise HTTPException(status_code=400, detail="'tenants' must be a list")
        try:
            clean = _lca.validate_tenant_edit(hub, sess, domain, want, _tenant_exists)
        except _lca.TenantEditError as e:
            logger.warning("LE-CERT-TENANTS SET rejected by validate domain=%r "
                           "want=%r: %s", domain, want, e)
            raise HTTPException(status_code=400, detail=str(e))
        _lca.set_tenants(hub, domain, clean)
        stored = _lca.get_tenants(hub, domain)
        logger.info("LE-CERT-TENANTS SET stored domain=%r validated=%r read-back=%r "
                    "store_keys=%r", domain, clean, stored,
                    _le_cert_tenant_store_keys())
        # Durability-critical: the assignment IS the operation, so a failed
        # persist must surface as an error — never a false "saved" toast that
        # silently loses the tenant list on the next hub restart. (Sibling LE
        # change ops — add/remove target, client-auth — persist the same way.)
        try:
            await app.state.hub.state.save_state_now()
        except Exception as e:  # noqa: BLE001
            logger.error("persist le cert tenants (set_tenants) failed: %s", e)
            raise HTTPException(
                status_code=500,
                detail="The tenant assignment was applied in memory but could "
                       "not be saved to disk, so it would be lost on restart. "
                       "Check the hub state-storage location and permissions, "
                       "then try again.")
        logger.info("LE-CERT-TENANTS SET persisted domain=%r read-back-after-save=%r",
                    domain, _lca.get_tenants(hub, domain))
        return {"status": "ok", "domain": domain, **_lca.meta(hub, sess, domain)}

    # Domain in the BODY, not the URL path: a cert domain can be a WILDCARD
    # (``*.example.com`` → ``%2A.example.com`` once URL-encoded) or otherwise
    # carry reserved characters, and some reverse proxies / WAFs RESET the
    # connection on encoded reserved chars in the path — which surfaces in the
    # browser as an opaque ``TypeError: Load failed`` (a transport-level fetch
    # rejection, not an HTTP error). Keeping the domain out of the path makes the
    # request URL a static, always-safe string. This is the WebUI's save path.
    @app.post("/api/le/cert-tenants")
    async def le_set_cert_tenants_body(request: Request):
        """Replace a cert's owner-tenant list (domain + tenants in the JSON body).
        See :func:`_le_apply_cert_tenants` for the authorization/validation
        semantics."""
        body = await request.json()
        body = body if isinstance(body, dict) else {}
        return await _le_apply_cert_tenants(
            request, body.get("domain"), body.get("tenants"))

    # Backward-compatible alias (domain in the path). Retained so an older WebUI
    # bundle keeps working; new clients POST /api/le/cert-tenants (body) to dodge
    # proxy/WAF path-encoding resets on wildcard domains.
    @app.put("/api/le/certs/{domain}/tenants")
    async def le_set_cert_tenants(domain: str, request: Request):
        """Replace the cert's owner-tenant list. Admin → any existing-tenant set.
        A non-admin owner may add/remove OTHER tenants but never their own (their
        active tenant must remain). Adding the shared tenant makes the cert
        deployable by every tenant to their own devices."""
        body = await request.json()
        want = body.get("tenants") if isinstance(body, dict) else None
        return await _le_apply_cert_tenants(request, domain, want)

    @app.get("/api/le/dns-credentials")
    async def le_list_dns_creds(request: Request):
        """This tenant's saved DNS-01 credentials (names + providers; NO secrets),
        plus the provider field catalog for the editor."""
        _hub, _sid, payload = await _le_request(
            "LE_LIST_DNS_CREDS", {"tenant_id": _le_tenant(request)})
        if isinstance(payload, dict):
            vault_on = _le_vault_enabled()
            data = _le_inner(payload)
            creds = data.get("credentials") or data.get("creds") or []
            has_local = bool(creds)
            payload["vault_enabled"] = vault_on
            payload["local_passwords_present"] = has_local
            payload["migrate_warning"] = _LE_MIGRATE_WARNING if (vault_on and has_local) else ""
        return payload

    @app.post("/api/le/dns-credentials")
    async def le_set_dns_cred(request: Request):
        """DISABLED — creating raw DNS-01 credentials in the LE module is no
        longer allowed. Store DNS credentials in the Credential Vault (add a
        ``DNS-01`` secret, automation-readable) and select it in the issue-cert
        form; the hub resolves it unattended at issue time. Existing spoke-stored
        credentials are left untouched (no migration, no auto-delete) and can
        still be used by name or deleted for cleanup."""
        raise HTTPException(
            status_code=409,
            detail=("Creating DNS credentials in the LE module is disabled. Store "
                    "them in the Credential Vault (add a 'DNS-01' secret) and pick "
                    "the vault credential when issuing a certificate."))

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
            # Certificate-issuance hostname enumeration (le module) — out of
            # scope for the DNS tenant-routing fix above; certificates aren't
            # tenant-scoped yet either (see the multi-tenant-spoke scan).
            # Left on the legacy first-connected-spoke resolver.
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

    def _le_certs_holder(data):
        """Locate the cert list inside an le-certs response.

        The list lives at DIFFERENT depths depending on the caller:
        * flat ``{"certs": [...]}`` — the already-unwrapped shape unit tests use;
        * the spoke SUCCESS envelope ``{"status": ..., "data": {"certs": [...]}}``
          — the REAL shape ``_relay_spoke`` returns and the warm cache stores
          (``le_cache_get('certs')``), and the shape the WebUI unwraps via
          ``inner(d).certs``.

        Returns the list (possibly empty) or ``None`` when there is no cert list.
        Fixes the silent-no-op bug where the tag/filter helpers read top-level
        ``data['certs']`` (``None`` on the enveloped shape), so per-cert tenant
        ownership / ab tags / the ownership filter never reached the certs
        the UI actually renders."""
        if not isinstance(data, dict):
            return None
        if isinstance(data.get("certs"), list):
            return data["certs"]
        inner = data.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("certs"), list):
            return inner["certs"]
        return None

    def _le_with_certs(data, new_certs):
        """Return ``data`` with its cert list replaced by ``new_certs`` at the
        SAME nesting level the originals were found (flat top-level, or nested
        under ``data``), so a tag/filter transform reaches the list the WebUI
        reads instead of injecting a stray, ignored top-level ``certs`` key."""
        if not isinstance(data, dict):
            return data
        if isinstance(data.get("certs"), list):
            return {**data, "certs": new_certs}
        inner = data.get("data")
        if isinstance(inner, dict) and isinstance(inner.get("certs"), list):
            return {**data, "data": {**inner, "certs": new_certs}}
        return {**data, "certs": new_certs}

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
        # Tenant set the caller is scoped to (an explicit picker tenant, else the
        # session user's own tenants) — used by the explicit-ownership visibility
        # test below.
        want_tenants = ([tid] if (tenant and tid)
                        else _lca.user_tenants(sess))
        # An EXPLICIT tenant (the picker) scopes visibility to THAT tenant even
        # for a Global Admin (matches nw/ipam/firewall) — so an admin viewing
        # tenant LRB does NOT see certs owned solely by 'default' or another
        # tenant. With no picker, an admin keeps their see-everything pass.
        explicit_scope = bool(tenant and tid)
        if tenant and tid:
            # Explicit tenant selected → scope by its prefixes (admins included).
            prefixes = await access.resolve_prefixes_for_tenant(hub, tid)
            if not prefixes:
                # No DNS prefixes for the tenant — but explicit cert OWNERSHIP
                # (own or shared) must still surface certs, so don't fail closed
                # unconditionally; fall through with an empty prefix set.
                prefixes = []
        else:
            if not sess or _is_admin(sess):
                return data
            prefixes = await access.resolve_prefixes(hub, sess)
            if not prefixes:
                prefixes = []
        import ipaddress
        nets = []
        for p in prefixes:
            try:
                nets.append(ipaddress.ip_network(p, strict=False))
            except ValueError:
                continue
        tenant_hosts, any_source = await _dns_hosts(nets) if nets else (set(), True)
        if nets and not any_source:
            return data  # both DNS sources unreachable → fail open

        def _match(cert):
            # Explicit per-cert tenant ownership takes precedence: an owned or
            # shared cert is always visible; a cert owned by OTHER tenants only
            # is hidden — regardless of DNS. Certs with no explicit owners fall
            # back to the legacy DNS-subnet match below (backward compatible).
            own = _lca.visible_to(hub, sess, cert.get("domain"), want_tenants,
                                  admin_all=not explicit_scope)
            if own is not None:
                return own
            if not tenant_hosts:
                return False
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

        return _le_with_certs(data, [c for c in (_le_certs_holder(data) or []) if _match(c)])

    def _ab_pinned():
        """The set of DNS names designated as AppBuilder certs (H1) —
        ``global_config['ab_cert_identities']``. The HUB_REQUEST channel
        is gated to a connection presenting one of these over mTLS."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        # Lower-cased: le_set_ab stores lowercase, and DNS names are
        # case-insensitive — so match case-insensitively (a cert whose domain
        # carries any uppercase would otherwise never show as tagged).
        return {str(n).strip().lower() for n in (gc.get("ab_cert_identities") or [])}

    def _tag_ab(data):
        """Tag each cert with ``ab: bool`` (its domain / any SAN is in the
        pinned AppBuilder list) so the LE-module UI can show the AppBuilder toggle's
        state. Runs on both live + cached-stale paths."""
        if not isinstance(data, dict):
            return data
        pinned = _ab_pinned()
        certs = _le_certs_holder(data)
        if certs is None:
            return data
        tagged = []
        for c in certs:
            if not isinstance(c, dict):
                tagged.append(c)
                continue
            names = {str(c.get("domain") or "").strip().lower()}
            for san in (c.get("domains") or []):
                names.add(str(san or "").strip().lower())
            is_bf = any(n and n in pinned for n in names)
            tagged.append({**c, "ab": is_bf})
        return _le_with_certs(data, tagged)

    def _tag_cert_tenants(request, data):
        """Tag each cert with its explicit owner ``tenants`` list plus the
        caller's rights (``shared``/``owned``/``can_edit``) so the LE UI can show
        tenant chips and enable/disable the change actions."""
        if not isinstance(data, dict):
            return data
        sess = _session_user(request)
        certs = _le_certs_holder(data)
        if certs is None:
            # No cert list at any known depth — nothing to tag. Log the shape so
            # a future envelope change is obvious rather than silently untagged.
            logger.info("LE-CERT-TENANTS LIST no cert list in response; top_keys=%r",
                        list(data.keys()))
            return data
        out = []
        tagged_owned = {}
        for c in certs:
            if not isinstance(c, dict):
                out.append(c)
                continue
            dom = c.get("domain")
            meta = _lca.meta(hub, sess, dom)
            if meta.get("tenants"):
                tagged_owned[dom] = meta["tenants"]
            out.append({**c, **meta})
        # Surface the cross-reference so a save that 'doesn't stick' is easy to
        # diagnose: the domains the cert LIST reports (verbatim), which of them
        # resolved to an owner-tenant list, and the domains that actually have a
        # stored list. A stored key not appearing under a cert domain (or vice
        # versa) = a domain-key mismatch between save + list.
        logger.info(
            "LE-CERT-TENANTS LIST cert_domains=%r tagged_with_tenants=%r store_keys=%r",
            [c.get("domain") for c in certs if isinstance(c, dict)],
            tagged_owned, _le_cert_tenant_store_keys())
        return _le_with_certs(data, out)

    @app.get("/api/le/certs")
    async def le_list_certs(request: Request, tenant: str = None):
        """List managed certificates from the le spoke.

        Warm-cached (``le_cache``): serves last-known certs (marked ``stale``)
        when the le spoke is offline or a live fetch overruns, so the
        Certificates page renders instantly instead of blocking/503-ing. A
        successful live fetch refreshes + persists the cache. Tenant subnet
        filtering (``_filter_le_certs``) runs per request on the UNFILTERED cache.
        Each cert is also tagged ``ab: bool`` (H1) from the pinned
        ``global_config['ab_cert_identities']`` list, and with its explicit
        owner ``tenants`` + the caller's rights (``_tag_cert_tenants``)."""
        logger.debug("relay GET /api/le/certs")
        hub = app.state.hub
        le_sid = hub.get_spoke_by_type("certificates")
        if not le_sid:
            cached = hub.le_cache_get("certs")
            if cached is not None:
                out = dict(cached) if isinstance(cached, dict) else {"certs": cached}
                out["stale"] = True
                return _tag_cert_tenants(request, await _filter_le_certs(request, _tag_ab(out), tenant))
            raise HTTPException(status_code=503, detail="No spoke connected")
        try:
            data = await _relay_spoke(le_sid, "LE_LIST_CERTS", log_name="le_list_certs")
            await hub.le_cache_set("certs", data)
            return _tag_cert_tenants(request, await _filter_le_certs(request, _tag_ab(data), tenant))
        except HTTPException:
            cached = hub.le_cache_get("certs")
            if cached is not None:
                out = dict(cached) if isinstance(cached, dict) else {"certs": cached}
                out["stale"] = True
                return _tag_cert_tenants(request, await _filter_le_certs(request, _tag_ab(out), tenant))
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
        # Re-issuing an existing cert owned by ANOTHER tenant is a change op —
        # block it (a shared cert is deploy-only for non-owners).
        _req_domain = (body.get("domain")
                       or (body.get("domains") or [None])[0]
                       if isinstance(body, dict) else None)
        if _req_domain and _lca.has_owners(app.state.hub, _req_domain):
            _le_guard_change(request, _req_domain)
        await _le_resolve_vault_dns_cred(request, body)  # {bucket,name} → inline creds
        vault_ref = body.get("dns_vault_credential") if isinstance(body, dict) else None
        hub, le_sid, payload = await _le_request("LE_ISSUE_CERT", body,
                                                  timeout=_LE_CERTBOT_TIMEOUT)
        inner = _le_inner(payload)
        domain = inner.get("domain")
        targets = inner.get("targets") or []
        # Auto-assign the creator's current tenant as an owner of the new cert so
        # it is scoped to (and manageable by) their tenant from the start.
        if domain:
            _lca.add_tenant(hub, domain, _le_tenant(request))
            await _le_persist("issue add_tenant")
        # Persist the vault DNS-01 reference hub-side (durable across a spoke
        # reinstall) and re-seed the spoke's DNS hook creds from the vault now.
        if domain and isinstance(vault_ref, dict):
            _le_store_vault_ref(domain, vault_ref)
            try:
                await hub.state.save_state_now()
            except Exception as e:  # noqa: BLE001
                logger.warning("persist le vault ref for %s failed: %s", domain, e)
            if le_sid:
                asyncio.create_task(hub._le_sync_vault_dns_creds(le_sid))
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

    @app.get("/api/mtls/client-certs")
    async def mtls_client_certs(request: Request):
        """The Hub-Local-CA mTLS client certs the hub has issued to spokes
        (system_state.mtls_client_certs) — so the LE module can list/manage them
        alongside LE certs. Admin-only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        reg = (hub.state.system_state.get("mtls_client_certs") or {})
        active = set((hub.active_connections or {}).keys())
        certs = []
        for pk, e in reg.items():
            certs.append({**e, "pk": pk, "connected": pk in active})
        certs.sort(key=lambda c: (not c.get("connected"), c.get("spoke_id", "")))
        return {"certs": certs}

    @app.post("/api/mtls/reprovision")
    async def mtls_reprovision(request: Request):
        """Force-(re)issue Hub-Local-CA mTLS client certs. Body {spoke_id} for one,
        else every connected spoke. Admin-only. Used to roll certs out immediately
        instead of waiting for the next reconnect."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        body = await request.json() if request.headers.get("content-length") else {}
        one = (body or {}).get("spoke_id") if isinstance(body, dict) else None
        targets = [one] if one else list((hub.active_connections or {}).keys())
        results = []
        for sid in targets:
            try:
                r = await hub._provision_spoke_mtls_cert(sid, force=True)
                results.append({"spoke_id": sid, **(r or {})})
            except Exception as e:  # noqa: BLE001
                results.append({"spoke_id": sid, "status": "error", "message": str(e)})
        return {"provisioned": results, "count": len(results)}

    @app.post("/api/mtls/revoke")
    async def mtls_revoke(request: Request):
        """Revoke a spoke's Hub-CA mTLS client cert: it's cleared on the spoke
        (reconnects cert-less), removed from the registry, and marked revoked so
        auto-provision won't re-mint until an explicit (re)issue. Body {spoke_id}.
        Admin-only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        body = await request.json()
        sid = (body or {}).get("spoke_id") if isinstance(body, dict) else None
        if not sid:
            raise HTTPException(status_code=400, detail="spoke_id required")
        return await hub._revoke_spoke_mtls_cert(sid)

    @app.get("/api/le/acme-info")
    async def le_acme_info(request: Request):
        """certbot version + ACME profile support + the CA's advertised profiles,
        relayed from the le spoke. Diagnoses 'requested clientAuth but got
        serverAuth-only' — shows whether certbot is new enough (>=4.0 for
        --preferred-profile) and the clientAuth-capable profile's real name."""
        hub = app.state.hub
        le_sid = hub.get_spoke_by_type("certificates")
        if not le_sid:
            return {"available": False, "reason": "certificate spoke not connected"}
        try:
            payload = await _relay_spoke(le_sid, "LE_ACME_INFO", log_name="le_acme_info")
            inner = payload.get("data") if isinstance(payload, dict) and isinstance(payload.get("data"), dict) else payload
            return {"available": True, **(inner or {})}
        except Exception as e:  # noqa: BLE001
            return {"available": False, "error": str(e)}

    @app.post("/api/le/certs/{domain}/clientauth")
    async def le_set_clientauth(domain: str, request: Request):
        """Toggle the clientAuth EKU on a managed cert and re-issue now. The ACME
        'classic'-style profile carries serverAuth+clientAuth; the default profile
        is server-only. Needed for mTLS CLIENT certs (AppBuilder, the mTLS wildcard) —
        certs that don't need it stay server-only. Re-distributes the freshly-issued
        material to the cert's targets, like /api/le/issue."""
        body = await request.json()
        enabled = bool(body.get("enabled", body.get("client_auth", False))) if isinstance(body, dict) else False
        _le_guard_change(request, domain)
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
        hub = app.state.hub
        renew_body = await request.json()
        renew_body = dict(renew_body) if isinstance(renew_body, dict) else {}
        # A single-domain renew is a change op → require ownership. A renew-all
        # (no domain) is a FLEET-WIDE op across every tenant's certs → Global
        # Admin only; a tenant-admin must name a domain they own.
        if renew_body.get("domain"):
            _le_guard_change(request, renew_body["domain"])
        elif not _is_admin(_session_user(request)):
            raise HTTPException(
                status_code=403,
                detail="Renewing all certificates is a Global Admin action. "
                       "Specify a domain you own to renew just that certificate.")
        # Re-seed DNS-01 hook creds from the vault for this renew, so an on-demand
        # renew succeeds even if the spoke's local he-login.ini was lost.
        try:
            vmap = await hub._le_resolve_vault_map()
            if vmap:
                renew_body["vault_dns_creds"] = vmap
        except Exception as e:  # noqa: BLE001
            logger.debug("le renew vault map resolve skipped: %s", e)
        hub, le_sid, payload = await _le_request("LE_RENEW_CERT", renew_body,
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
        body = await request.json()
        domain = (body or {}).get("domain") if isinstance(body, dict) else None
        if domain:
            _le_guard_change(request, domain)
        elif not _is_admin(_session_user(request)):
            raise HTTPException(
                status_code=403,
                detail="Revoking requires naming a domain you own.")
        result = await _relay_spoke(_get_le_spoke(app.state.hub), "LE_REVOKE_CERT",
                                    body, log_name="le_revoke_cert",
                                    timeout=_LE_CERTBOT_TIMEOUT)
        # Drop the stored vault DNS-01 reference for a revoked domain so it isn't
        # re-pushed to spokes after the cert is gone.
        if domain and _le_forget_vault_ref(domain):
            try:
                await app.state.hub.state.save_state_now()
            except Exception as e:  # noqa: BLE001
                logger.warning("prune le vault ref for %s failed: %s", domain, e)
        # Ownership metadata is no longer meaningful once the cert is gone.
        if domain and _lca.forget(hub, domain):
            await _le_persist("revoke forget")
        return result

    @app.post("/api/le/distribute")
    async def le_distribute(request: Request):
        """Re-push any stale cert material to its targets now (no certbot
        invocation — just LE_GET_CERT → INSTALL_CERT for targets whose
        last_pushed_hash differs). Returns the refreshed cert list (for the
        table) with an added ``distribution`` per-target summary so the UI can
        show a per-target toast — mirrors /api/le/issue. Without the summary,
        Distribute now gave the UI zero feedback (results were only in
        Logs/Certificates, which needs a manual refresh)."""
        # Fleet-wide redistribute across every tenant's certs → Global Admin only.
        # A tenant-admin re-deploys a cert they own via
        # POST /api/le/certs/{domain}/distribute (ownership-guarded).
        if not _is_admin(_session_user(request)):
            raise HTTPException(
                status_code=403,
                detail="Distributing all certificates is a Global Admin action. "
                       "Use per-certificate deploy for a certificate you own.")
        hub = app.state.hub
        le_sid = _get_le_spoke(hub)
        try:
            dist = await hub._distribute_all_certs(le_sid)
        except Exception as e:
            logger.exception("le_distribute failed")
            raise HTTPException(status_code=500, detail=str(e))
        # Distributing a cert to the "hub" target self-restarts the hub (to load
        # the new server cert), which briefly severs the le spoke connection.
        # The distribution itself already succeeded (``dist`` holds the per-
        # target results); don't turn that into a red "failed" just because the
        # trailing refresh can't reach the momentarily-gone le spoke. Fall back
        # to the warm cert cache (marked stale) so the UI still renders the
        # table + the per-target toast, mirroring GET /api/le/certs.
        try:
            payload = await _relay_spoke(le_sid, "LE_LIST_CERTS", log_name="le_distribute")
        except HTTPException:
            cached = hub.le_cache_get("certs")
            payload = (dict(cached) if isinstance(cached, dict)
                       else {"certs": cached or []})
            payload["stale"] = True
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
        _le_guard_change(request, domain)
        # Per-target tenant scope (same rule as le_add_target): a tenant-admin may
        # re-deploy only to a target in their own tenant; the hub + shared spokes
        # are Global-Admin-only.
        _le_guard_target(request, body.get("module_type"),
                         body.get("identifier"), body.get("spoke_id"))
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
    async def le_available_targets(request: Request):
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
        shaping is in cert_distribution.build_available_targets (pure, tested).

        Tenant scoping: a non-admin (tenant-admin) sees ONLY targets bound to one
        of their own tenants — the hub and any shared / other-tenant target are
        omitted, so they can't select an install target they aren't allowed to
        deploy to (le_add_target / le_distribute_target enforce the same rule)."""
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
        targets = build_available_targets(
            dict(hub.spoke_module_types), hub.active_connections,
            module_names, hub.CERT_CAPABLE_MODULES, agents,
            netbox_server_agents=set(getattr(hub, "netbox_server_agents", set())),
            ldap_server_agents=set(getattr(hub, "ldap_server_agents", set())))
        sess = _session_user(request)
        if sess and not _is_admin(sess):
            mine = set(_lca.user_tenants(sess)) | {_lca.current_tenant(sess)}
            targets = [t for t in targets
                       if _le_target_tenant(t.get("module_type"),
                                            t.get("identifier"),
                                            t.get("spoke_id")) in mine]
        return {"targets": targets}

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
        _le_guard_change(request, domain)
        # Per-target tenant scope: a Global Admin may attach any target (incl. the
        # hub + shared spokes); a tenant-admin may attach ONLY a spoke/agent bound
        # to one of their own tenants (their Proxmox nodes, their spokes) — never
        # the hub and never another tenant's or an unattributable/shared target.
        _le_guard_target(request, body.get("module_type"),
                         body.get("identifier"), body.get("spoke_id"))
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

    @app.post("/api/le/certs/{domain}/ab")
    async def le_set_ab(domain: str, request: Request):
        """H1: label a managed cert as the AppBuilder cert. Toggles membership of
        ``domain`` in ``global_config['ab_cert_identities']`` — the pinned
        list the HUB_REQUEST channel authorizes on (a connection must present one
        of these certs over mTLS, see ``LabManagerHub._hub_request_authorized``).
        ``enabled:true`` adds the domain (dedup, order-stable); ``false`` removes
        it. Admin-only. The cert itself is issued/managed via the normal LE flow;
        this just records which domain's cert is the AppBuilder identity."""
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
        pinned = [str(n).strip().lower() for n in (gc.get("ab_cert_identities") or [])]
        if enabled:
            if domain not in pinned:
                pinned.append(domain)
        else:
            pinned = [n for n in pinned if n != domain]
        gc["ab_cert_identities"] = pinned
        hub.state.system_state["global_config"] = gc
        await hub.state.save_state_now()
        logger.info("[H1] AppBuilder cert label for %s -> %s (pinned=%s)",
                    domain, enabled, pinned)
        return {"status": "ok", "domain": domain, "ab": enabled,
                "pinned": pinned}

    @app.get("/api/mtls/trust-diag")
    async def mtls_trust_diag(request: Request):
        """H1 debug: what the hub's mTLS client-verify path trusts, and whether it
        would ACCEPT each pinned AppBuilder cert. Surfaces (a) the LM_MTLS_CA chain in
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
        gc = hub.state.system_state.get("global_config", {}) or {}
        pinned = [str(n).strip() for n in (gc.get("ab_cert_identities") or []) if str(n).strip()]
        # Per-connection mTLS status: which connected spokes/agents ACTUALLY
        # presented a verified client cert vs. connected cert-less (permissive
        # fallback). Answers "who is really using mTLS" — the whole point being that
        # under CERT_OPTIONAL a spoke works either way, so mTLS can be silently
        # inactive fleet-wide without anyone noticing.
        pinned_lc = {str(n).strip().lower() for n in pinned}
        _md = hub.state.system_state.get("module_metadata", {}) or {}

        def _label(_pk):
            m = _md.get(_pk, {}) or {}
            nm = (m.get("display_name") or m.get("name") or m.get("hostname") or "").strip()
            return nm or _pk

        clients = []
        for pk, ws in list((hub.active_connections or {}).items()):
            ident = getattr(ws, "peer_cert_identity", None)
            raw = getattr(ws, "peer_cert_raw", None) or {}
            sans = list(ident) if ident else []
            subj = ""
            issuer = ""
            not_after = ""
            try:
                if isinstance(raw, dict):
                    subj = ", ".join("=".join(x) for rdn in raw.get("subject", ()) for x in rdn)
                    issuer = ", ".join("=".join(x) for rdn in raw.get("issuer", ()) for x in rdn)
                    not_after = raw.get("notAfter", "") or ""
            except Exception:  # noqa: BLE001
                pass
            # Co-located spokes connect over plaintext loopback (ws://127.0.0.1):
            # no TLS leg, so mTLS is not applicable (never a failure — just N/A).
            local = hub._is_loopback_spoke(pk)
            clients.append({
                "spoke_id": pk,
                "label": _label(pk),
                "module_type": (hub.spoke_module_types or {}).get(pk, ""),
                "mtls_active": bool(ident),        # presented a VERIFIED client cert
                "local": local,                    # loopback ws — mTLS N/A (remote-only)
                "sans": sans,
                "subject": subj,
                "issuer": issuer,
                "not_after": not_after,
                "is_ab_pinned": bool(ident) and any(s.lower() in pinned_lc for s in sans),
            })
        # Sort: active first, then remote-eligible (cert-less), then loopback N/A last.
        clients.sort(key=lambda c: (not c["mtls_active"], c.get("local", False),
                                    c.get("label") or c["spoke_id"]))
        diag["clients"] = clients
        diag["clients_summary"] = {
            "connected": len(clients),
            "mtls_active": sum(1 for c in clients if c["mtls_active"]),
            "cert_less": sum(1 for c in clients if not c["mtls_active"] and not c.get("local")),
            "local": sum(1 for c in clients if c.get("local")),
        }
        # Pinned AppBuilder identity — reflect the LIVE connection: is a connected
        # spoke presenting a VERIFIED cert whose SAN matches the pin? (The LE cert is
        # no longer the mTLS cert — ab presents the hub-CA clientAuth cert, so
        # verifying the LE cert here always failed and was misleading.)
        checks = []
        for name in pinned:
            nl = name.lower()
            live = next((c for c in clients if c["mtls_active"]
                         and any(str(s).lower() == nl for s in (c.get("sans") or []))), None)
            if live:
                checks.append({"domain": name, "ok": True,
                               "detail": f"presented + verified live by "
                                         f"{live.get('label') or live.get('spoke_id')}"
                                         f" (issuer: {live.get('issuer', '')})"})
            else:
                checks.append({"domain": name, "ok": False,
                               "detail": "no connected spoke is presenting a verified cert "
                                         "with this SAN — issue/re-provide its mTLS cert"})
        diag["pinned_cert_checks"] = checks
        gc2 = hub.state.system_state.get("global_config", {}) or {}
        diag["auto_provision"] = bool(gc2.get("mtls_ca_auto_provision", True))
        return diag

    @app.post("/api/mtls/auto-provision")
    async def mtls_set_auto_provision(request: Request):
        """Toggle whether the hub auto-mints + delivers a Hub-CA mTLS client cert to
        each spoke on connect. Default ON. Admin-only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        body = await request.json()
        enabled = bool(body.get("enabled")) if isinstance(body, dict) else False
        gc = hub.state.system_state.get("global_config", {}) or {}
        gc["mtls_ca_auto_provision"] = enabled
        hub.state.system_state["global_config"] = gc
        await hub.state.save_state_now()
        logger.info("[mtls] auto-provision set to %s", enabled)
        return {"status": "ok", "auto_provision": enabled}

    @app.get("/api/hub/health")
    async def hub_health(request: Request):
        """Hub event-loop / overload health for the WebUI diagnostics card. The
        loop-lag + protect + per-spoke msg-rate signals here are what diagnose
        fleet-wide WS backpressure (spokes dropping with 1011 keepalive timeout
        because a saturated hub loop can't drain their sockets). Admin-only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        import psutil as _ps
        lag_hist = list(getattr(hub, "_loop_lag_hist", []) or [])
        gc = (hub.state.get_global_config() or {})
        pcfg = (gc.get("protect", {}) or {})
        try:
            memp = _ps.virtual_memory().percent
        except Exception:  # noqa: BLE001
            memp = 0.0
        # Top talkers — the spokes offering the most frames/s (a provisioning storm
        # relaying a flood of agent logs is the usual hub-loop saturator).
        smps = getattr(hub, "spoke_mps", {}) or {}
        top = sorted(smps.items(), key=lambda kv: kv[1] or 0, reverse=True)[:8]
        def _label(sid):
            try:
                return hub._spoke_label(sid)
            except Exception:  # noqa: BLE001
                return sid
        now = time.time()
        recent_to = len({k: v for k, v in (getattr(hub, "_recent_request_timeouts", {}) or {}).items()
                         if v > now})
        # Per-connection TRANSPORT health — to rule network path (the hub is in
        # Azure) in or out. rtt_ms is the websockets keepalive ping RTT (network
        # latency to that spoke); write_buffer_bytes is the hub→spoke outbound
        # backlog (a growing buffer = that spoke/network isn't draining = transport
        # backpressure, NOT a hub-loop problem). High loop_lag + LOW rtt/buffers =
        # hub loop; high rtt or growing buffers = network/spoke transport.
        tel_all = getattr(hub, "spoke_telemetry", {}) or {}
        conns = []
        for pk, ws in list((getattr(hub, "active_connections", {}) or {}).items()):
            lat = getattr(ws, "latency", None)   # seconds (websockets keepalive RTT)
            wbuf = None
            try:
                tr = getattr(ws, "transport", None)
                if tr is not None and hasattr(tr, "get_write_buffer_size"):
                    wbuf = int(tr.get_write_buffer_size())
            except Exception:  # noqa: BLE001
                wbuf = None
            raddr = ""
            try:
                ra = getattr(ws, "remote_address", None)
                raddr = ra[0] if ra else ""
            except Exception:  # noqa: BLE001
                pass
            tel = tel_all.get(pk, {}) or {}
            conns.append({
                "spoke": _label(pk),
                "remote_ip": raddr or tel.get("remote_ip", ""),
                "rtt_ms": (round(lat * 1000, 1) if isinstance(lat, (int, float)) and lat else None),
                "write_buffer_bytes": wbuf,
                "mps": round((smps.get(pk) or 0), 1),
            })
        conns.sort(key=lambda c: ((c["write_buffer_bytes"] or 0), (c["rtt_ms"] or 0)), reverse=True)
        return {
            "loop_lag_s": round(getattr(hub, "_loop_lag", 0.0), 3),
            "loop_lag_max_s": round(max(lag_hist) if lag_hist else 0.0, 3),
            "loop_lag_avg_s": round(sum(lag_hist) / len(lag_hist), 3) if lag_hist else 0.0,
            "loop_lag_hist": [round(x, 3) for x in lag_hist],
            "cpu_pct": round(getattr(hub, "_proc_cpu", 0.0), 1),
            "mem_pct": round(memp, 1),
            "mps": round(getattr(hub, "mps", 0.0), 1),
            "throughput_mbps": round(getattr(hub, "throughput_mbps", 0.0), 3),
            "protect_mode": bool(getattr(hub, "_protect_mode", False)),
            "protect_reason": getattr(hub, "_protect_reason", "") or "",
            "protect_since": (round(now - getattr(hub, "_protect_entered_ts", 0), 0)
                              if getattr(hub, "_protect_mode", False) else 0),
            "request_timeouts_recent": recent_to,
            "request_timeouts_total": int(getattr(hub, "_request_timeouts_total", 0)),
            "connected_spokes": len(getattr(hub, "active_connections", {}) or {}),
            "top_talkers": [{"spoke": _label(sid), "mps": round(m or 0, 1)} for sid, m in top],
            "connections": conns,
            "thresholds": {
                "loop_lag_high_s": float(pcfg.get("loop_lag_high_s", 0.75)),
                "cpu_high_pct": float(pcfg.get("cpu_high_pct", 90)),
                "mem_high_pct": float(pcfg.get("mem_high_pct", 90)),
            },
        }

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
        # A shared cert may be deployed by any tenant to THEIR OWN devices; an
        # owned cert only by an owner/admin. Reject a deploy to a device that
        # isn't the caller's (unless they can change the cert outright).
        dev_tenant = _nw_device_tenant(device_id)
        if not _lca.can_deploy(hub, _session_user(request), domain, dev_tenant):
            raise HTTPException(
                status_code=403,
                detail="You may only deploy this certificate to devices in your "
                       "own tenant, and only if the certificate is shared.")
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
    async def le_remove_target(domain: str, idx: int, request: Request):
        # Owner-or-admin: detaching a target from a cert you own only removes the
        # install intent (no cert material is pushed), so the cert-change guard is
        # the right gate — a tenant-admin may prune targets from their own cert.
        _le_guard_change(request, domain)
        return await _relay_spoke(_get_le_spoke(app.state.hub), "LE_REMOVE_TARGET",
                                  {"domain": domain, "idx": idx},
                                  log_name="le_remove_target")

    # ─── DHCP API ─────────────────────────────────────────────────────────────

    def _get_dhcp_spoke(hub):
        return get_spoke_or_503(hub, "dhcp", "DHCP")

    # ── tenant-aware DHCP spoke resolution ──────────────────────────────────
    # Mirrors the DNS resolver above / cppm.py's _nac_spoke_for_request:
    # multiple ``dhcp`` spokes may be connected, each bound to a different
    # tenant (a tenant runs their own Kea server). Every DHCP route below used
    # to resolve via ``_get_dhcp_spoke`` — the first connected dhcp spoke, full
    # stop — so with more than one dhcp spoke connected, EVERY tenant's
    # request silently hit whichever one connected first.
    def _dhcp_spoke_for_request(request: Request, tenant: str = None):
        """The dhcp spoke that should answer THIS request, or a 503 (matches
        the ``get_spoke_or_503``/``_get_dhcp_spoke`` contract every caller
        here already relies on — ``_relay_spoke`` itself does NOT check for a
        falsy spoke_id, it trusts the resolver already raised). Prefers the
        caller's effective tenant's own ``dhcp_instances`` record (a tenant-
        admin's self-configured DHCP connection via
        ``/tenant/devices/dhcp-instances``), falling back to a spoke bound to
        that tenant by module_type, then the shared-tenant spoke. Admin with
        no tenant selected keeps the legacy global-first-connected-spoke
        behavior — see ``_dhcp_merge_fanout`` for the admin combined view."""
        hub = app.state.hub
        tid = _effective_tenant(request, tenant)
        if not tid:
            return spoke_or_503(hub.get_spoke_by_type("dhcp"), "DHCP")
        instances = (hub.state.system_state.get("global_config", {}) or {}).get("dhcp_instances", []) or []
        inst = next((i for i in instances if isinstance(i, dict) and i.get("tenant_id") == tid), None)
        spoke_id = (inst or {}).get("spoke_id") or ""
        if spoke_id and hub._primary_key(spoke_id) in hub.active_connections:
            return spoke_id
        resolved = (hub.get_dhcp_spoke_for_shared()
                   if access.tenant_is_shared(tid)
                   else hub.get_dhcp_spoke_for_tenant(tid))
        return spoke_or_503(resolved, "DHCP")

    async def _dhcp_merge_fanout(cmd: str, payload: dict, list_key: str):
        """Admin, no tenant selected, 2+ dhcp spokes connected: fan ``cmd``
        out to EVERY connected, approved dhcp spoke, tag each returned record
        with its spoke's owning tenant (``_tenant``), and merge. Mirrors
        cppm.py's ``_nac_merge_fanout`` / the DNS resolver above."""
        hub = app.state.hub
        spokes = [s for s in (hub.get_all_spokes_by_type("dhcp") or [])
                  if s in hub.active_connections and hub.approved_modules.get(s, False)]
        if not spokes:
            raise HTTPException(status_code=503, detail="No spoke connected")

        async def _one(sid):
            try:
                result = await hub.request_response(sid, cmd, payload or {})
                data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
                data = _spoke_payload_or_raise(data)
            except Exception as e:  # noqa: BLE001 — one bad/offline spoke must not fail the merge
                logger.debug("dhcp merge fanout: %s failed: %s", sid, e)
                return []
            recs = data.get(list_key) if isinstance(data, dict) else None
            if not isinstance(recs, list):
                return []
            tid = hub.state.get_spoke_tenant(sid) or ""
            return [{**r, "_tenant": tid} if isinstance(r, dict) else r for r in recs]

        merged = [r for recs in await asyncio.gather(*[_one(s) for s in spokes]) for r in recs]
        return {list_key: merged, "total": len(merged)}

    async def _dhcp_list_or_merge(request: Request, tenant: str, cmd: str,
                                  payload: dict, list_key: str, log_name: str):
        """Shared GET-list preamble for subnets/leases/reservations: admin
        with no tenant selected AND 2+ dhcp spokes connected combines every
        spoke (see _dhcp_merge_fanout); otherwise the normal single-spoke
        tenant-resolved relay."""
        sess = _session_user(request)
        tid = _effective_tenant(request, tenant)
        if not tid and sess and _is_admin(sess) and len(hub.get_all_spokes_by_type("dhcp") or []) > 1:
            return await _dhcp_merge_fanout(cmd, payload, list_key)
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), cmd, payload, log_name=log_name)

    @app.get("/api/dhcp/subnets")
    async def dhcp_list_subnets(request: Request, tenant: str = None):
        """List DHCP subnets configured on the Kea spoke, subnet-filtered per
        the caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). The subnet's ``subnet`` field is a CIDR; the
        filter matches it against the tenant's NetBox prefixes by overlap, so a
        non-admin sees only their own tenant's subnets. Admins always see all.
        Unfiltered when the subnet-filter toggle is off (shared single-view Kea).

        Admin with no tenant selected AND 2+ dhcp spokes connected: subnets
        are combined across every spoke (tagged _tenant)."""
        logger.debug("relay GET /api/dhcp/subnets")
        data = await _dhcp_list_or_merge(request, tenant, "DHCP_LIST_SUBNETS", {}, "subnets", "dhcp_list_subnets")
        return await _filter_tenant(request, data, "dhcp", ["subnet"], tenant)

    @app.get("/api/dhcp/leases")
    async def dhcp_list_leases(request: Request, subnet: str = None, tenant: str = None):
        """List DHCP leases (optionally per-subnet); subnet-filtered before
        return. Admin with no tenant selected AND 2+ dhcp spokes connected:
        leases are combined across every spoke (tagged _tenant)."""
        logger.debug("relay %s %s subnet=%s", request.method, request.url.path, subnet)
        data = await _dhcp_list_or_merge(request, tenant, "DHCP_LIST_LEASES", {"subnet": subnet}, "leases", "dhcp_list_leases")
        return await _filter_tenant(request, data, "dhcp", ["ip", "address"], tenant)

    @app.post("/api/dhcp/reservation")
    async def dhcp_add_reservation(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), "DHCP_ADD_RES", body, log_name="dhcp_add_reservation")

    @app.get("/api/dhcp/reservations")
    async def dhcp_list_reservations(request: Request, tenant: str = None):
        """List DHCP reservations from the Kea spoke, subnet-filtered per the
        caller's tenant when the ``dhcp`` subnet-filter module is enabled
        (mirrors /api/dhcp/leases). A reservation's ``ip`` is matched against
        the tenant's NetBox prefixes, so a non-admin sees only their own
        tenant's reservations (hostname/MAC/client-id are tenant-identifying).
        Admins always see all. Unfiltered when the toggle is off.

        Admin with no tenant selected AND 2+ dhcp spokes connected:
        reservations are combined across every spoke (tagged _tenant)."""
        logger.debug("relay GET /api/dhcp/reservations")
        data = await _dhcp_list_or_merge(request, tenant, "DHCP_LIST_RES", {}, "reservations", "dhcp_list_reservations")
        return await _filter_tenant(request, data, "dhcp", ["ip"], tenant)

    @app.put("/api/dhcp/reservation")
    async def dhcp_update_reservation(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), "DHCP_UPDATE_RES", body, log_name="dhcp_update_reservation")

    @app.delete("/api/dhcp/reservation")
    async def dhcp_delete_reservation(request: Request, tenant: str = None):
        body = await request.json()
        await _constrain_shared_write(request, body, ["ip", "address"], "DHCP reservation")
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), "DHCP_DEL_RES", body, log_name="dhcp_delete_reservation")

    @app.get("/api/dhcp/status")
    async def dhcp_status(request: Request, tenant: str = None):
        """Kea DHCP4 service status / health from the DHCP spoke."""
        logger.debug("relay GET /api/dhcp/status")
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), "DHCP_STATUS", log_name="dhcp_status")

    @app.get("/api/dhcp/stats")
    async def dhcp_stats(request: Request, tenant: str = None):
        """Kea DHCP4 statistics — global + per-subnet pool utilization and the
        headline packet counters for the DHCP analytics panel."""
        logger.debug("relay GET /api/dhcp/stats")
        return await _relay_spoke(_dhcp_spoke_for_request(request, tenant), "DHCP_STATS", log_name="dhcp_stats")

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
            raise HTTPException(status_code=503, detail=result.get("reason", "No spoke connected"))
        if result.get("status") == "error":
            raise HTTPException(status_code=500, detail=result.get("error", "sync failed"))
        return result

    # ── Cache management (/admin/cache/*, /setup/cache-config) ───────────────
