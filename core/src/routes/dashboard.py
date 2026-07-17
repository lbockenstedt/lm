"""Dashboard summary/all-tenants + cross-system search routes."""
from api import (
    HTTPException, Request, access, filter_items_by_prefixes, get_tenant_scoping, logger,
)


def register(app, hub, ctx):
    """Register dashboard routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    _resolve_prefixes_for_tenant = ctx._resolve_prefixes_for_tenant
    _filter_enabled = ctx._filter_enabled

    async def _compute_tenant_counts(hub, scoping: dict) -> dict:
        """Per-tenant aggregate counts across all connected spokes, scoped by
        the tenant's netbox_tenant_slug / proxmox_tag. Returns
        {devices, vms, sessions, prefixes, ips_used}. Shared by the single-tenant
        dashboard summary and the admin all-tenants overview so both show
        identical numbers for a given tenant."""
        import asyncio as _asyncio
        nb_slug  = scoping["netbox_tenant_slug"] or None
        pxmx_tag = scoping["proxmox_tag"]        or None

        spoke_ipam       = hub.get_spoke_by_type("ipam")
        # Tenant-aware: only count VMs from a hypervisor BOUND to this tenant.
        # The global get_hypervisor_spoke() returned tenant 1's pxmx spoke for
        # every tenant, and a tagless tenant's unfiltered PXMX_LIST_VMS then
        # returned the whole hypervisor's VM list — so all tenants showed the
        # one bound tenant's VMs. Now a tenant with no bound hypervisor → 0 VMs.
        # The admin's unscoped/default view still falls back to any hypervisor.
        spoke_hypervisor = hub.get_hypervisor_spoke_for_tenant(scoping.get("tenant_id"))
        spoke_nac        = hub.get_spoke_by_type("nac")

        async def _req(spoke, cmd, payload=None):
            if not spoke:
                return {}
            try:
                timeout = 30.0 if isinstance(cmd, str) and cmd.startswith("NETBOX_") else 5.0
                r = await hub.request_response(spoke, cmd, payload or {}, timeout=timeout)
                return r.get("payload", {}).get("data", r) if isinstance(r, dict) else {}
            except Exception:
                return {}

        devices_r, prefixes_r, ips_r, vms_r, sessions_r = await _asyncio.gather(
            _req(spoke_ipam, "NETBOX_GET_DEVICES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_PREFIXES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_IPS",     {"tenant": nb_slug}),
            _req(spoke_hypervisor, "PXMX_LIST_VMS",
                 {"tag_filter": pxmx_tag} if pxmx_tag else {}),
            _req(spoke_nac, "CPPM_GET_ACCESS_TRACKER", {}),
        )

        devices  = len(devices_r.get("devices",   []))
        prefixes = len(prefixes_r.get("prefixes", []))
        ips_used = len(ips_r.get("ip_addresses",  []))
        all_vms  = vms_r.get("vms", [])
        sessions_list = sessions_r.get("sessions", sessions_r.get("data", []))
        # Scope the VM + active-session counts by the tenant's subnets so the
        # dashboard matches the (tenant-scoped) hypervisor + Access Tracker views,
        # not the global totals. VMs filter on their ``ips`` list (a VM with no
        # concrete IPs, e.g. stopped, is shown — can't filter, err on showing).
        sess_prefixes = await _resolve_prefixes_for_tenant(hub, scoping.get("tenant_id"))
        if sess_prefixes and _filter_enabled(hub, "hypervisor"):
            all_vms = filter_items_by_prefixes(all_vms, sess_prefixes, ["ips"])
        # NAC sessions come from the SHARED (global) nac spoke — CPPM_GET_ACCESS_TRACKER
        # returns every tenant's sessions, so subnet scoping is the ONLY isolation.
        # A tenant with no bound prefixes must therefore show 0, NOT the global list
        # (else every unbound tenant shows the same cross-tenant total). Strict,
        # matching the tenant-bound hypervisor VM isolation.
        sessions_list = (filter_items_by_prefixes(sessions_list, sess_prefixes, ["ip"])
                         if sess_prefixes else [])
        vms      = sum(1 for v in all_vms if v.get("status") == "running")
        sessions = len(sessions_list)

        return {
            "devices":   devices,
            "vms":       vms,
            "sessions":  sessions,
            "prefixes":  prefixes,
            "ips_used":  ips_used,
        }

    @app.get("/api/dashboard/summary")
    async def dashboard_summary(request: Request, tenant: str = None):
        """
        Aggregate counts for the active tenant across all connected spokes.
        Returns: devices (NetBox), vms (Proxmox running), sessions (CPPM), prefixes, ips_used.
        All counts are scoped by the tenant's netbox_tenant_slug / proxmox_tag.
        """
        hub = app.state.hub
        scoping = get_tenant_scoping(hub, _resolve_tenant(request, tenant))
        counts = await _compute_tenant_counts(hub, scoping)
        return {"tenant": scoping["tenant_id"], **counts}

    @app.get("/api/dashboard/infra-status")
    async def infra_status(request: Request, tenant: str = None):
        """Hub + spoke/agent up-down summary (green/yellow/red) for the Overview.
        Tenant-scoped: a Global Admin sees ALL (or a chosen tenant); a tenant user
        sees only spokes bound to its tenant (module_metadata.tenant_id) plus
        untagged shared infra. green = connected + healthy; yellow = out-of-contact
        WARNING tier; red = offline or ERROR tier. Hub is always green (it served
        this request)."""
        hub = app.state.hub
        sess = _session_user(request)
        is_admin = _is_admin(sess)
        tid = _resolve_tenant(request, tenant)
        want_all = is_admin and (tenant in (None, "", "all"))
        md = hub.state.system_state.get("module_metadata", {}) or {}
        connected = set((hub.active_connections or {}).keys())
        try:
            alerts = {a["spoke_id"]: a.get("tier") for a in hub.get_active_spoke_alerts()}
        except Exception:  # noqa: BLE001
            alerts = {}
        items = []
        for sid, meta in md.items():
            meta = meta or {}
            stid = meta.get("tenant_id")
            if not want_all and tid and stid and stid != tid:
                continue  # bound to another tenant (untagged = shared infra → shown)
            tier = alerts.get(sid, "none")
            online = hub._primary_key(sid) in connected
            status = ("red" if (not online or tier == "error")
                      else "yellow" if tier == "warning" else "green")
            items.append({
                "id": sid,
                "name": meta.get("display_name") or meta.get("name") or sid,
                "type": hub.spoke_module_types.get(hub._primary_key(sid)) or meta.get("module_type") or "",
                "role": meta.get("role") or "",
                "tenant": stid or "",
                "online": online, "tier": tier, "status": status,
            })
        items.sort(key=lambda i: ({"red": 0, "yellow": 1, "green": 2}.get(i["status"], 3), i["name"]))
        counts = {c: sum(1 for i in items if i["status"] == c) for c in ("green", "yellow", "red")}
        return {"hub": {"status": "green", "name": "Hub"}, "items": items,
                "counts": counts, "tenant": tid, "all_tenants": bool(want_all)}

    # Admin all-tenants overview: memoized 60s so repeated renders don't re-fan-out.
    _all_tenants_summary_cache: dict = {"ts": 0.0, "data": None}

    @app.get("/api/dashboard/all-tenants")
    async def dashboard_all_tenants(request: Request, refresh: int = 0):
        """Admin-only: one row per tenant with the same counts as the
        single-tenant summary, fanned out in parallel (bounded) and memoized
        for 60s. ``?refresh=1`` bypasses the memo. ``default`` is excluded
        (unscoped — its counts would be global/all and misleading)."""
        import asyncio as _asyncio, time as _time
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin only")
        if not refresh and _all_tenants_summary_cache["data"] is not None \
                and (_time.time() - _all_tenants_summary_cache["ts"]) < 60:
            return _all_tenants_summary_cache["data"]

        tenants = hub.state.tenant_state.get("tenants", {})
        tids = [tid for tid in tenants.keys() if tid != "default"]

        sem = _asyncio.Semaphore(5)

        async def _one(tid):
            cfg = tenants.get(tid) or {}
            scoping = get_tenant_scoping(hub, tid)
            async with sem:
                counts = await _compute_tenant_counts(hub, scoping)
            return {
                "id":          tid,
                "name":        cfg.get("name") or tid,
                "slug":        cfg.get("netbox_tenant_slug") or tid,
                "description": cfg.get("description", ""),
                **counts,
            }

        rows = await _asyncio.gather(*[_one(tid) for tid in tids], return_exceptions=True)
        out = []
        for tid, row in zip(tids, rows):
            if isinstance(row, Exception):
                logger.warning(f"all-tenants counts for '{tid}' failed: {row}")
                cfg = tenants.get(tid) or {}
                out.append({
                    "id": tid, "name": cfg.get("name") or tid,
                    "slug": cfg.get("netbox_tenant_slug") or tid,
                    "description": cfg.get("description", ""),
                    "devices": 0, "vms": 0, "sessions": 0, "prefixes": 0, "ips_used": 0,
                })
            else:
                out.append(row)
        out.sort(key=lambda r: r["name"].lower())
        data = {"tenants": out}
        _all_tenants_summary_cache["ts"] = _time.time()
        _all_tenants_summary_cache["data"] = data
        return data

    @app.get("/api/search")
    # ── Dashboard + global search (/api/search, /api/dashboard) ──────────────
    # cross_system_search fans `q` to every spoke type (NETBOX/VMs/SESSIONS/
    # USERS/DHCP); matching is spoke-side. See docs/architecture.md search table
    # and memory `global-device-search-fanout`.
    async def cross_system_search(request: Request, q: str, tenant: str = None):
        """
        Fan-out search across all connected spoke types.
        Each spoke's results are tagged with source= so the UI can group them.

        Query type detection:
          - IP / prefix: contains '.' or ':' (IPv4/IPv6/CIDR)
          - MAC: matches hex pairs separated by : or -
          - Name / hostname / username: everything else
        """
        import re, asyncio as _asyncio
        hub = app.state.hub
        if not q or not q.strip():
            raise HTTPException(status_code=400, detail="q must not be empty")

        raw_q = q.strip()
        # Hub-side MAC normalization: a MAC typed in any separator form (colon /
        # dash / dot / bare 12-hex) is normalized to the canonical lower-colon
        # form before fan-out, so a spoke that substring-matches on a single form
        # (the netbox spoke's REST q-search against the colon-form mac_address
        # custom field) finds it regardless of how it was typed. The CPPM /
        # OPNsense spokes already match separator-insensitively; this also fixes
        # the query_type (a bare/dash/dot MAC used to be filed as a "name"
        # query). See memory `global-device-search-fanout`.
        _MAC_RE = re.compile(
            r'^([0-9a-fA-F]{2}[:\-\.]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$')
        is_mac = bool(_MAC_RE.match(raw_q))
        q_search = access.norm_mac(raw_q) if is_mac else raw_q

        resolved = _resolve_tenant(request, tenant)
        scoping = get_tenant_scoping(hub, resolved)
        payload = {"q": q_search, "tenant": scoping["netbox_tenant_slug"] or resolved}

        async def _call(spoke, cmd):
            if not spoke:
                return []
            try:
                r = await hub.request_response(spoke, cmd, payload)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                return d.get("results", []) if isinstance(d, dict) else []
            except Exception as e:
                return [{"source": cmd, "type": "error", "name": str(e)}]

        async def _empty():
            # Placeholder for a leg a non-admin may not run (directory SEARCH_USERS
            # is admin-only — see can_search_directory) so the gather shape stays
            # uniform without fanning the directory spoke.
            return []

        spoke_ipam       = hub.get_spoke_by_type("ipam")
        spoke_hypervisor = hub.get_hypervisor_spoke()
        spoke_nac        = hub.get_spoke_by_type("nac")
        spoke_directory  = hub.get_spoke_by_type("directory")
        spoke_firewall   = hub.get_spoke_by_type("firewall")

        # SECURITY: the directory (LDAP) SEARCH_USERS leg bypasses the
        # ``/api/ldap/*`` admin gate — a non-admin could enumerate directory
        # users via the global search. The IPAM/NAC/Hypervisor/Firewall legs
        # are tenant-scoped via the payload tenant slug above, but directory
        # users are not tenant-scoped, so fan SEARCH_USERS only for admins.
        sess = _session_user(request)
        can_search_directory = bool(sess and _is_admin(sess))

        tasks = [
            _call(spoke_ipam,       "NETBOX_SEARCH"),
            _call(spoke_hypervisor, "SEARCH_VMS"),
            _call(spoke_nac,        "SEARCH_SESSIONS"),
            _call(spoke_directory,  "SEARCH_USERS") if can_search_directory else _empty(),
            _call(spoke_firewall,   "SEARCH_DHCP"),
        ]
        all_results = await _asyncio.gather(*tasks)
        merged = [item for sublist in all_results for item in sublist]

        # Categorise for the UI
        is_ip  = bool(re.match(r'^[\d:.]+(/\d+)?$', raw_q))
        return {
            "query":       q,
            "query_type":  "ip" if is_ip else ("mac" if is_mac else "name"),
            "total":       len(merged),
            "results":     merged,
            "spokes_queried": {
                "ipam":       spoke_ipam is not None,
                "hypervisor": spoke_hypervisor is not None,
                "nac":        spoke_nac is not None,
                # directory leg is admin-only; reflect whether it actually ran.
                "directory":  bool(spoke_directory is not None and can_search_directory),
                "firewall":   spoke_firewall is not None,
            },
        }
