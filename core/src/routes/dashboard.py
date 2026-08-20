"""Dashboard summary/all-tenants + cross-system search routes."""
import time

from api import (
    HTTPException, Request, _unwrap_spoke, access, filter_items_by_prefixes, get_tenant_scoping, logger,
)
from search_index import search_scope_key, search_result_matches

# GREEN/YELLOW/RED age bands for a relayed agent, matching HeartbeatManager.get_status
# (and routes/pxmx.py:107-127) so one agent can't read "online" on the Spokes &
# Agents page and "offline" on the dashboard tile.
_AGENT_GREEN_S = 120
_AGENT_RED_S = 300


def relayed_agent_last_seen(hub) -> dict:
    """``{agent_primary_key: last_seen_epoch}`` for every relayed node agent.

    A node agent (pxmx / cs) NEVER appears in ``active_connections``: it dials
    its PARENT SPOKE, which relays ``AGENT_RELAY_UP`` to the hub. Two signals
    carry its liveness, and the freshest wins:

    * ``agent_info[pk]["last_seen"]`` — stamped on EVERY relayed frame
      (main.py ``_dispatch_relayed_agent_frame``); evicted when the parent
      spoke disconnects and wiped on hub restart.
    * the composite ``{spoke_pk}:{agent_pk}`` heartbeat key — persisted via
      ``spoke_last_seen`` and re-seeded on boot, so it survives both.

    Never raises: a malformed hub degrades to an empty index, which just means
    the caller falls back to the spoke-only test (previous behaviour).
    """
    out: dict = {}
    for pk, info in (getattr(hub, "agent_info", {}) or {}).items():
        ls = (info or {}).get("last_seen")
        if isinstance(ls, (int, float)):
            out[pk] = max(out.get(pk, 0.0), float(ls))
    hb = getattr(hub, "heartbeat", None)
    for key, ts in (getattr(hb, "last_seen", {}) or {}).items():
        k = str(key)
        if ":" in k and isinstance(ts, (int, float)):
            apk = k.split(":", 1)[1]
            out[apk] = max(out.get(apk, 0.0), float(ts))
    return out


def infra_item_status(hub, sid, tier, connected, agent_last, now=None):
    """``(online, status)`` for one Infrastructure Status row.

    Spokes keep the original test — a live WebSocket in ``active_connections``.
    Only when that says offline do we retry as a relayed AGENT, so a connected
    spoke's verdict is never reinterpreted and a spoke id that happens to
    collide with an agent key cannot be downgraded.

    Without the agent branch a perfectly healthy pxmx agent read as permanently
    "offline" here while Setup → Spokes & Agents showed it Online, seen seconds
    ago — the same spoke-vs-agent confusion ``spoke_alert_sync`` already fixed
    for the out-of-contact alerts.
    """
    now = time.time() if now is None else now
    online = hub._primary_key(sid) in connected
    agent_age = None
    if not online:
        last = (agent_last or {}).get(hub._agent_primary_key(sid))
        if isinstance(last, (int, float)) and last > 0:
            agent_age = max(0.0, now - last)
            online = agent_age < _AGENT_RED_S
    if not online or tier == "error":
        return online, "red"
    if tier == "warning" or (agent_age is not None and agent_age >= _AGENT_GREEN_S):
        return online, "yellow"
    return online, "green"


def _spoke_rosters(hub) -> dict:
    """Per-tenant spoke up/down/decommissioned roster built straight from
    ``known_modules`` + ``module_metadata`` + heartbeat — NOT from the
    connected-spoke count queries (those route only to live spokes, so an
    OFFLINE spoke contributes nothing and the user "can't see it" in the
    all-tenants overview). This is O(spokes), no fan-out.

    Returns ``{tenant_id: {up, down, decommissioned, down_spokes:[...]}}`` plus
    a ``"__shared__"`` bucket for untagged (shared / unassigned) spokes so they
    are never lost. A spoke is:
      * decommissioned → decommissioned bucket (record kept, alerts suppressed),
      * approved + in-contact → up,
      * approved + not in-contact → down (listed in down_spokes with last_seen),
      * not approved → skipped (pending onboarding, not a "down system").
    down_spokes entries: ``{spoke_id, name, module_type, last_seen_epoch}``.
    Never raises — best-effort so the overview never blanks on a bad state."""
    try:
        md = hub.state.system_state.get("module_metadata", {}) or {}
        connected = set((hub.active_connections or {}).keys())
        out: dict = {}
        def _bucket(tid):
            return out.setdefault(tid or "__shared__",
                                  {"up": 0, "down": 0, "decommissioned": 0,
                                   "down_spokes": []})
        for sid in (hub.state.system_state.get("known_modules", []) or []):
            pk = hub._primary_key(sid)
            meta = (md.get(sid) or {}) if isinstance(md, dict) else {}
            tid = meta.get("tenant_id") or ""
            if hub.state.is_module_decommissioned(pk):
                _bucket(tid)["decommissioned"] += 1
                continue
            if not hub.approved_modules.get(pk, False):
                continue  # pending — not a down system
            if hub.is_spoke_in_contact(sid) or pk in connected:
                _bucket(tid)["up"] += 1
            else:
                b = _bucket(tid)
                b["down"] += 1
                last = hub.heartbeat.last_seen.get(sid)
                b["down_spokes"].append({
                    "spoke_id": sid,
                    "name": (meta.get("display_name") or meta.get("name")
                            or meta.get("hostname") or sid),
                    "module_type": (hub.spoke_module_types.get(pk)
                                     or meta.get("module_type") or ""),
                    "last_seen_epoch": last if isinstance(last, (int, float)) else None,
                })
        return out
    except Exception:  # noqa: BLE001 — the roster must never blank the overview
        logger.exception("spoke roster build failed")
        return {}


def register(app, hub, ctx):
    """Register dashboard routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant
    _resolve_prefixes_for_tenant = ctx._resolve_prefixes_for_tenant
    _filter_enabled = ctx._filter_enabled

    async def _compute_tenant_counts(hub, scoping: dict, failed_spokes: set = None) -> dict:
        """Per-tenant aggregate counts across all connected spokes, scoped by
        the tenant's netbox_tenant_slug / proxmox_tag. Returns
        {devices, vms, sessions, prefixes, ips_used}. Shared by the single-tenant
        dashboard summary and the admin all-tenants overview so both show
        identical numbers for a given tenant."""
        import asyncio as _asyncio
        nb_slug  = scoping["netbox_tenant_slug"] or None
        pxmx_tag = scoping["proxmox_tag"]        or None

        spoke_ipam       = hub.get_spoke_by_type("ipam")
        # Tenant-aware VM counting. Count VMs from EVERY hypervisor spoke VISIBLE
        # to this tenant, not just the single one directly BOUND to it — the
        # singular get_hypervisor_spoke_for_tenant() misses SHARED spokes and
        # per-agent-PINNED hosts, so a tenant whose Proxmox host dials a shared
        # pxmx spoke (pinned to it) showed ~0 VMs here while its VMs were
        # attributed to the shared tenant's row. Mirror the Hypervisors VM page
        # (get_pxmx_vms / get_hypervisor_spokes_for_tenant): fan PXMX_LIST_VMS
        # across the plural visible set + the unbound-global spoke, merge/dedupe,
        # then subnet/tag-filter (below) so shared-spoke VMs land on the right
        # tenant. admin/default → the single global hypervisor (legacy behavior).
        _tid = scoping.get("tenant_id")
        if _tid and _tid != "default":
            hv_spokes = list(hub.get_hypervisor_spokes_for_tenant(_tid))
            # Include a hypervisor bound to NO tenant (global/unassigned) — the
            # same fallback get_pxmx_vms adds — so an unbound lab hypervisor's
            # VMs still count. A spoke bound to a DIFFERENT tenant is excluded.
            _gs = hub.get_hypervisor_spoke()
            if _gs and _gs not in hv_spokes:
                _md = hub.state.system_state.get("module_metadata", {}) or {}
                if not (_md.get(_gs, {}) or {}).get("tenant_id"):
                    hv_spokes.append(_gs)
        else:
            _gs = hub.get_hypervisor_spoke()
            hv_spokes = [_gs] if _gs else []
        spoke_nac        = hub.get_spoke_by_type("nac")

        async def _req(spoke, cmd, payload=None):
            if not spoke:
                return {}
            # A connected-but-WEDGED spoke (WS open but not answering) makes each
            # call wait out the full timeout. The ipam/hypervisor spoke is the
            # SAME for every tenant, so once it fails for one tenant, skip it for
            # the rest of this fan-out rather than re-waiting the timeout N times
            # (the all-tenants "several minutes, page never completes" hang).
            if failed_spokes is not None and spoke in failed_spokes:
                return {}
            try:
                # Overview counts don't warrant the 30s heavy-op budget — an 8s cap
                # keeps the dashboard responsive; a slow NetBox shows a stale/0 count
                # (memoized 60s) instead of hanging the whole page.
                timeout = 8.0 if isinstance(cmd, str) and cmd.startswith("NETBOX_") else 5.0
                r = await hub.request_response(spoke, cmd, payload or {}, timeout=timeout)
                return _unwrap_spoke(r) if isinstance(r, dict) else {}
            except Exception:
                if failed_spokes is not None:
                    failed_spokes.add(spoke)
                return {}

        _core = await _asyncio.gather(
            _req(spoke_ipam, "NETBOX_GET_DEVICES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_PREFIXES", {"tenant": nb_slug}),
            _req(spoke_ipam, "NETBOX_GET_IPS",     {"tenant": nb_slug}),
            _req(spoke_nac, "CPPM_GET_ACCESS_TRACKER", {}),
            # One PXMX_LIST_VMS per visible hypervisor spoke, concurrently. The
            # same spoke shared by several tenants is de-duped across the fan-out
            # by the shared ``failed_spokes`` skip; results are merged below.
            *[_req(s, "PXMX_LIST_VMS", {"tag_filter": pxmx_tag} if pxmx_tag else {})
              for s in hv_spokes],
        )
        devices_r, prefixes_r, ips_r, sessions_r = _core[:4]
        _vm_envelopes = _core[4:]

        devices  = len(devices_r.get("devices",   []))
        prefixes = len(prefixes_r.get("prefixes", []))
        ips_used = len(ips_r.get("ip_addresses",  []))
        # Merge VMs across all visible spokes, de-duped by unique_id
        # ("<cluster>/<node>/<vmid>") so a cluster-mate spoke self-reporting the
        # full cluster (or the unbound-global spoke overlapping a visible one)
        # can't double-count. Falls back to (node, vmid) when unique_id is absent.
        _seen: dict = {}
        for _env in _vm_envelopes:
            for _v in (_env.get("vms") or []):
                if isinstance(_v, dict):
                    _key = _v.get("unique_id") or (_v.get("node"), _v.get("vmid"))
                    _seen[_key] = _v
        all_vms  = list(_seen.values())
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
        # Relayed node agents never appear in active_connections (they dial their
        # parent spoke); infra_item_status falls back to their heartbeat so a
        # live agent stops reading "offline" here. See relayed_agent_last_seen.
        agent_last = relayed_agent_last_seen(hub)
        now = time.time()

        items = []
        for sid, meta in md.items():
            meta = meta or {}
            stid = meta.get("tenant_id")
            if not want_all and tid and stid and stid != tid:
                continue  # bound to another tenant (untagged = shared infra → shown)
            tier = alerts.get(sid, "none")
            online, status = infra_item_status(hub, sid, tier, connected,
                                               agent_last, now)
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

        # Per-tenant spoke up/down/decommissioned roster (cheap, no fan-out) so
        # the overview surfaces OFFLINE spokes the connected-spoke count queries
        # hide. Built once, merged per row.
        rosters = _spoke_rosters(hub)

        sem = _asyncio.Semaphore(5)
        # Shared across the fan-out: a spoke that times out for one tenant is
        # skipped for the rest (it's the same ipam/hypervisor spoke for all), so a
        # wedged spoke costs ~one timeout total instead of one per tenant.
        failed_spokes: set = set()

        async def _one(tid):
            cfg = tenants.get(tid) or {}
            scoping = get_tenant_scoping(hub, tid)
            async with sem:
                # Hard per-tenant ceiling so nothing can hang the endpoint even if
                # a spoke call ignores its own timeout — degrades to the zeros row.
                counts = await _asyncio.wait_for(
                    _compute_tenant_counts(hub, scoping, failed_spokes), timeout=12)
            return {
                "id":          tid,
                "name":        cfg.get("name") or tid,
                "slug":        cfg.get("netbox_tenant_slug") or tid,
                "description": cfg.get("description", ""),
                "spokes":      rosters.get(tid,
                                          {"up": 0, "down": 0, "decommissioned": 0,
                                           "down_spokes": []}),
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
                    "spokes": rosters.get(tid,
                                          {"up": 0, "down": 0, "decommissioned": 0,
                                           "down_spokes": []}),
                    "devices": 0, "vms": 0, "sessions": 0, "prefixes": 0, "ips_used": 0,
                })
            else:
                out.append(row)
        out.sort(key=lambda r: r["name"].lower())
        # Untagged (shared / unassigned) spokes are not bound to a tenant row;
        # surface them separately so an offline shared spoke is never lost from
        # the overview (an admin still needs to see it to clean it up).
        shared = rosters.get("__shared__",
                             {"up": 0, "down": 0, "decommissioned": 0,
                              "down_spokes": []})
        data = {"tenants": out, "shared_spokes": shared}
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

        Tenant scoping: the payload carries the active tenant's scope keys —
        ``tenant`` (NetBox slug; used by netbox + cppm and as the LDAP OU slug),
        ``proxmox_tag`` (pxmx/kvm tag_filter), ``prefixes`` (CIDRs for DHCP
        filtering), and ``is_admin``. Each spoke enforces scoping: if its scope
        key is present it filters to that tenant (shared/global objects are
        included); if the key is absent the spoke returns unscoped results ONLY
        for admins, and empty for non-admins — never leak another tenant's data.
        The hypervisor leg is routed to the tenant-bound spoke so a non-admin
        never reaches another tenant's hypervisor at all.
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
        sess = _session_user(request)
        is_admin = bool(sess and _is_admin(sess))
        # NetBox tenant slug drives netbox + cppm scoping and is the LDAP OU
        # slug. For a non-default tenant with no bound NetBox slug, fall back to
        # the tenant id so LDAP OU derivation (ou=<slug>,<base>) still works.
        nb_slug = scoping.get("netbox_tenant_slug") or (resolved if resolved and resolved != "default" else "")
        # Admins are trusted to search the whole directory / NetBox. When the
        # UI sends no explicit tenant (admin on "default"/global), stay
        # unscoped — otherwise _resolve_tenant's session-tenant fallback would
        # OU-scope the admin to their home tenant and hide users outside that
        # OU (the "search returns nothing" regression). An admin who explicitly
        # picks a tenant still gets that tenant's scope.
        if is_admin and not tenant:
            nb_slug = ""
        proxmox_tag = scoping.get("proxmox_tag") or ""
        # Scope key for the in-memory search index. Derived from the scope-
        # identifying inputs ONLY (tenant slug + proxmox tag + admin flag) — a
        # caller reads solely its own scope bucket, so a warmed index can never
        # leak another tenant's rows. Prefixes are deliberately excluded: they
        # are a deterministic function of the slug, so this key needs no prefix
        # fetch (that cost moves to the background populate). See SearchIndexMixin.
        scope_key = search_scope_key(nb_slug, proxmox_tag, is_admin)
        idx_on = hub.search_index_enabled()
        needle = q_search.lower()
        # ── Spoke resolution (needed by the live fan-out and by reporting). ──
        spoke_ipam       = hub.get_spoke_by_type("ipam")
        # Tenant-bound hypervisor: a non-admin only reaches a hypervisor bound
        # to its tenant (None → no VM results, no leak). The admin's
        # unscoped/default view falls back to any hypervisor.
        if resolved and resolved != "default":
            spoke_hypervisor = hub.get_hypervisor_spoke_for_tenant(resolved)
        else:
            spoke_hypervisor = hub.get_hypervisor_spoke()
        spoke_nac        = hub.get_spoke_by_type("nac")
        # Tenant-bound directory: a non-admin only reaches the LDAP spoke bound
        # to its tenant (None → no user results). The spoke additionally scopes
        # by the tenant's OU base DN (see ldap_spoke SEARCH_USERS), so even a
        # shared directory spoke returns only the tenant's own OU.
        if resolved and resolved != "default":
            spoke_directory = hub.get_directory_spoke_for_tenant(resolved) or hub.get_spoke_by_type("directory")
        else:
            spoke_directory = hub.get_spoke_by_type("directory")
        spoke_firewall   = hub.get_spoke_by_type("firewall")
        _legs = [
            (spoke_ipam,       "NETBOX_SEARCH"),
            (spoke_hypervisor, "SEARCH_VMS"),
            (spoke_nac,        "SEARCH_SESSIONS"),
            (spoke_directory,  "SEARCH_USERS"),
            (spoke_firewall,   "SEARCH_DHCP"),
        ]

        is_ip = bool(re.match(r'^[\\d:.]+(/\\d+)?$', raw_q))

        def _envelope(results, cached, warming=False):
            env = {
                "query":       q,
                "query_type":  "ip" if is_ip else ("mac" if is_mac else "name"),
                "total":       len(results),
                "results":     results,
                "cached":      cached,
                "spokes_queried": {
                    "ipam":       spoke_ipam is not None,
                    "hypervisor": spoke_hypervisor is not None,
                    "nac":        spoke_nac is not None,
                    "directory":  spoke_directory is not None,
                    "firewall":   spoke_firewall is not None,
                    "console":    bool(getattr(app.state, "console_list_visible_ports", None)),
                    "credvault":  bool(sess and (is_admin or access.is_tenant_admin(sess))),
                },
            }
            if warming:
                env["warming"] = True
            return env

        # ── Console leg (local, in-memory): cheap, so evaluate it up front — a
        #    console hit counts as "found in memory". Reuses the Console page's
        #    tenant-scoped listing (same visibility/masking), so a non-admin
        #    only ever sees consoles for its own tenant. Best-effort: a
        #    slow/absent console fleet must not fail the rest of the search.
        console_hits = []
        try:
            from routes.console import console_port_matches, console_port_result
            lister = getattr(app.state, "console_list_visible_ports", None)
            if lister:
                cdata = await lister(request)
                cneedle = raw_q.lower()
                for p in (cdata.get("ports") or []):
                    if console_port_matches(p, cneedle):
                        console_hits.append(console_port_result(p))
        except Exception as e:
            logger.warning(f"search: console leg failed: {e}")
            console_hits.append({"source": "console", "type": "error", "name": str(e)})

        # ── Credential Vault leg (local, in-memory): match secret METADATA only
        #    (name / type / description — NEVER the secret value) in the buckets
        #    the caller can reach. Restricted to the vault's own audience — a
        #    Global Admin (every bucket + the admin slot) or a tenant-admin
        #    (their own tenant buckets only); any other user gets nothing, so a
        #    plain user's banner search never surfaces credential names. Cheap
        #    (reads hub state), so evaluate it up front like the console leg.
        credvault_hits = []
        try:
            if sess and (is_admin or access.is_tenant_admin(sess)):
                import cred_vault as _cv
                if is_admin:
                    reach = set(b["bucket"] for b in _cv.list_buckets(hub)) | {_cv.ADMIN_BUCKET}
                else:
                    reach = set((sess.get("user", {}) or {}).get("tenants") or [])
                cvneedle = raw_q.lower()
                for bucket in sorted(reach):
                    label = "Global Admin slot" if bucket == _cv.ADMIN_BUCKET else bucket
                    for s in _cv.list_secrets(hub, bucket):
                        hay = " ".join([str(s.get("name", "")), str(s.get("type", "")),
                                        str(s.get("description", ""))]).lower()
                        if cvneedle in hay:
                            credvault_hits.append({
                                "source": "credvault", "type": s.get("type") or "generic",
                                "name": s.get("name"), "bucket": bucket, "bucket_label": label,
                                "mode": s.get("mode"), "description": s.get("description") or "",
                            })
        except Exception as e:
            logger.warning(f"search: cred-vault leg failed: {e}")

        # ── Memory-first ────────────────────────────────────────────────────
        # Match the query against every warm, spoke-scoped index leg (+ the
        # local console list) with NO network. If ANYTHING matches, return it
        # immediately and warm the remaining/stale legs in the background — the
        # operator never waits on a live NetBox / LDAP / hypervisor / DHCP
        # round-trip unless memory yields nothing at all. (Requested UX: show
        # what is in memory now; only pay the live fan-out when there is no
        # in-memory hit.)
        if idx_on:
            hub.search_register_scope(
                scope_key, resolved=resolved, is_admin=is_admin,
                nb_slug=nb_slug, proxmox_tag=proxmox_tag)
            mem = []
            any_cold = False
            for _spoke, cmd in _legs:
                items = hub.search_index_leg_items(cmd, scope_key)
                if items is None:
                    any_cold = True
                else:
                    mem.extend(r for r in items if search_result_matches(r, needle))
            if mem or console_hits or credvault_hits:
                # Found in memory → serve now; collect the rest in the
                # background so the next query for this scope is instant too.
                hub.search_kick_warm(scope_key)
                return _envelope(mem + console_hits + credvault_hits, True, warming=any_cold)
            # Nothing in memory → warm for next time, then fall through to the
            # blocking live fan-out below.
            hub.search_kick_warm(scope_key)

        # ── Live fan-out (blocking): index disabled or no in-memory hit. Pay
        #    the (uncached, ~30s) NetBox prefix fetch + the 5-spoke fan-out
        #    here; the background warm above makes the next such query instant.
        prefixes = []
        if nb_slug:
            try:
                prefixes = await _resolve_prefixes_for_tenant(hub, resolved) or []
            except Exception as e:
                logger.warning(f"search: prefix fetch for '{resolved}' failed: {e}")
        payload = {
            "q": q_search,
            "tenant": nb_slug,           # netbox + cppm + ldap OU slug
            "proxmox_tag": proxmox_tag,  # pxmx/kvm tag_filter
            "prefixes": prefixes,        # opnsense DHCP filter
            "is_admin": is_admin,
        }

        async def _call(spoke, cmd):
            if not spoke:
                return []
            try:
                r = await hub.request_response(spoke, cmd, payload)
                d = _unwrap_spoke(r)
                # Surface spoke ERROR envelopes (bind failure, missing OU, bad
                # slug) as an error row instead of collapsing them to [] —
                # otherwise a broken leg is indistinguishable from "no matches".
                if isinstance(d, dict) and d.get("status") == "ERROR":
                    return [{"source": cmd, "type": "error",
                             "name": d.get("message") or d.get("error") or "spoke error"}]
                return d.get("results", []) if isinstance(d, dict) else []
            except Exception as e:
                return [{"source": cmd, "type": "error", "name": str(e)}]

        all_results = await _asyncio.gather(*[_call(s, c) for s, c in _legs])
        merged = [item for sublist in all_results for item in sublist]
        merged.extend(console_hits)
        merged.extend(credvault_hits)
        return _envelope(merged, False)
