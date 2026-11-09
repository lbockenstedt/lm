"""Monitoring routes (admin only).

The monitoring spoke is vendor-neutral (module_type "monitoring"); these routes
only relay MON_STATUS / MON_SYNC / MON_REBUILD to it. Tenants never see the
backend — the LM WebUI is the only front end.
"""
# Regular expressions, used to validate the monitoring server address.
import re

# Request/exception types and the shared logger from the main API module.
from api import HTTPException, Request, logger


async def inventory_devices(hub):
    """LM inventory as monitoring devices, with each SNMP community resolved
    from the credential vault (the credential the network scan found to work).
    Only devices verified to answer SNMP are returned, plus IPs a user pinned
    from IPAM (``monitoring_watch``), which fall back to ping without SNMP.
    The scanner never adds ping-only hosts (the Zabbix spoke purges those)."""
    # Per-device credential overlay: fills vault-held secrets (e.g. SNMP community) into inventory
    # rows.
    import instance_vault
    # Start from the network device inventory and the global config.
    inv = (hub.state.system_state.get("global_config", {}).get("nw_devices", []) or [])
    gc = hub.state.system_state.get("global_config", {})
    # One host per physical box: drop rows that are the same hardware as
    # another (a switch discovered at each of its SVI addresses).
    if callable(getattr(hub, "_nw_identity_cache", None)):
        from nw_discovery_sync import nw_hardware_primaries
        prim = nw_hardware_primaries(inv, hub._nw_identity_cache())
        inv = [d for d in inv if not isinstance(d, dict) or not d.get("id")
               or prim.get(str(d["id"]), str(d["id"])) == str(d["id"])]
    # Resolve each device's vault-backed fields; rows without a name and address cannot be
    # monitored.
    inv = await instance_vault.overlay_many(
        hub, [d for d in inv if isinstance(d, dict) and d.get("name") and d.get("address")],
        "nw_devices")
    # Scanned devices are found over SSH and carry no community; fall back to
    # the SNMP community of their tenant's scan credential set.
    scan = await instance_vault.overlay_many(
        hub, [c for c in (gc.get("nw_scan_credentials", []) or []) if isinstance(c, dict)],
        "nw_scan_credentials")
    # Collected SNMP communities: per tenant bucket, and per exact vault reference
    # ("snmp:bucket:name").
    tenant_snmp, by_ref = {}, {}
    # A vault secret of type "snmp" in the tenant's bucket is the primary source.
    import cred_vault
    # Index every vault SNMP secret by tenant bucket (first one wins) and by its exact reference.
    for s in await cred_vault.automation_list_by_type(hub, "snmp"):
        val = s.get("value") or {}
        community = val.get("snmp_community") or val.get("community") or ""
        if community:
            tenant_snmp.setdefault(s["bucket"], community)
            by_ref[f"snmp:{s['bucket']}:{s['name']}"] = community
    # Record which tenant buckets had an SNMP secret, to help debug missing communities.
    logger.info("monitoring: snmp vault buckets=%s", sorted(tenant_snmp))
    # Scan credential sets only fill in a tenant community where the vault had none.
    for c in scan:
        if c.get("snmp_community"):
            tenant_snmp.setdefault(c.get("tenant_id") or "default", c["snmp_community"])
    # Output rows, plus the names already present (case-insensitive) so extras are not duplicated.
    out = []
    names = {str(d.get("name")).casefold() for d in inv}
    # LLDP neighbours that are not scanned devices (e.g. TOR switches) are
    # monitored too once verify_credentials found them answering SNMP.
    extra = [n for n in (gc.get("nw_monitor_neighbors", []) or [])
             if isinstance(n, dict) and n.get("name") and n.get("address")
             and str(n["name"]).casefold() not in names]
    # Hosts the nw scan/sweep saw answering SNMP within the last day.
    import time
    import nw_seen_hosts
    # Every address already covered (primary and alternates), so seen hosts do not duplicate them.
    addrs = {str(a or "").strip() for d in list(inv) + extra
             for a in [d.get("address")] + list(d.get("alt_addresses") or [])}
    # Append recently seen hosts that are not already in the list by address or name.
    extra += nw_seen_hosts.monitor_rows(
        gc.get("nw_seen_hosts") or {}, time.time(), addrs,
        names | {str(n["name"]).casefold() for n in extra})
    # Addresses a scan reached over SNMP, with the vault credential that worked.
    snmp_seen = {ip: e["snmp_credential_id"]
                 for reg in (gc.get("nw_seen_hosts") or {}).values() if isinstance(reg, dict)
                 for ip, e in reg.items()
                 if isinstance(e, dict) and e.get("snmp_ok") and e.get("snmp_credential_id")}
    # IPs a user chose to monitor from IPAM (Monitor button): always monitored,
    # over SNMP when verified, otherwise by ping. New ones become extra hosts.
    def ips_of(d):
        return [str(a or "").split("/")[0].strip()
                for a in [d.get("address")] + list(d.get("alt_addresses") or [])]
    watch = gc.get("monitoring_watch") or {}
    watched = {(str(t).casefold(), ip) for t, ips in watch.items() if isinstance(ips, dict)
               for ip in ips}
    covered = {ip for d in list(inv) + extra for ip in ips_of(d)}
    taken = names | {str(n["name"]).casefold() for n in extra}
    for t, ips in sorted(watch.items()):
        for ip, info in sorted((ips or {}).items()):
            if ip in covered:
                continue
            name = str((info or {}).get("name") or "").strip() or ip
            name = ip if name.casefold() in taken else name
            taken.add(name.casefold())
            extra.append({"tenant_id": t, "name": name, "address": ip, "type": "host"})
    # Tenant-group membership tables, used to share SNMP buckets/proxies within a group.
    import access
    # Build one monitoring row per device (inventory plus extras).
    skipped = 0
    for d in list(inv) + extra:
        # The device's tenant, and whether a user pinned one of its IPs in IPAM.
        tenant = d.get("tenant") or d.get("tenant_id") or "default"
        pinned = any((str(tenant).casefold(), ip) in watched for ip in ips_of(d))
        # Scanned devices are monitored only when proven to answer SNMP: verified
        # on the device itself, or by a scan that reached one of its addresses.
        ref = d.get("snmp_secret") or ""
        verified = d.get("snmp_ok") is True
        if not verified:
            cred = next((snmp_seen[ip] for ip in ips_of(d) if snmp_seen.get(ip)), "")
            verified, ref = bool(cred), ref or cred
        if not verified and not pinned:
            skipped += 1
            continue
        # The tenant the device was moved from (if any).
        moved = d.get("moved_from") if isinstance(d.get("moved_from"), dict) else {}
        former = str(moved.get("tenant_id") or "")
        # A tenant group has no SNMP bucket or proxy of its own: its member
        # tenants' are its own (the device it holds came from one of them).
        members = sorted(access._GROUP_MEMBERS.get(access._norm_tenant_id(tenant), set()),
                         key=lambda m: (m != access._norm_tenant_id(former), m != "default", m))
        # Which vault bucket the device's verified SNMP secret lives in (None when not a vault
        # reference).
        # Credentials never cross tenants: the verified credential and the
        # tenant bucket only count when they belong to this device's tenant.
        # Only the Admin/Default tenant may use the Global Admin slot.
        ref_bucket = ref.split(":")[1] if ref.startswith("snmp:") and ref.count(":") >= 2 else None
        # Buckets this device may draw from: its tenant and its group members (plus the admin slot
        # for default).
        own = {tenant, *members}
        if "default" in own:
            own.add(cred_vault.ADMIN_BUCKET)
        # Pick a community in priority order: set on the device, its verified vault secret, its
        # tenant's, a member tenant's, then the Global Admin slot.
        community = verified and (
            d.get("snmp_community")
            or (by_ref.get(ref, "") if ref_bucket in own else "")
            or tenant_snmp.get(tenant)
            or next((tenant_snmp[m] for m in members if tenant_snmp.get(m)), "")
            or (tenant_snmp.get(cred_vault.ADMIN_BUCKET, "") if "default" in own else "")) or ""
        # No community this tenant may use: cannot be polled (pinned IPs fall back to ping).
        if not community and not pinned:
            skipped += 1
            continue
        # A box seen at several addresses is polled over its out-of-band port when the
        # cached interface data shows which address that is.
        oobm_ip = ""
        getter = getattr(hub, "nw_cache_get_device", None)
        if d.get("id") and callable(getter) and d.get("alt_addresses"):
            from nw_discovery_sync import nw_oobm_address
            oobm_ip = nw_oobm_address(d, getter(str(d["id"]), "interfaces"))
        # The row the monitoring spoke syncs into Zabbix (IP without any /prefix).
        row = {"tenant": tenant, "name": d.get("name"),
               "type": d.get("type") or d.get("object_type") or d.get("model") or "",
               "ip": oobm_ip or str(d.get("address") or "").split("/")[0],
               "snmp": bool(community), "snmp_community": community}
        if members:
            # Proxies to try after the group's own: its member tenants'.
            row["proxy_tenants"] = members
        if former and former != tenant:
            # Lets the sync re-key the device's existing host instead of
            # creating a second one next to it.
            row["moved_from"] = former
        # Collect the finished row.
        out.append(row)
    logger.info("monitoring: %d devices (%d pinned from IPAM), %d skipped (no verified SNMP)",
                len(out), len(watched), skipped)
    return out


def vault_snmp_scan_sets(hub, tenant):
    """Scan credential sets for every hub-mode vault secret of type "snmp" in the
    tenant's bucket and the Global Admin slot, so a scan tries each community."""
    # Vault helpers (admin bucket name) and the global config holding the vault index.
    import cred_vault
    gc = hub.state.system_state.get("global_config", {})
    # Walk each vault bucket; only the tenant's own bucket (and the admin slot for "default") is
    # eligible.
    out = []
    for bucket, secrets in ((gc.get("cred_vault", {}) or {}).get("secrets", {}) or {}).items():
        if bucket != tenant and not (tenant == "default" and bucket == cred_vault.ADMIN_BUCKET):
            continue
        # Keep hub-mode SNMP secrets and turn each into a scan credential set referencing the vault.
        for name, meta in (secrets or {}).items():
            if isinstance(meta, dict) and meta.get("type") == "snmp" and meta.get("mode") == "hub":
                out.append({"id": f"snmp:{bucket}:{name}", "name": name, "tenant_id": tenant,
                            "username": "", "vault_credential": {"bucket": bucket, "name": name}})
    return out


async def verify_credentials(hub, tenant="default", apply=False):
    """Probe every known device of ``tenant`` with BOTH its SSH vault login and the
    SNMP community (vault "snmp" secrets) on the nw spoke that owns it, and report
    which credential worked per device. With ``apply`` the SNMP outcome is stored
    on the device (``snmp_ok``) so the Zabbix sync only enables SNMP where it answers."""
    # Vault overlay, the vault index and tenant helpers.
    import instance_vault
    import cred_vault
    import access
    # All of this tenant's devices that have an address.
    gc = hub.state.system_state.get("global_config", {})
    devices = [d for d in (gc.get("nw_devices", []) or []) if isinstance(d, dict)
               and d.get("address") and (d.get("tenant_id") or "default") == tenant]
    # Build one SSH credential set per distinct vault login used by these devices.
    sets, seen = [], set()
    for d in devices:
        ref = d.get("vault_credential")
        if ref and (ref["bucket"], ref["name"]) not in seen:
            seen.add((ref["bucket"], ref["name"]))
            sets.append({"id": f"ssh:{ref['bucket']}:{ref['name']}", "name": ref["name"],
                         "tenant_id": tenant, "username": "", "vault_credential": ref})
    # Add the tenant's SNMP vault secrets so the scan tries each community too.
    sets += vault_snmp_scan_sets(hub, tenant)
    # Resolve the vault references into real usernames/passwords/communities.
    resolved = await instance_vault.overlay_many(hub, sets, "nw_scan_credentials")
    # Flatten them to the credential format NW_SCAN expects.
    creds = [{"id": c["id"], "name": c["name"], "username": c.get("username") or "",
              "password": c.get("password") or "",
              "enable_secret": c.get("enable_secret") or "",
              "snmp_community": c.get("snmp_community") or ""} for c in resolved]
    # Group devices by the nw spoke that owns them, since each spoke scans its own devices.
    by_spoke = {}
    for d in devices:
        by_spoke.setdefault(d.get("spoke_id"), []).append(d)
    # Addresses and names already known, so LLDP neighbours are only added when new.
    known = {str(d["address"]).split("/")[0] for d in devices}
    known_names = {str(d.get("name")).casefold() for d in devices}
    neighbours = {}  # address -> {name, spoke_id}
    # Ask each device for its LLDP neighbours to discover unmanaged switches worth monitoring.
    for d in devices:
        # Devices without an id or spoke cannot be queried.
        if not d.get("id") or not d.get("spoke_id"):
            continue
        # Fetch LLDP neighbours from the owning spoke; a failure only skips that device.
        try:
            res = await hub.request_response(
                d["spoke_id"], "NW_GET_LLDP_NEIGHBORS",
                {"device_id": d["id"], "tenant": tenant}, timeout=30.0)
            rows = access.unwrap_spoke(res)
            rows = rows.get("data", rows) if isinstance(rows, dict) else rows
        except Exception as e:
            logger.info("monitoring: lldp for %s failed: %s", d.get("name"), e)
            continue
        # Keep neighbours with a management IP and a short (non-FQDN) name that are not already
        # known.
        for r in rows or []:
            ip = str((r or {}).get("remote_mgmt_ip") or "").split("/")[0]
            name = str((r or {}).get("remote_name") or "").strip()
            if (ip and name and ip not in known and name.casefold() not in known_names
                    and "." not in name):
                neighbours.setdefault(ip, {"name": name, "spoke_id": d["spoke_id"]})
    # Per-device results to return.
    report = []
    # Run one scan per spoke over its devices plus the neighbours it discovered (SNMP on, no
    # nmap/crawl).
    for spoke_id, devs in by_spoke.items():
        extra_ips = sorted(ip for ip, n in neighbours.items() if n["spoke_id"] == spoke_id)
        res = await hub.request_response(
            spoke_id, "NW_SCAN",
            {"targets": sorted({d["address"] for d in devs} | set(extra_ips)), "credentials": creds,
             "options": {"try_snmp": True, "use_nmap": False, "crawl": False},
             "tenant": tenant}, timeout=300.0)
        # Unwrap the reply and index results by address (identified and merely reachable hosts).
        res = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
        found = {r["address"]: r for r in (res.get("identified") or []) + (res.get("reachable") or [])}
        # Report, per device, whether it answered and which SSH/SNMP credential worked.
        for d in devs:
            r = found.get(d["address"]) or {}
            report.append({"name": d["name"], "address": d["address"],
                           "reachable": bool(r.get("reachable")),
                           "ssh": r.get("credential") if r.get("method") == "ssh" else None,
                           "snmp_ok": r.get("snmp_ok"), "snmp_secret": r.get("snmp_credential_id")})
            # In apply mode store the SNMP outcome (and the working secret) on the device itself.
            if apply and r.get("snmp_ok") is not None:
                d["snmp_ok"] = bool(r["snmp_ok"])
                d["snmp_secret"] = r.get("snmp_credential_id") if r["snmp_ok"] else None
        # Report the neighbours the same way, flagged as neighbours.
        for ip in extra_ips:
            r = found.get(ip) or {}
            report.append({"name": neighbours[ip]["name"], "address": ip, "neighbour": True,
                           "reachable": bool(r.get("reachable")), "snmp_ok": r.get("snmp_ok"),
                           "snmp_secret": r.get("snmp_credential_id")})
    # In apply mode replace this tenant's monitored neighbours with those that answered SNMP.
    if apply:
        keep = [n for n in (gc.get("nw_monitor_neighbors", []) or [])
                if n.get("tenant_id") != tenant]
        keep += [{"tenant_id": tenant, "name": x["name"], "address": x["address"],
                  "type": "switch", "snmp_ok": x["snmp_ok"], "snmp_secret": x["snmp_secret"]}
                 for x in report if x.get("neighbour") and x["snmp_ok"]]
        gc["nw_monitor_neighbors"] = keep
        hub.state._mark_dirty()
    # Return the tenant, the credentials tried and the per-device report.
    return {"tenant": tenant, "credentials_tried": [c["id"] for c in creds], "devices": report}



def monitoring_server_address(hub):
    """The Zabbix server address (host[:port]) proxies dial out to; admin-configured."""
    # Read the configured address, trimmed (empty when unset).
    gc = hub.state.system_state.get("global_config", {}) or {}
    return str(gc.get("monitoring_server") or "").strip()


def scope_monitoring_hosts(hosts, tenant, sess, is_admin):
    """Hosts the session may see. Non-admins are bound to their own tenants;
    ``tenant`` (the picker) can only narrow that set further."""
    # None means "no restriction" (admin); otherwise the set of tenants on the session.
    allowed = None if is_admin else set((sess or {}).get("user", {}).get("tenants") or [])
    want = tenant or None
    out = []
    # Keep a host only if it is in an allowed tenant and matches the picked tenant (if any).
    for h in hosts:
        t = h.get("tenant") or "default"
        if allowed is not None and t not in allowed:
            continue
        if want and t != want:
            continue
        out.append(h)
    return out


def monitoring_problem_list(hosts):
    """Flat, severity-then-newest ordered list of every open problem."""
    # One row per open problem across all hosts.
    rows = [{"host": h.get("name"), "tenant": h.get("tenant"), "ip": h.get("ip"),
             "name": p.get("name"), "severity": p.get("severity", 0), "clock": p.get("clock", 0)}
            for h in hosts for p in (h.get("problems") or [])]
    # Highest severity first, then most recent first.
    rows.sort(key=lambda r: (-int(r["severity"] or 0), -int(r["clock"] or 0)))
    return rows


# Default automatic sync interval in seconds (5 minutes).
MONITORING_SYNC_INTERVAL = 300.0


def monitoring_sync_config(hub):
    """Return the automatic sync settings: enabled (default on) and the interval in minutes (minimum
    1).
    """
    # Read the saved monitoring_sync settings.
    gc = hub.state.system_state.get("global_config", {}) or {}
    cfg = gc.get("monitoring_sync") or {}
    # Use the saved interval (at least 1 minute) or the default; unparseable values fall back to the
    # default.
    try:
        minutes = max(1, int(cfg.get("interval_minutes") or MONITORING_SYNC_INTERVAL // 60))
    except (TypeError, ValueError):
        minutes = int(MONITORING_SYNC_INTERVAL // 60)
    # Enabled unless explicitly turned off.
    return {"enabled": cfg.get("enabled") is not False, "interval_minutes": minutes}


def record_monitoring_sync(hub, res=None, error=None, trigger="scheduled"):
    """Remember the last sync outcome so the System > Sync card can show it."""
    # time is needed for the timestamp of this sync.
    import time
    # Unwrap the spoke's reply into a dict (empty when there was no usable reply).
    data = {}
    if isinstance(res, dict):
        data = res.get("payload", {}).get("data", res)
        data = data if isinstance(data, dict) else {}
    # The sync failed if it raised or reported per-host errors.
    errors = data.get("errors") or []
    status = "error" if (error or errors) else "success"
    # Store a compact summary: when, outcome, trigger, counts and the first error (capped at 300
    # chars).
    gc = hub.state.system_state.setdefault("global_config", {})
    gc["monitoring_sync_status"] = {
        "ts": time.time(), "status": status, "trigger": trigger,
        "created": data.get("created", 0), "refreshed": data.get("refreshed", 0),
        "disabled": data.get("disabled", 0), "deleted": data.get("deleted", 0),
        "errors": len(errors) + (1 if error else 0),
        "message": str(error or (errors[0] if errors else ""))[:300]}
    # Flag state for saving.
    hub.state._mark_dirty()


async def run_monitoring_sync_once(hub, trigger="scheduled"):
    """Run one full MON_SYNC with the current inventory and record the outcome.

    Returns the spoke reply, or None when no monitoring spoke is connected. Re-raises sync failures
    after recording them.
    """
    # Find the monitoring spoke; nothing to do when it is not connected.
    sid = hub.get_spoke_by_type("monitoring")
    if not sid:
        return None
    # Push the whole inventory (not a dry run) and wait up to 5 minutes.
    try:
        res = await hub.request_response(
            sid, "MON_SYNC", {"devices": await inventory_devices(hub), "dry_run": False},
            timeout=300.0)
    # Record the failure for the status card, then let the caller see it.
    except Exception as e:  # noqa: BLE001
        record_monitoring_sync(hub, error=e, trigger=trigger)
        raise
    # Record the success summary and return the reply.
    record_monitoring_sync(hub, res=res, trigger=trigger)
    return res


async def run_monitoring_sync_loop(hub):
    """Keep Zabbix converged with the LM inventory (the source of truth) without
    anyone pressing Sync. Honours System > Sync settings; skips quietly while the
    monitoring spoke is offline."""
    import asyncio
    import time
    # Give the hub two minutes after start-up so spokes can connect before the first sync.
    await asyncio.sleep(120)
    last = 0.0
    # Run forever, checking every 30 seconds whether a sync is due.
    while True:
        try:
            # Re-read settings each time so changes apply without a restart.
            cfg = monitoring_sync_config(hub)
            if cfg["enabled"] and time.time() - last >= cfg["interval_minutes"] * 60:
                last = time.time()
                res = await run_monitoring_sync_once(hub)
                # Only log when a sync actually ran (spoke connected).
                if res is not None:
                    logger.info("monitoring: scheduled sync done: %s", str(res)[:300])
        # Let task cancellation (hub shutdown) stop the loop.
        except asyncio.CancelledError:
            raise
        # Any other failure is logged and the loop keeps going.
        except Exception as e:  # noqa: BLE001 — never kill the loop
            logger.warning("monitoring: scheduled sync failed: %s", e)
        # Wait before checking again.
        await asyncio.sleep(30)


def register(app, hub, ctx):
    """Attach the monitoring routes to the web app and start the background sync loop.

    Args: app is the web application, hub is the running LM hub, ctx carries shared session/role
    helpers.
    """
    # Pull the session/role helpers out of ctx once for the route closures below.
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _admin_spoke(request):
        """Require an admin caller and a connected monitoring spoke; returns the spoke id."""
        # Only admins may use these routes.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        # The monitoring spoke must be connected to relay anything.
        sid = hub.get_spoke_by_type("monitoring")
        if not sid:
            raise HTTPException(status_code=503, detail="Monitoring spoke not connected")
        return sid

    async def _start_sync_loop():
        """Launch the periodic monitoring sync as a background task."""
        import asyncio
        asyncio.create_task(run_monitoring_sync_loop(hub))

    # Start the loop once the web app has started.
    app.router.on_startup.append(_start_sync_loop)

    async def _relay(sid, command, payload=None):
        """Send a command to the monitoring spoke and return its reply; failures become a 502."""
        try:
            return await hub.request_response(sid, command, payload or {}, timeout=300.0)
        except Exception as e:
            logger.exception("monitoring %s failed", command)
            raise HTTPException(status_code=502, detail=str(e))

    @app.get("/api/monitoring/status")
    async def monitoring_status(request: Request):
        """Relay MON_STATUS (backend health) from the monitoring spoke (admin only)."""
        return await _relay(_admin_spoke(request), "MON_STATUS")

    @app.get("/api/monitoring/hosts")
    async def monitoring_hosts(request: Request, tenant: str = None):
        """Monitored hosts + open problems, tenant-scoped like the other pages:
        a Global Admin sees every tenant (optionally narrowed with ``?tenant=``);
        anyone else only the tenants on their own session (deny by default)."""
        import access
        # Any logged-in user may call this; results are scoped to their tenants below.
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        # The monitoring spoke must be connected.
        sid = hub.get_spoke_by_type("monitoring")
        if not sid:
            raise HTTPException(status_code=503, detail="Monitoring spoke not connected")
        # Fetch all hosts and problems from the spoke.
        res = await _relay(sid, "MON_HOSTS")
        # A Global Admin without a tenant filter gets everything as-is.
        if _is_admin(sess) and not tenant:
            return res
        # Everyone else: unwrap the reply and keep only hosts in their allowed tenants.
        data = access.unwrap_spoke(res)
        hosts = (data or {}).get("hosts") if isinstance(data, dict) else None
        out = scope_monitoring_hosts(hosts or [], tenant, sess, _is_admin(sess))
        # Return the scoped hosts and their open problems ordered by severity.
        return {"status": "ok", "hosts": out, "problems": monitoring_problem_list(out)}

    @app.get("/api/monitoring/config")
    async def monitoring_config_get(request: Request):
        """Return the configured Zabbix server address (admin only)."""
        # Only admins may read this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        return {"server": monitoring_server_address(hub)}

    @app.put("/api/monitoring/config")
    async def monitoring_config_put(request: Request):
        """Set the Zabbix server address that monitoring proxies dial out to (admin only)."""
        # Only admins may change this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        # Read the JSON body; a missing, broken or non-object body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        # The new address, trimmed; empty clears it.
        server = str(body.get("server") or "").strip()
        # Accept only a hostname/IP with an optional port, so nothing odd reaches the proxies.
        if server and not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?", server):
            raise HTTPException(status_code=400, detail="server must be host or host:port")
        # Save it, flag state for saving and log the change.
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["monitoring_server"] = server
        hub.state._mark_dirty()
        logger.info("monitoring: proxy server address set to %r", server)
        return {"server": server}

    @app.post("/api/monitoring/sync")
    async def monitoring_sync(request: Request):
        """Run a manual sync (or dry run) of the LM inventory into Zabbix (admin only)."""
        # Admin check, then build the payload with the current inventory.
        sid = _admin_spoke(request)
        payload = await _payload(request)
        # Relay the sync; only real (non-dry-run) syncs are recorded on the status card.
        res = await _relay(sid, "MON_SYNC", payload)
        if not payload.get("dry_run"):
            record_monitoring_sync(hub, res=res, trigger="manual")
        return res

    @app.get("/api/monitoring/sync-config")
    async def monitoring_sync_config_get(request: Request):
        """Return the automatic sync settings plus the last sync outcome (admin only)."""
        # Only admins may read this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        # Combine the settings with the last recorded sync status.
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {**monitoring_sync_config(hub), "status": gc.get("monitoring_sync_status")}

    @app.put("/api/monitoring/sync-config")
    async def monitoring_sync_config_put(request: Request):
        """Change the automatic sync settings (admin only)."""
        # Only admins may change this.
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        # Read the JSON body; a missing, broken or non-object body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        # Interval clamped to 1 minute .. 1 day (default 5); a non-number is a 400.
        try:
            minutes = max(1, min(1440, int(body.get("interval_minutes") or 5)))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="interval_minutes must be a number")
        # Save the settings and flag state for saving; the loop picks them up on its next check.
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["monitoring_sync"] = {"enabled": bool(body.get("enabled", True)),
                                 "interval_minutes": minutes}
        hub.state._mark_dirty()
        # Return the effective settings.
        return monitoring_sync_config(hub)

    def _watch_tenant(request, requested, write=False):
        """Resolve the tenant for an IPAM Monitor call and enforce access."""
        import access
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not (_is_admin(sess) or access.has_ipam_access(sess)):
            raise HTTPException(status_code=403, detail="IPAM access required")
        tenant, code, detail = access.resolve_module_tenant(
            _is_admin(sess), (sess.get("user") or {}).get("tenants") or [], requested, "monitoring")
        if not tenant:
            raise HTTPException(status_code=code, detail=detail)
        if write and access.write_scope(sess, tenant) == "deny":
            raise HTTPException(status_code=403, detail="Write access required")
        return tenant, sess

    @app.get("/api/monitoring/watch")
    async def monitoring_watch_list(request: Request, tenant: str = None):
        """IPs the tenant pinned for monitoring from IPAM."""
        tenant, _ = _watch_tenant(request, tenant)
        gc = hub.state.system_state.get("global_config", {}) or {}
        return {"tenant": tenant, "ips": (gc.get("monitoring_watch") or {}).get(tenant) or {}}

    @app.put("/api/monitoring/watch")
    async def monitoring_watch_set(request: Request):
        """Turn monitoring of one IPAM address on or off. Body:
        ``{tenant, ip, name?, monitor: bool}``. The next sync adds or removes
        the Zabbix host (SNMP when verified, otherwise ping)."""
        import ipaddress
        import time
        try:
            body = await request.json()
        except Exception:
            body = {}
        body = body if isinstance(body, dict) else {}
        tenant, sess = _watch_tenant(request, body.get("tenant"), write=True)
        try:
            ip = str(ipaddress.ip_address(str(body.get("ip") or "").split("/")[0].strip()))
        except ValueError:
            raise HTTPException(status_code=400, detail="ip must be an IP address")
        name = str(body.get("name") or "").strip()[:64]
        # The name becomes the Zabbix visible name: keep it to plain host-name characters.
        if name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._\- ]*", name):
            raise HTTPException(status_code=400, detail="invalid name")
        gc = hub.state.system_state.setdefault("global_config", {})
        watch = gc.setdefault("monitoring_watch", {})
        ips = watch.setdefault(tenant, {})
        if body.get("monitor"):
            ips[ip] = {"name": name, "by": (sess.get("user") or {}).get("username") or "",
                       "at": int(time.time())}
        else:
            ips.pop(ip, None)
            if not ips:
                watch.pop(tenant, None)
        hub.state._mark_dirty()
        logger.info("monitoring: IPAM %s %s for tenant %s",
                    "monitor" if body.get("monitor") else "unmonitor", ip, tenant)
        return {"tenant": tenant, "ip": ip, "monitored": bool(body.get("monitor"))}

    @app.post("/api/monitoring/rebuild")
    async def monitoring_rebuild(request: Request):
        """Rebuild the monitoring backend's hosts from the LM inventory (admin only)."""
        # Admin check, then relay MON_REBUILD with the current inventory.
        sid = _admin_spoke(request)
        return await _relay(sid, "MON_REBUILD", await _payload(request))

    async def _payload(request):
        """Build the sync/rebuild payload: the current inventory plus the dry_run flag from the
        body.
        """
        # Read the JSON body; a missing or broken body is treated as empty.
        try:
            body = await request.json()
        except Exception:
            body = {}
        return {"devices": await inventory_devices(hub),
                "dry_run": bool((body or {}).get("dry_run"))}
