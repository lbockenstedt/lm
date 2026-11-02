"""Monitoring routes (admin only).

The monitoring spoke is vendor-neutral (module_type "monitoring"); these routes
only relay MON_STATUS / MON_SYNC / MON_REBUILD to it. Tenants never see the
backend — the LM WebUI is the only front end.
"""
import re

from api import HTTPException, Request, logger


async def inventory_devices(hub):
    """LM inventory as monitoring devices, with each SNMP community resolved
    from the credential vault (the credential the network scan found to work)."""
    import instance_vault
    inv = (hub.state.system_state.get("global_config", {}).get("nw_devices", []) or [])
    gc = hub.state.system_state.get("global_config", {})
    inv = await instance_vault.overlay_many(
        hub, [d for d in inv if isinstance(d, dict) and d.get("name") and d.get("address")],
        "nw_devices")
    # Scanned devices are found over SSH and carry no community; fall back to
    # the SNMP community of their tenant's scan credential set.
    scan = await instance_vault.overlay_many(
        hub, [c for c in (gc.get("nw_scan_credentials", []) or []) if isinstance(c, dict)],
        "nw_scan_credentials")
    tenant_snmp, by_ref = {}, {}
    # A vault secret of type "snmp" in the tenant's bucket is the primary source.
    import cred_vault
    for s in await cred_vault.automation_list_by_type(hub, "snmp"):
        val = s.get("value") or {}
        community = val.get("snmp_community") or val.get("community") or ""
        if community:
            tenant_snmp.setdefault(s["bucket"], community)
            by_ref[f"snmp:{s['bucket']}:{s['name']}"] = community
    logger.info("monitoring: snmp vault buckets=%s", sorted(tenant_snmp))
    for c in scan:
        if c.get("snmp_community"):
            tenant_snmp.setdefault(c.get("tenant_id") or "default", c["snmp_community"])
    out = []
    names = {str(d.get("name")).casefold() for d in inv}
    # LLDP neighbours that are not scanned devices (e.g. TOR switches) are
    # monitored too once verify_credentials found them answering SNMP.
    extra = [n for n in (gc.get("nw_monitor_neighbors", []) or [])
             if isinstance(n, dict) and n.get("name") and n.get("address")
             and str(n["name"]).casefold() not in names]
    for d in list(inv) + extra:
        tenant = d.get("tenant") or d.get("tenant_id") or "default"
        # The credential the scan verified, then the tenant bucket, then the
        # Global Admin slot as the shared default.
        community = (d.get("snmp_community") or by_ref.get(d.get("snmp_secret") or "")
                     or tenant_snmp.get(tenant)
                     or tenant_snmp.get(cred_vault.ADMIN_BUCKET, ""))
        out.append({"tenant": tenant, "name": d.get("name"),
                    "type": d.get("type") or d.get("object_type") or d.get("model") or "",
                    "ip": str(d.get("address") or "").split("/")[0],
                    # Only a device that failed an SNMP probe is held back.
                    "snmp": (bool(community) or d.get("transport") == "snmp")
                    and d.get("snmp_ok") is not False,
                    "snmp_community": community, "_ok": d.get("snmp_ok")})
    # The sync keeps the first address per device name: prefer one that answered SNMP.
    out.sort(key=lambda x: 0 if x["_ok"] is True else (2 if x["_ok"] is False else 1))
    for x in out:
        x.pop("_ok")
    return out


def vault_snmp_scan_sets(hub, tenant):
    """Scan credential sets for every hub-mode vault secret of type "snmp" in the
    tenant's bucket and the Global Admin slot, so a scan tries each community."""
    import cred_vault
    gc = hub.state.system_state.get("global_config", {})
    out = []
    for bucket, secrets in ((gc.get("cred_vault", {}) or {}).get("secrets", {}) or {}).items():
        if bucket not in (tenant, cred_vault.ADMIN_BUCKET):
            continue
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
    import instance_vault
    import cred_vault
    import access
    gc = hub.state.system_state.get("global_config", {})
    devices = [d for d in (gc.get("nw_devices", []) or []) if isinstance(d, dict)
               and d.get("address") and (d.get("tenant_id") or "default") == tenant]
    sets, seen = [], set()
    for d in devices:
        ref = d.get("vault_credential")
        if ref and (ref["bucket"], ref["name"]) not in seen:
            seen.add((ref["bucket"], ref["name"]))
            sets.append({"id": f"ssh:{ref['bucket']}:{ref['name']}", "name": ref["name"],
                         "tenant_id": tenant, "username": "", "vault_credential": ref})
    sets += vault_snmp_scan_sets(hub, tenant)
    resolved = await instance_vault.overlay_many(hub, sets, "nw_scan_credentials")
    creds = [{"id": c["id"], "name": c["name"], "username": c.get("username") or "",
              "password": c.get("password") or "",
              "enable_secret": c.get("enable_secret") or "",
              "snmp_community": c.get("snmp_community") or ""} for c in resolved]
    by_spoke = {}
    for d in devices:
        by_spoke.setdefault(d.get("spoke_id"), []).append(d)
    known = {str(d["address"]).split("/")[0] for d in devices}
    known_names = {str(d.get("name")).casefold() for d in devices}
    neighbours = {}  # address -> {name, spoke_id}
    for d in devices:
        if not d.get("id") or not d.get("spoke_id"):
            continue
        try:
            res = await hub.request_response(
                d["spoke_id"], "NW_GET_LLDP_NEIGHBORS",
                {"device_id": d["id"], "tenant": tenant}, timeout=30.0)
            rows = access.unwrap_spoke(res)
            rows = rows.get("data", rows) if isinstance(rows, dict) else rows
        except Exception as e:
            logger.info("monitoring: lldp for %s failed: %s", d.get("name"), e)
            continue
        for r in rows or []:
            ip = str((r or {}).get("remote_mgmt_ip") or "").split("/")[0]
            name = str((r or {}).get("remote_name") or "").strip()
            if (ip and name and ip not in known and name.casefold() not in known_names
                    and "." not in name):
                neighbours.setdefault(ip, {"name": name, "spoke_id": d["spoke_id"]})
    report = []
    for spoke_id, devs in by_spoke.items():
        extra_ips = sorted(ip for ip, n in neighbours.items() if n["spoke_id"] == spoke_id)
        res = await hub.request_response(
            spoke_id, "NW_SCAN",
            {"targets": sorted({d["address"] for d in devs} | set(extra_ips)), "credentials": creds,
             "options": {"try_snmp": True, "use_nmap": False, "crawl": False},
             "tenant": tenant}, timeout=300.0)
        res = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
        found = {r["address"]: r for r in (res.get("identified") or []) + (res.get("reachable") or [])}
        for d in devs:
            r = found.get(d["address"]) or {}
            report.append({"name": d["name"], "address": d["address"],
                           "reachable": bool(r.get("reachable")),
                           "ssh": r.get("credential") if r.get("method") == "ssh" else None,
                           "snmp_ok": r.get("snmp_ok"), "snmp_secret": r.get("snmp_credential_id")})
            if apply and r.get("snmp_ok") is not None:
                d["snmp_ok"] = bool(r["snmp_ok"])
                d["snmp_secret"] = r.get("snmp_credential_id") if r["snmp_ok"] else None
        for ip in extra_ips:
            r = found.get(ip) or {}
            report.append({"name": neighbours[ip]["name"], "address": ip, "neighbour": True,
                           "reachable": bool(r.get("reachable")), "snmp_ok": r.get("snmp_ok"),
                           "snmp_secret": r.get("snmp_credential_id")})
    if apply:
        keep = [n for n in (gc.get("nw_monitor_neighbors", []) or [])
                if n.get("tenant_id") != tenant]
        keep += [{"tenant_id": tenant, "name": x["name"], "address": x["address"],
                  "type": "switch", "snmp_ok": x["snmp_ok"], "snmp_secret": x["snmp_secret"]}
                 for x in report if x.get("neighbour") and x["snmp_ok"]]
        gc["nw_monitor_neighbors"] = keep
        hub.state._mark_dirty()
    return {"tenant": tenant, "credentials_tried": [c["id"] for c in creds], "devices": report}



def monitoring_server_address(hub):
    """The Zabbix server address (host[:port]) proxies dial out to; admin-configured."""
    gc = hub.state.system_state.get("global_config", {}) or {}
    return str(gc.get("monitoring_server") or "").strip()


def scope_monitoring_hosts(hosts, tenant, sess, is_admin):
    """Hosts the session may see. Non-admins are bound to their own tenants;
    ``tenant`` (the picker) can only narrow that set further."""
    allowed = None if is_admin else set((sess or {}).get("user", {}).get("tenants") or [])
    want = tenant if tenant and tenant != "default" else None
    out = []
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
    rows = [{"host": h.get("name"), "tenant": h.get("tenant"), "ip": h.get("ip"),
             "name": p.get("name"), "severity": p.get("severity", 0), "clock": p.get("clock", 0)}
            for h in hosts for p in (h.get("problems") or [])]
    rows.sort(key=lambda r: (-int(r["severity"] or 0), -int(r["clock"] or 0)))
    return rows


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _admin_spoke(request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        sid = hub.get_spoke_by_type("monitoring")
        if not sid:
            raise HTTPException(status_code=503, detail="Monitoring spoke not connected")
        return sid

    async def _relay(sid, command, payload=None):
        try:
            return await hub.request_response(sid, command, payload or {}, timeout=300.0)
        except Exception as e:
            logger.exception("monitoring %s failed", command)
            raise HTTPException(status_code=502, detail=str(e))

    @app.get("/api/monitoring/status")
    async def monitoring_status(request: Request):
        return await _relay(_admin_spoke(request), "MON_STATUS")

    @app.get("/api/monitoring/hosts")
    async def monitoring_hosts(request: Request, tenant: str = None):
        """Monitored hosts + open problems, tenant-scoped like the other pages:
        a Global Admin sees every tenant (optionally narrowed with ``?tenant=``);
        anyone else only the tenants on their own session (deny by default)."""
        import access
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        sid = hub.get_spoke_by_type("monitoring")
        if not sid:
            raise HTTPException(status_code=503, detail="Monitoring spoke not connected")
        res = await _relay(sid, "MON_HOSTS")
        if _is_admin(sess) and not tenant:
            return res
        data = access.unwrap_spoke(res)
        hosts = (data or {}).get("hosts") if isinstance(data, dict) else None
        out = scope_monitoring_hosts(hosts or [], tenant, sess, _is_admin(sess))
        return {"status": "ok", "hosts": out, "problems": monitoring_problem_list(out)}

    @app.get("/api/monitoring/config")
    async def monitoring_config_get(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        return {"server": monitoring_server_address(hub)}

    @app.put("/api/monitoring/config")
    async def monitoring_config_put(request: Request):
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Admin access required")
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            body = {}
        server = str(body.get("server") or "").strip()
        if server and not re.fullmatch(r"[A-Za-z0-9.\-]+(:\d{1,5})?", server):
            raise HTTPException(status_code=400, detail="server must be host or host:port")
        gc = hub.state.system_state.setdefault("global_config", {})
        gc["monitoring_server"] = server
        hub.state._mark_dirty()
        logger.info("monitoring: proxy server address set to %r", server)
        return {"server": server}

    @app.post("/api/monitoring/sync")
    async def monitoring_sync(request: Request):
        sid = _admin_spoke(request)
        return await _relay(sid, "MON_SYNC", await _payload(request))

    @app.post("/api/monitoring/rebuild")
    async def monitoring_rebuild(request: Request):
        sid = _admin_spoke(request)
        return await _relay(sid, "MON_REBUILD", await _payload(request))

    async def _payload(request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return {"devices": await inventory_devices(hub),
                "dry_run": bool((body or {}).get("dry_run"))}
