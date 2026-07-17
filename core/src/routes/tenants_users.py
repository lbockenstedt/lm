"""Setup: updates, modules, tenants, users routes."""
from api import (
    HTTPException, Request, _hash_password, _hub_msg, _invalidate_user_sessions,
    _unwrap_spoke, get_netbox_spoke, get_tenant_scoping, logger, time,
)
from access import (
    ENFORCED_RIGHTS, resolve_effective_permissions, refresh_shared_tenant,
    valid_display_name as _valid_display_name,
    valid_hostname as _valid_hostname,
    valid_identifier as _valid_identifier,
)


def register(app, hub, ctx):
    # Prime the shared-tenant cache at startup so the visibility gate is correct
    # before the first /setup/tenants load (refreshed again on every tenant write).
    try:
        refresh_shared_tenant(hub)
    except Exception:
        pass
    """Register tenants_users routes on the Hub app."""

    @app.post("/setup/update")
    async def trigger_update(request: Request):
        """Manual "Update now" (footer ↻ Update / Update All).

        This runs the SAME process as the scheduled repo-sync
        (``run_repo_sync_all``) — pull ``provisioning_repos/*`` + version-gated
        hub tree pull + ``SPOKE_UPDATE`` fan-out — just triggered on demand
        instead of on the WebUI-configured interval. There is exactly ONE
        scheduler (Setup → Sync); this button is "run that cycle now".

        A manual click sends ``force_spokes=true`` so the spoke fan-out bypasses
        the per-spoke re-push cooldown/gate (the hub itself still only re-pulls
        its own tree when genuinely behind). It ALSO passes ``force=True`` so any
        resulting hub restart sentinel bypasses the maintenance-window/idle gate —
        the button's name says "Update now", so a click that pulls new code (or
        finds the process stale) restarts the hub immediately, not deferred to
        the 02:00 window. A no-op click (already current, not stale) restarts
        nothing — ``perform_update`` only restarts on ``hub_updated or
        stale_reload``, both False when current.
        """
        hub = app.state.hub
        force_spokes = request.query_params.get("force_spokes", "false").lower() == "true"
        logger.info(f"API: Manual update — run_repo_sync_all(force_spokes={force_spokes}, force=True)")
        result = await hub.run_repo_sync_all(force_spokes=force_spokes, force=True)
        hub_r = result.get("hub") if isinstance(result, dict) else None
        hub_r = hub_r if isinstance(hub_r, dict) else {}
        status = hub_r.get("status") or "checked"
        prov = (result.get("provisioning_repos") if isinstance(result, dict) else None) or []
        prov_changed = sum(1 for r in prov if r.get("changed"))
        message = (hub_r.get("message") or (result.get("message") if isinstance(result, dict) else None)
                   or "Update cycle complete.")
        if prov_changed:
            message = f"{message} ({prov_changed} auxiliary repo(s) updated)"
        # run_repo_sync_all is best-effort and never raises; a hub-tree error is
        # reported as status=="error" in its sub-result. Surface that as 500 so
        # the WebUI shows it, but success/checked/no_update stay 200 (avoids the
        # UI "Critical Error:" prefix on a healthy up-to-date outcome).
        if status == "error":
            logger.error("manual update: hub sub-result error: %s", message)
            raise HTTPException(status_code=500, detail=message)
        # Exact-to-the-click version context for the WebUI toast: running = the
        # startup sentinel (what this hub is running NOW), target = /opt/lm/VERSION
        # (the tip just pulled by run_repo_sync_all — what it'll restart into).
        # Same sources as the footer version indicator + the watchdog. Best-effort.
        def _read_ver(path):
            try:
                with open(path) as _f:
                    return _f.read().strip()
            except Exception:  # noqa: BLE001
                return ""
        return {"status": status, "message": message,
                "running_version": _read_ver("/var/lib/lm/state/running-version"),
                "target_version": _read_ver("/opt/lm/VERSION")}

    @app.post("/setup/update/spokes")
    async def trigger_spoke_updates(request: Request):
        """Send SPOKE_UPDATE to all approved spokes without restarting the Hub.

        Called by BugFixer immediately after pushing a fix to GitHub so all deployed
        services pull the latest code before the QA service runs its test suite.
        Returns 200 with a summary once all SPOKE_UPDATE messages have been queued
        (spoke restarts happen asynchronously — poll GET /status for reconnection).
        """
        hub = app.state.hub
        logger.info("API: /setup/update/spokes — queuing SPOKE_UPDATE for all approved spokes")
        result = await hub.update_spokes_only()
        return result

    @app.get("/setup/modules")
    async def get_modules():
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        is_single_server = global_config.get("single_server_mode", False)

        modules = {
            "cppm":     {"path": "cppm/install.sh",              "installed": False},
            "cs":       {"path": "cs/install_cs.sh",             "installed": False},
            "dhcp":     {"path": "dhcp/install_dhcp.sh",         "installed": False},
            "dns":      {"path": "dns/install_dns.sh",           "installed": False},
            "ldap":     {"path": "ldap/install_ldap.sh",         "installed": False},
            "netbox":   {"path": "netbox/install.sh",            "installed": False},
            "opnsense": {"path": "opnsense/install_opnsense.sh", "installed": False},
            "pxmx":     {"path": "pxmx/install_pxmx.sh",        "installed": False},
        }

        for mod in modules:
            if any(mod in sid for sid in hub.active_connections):
                modules[mod]["installed"] = True

        return {
            "single_server_mode": is_single_server,
            "modules": modules
        }

    @app.post("/setup/install-module")
    async def install_module(request: Request):
        hub = app.state.hub
        global_config = hub.state.system_state.get("global_config", {})
        if not global_config.get("single_server_mode", False):
            raise HTTPException(status_code=403, detail="On-demand installation is only supported in single-server mode.")

        try:
            data = await request.json()
            module_id = data.get("module_id")
            custom_spoke_id = data.get("spoke_id")
            display_name = data.get("display_name")

            if not module_id:
                raise HTTPException(status_code=400, detail="Missing module_id")

            # Unified agent model: on-demand "install a module" on the
            # co-located node = loading its ROLE on the local generic agent,
            # which self-installs the role's repo + deps + host infra
            # (_install_role / --infra-only). Replaces the old per-module
            # dedicated installer + {module}-spoke-1 registration; reuses the
            # same LOAD_ROLE path as the WebUI Load Role action, so the module
            # runs as a sub-spoke {agent}-{role} (parent-auto-approved).
            _MODULE_ROLE = {
                "cppm": "cppm", "cs": "simulation", "dhcp": "dhcp", "dns": "dns",
                "ldap": "ldap", "netbox": "netbox", "opnsense": "opnsense",
                "pxmx": "proxmox", "nw": "network", "le": "le", "console": "console",
            }
            role = _MODULE_ROLE.get(module_id, module_id)
            agent_id = hub.get_spoke_by_type("agent")
            if not agent_id:
                raise HTTPException(status_code=409,
                    detail="No generic agent connected to host the role — install the "
                           "agent first (install_all.sh / install_agent.sh).")
            result = await hub.request_response(agent_id, "LOAD_ROLE", {"role": role})
            rdata = result.get("payload", {}).get("data", result) if isinstance(result, dict) else result
            return {"status": "ok",
                    "message": f"Loading role '{role}' on agent {agent_id}.",
                    "agent_id": agent_id, "role": role, "result": rdata}
        except HTTPException:
            raise  # 4xx/503 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("install_module failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-name")
    async def rename_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            new_name = data.get("display_name")
            new_hostname = data.get("hostname")

            if not spoke_id or not new_name:
                raise HTTPException(status_code=400, detail="Missing spoke_id or display_name")
            # Validate identifiers/hostnames BEFORE they're stored or sent to a
            # spoke. new_hostname is relayed to the spoke's SPOKE_SET_HOSTNAME,
            # which applies it via a shell ``hostname`` call — a value carrying
            # shell metacharacters would be remote command injection on the
            # spoke. display_name is stored/rendered (no shell), so it gets the
            # softer valid_display_name check (no control/shell chars).
            if not _valid_identifier(spoke_id):
                raise HTTPException(status_code=400, detail="Invalid spoke_id")
            if not _valid_display_name(new_name):
                raise HTTPException(status_code=400, detail="Invalid display_name")
            if new_hostname and not _valid_hostname(new_hostname):
                raise HTTPException(status_code=400, detail="Invalid hostname")

            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail="Spoke not found")

            hub.state.set_module_name(spoke_id, new_name)
            hub.state.save_state()

            if new_hostname:
                if hub._primary_key(spoke_id) in hub.active_connections:
                    msg = _hub_msg(spoke_id, "SPOKE_SET_HOSTNAME", {"hostname": new_hostname})
                    await hub.send_to_spoke(msg)
                    hostname_status = "Hostname update triggered."
                else:
                    hostname_status = "Spoke not connected; hostname update will be queued."
                    msg = _hub_msg(spoke_id, "SPOKE_SET_HOSTNAME", {"hostname": new_hostname})
                    await hub.mailbox.push(msg, hub.send_to_spoke)
            else:
                hostname_status = ""

            return {"status": "ok", "message": f"Spoke {spoke_id} renamed to {new_name}. {hostname_status}".strip()}
        except HTTPException:
            raise  # 4xx must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("rename_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Tenants + users (/setup/tenants/*, /setup/users/*) ───────────────────
    @app.get("/setup/tenants")
    async def get_tenants():
        hub = app.state.hub
        tenants = hub.state.tenant_state.get("tenants", {})
        tenant_list = [
            {
                "id": tid,
                "name": cfg.get("name") or tid,
                "slug": cfg.get("netbox_tenant_slug") or tid,
                "netbox_id": cfg.get("netbox_id"),
                "description": cfg.get("description", ""),
                # A shared tenant's spokes/resources are visible to every tenant
                # (objects still subnet-scoped). Exactly one tenant carries it.
                "shared": bool(cfg.get("shared")),
            }
            for tid, cfg in tenants.items()
        ]
        if "default" not in [t["id"] for t in tenant_list]:
            tenant_list.insert(0, {"id": "default", "name": "Default", "slug": "default", "netbox_id": None, "description": "", "shared": False})
        # Keep the shared-tenant cache fresh whenever the list is loaded.
        shared_id = refresh_shared_tenant(hub)
        return {"tenants": tenant_list, "shared_tenant_id": shared_id}

    @app.post("/setup/sync-tenants")
    async def sync_tenants_from_netbox():
        """Pull tenants from NetBox and upsert them into hub tenant state."""
        hub = app.state.hub
        spoke_id = hub.get_spoke_by_type("ipam")
        if not spoke_id:
            raise HTTPException(status_code=503, detail="NetBox spoke not connected")
        try:
            result = await hub.request_response(spoke_id, "NETBOX_GET_TENANTS", {})
            data = _unwrap_spoke(result)
            nb_tenants = data.get("tenants", [])
            if data.get("status") != "SUCCESS":
                raise HTTPException(status_code=502, detail=data.get("message", "NetBox error"))

            added, updated = [], []
            existing_ids = set(hub.state.tenant_state.get("tenants", {}).keys())
            nb_slugs = {t["slug"] for t in nb_tenants}

            for t in nb_tenants:
                slug = t["slug"]
                exists = slug in existing_ids
                cfg = hub.state.get_tenant(slug) or {}
                hub.state.update_tenant(slug, {
                    "name": t["name"],
                    "netbox_tenant_slug": slug,
                    "netbox_id": t["id"],
                    "description": t.get("description", ""),
                    **{k: v for k, v in cfg.items() if k not in ("name", "netbox_tenant_slug", "netbox_id", "description")},
                })
                (updated if exists else added).append(slug)

            hub.state.save_state()
            return {
                "status": "ok",
                "added": added, "updated": updated,
                "message": f"Synced {len(nb_tenants)} tenant(s) from NetBox: {len(added)} added, {len(updated)} updated",
            }
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("sync_tenants_from_netbox failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/tenants/{tenant_id}")
    async def get_tenant_details(tenant_id: str):
        hub = app.state.hub
        logger.info(f"API: Fetching details for tenant {tenant_id}")
        tenant = hub.state.get_tenant(tenant_id)
        if tenant is None:
            logger.warning(f"API: Tenant {tenant_id} not found in state.")
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return {"tenant_id": tenant_id, "config": tenant}

    @app.get("/api/tenant/scoping")
    async def get_current_tenant_scoping(tenant: str = None):
        """Returns the active tenant's spoke-scoping config (netbox slug, proxmox tag, ldap base DN)."""
        hub = app.state.hub
        return get_tenant_scoping(hub, tenant)

    @app.post("/setup/tenants")
    async def create_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id")
            if not tenant_id:
                raise HTTPException(status_code=400, detail="Missing tenant_id")

            hub.state.update_tenant(tenant_id, {})
            hub.state.save_state()
            return {"status": "ok", "message": f"Tenant {tenant_id} created."}
        except Exception as e:
            logger.exception("create_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/tenant")
    async def update_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            tenant_id = data.get("tenant_id", "default")
            config = data.get("config", {})

            # Single-shared invariant: setting shared=True on a tenant clears the
            # flag on every OTHER tenant, so exactly one shared tenant exists.
            if "shared" in config and config.get("shared"):
                for other_tid, other_cfg in (hub.state.tenant_state.get("tenants", {}) or {}).items():
                    if other_tid != tenant_id and isinstance(other_cfg, dict) and other_cfg.get("shared"):
                        hub.state.update_tenant(other_tid, {"shared": False})

            hub.state.update_tenant(tenant_id, config)

            if config.get("active"):
                hub.state.set_active_tenant(tenant_id)

            hub.state.save_state()
            # Refresh the cached shared-tenant id so the visibility gate is
            # correct on the very next request.
            refresh_shared_tenant(hub)

            return {"status": "ok", "message": f"Tenant {tenant_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    @app.post("/api/tenant/migrate")
    async def migrate_tenant_all(request: Request):
        """Migrate Data to new Tenant — CROSS-MODULE, keyed by LM tenant_id.

        Copies tenant SOURCE's data to TARGET across modules and (by default)
        purges the source's data. Phase 1 covers ``cs`` (all simulations store
        blobs) + ``netbox`` (reassign objects via each tenant's
        netbox_tenant_slug, delete the source NetBox tenant). ``pxmx``/``ldap``
        are accepted but report TODO until Phase 2. ADMIN-ONLY (destructive,
        cross-tenant). Body: ``{source, target, delete_source=true, modules=[…]}``
        where source/target are LM tenant_ids. NOTE: the source LM tenant *shell*
        (registry entry + user assignments) is intentionally NOT deleted here —
        only its per-module data is moved/cleared; remove the empty tenant via
        tenant management if desired."""
        hub = app.state.hub
        sess = ctx._session_user(request)
        if not (sess and ctx._is_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin only")
        body = await request.json()
        source = (body.get("source") or "").strip()
        target = (body.get("target") or "").strip()
        if not source or not target:
            raise HTTPException(status_code=400, detail="source and target tenant are required")
        if source == target:
            raise HTTPException(status_code=400, detail="source and target must differ")
        purge = bool(body.get("delete_source", True))
        mods = set(body.get("modules") or ["cs", "netbox"])
        out = {"source": source, "target": target, "modules": {}}

        # ── CS / Simulations: one deep-merge of _data[source] → _data[target] ──
        if "cs" in mods:
            try:
                out["modules"]["cs"] = await hub.simulations_store.migrate_tenant_data(
                    source, target, purge_source=purge)
            except Exception as e:  # noqa: BLE001
                out["modules"]["cs"] = {"status": "ERROR", "message": str(e)}

        # ── NetBox: reassign objects via each tenant's netbox_tenant_slug ──
        if "netbox" in mods:
            src_slug = (get_tenant_scoping(hub, source) or {}).get("netbox_tenant_slug") or source
            tgt_slug = (get_tenant_scoping(hub, target) or {}).get("netbox_tenant_slug") or target
            spoke_id = get_netbox_spoke(hub)
            if not spoke_id:
                out["modules"]["netbox"] = {"status": "SKIPPED", "message": "NetBox spoke not connected"}
            else:
                try:
                    r = await hub.request_response(
                        spoke_id, "NETBOX_MIGRATE_TENANT",
                        {"source": src_slug, "target": tgt_slug, "delete_source": purge},
                        timeout=300.0)
                    out["modules"]["netbox"] = (_unwrap_spoke(r) if r is not None
                                                else {"status": "ERROR", "message": "no response from NetBox spoke"})
                except Exception as e:  # noqa: BLE001
                    out["modules"]["netbox"] = {"status": "ERROR", "message": str(e)}

        # ── pxmx: re-tag VMs from the source tenant's proxmox_tag to the target's.
        # pxmx agents may be hosted by a 'hypervisor' spoke (direct) OR a
        # 'simulation'/cs spoke (split) — relay to whichever is connected + sum. ──
        if "pxmx" in mods:
            old_tag = (get_tenant_scoping(hub, source) or {}).get("proxmox_tag") or source
            new_tag = (get_tenant_scoping(hub, target) or {}).get("proxmox_tag") or target
            legs, total, errs = [], 0, []
            for mt in ("hypervisor", "simulation"):
                sid = hub.get_spoke_by_type(mt)
                if not sid:
                    continue
                try:
                    r = await hub.request_response(
                        sid, "PXMX_RETAG_TENANT", {"old_tag": old_tag, "new_tag": new_tag}, timeout=180.0)
                    u = _unwrap_spoke(r) if r is not None else {}
                    total += int((u or {}).get("count", 0) or 0)
                    legs.append(mt)
                    if (u or {}).get("status") not in ("SUCCESS", None):
                        errs.append(f"{mt}: {(u or {}).get('message', '?')}")
                except Exception as e:  # noqa: BLE001
                    errs.append(f"{mt}: {e}")
            if not legs:
                out["modules"]["pxmx"] = {"status": "SKIPPED", "message": "no hypervisor/simulation spoke connected"}
            else:
                out["modules"]["pxmx"] = {
                    "status": "PARTIAL" if errs else "SUCCESS", "count": total,
                    "message": f"re-tagged {total} VM(s) {old_tag}→{new_tag}"
                               + (f"; {'; '.join(errs)}" if errs else "")}

        # ── ldap: re-home the source tenant's directory subtree to the target's ──
        if "ldap" in mods:
            src_dn = (get_tenant_scoping(hub, source) or {}).get("ldap_base_dn") or ""
            tgt_dn = (get_tenant_scoping(hub, target) or {}).get("ldap_base_dn") or ""
            sid = hub.get_spoke_by_type("directory")
            if not sid:
                out["modules"]["ldap"] = {"status": "SKIPPED", "message": "no directory (LDAP) spoke connected"}
            elif not src_dn or not tgt_dn:
                out["modules"]["ldap"] = {"status": "SKIPPED",
                                          "message": "source/target tenant has no ldap_base_dn configured"}
            else:
                try:
                    r = await hub.request_response(
                        sid, "LDAP_MIGRATE_TENANT",
                        {"source_base_dn": src_dn, "target_base_dn": tgt_dn, "purge_source": purge},
                        timeout=180.0)
                    out["modules"]["ldap"] = (_unwrap_spoke(r) if r is not None
                                              else {"status": "ERROR", "message": "no response from LDAP spoke"})
                except Exception as e:  # noqa: BLE001
                    out["modules"]["ldap"] = {"status": "ERROR", "message": str(e)}

        statuses = [v.get("status") for v in out["modules"].values()]
        out["status"] = ("ERROR" if any(s == "ERROR" for s in statuses)
                         else "PARTIAL" if any(s in ("SKIPPED", "TODO", "PARTIAL") for s in statuses)
                         else "SUCCESS")
        logger.info("tenant migrate %s → %s (purge=%s, modules=%s) by %s: %s",
                    source, target, purge, sorted(mods),
                    (sess.get("user", {}) or {}).get("username"), out["status"])
        return out

    @app.post("/setup/generate-secret")
    async def generate_secret(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            secret = hub.key_manager.generate_first_secret(hub._primary_key(spoke_id))
            return {"spoke_id": spoke_id, "secret": secret}
        except HTTPException:
            raise  # 400 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("generate_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/assign-tenant")
    async def assign_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            if not hub.state.get_tenant(tenant_id):
                raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")

            users = hub.state.system_state.get("users", {})
            if users.get(user_id, {}).get("protected"):
                raise HTTPException(status_code=403, detail="The protected admin account cannot be assigned to a tenant")

            hub.state.assign_user_to_tenant(user_id, tenant_id)
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok", "message": f"User {user_id} assigned to tenant {tenant_id}"}
        except HTTPException:
            raise  # 400/404/403 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("assign_user_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/remove-tenant")
    async def remove_user_tenant(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            tenant_id = data.get("tenant_id")

            if not user_id or not tenant_id:
                raise HTTPException(status_code=400, detail="Missing user_id or tenant_id")

            hub.state.remove_user_from_tenant(user_id, tenant_id)
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok", "message": f"User {user_id} removed from tenant {tenant_id}"}
        except HTTPException:
            raise  # 400 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("remove_user_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/set-tenants")
    async def set_user_tenants(request: Request):
        """Batch tenant-membership change for ONE user in a single call. The User
        edit form sends its full add/remove delta here instead of one
        assign-tenant / remove-tenant POST per changed tenant. Adds + removes are
        applied, then the user's sessions are invalidated ONCE."""
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            add = data.get("add") or []
            remove = data.get("remove") or []
            if not user_id:
                raise HTTPException(status_code=400, detail="Missing user_id")
            if not isinstance(add, list) or not isinstance(remove, list):
                raise HTTPException(status_code=400, detail="add/remove must be lists")
            users = hub.state.system_state.get("users", {})
            if users.get(user_id, {}).get("protected") and add:
                raise HTTPException(status_code=403,
                    detail="The protected admin account cannot be assigned to a tenant")
            assigned, removed, errors = [], [], []
            for tid in add:
                if not hub.state.get_tenant(tid):
                    errors.append(f"tenant {tid} not found")
                    continue
                hub.state.assign_user_to_tenant(user_id, tid)
                assigned.append(tid)
            for tid in remove:
                hub.state.remove_user_from_tenant(user_id, tid)
                removed.append(tid)
            if assigned or removed:
                _invalidate_user_sessions(hub, user_id)
            return {"status": "ok", "assigned": assigned, "removed": removed, "errors": errors}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("set_user_tenants failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/users")
    async def get_users():
        hub = app.state.hub
        raw = hub.state.system_state.get("users", {})
        # Strip password hashes; surface the RBAC-resolved effective permissions
        # (group + per-user union) alongside the stored per-user overrides so the
        # UI can show what a user actually gets vs. what's set directly on them.
        safe = {}
        for uid, u in raw.items():
            rec = {k: v for k, v in u.items() if k != "password_hash"}
            rec["groups"] = u.get("groups", [])
            rec["effective_permissions"] = resolve_effective_permissions(hub, u)
            safe[uid] = rec
        return {"users": safe}

    @app.post("/setup/users")
    async def update_user(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            permissions = data.get("permissions", {})
            password = data.get("password", "")
            auth_type = data.get("auth_type", "local")
            tenant_id = data.get("tenant_id")
            groups = data.get("groups")  # None = leave unchanged; list = replace

            if not user_id:
                raise HTTPException(status_code=400, detail="Missing user_id")

            users = hub.state.system_state.setdefault("users", {})
            existing = users.get(user_id, {})

            # Create vs edit: the WebUI "Add New User" flow sends create=true.
            # Reject an already-existing user_id on create so the modal can't
            # silently upsert — and demote — an existing user (e.g. reusing a
            # non-protected admin's id with System Admin unchecked). The edit
            # modal does not send create, so edits still upsert as before.
            if data.get("create") and user_id in users:
                raise HTTPException(status_code=409, detail="User already exists")

            # Anti-lockout: protected account cannot be demoted or assigned to a tenant
            if existing.get("protected"):
                permissions = existing.get("permissions", {"role": "admin"})
                tenant_id = None  # ignore any tenant assignment attempt

            # Keep the two admin-flag forms (role + boolean) in sync on every
            # write so the WebUI role selector and _is_admin() never diverge —
            # a role-only admin would otherwise show unchecked and an edit could
            # drop the role, silently demoting the user.
            _p = permissions or {}
            if _p.get("admin") or _p.get("role") == "admin":
                permissions = {**_p, "admin": True, "role": "admin"}
            elif _p.get("role") == "tenant_admin" or _p.get("tenant_admin"):
                # Tenant Admin tier: authoritative role, NO admin flag (so
                # is_admin() stays False — the tier is tenant-confined, not
                # system-wide). Clear any stray admin flag so a Global→tenant
                # demotion takes effect rather than leaving a latent Global.
                # Accept both the role form (role:"tenant_admin") and the flag
                # form (tenant_admin:true) the WebUI checkbox sends — normalize
                # to the role form for storage consistency.
                permissions = {**_p}
                permissions.pop("admin", None)
                permissions.pop("tenant_admin", None)
                permissions["role"] = "tenant_admin"

            entry = {
                **existing,
                "permissions": permissions,
                "auth_type": auth_type,
                "updated_at": time.time(),
            }
            # Group membership (RBAC). Only touched when the caller sends a
            # `groups` list, so older edit payloads that omit it don't wipe it.
            # Protected accounts stay admin regardless, so groups are moot there.
            if groups is not None and not existing.get("protected"):
                if not isinstance(groups, list):
                    raise HTTPException(status_code=400, detail="groups must be a list")
                valid = hub.state.system_state.get("permission_groups", {})
                entry["groups"] = [g for g in groups if g in valid]
            if password:
                entry["password_hash"] = _hash_password(password)
            # Assigned tenants. Accept a `tenants` LIST (the Add/Edit User modal's
            # multi-select) — authoritative so an edit can also REMOVE tenants —
            # and/or a single legacy `tenant_id` (unioned in). Ignored for
            # protected accounts (anti-lockout; tenant_id was cleared above). This
            # is the Global-admin path, so no ownership filtering — that is the
            # tenant-scoped /tenant/... route's job.
            tenants_list = data.get("tenants")
            if tenants_list is not None and not isinstance(tenants_list, list):
                raise HTTPException(status_code=400, detail="tenants must be a list")
            if not existing.get("protected"):
                if tenants_list is not None:
                    wanted = {t for t in tenants_list if t}
                    if tenant_id:
                        wanted.add(tenant_id)
                    entry["tenants"] = sorted(wanted)
                elif tenant_id:
                    entry.setdefault("tenants", [])
                    if tenant_id not in entry["tenants"]:
                        entry["tenants"].append(tenant_id)
            # A Tenant Admin is tenant-confined (check_tenant_access /
            # filter_session deny-by-default for tenantless users since
            # 21d483e); require ≥1 assigned tenant at config time so a
            # misconfigured tenant admin isn't silently created with no access.
            if entry.get("permissions", {}).get("role") == "tenant_admin" and not entry.get("tenants"):
                raise HTTPException(
                    status_code=400,
                    detail="Tenant Admin requires at least one assigned tenant",
                )
            users[user_id] = entry
            hub.state.save_state()
            # Drop this user's existing sessions so the change (password, perms,
            # tenant, group membership) takes effect immediately rather than being
            # honored from a stale cookie until the 8h TTL / idle timeout. An
            # admin-initiated edit is infrequent; forcing one re-login is the
            # correct security posture (esp. a demotion).
            _invalidate_user_sessions(hub, user_id)

            return {"status": "ok", "message": f"User {user_id} updated."}
        except HTTPException:
            raise  # 400/409 (e.g. "User already exists") must reach the client, not become 500
        except Exception as e:
            logger.exception("update_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/users/{user_id}/set-password")
    async def set_user_password(user_id: str, request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            password = data.get("password", "")
            if not password:
                raise HTTPException(status_code=400, detail="Password required")
            users = hub.state.system_state.get("users", {})
            if user_id not in users:
                raise HTTPException(status_code=404, detail="User not found")
            users[user_id]["password_hash"] = _hash_password(password)
            hub.state.save_state()
            # Force re-login: the old credential is no longer valid, so any
            # session minted under it must not remain usable.
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("set_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Tenant-scoped user management (Phase 2) ───────────────────────────────
    # A tenant Admin may manage the operators of its own tenant(s) WITHOUT any
    # system-wide power: it can create a user (force-assigned to an owned
    # tenant), edit a user's module rights / password, set a password, and
    # remove a user from one of its tenants. The /setup/users* routes stay
    # Global-Admin-only (the middleware's /setup/ gate is untouched); these
    # /api/tenant/{tenant}/users* routes are the tenant-scoped path.
    #
    # Safety rules (tenant_admin caller; Global admin is unconstrained):
    #   * the path {tenant} must be in the caller's user.tenants (gate + the
    #     middleware's ?tenant= scoping both enforce this);
    #   * a tenant_admin may only MODIFY a user whose tenants ⊆ the admin's
    #     tenants (so a perm/password change can't bleed into a tenant the
    #     admin doesn't own), and who is NOT an admin-tier user (no editing a
    #     Global admin or another tenant Admin) and NOT protected;
    #   * a tenant_admin may NEVER grant the admin or tenant_admin role
    #     (no privilege escalation via the tenant admin) — only module rights;
    #   * a tenant_admin may only ASSIGN tenants it owns (intersect any body
    #     tenants with its own);
    #   * "delete" here is "remove from my tenant" (non-destructive across
    #     other tenants): the user record survives, minus this tenant. A user
    #     left with no tenants is inert (deny-by-default, 21d483e). Deleting the
    #     user RECORD entirely stays Global-Admin-only.

    def _ta_gate(request: Request, tenant: str):
        """Auth + tier + tenant-ownership gate for the tenant-scoped user
        routes. Returns the caller's session. A Global Admin (any tenant) or a
        tenant Admin (own tenant only, via _check_tenant_access) passes; a
        plain authenticated user is blocked — user management is an admin
        operation, even at the tenant tier."""
        sess = ctx._session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if not (ctx._is_admin(sess) or ctx._is_tenant_admin(sess)):
            raise HTTPException(status_code=403, detail="Admin access required")
        if not ctx._check_tenant_access(sess, tenant):
            raise HTTPException(status_code=403,
                                detail=f"Not authorized for tenant '{tenant}'")
        return sess

    def _admin_tenants(sess) -> set:
        return set((sess or {}).get("user", {}).get("tenants") or [])

    def _is_target_admin_tier(target_user: dict) -> bool:
        tp = (target_user or {}).get("permissions", {}) or {}
        return bool(tp.get("admin") or tp.get("role") in ("admin", "tenant_admin"))

    def _reject_role_escalation(permissions: dict):
        """A tenant Admin may only grant module rights, never an admin tier."""
        _p = permissions or {}
        if _p.get("admin") or _p.get("role") == "admin":
            raise HTTPException(status_code=400,
                                detail="Tenant admin cannot grant Global Admin")
        if _p.get("role") == "tenant_admin" or _p.get("tenant_admin"):
            raise HTTPException(status_code=400,
                                detail="Tenant admin cannot grant the tenant Admin role")

    def _normalize_tenant_admin_perms(permissions: dict) -> dict:
        """Drop the admin/tenant_admin keys a client might send and keep only
        the recognised module rights (so a tenant_admin's grant is always a
        plain module-right set, never a tier). Mirrors upsert_group's allowlist."""
        _p = dict(permissions or {})
        _p.pop("admin", None)
        _p.pop("tenant_admin", None)
        _p.pop("role", None)
        # Keep only ENFORCED_RIGHTS (+ console_write) — no synthetic keys.
        allowed = set(ENFORCED_RIGHTS)
        return {k: bool(v) for k, v in _p.items() if k in allowed and v}

    @app.get("/api/tenant/{tenant}/users")
    async def ta_get_tenant_users(tenant: str, request: Request):
        """List the users who are members of {tenant} (tenant ∈ their tenants).
        A tenant Admin sees its own tenant's roster; a Global Admin may list
        any. Password hashes are stripped; effective_permissions are resolved."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        raw = hub.state.system_state.get("users", {})
        out = {}
        for uid, u in raw.items():
            if tenant in (u.get("tenants") or []):
                rec = {k: v for k, v in u.items() if k != "password_hash"}
                rec["groups"] = u.get("groups", [])
                rec["effective_permissions"] = resolve_effective_permissions(hub, u)
                out[uid] = rec
        return {"users": out, "tenant": tenant}

    @app.post("/api/tenant/{tenant}/users")
    async def ta_create_tenant_user(tenant: str, request: Request):
        """Create a user force-assigned to {tenant} (an owned tenant). A tenant
        Admin may only grant module rights (never admin/tenant_admin). The new
        user starts with tenants=[{tenant}] — additional owned tenants can be
        added later via the edit route. Reject if the user_id already exists
        (the WebUI Add-User modal sends create=true semantics)."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        try:
            data = await request.json()
            user_id = data.get("user_id")
            permissions = data.get("permissions", {})
            password = data.get("password", "")
            auth_type = data.get("auth_type", "local")

            if not user_id:
                raise HTTPException(status_code=400, detail="Missing user_id")
            _reject_role_escalation(permissions)

            users = hub.state.system_state.setdefault("users", {})
            if user_id in users:
                raise HTTPException(status_code=409, detail="User already exists")

            perms = _normalize_tenant_admin_perms(permissions)
            entry = {
                "permissions": perms,
                "auth_type": auth_type,
                "tenants": [tenant],
                "created_at": time.time(),
                "updated_at": time.time(),
            }
            if password:
                entry["password_hash"] = _hash_password(password)
            users[user_id] = entry
            hub.state.save_state()
            _invalidate_user_sessions(hub, user_id)
            logger.info("tenant admin %s created user %s in tenant %s",
                        (sess.get("user") or {}).get("user_id", "?"), user_id, tenant)
            return {"status": "ok", "message": f"User {user_id} created in tenant {tenant}."}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ta_create_tenant_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/tenant/{tenant}/users/{user_id}")
    async def ta_update_tenant_user(tenant: str, user_id: str, request: Request):
        """Edit a user's module rights / password / auth_type. A tenant Admin
        may only edit a user whose tenants ⊆ the admin's tenants and who is not
        an admin-tier/protected user; it may only grant module rights and may
        only assign tenants it owns. A Global Admin is unconstrained but still
        cannot demote the protected account. Tenant membership for the path
        tenant is never removed here — use the DELETE route for that."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        try:
            data = await request.json()
            permissions = data.get("permissions", {})
            password = data.get("password", "")
            auth_type = data.get("auth_type")
            extra_tenants = data.get("tenants")  # list = replace membership (intersect w/ owned)

            users = hub.state.system_state.get("users", {})
            existing = users.get(user_id)
            if not existing:
                raise HTTPException(status_code=404, detail="User not found")
            if existing.get("protected"):
                raise HTTPException(status_code=403,
                                    detail="The protected admin account cannot be modified")
            is_global = ctx._is_admin(sess)
            if not is_global:
                # Tenant-admin constraints: no touching admin-tier users, and
                # the target's tenant set must be a subset of the admin's own
                # (so a change can't bleed into a tenant the admin doesn't own).
                if _is_target_admin_tier(existing):
                    raise HTTPException(status_code=403,
                                        detail="Tenant admin cannot modify an admin-tier user")
                if not set(existing.get("tenants") or []).issubset(_admin_tenants(sess)):
                    raise HTTPException(status_code=403,
                                        detail="User extends beyond your tenants — ask a Global admin")
                _reject_role_escalation(permissions)

            _p = dict(permissions or {})
            if is_global:
                # Global admin: reuse the /setup/users normalization so the two
                # admin-flag forms stay in sync and the tenant_admin tier is
                # normalized exactly as the Global user-management route does.
                if _p.get("admin") or _p.get("role") == "admin":
                    permissions = {**_p, "admin": True, "role": "admin"}
                elif _p.get("role") == "tenant_admin" or _p.get("tenant_admin"):
                    permissions = {**_p}
                    permissions.pop("admin", None)
                    permissions.pop("tenant_admin", None)
                    permissions["role"] = "tenant_admin"
            else:
                permissions = _normalize_tenant_admin_perms(_p)

            entry = {**existing, "permissions": permissions, "updated_at": time.time()}
            if auth_type:
                entry["auth_type"] = auth_type
            if password:
                entry["password_hash"] = _hash_password(password)
            if extra_tenants is not None:
                if not isinstance(extra_tenants, list):
                    raise HTTPException(status_code=400, detail="tenants must be a list")
                owned = _admin_tenants(sess) if not is_global else None
                # The path tenant is always retained (edit must not drop it; use
                # DELETE to leave the tenant). A tenant admin can only ADD owned
                # tenants; a Global admin may set any list.
                wanted = set(extra_tenants) | {tenant}
                if owned is not None:
                    wanted &= owned | {tenant}  # drop tenants the admin doesn't own
                entry["tenants"] = sorted(wanted)
            if entry.get("permissions", {}).get("role") == "tenant_admin" and not entry.get("tenants"):
                raise HTTPException(status_code=400,
                                    detail="Tenant Admin requires at least one assigned tenant")
            users[user_id] = entry
            hub.state.save_state()
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok", "message": f"User {user_id} updated."}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ta_update_tenant_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/tenant/{tenant}/users/{user_id}/set-password")
    async def ta_set_tenant_user_password(tenant: str, user_id: str, request: Request):
        """Set/reset a user's password. The user must be a member of {tenant}
        (an owned tenant). A tenant admin may not reset an admin-tier or
        protected user's password (no credential takeover of admins)."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        try:
            data = await request.json()
            password = data.get("password", "")
            if not password:
                raise HTTPException(status_code=400, detail="Password required")
            users = hub.state.system_state.get("users", {})
            existing = users.get(user_id)
            if not existing:
                raise HTTPException(status_code=404, detail="User not found")
            if existing.get("protected"):
                raise HTTPException(status_code=403,
                                    detail="The protected admin account cannot be modified")
            if tenant not in (existing.get("tenants") or []):
                raise HTTPException(status_code=403,
                                    detail="User is not a member of this tenant")
            if not ctx._is_admin(sess) and _is_target_admin_tier(existing):
                raise HTTPException(status_code=403,
                                    detail="Tenant admin cannot reset an admin-tier user's password")
            existing["password_hash"] = _hash_password(password)
            existing["updated_at"] = time.time()
            hub.state.save_state()
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ta_set_tenant_user_password failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/api/tenant/{tenant}/users/{user_id}")
    async def ta_remove_tenant_user(tenant: str, user_id: str, request: Request):
        """Remove a user from {tenant} (the non-destructive "delete from my
        tenant" op): the user record survives minus this tenant. A user left
        with no tenants is inert (deny-by-default). The protected account and
        admin-tier users are never removable by a tenant admin. Deleting the
        user RECORD entirely stays Global-Admin-only (/setup/users)."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        try:
            users = hub.state.system_state.get("users", {})
            existing = users.get(user_id)
            if not existing:
                raise HTTPException(status_code=404, detail="User not found")
            if existing.get("protected"):
                raise HTTPException(status_code=403,
                                    detail="The protected admin account cannot be modified")
            if not ctx._is_admin(sess) and _is_target_admin_tier(existing):
                raise HTTPException(status_code=403,
                                    detail="Tenant admin cannot remove an admin-tier user from a tenant")
            hub.state.remove_user_from_tenant(user_id, tenant)
            _invalidate_user_sessions(hub, user_id)
            return {"status": "ok",
                    "message": f"User {user_id} removed from tenant {tenant}",
                    "remaining_tenants": list((users.get(user_id) or {}).get("tenants") or [])}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ta_remove_tenant_user failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Phase 4: tenant CRUD on own tenants (tenant-scoped tenant edit) ──────
    # `/setup/tenants*` (create / delete / sync / cross-tenant) stays
    # Global-Admin-only via the access-control middleware's `/setup/` gate.
    # These `/api/tenant/{tenant}` routes give a tenant Admin a scoped EDIT
    # path for a tenant that is IN its `user.tenants` list. Creating a
    # brand-new tenant, deleting a tenant, or editing a tenant the admin does
    # NOT own stays Global-Admin-only — escalation prevention (a new tenant is
    # a system-wide act; a non-owned tenant is another tenant's data).
    #
    # Editable allowlist for a tenant_admin (own tenant): `name`, `description`,
    # `quotas` — the cosmetic + self-limit fields. The scoping fields
    # (`netbox_tenant_slug`, `netbox_id`, `proxmox_tag`, `ldap_base_dn`) and
    # `active` are deliberately NOT editable here: they re-scope the tenant to a
    # different external-system tenant (NetBox tenant / Proxmox tag / LDAP
    # branch), so a tenant_admin changing them could pull ANOTHER tenant's data
    # into its own view — a cross-tenant escalation. Re-scoping + setting the
    # system-wide active tenant stay Global-Admin-only (`/setup/tenant`).
    # Onboarding-PSK management has its own tenant-scoped routes (Phase 1).
    _TA_TENANT_EDITABLE = ("name", "description", "quotas")

    @app.get("/api/tenant/{tenant}")
    async def ta_get_tenant(tenant: str, request: Request):
        """Tenant-scoped tenant details for the editor. A Global admin gets the
        full record (mirrors `/setup/tenants/{tenant_id}`); a tenant_admin gets
        only its editable fields plus the current scoping values read-only for
        display. The path {tenant} must be in the caller's `user.tenants`
        (enforced by `_ta_gate` → `_check_tenant_access`)."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        tenant_rec = hub.state.get_tenant(tenant)
        if tenant_rec is None:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant} not found")
        if ctx._is_admin(sess):
            return {"tenant_id": tenant, "config": dict(tenant_rec)}
        # tenant_admin: editable fields + read-only scoping for display.
        view_keys = _TA_TENANT_EDITABLE + ("netbox_tenant_slug", "proxmox_tag", "ldap_base_dn")
        return {"tenant_id": tenant,
                "config": {k: tenant_rec.get(k) for k in view_keys if k in tenant_rec}}

    @app.post("/api/tenant/{tenant}")
    async def ta_update_tenant(tenant: str, request: Request):
        """Tenant-scoped tenant edit. A tenant_admin may merge ONLY the editable
        allowlist (`name`/`description`/`quotas`) into its OWN tenant's record;
        scoping fields + `active` are dropped (cross-tenant re-scope protection).
        A Global admin may set any field (same semantics as `/setup/tenant`),
        so this route is also a valid edit path for Global. The path {tenant}
        must be in the caller's `user.tenants` (enforced by `_ta_gate`)."""
        sess = _ta_gate(request, tenant)
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {}) or {}
            # This is the EDIT path: the tenant must already exist. Creating a
            # tenant stays Global-Admin-only via /setup/tenants; do NOT silently
            # create here (update_tenant would otherwise upsert). 404 either way.
            if hub.state.get_tenant(tenant) is None:
                raise HTTPException(status_code=404,
                                    detail=f"Tenant {tenant} not found")
            if ctx._is_admin(sess):
                merged = dict(config)  # Global — full merge (mirrors /setup/tenant)
            else:
                # tenant_admin — allowlist only; scoping/active silently dropped.
                merged = {k: v for k, v in config.items() if k in _TA_TENANT_EDITABLE}
            if not merged:
                raise HTTPException(
                    status_code=400,
                    detail="No editable fields supplied (a tenant admin may only set name, description, quotas)")
            hub.state.update_tenant(tenant, merged)
            hub.state.save_state()
            return {"status": "ok", "message": f"Tenant {tenant} updated.",
                    "updated": merged}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("ta_update_tenant failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Permission groups (RBAC) ────────────────────────────────────────────
    # All /setup/* is admin-only via the access-control middleware, so these
    # need no extra gate. A group bundles the same right-keys a user carries;
    # a user's effective perms = union(their groups) OR per-user overrides.

    def _slug_group_id(name: str) -> str:
        """Derive a stable id from a group name (lowercase, non-alnum→-)."""
        import re
        base = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
        return base or "group"

    @app.get("/setup/groups")
    async def get_groups():
        hub = app.state.hub
        groups = hub.state.system_state.get("permission_groups", {})
        # Report membership counts so the UI can warn before deleting a group
        # that still has members.
        users = hub.state.system_state.get("users", {})
        counts = {}
        for u in users.values():
            for gid in u.get("groups", []) or []:
                counts[gid] = counts.get(gid, 0) + 1
        enriched = {gid: {**g, "member_count": counts.get(gid, 0)}
                    for gid, g in groups.items()}
        return {"groups": enriched, "enforced_rights": list(ENFORCED_RIGHTS)}

    @app.post("/setup/groups")
    async def upsert_group(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            group_id = (data.get("group_id") or "").strip()
            name = (data.get("name") or "").strip()
            if not name and not group_id:
                raise HTTPException(status_code=400, detail="Group name required")
            groups = hub.state.system_state.setdefault("permission_groups", {})
            # New group → derive an id from the name (avoid clobbering an
            # existing id); edit → the client sends the existing group_id.
            if not group_id:
                group_id = _slug_group_id(name)
                if group_id in groups:
                    n = 2
                    while f"{group_id}-{n}" in groups:
                        n += 1
                    group_id = f"{group_id}-{n}"
            existing = groups.get(group_id, {})
            # Only persist recognised right-keys (+ admin/tenant_admin tiers) so
            # a group can't smuggle an arbitrary/unknown flag into a user's
            # effective permissions. A group may grant the Global Admin tier
            # (``admin``) or the tenant Admin tier (``tenant_admin``); Global
            # wins if both are set (see resolve_effective_permissions).
            raw_perms = data.get("permissions", {}) or {}
            allowed = set(ENFORCED_RIGHTS) | {"admin", "tenant_admin"}
            perms = {k: True for k, v in raw_perms.items() if v and k in allowed}
            if perms.get("admin"):
                perms["role"] = "admin"
            elif perms.get("tenant_admin"):
                perms["role"] = "tenant_admin"
            # Granted tenant scope: a group may carry a ``tenants`` list so a
            # single Entra group grants BOTH RBAC permissions AND tenant scope
            # (the source of truth for Entra-provisioned users). Validate each
            # id is a real tenant (drop unknowns silently — a typo'd id granting
            # a non-existent tenant would otherwise widen scope unexpectedly).
            raw_tenants = data.get("tenants")
            if raw_tenants is None:
                # Not sent → preserve existing (edit flow); only replace on an
                # explicit send (list = replace, empty list = clear).
                granted_tenants = existing.get("tenants", [])
            else:
                known_tenants = set(
                    (hub.state.tenant_state.get("tenants", {}) or {}).keys())
                granted_tenants = []
                for tid in raw_tenants or []:
                    t = str(tid).strip()
                    if t and t in known_tenants and t not in granted_tenants:
                        granted_tenants.append(t)
            groups[group_id] = {
                **existing,
                "name": name or existing.get("name", group_id),
                "description": data.get("description", existing.get("description", "")),
                "permissions": perms,
                "ldap_group": (data.get("ldap_group") or existing.get("ldap_group", "")).strip(),
                "tenants": granted_tenants,
                "updated_at": time.time(),
            }
            hub.state.save_state()
            # A group's permissions feed every member's effective permission set
            # (union of group bundles + per-user rights). Invalidate members'
            # sessions so a permission/demotion change takes effect immediately
            # instead of being evadable up to the 8h session TTL (a demoted
            # group shouldn't keep admin access by simply avoiding /auth/me).
            for uid, u in hub.state.system_state.get("users", {}).items():
                if group_id in (u.get("groups", []) or []):
                    _invalidate_user_sessions(hub, uid)
            return {"status": "ok", "group_id": group_id}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("upsert_group failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/groups/{group_id}")
    async def delete_group(group_id: str):
        hub = app.state.hub
        try:
            groups = hub.state.system_state.setdefault("permission_groups", {})
            if group_id not in groups:
                raise HTTPException(status_code=404, detail="Group not found")
            if groups[group_id].get("protected"):
                raise HTTPException(status_code=403, detail="Group is protected")
            # Detach the group from every member so no user keeps a dangling id.
            users = hub.state.system_state.get("users", {})
            member_ids = []
            for uid, u in users.items():
                if group_id in (u.get("groups", []) or []):
                    u["groups"] = [g for g in u["groups"] if g != group_id]
                    member_ids.append(uid)
            del groups[group_id]
            hub.state.save_state()
            # Detaching the group changes each member's effective permissions —
            # invalidate their sessions so the loss takes effect immediately
            # (was evadable up to the 8h session TTL).
            for uid in member_ids:
                _invalidate_user_sessions(hub, uid)
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("delete_group failed")
            raise HTTPException(status_code=500, detail=str(e))
