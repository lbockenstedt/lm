"""Setup: updates, modules, tenants, users routes."""
from api import (
    HTTPException, Request, _hash_password, _hub_msg, _unwrap_spoke, get_tenant_scoping,
    logger, time,
)
from access import ENFORCED_RIGHTS, resolve_effective_permissions


def register(app, hub, ctx):
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
        its own tree when genuinely behind).
        """
        hub = app.state.hub
        force_spokes = request.query_params.get("force_spokes", "false").lower() == "true"
        logger.info(f"API: Manual update — run_repo_sync_all(force_spokes={force_spokes})")
        result = await hub.run_repo_sync_all(force_spokes=force_spokes)
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
        return {"status": status, "message": message}

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

            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail="Spoke not found")

            hub.state.set_module_name(spoke_id, new_name)
            hub.state.save_state()

            if new_hostname:
                if spoke_id in hub.active_connections:
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
            }
            for tid, cfg in tenants.items()
        ]
        if "default" not in [t["id"] for t in tenant_list]:
            tenant_list.insert(0, {"id": "default", "name": "Default", "slug": "default", "netbox_id": None, "description": ""})
        return {"tenants": tenant_list}

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

            hub.state.update_tenant(tenant_id, config)

            if config.get("active"):
                hub.state.set_active_tenant(tenant_id)

            hub.state.save_state()

            return {"status": "ok", "message": f"Tenant {tenant_id} updated."}
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid request: {str(e)}")

    @app.post("/setup/generate-secret")
    async def generate_secret(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            secret = hub.key_manager.generate_first_secret(spoke_id)
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
            return {"status": "ok", "message": f"User {user_id} removed from tenant {tenant_id}"}
        except HTTPException:
            raise  # 400 must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("remove_user_tenant failed")
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
            # write so the WebUI "System Admin" checkbox and _is_admin() never
            # diverge — a role-only admin would otherwise show unchecked and an
            # edit could drop the role, silently demoting the user.
            _p = permissions or {}
            if _p.get("admin") or _p.get("role") == "admin":
                permissions = {**_p, "admin": True, "role": "admin"}

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
            if tenant_id:
                entry.setdefault("tenants", [])
                if tenant_id not in entry["tenants"]:
                    entry["tenants"].append(tenant_id)
            users[user_id] = entry
            hub.state.save_state()

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
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("set_user_password failed")
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
            # Only persist recognised right-keys (+ admin) so a group can't smuggle
            # an arbitrary/unknown flag into a user's effective permissions.
            raw_perms = data.get("permissions", {}) or {}
            allowed = set(ENFORCED_RIGHTS) | {"admin"}
            perms = {k: True for k, v in raw_perms.items() if v and k in allowed}
            if perms.get("admin"):
                perms["role"] = "admin"
            groups[group_id] = {
                **existing,
                "name": name or existing.get("name", group_id),
                "description": data.get("description", existing.get("description", "")),
                "permissions": perms,
                "ldap_group": (data.get("ldap_group") or existing.get("ldap_group", "")).strip(),
                "updated_at": time.time(),
            }
            hub.state.save_state()
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
            for u in users.values():
                if group_id in (u.get("groups", []) or []):
                    u["groups"] = [g for g in u["groups"] if g != group_id]
            del groups[group_id]
            hub.state.save_state()
            return {"status": "ok"}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("delete_group failed")
            raise HTTPException(status_code=500, detail=str(e))
