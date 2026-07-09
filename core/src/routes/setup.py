"""Hub Setup routes: spokes, sync loops, module configs, metadata."""
from api import (
    HTTPException, Request, _hub_msg, logger, time,
)


def register(app, hub, ctx):
    """Register setup routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    @app.get("/setup/spoke-hosts")
    async def get_spoke_hosts():
        """Return the remote IP for each connected spoke, keyed by module_type.
        Used by the WebUI to auto-populate service URL fields."""
        hub = app.state.hub
        result = {}
        for spoke_id, telemetry in hub.spoke_telemetry.items():
            ip = telemetry.get("remote_ip")
            if not ip:
                continue
            module_type = hub.spoke_module_types.get(spoke_id)
            if module_type:
                result[module_type] = {"ip": ip, "spoke_id": spoke_id}
        return {"hosts": result}

    @app.post("/setup/hub-backlog/purge")
    async def purge_hub_backlog(request: Request):
        """Diag (System → Hub Status 'Drop Backlog'): drop the hub's outbound
        message backlog — all, or only ``?type=SPOKE_UPDATE`` — from both
        pending_ack and the per-spoke offline queues. For clearing a backlog
        that won't drain (e.g. undeliverable SPOKE_UPDATE to a flapping spoke)
        without deleting/re-approving the spoke. Admin only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        msg_type = request.query_params.get("type") or None
        before = hub.mailbox.backlog_stats().get("total", 0)
        dropped = await hub.mailbox.purge_all(msg_type=msg_type)
        logger.warning("[diag] Hub backlog purge by %s: dropped %d%s (was %d)",
                       (sess.get("username") if isinstance(sess, dict) else "?"),
                       dropped, f" of type {msg_type}" if msg_type else "", before)
        return {"dropped": dropped, "type": msg_type or "all",
                "backlog": hub.mailbox.backlog_stats()}

    @app.post("/setup/rate-limit-drops/reset")
    async def reset_rate_limit_drops(request: Request):
        """Reset the per-spoke rate-limit drop counters (in-memory running totals
        shown in System → Hub Status). Otherwise they only reset on a hub
        restart. Admin only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        n = len(getattr(hub, "rate_limit_drops", {}) or {})
        try:
            hub.rate_limit_drops.clear()
        except Exception:  # noqa: BLE001
            hub.rate_limit_drops = {}
        logger.info("[diag] rate-limit drop counters reset (%d spoke(s)) by %s", n,
                    (sess.get("username") if isinstance(sess, dict) else "?"))
        return {"status": "ok", "cleared_spokes": n}

    @app.get("/status")
    async def get_status():
        hub = app.state.hub
        if not getattr(hub, "is_ready", False):
            raise HTTPException(status_code=503, detail="Hub is not yet ready (WebSocket server starting)")
        metrics = await hub.get_system_metrics()
        return {
            "active_connections": list(hub.active_connections.keys()),
            "spoke_module_types": dict(hub.spoke_module_types),
            "heartbeats": {sid: str(s) for sid, s in hub.heartbeat.get_all_statuses().items()},
            # Out-of-contact alerts (SpokeAlertMixin) — drives the WebUI header
            # badge (count + list) off the already-polled /status fetch.
            "active_alert_count": len(getattr(hub, "_spoke_alerts", {}) or {}),
            "active_alerts": hub.get_active_spoke_alerts(),
            "state": hub.state.system_state,
            "metrics": metrics
        }


    @app.get("/vm/{vm_id}/firewall")
    async def get_vm_firewall(vm_id: str):
        hub = app.state.hub

        # 1. Find the IP for this VM from the state manager
        res_info = hub.state.system_state.get("resources", {}).get(vm_id, {})
        ip = res_info.get("metadata", {}).get("ip")

        if not ip:
            raise HTTPException(status_code=404, detail=f"No IP address found for VM {vm_id}")

        # 2. Identify the OPNsense spoke
        opn_spoke = hub.get_spoke_by_type("firewall")

        if not opn_spoke:
            raise HTTPException(status_code=503, detail="No OPNsense spoke connected")

        # 3. Use the async bridge to request rules from the spoke
        try:
            result = await hub.request_response(opn_spoke, "OPNSENSE_GET_RULES_BY_IP", {"ip": ip})
            return result.get("payload", {}).get("data", {}) if isinstance(result, dict) else result
        except Exception as e:
            logger.exception("get_vm_firewall failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Setup: spoke approval / secrets / agents (/setup/spokes/*) ───────────
    @app.post("/setup/spokes/{spoke_id}/reset-secret")
    async def reset_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            hub.key_manager.delete_spoke_key(spoke_id)
            # Drop any queued/pending messages for this spoke — without its key
            # they can no longer be signed and would retry against the keyless
            # spoke (log flood). Re-onboarding generates a fresh key + pushes.
            await hub.mailbox.clear_spoke(spoke_id)
            return {"status": "ok", "message": f"Secret for spoke {spoke_id} has been reset. It can now be re-onboarded."}
        except Exception as e:
            logger.exception("reset_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.delete("/setup/spokes/{spoke_id}")
    async def delete_spoke(spoke_id: str):
        """Permanently remove a spoke/generic-agent registration.

        Closes the live WebSocket if the spoke is currently connected (the
        disconnect handler then clears active_connections / spoke_module_types /
        spoke_telemetry), drops the in-memory approval mirror, removes the
        persisted registration + metadata, and wipes the crypto material
        (current key + history). The spoke must fully re-onboard to return.
        """
        hub = app.state.hub
        try:
            ws = hub.active_connections.get(spoke_id)
            if ws is not None:
                try:
                    await ws.close(code=1008, reason="Removed by admin")
                except Exception as e:
                    logger.warning(f"Could not close live WS for {spoke_id} during delete: {e}")
            hub.approved_modules.pop(spoke_id, None)
            hub.state.remove_module(spoke_id)
            hub.key_manager.delete_spoke_key(spoke_id)
            # Drop queued/pending messages for the deleted spoke — its key is
            # gone, so they can no longer be signed and would retry against the
            # keyless spoke (log flood). The spoke must fully re-onboard to
            # return, at which point new messages get a fresh key.
            await hub.mailbox.clear_spoke(spoke_id)
            # Drop per-spoke runtime caches (simulations_cache, telemetry,
            # rate_limiters, events, recovery, agent_logs). The disconnect
            # handler only clears active_connections/spoke_module_types, so
            # without this the per-spoke dicts grow unbounded as admins
            # delete/recreate spokes over time. Safe to evict on permanent
            # delete (unlike a transient disconnect, which needs telemetry
            # for the WebUI's DISCONNECTED status + recovery for the watchdog).
            hub._evict_spoke(spoke_id)
            return {"status": "ok", "message": f"Spoke '{spoke_id}' removed."}
        except Exception as e:
            logger.exception("delete_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/purge-prefix")
    async def purge_spokes_prefix(request: Request):
        """Bulk-remove every spoke/agent whose id starts with a prefix (default
        'loadtest-'), running the same teardown as DELETE /setup/spokes/{id} for
        each. For cleaning up synthetic load-test spokes in one shot / resetting
        between runs. Admin only."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        prefix = (request.query_params.get("prefix") or "loadtest-").strip()
        if not prefix:
            raise HTTPException(status_code=400, detail="prefix required")

        def _mid(m):
            if isinstance(m, str):
                return m
            if isinstance(m, dict):
                return m.get("id") or m.get("spoke_id")
            return None

        targets = set()
        for m in list(hub.state.system_state.get("known_modules", []) or []):
            mid = _mid(m)
            if mid and mid.startswith(prefix):
                targets.add(mid)
        # Catch anything connected/approved not yet mirrored into known_modules.
        for mid in list(hub.approved_modules) + list(getattr(hub, "active_connections", {})):
            if isinstance(mid, str) and mid.startswith(prefix):
                targets.add(mid)

        removed = 0
        for spoke_id in sorted(targets):
            try:
                ws = hub.active_connections.get(spoke_id)
                if ws is not None:
                    try:
                        await ws.close(code=1008, reason="load-test purge")
                    except Exception:
                        pass
                hub.approved_modules.pop(spoke_id, None)
                hub.state.remove_module(spoke_id)
                hub.key_manager.delete_spoke_key(spoke_id)
                await hub.mailbox.clear_spoke(spoke_id)
                hub._evict_spoke(spoke_id)
                removed += 1
            except Exception as e:  # noqa: BLE001 — best-effort per spoke
                logger.warning("purge_spokes_prefix: %s failed: %s", spoke_id, e)
        logger.warning("[diag] purged %d spoke(s) with prefix '%s' by %s",
                       removed, prefix,
                       (sess.get("username") if isinstance(sess, dict) else "?"))
        return {"status": "ok", "removed": removed, "prefix": prefix}

    @app.post("/setup/spokes/{spoke_id}/rotate-secret")
    async def rotate_spoke_secret(spoke_id: str):
        hub = app.state.hub
        try:
            new_key = hub.key_manager.rotate_key(spoke_id)
            return {"status": "ok", "new_secret": new_key.secret}
        except Exception as e:
            logger.exception("rotate_spoke_secret failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spokes/{spoke_id}/ack-change")
    async def ack_identity_change(spoke_id: str):
        """Dismiss the amber "renamed" banner for a spoke/agent.

        Stamps ``change_acked_ts`` into module_metadata so ``_identity_change_for``
        stops surfencing the latest identity_changed/hostname_changed/reimaged
        event until a newer one arrives. Idempotent.
        """
        hub = app.state.hub
        try:
            hub.state.update_module_metadata(
                spoke_id, {"change_acked_ts": time.time()}
            )
            hub.state.save_state()
            return {"status": "ok", "spoke_id": spoke_id}
        except Exception as e:
            logger.exception("ack_identity_change failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/rotate-key/{spoke_id}")
    async def rotate_key_live(spoke_id: str):
        """
        Generate a new spoke secret and push it to the live spoke in a single call.

        Flow:
          1. Hub generates new secret via key_manager.rotate_key()
          2. Hub sends SPOKE_UPDATE_SESSION_KEY to the spoke over the live WS
          3. Spoke updates self.secret + self.signer, persists to .env, acks
          4. Hub returns the new secret (store it securely; the old one is invalidated)

        If the spoke is not currently connected, the new key is stored and the spoke
        will use it on its next connection (key_manager accepts the new key from then on).
        """
        hub = app.state.hub
        try:
            # Capture the secret the spoke currently holds BEFORE rotating, so
            # the key-delivery push is signed with it — the spoke can't verify a
            # frame signed with the new secret it hasn't installed yet.
            prev_secret = hub.key_manager.current_session_secret(spoke_id)
            new_key = hub.key_manager.rotate_key(spoke_id)
            new_secret = new_key.secret

            spoke_conn = hub.active_connections.get(spoke_id)
            if spoke_conn:
                try:
                    result = await hub.request_response(
                        spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": new_secret},
                        signing_secret=prev_secret,
                    )
                    pushed = result.get("status") == "SUCCESS"
                except Exception as push_err:
                    logger.warning(f"Could not push new key to spoke {spoke_id}: {push_err}")
                    pushed = False
            else:
                pushed = False

            return {
                "status":    "ok",
                "spoke_id":  spoke_id,
                "pushed":    pushed,
                "message":   ("New key pushed to live spoke and persisted." if pushed
                               else "New key stored. Spoke will pick it up on next connect."),
            }
        except Exception as e:
            logger.exception("rotate_key_live failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spokes/{spoke_id}/agents")
    async def get_spoke_agents(spoke_id: str):
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        agents = [sid for sid in known_spokes if sid != spoke_id]
        return {"spoke_id": spoke_id, "agents": agents}

    @app.post("/setup/spokes/{spoke_id}/agents/{agent_id}/approve")
    async def approve_agent_under_spoke(spoke_id: str, agent_id: str):
        hub = app.state.hub
        try:
            # A Proxmox node agent connects THROUGH the pxmx hypervisor spoke,
            # not directly to the hub, so it must NOT be registered as a
            # hub-direct spoke (known_modules). Doing so made /setup/diagnostics
            # render a bogus OFFLINE spoke row for it — the hub has no
            # WebSocket for the agent, so get_diagnostics() emitted
            # connection_state="OFFLINE"/authenticated=False even though the
            # agent was genuinely connected (its real state lives in the
            # spoke's GET_AGENTS response, shown in the Agents table). Persist
            # the approval flag only, and clean up any prior leak so an
            # already-registered agent stops showing as an offline spoke.
            hub.approved_modules[agent_id] = True
            approved_map = hub.state.system_state.setdefault("approved_modules", {})
            approved_map[agent_id] = True
            known = hub.state.system_state.get("known_modules", [])
            if agent_id in known:
                known.remove(agent_id)
            hub.state.save_state()

            # Resolve the spoke that actually owns this agent rather than
            # trusting the path's spoke_id blindly — the WebUI's approve
            # button doesn't always know which spoke a given agent is
            # connected through (a cs-dialed agent in the split-topology case
            # is not on the pxmx spoke), so a caller-supplied wrong spoke_id
            # would silently no-op (relay sent to a spoke that has never
            # heard of this agent_id, leaving it pending forever). Falls back
            # to the path param when agent_info has no entry yet (e.g.
            # approving before the first relayed frame has arrived).
            target_spoke = hub.get_spoke_for_agent(agent_id, fallback_hypervisor=False) or spoke_id

            # Inherit the parent spoke's tenant binding (Setup → Spokes &
            # Agents' "Tenant" button / Simulations → Spoke Management) so an
            # agent connecting to a tenant-bound spoke is assigned to that
            # tenant automatically — no per-agent config needed. Only seeds
            # when the agent has no explicit tenant of its own yet (an
            # existing override, e.g. set via the Agent Configuration modal,
            # is left alone) and the spoke actually has a tenant to inherit.
            spoke_tenant = hub.state.get_spoke_tenant(target_spoke)
            if spoke_tenant:
                agent_cfg_store = hub.state.system_state.setdefault("agent_config", {})
                entry = dict(agent_cfg_store.get(agent_id, {}))
                cs_cfg = dict(entry.get("client_simulation") or {})
                if not cs_cfg.get("tenant_id"):
                    cs_cfg["tenant_id"] = spoke_tenant
                    entry["client_simulation"] = cs_cfg
                    agent_cfg_store[agent_id] = entry
                    hub.state.save_state()

            if target_spoke in hub.active_connections:
                msg = _hub_msg(target_spoke, "SPOKE_RELAY", {
                    "target_agent_id": agent_id,
                    "command": "APPROVAL_SUCCESS",
                    "payload": {}
                })
                await hub.send_to_spoke(msg)

            return {"status": "ok", "message": f"Agent {agent_id} approved under spoke {target_spoke}"}
        except Exception as e:
            logger.exception("approve_agent_under_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/pending_spokes")
    async def get_all_spokes_status():
        hub = app.state.hub
        known_spokes = hub.state.system_state.get("known_modules", [])
        module_names = hub.state.system_state.get("module_names", {})

        # module_type is held in the live spoke_module_types dict, which is
        # popped on disconnect (main.py disconnect handler) — so an offline
        # spoke reports None and the WebUI can't show its module. Fall back to
        # the spoke_id prefix so the Setup tile still labels offline spokes
        # (opn/cppm/cs/etc.) with their module instead of "—".
        _PREFIX_MODULE = {
            "pxmx": "hypervisor", "opn": "firewall", "cppm": "nac",
            "cs": "simulation", "netbox": "ipam", "ldap": "directory",
            "dns": "dns", "dhcp": "dhcp", "nw": "nw",
        }

        def _module_type_for(sid: str):
            # Live registration wins; then the module_type we PERSISTED at
            # registration (module_metadata[sid].module_type, written in main.py
            # on connect) so an OFFLINE spoke/agent keeps its true type; then a
            # spoke_id-prefix fallback for legacy dedicated ids. The persisted
            # read is what lets a disconnected generic agent (module_type
            # "agent") or a role sub-spoke "{base}-{role}" keep its category
            # instead of falling through to "—" or a wrong prefix guess.
            mt = hub.spoke_module_types.get(sid)
            if mt:
                return mt
            meta = (hub.state.system_state.get("module_metadata", {}) or {}).get(sid, {}) or {}
            if meta.get("module_type"):
                return meta["module_type"]
            for prefix, fallback in _PREFIX_MODULE.items():
                if sid == prefix or sid.startswith(prefix + "-"):
                    return fallback
            return None

        spokes_status = []
        module_metadata = hub.state.system_state.get("module_metadata", {})
        for sid in known_spokes:
            meta = module_metadata.get(sid, {}) or {}
            spokes_status.append({
                "spoke_id": sid,
                "display_name": module_names.get(sid, sid),
                "approved": hub.approved_modules.get(sid, False),
                "module_type": _module_type_for(sid),
                # Install-UUID identity tracking: current OS hostname + the latest
                # unacknowledged rename/hostname-change event (for the UI banner).
                "hostname": meta.get("hostname", ""),
                "install_uuid": meta.get("install_uuid", ""),
                "identity_change": _identity_change_for(hub, sid, meta),
                "tenant_id": hub.state.get_spoke_tenant(sid) or "",
            })

        return {"spokes": spokes_status}

    def _identity_change_for(hub, sid: str, meta: dict):
        """Latest unacknowledged identity_changed/hostname_changed event for a spoke.

        Returns ``None`` when there is no such event newer than the last ack ts
        (``module_metadata[sid]["change_acked_ts"]``), so the WebUI only shows the
        amber "renamed" banner until an admin dismisses it. Mirrored for agents
        via the parent spoke's event timeline.
        """
        acked_ts = float(meta.get("change_acked_ts") or 0.0)
        for ev in hub.get_spoke_events(sid, limit=20):
            if ev.get("event") in ("identity_changed", "hostname_changed", "reimaged"):
                if ev.get("ts", 0) > acked_ts:
                    return ev
        return None

    @app.post("/setup/approve_spoke")
    async def approve_spoke(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            action = data.get("action", "approve")

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            if action == "unapprove":
                hub.state.register_module(spoke_id, approved=False)
                hub.approved_modules[spoke_id] = False
                # An un-approved spoke's session key is no longer valid for
                # outbound commands; drop queued messages so they don't retry
                # against it. Re-approval generates a fresh key + pushes.
                await hub.mailbox.clear_spoke(spoke_id)
            else:
                hub.state.register_module(spoke_id, approved=True)
                hub.approved_modules[spoke_id] = True

            # Spoke→tenant binding (admin assigns at approval time). Omitting
            # tenant_id leaves any existing binding untouched.
            tenant_id = data.get("tenant_id")
            if tenant_id is not None:
                hub.state.set_spoke_tenant(spoke_id, tenant_id)

            hub.state.save_state()

            if spoke_id in hub.active_connections:
                if action != "unapprove":
                    # Generate a session secret for the spoke (idempotent — reuses existing key if present).
                    # Sign the key-delivery push with the secret the spoke currently holds (None = pending,
                    # it accepts anyway) so it can verify and install the new secret.
                    prev_secret = hub.key_manager.current_session_secret(spoke_id)
                    session_secret = hub.key_manager.generate_first_secret(spoke_id)
                    key_msg = _hub_msg(spoke_id, "SPOKE_UPDATE_SESSION_KEY", {"secret": session_secret})
                    await hub.send_to_spoke(key_msg, signing_secret=prev_secret)

                msg_type = "APPROVED" if action != "unapprove" else "DENIED"
                approval_msg = _hub_msg(spoke_id, msg_type, {})
                await hub.send_to_spoke(approval_msg)

                if action != "unapprove":
                    await hub.push_config_to_spoke(spoke_id)
                    # Query the spoke's version now that it's approved + keyed,
                    # so a spoke approved AFTER connecting (not via PSK
                    # self-provision) still reports a version on the
                    # Diagnostics page without reconnecting. Mirrors the
                    # connect-time get_version in main.py. Best-effort.
                    try:
                        await hub.send_to_spoke(_hub_msg(spoke_id, "get_version", {}))
                    except Exception as e:
                        logger.error(f"Failed to request version from {spoke_id}: {e}")

            return {"status": "ok", "message": f"Spoke {spoke_id} {'approved' if action != 'unapprove' else 'un-approved'}."}
        except HTTPException:
            raise  # 4xx must propagate as-is, not be re-wrapped as 500
        except Exception as e:
            logger.exception("approve_spoke failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── Product config pairs: cppm/pxmx/ldap/dns/dhcp (/setup/*-config) ───────
    @app.get("/setup/cppm-config")
    async def get_cppm_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("cppm", {})
        return {"config": config}

    @app.post("/setup/cppm-config")
    async def update_cppm_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["cppm"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            cppm_spoke = hub.get_spoke_by_type("nac")
            if cppm_spoke:
                msg = _hub_msg(cppm_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but CPPM spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_cppm_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    # ── NetBox → CPPM endpoint sync (hub-orchestrated) ──────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup →
    # Security/NAC "NetBox → ClearPass Endpoint Sync" card. Config (enabled /
    # mode / interval_seconds / daily_time) is stored under
    # global_config["netbox_cppm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_endpoint_sync_loop) reads that same key.

    @app.post("/setup/endpoint-sync/run")
    async def run_endpoint_sync(request: Request):
        """On-demand NetBox → CPPM endpoint sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant; absent →
        all tenants bound to NetBox. Returns per-tenant results + a summary.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_endpoints(target)]
        else:
            results = [await hub.sync_tenant_endpoints(tid)
                       for tid in hub._endpoint_sync_tenants()]
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "tenants": len(results)}}

    @app.get("/setup/endpoint-sync/status")
    async def endpoint_sync_status(request: Request):
        """Per-tenant last-sync status for the Setup → Security/NAC card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_endpoint_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "message": st.get("message", ""),
                "endpoints_total": st.get("endpoints_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
                "skipped_details": st.get("skipped_details", []),
            })
        return {"tenants": tenants}

    @app.get("/setup/endpoint-sync/sources")
    async def endpoint_sync_sources(request: Request):
        """List the available IPAM pull-sources for the sync source selector.

        Driven by Hub.IPAM_SOURCES so adding a product is a one-entry registry
        change and the WebUI dropdown picks it up with no client change.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._endpoint_sync_source().get("module_type")
        sources = []
        for name, se in hub.IPAM_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        return {"active": active, "sources": sources}

    # ── Hypervisor → NetBox VM sync (hub-orchestrated) ───────────────────────
    # On-demand trigger + per-tenant last-sync status for the Setup → IPAM
    # "Hypervisor → NetBox VM Sync" card. Config (enabled / mode /
    # interval_seconds / daily_time) is stored under
    # global_config["pxmx_netbox_vm_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_vm_sync_loop) reads that same key.

    @app.post("/setup/vm-sync/run")
    async def run_vm_sync(request: Request):
        """On-demand Hypervisor → NetBox VM sync ('Sync now').

        The sync is cluster-wide (one grab-all pull + one NetBox push); a body
        ``{"tenant_id": "<id>"}`` just selects which per-tenant row to return
        (the pull still grabs everything so the NetBox mirror stays complete).
        Absent → returns every per-tenant row + an unassigned row. Returns
        per-tenant results + a summary.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_vms(target)]
        else:
            agg = await hub.sync_all_vms()
            results = agg.get("results", []) or []
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors,
                            "deleted": deleted, "tenants": len(results)}}

    @app.get("/setup/vm-sync/status")
    async def vm_sync_status(request: Request):
        """Per-tenant last-VM-sync status for the Setup → IPAM card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_vm_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "vms_total": st.get("vms_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/vm-sync/sources")
    async def vm_sync_sources(request: Request):
        """List the available hypervisor pull-sources for the sync source selector.

        Driven by Hub.HYPERVISOR_SOURCES so adding a product is a one-entry
        registry change and the WebUI dropdown picks it up with no client change.
        Also returns the connected pxmx agents (the actual Proxmox servers /
        clusters the sync can be scoped to) so the UI can list them and let the
        admin pick one instead of just the generic source type.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._vm_sync_source().get("module_type")
        sources = []
        for name, se in hub.HYPERVISOR_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_spoke_by_type(se.get("module_type", "")))})
        # Connected pxmx agents — the real servers the sync pulls from. Empty
        # when the hypervisor spoke is down (sources[*].connected already flags
        # that; agents just enriches with the per-server detail).
        agents: list = []
        pxmx_spoke = hub.get_hypervisor_spoke()
        if pxmx_spoke:
            try:
                r = await hub.request_response(pxmx_spoke, "GET_AGENTS", {}, timeout=15.0)
                d = r.get("payload", {}).get("data", r) if isinstance(r, dict) else r
                for a in (d or {}).get("agents", []) if isinstance(d, dict) else []:
                    agents.append({
                        "agent_id":   a.get("agent_id", ""),
                        "hostname":   a.get("hostname", ""),
                        "cluster":    a.get("cluster_name", "") or a.get("hostname", ""),
                        "nodes":      a.get("nodes", []) or [],
                        "vm_count":   a.get("vm_count", 0) or 0,
                        "status":     a.get("status", "connected"),
                    })
            except Exception as e:
                logger.debug("vm_sync_sources: GET_AGENTS failed: %s", e)
        return {"active": active, "sources": sources, "agents": agents}

    # ── Firewall → NetBox device-discovery sync (Setup → Sync) ──
    # global_config["opnsense_netbox_device_sync"] and saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_fw_discovery_sync_loop) reads that same key.

    @app.post("/setup/fw-discovery-sync/run")
    async def run_fw_discovery_sync(request: Request):
        """On-demand Firewall → NetBox device-discovery sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/deleted/
        skipped/dropped_unattributed/discovered_total).
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_devices(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            discovered = int(results[0].get("discovered_total_global", 0) or 0)
        else:
            agg = await hub.run_fw_discovery_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            discovered = int(agg.get("discovered_total", 0) or 0)
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped, "discovered_total": discovered}}

    @app.get("/setup/fw-discovery-sync/status")
    async def fw_discovery_sync_status(request: Request):
        """Per-tenant last firewall-discovery-sync status for the Setup → Sync card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_fw_discovery_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "discovered_total": st.get("discovered_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/fw-discovery-sync/sources")
    async def fw_discovery_sync_sources(request: Request):
        """List the available firewall pull-sources + the firewalls the sync can
        be scoped to, for the Setup → Sync source selector + firewall picker.

        Driven by Hub.FIREWALL_DISCOVERY_SOURCES so adding a product is a
        one-entry registry change and the WebUI dropdown picks it up with no
        client change. ``firewalls`` come from global_config["firewalls"]
        (each → {id, name, spoke_id, connected}) so the admin can pin the sync
        to one firewall. ``netbox_connected`` flags whether the sink is up.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._fw_discovery_source().get("module_type")
        sources = []
        for name, se in hub.FIREWALL_DISCOVERY_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_all_spokes_by_type(se.get("module_type", "")))})
        firewalls = []
        for fw in hub.state.system_state.get("global_config", {}).get("firewalls", []) or []:
            sid = fw.get("spoke_id") if isinstance(fw, dict) else None
            firewalls.append({
                "id": fw.get("id", "") if isinstance(fw, dict) else "",
                "name": fw.get("name", fw.get("id", "")) if isinstance(fw, dict) else "",
                "spoke_id": sid or "",
                "connected": bool(sid and sid in getattr(hub, "active_connections", {})),
            })
        return {"active": active, "sources": sources, "firewalls": firewalls,
                "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    # ── Realtime NAC → IPAM reverse sync (Setup → Sync, "IPAM ↔ NAC Sync" card) ─
    # The bidirectional counterpart to the forward endpoint-sync routes above.
    # Pulls recent ClearPass Access Tracker sessions from the CPPM (NAC) spoke
    # and adds the MACs NetBox is missing (only-add-missing). See
    # RealtimeIpamNacSyncMixin (core/src/realtime_ipam_nac_sync.py). Config
    # toggle persists via POST /setup/config into
    # global_config["realtime_ipam_nac_sync"].
    @app.post("/setup/realtime-nac-sync/run")
    async def run_realtime_nac_sync(request: Request):
        """On-demand realtime NAC → IPAM reverse sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/skipped/
        deleted/dropped_unattributed/sessions_total).
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_realtime(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            sessions_total = int(results[0].get("sessions_total_global", 0) or 0)
        else:
            agg = await hub.run_realtime_nac_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            sessions_total = int(agg.get("sessions_total", 0) or 0)
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped,
                            "sessions_total": sessions_total}}

    @app.get("/setup/realtime-nac-sync/status")
    async def realtime_nac_sync_status(request: Request):
        """Per-tenant last realtime-NAC-sync status for the Setup → Sync card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_realtime_nac_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "sessions_total": st.get("sessions_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/realtime-nac-sync/sources")
    async def realtime_nac_sync_sources(request: Request):
        """Connection state for the realtime reverse-sync card: whether the NAC
        (CPPM) pull source and the IPAM (netbox) push sink are connected."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return {"nac_connected": bool(hub.get_spoke_by_type("nac")),
                "ipam_connected": bool(hub.get_spoke_by_type("ipam"))}

    # ── NetBox staleness sweep (Setup → Sync, cluster-wide) ──────────────
    # global_config["staleness_sweep"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_staleness_sweep_loop) reads that same key.
    @app.post("/setup/staleness-sweep/run")
    async def run_staleness_sweep(request: Request):
        """On-demand NetBox staleness sweep ('Sweep now').

        Runs one cluster-wide sweep on the IPAM (netbox) spoke: devices/VMs not
        seen for ``stale_days`` → offline + decommissioned_at; offline + aged past
        ``delete_days`` → deleted (IPs free automatically); unassigned stale IPs →
        freed. Returns the spoke's result + a summary.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        result = await hub.run_staleness_sweep_all()
        return {"result": result,
                "summary": {"scanned": result.get("scanned", 0),
                            "decommissioned": result.get("decommissioned", 0),
                            "deleted": result.get("deleted", 0),
                            "ip_freed": result.get("ip_freed", 0),
                            "errors": result.get("errors", 0),
                            "status": result.get("status")}}

    @app.get("/setup/staleness-sweep/status")
    async def staleness_sweep_status(request: Request):
        """Last cluster-wide staleness-sweep status for the Setup → Sync card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return await hub.simulations_store.get_staleness_sweep_status()

    # ── GitHub repo sync (Setup → Sync, replaces the old autoupdate loop) ───
    # global_config["repo_sync"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_repo_sync_loop) reads that same key.
    @app.post("/setup/repo-sync/run")
    async def run_repo_sync(request: Request):
        """On-demand GitHub repo sync ('Sync now').

        Pulls each hub-local ``provisioning_repos/*`` git repo, then runs the
        version-gated hub pull + ``SPOKE_UPDATE`` fan-out to every approved
        spoke (``perform_update``). The hub self-restarts only when its own
        code changed; spokes self-pull and restart on their own version change.
        Returns the per-repo results + the hub update result.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        result = await hub.run_repo_sync_all()
        prov = result.get("provisioning_repos", []) or []
        return {"result": result,
                "summary": {"status": (result.get("hub") or {}).get("status"),
                            "provisioning_repos": len(prov),
                            "provisioning_repos_ok":
                                sum(1 for r in prov if r.get("status") == "ok"),
                            "provisioning_repos_error":
                                sum(1 for r in prov if r.get("status") == "error"),
                            "message": result.get("message")}}

    @app.get("/setup/repo-sync/status")
    async def repo_sync_status(request: Request):
        """Last GitHub repo-sync status for the Setup → Sync card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return await hub.simulations_store.get_repo_sync_status()

    # ── Spoke out-of-contact alerts (Setup → Sync) ───────────────────────
    # global_config["spoke_alert"] is saved via the generic POST /setup/config
    # shallow-merge — no dedicated config route needed. The background loop
    # (main.py run_spoke_alert_loop) reads that same key. This route exposes the
    # live active-alert list for the Sync sub-block; /status also carries the
    # count + list for the header badge (no extra polling).
    @app.get("/setup/spoke-alerts")
    async def spoke_alerts(request: Request):
        """Active spoke out-of-contact alerts (warning/error tiers) for the
        Setup → Sync card. Each entry: {spoke_id, tier, since_ts, duration_s,
        detail}."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        return {"active_alerts": hub.get_active_spoke_alerts()}

    # ── Network Devices → NetBox device-discovery sync (Setup → Sync) ──
    # global_config["nw_netbox_device_sync"] is saved via the generic POST
    # /setup/config shallow-merge — no dedicated config route needed. The
    # background loop (main.py run_nw_discovery_sync_loop) reads that same key.
    @app.post("/setup/nw-discovery-sync/run")
    async def run_nw_discovery_sync(request: Request):
        """On-demand Network Devices → NetBox device-discovery sync ('Sync now').

        Body optional: ``{"tenant_id": "<id>"}`` to sync one tenant (pull global,
        push just that tenant); absent → pull global, push every attributed
        tenant. Returns per-tenant results + a summary (pushed/errors/skipped/
        deleted/dropped_unattributed/discovered_total).
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        target = (data or {}).get("tenant_id") if isinstance(data, dict) else None
        if target:
            results = [await hub.sync_tenant_nw_devices(target)]
            dropped = int(results[0].get("dropped_unattributed", 0) or 0)
            discovered = int(results[0].get("discovered_total_global", 0) or 0)
        else:
            agg = await hub.run_nw_discovery_sync_all()
            results = agg.get("results", [])
            dropped = int(agg.get("dropped_unattributed", 0) or 0)
            discovered = int(agg.get("discovered_total", 0) or 0)
        pushed = sum(int(r.get("pushed", 0)) for r in results)
        errors = sum(int(r.get("errors", 0)) for r in results)
        skipped = sum(int(r.get("skipped", 0)) for r in results)
        deleted = sum(int(r.get("deleted", 0)) for r in results)
        return {"results": results,
                "summary": {"pushed": pushed, "errors": errors, "skipped": skipped,
                            "deleted": deleted, "tenants": len(results),
                            "dropped_unattributed": dropped,
                            "discovered_total": discovered}}

    @app.get("/setup/nw-discovery-sync/status")
    async def nw_discovery_sync_status(request: Request):
        """Per-tenant last nw-discovery-sync status for the Setup → Sync card."""
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        statuses = hub.simulations_store.get_all_nw_discovery_sync_status()
        tenants = []
        for tid, st in statuses.items():
            tenants.append({
                "tenant_id": tid,
                "tenant_name": st.get("tenant_name") or tid,
                "status": st.get("status"),
                "pushed": st.get("pushed", 0),
                "errors": st.get("errors", 0),
                "skipped": st.get("skipped", 0),
                "deleted": st.get("deleted", 0),
                "message": st.get("message", ""),
                "discovered_total": st.get("discovered_total", 0),
                "last_sync_ts": st.get("last_sync_ts"),
            })
        return {"tenants": tenants}

    @app.get("/setup/nw-discovery-sync/sources")
    async def nw_discovery_sync_sources(request: Request):
        """Available nw pull-sources + the network devices the sync can be scoped
        to, for the Setup → Sync source selector + device picker.

        Driven by ``hub.NW_DISCOVERY_SOURCES`` so adding a network-device product
        is a one-entry registry change and the WebUI dropdown picks it up with no
        client change. ``devices`` come from ``global_config["nw_devices"]``
        (each → {id, name, spoke_id, connected}) so the admin can pin the sync.
        ``netbox_connected`` flags whether the IPAM sink is up.
        """
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        active = hub._nw_discovery_source().get("module_type")
        sources = []
        for name, se in hub.NW_DISCOVERY_SOURCES.items():
            sources.append({"name": name, "label": se.get("label", name),
                            "module_type": se.get("module_type", ""),
                            "connected": bool(hub.get_all_spokes_by_type(se.get("module_type", "")))})
        devices = []
        for d in hub.state.system_state.get("global_config", {}).get("nw_devices", []) or []:
            sid = d.get("spoke_id") if isinstance(d, dict) else None
            devices.append({
                "id": d.get("id", "") if isinstance(d, dict) else "",
                "name": d.get("name", d.get("id", "")) if isinstance(d, dict) else "",
                "spoke_id": sid or "",
                "connected": bool(sid and sid in getattr(hub, "active_connections", {})),
            })
        return {"active": active, "sources": sources, "devices": devices,
                "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    @app.get("/setup/pxmx-config")
    async def get_pxmx_config():
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("pxmx", {
            "default_node": "pve",
            "cluster_id": "cluster-1"
        })
        return {"config": config}

    @app.post("/setup/pxmx-config")
    async def update_pxmx_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            global_config = hub.state.system_state.get("global_config", {})
            global_config["pxmx"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            pxmx_spoke = hub.get_hypervisor_spoke()
            if pxmx_spoke:
                msg = _hub_msg(pxmx_spoke, "update_config", config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "Configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but Proxmox spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_pxmx_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/ldap-config")
    async def get_ldap_config():
        """Return the stored LDAP/directory configuration (global_config.ldap)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("ldap", {})
        return {"config": config}

    @app.post("/setup/ldap-config")
    async def update_ldap_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})

            spoke_config = {
                "LDAP_SERVER_URL": config.get("server_url"),
                "LDAP_BASE_DN": config.get("base_dn"),
                "LDAP_ADMIN_DN": config.get("admin_dn"),
                "LDAP_ADMIN_PW": config.get("admin_pw"),
            }
            spoke_config = {k: v for k, v in spoke_config.items() if v is not None}

            global_config = hub.state.system_state.get("global_config", {})
            global_config["ldap"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()

            ldap_spoke = hub.get_spoke_by_type("directory")
            if ldap_spoke:
                msg = _hub_msg(ldap_spoke, "UPDATE_CONFIG", spoke_config)
                await hub.send_to_spoke(msg)
                return {"status": "ok", "message": "LDAP configuration updated and pushed to spoke.", "pushed": True}
            else:
                return {"status": "partial_success", "message": "Configuration saved, but LDAP spoke is not connected.", "pushed": False}
        except Exception as e:
            logger.exception("update_ldap_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/dns-config")
    async def get_dns_config():
        """Return the stored DNS/Unbound configuration (global_config.dns)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dns", {})
        return {"config": config}

    @app.post("/setup/dns-config")
    async def update_dns_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dns"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            return {"status": "ok"}
        except Exception as e:
            logger.exception("update_dns_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/dhcp-config")
    async def get_dhcp_config():
        """Return the stored DHCP/Kea configuration (global_config.dhcp)."""
        hub = app.state.hub
        config = hub.state.system_state.get("global_config", {}).get("dhcp", {})
        return {"config": config}

    @app.post("/setup/dhcp-config")
    async def update_dhcp_config(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            config = data.get("config", {})
            global_config = hub.state.system_state.get("global_config", {})
            global_config["dhcp"] = config
            hub.state.system_state["global_config"] = global_config
            hub.state.save_state()
            return {"status": "ok"}
        except Exception as e:
            logger.exception("update_dhcp_config failed")
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/setup/spoke-metadata")
    async def update_spoke_metadata(request: Request):
        hub = app.state.hub
        try:
            data = await request.json()
            spoke_id = data.get("spoke_id")
            metadata = data.get("metadata", {})

            if not spoke_id:
                raise HTTPException(status_code=400, detail="Missing spoke_id")

            known_modules = hub.state.system_state.get("known_modules", [])
            if spoke_id not in known_modules:
                raise HTTPException(status_code=404, detail=f"Spoke '{spoke_id}' not found in known_modules: {known_modules}")

            hub.state.update_module_metadata(spoke_id, metadata)
            hub.state.save_state()

            return {"status": "ok", "message": f"Metadata for spoke {spoke_id} updated."}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("Error updating spoke metadata")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/setup/spoke-metadata/{spoke_id}")
    async def get_spoke_metadata(spoke_id: str):
        hub = app.state.hub
        metadata = hub.state.system_state.get("module_metadata", {}).get(spoke_id, {})
        if not metadata:
            raise HTTPException(status_code=404, detail="Spoke metadata not found")
        return {"metadata": metadata}

    @app.get("/setup/firewalls")
    async def get_firewalls():
        hub = app.state.hub
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        return {"firewalls": firewalls}
