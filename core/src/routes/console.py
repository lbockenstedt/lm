"""VNC + serial console relay routes and helpers."""
import os

from api import (
    HTTPException, Request, WebSocket, WebSocketDisconnect, WebSocketState, access, asyncio,
    base64, json, logger, secrets, uuid,
)


def _console_port_disposition(admin: bool, visible: bool, eff: str, sel, shared: bool) -> str:
    """How a console port should be treated for the requesting session.

    Returns one of:
      * ``"show"``  — list the port as-is (full, no masking).
      * ``"mask"``  — SHARED-tenant infra: list only if the device IP falls in
                      the scoping tenant's NetBox prefixes (subnet mask applied
                      by the caller). This is how a shared console server's ports
                      get routed to the right tenant.
      * ``"hide"``  — not visible to this session / selected tenant.

    Inputs mirror the tenant model:
      * ``visible`` — ``access.spoke_visible_to_session(sess, eff)``: admin→all,
        SHARED tenant→everyone, own dedicated tenant→yes, unassigned→admin-only.
      * ``eff``     — the port's effective tenant (per-port override, else the
        agent binding; ``""`` when unassigned). A per-port override is exactly
        how an admin pins ONE device of a shared console server to a tenant.
      * ``sel``     — the SELECTED tenant from the picker (``None`` == the global
        "All" view).
      * ``shared``  — ``access.tenant_is_shared(eff)``.

    Dedicated data belongs wholly to its tenant (exact-match the picker, like
    ``/api/pxmx/agents``); shared data is visible to all but subnet-masked;
    unassigned is an admin-only holding state shown only in the global view.
    """
    if not visible:
        return "hide"
    if not eff:                              # unassigned holding state
        return "show" if (admin and sel is None) else "hide"
    if shared:                               # shared infra → everyone, masked
        return "show" if (admin and sel is None) else "mask"
    if sel is not None and eff != sel:       # dedicated → honor the picker
        return "hide"
    return "show"


def register(app, hub, ctx):
    """Register console routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _resolve_tenant = ctx._resolve_tenant

    @app.websocket("/ws/console/{session_id}")
    async def pxmx_console_ws(websocket: WebSocket, session_id: str):
        """Browser↔Proxmox VNC byte relay (agent-terminates-WSS).

        Auth: the single-use ``ws_token`` query param must match the session
        record minted by ``pxmx_create_console``. Two relay tasks:
        ``browser_to_spoke`` sends raw bytes to the agent as VNC_FRAME_DOWN
        (fire-and-forget); ``spoke_to_browser`` sends queued Proxmox frames
        (VNC_FRAME_UP) to the browser as bytes, and handles control tuples
        (VNC_READY / VNC_ERROR / VNC_DISCONNECT) from _handle_agent_relay_up.
        On any exit, sends VNC_DISCONNECT down so the agent closes the Proxmox
        WSS and drops the session."""
        token = websocket.query_params.get("token") or ""
        hub = app.state.hub
        sess = hub.get_vnc_session(session_id)
        if not sess or sess.get("ws_token") != token:
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired console session")
            return
        spoke_id = sess["spoke_id"]
        queue = sess["queue"]
        await websocket.accept()
        relay_tasks: list = []
        try:
            async def browser_to_spoke():
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        raise WebSocketDisconnect(code=msg.get("code", 1000))
                    raw = msg.get("bytes")
                    if raw is None:
                        text = msg.get("text")
                        if not text:
                            continue
                        raw = text.encode()
                    await hub.send_to_spoke_command(spoke_id, "VNC_FRAME_DOWN", {
                        "session_id": session_id,
                        "data": base64.b64encode(raw).decode(),
                    })

            async def spoke_to_browser():
                while True:
                    item = await queue.get()
                    if isinstance(item, (bytes, bytearray)):
                        await websocket.send_bytes(bytes(item))
                    elif isinstance(item, tuple) and item:
                        kind = item[0]
                        if kind == "error":
                            await websocket.close(code=1011, reason=str(item[1]))
                            return
                        if kind == "disconnect":
                            # Proxmox side closed — close the browser WS so noVNC
                            # surfaces "Disconnected" instead of hanging on a dead
                            # socket waiting for bytes that will never come.
                            await websocket.close(code=1000, reason="console closed")
                            return
                        # kind == "ready": the Proxmox WSS is open and RFB frames
                        # are about to flow. No-op — KEEP the relay loop running so
                        # later VNC_FRAME_UP bytes reach the browser. Returning here
                        # was the bug: it killed the only queue consumer on
                        # VNC_READY, so the RFB handshake never reached the browser
                        # and noVNC timed out → "Disconnected: closed" / blank screen.
                        continue
                    else:
                        return

            relay_tasks = [asyncio.create_task(browser_to_spoke()),
                           asyncio.create_task(spoke_to_browser())]
            done, pending = await asyncio.wait(relay_tasks,
                                               return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                    raise exc
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("console ws %s relay failed: %s", session_id, exc)
        finally:
            hub.unregister_vnc_session(session_id)
            try:
                await hub.send_to_spoke_command(spoke_id, "VNC_DISCONNECT",
                                                {"session_id": session_id})
            except Exception:
                pass
            for task in relay_tasks:
                if not task.done():
                    task.cancel()
            if relay_tasks:
                await asyncio.gather(*relay_tasks, return_exceptions=True)
            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass

    @app.websocket("/ws/console-shell/{session_id}")
    async def pxmx_shell_ws(websocket: WebSocket, session_id: str):
        """Browser↔host-PTY byte relay (agent-terminates-PTY) — the xterm terminal.
        Mirrors /ws/console (VNC): browser keystrokes → SHELL_IN; PTY output
        (SHELL_OUT, queued via _handle_agent_relay_up) → browser bytes. A JSON text
        frame ``{"resize":{"rows","cols"}}`` becomes SHELL_RESIZE. ws_token gated."""
        token = websocket.query_params.get("token") or ""
        hub = app.state.hub
        sess = hub.get_shell_session(session_id)
        if not sess or sess.get("ws_token") != token:
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired shell session")
            return
        spoke_id = sess["spoke_id"]
        queue = sess["queue"]
        sess["connected"] = True
        await websocket.accept()
        relay_tasks: list = []
        try:
            async def browser_to_spoke():
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        raise WebSocketDisconnect(code=msg.get("code", 1000))
                    raw = msg.get("bytes")
                    if raw is None:
                        text = msg.get("text")
                        if not text:
                            continue
                        # A JSON control frame carries a window resize; anything
                        # else is treated as keystroke text.
                        try:
                            ctl = json.loads(text)
                        except Exception:
                            ctl = None
                        if isinstance(ctl, dict) and "resize" in ctl:
                            r = ctl.get("resize") or {}
                            await hub.send_to_spoke_command(spoke_id, "SHELL_RESIZE", {
                                "session_id": session_id,
                                "rows": r.get("rows", 24), "cols": r.get("cols", 80),
                            })
                            continue
                        raw = text.encode()
                    await hub.send_to_spoke_command(spoke_id, "SHELL_IN", {
                        "session_id": session_id,
                        "data": base64.b64encode(raw).decode(),
                    })

            async def spoke_to_browser():
                while True:
                    item = await queue.get()
                    if isinstance(item, (bytes, bytearray)):
                        await websocket.send_bytes(bytes(item))
                    elif isinstance(item, tuple) and item:
                        kind = item[0]
                        if kind == "error":
                            await websocket.close(code=1011, reason=str(item[1]))
                            return
                        if kind == "disconnect":
                            await websocket.close(code=1000, reason="shell closed")
                            return
                        continue  # "ready" — keep draining
                    else:
                        return

            relay_tasks = [asyncio.create_task(browser_to_spoke()),
                           asyncio.create_task(spoke_to_browser())]
            done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                    raise exc
        except WebSocketDisconnect:
            pass
        except Exception as exc:
            logger.warning("shell ws %s relay failed: %s", session_id, exc)
        finally:
            hub.unregister_shell_session(session_id)
            try:
                await hub.send_to_spoke_command(spoke_id, "SHELL_DISCONNECT", {"session_id": session_id})
            except Exception:
                pass
            for task in relay_tasks:
                if not task.done():
                    task.cancel()
            if relay_tasks:
                await asyncio.gather(*relay_tasks, return_exceptions=True)
            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass

    # ── Console role: serial console access (/api/console/*, /ws/console-serial) ──
    def _console_unwrap(result):
        """request_response envelope → the spoke's inner data dict."""
        if isinstance(result, dict):
            return result.get("payload", {}).get("data", result)
        return {}

    def _console_spoke_or_none(hub, body):
        """Target console spoke: explicit spoke_id, else the first connected one."""
        return (body or {}).get("spoke_id") or hub.get_spoke_by_type("console")

    async def _console_tenant_ok(sess, sid, eff, device_ip):
        """Whether a NON-admin session may open/act on a console port — kept
        consistent with the ``/api/console/ports`` listing so a tenant can use
        exactly the ports it can see. Dedicated → the caller's own tenant. SHARED
        → the identified device IP must fall in the caller's tenant prefixes (the
        ``console`` subnet-filter), fail-closed when the tenant has no prefixes or
        the device has no IP. Unassigned / other tenant → no. (Admin bypasses at
        the call site.)"""
        if not access.spoke_visible_to_session(sess, eff):
            return False
        if not access.tenant_is_shared(eff):
            return True                      # dedicated to a tenant the caller owns
        if not access.filter_enabled(hub, "console"):
            return True                      # subnet mask off → shared is open to all
        scope_tid = (sess or {}).get("user", {}).get("tenant_id") or None
        if not scope_tid:
            return False
        try:
            prefixes = await access.resolve_prefixes_for_tenant(hub, scope_tid)
        except Exception:  # noqa: BLE001
            prefixes = []
        if not prefixes:
            return False
        return access.filter_record_by_prefixes({"ip": device_ip}, prefixes, ("ip",)) is not None

    async def _assert_port_tenant(request, sid, port_id):
        """Cross-tenant guard for per-port Console actions (settings, detect-baud,
        identify, config get/push). A non-admin may only act on a port it can see
        in the listing (see :func:`_console_tenant_ok`): dedicated to one of its
        tenants, or a SHARED-tenant device whose IP is in its prefixes. Admin
        bypasses. The port's effective tenant + device IP are resolved from
        CONSOLE_LIST_PORTS (best-effort: a fetch failure falls back to the
        agent's whole-agent tenant, fail-closed if that isn't accessible)."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        if _is_admin(sess):
            return
        pid = str(port_id or "").strip()
        override, device_ip = "", None
        if pid:
            try:
                lr = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
                match = next((x for x in (_console_unwrap(lr).get("ports") or [])
                              if str(x.get("port_id", "")) == pid), None)
                override = (match or {}).get("tenant_id") or ""
                device_ip = ((match or {}).get("probe") or {}).get("identity", {}).get("ip")
            except Exception:  # noqa: BLE001
                pass
        eff = override or (hub.state.get_spoke_tenant(sid) or "")
        if not await _console_tenant_ok(sess, sid, eff, device_ip):
            raise HTTPException(status_code=403,
                                detail="not authorized for this console port's tenant")

    def _console_credentials_ref(hub):
        """The configured Key Vault reference for the console auto-login
        credential list, or "" when the creds live in hub state. Env
        ``LM_CONSOLE_CREDENTIALS_REF`` wins, then
        ``global_config["console_credentials_ref"]``. A value like
        ``kv:console-auto-credentials`` (or a bare secret name) names a Key Vault
        secret holding the JSON credential list."""
        gc = hub.state.system_state.get("global_config", {}) or {}
        return (os.environ.get("LM_CONSOLE_CREDENTIALS_REF")
                or (gc.get("console_credentials_ref") if isinstance(gc, dict) else "")
                or "").strip()

    def _console_creds_keyvault_backed(hub):
        """True when the credential list is sourced (read-only) from Key Vault."""
        return bool(_console_credentials_ref(hub))

    def _console_creds_from_vault(hub, ref):
        """Resolve + parse the JSON credential list from the credential store
        (Key Vault). Returns a normalised ``[{username,password}]`` list, or
        ``None`` if the secret can't be fetched/parsed (caller fails closed)."""
        from security.credential_store import get_credential_provider, resolve_secret_text
        gc = hub.state.system_state.get("global_config", {}) or {}
        raw = resolve_secret_text(ref, get_credential_provider(gc))
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except Exception:  # noqa: BLE001
            logger.warning("console: Key Vault credential secret is not valid JSON")
            return None
        out = []
        for c in (data or []):
            if isinstance(c, dict) and c.get("username"):
                out.append({"username": str(c.get("username", "")),
                            "password": str(c.get("password", ""))})
        return out

    def _console_load_credentials(hub):
        """Decrypt/resolve the global auto-identify credential list ([] if
        unset/undecryptable). Sourced from Key Vault when a reference is
        configured (:func:`_console_credentials_ref`), else the Fernet-encrypted
        blob in hub state."""
        ref = _console_credentials_ref(hub)
        if ref:
            creds = _console_creds_from_vault(hub, ref)
            if creds is None:
                logger.warning("console: credential ref %r configured but could "
                               "not be resolved from the vault", ref)
                return []
            return creds
        blob = hub.state.system_state.get("console_credentials_enc")
        if not blob:
            return []
        try:
            from security.encryption import hub_encryption
            return json.loads(hub_encryption.decrypt(blob.encode()))
        except Exception:  # noqa: BLE001
            logger.warning("console: could not decrypt stored credentials")
            return []

    def _console_save_credentials(hub, creds):
        from security.encryption import hub_encryption
        hub.state.system_state["console_credentials_enc"] = \
            hub_encryption.encrypt(json.dumps(creds)).decode()
        hub.state._mark_dirty()

    def _console_mark_seeded(hub, sid):
        s = getattr(hub, "_console_creds_seeded", None)
        if s is None:
            s = set()
            hub._console_creds_seeded = s
        s.add(sid)

    async def _console_seed_credentials(hub, spokes):
        """Push the credential list to any console spoke not yet seeded this
        process (so a spoke that connects after credentials were set still gets
        them). Fire-and-forget + signed."""
        creds = _console_load_credentials(hub)
        if not creds:
            return
        seeded = getattr(hub, "_console_creds_seeded", None) or set()
        for sid in spokes:
            if sid in seeded:
                continue
            try:
                await hub.send_to_spoke_command(sid, "CONSOLE_SET_CREDENTIALS", {"credentials": creds})
                _console_mark_seeded(hub, sid)
            except Exception:  # noqa: BLE001
                pass

    async def _console_push_llm_flag(hub, spokes, enabled):
        """Push the LLM-identify runtime gate to console spokes (fire-and-forget,
        signed) so the toggle takes effect without an agent restart."""
        for sid in spokes:
            try:
                await hub.send_to_spoke_command(sid, "CONSOLE_SET_LLM_IDENTIFY",
                                                {"enabled": bool(enabled)})
            except Exception:  # noqa: BLE001
                pass

    async def _list_visible_console_ports(request: Request):
        """Serial ports across every connected Console spoke, each tagged with its
        spoke_id and EFFECTIVE tenant (per-port override, else the agent's tenant).

        Tenant-scoped exactly like the rest of the platform (the WebUI passes
        ``?tenant=<currentTenant>`` from the picker; ``default``/empty == the
        global "All" view):

          * A console agent DEDICATED to a tenant → all its ports are that
            tenant's; they never appear under another tenant (the reported leak).
          * A console agent on the SHARED tenant → visible to every tenant, but
            each port is routed by its identified device IP against the viewing
            tenant's NetBox prefixes (the ``console`` subnet-filter module). An
            admin can still pin ONE port to a specific tenant via the per-port
            override, which then behaves as dedicated.
          * An UNASSIGNED agent/port → admin-only holding state (global view).

        Visibility mirrors ``access.spoke_visible_to_session`` +
        ``filter_record_by_prefixes`` (see ``_console_port_disposition``)."""
        sess = _session_user(request)
        admin = _is_admin(sess)
        explicit = str(request.query_params.get("tenant") or "").strip()
        # Picker tenant (like /api/pxmx/agents): explicit ?tenant= else session
        # tenant. "default"/empty == the global "All" view (no tenant filter).
        tid = _resolve_tenant(request, explicit or None)
        sel = tid if (tid and tid != "default") else None
        # Tenant whose prefixes shared-console ports are masked against: the
        # selected tenant, else (non-admin) the caller's own tenant.
        mask_scope = sel or (None if admin else (sess or {}).get("user", {}).get("tenant_id") or None)
        hub = app.state.hub
        console_filter_on = access.filter_enabled(hub, "console")
        mask_prefixes = None
        if mask_scope and console_filter_on:
            try:
                mask_prefixes = await access.resolve_prefixes_for_tenant(hub, mask_scope)
            except Exception:  # noqa: BLE001 - prefix fetch best-effort; fail closed below
                mask_prefixes = []
        spokes = hub.get_all_spokes_by_type("console") or []
        await _console_seed_credentials(hub, spokes)  # ensure new console spokes have creds
        ports, errors, visible_spokes = [], {}, set()
        for sid in spokes:
            stenant = hub.state.get_spoke_tenant(sid) or ""
            agent_name = hub.state.get_module_name(sid)  # friendly name, not the UUID
            # A dedicated agent bound to the selected tenant is "present" for it
            # even before its ports enumerate (accurate empty-state); shared /
            # unassigned agents only count once a port actually passes below.
            if sel is None or (stenant == sel and not access.tenant_is_shared(stenant)):
                visible_spokes.add(sid)
            try:
                r = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
            except Exception as e:  # noqa: BLE001 - one dead console shouldn't blank the rest
                errors[sid] = str(e)
                continue
            for p in (_console_unwrap(r).get("ports") or []):
                override = p.get("tenant_id") or ""
                eff = override or stenant
                p["spoke_id"] = sid
                p["agent_name"] = agent_name    # display name for the "Console agent" column
                p["tenant_id"] = eff            # effective (what scoping/NetBox uses)
                p["tenant_override"] = override  # per-port override, if any
                p["agent_tenant"] = stenant      # the whole-agent binding
                shared = access.tenant_is_shared(eff)
                visible = access.spoke_visible_to_session(sess, eff)
                disp = _console_port_disposition(admin, visible, eff, sel, shared)
                if disp == "hide":
                    continue
                if disp == "mask":
                    # Shared infra: route by the identified device IP. Toggle off
                    # → show unmasked; no scope/prefixes → fail closed (hide).
                    if console_filter_on:
                        if not mask_scope or not mask_prefixes:
                            continue
                        device_ip = ((p.get("probe") or {}).get("identity") or {}).get("ip")
                        if access.filter_record_by_prefixes(
                                {"ip": device_ip}, mask_prefixes, ("ip",)) is None:
                            continue
                ports.append(p)
                visible_spokes.add(sid)
        consoles = spokes if sel is None else [s for s in spokes if s in visible_spokes]
        return {"consoles": consoles, "ports": ports, "errors": errors}

    @app.get("/api/console/ports")
    async def console_ports(request: Request):
        """Serial ports across every connected Console spoke (tenant-scoped)."""
        return await _list_visible_console_ports(request)

    @app.post("/api/console/settings")
    async def console_settings(request: Request):
        """Set per-port settings (baud/parity/flow) or alias on a Console spoke."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        cmd = "CONSOLE_SET_ALIAS" if "alias" in body else "CONSOLE_SET_SETTINGS"
        r = await hub.request_response(sid, cmd, body or {}, timeout=15.0)
        return _console_unwrap(r)

    @app.post("/api/console/detect-baud")
    async def console_detect_baud(request: Request):
        """Auto-detect + lock a port's baud rate (sweeps candidates; up to ~45s)."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        r = await hub.request_response(sid, "CONSOLE_DETECT_BAUD",
                                       {"port_id": (body or {}).get("port_id")}, timeout=45.0)
        return _console_unwrap(r)

    @app.post("/api/console/identify")
    async def console_identify(request: Request):
        """Manually trigger the read-only auto-identify (fingerprint) on a port.
        Seeds credentials first so the login step can succeed."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        await _console_seed_credentials(hub, [sid])
        r = await hub.request_response(sid, "CONSOLE_AUTOPROBE",
                                       {"port_id": (body or {}).get("port_id")}, timeout=90.0)
        return _console_unwrap(r)

    @app.post("/api/console/identify-llm")
    async def console_identify_llm(request: Request):
        """LLM-driven identify for a device the built-in fingerprint profiles
        don't recognize: relay its console output to the LLM, run any read-only
        commands it asks for (spoke-validated), and extract the identity. Admin
        only; gated off by default (LM_CONSOLE_LLM_IDENTIFY + spoke config)."""
        from routes import console_llm_identify as llm  # local import (optional feature)
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        if not llm.hub_llm_identify_enabled(hub):
            raise HTTPException(status_code=409,
                                detail="LLM-assisted identify is disabled — enable it in the Console tools.")
        agent = llm.find_bugfixer(hub)
        if not agent:
            raise HTTPException(status_code=409,
                                detail="LLM identify unavailable — the BugFixer LLM agent is not connected.")
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        port_id = (body or {}).get("port_id")
        if not sid or not port_id:
            raise HTTPException(status_code=400, detail="spoke_id/port_id required")
        await _assert_port_tenant(request, sid, port_id)
        await _console_seed_credentials(hub, [sid])  # so the generic login can succeed
        await _console_push_llm_flag(hub, [sid], True)  # ensure the spoke gate is on
        try:
            return await llm.orchestrate(hub, agent, sid, port_id)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"LLM identify error: {e}")

    @app.post("/api/console/identify-llm-all")
    async def console_identify_llm_all(request: Request):
        """Bulk 'scrape all devices' trigger: kick off LLM-driven identify for
        EVERY visible console port at once. Runs in the background (bounded
        concurrency, so the single BugFixer agent isn't swamped) and returns
        immediately — results stream back through the normal probe/port refresh.
        Ports a user currently has open are skipped so a live session isn't
        disrupted. Admin only; same gating as the per-port identify."""
        from routes import console_llm_identify as llm  # local import (optional feature)
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        if not llm.hub_llm_identify_enabled(hub):
            raise HTTPException(status_code=409,
                                detail="LLM-assisted identify is disabled — enable it in the Console tools.")
        agent = llm.find_bugfixer(hub)
        if not agent:
            raise HTTPException(status_code=409,
                                detail="LLM identify unavailable — the BugFixer LLM agent is not connected.")
        data = await _list_visible_console_ports(request)  # tenant-scoped like the list view
        all_ports = data.get("ports") or []
        targets = [(p.get("spoke_id"), p.get("port_id")) for p in all_ports
                   if p.get("spoke_id") and p.get("port_id") and not p.get("in_use")]
        skipped_in_use = sum(1 for p in all_ports if p.get("in_use"))
        if not targets:
            return {"queued": 0, "skipped_in_use": skipped_in_use}
        # Prep every involved spoke once (seed creds + runtime gate) up front.
        spokes = sorted({sid for sid, _ in targets})
        await _console_seed_credentials(hub, spokes)
        await _console_push_llm_flag(hub, spokes, True)

        sem = asyncio.Semaphore(2)  # single BugFixer agent → keep it gentle

        async def _run_one(sid, pid):
            async with sem:
                try:
                    await llm.orchestrate(hub, agent, sid, pid)
                except Exception as e:  # noqa: BLE001 - one bad port can't stop the batch
                    logger.warning("bulk AI identify failed for %s/%s: %s", sid, pid, e)

        async def _run_all():
            await asyncio.gather(*[_run_one(sid, pid) for sid, pid in targets])

        asyncio.create_task(_run_all())  # fire-and-forget; survives this request
        return {"queued": len(targets), "skipped_in_use": skipped_in_use}

    @app.get("/api/console/llm-identify")
    async def console_llm_identify_get(request: Request):
        """Current state of the LLM-assisted identify toggle (admin). Reports
        whether it's enabled and whether the BugFixer LLM agent is connected."""
        from routes import console_llm_identify as llm
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        return {"enabled": llm.hub_llm_identify_enabled(hub),
                "available": llm.find_bugfixer(hub) is not None}

    @app.post("/api/console/llm-identify")
    async def console_llm_identify_set(request: Request):
        """Enable/disable LLM-assisted identify (admin). Persists the hub setting
        and pushes the runtime gate to every connected Console spoke."""
        from routes import console_llm_identify as llm
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        enabled = bool((body or {}).get("enabled"))
        hub.state.system_state["console_llm_identify_enabled"] = enabled
        hub.state._mark_dirty()
        await _console_push_llm_flag(hub, hub.get_all_spokes_by_type("console") or [], enabled)
        return {"enabled": enabled, "available": llm.find_bugfixer(hub) is not None}

    @app.post("/api/console/capture")
    async def console_capture(request: Request):
        """Return the recent passive-capture buffer for a port — whatever the
        device has emitted (banner/boot/log/prompt), even with no user attached.
        Tenant-guarded exactly like the other per-port actions."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        r = await hub.request_response(sid, "CONSOLE_GET_CAPTURE", {
            "port_id": (body or {}).get("port_id"),
            "bytes": (body or {}).get("bytes"),
        }, timeout=15.0)
        return _console_unwrap(r)

    async def console_set_tenant(request: Request):
        """Bind a single PORT to a tenant (per-port override). Admin-only, like the
        whole-agent tenant assignment. Empty tenant_id clears the override so the
        port falls back to the agent's tenant."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid or not (body or {}).get("port_id"):
            raise HTTPException(status_code=400, detail="spoke_id/port_id required")
        r = await hub.request_response(sid, "CONSOLE_SET_TENANT", {
            "port_id": body.get("port_id"), "tenant_id": body.get("tenant_id", ""),
        }, timeout=15.0)
        return _console_unwrap(r)

    @app.get("/api/console/diagnostics")
    async def console_diagnostics(request: Request):
        """Serial-connection health report across every Console spoke: ports that
        keep failing to open (faulty/non-real), get disconnected (device pulled),
        or flap. Admin-gated (ops/troubleshooting view of infra-wide errors)."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        spokes = hub.get_all_spokes_by_type("console") or []
        rows, errors, summaries = [], {}, {}
        for sid in spokes:
            agent_name = hub.state.get_module_name(sid)
            stenant = hub.state.get_spoke_tenant(sid) or ""
            try:
                r = await hub.request_response(sid, "CONSOLE_DIAGNOSTICS", {}, timeout=15.0)
            except Exception as e:  # noqa: BLE001 - one dead console shouldn't blank the rest
                errors[sid] = str(e)
                continue
            payload = _console_unwrap(r)
            summ = payload.get("summary")
            if summ:
                summaries[sid] = {**summ, "agent_name": agent_name}
            for d in (payload.get("diagnostics") or []):
                d["spoke_id"] = sid
                d["agent_name"] = agent_name
                d["tenant_id"] = d.get("tenant_id") or stenant  # per-port override else agent binding
                rows.append(d)
        rows.sort(key=lambda d: (d.get("currently_failing", False),
                                 d.get("open_failures", 0) + d.get("disconnects", 0)), reverse=True)
        return {"diagnostics": rows, "errors": errors, "consoles": spokes, "summaries": summaries}

    @app.post("/api/console/diagnostics/purge")
    async def console_diagnostics_purge(request: Request):
        """Purge ALL collected serial-health / identify telemetry across every
        Console spoke (failure/disconnect counts, identify attempts, transcript
        tails). Live 'currently failing' state re-derives on the next probe cycle.
        Admin-gated, like the diagnostics report itself."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        spokes = hub.get_all_spokes_by_type("console") or []
        purged, errors = 0, {}
        for sid in spokes:
            try:
                r = await hub.request_response(sid, "CONSOLE_DIAGNOSTICS_PURGE", {}, timeout=15.0)
                purged += int(_console_unwrap(r).get("purged") or 0)
            except Exception as e:  # noqa: BLE001 - one dead console shouldn't block the rest
                errors[sid] = str(e)
        return {"purged": purged, "errors": errors, "consoles": spokes}

    @app.get("/api/console/credentials")
    async def console_get_credentials(request: Request):
        """Return the global auto-identify credential list with passwords MASKED
        (usernames + has_password only). Admin-gated by the /api/console/* rule +
        this explicit admin check (credentials are privileged)."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        creds = _console_load_credentials(app.state.hub)
        return {"credentials": [{"username": c.get("username", ""),
                                 "has_password": bool(c.get("password"))} for c in creds],
                "source": "keyvault" if _console_creds_keyvault_backed(app.state.hub) else "hub",
                "read_only": _console_creds_keyvault_backed(app.state.hub)}

    @app.post("/api/console/credentials")
    async def console_post_credentials(request: Request):
        """Replace the global auto-identify credential list (Fernet-encrypted in
        hub state) and push it (signed) to every connected Console spoke. Admin
        only."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        # Vault-backed lists are managed in Key Vault (least-privilege: the hub
        # only reads them) — editing here would be silently lost, so reject it.
        if _console_creds_keyvault_backed(hub):
            raise HTTPException(status_code=409,
                                detail="console credentials are managed in Azure Key Vault (read-only here)")
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Merge: a blank password keeps the currently-stored one for that username
        # (the GET never returns passwords, so the UI submits blanks to keep them).
        stored = {c.get("username"): c.get("password") for c in _console_load_credentials(hub)}
        creds = []
        for c in (body.get("credentials") or []):
            if not isinstance(c, dict):
                continue
            u = str(c.get("username", "")).strip()
            if not u:
                continue
            p = str(c.get("password", ""))
            if not p and u in stored:
                p = stored[u]
            creds.append({"username": u, "password": p})
        _console_save_credentials(hub, creds)
        hub._console_creds_seeded = set()  # force re-seed with the new list
        for sid in (hub.get_all_spokes_by_type("console") or []):
            try:
                await hub.send_to_spoke_command(sid, "CONSOLE_SET_CREDENTIALS", {"credentials": creds})
                _console_mark_seeded(hub, sid)
            except Exception:  # noqa: BLE001
                pass
        return {"status": "ok", "count": len(creds)}

    @app.post("/api/console/open")
    async def console_open(request: Request):
        """Mint a console session + ws_token and open the serial handle on the
        Console spoke (request/response). The reader then pushes CONSOLE_DATA_UP,
        which the browser drains via /ws/console-serial/{session_id}."""
        sess = _session_user(request)
        admin = _is_admin(sess)
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        port_id = str((body or {}).get("port_id", "")).strip()
        mode = str((body or {}).get("mode", "rw")).lower()
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        if not port_id:
            raise HTTPException(status_code=400, detail="port_id is required")
        # Enforce the port's effective tenant for non-admins — same rule as the
        # /api/console/ports listing (dedicated own-tenant, or a SHARED device
        # routed by its IP to the caller's prefixes).
        if not admin:
            override, device_ip = "", None
            try:
                lr = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
                match = next((x for x in (_console_unwrap(lr).get("ports") or [])
                              if x.get("port_id") == port_id), None)
                override = (match or {}).get("tenant_id") or ""
                device_ip = ((match or {}).get("probe") or {}).get("identity", {}).get("ip")
            except Exception:
                pass
            eff = override or (hub.state.get_spoke_tenant(sid) or "")
            if not await _console_tenant_ok(sess, sid, eff, device_ip):
                raise HTTPException(status_code=403,
                                    detail="not authorized for this console port's tenant")
        session_id = str(uuid.uuid4())
        ws_token = secrets.token_urlsafe(32)
        relay_token = secrets.token_urlsafe(32)   # edge-proxy relay leg (Phase 2)
        tenant_id = (sess or {}).get("tenant_id") or ""
        hub.register_console_session(session_id, {
            "spoke_id": sid, "tenant_id": tenant_id, "ws_token": ws_token,
            "relay_token": relay_token, "port_id": port_id,
        })
        try:
            r = await hub.request_response(sid, "CONSOLE_OPEN", {
                "session_id": session_id, "port_id": port_id, "mode": mode,
                "relay_token": relay_token,
            }, timeout=15.0)
        except Exception as e:
            hub.unregister_console_session(session_id)
            raise HTTPException(status_code=502, detail=f"failed to open console: {e}")
        data = _console_unwrap(r)
        if data.get("status") not in ("SUCCESS", "OK"):
            hub.unregister_console_session(session_id)
            raise HTTPException(status_code=502,
                                detail=data.get("message") or "console spoke refused CONSOLE_OPEN")
        return {"session_id": session_id, "ws_token": ws_token,
                "settings": data.get("settings", {}), "read_only": bool(data.get("read_only")),
                "writer": data.get("writer"), "expires_in": 60,
                # Phase 2 edge-proxy relay descriptor (serial: no agent — the console
                # spoke writes DOWN frames to /dev/tty* itself via its down_handler).
                # A proxy relay only works when the console role runs its listener
                # (LM_CONSOLE_RELAY_LISTENER=1); otherwise the proxy falls back to
                # the hub relay.
                "relay": {"session_id": session_id, "relay_token": relay_token,
                          "spoke_id": sid, "kind": "serial"}}

    @app.post("/api/console/config/get")
    async def console_config_get(request: Request):
        """Read/back up a port's running-config. Gated by console_write (middleware)."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        await _console_seed_credentials(hub, [sid])
        r = await hub.request_response(sid, "CONSOLE_GET_CONFIG",
                                       {"port_id": (body or {}).get("port_id")}, timeout=90.0)
        return _console_unwrap(r)

    @app.post("/api/console/config/push")
    async def console_config_push(request: Request):
        """Transactional config push (verify → save-on-pass → rollback-on-fail).
        No post-request approval. Gated by console_write (middleware)."""
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        if not sid:
            raise HTTPException(status_code=503, detail="No Console spoke connected")
        if not str((body or {}).get("config", "")).strip():
            raise HTTPException(status_code=400, detail="config is required")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        await _console_seed_credentials(hub, [sid])
        r = await hub.request_response(sid, "CONSOLE_PUSH_CONFIG", {
            "port_id": body.get("port_id"), "config": body.get("config"),
            "save": bool(body.get("save", True)),
            "rollback": body.get("rollback") or "negate",
        }, timeout=180.0)
        return _console_unwrap(r)

    @app.websocket("/ws/console-serial/{session_id}")
    async def console_serial_ws(websocket: WebSocket, session_id: str):
        """Browser↔serial byte relay for the Console role. Gated by the one-shot
        ws_token from POST /api/console/open. browser keystrokes → CONSOLE_DATA
        (fire-and-forget); queued device output → browser bytes, with
        ready/error/disconnect control tuples (ready must CONTINUE, not return —
        the VNC relay bug). On exit: CONSOLE_CLOSE down + unregister."""
        token = websocket.query_params.get("token") or ""
        hub = app.state.hub
        sess = hub.get_console_session(session_id)
        if not sess or sess.get("ws_token") != token:
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired console session")
            return
        spoke_id = sess["spoke_id"]
        queue = sess["queue"]
        sess["connected"] = True  # long-lived interactive session; TTL no longer applies
        await websocket.accept()
        relay_tasks: list = []
        try:
            async def browser_to_spoke():
                while True:
                    msg = await websocket.receive()
                    if msg.get("type") == "websocket.disconnect":
                        raise WebSocketDisconnect(code=msg.get("code", 1000))
                    raw = msg.get("bytes")
                    if raw is None:
                        text = msg.get("text")
                        if not text:
                            continue
                        raw = text.encode()
                    await hub.send_to_spoke_command(spoke_id, "CONSOLE_DATA", {
                        "session_id": session_id,
                        "data": base64.b64encode(raw).decode(),
                    })

            async def spoke_to_browser():
                while True:
                    item = await queue.get()
                    if isinstance(item, (bytes, bytearray)):
                        await websocket.send_bytes(bytes(item))
                    elif isinstance(item, tuple) and item:
                        kind = item[0]
                        if kind == "error":
                            await websocket.close(code=1011, reason=str(item[1]))
                            return
                        if kind == "disconnect":
                            await websocket.close(code=1000, reason="console closed")
                            return
                        continue  # "ready": keep the consumer alive (VNC ready-return bug)
                    else:
                        return

            relay_tasks = [asyncio.create_task(browser_to_spoke()),
                           asyncio.create_task(spoke_to_browser())]
            done, pending = await asyncio.wait(relay_tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*relay_tasks, return_exceptions=True)
            for task in done:
                exc = task.exception()
                if exc and not isinstance(exc, (WebSocketDisconnect, asyncio.CancelledError)):
                    raise exc
        except WebSocketDisconnect:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("console-serial ws %s relay failed: %s", session_id, exc)
        finally:
            hub.unregister_console_session(session_id)
            try:
                await hub.send_to_spoke_command(spoke_id, "CONSOLE_CLOSE", {"session_id": session_id})
            except Exception:
                pass
            for task in relay_tasks:
                if not task.done():
                    task.cancel()
            if relay_tasks:
                await asyncio.gather(*relay_tasks, return_exceptions=True)
            if websocket.application_state != WebSocketState.DISCONNECTED:
                try:
                    await websocket.close()
                except Exception:
                    pass
