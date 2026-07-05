"""VNC + serial console relay routes and helpers."""
from api import (
    HTTPException, Request, WebSocket, WebSocketDisconnect, WebSocketState, asyncio, base64,
    json, logger, secrets, uuid,
)


def register(app, hub, ctx):
    """Register console routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _check_tenant_access = ctx._check_tenant_access

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

    # ── Console role: serial console access (/api/console/*, /ws/console-serial) ──
    def _console_unwrap(result):
        """request_response envelope → the spoke's inner data dict."""
        if isinstance(result, dict):
            return result.get("payload", {}).get("data", result)
        return {}

    def _console_spoke_or_none(hub, body):
        """Target console spoke: explicit spoke_id, else the first connected one."""
        return (body or {}).get("spoke_id") or hub.get_spoke_by_type("console")

    def _console_load_credentials(hub):
        """Decrypt the global auto-identify credential list from hub state ([] if
        unset/undecryptable)."""
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
        hub.state.save_state()

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

    @app.get("/api/console/ports")
    async def console_ports(request: Request):
        """Serial ports across every connected Console spoke, each tagged with its
        spoke_id and EFFECTIVE tenant (per-port override, else the agent's tenant).
        Non-admins only see ports whose effective tenant they can access."""
        sess = _session_user(request)
        admin = _is_admin(sess)
        hub = app.state.hub
        spokes = hub.get_all_spokes_by_type("console") or []
        await _console_seed_credentials(hub, spokes)  # ensure new console spokes have creds
        ports, errors = [], {}
        for sid in spokes:
            stenant = hub.state.get_spoke_tenant(sid) or ""
            try:
                r = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
            except Exception as e:  # noqa: BLE001 - one dead console shouldn't blank the rest
                errors[sid] = str(e)
                continue
            for p in (_console_unwrap(r).get("ports") or []):
                override = p.get("tenant_id") or ""
                eff = override or stenant
                p["spoke_id"] = sid
                p["tenant_id"] = eff            # effective (what scoping/NetBox uses)
                p["tenant_override"] = override  # per-port override, if any
                p["agent_tenant"] = stenant      # the whole-agent binding
                if admin or _check_tenant_access(sess, eff):
                    ports.append(p)
        return {"consoles": spokes, "ports": ports, "errors": errors}

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
        await _console_seed_credentials(hub, [sid])
        r = await hub.request_response(sid, "CONSOLE_AUTOPROBE",
                                       {"port_id": (body or {}).get("port_id")}, timeout=90.0)
        return _console_unwrap(r)

    @app.post("/api/console/tenant")
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
                                 "has_password": bool(c.get("password"))} for c in creds]}

    @app.post("/api/console/credentials")
    async def console_post_credentials(request: Request):
        """Replace the global auto-identify credential list (Fernet-encrypted in
        hub state) and push it (signed) to every connected Console spoke. Admin
        only."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
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
        # Enforce the port's effective tenant for non-admins (per-port override,
        # else the agent's tenant).
        if not admin:
            override = ""
            try:
                lr = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
                match = next((x for x in (_console_unwrap(lr).get("ports") or [])
                              if x.get("port_id") == port_id), None)
                override = (match or {}).get("tenant_id") or ""
            except Exception:
                pass
            eff = override or (hub.state.get_spoke_tenant(sid) or "")
            if not _check_tenant_access(sess, eff):
                raise HTTPException(status_code=403,
                                    detail="not authorized for this console port's tenant")
        session_id = str(uuid.uuid4())
        ws_token = secrets.token_urlsafe(32)
        tenant_id = (sess or {}).get("tenant_id") or ""
        hub.register_console_session(session_id, {
            "spoke_id": sid, "tenant_id": tenant_id, "ws_token": ws_token, "port_id": port_id,
        })
        try:
            r = await hub.request_response(sid, "CONSOLE_OPEN", {
                "session_id": session_id, "port_id": port_id, "mode": mode,
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
                "writer": data.get("writer"), "expires_in": 60}

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
