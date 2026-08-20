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


def console_port_search_blob(p: dict) -> str:
    """Lower-cased haystack of a console port's identifiers, for substring
    search matching (hostname, alias, vendor, model, device path, port_id,
    agent name, and the identified device IP)."""
    probe = p.get("probe") or {}
    ident = probe.get("identity") or {}
    parts = [
        p.get("alias"), ident.get("hostname"), ident.get("ip"),
        ident.get("vendor") or probe.get("vendor"), ident.get("model"),
        p.get("device"), p.get("port_id"), p.get("agent_name"),
    ]
    return " ".join(str(x) for x in parts if x).lower()


def console_port_matches(p: dict, needle: str) -> bool:
    """True when ``needle`` (already lower-cased, non-empty) is a substring of
    the port's identifier blob."""
    return bool(needle) and needle in console_port_search_blob(p)


def console_port_result(p: dict) -> dict:
    """Shape a tenant-scoped console port into a global-search / device-detail
    result row carrying everything the WebUI needs to connect
    (``openConsoleTerminal(spoke_id, port_id)``)."""
    probe = p.get("probe") or {}
    ident = probe.get("identity") or {}
    return {
        "source": "console",
        "type": "console",
        "name": ident.get("hostname") or p.get("alias") or p.get("device"),
        "ip": ident.get("ip") or None,
        "spoke_id": p.get("spoke_id"),
        "port_id": p.get("port_id"),
        "device": p.get("device"),
        "agent_name": p.get("agent_name"),
        "tenant_id": p.get("tenant_id") or "",
        "baud": (p.get("settings") or {}).get("baud"),
        "vendor": ident.get("vendor") or probe.get("vendor") or None,
        "model": ident.get("model") or None,
        "in_use": bool(p.get("in_use")),
        "dpa": p.get("dpa"),
    }


def register(app, hub, ctx):
    """Register console routes on the Hub app."""
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin
    _has_console_write_access = ctx._has_console_write_access
    _has_console_access = ctx._has_console_access
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
        unique_id = str(sess.get("unique_id") or "")
        # Mark connected so the 60s TTL no longer reaps this session (a viewer
        # sits on a console far longer than 60s, and each upstream frame re-reads
        # the session by id). connected_at drives the multiuser presence roster.
        import time as _time
        sess["connected"] = True
        sess["connected_at"] = _time.time()
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
                    # Write-lock gate: a read-only viewer's keyboard/mouse input
                    # never reaches the VM. The screen keeps streaming to them
                    # either way (QEMU multiplexes VNC_FRAME_UP to every viewer
                    # regardless) — only this direction is gated. Re-checked live
                    # (not just at open) so a force-takeover elsewhere downgrades
                    # this session's input immediately, without a reconnect.
                    if unique_id and not hub.vnc_is_writer(unique_id, session_id):
                        continue
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
                        if kind == "downgraded":
                            # Another viewer forced a takeover — tell the browser
                            # to flip noVNC into view-only, without closing the
                            # connection (the screen keeps streaming).
                            try:
                                await websocket.send_text(json.dumps({"type": "downgraded"}))
                            except Exception:
                                pass
                            continue
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

    def _console_load_local_credentials(hub):
        """The LOCAL Fernet-encrypted console credential list (hub state only),
        ignoring any Key Vault ref. These legacy passwords are what an operator
        may DELETE to clean up once the Credential Vault is in use — deletion is
        the one mutation still allowed on this store (creation is disabled)."""
        blob = hub.state.system_state.get("console_credentials_enc")
        if not blob:
            return []
        try:
            from security.encryption import hub_encryption
            return json.loads(hub_encryption.decrypt(blob.encode()))
        except Exception:  # noqa: BLE001
            logger.warning("console: could not decrypt stored credentials")
            return []

    # Name of the Credential Vault secret (in the Global Admin slot, __admin__)
    # that holds the console auto-identify login list as a hub-mode
    # (automation-readable) secret ``{"credentials": [{username,password}, …]}``.
    _CONSOLE_VAULT_SECRET = "console-auto-credentials"

    def _console_creds_from_cred_vault(creds_dict):
        """Normalise a Credential Vault secret value into ``[{username,password}]``.

        Accepts BOTH shapes: the multi-login list
        ``{"credentials":[{username,password},…]}`` (legacy
        ``console-auto-credentials`` secret) and a single flat login
        ``{"username","password"}`` (a ``console``-type secret, one login each)."""
        d = creds_dict or {}
        out = []
        items = d.get("credentials")
        if isinstance(items, list):
            for c in items:
                if isinstance(c, dict) and c.get("username"):
                    out.append({"username": str(c.get("username", "")),
                                "password": str(c.get("password", ""))})
        if not out and d.get("username"):
            out.append({"username": str(d.get("username", "")),
                        "password": str(d.get("password", ""))})
        return out

    async def _console_creds_for_tenant(hub, tenant):
        """Aggregate console auto-login credentials from the Credential Vault for
        a console spoke bound to ``tenant``. ONLY secrets explicitly typed
        ``console`` count — so an operator marks exactly which vault logins are
        for device auto-identify (we never sweep unrelated ``login`` secrets in).

        Reachable slots: the spoke's own tenant bucket + the global ``__admin__``
        slot — so a tenant's console password is never pushed to another tenant's
        console spoke. The legacy global ``console-auto-credentials`` list secret
        (``__admin__``) is still honoured for backward-compat. De-duped by
        (username, password)."""
        creds, seen = [], set()

        def _add(items):
            for c in items:
                key = (c["username"], c["password"])
                if key not in seen:
                    seen.add(key)
                    creds.append(c)

        try:
            import cred_vault as _cv
            buckets = [_cv.ADMIN_BUCKET]
            if tenant and tenant not in buckets:
                buckets.append(tenant)
            for rec in await _cv.automation_list_by_type(hub, "console", buckets):
                _add(_console_creds_from_cred_vault(rec.get("value")))
            # Legacy single named list secret in the admin slot.
            try:
                val = await _cv.automation_get(hub, _cv.ADMIN_BUCKET, _CONSOLE_VAULT_SECRET)
                _add(_console_creds_from_cred_vault(val))
            except Exception:  # noqa: BLE001 — absent / unreadable
                pass
        except Exception:  # noqa: BLE001 — vault not configured
            pass
        return creds

    async def _console_load_credentials_resolved(hub, tenant=None):
        """Async credential resolution used by the (async) seed path. Prefers the
        central Credential Vault so console logins can be managed alongside every
        other secret; falls back to the legacy ref / hub-state loader when no
        vault console secret applies. Purely additive — never worse than today.

        ``tenant`` scopes the vault lookup to that tenant's bucket + ``__admin__``
        (the per-spoke seed passes the spoke's tenant); ``None`` aggregates every
        reachable ``console``-type secret (used by diagnostics/reporting)."""
        try:
            creds = await _console_creds_for_tenant(hub, tenant)
            if creds:
                return creds
        except Exception:  # noqa: BLE001 — not configured / absent / unreadable
            pass
        return _console_load_credentials(hub)

    def _cv_admin_bucket():
        try:
            import cred_vault as _cv
            return _cv.ADMIN_BUCKET
        except Exception:  # noqa: BLE001
            return "__admin__"

    def _vault_enabled(hub):
        """True when the Credential Vault is usable as a credential store — i.e.
        an Azure Key Vault is configured (:func:`cred_vault._vault_available`).
        Per the operator directive, when this is on, module passwords belong in
        the vault; local passwords should be migrated there manually."""
        try:
            import cred_vault as _cv
            return bool(_cv._vault_available(hub))
        except Exception:  # noqa: BLE001
            return False

    async def _console_vault_secret_present(hub):
        """True when at least one console login lives in the Credential Vault —
        any ``console``-type automation-readable secret (any reachable bucket) or
        the legacy ``__admin__``/``console-auto-credentials`` list secret."""
        try:
            return bool(await _console_creds_for_tenant(hub, None))
        except Exception:  # noqa: BLE001
            return False

    def _console_local_passwords_present(hub):
        """True when legacy LOCAL console passwords still exist on the hub
        (Fernet-encrypted ``console_credentials_enc``) — the thing the migrate
        warning nudges the operator to move into the vault."""
        return bool(hub.state.system_state.get("console_credentials_enc"))

    async def _console_hub_git_head():
        """Short git HEAD of the hub's own checkout, for the diagnostics debug
        block (tells an operator whether the HUB — where the console seed /
        self-update logic lives — is actually on the latest code). '' on any
        failure; never raises."""
        try:
            repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
            proc = await asyncio.create_subprocess_exec(
                "git", "-C", repo, "rev-parse", "--short", "HEAD",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            return out.decode().strip() if proc.returncode == 0 else ""
        except Exception:  # noqa: BLE001
            return ""

    def _console_mark_seeded(hub, sid):
        s = getattr(hub, "_console_creds_seeded", None)
        if s is None:
            s = set()
            hub._console_creds_seeded = s
        s.add(sid)

    async def _console_seed_credentials(hub, spokes):
        """Push the credential list to any console spoke not yet seeded this
        process (so a spoke that connects after credentials were set still gets
        them). Credentials are resolved PER SPOKE from the spoke's tenant scope,
        so a tenant's console logins only ever reach that tenant's console spoke.
        Fire-and-forget + signed."""
        seeded = getattr(hub, "_console_creds_seeded", None) or set()
        for sid in spokes:
            if sid in seeded:
                continue
            try:
                tenant = hub.state.get_spoke_tenant(sid) or ""
            except Exception:  # noqa: BLE001
                tenant = ""
            creds = await _console_load_credentials_resolved(hub, tenant)
            if not creds:
                continue  # nothing to push yet — retry on the next seed trigger
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

    async def _console_profile_one(hub, sid, port_id):
        """Profile one port, fingerprint-first: run the deterministic built-in
        fingerprint (spoke login-identify) and, only when it can't recognize the
        device, fall back to the AI (scrubbed output → AppBuilder). Returns an
        identify-shaped result dict (adds ``source='fingerprint'`` on a DB hit).

        This is the explicit, on-demand profiling path — nothing calls it
        automatically, so passive capture stays passive unless an operator asks."""
        from routes import console_llm_identify as llm  # local import (optional feature)
        await _console_seed_credentials(hub, [sid])
        # 1. Known fingerprint in the DB → no AI needed.
        try:
            r = _console_unwrap(await hub.request_response(
                sid, "CONSOLE_AUTOPROBE", {"port_id": port_id}, timeout=90.0))
        except Exception:  # noqa: BLE001
            r = {}
        if r and (r.get("vendor") or r.get("identity")):
            return {"status": "OK", "identified": True, "source": "fingerprint",
                    "vendor": r.get("vendor"), "identity": r.get("identity") or {},
                    "logged_in": bool(r.get("logged_in"))}
        # 2. Unknown device → ask the AI (requires the AppBuilder relay).
        agent = llm.find_ab(hub)
        if not agent:
            return {"status": "ERROR", "identified": False, "need_agent": True,
                    "message": "Device not in the fingerprint DB and the AppBuilder LLM agent is not connected."}
        await _console_push_llm_flag(hub, [sid], True)  # permit the spoke's LLM collect
        return await llm.orchestrate(hub, agent, sid, port_id)

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
        stale_spokes: set = set()

        def _emit_ports(sid, raw_ports, stale):
            """Enrich + tenant-gate one spoke's raw port list into ``ports``.

            Shared by the live path and the warm-cache (spoke-offline) path so the
            visibility/masking rules are identical. ``stale=True`` tags ports
            served from the last-known snapshot. Each port dict is COPIED before
            enrichment so the persisted warm-cache list is never mutated in place
            (it's reused across requests)."""
            stenant = hub.state.get_spoke_tenant(sid) or ""
            agent_name = hub.state.get_module_name(sid)  # friendly name, not the UUID
            # A dedicated agent bound to the selected tenant is "present" for it
            # even before its ports enumerate (accurate empty-state); shared /
            # unassigned agents only count once a port actually passes below.
            if sel is None or (stenant == sel and not access.tenant_is_shared(stenant)):
                visible_spokes.add(sid)
            for src in (raw_ports or []):
                p = dict(src)
                override = p.get("tenant_id") or ""
                eff = override or stenant
                p["spoke_id"] = sid
                p["agent_name"] = agent_name    # display name for the "Console agent" column
                p["tenant_id"] = eff            # effective (what scoping/NetBox uses)
                p["tenant_override"] = override  # per-port override, if any
                p["agent_tenant"] = stenant      # the whole-agent binding
                if stale:
                    p["stale"] = True            # served from warm cache (spoke offline)
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

        for sid in spokes:
            try:
                r = await hub.request_response(sid, "CONSOLE_LIST_PORTS", {}, timeout=15.0)
                raw_ports = _console_unwrap(r).get("ports") or []
                # Persist the last-known port list (aliases + fingerprint identity)
                # so the page warm-starts after a hub restart / brief disconnect
                # instead of blanking until the spoke re-answers — mirrors the
                # pxmx/netbox warm cache. Raw (pre tenant-filter) per the cache
                # contract; _emit_ports re-applies visibility per reader.
                await hub.warm_set("console_ports", sid, raw_ports)
                _emit_ports(sid, raw_ports, stale=False)
            except Exception as e:  # noqa: BLE001 - one dead console shouldn't blank the rest
                cached = hub.warm_get("console_ports", sid)
                if cached:
                    stale_spokes.add(sid)
                    _emit_ports(sid, cached, stale=True)  # names survive the outage
                else:
                    errors[sid] = str(e)

        # Known console spokes that are fully DISCONNECTED (not in the live list)
        # but have a warm-cached port list: surface their last-known device names
        # marked stale, so a hub reboot while a console host is also down still
        # shows the fleet instead of an empty page.
        for sid in list((getattr(hub, "warm_cache", {}) or {}).get("console_ports", {})):
            if sid in spokes:
                continue
            cached = hub.warm_get("console_ports", sid)
            if cached:
                stale_spokes.add(sid)
                _emit_ports(sid, cached, stale=True)

        all_spokes = list(spokes) + [s for s in stale_spokes if s not in spokes]
        consoles = all_spokes if sel is None else [s for s in all_spokes if s in visible_spokes]
        return {"consoles": consoles, "ports": ports, "errors": errors,
                "stale_spokes": sorted(stale_spokes)}

    @app.get("/api/console/ports")
    async def console_ports(request: Request):
        """Serial ports across every connected Console spoke (tenant-scoped)."""
        return await _list_visible_console_ports(request)

    # Expose the tenant-scoped console listing so other route modules (global
    # search, device-detail) can surface a found device's console for connect
    # without duplicating the visibility/masking logic.
    app.state.console_list_visible_ports = _list_visible_console_ports

    # ── Console → NetBox device sync config/status (System → Sync card) ───────
    # Console auto-identify results are mirrored into NetBox event-driven (see
    # HubVncConsoleMixin._handle_console_probe). These routes expose the toggle
    # + creation defaults (global_config["console_netbox_device_sync"]) and the
    # per-tenant last-sync status, mirroring the other discovery-sync cards.
    @app.get("/setup/console-netbox-sync")
    async def get_console_netbox_sync(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        cfg = hub.state.system_state.get("global_config", {}).get("console_netbox_device_sync", {}) or {}
        return {"config": cfg, "netbox_connected": bool(hub.get_spoke_by_type("ipam"))}

    @app.post("/setup/console-netbox-sync")
    async def set_console_netbox_sync(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        try:
            data = await request.json()
        except Exception:
            data = {}
        cfg = (data or {}).get("config", {}) if isinstance(data, dict) else {}
        gc = hub.state.system_state.get("global_config", {}) or {}
        old = gc.get("console_netbox_device_sync", {}) or {}
        merged = {**old, **cfg}
        gc["console_netbox_device_sync"] = merged
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return {"status": "ok", "config": merged}

    @app.get("/setup/console-netbox-sync/status")
    async def console_netbox_sync_status(request: Request):
        hub = app.state.hub
        sess = _session_user(request)
        if not sess or not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin required")
        rows = hub.console_netbox_sync_status()
        tenants = [{
            "tenant_id": r.get("tenant_id"),
            "tenant_name": r.get("tenant_name") or r.get("tenant_id"),
            "status": r.get("status"),
            "synced": r.get("synced", 0),
            "errors": r.get("errors", 0),
            "last_device": r.get("last_device", ""),
            "message": r.get("message", ""),
            "last_sync_ts": r.get("last_sync_ts"),
        } for r in rows]
        return {"tenants": tenants}

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
            raise HTTPException(status_code=503, detail="No spoke connected")
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
            raise HTTPException(status_code=503, detail="No spoke connected")
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
            raise HTTPException(status_code=503, detail="No spoke connected")
        await _assert_port_tenant(request, sid, (body or {}).get("port_id"))
        await _console_seed_credentials(hub, [sid])
        r = await hub.request_response(sid, "CONSOLE_AUTOPROBE",
                                       {"port_id": (body or {}).get("port_id")}, timeout=90.0)
        return _console_unwrap(r)

    @app.post("/api/console/identify-llm")
    async def console_identify_llm(request: Request):
        """Profile ONE device (on-demand). Fingerprint-first: a device the
        built-in/learned fingerprint DB already recognizes is resolved WITHOUT the
        AI; only an unknown device is relayed (scrubbed) to the LLM, which may run
        spoke-validated read-only commands to identify it. Clicking this button is
        the explicit opt-in, so no global toggle gates it. Profiling is read-only
        device identification, so it's open to the console VIEW tier (Global
        Admin, tenant admin, or any ``console`` user) — matching the plain
        ``/api/console/identify`` fingerprint action; the per-port
        ``_assert_port_tenant`` guard then confines a non-admin to a port it can
        see (own-dedicated, or a shared device in its subnet)."""
        sess = _session_user(request)
        if not (_is_admin(sess) or _has_console_access(sess)):
            raise HTTPException(status_code=403, detail="Console access required")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        sid = _console_spoke_or_none(hub, body)
        port_id = (body or {}).get("port_id")
        if not sid or not port_id:
            raise HTTPException(status_code=400, detail="spoke_id/port_id required")
        await _assert_port_tenant(request, sid, port_id)
        try:
            res = await _console_profile_one(hub, sid, port_id)
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"profiling error: {e}")
        if res.get("need_agent"):
            raise HTTPException(status_code=409, detail=res.get("message"))
        return res

    @app.post("/api/console/identify-llm-all")
    async def console_identify_llm_all(request: Request):
        """Profile EVERY visible console port at once (on-demand). Each port is
        fingerprint-first (known devices resolve without the AI); only unknown
        ones are relayed (scrubbed) to the LLM. Runs in the background with bounded
        concurrency and returns immediately — results stream back through the
        normal probe/port refresh. Ports a user currently has open are skipped.
        Profiling is read-only device identification, so it's open to the console
        VIEW tier (Global Admin, tenant admin, or any ``console`` user); the target
        list is the caller's tenant-scoped visible ports
        (``_list_visible_console_ports``), so a non-admin only profiles the ports
        it can see."""
        sess = _session_user(request)
        if not (_is_admin(sess) or _has_console_access(sess)):
            raise HTTPException(status_code=403, detail="Console access required")
        hub = app.state.hub
        data = await _list_visible_console_ports(request)  # tenant-scoped like the list view
        all_ports = data.get("ports") or []
        targets = [(p.get("spoke_id"), p.get("port_id")) for p in all_ports
                   if p.get("spoke_id") and p.get("port_id") and not p.get("in_use")]
        skipped_in_use = sum(1 for p in all_ports if p.get("in_use"))
        if not targets:
            return {"queued": 0, "skipped_in_use": skipped_in_use}
        # Prep every involved spoke once (seed creds) up front.
        spokes = sorted({sid for sid, _ in targets})
        await _console_seed_credentials(hub, spokes)

        sem = asyncio.Semaphore(2)  # single AppBuilder agent → keep it gentle

        async def _run_one(sid, pid):
            async with sem:
                try:
                    await _console_profile_one(hub, sid, pid)
                except Exception as e:  # noqa: BLE001 - one bad port can't stop the batch
                    logger.warning("bulk profiling failed for %s/%s: %s", sid, pid, e)

        async def _run_all():
            await asyncio.gather(*[_run_one(sid, pid) for sid, pid in targets])

        asyncio.create_task(_run_all())  # fire-and-forget; survives this request
        return {"queued": len(targets), "skipped_in_use": skipped_in_use}

    @app.get("/api/console/llm-identify")
    async def console_llm_identify_get(request: Request):
        """Current state of the LLM-assisted identify toggle (admin). Reports
        whether it's enabled and whether the AppBuilder LLM agent is connected."""
        from routes import console_llm_identify as llm
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        return {"enabled": llm.hub_llm_identify_enabled(hub),
                "available": llm.find_ab(hub) is not None}

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
        return {"enabled": enabled, "available": llm.find_ab(hub) is not None}

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
            raise HTTPException(status_code=503, detail="No spoke connected")
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
        or flap. Open to the console VIEW tier (Global Admin, tenant admin, or any
        ``console`` user); a non-admin sees only the diagnostics for the console
        ports it can see (tenant-scoped exactly like the ports list), while a
        Global Admin sees the infra-wide report across every tenant."""
        sess = _session_user(request)
        if not (_is_admin(sess) or _has_console_access(sess)):
            raise HTTPException(status_code=403, detail="Console access required")
        admin = _is_admin(sess)
        hub = app.state.hub
        all_spokes = hub.get_all_spokes_by_type("console") or []
        # Tenant scoping for non-admins: reuse the EXACT port-visibility logic so a
        # tenant admin only ever sees its own tenant's console diagnostics (and
        # shared-infra ports masked to it), never another tenant's or the
        # admin-only unassigned holding state.
        if admin:
            spokes = all_spokes
            ded_visible = set(all_spokes)   # every spoke fully visible
            visible_keys = None             # None == no per-row filtering
        else:
            explicit = str(request.query_params.get("tenant") or "").strip()
            tid = _resolve_tenant(request, explicit or None)
            sel = tid if (tid and tid != "default") else None
            vis = await _list_visible_console_ports(request)
            visible_keys = {(p.get("spoke_id"), p.get("port_id"))
                            for p in (vis.get("ports") or [])}
            # A spoke DEDICATED to a tenant the caller can see: all its diagnostics
            # belong to that tenant, so include even non-enumerated failing ports.
            ded_visible = {
                sid for sid in all_spokes
                if (lambda st: st and not access.tenant_is_shared(st)
                    and access.spoke_visible_to_session(sess, st)
                    and (sel is None or st == sel))(hub.state.get_spoke_tenant(sid) or "")
            }
            contributing = {k[0] for k in visible_keys}
            spokes = [s for s in all_spokes if s in ded_visible or s in contributing]
        # Re-seed operator credentials into any spoke that (re)connected since the
        # last seed — the console spoke holds them in memory only, so a restart
        # (manual or self-update) wipes them and auto-identify falls back to the
        # factory-default set alone ("auth rejected" for devices whose real creds
        # were saved). Diagnostics is the page an operator opens FIRST when login
        # is failing, so seeding here (like the ports list does) guarantees the
        # fresh process regains its creds instead of the operator having to open
        # the ports tab to trigger it. See _forget_console_creds_seed / #275.
        await _console_seed_credentials(hub, spokes)
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
                if not admin and sid not in ded_visible \
                        and (sid, d.get("port_id")) not in visible_keys:
                    continue  # a shared-spoke port not scoped to this tenant
                d["spoke_id"] = sid
                d["agent_name"] = agent_name
                d["tenant_id"] = d.get("tenant_id") or stenant  # per-port override else agent binding
                rows.append(d)
        rows.sort(key=lambda d: (d.get("currently_failing", False),
                                 d.get("open_failures", 0) + d.get("disconnects", 0)), reverse=True)
        # Hub-side credential/seed debug — visible even when a console agent's own
        # summary isn't rendering. Answers the two questions that explain the vast
        # majority of "auth rejected / can't log in" reports without touching the
        # agent: (1) are operator credentials actually SAVED on the hub, and where
        # from; (2) has the hub pushed them to each connected agent (seed marker),
        # or is the agent still on factory-defaults only. Plus the hub's own code
        # version, so a stale hub (the seed/self-update fixes live here, not on the
        # agent) is obvious at a glance. Credentials are reported as COUNTS only —
        # never values.
        seeded = getattr(hub, "_console_creds_seeded", None) or set()
        # Console credential inventory available to the CALLER — a hub-level fact
        # independent of which console spokes are currently connected: the
        # Credential-Vault ``console``-typed secrets in the buckets the caller can
        # reach (a tenant admin → its own tenants + the admin slot; a Global Admin
        # → every bucket), plus the legacy hub-state / keyvault-ref list. Mirrors
        # what _console_seed_credentials pushes, so the banner never falsely warns
        # "0 saved / factory defaults only" when the creds live in the vault.
        # Counts only — never values.
        saved_creds, _seen_c, vault_present = [], set(), False
        try:
            import cred_vault as _cv
            if admin:
                _recs = await _cv.automation_list_by_type(hub, "console", None)
            else:
                _reach = list((sess or {}).get("user", {}).get("tenants") or [])
                _buckets = list(dict.fromkeys([_cv.ADMIN_BUCKET] + _reach))
                _recs = await _cv.automation_list_by_type(hub, "console", _buckets)
            for _rec in _recs:
                _cc = _console_creds_from_cred_vault(_rec.get("value"))
                if _cc:
                    vault_present = True
                for c in _cc:
                    k = (c.get("username"), c.get("password"))
                    if k not in _seen_c:
                        _seen_c.add(k)
                        saved_creds.append(c)
            # Legacy admin-slot named list secret (backward-compat).
            try:
                for c in _console_creds_from_cred_vault(
                        await _cv.automation_get(hub, _cv.ADMIN_BUCKET, _CONSOLE_VAULT_SECRET)):
                    k = (c.get("username"), c.get("password"))
                    if k not in _seen_c:
                        _seen_c.add(k)
                        saved_creds.append(c)
                        vault_present = True
            except Exception:  # noqa: BLE001 — absent / unreadable
                pass
        except Exception:  # noqa: BLE001 — vault not configured / unavailable
            pass
        # Legacy hub-state / keyvault-ref list (backward-compat).
        try:
            _legacy = _console_load_credentials(hub)
        except Exception:  # noqa: BLE001 - debug must never blank the report
            _legacy = []
        legacy_present = bool(_legacy)
        for c in _legacy:
            k = (c.get("username"), c.get("password"))
            if k not in _seen_c:
                _seen_c.add(k)
                saved_creds.append(c)
        if vault_present:
            cred_source = "credential vault" + (" + legacy" if legacy_present else "")
        elif _console_creds_keyvault_backed(hub):
            cred_source = "keyvault:" + _console_credentials_ref(hub)
        elif hub.state.system_state.get("console_credentials_enc"):
            cred_source = "hub-state (encrypted)"
        else:
            cred_source = "none"
        debug = {
            "hub_credentials_saved": len(saved_creds),
            "hub_credentials_source": cred_source,
            "hub_version": (hub._hub_version_str() if hasattr(hub, "_hub_version_str") else "unknown"),
            "hub_head": await _console_hub_git_head(),
            "spokes": {
                sid: {
                    "seeded": (sid in seeded),          # did the hub push creds to it
                    "responded": (sid not in errors),   # did it answer CONSOLE_DIAGNOSTICS
                    "summary_reported": (sid in summaries),
                }
                for sid in spokes
            },
        }
        return {"diagnostics": rows, "errors": errors, "consoles": spokes,
                "summaries": summaries, "debug": debug}

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
        this explicit admin check (credentials are privileged).

        Creating credentials here is DISABLED: console logins are managed in the
        Credential Vault (Global Admin slot → ``console-auto-credentials``) and
        pulled unattended by the seed loop. ``creation_disabled`` tells the WebUI
        to show the read-only, vault-managed view (no password entry)."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        creds = await _console_load_credentials_resolved(hub)
        vault_backed = await _console_vault_secret_present(hub)
        vault_on = _vault_enabled(hub)
        local_present = _console_local_passwords_present(hub)
        # Warn (never auto-migrate/drop) when the vault is enabled but local
        # passwords still linger — nudge the operator to move them by hand.
        warning = ""
        if vault_on and local_present and not vault_backed:
            warning = ("The credential vault is enabled but local console passwords "
                       "still exist on the hub. Migrate them into the Credential Vault "
                       "(Global Admin slot → 'console-auto-credentials') manually; they "
                       "are otherwise ignored and won't be updatable here.")
        return {"credentials": [{"username": c.get("username", ""),
                                 "has_password": bool(c.get("password"))} for c in creds],
                "source": ("cred_vault" if vault_backed
                           else "keyvault" if _console_creds_keyvault_backed(hub) else "hub"),
                "read_only": True, "creation_disabled": True,
                "vault_enabled": vault_on, "local_passwords_present": local_present,
                "migrate_warning": warning,
                "local_credentials": [{"username": c.get("username", ""),
                                       "has_password": bool(c.get("password"))}
                                      for c in _console_load_local_credentials(hub)],
                "vault_bucket": _cv_admin_bucket(), "vault_secret": _CONSOLE_VAULT_SECRET}

    @app.post("/api/console/credentials")
    async def console_post_credentials(request: Request):
        """Delete-only. CREATING or CHANGING console passwords here is disabled —
        store console logins in the Credential Vault (Global Admin slot
        ``__admin__`` → secret ``console-auto-credentials``, automation-readable)
        and the seed loop pulls them unattended. But an operator MAY still REMOVE
        legacy LOCAL passwords to clean them up once the vault is in use (the
        agreed "delete but not add" rule): the submitted ``credentials`` list must
        be a subset of the existing local usernames with NO passwords supplied;
        any new username or supplied password is rejected 409. Submitting an empty
        list clears all local passwords. Never touches Key-Vault-backed creds
        (those are read-only / managed in the vault). Admin only."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        existing = _console_load_local_credentials(hub)
        existing_users = {c.get("username") for c in existing}
        keep_users = set()
        for c in (body.get("credentials") or []):
            if not isinstance(c, dict):
                continue
            u = str(c.get("username", "")).strip()
            if not u:
                continue
            if u not in existing_users:
                raise HTTPException(status_code=409, detail=(
                    "Creating passwords in the Console module is disabled. Store "
                    "console logins in the Credential Vault (Global Admin slot → "
                    "'console-auto-credentials'). You may only DELETE existing "
                    "local credentials here."))
            if str(c.get("password", "")):
                raise HTTPException(status_code=409, detail=(
                    "Changing console passwords here is disabled. Store console "
                    "logins in the Credential Vault. You may only DELETE existing "
                    "local credentials here."))
            keep_users.add(u)
        new_local = [c for c in existing if c.get("username") in keep_users]
        removed = len(existing) - len(new_local)
        if removed == 0:
            # Nothing to delete — reject rather than silently no-op so the caller
            # knows this endpoint only performs deletions now.
            raise HTTPException(status_code=409, detail=(
                "No local credentials to delete. Creating console passwords is "
                "disabled — manage them in the Credential Vault."))
        _console_save_credentials(hub, new_local)
        hub._console_creds_seeded = set()  # force re-seed with the reduced list
        # Push the effective (resolved) credential list so removals take effect on
        # the spokes immediately (vault-backed creds still win if a vault secret
        # exists; otherwise the reduced local list — possibly empty — is pushed).
        resolved = await _console_load_credentials_resolved(hub)
        for sid in (hub.get_all_spokes_by_type("console") or []):
            try:
                await hub.send_to_spoke_command(sid, "CONSOLE_SET_CREDENTIALS",
                                                {"credentials": resolved})
                _console_mark_seeded(hub, sid)
            except Exception:  # noqa: BLE001
                pass
        logger.info("console: %d local credential(s) deleted by %s",
                    removed, (sess.get("user", {}) or {}).get("username", "?"))
        return {"status": "ok", "removed": removed, "remaining": len(new_local)}

    @app.post("/api/console/credentials/to-vault")
    async def console_creds_to_vault(request: Request):
        """Migrate the current auto-identify credential list into the Credential
        Vault (Global Admin slot ``__admin__``, automation-readable) so it's
        managed alongside every other secret and pulled unattended by the seed
        loop. Requires the admin-slot pass-phrase. Admin only."""
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="admin only")
        hub = app.state.hub
        try:
            body = await request.json()
        except Exception:
            body = {}
        psk = str((body or {}).get("psk") or "")
        creds = _console_load_credentials(hub)
        if not creds:
            raise HTTPException(status_code=400, detail="no console credentials to migrate")
        import cred_vault as _cv
        try:
            await _cv.put_secret(hub, _cv.ADMIN_BUCKET, _CONSOLE_VAULT_SECRET,
                                 {"credentials": creds}, mode="hub", sec_type="console",
                                 description="Console auto-identify login list",
                                 psk=psk, actor=(sess.get("user", {}) or {}).get("username", "?"))
        except _cv.CredVaultError as e:
            raise HTTPException(status_code=400, detail=str(e))
        logger.info("console: %d credential(s) migrated into the Credential Vault by %s",
                    len(creds), (sess.get("user", {}) or {}).get("username", "?"))
        return {"status": "ok", "count": len(creds), "bucket": _cv.ADMIN_BUCKET,
                "name": _CONSOLE_VAULT_SECRET}

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
            raise HTTPException(status_code=503, detail="No spoke connected")
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

    @app.post("/api/console/{session_id}/takeover")
    async def console_takeover(session_id: str, request: Request):
        """Forcibly become the writer for an already-open, read-only serial
        console session, evicting whoever currently holds it. Requires
        edit-tier access — a stronger action than opening a plain ``rw``
        session, which /api/console/open does not itself gate."""
        sess = _session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Authentication required")
        hub = app.state.hub
        csess = hub.get_console_session(session_id)
        if not csess:
            raise HTTPException(status_code=404, detail="console session not found or expired")
        if not access.has_edit_access(sess):  # covers admin/tenant-admin too
            raise HTTPException(status_code=403, detail="write access required to take over a console")
        spoke_id = csess.get("spoke_id")
        port_id = csess.get("port_id")
        if not spoke_id or not port_id:
            raise HTTPException(status_code=400, detail="console session has no port bound")
        await _assert_port_tenant(request, spoke_id, port_id)
        try:
            r = await hub.request_response(spoke_id, "CONSOLE_TAKEOVER",
                                           {"session_id": session_id}, timeout=15.0)
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"takeover failed: {e}")
        data = _console_unwrap(r)
        if data.get("status") not in ("SUCCESS", "OK"):
            raise HTTPException(status_code=502,
                                detail=data.get("message") or "console spoke refused takeover")
        return {"status": "ok", "session_id": session_id,
                "previous_writer": data.get("previous_writer")}

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
            raise HTTPException(status_code=503, detail="No spoke connected")
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
            raise HTTPException(status_code=503, detail="No spoke connected")
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
        logger.info("CONSOLE-DIAG ws attach sid=%s found=%s token_match=%s",
                    session_id, bool(sess), bool(sess) and sess.get("ws_token") == token)
        if not sess or sess.get("ws_token") != token:
            await websocket.accept()
            await websocket.close(code=4401, reason="invalid or expired console session")
            logger.info("CONSOLE-DIAG ws REJECTED sid=%s (invalid/expired) — closed 4401", session_id)
            return
        spoke_id = sess["spoke_id"]
        queue = sess["queue"]
        sess["connected"] = True  # long-lived interactive session; TTL no longer applies
        await websocket.accept()
        logger.info("CONSOLE-DIAG ws ACCEPTED sid=%s spoke=%s qsize=%s", session_id, spoke_id, queue.qsize())
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
                            logger.info("CONSOLE-DIAG ws sid=%s CLOSING 1011 — spoke CONSOLE_ERROR: %s", session_id, item[1])
                            return
                        if kind == "disconnect":
                            await websocket.close(code=1000, reason="console closed")
                            logger.info("CONSOLE-DIAG ws sid=%s CLOSING 1000 — spoke CONSOLE_CLOSED", session_id)
                            return
                        if kind == "downgraded":
                            # Another session forced a write-lock takeover on
                            # this port — flip the browser's terminal to
                            # read-only without closing the connection.
                            try:
                                await websocket.send_text(json.dumps({"type": "downgraded"}))
                            except Exception:
                                pass
                            continue
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
                logger.info("CONSOLE-DIAG ws sid=%s first-done exc=%r", session_id, exc)
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
