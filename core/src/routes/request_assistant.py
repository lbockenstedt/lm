"""Bug/Feature Request Assistant — the interactive mode of the WebUI footer
"🐞 Bug/Feature Request" modal.

Same machinery as the Simulation Build Assistant's interactive sessions: the
conversation runs ENTIRELY on AppBuilder (ab/request_session.py, a read-only
GitHub Copilot CLI session over the configured repos) which interviews the
user one question at a time until a structured bug or feature spec is
complete, with a server-side gate on the required fields. The hub only gates
access and relays REQ_SESSION_* commands over the existing WS.

Filing goes through the EXISTING bug-report store (setup_admin.store_bug_report
→ hub._store_bug_report), so everything downstream is unchanged: ab's
scan_bugs files bugs for auto-fix and holds features for Global Admin
approval. AB renders the explanation (title first line, request trace on top)
and the hub stores it with the browser-captured console/HTML/screenshot.

An older AB that doesn't know REQ_SESSION_* never answers the PING, so
/available reports sessions=false and the WebUI keeps the one-shot form.
"""
import asyncio
import time

from api import HTTPException, Request, logger

from routes.setup_admin import store_bug_report


def register(app, hub, ctx):
    _caps = {"ts": 0.0, "agent": None, "sessions": False, "reason": ""}
    _submit_locks: dict = {}

    def _ab_agent():
        conns = getattr(hub, "active_connections", {}) or {}
        if hub._primary_key("ab") in conns:
            return "ab"
        for sid in conns:
            if "ab" in str(sid).lower():
                return sid
        return None

    async def _capability(agent):
        now = time.time()
        if _caps["agent"] == agent and now - _caps["ts"] < (60 if _caps["sessions"] else 20):
            return _caps["sessions"], _caps["reason"]
        ok, reason = False, ""
        try:
            res = await hub.request_response(agent, "REQ_SESSION_PING", {}, timeout=8.0)
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                ok = bool(data.get("ready"))
                reason = "; ".join(data.get("reasons") or [])
            else:
                reason = "AppBuilder does not support the request assistant (update AppBuilder)"
        except Exception as e:  # noqa: BLE001
            reason = f"capability probe failed: {e}"
        _caps.update(ts=now, agent=agent, sessions=ok, reason=reason)
        return ok, reason

    def _owner(request):
        # Any authenticated user may file a bug/feature request (same as
        # /api/bug-report). auth_type/ip are audit-only (they land in the
        # report's request trace); AB matches ownership on user + tenant.
        sess = ctx._session_user(request)
        if not sess:
            raise HTTPException(status_code=401, detail="Login required")
        u = sess.get("user") if isinstance(sess.get("user"), dict) else {}
        user = sess.get("user_id") or sess.get("username") or u.get("username") or u.get("id")
        try:
            tenant = ctx._resolve_tenant(request) or ""
        except Exception:  # noqa: BLE001
            tenant = ""
        if tenant == "default":
            tenant = ""
        try:
            admin = bool(ctx._is_admin(sess))
        except Exception:  # noqa: BLE001
            admin = False
        return {"user": str(user or "?"), "tenant": str(tenant), "admin": admin,
                "auth_type": str(u.get("auth_type") or ""), "ip": str(sess.get("client_ip") or "")}

    async def _relay(cmd, data, timeout=20.0):
        agent = _ab_agent()
        if not agent:
            raise HTTPException(status_code=409, detail="Request assistant unavailable — "
                                                        "the AppBuilder agent is not connected.")
        try:
            res = await hub.request_response(agent, cmd, data, timeout=timeout)
        except Exception as e:  # noqa: BLE001
            logger.warning("request_assistant %s relay failed: %s", cmd, e)
            raise HTTPException(status_code=502, detail=f"Request assistant error: {e}")
        out = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
        if not isinstance(out, dict):
            raise HTTPException(status_code=502, detail="Request assistant error")
        if out.get("status") != "SUCCESS":
            msg = str(out.get("message") or "Request assistant error")
            if out.get("code") == "not_found":
                raise HTTPException(status_code=404, detail="Session not found")
            if "Timed out" in msg:
                raise HTTPException(status_code=504, detail="AppBuilder did not answer in time — retry")
            raise HTTPException(status_code=409, detail=msg)
        out = dict(out)
        out.pop("status", None)
        return out

    async def _body(request):
        try:
            body = await request.json()
        except Exception:
            body = {}
        return body if isinstance(body, dict) else {}

    def _message(body):
        msg = str(body.get("message") or "").strip()
        if not msg:
            raise HTTPException(status_code=400, detail="message is required")
        return msg

    @app.get("/api/request-assistant/available")
    async def request_assistant_available(request: Request):
        """Whether the guided (interactive) bug/feature capture is usable. When
        sessions is false the WebUI shows the one-shot form."""
        agent = _ab_agent()
        if agent is None:
            return {"available": False, "sessions": False,
                    "sessions_reason": "AppBuilder agent is not connected"}
        sessions, reason = await _capability(agent)
        return {"available": True, "sessions": sessions, "sessions_reason": reason}

    @app.post("/api/request-assistant/session")
    async def request_session_start(request: Request):
        owner = _owner(request)
        body = await _body(request)
        msg = _message(body)
        context = body.get("context") if isinstance(body.get("context"), dict) else {}
        context = dict(context)
        rtype = str(body.get("type") or "").strip().lower()
        if rtype in ("bug", "feature"):
            context["type"] = rtype
        if body.get("console_errors"):
            context["console_errors"] = str(body.get("console_errors"))[:4000]
        out = await _relay("REQ_SESSION_START", {"owner": owner, "message": msg, "context": context})
        logger.info("request_assistant: session %s started by %s", out.get("session_id"), owner["user"])
        return out

    @app.get("/api/request-assistant/session/{session_id}")
    async def request_session_poll(session_id: str, request: Request, since: int = 0):
        owner = _owner(request)
        return await _relay("REQ_SESSION_POLL", {"owner": owner, "session_id": session_id, "since": since})

    @app.post("/api/request-assistant/session/{session_id}/reply")
    async def request_session_reply(session_id: str, request: Request):
        owner = _owner(request)
        msg = _message(await _body(request))
        return await _relay("REQ_SESSION_REPLY", {"owner": owner, "session_id": session_id, "message": msg})

    @app.post("/api/request-assistant/session/{session_id}/cancel")
    async def request_session_cancel(session_id: str, request: Request):
        owner = _owner(request)
        return await _relay("REQ_SESSION_CANCEL", {"owner": owner, "session_id": session_id})

    @app.post("/api/request-assistant/session/{session_id}/submit")
    async def request_session_submit(session_id: str, request: Request):
        """File the finished report. AB checks the required-field gate and
        renders the explanation; the hub stores it through the same store as
        /api/bug-report (with the browser's console/HTML/screenshot), then
        tells AB the report id. Bugs go to AB auto-fix; features wait for
        Global Admin approval — exactly as one-shot reports do."""
        owner = _owner(request)
        body = await _body(request)
        lock = _submit_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            out = await _relay("REQ_SESSION_SUBMIT", {"owner": owner, "session_id": session_id},
                               timeout=30.0)
            report = out.pop("report", None)
            if not isinstance(report, dict):
                # Already stored on an earlier submit.
                return out
            rtype = str(report.get("type") or "bug")
            browser_ctx = body.get("context") if isinstance(body.get("context"), dict) else {}
            data = {
                "explanation": str(report.get("explanation") or ""),
                "severity": str(report.get("severity") or "medium"),
                "type": rtype if rtype in ("bug", "feature") else "bug",
                "title": str(report.get("title") or ""),
                "request_spec": report.get("spec") if isinstance(report.get("spec"), dict) else {},
                "assistant_session": session_id,
                "console_logs": body.get("console_logs") or "",
                "html": body.get("html") or "",
                "screenshot": body.get("screenshot") or "",
                "context": {**browser_ctx, "source": "request-assistant",
                            "assistant_session": session_id},
            }
            if not data["explanation"].strip():
                raise HTTPException(status_code=502, detail="AppBuilder returned an empty report")
            rid = await store_bug_report(hub, ctx, request, data)
            try:
                out = await _relay("REQ_SESSION_FILED", {"owner": owner, "session_id": session_id,
                                                         "report_id": rid})
            except HTTPException as e:
                # The report is stored; AB only misses the confirmation event.
                logger.warning("request_assistant: FILED relay for %s failed: %s", session_id, e.detail)
            _submit_locks.pop(session_id, None)
        logger.info("request_assistant: session %s filed by %s as %s report %s",
                    session_id, owner["user"], data["type"], rid)
        return {**out, "report_id": rid, "type": data["type"]}
