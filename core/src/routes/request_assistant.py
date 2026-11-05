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
# asyncio provides per-session locks so a report is filed only once.
import asyncio
# time stamps the cached capability probe so it can be refreshed.
import time

# FastAPI request/error types plus the hub-wide logger, re-exported by the api module.
from api import HTTPException, Request, logger
# Finds the connected AppBuilder (AB) agent that runs the assistant sessions.
from routes.console_llm_identify import find_ab

# Same bug-report store the one-shot form uses, so downstream handling is unchanged.
from routes.setup_admin import store_bug_report


def register(app, hub, ctx):
    """Register the Bug/Feature Request Assistant API routes on the Hub app.

    Args: app is the FastAPI app, hub is the running hub, ctx carries shared auth/tenant helpers.
    """
    # Cached result of the last capability probe: when, which agent, and whether sessions work.
    _caps = {"ts": 0.0, "agent": None, "sessions": False, "reason": ""}
    # One asyncio lock per session id so concurrent submits cannot file the report twice.
    _submit_locks: dict = {}

    async def _capability(agent):
        """Ask AB whether it supports interactive request sessions, with a short cache.

        Returns a (supported, reason) tuple; reason explains why it is not supported.
        """
        # Current time, used to judge cache freshness.
        now = time.time()
        # Reuse the cached answer for the same agent: 60s when supported, 20s when not, so a
        # freshly updated AB is noticed quickly.
        if _caps["agent"] == agent and now - _caps["ts"] < (60 if _caps["sessions"] else 20):
            return _caps["sessions"], _caps["reason"]
        # Assume unsupported until the probe says otherwise.
        ok, reason = False, ""
        try:
            # Ping AB; an older AB never answers, which ends in a timeout exception below.
            res = await hub.request_response(agent, "REQ_SESSION_PING", {}, timeout=8.0)
            # Unwrap the reply to the inner data dict (some replies nest it under payload.data).
            data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
            # SUCCESS means AB understands the command; "ready" says whether sessions can start now.
            if isinstance(data, dict) and data.get("status") == "SUCCESS":
                ok = bool(data.get("ready"))
                reason = "; ".join(data.get("reasons") or [])
            # AB answered but not with SUCCESS, so it is an older version.
            else:
                reason = "AppBuilder does not support the request assistant (update AppBuilder)"
        # Timeout or relay error: treat as unsupported and keep the reason for the UI.
        except Exception as e:  # noqa: BLE001
            reason = f"capability probe failed: {e}"
        # Cache this probe result and return it.
        _caps.update(ts=now, agent=agent, sessions=ok, reason=reason)
        return ok, reason

    def _owner(request):
        """Identify the requester for AB: user, tenant, admin flag, plus audit-only fields.

        Raises 401 when nobody is logged in.
        """
        # Any authenticated user may file a bug/feature request (same as
        # /api/bug-report). auth_type/ip are audit-only (they land in the
        # report's request trace); AB matches ownership on user + tenant.
        sess = ctx._session_user(request)
        # Requests are filed on behalf of a user, so an anonymous caller is refused.
        if not sess:
            raise HTTPException(status_code=401, detail="Login required")
        # The session may carry a nested user dict; use it as a fallback source of identity.
        u = sess.get("user") if isinstance(sess.get("user"), dict) else {}
        # Pick the first available user identifier.
        user = sess.get("user_id") or sess.get("username") or u.get("username") or u.get("id")
        # Resolve the tenant being viewed; any lookup error just means no tenant.
        try:
            tenant = ctx._resolve_tenant(request) or ""
        except Exception:  # noqa: BLE001
            tenant = ""
        # The "default" tenant is stored as an empty tenant id.
        if tenant == "default":
            tenant = ""
        # Check admin status defensively; failure means "not admin".
        try:
            admin = bool(ctx._is_admin(sess))
        except Exception:  # noqa: BLE001
            admin = False
        # Return everything as strings so AB gets a predictable payload.
        return {"user": str(user or "?"), "tenant": str(tenant), "admin": admin,
                "auth_type": str(u.get("auth_type") or ""), "ip": str(sess.get("client_ip") or "")}

    async def _relay(cmd, data, timeout=20.0):
        """Send ``cmd`` to the AppBuilder agent and return its reply data.

        Maps AB failures to HTTP errors: 409 not connected/refused, 404 unknown session, 504
        timeout, 502 relay failure.
        """
        # Find the AppBuilder agent; without it no assistant session can run.
        agent = find_ab(hub)
        if not agent:
            raise HTTPException(status_code=409, detail="Request assistant unavailable — "
                                                        "the AppBuilder agent is not connected.")
        # Send the command and wait for AB's reply.
        try:
            res = await hub.request_response(agent, cmd, data, timeout=timeout)
        # Connection or relay failure: log it and return 502 (bad upstream).
        except Exception as e:  # noqa: BLE001
            logger.warning("request_assistant %s relay failed: %s", cmd, e)
            raise HTTPException(status_code=502, detail=f"Request assistant error: {e}")
        # Unwrap the reply to the inner data dict.
        out = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
        # Anything that is not a dict is an unusable reply.
        if not isinstance(out, dict):
            raise HTTPException(status_code=502, detail="Request assistant error")
        # AB reported failure; translate known cases into specific HTTP codes.
        if out.get("status") != "SUCCESS":
            msg = str(out.get("message") or "Request assistant error")
            if out.get("code") == "not_found":
                raise HTTPException(status_code=404, detail="Session not found")
            if "Timed out" in msg:
                raise HTTPException(status_code=504, detail="AppBuilder did not answer in time — retry")
            raise HTTPException(status_code=409, detail=msg)
        # Copy the reply and drop the internal status field before returning it to the browser.
        out = dict(out)
        out.pop("status", None)
        return out

    async def _body(request):
        """Return the request's JSON body as a dict, or ``{}`` if missing or malformed."""
        # Parse JSON; a bad body falls back to an empty dict.
        try:
            body = await request.json()
        except Exception:
            body = {}
        # Ignore non-object JSON (lists, strings) by treating it as empty.
        return body if isinstance(body, dict) else {}

    def _message(body):
        """Return the trimmed "message" field from the body, raising 400 if it is blank."""
        msg = str(body.get("message") or "").strip()
        if not msg:
            raise HTTPException(status_code=400, detail="message is required")
        return msg

    # Tell the WebUI whether the interactive assistant can be used.
    @app.get("/api/request-assistant/available")
    async def request_assistant_available(request: Request):
        """Whether the guided (interactive) bug/feature capture is usable. When
        sessions is false the WebUI shows the one-shot form."""
        # Without a connected AppBuilder, neither mode is available.
        agent = find_ab(hub)
        if agent is None:
            return {"available": False, "sessions": False,
                    "sessions_reason": "AppBuilder agent is not connected"}
        # AB is connected; probe (or reuse the cached answer) for interactive session support.
        sessions, reason = await _capability(agent)
        return {"available": True, "sessions": sessions, "sessions_reason": reason}

    # Start a new assistant conversation.
    @app.post("/api/request-assistant/session")
    async def request_session_start(request: Request):
        """Start an assistant session with the user's first message and return AB's reply."""
        # Identify the caller, read the body, and require a first message.
        owner = _owner(request)
        body = await _body(request)
        msg = _message(body)
        # Copy the optional browser context so the edits below do not mutate the request body.
        context = body.get("context") if isinstance(body.get("context"), dict) else {}
        context = dict(context)
        # Pass a valid "bug"/"feature" type through so AB skips asking for it.
        rtype = str(body.get("type") or "").strip().lower()
        if rtype in ("bug", "feature"):
            context["type"] = rtype
        # Include console errors, capped at 4000 chars to keep the relay payload small.
        if body.get("console_errors"):
            context["console_errors"] = str(body.get("console_errors"))[:4000]
        # Start the session on AB, log it, and return AB's reply (session id and first question).
        out = await _relay("REQ_SESSION_START", {"owner": owner, "message": msg, "context": context})
        logger.info("request_assistant: session %s started by %s", out.get("session_id"), owner["user"])
        return out

    # Fetch new messages in a session.
    @app.get("/api/request-assistant/session/{session_id}")
    async def request_session_poll(session_id: str, request: Request, since: int = 0):
        """Return session messages after index ``since`` (polled by the WebUI)."""
        # Identify the caller so AB can confirm they own the session, then relay the poll.
        owner = _owner(request)
        return await _relay("REQ_SESSION_POLL", {"owner": owner, "session_id": session_id, "since": since})

    # Send the user's answer to the assistant's question.
    @app.post("/api/request-assistant/session/{session_id}/reply")
    async def request_session_reply(session_id: str, request: Request):
        """Relay the user's reply message to an assistant session."""
        # Identify the caller and require a non-empty message, then relay it.
        owner = _owner(request)
        msg = _message(await _body(request))
        return await _relay("REQ_SESSION_REPLY", {"owner": owner, "session_id": session_id, "message": msg})

    # Abandon a session.
    @app.post("/api/request-assistant/session/{session_id}/cancel")
    async def request_session_cancel(session_id: str, request: Request):
        """Cancel an assistant session on AB."""
        # Identify the caller, then relay the cancel.
        owner = _owner(request)
        return await _relay("REQ_SESSION_CANCEL", {"owner": owner, "session_id": session_id})

    @app.post("/api/request-assistant/session/{session_id}/submit")
    async def request_session_submit(session_id: str, request: Request):
        """File the finished report. AB checks the required-field gate and
        renders the explanation; the hub stores it through the same store as
        /api/bug-report (with the browser's console/HTML/screenshot), then
        tells AB the report id. Bugs go to AB auto-fix; features wait for
        Global Admin approval — exactly as one-shot reports do."""
        # Identify the caller and read the browser-captured extras (console, HTML, screenshot).
        owner = _owner(request)
        body = await _body(request)
        # Serialise submits of the same session so a double click cannot file two reports.
        lock = _submit_locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            # Ask AB to finalise; AB checks required fields and returns the rendered report.
            out = await _relay("REQ_SESSION_SUBMIT", {"owner": owner, "session_id": session_id},
                               timeout=30.0)
            report = out.pop("report", None)
            if not isinstance(report, dict):
                # Already stored on an earlier submit.
                return out
            # Normalise the type, then take the browser context if one was sent.
            rtype = str(report.get("type") or "bug")
            browser_ctx = body.get("context") if isinstance(body.get("context"), dict) else {}
            # Build the record in the exact shape the one-shot bug-report store expects.
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
            # An empty explanation means AB produced nothing usable, so do not store it.
            if not data["explanation"].strip():
                raise HTTPException(status_code=502, detail="AppBuilder returned an empty report")
            # Store the report and get its id.
            rid = await store_bug_report(hub, ctx, request, data)
            # Tell AB the report id so it marks the session filed.
            try:
                out = await _relay("REQ_SESSION_FILED", {"owner": owner, "session_id": session_id,
                                                         "report_id": rid})
            except HTTPException as e:
                # The report is stored; AB only misses the confirmation event.
                logger.warning("request_assistant: FILED relay for %s failed: %s", session_id, e.detail)
            # The session is done, so its lock is no longer needed.
            _submit_locks.pop(session_id, None)
        # Log the filing and return AB's reply plus the stored report id and type.
        logger.info("request_assistant: session %s filed by %s as %s report %s",
                    session_id, owner["user"], data["type"], rid)
        return {**out, "report_id": rid, "type": data["type"]}
