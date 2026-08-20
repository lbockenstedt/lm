"""Edge-proxy reverse-proxy app (aiohttp): browser ↔ hub.

The browser leg is served with NO client-cert request (the caller builds a
CERT_NONE SSL context, so OpenSSL never sends a TLS CertificateRequest → no macOS
Keychain prompt). Every request is forwarded to the hub over an mTLS upstream
(the proxy presents its hub-issued spoke client cert). Both normal HTTP (streamed,
any method/body) and WebSocket upgrades (/ws/console*, /sim/ws) are proxied.

Phase 1 (Option A): the hub keeps ALL logic + the live `hub` object; this is a
dumb forwarding front door. See docs/edge-proxy-role.md.
"""
import asyncio
import base64
import html
import json
import logging

from aiohttp import (ClientSession, ClientTimeout, TCPConnector, WSMsgType,
                     client_exceptions, web)

logger = logging.getLogger("ProxySpoke")

# Hop-by-hop headers (RFC 7230 §6.1) — never forwarded across the proxy.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host"}

# WebSocket handshake headers the browser sends that MUST NOT be forwarded to
# aiohttp's ClientSession.ws_connect(): aiohttp generates its own Sec-WebSocket-*
# handshake for the upstream leg. Forwarding the browser's values makes aiohttp
# emit a corrupt/duplicated handshake — the upstream opens but the first data
# frame breaks the connection, which the browser sees as an immediate console
# disconnect.
_WS_HANDSHAKE = {"sec-websocket-key", "sec-websocket-version",
                 "sec-websocket-extensions", "sec-websocket-accept",
                 "sec-websocket-protocol"}

# Console-open endpoints whose JSON response carries the Phase-2 `relay` descriptor.
_CONSOLE_OPEN_PATHS = ("/api/pxmx/console", "/api/pxmx/shell")

# Streaming chunk size for request/response bodies.
_CHUNK = 64 * 1024

# How often the friendly "hub unavailable" page reloads itself (seconds).
_REFRESH_SECS = 60

# Self-contained "Hub is not accessible" splash — styled to match the hub login
# page (WebUI/index.html): dark #1F2531 canvas, #263040 card, HPE-green accent,
# HPE wordmark. Served by the edge proxy when the hub upstream is unreachable
# (e.g. rebooting) so the browser sees a branded, auto-refreshing page instead of
# a raw gateway error. Placeholders: __SECS__ (countdown) and __DETAIL__ (escaped
# technical detail shown in the footer). No external assets (offline-safe).
_HUB_DOWN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="__SECS__">
<title>Lab Manager | Hub unavailable</title>
<style>
  :root { --accent:#01A982; }
  * { box-sizing:border-box; }
  html,body { height:100%; margin:0; }
  body {
    background-color:#1F2531;
    color:#e2e8f0;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    min-height:100vh; padding:24px;
  }
  .brand { text-align:center; margin-bottom:32px; }
  .brand svg { height:32px; width:auto; display:block; margin:0 auto 16px; color:#fff; }
  .brand h1 { font-size:1.5rem; font-weight:700; letter-spacing:-.01em; color:#fff; margin:0; }
  .brand p { color:#94a3b8; font-size:.875rem; margin:.25rem 0 0; }
  .card {
    width:100%; max-width:24rem; background:#263040;
    border:1px solid #334155; border-radius:.75rem;
    box-shadow:0 25px 50px -12px rgba(0,0,0,.5);
    padding:2rem; text-align:center;
  }
  .spinner {
    width:40px; height:40px; margin:0 auto 20px;
    border:3px solid rgba(1,169,130,.25); border-top-color:var(--accent);
    border-radius:50%; animation:spin 1s linear infinite;
  }
  @keyframes spin { to { transform:rotate(360deg); } }
  .card h2 { font-size:1.05rem; font-weight:700; color:#fff; margin:0 0 .5rem; }
  .card .sub { color:#94a3b8; font-size:.85rem; margin:0; }
  .card .countdown { color:var(--accent); font-weight:700; }
  .retry {
    display:inline-block; margin-top:1.25rem; padding:.55rem 1.1rem;
    background:var(--accent); color:#fff; font-weight:700; font-size:.8rem;
    border:none; border-radius:.5rem; text-decoration:none; cursor:pointer;
  }
  .retry:hover { background:#008c6a; }
  footer {
    margin-top:1.5rem; max-width:36rem; width:100%; text-align:center;
  }
  footer .label {
    color:#64748b; font-size:.65rem; text-transform:uppercase;
    letter-spacing:.08em; font-weight:700; margin-bottom:.4rem;
  }
  footer .detail {
    color:#94a3b8; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:.72rem; word-break:break-word; line-height:1.4;
    background:rgba(0,0,0,.2); border:1px solid #334155; border-radius:.4rem;
    padding:.6rem .75rem;
  }
</style>
</head>
<body>
  <div class="brand">
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 180 504 144" role="img" aria-label="HPE"><path fill="#01A982" d="M391.2 261.27v35.46H504V324H362.4v-90H504v27.27H391.2Z"/><path fill="currentColor" d="M276.67 180h-89.25v144h28.8v-36.6h60c37.92 0 59.7-21.6 59.7-53.4 0-32.01-21.78-54-59.25-54Zm-1.88 79.8h-58.57v-52.54h58.57c22.68 0 31.28 10.48 31.28 26.73 0 16.08-8.6 25.8-31.28 25.8Zm116.41-39.18h-28.8V180H504v27.27H391.2v13.36ZM151.2 180v144h-28.8v-59.02H28.8V324H0V180h28.8v57.38h93.6V180h28.8Z"/></svg>
    <h1>Lab Manager</h1>
    <p>Hub</p>
  </div>
  <div class="card">
    <div class="spinner"></div>
    <h2>LabManager Hub is not accessible</h2>
    <p class="sub">Refreshing in <span class="countdown" id="cd">__SECS__</span> seconds&hellip;</p>
    <a class="retry" href="javascript:location.reload()">Retry now</a>
  </div>
  <footer>
    <div class="label">Technical detail</div>
    <div class="detail">__DETAIL__</div>
  </footer>
<script>
  (function () {
    var n = __SECS__;
    var el = document.getElementById('cd');
    setInterval(function () {
      n -= 1;
      if (n <= 0) { location.reload(); return; }
      if (el) el.textContent = n;
    }, 1000);
  })();
</script>
</body>
</html>"""


def _hub_unavailable(request: web.BaseRequest, detail: str) -> web.Response:
    """503 response for an unreachable hub upstream. Browser navigations (Accept:
    text/html) get the branded auto-refreshing splash; API/XHR/other callers get a
    short text body. Both carry Retry-After so clients back off politely."""
    secs = _REFRESH_SECS
    headers = {"Retry-After": str(secs), "Cache-Control": "no-store"}
    accepts_html = "text/html" in (request.headers.get("Accept") or "")
    if accepts_html and request.method in ("GET", "HEAD"):
        body = (_HUB_DOWN_HTML
                .replace("__SECS__", str(secs))
                .replace("__DETAIL__", html.escape(detail or "connection refused")))
        return web.Response(status=503, text=body, content_type="text/html",
                            headers=headers)
    return web.Response(status=503, headers=headers,
                        text=f"LabManager Hub is not accessible: {detail}")


def build_proxy_app(spoke) -> web.Application:
    """aiohttp app with a single catch-all route that forwards to the hub."""
    app = web.Application(client_max_size=0)  # 0 = unlimited (large uploads stream)
    app["spoke"] = spoke
    app.router.add_route("*", "/{tail:.*}", _dispatch)
    app.on_cleanup.append(_close_session)
    return app


async def _close_session(app) -> None:
    sess = app.get("_session")
    if sess is not None and not sess.closed:
        await sess.close()


def _session(spoke) -> ClientSession:
    """Lazily build the shared upstream client session bound to the spoke's
    mTLS/verify SSL context (so the proxy presents its client cert to the hub)."""
    app = spoke._proxy_app
    sess = app.get("_session")
    if sess is None or sess.closed:
        connector = TCPConnector(ssl=spoke.upstream_ssl(), limit=0)
        sess = ClientSession(connector=connector,
                             timeout=ClientTimeout(total=None, sock_connect=15),
                             auto_decompress=False)  # pass bytes through verbatim
        app["_session"] = sess
    return sess


def _fwd_headers(request: web.BaseRequest, client_ip: str) -> dict:
    """Copy client headers minus hop-by-hop, and stamp the X-Forwarded-* chain so
    the hub sees the REAL client IP (its per-IP login lockout depends on this)."""
    headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP}
    prior = request.headers.get("X-Forwarded-For")
    headers["X-Forwarded-For"] = f"{prior}, {client_ip}" if prior else client_ip
    headers["X-Forwarded-Proto"] = request.scheme
    host = request.headers.get("Host")
    if host:
        headers["X-Forwarded-Host"] = host
    return headers


async def _dispatch(request: web.Request) -> web.StreamResponse:
    spoke = request.app["spoke"]
    upstream = spoke.upstream_url
    if not upstream:
        return _hub_unavailable(request, "no upstream configured")
    target = upstream.rstrip("/") + request.rel_url.raw_path_qs
    if request.headers.get("Upgrade", "").lower() == "websocket":
        # Phase 2: an edge-relayed console session (browser opened /ws/console/{id}
        # after the hub returned a `relay` descriptor we snooped) is relayed
        # straight to the spoke, keeping the hub out of the byte path — but ONLY
        # when this proxy is tenant-local to the target (see
        # _tenant_allows_shortcut). Anything without a cached descriptor, no
        # relay_spoke_url, or a cross-tenant/shared/unassigned proxy falls back to
        # the Phase-1 hub WS proxy.
        sid = _console_ws_session(request.path)
        if sid and spoke.relay_spoke_url:
            cached = (spoke._console_relay_cache or {}).get(sid)
            if cached and cached.get("relay") and _tenant_allows_shortcut(spoke, cached["relay"]):
                relayed = await _proxy_console_relay(request, spoke, sid, cached)
                # None → the spoke relay leg was unavailable (e.g. the console
                # role's listener is off): fall through to the hub WS proxy so the
                # console still works, just via the hub.
                if relayed is not None:
                    return relayed
        return await _proxy_ws(request, spoke, target)
    return await _proxy_http(request, spoke, target)


def _console_ws_session(path: str):
    """Return the session id for a browser console WS path, else None.
    /ws/console/{id}, /ws/console-shell/{id}, /ws/console-serial/{id}."""
    for pfx in ("/ws/console-shell/", "/ws/console-serial/", "/ws/console/"):
        if path.startswith(pfx):
            return path[len(pfx):].split("/", 1)[0] or None
    return None


def _tenant_allows_shortcut(spoke, desc: dict) -> bool:
    """Tenant gate for the Phase-2 console shortcut. A proxy relays a console
    locally (hub out of the byte path) ONLY when it is assigned to a specific,
    non-shared tenant AND the target spoke belongs to that same tenant. A shared
    or unassigned proxy — and any cross-tenant target — falls through to the hub.
    All tenant assignment is authored on the hub; the proxy just compares the
    tenant it was told it owns against the tenant the hub stamped on the
    descriptor."""
    my_tenant = getattr(spoke, "tenant_id", "") or ""
    if not my_tenant or getattr(spoke, "tenant_shared", False):
        return False
    return (desc.get("tenant_id") or "") == my_tenant


async def _proxy_http(request: web.Request, spoke, target: str) -> web.StreamResponse:
    client_ip = request.remote or ""
    headers = _fwd_headers(request, client_ip)
    sess = _session(spoke)
    snoop = request.method == "POST" and request.path in _CONSOLE_OPEN_PATHS
    try:
        async with sess.request(
            request.method, target, headers=headers,
            data=request.content.iter_chunked(_CHUNK) if request.body_exists else None,
            allow_redirects=False,
        ) as upstream_resp:
            if snoop:
                # Buffer the small console-open JSON, cache its `relay` descriptor
                # (+ ws_token for browser-leg auth), then forward it verbatim.
                body = await upstream_resp.read()
                try:
                    obj = json.loads(body)
                    rel = obj.get("relay") if isinstance(obj, dict) else None
                    sid = (rel or {}).get("session_id")
                    if sid:
                        spoke._console_relay_cache[sid] = {
                            "relay": rel, "ws_token": obj.get("ws_token")}
                except Exception:  # noqa: BLE001 — gzipped/odd body: skip caching, still forward
                    pass
                return web.Response(
                    status=upstream_resp.status, body=body,
                    headers={k: v for k, v in upstream_resp.headers.items()
                             if k.lower() not in _HOP and k.lower() != "content-length"})
            resp = web.StreamResponse(status=upstream_resp.status,
                                      headers={k: v for k, v in upstream_resp.headers.items()
                                               if k.lower() not in _HOP})
            await resp.prepare(request)
            async for chunk in upstream_resp.content.iter_chunked(_CHUNK):
                await resp.write(chunk)
            await resp.write_eof()
            return resp
    except client_exceptions.ClientError as e:
        logger.warning("proxy upstream error %s %s: %s", request.method, target, e)
        return _hub_unavailable(request, f"{type(e).__name__}: {e}")
    except asyncio.TimeoutError:
        logger.warning("proxy upstream timeout %s %s", request.method, target)
        return _hub_unavailable(request, "upstream connect timed out")


async def _proxy_ws(request: web.Request, spoke, target: str) -> web.StreamResponse:
    """Full-duplex WebSocket proxy (browser ↔ hub). Covers /ws/console*, /sim/ws."""
    ws_client = web.WebSocketResponse(heartbeat=None, max_msg_size=0)
    await ws_client.prepare(request)
    ws_target = target.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
    sess = _session(spoke)
    headers = _fwd_headers(request, request.remote or "")
    # Strip the browser's WebSocket handshake headers — aiohttp mints its own for
    # the upstream leg (see _WS_HANDSHAKE). Leaving them in opens the upstream but
    # breaks it on the first data frame (browser sees an immediate disconnect).
    headers = {k: v for k, v in headers.items() if k.lower() not in _WS_HANDSHAKE}
    try:
        async with sess.ws_connect(ws_target, headers=headers, max_msg_size=0,
                                   autoping=True) as ws_up:
            async def pump(src, dst):
                async for msg in src:
                    if msg.type == WSMsgType.TEXT:
                        await dst.send_str(msg.data)
                    elif msg.type == WSMsgType.BINARY:
                        await dst.send_bytes(msg.data)
                    elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                        break
                    elif msg.type == WSMsgType.ERROR:
                        break
            b2h = asyncio.ensure_future(pump(ws_client, ws_up))
            h2b = asyncio.ensure_future(pump(ws_up, ws_client))
            done, pending = await asyncio.wait({b2h, h2b},
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except client_exceptions.ClientError as e:
        logger.warning("proxy ws upstream error %s: %s", ws_target, e)
    finally:
        if not ws_client.closed:
            await ws_client.close()
    return ws_client


async def _proxy_console_relay(request: web.Request, spoke, session_id: str,
                               cached: dict) -> web.StreamResponse:
    """Phase 2 edge relay: browser console WS ↔ spoke ``/ws/console-relay`` ↔ agent
    ↔ Proxmox, with the hub OUT of the byte path. The browser speaks raw noVNC
    bytes; we wrap them as ``VNC_FRAME_DOWN`` and unwrap ``VNC_FRAME_UP`` back to
    bytes. (Shell/serial reuse the same shape once their brokers emit a descriptor.)"""
    desc = cached.get("relay") or {}
    # Browser-leg auth: the same ws_token the hub minted (mirrors the hub console WS).
    want = cached.get("ws_token")
    got = request.query.get("token")
    if want and got != want:
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        await ws.close(code=4401, reason="invalid or expired console session")
        return ws  # authoritative reject (NOT a fall-back)
    kind = desc.get("kind") or "vnc"
    down_cmd, up_type, disc_cmd = {
        "shell":  ("SHELL_IN",     "SHELL_OUT",      "SHELL_DISCONNECT"),
        "serial": ("CONSOLE_DATA", "CONSOLE_DATA_UP", "CONSOLE_CLOSE"),
    }.get(kind, ("VNC_FRAME_DOWN", "VNC_FRAME_UP", "VNC_DISCONNECT"))
    disconnect_types = ("VNC_DISCONNECT", "VNC_ERROR", "SHELL_DISCONNECT",
                        "SHELL_ERROR", "CONSOLE_CLOSE", "CONSOLE_CLOSED", "CONSOLE_ERROR")

    relay_url = (spoke.relay_spoke_url.rstrip("/") + "/ws/console-relay/" + session_id)
    relay_url = relay_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
    ssl_ctx = spoke.upstream_ssl() if relay_url.startswith("wss://") else None
    sess = _session(spoke)

    # Connect to the spoke FIRST (before committing the browser WS) so an
    # unavailable relay endpoint falls back to the hub proxy (return None).
    try:
        ws_sp = await sess.ws_connect(relay_url, ssl=ssl_ctx, max_msg_size=0, autoping=True)
    except (client_exceptions.ClientError, OSError, asyncio.TimeoutError) as e:
        logger.info("console relay to spoke unavailable (%s): %s — hub fallback", relay_url, e)
        return None
    ws_browser = None
    try:
        await ws_sp.send_json({"relay_token": desc.get("relay_token")})
        ack = await ws_sp.receive()
        ok = (ack.type == WSMsgType.TEXT
              and (json.loads(ack.data) or {}).get("status") == "RELAY_OK")
        if not ok:
            return None  # relay refused → hub fallback (finally closes ws_sp)

        ws_browser = web.WebSocketResponse(max_msg_size=0)
        await ws_browser.prepare(request)

        async def browser_to_spoke():
            async for msg in ws_browser:
                if msg.type == WSMsgType.BINARY:
                    await ws_sp.send_json({"type": down_cmd,
                                           "data": {"data": base64.b64encode(msg.data).decode()}})
                elif msg.type == WSMsgType.TEXT:
                    await ws_sp.send_json({"type": down_cmd,
                                           "data": {"data": base64.b64encode(msg.data.encode()).decode()}})
                elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING,
                                  WSMsgType.CLOSED, WSMsgType.ERROR):
                    break
            try:
                await ws_sp.send_json({"type": disc_cmd, "data": {}})
            except Exception:  # noqa: BLE001
                pass

        async def spoke_to_browser():
            async for msg in ws_sp:
                if msg.type != WSMsgType.TEXT:
                    if msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING,
                                    WSMsgType.CLOSED, WSMsgType.ERROR):
                        break
                    continue
                try:
                    obj = json.loads(msg.data)
                except Exception:  # noqa: BLE001
                    continue
                t = obj.get("type")
                d = obj.get("data") or {}
                if t == up_type:
                    try:
                        await ws_browser.send_bytes(base64.b64decode(d.get("data") or ""))
                    except Exception:  # noqa: BLE001
                        break
                elif t in disconnect_types:
                    break
                # *_READY carries no bytes — the RFB/PTY stream itself signals readiness.

        b2s = asyncio.ensure_future(browser_to_spoke())
        s2b = asyncio.ensure_future(spoke_to_browser())
        _, pending = await asyncio.wait({b2s, s2b}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
    except client_exceptions.ClientError as e:
        logger.warning("console relay to spoke failed (%s): %s", relay_url, e)
    finally:
        spoke._console_relay_cache.pop(session_id, None)
        try:
            await ws_sp.close()
        except Exception:  # noqa: BLE001
            pass
        if ws_browser is not None and not ws_browser.closed:
            await ws_browser.close()
    return ws_browser
