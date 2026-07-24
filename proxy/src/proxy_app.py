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
import json
import logging

from aiohttp import (ClientSession, ClientTimeout, TCPConnector, WSMsgType,
                     client_exceptions, web)

logger = logging.getLogger("ProxySpoke")

# Hop-by-hop headers (RFC 7230 §6.1) — never forwarded across the proxy.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host"}

# Console-open endpoints whose JSON response carries the Phase-2 `relay` descriptor.
_CONSOLE_OPEN_PATHS = ("/api/pxmx/console", "/api/pxmx/shell")

# Streaming chunk size for request/response bodies.
_CHUNK = 64 * 1024


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
        return web.Response(status=502, text="proxy: no upstream configured")
    target = upstream.rstrip("/") + request.rel_url.raw_path_qs
    if request.headers.get("Upgrade", "").lower() == "websocket":
        # Phase 2: an edge-relayed console session (browser opened /ws/console/{id}
        # after the hub returned a `relay` descriptor we snooped) is relayed
        # straight to the spoke, keeping the hub out of the byte path. Anything
        # without a cached descriptor (or no relay_spoke_url) falls back to the
        # Phase-1 hub WS proxy.
        sid = _console_ws_session(request.path)
        if sid and spoke.relay_spoke_url:
            cached = (spoke._console_relay_cache or {}).get(sid)
            if cached and cached.get("relay"):
                return await _proxy_console_relay(request, spoke, sid, cached)
        return await _proxy_ws(request, spoke, target)
    return await _proxy_http(request, spoke, target)


def _console_ws_session(path: str):
    """Return the session id for a browser console WS path, else None.
    /ws/console/{id}, /ws/console-shell/{id}, /ws/console-serial/{id}."""
    for pfx in ("/ws/console-shell/", "/ws/console-serial/", "/ws/console/"):
        if path.startswith(pfx):
            return path[len(pfx):].split("/", 1)[0] or None
    return None


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
        return web.Response(status=502, text=f"proxy upstream error: {e}")


async def _proxy_ws(request: web.Request, spoke, target: str) -> web.StreamResponse:
    """Full-duplex WebSocket proxy (browser ↔ hub). Covers /ws/console*, /sim/ws."""
    ws_client = web.WebSocketResponse(heartbeat=None, max_msg_size=0)
    await ws_client.prepare(request)
    ws_target = target.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
    sess = _session(spoke)
    headers = _fwd_headers(request, request.remote or "")
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
        return ws
    kind = desc.get("kind") or "vnc"
    down_cmd = "SHELL_IN" if kind == "shell" else "VNC_FRAME_DOWN"
    up_type = "SHELL_OUT" if kind == "shell" else "VNC_FRAME_UP"
    disc_cmd = "SHELL_DISCONNECT" if kind == "shell" else "VNC_DISCONNECT"

    ws_browser = web.WebSocketResponse(max_msg_size=0)
    await ws_browser.prepare(request)

    relay_url = (spoke.relay_spoke_url.rstrip("/") + "/ws/console-relay/" + session_id)
    relay_url = relay_url.replace("https://", "wss://", 1).replace("http://", "ws://", 1)
    ssl_ctx = spoke.upstream_ssl() if relay_url.startswith("wss://") else None
    sess = _session(spoke)
    try:
        async with sess.ws_connect(relay_url, ssl=ssl_ctx, max_msg_size=0,
                                   autoping=True) as ws_sp:
            await ws_sp.send_json({"relay_token": desc.get("relay_token")})
            ack = await ws_sp.receive()
            ok = (ack.type == WSMsgType.TEXT
                  and (json.loads(ack.data) or {}).get("status") == "RELAY_OK")
            if not ok:
                await ws_browser.close(code=1011, reason="relay auth failed")
                return ws_browser

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
                    elif t in ("VNC_DISCONNECT", "VNC_ERROR",
                               "SHELL_DISCONNECT", "SHELL_ERROR"):
                        break
                    # *_READY carries no bytes — the RFB/PTY stream itself signals readiness.

            b2s = asyncio.ensure_future(browser_to_spoke())
            s2b = asyncio.ensure_future(spoke_to_browser())
            _, pending = await asyncio.wait({b2s, s2b},
                                            return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except client_exceptions.ClientError as e:
        logger.warning("console relay to spoke failed (%s): %s", relay_url, e)
    finally:
        spoke._console_relay_cache.pop(session_id, None)
        if not ws_browser.closed:
            await ws_browser.close()
    return ws_browser
