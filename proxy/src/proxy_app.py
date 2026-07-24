"""Edge-proxy reverse-proxy app (aiohttp): browser ↔ hub.

The browser leg is served with NO client-cert request (the caller builds a
CERT_NONE SSL context, so OpenSSL never sends a TLS CertificateRequest → no macOS
Keychain prompt). Every request is forwarded to the hub over an mTLS upstream
(the proxy presents its hub-issued spoke client cert). Both normal HTTP (streamed,
any method/body) and WebSocket upgrades (/ws/console*, /sim/ws) are proxied.

Phase 1 (Option A): the hub keeps ALL logic + the live `hub` object; this is a
dumb forwarding front door. See docs/edge-proxy-role.md.
"""
import logging

from aiohttp import (ClientSession, ClientTimeout, TCPConnector, WSMsgType,
                     client_exceptions, web)

logger = logging.getLogger("ProxySpoke")

# Hop-by-hop headers (RFC 7230 §6.1) — never forwarded across the proxy.
_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host"}

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
        return await _proxy_ws(request, spoke, target)
    return await _proxy_http(request, spoke, target)


async def _proxy_http(request: web.Request, spoke, target: str) -> web.StreamResponse:
    client_ip = request.remote or ""
    headers = _fwd_headers(request, client_ip)
    sess = _session(spoke)
    try:
        async with sess.request(
            request.method, target, headers=headers,
            data=request.content.iter_chunked(_CHUNK) if request.body_exists else None,
            allow_redirects=False,
        ) as upstream_resp:
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
            import asyncio
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
