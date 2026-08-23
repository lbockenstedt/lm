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
import ipaddress
import json
import logging
import os
import re

from aiohttp import (ClientSession, ClientTimeout, DummyCookieJar, TCPConnector,
                     WSMsgType, client_exceptions, web)
from multidict import CIMultiDict

try:  # shared scanner-signature classifier (single source of truth with the hub)
    from security.probe_signatures import looks_like_probe
except ImportError:  # pragma: no cover - packaging layout fallback
    from core.src.security.probe_signatures import looks_like_probe

try:  # node-side operator canary endpoints (generic engine; inert until hub push)
    from security import node_canary as _node_canary
except ImportError:  # pragma: no cover - packaging layout fallback
    from core.src.security import node_canary as _node_canary

logger = logging.getLogger("ProxySpoke")


def _load_trusted_proxies() -> tuple:
    """Parse ``LM_TRUSTED_PROXIES`` (comma/space-separated IPs/CIDRs) into a
    tuple of ``ipaddress`` networks. Empty when unset.

    Mirrors the hub's ``_client_ip`` discipline (core/src/api.py): this edge is
    internet-facing, so ``X-Forwarded-For`` is CLIENT-SETTABLE and must NOT be
    trusted unless the immediate TCP peer is a configured front load balancer /
    CDN that stamped it. Fail-safe: with no trusted proxies configured, XFF is
    ignored and the TCP peer is used."""
    raw = os.environ.get("LM_TRUSTED_PROXIES", "").strip()
    nets = []
    if raw:
        for tok in re.split(r"[,\s]+", raw):
            tok = tok.strip()
            if not tok:
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                logger.warning("LM_TRUSTED_PROXIES: skipping unparseable entry %r", tok)
    return tuple(nets)


_TRUSTED_PROXY_NETS = _load_trusted_proxies()


def _ip_in_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _TRUSTED_PROXY_NETS)

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

# WebSocket keepalive cadence (seconds) for the console/sim relays. Enables
# aiohttp's protocol PING/PONG on every leg the proxy terminates so idle
# tunnels are not dropped by an intermediary's idle timeout, and a dead peer is
# detected (aiohttp closes the leg → the browser sees a clean disconnect). Well
# under common idle timeouts (nginx 60s, Azure LB 4min).
_WS_HEARTBEAT = 25.0

# App-level idle ping cadence (seconds) for the edge console relay, where the
# hub is OUT of the byte path and so can't send its own control "ping". A quiet
# session still gets a visible frame the browser can see, feeding its liveness
# watchdog. Kept just under the protocol heartbeat so a live tunnel never looks
# idle to the browser.
_WS_APP_PING_SECS = 20.0

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
        # DummyCookieJar: a reverse proxy MUST be cookie-stateless. aiohttp's
        # default ClientSession carries a shared CookieJar — with ONE session
        # reused for every browser, the hub's Set-Cookie (lm_session) from user
        # A would be stored in that jar and then injected onto EVERY other user's
        # upstream request, so whoever logged in first "owns" the jar and all
        # users behind the proxy become that identity (and each new login flips
        # the jar, logging the others out). The browser's own Cookie header is
        # already forwarded verbatim (_fwd_headers) and Set-Cookie flows back
        # verbatim, so the proxy must hold NO cookie state of its own.
        sess = ClientSession(connector=connector,
                             timeout=ClientTimeout(total=None, sock_connect=15),
                             cookie_jar=DummyCookieJar(),
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


def _report_source_ip(request: web.BaseRequest) -> str:
    """Real client IP for a scanner-probe report — the IP the hub will NSG-block.

    SECURITY: this edge is internet-facing, so ``X-Forwarded-For`` is fully
    client-settable. Trusting it blindly lets any anonymous scanner set
    ``X-Forwarded-For: <victim>`` on a probe path and make the hub block an
    arbitrary IP — including the shared NAT-gateway egress every internal spoke
    uses, which severs the whole fleet from the hub (a remotely-triggerable
    outage). So we trust XFF ONLY when the immediate TCP peer is a configured
    front proxy (``LM_TRUSTED_PROXIES``), then walk the chain right-to-left past
    trusted hops to the first non-trusted address = the real origin. Otherwise we
    report the direct TCP peer (``request.remote``) — the host actually sending
    the probe. This mirrors the hub's ``_client_ip`` discipline; the forwarding
    path already uses ``request.remote`` for the same reason."""
    peer = request.remote or ""
    if not _TRUSTED_PROXY_NETS or not _ip_in_trusted(peer):
        return peer
    xff = request.headers.get("X-Forwarded-For", "")
    chain = [h.strip() for h in xff.split(",") if h.strip()]
    for hop in reversed(chain):
        if not _ip_in_trusted(hop):
            return hop
    return chain[0] if chain else peer


def _report_edge_probe(spoke, request: web.BaseRequest) -> None:
    """Fire-and-forget: relay a detected scanner probe up the authenticated tunnel
    to the hub (``HTTP_PROBE_REPORT``) so it blocks the source centrally. Never
    raises into the request path — a missing control-plane back-reference (not yet
    connected) or no running loop just drops the report (best-effort)."""
    cp = getattr(spoke, "control_plane", None)
    if cp is None or not hasattr(cp, "send_to_hub"):
        return
    data = {
        "source_ip": _report_source_ip(request),
        "path": request.path,
        "method": request.method,
        "node": getattr(spoke, "spoke_id", None) or "proxy",
    }
    try:
        asyncio.get_event_loop().create_task(cp.send_to_hub("HTTP_PROBE_REPORT", data))
    except RuntimeError:  # pragma: no cover - no running loop (never inside a handler)
        pass


def _report_canary_hit(spoke, request: web.BaseRequest) -> None:
    """Fire-and-forget: relay an interaction with an operator canary endpoint up
    the authenticated tunnel (``NODE_CANARY_HIT``) so the hub decides the response
    centrally (self-scoped containment for a tenant node, source block at the
    perimeter). A canary has no legitimate use, so any hit is high-signal. Mirrors
    ``_report_edge_probe``: never raises into the request path."""
    cp = getattr(spoke, "control_plane", None)
    if cp is None or not hasattr(cp, "send_to_hub"):
        return
    data = {
        "source_ip": _report_source_ip(request),
        "path": request.path,
        "method": request.method,
        "node": getattr(spoke, "spoke_id", None) or "proxy",
    }
    try:
        asyncio.get_event_loop().create_task(cp.send_to_hub("NODE_CANARY_HIT", data))
    except RuntimeError:  # pragma: no cover - no running loop (never inside a handler)
        pass


async def _dispatch(request: web.Request) -> web.StreamResponse:
    spoke = request.app["spoke"]
    # HTTPS-port scanner detection at the edge. A request for a path we never
    # serve (PHP/dotfiles/DB-admin panels/app-server consoles) is an automated
    # vulnerability scanner fingerprinting THIS proxy, not a real client. When
    # enabled (per-node toggle), report it up the authenticated tunnel so the hub
    # blocks the source centrally on the NSG — one deny protects every edge — and
    # answer a bare 404 instead of forwarding the junk to the hub. Runs FIRST so
    # a scan is caught even when the upstream is unavailable. Uses the SAME shared
    # signatures as the hub's own _looks_like_probe, so proxied SPA deep-links and
    # static assets never trip it.
    if getattr(spoke, "probe_detection_enabled", True) and looks_like_probe(request.path):
        _report_edge_probe(spoke, request)
        return web.Response(status=404)
    # Operator canary endpoints (hub-provisioned; inert until the hub pushes a
    # set). A request for one is a definitive intrusion attempt — no legitimate
    # client, SPA route, or asset ever touches it. Answer with the operator-
    # supplied body (so the port looks live) and relay the hit up so the hub
    # decides the response centrally. Runs after the generic probe check and
    # before any upstream forwarding; empty config → match() is None → no-op.
    _canary = _node_canary.match(request.path)
    if _canary is not None:
        _report_canary_hit(spoke, request)
        return web.Response(status=_canary["status"], body=_canary["body"],
                            content_type=_canary["ctype"])
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


def _resp_headers(upstream_resp, *, drop_content_length: bool = False) -> CIMultiDict:
    """Copy upstream response headers into a CIMultiDict, PRESERVING duplicate
    headers. This is critical for Set-Cookie: the hub legitimately emits several
    at once — e.g. the OIDC callback sets ``lm_session`` AND deletes
    ``lm_oidc_state`` in one 302 — and building a plain ``dict`` collapses them to
    a single entry, silently dropping the session cookie and breaking SSO. Now
    that the proxy holds no cookie state of its own (DummyCookieJar), the browser
    MUST receive every Set-Cookie verbatim. Hop-by-hop headers are stripped."""
    out: CIMultiDict = CIMultiDict()
    for k, v in upstream_resp.headers.items():
        lk = k.lower()
        if lk in _HOP:
            continue
        if drop_content_length and lk == "content-length":
            continue
        out.add(k, v)
    return out


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
                    headers=_resp_headers(upstream_resp, drop_content_length=True))
            resp = web.StreamResponse(status=upstream_resp.status,
                                      headers=_resp_headers(upstream_resp))
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
    ws_client = web.WebSocketResponse(heartbeat=_WS_HEARTBEAT, max_msg_size=0)
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
                                   heartbeat=_WS_HEARTBEAT) as ws_up:
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
        ws_sp = await sess.ws_connect(relay_url, ssl=ssl_ctx, max_msg_size=0,
                                      heartbeat=_WS_HEARTBEAT)
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

        ws_browser = web.WebSocketResponse(heartbeat=_WS_HEARTBEAT, max_msg_size=0)
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
            while True:
                # Idle app-ping: in this edge path the hub is out of the byte
                # stream, so it can't send its own control "ping". When the spoke
                # side is quiet, emit one ourselves so the browser still sees a
                # frame within its watchdog window (and idle timers stay reset).
                # This coroutine is the sole writer to ws_browser, so the ping
                # can't race the byte sends below.
                try:
                    msg = await asyncio.wait_for(ws_sp.receive(), timeout=_WS_APP_PING_SECS)
                except asyncio.TimeoutError:
                    try:
                        await ws_browser.send_json({"type": "ping"})
                        continue
                    except Exception:  # noqa: BLE001
                        break
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
