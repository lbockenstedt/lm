"""Core /ws/spoke and /ws/agent WebSocket transport routes."""
# WebSocket types, the Starlette-to-websockets adapter, and shared stdlib/third-party modules
# re-exported by the api module (asyncio for concurrency, os for env vars, websockets client).
from api import (
    StarletteWSAdapter, WebSocket, WebSocketDisconnect, asyncio, logger, os, websockets,
)
# Turns the TLS peer certificate dict into the stable identity used by the HUB_REQUEST gate.
from security.peer_cert_ws import peer_cert_identity_from_getpeercert


def register(app, hub, ctx):
    """Register ws_transport routes on the Hub app."""

    # Spokes and agent-control clients connect to the hub over this WebSocket path.
    @app.websocket("/ws/spoke")
    async def spoke_ws(websocket: WebSocket):
        """Spoke/agent-control WebSocket on the unified :443 uvicorn.

        Replaces the former bare ``websockets.serve`` listener (which lived in
        the hub's main asyncio loop on 8765 loopback / 443 wss). The hub's
        ``handle_connection`` owns the full mutual-auth handshake + signed-frame
        dispatch loop; it expects a ``websockets``-lib-style socket, so wrap the
        Starlette ``WebSocket`` in ``StarletteWSAdapter`` and hand it off. The
        route ``accept()``s first — ``handle_connection`` does its own
        ``recv``/``send``/``close`` and never calls accept.
        """
        # Use the live hub object stored on the app state.
        hub = app.state.hub
        # Complete the WebSocket handshake now, because handle_connection never calls accept().
        await websocket.accept()
        # Wrap the Starlette socket so it looks like a ``websockets`` library connection.
        adapter = StarletteWSAdapter(websocket)
        # H1: capture the verified peer (client) cert identity for this
        # connection. ``PeerCertWebSocketProtocol`` injected the parsed
        # ``getpeercert()`` dict into ``scope["extensions"]["x_peer_cert"]``
        # (None when mTLS off / no cert presented / extraction failed). Derive
        # the renewal-stable SAN-DNS identity and stash it on the adapter so the
        # HUB_REQUEST gate (``_hub_request_authorized``) can pin it to the
        # designated AppBuilder cert. ``None`` here → gate denies (fail-closed).
        try:
            # Read the parsed client certificate, if any, that the TLS layer stashed in the ASGI
            # scope.
            raw_peer_cert = (websocket.scope.get("extensions") or {}).get("x_peer_cert")
            adapter.peer_cert_identity = peer_cert_identity_from_getpeercert(raw_peer_cert)
            # Keep the parsed getpeercert() dict (subject/issuer/notAfter/SANs) for
            # the mTLS-clients debug view — so an operator can see WHICH connections
            # actually presented a verified client cert vs. connected cert-less.
            adapter.peer_cert_raw = raw_peer_cert if isinstance(raw_peer_cert, dict) else None
            # DER for the hub's cert↔spoke binding + revocation check
            # (_mtls_connect_gate). Only meaningful when the cert verified.
            _der = (websocket.scope.get("extensions") or {}).get("x_peer_cert_der")
            adapter.peer_cert_der = (bytes(_der) if _der and adapter.peer_cert_raw
                                     else None)
        # If reading the cert fails, clear all cert fields so the gates fail closed.
        except Exception:  # noqa: BLE001 - never drop a connection on a read hiccup
            adapter.peer_cert_identity = None
            adapter.peer_cert_raw = None
            adapter.peer_cert_der = None
        # Hand the connection to the hub, which runs the auth handshake and message loop.
        await hub.handle_connection(adapter)

    # Remote pxmx agents connect here; traffic is relayed to the local pxmx spoke.
    @app.websocket("/ws/agent")
    async def agent_ws_proxy(websocket: WebSocket):
        """Dumb byte-proxy: pxmx agent (remote, wss terminated here at :443) ↔
        the co-located pxmx spoke's loopback agent listener.

        Under the unified-443 merge the hub owns the single :443 surface an agent
        dials (``wss://<hub>:443/ws/agent``), but the agent protocol — auth,
        approval, telemetry, signed frames — is owned by the pxmx spoke's
        ``_agent_handler``. The hub does NOT parse the agent protocol: it pipes
        bytes both ways to the spoke's loopback listener
        (``ws://127.0.0.1:<LM_PXMX_AGENT_PORT>/ws/agent``, plaintext — TLS
        terminates at the hub's 443). The spoke just sees an agent connecting
        from 127.0.0.1, so its auth/signing logic is unchanged.

        If the loopback listener is unreachable (pxmx spoke not running / not
        co-located), close the agent WS with a clear 1011 so the agent surfaces
        "agent loopback unreachable" instead of hanging.
        """
        # Complete the WebSocket handshake with the agent before dialing the loopback side.
        await websocket.accept()
        # Find the loopback agent port: the hub's setting first, then the env var, then 8443.
        hub = app.state.hub
        loopback_port = int(getattr(hub, "pxmx_agent_port", None) or
                            os.environ.get("LM_PXMX_AGENT_PORT", "8443"))
        # Plaintext loopback URL of the co-located pxmx spoke's agent listener.
        upstream_uri = f"ws://127.0.0.1:{loopback_port}/ws/agent"
        try:
            # perf-scan C3a: bound the loopback dial so a hung/absent listener
            # can't stall the hub loop. C5d: cap frame size (16 MiB) so an
            # oversized loopback frame can't blow memory on recv.
            upstream = await websockets.connect(
                upstream_uri, open_timeout=5, max_size=16 * 1024 * 1024)
        # Any failure to reach the loopback listener closes the agent socket with a clear reason.
        except Exception as exc:  # noqa: BLE001 — any connect failure → close
            logger.warning("agent /ws/agent proxy: loopback unreachable (%s): %s",
                           upstream_uri, exc)
            await websocket.close(code=1011, reason="agent loopback unreachable")
            return

        async def agent_to_upstream():
            """Agent WS (Starlette) → loopback (websockets lib)."""
            # Forward agent frames forever until the agent disconnects.
            while True:
                # Wait for the next ASGI WebSocket event from the agent.
                msg = await websocket.receive()
                # A disconnect event ends this direction by raising, which stops the relay.
                if msg.get("type") == "websocket.disconnect":
                    raise WebSocketDisconnect(code=msg.get("code", 1000))
                # Text frames are forwarded as text; skip the bytes check once sent.
                text = msg.get("text")
                if text is not None:
                    await upstream.send(text)
                    continue
                # Binary frames are forwarded as bytes.
                raw = msg.get("bytes")
                if raw is not None:
                    await upstream.send(bytes(raw))

        async def upstream_to_agent():
            """Loopback (websockets lib) → agent WS (Starlette)."""
            # Relay every frame from the loopback listener back to the agent, keeping its type.
            async for raw in upstream:
                if isinstance(raw, str):
                    await websocket.send_text(raw)
                else:
                    await websocket.send_bytes(bytes(raw))

        # Run both directions at once; return_exceptions stops one side's error from leaking out.
        try:
            await asyncio.gather(agent_to_upstream(), upstream_to_agent(),
                                 return_exceptions=True)
        # Whatever happened, close both sockets; close errors are ignored as they are already dead.
        finally:
            try:
                await upstream.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                await websocket.close(code=1000, reason="agent proxy done")
            except Exception:  # noqa: BLE001
                pass
