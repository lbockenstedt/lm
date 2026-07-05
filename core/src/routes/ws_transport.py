"""Core /ws/spoke and /ws/agent WebSocket transport routes."""
from api import (
    StarletteWSAdapter, WebSocket, WebSocketDisconnect, asyncio, logger, os, websockets,
)


def register(app, hub, ctx):
    """Register ws_transport routes on the Hub app."""

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
        hub = app.state.hub
        await websocket.accept()
        await hub.handle_connection(StarletteWSAdapter(websocket))

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
        await websocket.accept()
        hub = app.state.hub
        loopback_port = int(getattr(hub, "pxmx_agent_port", None) or
                            os.environ.get("LM_PXMX_AGENT_PORT", "8443"))
        upstream_uri = f"ws://127.0.0.1:{loopback_port}/ws/agent"
        try:
            upstream = await websockets.connect(upstream_uri)
        except Exception as exc:  # noqa: BLE001 — any connect failure → close
            logger.warning("agent /ws/agent proxy: loopback unreachable (%s): %s",
                           upstream_uri, exc)
            await websocket.close(code=1011, reason="agent loopback unreachable")
            return

        async def agent_to_upstream():
            """Agent WS (Starlette) → loopback (websockets lib)."""
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    raise WebSocketDisconnect(code=msg.get("code", 1000))
                text = msg.get("text")
                if text is not None:
                    await upstream.send(text)
                    continue
                raw = msg.get("bytes")
                if raw is not None:
                    await upstream.send(bytes(raw))

        async def upstream_to_agent():
            """Loopback (websockets lib) → agent WS (Starlette)."""
            async for raw in upstream:
                if isinstance(raw, str):
                    await websocket.send_text(raw)
                else:
                    await websocket.send_bytes(bytes(raw))

        try:
            await asyncio.gather(agent_to_upstream(), upstream_to_agent(),
                                 return_exceptions=True)
        finally:
            try:
                await upstream.close()
            except Exception:  # noqa: BLE001
                pass
            try:
                await websocket.close(code=1000, reason="agent proxy done")
            except Exception:  # noqa: BLE001
                pass
