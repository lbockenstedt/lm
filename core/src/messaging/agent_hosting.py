"""Agent-hosting control plane mixin — ``AgentHostingControlPlane``.

Lifts the generic agent-listener machinery that used to live only in
``pxmx/src/control_plane.py::PxmxControlPlane`` so any spoke that needs to
host inbound agents can share one implementation. Today two spokes use it:

* **pxmx** (``hypervisor``) — the original. A Proxmox agent dials the pxmx
  spoke's ``/ws/agent`` (standalone ``wss://0.0.0.0:443`` default, or loopback
  ``127.0.0.1:8443`` on the co-located all-in-one path); the spoke relays frames
  up to the hub wrapped in ``AGENT_RELAY_UP``.
* **cs** (``simulation``) — opt-in via ``--agent-listener`` /
  ``LM_CS_AGENT_LISTENER=1``. In the split (per-module-LXC) topology a
  cs-dialed pxmx agent connects directly to the cs spoke instead of the pxmx
  spoke; the cs spoke then relays the same way. all-in-one keeps cs relay-only
  (the ``CSBridgePoller`` handles co-located cs agents), so the cs listener is
  gated and does NOT bind ``:443`` on the hub box.

Behavior is parameterized via class attrs so the lifted code is byte-identical
in behavior to the original pxmx implementation (pxmx tests are the regression
gate). Subclass hooks (``_on_agent_telemetry``, ``_on_agent_registered``) carry
the pxmx-specific telemetry caching + config re-push; the base mixin is generic.
"""

import asyncio
import json
import uuid
import time
import os
import ssl
import hmac
import logging
import websockets
from typing import Any, Dict, List, Optional

try:
    from .control_plane import BaseControlPlane
    from ..security.signer import MessageSigner
except ImportError:  # imported off a stale path (bare modules on sys.path)
    from messaging.control_plane import BaseControlPlane  # type: ignore
    from security.signer import MessageSigner  # type: ignore

logger = logging.getLogger("AgentHostingControlPlane")


class AgentHostingControlPlane(BaseControlPlane):
    """A spoke that also serves an inbound ``/ws/agent`` listener.

    Subclasses set the class attrs below (pxmx / cs values shown):

    * ``MODULE_TYPE``           — ``"hypervisor"`` / ``"simulation"``
    * ``AGENT_PORT_ENV``        — ``"LM_PXMX_AGENT_PORT"`` / ``"LM_CS_AGENT_PORT"``
    * ``AGENT_LOOPBACK_ENV``    — ``"LM_PXMX_AGENT_LOOPBACK"`` / ``"LM_CS_AGENT_LOOPBACK"``
    * ``AGENT_LISTENER_ENV``    — ``"LM_PXMX_AGENT_LISTENER"`` / ``"LM_CS_AGENT_LISTENER"``
    * ``AGENT_CONFIG_PATH``     — ``"/etc/lm-agent/config.json"`` / ``"/etc/lm-cs-agent/config.json"``
    * ``AGENT_LISTENER_OPT_IN`` — ``False`` (pxmx: always on) / ``True`` (cs: env-gated)
    * ``AGENT_LOOPBACK_PORT``   — ``8443`` (loopback + wss default when env unset)
    * ``AGENT_WSS_PORT``        — ``8443`` (pxmx; installer pins 443) / ``443`` (cs standalone)
    * ``AGENT_FALLBACK_PORT``   — ``8766`` (pxmx legacy no-cert) / ``8767`` (cs)

    Hooks (base default is a no-op):

    * ``_on_agent_registered(agent_id)`` — pxmx re-pushes stored PVE config.
    * ``_on_agent_telemetry(agent_id, rec, data)`` — pxmx caches nodes/vms/cluster
      + persists the disk cache; cs stores minimal fields.
    """

    # ── Subclass-tunable knobs (defaults are pxmx's so a pxmx subclass that
    #    forgets to set them still behaves exactly as before) ────────────────
    MODULE_TYPE: Optional[str] = "hypervisor"
    AGENT_PORT_ENV: str = "LM_PXMX_AGENT_PORT"
    AGENT_LOOPBACK_ENV: str = "LM_PXMX_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV: str = "LM_PXMX_AGENT_LISTENER"
    AGENT_CONFIG_PATH: str = "/etc/lm-agent/config.json"
    AGENT_LISTENER_OPT_IN: bool = False
    AGENT_LOOPBACK_PORT: int = 8443
    AGENT_WSS_PORT: int = 8443
    AGENT_FALLBACK_PORT: int = 8766

    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None,
                 hub_url: str = None, onboarding_psk: str = None,
                 tenant_id_hint: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url,
                         onboarding_psk=onboarding_psk, tenant_id_hint=tenant_id_hint)
        if self.MODULE_TYPE:
            self.module_type = self.MODULE_TYPE

        # Agent onboarding secret — one value used as BOTH the auth PSK
        # (hmac.compare_digest against the agent's ``secret`` field) AND the
        # HMAC signing key for all agent↔spoke frames (``agent_signer``).
        # Generated at install time into AGENT_CONFIG_PATH so
        # ``approve_pending_agent`` can push it down to a pending agent on
        # admin approval. Absent → zero-touch only (agents approved before
        # they receive a secret).
        config_path = self.AGENT_CONFIG_PATH
        self.config: Dict[str, Any] = {}
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Could not load agent config: {e}")

        self.agent_secret: Optional[str] = self.config.get("agent_secret")
        if not self.agent_secret:
            logger.warning("agent_secret not set — zero-touch provisioning only "
                           "(agents will be approved before receiving a secret)")
        self.agent_signer = MessageSigner(self.agent_secret or "")

        # Correlated agent command/response futures (corr_id → Future).
        self.pending_responses: Dict[str, asyncio.Future] = {}
        # agent_id → {ws, hostname, cluster_name, last_seen, nodes, vms, ...}
        self.connected_agents: Dict[str, Dict[str, Any]] = {}
        # agent_id → {ws, event} for agents awaiting admin approval.
        self.pending_agents: Dict[str, Dict[str, Any]] = {}

        # Strong reference to the self-healing agent-server task so the loop
        # does not GC it mid-flight ("coroutine ignored GeneratorExit").
        self._agent_server_task: Optional[asyncio.Task] = None

    # ── Listener enablement ────────────────────────────────────────────────

    def _agent_listener_enabled(self) -> bool:
        """True when this spoke should serve ``/ws/agent``.

        pxmx (``AGENT_LISTENER_OPT_IN=False``) always serves it — backward
        compatible with existing pxmx installs that never set the env. cs
        (``AGENT_LISTENER_OPT_IN=True``) only serves it when
        ``LM_CS_AGENT_LISTENER=1`` (set by ``install_cs.sh --agent-listener``),
        so an all-in-one / relay-only cs spoke never binds ``:443``.
        """
        if not self.AGENT_LISTENER_OPT_IN:
            return True
        return os.environ.get(self.AGENT_LISTENER_ENV, "").strip() in ("1", "true", "True")

    # ── System command propagation ──────────────────────────────────────────

    async def handle_system_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Handle a Hub system command; on log-level changes also broadcast to
        all connected agents so the WebUI "Enable Debug" toggle reaches them."""
        result = await super().handle_system_command(cmd_type, data)
        if cmd_type in ("SET_LOG_LEVEL", "SPOKE_SET_LOG_LEVEL"):
            if self.connected_agents:
                await self.broadcast_to_agents("SET_LOG_LEVEL", data)
        return result

    # ── Agent WebSocket server ──────────────────────────────────────────────

    async def run_agent_server(self):
        """Serve the agent listener. Three modes:

        * **Loopback** (``<AGENT_LOOPBACK_ENV>=1``): bind ``127.0.0.1`` only,
          plaintext, on ``<AGENT_PORT_ENV>`` (default ``AGENT_LOOPBACK_PORT``).
          TLS terminates upstream (the hub's ``/ws/agent`` byte-proxy on the
          all-in-one path); the port is NOT advertised externally.
        * **Standalone wss** — a cert is present (``LM_TLS_CERT``/``LM_TLS_KEY``)
          and loopback is OFF: ``wss`` on ``0.0.0.0:<AGENT_PORT_ENV>`` (default
          ``AGENT_WSS_PORT``); a standalone spoke sets it to 443 so agents dial
          ``wss://<spoke>:443/ws/agent`` directly.
        * **Standalone plaintext (legacy / cert-less)** — no cert, loopback OFF:
          ``ws`` on ``0.0.0.0:<AGENT_PORT_ENV>`` (default ``AGENT_FALLBACK_PORT``).

        Retries up to 10× on EADDRINUSE.
        """
        loopback = os.environ.get(self.AGENT_LOOPBACK_ENV, "").strip() in ("1", "true", "True")
        cert = os.environ.get("LM_TLS_CERT", "").strip()
        key = os.environ.get("LM_TLS_KEY", "").strip()
        if loopback:
            # TLS terminates upstream; the loopback hop is plaintext.
            host = "127.0.0.1"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_LOOPBACK_PORT)))
            serve_kwargs = {}
            scheme = "ws"
        elif cert and key:
            host = "0.0.0.0"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_WSS_PORT)))
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert, key)
            serve_kwargs = {"ssl": server_ctx}
            scheme = "wss"
        else:
            host = "0.0.0.0"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_FALLBACK_PORT)))
            serve_kwargs = {}
            scheme = "ws"
        for attempt in range(10):
            try:
                async with websockets.serve(
                    self._agent_handler, host, port, **serve_kwargs,
                ):
                    logger.info(f"Agent listener on {scheme}://{host}:{port}")
                    await asyncio.Future()
                return
            except OSError as e:
                # errno 98 = address in use (Linux), errno 48 = macOS equivalent
                if e.errno in (98, 48) and attempt < 9:
                    logger.warning(f"Port {port} in use, retrying in 3s (attempt {attempt + 1}/10)…")
                    await asyncio.sleep(3)
                else:
                    logger.error(f"Agent server failed to bind to port {port}: {e}")
                    raise
            except Exception as e:
                logger.error(f"Agent server unexpected error: {e}", exc_info=True)
                raise

    def _start_agent_server_task(self) -> None:
        """Create the self-healing agent-server task (caller invokes this from
        ``run()`` only when ``_agent_listener_enabled()`` is True). Stores a
        strong reference on ``self._agent_server_task`` so the loop does not
        garbage-collect it mid-flight."""

        async def _run_agent_server_logged():
            # Self-heal: if the agent listener ever exits (e.g. its serve task is
            # GC'd and raises "coroutine ignored GeneratorExit"), restart it after
            # a short backoff instead of leaving the port dark until a unit restart.
            while True:
                try:
                    await self.run_agent_server()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Agent server exited: {e} — restarting in 5s", exc_info=True)
                    await asyncio.sleep(5)

        self._agent_server_task = asyncio.create_task(_run_agent_server_logged())

    # ── Pending approval / revocation ───────────────────────────────────────

    async def approve_pending_agent(self, agent_id: str):
        """Called when the LM hub approves a pending agent. Sends the
        provisioned secret (this spoke's ``agent_secret``) so the agent can
        reconnect authenticated + sign its frames."""
        pending = self.pending_agents.get(agent_id)
        if not pending:
            logger.warning(f"Approval for unknown/already-connected agent '{agent_id}'")
            return
        try:
            await pending["ws"].send(json.dumps({
                "status": "APPROVED",
                "secret": self.agent_secret,
            }))
            logger.info(f"Agent '{agent_id}' approved — secret provisioned")
            pending["event"].set()
        except Exception as e:
            logger.error(f"Failed to deliver approval to agent '{agent_id}': {e}")

    async def revoke_agent(self, agent_id: str):
        """Disconnect a connected or pending agent — it will auto-heal and
        re-enter pending."""
        agent = self.connected_agents.get(agent_id)
        if agent:
            try:
                await agent["ws"].close(1008, "Revoked by admin")
            except Exception:
                pass
            self.connected_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' revoked (was connected)")
            return
        pending = self.pending_agents.get(agent_id)
        if pending:
            try:
                await pending["ws"].close(1008, "Revoked by admin")
            except Exception:
                pass
            pending["event"].set()
            self.pending_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' revoked (was pending)")
            return
        logger.warning(f"Revoke requested for unknown agent '{agent_id}'")

    # ── Agent connection handler ────────────────────────────────────────────

    async def _agent_handler(self, websocket, path=None):
        agent_id = None
        try:
            # 0. Path enforcement — an agent dials ``/ws/agent`` (the hub proxies
            # /ws/agent to this listener on the all-in-one loopback path; a
            # standalone spoke serves /ws/agent directly on 443). Reject any
            # other path so this listener is never reached via a stray URL.
            # ``path`` is the 3rd arg on older websockets; newer versions drop it
            # from the handler sig → read ``websocket.path`` (or
            # ``websocket.request.path``).
            if path is None:
                path = getattr(websocket, "path", None) or getattr(
                    getattr(websocket, "request", None), "path", None)
            if path != "/ws/agent":
                logger.warning(f"Agent handler rejecting unexpected path: {path!r}")
                await websocket.close(1008, "unexpected path")
                return

            # 1. Auth
            auth = json.loads(await websocket.recv())
            agent_id     = auth.get("agent_id")
            agent_secret = auth.get("secret")
            # Stable install UUID + current OS hostname (sent by the agent on
            # every connect) so the hub can detect a clone-and-rename and carry
            # over per-agent config. Captured here and relayed up on every
            # AGENT_RELAY_UP frame via _relay_agent_msg_up.
            agent_install_uuid = (auth.get("install_uuid") or "").strip()
            agent_hostname     = (auth.get("hostname") or "").strip()

            if not agent_id:
                await websocket.close(1008, "Missing agent_id"); return

            # ── Zero-touch / pending-approval path ───────────────────────────
            if not agent_secret:
                logger.info(f"Agent '{agent_id}' connected without credentials — pending approval")
                event = asyncio.Event()
                self.pending_agents[agent_id] = {"ws": websocket, "event": event}
                await websocket.send(json.dumps({"status": "APPROVAL_REQUIRED"}))
                try:
                    # Keep connection alive (heartbeats only) until approved/disconnected
                    while not event.is_set():
                        try:
                            raw = await asyncio.wait_for(websocket.recv(), timeout=10.0)
                            msg = json.loads(raw)
                            # Only heartbeats are processed while pending
                        except asyncio.TimeoutError:
                            pass
                except Exception:
                    pass
                finally:
                    self.pending_agents.pop(agent_id, None)
                    if not event.is_set():
                        logger.info(f"Pending agent '{agent_id}' disconnected before approval")
                return

            # ── Authenticated path ────────────────────────────────────────────
            if not self.agent_secret or not hmac.compare_digest(str(agent_secret), str(self.agent_secret)):
                logger.warning(f"Agent '{agent_id}' auth failed — bad secret")
                await websocket.close(1008, "Auth failed"); return

            # 2. Mutual auth
            await websocket.send(json.dumps({"status": "HUB_VERIFIED"}))
            ack = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5.0))
            if ack.get("status") != "HUB_OK":
                await websocket.close(1008, "Agent failed mutual auth"); return

            logger.info(f"Agent '{agent_id}' connected")
            self.connected_agents[agent_id] = {
                "ws":           websocket,
                "hostname":     agent_hostname or agent_id,
                "cluster_name": agent_id,   # overwritten by telemetry (pxmx)
                "install_uuid": agent_install_uuid,
                "last_seen":    time.time(),
                "nodes":        [],
                "vms":          [],
                "agent_metrics": {},
                "version":      "unknown",  # overwritten by AGENT_TELEMETRY
            }

            # Post-register hook (pxmx re-pushes stored PVE credentials).
            await self._on_agent_registered(agent_id)

            # 3. Message loop
            async for raw in websocket:
                msg = json.loads(raw)

                if "signature" not in msg or not self.agent_signer.verify(msg):
                    logger.warning("Invalid agent message signature — dropping")
                    continue

                payload  = msg.get("payload", {})
                msg_type = payload.get("type")
                data     = payload.get("data", {})
                corr_id  = msg.get("header", {}).get("correlation_id")

                if msg_type == "AGENT_HEARTBEAT":
                    if agent_id in self.connected_agents:
                        self.connected_agents[agent_id]["last_seen"] = time.time()
                    # Relay up so the hub's HeartbeatManager tracks per-agent
                    # liveness (keyed spoke_id:agent_id) and System → Diagnostics
                    # can render a GREEN/YELLOW/RED heartbeat for the agent like
                    # it does for spokes. Best-effort (see _relay_agent_msg_up).
                    await self._relay_agent_msg_up(agent_id, "AGENT_HEARTBEAT", data)

                elif msg_type == "AGENT_TELEMETRY":
                    rec = self.connected_agents.get(agent_id)
                    if rec is not None:
                        rec["last_seen"] = time.time()
                        rec["hostname"] = data.get("hostname", agent_id)
                        rec["version"] = (data.get("agent_version") or data.get("version")
                                          or rec.get("version", "unknown"))
                    # Hook: pxmx caches nodes/vms/cluster + persists the disk
                    # cache; cs stores minimal fields. Never raises.
                    await self._on_agent_telemetry(agent_id, rec, data)

                elif msg_type == "AGENT_RESPONSE":
                    if corr_id in self.pending_responses:
                        fut = self.pending_responses.pop(corr_id)
                        if not fut.done():
                            fut.set_result(data)

                elif msg_type == "AGENT_LOG":
                    # Relay to hub so it appears in Setup → Agent Logs.
                    await self._relay_agent_msg_up(agent_id, "AGENT_LOG", data)

                elif msg_type and msg_type.startswith("CS_"):
                    # Relay Client-Simulation events (CS_TELEMETRY / CS_LOG /
                    # CS_WATCHDOG_EVENT / CS_HW_RESET_EVENT / CS_PROGRESS /
                    # CS_COMMAND_RESULT / CS_TOKEN_RESULT) up to the hub, which
                    # dispatches them to the cs spoke via the AGENT_RELAY_UP
                    # CS_* dispatcher. The agent's send_cs_event already injected
                    # hostname + agent_id into ``data`` so the hub can resolve
                    # tenant/host.
                    await self._relay_agent_msg_up(agent_id, msg_type, data)

                elif msg_type and msg_type.startswith("VNC_"):
                    # VNC console frames from the agent (VNC_FRAME_UP / VNC_READY
                    # / VNC_ERROR / VNC_DISCONNECT) — relay up to the hub's
                    # AGENT_RELAY_UP dispatcher, which routes them to the browser
                    # WS for the session. data carries session_id (+ b64 frame for
                    # VNC_FRAME_UP). No Future involved — one-way.
                    await self._relay_agent_msg_up(agent_id, msg_type, data)

        except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
            # Expected disconnect — the agent rebooted, the network blipped,
            # or the spoke restarted. The finally below removes it from
            # connected_agents + pending_agents and the agent re-registers on
            # reconnect. No traceback for the documented case (was a 60-line
            # ERROR+exc_info dump per disconnect); keep ERROR+exc_info below
            # for genuinely unexpected exceptions.
            pass
        except Exception as e:
            logger.error(f"Agent handler error: {e}", exc_info=True)
        finally:
            if agent_id:
                self.connected_agents.pop(agent_id, None)
                self.pending_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' disconnected")

    # ── Hub relay ───────────────────────────────────────────────────────────

    async def _relay_agent_msg_up(self, agent_id: str, msg_type: str, data: Dict[str, Any]) -> None:
        """Wrap an agent message into an AGENT_RELAY_UP frame and forward it to
        the hub (best-effort). Shared by the AGENT_LOG / HEARTBEAT / CS_* / VNC_*
        relay branches: the hub's AGENT_RELAY_UP handler logs AGENT_LOG and
        routes CS_* payloads to the cs spoke. Never raises — relay failures
        must not tear down the agent connection."""
        hub_ws = getattr(self, "_hub_ws", None)
        if not hub_ws:
            if msg_type == "AGENT_LOG":
                level = data.get("level", "INFO")
                msg_text = data.get("message", "")
                logger.warning("[agent:%s no-hub-relay] %s: %s", agent_id, level, msg_text)
            else:
                logger.debug("[agent:%s no-hub-relay] %s dropped", agent_id, msg_type)
            return
        if not self.signer:
            logger.warning(
                "Cannot relay %s from '%s': spoke has no session signer "
                "(hub connection not yet authenticated)", msg_type, agent_id)
            return
        try:
            # Attach the agent's install_uuid + hostname to the relay envelope so
            # the hub can reconcile agent identity (clone-and-rename detection)
            # on every relayed frame, not just telemetry. Sourced from the
            # capture in _agent_handler; falls back to agent_id when absent.
            rec = self.connected_agents.get(agent_id, {})
            relay = {
                "header": {
                    "message_id": str(uuid.uuid4()),
                    "timestamp": time.time(),
                    "sender_id": self.spoke_id,
                    "destination_id": "hub",
                },
                "payload": {
                    "type": "AGENT_RELAY_UP",
                    "data": {
                        "agent_id": agent_id,
                        "install_uuid": rec.get("install_uuid", ""),
                        "hostname": rec.get("hostname", agent_id),
                        "original_payload": {"payload": {"type": msg_type, "data": data}},
                    },
                },
            }
            relay["signature"] = self.signer.sign(relay)
            await hub_ws.send(json.dumps(relay, separators=(",", ":")))
        except Exception as _e:
            logger.warning("Failed to relay %s from '%s' to hub: %s", msg_type, agent_id, _e)

    # ── Agent command routing ───────────────────────────────────────────────

    async def send_to_agent(self, cmd_type: str, data: Dict[str, Any],
                            agent_id: Optional[str] = None,
                            timeout: float = 15.0) -> Dict[str, Any]:
        """Send a command to a specific agent (by agent_id) or the first
        available one. Returns the agent's response or an error dict.
        ``timeout`` bounds the wait for the agent's correlated response
        (default 15s; pass a longer window for slow ops like qm stop/snapshot).
        """
        if agent_id:
            rec = self.connected_agents.get(agent_id)
            if not rec:
                return {"status": "ERROR", "message": f"Agent '{agent_id}' not connected"}
            ws = rec["ws"]
        else:
            if not self.connected_agents:
                return {"status": "ERROR", "message": "No agents connected"}
            rec = next(iter(self.connected_agents.values()))
            ws = rec["ws"]

        corr_id = str(uuid.uuid4())
        msg = {
            "header": {
                "message_id": corr_id, "timestamp": time.time(),
                "sender_id": self.spoke_id, "destination_id": agent_id or "pxmx-agent",
            },
            "payload": {"type": cmd_type, "data": data},
        }
        msg["signature"] = self.agent_signer.sign(msg)

        fut = asyncio.get_running_loop().create_future()
        self.pending_responses[corr_id] = fut
        try:
            await ws.send(json.dumps(msg, separators=(',', ':')))
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self.pending_responses.pop(corr_id, None)
            return {"status": "ERROR", "message": "Agent response timeout"}
        except Exception as e:
            self.pending_responses.pop(corr_id, None)
            return {"status": "ERROR", "message": str(e)}

    async def send_raw_to_agent(self, agent_id: str, cmd_type: str,
                                data: Dict[str, Any]) -> bool:
        """Fire-and-forget signed send to one agent — no response Future, no
        timeout. Used for VNC down-frames + control (VNC_START / VNC_FRAME_DOWN
        / VNC_DISCONNECT) which are high-volume or one-way; the agent's
        AGENT_RESPONSE (if any) is dropped by the ``AGENT_RESPONSE`` branch
        above (no pending corr_id). Returns True on a successful send, False if
        the agent is gone or the send failed. Caller MUST NOT await a result."""
        rec = (self.connected_agents or {}).get(agent_id)
        if not rec or not rec.get("ws"):
            return False
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()), "timestamp": time.time(),
                "sender_id": self.spoke_id, "destination_id": agent_id,
            },
            "payload": {"type": cmd_type, "data": data},
        }
        msg["signature"] = self.agent_signer.sign(msg)
        try:
            await rec["ws"].send(json.dumps(msg, separators=(',', ':')))
            return True
        except Exception as e:
            logger.warning(f"send_raw_to_agent {cmd_type} -> {agent_id} failed: {e}")
            return False

    async def broadcast_to_agents(self, cmd_type: str,
                                  data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fan out a command to every connected agent; collect all results."""
        if not self.connected_agents:
            return []
        tasks = [
            self.send_to_agent(cmd_type, data, agent_id=aid)
            for aid in list(self.connected_agents)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for aid, res in zip(self.connected_agents, results):
            if isinstance(res, Exception):
                out.append({"agent_id": aid, "status": "ERROR", "message": str(res)})
            else:
                out.append({"agent_id": aid, **res})
        return out

    # ── Subclass hooks (default no-ops) ──────────────────────────────────────

    async def _on_agent_registered(self, agent_id: str) -> None:
        """Called after a newly-authenticated agent is recorded in
        ``connected_agents``. pxmx overrides to re-push stored PVE credentials."""
        return None

    async def _on_agent_telemetry(self, agent_id: str, rec: Optional[Dict[str, Any]],
                                  data: Dict[str, Any]) -> None:
        """Called for each AGENT_TELEMETRY frame after the generic rec fields
        (last_seen / hostname / version) are updated. pxmx overrides to cache
        nodes/vms/cluster_name/agent_metrics + persist the disk cache + mirror
        into the module telemetry_cache; cs stores minimal fields."""
        return None