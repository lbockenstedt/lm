"""Virtual hub-self spoke (agent-rework #5 / Phase 4).

A loopback ``/ws/agent`` listener bound INSIDE the hub process + an in-process
dumb agent that dials it, so the hub's own cert-install path
(``_install_cert_on_hub``) routes through the SAME ``WRITE_FILE`` + ``RUN_COMMAND``
primitives spoke-side cert deploys use — uniformity with the always-a-spoke
model. The hub is not a spoke and has no ``module_type``; this is a loopback-only
``AgentHostingControlPlane`` (``MODULE_TYPE="hub-self"``) run as a task in
``core/src/main.py`` — NOT a separate unit, NOT a spoke in the hub registry
(invisible to the WebUI Spokes list).

Safety — why the in-process agent is a minimal executor, NOT the device-mode
``SpokeClient``:

``SpokeClient.run()`` arms the code-drift watchdog, whose ``os._exit(3)`` would
kill the HUB process if the agent repo dir ever drifts. Running that inside the
hub is unacceptable, so ``_HubSelfAgent`` here reuses only the two primitives
that matter (``command_runner.run_local_command`` + an atomic ``WRITE_FILE``) and
NONE of the process-management scaffolding. ``HubSelfControlPlane`` also undoes
``BaseControlPlane.__init__``'s root-logger/excepthook side effects for the same
reason — it is an in-process guest, not a standalone process.

Loopback-only: always binds ``127.0.0.1`` (plaintext; TLS terminates on the
hub's unified :443 surface). Never ``0.0.0.0``. ``LM_HUB_SELF_AGENT_PORT``
overrides the default port (8768); ``LM_HUB_SELF_AGENT=0`` disables the feature
so ``_install_cert_on_hub`` falls back to direct inline writes.

Only ``_install_cert_on_hub`` (the server-cert write + ``lm-self-restart``) routes
through the hub-self agent. The 13 other hub-direct ops stay hub-local — see
``docs/hub-direct-ops.md``.
"""
# Postpone evaluation of type hints so annotations never trigger imports at runtime.
from __future__ import annotations

# asyncio drives the loopback listener, the in-process agent and its reconnect loop.
import asyncio
# base64 decodes WRITE_FILE payloads that arrive as base64 text.
import base64
# json encodes/decodes the handshake and command frames.
import json
# logging reports connection and persistence problems.
import logging
# os handles paths, env-var overrides and atomic file replacement.
import os
# secrets mints a random shared agent secret when none is configured.
import secrets
# sys lets us save/restore the hub's global excepthook.
import sys
# Type hints describing dict payloads and optional values.
from typing import Any, Dict, Optional

# websockets is the client library the in-process agent uses to dial the listener.
import websockets

# Import the agent-hosting base class and frame signer; the package-relative form works
# when imported as part of the package, the fallback when /opt/lm/core is on sys.path.
try:
    from .messaging.agent_hosting import AgentHostingControlPlane
    from .security.signer import MessageSigner, encode_frame, split_frame
except ImportError:  # bare-module layout (/opt/lm/core on sys.path)
    from messaging.agent_hosting import AgentHostingControlPlane  # type: ignore
    from security.signer import MessageSigner, encode_frame, split_frame  # type: ignore

# Named logger so hub-self messages can be filtered on their own.
logger = logging.getLogger("HubSelf")

#: The in-process dumb agent's stable id (handshake + send_to_agent target).
HUB_SELF_AGENT_ID = "hub-self-agent"
# Loopback port for the hub-self listener; the next free slot after the other planes.
_DEFAULT_PORT = 8768          # 8765=hub, 8766=pxmx, 8767=cs → 8768=hub-self
# Seconds to wait for a WRITE_FILE round trip before giving up.
_WRITE_TIMEOUT = 20.0
# Seconds to wait for the self-restart command to be acknowledged.
_RESTART_TIMEOUT = 15.0
# Helper script that restarts the hub service (used after installing a new cert).
_LM_SELF_RESTART = "/usr/local/bin/lm-self-restart"


def _write_local_file(path: str, content: str = "", *, b64: str = "",
                      mode: int = 0o600, mkdirs: bool = True,
                      atomic: bool = True) -> Dict[str, Any]:
    """Atomic file write with mode (mirrors ``agent/src/command_runner.py``'s
    ``write_local_file`` so the hub-self agent's ``WRITE_FILE`` is byte-for-byte
    the same primitive a real device-mode ``SpokeClient`` runs). ``content`` OR
    base64 ``b64``."""
    try:
        # Choose the raw bytes: decode base64 when given, else encode the text content.
        if b64:
            data = base64.b64decode(b64)
        else:
            data = (content or "").encode() if isinstance(content, str) \
                else bytes(content or b"")
        # Create the parent directory first when asked so the write cannot fail on a missing dir.
        d = os.path.dirname(path)
        if mkdirs and d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        # Write to a .tmp sibling when atomic so readers never see a half-written file.
        target = (path + ".tmp") if atomic else path
        with open(target, "wb") as f:
            f.write(data)
        # Apply the requested permission bits before the file becomes visible.
        os.chmod(target, mode)
        # Atomically swap the temp file into place.
        if atomic:
            os.replace(target, path)
        # Report success with the number of bytes written.
        return {"ok": True, "path": path, "bytes": len(data)}
    except Exception as e:  # noqa: BLE001
        # Any I/O failure is reported back to the caller instead of raising.
        return {"ok": False, "path": path, "error": str(e)}


class HubSelfControlPlane(AgentHostingControlPlane):
    """A loopback-only ``/ws/agent`` host living inside the hub process.

    Serves ``/ws/agent`` on ``127.0.0.1`` to the in-process ``_HubSelfAgent`` and
    exposes ``send_to_agent`` so the hub's cert-install path can issue
    ``WRITE_FILE`` / ``RUN_COMMAND`` to it. Never dials a hub (``run()`` does not
    call ``super().run()``); not registered as a spoke.
    """

    # Identity and env-var names that configure the agent-hosting base class for hub-self.
    MODULE_TYPE = "hub-self"
    AGENT_PORT_ENV = "LM_HUB_SELF_AGENT_PORT"
    AGENT_LOOPBACK_ENV = "LM_HUB_SELF_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_HUB_SELF_AGENT_LISTENER"
    AGENT_CONFIG_PATH = "/etc/lm-hub-self-agent/config.json"
    # The listener is not opt-in here: if hub-self is enabled at all, it listens.
    AGENT_LISTENER_OPT_IN = False       # always on when the feature is on
    # All port variants collapse to the single loopback port.
    AGENT_LOOPBACK_PORT = _DEFAULT_PORT
    AGENT_WSS_PORT = _DEFAULT_PORT
    AGENT_FALLBACK_PORT = _DEFAULT_PORT

    def __init__(self, spoke_id: str = "hub-self"):
        """Create the loopback host and make sure a shared agent secret exists."""
        # Remember the hub's excepthook so the base-class constructor cannot replace it.
        _prev_excepthook = sys.excepthook
        super().__init__(spoke_id)
        # In-process guest: undo BaseControlPlane.__init__'s process-global side
        # effects so the hub's own root-logger handler + excepthook stay intact.
        sys.excepthook = _prev_excepthook
        # Drop the log-relay handler the base class attached to the hub's root logger.
        try:
            logging.getLogger().removeHandler(self._log_relay_handler)
        except Exception:  # noqa: BLE001
            # Missing handler is harmless; nothing to undo.
            pass

        # The hub-self server + its in-process agent are the SAME process, so the
        # shared agent_secret just needs to be consistent between them — it does
        # not need installer provisioning. Mint one if the config file lacks it
        # (best-effort persist so it's stable across hub restarts).
        if not self.agent_secret:
            self.agent_secret = secrets.token_hex(32)
            self.agent_signer = MessageSigner(self.agent_secret)
            self._persist_self_config()
        # Handle for the in-process agent task, created later in run().
        self._agent_client_task: Optional[asyncio.Task] = None
        # Log whether the secret came from config or was freshly minted.
        logger.info("hub-self loopback agent-host ready (secret %s)",
                    "loaded" if self.config.get("agent_secret") else "minted")

    def _persist_self_config(self) -> None:
        """Best-effort persist the minted secret to ``AGENT_CONFIG_PATH`` (0600)
        so it's stable across hub restarts. In-memory works too — the agent is
        in-process and re-shares the secret each start."""
        # Make sure the config directory exists.
        try:
            os.makedirs(os.path.dirname(self.AGENT_CONFIG_PATH), exist_ok=True)
            # Write the secret to a temp file first so the real file is replaced atomically.
            tmp = self.AGENT_CONFIG_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"agent_secret": self.agent_secret}, f)
            # Restrict the file to the owner (it holds a secret), then swap it in.
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.AGENT_CONFIG_PATH)
        except Exception as e:  # noqa: BLE001
            # Persisting is optional; an in-memory secret still works for this process.
            logger.debug("hub-self config persist failed: %s", e)

    # ── Listener enablement ────────────────────────────────────────────────

    def _agent_listener_enabled(self) -> bool:
        """Report that the agent listener is enabled (always true for hub-self)."""
        # Always on when the feature is on (the caller in main.py gates the whole
        # feature via LM_HUB_SELF_AGENT).
        return True

    async def run_agent_server(self):
        """Start the agent listener, forcing it onto loopback only."""
        # Force loopback-only regardless of env: the hub-self listener NEVER binds
        # 0.0.0.0 (TLS terminates on the hub's unified :443 surface). The parent's
        # loopback branch binds 127.0.0.1 plaintext on AGENT_PORT_ENV/loopback port.
        os.environ[self.AGENT_LOOPBACK_ENV] = "1"
        # Delegate the actual listener startup to the base class.
        return await super().run_agent_server()

    async def run(self):
        """Run the loopback listener and the in-process agent until cancelled."""
        # Serve the loopback /ws/agent listener + start the in-process dumb agent
        # that dials it. Do NOT call super().run() — BaseControlPlane.run() dials
        # a hub; the hub-self spoke is in-process and dials only its own loopback.
        self._start_agent_server_task()
        # Give the listener a moment to bind before the client dials (avoids a
        # first-connect refused → backoff cycle on every hub start).
        await asyncio.sleep(0.5)
        # Launch the in-process agent that dials the listener.
        self._agent_client_task = asyncio.create_task(self._run_in_process_agent())
        try:
            await asyncio.Event().wait()   # serve forever (until cancelled)
        finally:
            # Cancel the two child tasks so they don't log "Task was destroyed
            # but it is pending!" when the hub shuts down and main.py cancels
            # this run() task. Both are fire-and-forget loops; cancel + await.
            # First request cancellation of every still-running child task.
            for _t in (getattr(self, "_agent_server_task", None),
                       getattr(self, "_agent_client_task", None)):
                if _t is not None and not _t.done():
                    _t.cancel()
            # Then wait for each to finish, swallowing the expected cancellation errors.
            for _t in (getattr(self, "_agent_server_task", None),
                       getattr(self, "_agent_client_task", None)):
                if _t is not None and not _t.done():
                    try:
                        await _t
                    except (asyncio.CancelledError, Exception):  # noqa: BLE001
                        pass

    # ── In-process dumb agent ───────────────────────────────────────────────

    async def _run_in_process_agent(self):
        """A minimal executor that dials THIS hub-self loopback listener and
        dispatches ``RUN_COMMAND`` / ``WRITE_FILE``. Reuses the same primitives a
        real ``SpokeClient`` runs, without the process-management scaffolding
        (drift watchdog's ``os._exit(3)`` must never run inside the hub)."""
        # Port the listener is bound on (env override, else the class default).
        port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_LOOPBACK_PORT)))
        # Loopback URL of this process's own /ws/agent listener.
        url = f"ws://127.0.0.1:{port}/ws/agent"
        # Signer used to verify incoming frames with the shared secret.
        signer = MessageSigner(self.agent_secret)
        # Initial reconnect delay in seconds; doubles on failure up to 30s.
        backoff = 2
        # Keep reconnecting forever; the task is cancelled on hub shutdown.
        while True:
            try:
                async with websockets.connect(url) as ws:
                    # Send the handshake identifying this agent and proving it knows the secret.
                    await ws.send(json.dumps({
                        "agent_id": HUB_SELF_AGENT_ID,
                        "secret": self.agent_secret,
                        "hostname": "hub-self",
                    }))
                    # Wait (max 5s) for the listener to confirm the handshake.
                    proof = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                    if proof.get("status") != "HUB_VERIFIED":
                        # Shouldn't happen (shared secret) — backoff + retry.
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                        continue
                    # Acknowledge the hub's proof to finish the handshake.
                    await ws.send(json.dumps({"status": "HUB_OK"}))
                    logger.info("hub-self in-process agent connected on %s", url)
                    # Reset the backoff after a successful connection.
                    backoff = 2
                    # Process every incoming command frame until the socket closes.
                    async for raw in ws:
                        await self._agent_handle_frame(ws, signer, raw)
            except asyncio.CancelledError:
                # Cancellation means shutdown; let it propagate.
                raise
            except Exception as e:  # noqa: BLE001 - reconnect loop
                # Any connection failure: log quietly, wait, and retry with growing backoff.
                logger.debug("hub-self agent reconnect (%s): %s", url, e)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _agent_handle_frame(self, ws, signer, raw) -> None:
        """Verify one signed command frame, run it, and send the signed response back."""
        # Decode the frame into its signature and JSON body.
        try:
            text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            sig, body = split_frame(text)
            msg = json.loads(body)
        except Exception:  # noqa: BLE001 - drop undecodable frames
            return
        # Ignore frames that are unsigned or whose signature does not match.
        if not sig or not signer.verify_bytes(body.encode(), sig):
            return
        # Pull out the correlation id (to match the reply) and the command type/data.
        corr = msg.get("header", {}).get("correlation_id")
        payload = msg.get("payload", {}) or {}
        cmd = payload.get("type")
        data = payload.get("data") or {}
        # Dispatch in a thread — run_local_command blocks on a subprocess.
        result = await asyncio.to_thread(self._agent_dispatch, cmd, data)
        # Only reply when the sender expects a response (has a correlation id).
        if corr is not None:
            resp = {"header": {"correlation_id": corr, "sender_id": HUB_SELF_AGENT_ID},
                    "payload": {"type": "AGENT_RESPONSE", "data": result}}
            # Send the signed response; a closed socket is ignored (the hub will time out).
            try:
                await ws.send(encode_frame(signer, resp))
            except Exception:  # noqa: BLE001
                pass

    def _agent_dispatch(self, cmd: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """Generic primitives only — mirrors ``SpokeClient._dispatch``."""
        # Keep-alive pings just get a success reply.
        if cmd in ("HUB_PING", "HEARTBEAT_ACK"):
            return {"status": "SUCCESS"}
        # RUN_COMMAND: execute a local command via the shared command runner.
        if cmd == "RUN_COMMAND":
            try:
                # Imported lazily because command_runner may not be on the path in every layout.
                from command_runner import run_local_command
            except ImportError:  # type: ignore
                return {"status": "ERROR", "message": "command_runner unavailable"}
            # Run the command with the caller's shell flag and timeout (default 30s).
            res = run_local_command(data.get("command", ""),
                                    bool(data.get("allow_shell", False)),
                                    float(data.get("timeout", 30.0) or 30.0))
            # Wrap the runner result in the standard response shape.
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        # WRITE_FILE: write a file with the same atomic primitive spokes use.
        if cmd == "WRITE_FILE":
            res = _write_local_file(data.get("path", ""), data.get("content", ""),
                                    b64=data.get("b64", ""),
                                    mode=int(data.get("mode", 0o600)),
                                    mkdirs=bool(data.get("mkdirs", True)),
                                    atomic=bool(data.get("atomic", True)))
            # Wrap the write result in the standard response shape.
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        # Anything else is not supported by this minimal executor.
        return {"status": "ERROR", "message": f"unsupported: {cmd}"}

    # ── Hub-facing helpers (called by _install_cert_on_hub) ─────────────────

    async def write_file(self, path: str, content: str, mode: int = 0o600,
                         timeout: float = _WRITE_TIMEOUT) -> Dict[str, Any]:
        """WRITE_FILE to the in-process agent. Returns the AGENT_RESPONSE data
        (``{status, result, message}``) — ``status == "SUCCESS"`` +
        ``result.ok`` means the file landed."""
        # Send WRITE_FILE to the in-process agent and wait for its reply.
        return await self.send_to_agent(
            "WRITE_FILE",
            {"path": path, "content": content, "mode": mode, "atomic": True},
            agent_id=HUB_SELF_AGENT_ID, timeout=timeout)

    async def run_command(self, command: str, allow_shell: bool = True,
                          timeout: float = 10.0) -> Dict[str, Any]:
        """RUN_COMMAND on the in-process agent. Used for ``lm-self-restart``
        (backgrounded so the agent responds before the restart kills the hub)."""
        # Send RUN_COMMAND to the in-process agent and wait for its reply.
        return await self.send_to_agent(
            "RUN_COMMAND",
            {"command": command, "allow_shell": allow_shell, "timeout": timeout},
            agent_id=HUB_SELF_AGENT_ID, timeout=timeout + 5.0)