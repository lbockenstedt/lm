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
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import sys
from typing import Any, Dict, Optional

import websockets

try:
    from .messaging.agent_hosting import AgentHostingControlPlane
    from .security.signer import MessageSigner, encode_frame, split_frame
except ImportError:  # bare-module layout (/opt/lm/core on sys.path)
    from messaging.agent_hosting import AgentHostingControlPlane  # type: ignore
    from security.signer import MessageSigner, encode_frame, split_frame  # type: ignore

logger = logging.getLogger("HubSelf")

#: The in-process dumb agent's stable id (handshake + send_to_agent target).
HUB_SELF_AGENT_ID = "hub-self-agent"
_DEFAULT_PORT = 8768          # 8765=hub, 8766=pxmx, 8767=cs → 8768=hub-self
_WRITE_TIMEOUT = 20.0
_RESTART_TIMEOUT = 15.0
_LM_SELF_RESTART = "/usr/local/bin/lm-self-restart"


def _write_local_file(path: str, content: str = "", *, b64: str = "",
                      mode: int = 0o600, mkdirs: bool = True,
                      atomic: bool = True) -> Dict[str, Any]:
    """Atomic file write with mode (mirrors ``agent/src/command_runner.py``'s
    ``write_local_file`` so the hub-self agent's ``WRITE_FILE`` is byte-for-byte
    the same primitive a real device-mode ``SpokeClient`` runs). ``content`` OR
    base64 ``b64``."""
    try:
        if b64:
            data = base64.b64decode(b64)
        else:
            data = (content or "").encode() if isinstance(content, str) \
                else bytes(content or b"")
        d = os.path.dirname(path)
        if mkdirs and d and not os.path.exists(d):
            os.makedirs(d, exist_ok=True)
        target = (path + ".tmp") if atomic else path
        with open(target, "wb") as f:
            f.write(data)
        os.chmod(target, mode)
        if atomic:
            os.replace(target, path)
        return {"ok": True, "path": path, "bytes": len(data)}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "path": path, "error": str(e)}


class HubSelfControlPlane(AgentHostingControlPlane):
    """A loopback-only ``/ws/agent`` host living inside the hub process.

    Serves ``/ws/agent`` on ``127.0.0.1`` to the in-process ``_HubSelfAgent`` and
    exposes ``send_to_agent`` so the hub's cert-install path can issue
    ``WRITE_FILE`` / ``RUN_COMMAND`` to it. Never dials a hub (``run()`` does not
    call ``super().run()``); not registered as a spoke.
    """

    MODULE_TYPE = "hub-self"
    AGENT_PORT_ENV = "LM_HUB_SELF_AGENT_PORT"
    AGENT_LOOPBACK_ENV = "LM_HUB_SELF_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_HUB_SELF_AGENT_LISTENER"
    AGENT_CONFIG_PATH = "/etc/lm-hub-self-agent/config.json"
    AGENT_LISTENER_OPT_IN = False       # always on when the feature is on
    AGENT_LOOPBACK_PORT = _DEFAULT_PORT
    AGENT_WSS_PORT = _DEFAULT_PORT
    AGENT_FALLBACK_PORT = _DEFAULT_PORT

    def __init__(self, spoke_id: str = "hub-self"):
        _prev_excepthook = sys.excepthook
        super().__init__(spoke_id)
        # In-process guest: undo BaseControlPlane.__init__'s process-global side
        # effects so the hub's own root-logger handler + excepthook stay intact.
        sys.excepthook = _prev_excepthook
        try:
            logging.getLogger().removeHandler(self._log_relay_handler)
        except Exception:  # noqa: BLE001
            pass

        # The hub-self server + its in-process agent are the SAME process, so the
        # shared agent_secret just needs to be consistent between them — it does
        # not need installer provisioning. Mint one if the config file lacks it
        # (best-effort persist so it's stable across hub restarts).
        if not self.agent_secret:
            self.agent_secret = secrets.token_hex(32)
            self.agent_signer = MessageSigner(self.agent_secret)
            self._persist_self_config()
        self._agent_client_task: Optional[asyncio.Task] = None
        logger.info("hub-self loopback agent-host ready (secret %s)",
                    "loaded" if self.config.get("agent_secret") else "minted")

    def _persist_self_config(self) -> None:
        """Best-effort persist the minted secret to ``AGENT_CONFIG_PATH`` (0600)
        so it's stable across hub restarts. In-memory works too — the agent is
        in-process and re-shares the secret each start."""
        try:
            os.makedirs(os.path.dirname(self.AGENT_CONFIG_PATH), exist_ok=True)
            tmp = self.AGENT_CONFIG_PATH + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"agent_secret": self.agent_secret}, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.AGENT_CONFIG_PATH)
        except Exception as e:  # noqa: BLE001
            logger.debug("hub-self config persist failed: %s", e)

    # ── Listener enablement ────────────────────────────────────────────────

    def _agent_listener_enabled(self) -> bool:
        # Always on when the feature is on (the caller in main.py gates the whole
        # feature via LM_HUB_SELF_AGENT).
        return True

    async def run_agent_server(self):
        # Force loopback-only regardless of env: the hub-self listener NEVER binds
        # 0.0.0.0 (TLS terminates on the hub's unified :443 surface). The parent's
        # loopback branch binds 127.0.0.1 plaintext on AGENT_PORT_ENV/loopback port.
        os.environ[self.AGENT_LOOPBACK_ENV] = "1"
        return await super().run_agent_server()

    async def run(self):
        # Serve the loopback /ws/agent listener + start the in-process dumb agent
        # that dials it. Do NOT call super().run() — BaseControlPlane.run() dials
        # a hub; the hub-self spoke is in-process and dials only its own loopback.
        self._start_agent_server_task()
        # Give the listener a moment to bind before the client dials (avoids a
        # first-connect refused → backoff cycle on every hub start).
        await asyncio.sleep(0.5)
        self._agent_client_task = asyncio.create_task(self._run_in_process_agent())
        try:
            await asyncio.Event().wait()   # serve forever (until cancelled)
        finally:
            # Cancel the two child tasks so they don't log "Task was destroyed
            # but it is pending!" when the hub shuts down and main.py cancels
            # this run() task. Both are fire-and-forget loops; cancel + await.
            for _t in (getattr(self, "_agent_server_task", None),
                       getattr(self, "_agent_client_task", None)):
                if _t is not None and not _t.done():
                    _t.cancel()
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
        port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_LOOPBACK_PORT)))
        url = f"ws://127.0.0.1:{port}/ws/agent"
        signer = MessageSigner(self.agent_secret)
        backoff = 2
        while True:
            try:
                async with websockets.connect(url) as ws:
                    await ws.send(json.dumps({
                        "agent_id": HUB_SELF_AGENT_ID,
                        "secret": self.agent_secret,
                        "hostname": "hub-self",
                    }))
                    proof = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
                    if proof.get("status") != "HUB_VERIFIED":
                        # Shouldn't happen (shared secret) — backoff + retry.
                        await asyncio.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                        continue
                    await ws.send(json.dumps({"status": "HUB_OK"}))
                    logger.info("hub-self in-process agent connected on %s", url)
                    backoff = 2
                    async for raw in ws:
                        await self._agent_handle_frame(ws, signer, raw)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - reconnect loop
                logger.debug("hub-self agent reconnect (%s): %s", url, e)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    async def _agent_handle_frame(self, ws, signer, raw) -> None:
        try:
            text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            sig, body = split_frame(text)
            msg = json.loads(body)
        except Exception:  # noqa: BLE001 - drop undecodable frames
            return
        if not sig or not signer.verify_bytes(body.encode(), sig):
            return
        corr = msg.get("header", {}).get("correlation_id")
        payload = msg.get("payload", {}) or {}
        cmd = payload.get("type")
        data = payload.get("data") or {}
        # Dispatch in a thread — run_local_command blocks on a subprocess.
        result = await asyncio.to_thread(self._agent_dispatch, cmd, data)
        if corr is not None:
            resp = {"header": {"correlation_id": corr, "sender_id": HUB_SELF_AGENT_ID},
                    "payload": {"type": "AGENT_RESPONSE", "data": result}}
            try:
                await ws.send(encode_frame(signer, resp))
            except Exception:  # noqa: BLE001
                pass

    def _agent_dispatch(self, cmd: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """Generic primitives only — mirrors ``SpokeClient._dispatch``."""
        if cmd in ("HUB_PING", "HEARTBEAT_ACK"):
            return {"status": "SUCCESS"}
        if cmd == "RUN_COMMAND":
            try:
                from command_runner import run_local_command
            except ImportError:  # type: ignore
                return {"status": "ERROR", "message": "command_runner unavailable"}
            res = run_local_command(data.get("command", ""),
                                    bool(data.get("allow_shell", False)),
                                    float(data.get("timeout", 30.0) or 30.0))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        if cmd == "WRITE_FILE":
            res = _write_local_file(data.get("path", ""), data.get("content", ""),
                                    b64=data.get("b64", ""),
                                    mode=int(data.get("mode", 0o600)),
                                    mkdirs=bool(data.get("mkdirs", True)),
                                    atomic=bool(data.get("atomic", True)))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        return {"status": "ERROR", "message": f"unsupported: {cmd}"}

    # ── Hub-facing helpers (called by _install_cert_on_hub) ─────────────────

    async def write_file(self, path: str, content: str, mode: int = 0o600,
                         timeout: float = _WRITE_TIMEOUT) -> Dict[str, Any]:
        """WRITE_FILE to the in-process agent. Returns the AGENT_RESPONSE data
        (``{status, result, message}``) — ``status == "SUCCESS"`` +
        ``result.ok`` means the file landed."""
        return await self.send_to_agent(
            "WRITE_FILE",
            {"path": path, "content": content, "mode": mode, "atomic": True},
            agent_id=HUB_SELF_AGENT_ID, timeout=timeout)

    async def run_command(self, command: str, allow_shell: bool = True,
                          timeout: float = 10.0) -> Dict[str, Any]:
        """RUN_COMMAND on the in-process agent. Used for ``lm-self-restart``
        (backgrounded so the agent responds before the restart kills the hub)."""
        return await self.send_to_agent(
            "RUN_COMMAND",
            {"command": command, "allow_shell": allow_shell, "timeout": timeout},
            agent_id=HUB_SELF_AGENT_ID, timeout=timeout + 5.0)