"""Spoke-client "device mode" for the Agent.

The dumb Agent dials its **spoke's** ``/ws/agent`` listener (never the hub) and
executes whatever the spoke tells it — generic primitives only (``RUN_COMMAND`` /
``WRITE_FILE``). All hub-bound traffic goes Agent→Spoke→Hub via the spoke's
``AGENT_RELAY_UP``; the Agent has no hub URL or hub creds.

Wire protocol (matches ``core/src/messaging/agent_hosting.py``):
  * connect wss/ws → handshake ``{agent_id, secret?}`` → ``APPROVAL_REQUIRED``
    (pend, then ``APPROVED``+secret) or ``HUB_VERIFIED`` → send ``HUB_OK``.
  * frames are ``<sig>.<body>``; body = ``{header:{correlation_id}, payload:{type,data}}``.
  * reply with ``{header:{correlation_id}, payload:{type:"AGENT_RESPONSE", data:result}}``.

Protocol-compatible with the pxmx node-agent; product-agnostic (no pvesh/qm).
"""

import asyncio
import json
import logging
import os
import ssl as _ssl

import websockets

try:
    from core.src.security.signer import MessageSigner, encode_frame, split_frame
except ImportError:  # bare-module layout (/opt/lm/core on sys.path)
    from security.signer import MessageSigner, encode_frame, split_frame

logger = logging.getLogger("Agent.SpokeClient")

_AGENT_WS_PATH = "/ws/agent"


def normalize_spoke_url(url: str) -> str:
    """Fill scheme/port/path → ``wss://host:443/ws/agent`` (or as given)."""
    u = (url or "").strip()
    if not u:
        return u
    if "://" not in u:
        u = "wss://" + u
    scheme, rest = u.split("://", 1)
    host_port, _, path = rest.partition("/")
    if ":" not in host_port:
        host_port += ":443" if scheme == "wss" else ":8767"
    path = "/" + path if path else ""
    if not path.endswith(_AGENT_WS_PATH):
        path = _AGENT_WS_PATH
    return f"{scheme}://{host_port}{path}"


class SpokeClient:
    """A generic dumb executor that dials a spoke and runs primitives."""

    def __init__(self, agent_id: str, spoke_url: str, secret: str = "",
                 secret_path: str = ""):
        self.agent_id = agent_id
        self.spoke_url = normalize_spoke_url(spoke_url)
        self.secret = secret or ""
        self.secret_path = secret_path or os.path.expanduser("~/.lm-agent-secret")
        self.signer = MessageSigner(self.secret)
        self.hostname = os.uname().nodename if hasattr(os, "uname") else ""
        self.websocket = None
        self._stop = False
        if not self.secret:
            self._load_secret()

    # ── secret persistence (provisioned on approval) ────────────────────────
    def _load_secret(self):
        try:
            if os.path.exists(self.secret_path):
                with open(self.secret_path) as f:
                    self.secret = f.read().strip()
                self.signer = MessageSigner(self.secret)
        except Exception as e:  # noqa: BLE001
            logger.debug("secret load skipped: %s", e)

    def _save_secret(self, secret: str):
        try:
            with open(self.secret_path, "w") as f:
                f.write(secret)
            os.chmod(self.secret_path, 0o600)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not persist provisioned secret: %s", e)

    def _ssl_ctx(self):
        if self.spoke_url.startswith("wss://"):
            # Unverified for now; mTLS verification is plumbed + flag-gated later.
            return _ssl._create_unverified_context()
        return None

    # ── run loop ────────────────────────────────────────────────────────────
    async def run(self):
        backoff = 5
        while not self._stop:
            try:
                await self._connect_once()
                backoff = 5
            except Exception as e:  # noqa: BLE001
                logger.warning("spoke connection to %s failed: %s — retry in %ss",
                               self.spoke_url, e, backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300)

    async def _connect_once(self):
        logger.info("Agent (device mode) → dialing spoke %s", self.spoke_url)
        async with websockets.connect(self.spoke_url, ssl=self._ssl_ctx()) as ws:
            self.websocket = ws
            handshake = {"agent_id": self.agent_id}
            if self.secret:
                handshake["secret"] = self.secret
            if self.hostname:
                handshake["hostname"] = self.hostname
            await ws.send(json.dumps(handshake))

            proof = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            status = proof.get("status")
            if status == "APPROVAL_REQUIRED":
                logger.info("Agent '%s' pending admin approval (Setup → Spokes & "
                            "Agents).", self.agent_id)
                async for raw in ws:
                    msg = json.loads(raw if raw[:1] == "{" else split_frame(raw)[1])
                    if msg.get("status") == "APPROVED" and msg.get("secret"):
                        self.secret = msg["secret"]
                        self.signer = MessageSigner(self.secret)
                        self._save_secret(self.secret)
                        logger.info("Agent '%s' approved — reconnecting with secret.",
                                    self.agent_id)
                        return
                return
            if status != "HUB_VERIFIED":
                await ws.close(1008, "spoke identity not verified")
                raise RuntimeError(f"spoke identity proof failed: {proof}")
            await ws.send(json.dumps({"status": "HUB_OK"}))
            logger.info("Agent '%s' authenticated to spoke.", self.agent_id)

            hb = asyncio.create_task(self._heartbeat_loop())
            try:
                async for message in ws:
                    await self._handle_frame(ws, message)
            finally:
                hb.cancel()

    async def _handle_frame(self, ws, message):
        try:
            sig, body = split_frame(message)
            msg = json.loads(body)
        except Exception:  # noqa: BLE001
            return
        if sig and not self.signer.verify_bytes(body.encode(), sig):
            logger.warning("invalid signature — dropping")
            return
        payload = msg.get("payload", {})
        cmd = payload.get("type")
        data = payload.get("data", {}) or {}
        corr = msg.get("header", {}).get("correlation_id")
        result = await self._dispatch(cmd, data)
        if corr is not None:
            resp = {"header": {"correlation_id": corr, "sender_id": self.agent_id},
                    "payload": {"type": "AGENT_RESPONSE", "data": result}}
            try:
                await ws.send(encode_frame(self.signer, resp))
            except Exception as e:  # noqa: BLE001
                logger.debug("response send failed: %s", e)

    async def _dispatch(self, cmd, data):
        """Generic primitives ONLY — the spoke holds all product logic."""
        from command_runner import run_local_command, write_local_file
        if cmd in ("HUB_PING", "HEARTBEAT_ACK"):
            return {"status": "SUCCESS"}
        if cmd == "RUN_COMMAND":
            res = await asyncio.to_thread(
                run_local_command, data.get("command", ""),
                bool(data.get("allow_shell", False)),
                float(data.get("timeout", 30.0) or 30.0))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        if cmd == "WRITE_FILE":
            res = await asyncio.to_thread(
                write_local_file, data.get("path", ""), data.get("content", ""),
                b64=data.get("b64", ""), mode=int(data.get("mode", 0o600)),
                mkdirs=bool(data.get("mkdirs", True)),
                atomic=bool(data.get("atomic", True)))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        logger.debug("device-mode agent got non-primitive command %s (ignored)", cmd)
        return {"status": "ERROR", "message": f"unsupported in device mode: {cmd}"}

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(30)
            try:
                msg = {"header": {"sender_id": self.agent_id},
                       "payload": {"type": "HEARTBEAT",
                                   "data": {"agent_id": self.agent_id}}}
                await self.websocket.send(encode_frame(self.signer, msg))
            except Exception:  # noqa: BLE001
                return
