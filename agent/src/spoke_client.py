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
import uuid
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
                 secret_path: str = "", install_uuid_path: str = ""):
        self.agent_id = agent_id
        self.spoke_url = normalize_spoke_url(spoke_url)
        self.secret = secret or ""
        self.secret_path = secret_path or os.path.expanduser("~/.lm-agent-secret")
        self.install_uuid_path = install_uuid_path or os.path.expanduser(
            "~/.lm-agent-install-uuid")
        self.signer = MessageSigner(self.secret)
        self.hostname = os.uname().nodename if hasattr(os, "uname") else ""
        self.websocket = None
        self._stop = False
        # Stable per-install guid (Phase 1): lets the hub address this node
        # agent by guid, not its observable agent_id/hostname. Minted on first
        # start, persisted next to the secret (chmod 600); "" on write failure
        # (legacy — hub treats an absent guid as spoke_id-keyed, no flip).
        self.install_uuid = self._ensure_install_uuid()
        # Cert self-heal fallback: if an mTLS connect fails (the wildcard cert is
        # expired/broken so verification can't complete), the NEXT attempt drops
        # to the plain PSK-authenticated channel (encrypted, unverified) purely to
        # let the spoke re-deploy a fresh cert (_on_agent_registered custodian
        # deploy). Once connected + cert refreshed, mTLS resumes automatically.
        self._mtls_fallback = False
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

    def _ensure_install_uuid(self) -> str:
        """Stable per-install guid for a device-mode node agent — minted on
        first start and persisted next to the agent secret (chmod 600), so a
        process restart reuses the SAME guid and the hub can address it by guid
        instead of its observable agent_id/hostname. Re-imaging clears it (a
        fresh identity), mirroring spokes' INSTALL_UUID semantics. Returns ''
        on write failure so the identity never flips per boot (hub treats ''
        as legacy spoke_id-keyed)."""
        path = self.install_uuid_path
        try:
            if os.path.exists(path):
                with open(path) as f:
                    val = f.read().strip()
                if val:
                    return val
            new_uuid = str(uuid.uuid4())
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(new_uuid)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except Exception:  # noqa: BLE001
                pass
            return new_uuid
        except Exception as e:  # noqa: BLE001
            logger.debug("install_uuid persist skipped: %s", e)
            return ""

    def _build_handshake(self) -> dict:
        """The /ws/agent auth frame: agent_id + optional secret/hostname +
        the per-install guid (so the hub's AGENT_RELAY_UP carries a stable,
        non-observable identity, not just the agent_id/hostname)."""
        hs = {"agent_id": self.agent_id}
        if self.secret:
            hs["secret"] = self.secret
        if self.hostname:
            hs["hostname"] = self.hostname
        if self.install_uuid:
            hs["install_uuid"] = self.install_uuid
        return hs

    def _ssl_ctx(self):
        # mTLS-aware (plumbed, default-off): today's unverified-but-encrypted
        # context unless LM_MTLS_ENABLED — then verify the spoke against the CA
        # and present the client cert. See core/src/security/mtls.py.
        is_wss = self.spoke_url.startswith("wss://")
        if not is_wss:
            return None
        # Self-heal: this attempt is a cert-refresh recovery → force the plain
        # unverified context so a broken/expired cert can't block reconnection.
        if self._mtls_fallback:
            return _ssl._create_unverified_context()
        try:
            try:
                from core.src.security.mtls import client_context
            except ImportError:
                from security.mtls import client_context
            return client_context(is_wss)
        except Exception:  # noqa: BLE001 - fall back to today's behavior
            return _ssl._create_unverified_context()

    # ── run loop ────────────────────────────────────────────────────────────
    async def run(self):
        backoff = 5
        while not self._stop:
            was_fallback = self._mtls_fallback
            try:
                await self._connect_once()
                self._mtls_fallback = False  # connected cleanly → resume mTLS
                backoff = 5
            except Exception as e:  # noqa: BLE001
                # If an mTLS attempt failed, the next attempt drops to the plain
                # PSK channel for a cert-refresh recovery (self-heal). If the
                # fallback attempt ALSO failed, go back to mTLS next (avoid
                # sticking in plain mode).
                try:
                    try:
                        from core.src.security.mtls import mtls_enabled as _me
                    except ImportError:
                        from security.mtls import mtls_enabled as _me
                    mtls_on = _me()
                except Exception:  # noqa: BLE001
                    mtls_on = False
                self._mtls_fallback = bool(mtls_on and not was_fallback)
                logger.warning("spoke connection to %s failed: %s — retry in %ss%s",
                               self.spoke_url, e, backoff,
                               " (cert-refresh fallback)" if self._mtls_fallback else "")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300)

    async def _connect_once(self):
        logger.info("Agent (device mode) → dialing spoke %s", self.spoke_url)
        async with websockets.connect(self.spoke_url, ssl=self._ssl_ctx()) as ws:
            self.websocket = ws
            await ws.send(json.dumps(self._build_handshake()))

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
