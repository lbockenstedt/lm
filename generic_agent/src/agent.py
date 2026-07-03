import asyncio
import json
import uuid
import time
import logging
import psutil
import argparse
import os
import ssl
import socket
import sys
from typing import Dict, Any, Optional

# Make this file's dir importable so the vendored hub_discovery.py resolves
# regardless of PYTHONPATH (the systemd unit sets PYTHONPATH=/opt/lm, which
# does NOT include generic-agent/src).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Logging: write to stderr only — do NOT open a log file from the agent. The
# systemd unit captures stderr to /var/log/lm/agent.log
# (StandardOutput/StandardError=append:...), and the systemd manager opens that
# file as root. This service runs as User=svc_lm, so a svc_lm FileHandler can't
# append to the root-owned file systemd created (PermissionError → crash-loop).
# Logging to stderr and letting systemd own the file works for any service
# User= and keeps a single canonical log under /var/log/lm. A manual run just
# sees the same output on the console.
try:
    from logging_setup import configure_logging, set_log_level
except ImportError:
    try:
        from core.src.logging_setup import configure_logging, set_log_level
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
        def set_log_level(enabled):
            level = _logging.DEBUG if enabled else _logging.INFO
            _logging.getLogger().setLevel(level)
            for _n in list(_logging.root.manager.loggerDict):
                _logging.getLogger(_n).setLevel(level)
            return level
configure_logging()
logger = logging.getLogger("GenericLeafAgent")

# Hub auto-discovery (vendored copy kept byte-identical to lm core + pxmx).
# Resolves same-box → ws://127.0.0.1:8765 (loopback plain) vs remote →
# wss://<hub>:443 (TLS) from the hub's mDNS TXT tls_port / DNS lm-hub.<suffix>.
try:
    from hub_discovery import discover_hub_url
except ImportError:  # dev box without the vendored copy on path
    try:
        from core.src.messaging.hub_discovery import discover_hub_url
    except ImportError:
        discover_hub_url = None
        logger.warning("hub_discovery module unavailable — --spoke-url must be pinned.")


class GenericLeafAgent:
    def __init__(self, spoke_url: str, agent_id: str, secret: Optional[str] = None):
        # spoke_url may be a concrete URL, "" / "auto" (auto-discover), or a pin.
        self.spoke_url = self._normalize_url(spoke_url or "auto")
        self.agent_id = agent_id
        self.secret = secret or self._load_secret()
        # No secret is OK — agent will connect unauthenticated and await admin approval.
        # TLS trust for wss:// connects (mirrors BaseControlPlane._client_ssl_ctx):
        # verify OFF by default (self-signed hub cert → encrypt without auth, the
        # lab default); LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT verifies against a CA.
        self._tls_verify = os.environ.get("LM_HUB_TLS_VERIFY", "0").strip() in ("1", "true", "yes")
        self._tls_ca_cert = os.environ.get("LM_HUB_CA_CERT", "").strip()

        logger.info(f"Initializing GenericLeafAgent [{agent_id}] -> {spoke_url or 'auto'}")
        self.websocket = None
        self.config = {}

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize a pinned spoke URL against the hub's two-listener contract:
        port 8765 is the loopback *plaintext* listener, port 443 is the remote
        *TLS* (wss://) listener. A pinned ``ws://<host>:443`` is plaintext to a
        TLS port — the server does a TLS handshake and the client's plaintext
        HTTP upgrade reads as gibberish → ``InvalidMessage: did not receive a
        valid HTTP response``. That pin is a stale pre-TLS-rollout value; upgrade
        it to ``wss://`` so it works without an operator edit. ``ws://`` on any
        other port (e.g. 8765 loopback) and the ``auto`` sentinel are untouched.
        """
        if not url or url == "auto" or not url.lower().startswith("ws://"):
            return url
        try:
            from urllib.parse import urlparse
            port = urlparse(url).port
        except Exception:
            port = None
        if port == 443:
            upgraded = "wss://" + url[len("ws://"):]
            logger.info("Upgrading pinned %s → %s (port 443 is the hub's TLS listener)", url, upgraded)
            return upgraded
        return url

    def _load_secret(self) -> Optional[str]:
        config_path = "/etc/lm-agent/config.json"
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return json.load(f).get("secret")
        except Exception as e:
            logger.error(f"Failed to load secret: {e}")
        return None

    async def _resolve_spoke_url(self) -> None:
        """When spoke_url is the auto-discovery sentinel, locate the hub via
        DNS (lm-hub.<suffix>) then mDNS and set spoke_url to the result. A
        co-located agent gets ws://127.0.0.1:8765; a remote one gets
        wss://<hub>:443 when the hub advertises TLS."""
        if self.spoke_url not in ("", "auto", None):
            return
        if discover_hub_url is None:
            logger.warning("Cannot auto-discover hub (hub_discovery unavailable); "
                           "pass --spoke-url to pin.")
            return
        url = discover_hub_url(timeout=5.0)
        if url:
            self.spoke_url = url
            logger.info(f"Auto-discovered hub at {url}")
        else:
            logger.warning("Hub auto-discovery found no hub (no lm-hub DNS record / "
                           "mDNS broadcast); will retry on reconnect. Pass --spoke-url to pin.")

    def _client_ssl_ctx(self):
        """SSL context for a wss:// connect. Default: unverified (encrypt
        without authenticating the self-signed hub cert). Verify-on with
        LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT. Returns None on build failure so
        the caller connects without TLS and fails fast (surfacing the
        misconfiguration instead of hanging)."""
        try:
            if self._tls_verify and self._tls_ca_cert:
                ctx = ssl.create_default_context(cafile=self._tls_ca_cert)
                logger.info("wss: verifying hub cert against CA %s", self._tls_ca_cert)
                return ctx
            ctx = ssl._create_unverified_context()
            logger.debug("wss: using unverified context (set LM_HUB_TLS_VERIFY=1 "
                         "+ LM_HUB_CA_CERT to verify)")
            return ctx
        except Exception as e:
            logger.error("Could not build wss SSL context: %s — connecting without TLS", e)
            return None

    async def collect_metrics(self) -> Dict[str, Any]:
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "timestamp": time.time()
        }

    async def run(self):
        """Reconnect loop: resolve the hub, connect, serve, back off on loss.
        Re-discovers each pass while the URL is still the sentinel so a hub that
        comes up after this agent (or moves) is found without a restart. When
        discovery can't find a hub yet, it backs off and retries discovery next
        pass — it must NOT try to connect to the literal "auto" sentinel, which
        is not a URI (``websockets.connect("auto")`` → InvalidURI)."""
        backoff = 5
        while True:
            # Resolve the sentinel each pass (a concrete pin is left untouched) so
            # a hub that appears later is picked up without a restart.
            if self.spoke_url in ("", "auto", None):
                await self._resolve_spoke_url()
            # Discovery may still have nothing — back off + re-discover instead of
            # connecting to the "auto" string (InvalidURI spam every 5s).
            if self.spoke_url in ("", "auto", None):
                logger.info("No hub discovered yet; retrying in %ss (pass --spoke-url to pin).", backoff)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            try:
                await self._connect_once()
                backoff = 5  # clean disconnect → reset
            except (OSError, asyncio.TimeoutError) as e:
                logger.warning(f"Connection to {self.spoke_url} failed: {e} — retrying in {backoff}s")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)
            except Exception as e:
                logger.error(f"Unexpected connection error: {e} — retrying in {backoff}s")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120)
            await asyncio.sleep(backoff)

    async def _connect_once(self):
        import websockets
        # TLS: wss:// gets an SSL context (verify-off default for the self-signed
        # hub cert; LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT verifies). ws:// stays
        # plaintext (loopback / legacy). compression=None sidesteps the
        # per-message-deflate desync the rest of the codebase guards against.
        ssl_ctx = self._client_ssl_ctx() if self.spoke_url.lower().startswith("wss://") else None
        if ssl_ctx is None:
            _tls_mode = "plaintext (loopback/legacy)"
        elif self._tls_verify and self._tls_ca_cert:
            _tls_mode = f"TLS verified (CA={self._tls_ca_cert})"
        else:
            _tls_mode = "TLS unverified (self-signed hub cert)"
        logger.info(f"Connecting to Spoke Gateway at {self.spoke_url}... [{_tls_mode}]")

        async with websockets.connect(self.spoke_url, compression=None, ssl=ssl_ctx) as websocket:
            self.websocket = websocket

            # 1. Handshake: prove agent identity to the Hub. The hub's spoke
            #    endpoint reads `spoke_id` (+ optional module_type/hostname) —
            #    NOT `agent_id` — so use the hub's envelope. module_type "agent"
            #    routes this spoke into the WebUI "Generic Nodes" list. No secret
            #    is valid at first install: the hub keeps the connection open in
            #    pending-negotiation and an admin approves it there, after which
            #    the hub negotiates a session secret.
            auth_msg = {
                "spoke_id": self.agent_id,
                "module_type": "agent",
                "secret": self.secret,
            }
            try:
                auth_msg["hostname"] = socket.gethostname()
            except Exception:
                pass
            await websocket.send(json.dumps(auth_msg))
            logger.info(f"Handshake sent for spoke {self.agent_id}")

            # 2. Mutual Auth: the hub proves its identity. A secret-less (pending)
            #    install may send HUB_VERIFIED (we reply HUB_OK) or skip straight
            #    to APPROVAL_REQUIRED — both are normal. Stay connected either way
            #    so the heartbeat loop keeps us alive while an admin approves.
            try:
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)
                if hub_proof.get("status") == "HUB_VERIFIED":
                    logger.info("Hub identity verified. Sending HUB_OK.")
                    await websocket.send(json.dumps({"status": "HUB_OK"}))
                else:
                    _what = hub_proof.get("status") or (hub_proof.get("payload") or {}).get("type")
                    logger.info(f"Pending approval on hub (received {_what}); awaiting admin approval.")
            except Exception as e:
                logger.warning(f"Mutual authentication not performed or failed: {e}")

            # 3. Background Tasks
            heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            telemetry_task = asyncio.create_task(self._telemetry_loop())

            try:
                async for message in websocket:
                    msg_data = json.loads(message)
                    logger.debug(f"Received message: {msg_data}")

                    # Leaf agents receive SPOKE_COMMAND from the Gateway
                    if msg_data.get("type") == "SPOKE_COMMAND":
                        command = msg_data.get("command")
                        params = msg_data.get("params", {})
                        corr_id = msg_data.get("correlation_id")

                        logger.info(f"Executing command: {command}")
                        result = await self.handle_command(command, params)

                        # Response wrapped in AGENT_RESPONSE
                        resp = {
                            "header": {
                                "message_id": str(uuid.uuid4()),
                                "correlation_id": corr_id,
                                "timestamp": time.time(),
                                "sender_id": self.agent_id,
                                "destination_id": "gateway"
                            },
                            "payload": {"type": "AGENT_RESPONSE", "data": result}
                        }
                        await websocket.send(json.dumps(resp))

            finally:
                heartbeat_task.cancel()
                telemetry_task.cancel()

    async def handle_command(self, command: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if command == "GET_SYSTEM_STATS":
            return await self.collect_metrics()

        if command == "SET_LOG_LEVEL":
            enabled = params.get("enabled", False)
            level = set_log_level(enabled)
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

        if command == "UPDATE_CONFIG":
            self.config = params
            return {"status": "SUCCESS", "message": "Config updated"}

        return {"status": "ERROR", "message": f"Unknown command: {command}"}

    async def _heartbeat_loop(self):
        while True:
            try:
                msg = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                               "sender_id": self.agent_id, "destination_id": "gateway"},
                    "payload": {"type": "AGENT_HEARTBEAT", "data": {}}
                }
                await self.websocket.send(json.dumps(msg))
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f"Heartbeat failed: {e}")
                await asyncio.sleep(5)

    async def _telemetry_loop(self):
        while True:
            try:
                metrics = await self.collect_metrics()
                msg = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                               "sender_id": self.agent_id, "destination_id": "gateway"},
                    "payload": {"type": "AGENT_TELEMETRY", "data": {"metrics": metrics}}
                }
                await self.websocket.send(json.dumps(msg))
                await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"Telemetry failed: {e}")
                await asyncio.sleep(10)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # --spoke-url is now optional: omit it (or pass "auto") to let the agent
    # auto-discover the hub (same-box ws://127.0.0.1:8765, remote wss://:443).
    # Pin a concrete URL to override.
    parser.add_argument("--spoke-url", default="auto",
                        help="URL of the Spoke Gateway (or 'auto' to discover; default)")
    parser.add_argument("--id", default="generic-agent-1", help="Agent ID")
    parser.add_argument("--secret", help="Agent session secret")
    args = parser.parse_args()

    try:
        agent = GenericLeafAgent(args.spoke_url, args.id, args.secret)
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.exception(f"Critical failure: {e}")