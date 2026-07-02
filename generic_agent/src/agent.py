import asyncio
import json
import uuid
import time
import logging
import psutil
import argparse
import os
import socket
from typing import Dict, Any, Optional

# Setup logging to both console and file
def get_log_path():
    # Log under /var/log/lm alongside the hub + spokes (the installer creates
    # /var/log/lm and chowns it to svc_lm so the systemd service can write
    # here). Falls back to a local logs/ dir if that path isn't writable
    # (e.g. run by hand as an unprivileged user without the install step).
    primary = "/var/log/lm/generic-agent.log"
    try:
        with open(primary, "a") as f:
            pass
        return primary
    except Exception:
        local_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(local_dir, exist_ok=True)
        return os.path.join(local_dir, "generic-agent.log")

log_file = get_log_path()
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
configure_logging(log_file=log_file)
logger = logging.getLogger("GenericLeafAgent")

class GenericLeafAgent:
    def __init__(self, spoke_url: str, agent_id: str, secret: Optional[str] = None):
        self.spoke_url = spoke_url
        self.agent_id = agent_id
        self.secret = secret or self._load_secret()
        # No secret is OK — agent will connect unauthenticated and await admin approval.

        logger.info(f"Initializing GenericLeafAgent [{agent_id}] -> {spoke_url}")
        self.websocket = None
        self.config = {}

    def _load_secret(self) -> Optional[str]:
        config_path = "/etc/lm-agent/config.json"
        try:
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return json.load(f).get("secret")
        except Exception as e:
            logger.error(f"Failed to load secret: {e}")
        return None

    async def collect_metrics(self) -> Dict[str, Any]:
        return {
            "cpu_usage": psutil.cpu_percent(interval=1),
            "memory_usage": psutil.virtual_memory().percent,
            "disk_usage": psutil.disk_usage('/').percent,
            "timestamp": time.time()
        }

    async def run(self):
        import websockets
        logger.info(f"Connecting to Spoke Gateway at {self.spoke_url}...")

        async with websockets.connect(self.spoke_url) as websocket:
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
    parser.add_argument("--spoke-url", required=True, help="URL of the Spoke Gateway")
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
