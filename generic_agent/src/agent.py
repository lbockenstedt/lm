import asyncio
import json
import uuid
import time
import logging
import psutil
import argparse
import os
from typing import Dict, Any, Optional

# Setup logging to both console and file
def get_log_path():
    primary = "/var/log/generic-agent.log"
    try:
        with open(primary, "a") as f:
            pass
        return primary
    except Exception:
        local_dir = os.path.join(os.getcwd(), "logs")
        os.makedirs(local_dir, exist_ok=True)
        return os.path.join(local_dir, "generic-agent.log")

log_file = get_log_path()
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
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

            # 1. Handshake: Prove Agent identity to Gateway
            auth_msg = {
                "agent_id": self.agent_id,
                "secret": self.secret
            }
            await websocket.send(json.dumps(auth_msg))
            logger.info(f"Handshake sent for agent {self.agent_id}")

            # 2. Mutual Auth: Gateway proves identity to Agent
            try:
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)
                if hub_proof.get("status") == "HUB_VERIFIED":
                    logger.info("Gateway identity verified. Sending HUB_OK.")
                    await websocket.send(json.dumps({"status": "HUB_OK"}))
                else:
                    logger.error(f"Gateway failed to prove identity: {hub_proof}")
                    await websocket.close(1008, "Gateway identity not verified")
                    return
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
            level = logging.DEBUG if enabled else logging.INFO
            logging.getLogger().setLevel(level)
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
