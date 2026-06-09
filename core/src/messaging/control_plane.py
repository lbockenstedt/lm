import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
from typing import Dict, Any, Type
from .protocol import Message, MessageHeader, MessagePayload

logger = logging.getLogger("BaseControlPlane")

class BaseControlPlane:
    """
    Generic Control Plane for Lab Manager Spokes.
    Handles Hub connectivity, mutual authentication, and module routing.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_secret = hub_secret
        self.hub_url = hub_url
        self.modules: Dict[str, Any] = {} # { module_name: BaseSpoke instance }

    def register_module(self, name: str, module_instance: Any):
        """Registers a module to be handled by this control plane."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Main loop for the control plane."""
        logger.info(f"Starting Control Plane in HUB MODE -> {self.hub_url}")

        async with websockets.connect(self.hub_url) as websocket:
            # 1. Spoke Authentication Handshake
            await websocket.send(json.dumps({"spoke_id": self.spoke_id, "secret": self.secret}))
            logger.info(f"Connected to Lab Manager Hub as {self.spoke_id}. Performing mutual authentication...")

            # 2. Hub Mutual Authentication (Verify Hub's identity)
            try:
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)

                if hub_proof.get("status") == "HUB_VERIFIED":
                    challenge = hub_proof.get("challenge")
                    signature = hub_proof.get("signature")

                    if self.hub_secret:
                        expected_sig = hmac.new(
                            self.hub_secret.encode(),
                            challenge.encode(),
                            hashlib.sha256
                        ).hexdigest()

                        if hmac.compare_digest(expected_sig, signature):
                            logger.info("Hub identity verified successfully.")
                            await websocket.send(json.dumps({"status": "HUB_OK"}))
                        else:
                            logger.error("Hub identity verification failed: Invalid signature.")
                            await websocket.close(1008, "Hub verification failed")
                            return
                    else:
                        logger.warning("Hub secret not configured. Skipping Hub identity verification (Insecure).")
                        await websocket.send(json.dumps({"status": "HUB_OK"}))
                else:
                    logger.error(f"Unexpected response during Hub verification: {hub_proof.get('status')}")
                    await websocket.close(1008, "Mutual authentication failed")
                    return
            except Exception as e:
                logger.error(f"Hub verification timed out or failed: {e}")
                await websocket.close(1008, "Mutual authentication timed out")
                return

            # Heartbeat loop
            async def heartbeat():
                while True:
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "HEARTBEAT", "data": {}}
                    }
                    msg["signature"] = self._sign(msg)
                    await websocket.send(json.dumps(msg))
                    await asyncio.sleep(30)

            asyncio.create_task(heartbeat())

            # Main Message Loop
            async for message in websocket:
                msg = json.loads(message)
                if not self._verify_signature(msg):
                    continue

                payload = msg.get("payload", {})
                cmd_type = payload.get("type")
                data = payload.get("data", {})
                corr_id = msg.get("header", {}).get("message_id")

                # Route to the appropriate module
                # If a module explicitly handles this command_type, use it.
                # Otherwise, try all registered modules.
                result = None
                for module_name, module in self.modules.items():
                    # We check if the command_type is specific to this module
                    # In a real system, cmd_type might be "pxmx.get_vms"
                    if cmd_type.startswith(module_name) or self._module_handles_command(module, cmd_type):
                        result = await module.handle_command(cmd_type, data)
                        break

                if result is None and self.modules:
                    # Fallback: Try the first module if no specific match
                    first_mod = list(self.modules.values())[0]
                    result = await first_mod.handle_command(cmd_type, data)

                resp = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                               "sender_id": self.spoke_id, "destination_id": "hub",
                               "correlation_id": corr_id},
                    "payload": {"type": "COMMAND_RESULT", "data": result}
                }
                resp["signature"] = self._sign(resp)
                await websocket.send(json.dumps(resp))

    def _module_handles_command(self, module, cmd_type: str) -> bool:
        """Check if a module should handle a specific command type."""
        # This can be expanded with a registry of commands per module
        return True # Default to true for now, let the module decide

    def _sign(self, msg):
        data = {k: v for k, v in msg.items() if k != "signature"}
        message_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        return hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

    def _verify_signature(self, msg):
        sig = msg.get("signature")
        data = {k: v for k, v in msg.items() if k != "signature"}
        message_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        expected = hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
