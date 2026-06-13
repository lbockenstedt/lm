import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
import subprocess
import os
from typing import Dict, Any, Type
from .protocol import Message, MessageHeader, MessagePayload
from ..security.signer import MessageSigner

logger = logging.getLogger("BaseControlPlane")

class BaseControlPlane:
    """
    Generic Control Plane for Lab Manager Spokes.
    Handles Hub connectivity, mutual authentication, and module routing.
    """
    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None, hub_url: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_secrets = [hub_secret] if hub_secret else []
        self.hub_url = hub_url
        self.modules: Dict[str, Any] = {} # { module_name: BaseSpoke instance }
        self.signer = MessageSigner(secret) if secret else None


    def register_module(self, name: str, module_instance: Any):
        """Registers a module to be handled by this control plane."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Main loop for the control plane."""
        logger.info(f"Starting Control Plane in HUB MODE -> {self.hub_url}")

        async with websockets.connect(self.hub_url) as websocket:
            # 1. Spoke Authentication Handshake
            auth_payload = {"spoke_id": self.spoke_id}
            if self.secret:
                auth_payload["secret"] = self.secret

            await websocket.send(json.dumps(auth_payload, separators=(',', ':')))
            logger.info(f"Connected to Lab Manager Hub as {self.spoke_id}. Performing mutual authentication...")

            # 2. Hub Mutual Authentication (Verify Hub's identity)
            try:
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)

                if hub_proof.get("status") == "HUB_VERIFIED":
                    challenge = hub_proof.get("challenge")
                    signature = hub_proof.get("signature")

                    if self.hub_secrets:
                        verified = False
                        for hs in self.hub_secrets:
                            expected_sig = hmac.new(
                                hs.encode(),
                                challenge.encode(),
                                hashlib.sha256
                            ).hexdigest()
                            if hmac.compare_digest(expected_sig, signature):
                                verified = True
                                break

                        if verified:
                            logger.info("Hub identity verified successfully.")
                            await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                        else:
                            logger.error("Hub identity verification failed: Invalid signature for all known secrets.")
                            await websocket.close(1008, "Hub verification failed")
                            return
                    else:
                        logger.warning("Hub secrets not configured. Skipping Hub identity verification (Insecure).")
                        await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
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
                    ts = round(time.time(), 6)
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "HEARTBEAT", "data": {}}
                    }
                    msg["signature"] = self._sign(msg)
                    await websocket.send(json.dumps(msg, separators=(',', ':')))
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

                # First, try handling as a system command
                result = await self.handle_system_command(cmd_type, data)

                # Route to the appropriate module if not handled by system
                if result is None:
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

                ts = round(time.time(), 6)
                resp = {
                    "correlation_id": corr_id,
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "COMMAND_RESULT", "data": result}
                }
                resp["signature"] = self._sign(resp)
                await websocket.send(json.dumps(resp, separators=(',', ':')))

    def _module_handles_command(self, module, cmd_type: str) -> bool:
        """Check if a module should handle a specific command type."""
        # This can be expanded with a registry of commands per module
        return True # Default to true for now, let the module decide

    async def handle_system_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Handles commands that affect the entire spoke system rather than a specific module."""
        if cmd_type == "SPOKE_UPDATE":
            repo_url = data.get("repo_url")
            if not repo_url:
                return {"status": "ERROR", "message": "Missing repo_url for update"}

            try:
                # Identify spoke root directory (assuming the control plane is running from src/...)
                # e.g. /opt/lm/pxmx/src/control_plane.py -> /opt/lm/pxmx
                cwd = os.path.abspath(os.getcwd())
                # If we are in a src folder, go up one level
                if cwd.endswith("src"):
                    cwd = os.path.dirname(cwd)

                logger.info(f"Performing update in {cwd} from {repo_url}...")

                # 1. Update remote origin
                subprocess.run(["git", "remote", "set-url", "origin", repo_url], cwd=cwd, check=True)

                # 2. Pull latest changes
                subprocess.run(["git", "pull"], cwd=cwd, check=True)

                # 3. Restart the service
                # Derive service name from spoke_id (e.g., pxmx-spoke-1 -> lm-pxmx)
                module_name = self.spoke_id.split("-")[0]
                service_name = f"lm-{module_name}"

                logger.info(f"Restarting service {service_name}...")
                subprocess.Popen(["sudo", "systemctl", "restart", service_name])

                return {"status": "SUCCESS", "message": f"Updated from {repo_url} and triggered restart of {service_name}"}
            except Exception as e:
                logger.error(f"SPOKE_UPDATE failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        if cmd_type == "SPOKE_SET_HUB_SECRET":
            new_secret = data.get("hub_secret")
            if new_secret:
                self.hub_secrets.insert(0, new_secret)
                self.hub_secrets = self.hub_secrets[:3] # Window of 3
                logger.info(f"Hub secret updated for {self.spoke_id}. Current window size: {len(self.hub_secrets)}")
                return {"status": "SUCCESS", "message": "Hub secret updated successfully"}
            return {"status": "ERROR", "message": "Missing hub_secret in data"}

        if cmd_type == "SPOKE_UPDATE_SESSION_KEY":
            new_secret = data.get("secret")
            if new_secret:
                self.secret = new_secret
                self.signer = MessageSigner(new_secret)
                logger.info(f"Session key updated for {self.spoke_id}")
                return {"status": "SUCCESS", "message": "Session key updated successfully"}
            return {"status": "ERROR", "message": "Missing secret in data"}

        if cmd_type == "SPOKE_SET_HOSTNAME":
            new_hostname = data.get("hostname")
            if not new_hostname:
                return {"status": "ERROR", "message": "Missing hostname in data"}

            try:
                logger.info(f"Updating system hostname to: {new_hostname}")
                # 1. Set the hostname
                subprocess.run(["sudo", "hostnamectl", "set-hostname", new_hostname], check=True)

                # 2. Update /etc/hosts to prevent sudo/etc lag (replace 127.0.1.1 entry)
                # This is a simple sed replacement for the 127.0.1.1 line commonly found in Debian/Ubuntu
                a = subprocess.run(
                    ["sudo", "sed", "-i", f"s/127.0.1.1[[:space:]]*.*/127.0.1.1 {new_hostname}/", "/etc/hosts"],
                    check=True
                )

                return {"status": "SUCCESS", "message": f"Hostname updated to {new_hostname}"}
            except Exception as e:
                logger.error(f"SPOKE_SET_HOSTNAME failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        return None

    def _sign(self, msg):
        return self.signer.sign(msg)

    def _verify_signature(self, msg):
        if not self.secret or not self.signer:
            # If we don't have a secret yet, we can't verify signatures.
            # In the bootstrap phase, we allow this so heartbeats can pass.
            return True
        return self.signer.verify(msg)
