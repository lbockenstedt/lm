import asyncio
import json
import logging
import uuid
import time
from typing import Dict, Any, Optional
import websockets
from ..messaging.protocol import Message, MessageHeader, MessagePayload
from ..base_spoke import BaseSpoke
from ..messaging.control_plane import BaseControlPlane

logger = logging.getLogger("SpokeGateway")

class SpokeGateway(BaseControlPlane):
    """
    The SpokeGateway acts as a bridge between the Hub and multiple leaf Agents.
    It is a 'Spoke' to the Hub and a 'Hub' to its agents.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None, agent_port: int = 8767):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self.agent_port = agent_port
        # { agent_id: websocket_connection }
        self.active_agents: Dict[str, websockets.WebSocketServerProtocol] = {}
        # { agent_id: secret }
        self.agent_secrets: Dict[str, str] = {}

    async def start_agent_server(self):
        """Starts the WebSocket server for leaf agents."""
        logger.info(f"Starting Agent Gateway server on port {self.agent_port}...")
        async with websockets.serve(self._handle_agent_connection, "0.0.0.0", self.agent_port):
            await asyncio.Future() # Keep server running

    async def _handle_agent_connection(self, websocket):
        agent_id = None
        try:
            # 1. Agent Handshake
            auth_json = await websocket.recv()
            auth_data = json.loads(auth_json)
            agent_id = auth_data.get("agent_id")
            secret = auth_data.get("secret")

            if not agent_id or not secret:
                await websocket.close(1008, "Missing agent_id or secret")
                return

            # 2. Verify Agent Secret (Simple check, can be expanded to Hub-relay)
            # In a full implementation, the Gateway would relay this to the Hub
            # for a central identity check. For now, we check a local map or
            # allow the first-secret bootstrap.
            if not self._verify_agent_secret(agent_id, secret):
                logger.warning(f"Authentication failed for agent {agent_id}")
                await websocket.close(1008, "Authentication failed")
                return

            logger.info(f"Agent {agent_id} authenticated successfully. Adding to registry.")
            self.active_agents[agent_id] = websocket

            # 3. Message Loop
            async for message in websocket:
                agent_msg = json.loads(message)

                # Relays agent messages (like telemetry/heartbeats) to the Hub
                # We wrap the agent's message in a relay payload
                relay_msg = Message(
                    header=MessageHeader(
                        message_id=str(uuid.uuid4()),
                        timestamp=time.time(),
                        sender_id=self.spoke_id,
                        destination_id="hub"
                    ),
                    payload=MessagePayload(
                        type="AGENT_RELAY_UP",
                        data={
                            "agent_id": agent_id,
                            "original_payload": agent_msg
                        }
                    )
                )
                await self.send_to_hub(relay_msg)

        except Exception as e:
            logger.error(f"Error handling agent connection {agent_id}: {e}")
        finally:
            if agent_id:
                self.active_agents.pop(agent_id, None)
                logger.info(f"Agent {agent_id} disconnected.")

    def _verify_agent_secret(self, agent_id: str, secret: str) -> bool:
        # Implementation of agent secret verification
        # For now, we allow if the secret matches what's in the map
        # In production, this would be managed via the Hub's KeyManager
        return self.agent_secrets.get(agent_id) == secret

    async def handle_hub_command(self, cmd_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handles commands from the Hub.
        """
        if cmd_type == "SPOKE_RELAY":
            target_agent_id = data.get("target_agent_id")
            command = data.get("command_type")
            params = data.get("data", {})

            if not target_agent_id or target_agent_id not in self.active_agents:
                return {"status": "ERROR", "message": f"Agent {target_agent_id} not connected to this gateway"}

            ws = self.active_agents[target_agent_id]
            relay_msg = {
                "type": "SPOKE_COMMAND",
                "command": command,
                "params": params
            }
            await ws.send(json.dumps(relay_msg))
            return {"status": "SUCCESS", "message": f"Command relayed to agent {target_agent_id}"}

        # Fallback to default spoke behavior
        return {"status": "ERROR", "message": "Unknown gateway command"}
