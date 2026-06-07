import asyncio
import json
import logging
import threading
import time
from typing import Dict
import websockets

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement
from messaging.mailbox import Mailbox
from messaging.heartbeat import HeartbeatManager
from security.key_manager import KeyManager
from state.manager import StateManager
from security.auth_manager import AuthManager, LDAPAuthProvider
from api import run_api_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Hub")

class TokenBucket:
    def __init__(self, capacity: float, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: float = 1.0) -> bool:
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

class LabManagerHub:
    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        self.mailbox = Mailbox()
        self.heartbeat = HeartbeatManager()
        self.key_manager = KeyManager()
        self.state = StateManager()

        # Initialize Auth with LDAP
        self.auth = AuthManager(LDAPAuthProvider({"server": "ldap://localhost"}))

        # { spoke_id: websocket_connection }
        self.active_connections: Dict[str, websockets.WebSocketServerProtocol] = {}
        # { spoke_id: TokenBucket } for rate limiting non-heartbeat messages
        self.rate_limiters: Dict[str, TokenBucket] = {}
        # { correlation_id: response_data } for request-response bridging
        self.response_cache: Dict[str, Any] = {}

    async def send_to_spoke(self, message: Message):
        """
        The low-level send function used by the Mailbox.
        """
        spoke_id = message.header.destination_id
        ws = self.active_connections.get(spoke_id)

        if ws:
            # Sign the message before sending
            message_bytes = json.dumps({
                "header": vars(message.header),
                "payload": vars(message.payload)
            }, sort_keys=True).encode()

            message.signature = self.key_manager.sign_message(spoke_id, message_bytes)

            payload = {
                "header": vars(message.header),
                "payload": vars(message.payload),
                "signature": message.signature
            }
            await ws.send(json.dumps(payload))
        else:
            raise ConnectionError(f"Spoke {spoke_id} is not connected")

    async def request_response(self, spoke_id: str, command_type: str, data: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Sends a command to a spoke and waits for its acknowledgement.
        """
        msg_id = str(uuid.uuid4())
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id
            ),
            payload=MessagePayload(type=command_type, data=data)
        )

        await self.send_to_spoke(msg)

        # Wait for the response in the mailbox
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Check for a message in the mailbox specifically for this correlation_id
            # Since the mailbox currently doesn't have a 'wait for id' method,
            # we check the internal store or a shared event.
            # For simplicity in this demo, we'll poll the state or a response queue.
            # In a real system, we'd use a Future.
            await asyncio.sleep(0.1)
            # Implementation detail: The Hub currently processes ACKs in the message loop.
            # We would need a way to retrieve the result of a specific correlation_id.
            # I will add a simple result cache to the Hub.
            if msg_id in getattr(self, "response_cache", {}):
                return self.response_cache.pop(msg_id)

        return {"status": "ERROR", "message": "Timed out waiting for spoke response"}

    async def handle_connection(self, websocket):
        """
        Handles the lifecycle of a Spoke connection with authentication.
        """
        spoke_id = None
        try:
            # 1. Authentication Handshake
            auth_json = await websocket.recv()
            auth_data = json.loads(auth_json)
            spoke_id = auth_data.get("spoke_id")
            secret = auth_data.get("secret")

            if not spoke_id or not secret:
                await websocket.close(1008, "Missing spoke_id or secret")
                return

            key_id = self.key_manager.get_valid_key(spoke_id, secret)
            if not key_id:
                logger.warning(f"Authentication failed for spoke {spoke_id}")
                await websocket.close(1008, "Authentication failed")
                return

            logger.info(f"Spoke {spoke_id} authenticated successfully.")
            self.active_connections[spoke_id] = websocket
            # Initialize rate limiter (e.g., 5 messages/sec burst of 10)
            self.rate_limiters[spoke_id] = TokenBucket(capacity=10, fill_rate=5)

            # 2. Flush Mailbox
            await self.mailbox.flush_mailbox(spoke_id, self.send_to_spoke)

            # 3. Message Loop
            async for message_json in websocket:
                msg_data = json.loads(message_json)

                # Signature Verification
                signature = msg_data.get("signature")
                data_to_verify = {k: v for k, v in msg_data.items() if k != "signature"}
                message_bytes = json.dumps(data_to_verify, sort_keys=True).encode()

                if not self.key_manager.verify_signature(spoke_id, message_bytes, signature):
                    logger.warning(f"Invalid signature from spoke {spoke_id}")
                    continue

                # Process Acknowledgement
                if "correlation_id" in msg_data:
                    corr_id = msg_data["correlation_id"]
                    ack = Acknowledgement(
                        correlation_id=corr_id,
                        status=msg_data.get("status", "FAILED"),
                        error=msg_data.get("error")
                    )
                    await self.mailbox.acknowledge(ack)

                    # Store in response cache for API request bridging
                    if hasattr(self, "response_cache"):
                        self.response_cache[corr_id] = msg_data
                    continue

                # Process Heartbeat
                payload = msg_data.get("payload", {})
                if payload.get("type") == "HEARTBEAT":
                    self.heartbeat.update_heartbeat(spoke_id)
                    continue

                # Rate Limiting for non-heartbeat messages
                limiter = self.rate_limiters.get(spoke_id)
                if limiter and not limiter.consume():
                    logger.warning(f"Rate limit exceeded for spoke {spoke_id}. Dropping message.")
                    continue

                # Handle other messages
                logger.info(f"Received verified message from {spoke_id}: {payload.get('type')}")

        except websockets.ConnectionClosed:
            logger.info(f"Connection closed for spoke {spoke_id}")
        except Exception as e:
            logger.error(f"Error handling connection for {spoke_id}: {e}")
        finally:
            if spoke_id and spoke_id in self.active_connections:
                del self.active_connections[spoke_id]

    async def start(self):
        """
        Starts the WebSocket server and background tasks.
        """
        # Load version
        version = "unknown"
        try:
            with open("../VERSION", "r") as f:
                version = f.read().strip()
        except Exception:
            pass

        # Store the event loop for the API server to use
        self.loop = asyncio.get_running_loop()

        # Start the REST API server in a separate thread
        api_thread = threading.Thread(target=run_api_server, args=(self,), daemon=True)
        api_thread.start()

        # Start the retry loop as a background task
        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())

        async with websockets.serve(self.handle_connection, self.host, self.port):
            logger.info(f"Lab Manager Hub v{version} started on ws://{self.host}:{self.port}")
            logger.info(f"Hub API started on port 8000")
            await asyncio.Future()

    async def run_retry_loop(self):
        class ConnectionMap(dict):
            def get(self, spoke_id):
                async def _send(msg):
                    await self.send_to_spoke(msg)
                return _send

        await self.mailbox.retry_loop(ConnectionMap())

if __name__ == "__main__":
    hub = LabManagerHub()
    try:
        asyncio.run(hub.start())
    except KeyboardInterrupt:
        pass
