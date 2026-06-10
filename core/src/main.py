import asyncio
import json
import logging
import threading
import time
import subprocess
import httpx
import psutil
import os
import uuid
import secrets
from collections import deque
from typing import Dict, Any
from dataclasses import asdict
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

        # State is now managed via StateManager methods
        self.approved_modules = self.state.get_approved_modules()
        self.known_modules = self.state.system_state.get("known_modules", [])

        # { spoke_id: str } tracking spoke versions
        self.spoke_versions: Dict[str, str] = {}

        # --- System Diagnostics ---
        self.logs = deque(maxlen=500)
        self.message_count = 0
        self.mps = 0.0
        self.bytes_count = 0 # Total bytes sent/received in the current window
        self.throughput_mbps = 0.0 # Throughput in Mbps (or MB/s)
        self.message_history = deque(maxlen=10) # Last 10 seconds of counts

        class HubLogHandler(logging.Handler):
            def __init__(self, hub):
                super().__init__()
                self.hub = hub
            def emit(self, record):
                msg = self.format(record)
                self.hub.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

        log_handler = HubLogHandler(self)
        log_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(log_handler)

        # { spoke_id: websocket_connection }
        self.active_connections: Dict[str, websockets.WebSocketServerProtocol] = {}
        # { spoke_id: ConnectionTelemetry }
        self.spoke_telemetry: Dict[str, Dict[str, Any]] = {}
        # { spoke_id: TokenBucket } for rate limiting non-heartbeat messages
        self.rate_limiters: Dict[str, TokenBucket] = {}
        # { correlation_id: response_data } for request-response bridging
        self.response_cache: Dict[str, Any] = {}
        self.is_ready = False


    async def send_to_spoke(self, message: Message):
        """
        The low-level send function used by the Mailbox.
        """
        spoke_id = message.header.destination_id
        ws = self.active_connections.get(spoke_id)

        if ws:
            # Sign the message before sending
            header_dict = asdict(message.header)
            if "timestamp" in header_dict:
                header_dict["timestamp"] = round(header_dict["timestamp"], 6)

            payload_dict = asdict(message.payload)

            # Sign the structured data (KeyManager now handles canonicalization)
            message.signature = self.key_manager.sign_message(spoke_id, {
                "header": header_dict,
                "payload": payload_dict
            })

            payload = {
                "header": header_dict,
                "payload": payload_dict,
                "signature": message.signature
            }
            json_payload = json.dumps(payload, separators=(',', ':'))
            self.bytes_count += len(json_payload.encode())
            await ws.send(json_payload)
            self.message_count += 1
        else:
            raise ConnectionError(f"Spoke {spoke_id} is not connected")

    async def request_response(self, spoke_id: str, command_type: str, data: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Sends a command to a spoke and waits for its acknowledgement.
        """
        msg_id = str(uuid.uuid4())
        logger.info(f"Request: {msg_id} -> {spoke_id} [{command_type}] data={data}")
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
                result = self.response_cache.pop(msg_id)
                logger.info(f"Response: {msg_id} received from {spoke_id}: {result}")
                return result

        logger.error(f"Request Timeout: {msg_id} from {spoke_id} after {timeout}s")
        return {"status": "ERROR", "message": "Timed out waiting for spoke response"}

    async def push_config_to_spoke(self, spoke_id: str):
        """Pushes the module-specific configuration from global state to the spoke."""
        try:
            # Identify which module this spoke belongs to
            module_key = None
            module_map = {'pxmx': 'pxmx', 'opn': 'opnsense', 'cs': 'cs', 'cppm': 'cppm'}
            for key in module_map:
                if key in spoke_id:
                    module_key = key
                    break

            if not module_key:
                return

            config = self.state.get_global_config().get(module_key, {})
            if not config:
                return

            msg_id = str(uuid.uuid4())
            msg = Message(
                header=MessageHeader(
                    message_id=msg_id,
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=spoke_id
                ),
                payload=MessagePayload(type="UPDATE_CONFIG", data=config)
            )
            await self.send_to_spoke(msg)
            logger.info(f"Pushed {module_key} config to module {spoke_id}")
        except Exception as e:
            logger.error(f"Failed to push config to {spoke_id}: {e}")

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
                logger.warning(f"Authentication failed for spoke {spoke_id}: Secret mismatch or key not found.")
                if spoke_id not in self.known_modules:
                    self.state.register_module(spoke_id, approved=False)
                    self.known_modules = self.state.system_state["known_modules"]

                # Update telemetry
                self.spoke_telemetry[spoke_id] = {
                    "last_attempt": time.time(),
                    "status": "AUTH_FAILED",
                    "error": "Invalid secret"
                }

                await websocket.close(1008, "Authentication failed")
                return

            logger.info(f"Spoke {spoke_id} authenticated successfully.")
            self.active_connections[spoke_id] = websocket

            # --- Mutual Authentication (Hub Identity Proof) ---
            try:
                challenge = secrets.token_urlsafe(32)
                signature = self.key_manager.sign_hub_challenge(challenge.encode())

                proof = {
                    "status": "HUB_VERIFIED",
                    "challenge": challenge,
                    "signature": signature
                }
                await websocket.send(json.dumps(proof))

                # Wait for spoke to verify and respond
                hub_response_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_response = json.loads(hub_response_json)

                if hub_response.get("status") != "HUB_OK":
                    logger.warning(f"Mutual auth failed: Spoke {spoke_id} rejected Hub identity.")
                    await websocket.close(1008, "Hub identity rejected")
                    return

                logger.info(f"Mutual authentication complete for {spoke_id}.")
            except Exception as e:
                logger.error(f"Mutual authentication error for {spoke_id}: {e}")
                await websocket.close(1008, "Mutual authentication failed")
                return

            # Update telemetry
            self.spoke_telemetry[spoke_id] = {
                "last_attempt": time.time(),
                "status": "CONNECTED",
                "error": None
            }

            # Track this module as known for approval lists
            if spoke_id not in self.known_modules:
                self.state.register_module(spoke_id, approved=False)
                self.known_modules = self.state.system_state["known_modules"]

            # Initialize rate limiter (e.g., 5 messages/sec burst of 10)
            self.rate_limiters[spoke_id] = TokenBucket(capacity=10, fill_rate=5)

            # Request Spoke Version immediately after auth
            try:
                version_msg = Message(
                    header=MessageHeader(
                        message_id=str(uuid.uuid4()),
                        timestamp=time.time(),
                        sender_id="hub",
                        destination_id=spoke_id
                    ),
                    payload=MessagePayload(type="get_version", data={})
                )
                await self.send_to_spoke(version_msg)
            except Exception as e:
                logger.error(f"Failed to request version from {spoke_id}: {e}")

            # Check if the module is already approved
            if not self.approved_modules.get(spoke_id, False):
                logger.info(f"Module {spoke_id} is pending approval.")
                # Send Approval Required message
                approval_msg = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                               "sender_id": "hub", "destination_id": spoke_id},
                    "payload": {"type": "APPROVAL_REQUIRED", "data": {}}
                }
                # Sign the message
                approval_msg["signature"] = self.key_manager.sign_message(spoke_id, {
                    "header": approval_msg["header"],
                    "payload": approval_msg["payload"]
                })

                await websocket.send(json.dumps(approval_msg))
                # We don't return; we enter the loop but the loop will filter messages
            else:
                # MODULE IS APPROVED: Push initial configuration
                await self.push_config_to_spoke(spoke_id)

            # 2. Flush Mailbox
            await self.mailbox.flush_mailbox(spoke_id, self.send_to_spoke)

            # 3. Message Loop
            async for message_json in websocket:
                msg_data = json.loads(message_json)

                # Signature Verification
                signature = msg_data.get("signature")
                data_to_verify = {k: v for k, v in msg_data.items() if k != "signature"}
                message_bytes = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':')).encode()

                if not self.key_manager.verify_signature(spoke_id, message_bytes, signature):
                    logger.warning(f"Invalid signature from spoke {spoke_id}")
                    continue

                # Process Heartbeat (Always allowed for pending spokes to maintain connection)
                payload = msg_data.get("payload", {})
                self.bytes_count += len(message_json) # Track received bytes
                if payload.get("type") == "HEARTBEAT":
                    self.message_count += 1
                    self.heartbeat.update_heartbeat(spoke_id)
                    continue

                # If the module is not approved, ignore all other messages
                if not self.approved_modules.get(spoke_id, False):
                    logger.debug(f"Dropping message from unapproved module {spoke_id}")
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

                    # Special case: if this was a version request, store the version
                    payload = msg_data.get("payload", {})
                    if payload.get("type") == "COMMAND_RESULT":
                        data = payload.get("data", {})
                        if isinstance(data, dict) and "version" in data:
                            self.spoke_versions[spoke_id] = data["version"]

                    # Store in response cache for API request bridging
                    if hasattr(self, "response_cache"):
                        self.response_cache[corr_id] = msg_data

                    self.message_count += 1
                    continue

                # Rate Limiting for non-heartbeat messages
                limiter = self.rate_limiters.get(spoke_id)
                if limiter and not limiter.consume():
                    logger.warning(f"Rate limit exceeded for spoke {spoke_id}. Dropping message.")
                    continue

                # Handle other messages
                self.message_count += 1
                logger.info(f"Received verified message from {spoke_id}: {payload.get('type')}")

        except websockets.ConnectionClosed:
            logger.info(f"Connection closed for spoke {spoke_id}")
            if spoke_id:
                self.spoke_telemetry[spoke_id]["status"] = "DISCONNECTED"
        except Exception as e:
            logger.error(f"Error handling connection for {spoke_id}: {e}")
            if spoke_id:
                self.spoke_telemetry[spoke_id] = {
                    "last_attempt": time.time(),
                    "status": "ERROR",
                    "error": str(e)
                }
        finally:
            if spoke_id and spoke_id in self.active_connections:
                del self.active_connections[spoke_id]

    async def get_local_version(self) -> str:
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            with open(version_path, "r") as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"Failed to read local version: {e}")
            return "unknown"

    async def get_remote_version(self) -> str:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get("https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION")
                if resp.status_code == 200:
                    return resp.text.strip()
        except Exception as e:
            logger.error(f"Failed to fetch remote version: {e}")
        return "unknown"

    async def perform_update(self):
        """
        Checks for updates and performs a git pull if a new version is available.
        """
        local_v = await self.get_local_version()
        remote_v = await self.get_remote_version()

        if local_v == remote_v:
            return {"status": "no_update", "message": f"System is already up to date (v{local_v})."}

        if remote_v == "unknown":
            return {"status": "error", "message": "Could not retrieve remote version from GitHub."}

        try:
            logger.info(f"Updating system from v{local_v} to v{remote_v}...")
            # Update by navigating to the root of the hub repository
            hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
            cmd = f"cd {hub_root} && git pull"
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode == 0:
                logger.info("Update successful. Triggering service restart...")
                subprocess.Popen(["sudo", "systemctl", "restart", "lm"])
                return {"status": "success", "message": f"Updated from v{local_v} to v{remote_v}. Server is restarting..."}
            else:
                logger.error(f"Git pull failed: {stderr.decode()}")
                return {"status": "error", "message": f"Update failed: {stderr.decode()}"}
        except Exception as e:
            logger.error(f"Unexpected error during update: {e}")
            return {"status": "error", "message": f"Unexpected error: {str(e)}"}

    async def run_mps_loop(self):
        """
        Calculates messages per second and throughput using a 10-second moving average.
        """
        logger.info("MPS and Throughput monitoring loop started.")
        while True:
            await asyncio.sleep(1.0)
            self.message_history.append(self.message_count)

            # Calculate MPS (Packets Per Second)
            if len(self.message_history) > 0:
                self.mps = sum(self.message_history) / len(self.message_history)
            else:
                self.mps = 0.0

            # Calculate Throughput (MB/s)
            # bytes_count is total bytes since last check.
            # Divide by 1024 * 1024 to get MB.
            self.throughput_mbps = self.bytes_count / (1024 * 1024)

            self.message_count = 0
            self.bytes_count = 0

    async def get_system_metrics(self) -> Dict[str, Any]:
        """
        Collects CPU, Memory, and Disk metrics.
        Returns default values if collection fails to prevent API errors.
        """
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                "cpu_util": cpu,
                "mem_util": mem.percent,
                "disk_util": disk.percent,
                "disk_free": disk.free // (1024 * 1024), # MB
                "disk_total": disk.total // (1024 * 1024), # MB
                "queue_size": len(self.mailbox.get_all_pending()),
                "backlog": len(self.mailbox.get_all_pending()),
                "mps": self.mps,
                "throughput": self.throughput_mbps
            }
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {
                "cpu_util": 0,
                "mem_util": 0,
                "disk_util": 0,
                "disk_free": 0,
                "disk_total": 0,
                "queue_size": len(self.mailbox.get_all_pending()) if hasattr(self, 'mailbox') else 0,
                "backlog": len(self.mailbox.get_all_pending()) if hasattr(self, 'mailbox') else 0,
                "mps": getattr(self, 'mps', 0.0),
                "throughput": getattr(self, 'throughput_mbps', 0.0)
            }

    async def run_autoupdate_loop(self):
        """
        Background loop that checks for updates based on global configuration.
        """
        logger.info("Auto-update loop started.")
        while True:
            try:
                config = self.state.get_global_config()
                enabled = config.get("autoupdate", True) # Default to enabled
                interval_hours = config.get("update_interval", 1) # Default to 1 hour

                if enabled:
                    logger.info(f"Auto-update enabled. Checking for updates every {interval_hours} hours.")
                    # Wait for the configured interval
                    await asyncio.sleep(interval_hours * 3600)

                    # Trigger update
                    await self.perform_update()
                else:
                    # If disabled, check again every 5 minutes to see if it was enabled
                    await asyncio.sleep(300)
            except Exception as e:
                logger.error(f"Error in auto-update loop: {e}")
                await asyncio.sleep(300)

    async def start(self):
        """
        Starts the WebSocket server and background tasks.
        """
        # Load version
        version = "unknown"
        try:
            # Try relative to the script directory first, then fallback to repo root
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")

            with open(version_path, "r") as f:
                version = f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load version file: {e}")

        # Start the REST API server in a separate thread
        api_thread = threading.Thread(target=run_api_server, args=(self,), daemon=True)
        api_thread.start()

        # Start the retry loop as a background task
        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())
        autoupdate_task = asyncio.create_task(self.run_autoupdate_loop())
        mps_task = asyncio.create_task(self.run_mps_loop())

        async with websockets.serve(self.handle_connection, self.host, self.port) as server:
            self.is_ready = True
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
