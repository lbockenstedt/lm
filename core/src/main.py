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
from typing import Dict, Any, Optional
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
        self.opnsense_cache: Dict[str, Any] = {}
        self.cache_dir = os.path.join(self.state.data_dir, "cache")
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

    def get_spoke_for_firewall(self, firewall_id: str) -> Optional[str]:
        """Finds the spoke associated with a given firewall ID."""
        firewalls = self.state.get_global_config().get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        return fw.get("spoke_id") if fw else None

    async def push_config_to_spoke(self, spoke_id: str):
        """Pushes the firewall/module-specific configuration from global state to the spoke."""
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

            # Handle Firewall multi-instance config
            if module_key == 'opn':
                firewalls = self.state.get_global_config().get("firewalls", [])
                # Find the firewall that matches this spoke_id
                fw_config = next((f for f in firewalls if f.get("spoke_id") == spoke_id), None)

                if fw_config:
                    config = fw_config
                else:
                    # Fallback to first OPNsense firewall if no explicit mapping
                    opn_fws = [f for f in firewalls if f.get("model") == "opnsense"]
                    config = opn_fws[0] if opn_fws else {}
            else:
                # Use existing singleton pattern for other modules (pxmx, cppm, cs)
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

            # Push the Hub Secret for mutual authentication
            hub_secret = self.key_manager.hub_secret
            secret_msg_id = str(uuid.uuid4())
            secret_msg = Message(
                header=MessageHeader(
                    message_id=secret_msg_id,
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=spoke_id
                ),
                payload=MessagePayload(type="SPOKE_SET_HUB_SECRET", data={"hub_secret": hub_secret})
            )
            await self.send_to_spoke(secret_msg)
            logger.info(f"Pushed Hub secret to {spoke_id}")
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

            logger.info(f"Auth attempt: spoke_id={spoke_id}, secret={f'{secret[:4]}...{secret[-4:]}' if secret and len(secret) > 8 else '***'}")

            if not spoke_id or not secret:
                await websocket.close(1008, "Missing spoke_id or secret")
                return

            key_id = self.key_manager.get_valid_key(spoke_id, secret)
            logger.info(f"KeyManager result for {spoke_id}: key_id={key_id}")

            if not key_id:
                masked_secret = f"{secret[:4]}...{secret[-4:]}" if secret and len(secret) > 8 else "***"
                logger.warning(f"Authentication failed for spoke {spoke_id}: Secret {masked_secret} is invalid.")
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

                    # Debug: Log if this response is actually expected
                    if corr_id not in self.response_cache:
                        # This is tricky because request_response pops the id from cache
                        # but the message loop handles the receipt.
                        # Let's just log the receipt of every correlation ID.
                        logger.debug(f"Received response for correlation_id: {corr_id}")

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
            config = self.state.get_global_config()
            sources = config.get("update_sources", {})
            repo_url = sources.get("hub", "https://github.com/lbockenstedt/lm")

            # Convert github.com/user/repo to raw.githubusercontent.com/user/repo/main/VERSION
            if "github.com" in repo_url:
                parts = repo_url.rstrip("/").split("github.com/")
                if len(parts) == 2:
                    path = parts[1]
                    version_url = f"https://raw.githubusercontent.com/{path}/main/VERSION"
                else:
                    version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"
            else:
                version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"

            async with httpx.AsyncClient() as client:
                resp = await client.get(version_url)
                if resp.status_code == 200:
                    return resp.text.strip()
        except Exception as e:
            logger.error(f"Failed to fetch remote version: {e}")
        return "unknown"

    async def perform_update(self, force=False):
        """
        Checks for updates and performs a git pull if a new version is available.
        Also triggers updates for all approved modules (connected or offline).
        """
        local_v = await self.get_local_version()
        remote_v = await self.get_remote_version()

        if not force and local_v == remote_v:
            # Even if Hub is up to date, we might want to trigger spoke updates
            # For now, we'll return early to match previous behavior unless we want forced updates
            return {"status": "no_update", "message": f"System is already up to date (v{local_v})."}

        if remote_v == "unknown":
            return {"status": "error", "message": "Could not retrieve remote version from GitHub."}

        try:
            logger.info(f"Updating system from v{local_v} to v{remote_v} (force={force})...")

            # 1. Update Hub itself
            hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

            # Use configured repo URL if available
            config = self.state.get_global_config()
            sources = config.get("update_sources", {})
            hub_repo = sources.get("hub", "https://github.com/lbockenstedt/lm")
            branch = config.get("global_branch", "main")

            # Record the attempt timestamp
            self.state.update_global_config({"last_update_ts": time.time()})
            self.state.save_state()

            # Set remote origin, stash local changes, fetch, checkout, pull, and pop stash
            # This ensures that local modifications don't block the update

            # Ensure the directory is marked as safe for git (especially if running as root)
            await asyncio.create_subprocess_shell(f"git config --global --add safe.directory {hub_root}")

            update_cmd = (
                f"cd {hub_root} && "
                f"git remote set-url origin {hub_repo} && "
                f"git stash && "
                f"git fetch origin && "
                f"git checkout {branch} && "
                f"git pull origin {branch} && "
                f"git stash pop"
            )

            process = await asyncio.create_subprocess_shell(
                update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                # If stash pop fails, it's often because there were no changes to stash or conflicts.
                # We log it but don't necessarily fail the whole update if the pull worked.
                err_msg = stderr.decode().strip()
                if "No stash entry found" in err_msg or "conflict" not in err_msg.lower():
                    logger.info(f"Update completed with minor stash warning: {err_msg}")
                else:
                    logger.error(f"Hub git pull failed: {err_msg}")
                    return {"status": "error", "message": f"Hub update failed: {err_msg}"}

            # 2. Trigger updates for all approved modules (connected or offline)
            update_results = []
            for spoke_id, approved in self.approved_modules.items():
                if not approved:
                    continue

                # Identify module type
                module_key = None
                module_map = {'pxmx': 'pxmx', 'opn': 'opnsense', 'cs': 'cs', 'cppm': 'cppm', 'netbox': 'netbox', 'ldap': 'ldap'}
                for key in module_map:
                    if key in spoke_id:
                        module_key = key
                        break

                if module_key:
                    repo_url = sources.get(module_key)
                    if repo_url:
                        logger.info(f"Triggering update for spoke {spoke_id} from {repo_url} on branch {branch}...")
                        msg_id = str(uuid.uuid4())
                        msg = Message(
                            header=MessageHeader(
                                message_id=msg_id,
                                timestamp=time.time(),
                                sender_id="hub",
                                destination_id=spoke_id
                            ),
                            payload=MessagePayload(type="SPOKE_UPDATE", data={"repo_url": repo_url, "branch": branch})
                        )
                        try:
                            await self.mailbox.push(msg, self.send_to_spoke)
                            update_results.append(f"{spoke_id}: triggered ({branch})")
                        except Exception as e:
                            logger.error(f"Failed to push update for {spoke_id}: {e}")
                            update_results.append(f"{spoke_id}: failed")
                    else:
                        update_results.append(f"{spoke_id}: no repo configured")
                else:
                    update_results.append(f"{spoke_id}: unknown module type")

            logger.info(f"Spoke update triggers: {update_results}")
            logger.info("Update successful. Triggering service restart...")
            subprocess.Popen(["sudo", "systemctl", "restart", "lm"])
            return {"status": "success", "message": f"Updated Hub from v{local_v} to v{remote_v} on branch {branch} and triggered spoke updates. Server is restarting..."}

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
            version = await self.get_local_version()

            return {
                "cpu_util": cpu,
                "mem_util": mem.percent,
                "disk_util": disk.percent,
                "disk_free": disk.free // (1024 * 1024), # MB
                "disk_total": disk.total // (1024 * 1024), # MB
                "queue_size": len(self.mailbox.get_all_pending()),
                "backlog": len(self.mailbox.get_all_pending()),
                "mps": self.mps,
                "throughput": self.throughput_mbps,
                "version": version
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
                "throughput": getattr(self, 'throughput_mbps', 0.0),
                "version": "unknown"
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
                    # Trigger update check immediately on loop start or every interval
                    await self.perform_update()

                    # Wait for the configured interval
                    await asyncio.sleep(interval_hours * 3600)
                else:
                    # If disabled, check again every 5 minutes to see if it was enabled
                    await asyncio.sleep(300)
            except Exception as e:
                logger.error(f"Error in auto-update loop: {e}")
                await asyncio.sleep(300)

    async def poll_opnsense_rules(self, firewall_id: str = None):
        """
        Polls OPNsense for all firewall rules and caches them locally and in-memory.
        If firewall_id is provided, it polls that specific firewall.
        """
        logger.info(f"Polling OPNsense firewall rules (ID: {firewall_id or 'Default'})...")

        if firewall_id:
            spoke_id = self.get_spoke_for_firewall(firewall_id)
            if not spoke_id:
                logger.error(f"OPNsense polling failed: No spoke found for firewall {firewall_id}")
                return False
        else:
            opn_spoke = next((sid for sid in self.active_connections if "opn" in sid), None)
            if not opn_spoke:
                logger.error("OPNsense polling failed: No OPNsense spoke connected")
                return False
            spoke_id = opn_spoke

        try:
            result = await self.request_response(spoke_id, "OPNSENSE_GET_ALL_RULES", {})

            # Robust extraction
            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    data = result
            else:
                data = result

            if not data:
                logger.warning(f"OPNsense polling returned empty data for {spoke_id}")
                return False

            # Update in-memory cache (now keyed by firewall_id or spoke_id)
            if not hasattr(self, "firewall_caches"):
                self.firewall_caches = {}

            cache_key = firewall_id or spoke_id
            self.firewall_caches[cache_key] = data

            # Save to local disk
            try:
                if not os.path.exists(self.cache_dir):
                    os.makedirs(self.cache_dir, exist_ok=True)

                cache_filename = f"rules_{cache_key}.json"
                cache_path = os.path.join(self.cache_dir, cache_filename)
                with open(cache_path, "w") as f:
                    json.dump(data, f)
                logger.info(f"OPNsense rules cached to {cache_path}")
            except Exception as e:
                logger.error(f"Failed to persist OPNsense cache to disk for {cache_key}: {e}")

            return True
        except Exception as e:
            logger.error(f"Error during OPNsense rule polling for {spoke_id}: {e}", exc_info=True)
            return False

    async def run_opnsense_polling_loop(self):
        """
        Background loop that polls OPNsense rules at the configured interval.
        """
        logger.info("OPNsense polling loop started.")
        while True:
            try:
                config = self.state.get_global_config()
                # Default to 1 hour (3600 seconds)
                interval_hours = config.get("opnsense_poll_interval", 1)

                await self.poll_opnsense_rules()

                # Wait for the configured interval
                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                logger.error(f"Error in OPNsense polling loop: {e}")
                await asyncio.sleep(300) # Retry after 5 mins on error

    async def load_caches(self):
        """
        Loads cached data from disk into memory.
        """
        logger.info("Loading local caches from disk...")
        try:
            if not os.path.exists(self.cache_dir):
                return

            opn_cache_path = os.path.join(self.cache_dir, "opnsense_rules.json")
            if os.path.exists(opn_cache_path):
                with open(opn_cache_path, "r") as f:
                    self.opnsense_cache = json.load(f)
                logger.info(f"Loaded OPNsense rules from {opn_cache_path}")
        except Exception as e:
            logger.error(f"Error loading local caches: {e}")

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

        await self.load_caches()

        # Start the retry loop as a background task
        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())
        autoupdate_task = asyncio.create_task(self.run_autoupdate_loop())
        mps_task = asyncio.create_task(self.run_mps_loop())
        opnsense_poll_task = asyncio.create_task(self.run_opnsense_polling_loop())

        async with websockets.serve(self.handle_connection, self.host, self.port) as server:
            self.is_ready = True
            logger.info(f"Lab Manager Hub v{version} started on ws://{self.host}:{self.port}")
            logger.info(f"Hub API started on port 8000")
            await asyncio.Future()


    async def run_retry_loop(self):
        class ConnectionMap(dict):
            def get(self, spoke_id):
                # Access the Hub instance (the outer 'self')
                hub = self.hub_instance
                if spoke_id not in hub.active_connections:
                    return None
                async def _send(msg):
                    await hub.send_to_spoke(msg)
                return _send

        conn_map = ConnectionMap()
        conn_map.hub_instance = self
        await self.mailbox.retry_loop(conn_map)

if __name__ == "__main__":
    hub = LabManagerHub()
    try:
        asyncio.run(hub.start())
    except KeyboardInterrupt:
        pass
