"""QA mock spoke for exercising the Hub's mutual authentication and command routing.

Connects to a running Hub as a fake spoke, verifies the Hub's HMAC proof, and answers
every command with a signed, mocked COMMAND_RESULT.
"""
# asyncio runs the async WebSocket client.
import asyncio
# json encodes and decodes WebSocket messages.
import json
# websockets is the WebSocket client library used to reach the Hub.
import websockets
# Standard-library logging for test progress and failures.
import logging
# hmac and hashlib compute and check HMAC-SHA256 signatures.
import hmac
import hashlib
# secrets generates random message ids.
import secrets
# time stamps outgoing message headers.
import time
# os reads .env and QA_* environment settings.
import os

def load_dotenv():
    """Load KEY=VALUE pairs from ./.env into os.environ (lines starting with # are skipped)."""
    # Only do anything if a .env file exists in the current directory.
    if os.path.exists(".env"):
        with open(".env") as f:
            # Process each line of the file.
            for line in f:
                line = line.strip()
                # Skip blank lines and comment lines.
                if line and not line.startswith("#"):
                    # Only lines containing "=" are assignments; split on the first "=".
                    if "=" in line:
                        key, value = line.split("=", 1)
                        # Store the value with surrounding quotes removed.
                        os.environ[key.strip()] = value.strip().strip('"').strip("'")

# Load .env before reading any settings below.
load_dotenv()

# Prefer the shared logging setup; the import path differs between deployed and dev layouts.
try:
    from logging_setup import configure_logging
# Not found at top level: try the package path used in the source tree.
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    # Neither location exists: define a minimal stand-in with the same signature.
    except ImportError:
        import logging as _logging
        # Log line format and timestamp format, matching the shared logging setup.
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            """Fallback logging setup: log to stderr, and also to log_file when one is given."""
            # Write to both a file and the console when a log file was requested.
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            # force=True replaces any handlers another import may have already installed.
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
# Configure logging now so every message below uses the standard format.
configure_logging()
# One named logger for the QA tester.
logger = logging.getLogger("QA-Tester")

class QASpokeMock:
    """
    A mock spoke used to test the Hub's mutual authentication and command routing.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        """Remember the identity and secrets used to authenticate with the Hub.

        Args:
            spoke_id: Identifier this fake spoke presents to the Hub.
            secret: Spoke secret sent to the Hub and used to sign responses.
            hub_secret: Shared secret used to verify the Hub's proof (None skips the check).
            hub_url: WebSocket URL of the Hub's spoke endpoint.
        """
        # Store connection details for run().
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_secret = hub_secret
        self.hub_url = hub_url

    async def run(self):
        """Connect to the Hub, complete mutual auth, then answer every command with a mock result.
        """
        # Log which Hub we are testing against.
        logger.info(f"Starting QA Mock Spoke {self.spoke_id} -> {self.hub_url}")

        # Open the WebSocket; it is closed automatically when the block exits.
        async with websockets.connect(self.hub_url) as websocket:
            # 1. Auth Handshake
            # Send our spoke id and secret as the first frame.
            await websocket.send(json.dumps({"spoke_id": self.spoke_id, "secret": self.secret}))

            # 2. Mutual Auth
            # Any timeout or bad reply during Hub verification aborts the test.
            try:
                # Wait up to 5 s for the Hub's proof message and decode it.
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)

                # The Hub proves itself by signing a challenge with the shared hub secret.
                if hub_proof.get("status") == "HUB_VERIFIED":
                    challenge = hub_proof.get("challenge")
                    signature = hub_proof.get("signature")

                    # If we know the hub secret, recompute the expected signature ourselves.
                    if self.hub_secret:
                        expected_sig = hmac.new(
                            self.hub_secret.encode(),
                            challenge.encode(),
                            hashlib.sha256
                        ).hexdigest()

                        # Constant-time comparison avoids leaking timing info; accept or abort.
                        if hmac.compare_digest(expected_sig, signature):
                            logger.info("Hub verified successfully.")
                            await websocket.send(json.dumps({"status": "HUB_OK"}))
                        # Signature mismatch: the Hub is not who it claims to be, so stop.
                        else:
                            logger.error("Hub verification failed.")
                            return
                    # No hub secret configured: accept the Hub without checking the signature.
                    else:
                        await websocket.send(json.dumps({"status": "HUB_OK"}))
                # Hub sent something other than a proof: abort.
                else:
                    logger.error("Hub did not provide verification proof.")
                    return
            # Timeout, bad JSON or connection loss during auth: log it and stop.
            except Exception as e:
                logger.error(f"Hub auth failed: {e}")
                return

            # 3. Wait for Approval or Commands
            # Handle every message the Hub sends until the connection closes.
            async for message in websocket:
                # Decode the message and get its payload.
                msg = json.loads(message)
                payload = msg.get("payload", {})

                # An approval request is just logged; the mock keeps answering anyway.
                if payload.get("type") == "APPROVAL_REQUIRED":
                    logger.info("Hub requested approval.")

                # Respond to commands
                # Link our reply to the Hub's request via its message id.
                corr_id = msg.get("header", {}).get("message_id")
                # Build a mocked successful COMMAND_RESULT addressed back to the Hub.
                resp = {
                    "header": {"message_id": str(secrets.token_urlsafe(16)),
                               "timestamp": time.time(),
                               "sender_id": self.spoke_id, "destination_id": "hub",
                               "correlation_id": corr_id},
                    "payload": {"type": "COMMAND_RESULT", "data": {"status": "OK", "result": "mocked"}}
                }

                # Sign response
                # Sign the reply (excluding the signature field) with HMAC-SHA256 over sorted JSON,
                # matching how the Hub verifies spoke messages.
                data_to_sign = {k: v for k, v in resp.items() if k != "signature"}
                message_bytes = json.dumps(data_to_sign, sort_keys=True).encode()
                resp["signature"] = hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

                # Send the signed reply.
                await websocket.send(json.dumps(resp))

async def test_mutual_auth():
    """
    Test scenario: Spoke connects to Hub, both authenticate.
    """
    # Identity and secrets come from env vars, with test defaults for a local Hub.
    # This requires a running Hub.
    # For the purpose of this QA module, we assume Hub is at the unified :443
    # surface (wss, /ws/spoke route).
    spoke_id = "qa-spoke-1"
    secret = os.getenv("QA_SPOKE_SECRET", "qa-secret-123")
    hub_secret = os.getenv("QA_HUB_SECRET", "hub-secret-abc") # This must match the Hub's hub_secret.json
    hub_url = os.getenv("QA_HUB_URL", "wss://localhost:443/ws/spoke")

    # Run the mock spoke; any failure is logged as a test failure instead of crashing.
    tester = QASpokeMock(spoke_id, secret, hub_secret, hub_url)
    try:
        await tester.run()
    # Connection refused, TLS error, etc.: report the test as failed.
    except Exception as e:
        logger.error(f"Test failed: {e}")

# Run the test scenario when executed as a script.
if __name__ == "__main__":
    asyncio.run(test_mutual_auth())
