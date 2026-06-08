import asyncio
import json
import websockets
import logging
import hmac
import hashlib
import secrets
import time
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("QA-Tester")

class QASpokeMock:
    """
    A mock spoke used to test the Hub's mutual authentication and command routing.
    """
    def __init__(self, spoke_id: str, secret: str, hub_secret: str = None, hub_url: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_secret = hub_secret
        self.hub_url = hub_url

    async def run(self):
        logger.info(f"Starting QA Mock Spoke {self.spoke_id} -> {self.hub_url}")

        async with websockets.connect(self.hub_url) as websocket:
            # 1. Auth Handshake
            await websocket.send(json.dumps({"spoke_id": self.spoke_id, "secret": self.secret}))

            # 2. Mutual Auth
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
                            logger.info("Hub verified successfully.")
                            await websocket.send(json.dumps({"status": "HUB_OK"}))
                        else:
                            logger.error("Hub verification failed.")
                            return
                    else:
                        await websocket.send(json.dumps({"status": "HUB_OK"}))
                else:
                    logger.error("Hub did not provide verification proof.")
                    return
            except Exception as e:
                logger.error(f"Hub auth failed: {e}")
                return

            # 3. Wait for Approval or Commands
            async for message in websocket:
                msg = json.loads(message)
                payload = msg.get("payload", {})

                if payload.get("type") == "APPROVAL_REQUIRED":
                    logger.info("Hub requested approval.")

                # Respond to commands
                corr_id = msg.get("header", {}).get("message_id")
                resp = {
                    "header": {"message_id": str(secrets.token_urlsafe(16)),
                               "timestamp": time.time(),
                               "sender_id": self.spoke_id, "destination_id": "hub",
                               "correlation_id": corr_id},
                    "payload": {"type": "COMMAND_RESULT", "data": {"status": "OK", "result": "mocked"}}
                }

                # Sign response
                data_to_sign = {k: v for k, v in resp.items() if k != "signature"}
                message_bytes = json.dumps(data_to_sign, sort_keys=True).encode()
                resp["signature"] = hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

                await websocket.send(json.dumps(resp))

async def test_mutual_auth():
    """
    Test scenario: Spoke connects to Hub, both authenticate.
    """
    # This requires a running Hub.
    # For the purpose of this QA module, we assume Hub is at localhost:8765
    spoke_id = "qa-spoke-1"
    secret = "qa-secret-123"
    hub_secret = "hub-secret-abc" # This must match the Hub's hub_secret.json
    hub_url = "ws://localhost:8765"

    tester = QASpokeMock(spoke_id, secret, hub_secret, hub_url)
    try:
        await tester.run()
    except Exception as e:
        logger.error(f"Test failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_mutual_auth())
