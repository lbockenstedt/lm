import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("MockSpoke")

class MockSpoke:
    def __init__(self, spoke_id, secret, hub_url="ws://localhost:8765"):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_url = hub_url

    def sign_message(self, message_dict):
        # Remove signature if present
        data = {k: v for k, v in message_dict.items() if k != "signature"}
        message_bytes = json.dumps(data, sort_keys=True).encode()
        return hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

    async def run(self):
        retry_delay = 1  # Initial backoff in seconds
        max_delay = 60

        while True:
            try:
                async with websockets.connect(self.hub_url) as websocket:
                    retry_delay = 1 # Reset delay on successful connection
                    # 1. Handshake: Send spoke_id and secret
                    await websocket.send(json.dumps({
                        "spoke_id": self.spoke_id,
                        "secret": self.secret
                    }))
                    logger.info(f"Connected and authenticated as {self.spoke_id}")

                    # 2. Heartbeat Task
                    async def heartbeat_loop():
                        while True:
                            try:
                                msg_dict = {
                                    "header": {
                                        "message_id": str(uuid.uuid4()),
                                        "timestamp": time.time(),
                                        "sender_id": self.spoke_id,
                                        "destination_id": "hub"
                                    },
                                    "payload": {"type": "HEARTBEAT", "data": {}}
                                }
                                msg_dict["signature"] = self.sign_message(msg_dict)
                                await websocket.send(json.dumps(msg_dict))
                                logger.debug("Heartbeat sent")
                            except Exception as e:
                                logger.error(f"Heartbeat failed: {e}")
                            await asyncio.sleep(30)

                    asyncio.create_task(heartbeat_loop())

                    # 3. Message Handling Loop
                    async for message_json in websocket:
                        msg = json.loads(message_json)
                        header = msg.get("header", {})
                        payload = msg.get("payload", {})

                        # Verify signature (Hub's signature)
                        signature = msg.get("signature")
                        data_to_verify = {k: v for k, v in msg.items() if k != "signature"}
                        message_bytes = json.dumps(data_to_verify, sort_keys=True).encode()
                        expected = hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

                        if not hmac.compare_digest(expected, signature):
                            logger.warning("Invalid signature from Hub!")
                            continue

                        logger.info(f"Received verified message: {payload.get('type')} (ID: {header.get('message_id')})")

                        # Send Acknowledgement
                        ack = {
                            "correlation_id": header.get("message_id"),
                            "status": "SUCCESS",
                            "timestamp": time.time(),
                            "header": {
                                "message_id": str(uuid.uuid4()),
                                "sender_id": self.spoke_id,
                                "destination_id": "hub"
                            }
                        }
                        ack["signature"] = self.sign_message(ack)
                        await websocket.send(json.dumps(ack))
                        logger.info(f"Sent Ack for {header.get('message_id')}")

            except (websockets.exceptions.ConnectionClosed, OSError) as e:
                logger.error(f"Connection lost/failed ({e}). Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, max_delay) # Exponential backoff
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                await asyncio.sleep(5)

if __name__ == "__main__":
    # Read credentials from the environment — never hardcode a real first-secret.
    SPOKE_ID = os.getenv("LM_MOCK_SPOKE_ID", "spoke-1")
    SECRET = os.getenv("LM_MOCK_SPOKE_SECRET")
    if not SECRET:
        print("Set LM_MOCK_SPOKE_SECRET to a real first-secret from the Hub to run this mock spoke.")
        raise SystemExit(1)

    try:
        spoke = MockSpoke(SPOKE_ID, SECRET)
        asyncio.run(spoke.run())
    except KeyboardInterrupt:
        pass
