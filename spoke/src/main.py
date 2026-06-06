import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib

logging.basicConfig(level=logging.INFO)
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
        async with websockets.connect(self.hub_url) as websocket:
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

if __name__ == "__main__":
    # Replace these with values from the Hub's keys.json or generated first secret
    SPOKE_ID = "spoke-1"
    SECRET = "741R-ijB6DcUZmQcYCU91nT81kIA16XyNQIm0-RmHmc"

    try:
        spoke = MockSpoke(SPOKE_ID, SECRET)
        asyncio.run(spoke.run())
    except KeyboardInterrupt:
        pass
