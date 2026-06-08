import asyncio
import json
import uuid
import time
import websockets
import hmac
import hashlib
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("GhostTenant")

class GhostTenant:
    def __init__(self, spoke_id, secret, hub_url="ws://localhost:8765"):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_url = hub_url

    def sign_message(self, message_dict):
        data = {k: v for k, v in message_dict.items() if k != "signature"}
        message_bytes = json.dumps(data, sort_keys=True).encode()
        return hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

    async def run_test_suite(self):
        async with websockets.connect(self.hub_url) as websocket:
            # 1. Authenticate
            await websocket.send(json.dumps({
                "spoke_id": self.spoke_id,
                "secret": self.secret
            }))
            logger.info("Authenticated as Ghost Tenant.")

            # 2. Test Standard Build Request
            logger.info("Testing Standard Build request...")
            msg_id = str(uuid.uuid4())
            build_req = {
                "header": {
                    "message_id": msg_id,
                    "timestamp": time.time(),
                    "sender_id": self.spoke_id,
                    "destination_id": "hub"
                },
                "payload": {
                    "type": "REQUEST_BUILD",
                    "data": {"type": "STANDARD_VM", "cpu": 2, "ram": 4096}
                }
            }
            build_req["signature"] = self.sign_message(build_req)
            await websocket.send(json.dumps(build_req))

            # Wait for Ack
            try:
                resp = await asyncio.wait_for(websocket.recv(), timeout=5)
                resp_data = json.loads(resp)
                if resp_data.get("correlation_id") == msg_id:
                    logger.info(f"Build request acknowledged: {resp_data.get('status')}")
                else:
                    logger.error("Unexpected response received.")
            except asyncio.TimeoutError:
                logger.error("Build request timed out.")

            # 3. Test Rollback Logic (by requesting an impossible resource)
            logger.info("Testing Atomic Rollback by requesting excessive resources...")
            fail_id = str(uuid.uuid4())
            fail_req = {
                "header": {
                    "message_id": fail_id,
                    "timestamp": time.time(),
                    "sender_id": self.spoke_id,
                    "destination_id": "hub"
                },
                "payload": {
                    "type": "REQUEST_BUILD",
                    "data": {"type": "CUSTOM_VM", "cpu": 9999, "ram": 999999}
                }
            }
            fail_req["signature"] = self.sign_message(fail_req)
            await websocket.send(json.dumps(fail_req))

            try:
                resp = await asyncio.wait_for(websocket.recv(), timeout=5)
                resp_data = json.loads(resp)
                if resp_data.get("correlation_id") == fail_id:
                    logger.info(f"Rollback request acknowledged: {resp_data.get('status')}")
                else:
                    logger.error("Unexpected response received.")
            except asyncio.TimeoutError:
                logger.error("Rollback test timed out.")

if __name__ == "__main__":
    # Use the same secret we used for the mock spoke
    SPOKE_ID = "spoke-1"
    SECRET = "741R-ijB6DcUZmQcYCU91nT81kIA16XyNQIm0-RmHmc"

    tenant = GhostTenant(SPOKE_ID, SECRET)
    asyncio.run(tenant.run_test_suite())
