import hmac
import hashlib
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("Signer")

class MessageSigner:
    """Utility for signing and verifying messages using HMAC-SHA256.
    Ensures deterministic serialization to prevent signature mismatches.
    """

    def __init__(self, secret: str):
        self.secret = secret

    def sign(self, msg: Dict[str, Any]) -> str:
        """Signs a message by creating an HMAC-SHA256 hash of its JSON representation."""
        # Exclude signature from the data being signed
        data = {k: v for k, v in msg.items() if k != "signature"}
        message_bytes = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
        sig = self.sign_bytes(message_bytes)
        return sig

    def sign_bytes(self, message_bytes: bytes) -> str:
        """Signs raw bytes using HMAC-SHA256."""
        return hmac.new(self.secret.encode(), message_bytes, hashlib.sha256).hexdigest()

    def verify(self, msg: Dict[str, Any]) -> bool:
        """Verifies the signature of a message."""
        sig = msg.get("signature")
        if not sig:
            return False

        expected = self.sign(msg)
        result = hmac.compare_digest(expected, sig)
        if not result:
            data = {k: v for k, v in msg.items() if k != "signature"}
            bytes_used = json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
            logger.warning(f"Signature mismatch! Expected: {expected}, Got: {sig}. Data: {bytes_used}")
        return result

    def verify_bytes(self, message_bytes: bytes, signature: str) -> bool:
        """Verifies a signature against raw bytes."""
        expected = self.sign_bytes(message_bytes)
        result = hmac.compare_digest(expected, signature)
        if not result:
            logger.warning(f"Bytes signature mismatch! Expected: {expected}, Got: {signature}. Bytes: {message_bytes}")
        return result
