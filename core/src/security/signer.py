"""HMAC-SHA256 message signing and verification for Hub↔spoke traffic.

Owns the canonical-JSON serialization used to produce deterministic signatures
across Python versions and platforms, plus the ``MessageSigner`` utility that
computes and verifies per-message HMACs over that canonical form. Verification
logs are redacted so token-bearing frames (auth/first-secret) never leak their
signed bytes to the logs.

This module is intentionally stateless — it holds no secrets. The secret used
to instantiate ``MessageSigner`` is supplied by ``key_manager.py``, which owns
the lifecycle (generation, rotation, persistence) of Hub root and per-spoke
session keys. The envelope that carries these signatures on the wire is
defined in ``messaging/protocol.py``.
"""

import hmac
import hashlib
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("Signer")

def encode_frame(signer, msg: Dict[str, Any]) -> str:
    """Wire form ``<sig>.<body>``: body is compact JSON serialized ONCE; sig is
    HMAC over those exact body bytes (or '' when there is no signer, for
    bootstrap heartbeats). The receiver HMACs the RECEIVED body bytes directly
    (no re-serialization, no sort_keys) — the per-frame json.dumps that dominated
    hub ingest CPU disappears. WIP: sig-verify-raw-bytes branch."""
    body = json.dumps(msg, separators=(',', ':'))
    sig = signer.sign_bytes(body.encode()) if signer is not None else ""
    return sig + "." + body


def split_frame(wire: str):
    """Split ``<sig>.<body>`` → (sig, body). sig may be '' (unsigned). A frame
    with no separator is treated as an unsigned raw body (defensive)."""
    sig, sep, body = wire.partition(".")
    if not sep:
        return "", wire
    return sig, body


class MessageSigner:
    """Utility for signing and verifying messages using HMAC-SHA256.
    Ensures deterministic serialization to prevent signature mismatches.
    """

    def __init__(self, secret: str):
        self.secret = secret

    def _canonicalize(self, obj: Any) -> Any:
        """Recursively sorts dictionary keys to ensure deterministic serialization."""
        if isinstance(obj, dict):
            return {k: self._canonicalize(obj[k]) for k in sorted(obj.keys())}
        elif isinstance(obj, list):
            return [self._canonicalize(i) for i in obj]
        return obj

    def sign(self, msg: Dict[str, Any]) -> str:
        """Signs a message by creating an HMAC-SHA256 hash of its canonical JSON representation."""
        # Exclude signature from the data being signed
        data = {k: v for k, v in msg.items() if k != "signature"}
        canonical_data = self._canonicalize(data)
        message_bytes = json.dumps(canonical_data, separators=(',', ':')).encode()
        sig = self.sign_bytes(message_bytes)
        # logger.debug(f"Signing with secret {self.secret[:4]}...{self.secret[-4:]} -> {sig[:8]}")
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
            canonical_data = self._canonicalize(data)
            bytes_used = json.dumps(canonical_data, separators=(',', ':')).encode()
            # Redact the signed payload: a mismatched frame may still carry a valid
            # token (e.g. auth/first-secret frames), and dumping the raw bytes would
            # write that token into the logs. Log only the length + a short hex
            # prefix so the mismatch stays diagnosable without leaking secrets.
            logger.warning(
                f"Signature mismatch! Expected: {expected}, Got: {sig}. "
                f"Data: <redacted {len(bytes_used)}B {bytes_used[:8].hex()}>"
            )
        return result

    def encode_frame(self, msg: Dict[str, Any]) -> str:
        """Serialize + sign a frame ONCE into the wire form ``<sig>.<body>``.

        This is the fast frame format: the receiver HMACs the RECEIVED body
        bytes directly (verify_frame) instead of re-serialising the parsed dict,
        eliminating the per-frame json.dumps that dominated hub ingest CPU. No
        sort_keys is needed — the receiver verifies the exact bytes, not a
        canonical re-serialization, so signing order is irrelevant."""
        return encode_frame(self, msg)

    def verify_bytes(self, message_bytes: bytes, signature: str) -> bool:
        """Verifies a signature against raw bytes."""
        expected = self.sign_bytes(message_bytes)
        result = hmac.compare_digest(expected, signature)
        if not result:
            # Redact raw bytes: token-bearing frames (auth/first-secret) may be
            # verified via this path; never log the raw signed bytes. Length + a
            # short hex prefix is enough to confirm a mismatch occurred.
            logger.warning(
                f"Bytes signature mismatch! Expected: {expected}, Got: {signature}. "
                f"Bytes: <redacted {len(message_bytes)}B {message_bytes[:8].hex()}>"
            )
        return result
