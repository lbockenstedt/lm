"""Central authority for the Hub's cryptographic secrets.

Owns two distinct secret classes: the long-lived Hub root secret (used to prove
Hub identity to spokes during mutual challenge-authentication, with a 3-entry
rotation window to tolerate restores) and the per-spoke ``ManagedKey`` session
secrets (short/medium-term HMAC keys used to sign per-message traffic). Secrets
are persisted as encrypted JSON in the data directory; at-rest encryption is
delegated to ``encryption.py`` (``hub_encryption``).

Signing/verification primitives are delegated to ``signer.py`` (``MessageSigner``);
this module only selects which secret to feed it. The wire envelope that carries
the resulting signatures is defined in ``messaging/protocol.py``.
"""

import secrets
import hashlib
import hmac
import time
import json
import os
import uuid  # used by generate_first_secret / rotate_key to mint key_ids
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from .signer import MessageSigner
from .encryption import hub_encryption

logger = logging.getLogger("KeyManager")

@dataclass
class ManagedKey:
    key_id: str
    secret: str
    created_at: float
    expires_at: float

class KeyManager:
    """
    The KeyManager is the central authority for cryptographic secrets within the Hub.
    It manages two distinct types of secrets:
    1. The Hub Root Secret: A long-term secret used by the Hub to prove its identity
       to spokes during mutual authentication. It maintains a rotation window to
       support system restores.
    2. ManagedKeys (Spoke Secrets): Short-to-medium term secrets used for HMAC
       signing of per-message traffic between the Hub and a specific spoke.

    Persistence is handled independently via encrypted JSON files in the data directory.
    """
    def __init__(self, system_path="keys.json", hub_secret_path="hub_secret.json"):
        # Resolve absolute paths to avoid PermissionErrors under systemd/different CWDs
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.abspath(os.path.join(base_dir, "../../data"))
        os.makedirs(data_dir, exist_ok=True)

        self.storage_path = os.path.join(data_dir, system_path)
        self.hub_secret_path = os.path.join(data_dir, hub_secret_path)
        self.keys: Dict[str, ManagedKey] = {} # { spoke_id: current_key }
        self.history: Dict[str, List[ManagedKey]] = {} # { spoke_id: [previous_keys] }
        self.hub_secrets = self._load_or_generate_hub_secrets()
        self.load_keys()

    def _load_or_generate_hub_secrets(self) -> List[str]:
        """Loads or generates the persistent secrets used by the Hub.
        Maintains a window of the last 3 secrets.
        """
        if os.path.exists(self.hub_secret_path):
            try:
                with open(self.hub_secret_path, "rb") as f:
                    content = f.read()
                    try:
                        decrypted = hub_encryption.decrypt(content)
                        data = json.loads(decrypted)
                        if isinstance(data, list):
                            return data[:3]
                        # Migration: if it was a single string
                        return [data] if isinstance(data, str) else [str(data)]
                    except Exception:
                        # Fallback to plain text for migration
                        text = content.decode().strip()
                        return [text] if "," not in text else text.split(",")
            except Exception as e:
                logger.error(f"Failed to load hub secrets: {e}")

        # Initial generation
        secrets_list = [secrets.token_urlsafe(64)]
        self._save_hub_secrets(secrets_list)
        return secrets_list

    def _save_hub_secrets(self, secrets_list: List[str]):
        try:
            json_data = json.dumps(secrets_list, separators=(',', ':'))
            encrypted_secret = hub_encryption.encrypt(json_data)
            with open(self.hub_secret_path, "wb") as f:
                f.write(encrypted_secret)
        except Exception as e:
            logger.error(f"Failed to save hub secrets: {e}")

    def rotate_hub_secret(self) -> str:
        """
        Rotates the Hub's root identity secret.

        The Hub maintains a window of the last 3 root secrets. When a rotation occurs:
        1. A new 64-character URL-safe token is generated.
        2. The new secret is prepended to the `hub_secrets` list.
        3. The list is truncated to 3 entries.
        4. The updated list is encrypted and persisted to disk.

        This window allows spokes to verify the Hub's identity even if they have
        not yet received the latest rotation update or if they were restored
        from a backup.

        Returns:
            The new root secret as a string.
        """
        new_secret = secrets.token_urlsafe(64)
        self.hub_secrets.insert(0, new_secret)
        self.hub_secrets = self.hub_secrets[:3]
        self._save_hub_secrets(self.hub_secrets)
        return new_secret

    def sign_hub_challenge(self, challenge_bytes: bytes) -> str:
        """Signs a challenge using the most recent Hub secret."""
        return hmac.new(
            self.hub_secrets[0].encode(),
            challenge_bytes,
            hashlib.sha256
        ).hexdigest()

    def _save_keys(self):
        data = {
            "current": {sid: asdict(k) for sid, k in self.keys.items()},
            "history": {sid: [asdict(k) for k in ks] for sid, ks in self.history.items()}
        }
        json_data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        encrypted_data = hub_encryption.encrypt(json_data)
        with open(self.storage_path, "wb") as f:
            f.write(encrypted_data)

    def load_keys(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "rb") as f:
                    content = f.read()
                    try:
                        # Try decrypting
                        decrypted = hub_encryption.decrypt(content)
                        data = json.loads(decrypted)
                    except Exception:
                        # Fallback to plain text for migration
                        with open(self.storage_path, "r") as f:
                            data = json.load(f)

                    for sid, k in data["current"].items():
                        self.keys[sid] = ManagedKey(**k)
                    for sid, ks in data["history"].items():
                        self.history[sid] = [ManagedKey(**k) for k in ks]
            except Exception as e:
                logger.error(f"Error loading keys from {self.storage_path}: {e}")

    def generate_first_secret(self, spoke_id: str) -> str:
        """
        Generates a 'First Secret' for a new spoke to use for onboarding.
        """
        secret = secrets.token_urlsafe(32)
        key = ManagedKey(
            key_id=str(uuid.uuid4()),
            secret=secret,
            created_at=time.time(),
            expires_at=time.time() + 3600 # First secret expires in 1 hour
        )
        self.keys[spoke_id] = key
        self._save_keys()
        return secret

    def rotate_key(self, spoke_id: str) -> ManagedKey:
        """
        Rotates the session key for a specific spoke.
        """
        if spoke_id in self.keys:
            old_key = self.keys[spoke_id]
            if spoke_id not in self.history:
                self.history[spoke_id] = []
            self.history[spoke_id].insert(0, old_key)
            # Keep only 1 previous key (Total: Current + 1 Previous)
            self.history[spoke_id] = self.history[spoke_id][:1]

        new_key = ManagedKey(
            key_id=str(uuid.uuid4()),
            secret=secrets.token_urlsafe(32),
            created_at=time.time(),
            expires_at=time.time() + (30 * 24 * 3600) # 30 days
        )
        self.keys[spoke_id] = new_key
        self._save_keys()
        return new_key

    def delete_spoke_key(self, spoke_id: str):
        """
        Completely removes all keys and history for a spoke.
        This forces the spoke to undergo a new 'first-secret' onboarding.
        """
        self.keys.pop(spoke_id, None)
        self.history.pop(spoke_id, None)
        self._save_keys()
        logger.info(f"Completely wiped keys for spoke {spoke_id}")

    def rename_spoke_keys(self, old_id: str, new_id: str) -> None:
        """Re-key a spoke's current key + history from ``old_id`` → ``new_id``.

        Called when a cloned+renamed spoke reconnects with the same install UUID
        but a new spoke_id: the renamed spoke still holds the SAME ``SPOKE_SECRET``
        (cloned from .env), so re-keying its key material to the new id lets
        :meth:`get_valid_key` authenticate it seamlessly — without this the new id
        has no key and falls into pending-negotiation, making approval carryover
        useless. Idempotent. Caller persists via the internal ``_save_keys``.
        """
        if old_id == new_id:
            return
        moved = False
        if old_id in self.keys:
            self.keys[new_id] = self.keys.pop(old_id)
            moved = True
        if old_id in self.history:
            self.history[new_id] = self.history.pop(old_id)
            moved = True
        if moved:
            self._save_keys()
            logger.info(f"Re-keyed spoke keys {old_id} → {new_id}")

    def get_valid_key(self, spoke_id: str, secret: str) -> Optional[str]:
        """
        Validates a secret against the current key or the history of keys.
        Returns the key_id if valid.
        """
        # Check current
        current = self.keys.get(spoke_id)
        if current and hmac.compare_digest(current.secret, secret):
            return current.key_id

        # Check history
        for key in self.history.get(spoke_id, []):
            if hmac.compare_digest(key.secret, secret):
                return key.key_id

        return None

    def get_keys_due_for_rotation(self, days: int = 30) -> List[str]:
        """Spoke IDs due for rotation: keys created more than ``days`` ago, OR
        whose ``expires_at`` has passed.

        The second clause makes the zero-touch bootstrap's short lifetime real:
        ``generate_first_secret`` stamps ``expires_at = now + 3600`` (1 hour) so
        a captured bootstrap secret is only good briefly before the hub
        proactively rotates it into a full 30-day key. Previously this field was
        set but never read — rotation was driven solely by ``created_at`` (30
        days), so the "first secret expires in 1 hour" comment was a lie and the
        bootstrap secret actually lived 30 days. Now the hourly rotation loop
        picks up an expired first secret the first tick after it expires (worst
        case ~2h: 1h expiry + up to 1h to the next loop tick). A rotated key's
        ``expires_at`` is ``created_at + 30d``, so the two clauses agree for
        full keys — no double-rotation.
        """
        now = time.time()
        threshold = days * 24 * 3600
        due = []
        for sid, key in self.keys.items():
            if (now - key.created_at) > threshold:
                due.append(sid)
            elif key.expires_at and now > key.expires_at:
                due.append(sid)
        return due

    def sign_message(self, spoke_id: str, message_dict: Dict[str, Any]) -> str:
        """
        Signs a message dictionary using the current secret for the spoke.
        Uses canonical serialization for deterministic results.
        """
        key = self.keys.get(spoke_id)
        if not key:
            raise ValueError(f"No key found for spoke {spoke_id}")

        return MessageSigner(key.secret).sign(message_dict)

    def current_session_secret(self, spoke_id: str) -> Optional[str]:
        """The session secret currently held for a spoke, or None if it has none.

        Callers delivering a NEW session key capture this BEFORE
        ``generate_first_secret``/``rotate_key`` so they can sign the
        ``SPOKE_UPDATE_SESSION_KEY`` push with the secret the spoke still holds
        (it cannot verify a frame signed with the new secret it has not yet
        installed). None means the spoke is pending (no secret) — it accepts
        the delivery unauthenticated.
        """
        key = self.keys.get(spoke_id)
        return key.secret if key else None

    def sign_with_secret(self, secret: str, message_dict: Dict[str, Any]) -> str:
        """Sign a message with an EXPLICIT secret instead of ``keys[spoke_id]``.

        Used only for ``SPOKE_UPDATE_SESSION_KEY`` delivery: the push carries
        the new session secret but must be signed with the PREVIOUS secret the
        spoke still holds so it can verify and dispatch it. See
        ``main.py send_to_spoke(signing_secret=...)``.
        """
        return MessageSigner(secret).sign(message_dict)

    def encode_frame(self, spoke_id: str, message_dict: Dict[str, Any]) -> str:
        """Serialize + sign ``message_dict`` into the wire form ``<sig>.<body>``
        using the spoke's current key. The receiver verifies the RECEIVED body
        bytes directly (no re-serialization), so this replaces the sign()+dumps()
        that dominated per-frame CPU."""
        key = self.keys.get(spoke_id)
        if not key:
            raise ValueError(f"No key found for spoke {spoke_id}")
        return MessageSigner(key.secret).encode_frame(message_dict)

    def encode_frame_with_secret(self, secret: str, message_dict: Dict[str, Any]) -> str:
        """``encode_frame`` with an EXPLICIT secret (SPOKE_UPDATE_SESSION_KEY
        delivery — signed with the PREVIOUS secret the spoke still holds)."""
        return MessageSigner(secret).encode_frame(message_dict)

    def encode_frame(self, spoke_id: str, message_dict: Dict[str, Any]) -> str:
        """Serialize + sign ``message_dict`` into the wire form ``<sig>.<body>``
        using the spoke's current key. The receiver verifies the RECEIVED body
        bytes directly (verify_signature), so this replaces sign()+dumps() and
        removes the per-frame re-serialization."""
        key = self.keys.get(spoke_id)
        if not key:
            raise ValueError(f"No key found for spoke {spoke_id}")
        return MessageSigner(key.secret).encode_frame(message_dict)

    def encode_frame_with_secret(self, secret: str, message_dict: Dict[str, Any]) -> str:
        """``encode_frame`` with an EXPLICIT secret (SPOKE_UPDATE_SESSION_KEY
        delivery — signed with the PREVIOUS secret the spoke still holds)."""
        return MessageSigner(secret).encode_frame(message_dict)

    def verify_signature(self, spoke_id: str, message_bytes: bytes, signature: str) -> bool:
        """Verifies the HMAC signature of a message.

        Accepts the current key OR any key in the rotation history, mirroring
        ``get_valid_key``'s auth-time acceptance. Without the history window a
        frame signed with the just-rotated-out key (in flight when
        ``rotate_key`` pushed the new secret to the spoke) would wrongly fail,
        creating an auth/verify asymmetry where a spoke authenticates via the
        history window but every subsequent frame fails verification.
        """
        key = self.keys.get(spoke_id)
        if key and MessageSigner(key.secret).verify_bytes(message_bytes, signature):
            return True
        # Rotation window: tolerate frames signed with the previous key.
        for hist in self.history.get(spoke_id, []):
            if MessageSigner(hist.secret).verify_bytes(message_bytes, signature):
                return True
        return False
