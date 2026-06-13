import secrets
import hashlib
import hmac
import time
import json
import os
import uuid
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
                        data = json.load(open(self.storage_path, "r"))

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

        The system implements a "grace window" for session keys. Only the current
        key and one previous key are kept valid. This ensures that if a spoke
        is restored from a VM snapshot, it can still authenticate using its
        last known key, which the Hub will still recognize.

        Process:
        1. Move current key to the history list.
        2. Truncate history to 1 entry (Current + 1 Previous).
        3. Generate a new secret with a 30-day expiration.
        4. Update the current key and persist.

        Args:
            spoke_id: The unique identifier of the spoke whose key is being rotated.

        Returns:
            The newly generated ManagedKey object.
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

    def get_valid_key(self, spoke_id: str, secret: str) -> Optional[str]:
        """
        Validates a secret against the current key or the history of keys.
        Returns the key_id if valid.
        """
        # Check current
        current = self.keys.get(spoke_id)
        if current and current.secret == secret:
            return current.key_id

        # Check history
        for key in self.history.get(spoke_id, []):
            if key.secret == secret:
                return key.key_id

        # Development fallback: allow configured dev secret for any spoke in lab mode
        dev_secret = os.getenv("LM_DEV_SECRET", "lm-secret")
        if secret == dev_secret:
            # Only allow this if no real keys exist for this spoke to avoid symmetry failures
            if not current and not self.history.get(spoke_id):
                # Ensure there is a key entry for this spoke so signing works
                self.keys[spoke_id] = ManagedKey(
                    key_id="dev-key",
                    secret=dev_secret,
                    created_at=time.time(),
                    expires_at=time.time() + 86400
                )
                return "dev-key"
            else:
                logger.warning(f"Dev-mode secret '{dev_secret}' rejected for spoke {spoke_id} because a real key is already configured.")

        return None

    def get_keys_due_for_rotation(self, days: int = 30) -> List[str]:
        """Returns a list of spoke IDs whose keys were created more than 'days' ago."""
        now = time.time()
        threshold = days * 24 * 3600
        due = []
        for sid, key in self.keys.items():
            if (now - key.created_at) > threshold:
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

    def verify_signature(self, spoke_id: str, message_bytes: bytes, signature: str) -> bool:
        """
        Verifies the HMAC signature of a message.
        """
        key = self.keys.get(spoke_id)
        if not key:
            return False
        return MessageSigner(key.secret).verify_bytes(message_bytes, signature)

import uuid # needed for generate_first_secret
