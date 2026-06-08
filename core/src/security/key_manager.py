import secrets
import hashlib
import hmac
import time
import json
import os
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

@dataclass
class ManagedKey:
    key_id: str
    secret: str
    created_at: float
    expires_at: float

class KeyManager:
    def __init__(self, storage_path="keys.json"):
        self.storage_path = storage_path
        self.keys: Dict[str, ManagedKey] = {} # { spoke_id: current_key }
        self.history: Dict[str, List[ManagedKey]] = {} # { spoke_id: [previous_keys] }
        self.load_keys()

    def _save_keys(self):
        data = {
            "current": {sid: asdict(k) for sid, k in self.keys.items()},
            "history": {sid: [asdict(k) for k in ks] for sid, ks in self.history.items()}
        }
        with open(self.storage_path, "w") as f:
            json.dump(data, f)

    def load_keys(self):
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r") as f:
                    data = json.load(f)
                    for sid, k in data["current"].items():
                        self.keys[sid] = ManagedKey(**k)
                    for sid, ks in data["history"].items():
                        self.history[sid] = [ManagedKey(**k) for k in ks]
            except Exception as e:
                print(f"Error loading keys: {e}")

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
        Rotates the key for a spoke. Moves current key to history.
        """
        if spoke_id in self.keys:
            old_key = self.keys[spoke_id]
            if spoke_id not in self.history:
                self.history[spoke_id] = []
            self.history[spoke_id].insert(0, old_key)
            # Keep only 4 previous keys
            self.history[spoke_id] = self.history[spoke_id][:4]

        new_key = ManagedKey(
            key_id=str(uuid.uuid4()),
            secret=secrets.token_urlsafe(32),
            created_at=time.time(),
            expires_at=time.time() + (7 * 24 * 3600) # 7 days
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

        return None

    def sign_message(self, spoke_id: str, message_bytes: bytes) -> str:
        """
        Signs a message using the current secret for the spoke.
        """
        key = self.keys.get(spoke_id)
        if not key:
            raise ValueError(f"No key found for spoke {spoke_id}")

        return hmac.new(
            key.secret.encode(),
            message_bytes,
            hashlib.sha256
        ).hexdigest()

    def verify_signature(self, spoke_id: str, message_bytes: bytes, signature: str) -> bool:
        """
        Verifies the HMAC signature of a message.
        """
        try:
            expected = self.sign_message(spoke_id, message_bytes)
            return hmac.compare_digest(expected, signature)
        except ValueError:
            return False

import uuid # needed for generate_first_secret
