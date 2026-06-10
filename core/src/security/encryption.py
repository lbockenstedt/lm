import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

logger = logging.getLogger("Encryption")

class HubEncryption:
    """
    Handles transparent at-rest encryption for Hub JSON files.
    Uses the system machine-id as a root of trust for key derivation.
    """
    def __init__(self):
        self.fernet = self._initialize_fernet()

    def _initialize_fernet(self) -> Fernet:
        # 1. Get machine-id as the seed for the master key
        machine_id = self._get_machine_id()

        # 2. Derive a 32-byte key using PBKDF2
        # We use a fixed salt for consistency across restarts on the same machine
        salt = b'lab-manager-salt-2026'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(machine_id.encode())

        # Fernet keys must be base64 encoded
        fernet_key = base64.urlsafe_b64encode(key)
        return Fernet(fernet_key)

    def _get_machine_id(self) -> str:
        """Retrieves the unique machine ID from the system."""
        paths = ['/etc/machine-id', '/var/lib/dbus/machine-id']
        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        return f.read().strip()
                except Exception as e:
                    logger.error(f"Failed to read {path}: {e}")

        # Mac/BSD fallback: Use the hardware UUID or MAC address
        import uuid
        machine_uuid = str(uuid.getnode())

        # Still try the fallback path for persistent override
        fallback_path = "/etc/lm-encryption-secret"
        if os.path.exists(fallback_path):
            try:
                with open(fallback_path, 'r') as f:
                    return f.read().strip()
            except Exception as e:
                logger.error(f"Failed to read fallback secret: {e}")

        # If we have a stable hardware ID, use it as the base for the fallback secret
        return machine_uuid

    def encrypt(self, data: str) -> bytes:
        """Encrypts a string and returns the ciphertext bytes."""
        return self.fernet.encrypt(data.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        """Decrypts ciphertext bytes and returns the original string."""
        return self.fernet.decrypt(ciphertext).decode()

# Singleton instance for the process
hub_encryption = HubEncryption()
