"""Transparent at-rest encryption for Hub JSON state files.

Owns the ``HubEncryption`` singleton (``hub_encryption``) that wraps
``cryptography.fernet.Fernet`` to encrypt/decrypt persisted JSON such as
``hub_secret.json``, ``keys.json``, ``system.json``, and ``tenants.json``.
The primary key is sourced from the ``LM_FERNET_KEY`` env var (REQUIRED,
fail-closed); a weak machine-id-derived key is retained only as
``_legacy_fernet`` so blobs encrypted before ``LM_FERNET_KEY`` was deployed
remain decryptable (transparent migration — new writes always use the primary
key).

This module is consumed by ``security/key_manager.py`` (which encrypts/decrypts
the key and hub-secret stores) and by ``state/manager.py`` (which uses
``hub_encryption`` to protect broader persisted state). It is not involved in
per-message wire signing — that is ``security/signer.py``.
"""

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
    Handles transparent at-rest encryption for Hub JSON files
    (hub_secret.json, keys.json, system.json, tenants.json).

    Key source: LM_FERNET_KEY env var — a full base64 Fernet key (REQUIRED, fail-closed).
    Generate with:
      python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    If LM_FERNET_KEY is unset or invalid, initialization raises and the Hub will not start.

    A weak machine-id-derived key is still computed as `_legacy_fernet` ONLY so that blobs
    encrypted before LM_FERNET_KEY was deployed remain decryptable (transparent migration):
    decrypt tries the primary key first, then the legacy key. New writes always use the
    primary (LM_FERNET_KEY) key, so state migrates off the legacy key as it is rewritten.
    """
    def __init__(self):
        self._legacy_fernet = self._derive_machine_id_fernet()
        self.fernet = self._load_primary_fernet()

    def _derive_machine_id_fernet(self) -> Fernet:
        """Legacy key derivation from the machine-id (INSECURE; fallback only)."""
        machine_id = self._get_machine_id()
        salt = b'lab-manager-salt-2026'  # legacy; only used by the fallback path
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(machine_id.encode())
        return Fernet(base64.urlsafe_b64encode(key))

    def _load_primary_fernet(self) -> Fernet:
        """Loads the primary Fernet key from LM_FERNET_KEY.

        LM_FERNET_KEY is REQUIRED (fail-closed): if it is unset or invalid, this raises
        and the Hub will not start. The weak machine-id-derived key is kept only as
        `_legacy_fernet` for transparent decryption of blobs encrypted before
        LM_FERNET_KEY was deployed (new writes use the primary key)."""
        key_env = os.getenv("LM_FERNET_KEY")
        if not key_env:
            raise RuntimeError(
                "LM_FERNET_KEY is not set. At-rest encryption requires a Fernet key. "
                "Generate one with: python -c \"from cryptography.fernet import Fernet; "
                "print(Fernet.generate_key().decode())\" and set LM_FERNET_KEY (see .env.example)."
            )
        key = key_env.strip().encode()
        try:
            return Fernet(key)
        except Exception as e:
            raise RuntimeError(f"LM_FERNET_KEY is set but is not a valid Fernet key: {e}")

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
        """Decrypts ciphertext bytes and returns the original string.
        Falls back to the legacy machine-id key for blobs encrypted before
        LM_FERNET_KEY was configured (transparent migration)."""
        try:
            return self.fernet.decrypt(ciphertext).decode()
        except Exception:
            if self.fernet is not self._legacy_fernet:
                return self._legacy_fernet.decrypt(ciphertext).decode()
            raise

# Singleton instance for the process
hub_encryption = HubEncryption()
