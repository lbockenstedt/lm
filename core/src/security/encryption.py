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


def plaintext_fallback_allowed() -> bool:
    """Whether a plaintext-JSON fallback is permitted when an at-rest state
    file fails Fernet decryption. Default ON (``1``) preserves the legacy
    migration path for files written before at-rest encryption; set
    ``LM_ALLOW_PLAINTEXT_FALLBACK=0`` to fail-closed so a botched rotation or
    lost key can NOT silently flip a state file (system.json/tenants.json/
    sessions/simulations) to a plaintext read. Shared by KeyManager (secrets)
    and the StateManager/SimulationsStore plaintext fallbacks so the operator's
    fail-closed promise holds across EVERY encrypted store, not just keys."""
    return os.environ.get("LM_ALLOW_PLAINTEXT_FALLBACK", "1").strip() in ("1", "true", "yes")


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
        self._previous_fernets = self._load_previous_fernets()
        # Decrypt attempt order: current primary key, then any PREVIOUS
        # (post-rotation) keys, then the legacy machine-id key. A blob that only
        # decrypts via a non-primary key is re-encrypted under the primary the
        # next time it's written (state manager re-key on load) so the fleet
        # migrates off old keys instead of stranding files — the exact failure
        # that left system.json/tenants.json unreadable after a rotation.
        self._decrypt_chain = [self.fernet] + self._previous_fernets + [self._legacy_fernet]

    def _load_previous_fernets(self) -> list:
        """Old Fernet keys kept ONLY for decrypt fallback after a key rotation,
        from ``LM_FERNET_KEY_PREVIOUS`` (comma- or space-separated list of full
        base64 Fernet keys). Set it to the OLD key(s) when you rotate
        ``LM_FERNET_KEY`` so the hub can still read state encrypted under them;
        those blobs migrate to the current key on their next save. Invalid
        entries are skipped with a warning (never fatal)."""
        raw = os.getenv("LM_FERNET_KEY_PREVIOUS", "") or ""
        out = []
        for tok in raw.replace(",", " ").split():
            try:
                out.append(Fernet(tok.strip().encode()))
            except Exception as e:  # noqa: BLE001
                logger.warning("Ignoring invalid key in LM_FERNET_KEY_PREVIOUS: %s", e)
        if out:
            logger.info("Loaded %d previous Fernet key(s) for decrypt fallback.", len(out))
        return out

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
        """Decrypts ciphertext, trying the current key, then PREVIOUS (rotation)
        keys, then the legacy machine-id key (transparent migration)."""
        return self.decrypt_with_meta(ciphertext)[0]

    def decrypt_with_meta(self, ciphertext: bytes):
        """Like ``decrypt`` but returns ``(plaintext, used_primary)``.

        Tries every key in ``_decrypt_chain`` in order (current → previous →
        legacy). ``used_primary`` is False when a fallback key succeeded, which
        signals the caller (state manager) to re-encrypt the blob under the
        current key so it stops depending on the old key. Raises the primary
        key's error if NONE succeed (preserving the original failure surface)."""
        first_err = None
        for f in self._decrypt_chain:
            try:
                return f.decrypt(ciphertext).decode(), (f is self.fernet)
            except Exception as e:  # noqa: BLE001
                if first_err is None:
                    first_err = e
        raise first_err

# Singleton instance for the process
hub_encryption = HubEncryption()
