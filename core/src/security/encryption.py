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
        # Raw primary key string, captured at load so consumers that legitimately
        # need the key material (e.g. oidc.py's state-cookie HMAC fallback) can
        # read it from HERE instead of re-reading os.environ — which lets us DROP
        # LM_FERNET_KEY from the environment after load (Tier-0 root/LPE
        # hardening: shrink the /proc/<pid>/environ window a root reader can grab
        # the key from without ptrace/core-dump).
        self._primary_key_str: str = ""
        self._legacy_fernet = self._derive_machine_id_fernet()
        self.fernet = self._load_primary_fernet()
        self._previous_fernets = self._load_previous_fernets()
        self._maybe_drop_env_key()
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
        """Load + validate the primary Fernet key, stash the raw value, return a
        ``Fernet``.

        Key source, in order:
          1. **Tier 1 — Azure Key Vault** (only when ``LM_FERNET_KEY_KV_SECRET``
             names a secret AND a vault is reachable): fetch the key from Key
             Vault so it never lives on disk in ``.env``. See
             ``_resolve_primary_key`` — this is a no-op on-prem (the env var is
             unset), so a non-Azure install keeps the pure env behavior.
          2. **Env** — ``LM_FERNET_KEY`` (the on-prem / default path, and the
             migration fallback when a configured vault is momentarily
             unreachable).

        REQUIRED (fail-closed): if neither source yields a valid key this raises
        and the hub will not start. The weak machine-id key is kept only as
        ``_legacy_fernet`` for transparent decrypt of pre-``LM_FERNET_KEY``
        blobs (new writes use the primary key)."""
        key_str, source = self._resolve_primary_key()
        if not key_str:
            raise RuntimeError(
                "No Fernet key available. At-rest encryption requires a key. "
                "Set LM_FERNET_KEY (see .env.example), or — for the off-disk "
                "'Tier 1' path — set LM_FERNET_KEY_KV_SECRET (the Key Vault "
                "secret name) plus LM_KEYVAULT_URL and install the Azure SDK. "
                "Generate a key with: python -c \"from cryptography.fernet import "
                "Fernet; print(Fernet.generate_key().decode())\"."
            )
        try:
            fernet = Fernet(key_str.encode())
        except Exception as e:
            raise RuntimeError(
                f"The Fernet key from {source} is not a valid Fernet key: {e}")
        # Stash the validated raw key so consumers (oidc.py, key_vault.py) can get
        # it from the singleton after we drop LM_FERNET_KEY from os.environ.
        self._primary_key_str = key_str
        if source.startswith("keyvault"):
            logger.info("Loaded primary Fernet key from %s (off-disk Tier 1).", source)
        return fernet

    def _resolve_primary_key(self) -> tuple:
        """Resolve the raw primary Fernet key string + a source label.

        Tier 1 (Key Vault) is attempted ONLY when ``LM_FERNET_KEY_KV_SECRET`` is
        set — that env var is the explicit opt-in that says "the master key lives
        in the vault under this name". When set, the key is fetched via the shared
        ``security.credential_store`` provider (which reads ``LM_KEYVAULT_URL`` /
        ``LM_KEYVAULT_CLIENT_ID`` and uses managed identity). A configured-but-
        unreachable vault does NOT hard-fail: it falls back to ``LM_FERNET_KEY``
        (env) with a warning, so a migrating deployment that still keeps the key
        in ``.env`` stays bootable. Returns ``("", "")`` if nothing resolves."""
        kv_secret = (os.getenv("LM_FERNET_KEY_KV_SECRET") or "").strip()
        if kv_secret:
            val = self._fetch_key_from_vault(kv_secret)
            if val:
                return val.strip(), f"keyvault:{kv_secret}"
            logger.warning(
                "LM_FERNET_KEY_KV_SECRET=%r is set but the key could not be "
                "fetched from Key Vault (SDK missing, LM_KEYVAULT_URL unset, "
                "auth/network error, or secret absent). Falling back to "
                "LM_FERNET_KEY from the environment if present.", kv_secret)
        env_key = (os.getenv("LM_FERNET_KEY") or "").strip()
        if env_key:
            return env_key, "env"
        return "", ""

    @staticmethod
    def _fetch_key_from_vault(secret_name: str):
        """Best-effort fetch of ``secret_name`` from Azure Key Vault via the
        shared credential provider. Returns the secret value or ``None`` (never
        raises — a vault problem must not crash import)."""
        try:
            from security.credential_store import get_credential_provider
        except ImportError:  # pragma: no cover - import-path fallback
            try:
                from credential_store import get_credential_provider
            except Exception:  # noqa: BLE001
                return None
        try:
            provider = get_credential_provider()
            if getattr(provider, "name", "") != "keyvault" or not provider.ready:
                return None
            return provider.get_secret(secret_name)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Key Vault fetch of Fernet key %r failed: %s",
                           secret_name, exc)
            return None

    def _maybe_drop_env_key(self) -> None:
        """Remove ``LM_FERNET_KEY``/``LM_FERNET_KEY_PREVIOUS`` from ``os.environ``
        once they are loaded (Tier-0 root/LPE hardening).

        The key material stays in-process (Fernet objects + ``_primary_key_str``);
        this only removes it from ``/proc/<pid>/environ``, which a root reader can
        slurp WITHOUT ptrace or a core dump. systemd re-sources the key from
        ``.env`` (``EnvironmentFile``) on every restart, so this does not affect
        the hub's own restart path.

        OPT-IN (default OFF): enabled by ``LM_DROP_FERNET_KEY_ENV=1`` — set by the
        installer in the hub's systemd unit. Kept opt-in so the test suite and any
        tooling that constructs the singleton in a shell keep the env var by
        default. ``LM_KEEP_FERNET_KEY_ENV=1`` force-disables it even when the drop
        flag is on (the rotate CLI sets this). No-op if the key material could not
        be captured (fail-safe)."""
        if os.environ.get("LM_DROP_FERNET_KEY_ENV", "").strip() not in ("1", "true", "yes"):
            return
        if os.environ.get("LM_KEEP_FERNET_KEY_ENV", "").strip() in ("1", "true", "yes"):
            return
        if not self._primary_key_str:
            return
        dropped = []
        for var in ("LM_FERNET_KEY", "LM_FERNET_KEY_PREVIOUS"):
            if os.environ.pop(var, None) is not None:
                dropped.append(var)
        if dropped:
            logger.info(
                "Dropped %s from the process environment after load "
                "(root/LPE hardening: /proc/<pid>/environ no longer exposes the "
                "at-rest key). Unset LM_DROP_FERNET_KEY_ENV to disable.",
                ", ".join(dropped),
            )

    def primary_key(self) -> str:
        """The raw primary Fernet key string captured at load. Prefer this over
        ``os.environ['LM_FERNET_KEY']`` — the env var is dropped after load."""
        return self._primary_key_str

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


def primary_fernet_key() -> str:
    """Best-effort accessor for the raw primary Fernet key string.

    Reads it from the loaded ``hub_encryption`` singleton (which captured it
    before dropping ``LM_FERNET_KEY`` from ``os.environ``), falling back to the
    env var if the singleton is somehow unavailable or the key was kept in env
    (``LM_KEEP_FERNET_KEY_ENV=1``). Returns ``""`` if nothing is resolvable.

    Consumers that historically read ``os.environ['LM_FERNET_KEY']`` (e.g.
    ``oidc.py``'s state-cookie HMAC fallback) MUST use this so they keep working
    after the env-drop."""
    try:
        k = hub_encryption.primary_key()
        if k:
            return k
    except Exception:  # noqa: BLE001
        pass
    return (os.environ.get("LM_FERNET_KEY", "") or "").strip()
