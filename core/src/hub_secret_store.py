"""Storage for secrets the HUB generates itself (no operator types them in).

Examples: the 802.1X just-in-time account passwords (dot1x_jit) and the
Graylog admin/reader passwords the syslog archive role installs with
(syslog_archive). The operator's Credential Vault (cred_vault) cannot hold
these: it needs the bucket PSK, which the hub does not have unattended.

Every value is encrypted with the hub key first. When a cloud vault is enabled
the ciphertext goes there (record ``{"store": "kv", "kv_name": ...}``);
otherwise it is kept in a caller-owned dict inside the encrypted hub state
(record ``{"store": "local"}``). The caller keeps the small record next to its
own data and passes it back on get/delete; the value itself is never in it.
"""

import logging
import uuid
from typing import Any, Dict, Optional

import cloud_vault
from security.encryption import hub_encryption

logger = logging.getLogger("HubSecretStore")


def vault_on(hub) -> bool:
    """Return True if a cloud vault is enabled."""
    # Any error counts as "no vault".
    try:
        return cloud_vault.active_provider(hub) is not None
    except Exception:  # noqa: BLE001
        return False


async def put(hub, blobs: Dict[str, str], key: str, rec: Dict[str, Any],
              value: str, kv_prefix: str) -> None:
    """Encrypt and store ``value`` under ``key``, updating ``rec``'s storage fields.

    ``blobs`` is the caller's local dict in hub state; ``kv_prefix`` names the
    cloud-vault secret (``<prefix><random>``)."""
    # Always encrypt with the hub key first.
    token = hub_encryption.encrypt(value).decode("ascii")
    # Existing vault secret name, if the value already lives in the vault.
    old_kv = rec.get("kv_name") if rec.get("store") == "kv" else None
    # Vault enabled: write there (reusing the name) and drop any local copy.
    if vault_on(hub):
        name = old_kv or (kv_prefix + uuid.uuid4().hex)
        await cloud_vault.set_secret(hub, name, token)
        blobs.pop(key, None)
        rec["store"], rec["kv_name"] = "kv", name
    # No vault: store locally and remove any old vault copy.
    else:
        blobs[key] = token
        rec["store"] = "local"
        rec.pop("kv_name", None)
        if old_kv:
            await cloud_vault.delete_secret(hub, old_kv)


async def get(hub, blobs: Dict[str, str], key: str, rec: Dict[str, Any]) -> Optional[str]:
    """Return the decrypted value for ``key``, or None if missing/unreadable."""
    # Read from the vault or the local map, then decrypt.
    try:
        if rec.get("store") == "kv":
            token = await cloud_vault.get_secret(hub, rec.get("kv_name") or "")
        else:
            token = blobs.get(key)
        if not token:
            return None
        return hub_encryption.decrypt(token.encode("ascii"))
    # Any failure is logged (key only, never the value) and treated as missing.
    except Exception as e:  # noqa: BLE001
        logger.warning("hub secret read for %s failed: %s", key, e)
        return None


async def delete(hub, blobs: Dict[str, str], key: str, rec: Dict[str, Any]) -> None:
    """Delete the stored value for ``key`` (local copy and any vault copy)."""
    # Remove the local copy, then the vault copy if present.
    blobs.pop(key, None)
    if rec.get("store") == "kv" and rec.get("kv_name"):
        await cloud_vault.delete_secret(hub, rec["kv_name"])
