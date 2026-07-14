"""Azure Key Vault hook (hub broker) — disaster-recovery kit off-box.

Pushes to an Azure Key Vault, authenticated with the SAME SSO app certificate
(``security.oidc.fetch_app_token`` → ``https://vault.azure.net/.default``):

  * the local **admin password** (rotated on a schedule — break-glass: after
    rotation it exists ONLY in the vault),
  * the config **Fernet key** (``LM_FERNET_KEY`` — needed to decrypt a backup),
  * rolling **min backups** (gzip+base64), keeping the most recent ``retain``
    daily copies. A min backup is NOT the full config (that's >25 KB — it lives in
    the real backup source) — it's just enough to bring a fresh hub back online:
    users/logins, the OIDC + Azure connection config, the OIDC cert/key, and the
    Fernet key. Restore it → the hub can auth to Azure and let admins log in →
    then restore the full backup from source.

The app registration needs the **Key Vault Secrets Officer** RBAC role (or a Set
secret access policy) on the vault. Key Vault secrets are capped at 25 KB, so a
min backup that exceeds that (many local users) is refused with a clear error.

Pure REST (no azure SDK). Errors carry the vault response body.
"""
from __future__ import annotations

import base64
import gzip
import logging
import secrets
import string
from typing import Any, Dict, List, Optional

import httpx

from security.oidc import OidcConfig, fetch_app_token

logger = logging.getLogger("KeyVault")

_SCOPE = "https://vault.azure.net/.default"
_API = "7.4"
_MAX_SECRET_BYTES = 25 * 1024  # Key Vault hard limit on secret value size


class KeyVaultError(Exception):
    """Raised for any Key Vault failure; message is safe to surface."""


def gen_password(n: int = 24) -> str:
    """Random password meeting complexity (all four classes), length ``n``."""
    lo, up, dg = string.ascii_lowercase, string.ascii_uppercase, string.digits
    sy = "!@#$%^&*()-_=+"
    n = max(12, n)
    pw = [secrets.choice(lo), secrets.choice(up), secrets.choice(dg), secrets.choice(sy)]
    allc = lo + up + dg + sy
    pw += [secrets.choice(allc) for _ in range(n - 4)]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)


def encode_config_secret(raw: bytes) -> str:
    """gzip + base64 the (already-encrypted) state bytes for a Key Vault secret;
    raise if the result exceeds the 25 KB secret limit."""
    blob = base64.b64encode(gzip.compress(raw)).decode()
    if len(blob) > _MAX_SECRET_BYTES:
        raise KeyVaultError(
            f"config backup is {len(blob)} bytes compressed — over Key Vault's "
            f"{_MAX_SECRET_BYTES}-byte secret limit; use Azure Blob Storage for backups")
    return blob


def decode_config_secret(blob: str) -> bytes:
    return gzip.decompress(base64.b64decode(blob))


def _base(vault_url: str) -> str:
    return str(vault_url or "").rstrip("/")


async def _token(cfg: OidcConfig, http: Optional[httpx.AsyncClient] = None) -> str:
    return await fetch_app_token(cfg, _SCOPE, http=http)


async def set_secret(cfg: OidcConfig, vault_url: str, name: str, value: str,
                     http: Optional[httpx.AsyncClient] = None) -> str:
    """PUT a secret (new version). Returns the secret id."""
    if not vault_url:
        raise KeyVaultError("Key Vault URL not configured")
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.put(url, headers={"Authorization": f"Bearer {token}",
                                         "Content-Type": "application/json"},
                           json={"value": value})
    if resp.status_code not in (200, 201):
        raise KeyVaultError(f"Key Vault PUT {name} failed: HTTP {resp.status_code} — {resp.text[:300]}")
    return resp.json().get("id", "")


async def get_secret(cfg: OidcConfig, vault_url: str, name: str,
                     http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        raise KeyVaultError(f"Key Vault GET {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return resp.json().get("value")


async def list_secret_names(cfg: OidcConfig, vault_url: str, prefix: str = "",
                            http: Optional[httpx.AsyncClient] = None) -> List[str]:
    """All secret names (optionally prefix-filtered), paged."""
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets?api-version={_API}"
    out: List[str] = []
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        while url:
            resp = await c.get(url, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                raise KeyVaultError(f"Key Vault list failed: HTTP {resp.status_code} — {resp.text[:200]}")
            body = resp.json()
            for item in body.get("value", []):
                sid = item.get("id", "")
                nm = sid.rsplit("/", 1)[-1]
                if nm and (not prefix or nm.startswith(prefix)):
                    out.append(nm)
            url = body.get("nextLink")
    return out


async def delete_secret(cfg: OidcConfig, vault_url: str, name: str,
                        http: Optional[httpx.AsyncClient] = None) -> bool:
    token = await _token(cfg, http=http)
    url = f"{_base(vault_url)}/secrets/{name}?api-version={_API}"
    async with (http or httpx.AsyncClient(timeout=20.0)) as c:
        resp = await c.delete(url, headers={"Authorization": f"Bearer {token}"})
    if resp.status_code not in (200, 204, 404):
        raise KeyVaultError(f"Key Vault DELETE {name} failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return True


async def test_connection(cfg: OidcConfig, vault_url: str,
                          http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """List secrets to confirm the token + RBAC + URL resolve. Returns a count."""
    names = await list_secret_names(cfg, vault_url, http=http)
    return {"ok": True, "secret_count": len(names)}
