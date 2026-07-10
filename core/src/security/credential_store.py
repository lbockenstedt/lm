"""Pluggable credential/secrets store for the LM hub.

A single small abstraction over where secrets live — process environment today,
Azure Key Vault tomorrow — so callers (the Entra OIDC provider's cert private
key, the break-glass admin password hash) don't hard-code a source. The default
``EnvCredentialProvider`` reads ``os.environ`` and is always available; the
``KeyVaultCredentialProvider`` lazy-imports the Azure SDK and degrades to
"not ready" when the SDK or a vault URL is absent, so a hub without Key Vault
configured is unaffected (no hard dep, no crash).

Resolution helpers
------------------
* :func:`resolve_private_key_material` — used by ``security/oidc.py`` to load
  the Entra client-cert private key. Accepts a filesystem path (unchanged
  behaviour) OR a Key Vault reference (``kv:<secret-name>``) OR a bare secret
  name resolved through the active provider; returns the PEM bytes.
* :func:`resolve_password_hash` — used by ``routes/auth.py`` for the break-glass
  local login. Returns the stored ``password_hash`` when present, else the hash
  fetched from the store via the user's ``password_hash_ref`` (so the break-glass
  admin's hash can live in Key Vault instead of the state file). Additive: when
  no ``password_hash_ref`` is set, behaviour is identical to today.

The provider is selected once by :func:`get_credential_provider` (Key Vault when
configured + ready, otherwise env) and cached. ``LM_DEP_GUARD_DISABLE``-style
graceful failure everywhere: a missing SDK / unreachable vault logs and returns
``None``; it never raises, so OIDC / login fall back to their env / state paths.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional

logger = logging.getLogger("Creds")

# ── Azure SDK (optional, lazy) ───────────────────────────────────────────────
# Imported at module load so a single try/except sets availability; the names
# are only referenced inside KeyVaultCredentialProvider when _AZURE_AVAILABLE.
_AZURE_AVAILABLE = False
SecretClient = None  # type: ignore[assignment]
DefaultAzureCredential = None  # type: ignore[assignment]
try:  # pragma: no cover — exercised only on boxes with the SDK installed
    from azure.keyvault.secrets import SecretClient  # type: ignore[import]
    from azure.identity import DefaultAzureCredential  # type: ignore[import]
    _AZURE_AVAILABLE = True
except ImportError:
    # The Azure SDK is an OPTIONAL dep — not in requirements.txt (it's heavy and
    # most hubs use env secrets). A missing SDK simply means Key Vault isn't an
    # available source; env remains the default. See docs/deploy.
    logger.debug("azure-identity / azure-keyvault-secrets not installed — "
                 "Key Vault credential provider disabled (env-only).")


# ── Provider ABC ─────────────────────────────────────────────────────────────

class CredentialProvider:
    """A source of named secret material (env, Key Vault, …)."""

    name: str = "base"

    @property
    def ready(self) -> bool:
        """True when this provider can actually serve secrets."""
        return False

    def get_secret(self, name: str) -> Optional[str]:
        """Return the secret value for ``name``, or ``None`` if unavailable.

        Never raises: an unreachable backend / missing key returns ``None`` so
        callers fall back to their alternate source."""
        raise NotImplementedError


class EnvCredentialProvider(CredentialProvider):
    """Reads secrets from ``os.environ``. Always ready."""

    name = "env"

    @property
    def ready(self) -> bool:
        return True

    def get_secret(self, name: str) -> Optional[str]:
        if not name:
            return None
        val = os.environ.get(name)
        return val if val else None


class KeyVaultCredentialProvider(CredentialProvider):
    """Resolves secrets from Azure Key Vault.

    Configured via ``LM_KEYVAULT_URL`` (env) or
    ``global_config["credential_store"]["vault_url"]``. Optional
    ``LM_KEYVAULT_CLIENT_ID`` selects a user-assigned managed identity; absent
    → ``DefaultAzureCredential`` (managed identity / CLI / env chain).

    ``ready`` requires both a vault URL and the Azure SDK. ``get_secret`` is
    best-effort: any failure (network, auth, missing secret) logs + returns
    ``None``. Results are cached for ``_CACHE_TTL_S`` so a multi-step OIDC
    flow doesn't re-fetch the same key."""

    name = "keyvault"
    _CACHE_TTL_S = 300

    def __init__(self, vault_url: str, client_id: str = ""):
        self.vault_url = (vault_url or "").strip()
        self.client_id = (client_id or "").strip()
        self._client = None  # lazily constructed SecretClient
        self._cache: dict = {}  # name -> (fetched_at, value)

    @property
    def ready(self) -> bool:
        return bool(self.vault_url) and _AZURE_AVAILABLE

    def _client_obj(self):
        """Lazily build a SecretClient. Returns None if anything is missing."""
        if self._client is not None:
            return self._client
        if not self.ready:
            return None
        try:  # pragma: no cover — needs SDK + Azure auth
            if self.client_id:
                cred = DefaultAzureCredential(
                    managed_identity_client_id=self.client_id)
            else:
                cred = DefaultAzureCredential()
            self._client = SecretClient(vault_url=self.vault_url, credential=cred)
            return self._client
        except Exception as exc:  # noqa: BLE001 — never raise from a provider
            logger.warning("Key Vault client init failed for %s: %s",
                           self.vault_url, exc)
            return None

    def get_secret(self, name: str) -> Optional[str]:
        if not name or not self.ready:
            return None
        now = time.time()
        cached = self._cache.get(name)
        if cached and now - cached[0] < self._CACHE_TTL_S:
            return cached[1]
        client = self._client_obj()
        if client is None:
            return None
        try:  # pragma: no cover — needs live Azure
            secret = client.get_secret(name)
            value = getattr(secret, "value", None)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Key Vault fetch of %r failed: %s", name, exc)
            value = None
        self._cache[name] = (now, value)
        return value


# ── Factory ──────────────────────────────────────────────────────────────────

_provider_singleton: Optional[CredentialProvider] = None
_provider_key: tuple = ()


def get_credential_provider(stored: Optional[dict] = None) -> CredentialProvider:
    """Return the active credential provider (cached).

    Selects Key Vault when a vault URL is configured (env ``LM_KEYVAULT_URL``
    wins, then ``stored["credential_store"]["vault_url"]``) AND the Azure SDK
    is importable; otherwise the env provider. The result is cached by its
    config key so repeated calls don't rebuild the KV client."""
    global _provider_singleton, _provider_key
    stored = stored or {}
    cs_cfg = (stored.get("credential_store") or {}) if isinstance(stored, dict) else {}
    vault_url = (os.environ.get("LM_KEYVAULT_URL")
                 or (cs_cfg.get("vault_url") if isinstance(cs_cfg, dict) else "")
                 or "").strip()
    client_id = (os.environ.get("LM_KEYVAULT_CLIENT_ID")
                 or (cs_cfg.get("client_id") if isinstance(cs_cfg, dict) else "")
                 or "").strip()
    key = ("kv", vault_url, client_id)
    if vault_url and _AZURE_AVAILABLE:
        if _provider_singleton is None or _provider_key != key:
            _provider_singleton = KeyVaultCredentialProvider(vault_url, client_id)
            _provider_key = key
            logger.info("Credential provider: Key Vault (%s)", vault_url)
        return _provider_singleton
    # Env is the default and the fallback when KV isn't configured/available.
    key = ("env",)
    if _provider_singleton is None or _provider_key != key:
        _provider_singleton = EnvCredentialProvider()
        _provider_key = key
        logger.debug("Credential provider: env")
    return _provider_singleton


def reset_credential_provider() -> None:
    """Clear the cached provider (tests + config changes)."""
    global _provider_singleton, _provider_key
    _provider_singleton = None
    _provider_key = ()


# ── Resolution helpers ───────────────────────────────────────────────────────

_KV_PREFIX = "kv:"


def _looks_like_path(ref: str) -> bool:
    """Heuristic: a filesystem path (vs a secret name / ``kv:`` ref).

    A leading ``/``/``./``/``../``, a ``file:`` URI, or any ``/`` separator
    (Key Vault secret names don't contain ``/``) → a path."""
    if not ref:
        return False
    if ref.startswith(_KV_PREFIX):
        return False
    return ref.startswith(("/", "./", "../")) or ref.startswith("file:") or "/" in ref


def resolve_private_key_material(ref: str,
                                 provider: Optional[CredentialProvider] = None
                                 ) -> Optional[bytes]:
    """Load PEM private-key material for the Entra OIDC client cert.

    Accepts, in order of detection:
      * a ``kv:<secret-name>`` reference → fetched from the credential store;
      * a filesystem path (an existing file, or anything path-shaped —
        ``/…``, ``./…``, ``file:…``, or containing ``/``) → read from disk;
      * a bare secret name → the credential store.

    Returns the PEM bytes, or ``None`` if the material can't be resolved.
    Never raises. Backward compatible: a plain path (absolute or a relative
    ``key.pem`` in the cwd) still reads the file — an existing file is always
    treated as a path before the secret-name branch."""
    if not ref:
        return None
    prov = provider or get_credential_provider()
    # 1) Explicit Key Vault reference.
    if ref.startswith(_KV_PREFIX):
        name = ref[len(_KV_PREFIX):].strip()
        val = prov.get_secret(name)
        return val.encode("utf-8") if val else None
    # 2) Filesystem path — an existing file (any form) OR an explicit path
    #    shape. Checked before the secret branch so a relative "key.pem" that
    #    exists still reads (the historical key_path behaviour).
    if os.path.isfile(ref) or _looks_like_path(ref):
        try:
            with open(ref, "rb") as f:
                return f.read()
        except OSError as exc:
            logger.warning("could not read private key file %s: %s", ref, exc)
            return None
    # 3) Bare name → treat as a credential-store secret name.
    val = prov.get_secret(ref)
    return val.encode("utf-8") if val else None


def resolve_password_hash(user: dict,
                          provider: Optional[CredentialProvider] = None
                          ) -> Optional[str]:
    """Resolve the password hash to verify a break-glass local login against.

    Returns the user's stored ``password_hash`` when present; otherwise, if the
    record carries a ``password_hash_ref`` (a credential-store secret name),
    fetches the hash from the store. This lets the protected admin's hash live
    in Key Vault instead of the state file. Additive: no ``password_hash_ref``
    → identical to reading ``password_hash`` directly. Never raises."""
    if not isinstance(user, dict):
        return None
    stored_hash = user.get("password_hash")
    if stored_hash:
        return stored_hash
    ref = (user.get("password_hash_ref") or "").strip()
    if not ref:
        return None
    prov = provider or get_credential_provider()
    try:
        return prov.get_secret(ref) or None
    except Exception as exc:  # noqa: BLE001 — never break login over a store hiccup
        logger.warning("could not resolve password_hash_ref %r: %s", ref, exc)
        return None