"""Generic Azure/OCI Vault credential-store dispatcher for the LM hub.

The single place that knows WHICH cloud vault backend is active, so no other
code has to branch on provider — ``site_ext.py`` / ``main.py`` (and anything
else that needs to resolve a ``kv:<name>`` reference or store a credential)
calls THIS module's ``resolve_ref`` / ``get_secret`` / ``set_secret`` /
``delete_secret`` / ``test_connection``, never ``key_vault.py`` or
``oci_vault.py`` directly.

Only ONE of {Azure Key Vault, OCI Vault} may be ``enabled`` at a time; that
exclusivity is enforced at config-save time by ``routes/key_vault.py`` /
``routes/oci_vault.py`` (via :func:`active_provider`, below) — this module is
a read-only dispatcher, it never writes config.

Scope note: this wraps ONLY the core secret-storage primitives that
``key_vault.py`` and ``oci_vault.py`` share (get/set/delete/resolve_ref/
test_connection) — it deliberately does NOT wrap ``key_vault.py``'s
Azure-only disaster-recovery scheduler (admin-password rotation, min-backup
bundles); that automation has no OCI equivalent and stays Azure-specific,
reached directly through ``key_vault.py``/``KeyVaultSchedulerMixin`` as
before. It also does NOT touch ``security.credential_store`` (the separate,
boot-time, env-var-driven Tier-1 mechanism used to resolve the Entra
client-cert key/Fernet key before ``global_config`` itself can be decrypted)
— that's out of scope for this "which vault does the hub use for its own
credentials" abstraction.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("CloudVault")

CATEGORY = "vault"
# The global_config keys each provider's "enabled" flag lives under.
_PROVIDER_KEYS = {"azure": "key_vault", "oci": "oci_vault"}


def active_provider(hub) -> Optional[str]:
    """``"azure"`` | ``"oci"`` | ``None`` — whichever cloud vault provider is
    currently enabled. If (e.g. due to a hand-edited ``global_config`` or a
    race) BOTH somehow end up enabled at once, ``"azure"`` wins
    deterministically and a warning is logged — this should never happen
    through the UI/API, which reject enabling one while the other is on."""
    gc = hub.state.system_state.get("global_config", {}) or {}
    az_on = bool((gc.get("key_vault", {}) or {}).get("enabled"))
    oc_on = bool((gc.get("oci_vault", {}) or {}).get("enabled"))
    if az_on and oc_on:
        logger.warning("both key_vault and oci_vault are enabled simultaneously — "
                       "this should be prevented at save time; defaulting to azure")
        return "azure"
    if az_on:
        return "azure"
    if oc_on:
        return "oci"
    return None


def other_provider_enabled(hub, provider: str) -> bool:
    """True if the OTHER vault provider (not ``provider``) is currently
    enabled — the exclusivity check each save-config route calls before
    accepting ``enabled=true``."""
    other = "oci" if provider == "azure" else "azure"
    gc = hub.state.system_state.get("global_config", {}) or {}
    key = _PROVIDER_KEYS[other]
    return bool((gc.get(key, {}) or {}).get("enabled"))


async def resolve_ref(hub, ref: Optional[str],
                      http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Resolve a ``kv:<name>`` (or inline-literal) secret reference against
    whichever cloud vault is currently enabled. ``None`` if no vault is
    enabled, the secret doesn't exist, or the lookup fails — callers decide
    how to degrade. Never raises."""
    provider = active_provider(hub)
    if provider == "azure":
        import key_vault
        return await key_vault.resolve_ref(hub, ref, http=http)
    if provider == "oci":
        import oci_vault
        return await oci_vault.resolve_ref(hub, ref, http=http)
    # No vault enabled: mirror both backends' "inline literal passthrough"
    # behavior so self-hosted / no-vault deployments keep working.
    if ref and not str(ref).startswith("kv:"):
        return str(ref)
    return None


async def get_secret(hub, name: str, http: Optional[httpx.AsyncClient] = None) -> Optional[str]:
    """Fetch a named secret from whichever cloud vault is currently enabled.
    ``None`` if no vault is enabled or the secret doesn't exist."""
    provider = active_provider(hub)
    if provider is None or not name:
        return None
    gc = hub.state.system_state.get("global_config", {}) or {}
    if provider == "azure":
        import key_vault
        from security.oidc import get_oidc_config
        vault_url = (gc.get("key_vault", {}) or {}).get("vault_url")
        if not vault_url:
            return None
        return await key_vault.get_secret(get_oidc_config(hub), vault_url, name, http=http)
    import oci_vault
    vcfg = dict(gc.get("oci_vault", {}) or {})
    return await oci_vault.get_secret(oci_vault.get_oci_config(hub), vcfg, name, http=http)


async def set_secret(hub, name: str, value: str, http: Optional[httpx.AsyncClient] = None,
                     *, confirm: bool = True, attempts: int = 8,
                     delay: float = 2.0) -> Any:
    """Store a named secret in whichever cloud vault is currently enabled.
    Raises if no vault is enabled (unlike the read-side helpers, a caller
    that explicitly asked to STORE a credential needs to know it didn't
    happen) or if the backend call itself fails.

    ``confirm`` (default on) re-reads the secret until it comes back, so the
    write is only reported successful once the value is actually READABLE.
    Cloud vaults are not read-your-writes: OCI returns CreateSecret 200 with
    the secret in ``CREATING`` and 404s the bundle until it goes ``ACTIVE``,
    and Azure can briefly 404 a freshly created (or soft-delete-recovered)
    secret while it propagates. Without this, "save a credential then use it"
    races — which is exactly what saving a token and immediately fetching
    does. Provider-agnostic on purpose: any backend added later inherits it.

    Best-effort: a confirmation timeout logs and returns the write result
    rather than raising, because the secret IS stored — only its visibility
    lagged, and failing the save would be more destructive than a slow read."""
    provider = active_provider(hub)
    if provider is None:
        raise RuntimeError("no cloud vault provider is enabled — cannot store credential")
    gc = hub.state.system_state.get("global_config", {}) or {}
    if provider == "azure":
        import key_vault
        from security.oidc import get_oidc_config
        vault_url = (gc.get("key_vault", {}) or {}).get("vault_url")
        if not vault_url:
            raise RuntimeError("Azure Key Vault enabled but 'vault_url' is not configured")
        result = await key_vault.set_secret(get_oidc_config(hub), vault_url, name, value, http=http)
    else:
        import oci_vault
        vcfg = dict(gc.get("oci_vault", {}) or {})
        result = await oci_vault.set_secret(oci_vault.get_oci_config(hub), vcfg, name, value,
                                            http=http)
    if confirm:
        await _confirm_readable(hub, name, attempts=attempts, delay=delay)
    return result


async def _confirm_readable(hub, name: str, *, attempts: int = 8,
                            delay: float = 2.0) -> bool:
    """Poll ``get_secret`` until the named secret reads back, or give up."""
    for i in range(attempts):
        try:
            if await get_secret(hub, name) is not None:
                return True
        except Exception:  # noqa: BLE001 — a transient backend error is a retry
            pass
        if i < attempts - 1:
            await asyncio.sleep(delay)
    logger.warning("cloud vault: secret %r stored but not readable after %.0fs — "
                   "an immediate read may fail until it propagates", name, attempts * delay)
    return False


async def delete_secret(hub, name: str, http: Optional[httpx.AsyncClient] = None) -> bool:
    """Delete a named secret from whichever cloud vault is currently enabled.
    ``True`` (no-op) if no vault is enabled or the name is empty — mirroring
    ``get_secret``'s "nothing to do" semantics rather than ``set_secret``'s
    "raise, caller asked to write" contract, since a delete of something
    that's already absent is the desired end state either way. Backend
    failures are swallowed (logged) and return ``False`` rather than
    raising, so a best-effort caller (e.g. ``cred_vault``'s metadata cleanup)
    can proceed regardless."""
    provider = active_provider(hub)
    if provider is None or not name:
        return True
    gc = hub.state.system_state.get("global_config", {}) or {}
    if provider == "azure":
        import key_vault
        from security.oidc import get_oidc_config
        vault_url = (gc.get("key_vault", {}) or {}).get("vault_url")
        if not vault_url:
            return True
        try:
            return await key_vault.delete_secret(get_oidc_config(hub), vault_url, name, http=http)
        except key_vault.KeyVaultError as e:
            logger.warning("Azure Key Vault delete_secret(%s) failed: %s", name, e)
            return False
    import oci_vault
    vcfg = dict(gc.get("oci_vault", {}) or {})
    try:
        return await oci_vault.delete_secret(oci_vault.get_oci_config(hub), vcfg, name, http=http)
    except oci_vault.OciVaultError as e:
        logger.warning("OCI Vault delete_secret(%s) failed: %s", name, e)
        return False


async def test_connection(hub, http: Optional[httpx.AsyncClient] = None) -> Dict[str, Any]:
    """Confirm connectivity to whichever cloud vault is currently enabled."""
    provider = active_provider(hub)
    if provider is None:
        return {"status": "SKIPPED", "message": "no cloud vault provider enabled"}
    gc = hub.state.system_state.get("global_config", {}) or {}
    if provider == "azure":
        import key_vault
        from security.oidc import get_oidc_config
        vault_url = (gc.get("key_vault", {}) or {}).get("vault_url")
        if not vault_url:
            return {"status": "SKIPPED", "message": "Azure Key Vault not configured"}
        return {"status": "SUCCESS", "provider": "azure",
                **await key_vault.test_connection(get_oidc_config(hub), vault_url, http=http)}
    import oci_vault
    vcfg = dict(gc.get("oci_vault", {}) or {})
    return {"status": "SUCCESS", "provider": "oci",
            **await oci_vault.test_connection(oci_vault.get_oci_config(hub), vcfg, http=http)}
