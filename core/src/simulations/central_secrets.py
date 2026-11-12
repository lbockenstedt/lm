"""Central API secrets live in the cloud vault when one is configured.

With a vault enabled (any provider) the stored ``central_config`` /
``central_on_prem_config`` keep only ``kv:<name>`` references for the secret
fields; without a vault the secrets stay inline in the Fernet-encrypted
simulations store, exactly as before.
"""
# Standard-library logging for vault read/migration warnings.
import logging
# Regular expressions, used to sanitise generated vault secret names.
import re
# Clock for the cache age below (monotonic, so a wall-clock change cannot
# stretch it).
import time
# Type hints only; they document the config dictionaries passed around.
from typing import Any, Dict

# Cloud vault abstraction (Azure Key Vault, etc.) that actually stores and reads secrets.
import cloud_vault

# Module-level logger named after this module.
logger = logging.getLogger(__name__)

# The Central config fields that hold credentials and therefore belong in the vault.
SECRET_FIELDS = ("client_secret", "access_token", "refresh_token")
# Short labels per config slot, used to build readable, distinct vault secret names.
_SLOT_LABELS = {"central_config": "central", "central_on_prem_config": "central-on-prem"}

# ref -> secret value. Avoids a vault round trip on every poll/browse, and keeps
# Central working through a brief vault outage. Filled on write and on read.
_resolved: Dict[str, str] = {}
# ref -> when it was last read from (or written to) the vault. A cached value
# younger than _CACHE_S is used without asking the vault again.
_fetched: Dict[str, float] = {}
_CACHE_S = 900


def _vault_on(hub) -> bool:
    """Return True when the hub has an active cloud-vault provider configured."""
    try:
        # Any configured provider means secrets should be moved out of the local store.
        return bool(cloud_vault.active_provider(hub))
    except AttributeError:  # hub without state (e.g. a test double)
        return False


def secret_name(slot: str, tenant_id: str, field: str) -> str:
    """Build the vault secret name for one tenant's config slot and field."""
    # Combine slot label, tenant and field so each secret gets a unique, readable name.
    raw = f"sim-{_SLOT_LABELS[slot]}-{tenant_id}-{field}"
    # Vault names only allow letters, digits and dashes, so replace anything else with '-'.
    return re.sub(r"[^A-Za-z0-9-]", "-", raw)


async def to_vault(hub, slot: str, tenant_id: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``cfg`` with inline secrets stored in the vault and
    replaced by ``kv:`` references. Unchanged when no vault is configured.
    Raises if the vault write fails, so a secret is never silently dropped."""
    # Work on a copy so the caller's dict is never mutated.
    out = dict(cfg or {})
    # No vault configured: keep secrets inline, exactly as before.
    if not _vault_on(hub):
        return out
    # Visit each credential field that might need to move into the vault.
    for field in SECRET_FIELDS:
        # Normalise the value to a trimmed string (None becomes "").
        value = str(out.get(field) or "").strip()
        # Skip empty fields and fields that are already vault references.
        if not value or value.startswith("kv:"):
            continue
        # Write the secret to the vault; an exception propagates so nothing is silently lost.
        name = secret_name(slot, tenant_id, field)
        await cloud_vault.set_secret(hub, name, value)
        # Cache the value under its reference and replace the inline secret with the reference.
        ref = "kv:" + name
        _resolved[ref] = value
        _fetched[ref] = time.monotonic()
        out[field] = ref
    return out


async def resolve(hub, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``cfg`` with ``kv:`` references replaced by the real
    secrets. Only for code that actually talks to Central (or pushes creds to a
    spoke). An unresolvable reference becomes empty rather than being sent."""
    # Work on a copy so the stored (reference-only) config stays untouched.
    out = dict(cfg or {})
    # Look at each credential field and resolve the ones that are vault references.
    for field in SECRET_FIELDS:
        ref = str(out.get(field) or "")
        # Inline values (no "kv:" prefix) are already the real secret; leave them alone.
        if not ref.startswith("kv:"):
            continue
        # Recently read: use the cached value instead of another vault round trip.
        if _resolved.get(ref) and time.monotonic() - _fetched.get(ref, 0.0) < _CACHE_S:
            out[field] = _resolved[ref]
            continue
        # Ask the vault for the real value behind the reference.
        value = await cloud_vault.resolve_ref(hub, ref)
        # Success: remember it so later reads survive a short vault outage.
        if value:
            _resolved[ref] = value
            _fetched[ref] = time.monotonic()
        # Vault read failed: fall back to the last cached value (or empty) and warn.
        else:
            value = _resolved.get(ref, "")
            logger.warning("Central secret %s could not be read from the vault", ref)
        # Put the resolved (or fallback) secret into the returned config.
        out[field] = value
    return out


async def migrate_to_vault(hub, store) -> int:
    """Move existing inline Central secrets into the vault (no-op without one).
    Returns how many configs were updated."""
    # Nothing to migrate when there is no vault.
    if not _vault_on(hub):
        return 0
    # Count of configs actually rewritten, returned to the caller.
    moved = 0
    # Each Central config slot with its store getter and setter.
    slots = (
        ("central_config", store.get_central_config, store.set_central_config),
        ("central_on_prem_config", store.get_central_on_prem_config,
         store.set_central_on_prem_config),
    )
    # Walk every tenant and every Central config slot it may have.
    for tenant_id in store.tenant_ids():
        for slot, get_cfg, set_cfg in slots:
            try:
                # Load the stored config; tenants without one are skipped.
                cfg = await get_cfg(tenant_id)
                if not cfg:
                    continue
                # Move inline secrets into the vault; only save back when something changed.
                new_cfg = await to_vault(hub, slot, tenant_id, cfg)
                if new_cfg != cfg:
                    await set_cfg(tenant_id, new_cfg)
                    moved += 1
                    logger.warning("Moved %s secrets for tenant %s into the vault", slot, tenant_id)
            # A failure for one tenant/slot is logged so the other tenants still migrate.
            except Exception as exc:  # noqa: BLE001 — one tenant never blocks the rest
                logger.warning("Could not move %s secrets for tenant %s into the vault: %s",
                               slot, tenant_id, exc)
    return moved
