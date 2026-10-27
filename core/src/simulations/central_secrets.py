"""Central API secrets live in the cloud vault when one is configured.

With a vault enabled (any provider) the stored ``central_config`` /
``central_on_prem_config`` keep only ``kv:<name>`` references for the secret
fields; without a vault the secrets stay inline in the Fernet-encrypted
simulations store, exactly as before.
"""
import logging
import re
from typing import Any, Dict

import cloud_vault

logger = logging.getLogger(__name__)

SECRET_FIELDS = ("client_secret", "access_token", "refresh_token")
_SLOT_LABELS = {"central_config": "central", "central_on_prem_config": "central-on-prem"}

# ref -> secret value. Avoids a vault round trip on every poll/browse, and keeps
# Central working through a brief vault outage. Filled on write and on read.
_resolved: Dict[str, str] = {}


def _vault_on(hub) -> bool:
    try:
        return bool(cloud_vault.active_provider(hub))
    except AttributeError:  # hub without state (e.g. a test double)
        return False


def secret_name(slot: str, tenant_id: str, field: str) -> str:
    raw = f"sim-{_SLOT_LABELS[slot]}-{tenant_id}-{field}"
    return re.sub(r"[^A-Za-z0-9-]", "-", raw)


async def to_vault(hub, slot: str, tenant_id: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``cfg`` with inline secrets stored in the vault and
    replaced by ``kv:`` references. Unchanged when no vault is configured.
    Raises if the vault write fails, so a secret is never silently dropped."""
    out = dict(cfg or {})
    if not _vault_on(hub):
        return out
    for field in SECRET_FIELDS:
        value = str(out.get(field) or "").strip()
        if not value or value.startswith("kv:"):
            continue
        name = secret_name(slot, tenant_id, field)
        await cloud_vault.set_secret(hub, name, value)
        ref = "kv:" + name
        _resolved[ref] = value
        out[field] = ref
    return out


async def resolve(hub, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``cfg`` with ``kv:`` references replaced by the real
    secrets. Only for code that actually talks to Central (or pushes creds to a
    spoke). An unresolvable reference becomes empty rather than being sent."""
    out = dict(cfg or {})
    for field in SECRET_FIELDS:
        ref = str(out.get(field) or "")
        if not ref.startswith("kv:"):
            continue
        value = await cloud_vault.resolve_ref(hub, ref)
        if value:
            _resolved[ref] = value
        else:
            value = _resolved.get(ref, "")
            logger.warning("Central secret %s could not be read from the vault", ref)
        out[field] = value
    return out


async def migrate_to_vault(hub, store) -> int:
    """Move existing inline Central secrets into the vault (no-op without one).
    Returns how many configs were updated."""
    if not _vault_on(hub):
        return 0
    moved = 0
    slots = (
        ("central_config", store.get_central_config, store.set_central_config),
        ("central_on_prem_config", store.get_central_on_prem_config,
         store.set_central_on_prem_config),
    )
    for tenant_id in store.tenant_ids():
        for slot, get_cfg, set_cfg in slots:
            try:
                cfg = await get_cfg(tenant_id)
                if not cfg:
                    continue
                new_cfg = await to_vault(hub, slot, tenant_id, cfg)
                if new_cfg != cfg:
                    await set_cfg(tenant_id, new_cfg)
                    moved += 1
                    logger.warning("Moved %s secrets for tenant %s into the vault", slot, tenant_id)
            except Exception as exc:  # noqa: BLE001 — one tenant never blocks the rest
                logger.warning("Could not move %s secrets for tenant %s into the vault: %s",
                               slot, tenant_id, exc)
    return moved
