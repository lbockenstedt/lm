"""Generic Azure/OCI NSG dispatcher for the LM hub.

The single place that knows WHICH cloud NSG backend is active, so no other
code — routes, ``security.threat_monitor``, the WebUI — has to branch on
provider. Only ONE of {Azure NSG, OCI NSG} may be ``enabled`` at a time; that
exclusivity is enforced at config-save time by ``routes/azure_nsg.py`` /
``routes/oci_nsg.py`` (via :func:`active_provider`, below), NOT here — this
module is a read-only dispatcher, it never writes config.
"""
# Postpone evaluation of type hints so Optional[...] etc. are never evaluated at runtime.
from __future__ import annotations

# Standard-library logging for the "both providers enabled" warning.
import logging
# Type hints only; they document the hub/config shapes used below.
from typing import Any, Dict, Optional

# One named logger so cloud-NSG dispatcher messages can be filtered together.
logger = logging.getLogger("CloudNsg")

# Category name under which NSG-related settings/events are grouped elsewhere in the hub.
CATEGORY = "nsg"
# The global_config keys each provider's "enabled" flag lives under.
_PROVIDER_KEYS = {"azure": "azure_nsg", "oci": "oci_nsg"}


def active_provider(hub) -> Optional[str]:
    """``"azure"`` | ``"oci"`` | ``None`` — whichever cloud NSG provider is
    currently enabled. If (e.g. due to a hand-edited ``global_config`` or a
    race) BOTH somehow end up enabled at once, ``"azure"`` wins
    deterministically and a warning is logged — this should never happen
    through the UI/API, which reject enabling one while the other is on."""
    # Read the hub-wide settings; "or {}" protects against a stored None.
    gc = hub.state.system_state.get("global_config", {}) or {}
    # Is the Azure NSG integration switched on? bool() turns a missing flag into False.
    az_on = bool((gc.get("azure_nsg", {}) or {}).get("enabled"))
    # Is the OCI (Oracle Cloud) NSG integration switched on?
    oc_on = bool((gc.get("oci_nsg", {}) or {}).get("enabled"))
    # Both on should be impossible; warn loudly and pick Azure so behaviour stays predictable.
    if az_on and oc_on:
        logger.warning("both azure_nsg and oci_nsg are enabled simultaneously — "
                       "this should be prevented at save time; defaulting to azure")
        return "azure"
    # Only Azure is enabled.
    if az_on:
        return "azure"
    # Only OCI is enabled.
    if oc_on:
        return "oci"
    # Neither provider is enabled, so there is no active cloud NSG backend.
    return None


def other_provider_enabled(hub, provider: str) -> bool:
    """True if the OTHER NSG provider (not ``provider``) is currently
    enabled — the exclusivity check each save-config route calls before
    accepting ``enabled=true``."""
    # Work out which provider is "the other one" relative to the caller.
    other = "oci" if provider == "azure" else "azure"
    # Read the hub-wide settings; "or {}" protects against a stored None.
    gc = hub.state.system_state.get("global_config", {}) or {}
    # Map that provider to the global_config key that holds its settings.
    key = _PROVIDER_KEYS[other]
    # Report whether the other provider's "enabled" flag is set.
    return bool((gc.get(key, {}) or {}).get("enabled"))
