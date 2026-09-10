"""Generic Azure/OCI NSG dispatcher for the LM hub.

The single place that knows WHICH cloud NSG backend is active, so no other
code — routes, ``security.threat_monitor``, the WebUI — has to branch on
provider. Only ONE of {Azure NSG, OCI NSG} may be ``enabled`` at a time; that
exclusivity is enforced at config-save time by ``routes/azure_nsg.py`` /
``routes/oci_nsg.py`` (via :func:`active_provider`, below), NOT here — this
module is a read-only dispatcher, it never writes config.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("CloudNsg")

CATEGORY = "nsg"
# The global_config keys each provider's "enabled" flag lives under.
_PROVIDER_KEYS = {"azure": "azure_nsg", "oci": "oci_nsg"}


def active_provider(hub) -> Optional[str]:
    """``"azure"`` | ``"oci"`` | ``None`` — whichever cloud NSG provider is
    currently enabled. If (e.g. due to a hand-edited ``global_config`` or a
    race) BOTH somehow end up enabled at once, ``"azure"`` wins
    deterministically and a warning is logged — this should never happen
    through the UI/API, which reject enabling one while the other is on."""
    gc = hub.state.system_state.get("global_config", {}) or {}
    az_on = bool((gc.get("azure_nsg", {}) or {}).get("enabled"))
    oc_on = bool((gc.get("oci_nsg", {}) or {}).get("enabled"))
    if az_on and oc_on:
        logger.warning("both azure_nsg and oci_nsg are enabled simultaneously — "
                       "this should be prevented at save time; defaulting to azure")
        return "azure"
    if az_on:
        return "azure"
    if oc_on:
        return "oci"
    return None


def other_provider_enabled(hub, provider: str) -> bool:
    """True if the OTHER NSG provider (not ``provider``) is currently
    enabled — the exclusivity check each save-config route calls before
    accepting ``enabled=true``."""
    other = "oci" if provider == "azure" else "azure"
    gc = hub.state.system_state.get("global_config", {}) or {}
    key = _PROVIDER_KEYS[other]
    return bool((gc.get(key, {}) or {}).get("enabled"))
