"""Certificate distribution for the LM Hub (le → target spokes, hub-brokered)."""

from __future__ import annotations

import asyncio
import logging

# Pure transport helpers live in cert_distribution.py (no heavy imports, so they
# are unit-testable without constructing a LabManagerHub, which pulls in at-rest
# encryption). The Hub methods _distribute_one_cert / _distribute_all_certs are
# thin wrappers passing self.request_response / self.get_spoke_by_type /
# self.CERT_CAPABLE_MODULES. See cert_distribution.py for the architecture.
from cert_distribution import (
    CERT_CAPABLE_MODULES as _CERT_CAPABLE_MODULES,
    distribute_cert_to_targets as _distribute_cert_to_targets,
    distribute_all_certs as _distribute_all_certs_impl,
)

logger = logging.getLogger("Hub")


class HubCertDistributionMixin:
    """Hub-brokered cert distribution: pull renewed material from the le spoke
    and push it to each cert's target spokes (opnsense today). Thin wrappers over
    the pure helpers in cert_distribution.py so the transport is unit-testable."""

    # ── Certificate distribution (le → target spokes, hub-brokered) ─────────────
    # Thin wrappers over the module-level pure helpers (see _distribute_* above)
    # so the transport logic is unit-testable without constructing a Hub.
    CERT_CAPABLE_MODULES = _CERT_CAPABLE_MODULES  # v1: opnsense (firewall)

    async def _distribute_one_cert(self, le_spoke_id: str, domain: str,
                                   targets: list) -> list:
        """Pull cert material for ``domain`` from le → INSTALL_CERT to each
        target spoke (resolved by module_type). See _distribute_cert_to_targets."""
        return await _distribute_cert_to_targets(
            self.request_response, self.get_spoke_by_type,
            self.CERT_CAPABLE_MODULES, le_spoke_id, domain, targets)

    async def _distribute_all_certs(self, le_spoke_id: str) -> None:
        """Distribute every managed cert whose targets are stale. See
        _distribute_all_certs_impl."""
        await _distribute_all_certs_impl(
            self.request_response, self.get_spoke_by_type,
            self.CERT_CAPABLE_MODULES, le_spoke_id)

    async def run_cert_distribution_loop(self):
        """Hourly: push renewed cert material from the le spoke to each cert's
        target spokes (hub-brokered transport). Also fired inline on
        /api/le/issue + /api/le/renew for immediate effect after a
        (re)issue. See _distribute_one_cert / _distribute_all_certs."""
        await asyncio.sleep(60)  # let the le spoke connect + reconcile its ledger
        while True:
            try:
                le_sid = self.get_spoke_by_type("certificates")
                if le_sid:
                    await self._distribute_all_certs(le_sid)
            except Exception as e:
                logger.warning("[sync-error] cert-distribution loop failed: %s", e)
            await asyncio.sleep(3600)  # hourly

    async def _on_le_cert_renewed(self, le_spoke_id: str, domain: str,
                                  targets: list) -> None:
        """Event-driven cert distribution: a le spoke renewed a cert and emitted
        ``LE_CERT_RENEWED``; re-push the material to its targets NOW instead of
        waiting up to 1h for run_cert_distribution_loop. Mirrors the inline
        /api/le/issue + /api/le/renew path (_distribute_one_cert). The hourly
        loop is the fallback if this races a disconnect."""
        try:
            summary = await self._distribute_one_cert(le_spoke_id, domain, targets)
            ok = sum(1 for s in (summary or []) if s.get("status") == "SUCCESS")
            logger.info("[cert] LE_CERT_RENEWED %s from %s: %d/%d target(s) pushed",
                        domain, le_spoke_id, ok, len(summary or []))
        except Exception as e:
            logger.warning("[sync-error] LE_CERT_RENEWED distribution for %s "
                           "failed: %s", domain, e)
