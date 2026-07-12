"""Certificate distribution for the LM Hub (le → target spokes, hub-brokered)."""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import subprocess
import tempfile

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
# Cert-distribution activity (the hub-brokered transport: per-target push
# outcomes, hub self-install) is logged to the "le.distribution" logger so it
# surfaces under WebUI Logs → Certificates (the hub routes le.* into the
# /setup/logs/le buffer). The module-level `logger` ("Hub") is kept for any
# non-cert hub lines. See cert_distribution.py for the architecture.
cert_log = logging.getLogger("le.distribution")

# Path to the sudoers-allowed hub self-restart helper (provisioned by
# install_all.sh). Schedules `systemctl restart lm` from a transient systemd
# unit owned by PID 1 — OUTSIDE lm.service's cgroup — so the restart command
# survives the hub being stopped and completes cleanly. Non-blocking (`sleep 3`
# inside the helper) so the caller's response can return first.
_LM_SELF_RESTART = "/usr/local/bin/lm-self-restart"


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
            self.CERT_CAPABLE_MODULES, le_spoke_id, domain, targets,
            install_on_hub=self._install_cert_on_hub)

    async def _distribute_all_certs(self, le_spoke_id: str) -> None:
        """Distribute every managed cert whose targets are stale. See
        _distribute_all_certs_impl."""
        await _distribute_all_certs_impl(
            self.request_response, self.get_spoke_by_type,
            self.CERT_CAPABLE_MODULES, le_spoke_id,
            install_on_hub=self._install_cert_on_hub)

    async def _install_cert_on_hub(self, domain: str, fullchain: str,
                                   privkey: str, chain: str,
                                   identifier: str = "") -> dict:
        """Install a cert on the HUB ITSELF (module_type == "hub" target).

        Writes fullchain → ``LM_TLS_CERT`` and privkey → ``LM_TLS_KEY`` (the
        paths the hub's uvicorn + WS TLS context already read at startup), then
        schedules ``lm-self-restart`` so the new cert is loaded. The cert is
        VALIDATED first (loaded into a throwaway ssl context) so a malformed
        cert can't brick the hub — uvicorn's ``ssl_certfile`` has no plaintext
        fallback at boot, unlike the WS context's try/except.

        Returns ``{"status", "message"}``. Best-effort restart: if the helper is
        missing or sudo denies, the cert is still written (next hub restart
        picks it up) and the message notes the restart didn't schedule.
        ``identifier`` is ignored (there's only one hub TLS endpoint)."""
        cert_path = os.environ.get("LM_TLS_CERT", "").strip()
        key_path = os.environ.get("LM_TLS_KEY", "").strip()
        if not cert_path or not key_path:
            cert_log.warning("[cert] %s → hub: FAILED — hub TLS paths not configured "
                              "(set LM_TLS_CERT + LM_TLS_KEY env on the hub, then restart "
                              "lm.service so they load)", domain)
            return {"status": "ERROR",
                    "message": "hub TLS paths not configured — set LM_TLS_CERT + "
                               "LM_TLS_KEY env on the hub to a writable location"}
        if not fullchain or not privkey:
            cert_log.warning("[cert] %s → hub: FAILED — missing cert material", domain)
            return {"status": "ERROR", "message": "missing cert material"}

        # Validate BEFORE touching the live paths: load_cert_chain into a
        # throwaway context. A bad cert here returns ERROR and leaves the
        # running hub's TLS untouched (so it stays up on its current cert).
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as cf:
                cf.write(fullchain)
                cf_path = cf.name
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as kf:
                kf.write(privkey)
                kf_path = kf.name
            try:
                ctx.load_cert_chain(cf_path, kf_path)
            finally:
                os.unlink(cf_path)
                os.unlink(kf_path)
        except Exception as e:
            cert_log.warning("[cert] %s → hub: FAILED — cert validation failed (not "
                              "written): %s", domain, e)
            return {"status": "ERROR",
                    "message": f"cert validation failed (not written): {e}"}

        # Atomic write (temp + os.replace). Key 0600, chain 0644.
        try:
            self._atomic_write(cert_path, fullchain, 0o644)
            self._atomic_write(key_path, privkey, 0o600)
        except Exception as e:
            cert_log.warning("[cert] %s → hub: FAILED — write to %s/%s failed: %s",
                              domain, cert_path, key_path, e)
            return {"status": "ERROR",
                    f"message": f"write to {cert_path}/{key_path} failed: {e}"}

        # Schedule a non-blocking self-restart so uvicorn reloads the cert.
        restart_msg = "lm.service restarting to apply"
        try:
            subprocess.Popen(["sudo", "-n", _LM_SELF_RESTART],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            restart_msg = f"cert written; could not schedule self-restart ({e}) — restart lm.service manually"
        cert_log.info("[cert] %s → hub: installed on %s — %s", domain, cert_path, restart_msg)
        return {"status": "SUCCESS", "message": f"installed to {cert_path}; {restart_msg}"}

    @staticmethod
    def _atomic_write(path: str, content: str, mode: int) -> None:
        """Write content to path atomically (temp in the same dir + os.replace)
        at the given mode. Same-dir temp is required for os.replace to stay on
        one filesystem (rename across filesystems raises EXDEV)."""
        d = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

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
