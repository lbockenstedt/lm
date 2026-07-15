"""Certificate distribution for the LM Hub (le → target spokes, hub-brokered)."""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import subprocess
import tempfile
import time

# Pure transport helpers live in cert_distribution.py (no heavy imports, so they
# are unit-testable without constructing a LabManagerHub, which pulls in at-rest
# encryption). The Hub methods _distribute_one_cert / _distribute_all_certs are
# thin wrappers passing self.request_response / self.get_spoke_by_type /
# self.CERT_CAPABLE_MODULES. See cert_distribution.py for the architecture.
from cert_distribution import (
    CERT_CAPABLE_MODULES as _CERT_CAPABLE_MODULES,
    _is_wildcard,
    distribute_cert_to_targets as _distribute_cert_to_targets,
    distribute_all_certs as _distribute_all_certs_impl,
    distribute_wildcard_to_all_spokes as _distribute_wildcard_to_all_spokes,
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
                                   targets: list,
                                   material_hash: Optional[str] = None) -> list:
        """Pull cert material for ``domain`` from le → INSTALL_CERT to each
        target spoke (resolved by module_type). See _distribute_cert_to_targets.

        When the hub's ``wildcard_all_spokes`` flag is ON and ``domain`` is a
        wildcard, ALSO fan the cert out to every connected cert-capable spoke
        (plus the hub). The flag is OFF by default so this is a no-op while the
        operator is still testing cert distribution."""
        explicit = await _distribute_cert_to_targets(
            self._inflight_rr(self.request_response), self._cert_target_spoke,
            self.CERT_CAPABLE_MODULES, le_spoke_id, domain, targets,
            install_on_hub=self._install_cert_on_hub)
        if self._wildcard_all_spokes_enabled() and _is_wildcard(domain):
            wc = await _distribute_wildcard_to_all_spokes(
                self.request_response, self.get_all_spokes_by_type,
                self.CERT_CAPABLE_MODULES, le_spoke_id, domain, material_hash,
                self._wildcard_push_state(),
                install_on_hub=self._install_cert_on_hub)
            self._save_wildcard_push_state()
            combined = (explicit or []) + (wc or [])
            self._stash_cert_device_reports(combined)
            return combined
        self._stash_cert_device_reports(explicit)
        return explicit

    async def _distribute_all_certs(self, le_spoke_id: str) -> list:
        """Distribute every managed cert whose targets are stale. Returns a
        flat per-target summary (see _distribute_all_certs_impl) so the
        /api/le/distribute route can show a per-target toast. Passes the
        wildcard fan-out params (gated by the hub flag — OFF by default →
        no-op while the operator is testing)."""
        out = await _distribute_all_certs_impl(
            self._inflight_rr(self.request_response), self._cert_target_spoke,
            self.CERT_CAPABLE_MODULES, le_spoke_id,
            install_on_hub=self._install_cert_on_hub,
            wildcard_enabled=self._wildcard_all_spokes_enabled(),
            get_all_by_type=self.get_all_spokes_by_type,
            push_state=self._wildcard_push_state())
        self._save_wildcard_push_state()
        self._stash_cert_device_reports(out)
        return out

    # ── per-device cert reports (fleet spokes: nw switch fleet) ──────────────
    # A fleet spoke (nw) installs the cert on N devices and returns a per-device
    # breakdown; stash it keyed by domain|module_type|identifier so the WebUI can
    # drill down from the spoke-level target into which switches got the cert.
    # In-memory (repopulated by the hourly distribution loop) — the target's
    # aggregate status/message still lives in the persistent le ledger.
    def _cert_device_reports(self) -> Dict[str, Dict[str, Any]]:
        d = getattr(self, "cert_device_reports", None)
        if d is None:
            d = {}
            self.cert_device_reports = d
        return d

    def _stash_cert_device_reports(self, summary: list) -> None:
        import datetime as _dt
        store = self._cert_device_reports()
        for e in (summary or []):
            if not isinstance(e, dict) or e.get("devices") is None:
                continue
            key = f"{e.get('domain','')}|{e.get('module_type','')}|{e.get('identifier','')}"
            store[key] = {"devices": e.get("devices"), "message": e.get("message", ""),
                          "status": e.get("status", ""),
                          "at": _dt.datetime.now(_dt.timezone.utc).isoformat()}

    def cert_device_report(self, domain: str, module_type: str, identifier: str = "") -> Dict[str, Any]:
        return self._cert_device_reports().get(f"{domain}|{module_type}|{identifier}") or {}

    # ── wildcard-all-spokes toggle (OFF by default; the operator's testing
    # gate). Lives in global_config["certs"]["wildcard_all_spokes"]. When ON, a
    # wildcard cert (``*.domain``) is fanned out to EVERY connected cert-capable
    # spoke + the hub, not just its explicit targets. See
    # distribute_wildcard_to_all_spokes in cert_distribution.py.
    def _wildcard_all_spokes_enabled(self) -> bool:
        gc = (self.state.get_global_config() or {}).get("certs", {}) or {}
        return bool(gc.get("wildcard_all_spokes", False))

    def _cert_distribution_retry_seconds(self) -> float:
        """Configurable cadence for ``run_cert_distribution_loop``, in seconds.
        Reads ``global_config["certs"]["distribution_retry_hours"]`` (default 1h,
        matching the prior hard-coded 3600s). A target whose last push FAILED is
        never skipped (the le-ledger skip-check requires ``last_status ==
        "SUCCESS"``, see cert_distribution.distribute_cert_to_targets), so it is
        re-pushed on every sweep — this knob sets how soon that retry happens.
        Clamp to >= 60s so a typo can't turn the loop into a tight retry storm;
        a non-numeric/missing/zero/negative value falls back to the 1h default."""
        gc = (self.state.get_global_config() or {}).get("certs", {}) or {}
        try:
            hours = float(gc.get("distribution_retry_hours", 1))
        except (TypeError, ValueError):
            return 3600.0
        if hours <= 0:
            return 3600.0
        return max(hours * 3600.0, 60.0)

    # ── in-flight distribution tracking (yellow target badge + live timer) ───
    # While the hub is awaiting an INSTALL_CERT confirmation, the target is
    # "in flight". We can't predict how fast a cert will transfer or install
    # (the hypervisor path's pveproxy restart can take many minutes), so the
    # WebUI surfaces in-flight targets as yellow badges with an elapsed timer
    # (fetched from /api/le/inflight) instead of showing only the stale
    # last_status. Tracked hub-side (where the loop lives) and keyed by
    # domain|module_type|identifier — the same identity the le ledger uses.
    def _cert_inflight(self) -> Dict[str, Dict[str, Any]]:
        d = getattr(self, "cert_dist_inflight", None)
        if d is None:
            d = {}
            self.cert_dist_inflight = d
        return d

    def _inflight_rr(self, rr):
        """Wrap ``request_response`` so an in-flight INSTALL_CERT is recorded
        for the WebUI. The pure helpers call ``rr(target_sid, "INSTALL_CERT",
        {domain, module_type, identifier, ...})``; we record the target before
        the await and clear it in a finally so the badge transitions the moment
        the push returns (SUCCESS or ERROR). Non-INSTALL_CERT rr calls
        (LE_GET_CERT / LE_MARK_DISTRIBUTED) pass through untouched."""
        hub = self

        async def _wrapped(spoke_id, command, data=None, timeout=None):
            if command == "INSTALL_CERT" and isinstance(data, dict):
                key = f"{data.get('domain', '')}|{data.get('module_type', '')}|{data.get('identifier', '')}"
                hub._cert_inflight()[key] = {
                    "domain": data.get("domain", ""),
                    "module_type": data.get("module_type", ""),
                    "identifier": data.get("identifier", ""),
                    "since": time.time(),
                }
                try:
                    return await rr(spoke_id, command, data, timeout=timeout)
                finally:
                    hub._cert_inflight().pop(key, None)
            return await rr(spoke_id, command, data, timeout=timeout)
        return _wrapped

    def _wildcard_push_state(self) -> Dict[str, str]:
        """Persistent ``{f"{domain}|{spoke_id}": material_hash}`` so the hourly
        loop doesn't re-push a wildcard to spokes that already have the current
        material. Stored in system_state (saved via _save_wildcard_push_state)."""
        return self.state.system_state.setdefault("wildcard_push_state", {})

    def _save_wildcard_push_state(self) -> None:
        try:
            self.state.save_state()
        except Exception as e:  # never block distribution on a state-save
            cert_log.debug("wildcard push-state save failed: %s", e)

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
        """Periodic: push renewed cert material from the le spoke to each cert's
        target spokes (hub-brokered transport). Failed targets are retried every
        sweep — the cadence is configurable via
        ``global_config["certs"]["distribution_retry_hours"]`` (default 1h). Also
        fired inline on /api/le/issue + /api/le/renew for immediate effect after
        a (re)issue. See _distribute_one_cert / _distribute_all_certs."""
        await asyncio.sleep(60)  # let the le spoke connect + reconcile its ledger
        while True:
            try:
                le_sid = self.get_spoke_by_type("certificates")
                if le_sid:
                    await self._distribute_all_certs(le_sid)
            except Exception as e:
                logger.warning("[sync-error] cert-distribution loop failed: %s", e)
            await asyncio.sleep(self._cert_distribution_retry_seconds())

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
