"""Certificate distribution for the LM Hub (le → target spokes, hub-brokered)."""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import subprocess
import tempfile
import time

from sync_loop import run_sync_loop  # sibling leaf

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
    distribute_mtls_materials_to_all_spokes as _distribute_mtls_materials_impl,
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
        operator is still testing cert distribution.

        When ``mtls.auto_provision`` is ON and ``domain`` is a wildcard, ALSO
        fan the mTLS materials (CA + client cert/key) to every connected primary
        spoke + the hub (see _distribute_mtls_materials)."""
        explicit = await _distribute_cert_to_targets(
            self._inflight_rr(self.request_response), self._cert_target_spoke,
            self.CERT_CAPABLE_MODULES, le_spoke_id, domain, targets,
            install_on_hub=self._install_cert_on_hub)
        out = list(explicit or [])
        pushed_state = False
        if self._wildcard_all_spokes_enabled() and _is_wildcard(domain):
            wc = await _distribute_wildcard_to_all_spokes(
                self.request_response, self.get_all_spokes_by_type,
                self.CERT_CAPABLE_MODULES, le_spoke_id, domain, material_hash,
                self._wildcard_push_state(),
                install_on_hub=self._install_cert_on_hub)
            out += (wc or [])
            pushed_state = True
        if self._mtls_auto_provision_enabled() and _is_wildcard(domain):
            mtls = await self._distribute_mtls_materials(le_spoke_id, domain, material_hash)
            out += (mtls or [])
            pushed_state = True
        if pushed_state:
            self._save_wildcard_push_state()
        self._stash_cert_device_reports(out)
        return out

    async def _distribute_all_certs(self, le_spoke_id: str) -> list:
        """Distribute every managed cert whose targets are stale. Returns a
        flat per-target summary (see _distribute_all_certs_impl) so the
        /api/le/distribute route can show a per-target toast. Passes the
        wildcard fan-out params (gated by the hub flag — OFF by default →
        no-op while the operator is testing) and the mTLS-materials fan-out
        params (gated by ``mtls.auto_provision`` — OFF by default)."""
        out = await _distribute_all_certs_impl(
            self._inflight_rr(self.request_response), self._cert_target_spoke,
            self.CERT_CAPABLE_MODULES, le_spoke_id,
            install_on_hub=self._install_cert_on_hub,
            wildcard_enabled=self._wildcard_all_spokes_enabled(),
            get_all_by_type=self.get_all_spokes_by_type,
            push_state=self._wildcard_push_state(),
            mtls_auto_provision=self._mtls_auto_provision_enabled(),
            get_primary_spokes=self._get_primary_spokes,
            push=self.push_or_queue_to_spoke)
        self._save_wildcard_push_state()
        self._stash_cert_device_reports(out)
        return out

    async def _distribute_mtls_materials(self, le_spoke_id: str, domain: str,
                                         material_hash: Optional[str] = None) -> list:
        """Fan the LE wildcard's mTLS materials (CA + client cert/key) to every
        connected primary spoke + the hub. Thin wrapper over the pure helper
        (see _distribute_mtls_materials_impl) so the transport is unit-testable.
        Gated by ``mtls.auto_provision``; the caller checks the flag + wildcard
        domain, so this is a no-op unless auto-provision is on."""
        return await _distribute_mtls_materials_impl(
            self._inflight_rr(self.request_response),
            self.push_or_queue_to_spoke, self._get_primary_spokes,
            le_spoke_id, domain, material_hash,
            self._wildcard_push_state(),
            install_on_hub=self._install_cert_on_hub)

    def _get_primary_spokes(self) -> list:
        """Connected spokes that are PRIMARY transport endpoints — i.e. NOT
        role sub-spokes (which share their parent agent's process, .env, and
        cert dir; the parent's mTLS push covers them). Used by
        distribute_mtls_materials_to_all_spokes so a multi-role generic agent
        gets ONE push (to its base spoke_id), not one per loaded role (each of
        which would os._exit(3) the shared agent). Returns ``[(spoke_id,
        module_type)]``."""
        out = []
        for sid, mt in getattr(self, "spoke_module_types", {}).items():
            if sid in getattr(self, "active_connections", {}) and not getattr(
                    self, "spoke_parent_map", {}).get(sid):
                out.append((sid, mt))
        return out

    def _mtls_auto_provision_enabled(self) -> bool:
        """``global_config["mtls"]["auto_provision"]`` — the master switch for
        auto-deploying the LE wildcard + CA bundle to the hub + every primary
        spoke (and, in Phase B, auto-enabling mTLS once the fleet is ready).
        Default OFF; the operator turns it on from System → Hub Status."""
        gc = (self.state.get_global_config() or {}).get("mtls", {}) or {}
        return bool(gc.get("auto_provision", False))

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
        self._persist_cert_device_reports()

    def _cert_reports_path(self) -> str:
        import os as _os
        return _os.path.join(self.state.data_dir, "le", "cert_device_reports.json")

    def _persist_cert_device_reports(self) -> None:
        """Snapshot the per-device cert reports so the cert drill-down survives a
        restart instead of blanking until the hourly distribution loop repopulates."""
        try:
            from tenant_sharded import snapshot_save
            from security.encryption import hub_encryption
            snapshot_save(self._cert_reports_path(), self._cert_device_reports(),
                          encrypt=lambda s: hub_encryption.encrypt(s))
        except Exception:  # noqa: BLE001
            pass

    def warm_load_cert_device_reports(self) -> None:
        """Warm-start the per-device cert reports on boot (best-effort)."""
        try:
            from tenant_sharded import snapshot_load
            from security.encryption import hub_encryption
            data = snapshot_load(self._cert_reports_path(),
                                 decrypt=lambda b: hub_encryption.decrypt(b))
            if isinstance(data, dict):
                self.cert_device_reports = data
        except Exception:  # noqa: BLE001
            pass

    def cert_device_report(self, domain: str, module_type: str, identifier: str = "") -> Dict[str, Any]:
        return self._cert_device_reports().get(f"{domain}|{module_type}|{identifier}") or {}

    def update_cert_device_status(self, domain: str, module_type: str, identifier: str,
                                  device_id: str, result: Dict[str, Any]) -> None:
        """Merge a SINGLE device's install result into the stashed report (used by
        the per-device deploy button in the cert drill-down)."""
        import datetime as _dt
        store = self._cert_device_reports()
        rep = store.setdefault(f"{domain}|{module_type}|{identifier}",
                               {"devices": [], "message": "", "status": "", "at": ""})
        devs = rep.setdefault("devices", [])
        st = (result or {}).get("status", "")
        msg = (result or {}).get("message", "")
        for d in devs:
            if str(d.get("device_id")) == str(device_id):
                d["status"], d["message"] = st, msg
                break
        else:
            devs.append({"device_id": device_id, "status": st, "message": msg})
        rep["at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
        self._persist_cert_device_reports()

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
            self.state._mark_dirty()
        except Exception as e:  # never block distribution on a state-save
            cert_log.debug("wildcard push-state save failed: %s", e)

    async def _hub_self_write(self, path: str, content: str, mode: int = 0o600) -> bool:
        """Write a file ON THE HUB via the loopback hub-self agent's ``WRITE_FILE``
        primitive — the SAME primitive a spoke-side cert deploy uses — so the
        hub's own cert-install path is uniform with spoke deploys (agent-rework
        #5 / Phase 4). Falls back to a direct inline atomic write (identical to
        what the agent would have run) when the hub-self agent isn't connected:
        feature off (``LM_HUB_SELF_AGENT=0``), not booted yet, or the loopback
        listener died. Returns True iff the file landed."""
        hub_self = getattr(self, "_hub_self", None)
        if hub_self is not None:
            try:
                resp = await hub_self.write_file(path, content, mode=mode)
                if resp.get("status") == "SUCCESS" and (resp.get("result") or {}).get("ok"):
                    return True
                cert_log.debug("[cert] hub-self WRITE_FILE %s non-success → direct fallback (resp=%s)",
                               path, resp)
            except Exception as e:  # noqa: BLE001
                cert_log.debug("[cert] hub-self WRITE_FILE %s error → direct fallback: %s", path, e)
        # Direct fallback — the identical atomic write the in-process agent runs.
        try:
            self._atomic_write(path, content, mode)
            return True
        except Exception as e:  # noqa: BLE001
            cert_log.warning("[cert] direct write to %s failed: %s", path, e)
            return False

    async def _hub_self_restart(self) -> str:
        """Schedule ``lm-self-restart`` via the loopback hub-self agent's
        ``RUN_COMMAND`` — uniformity with spoke-side cert deploys. The command is
        backgrounded (``&``) so the agent responds BEFORE the restart kills the
        hub process (an awaited foreground restart would drop the WS mid-reply
        and the caller's ``send_to_agent`` would time out + double-restart on
        fallback). Falls back to a direct fire-and-forget ``subprocess.Popen`` if
        the hub-self agent isn't connected. Returns a status message."""
        hub_self = getattr(self, "_hub_self", None)
        if hub_self is not None:
            try:
                cmd = f"sudo -n {_LM_SELF_RESTART} >/dev/null 2>&1 &"
                resp = await hub_self.run_command(cmd, allow_shell=True, timeout=10.0)
                if resp.get("status") == "SUCCESS":
                    return "lm.service restarting to apply"
                cert_log.debug("[cert] hub-self RUN_COMMAND restart non-success → direct fallback (resp=%s)",
                               resp)
            except Exception as e:  # noqa: BLE001
                cert_log.debug("[cert] hub-self RUN_COMMAND restart error → direct fallback: %s", e)
        try:
            subprocess.Popen(["sudo", "-n", _LM_SELF_RESTART],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "lm.service restarting to apply"
        except Exception as e:
            return (f"cert written; could not schedule self-restart ({e}) — "
                    "restart lm.service manually")

    async def _install_cert_on_hub(self, domain: str, fullchain: str,
                                   privkey: str, chain: str,
                                   identifier: str = "", ca_only: bool = False) -> dict:
        """Install a cert on the HUB ITSELF (module_type == "hub" target).

        ``ca_only=True`` (the mTLS-materials fan-out): install ONLY the mTLS CA
        bundle so the hub can verify spoke client certs — the WILDCARD is never
        deployed as the hub's server cert (the hub keeps its own cert), and there
        is NO self-restart (the CA registers at runtime). This is the fix for the
        wildcard-on-hub self-restart loop.

        Writes fullchain → ``LM_TLS_CERT`` and privkey → ``LM_TLS_KEY`` (the
        paths the hub's uvicorn + WS TLS context already read at startup), then
        schedules ``lm-self-restart`` so the new cert is loaded. The cert is
        VALIDATED first (loaded into a throwaway ssl context) so a malformed
        cert can't brick the hub — uvicorn's ``ssl_certfile`` has no plaintext
        fallback at boot, unlike the WS context's try/except.

        Also writes the LE ``chain`` → ``<certdir>/mtls-ca.pem`` and registers it
        as the hub's ``LM_MTLS_CA`` (via the runtime registry + global_config),
        so the hub can verify spoke client certs once mTLS is enabled — the hub
        is the hub↔spoke server, so it needs the CA, not a client cert. Best-
        effort: a missing/empty chain leaves the existing CA untouched and the
        server-cert install still succeeds.

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
        # CA-bundle-only: the hub keeps its OWN server cert; write only the mTLS
        # CA bundle (next to LM_TLS_CERT) + register it at runtime. No wildcard
        # server-cert overwrite, no self-restart → this is what breaks the loop.
        if ca_only:
            if not (chain and "BEGIN CERTIFICATE" in chain):
                return {"status": "SUCCESS", "message": "no CA chain to install — hub unchanged"}
            ca_path = os.path.join(os.path.dirname(os.path.abspath(cert_path)), "mtls-ca.pem")
            # CA bundle file write via the loopback hub-self agent (WRITE_FILE) —
            # uniformity with spoke-side cert deploys — with a direct inline
            # atomic-write fallback. The runtime CA registration below is hub-
            # state (not a file-on-disk op), so it stays inline.
            if not await self._hub_self_write(ca_path, chain, 0o644):
                cert_log.warning("[mtls] %s → hub: CA bundle write to %s failed", domain, ca_path)
                return {"status": "ERROR", "message": f"CA bundle write to {ca_path} failed"}
            try:
                self._register_hub_mtls_ca(ca_path)
            except Exception as e:  # noqa: BLE001
                cert_log.warning("[mtls] %s → hub: CA register failed: %s", domain, e)
            cert_log.info("[mtls] %s → hub: CA bundle → %s (hub keeps its own cert; no restart)",
                          domain, ca_path)
            return {"status": "SUCCESS",
                    "message": f"mTLS CA bundle → {ca_path} (hub keeps its own cert)"}
        # The WILDCARD is NEVER the hub's own server cert. The hub keeps its own
        # (non-wildcard) cert; a wildcard reaching here via ANY path — explicit
        # "hub" target in distribute_cert_to_targets OR a fan-out — is a no-op for
        # the server cert (no LM_TLS_CERT overwrite, no self-restart). This is the
        # last-line guard that stops the restart loop regardless of caller.
        if _is_wildcard(domain):
            cert_log.info("[cert] %s → hub: SKIPPED — wildcard is not installed as the hub's "
                          "server cert (the hub keeps its own cert; no restart)", domain)
            return {"status": "SKIPPED",
                    "message": "wildcard not installed on the hub (hub keeps its own cert)"}
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

        # Atomic write via the loopback hub-self agent's WRITE_FILE — the SAME
        # primitive a spoke-side cert deploy uses (agent-rework #5 / Phase 4) —
        # with a direct inline atomic-write fallback when the hub-self agent
        # isn't connected. Cert 0644, key 0600 (temp + os.replace either way).
        ok_cert = await self._hub_self_write(cert_path, fullchain, 0o644)
        ok_key = await self._hub_self_write(key_path, privkey, 0o600)
        if not ok_cert or not ok_key:
            cert_log.warning("[cert] %s → hub: FAILED — write to %s/%s failed "
                              "(see cert log for detail)", domain, cert_path, key_path)
            return {"status": "ERROR",
                    "message": f"write to {cert_path}/{key_path} failed (see cert log)"}

        # Also write the LE chain → the mTLS CA bundle (LM_MTLS_CA) so the hub
        # can verify spoke client certs once mTLS is enabled. The hub is the
        # hub↔spoke SERVER (spokes dial it), so it needs the CA — NOT a client
        # cert. The path is by convention next to LM_TLS_CERT so the operator
        # never has to set LM_MTLS_CA by hand; the runtime registry (set below)
        # makes the readiness check see it immediately, no restart required.
        # A best-effort write: a missing/empty chain leaves the existing CA (if
        # any) untouched — the server cert install above still succeeds.
        ca_msg = ""
        if chain and "BEGIN CERTIFICATE" in chain:
            ca_path = os.path.join(os.path.dirname(os.path.abspath(cert_path)),
                                   "mtls-ca.pem")
            if await self._hub_self_write(ca_path, chain, 0o644):
                try:
                    self._register_hub_mtls_ca(ca_path)
                except Exception as e:  # noqa: BLE001
                    ca_msg = f"; CA bundle write OK but register FAILED ({e})"
                    cert_log.warning("[cert] %s → hub: CA register failed: %s", domain, e)
                else:
                    ca_msg = f"; CA bundle → {ca_path}"
                    cert_log.info("[cert] %s → hub: mTLS CA bundle installed on %s",
                                  domain, ca_path)
            else:
                ca_msg = "; CA bundle write FAILED"
                cert_log.warning("[cert] %s → hub: CA bundle write to %s failed",
                                 domain, ca_path)
        elif chain:
            cert_log.debug("[cert] %s → hub: chain present but not PEM — CA bundle not written", domain)

        # Schedule a non-blocking self-restart via the loopback hub-self agent's
        # RUN_COMMAND (uniformity with spoke-side cert deploys), backgrounded so
        # the agent responds before the restart kills the hub; direct fire-and-
        # forget subprocess.Popen fallback when the hub-self agent isn't
        # connected. uvicorn reloads the cert (and, if mTLS is on, arms client-
        # cert verification against the new CA — see api.build_server).
        restart_msg = await self._hub_self_restart()
        cert_log.info("[cert] %s → hub: installed on %s — %s", domain, cert_path, restart_msg)
        return {"status": "SUCCESS", "message": f"installed to {cert_path}{ca_msg}; {restart_msg}"}

    def _register_hub_mtls_ca(self, ca_path: str) -> None:
        """Register the hub's mTLS CA bundle path with the runtime registry AND
        persist it into ``global_config["mtls"]`` so a hub restart re-registers
        it (mirrors mtls.set_runtime_enabled). Best-effort persistence: a state
        save failure is logged but never blocks the cert install."""
        try:
            from security import mtls
            mtls.set_runtime_materials(ca=ca_path)
        except Exception as e:  # noqa: BLE001
            cert_log.warning("[cert] hub: mtls.set_runtime_materials failed: %s", e)
            return
        try:
            gc = (self.state.get_global_config() or {})
            mtls_cfg = gc.get("mtls", {}) or {}
            mtls_cfg["ca_path"] = ca_path
            gc["mtls"] = mtls_cfg
            # state.system_state["global_config"] is the persisted backing store
            # (see setup_admin.set_mtls_enable). Update both views + save.
            self.state.system_state["global_config"] = gc
            self.state._mark_dirty()
        except Exception as e:  # noqa: BLE001
            cert_log.debug("[cert] hub: persist mtls.ca_path failed: %s", e)

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
        async def _body():
            le_sid = self.get_spoke_by_type("certificates")
            if not le_sid:
                return
            await self._distribute_all_certs(le_sid)
            # Warm the Certificates page cache on the same cadence so a
            # hub restart / slow le spoke serves fresh-ish last-known data.
            await self._le_refresh_certs_cache(le_sid)
            # Phase B: when auto-provision is on, try to auto-enable mTLS
            # once the fleet is ready (hub + every connected primary spoke).
            await self._maybe_auto_enable_mtls()

        # stagger 60s: let the le spoke connect + reconcile its ledger. On
        # error the sleep is the SAME retry cadence (no shorter error sleep) —
        # unchanged from the inline loop.
        await run_sync_loop(stagger=60, body=_body,
                            delay=self._cert_distribution_retry_seconds,
                            error_label="cert-distribution loop failed",
                            error_delay=self._cert_distribution_retry_seconds)

    async def _le_refresh_certs_cache(self, le_sid: str) -> None:
        """Pull LE_LIST_CERTS from the le spoke → le_cache_set('certs'). Best-
        effort (a slow/offline spoke skips silently — the cache stays on
        last-known). Called from the distribution loop AND from the
        /api/le/issue + /api/le/renew routes after a (re)issue/deploy so the
        Certificates list + the cert-failure alert pull-branch see the new
        failed-issue entry / per-target last_status promptly (within the 60s
        alert tick) instead of waiting up to 1h for the next sweep."""
        try:
            rr = await self.request_response(le_sid, "LE_LIST_CERTS", {})
            certs = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else rr
            if isinstance(certs, dict) and str(certs.get("status", "SUCCESS")).upper() != "ERROR":
                await self.le_cache_set("certs", certs)
        except Exception as e:  # noqa: BLE001
            logger.debug("le cache refresh skipped: %s", e)

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
            # Event-driven auto-enable too — don't wait up to 1h after a renew.
            if self._mtls_auto_provision_enabled() and _is_wildcard(domain):
                await self._maybe_auto_enable_mtls()
        except Exception as e:
            logger.warning("[sync-error] LE_CERT_RENEWED distribution for %s "
                           "failed: %s", domain, e)

    async def _maybe_auto_enable_mtls(self) -> None:
        """Phase B: when ``mtls.auto_provision`` is ON and the fleet is ready
        (hub CA + server cert AND every connected primary spoke has its mTLS
        materials) but mTLS isn't enabled yet, flip it on — set
        ``global_config.mtls_enabled`` + ``mtls.set_runtime_enabled(True)``. No
        self-restart: the spoke/agent WS legs arm on their next reconnect, and
        enabling is SAFE because verification is PERMISSIVE (CERT_OPTIONAL, see
        api.build_server + mtls.server_verify_mode) — a peer with a cert is
        verified, a peer without one (every browser) falls back and still
        connects, so auto-enable can never lock the WebUI out. Idempotent: a
        no-op when auto-provision is off, mTLS is already on, or the fleet isn't
        ready. The readiness gate (hub + spokes) means this never orphans a
        spoke — the manual 409 guard and this auto path share _mtls_fleet_ready().

        This removes the human checkpoint the operator opted out of by turning
        auto-provision on; the auto_enabled_at timestamp is persisted for audit.
        """
        if not self._mtls_auto_provision_enabled():
            return
        try:
            from security import mtls as _mtls
        except Exception:  # noqa: BLE001
            return
        if _mtls.mtls_enabled():
            return
        if not await self._mtls_fleet_ready():
            return
        try:
            gc = self.state.system_state.get("global_config", {}) or {}
            gc["mtls_enabled"] = True
            import datetime as _dt
            (gc.setdefault("mtls", {}) or {})["auto_enabled_at"] = \
                _dt.datetime.now(_dt.timezone.utc).isoformat()
            self.state.system_state["global_config"] = gc
            await self.state.save_state_now()
            _mtls.set_runtime_enabled(True)
            # NO self-restart. mTLS applies to the spoke↔hub / agent↔spoke WS legs
            # (armed on the spokes' next reconnect); the browser-facing WebUI on the
            # unified :443 never requires client certs (api.build_server). The old
            # self-restart here didn't arm anything the WebUI serves and — because
            # mtls_enabled didn't reliably persist across the restart — re-fired
            # every distribution cycle, bouncing the hub every ~3 min. The runtime
            # flag is set now; a natural restart re-applies it from global_config.
            cert_log.info("[mtls] auto-provision: fleet ready — mTLS enabled "
                           "(spoke/agent legs arm on reconnect; no hub restart).")
        except Exception as e:  # noqa: BLE001
            cert_log.warning("[mtls] auto-provision: auto-enable failed: %s", e)

    async def _mtls_fleet_ready(self) -> bool:
        """True when the fleet is ready for mTLS (see mtls_readiness). Thin bool
        wrapper used by the auto-enable loop so it doesn't allocate the per-spoke
        breakdown dict."""
        return (await self.mtls_readiness())["ready"]

    async def mtls_readiness(self) -> dict:
        """Shared mTLS readiness computation (used by ``GET /setup/mtls-
        readiness`` via setup_admin and by the auto-enable loop). Returns the
        hub's material status + a per-connected-PRIMARY-spoke breakdown (queried
        via SPOKE_GET_MTLS_STATUS) + the auto_provision flag + blockers.

        ``ready`` = hub CA + server cert present AND every connected primary
        spoke has CA + client cert/key. Role sub-spokes are excluded (they share
        their parent agent's cert; the parent's dot covers them). A spoke that's
        mid-reconnect (no reply) is NOT ready — it must have the materials before
        mTLS is armed, else enabling would orphan it. An empty fleet is ready
        (mTLS on a hub with zero spokes can't orphan anyone)."""
        try:
            from security import mtls as _mtls
        except Exception:  # noqa: BLE001
            _mtls = None
        st = _mtls.status() if _mtls else {
            "enabled": False, "ca_present": False, "client_cert_present": False,
            "client_key_present": False, "server_cert_present": False,
            "ca_path": "", "client_cert_path": "", "client_key_path": "",
            "server_cert_path": ""}

        primary = self._get_primary_spokes()

        async def _query(sid):
            try:
                rr = await self.request_response(sid, "SPOKE_GET_MTLS_STATUS",
                                                {}, timeout=4.0)
                d = rr.get("payload", {}).get("data", rr) if isinstance(rr, dict) else {}
                if isinstance(d, dict) and d.get("status") == "SUCCESS" and isinstance(d.get("mtls"), dict):
                    return d["mtls"]
            except Exception:
                pass
            return None

        results = (await asyncio.gather(*[_query(sid) for sid, _ in primary])
                   if primary else [])
        # Friendly name per spoke: module_names defaults display_name to the sid
        # (UUID) when unnamed, so treat display_name===sid as unset and fall
        # through to the reported hostname before the UUID (same guard as the
        # WebUI spokes list). The UUID still rides as ``id`` for the hover title.
        _names = self.state.system_state.get("module_names", {}) or {}
        _meta_all = self.state.system_state.get("module_metadata", {}) or {}
        spoke_status = []
        spokes_ready = True
        for (sid, mt), mstat in zip(primary, results):
            online = isinstance(mstat, dict)
            ca = bool(mstat.get("ca_present")) if online else False
            cc = bool(mstat.get("client_cert_present")) if online else False
            ck = bool(mstat.get("client_key_present")) if online else False
            spoke_ready = online and ca and cc and ck
            spokes_ready = spokes_ready and spoke_ready
            _dn = _names.get(sid, sid)
            _name = _dn if (_dn and _dn != sid) else \
                ((_meta_all.get(sid, {}) or {}).get("hostname", "") or sid)
            spoke_status.append({
                "id": sid, "name": _name, "type": mt, "online": online,
                "ca_present": ca, "client_cert_present": cc,
                "client_key_present": ck, "ready": spoke_ready,
                "status": "ready" if spoke_ready
                          else ("offline" if not online else "missing materials"),
            })

        blockers = []
        if not st["ca_present"]:
            blockers.append("no CA bundle (LM_MTLS_CA) — distribute the LE wildcard chain")
        if not st["server_cert_present"]:
            blockers.append("hub server cert (LM_TLS_CERT) not present")
        if primary and not spokes_ready:
            not_ready = sum(1 for s in spoke_status if not s["ready"])
            blockers.append(f"{not_ready} connected spoke(s) missing mTLS materials")
        hub_ready = bool(st["ca_present"] and st["server_cert_present"])
        ready = hub_ready and (spokes_ready if primary else True)
        gc_mtls = ((self.state.get_global_config() or {}).get("mtls", {}) or {})
        return {"enabled": st["enabled"], "ready": ready,
                "auto_provision": bool(gc_mtls.get("auto_provision", False)),
                "status": st,
                "connected_spokes": len(primary), "spokes": spoke_status,
                "blockers": blockers}
