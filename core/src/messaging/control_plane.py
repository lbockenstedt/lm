import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
import subprocess
import threading
import queue
import os
import socket
import ssl
from typing import Dict, Any, Type
from .protocol import Message, MessageHeader, MessagePayload
from ..security.signer import MessageSigner

try:  # shared helper (lm/core/src); falls back if imported off a stale path
    from logging_setup import set_log_level
except ImportError:
    def set_log_level(enabled):
        level = logging.DEBUG if enabled else logging.INFO
        logging.getLogger().setLevel(level)
        for name in list(logging.root.manager.loggerDict):
            logging.getLogger(name).setLevel(level)
        return level

logger = logging.getLogger("BaseControlPlane")


class _SpokeLogRelayHandler(logging.Handler):
    """Captures ALL log records (INFO+) into a queue for async relay to the Hub.

    Forwards every level the root logger emits (not just WARNING/ERROR) so the
    Hub WebUI Logs view and BugFixer's GET_LOGS see the spoke's full trail —
    including the INFO lines around a connect/handshake and the last line before
    a process exit, which previously never reached the Hub because only
    WARNING+ was relayed. The root logger's effective level still gates what is
    actually produced; this handler simply does not further filter.
    """

    def __init__(self, log_queue: queue.Queue):
        super().__init__(level=logging.DEBUG)
        self._queue = log_queue

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{record.levelname}] {record.name}: {self.format(record)}"
            self._queue.put_nowait(entry)
        except Exception:
            pass


class BaseControlPlane:
    """
    Generic Control Plane for Lab Manager Spokes.
    Handles Hub connectivity, mutual authentication, and module routing.
    """
    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None, hub_url: str = None,
                 onboarding_psk: str = None, tenant_id_hint: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        # Fall back to persisted value from .env if no hub_secret was passed at startup
        _hs = hub_secret or os.environ.get("HUB_SECRET", "")
        self.hub_secrets = [_hs] if _hs else []
        self.hub_url = hub_url
        # PSK self-provisioning: a spoke deployed with the tenant's predefined
        # onboarding PSK (+ a tenant_id_hint) presents both in the WS auth frame
        # so the hub can auto-approve + auto-bind it to that tenant without an
        # admin (mirrors the legacy cs/webui-local /api/spokes/register flow).
        # Optional everywhere — a spoke without these env vars sends neither
        # field and connects exactly as before. The PSK is a deploy secret; it
        # transits the WS but is never logged and is never persisted by the hub.
        self.onboarding_psk = (onboarding_psk or os.environ.get("LM_ONBOARDING_PSK", "")).strip()
        self.tenant_id_hint = (tenant_id_hint or os.environ.get("LM_TENANT_ID_HINT", "")).strip()
        self.modules: Dict[str, Any] = {} # { module_name: BaseSpoke instance }
        self.signer = MessageSigner(secret) if secret else None
        # Subclasses set this to a logical type string (e.g. "hypervisor", "firewall")
        # so the hub can route by capability instead of by spoke ID prefix.
        self.module_type: str = None
        # Updater worker state
        self._updater_stop = threading.Event()
        self._updater_thread = None
        # Log relay: ALL captured log entries (INFO+) are queued here and flushed
        # to the hub every few seconds by _log_relay_task, plus a final flush is
        # attempted before a self-update restart so the spoke's last lines reach
        # the hub even when it is about to die.
        self._log_relay_queue: queue.Queue = queue.Queue(maxsize=500)
        self._log_relay_handler = _SpokeLogRelayHandler(self._log_relay_queue)
        logging.getLogger().addHandler(self._log_relay_handler)
        # Active hub websocket — set while connected so subclasses can relay messages up.
        self._hub_ws = None
        # Event loop running _connect_and_serve; captured so the updater thread (a
        # separate thread) can schedule a final synchronous log flush via
        # run_coroutine_threadsafe before os._exit(0).
        self._loop = None
        # Suppress repeated "Hub secrets not configured" warnings — only warn once per process.
        self._hub_secret_warned = False
        # Current OS hostname + a stable install UUID reported on every connect so
        # the hub can detect a clone-and-rename (same UUID, new id/hostname) and
        # carry over approval/tenant binding instead of treating it as a stranger.
        # The UUID is generated at FIRST START (not install) and persisted to .env
        # below; prep-for-imaging strips it so a cloned image mints a fresh one.
        self.hostname = socket.gethostname()
        self.install_uuid = self._ensure_install_uuid()
        # TLS trust for wss:// connects. Verification is OFF by default (the hub
        # presents a self-signed cert) — encryption without authentication, which
        # is the lab default. Set LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT=<path> to
        # verify the hub cert against a shipped CA. See _client_ssl_ctx.
        self._tls_verify = os.environ.get("LM_HUB_TLS_VERIFY", "0").strip() in ("1", "true", "yes")
        self._tls_ca_cert = os.environ.get("LM_HUB_CA_CERT", "").strip()


    # ------------------------------------------------------------------
    # Self-update helpers (shared by all spokes)
    # ------------------------------------------------------------------

    def _repo_root(self) -> str:
        cwd = os.path.abspath(os.getcwd())
        return os.path.dirname(cwd) if cwd.endswith("src") else cwd

    def _ensure_git_pull_strategy(self, cwd: str) -> None:
        subprocess.run(["git", "config", "pull.rebase", "true"], cwd=cwd, check=False)
        subprocess.run(["git", "config", "rebase.autoStash", "true"], cwd=cwd, check=False)

    def _run_git(self, args, cwd: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git"] + args, cwd=cwd, text=True, capture_output=True, check=False)

    def _prepare_service_restart(self, reason: str = "update") -> bool:
        """Signal that this spoke should restart to load new code.

        Returns True; the caller MUST then flush queued log entries and
        ``os._exit(3)``. We deliberately do NOT ``systemctl restart`` ourselves
        anymore. That client ran inside this spoke's own systemd cgroup, so
        systemd's restart stop-phase (``KillMode=control-group``, the default)
        SIGTERMed the whole cgroup and killed the ``systemctl`` child
        mid-transaction — before its start-phase committed. The unit then
        deactivated with ``code=killed, signal=TERM``, which
        ``Restart=on-failure`` treats as a clean stop and does NOT revive,
        stranding the spoke "offline / never connected" — the recurring
        outage this fixes. (``start_new_session=True`` would not have helped:
        it changes session/pgid, not cgroup membership, so the cgroup kill
        still reached the child.)

        Instead the caller exits with a non-zero status (3). systemd sees a
        *failure* exit, so ``Restart=on-failure`` — which every spoke unit is
        configured with — reliably relaunches us after ``RestartSec``. No
        subprocess is left in the cgroup, so there is no race and no sudo
        dependency. The cost is a ``RestartSec`` delay (acceptable for an
        update); the benefit is the spoke always comes back.
        """
        svc = self.get_service_name()
        logger.info(
            "Reloading %s to apply new code (reason: %s); exiting so systemd "
            "Restart=on-failure relaunches it.", svc, reason,
        )
        return True

    # ------------------------------------------------------------------
    # Failed-update rollback (shared by all spokes — cs + pxmx)
    # ------------------------------------------------------------------
    # Mirrors the hub's update_recovery state machine: snapshot the code before
    # the swap, write a pending-update manifest, schedule an EXTERNAL health-gate
    # watchdog (lm-component-update-restart), and exit. The watchdog runs outside
    # our cgroup (via systemd-run), waits for a ``healthy`` marker to re-appear,
    # and if the new code crashes at boot (no marker within the deadline, or a
    # systemd crash-loop) rolls back — ``git reset --hard <from_commit>`` for a
    # spoke (a git repo) — marks the commit bad, and restarts us. Without it a
    # bad update crash-loops forever under Restart=always.
    #
    # State lives in a per-spoke dir (/var/lib/lm/<spoke_id>/) separate from the
    # hub's /var/lib/lm/state so a co-located cs box never collides. The watchdog
    # script + sudoers land only on a full installer re-run (bootstrap caveat:
    # auto-update pulls code but not install-script/systemd changes); until then
    # the watchdog Popen fails silently and we degrade to the pre-rollback
    # behavior (restart, no rollback) — never fatal.

    def _spoke_state_dir(self) -> str:
        """Per-spoke recovery state dir (``/var/lib/lm/<spoke_id>/``)."""
        return os.path.join("/var/lib/lm", self.spoke_id)

    def _clear_healthy_marker(self) -> None:
        """Drop a stale ``healthy`` marker on boot so a fresh start must re-prove
        health (the watchdog treats the marker as the positive health signal)."""
        try:
            m = os.path.join(self._spoke_state_dir(), "healthy")
            if os.path.exists(m):
                os.remove(m)
        except Exception:  # pragma: no cover - state dir not writable / missing
            pass

    def _touch_healthy_marker(self) -> None:
        """Mark the spoke healthy after the hub mutual-auth succeeds — the
        watchdog's positive health signal (presence => new code booted + authed)."""
        try:
            d = self._spoke_state_dir()
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "healthy"), "w").close()
        except Exception as e:  # pragma: no cover - state dir not writable
            logger.debug("could not write healthy marker: %s", e)

    def _snapshot_for_update(self, head_before: str, repo_root: str):
        """Pre-swap code snapshot (belt-and-suspenders — ``git reset --hard`` is
        the primary rollback for a git repo). Returns the backup dir or None."""
        try:
            from update_recovery import snapshot_code
            ts = time.strftime("%Y%m%d-%H%M%S")
            return snapshot_code(repo_root, ts, tree_list=["src"],
                                 state_dir=self._spoke_state_dir())
        except Exception as e:
            logger.warning("Pre-update snapshot failed (rollback disabled): %s", e)
            return None

    def _is_known_bad_commit(self, commit: str) -> bool:
        """True if ``commit`` was rolled back before (skip re-pulling it)."""
        if not commit:
            return False
        try:
            from update_recovery import is_bad_commit
            return bool(is_bad_commit(commit, state_dir=self._spoke_state_dir()))
        except Exception:  # pragma: no cover - update_recovery unavailable
            return False

    def _clear_pending_update(self) -> None:
        try:
            from update_recovery import clear_pending
            clear_pending(state_dir=self._spoke_state_dir())
        except Exception:  # pragma: no cover
            pass

    def _prepare_restart_with_watchdog(self, head_before: str, head_after: str,
                                       backup_dir, repo_root: str,
                                       reason: str = "update",
                                       deadline: int = 90) -> bool:
        """Write the pending-update manifest, schedule the external health-gate
        watchdog, and signal a service restart. Returns True; the caller MUST
        then flush queued logs (sync or async per its context) and
        ``os._exit(3)``. Best-effort watchdog: a missing script / no sudoers
        (pre-reinstall box) fails silently — we still restart via os._exit(3)
        with no rollback, exactly the pre-rollback behavior."""
        state_dir = self._spoke_state_dir()
        service_unit = self.get_service_name()
        recovery_py = None
        try:
            from update_recovery import write_pending
            import update_recovery as _ur
            recovery_py = getattr(_ur, "__file__", None)
            ts = time.strftime("%Y%m%d-%H%M%S")
            write_pending(backup_dir or "", from_version=(head_before or "")[:12],
                          to_version=(head_after or "")[:12], ts=ts,
                          state_dir=state_dir,
                          extra={"from_commit": head_before, "to_commit": head_after,
                                 "service_unit": service_unit, "deadline": deadline})
        except Exception as e:
            logger.warning("write_pending failed (rollback disabled): %s", e)
        try:
            cmd = ["sudo", "-n", "/usr/local/bin/lm-component-update-restart",
                   "--unit", service_unit, "--state-dir", state_dir,
                   "--repo-root", repo_root, "--deadline", str(deadline)]
            if recovery_py:
                cmd += ["--recovery-py", recovery_py]
            subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception as e:  # pragma: no cover - sudo missing / not permitted
            logger.debug("could not schedule update watchdog: %s", e)
        return self._prepare_service_restart(reason=reason)

    def perform_self_update_check(self) -> bool:
        try:
            cwd = self._repo_root()
            self._ensure_git_pull_strategy(cwd)
            fetch = self._run_git(["fetch", "origin"], cwd=cwd)
            if fetch.returncode != 0:
                logger.warning("Self-update check failed: git fetch error: %s", (fetch.stderr or "").strip())
                return False
            branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
            branch_name = (branch.stdout or "").strip()
            upstream = f"origin/{branch_name}" if branch_name and branch_name != "HEAD" else "origin/HEAD"
            behind = self._run_git(["rev-list", "--count", f"HEAD..{upstream}"], cwd=cwd)
            try:
                behind_count = int((behind.stdout or "0").strip() or "0")
            except ValueError:
                behind_count = 0
            if behind_count <= 0:
                logger.debug("Self-update check: already up to date.")
                return False
            # Snapshot the current code + capture HEAD BEFORE the pull so the
            # external watchdog can roll back (git reset --hard head_before) if
            # the new code crashes at boot. belt-and-suspenders: the file snapshot
            # of src/ is the fallback if the working tree is dirty/broken.
            head_before = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()
            backup_dir = self._snapshot_for_update(head_before, cwd)
            logger.info("Self-update check: %d new commit(s) upstream; pulling.", behind_count)
            pull = self._run_git(["pull", "--rebase", "--autostash", "origin"], cwd=cwd)
            if pull.returncode != 0:
                logger.warning("Self-update check failed: git pull error: %s", (pull.stderr or pull.stdout or "").strip())
                return False
            logger.info("Self-update check: pull completed successfully.")
            head_after = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()
            if head_after == head_before:
                logger.debug("Self-update: no change after pull.")
                return False
            # Skip a known-bad commit (rolled back before): reset to head_before
            # and stay put rather than crash-looping into the same broken code.
            if self._is_known_bad_commit(head_after):
                logger.warning(
                    "Self-update: new HEAD %s is a known-bad commit (rolled back "
                    "before); resetting to %s and skipping this update.",
                    head_after[:8], head_before[:8])
                self._run_git(["reset", "--hard", head_before], cwd=cwd)
                self._clear_pending_update()
                return False
            # Re-install requirements so new deps are available before restart
            req_file = os.path.join(cwd, "requirements.txt")
            venv_pip = os.path.join(cwd, "venv", "bin", "pip")
            if os.path.exists(req_file) and os.path.exists(venv_pip):
                pip_r = subprocess.run([venv_pip, "install", "-r", req_file, "-q"],
                                       capture_output=True, check=False)
                if pip_r.returncode != 0:
                    logger.warning("Self-update: pip install failed: %s", (pip_r.stderr or b"").decode())
                else:
                    logger.info("Self-update: requirements refreshed.")
            # Restart the service to load new code. _prepare_restart_with_watchdog
            # writes the pending manifest + schedules the external health-gate
            # watchdog (lm-component-update-restart) so a bad update is rolled
            # back instead of crash-looping forever; then we flush queued log
            # entries (including the "reloading ..." line) to the hub and exit
            # NON-ZERO so systemd's Restart=on-failure reliably relaunches us.
            # A clean exit (0) would NOT be revived.
            if not self._prepare_restart_with_watchdog(
                    head_before, head_after, backup_dir, cwd, reason="self-update"):
                return False
            self._flush_log_relay_sync()
            os._exit(3)
        except Exception as e:
            logger.warning("Self-update check failed: %s", e)
            return False

    def updater_worker(self) -> None:
        # Wait 120 s after startup before the first check.  This gives the spoke
        # time to connect, receive its session key, and persist it to .env so that
        # a restart triggered by an update will re-authenticate cleanly rather than
        # falling back to zero-touch on every cycle.
        logger.info("Updater worker started; grace period 120s before first check.")
        if self._updater_stop.wait(timeout=120):
            logger.info("Updater worker exiting.")
            return
        logger.info("Updater worker: grace period elapsed; polling every 3600s.")
        while not self._updater_stop.is_set():
            try:
                logger.info("Checking for self-updates...")
                self.perform_self_update_check()
                if self._updater_stop.wait(timeout=3600):
                    break
            except Exception as e:
                logger.error("Updater worker error: %s", e)
                if self._updater_stop.wait(timeout=60):
                    break
        logger.info("Updater worker exiting.")

    def start_updater_worker(self) -> None:
        if self._updater_thread and self._updater_thread.is_alive():
            return
        self._updater_thread = threading.Thread(target=self.updater_worker, name="updater-worker", daemon=True)
        self._updater_thread.start()
        logger.info("Updater worker thread launched.")

    def stop_updater_worker(self) -> None:
        self._updater_stop.set()
        if self._updater_thread:
            self._updater_thread.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Log relay to hub
    # ------------------------------------------------------------------

    async def _send_spoke_log(self, websocket, entries) -> None:
        """Send one signed SPOKE_LOG message carrying the given log entries."""
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_id": self.spoke_id,
                "destination_id": "hub",
            },
            "payload": {"type": "SPOKE_LOG", "data": {"entries": entries}},
        }
        if self.signer:
            msg["signature"] = self.signer.sign(msg)
        await websocket.send(json.dumps(msg, separators=(",", ":")))

    async def _log_relay_task(self, websocket) -> None:
        """Drain the log queue and send captured log entries to the Hub as SPOKE_LOG.

        Flushes every 5 s (not 30 s) so a short-lived spoke process — which can be
        torn down ~22 s after startup — still gets several relay windows before
        it dies, and the Hub/WebUI/BugFixer see the connect/handshake trail and
        the final log line rather than losing everything in the queue.
        """
        while True:
            await asyncio.sleep(5)
            entries = []
            try:
                while True:
                    entries.append(self._log_relay_queue.get_nowait())
            except queue.Empty:
                pass
            if not entries:
                continue
            try:
                await self._send_spoke_log(websocket, entries)
            except Exception as e:
                logger.debug("Log relay send failed: %s", e)

    def _flush_log_relay_sync(self, timeout: float = 2.0) -> None:
        """Best-effort final flush of queued log entries before a hard exit.

        Called from the updater thread (a separate thread from the event loop)
        right before ``os._exit(0)`` during a self-update restart, so the spoke's
        last lines — including the "restarting service ..." message — actually
        reach the Hub instead of dying with the queue still populated. Schedules
        the send on the captured event loop and blocks briefly for it; any
        failure (no loop, loop closed, websocket gone, timeout) is swallowed
        because the process is about to exit regardless.
        """
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        if not entries:
            return
        loop = self._loop
        ws = self._hub_ws
        if loop is None or ws is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(self._send_spoke_log(ws, entries), loop)
            fut.result(timeout=timeout)
        except Exception as e:
            logger.debug("Pre-exit log flush failed: %s", e)

    async def _flush_log_relay_async(self, timeout: float = 2.0) -> None:
        """Best-effort final flush of queued log entries before a hard exit.

        Event-loop counterpart to ``_flush_log_relay_sync``: use this from
        command handlers (which run inside the event loop, e.g. the
        ``SPOKE_UPDATE`` handler) right before ``os._exit(0)`` during a
        self-update restart, so the spoke's final lines reach the Hub instead
        of dying with the relay queue still populated. Drains the queue and
        awaits a single SPOKE_LOG send; any failure is swallowed because the
        process is about to exit regardless.
        """
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        if not entries:
            return
        ws = self._hub_ws
        if ws is None:
            return
        try:
            await asyncio.wait_for(self._send_spoke_log(ws, entries), timeout=timeout)
        except Exception as e:
            logger.debug("Pre-exit async log flush failed: %s", e)

    # ------------------------------------------------------------------

    def register_module(self, name: str, module_instance: Any):
        """Registers a module to be handled by this control plane."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    async def run(self):
        """Main loop for the control plane."""
        # Clear any stale healthy marker from a prior boot — a fresh start must
        # re-prove health (re-auth with the hub) before the update watchdog treats
        # it as the "new code booted OK" signal. Without this, a crash-looping new
        # version could inherit a stale marker and the watchdog would never roll back.
        self._clear_healthy_marker()
        await self._resolve_hub_url()
        logger.info(f"Starting Control Plane in HUB MODE -> {self.hub_url}")
        self.start_updater_worker()
        _delay = 5
        while True:
            try:
                await self._connect_and_serve()
                _delay = 5  # clean return after a successful session → reset
            except (websockets.exceptions.ConnectionClosedError, OSError) as e:
                logger.warning("Connection lost (%s). Reconnecting in %ds...", e, _delay)
                _delay = min(_delay * 2, 300)  # cap at 5 min so a long hub outage
                #                                    doesn't spam ~12 lines/min forever
            except Exception as e:
                logger.error("Unexpected connection error (%s). Reconnecting in %ds...", e, _delay)
                _delay = min(_delay * 2, 300)
            # If the hub URL is the auto-discovery sentinel, re-resolve on each
            # reconnect so a hub that comes up after this spoke (or moves) is
            # found without a restart.
            if self.hub_url in ("", "auto", None):
                await self._resolve_hub_url()
            await asyncio.sleep(_delay)

    def _client_ssl_ctx(self):
        """Build an SSL context for a ``wss://`` connect to the hub.

        Default (lab): ``ssl._create_unverified_context()`` — traffic is
        encrypted but the self-signed hub cert is NOT authenticated (MITM-able
        on-path). Set ``LM_HUB_TLS_VERIFY=1`` and ``LM_HUB_CA_CERT=<path>`` to
        verify the hub cert against a shipped CA. Returns None only on a
        build failure (the caller then connects without TLS and fails fast,
        surfacing the misconfiguration instead of hanging)."""
        try:
            if self._tls_verify and self._tls_ca_cert:
                ctx = ssl.create_default_context(cafile=self._tls_ca_cert)
                logger.info("wss: verifying hub cert against CA %s", self._tls_ca_cert)
                return ctx
            ctx = ssl._create_unverified_context()
            logger.debug("wss: using unverified context (self-signed hub cert; "
                         "set LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT to verify)")
            return ctx
        except Exception as e:
            logger.error("Could not build wss SSL context: %s — connecting without TLS", e)
            return None

    async def _resolve_hub_url(self) -> None:
        """When ``self.hub_url`` is empty/``auto``/None, auto-discover the hub via
        DNS (``lm-hub.<suffix>``) then mDNS and set ``self.hub_url`` to the result.

        Lets a spoke install/launch with no ``--hub`` and still find the hub
        (mirroring the install-script discovery). Best-effort: on no result it
        leaves ``self.hub_url`` as the sentinel so the next reconnect retries —
        discovery is never fatal to the spoke."""
        if self.hub_url not in ("", "auto", None):
            return
        try:
            from .hub_discovery import discover_hub_url
        except ImportError:
            logger.warning("hub_discovery module unavailable — cannot auto-discover "
                           "the hub; pass --hub or set HUB_URL.")
            return
        url = discover_hub_url(timeout=5.0)
        if url:
            self.hub_url = url
            logger.info(f"Auto-discovered hub at {url}")
        else:
            logger.warning("Hub auto-discovery found no hub (no lm-hub DNS record / "
                           "mDNS broadcast); will retry on reconnect. Pass --hub to pin.")

    async def _connect_and_serve(self):
        # Disable per-message-deflate. A deflate-context desync between this
        # spoke's client and the hub manifests as "decompression failed"
        # (code 1002) and garbled frames that fail json.loads with
        # "Extra data: line 1 column 9 (char 8)". Negotiating no compression in
        # both directions sidesteps the whole class of failures at the cost of
        # a little bandwidth.
        # TLS: a wss:// hub_url gets an SSL context (verify-off by default for
        # the self-signed hub cert; LM_HUB_TLS_VERIFY=1 + LM_HUB_CA_CERT verifies).
        # ws:// stays plaintext (loopback / legacy). See _client_ssl_ctx.
        ssl_ctx = self._client_ssl_ctx() if self.hub_url.lower().startswith("wss://") else None
        # Surface the connect attempt + TLS mode at INFO so it reaches the hub
        # via the log relay (the unverified-context line in _client_ssl_ctx is
        # DEBUG). This pairs with the "Connection lost (...)" warning below to
        # form a troubleshooting trail: "Connecting wss://hub:443 [TLS
        # unverified]" then "Connection lost ([SSL: CERTIFICATE_VERIFY_FAILED])".
        if ssl_ctx is None:
            _tls_mode = "plaintext (loopback/legacy)"
        elif self._tls_verify and self._tls_ca_cert:
            _tls_mode = f"TLS verified (CA={self._tls_ca_cert})"
        else:
            _tls_mode = "TLS unverified (self-signed hub cert)"
        logger.info("Connecting to hub %s [%s]", self.hub_url, _tls_mode)
        async with websockets.connect(self.hub_url, compression=None, ssl=ssl_ctx) as websocket:
            self._hub_ws = websocket
            # Capture the running loop so the updater thread can schedule a final
            # synchronous log flush (run_coroutine_threadsafe) before os._exit(0).
            self._loop = asyncio.get_running_loop()
            # 1. Spoke Authentication Handshake
            auth_payload = {"spoke_id": self.spoke_id}
            if self.secret:
                auth_payload["secret"] = self.secret
            if self.module_type:
                auth_payload["module_type"] = self.module_type
            if self.onboarding_psk:
                auth_payload["onboarding_psk"] = self.onboarding_psk
            if self.tenant_id_hint:
                auth_payload["tenant_id_hint"] = self.tenant_id_hint
            # Stable install UUID + current OS hostname: lets the hub detect a
            # clone-and-rename (same UUID → carry over approval; new hostname →
            # report the change) instead of treating the renamed spoke as a
            # stranger. Empty install_uuid = .env unwritable → hub skips correlation.
            if self.install_uuid:
                auth_payload["install_uuid"] = self.install_uuid
            if self.hostname:
                auth_payload["hostname"] = self.hostname

            await websocket.send(json.dumps(auth_payload, separators=(',', ':')))
            logger.info(f"Connected to Lab Manager Hub as {self.spoke_id}. Performing mutual authentication...")

            # 2. Hub Mutual Authentication (Verify Hub's identity)
            try:
                hub_proof_json = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                hub_proof = json.loads(hub_proof_json)

                if hub_proof.get("status") == "HUB_VERIFIED":
                    challenge = hub_proof.get("challenge")
                    signature = hub_proof.get("signature")

                    if self.hub_secrets:
                        verified = False
                        for hs in self.hub_secrets:
                            expected_sig = hmac.new(
                                hs.encode(),
                                challenge.encode(),
                                hashlib.sha256
                            ).hexdigest()
                            if hmac.compare_digest(expected_sig, signature):
                                verified = True
                                break

                        if verified:
                            logger.info("Hub identity verified successfully.")
                            # New code booted AND authed with the hub → mark healthy.
                            # The external update watchdog treats this marker as the
                            # "new version is good" signal; its absence past the
                            # deadline triggers a rollback.
                            self._touch_healthy_marker()
                            await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                        else:
                            # All known hub_secrets failed to verify the hub's
                            # challenge — a stale hub root key (hub restart, a
                            # restore from a different install, or a rotation).
                            # Hard-closing here sent the spoke into an infinite
                            # reconnect storm against a hub that was willing to
                            # keep it pending. Fall back to zero-touch: drop the
                            # stale secret(s), accept the hub, and let admin
                            # approval + a fresh SPOKE_SET_HUB_SECRET re-establish
                            # verified mutual auth on the next reconnect.
                            logger.warning("Hub identity verification failed for all known secrets — discarding stale hub_secret(s), falling back to zero-touch (pending approval).")
                            self.hub_secrets = []
                            self._hub_secret_warned = True
                            # New code booted + reached the auth exchange (pending
                            # admin approval is NOT a code failure) → mark healthy.
                            self._touch_healthy_marker()
                            await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                    else:
                        if not self._hub_secret_warned:
                            logger.warning("Hub secrets not configured. Skipping Hub identity verification (Insecure).")
                            self._hub_secret_warned = True
                        # New code booted + reached the auth exchange → mark healthy
                        # (the watchdog rolls back on a boot crash-loop, not on the
                        # admin-approval / hub-secret state).
                        self._touch_healthy_marker()
                        await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                else:
                    logger.error(f"Unexpected response during Hub verification: {hub_proof.get('status')}")
                    await websocket.close(1008, "Mutual authentication failed")
                    return
            except websockets.exceptions.ConnectionClosedError as e:
                # Hub closed the connection during handshake. The most common cause is a
                # stale/rotated session secret — hub sends 1008 "Authentication failed".
                # Clear the stored secret so the next retry connects in zero-touch mode
                # and receives a freshly provisioned key from the hub.
                if (self.secret
                        and hasattr(e, 'rcvd') and e.rcvd
                        and e.rcvd.code == 1008
                        and "Authentication" in (e.rcvd.reason or "")):
                    logger.warning(
                        "Hub rejected secret for spoke '%s' — clearing and falling back to zero-touch.",
                        self.spoke_id)
                    self.secret = None
                    self.signer = None
                    self._hub_secret_warned = False  # allow the insecure-skip warning once on next attempt
                    self._persist_session_secret("")
                return
            except Exception as e:
                logger.error(f"Hub verification timed out or failed: {e}")
                # Guard the close: when the original failure was a handshake
                # timeout on an already-broken socket, websocket.close() can
                # raise ConnectionClosed/OSError. Raising inside this except
                # chains the new exception onto the old one ("During handling of
                # the above exception, another exception occurred"), producing
                # the traceback spam logged by dhcp/dns spokes on a persistently
                # unreachable hub. The `async with websockets.connect(...)`
                # already closes on exit, so this manual close is redundant —
                # best-effort it and never let it raise.
                try:
                    await websocket.close(1008, "Mutual authentication timed out")
                except Exception:
                    pass
                return

            # Heartbeat loop
            async def heartbeat():
                while True:
                    try:
                        ts = round(time.time(), 6)
                        msg = {
                            "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                                       "sender_id": self.spoke_id, "destination_id": "hub"},
                            "payload": {"type": "HEARTBEAT", "data": {}}
                        }
                        msg["signature"] = self._sign(msg)
                        await websocket.send(json.dumps(msg, separators=(',', ':')))
                        await asyncio.sleep(30)
                    except asyncio.CancelledError:
                        raise
                    except (websockets.exceptions.ConnectionClosed, OSError) as e:
                        # Connection is gone — let the main loop notice and
                        # reconnect. Swallowing here avoids an uncaught task
                        # exception printing a raw traceback to stderr.
                        logger.debug("Heartbeat send failed; letting main loop reconnect: %s", e)
                        return
                    except Exception as e:
                        logger.warning("Heartbeat task error: %s", e)
                        return

            _hb_task = asyncio.create_task(heartbeat())
            _lr_task = asyncio.create_task(self._log_relay_task(websocket))
            # Per-module health heartbeat — emits a greppable [heartbeat] line
            # every ~60s through the log relay so BugFixer can triage a missing
            # module. Inherited by every spoke via BaseControlPlane.
            _hh_task = asyncio.create_task(self._health_heartbeat_task(websocket))
            # Subclasses can attach extra long-lived per-connection tasks
            # (e.g. a telemetry relay loop) via this hook.
            _extra_tasks = self._create_spoke_tasks(websocket)

            # Main Message Loop
            try:
              async for message in websocket:
                msg = json.loads(message)
                if not self._verify_signature(msg):
                    continue

                payload = msg.get("payload", {})
                cmd_type = payload.get("type")
                data = payload.get("data", {})
                corr_id = msg.get("header", {}).get("message_id")

                # Hub notification messages — no response expected or needed
                if cmd_type == "APPROVAL_REQUIRED":
                    logger.info(
                        "Spoke '%s' is pending admin approval. "
                        "Approve it in the LM WebUI (Setup → Spoke Approvals).",
                        self.spoke_id,
                    )
                    continue
                if cmd_type == "APPROVED":
                    logger.info("Spoke '%s' approved by admin. Ready for commands.", self.spoke_id)
                    continue

                # First, try handling as a system command
                result = await self.handle_system_command(cmd_type, data)

                # Route to the appropriate module if not handled by system
                handled_by_module = None
                if result is None:
                    for module_name, module in self.modules.items():
                        # We check if the command_type is specific to this module
                        # In a real system, cmd_type might be "pxmx.get_vms"
                        if cmd_type.startswith(module_name) or self._module_handles_command(module, cmd_type):
                            try:
                                result = await module.handle_command(cmd_type, data)
                            except asyncio.CancelledError:
                                raise
                            except Exception as e:
                                # A module exception (e.g. backend unreachable:
                                # Kea down, unbound-control missing) must not
                                # tear down the hub websocket or dump a raw
                                # traceback. Return a clean error to the hub and
                                # keep the connection alive.
                                logger.exception("Module %s raised handling %s", module_name, cmd_type)
                                result = {"status": "ERROR",
                                          "message": f"{type(e).__name__}: {e}"}
                            handled_by_module = module
                            break

                    if result is None and self.modules:
                        # Fallback: Try the first module if no specific match
                        first_mod = list(self.modules.values())[0]
                        try:
                            result = await first_mod.handle_command(cmd_type, data)
                        except asyncio.CancelledError:
                            raise
                        except Exception as e:
                            logger.exception("Fallback module raised handling %s", cmd_type)
                            result = {"status": "ERROR",
                                      "message": f"{type(e).__name__}: {e}"}
                        handled_by_module = first_mod

                # Fallback for *_GET_STATUS commands: if the module returned an error
                # or None, use the module's get_status() method (required by BaseSpoke).
                # This ensures that status commands like CS_GET_STATUS work even when
                # a module's handle_command() doesn't explicitly implement them.
                if cmd_type and cmd_type.endswith("_GET_STATUS") and self.modules:
                    needs_fallback = False
                    if result is None:
                        needs_fallback = True
                    elif isinstance(result, dict) and result.get("status") == "ERROR":
                        needs_fallback = True

                    if needs_fallback:
                        # Try the module that was asked first, then any module
                        candidate_modules = []
                        if handled_by_module is not None:
                            candidate_modules.append(handled_by_module)
                        for m in self.modules.values():
                            if m not in candidate_modules:
                                candidate_modules.append(m)

                        for module in candidate_modules:
                            try:
                                fallback_status = await module.get_status()
                                if isinstance(fallback_status, dict):
                                    result = fallback_status
                                    logger.info(f"Module did not handle {cmd_type} in handle_command(); "
                                                f"used get_status() fallback successfully.")
                                    break
                            except Exception as e:
                                logger.warning(f"get_status() fallback failed for a module: {e}")

                ts = round(time.time(), 6)
                resp = {
                    "correlation_id": corr_id,
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "COMMAND_RESULT", "data": result}
                }
                resp["signature"] = self._sign(resp)
                await websocket.send(json.dumps(resp, separators=(',', ':')))
            finally:
                self._hub_ws = None
                _hb_task.cancel()
                _lr_task.cancel()
                _hh_task.cancel()
                for _t in _extra_tasks:
                    _t.cancel()
                await asyncio.gather(_hb_task, _lr_task, _hh_task, *_extra_tasks, return_exceptions=True)

    def _create_spoke_tasks(self, websocket) -> list:
        """Subclasses override to add long-lived per-connection async tasks
        (e.g. a telemetry relay loop) that run alongside the heartbeat/log-relay
        tasks. Returned tasks are cancelled and awaited when the connection
        closes. Default: no extra tasks."""
        return []

    async def _health_heartbeat_task(self, websocket):
        """Emit one greppable health line on a schedule so BugFixer (which reads
        Hub logs via GET_LOGS) can confirm this module is alive and triage when
        it is not. Unlike the transport ``heartbeat()`` frame (which only updates
        the Hub's in-memory last_seen and is never written to agent_logs), this
        line flows through the existing telemetry pipeline — the root-logger
        _SpokeLogRelayHandler captures it -> _log_relay_queue -> _log_relay_task
        -> SPOKE_LOG -> Hub agent_logs[spoke_id] — so BugFixer actually sees it.
        Zero Hub-side relay changes are needed. Every spoke inherits this from
        BaseControlPlane, so all modules emit the same signal uniformly."""
        interval = 60
        try:
            interval = max(10, int(os.environ.get("LM_HEARTBEAT_INTERVAL_S", "60")))
        except Exception:
            pass
        start = time.time()
        while True:
            try:
                uptime = int(time.time() - start)
                logger.info(
                    "[heartbeat] ok module=%s spoke_id=%s hub=connected uptime_s=%s queue=%d",
                    self.module_type or "unknown", self.spoke_id, uptime,
                    self._log_relay_queue.qsize(),
                )
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.debug("health heartbeat task error: %s", e)
                return

    def _module_handles_command(self, module, cmd_type: str) -> bool:
        """Check if a module should handle a specific command type."""
        # This can be expanded with a registry of commands per module
        return True # Default to true for now, let the module decide

    def get_service_name(self) -> str:
        """Returns the systemd service name for this spoke."""
        # Default: lm-module (e.g., pxmx-spoke-1 -> lm-pxmx)
        module_name = self.spoke_id.split("-")[0]
        return f"lm-{module_name}"

    async def handle_system_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Handles commands that affect the entire spoke system rather than a specific module."""
        if cmd_type in ("SPOKE_SET_LOG_LEVEL", "SET_LOG_LEVEL"):
            enabled = data.get("enabled", False)
            level = set_log_level(enabled)
            logger.info(f"Log level set to {logging.getLevelName(level)}")
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

        # Unified status command - works for all spokes by calling module.get_status()
        # This is the preferred way for the Hub to request status from any spoke.
        if cmd_type == "SPOKE_GET_STATUS":
            return await self._get_module_status()

        if cmd_type == "SPOKE_UPDATE":
            repo_url = data.get("repo_url")
            if not repo_url:
                return {"status": "ERROR", "message": "Missing repo_url for update"}

            try:
                # Identify spoke root directory (assuming the control plane is running from src/...)
                # e.g. /opt/lm/pxmx/src/control_plane.py -> /opt/lm/pxmx
                cwd = os.path.abspath(os.getcwd())
                # If we are in a src folder, go up one level
                if cwd.endswith("src"):
                    cwd = os.path.dirname(cwd)

                logger.info(f"Performing update in {cwd} from {repo_url}...")

                # 1. Update remote origin
                subprocess.run(["git", "remote", "set-url", "origin", repo_url], cwd=cwd, check=True)

                # 2. Configure pull strategy
                subprocess.run(["git", "config", "pull.rebase", "true"], cwd=cwd, check=True)
                subprocess.run(["git", "config", "rebase.autoStash", "true"], cwd=cwd, check=True)

                # 3. Abort any interrupted rebase before pulling
                self._run_git(["rebase", "--abort"], cwd=cwd)

                # 4. Snapshot HEAD + the code tree before pull so the external
                # watchdog can roll back (git reset --hard head_before) if the new
                # code crashes at boot. The src/ file snapshot is belt-and-suspenders.
                head_before = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()
                backup_dir = self._snapshot_for_update(head_before, cwd)

                # 5. Fetch + pull; on rebase conflict reset hard to origin
                subprocess.run(["git", "fetch", "origin"], cwd=cwd, check=True)
                pull = self._run_git(["pull", "--rebase", "--autostash", "origin"], cwd=cwd)
                if pull.returncode != 0:
                    logger.warning(f"git pull --rebase failed (rc={pull.returncode}); resetting hard to origin")
                    branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd).stdout.strip() or "main"
                    subprocess.run(["git", "rebase", "--abort"], cwd=cwd, check=False)
                    subprocess.run(["git", "reset", "--hard", f"origin/{branch}"], cwd=cwd, check=True)

                head_after = self._run_git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()

                # 6. Only restart if new commits were pulled
                if head_after != head_before:
                    # Skip a known-bad commit (rolled back before): reset to
                    # head_before and stay put rather than crash-looping into the
                    # same broken code.
                    if self._is_known_bad_commit(head_after):
                        logger.warning(
                            "SPOKE_UPDATE: new HEAD %s is a known-bad commit "
                            "(rolled back before); resetting to %s and skipping.",
                            head_after[:8], head_before[:8])
                        self._run_git(["reset", "--hard", head_before], cwd=cwd)
                        self._clear_pending_update()
                        return {"status": "SUCCESS",
                                "message": f"Update {head_after[:8]} is marked bad; stayed on {head_before[:8]}"}
                    # Reload to run the new code. _prepare_restart_with_watchdog
                    # writes the pending manifest + schedules the external
                    # health-gate watchdog (lm-component-update-restart) so a bad
                    # update is rolled back instead of crash-looping forever. We
                    # then flush logs and exit NON-ZERO (3); systemd sees a
                    # failure exit and Restart=on-failure reliably relaunches us.
                    # (The old `systemctl restart` child died in our own cgroup
                    # mid-restart, stranding the spoke offline — see
                    # _prepare_service_restart's docstring.)
                    if self._prepare_restart_with_watchdog(
                            head_before, head_after, backup_dir, cwd, reason="spoke-update"):
                        await self._flush_log_relay_async()
                        os._exit(3)
                    return {"status": "SUCCESS",
                            "message": f"Updated from {repo_url}; restart skipped"}
                else:
                    logger.debug("SPOKE_UPDATE: already up to date; no restart needed.")
                    return {"status": "SUCCESS", "message": "Already up to date; no restart needed"}
            except subprocess.CalledProcessError as e:
                logger.error(f"SPOKE_UPDATE failed (git command exit code {e.returncode}): {e}")
                stderr = e.stderr.decode('utf-8', errors='replace') if isinstance(e.stderr, bytes) else (e.stderr or '')
                stdout = e.stdout.decode('utf-8', errors='replace') if isinstance(e.stdout, bytes) else (e.stdout or '')
                detail = (stderr or stdout or str(e)).strip()
                return {"status": "ERROR", "message": f"git operation failed: {detail}"}
            except Exception as e:
                logger.error(f"SPOKE_UPDATE failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        if cmd_type == "SPOKE_SET_HUB_SECRET":
            new_secret = data.get("hub_secret")
            if new_secret:
                self.hub_secrets.insert(0, new_secret)
                self.hub_secrets = self.hub_secrets[:3] # Window of 3
                self._persist_hub_secret(new_secret)
                logger.info(f"Hub secret updated for {self.spoke_id}. Current window size: {len(self.hub_secrets)}")
                return {"status": "SUCCESS", "message": "Hub secret updated successfully"}
            return {"status": "ERROR", "message": "Missing hub_secret in data"}

        if cmd_type == "SPOKE_UPDATE_SESSION_KEY":
            new_secret = data.get("secret")
            if new_secret:
                self.secret = new_secret
                self.signer = MessageSigner(new_secret)
                self._persist_session_secret(new_secret)
                logger.info(f"Session key updated for {self.spoke_id}")
                return {"status": "SUCCESS", "message": "Session key updated successfully"}
            return {"status": "ERROR", "message": "Missing secret in data"}

        if cmd_type == "SPOKE_SET_HOSTNAME":
            new_hostname = data.get("hostname")
            if not new_hostname:
                return {"status": "ERROR", "message": "Missing hostname in data"}

            try:
                logger.info(f"Updating system hostname to: {new_hostname}")
                # 1. Set the hostname
                subprocess.run(["sudo", "hostnamectl", "set-hostname", new_hostname], check=True)

                # 2. Update /etc/hosts to prevent sudo/etc lag (replace 127.0.1.1 entry)
                # This is a simple sed replacement for the 127.0.1.1 line commonly found in Debian/Ubuntu
                subprocess.run(
                    ["sudo", "sed", "-i", f"s/127.0.1.1[[:space:]]*.*/127.0.1.1 {new_hostname}/", "/etc/hosts"],
                    check=True
                )

                return {"status": "SUCCESS", "message": f"Hostname updated to {new_hostname}"}
            except Exception as e:
                logger.error(f"SPOKE_SET_HOSTNAME failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        return None

    async def _get_module_status(self) -> Dict[str, Any]:
        """
        Retrieves status from the registered module(s) using their get_status() method.
        This is used by the SPOKE_GET_STATUS system command and as a fallback for
        module-specific *_GET_STATUS commands that modules don't explicitly implement.
        """
        if not self.modules:
            return {"status": "ERROR", "message": "No modules registered"}

        # If there's only one module, return its status directly
        if len(self.modules) == 1:
            module = list(self.modules.values())[0]
            try:
                return await module.get_status()
            except Exception as e:
                logger.error(f"Failed to get status from module: {e}")
                return {"status": "ERROR", "message": f"Failed to get status: {e}"}

        # Multiple modules - return a composite status
        results = {}
        for name, module in self.modules.items():
            try:
                results[name] = await module.get_status()
            except Exception as e:
                results[name] = {"status": "ERROR", "message": str(e)}
        return {"status": "SUCCESS", "data": results}

    def _persist_secret_to_env(self, key: str, value: str) -> None:
        """Upserts a key=value line in the spoke's .env file, creating it if needed."""
        try:
            env_path = os.path.join(self._repo_root(), ".env")
            lines: list = []
            if os.path.exists(env_path):
                with open(env_path, "r") as f:
                    lines = f.readlines()
            updated = []
            found = False
            prefix = f"{key}="
            for line in lines:
                if line.startswith(prefix):
                    updated.append(f"{prefix}{value}\n")
                    found = True
                else:
                    updated.append(line)
            if not found:
                updated.append(f"{prefix}{value}\n")
            with open(env_path, "w") as f:
                f.writelines(updated)
            logger.info("Persisted %s to %s", key, env_path)
        except Exception as e:
            logger.warning("Failed to persist %s to .env: %s", key, e)

    def _persist_session_secret(self, new_secret: str) -> None:
        """Writes the rotated session key back to .env so it survives spoke restarts."""
        self._persist_secret_to_env("SPOKE_SECRET", new_secret)

    def _read_env_value(self, key: str) -> str:
        """Reads a ``key=`` line from the spoke's .env file. Returns '' if absent/unreadable."""
        try:
            env_path = os.path.join(self._repo_root(), ".env")
            if not os.path.exists(env_path):
                return ""
            prefix = f"{key}="
            with open(env_path, "r") as f:
                for line in f:
                    if line.startswith(prefix):
                        return line[len(prefix):].strip()
            return ""
        except Exception:
            return ""

    def _ensure_install_uuid(self) -> str:
        """Returns this spoke's stable install UUID, minting + persisting it on first start.

        The UUID is created at FIRST START (not at install) so cloning the install
        tree does NOT copy a UUID — a clone gets its own on its first start. A
        prep-for-imaging run strips ``INSTALL_UUID`` from .env so a cloned image
        mints a fresh one here too (intentionally breaking correlation → a clean
        new identity rather than a rename of the original).

        We trust only what lands on disk: if the write fails we return '' (no
        UUID) rather than a volatile in-memory UUID, so a write failure never
        causes a different identity on every boot. The hub treats an empty UUID
        as "no correlation" and simply records the spoke by id as before.
        """
        existing = self._read_env_value("INSTALL_UUID")
        if existing:
            return existing
        new_uuid = str(uuid.uuid4())
        self._persist_secret_to_env("INSTALL_UUID", new_uuid)
        return self._read_env_value("INSTALL_UUID")

    def _persist_hub_secret(self, new_secret: str) -> None:
        """Writes the hub's identity secret to .env so mutual auth survives spoke restarts."""
        self._persist_secret_to_env("HUB_SECRET", new_secret)

    def _sign(self, msg):
        if not self.signer:
            return None
        return self.signer.sign(msg)

    def _verify_signature(self, msg):
        if not self.secret or not self.signer:
            # If we don't have a secret yet, we can't verify signatures.
            # In the bootstrap phase, we allow this so heartbeats can pass.
            return True
        return self.signer.verify(msg)