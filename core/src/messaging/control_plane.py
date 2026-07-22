import asyncio
import json
import uuid
import time
import websockets
import websockets.exceptions  # noqa: F401 — eager-load so websockets.exceptions.* is
                              # reachable without websockets.connect having run first
                              # (websockets >=11 lazy-imports submodules; unit tests that
                              # exercise the heartbeat/except paths don't call .connect).
import logging
import hmac
import hashlib
import subprocess
import threading
import queue
import random
import os
import tempfile
import socket
import ssl
import sys
import fcntl
import contextlib
import concurrent.futures
from typing import Dict, Any, List, Optional
try:
    from ..security.signer import MessageSigner, encode_frame, split_frame
    from ..security.frame_crypto import (ENCRYPTED_TYPES, ENC_MARKER,
                                         encryption_enabled, is_encrypted, wrap, unwrap)
except ImportError:  # imported off a stale path (messaging.* top-level, no repo root on sys.path)
    from security.signer import MessageSigner, encode_frame, split_frame  # type: ignore
    from security.frame_crypto import (ENCRYPTED_TYPES, ENC_MARKER,
                                       encryption_enabled, is_encrypted, wrap, unwrap)  # type: ignore
from cryptography.exceptions import InvalidTag

try:  # shared helper (lm/core/src); falls back if imported off a stale path
    from logging_setup import set_log_level, truncate_log_files
except ImportError:
    def set_log_level(enabled):
        level = logging.DEBUG if enabled else logging.INFO
        logging.getLogger().setLevel(level)
        for name in list(logging.root.manager.loggerDict):
            logging.getLogger(name).setLevel(level)
        return level

    def truncate_log_files(log_dir="/var/log/lm"):
        truncated = []
        try:
            names = os.listdir(log_dir)
        except Exception:
            return truncated
        for name in names:
            if not name.endswith(".log"):
                continue
            path = os.path.join(log_dir, name)
            try:
                if os.path.isfile(path):
                    with open(path, "w"):
                        pass
                    truncated.append(name)
            except Exception:  # noqa: BLE001 — per-file best-effort
                pass
        return truncated

# Code-drift watchdog mixin — shared with the device-mode SpokeClient (agent
# repo) so both consumers run ONE source of truth. Same-package relative import
# with a bare-module fallback (mirrors the logging_setup block above).
try:
    from .code_drift_watchdog import CodeDriftWatchdogMixin
except ImportError:  # bare-module layout (messaging.* top-level, no repo root)
    from code_drift_watchdog import CodeDriftWatchdogMixin  # type: ignore

# Self-update mixin — the git pull + snapshot + rollback-watchdog + restart
# machinery that backs SPOKE_UPDATE (hub→spoke) and AGENT_UPDATE (spoke→device-
# mode agent). Shared with the device-mode SpokeClient for the same reason
# CodeDriftWatchdogMixin is (single source of truth, MRO-preserving).
try:
    from .self_update import SelfUpdateMixin
except ImportError:  # bare-module layout (messaging.* top-level, no repo root)
    from self_update import SelfUpdateMixin  # type: ignore

# Log-relay mixin — the SPOKE_LOG relay drain/flush helpers + uncaught-exception
# relays, extracted verbatim (state stays in __init__). Same-package relative
# import with a bare-module fallback, mirroring the mixins above.
try:
    from .log_relay import LogRelayMixin
except ImportError:  # bare-module layout (messaging.* top-level, no repo root)
    from log_relay import LogRelayMixin  # type: ignore

# Hub-contact watchdog mixin — the opt-in escalating self-recovery ladder,
# extracted verbatim (outage clock + task handle stay in __init__/run). Same
# relative-import-with-fallback pattern as the mixins above.
try:
    from .hub_contact_watchdog import HubContactWatchdogMixin
except ImportError:  # bare-module layout (messaging.* top-level, no repo root)
    from hub_contact_watchdog import HubContactWatchdogMixin  # type: ignore

logger = logging.getLogger("BaseControlPlane")


def _ws_keepalive_env(name: str, default: float) -> float:
    """Env-overridable WebSocket keepalive knob (seconds) for the spoke's
    ``websockets.connect`` call. Mirrors the hub-side uvicorn knob in
    api.build_server so both ends of a link use the same ping interval / pong
    timeout. Clamped to >=5s. See control_plane.run() for why the library
    default 20s/20s is too tight."""
    try:
        return max(5.0, float(os.environ.get(name, str(default))))
    except Exception:
        return default


class _SpokeLogRelayHandler(logging.Handler):
    """Captures ALL log records (INFO+) into a queue for async relay to the Hub.

    Forwards every level the root logger emits (not just WARNING/ERROR) so the
    Hub WebUI Logs view and BugFixer's GET_LOGS see the spoke's full trail —
    including the INFO lines around a connect/handshake and the last line before
    a process exit, which previously never reached the Hub because only
    WARNING+ was relayed. The root logger's effective level still gates what is
    actually produced; this handler simply does not further filter.

    The entry is the canonical-formatted record (``<asctime> - <name> -
    <levelname> - <message>``) — the SAME shape the spoke writes to its own
    /var/log/lm/<x>.log via ``configure_logging``. The hub stores relayed
    entries verbatim (no re-stamping) so each line carries exactly ONE
    timestamp (the record's original emit time) and the WebUI Logs view is
    byte-identical to the spoke's local log. The prior ``time.strftime`` +
    ``[LEVEL] name:`` prefix added a second timestamp and duplicated the
    name/level already in the canonical record.
    """

    # Multi-role log scoping (optional; None on standalone spokes). A shared
    # "generic" agent process hosts N role sub-spokes, each a BaseControlPlane
    # that installs THIS handler on the ROOT logger. Without scoping, every
    # handler captures the WHOLE process's stream and relays it under its own
    # spoke_id — so the hub's ``agent_logs[{base}-cppm]`` and
    # ``agent_logs[{base}-opnsense]`` both hold the full mixed stream (CPPM logs
    # appear under OPNSense and vice versa). Scoping each handler to its role's
    # logger-name prefixes routes each line to exactly one bucket:
    #   include_prefixes — if set, relay ONLY records whose logger name matches
    #     one of these prefixes (a role sub-spoke relays only its own role's
    #     loggers). Matching is stem-style: ``name == p or name.startswith(p)``
    #     so ``"CPPM"`` catches ``CPPMSpoke``/``CPPMClient``/``CPPMQueries``/…
    #   exclude_prefixes — if set, DROP records matching any prefix (the base
    #     agent relays everything EXCEPT the roles' loggers, so its bucket holds
    #     agent/process/non-role lines + shared-infra loggers like
    #     ``HubDiscovery``/``DepGuard``/``UpdateRecovery`` that live in BOTH
    #     lm/core and a role repo and so can't be attributed by name).
    #   Both None (default) => relay everything — the STANDALONE spoke behavior
    #   (one process, one spoke, all its logs under one spoke_id), preserved
    #   unchanged for non-agent spokes.
    _include_prefixes: Optional[set] = None
    _exclude_prefixes: Optional[set] = None

    def __init__(self, log_queue: queue.Queue):
        super().__init__(level=logging.DEBUG)
        self._queue = log_queue
        # Canonical LM format — matches logging_setup.DEFAULT_FORMAT so a
        # relayed line is indistinguishable from the spoke's local log line.
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))

    def set_include_prefixes(self, prefixes) -> None:
        """Relay only records whose logger name matches one of ``prefixes``."""
        self._include_prefixes = set(prefixes) if prefixes else None

    def set_exclude_prefixes(self, prefixes) -> None:
        """Drop records whose logger name matches one of ``prefixes``."""
        self._exclude_prefixes = set(prefixes) if prefixes else None

    def _in_scope(self, name: str) -> bool:
        inc = self._include_prefixes
        if inc is not None:
            return any(name == p or name.startswith(p) for p in inc)
        exc = self._exclude_prefixes
        if exc is not None:
            return not any(name == p or name.startswith(p) for p in exc)
        return True

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if not self._in_scope(record.name):
                return
            entry = self.format(record)
            try:
                self._queue.put_nowait(entry)
            except queue.Full:
                # Ring-buffer semantics: on a full queue (a long hub outage),
                # drop the OLDEST line to make room for the newest — the most
                # recent lines are the ones worth keeping for the hub / BugFixer
                # (a crash's last words), not the start of the backlog.
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(entry)
                except queue.Full:
                    pass
        except Exception:
            pass


class BaseControlPlane(CodeDriftWatchdogMixin, SelfUpdateMixin, LogRelayMixin, HubContactWatchdogMixin):
    """
    Generic Control Plane for Lab Manager Spokes.
    Handles Hub connectivity, mutual authentication, and module routing.
    """
    # Deadline (seconds) the heartbeat thread waits for the event loop to
    # actually push a heartbeat frame. If the loop is blocked past this, the
    # thread logs an explicit 'event loop stalled' WARNING — the diagnostic
    # win of moving the heartbeat off the loop. See _heartbeat_thread_target.
    HEARTBEAT_SEND_DEADLINE_S = 5.0

    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None, hub_url: str = None,
                 onboarding_psk: str = None, tenant_id_hint: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        # Fall back to persisted value from .env if no hub_secret was passed at startup
        _hs = hub_secret or os.environ.get("HUB_SECRET", "")
        self.hub_secrets = [_hs] if _hs else []
        self.hub_url = self._normalize_hub_url(hub_url) if hub_url else hub_url
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
        # H4: True once the hub advertised ``enc="v1"`` in its HUB_VERIFIED proof
        # AND app-layer encryption is enabled — the spoke may AEAD-encrypt its
        # outbound secret-bearing frames to the hub. Reset to False before each
        # HUB_VERIFIED attempt (downgrade safety: a reconnect to a legacy hub
        # must not keep a stale True from a prior new-hub session). Read with
        # getattr() in _encode_frame so harnesses that bypass __init__ default
        # to plaintext (False), never AttributeError.
        self.hub_enc_capable: bool = False
        # Subclasses set this to a logical type string (e.g. "hypervisor", "firewall")
        # so the hub can route by capability instead of by spoke ID prefix.
        self.module_type: str = None
        # Updater worker state
        self._updater_stop = threading.Event()
        self._updater_thread = None
        # DRAINING: True while a self-update (hub-driven SPOKE_UPDATE or the
        # autonomous self-update timer) is running git pull + about to
        # os._exit+relaunch. Reported in CS_TELEMETRY so the hub stops firing
        # 5s request/reply commands (which time out when the WS drops mid-reply
        # on exit) and queues them to the mailbox instead. Per-process: a fresh
        # process starts False, so the first post-restart telemetry frame
        # ('draining: false') tells the hub to clear drain + resume live pushes.
        self._draining: bool = False
        self._spoke_update_in_progress: bool = False
        # Background code-drift watchdog task (armed in run()).
        self._drift_task = None
        # Log relay: ALL captured log entries (INFO+) are queued here and flushed
        # to the hub every few seconds by _log_relay_task, plus a final flush is
        # attempted before a self-update restart so the spoke's last lines reach
        # the hub even when it is about to die.
        self._log_relay_queue: queue.Queue = queue.Queue(maxsize=500)
        self._log_relay_handler = _SpokeLogRelayHandler(self._log_relay_queue)
        logging.getLogger().addHandler(self._log_relay_handler)
        # Route uncaught SYNC exceptions through the logger (→ relay handler →
        # hub Error Log + BugFixer) before the interpreter's default handler.
        # The asyncio-task counterpart is set at the top of run(). Without both,
        # a genuine crash / unhandled task exception reaches only local stderr,
        # never the hub — see logging-observability-contract.md req 4.
        self._install_uncaught_exception_relay()
        # Active hub websocket — set while connected so subclasses can relay messages up.
        self._hub_ws = None
        # Encrypted inbound frames that arrived during the bootstrap race —
        # BEFORE ``SPOKE_UPDATE_SESSION_KEY`` armed ``self.secret`` (the AEAD
        # key). The hub provisions the session key and an encrypted
        # ``UPDATE_CONFIG`` (carrying api_token / admin_pw / client_secret)
        # back-to-back via fire-and-forget ``send_to_spoke``; the session-key
        # handler runs as a CONCURRENT task (``_handle_one_command``), so the
        # encrypted frame is frequently decoded before ``self.secret`` is set
        # → ``_decode_frame`` would otherwise drop it ("Encrypted frame from
        # hub but no session secret — dropping"), and the role never repoints
        # (e.g. a netbox role stuck on localhost:8000). Buffer such frames here
        # and replay them once the key is armed — see
        # ``_drain_pending_encrypted`` (called from the SPOKE_UPDATE_SESSION_KEY
        # handler). Each entry is ``(wire, enq_time)``; a stale entry is pruned
        # past the drain deadline so a key that never arrives can't wedge the
        # buffer. Cleared per connection (run() finally + start).
        self._pending_encrypted_frames: List[tuple] = []
        # ``(websocket, send_lock, sem)`` captured at the top of the receive
        # loop so ``_drain_pending_encrypted`` can dispatch replayed frames
        # through the same bounded-concurrency path as live ones.
        self._decrypt_dispatch_ctx = None
        # Outstanding _drain_pending_encrypted tasks (kept referenced so the
        # GC can't reap a not-yet-awaited fire-and-forget drain).
        self._drain_tasks: set = set()
        # Pending HUB_REQUEST → HUB_RESPONSE waiters keyed by correlation_id
        # (header.message_id of the outbound request, which the hub echoes back
        # as data.correlation_id on the HUB_RESPONSE). A module awaiting a hub
        # reply (e.g. the netbox IPAM spoke relaying INSTALL_CERT to the
        # netbox-server agent) registers a Future here via request_to_hub() and
        # the receive loop resolves it when the matching HUB_RESPONSE lands.
        self._hub_response_futures: Dict[str, "asyncio.Future"] = {}
        # Wall-clock (epoch) of the last confirmed hub contact — updated on connect
        # and on every received frame. Seeded to "now" so a fresh boot has a grace
        # window before the hub-contact watchdog (below) can escalate, and reloaded
        # from the persisted watchdog state so an ongoing outage's clock survives a
        # service restart / reboot. Drives _hub_contact_watchdog.
        self._last_hub_contact = time.time()
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
        # presents a self-signed cert and cert deployment is still in progress) —
        # encryption without authentication, which is the lab default for now.
        # Flip to verify=ON once the hub cert is deployed:
        #   - public CA (e.g. Let's Encrypt on the Azure endpoint): just set
        #     LM_HUB_TLS_VERIFY=1 (uses the system trust store).
        #   - self-signed hub / private CA: set LM_HUB_TLS_VERIFY=1 +
        #     LM_HUB_CA_CERT=<path> (or LM_HUB_CA_BUNDLE=<path>) to pin the CA.
        # See _client_ssl_ctx. Never silently downgrades: verify=ON with a missing
        # CA path fails fast instead of falling back to unverified.
        self._tls_verify = os.environ.get("LM_HUB_TLS_VERIFY", "0").strip() in ("1", "true", "yes")
        self._tls_ca_cert = (os.environ.get("LM_HUB_CA_CERT", "").strip()
                             or os.environ.get("LM_HUB_CA_BUNDLE", "").strip())
        # Surface the TLS trust config once at startup so the spoke log states
        # plainly whether the hub cert is authenticated. The per-connect INFO line
        # in _connect_and_serve repeats this each reconnect.
        if self._tls_verify:
            _cfg = f"verify=ON ca={'<system store>' if not self._tls_ca_cert else self._tls_ca_cert}"
            logger.info("Spoke TLS config: %s (hub cert will be authenticated)", _cfg)
        else:
            logger.info("Spoke TLS config: verify=OFF (hub cert NOT authenticated — "
                        "set LM_HUB_TLS_VERIFY=1 to verify once the hub cert is deployed)")


    # ------------------------------------------------------------------
    # Self-update helpers (shared by all spokes)
    # ------------------------------------------------------------------

    def _repo_root(self) -> str:
        cwd = os.path.abspath(os.getcwd())
        return os.path.dirname(cwd) if cwd.endswith("src") else cwd

    # _ensure_git_pull_strategy / _run_git / _prepare_service_restart live on
    # SelfUpdateMixin now (shared with the device-mode SpokeClient). _repo_root
    # above stays here as the CWD-anchored hook the mixin calls.
    # _spoke_state_dir / _clear_healthy_marker / _touch_healthy_marker /
    # _snapshot_for_update / _is_known_bad_commit / _clear_pending_update /
    # _core_update_lock / _prepare_restart_with_watchdog / _perform_self_update_sync
    # ALSO live on SelfUpdateMixin now. _resolve_core_root below stays here as
    # the /opt/lm-anchored hook the mixin calls (the device-mode SpokeClient
    # overrides it __file__-anchored). See core/src/messaging/self_update.py.

    def _resolve_core_root(self) -> Optional[str]:
        """Locate the shared lm/core git checkout this spoke imports at runtime
        (the unit's PYTHONPATH points at ``$LM_DIR/core/src``).

        - ``/opt/lm/.git`` present → ``/opt/lm`` (agent all-in-one layout and
          the new cs layout from install_cs.sh — lm.git cloned to /opt/lm, so
          ``core/src/base_spoke.py`` lives at ``/opt/lm/core/src/...``).
        - ``/opt/lm/core/.git`` present → ``/opt/lm/core`` (le layout: a
          standalone lm checkout nested under core).
        - otherwise → ``None`` (old cs vendored /opt/lm/core without .git, or a
          box where /opt/lm isn't provisioned yet). The caller logs a one-time
          warning pointing at re-running the installer and skips core this
          cycle — the spoke's own repo still updates (graceful, not a crash).
        """
        for path in ("/opt/lm", "/opt/lm/core"):
            if os.path.isdir(os.path.join(path, ".git")):
                return path
        return None

    def perform_self_update_check(self) -> bool:
        """Git fetch + pull the spoke's own repo and, if new commits landed,
        snapshot the prior HEAD, refresh requirements, and hand off to the
        external health-gate watchdog (`_prepare_restart_with_watchdog`) which
        restarts the service and rolls back the snapshot if the new code fails
        to boot. Known-bad commits (rolled back before) are skipped. Returns
        True only in the never-reached tail that exits the process; the normal
        "applied an update" path exits with status 3 so systemd relaunches."""
        # Mark draining for the autonomous self-update path (LM_SPOKE_SELF_UPDATE)
        # just as the hub-driven SPOKE_UPDATE handler does, so the hub queues
        # request/reply pushes instead of timing them out on the exit. Off by
        # default (the hub drives updates via SPOKE_UPDATE); cheap when unused.
        self._draining = True
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
                                       capture_output=True, check=False, timeout=300)
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
        finally:
            # Non-exit paths (already up to date / fetch or pull error / no
            # change / known-bad skip / watchdog-prep failure) return without
            # os._exit, so clear _draining or the code-drift watchdog would
            # skip every cycle for the rest of this process lifetime. The exit
            # path os._exit(3)s above, killing the process before this runs.
            self._draining = False

    def updater_worker(self) -> None:
        """Background thread: wait a 120s post-startup grace (so the spoke can
        connect, receive+persist its session key, and re-auth cleanly after the
        restart this loop may trigger), then call `perform_self_update_check`
        every 3600s. Stops when `_updater_stop` is set."""
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
        """Launch the updater background thread (no-op if already running)."""
        if self._updater_thread and self._updater_thread.is_alive():
            return
        self._updater_thread = threading.Thread(target=self.updater_worker, name="updater-worker", daemon=True)
        self._updater_thread.start()
        logger.info("Updater worker thread launched.")

    def stop_updater_worker(self) -> None:
        """Signal the updater thread to stop and join it (5s timeout)."""
        self._updater_stop.set()
        if self._updater_thread:
            self._updater_thread.join(timeout=5.0)

    # ------------------------------------------------------------------
    # Log relay to hub
    # ------------------------------------------------------------------

    async def _deferred_restart_exit(self) -> None:
        """Scheduled ~0.5s after a handler that needs a process restart to apply
        its change returns (``SPOKE_SET_HUB_URL`` repoint, ``SPOKE_SET_MTLS_MATERIALS``
        mTLS arming). The caller persists its change to ``.env`` and returns a
        SUCCESS ack so the hub's mailbox clears the push (vs. SPOKE_UPDATE,
        which exits before acking and relies on idempotent re-delivery). This
        task then flushes the log relay — so the "… restarting" line actually
        reaches the hub — and exits NON-ZERO (3) so systemd
        ``Restart=always``/``on-failure`` relaunches the process, which on boot
        re-reads the now-persisted ``.env``. The short sleep lets the ack + any
        final relay frames land first."""
        try:
            await asyncio.sleep(0.5)
            await self._flush_log_relay_async()
        except Exception as e:  # noqa: BLE001
            logger.debug("Deferred restart-exit pre-flush failed: %s", e)
        finally:
            os._exit(3)

    # ------------------------------------------------------------------

    def register_module(self, name: str, module_instance: Any):
        """Registers a module to be handled by this control plane."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    def _extra_auth_fields(self) -> dict:
        """Extra fields merged into the WS auth frame on connect. Base default
        is empty; subclasses override (e.g. agent ``RoleConnection`` adds
        ``parent_spoke_id`` for hub parent-auto-approve of role sub-spokes)."""
        return {}

    async def send_to_hub(self, payload_type: str, data: Dict[str, Any]) -> bool:
        """Send an unsolicited signed frame to the hub (e.g. a spoke-initiated
        ``LE_CERT_RENEWED`` event so the hub re-distributes a renewed cert
        immediately instead of waiting for the hourly loop).

        Best-effort: a no-op + debug log if the websocket isn't connected yet
        (the hub's hourly distribution loop is the fallback). Mirrors the
        heartbeat send (signed, ``destination_id: hub``). Returns True on send.
        A module calls this via the ``control_plane`` reference its
        ControlPlane passes it (see LEControlPlane.run_hub_mode → LESpoke)."""
        ws = self._hub_ws
        if ws is None:
            logger.debug("send_to_hub(%s): not connected; skipping", payload_type)
            return False
        try:
            msg = {
                "header": {"message_id": str(uuid.uuid4()),
                           "timestamp": round(time.time(), 6),
                           "sender_id": self.spoke_id, "destination_id": "hub"},
                "payload": {"type": payload_type, "data": data or {}},
            }
            await ws.send(self._encode_frame(msg))
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("send_to_hub(%s) failed: %s", payload_type, e)
            return False

    async def request_to_hub(self, req_type: str, data: Dict[str, Any],
                             timeout: float = 30.0) -> Dict[str, Any]:
        """Send a HUB_REQUEST to the hub and await the correlated HUB_RESPONSE.

        The request/reply counterpart of ``send_to_hub`` (which is
        fire-and-forget). The hub's ``_handle_hub_request`` dispatches the
        request and replies with a signed HUB_RESPONSE carrying
        ``data.correlation_id`` = the request's ``header.message_id`` and
        ``data.result`` = the handler's return dict — exactly what this method
        awaits and returns.

        Used by spokes that need the hub to do something on their behalf and
        wait for the answer — e.g. the netbox IPAM spoke (API-only, no cert
        helper) relays ``RELAY_NETBOX_CERT`` so the hub resolves the
        netbox-server agent and runs ``INSTALL_CERT`` there, then hands the
        agent's result back to the spoke. Mirrors the HUB_REQUEST path BugFixer
        already uses; the only new piece is the spoke-side HUB_RESPONSE waiter.

        Best-effort transport: a missing websocket returns a clean ERROR (the
        caller surfaces it) and a timeout returns ERROR without leaking the
        waiter future. The frame is signed via the same path as ``send_to_hub``
        so the hub's approved-sender check succeeds.
        """
        ws = self._hub_ws
        if ws is None:
            logger.debug("request_to_hub(%s): not connected; skipping", req_type)
            return {"status": "ERROR", "message": "not connected to hub"}
        loop = asyncio.get_event_loop()
        corr_id = str(uuid.uuid4())
        fut: "asyncio.Future" = loop.create_future()
        self._hub_response_futures[corr_id] = fut
        msg = {
            "header": {"message_id": corr_id,
                       "timestamp": round(time.time(), 6),
                       "sender_id": self.spoke_id, "destination_id": "hub"},
            "payload": {"type": "HUB_REQUEST", "data": {"type": req_type, **(data or {})}},
        }
        try:
            await ws.send(self._encode_frame(msg))
        except Exception as e:  # noqa: BLE001 — socket closed mid-send
            self._hub_response_futures.pop(corr_id, None)
            logger.warning("request_to_hub(%s) send failed: %s", req_type, e)
            return {"status": "ERROR", "message": f"hub request send failed: {e}"}
        try:
            result = await asyncio.wait_for(fut, timeout)
            return result if isinstance(result, dict) else {"status": "SUCCESS",
                                                            "result": result}
        except asyncio.TimeoutError:
            logger.warning("request_to_hub(%s) timed out after %ss", req_type, timeout)
            return {"status": "ERROR",
                    "message": f"hub request timeout ({req_type})"}
        finally:
            self._hub_response_futures.pop(corr_id, None)

    async def run(self):
        """Main loop for the control plane."""
        # Route unhandled asyncio-task exceptions through the logger → hub relay
        # (sync excepthook was installed in __init__). Set here because the loop
        # is now running. See logging-observability-contract.md req 4.
        try:
            asyncio.get_running_loop().set_exception_handler(self._asyncio_exception_relay)
        except Exception:  # noqa: BLE001
            pass
        # Clear any stale healthy marker from a prior boot — a fresh start must
        # re-prove health (re-auth with the hub) before the update watchdog treats
        # it as the "new code booted OK" signal. Without this, a crash-looping new
        # version could inherit a stale marker and the watchdog would never roll back.
        self._clear_healthy_marker()
        await self._resolve_hub_url()
        logger.info(f"Starting Control Plane in HUB MODE -> {self.hub_url}")
        # Single-scheduler policy: the HUB's WebUI-configured repo-sync
        # (main.py run_repo_sync_loop, interval in global_config["repo_sync"])
        # is the ONE authoritative update schedule. It fans SPOKE_UPDATE to
        # every approved spoke, so a spoke pulling on its OWN independent 3600s
        # timer here is a redundant second scheduler: it advances a spoke's real
        # commit behind the hub's back, leaving the hub's per-spoke last-pushed
        # marker stale → the hub re-fires SPOKE_UPDATE at an already-current
        # device (the "blind send" + reconnect-flap driver). Disabled by
        # default; set LM_SPOKE_SELF_UPDATE=1 to restore the autonomous timer
        # (e.g. a spoke that must self-heal while its hub's repo-sync is off).
        if os.environ.get("LM_SPOKE_SELF_UPDATE", "0").lower() in ("1", "true", "yes"):
            logger.info("Spoke self-update timer ENABLED (LM_SPOKE_SELF_UPDATE).")
            self.start_updater_worker()
        else:
            logger.info("Spoke self-update timer disabled; hub repo-sync is the "
                        "single update scheduler (SPOKE_UPDATE fan-out).")
        # Periodic code-drift self-heal (ALL spokes): if code on disk advances
        # ahead of the running process — a SPOKE_UPDATE / manual pull that pulled
        # but never restarted, so the old class stays in memory AND the next
        # update sees "already up to date" — restart so systemd reloads current
        # code. Previously only the generic agent had this; now every
        # BaseControlPlane spoke (netbox/opnsense/le/ldap/nw/cppm/cs/...) gets it.
        # Opt out with LM_DISABLE_DRIFT_WATCHDOG=1.
        if os.environ.get("LM_DISABLE_DRIFT_WATCHDOG", "0").lower() not in ("1", "true", "yes"):
            self._drift_task = asyncio.create_task(self._code_drift_watchdog())
        # Escalating hub-contact watchdog: restart the service at 5m of no hub
        # contact, reboot the host at 15m, sleep 1h and retry, give up after 3
        # runs. The task always runs but stays a no-op until enabled (WebUI-pushed
        # SPOKE_SET_WATCHDOG config, persisted locally, or LM_HUB_CONTACT_WATCHDOG=1)
        # — off by default because the reboot stage is drastic (a pxmx agent runs
        # on the Proxmox HOST). Hard-disable the task with LM_DISABLE_HUB_CONTACT_WATCHDOG=1.
        if os.environ.get("LM_DISABLE_HUB_CONTACT_WATCHDOG", "0").lower() not in ("1", "true", "yes"):
            self._hub_contact_task = asyncio.create_task(self._hub_contact_watchdog())
        _delay = 5
        while True:
            _sess_start = time.time()
            try:
                await self._connect_and_serve()
                _delay = 5  # clean return after a successful session → reset
            except (websockets.exceptions.ConnectionClosedError, OSError) as e:
                _lasted = time.time() - _sess_start
                # A session that stayed up a while then dropped (e.g. ONE
                # keepalive-ping timeout after minutes of health) is NOT a
                # fast-failure — reset the backoff so a lone blip reconnects in
                # 5s instead of escalating the offline gap toward the cap
                # (which left the spoke offline far longer than the blip
                # warranted and stretched the request-timeout window). Only
                # rapid repeated failures (session < 60s: a real hub outage /
                # connect churn) grow the backoff — capped at 60s (was 300s: a
                # spoke restarting for updates/cert-arm has <60s sessions, so the
                # old cap left it offline up to 5 min after each bounce, the
                # "several-minute telemetry lag after an update" the operator saw).
                _delay = 5 if _lasted >= 60 else min(_delay * 2, 60)
                logger.warning("Connection lost after %.0fs (%s). Reconnecting in %ds...", _lasted, e, _delay)
            except Exception as e:
                _lasted = time.time() - _sess_start
                _delay = 5 if _lasted >= 60 else min(_delay * 2, 60)
                logger.error("Unexpected connection error after %.0fs (%s). Reconnecting in %ds...", _lasted, e, _delay)
            # If the hub URL is the auto-discovery sentinel, re-resolve on each
            # reconnect so a hub that comes up after this spoke (or moves) is
            # found without a restart.
            if self.hub_url in ("", "auto", None):
                await self._resolve_hub_url()
            # Apply ±20% jitter to the reconnect sleep so a mass disconnect
            # (e.g. an Azure hub restart dropping the whole fleet inside the same
            # minute) spreads its reconnect attempts across a window instead of
            # stampeding the hub on identical 5s/10s/20s/... cadences. The
            # deterministic _delay base still drives the exponential ladder and
            # the 300s cap; only the actual sleep is jittered, so a lone blip
            # (5s base) sleeps 4–6s and a maxed-out backoff sleeps 240–360s.
            await asyncio.sleep(self._jittered_reconnect_delay(_delay))

    @staticmethod
    def _jittered_reconnect_delay(base):
        """Return ``base`` with ±20% random jitter, clamped to ≥0.

        Used by the reconnect loop so a fleet-wide disconnect (e.g. a hub
        restart) spreads reconnect attempts across a window instead of every
        spoke sleeping the identical 5s/10s/20s/... cadence. The deterministic
        ``base`` still drives the exponential ladder and the 300s cap; only the
        actual sleep is jittered. A 5s base → 4–6s; a 300s cap → 240–360s.
        """
        return max(0.0, base * random.uniform(0.8, 1.2))

    # ------------------------------------------------------------------
    # Code-drift watchdog + _drift_watched_dirs now live on the shared
    # CodeDriftWatchdogMixin (core/src/messaging/code_drift_watchdog.py) so the
    # device-mode SpokeClient (agent repo, NOT a BaseControlPlane subclass) and
    # every spoke share ONE source of truth. This class keeps _repo_root +
    # _resolve_core_root (the hooks the mixin calls) anchored to the spoke's
    # CWD-based layout. The generic agent overrides _drift_watched_dirs to add
    # each loaded role's sibling repo.
    # ------------------------------------------------------------------

    def _client_ssl_ctx(self):
        """Build an SSL context for a ``wss://`` connect to the hub.

        Default (lab, cert deployment still in progress): verify OFF —
        ``ssl._create_unverified_context()``. Traffic is encrypted but the
        self-signed hub cert is NOT authenticated (MITM-able on-path). This is
        the explicit lab default for now; flip to verify=ON once the hub cert
        is deployed.

        Verify ON (``LM_HUB_TLS_VERIFY=1``):
          - ``LM_HUB_CA_CERT`` / ``LM_HUB_CA_BUNDLE`` set + readable →
            ``ssl.create_default_context(cafile=…)`` pins the hub CA (self-signed
            / private-CA case).
          - no CA path → ``ssl.create_default_context()`` trusts the system store
            (public-CA / Let's Encrypt case).
          - CA path set but MISSING → log ERROR + return None (fail fast). Never
            silently downgrade an operator who asked for verification to an
            unverified context — that's the footgun: they'd believe the hub cert
            is authenticated when it isn't.

        Returns None only on a build failure / misconfiguration (the caller then
        connects without TLS and fails fast, surfacing the problem instead of
        hanging or silently degrading security)."""
        try:
            if not self._tls_verify:
                ctx = ssl._create_unverified_context()
                logger.debug("wss: using unverified context (self-signed hub cert; "
                             "set LM_HUB_TLS_VERIFY=1 to verify)")
                return self._present_client_cert(ctx)
            # Verify ON: prefer a pinned CA, else the system store.
            if self._tls_ca_cert:
                if not os.path.isfile(self._tls_ca_cert):
                    logger.error("wss: LM_HUB_TLS_VERIFY=1 but CA path %s does not "
                                 "exist — refusing to silently downgrade to "
                                 "unverified. Fix the path or unset LM_HUB_TLS_VERIFY.",
                                 self._tls_ca_cert)
                    return None
                ctx = ssl.create_default_context(cafile=self._tls_ca_cert)
                logger.info("wss: verifying hub cert against pinned CA %s",
                            self._tls_ca_cert)
                return self._present_client_cert(ctx)
            ctx = ssl.create_default_context()  # system trust store (public CA)
            logger.info("wss: verifying hub cert against system trust store "
                        "(LM_HUB_TLS_VERIFY=1, no LM_HUB_CA_CERT)")
            return self._present_client_cert(ctx)
        except Exception as e:
            logger.error("Could not build wss SSL context: %s — connecting without TLS", e)
            return None

    def _present_client_cert(self, ctx):
        """Load this spoke's hub-issued mTLS CLIENT cert into the wss context so
        the spoke actually PRESENTS a verified client identity on the handshake.

        THE fleet-mTLS bug this fixes: _client_ssl_ctx built a context that only
        verified the *server* (hub) cert and never called load_cert_chain, so a
        remote spoke connected over TLS but sent NO client cert — the hub saw it
        cert-less and mTLS was silently inactive for every module except bugfixer
        (which has its own connect code that presents the cert).

        CRITICAL: present ONLY the DEDICATED hub-leg cert (mtls-hub-client.*, env
        LM_MTLS_HUB_CLIENT_CERT/KEY) written by _handle_set_mtls_client_cert — NOT
        the shared mtls-client.* / LM_MTLS_CLIENT_CERT that SPOKE_SET_MTLS_MATERIALS
        writes for the /ws/agent leg. Presenting the agent-leg cert to the hub is
        exactly what a cert-distribution push used to do — the hub rejected it and
        the spoke fell off the fleet. If the dedicated cert is absent we present
        NOTHING (cert-less still connects under the permissive model, and the hub
        re-issues the hub-CA cert on the next connect). Best-effort: a missing/broken
        cert never breaks the transport."""
        if ctx is None:
            return ctx
        try:
            cc = ck = ""
            try:
                cert_dir = self._mtls_material_dir()
                _cc = os.path.join(cert_dir, "mtls-hub-client.crt")
                _ck = os.path.join(cert_dir, "mtls-hub-client.key")
                if os.path.isfile(_cc) and os.path.isfile(_ck):
                    cc, ck = _cc, _ck
            except Exception:  # noqa: BLE001
                pass
            if not (cc and ck):
                _cc = os.getenv("LM_MTLS_HUB_CLIENT_CERT", "").strip()
                _ck = os.getenv("LM_MTLS_HUB_CLIENT_KEY", "").strip()
                if _cc and _ck and os.path.isfile(_cc) and os.path.isfile(_ck):
                    cc, ck = _cc, _ck
            if cc and ck:
                ctx.load_cert_chain(cc, ck)
                logger.info("wss: presenting hub-CA mTLS client cert to the hub (%s)", cc)
            else:
                logger.debug("wss: no hub-leg mTLS client cert installed yet — connecting cert-less")
        except Exception as e:  # noqa: BLE001 - never break the transport on cert load
            logger.warning("wss: could not present mTLS client cert (%s) — "
                           "connecting cert-less", e)
        return ctx

    @staticmethod
    def _normalize_hub_url(url):
        """Normalize a pinned hub URL for the unified-443 hub (best-effort).

        Fills in missing pieces with sane defaults (parity with the pxmx
        agent's ``_normalize_spoke_url``), plus the pre-existing unified-443
        migrations so operators don't have to re-edit stale pre-unified pins:

        1. **No scheme at all → default ``wss://``.** A bare ``--hub
           172.16.1.31`` (or ``host:port``) is assumed to mean the unified
           TLS listener, not raw/plaintext — "assume wss:// and 443 unless
           otherwise stated".

        2. **No port → default 443**, the hub's single unified listener.

        3. **``ws://…:443`` → ``wss://…:443``.** Port 443 is always the TLS
           listener; a ``ws://`` pin to it is plaintext-to-TLS →
           ``InvalidMessage: did not receive a valid HTTP response``. The
           hub's mDNS broadcast can also omit the ``tls_port`` TXT, so
           discovery can hand back ``ws://<ip>:443`` — upgrade it. ``ws://``
           on any OTHER (explicitly-given) port — e.g. 8765 loopback on a
           not-yet-upgraded hub — is left alone; that listener is plaintext
           by design.

        4. **Append ``/ws/spoke`` to a pathless :443 pin only.** Under the
           unified-443 merge the spoke-WS lives at ``/ws/spoke`` (path-routed
           on the single :443 uvicorn). A pin resolving to port 443 with no
           path hits the WebUI root ``/`` and is rejected ``HTTP 403``. This
           is gated on port 443 specifically: the legacy loopback ``:8765``
           listener has no path routing at all, so a pin to it must NOT get
           ``/ws/spoke`` appended. A pin that already carries a path is left
           as-is either way.

        The ``auto`` sentinel and empty string are returned unchanged
        (``_resolve_hub_url`` handles ``auto``).
        """
        if not url or url == "auto":
            return url
        raw = url.strip()
        if "://" not in raw:
            raw = "wss://" + raw
        try:
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(raw)
        except Exception:
            return url
        scheme = parts.scheme or "wss"
        netloc = parts.netloc
        host_part = netloc.rsplit("]", 1)[-1] if netloc else netloc
        if netloc and ":" not in host_part:
            netloc = f"{netloc}:443"
            port = 443
        else:
            port = parts.port
        if scheme == "ws" and port == 443:
            scheme = "wss"
            logger.info("Upgrading pinned %s → wss:// (port 443 is the hub TLS listener)", url)
        path = parts.path
        if port == 443 and path in ("", "/"):
            path = "/ws/spoke"
            logger.info("Appending /ws/spoke to pinned URL (unified-443 spoke-WS path): %s", url)
        elif path not in ("", "/"):
            path = path.rstrip("/")
        return urlunsplit((scheme, netloc, path, "", ""))

    @staticmethod
    def _hub_url_is_loopback(url: str) -> bool:
        """True if ``url`` points at a loopback / same-box address — a co-located
        spoke that must NOT be repointed to the hub's public URL on a DNS-name
        change (loopback is still correct after the hub's public name moves; a
        public URL may not even route from the same box — NAT hairpin, etc.).
        Mirrors the loopback test used by ``_connect_and_serve`` for TLS-mode
        logging (control_plane.py ``_is_loopback``). A ``ws://`` scheme is
        treated as loopback too: the unified-443 hub speaks ``wss://`` on 443,
        so a ``ws://`` pin is either the legacy plaintext loopback listener
        (``:8765``) or an explicit plaintext loopback — either way same-box."""
        if not url:
            return False
        u = url.lower()
        return ("127.0.0.1" in u or "localhost" in u or "::1" in u
                or u.startswith("ws://"))

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
        # the self-signed hub cert; LM_HUB_TLS_VERIFY=1 verifies — pinned CA via
        # LM_HUB_CA_CERT, else the system trust store). ws:// stays plaintext
        # (loopback / legacy). See _client_ssl_ctx.
        ssl_ctx = self._client_ssl_ctx() if self.hub_url.lower().startswith("wss://") else None
        # Surface the connect attempt + TLS mode at INFO so it reaches the hub
        # via the log relay. This pairs with the "Connection lost (...)" warning
        # below to form a troubleshooting trail: "Connecting wss://hub:443 [TLS
        # unverified]" then "Connection lost ([SSL: CERTIFICATE_VERIFY_FAILED])".
        # The unverified case is elevated to WARNING for a NON-LOOPBACK hub — a
        # remote/internet hub dialed without cert verification is the actual
        # MITM exposure and must not be silent. Loopback/legacy ws:// stays INFO.
        _is_loopback = ("127.0.0.1" in self.hub_url or "localhost" in self.hub_url
                        or "ws://" in self.hub_url.lower())
        if ssl_ctx is None:
            _tls_mode = "plaintext (loopback/legacy)"
        elif self._tls_verify and self._tls_ca_cert:
            _tls_mode = f"TLS verified (CA={self._tls_ca_cert})"
        elif self._tls_verify:
            _tls_mode = "TLS verified (system trust store)"
        else:
            _tls_mode = "TLS unverified (self-signed hub cert)"
        if "unverified" in _tls_mode and not _is_loopback:
            logger.warning("Connecting to hub %s [%s] — hub cert NOT authenticated; "
                           "an on-path MITM can read/forge the wire. Set "
                           "LM_HUB_TLS_VERIFY=1 once the hub cert is deployed.",
                           self.hub_url, _tls_mode)
        else:
            logger.info("Connecting to hub %s [%s]", self.hub_url, _tls_mode)
        # WebSocket keepalive: the websockets library defaults
        # (ping_interval=20s, ping_timeout=20s) tear down the connection on any
        # event-loop stall >20s — and the hub's uvicorn default pong timeout is
        # only 5s. A spoke that does any sync I/O on its shared loop (cs
        # telemetry relay's dhcp subprocess + config load + persist; dns
        # unbound-control) stalls past that, the hub closes the WS with 1011
        # "keepalive ping timeout", and this spoke enters the 5→300s reconnect
        # backoff — during which the hub's every-5s CS_POLL_AGENT_INBOX times
        # out → the "Request Timeout from <spoke> after 5.0s" flood. Widen to
        # 30s/90s (env-overridable via LM_WS_PING_INTERVAL_S /
        # LM_WS_PING_TIMEOUT_S) so a transient stall recovers instead of
        # cascading. The 30s app-level heartbeat below still detects a truly-dead
        # hub via send failure, so dead-peer detection is not materially delayed.
        async with websockets.connect(
            self.hub_url,
            compression=None,
            ssl=ssl_ctx,
            ping_interval=_ws_keepalive_env("LM_WS_PING_INTERVAL_S", 30.0),
            ping_timeout=_ws_keepalive_env("LM_WS_PING_TIMEOUT_S", 90.0),
        ) as websocket:
            self._hub_ws = websocket
            self._last_hub_contact = time.time()  # TCP+TLS+WS up = hub reachable
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
            # Subclasses (e.g. agent RoleConnection) can add extra auth fields
            # — notably ``parent_spoke_id`` so the hub auto-approves a multi-role
            # agent's role sub-spokes via the (already-approved) base agent.
            auth_payload.update(self._extra_auth_fields())
            # H4: advertise app-layer-encryption capability to the hub. A new
            # hub reads it and encrypts its outbound secret frames to this spoke;
            # a legacy hub ignores the unknown field (fail-safe → plaintext).
            # LM_APP_ENCRYPTION=0 → don't advertise (behave as legacy).
            if encryption_enabled():
                auth_payload["enc"] = ENC_MARKER

            await websocket.send(json.dumps(auth_payload, separators=(',', ':')))
            logger.info(f"Connected to Lab Manager Hub as {self.spoke_id}. Performing mutual authentication...")

            # 2. Hub Mutual Authentication (Verify Hub's identity)
            # H4: reset capability before each attempt (downgrade safety).
            self.hub_enc_capable = False
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
                            # H4: parse the hub's encryption capability. Combined
                            # with encryption_enabled() so LM_APP_ENCRYPTION=0
                            # makes a new spoke behave as legacy (don't encrypt
                            # outbound). A legacy hub sends no ``enc`` field →
                            # False → plaintext (fail-safe).
                            self.hub_enc_capable = bool(
                                hub_proof.get("enc") == ENC_MARKER) and encryption_enabled()
                            # New code booted AND authed with the hub → mark healthy.
                            # The external update watchdog treats this marker as the
                            # "new version is good" signal; its absence past the
                            # deadline triggers a rollback.
                            self._touch_healthy_marker()
                            await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                        else:
                            # All known hub_secrets failed to verify the hub's
                            # challenge — a stale hub root key (hub restart, a
                            # restore from a different install, or a rotation the
                            # spoke was offline for). How safe it is to proceed
                            # hinges on whether TLS authenticates the hub:
                            #
                            #   * TLS verify ON (LM_HUB_TLS_VERIFY=1): the TLS
                            #     layer already authenticated the hub, so a failed
                            #     hub_proof is a benign stale rotation. Fall back
                            #     to zero-touch (drop the stale secret, accept the
                            #     hub, let a fresh SPOKE_SET_HUB_SECRET re-establish
                            #     verified mutual auth). This is the original
                            #     behaviour and is SAFE because TLS binds the peer.
                            #
                            #   * TLS verify OFF: the hub_proof is the ONLY
                            #     authenticator. A failure here could be a MITM
                            #     hub (the TLS-verify-off posture is exactly what
                            #     lets an attacker redirect the spoke to their own
                            #     hub). Accepting it silently = the MITM can then
                            #     push SPOKE_UPDATE (RCE) / SPOKE_SET_HUB_SECRET /
                            #     SPOKE_UPDATE_SESSION_KEY. So DON'T accept: keep
                            #     the (stale) hub_secrets — wiping them is the
                            #     MITM's prize, re-onboarding the spoke onto the
                            #     attacker's hub — and close. The 5→300s reconnect
                            #     backoff (core reconnect chain) keeps this a slow
                            #     retry, not a storm. Operator re-onboards OOB
                            #     (re-deliver the current hub_secret, or flip
                            #     LM_HUB_TLS_VERIFY=1 once the hub cert is issued).
                            if self._tls_verify:
                                logger.warning("Hub identity verification failed for all known secrets — TLS verifies the hub, so treating as a stale rotation: discarding hub_secret(s), falling back to zero-touch (pending approval).")
                                self.hub_secrets = []
                                self._hub_secret_warned = True
                                # New code booted + reached the auth exchange
                                # (pending admin approval is NOT a code failure)
                                # → mark healthy.
                                self._touch_healthy_marker()
                                await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(',', ':')))
                            else:
                                logger.error("Hub identity verification failed for all known secrets AND TLS verify is OFF — refusing unverified hub (possible MITM). Keeping hub_secret(s); close + back off. Re-onboard OOB or set LM_HUB_TLS_VERIFY=1.")
                                self._hub_secret_warned = True
                                # The code booted fine — the trust failure is
                                # operational, not a code regression, so don't let
                                # the update watchdog roll back a good build over
                                # it. Mark healthy, then refuse the unverified hub.
                                self._touch_healthy_marker()
                                try:
                                    await websocket.close(1008, "Hub identity unverified (TLS verify off)")
                                except Exception:
                                    pass
                                return
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

            # Heartbeat — driven by a dedicated OS thread on its own clock so a
            # stalled event loop (sync-I/O in a command handler) can't drift the
            # cadence or hide the stall. See _heartbeat_thread_target.
            _hb_stop = threading.Event()
            _hb_thread = threading.Thread(
                target=self._heartbeat_thread_target,
                args=(websocket, asyncio.get_running_loop(), _hb_stop),
                name=f"lm-heartbeat-{self.spoke_id}", daemon=True)
            _hb_thread.start()
            _lr_task = asyncio.create_task(self._log_relay_task(websocket))
            # Per-module health heartbeat — emits a greppable [heartbeat] line
            # every ~60s through the log relay so BugFixer can triage a missing
            # module. Inherited by every spoke via BaseControlPlane.
            _hh_task = asyncio.create_task(self._health_heartbeat_task(websocket))
            # Subclasses can attach extra long-lived per-connection tasks
            # (e.g. a telemetry relay loop) via this hook.
            _extra_tasks = self._create_spoke_tasks(websocket)

            # Per-connection command concurrency. Each hub command is handled in
            # its own task so a slow handler (cs SPOKE_RELAY awaiting a pxmx
            # agent response for up to 15s; netbox 30s sync; dns/dhcp
            # unbound-control) cannot block the receive loop from reading and
            # acking the next command — the root cause of the hub's every-5s
            # "Request Timeout from cs-svr-02-spoke after 5.0s" flood. Concurrency
            # is bounded by a semaphore (backpressure); ack frames are serialized
            # via a send-lock so the WS frame stream stays well-formed. The hub
            # matches COMMAND_RESULTs by correlation_id, so out-of-order acks are
            # safe, and request_response callers serialize dependent command
            # sequences at the hub side (they await each ack before sending next).
            cmd_send_lock = asyncio.Lock()
            cmd_sem = asyncio.Semaphore(self._max_concurrent_commands())
            cmd_tasks: set = set()
            # Capture the dispatch context so _drain_pending_encrypted (fired
            # from the SPOKE_UPDATE_SESSION_KEY handler, which has no local
            # access to these) can replay deferred encrypted frames through the
            # same bounded-concurrency dispatch as live ones. Cleared in the
            # finally below. Fresh connection → drop any stale deferred frames
            # from a prior (dropped) connection.
            self._decrypt_dispatch_ctx = (websocket, cmd_send_lock, cmd_sem)
            self._pending_encrypted_frames = []

            # Main Message Loop
            try:
              async for message in websocket:
                self._last_hub_contact = time.time()  # any frame = hub reachable
                msg, _ok = self._decode_frame(message)
                if not _ok:
                    # _decode_frame returns ok=False for two distinct reasons:
                    # a genuinely bad frame (bad HMAC / tamper / undecryptable)
                    # OR a deferred encrypted frame it buffered into
                    # _pending_encrypted_frames for replay once the session key
                    # arms. Either way there's nothing to dispatch now; the
                    # deferred one is replayed by _drain_pending_encrypted.
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

                # Reply to a spoke-initiated request_to_hub() call. The hub's
                # _handle_hub_request echoes the request's header.message_id as
                # data.correlation_id and the handler return dict as data.result.
                # Resolve the matching waiter future (no ack, no module dispatch).
                if cmd_type == "HUB_RESPONSE":
                    corr = data.get("correlation_id")
                    fut = self._hub_response_futures.pop(corr, None)
                    if fut is not None and not fut.done():
                        fut.set_result(data.get("result") or {})
                    continue

                # Backpressure slow-down signal from the hub — a fire-and-forget
                # NOTIFICATION (no COMMAND_RESULT ack, like APPROVED) so it never
                # adds to the hub's in-flight/ack load while it's already busy.
                # level 0 = resume, 1 = this spoke is the offender, 2 = fleet-wide.
                # The spoke does the heavy lifting: coalesce/merge its outbound
                # updates LOCALLY and slow its send cadence (apply_backpressure).
                if cmd_type == "LM_BACKPRESSURE":
                    try:
                        self.apply_backpressure(
                            int(data.get("level", 0)),
                            coalesce=bool(data.get("coalesce", False)),
                            min_interval_s=float(data.get("min_interval_s", 0.0)),
                        )
                    except Exception as e:  # noqa: BLE001 — never crash the loop
                        logger.debug("apply_backpressure failed: %s", e)
                    continue

                # Backpressure: cap in-flight handlers so a sustained overload
                # can't grow unbounded. Reject with a fast ERROR ack so the hub
                # doesn't pile up timed-out requests waiting on a stalled spoke.
                if len(cmd_tasks) >= self._max_inflight_commands():
                    logger.warning("command queue full (%d in-flight); rejected %s",
                                   len(cmd_tasks), cmd_type)
                    await self._send_cmd_result(
                        websocket, corr_id,
                        {"status": "ERROR", "message": "spoke command queue full"},
                        cmd_send_lock)
                    continue
                # Handle + ack in a bounded concurrent task so the receive loop
                # keeps draining the socket while a slow handler runs.
                task = asyncio.create_task(self._handle_one_command(
                    websocket, cmd_type, data, corr_id, cmd_send_lock, cmd_sem))
                cmd_tasks.add(task)
                task.add_done_callback(cmd_tasks.discard)
            finally:
                self._hub_ws = None
                # Drop the bootstrap-race replay context + any still-pending
                # deferred frames — they belong to THIS (now-closed) connection.
                self._decrypt_dispatch_ctx = None
                self._pending_encrypted_frames = []
                _hb_stop.set()  # signal the heartbeat thread to exit
                _hb_thread.join(timeout=2.0)  # short — it ticks on its own clock
                _lr_task.cancel()
                _hh_task.cancel()
                for _t in _extra_tasks:
                    _t.cancel()
                for _t in list(cmd_tasks):
                    _t.cancel()
                await asyncio.gather(
                    _lr_task, _hh_task, *_extra_tasks,
                    *list(cmd_tasks), return_exceptions=True)

    def _heartbeat_thread_target(self, websocket, loop, stop_event) -> None:
        """Dedicated OS thread driving the 30s spoke heartbeat, independent of
        the asyncio event loop's scheduling.

        The heartbeat used to be an ``asyncio.create_task`` sharing the event
        loop, so any loop-blocking sync-I/O call in a command handler (the
        historical unbound-control / Kea-CA / netbox ``_ensure_cf`` stalls)
        starved it: ``asyncio.sleep(30)`` wouldn't tick and the hub's
        ``last_seen`` went stale silently until the 90s WS keepalive dropped the
        socket. This thread ticks on a real ``time.sleep`` clock (via
        ``stop_event.wait``), so the cadence can't drift and a stall can't hide:
        each tick schedules the send on the loop and waits up to
        ``HEARTBEAT_SEND_DEADLINE_S`` for it to complete. If it doesn't (the loop
        is blocked), the thread — which is NOT blocked — logs an explicit
        'heartbeat send overdue' WARNING so the stall is observable in the spoke
        log instead of a silent gap.

        Delivery still rides the event loop (the WS socket's ``send`` is a
        coroutine), so a hard stall still drops the WS via the hub's 90s
        keepalive; this thread makes the stall diagnosable and the cadence
        drift-free, and the on-the-second tick resumes with no missed beat the
        moment the loop unblocks.
        """
        while not stop_event.is_set():
            try:
                ts = round(time.time(), 6)
                msg = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "HEARTBEAT", "data": {}}
                }
                frame = self._encode_frame(msg)
            except Exception as e:  # noqa: BLE001 — encode is sync; never kill the thread
                logger.warning("Heartbeat encode failed: %s", e)
                if stop_event.wait(30.0):
                    return
                continue
            try:
                fut = asyncio.run_coroutine_threadsafe(websocket.send(frame), loop)
                fut.result(timeout=self.HEARTBEAT_SEND_DEADLINE_S)
            except concurrent.futures.TimeoutError:
                # The event loop didn't process the send within the deadline →
                # it's blocked on sync I/O somewhere. The send stays pending and
                # completes (or fails) when the loop unblocks; the hub's 90s WS
                # keepalive is the backstop. Surface the stall so it's diagnosable
                # instead of a silent last_seen gap.
                logger.warning(
                    "Event loop stalled — heartbeat send did not complete in %.0fs "
                    "(a sync-I/O call is likely blocking the loop). The WS keepalive "
                    "may drop this connection; the send will complete when the loop "
                    "unblocks.", self.HEARTBEAT_SEND_DEADLINE_S)
            except (websockets.exceptions.ConnectionClosed, OSError, ConnectionError) as e:
                logger.debug("Heartbeat send failed; letting main loop reconnect: %s", e)
                return
            except RuntimeError as e:
                # Loop is closing/stopped (connection teardown) — exit cleanly.
                logger.debug("Heartbeat thread: loop unavailable (%s)", e)
                return
            except Exception as e:  # noqa: BLE001
                logger.warning("Heartbeat thread error: %s", e)
                return
            if stop_event.wait(30.0):
                return

    def _create_spoke_tasks(self, websocket) -> list:
        """Subclasses override to add long-lived per-connection async tasks
        (e.g. a telemetry relay loop) that run alongside the heartbeat/log-relay
        tasks. Returned tasks are cancelled and awaited when the connection
        closes. Default: no extra tasks."""
        return []

    def apply_backpressure(self, level: int, coalesce: bool = False,
                           min_interval_s: float = 0.0) -> None:
        """Honor the hub's LM_BACKPRESSURE slow-down signal.

        The design pushes the merge work to the SPOKE: on level>0 a module
        should coalesce/merge its outbound updates locally (latest-wins, combine
        adjacent snapshots that are ~identical) and raise its send cadence to at
        least ``min_interval_s``. This base implementation just RECORDS the
        signal (so any send loop can consult ``self._bp_min_interval`` /
        ``self._bp_level``); domain modules override to do the real conflation.

        level: 0 resume · 1 this spoke is the offender · 2 fleet-wide."""
        self._bp_level = int(level)
        self._bp_coalesce = bool(coalesce)
        self._bp_min_interval = max(0.0, float(min_interval_s))
        if level:
            logger.info("backpressure ENGAGED (level=%d, min_interval=%.1fs) — "
                        "coalescing outbound locally", level, self._bp_min_interval)
        else:
            logger.info("backpressure RELEASED — resuming normal cadence")

    def _bp_send_interval(self, base_period: float) -> float:
        """A send loop's effective period under backpressure: the larger of its
        normal cadence and the hub-requested ``min_interval_s``. No-op (returns
        ``base_period``) when not throttled."""
        return max(base_period, getattr(self, "_bp_min_interval", 0.0))

    # --- Per-command concurrency (see Main Message Loop above) --------------
    # Tunable via env so an overloaded spoke can be adjusted without a code
    # change. Defaults: 8 concurrent handlers, 64 in-flight (waiting + running).
    def _max_concurrent_commands(self) -> int:
        try:
            return max(1, int(os.environ.get("LM_SPOKE_MAX_CONCURRENT_COMMANDS", "8")))
        except Exception:
            return 8

    def _max_inflight_commands(self) -> int:
        try:
            return max(1, int(os.environ.get("LM_SPOKE_MAX_INFLIGHT_COMMANDS", "64")))
        except Exception:
            return 64

    async def _send_cmd_result(self, websocket, corr_id, result, send_lock) -> None:
        """Build + send one COMMAND_RESULT ack. Serialized by ``send_lock`` so
        concurrent handlers don't interleave WS frames. A send failure (hub
        disconnected mid-handle) is logged at DEBUG and swallowed — the receive
        loop's outer finally owns teardown."""
        ts = round(time.time(), 6)
        resp = {
            "correlation_id": corr_id,
            "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                       "sender_id": self.spoke_id, "destination_id": "hub"},
            "payload": {"type": "COMMAND_RESULT", "data": result}
        }
        _wire = self._encode_frame(resp)
        try:
            async with send_lock:
                await websocket.send(_wire)
        except Exception as e:  # noqa: BLE001 — socket closed mid-handle
            logger.debug("failed to send COMMAND_RESULT for %s: %s", corr_id, e)

    async def _handle_one_command(self, websocket, cmd_type, data, corr_id,
                                  send_lock, sem) -> None:
        """Handle one hub command concurrently and send its COMMAND_RESULT ack.

        Isolated from the receive loop so a slow handler cannot block reading
        or acking the next command. The semaphore bounds concurrent execution;
        any exception is caught and returned as a clean ERROR ack so one bad
        command can't tear down the hub websocket. Preserves the prior serial
        dispatch order: system command → module match → first-module fallback →
        ``*_GET_STATUS`` get_status() fallback.
        """
        async with sem:
            result: Optional[Dict[str, Any]] = None
            handled_by_module = None
            try:
                # First, try handling as a system command
                result = await self.handle_system_command(cmd_type, data)

                # Route to the appropriate module if not handled by system
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
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.exception("Unhandled error dispatching %s", cmd_type)
                result = {"status": "ERROR", "message": f"{type(e).__name__}: {e}"}
            await self._send_cmd_result(websocket, corr_id, result, send_lock)

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
        # 15 min by default — the [heartbeat] line is a coarse module-alive signal
        # for BugFixer, not liveness (the 30s transport HEARTBEAT drives the hub's
        # spoke-down traffic light + alerting). A once-a-minute line was just log
        # noise. Override with LM_HEARTBEAT_INTERVAL_S if faster triage is wanted.
        interval = 900
        try:
            interval = max(10, int(os.environ.get("LM_HEARTBEAT_INTERVAL_S", "900")))
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
        # Hub liveness probe: _install_active_connection pings an existing
        # same-key connection to tell a half-open zombie (no reply) from a
        # live-but-paused spoke (replies) before deciding to evict. Echo the
        # nonce in the COMMAND_RESULT so the hub's inbound dispatch resolves the
        # exact ping waiter. Cheap + non-mutating, so it runs even under load
        # (a spoke too busy to reply within the hub's 2s probe window is treated
        # as a zombie — the correct call, since it isn't making progress).
        if cmd_type == "HUB_PING":
            return {"status": "SUCCESS", "nonce": data.get("nonce")}

        # Remote Console (WebUI → troubleshooting). The hub only ever dispatches
        # RUN_COMMAND after gating on Global-Admin + the remote_exec.enabled knob;
        # ``allow_shell`` mirrors the WebUI "Debug (shell)" toggle. The frame is
        # HMAC-signed by the authenticated hub, so a spoke trusts it exactly like
        # SPOKE_UPDATE. Runs off the event loop (subprocess) so a slow command
        # never stalls the shared spoke/role loop; the runner enforces the
        # allowlist (when not shell), a timeout, and an output cap.
        if cmd_type == "RUN_COMMAND":
            try:
                from ..command_runner import run_local_command
            except ImportError:  # bare-module path (production: core/src on sys.path)
                from command_runner import run_local_command  # type: ignore
            res = await asyncio.to_thread(
                run_local_command,
                data.get("command", ""),
                bool(data.get("allow_shell", False)),
                float(data.get("timeout", 30.0) or 30.0),
            )
            return {"status": "SUCCESS", "result": res}
        # The hub's Agents tile / cs-bridge fan GET_AGENTS out to spokes. Answer it
        # HERE for every spoke so it's never routed to a module — a non-agent
        # module (nw/netbox/dns/dhcp/ldap/...) or a role sub-spoke would otherwise
        # return "not supported by <module>" as an ERROR that spams the hub Error
        # Log. Genuine agent hosts have a populated connected_agents; module/role
        # spokes have {} or a shim → a benign empty list. Fields are preserved
        # verbatim (minus the non-serializable ws), so agent-hosting spokes report
        # the same data their module handler did.
        if cmd_type == "GET_AGENTS":
            ca = getattr(self, "connected_agents", None) or {}
            pa = getattr(self, "pending_agents", None) or {}
            agents = []
            for aid, info in ca.items():
                entry = {k: v for k, v in (info or {}).items() if k != "ws"}
                entry["agent_id"] = aid
                entry.setdefault("hostname", aid)
                entry.setdefault("version", "unknown")
                entry.setdefault("status", "connected")
                agents.append(entry)
            pending = [{"agent_id": aid, "status": "pending"} for aid in pa]
            return {"status": "SUCCESS", "agents": agents, "pending_agents": pending}

        if cmd_type in ("SPOKE_SET_LOG_LEVEL", "SET_LOG_LEVEL"):
            enabled = data.get("enabled", False)
            level = set_log_level(enabled)
            logger.info(f"Log level set to {logging.getLevelName(level)}")
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

        if cmd_type == "CLEAR_LOGS":
            # WebUI "Clear Logs" — truncate every on-disk /var/log/lm/*.log on
            # this spoke/agent box in place (O_TRUNC, same inode) so the open
            # RotatingFileHandlers keep writing at offset 0 instead of
            # detaching to a stale inode and losing every future line. The
            # hub clears its OWN in-memory relay view (agent_logs/hub.logs)
            # separately; this only touches this box's disk. Off the event
            # loop because os.listdir + N open()s can block on a slow/fsync-y
            # filesystem, and CLEAR_LOGS is fire-and-forget, not request/reply
            # the operator is waiting on. In-memory deques are NOT cleared
            # here — the spoke doesn't keep one (its logs relay up; the hub
            # holds the buffer the UI reads).
            files = await asyncio.to_thread(truncate_log_files)
            logger.info("[diag] CLEAR_LOGS: truncated %d log file(s)", len(files))
            return {"status": "SUCCESS", "truncated": files}

        # Unified status command - works for all spokes by calling module.get_status()
        # This is the preferred way for the Hub to request status from any spoke.
        if cmd_type == "SPOKE_GET_STATUS":
            return await self._get_module_status()

        if cmd_type == "SPOKE_UPDATE":
            repo_url = data.get("repo_url")
            if not repo_url:
                return {"status": "ERROR", "message": "Missing repo_url for update"}
            # lm/core source (optional). When the hub threads core_repo_url, the
            # spoke also pulls its /opt/lm(.git|/core/.git) checkout in the same
            # update so a core/src change reaches it via the button/auto-update
            # instead of a CLI `git -C /opt/lm pull` + restart. Absent on older
            # hubs / air-gapped deploys with update_sources.hub blank → no core
            # pull (behavior == today). See _perform_self_update_sync.
            core_repo_url = data.get("core_repo_url")
            core_branch = data.get("core_branch")
            # The git fetch/pull below can take anywhere from seconds to minutes
            # on a slow/rate-limited link. Run it off the event loop thread —
            # this handler used to call subprocess.run(...) inline, which froze
            # EVERY other coroutine (all other command handling, GET_AGENTS
            # polling, VM actions, etc.) for the whole duration, since asyncio
            # is single-threaded. That looked like the whole spoke going
            # unresponsive (in-flight requests timing out at the hub) each time
            # a new commit landed. See _perform_self_update_sync.
            #
            # Single-flight guard: the hub's mailbox retries UNACKED commands
            # at 5s/15s/60s (messaging/mailbox.py retry_intervals). Because the
            # ack only returns when the full git pull completes, a slow link
            # makes the mailbox re-deliver SPOKE_UPDATE — and without this
            # guard each re-delivery spawned a CONCURRENT git pull in
            # /opt/lm/<mod> (the "Performing update ... 3× in 20s" storm seen
            # on cs-svr-02). to_thread frees the event loop while the first
            # run executes, so a re-delivered duplicate arrives here while
            # the flag is set and short-circuits with an immediate ack —
            # which the mailbox read as the original being delivered, ending
            # the retry loop. The first call still returns its real result
            # (or os._exit(3)s the process); the flag is a no-op across a
            # hard exit.
            if getattr(self, "_spoke_update_in_progress", False):
                logger.info("SPOKE_UPDATE already in progress; "
                            "ignoring duplicate re-delivery.")
                return {"status": "SUCCESS",
                        "message": "update already in progress"}
            self._spoke_update_in_progress = True
            self._draining = True  # hub queues request/reply pushes; we os._exit at the end
            try:
                return await asyncio.to_thread(
                    self._perform_self_update_sync, repo_url,
                    core_repo_url=core_repo_url, core_branch=core_branch,
                    reason="spoke-update")
            finally:
                self._spoke_update_in_progress = False
                # Reaching here means _perform_self_update_sync RETURNED without
                # os._exit(3) — a non-exit path: "already up to date", known-bad
                # commit skipped, or a git error. The exit path os._exit(3)s from
                # the worker thread (killing the whole process), so this finally
                # never runs when an exit is coming. Clear _draining so the
                # process resumes normal hub request/reply AND the code-drift
                # watchdog stops skipping (``if self._draining or
                # _spoke_update_in_progress: continue``). Otherwise a no-op
                # SPOKE_UPDATE leaves _draining stuck True for the process
                # lifetime, permanently blinding the drift watchdog to a later
                # HEAD advance — the pulled-but-not-restarted trap.
                self._draining = False

        if cmd_type == "SPOKE_SET_HUB_SECRET":
            new_secret = data.get("hub_secret")
            if new_secret:
                self.hub_secrets.insert(0, new_secret)
                self.hub_secrets = self.hub_secrets[:3] # Window of 3
                self._persist_hub_secret(new_secret)
                logger.info(f"Hub secret updated for {self.spoke_id}. Current window size: {len(self.hub_secrets)}")
                return {"status": "SUCCESS", "message": "Hub secret updated successfully"}
            return {"status": "ERROR", "message": "Missing hub_secret in data"}

        if cmd_type == "SPOKE_SET_WATCHDOG":
            # Fleet-wide hub-contact watchdog config, pushed by the hub on every
            # (re)connect and on each WebUI save. Persist it locally so it applies
            # even after a restart/reboot when the hub is unreachable — that's the
            # scenario the watchdog exists for. The running _hub_contact_watchdog
            # task re-reads this file each tick, so enable/disable + retune take
            # effect without a restart.
            wd = data or {}
            cfg = {"enabled": bool(wd.get("enabled", False))}
            for k in ("service_s", "reboot_s", "reboot_grace_s", "sleep_s", "max_runs"):
                if wd.get(k) is not None:
                    cfg[k] = wd[k]
            self._hcw_save_config(cfg)
            logger.info("SPOKE_SET_WATCHDOG: hub-contact watchdog %s (service@%ss reboot@%ss).",
                        "ENABLED" if cfg["enabled"] else "disabled",
                        cfg.get("service_s", "def"), cfg.get("reboot_s", "def"))
            return {"status": "SUCCESS", "enabled": cfg["enabled"]}

        if cmd_type == "SPOKE_SET_HUB_URL":
            # Hub-initiated repoint: the operator changed the hub's external
            # URL/DNS name in Setup → Spokes & Agents (global_config["hub"][
            # "url"]) and the hub is pushing the new address so pinned remote
            # spokes/agents reconnect to it instead of dying on the retired old
            # name. The hub sends this on every (re)connect (push_config_to_spoke
            # reconcile path) AND once per save (push_hub_url_to_all_spokes
            # fan-out via push_or_queue_to_spoke, which expects an ack — hence
            # the deferred-exit below so the SUCCESS ack clears the mailbox
            # BEFORE the process restarts, instead of stranding the message as
            # an unacked retry like SPOKE_UPDATE does).
            #
            # Guards (return SUCCESS, no restart):
            #   * loopback/localhost current pin — a co-located spoke dialing
            #     loopback is still correct after the hub's PUBLIC name moves;
            #     repointing it to the public URL could break same-box routing.
            #   * the ``auto``/empty/None sentinel — an auto-discovering spoke
            #     already re-resolves on every reconnect and will follow the
            #     hub's new mDNS/DNS advertisement on its own; pinning it would
            #     remove that self-healing.
            #   * already on the requested URL (after normalization) —
            #     idempotent no-op. This is what makes the reconcile-on-every-
            #     connect path safe: apply once → restart → reconnect → pushed
            #     URL == current → no-op. No restart loop.
            new_url = (data.get("hub_url") or "").strip()
            if not new_url:
                return {"status": "ERROR", "message": "Missing hub_url in data"}
            new_norm = self._normalize_hub_url(new_url)
            if not new_norm or new_norm == "auto":
                return {"status": "ERROR",
                        "message": "Invalid hub_url (empty or 'auto' sentinel)"}
            cur = self.hub_url
            if self._hub_url_is_loopback(cur):
                logger.info(
                    "SPOKE_SET_HUB_URL: current hub URL is loopback (%s); "
                    "skipping repoint to %s (co-located spoke stays on "
                    "loopback).", cur, new_norm)
                return {"status": "SUCCESS",
                        "message": "skipped (loopback) — co-located spoke keeps "
                                   "dialing loopback"}
            if cur in ("", "auto", None):
                logger.info(
                    "SPOKE_SET_HUB_URL: current hub URL is the auto sentinel; "
                    "skipping repoint to %s (auto-discovery keeps self-healing "
                    "and will follow the hub's new advertisement).", new_norm)
                return {"status": "SUCCESS",
                        "message": "skipped (auto) — spoke keeps auto-discovering"}
            if new_norm == self._normalize_hub_url(cur):
                logger.debug("SPOKE_SET_HUB_URL: already on %s; no-op.", new_norm)
                return {"status": "SUCCESS", "message": "already current"}

            # Apply: persist the new URL to .env so the systemd unit's
            # EnvironmentFile re-reads it on relaunch (ExecStart … --hub
            # $HUB_URL — install_agent.sh), then exit NON-ZERO so systemd
            # Restart=always (agent) / on-failure (spokes) relaunches us dialed
            # to the new address. The exit is deferred 0.5s so this handler's
            # SUCCESS ack is sent first (clearing any mailbox retry).
            logger.warning(
                "SPOKE_SET_HUB_URL: repointing %s → %s; restarting to reconnect "
                "to the new hub address.", cur, new_norm)
            self._persist_secret_to_env("HUB_URL", new_norm)
            self.hub_url = new_norm  # in case the deferred exit is interrupted
            self._draining = True  # hub queues request/reply pushes during the exit window
            asyncio.create_task(self._deferred_restart_exit())
            return {"status": "SUCCESS",
                    "message": f"repointing to {new_norm}; restarting to reconnect"}

        if cmd_type == "SPOKE_UPDATE_SESSION_KEY":
            new_secret = data.get("secret")
            if new_secret:
                self.secret = new_secret
                self.signer = MessageSigner(new_secret)
                self._persist_session_secret(new_secret)
                logger.info(f"Session key updated for {self.spoke_id}")
                # Replay encrypted frames buffered during the bootstrap race
                # (decoded before this handler armed self.secret). Fire-and-
                # forget: THIS command's ack goes out first, then the drain
                # dispatches the replayed frames concurrently through the same
                # bounded-concurrency path as live ones.
                if self._pending_encrypted_frames:
                    _t = asyncio.create_task(self._drain_pending_encrypted())
                    self._drain_tasks.add(_t)
                    _t.add_done_callback(self._drain_tasks.discard)
                return {"status": "SUCCESS", "message": "Session key updated successfully"}
            return {"status": "ERROR", "message": "Missing secret in data"}

        if cmd_type == "SPOKE_SET_HOSTNAME":
            new_hostname = data.get("hostname")
            if not new_hostname:
                return {"status": "ERROR", "message": "Missing hostname in data"}

            try:
                logger.info(f"Updating system hostname to: {new_hostname}")
                # 1. Set the hostname (timeout — a stuck sudo/hostnamectl would
                # otherwise block this async handler on the spoke loop indefinitely).
                subprocess.run(["sudo", "hostnamectl", "set-hostname", new_hostname],
                                check=True, timeout=15)

                # 2. Update /etc/hosts to prevent sudo/etc lag (replace 127.0.1.1 entry)
                # This is a simple sed replacement for the 127.0.1.1 line commonly found in Debian/Ubuntu
                subprocess.run(
                    ["sudo", "sed", "-i", f"s/127.0.1.1[[:space:]]*.*/127.0.1.1 {new_hostname}/", "/etc/hosts"],
                    check=True, timeout=10
                )

                return {"status": "SUCCESS", "message": f"Hostname updated to {new_hostname}"}
            except Exception as e:
                logger.error(f"SPOKE_SET_HOSTNAME failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        if cmd_type == "SPOKE_GET_MTLS_STATUS":
            # Hub queries this spoke's mTLS material presence for the readiness
            # card (System → Hub Status). Returns mtls.status() — the same dict
            # the hub's own readiness check uses, so the card can render a
            # per-spoke green/amber dot. Read-only; no side effects.
            try:
                from security import mtls as _mtls
                return {"status": "SUCCESS", "mtls": _mtls.status()}
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"mtls status unavailable: {e}"}

        if cmd_type == "SPOKE_SET_MTLS_MATERIALS":
            # Hub-pushed mTLS materials: the LE chain (CA bundle) + the wildcard
            # client cert/key, so this spoke can mutually verify with the hub
            # once mTLS is enabled. Transport-layer (like SPOKE_SET_HUB_SECRET /
            # SPOKE_SET_HUB_URL), so handled here on the base — EVERY spoke dials
            # the hub, so every spoke needs these, not just cert-capable ones
            # (the per-device INSTALL_CERT only reaches CERT_CAPABLE_MODULES).
            # Writes to the spoke's cert dir (next to LM_TLS_CERT), persists the
            # paths to .env, registers them in the runtime registry (so the
            # spoke→hub client leg picks them up on the NEXT reconnect, no
            # restart needed for that leg), and restarts ONLY if material
            # changed so the /ws/agent SERVER leg re-arms apply_server_client_auth
            # (its SSL context is built once at startup). Carries a private key,
            # same as INSTALL_CERT already does over this signed channel — no
            # new exposure. Push-state idempotency (material_hash) keeps restarts
            # to cert-renewal cadence (~60–90 days), not hourly.
            return await self._handle_set_mtls_materials(data)

        if cmd_type == "SPOKE_SET_MTLS_CLIENT_CERT":
            # Hub-Local-CA clientAuth cert minted for THIS spoke's mTLS CLIENT
            # identity to the hub (public CAs no longer issue clientAuth). Install
            # it as the client cert ONLY — the server/WebUI cert is untouched.
            return await self._handle_set_mtls_client_cert(data)

        if cmd_type == "SPOKE_CLEAR_MTLS_CLIENT_CERT":
            return await self._handle_clear_mtls_client_cert(data)

        return None

    async def _handle_clear_mtls_client_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Revocation: delete this spoke's mTLS CLIENT cert/key + clear the runtime
        materials so the next reconnect presents NOTHING (cert-less), and restart to
        drop the current connection. Server/WebUI cert untouched."""
        if getattr(self, "parent_spoke_id", ""):
            return {"status": "SUCCESS", "message": "skipped — role sub-spoke"}
        cert_dir = self._mtls_material_dir()
        removed = False
        # The spoke→hub client identity now lives in mtls-hub-client.* (see
        # _handle_set_mtls_client_cert); clear those. The legacy mtls-client.* names
        # are cleared too for spokes that predate the split.
        for p in (os.path.join(cert_dir, "mtls-hub-client.crt"),
                  os.path.join(cert_dir, "mtls-hub-client.key"),
                  os.path.join(cert_dir, "mtls-client.crt"),
                  os.path.join(cert_dir, "mtls-client.key")):
            try:
                if os.path.exists(p):
                    os.remove(p)
                    removed = True
            except Exception:  # noqa: BLE001
                pass
        try:
            self._persist_secret_to_env("LM_MTLS_HUB_CLIENT_CERT", "")
            self._persist_secret_to_env("LM_MTLS_HUB_CLIENT_KEY", "")
            self._persist_secret_to_env("LM_MTLS_CLIENT_CERT", "")
            self._persist_secret_to_env("LM_MTLS_CLIENT_KEY", "")
        except Exception:  # noqa: BLE001
            pass
        try:
            from security import mtls as _mtls
            _mtls.set_runtime_materials(client_cert="", client_key="")
        except Exception:  # noqa: BLE001
            pass
        logger.info("SPOKE_CLEAR_MTLS_CLIENT_CERT: cleared mTLS client cert for %s "
                    "(revoked) — restarting cert-less", self.spoke_id)
        if removed:
            self._draining = True
            asyncio.create_task(self._deferred_restart_exit())
        return {"status": "SUCCESS", "message": "mTLS client cert cleared (revoked)"}

    async def _handle_set_mtls_client_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply ``SPOKE_SET_MTLS_CLIENT_CERT``: write the hub-issued clientAuth cert
        + key as this spoke's spoke→hub mTLS CLIENT identity and restart on change so
        the client leg re-presents immediately.

        DEDICATED files (``mtls-hub-client.crt``/``.key``, env
        ``LM_MTLS_HUB_CLIENT_CERT``/``KEY``) — NOT the shared ``mtls-client.crt`` that
        ``SPOKE_SET_MTLS_MATERIALS`` (the /ws/agent-leg materials) writes. They used to
        collide on the same file: a cert-distribution push (INSTALL_CERT →
        SET_MTLS_MATERIALS) would clobber the hub-CA clientAuth cert with the
        agent-leg cert, the spoke would then present THAT to the hub, the hub rejected
        it, and the spoke fell off the fleet (connected but invisible). Keeping the
        hub-leg identity in its own file makes the two independent. Leaves LM_MTLS_CA
        + the server cert alone (the WebUI cert stays LE-issued)."""
        if getattr(self, "parent_spoke_id", ""):
            return {"status": "SUCCESS",
                    "message": "skipped — role sub-spoke; parent carries the mTLS client cert"}
        cert = (data.get("cert") or "").strip()
        key = (data.get("key") or "").strip()
        if not cert or not key:
            return {"status": "ERROR", "message": "missing cert/key"}
        cert_dir = self._mtls_material_dir()
        cc_path = os.path.join(cert_dir, "mtls-hub-client.crt")
        ck_path = os.path.join(cert_dir, "mtls-hub-client.key")
        changed = False
        try:
            changed |= self._mtls_write_if_changed(
                cc_path, cert if cert.endswith("\n") else cert + "\n", 0o644)
            changed |= self._mtls_write_if_changed(
                ck_path, key if key.endswith("\n") else key + "\n", 0o600)
            self._persist_secret_to_env("LM_MTLS_HUB_CLIENT_CERT", cc_path)
            self._persist_secret_to_env("LM_MTLS_HUB_CLIENT_KEY", ck_path)
        except Exception as e:  # noqa: BLE001
            logger.warning("SPOKE_SET_MTLS_CLIENT_CERT: write to %s failed: %s", cert_dir, e)
            return {"status": "ERROR", "message": f"write failed: {e}"}
        if changed:
            logger.info("SPOKE_SET_MTLS_CLIENT_CERT: installed hub-CA mTLS client cert "
                        "for %s — restarting to present it", self.spoke_id)
            self._draining = True
            asyncio.create_task(self._deferred_restart_exit())
            return {"status": "SUCCESS",
                    "message": "hub-CA mTLS client cert installed; restarting to present it"}
        logger.info("SPOKE_SET_MTLS_CLIENT_CERT: mTLS client cert up to date for %s", self.spoke_id)
        return {"status": "SUCCESS", "message": "hub-CA mTLS client cert up to date (no change)"}

    async def _handle_set_mtls_materials(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply ``SPOKE_SET_MTLS_MATERIALS``: write CA + client cert/key to the
        spoke's cert dir, persist paths to .env, register runtime materials, and
        restart only on a real change. See the handler comment for the rationale."""
        # Role sub-spokes (RoleConnection) share their parent agent's process,
        # .env, cert dir, and /ws/agent listener — the parent agent IS the mTLS
        # transport endpoint and receives its own push. Applying here would
        # write the same files the parent already wrote AND os._exit(3) the
        # whole shared agent (once per loaded role). The hub excludes role
        # sub-spokes from the fan-out (spoke_parent_map); this guard is the
        # belt-and-suspenders so a stray push can't restart a shared agent.
        if getattr(self, "parent_spoke_id", ""):
            logger.debug("SPOKE_SET_MTLS_MATERIALS: skipping role sub-spoke %s "
                          "(parent %s carries the materials)", self.spoke_id,
                          self.parent_spoke_id)
            return {"status": "SUCCESS",
                    "message": "skipped — role sub-spoke; parent agent carries mTLS materials"}
        ca_bundle = (data.get("ca_bundle") or "").strip()
        client_cert = (data.get("client_cert") or "").strip()
        client_key = (data.get("client_key") or "").strip()
        if not ca_bundle:
            return {"status": "ERROR", "message": "missing ca_bundle"}
        cert_dir = self._mtls_material_dir()
        ca_path = os.path.join(cert_dir, "mtls-ca.pem")
        cc_path = os.path.join(cert_dir, "mtls-client.crt")
        ck_path = os.path.join(cert_dir, "mtls-client.key")
        changed = False
        try:
            changed |= self._mtls_write_if_changed(ca_path, ca_bundle, 0o644)
            self._persist_secret_to_env("LM_MTLS_CA", ca_path)
            if client_cert and client_key:
                changed |= self._mtls_write_if_changed(cc_path, client_cert, 0o644)
                changed |= self._mtls_write_if_changed(ck_path, client_key, 0o600)
                self._persist_secret_to_env("LM_MTLS_CLIENT_CERT", cc_path)
                self._persist_secret_to_env("LM_MTLS_CLIENT_KEY", ck_path)
        except Exception as e:  # noqa: BLE001
            logger.warning("SPOKE_SET_MTLS_MATERIALS: write to %s failed: %s",
                           cert_dir, e)
            return {"status": "ERROR", "message": f"write failed: {e}"}
        # Register with the runtime registry so the next client_context() call
        # (the next spoke→hub reconnect) uses the new paths immediately, even
        # before .env is re-read on restart.
        try:
            from security import mtls as _mtls
            _mtls.set_runtime_materials(
                ca=ca_path,
                client_cert=cc_path if (client_cert and client_key) else None,
                client_key=ck_path if (client_cert and client_key) else None)
        except Exception:  # noqa: BLE001
            pass
        what = "CA + client cert/key" if (client_cert and client_key) else "CA bundle"
        if changed:
            logger.info("SPOKE_SET_MTLS_MATERIALS: installed %s for %s — restarting "
                        "to arm the /ws/agent server leg", what, self.spoke_id)
            self._draining = True  # hub queues request/reply during the exit window
            asyncio.create_task(self._deferred_restart_exit())
            return {"status": "SUCCESS",
                    "message": f"mTLS {what} installed; restarting to arm verification"}
        logger.info("SPOKE_SET_MTLS_MATERIALS: %s up to date for %s (no change)",
                    what, self.spoke_id)
        return {"status": "SUCCESS",
                "message": f"mTLS {what} up to date (no change)"}

    def _mtls_material_dir(self) -> str:
        """Directory to write mTLS materials into — the same dir as the spoke's
        ``LM_TLS_CERT`` (its server cert, e.g. /opt/lm/cs/certs), so the CA +
        client cert/key live alongside the cert they verify. Falls back to a
        ``certs`` dir under the repo root when the spoke has no server cert
        (loopback / cert-less spokes), creating it (0700)."""
        cert = os.environ.get("LM_TLS_CERT", "").strip()
        if cert:
            d = os.path.dirname(os.path.abspath(cert)) or "."
            os.makedirs(d, exist_ok=True)
            return d
        d = os.path.join(self._repo_root(), "certs")
        os.makedirs(d, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return d

    @staticmethod
    def _mtls_write_if_changed(path: str, content: str, mode: int) -> bool:
        """Atomically write ``content`` to ``path`` at ``mode`` ONLY when it
        differs from the current file (returns True if changed / created).
        Same-dir temp + os.replace for atomicity; same-dir required for
        os.replace to stay on one filesystem. Skips the write (returns False)
        when the file already has this exact content — so an idempotent re-push
        (hourly loop before push-state catches up, or a reconnect re-trigger)
        doesn't trigger a needless restart."""
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    if f.read() == content:
                        return False
            except OSError:
                pass  # unreadable → treat as changed and overwrite
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
        return True

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

    def _machine_fingerprint(self) -> str:
        """A stable per-MACHINE id, used to detect a cloned .env (identity copied
        onto a different physical box). ``/etc/machine-id`` first (regenerated per
        clone by most provisioning / cloud-init), then the SMBIOS/DMI product UUID
        as a fallback. Returns '' if neither is readable — binding is then skipped
        (fail-open; we never re-mint on an unreadable fingerprint)."""
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id",
                     "/sys/class/dmi/id/product_uuid"):
            try:
                with open(path) as f:
                    v = f.read().strip()
                if v:
                    return v
            except Exception:
                continue
        return ""

    def _ensure_install_uuid(self) -> str:
        """Returns this spoke's stable install UUID, minting + persisting it on first start.

        MACHINE-BOUND (defends against cloned spokes stepping on each other): the
        UUID is pinned to this box's machine fingerprint via ``INSTALL_UUID_MACHINE``.
        A VM clone copies the whole .env — INSTALL_UUID *and* the secret — so without
        this the clone would present the ORIGIN's UUID, the hub would treat it as a
        "reimage" of the origin, and the two boxes collapse onto one identity and
        flap. Here, if a cloned .env lands on a DIFFERENT machine (stored fingerprint
        != this box), we mint a FRESH UUID and drop the copied ``HUB_SECRET`` so the
        clone re-onboards as its OWN identity instead of impersonating the origin.
        This makes prep-for-imaging optional: a clone self-heals on first boot.

        A missing stored fingerprint on an existing UUID = a pre-binding install
        (UUID predates this feature): we backfill the fingerprint and KEEP the UUID
        (it is NOT a clone). We trust only what lands on disk: a failed write returns
        '' so a write failure never yields a volatile identity across boots.
        """
        cur_fp = self._machine_fingerprint()
        existing = self._read_env_value("INSTALL_UUID")
        if existing:
            stored_fp = self._read_env_value("INSTALL_UUID_MACHINE")
            if cur_fp and stored_fp and stored_fp != cur_fp:
                logger.warning(
                    "INSTALL_UUID %s… was minted on a different machine "
                    "(fingerprint %s… != this box %s…) — cloned .env detected; "
                    "minting a fresh identity + dropping the copied HUB_SECRET so "
                    "this clone onboards as itself and cannot step on the origin.",
                    existing[:8], stored_fp[:8], cur_fp[:8])
                new_uuid = str(uuid.uuid4())
                self._persist_secret_to_env("INSTALL_UUID", new_uuid)
                self._persist_secret_to_env("INSTALL_UUID_MACHINE", cur_fp)
                # Drop the origin's hub secret so the clone re-onboards (and is
                # re-approved) as a distinct spoke rather than authenticating as
                # the box it was cloned from.
                self._persist_secret_to_env("HUB_SECRET", "")
                return self._read_env_value("INSTALL_UUID")
            if cur_fp and not stored_fp:
                # Pre-binding install — adopt this machine as the binding, keep UUID.
                self._persist_secret_to_env("INSTALL_UUID_MACHINE", cur_fp)
            return existing
        new_uuid = str(uuid.uuid4())
        self._persist_secret_to_env("INSTALL_UUID", new_uuid)
        if cur_fp:
            self._persist_secret_to_env("INSTALL_UUID_MACHINE", cur_fp)
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

    def _encode_frame(self, msg) -> str:
        """Serialize + sign ``msg`` into the wire form ``<sig>.<body>`` (body
        serialized ONCE, signed over those exact bytes). Unsigned (empty sig)
        during bootstrap (no signer yet).

        H4: before signing, AEAD-encrypt ``payload.data`` of secret-bearing
        outbound frames when the hub is encryption-capable (encrypt data → build
        body → HMAC-sign the encrypted body → send). The AEAD key is
        ``self.secret`` (the same key that signs). For an ``AGENT_RELAY_UP``
        envelope, the OUTER payload stays plaintext (the hub reads its routing
        fields) but a NESTED ``original_payload.payload`` whose type is secret-
        bearing is encrypted in place (refinement #2 — CS_TOKEN_RESULT, whose
        data carries a Proxmox API token, rides inside AGENT_RELAY_UP). ``enc``
        is additive; a legacy hub ignores it. ``getattr`` so harnesses that
        bypass ``__init__`` (no ``hub_enc_capable``) default to plaintext."""
        if isinstance(msg, dict):
            payload = msg.get("payload")
            if (isinstance(payload, dict) and getattr(self, "hub_enc_capable", False)
                    and self.secret and encryption_enabled()):
                ptype = payload.get("type")
                if ptype in ENCRYPTED_TYPES:
                    wrap(self.secret, payload)
                elif ptype == "AGENT_RELAY_UP":
                    _orig = (payload.get("data") or {}).get("original_payload") or {}
                    inner = _orig.get("payload")
                    if (isinstance(inner, dict)
                            and inner.get("type") in ENCRYPTED_TYPES):
                        wrap(self.secret, inner)
        return encode_frame(self.signer, msg)

    def _decode_frame(self, wire: str):
        """Split ``<sig>.<body>``, verify the RECEIVED body bytes directly, and
        parse ONCE. Returns ``(msg_dict, ok)`` (``ok=False`` → caller drops it).

        Bootstrap (no session secret yet): unsigned frames are accepted so the
        onboarding handshake (APPROVAL_REQUIRED / APPROVED / HUB_OK / heartbeats)
        can proceed before the spoke adopts its key. A signed frame with a bad
        HMAC is rejected even here.

        Post-bootstrap (session secret + signer set): the hub holds the spoke's
        session key and signs EVERY outbound frame, so an unsigned inbound frame
        here is a MITM injection (e.g. a forged SPOKE_UPDATE pulling an attacker
        repo_url → RCE, SPOKE_UPDATE_SESSION_KEY, or SPOKE_SET_HUB_SECRET). Drop
        unsigned non-heartbeat frames — mirrors the hub's own policy in
        main.py (an unsigned non-heartbeat from a spoke that has adopted its key
        is dropped). An unsigned HEARTBEAT is still accepted so a hub that
        momentarily omits the signature on a keepalive can't wedge the liveness
        loop. A signed frame is verified; bad HMAC → reject."""
        sig, body = split_frame(wire)
        has_key = bool(self.secret and self.signer)
        if has_key and sig:
            if not self.signer.verify_bytes(body.encode(), sig):
                return None, False
        if has_key and not sig:
            # Post-bootstrap unsigned frame — parse to inspect the type, then
            # accept ONLY a heartbeat. Anything else is an injection.
            try:
                preview = json.loads(body)
            except Exception:
                return None, False
            if (preview.get("payload") or {}).get("type") != "HEARTBEAT":
                logger.debug(
                    "Unsigned non-heartbeat dropped (session key active) type=%s",
                    (preview.get("payload") or {}).get("type"))
                return None, False
            return preview, True
        try:
            msg = json.loads(body)
        except Exception:
            return None, False
        # H4: AEAD-decrypt payload.data of an inbound secret-bearing frame
        # after HMAC verify, before dispatch reads data. ``self.secret`` is the
        # AEAD key — for SPOKE_UPDATE_SESSION_KEY it is still the PRE-rotation
        # key at decode time (the new key is installed later in dispatch), which
        # is exactly the key the hub encrypted the push with. A marked-encrypted
        # frame with no secret, or one that won't decrypt (tamper / wrong key /
        # malformed b64/JSON → InvalidTag or ValueError), is dropped — ciphertext
        # is never dispatched. Plaintext/legacy frames pass through untouched.
        _payload = msg.get("payload", {})
        if is_encrypted(_payload):
            if not self.secret:
                # Bootstrap race: the hub sent SPOKE_UPDATE_SESSION_KEY and this
                # encrypted frame back-to-back; the session-key handler (a
                # concurrent task) hasn't armed self.secret yet, so we can't
                # AEAD-decrypt here. DEFER instead of drop — buffer the raw wire
                # and replay it through _decode_frame once the key is armed (see
                # _drain_pending_encrypted, fired from the SPOKE_UPDATE_SESSION_KEY
                # handler). Cap + prune so a key that never arrives can't wedge
                # the buffer; the normal case drains within milliseconds.
                # getattr → test harnesses / subclasses that bypass __init__
                # (no buffer attr) fall back to the legacy drop (return ok=False).
                buf = getattr(self, "_pending_encrypted_frames", None)
                if isinstance(buf, list):
                    buf.append((wire, time.time()))
                    if len(buf) > 64:
                        buf.pop(0)
                        logger.warning(
                            "Encrypted frame deferred >64 times without a "
                            "session key; dropping oldest (spoke=%s)",
                            self.spoke_id)
                    else:
                        logger.debug(
                            "Encrypted frame from hub but no session secret "
                            "yet — deferring for replay (spoke=%s)",
                            self.spoke_id)
                else:
                    logger.debug(
                        "Encrypted frame from hub but no session secret — "
                        "dropping (spoke=%s)", self.spoke_id)
                return None, False
            try:
                unwrap(self.secret, _payload)
            except (InvalidTag, ValueError) as e:
                logger.debug("Dropping tampered/undecryptable frame from hub: %s", e)
                return None, False
        return msg, True

    async def _drain_pending_encrypted(self) -> None:
        """Replay encrypted frames buffered during the bootstrap race (see
        ``_decode_frame``). Called once ``SPOKE_UPDATE_SESSION_KEY`` arms
        ``self.secret``. Re-decodes each buffered raw wire frame (the AEAD key
        is now set → decode succeeds) and dispatches it through the same
        bounded-concurrency path as a live inbound frame. Stale entries (the
        key took too long / never came) are pruned, not held forever.

        Dispatch is sequential-await (encrypted config frames are few and
        fast); the shared semaphore still bounds total concurrency against any
        live receive-loop dispatches racing this drain. The drain runs as its
        own task so the SPOKE_UPDATE_SESSION_KEY ack goes out immediately."""
        if not self._pending_encrypted_frames or not self._decrypt_dispatch_ctx:
            return
        websocket, send_lock, sem = self._decrypt_dispatch_ctx
        pending = self._pending_encrypted_frames
        self._pending_encrypted_frames = []
        now = time.time()
        for wire, enq in pending:
            if now - enq > 30.0:
                logger.warning(
                    "Dropping deferred encrypted frame — session key not armed "
                    "within 30s (spoke=%s)", self.spoke_id)
                continue
            # Re-decode now that self.secret is armed. A still-failing decode
            # (tamper / key rotated again mid-drain) is dropped — the hub
            # re-pushes on the next config change or reconnect.
            msg, ok = self._decode_frame(wire)
            if not ok:
                continue
            payload = msg.get("payload", {}) or {}
            cmd_type = payload.get("type")
            if not cmd_type:
                continue
            data = payload.get("data", {})
            corr_id = msg.get("header", {}).get("message_id")
            logger.debug("Replaying deferred encrypted %s (spoke=%s)",
                         cmd_type, self.spoke_id)
            await self._handle_one_command(
                websocket, cmd_type, data, corr_id, send_lock, sem)