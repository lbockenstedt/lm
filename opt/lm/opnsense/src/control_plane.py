import asyncio
import json
import uuid
import time
import websockets
import logging
import hmac
import hashlib
import subprocess
import os
import threading
import queue
from typing import Dict, Any, Type, Optional
from .protocol import Message, MessageHeader, MessagePayload
from ..security.signer import MessageSigner

logger = logging.getLogger("BaseControlPlane")


class _SpokeLogRelayHandler(logging.Handler):
    """Captures WARNING+ log records into a queue for async relay to the Hub."""

    def __init__(self, log_queue: queue.Queue):
        super().__init__(level=logging.WARNING)
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

    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None, hub_url: str = None):
        self.spoke_id = spoke_id
        self.secret = secret
        self.hub_secrets = [hub_secret] if hub_secret else []
        self.hub_url = hub_url
        self.modules: Dict[str, Any] = {}  # { module_name: BaseSpoke instance }
        self.signer = MessageSigner(secret) if secret else None
        self._updater_thread: Optional[threading.Thread] = None
        self._updater_stop = threading.Event()
        self._log_relay_queue: queue.Queue = queue.Queue(maxsize=500)
        self._log_relay_handler = _SpokeLogRelayHandler(self._log_relay_queue)
        logging.getLogger().addHandler(self._log_relay_handler)

    def register_module(self, name: str, module_instance: Any):
        """Registers a module to be handled by this control plane."""
        self.modules[name] = module_instance
        logger.info(f"Registered module: {name}")

    def _repo_root(self) -> str:
        """Resolve the repository working directory for git operations."""
        cwd = os.path.abspath(os.getcwd())
        if cwd.endswith("src"):
            cwd = os.path.dirname(cwd)
        return cwd

    def _ensure_git_pull_strategy(self, cwd: str) -> None:
        """
        Configure git so that `git pull` knows how to reconcile divergent
        branches. Without this, `git pull` exits with code 128 and the error
        `fatal: Need to specify how to reconcile divergent branches.` whenever
        the local and remote histories have diverged.

        We pin the strategy to rebase (with autostash) so self-update checks
        are deterministic and never leave the working tree in a merge state.
        """
        subprocess.run(["git", "config", "pull.rebase", "true"], cwd=cwd, check=False)
        subprocess.run(["git", "config", "pull.ff", "only"], cwd=cwd, check=False)
        subprocess.run(["git", "config", "rebase.autoStash", "true"], cwd=cwd, check=False)

    def _run_git(self, args, cwd: str, capture: bool = True) -> subprocess.CompletedProcess:
        """Helper to run a git command, capturing output for diagnostics."""
        return subprocess.run(
            ["git"] + args,
            cwd=cwd,
            text=True,
            capture_output=capture,
            check=False,
        )

    def perform_self_update_check(self) -> bool:
        """
        Performs a single self-update check.

        Fetches from origin and, if the local branch is behind, rebases on
        top of the remote using autostash. The pull strategy is configured
        up-front so divergent branches are reconciled automatically rather
        than failing with exit code 128.

        Returns True if a pull/rebase was attempted (caller may choose to
        restart the service), False otherwise.
        """
        try:
            cwd = self._repo_root()
            self._ensure_git_pull_strategy(cwd)

            fetch = self._run_git(["fetch", "origin"], cwd=cwd)
            if fetch.returncode != 0:
                logger.warning(
                    "Self-update check failed: git fetch error: %s",
                    (fetch.stderr or "").strip(),
                )
                return False

            # Determine the current branch's upstream tracking ref.
            branch = self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
            branch_name = (branch.stdout or "").strip()
            upstream_ref = f"origin/{branch_name}" if branch_name and branch_name != "HEAD" else "origin/HEAD"

            behind = self._run_git(
                ["rev-list", "--count", f"HEAD..{upstream_ref}"], cwd=cwd
            )
            try:
                behind_count = int((behind.stdout or "0").strip() or "0")
            except ValueError:
                behind_count = 0

            if behind_count <= 0:
                logger.debug("Self-update check: already up to date.")
                return False

            logger.info("Self-update check: %d new commit(s) upstream; pulling.", behind_count)
            pull = self._run_git(
                ["pull", "--rebase", "--autostash", "origin"], cwd=cwd
            )
            if pull.returncode != 0:
                logger.warning(
                    "Self-update check failed: git pull error: %s",
                    (pull.stderr or pull.stdout or "").strip(),
                )
                return False

            logger.info("Self-update check completed successfully.")
            return True
        except Exception as e:
            logger.warning("Self-update check failed: %s", e)
            return False

    def updater_worker(self):
        """
        Background worker thread that performs periodic self-update checks.
        Runs in its own thread to avoid blocking the async event loop.

        Note: ``time`` must be imported at module scope for this method to
        function. A previous regression omitted the import, causing the
        thread to crash immediately with ``NameError: name 'time' is not
        defined`` on the first ``time.sleep(3600)`` call.
        """
        logger.info("Updater worker started; polling every 3600s.")
        while not self._updater_stop.is_set():
            try:
                self.perform_self_update_check()
                # Wait up to 3600s, but wake early if we are asked to stop.
                if self._updater_stop.wait(timeout=3600):
                    break
            except Exception as e:
                logger.error(f"Updater worker encountered an error: %s", e)
                try:
                    if self._updater_stop.wait(timeout=60):
                        break
                except Exception:
                    break
        logger.info("Updater worker exiting.")

    def start_updater_worker(self):
        """Starts the updater worker as a daemon thread."""
        if self._updater_thread is not None and self._updater_thread.is_alive():
            logger.warning("Updater worker already running.")
            return
        self._updater_thread = threading.Thread(
            target=self.updater_worker,
            name="updater-worker",
            daemon=True,
        )
        self._updater_thread.start()
        logger.info("Updater worker thread launched.")

    def stop_updater_worker(self):
        """Signals the updater worker to stop and joins it briefly."""
        self._updater_stop.set()
        if self._updater_thread is not None:
            self._updater_thread.join(timeout=5.0)

    async def run(self):
        """Main loop for the control plane."""
        logger.info(f"Starting Control Plane in HUB MODE -> {self.hub_url}")

        # Kick off the background updater worker thread.
        self.start_updater_worker()

        async with websockets.connect(self.hub_url) as websocket:
            # 1. Spoke Authentication Handshake
            auth_payload = {"spoke_id": self.spoke_id}
            if self.secret:
                auth_payload["secret"] = self.secret

            await websocket.send(json.dumps(auth_payload, separators=(",", ":")))
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
                                hashlib.sha256,
                            ).hexdigest()
                            if hmac.compare_digest(expected_sig, signature):
                                verified = True
                                break

                        if verified:
                            logger.info("Hub identity verified successfully.")
                            await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(",", ":")))
                        else:
                            logger.error("Hub identity verification failed: Invalid signature for all known secrets.")
                            await websocket.close(1008, "Hub verification failed")
                            return
                    else:
                        logger.warning("Hub secrets not configured. Skipping Hub identity verification (Insecure).")
                        await websocket.send(json.dumps({"status": "HUB_OK"}, separators=(",", ":")))
                else:
                    logger.error(f"Unexpected response during Hub verification: {hub_proof.get('status')}")
                    await websocket.close(1008, "Mutual authentication failed")
                    return
            except Exception as e:
                logger.error(f"Hub verification timed out or failed: {e}")
                await websocket.close(1008, "Mutual authentication timed out")
                return

            # Heartbeat loop
            async def heartbeat():
                while True:
                    ts = round(time.time(), 6)
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "HEARTBEAT", "data": {}}
                    }
                    msg["signature"] = self._sign(msg)
                    await websocket.send(json.dumps(msg, separators=(",", ":")))
                    await asyncio.sleep(30)

            asyncio.create_task(heartbeat())
            asyncio.create_task(self._log_relay_task(websocket))

            # Main Message Loop
            async for message in websocket:
                msg = json.loads(message)
                if not self._verify_signature(msg):
                    continue

                payload = msg.get("payload", {})
                cmd_type = payload.get("type")
                data = payload.get("data", {})
                corr_id = msg.get("header", {}).get("message_id")

                # First, try handling as a system command
                result = await self.handle_system_command(cmd_type, data)

                # Route to the appropriate module if not handled by system
                if result is None:
                    for module_name, module in self.modules.items():
                        if cmd_type.startswith(module_name) or self._module_handles_command(module, cmd_type):
                            result = await module.handle_command(cmd_type, data)
                            break

                    if result is None and self.modules:
                        first_mod = list(self.modules.values())[0]
                        result = await first_mod.handle_command(cmd_type, data)

                ts = round(time.time(), 6)
                resp = {
                    "correlation_id": corr_id,
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": ts,
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "COMMAND_RESULT", "data": result}
                }
                resp["signature"] = self._sign(resp)
                await websocket.send(json.dumps(resp, separators=(",", ":")))

    async def _log_relay_task(self, websocket) -> None:
        """Drain the log queue and send WARNING/ERROR entries to the Hub as SPOKE_LOG."""
        while True:
            await asyncio.sleep(30)
            entries = []
            try:
                while True:
                    entries.append(self._log_relay_queue.get_nowait())
            except queue.Empty:
                pass
            if not entries:
                continue
            try:
                msg = {
                    "header": {
                        "message_id": str(uuid.uuid4()),
                        "timestamp": time.time(),
                        "sender_id": self.spoke_id,
                        "destination_id": "hub",
                    },
                    "payload": {"type": "SPOKE_LOG", "data": {"entries": entries}},
                }
                msg["signature"] = self._sign(msg)
                await websocket.send(json.dumps(msg, separators=(",", ":")))
            except Exception as e:
                logger.debug("Log relay send failed: %s", e)

    def _module_handles_command(self, module, cmd_type: str) -> bool:
        """Check if a module should handle a specific command type."""
        return True  # Default to true for now, let the module decide

    def get_service_name(self) -> str:
        """Returns the systemd service name for this spoke."""
        module_name = self.spoke_id.split("-")[0]
        return f"lm-{module_name}"

    async def handle_system_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Handles commands that affect the entire spoke system rather than a specific module."""
        if cmd_type == "SPOKE_SET_LOG_LEVEL":
            enabled = data.get("enabled", False)
            level = logging.DEBUG if enabled else logging.INFO
            logging.getLogger().setLevel(level)
            for name in logging.root.manager.loggerDict:
                logging.getLogger(name).setLevel(level)
            logger.info(f"Log level set to {logging.getLevelName(level)}")
            return {"status": "SUCCESS", "message": f"Log level set to {logging.getLevelName(level)}"}

        if cmd_type == "SPOKE_UPDATE":
            repo_url = data.get("repo_url")
            if not repo_url:
                return {"status": "ERROR", "message": "Missing repo_url for update"}

            try:
                cwd = self._repo_root()

                logger.info(f"Performing update in {cwd} from {repo_url}...")

                subprocess.run(["git", "remote", "set-url", "origin", repo_url], cwd=cwd, check=True)
                # Configure the pull strategy BEFORE pulling so divergent
                # branches are reconciled automatically instead of failing
                # with exit code 128 ("Need to specify how to reconcile
                # divergent branches.").
                self._ensure_git_pull_strategy(cwd)
                subprocess.run(["git", "fetch", "origin"], cwd=cwd, check=True)
                subprocess.run(["git", "pull", "--rebase", "--autostash", "origin"], cwd=cwd, check=True)

                service_name = self.get_service_name()
                logger.info(f"Restarting service {service_name}...")
                subprocess.Popen(["sudo", "systemctl", "restart", service_name])

                return {"status": "SUCCESS", "message": f"Updated from {repo_url} and triggered restart of {service_name}"}
            except subprocess.CalledProcessError as e:
                logger.error(f"SPOKE_UPDATE failed (git command exit code {e.returncode}): {e}")
                stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
                stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
                detail = (stderr or stdout or str(e)).strip()
                return {"status": "ERROR", "message": f"git operation failed: {detail}"}
            except Exception as e:
                logger.error(f"SPOKE_UPDATE failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        if cmd_type == "SPOKE_SET_HUB_SECRET":
            new_secret = data.get("hub_secret")
            if new_secret:
                self.hub_secrets.insert(0, new_secret)
                self.hub_secrets = self.hub_secrets[:3]  # Window of 3
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
                subprocess.run(["sudo", "hostnamectl", "set-hostname", new_hostname], check=True)
                subprocess.run(
                    ["sudo", "sed", "-i", f"s/127.0.1.1[[:space:]]*.*/127.0.1.1 {new_hostname}/", "/etc/hosts"],
                    check=True,
                )
                return {"status": "SUCCESS", "message": f"Hostname updated to {new_hostname}"}
            except Exception as e:
                logger.error(f"SPOKE_SET_HOSTNAME failed: {e}")
                return {"status": "ERROR", "message": str(e)}

        return None

    def _persist_session_secret(self, new_secret: str) -> None:
        """Writes the rotated session key back to .env so it survives spoke restarts."""
        try:
            env_path = os.path.join(self._repo_root(), ".env")
            if not os.path.exists(env_path):
                return
            with open(env_path, "r") as f:
                lines = f.readlines()
            updated = []
            found = False
            for line in lines:
                if line.startswith("SPOKE_SECRET="):
                    updated.append(f"SPOKE_SECRET={new_secret}\n")
                    found = True
                else:
                    updated.append(line)
            if not found:
                updated.append(f"SPOKE_SECRET={new_secret}\n")
            with open(env_path, "w") as f:
                f.writelines(updated)
            logger.info("Session key persisted to .env")
        except Exception as e:
            logger.warning("Failed to persist session key to .env: %s", e)

    def _sign(self, msg):
        return self.signer.sign(msg)

    def _verify_signature(self, msg):
        if not self.secret or not self.signer:
            return True
        return self.signer.verify(msg)