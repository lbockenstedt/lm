"""Hub self-update + spoke/agent update pipeline (extracted from main.py).

These were methods of ``LabManagerHub`` (``get_local_version``,
``get_remote_version``, ``_is_git_repo``, ``_download_update``, ``_git_update``,
``perform_update``, ``update_spokes_only``, ``update_agents_only``) — ~500 lines
of git/version/tarball update logic plus the spoke/agent SPOKE_UPDATE fan-out.
They are gathered here as a **mixin** (``UpdatePipelineMixin``) that
``LabManagerHub`` inherits, so the methods keep operating on ``self`` (the Hub
instance) with **zero call-site changes** — ``hub.perform_update()`` /
``self.get_local_version()`` resolve exactly as before via inheritance.

The mixin must NOT import ``main`` (that would create a cycle, since ``main``
imports this module). It imports only stdlib, ``httpx``, the
``messaging.protocol`` / ``update_recovery`` leaves, and its own logger (same
``"Hub"`` name as main, so log config is unified). ``_save_sessions`` is
lazy-imported from ``api`` at the one call site that needs it, to avoid a
module-level ``api`` dependency.

Audience: Hub developers. See ``docs/user_manual.md`` for the update flow;
``update_recovery.py`` for the snapshot/rollback companion; [[webui-update-recovery-gap]].
"""

import os
import io
import time
import uuid
import shutil
import tarfile
import tempfile
import asyncio
import subprocess
import datetime as _dt
import logging
from typing import Any, Dict, Optional

import httpx

from messaging.protocol import Message, MessageHeader, MessagePayload
from update_recovery import (
    is_version_bad,
    clear_bad_versions_older_than,
    snapshot_code,
    write_pending,
    clear_pending,
)

logger = logging.getLogger("Hub")  # same name as main.py — shared log config

# module_type → update_sources config key (key space #2). NOTE "firewall" →
# "opnsense" here, NOT "opn". Used to look up global_config["update_sources"][k].
_UPDATE_SOURCE_MODULE_KEY = {
    "hypervisor": "pxmx", "firewall": "opnsense", "nac": "cppm",
    "directory": "ldap", "ipam": "netbox", "simulation": "cs",
}

# spoke_id substring → update_sources config key. "opn" → "opnsense" (the
# config key), the opposite of _PUSH_CONFIG_PREFIX_MAP — because this feeds an
# update_sources lookup, not a push_config branch.
_UPDATE_SOURCE_PREFIX_MAP = {
    'pxmx': 'pxmx', 'opn': 'opnsense', 'cs': 'cs',
    'cppm': 'cppm', 'netbox': 'netbox', 'ldap': 'ldap',
}


class UpdatePipelineMixin:
    """Hub self-update + spoke/agent update methods, extracted from
    ``LabManagerHub``. All methods operate on ``self`` (a fully-initialised Hub
    instance at runtime) so they read ``self.state`` / ``self.mailbox`` /
    ``self.approved_modules`` / etc. exactly as when they lived on the Hub."""

    async def get_local_version(self) -> str:
        """Return the locally-installed Hub version from the VERSION file, or ``"unknown"`` on error."""
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            with open(version_path, "r") as f:
                return f.read().strip()
        except Exception as e:
            logger.error(f"Failed to read local version: {e}")
            return "unknown"

    async def get_remote_version(self) -> str:
        try:
            config = self.state.get_global_config()
            sources = config.get("update_sources", {})
            repo_url = sources.get("hub", "https://github.com/lbockenstedt/lm")

            if "github.com" in repo_url:
                parts = repo_url.rstrip("/").split("github.com/")
                if len(parts) == 2:
                    path = parts[1].removesuffix(".git")
                    version_url = f"https://raw.githubusercontent.com/{path}/main/VERSION"
                else:
                    logger.warning(f"Malformed GitHub URL: {repo_url}. Falling back to default.")
                    version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"
            else:
                logger.warning(f"Non-GitHub repository URL configured ({repo_url}). Version check requires GitHub Raw format. Falling back to default.")
                version_url = "https://raw.githubusercontent.com/lbockenstedt/lm/main/VERSION"

            logger.info(f"Fetching remote version from: {version_url}")

            async with httpx.AsyncClient() as client:
                resp = await client.get(version_url)
                if resp.status_code == 200:
                    return resp.text.strip()
                else:
                    logger.error(f"Failed to fetch remote version: HTTP {resp.status_code}")
        except Exception as e:
            logger.error(f"Error fetching remote version: {e}")
        return "unknown"

    def _is_git_repo(self, path: str) -> bool:
        """Check if the given path is a git repository (contains a .git directory or is git rev-parse valid)."""
        git_dir = os.path.join(path, ".git")
        if os.path.isdir(git_dir) or os.path.isfile(git_dir):
            return True
        # Fallback: ask git itself (handles worktrees / bare configs)
        try:
            result = subprocess.run(
                ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except Exception:
            return False

    async def _download_update(self, hub_root: str, repo_url: str, branch: str) -> bool:
        """
        Alternative update mechanism for non-git installations.
        Downloads a tarball from GitHub and extracts it over the existing install.
        Returns True only if the local VERSION actually changes to match the remote.
        """
        tmp_dir = None
        try:
            if "github.com" in repo_url:
                parts = repo_url.rstrip("/").split("github.com/")
                if len(parts) != 2 or not parts[1]:
                    logger.error(f"Malformed GitHub URL for tarball update: {repo_url}")
                    return False
                repo_path = parts[1].rstrip("/")
                if repo_path.endswith(".git"):
                    repo_path = repo_path[:-4]
                tarball_url = f"https://github.com/{repo_path}/archive/refs/heads/{branch}.tar.gz"
            else:
                logger.error(f"Non-GitHub repository URL configured ({repo_url}). Cannot perform download-based update.")
                return False

            logger.info(f"Downloading update tarball from: {tarball_url}")
            async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
                resp = await client.get(tarball_url)
                if resp.status_code != 200:
                    logger.error(f"Failed to download update tarball: HTTP {resp.status_code}")
                    return False

                tar_bytes = io.BytesIO(resp.content)

            tmp_dir = tempfile.mkdtemp(prefix="lm_update_")
            with tarfile.open(fileobj=tar_bytes, mode="r:gz") as tar:
                # Prevent path traversal (zip-slip) attacks
                safe_members = []
                for m in tar.getmembers():
                    member_path = os.path.normpath(m.name)
                    if member_path.startswith("..") or os.path.isabs(member_path):
                        logger.warning(f"Skipping unsafe member in tarball: {m.name}")
                        continue
                    safe_members.append(m)
                tar.extractall(path=tmp_dir, members=safe_members)

            # Locate the extracted top-level directory
            entries = os.listdir(tmp_dir)
            if not entries:
                logger.error("Update tarball is empty.")
                return False
            extracted_root = os.path.join(tmp_dir, entries[0])
            if not os.path.isdir(extracted_root):
                logger.error(f"Update tarball top-level entry is not a directory: {entries[0]}")
                return False

            # Merge extracted contents into hub root. Never delete existing dirs —
            # rmtree would kill the running venv (breaking httpx/SSL mid-update).
            # Skip runtime-only dirs that must not be overwritten.
            top_preserve = {"data", "state", "cache", ".git", "__pycache__"}
            sub_ignore = shutil.ignore_patterns("venv", "__pycache__", "*.pyc", "*.pyo")
            for item in os.listdir(extracted_root):
                if item in top_preserve:
                    continue
                src = os.path.join(extracted_root, item)
                dst = os.path.join(hub_root, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=sub_ignore)
                else:
                    shutil.copy2(src, dst)

            # Verify update actually took effect
            new_local_v = await self.get_local_version()
            remote_v = await self.get_remote_version()
            if new_local_v == remote_v and new_local_v != "unknown":
                logger.info(f"Hub successfully updated via tarball download to v{new_local_v}.")
                return True
            else:
                logger.warning(
                    f"Tarball update applied but local version ({new_local_v}) "
                    f"does not match remote ({remote_v}). Update verification failed."
                )
                return False
        except Exception as e:
            logger.error(f"Error during download-based update: {e}", exc_info=True)
            return False
        finally:
            if tmp_dir and os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

    async def _git_update(self, hub_root: str, hub_repo: str, branch: str) -> bool:
        """
        Performs a git-based update. Returns True only if the update actually
        changed the local version (verified post-update).
        """
        try:
            await asyncio.create_subprocess_shell(f"git config --global --add safe.directory {hub_root}")

            update_cmd = (
                f"cd {hub_root} && "
                f"git remote set-url origin {hub_repo} && "
                f"git pull --rebase --autostash origin {branch}"
            )

            process = await asyncio.create_subprocess_shell(
                update_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            err_msg = stderr.decode().strip()
            out_msg = stdout.decode().strip()

            if process.returncode != 0:
                logger.error(f"Hub git pull failed (rc={process.returncode}): {err_msg}")
                return False

            # CRITICAL: verify the version actually changed to confirm success.
            new_local_v = await self.get_local_version()
            remote_v = await self.get_remote_version()
            if new_local_v == remote_v and new_local_v != "unknown":
                logger.info(f"Hub successfully updated via git to v{new_local_v}.")
                return True
            else:
                logger.warning(
                    f"Git update returned success but local version ({new_local_v}) "
                    f"does not match remote ({remote_v}). Update verification failed."
                )
                return False
        except Exception as e:
            logger.error(f"Unexpected error during git-based Hub update: {e}", exc_info=True)
            return False

    # ── Spoke-update fan-out helpers ────────────────────────────────────────
    # perform_update / update_spokes_only / update_agents_only all fan out
    # SPOKE_UPDATE messages to approved spokes. The module_key resolve (from
    # spoke_id via a prefix map), the Message construction, and the mailbox.push
    # are identical in shape; the log markers, the triggered/skipped result
    # formatting, the 'qa' prefix, the opnsense→opn legacy fallback, and the
    # agent-only filter differ and stay inline at each call site. Two small
    # helpers share the identical core so the three fan-out loops become short
    # inline tails (better a clean shared core + 3 small inline tails than 3
    # forced-fit bugs).

    def _resolve_module_key(
        self, spoke_id: str, mtype: str, prefix_map: Dict[str, str]
    ) -> Optional[str]:
        """Resolve the ``update_sources`` config key for a spoke: try the
        module-type registry (``_UPDATE_SOURCE_MODULE_KEY``) first, then fall
        back to the first substring match against ``prefix_map``. Returns the
        key string (e.g. ``"pxmx"``, ``"opnsense"``) or ``None``.

        Used by perform_update (with ``_UPDATE_SOURCE_PREFIX_MAP``) and
        update_spokes_only (with that map plus ``'qa': 'qa'``). update_agents_only
        does not resolve — it draws its repo_url directly from
        ``update_sources["agent"]``, so it does not call this helper.
        """
        module_key = _UPDATE_SOURCE_MODULE_KEY.get(mtype)
        if not module_key:
            for prefix, key in prefix_map.items():
                if prefix in spoke_id:
                    module_key = key
                    break
        return module_key

    async def _push_spoke_update(
        self,
        spoke_id: str,
        repo_url: str,
        branch: str,
        msg_type: str = "SPOKE_UPDATE",
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Exception]:
        """Build a SPOKE_UPDATE ``Message`` and push it to the spoke's mailbox.

        Shared core of the three update fan-out paths — the Message construction
        and ``mailbox.push`` are identical across all three; the log markers and
        triggered/skipped result formatting differ and stay inline at each call
        site. Returns ``None`` on success or the caught ``Exception`` on mailbox
        failure, so the caller can emit its own error log marker and append its
        own skipped/error entry with the exact format each path uses.
        """
        data: Dict[str, Any] = {"repo_url": repo_url, "branch": branch}
        if extra_data:
            data.update(extra_data)
        msg = Message(
            header=MessageHeader(
                message_id=str(uuid.uuid4()),
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id,
            ),
            payload=MessagePayload(type=msg_type, data=data),
        )
        try:
            await self.mailbox.push(msg, self.send_to_spoke)
            return None
        except Exception as e:
            return e

    async def perform_update(self, force=False):
        """
        Checks for updates and performs either a git pull (for git installs) or a
        tarball-based download (for non-git installs) if a new version is available.
        Also triggers updates for all approved modules (connected or offline).
        """
        # Anti-lockout: ensure the first admin account always retains its
        # privileges and reconcile the two admin-flag forms (role + boolean)
        # across all admin users. Runs on every update so manual edits to state
        # files cannot permanently lock out the initial admin or leave an
        # admin's "System Admin" checkbox unset in the WebUI.
        if self.state.ensure_admin_lockout():
            self.state.save_state()

        logger.info(f"Running update check (force={force})...")
        local_v = await self.get_local_version()
        remote_v = await self.get_remote_version()

        logger.info(f"Update check: local={local_v}, remote={remote_v}, force={force}")

        self.state.update_global_config({"last_update_ts": time.time()})
        self.state.save_state()

        def _ver(v: str):
            try:
                return tuple(int(x) for x in v.strip().split("."))
            except Exception:
                return (0, 0, 0)

        hub_updated = False
        if force or _ver(remote_v) > _ver(local_v):
            try:
                hub_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

                config = self.state.get_global_config()
                sources = config.get("update_sources", {})
                hub_repo = sources.get("hub", "https://github.com/lbockenstedt/lm")
                branch = config.get("global_branch", "main")

                # ── Recovery prelude ──────────────────────────────────────────
                # Skip a version that was rolled back after failing to boot. force
                # bypasses it (operator explicitly re-trying a known-bad version).
                # Stale bad entries older than this newer remote are cleared so a
                # "don't pull 1.0.9" marker doesn't block a forward move to 1.0.10.
                if not force and is_version_bad(remote_v):
                    logger.warning(
                        f"Remote v{remote_v} is marked bad after a failed boot; "
                        f"skipping auto-update (use ?force=true to retry)."
                    )
                else:
                    if not force and remote_v:
                        clear_bad_versions_older_than(remote_v)

                    # Snapshot core/src + WebUI *before* the swap so the root
                    # helper (lm-update-restart) can roll back if the new version
                    # fails to reach /status. The pending manifest tells it where
                    # the backup lives and which version to mark bad on rollback.
                    try:
                        ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
                        backup_dir = snapshot_code(hub_root, ts)
                        write_pending(backup_dir, local_v, remote_v, ts)
                    except Exception as _e:
                        logger.warning(
                            f"Pre-update snapshot failed (rollback disabled): {_e}"
                        )

                    # Check whether the installation directory is a git repository
                    is_git_repo = self._is_git_repo(hub_root)

                    if is_git_repo:
                        logger.info(f"Hub installation is a git repo. Attempting git-based update...")
                        hub_updated = await self._git_update(hub_root, hub_repo, branch)
                    else:
                        logger.info(
                            f"Hub installation directory {hub_root} is NOT a git repo. "
                            f"Using download-based (tarball) update mechanism."
                        )
                        hub_updated = await self._download_update(hub_root, hub_repo, branch)

                    if not hub_updated:
                        # Pull failed — local code is unchanged, so there is
                        # nothing to roll back to. Drop the pending manifest.
                        clear_pending()
                        logger.warning(
                            f"Hub update did NOT succeed. Local version remains {local_v} "
                            f"(target: {remote_v}). Will retry on next cycle."
                        )
            except Exception as e:
                logger.error(f"Unexpected error during Hub update: {e}", exc_info=True)
                hub_updated = False
                clear_pending()
        else:
            logger.info("Hub is already up to date. Skipping Hub pull.")

        update_results = []
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")

        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue

            mtype = self.spoke_module_types.get(spoke_id, "")
            # update-source config-key space — see _UPDATE_SOURCE_MODULE_KEY /
            # _UPDATE_SOURCE_PREFIX_MAP (firewall → "opnsense", NOT "opn"). The
            # prefix loop uses the dict VALUES (unlike push_config's loop, which
            # uses the keys) — so "opn" → "opnsense" is a real mapping here.
            module_key = self._resolve_module_key(spoke_id, mtype, _UPDATE_SOURCE_PREFIX_MAP)

            if module_key:
                repo_url = sources.get(module_key)
                if repo_url:
                    logger.info(f"Triggering update for spoke {spoke_id} from {repo_url} on branch {branch}...")
                    err = await self._push_spoke_update(spoke_id, repo_url, branch)
                    if err is None:
                        update_results.append(f"{spoke_id}: triggered")
                    else:
                        logger.error(f"Failed to push update for {spoke_id}: {err}")
                        update_results.append(f"{spoke_id}: failed")
                else:
                    update_results.append(f"{spoke_id}: no repo configured")
            else:
                update_results.append(f"{spoke_id}: unknown module type")

        logger.info(f"Spoke update results: {update_results}")

        if hub_updated:
            # Restart local in-repo spokes (dns/dhcp live inside the lm repo; they
            # are already updated by the hub git pull above and just need a restart).
            for local_svc in ("lm-dns", "lm-dhcp"):
                try:
                    subprocess.Popen(["sudo", "systemctl", "restart", local_svc])
                    logger.info(f"Restarting local spoke service {local_svc}")
                except Exception as _e:
                    logger.warning(f"Could not restart {local_svc}: {_e}")
            # Restart the hub from OUTSIDE its own cgroup so the restart
            # command survives lm.service being stopped. Calling
            # `systemctl restart lm` directly from here races the stop/start
            # against this process's cgroup and can strand the hub inactive
            # for ~16 min. /usr/local/bin/lm-update-restart uses
            # `systemd-run --no-block` to schedule the restart from a
            # transient unit owned by PID 1 (independent of lm.service), then
            # polls /status and rolls back the pre-swap snapshot if the new
            # version fails to boot (see core/src/update_recovery.py).
            logger.info("Hub was updated. Scheduling self-restart via transient unit...")
            # Flush the in-memory session store to disk so any login/logout since the
            # last save survives the restart (best-effort; save-on-mutation already
            # covers the common path, this closes the last-few-seconds window).
            try:
                from api import _save_sessions  # lazy: avoid a module-level api dep
                _save_sessions(self)
            except Exception as _e:
                logger.warning(f"Pre-restart session flush failed: {_e}")
            try:
                subprocess.Popen(["sudo", "-n", "/usr/local/bin/lm-update-restart"])
            except Exception as _e:
                logger.warning(f"Could not schedule hub self-restart: {_e}")
            return {"status": "success", "message": f"Updated Hub to v{remote_v} and triggered spoke updates. Server is restarting (rolled back automatically if it fails to boot)..."}

        return {"status": "checked", "message": f"Update successful. Hub is current at v{local_v}. {len(update_results)} spoke(s) updating to latest."}

    async def update_spokes_only(self):
        """Send SPOKE_UPDATE to every approved spoke without touching the Hub itself.

        Called by POST /setup/update/spokes — typically triggered by BugFixer after
        pushing a fix to GitHub so deployed services pick up the change before QA runs.
        """
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")

        # update-source config-key space, same as perform_update. The prefix map
        # adds "qa" → "qa" so a QA harness spoke can be pointed at a "qa" repo via
        # update_sources (perform_update intentionally omits qa — it doesn't
        # auto-update the test harness during a full hub update). See
        # _UPDATE_SOURCE_MODULE_KEY / _UPDATE_SOURCE_PREFIX_MAP.
        _upd_prefix_map = {**_UPDATE_SOURCE_PREFIX_MAP, 'qa': 'qa'}

        triggered = []
        skipped = []
        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue
            mtype = self.spoke_module_types.get(spoke_id, "")
            module_key = self._resolve_module_key(spoke_id, mtype, _upd_prefix_map)
            if not module_key:
                skipped.append(f"{spoke_id}: unknown module type")
                continue
            repo_url = sources.get(module_key)
            # Backward-compat: the Setup UI used to store the OPNsense repo URL
            # under the key "opn" while the hub looks it up as "opnsense". Honor
            # the legacy key so deployments that saved it before the fix still
            # self-update without a forced re-save of the Setup page.
            if not repo_url and module_key == "opnsense":
                repo_url = sources.get("opn")
            if not repo_url:
                skipped.append(f"{spoke_id}: no repo_url in update_sources.{module_key}")
                continue
            err = await self._push_spoke_update(spoke_id, repo_url, branch)
            if err is None:
                triggered.append(spoke_id)
                logger.info(f"SPOKE_UPDATE queued for {spoke_id} ({repo_url}@{branch})")
            else:
                logger.error(f"Failed to queue SPOKE_UPDATE for {spoke_id}: {err}")
                skipped.append(f"{spoke_id}: mailbox error — {err}")

        # Restart local in-repo spokes (dns/dhcp share the lm repo; they need a
        # service restart so they pick up the code the hub already pulled).
        for local_svc in ("lm-dns", "lm-dhcp"):
            try:
                subprocess.Popen(["sudo", "systemctl", "restart", local_svc])
                triggered.append(local_svc)
                logger.info(f"Restarting local spoke service {local_svc}")
            except Exception as _e:
                logger.warning(f"Could not restart {local_svc}: {_e}")
                skipped.append(f"{local_svc}: {_e}")

        summary = f"Triggered {len(triggered)} spoke(s): {', '.join(triggered) or 'none'}"
        if skipped:
            summary += f". Skipped: {'; '.join(skipped)}"
        logger.info(f"update_spokes_only complete — {summary}")
        return {"status": "ok", "triggered": triggered, "skipped": skipped, "message": summary}

    async def update_agents_only(self):
        """Send SPOKE_UPDATE to every approved *agent* (module_type == "agent").

        Mirrors update_spokes_only but filters to agent modules. Agents are
        generic (no per-type registry), so they all draw their repo_url from
        update_sources["agent"]; an agent is skipped if that source is unset.
        Triggered by BugFixer (via HUB_REQUEST TRIGGER_AGENT_UPDATES) after it
        pushes a fix, so deployed agents pick up the change before QA runs.
        """
        config = self.state.get_global_config()
        sources = config.get("update_sources", {})
        branch = config.get("global_branch", "main")
        repo_url = sources.get("agent")

        triggered = []
        skipped = []
        if not repo_url:
            # No agent update source configured — skip every agent with a clear reason.
            for spoke_id, approved in self.approved_modules.items():
                if not approved:
                    continue
                if self.spoke_module_types.get(spoke_id, "") == "agent":
                    skipped.append(f"{spoke_id}: no update_sources.agent repo_url")
            msg = "Skipped all agents: update_sources.agent not configured" if skipped else "No approved agents"
            logger.info(f"update_agents_only complete — {msg}")
            return {"status": "ok", "triggered": [], "skipped": skipped, "message": msg}

        for spoke_id, approved in self.approved_modules.items():
            if not approved:
                continue
            if self.spoke_module_types.get(spoke_id, "") != "agent":
                continue
            err = await self._push_spoke_update(spoke_id, repo_url, branch)
            if err is None:
                triggered.append(spoke_id)
                logger.info(f"SPOKE_UPDATE queued for agent {spoke_id} ({repo_url}@{branch})")
            else:
                logger.error(f"Failed to queue SPOKE_UPDATE for agent {spoke_id}: {err}")
                skipped.append(f"{spoke_id}: mailbox error — {err}")

        summary = f"Triggered {len(triggered)} agent(s): {', '.join(triggered) or 'none'}"
        if skipped:
            summary += f". Skipped: {'; '.join(skipped)}"
        logger.info(f"update_agents_only complete — {summary}")
        return {"status": "ok", "triggered": triggered, "skipped": skipped, "message": summary}