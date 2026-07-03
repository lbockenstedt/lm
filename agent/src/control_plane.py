import asyncio
import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import List

# sys.path bootstrap: ``core`` is a PEP-420 namespace package living at the lm
# repo root (``/opt/lm/core``), and ``messaging.control_plane`` reaches back up
# to ``core.src.security.signer`` via a parent relative import (``..security``)
# that only resolves when ``messaging.control_plane`` is imported AS
# ``core.src.messaging.control_plane``. That requires the lm ROOT (not just
# core/src) on sys.path. The systemd unit sets PYTHONPATH=/opt/lm:/opt/lm/core/
# src:/opt/lm/agent/src, but a hand-launch (or a stale unit missing the root)
# would otherwise hit ``ModuleNotFoundError: No module named 'core'`` → fallback
# ``ImportError: attempted relative import beyond top-level package`` and the
# agent crash-loops (the lm-opnsense role-activation saga). Derive the root
# from this file's location (lm/agent/src/control_plane.py → up three) so the
# import works regardless of how the process was launched.
_LM_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

try:
    from core.src.messaging.control_plane import BaseControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane

from agent_spoke import GenericAgent, _ROLE_MAP

try:
    from logging_setup import configure_logging
except ImportError:
    try:
        from core.src.logging_setup import configure_logging
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
configure_logging()
logger = logging.getLogger("GenericAgentControlPlane")


def _lm_root_for(path: str) -> Path:
    """lm repo root from a file path: lm/agent/src/control_plane.py → up three."""
    return Path(path).resolve().parent.parent.parent


class RoleConnection(BaseControlPlane):
    """One independent hub connection per loaded role (multi-role agent).

    The base ``AgentControlPlane`` keeps its primary connection as
    ``module_type "agent"`` (the Generic Node control channel). Each loaded role
    opens a ``RoleConnection`` under ``spoke_id {base}-{role}`` with the role's
    ``module_type``, so the hub routes role commands to it via
    ``get_spoke_by_type`` exactly like any other spoke.

    Sub-spoke identity rules:
      * ``parent_spoke_id`` = the base agent id — sent in the auth frame so the
        hub can auto-approve this sub-spoke via the (already-approved) parent
        agent and bind it to the parent's tenant (see hub ``handle_connection``
        parent-auto-approve + ``_auto_approve_pending_subspokes``).
      * **No ``install_uuid``** is sent. The hub's clone-and-rename reconciler
        maps one install UUID → one spoke id (``install_uuid_index``); a
        same-box sub-spoke sharing the base's UUID would be treated as a rename
        of the base and clobber it. Clearing ``install_uuid`` skips correlation
        — the sub-spoke is identified by its spoke_id + parent claim instead.

    Secrets: a ``RoleConnection`` starts zero-touch (no secret) and is
    re-provisioned by the hub on every boot via parent-auto-approve
    (``approve_and_bind_spoke`` → ``SPOKE_UPDATE_SESSION_KEY``). It therefore
    does NOT persist its session secret / hub secret to ``.env`` (which it
    shares with the base agent) — overriding the persist hooks to no-ops avoids
    clobbering the base agent's ``SPOKE_SECRET`` / ``HUB_SECRET`` lines. The
    in-memory secret survives reconnects within one process; a process restart
    re-provisions fresh.
    """

    def __init__(self, role_name: str, base_id: str, hub_url: str,
                 role_instance, secret: str = None):
        _, _, mtype, _ = _ROLE_MAP[role_name]
        sub_id = f"{base_id}-{role_name}"
        super().__init__(sub_id, secret, hub_secret="", hub_url=hub_url)
        self.role_name = role_name
        self.base_id = base_id
        self.module_type = mtype
        self.parent_spoke_id = base_id
        # Sub-spokes must NOT carry the base's install UUID (see class docstring).
        self.install_uuid = ""
        # Suppress the one-time "Hub secrets not configured" warning per role —
        # sub-spokes intentionally run zero-touch and re-provision via the parent.
        self._hub_secret_warned = True
        # The role instance handles this connection's commands; registered under
        # the role name so BaseControlPlane's first-module fallback routes to it.
        self.register_module(role_name, role_instance)

    def get_service_name(self) -> str:
        # Same systemd unit as the base agent (one process hosts all roles).
        return "lm-agent"

    def start_updater_worker(self) -> None:
        """No-op: the base agent's updater worker handles self-update for the
        whole process. A per-role updater would N-fold git-pull /opt/lm and
        race the base; sub-spokes update via hub-driven SPOKE_UPDATE
        (handle_system_command pulls THIS role's sibling repo)."""
        return

    def _lm_root(self) -> Path:
        return _lm_root_for(__file__)

    async def handle_system_command(self, cmd_type: str, data: dict) -> object:
        """Intercept SPOKE_UPDATE so this role's connection pulls ITS sibling
        repo (e.g. /opt/lm/opnsense), not /opt/lm — the base handler pulls in
        CWD and would corrupt the wrong tree. In-repo roles (dns/dhcp, repo_url
        None) delegate to the base handler (their code ships in the lm repo).
        Everything else delegates to base."""
        if cmd_type == "SPOKE_UPDATE":
            repo_url = _ROLE_MAP[self.role_name][3]
            if repo_url:
                clone_dir = _ROLE_MAP[self.role_name][0].split("/")[0]
                return await self._update_sibling_repo(
                    repo_url, self._lm_root() / clone_dir)
            return await super().handle_system_command(cmd_type, data)
        return await super().handle_system_command(cmd_type, data)

    async def _update_sibling_repo(self, repo_url: str, repo_dir: Path) -> dict:
        """git pull this role's sibling repo and restart lm-agent if it changed.
        Mirrors the base SPOKE_UPDATE handler's pull+exit(3) restart
        (core/src/messaging/control_plane.py) but with cwd=repo_dir. A restart
        exits the whole agent process; the durable LOADED_ROLES set in .env
        (written by GenericAgent on LOAD/UNLOAD_ROLE) re-spawns every loaded
        role's RoleConnection on the next boot."""
        cwd = str(repo_dir)
        try:
            if not repo_dir.exists():
                return {"status": "ERROR",
                        "message": f"role repo not present at {cwd}"}
            logger.info("SPOKE_UPDATE: pulling role repo %s from %s…", cwd, repo_url)
            subprocess.run(["git", "remote", "set-url", "origin", repo_url],
                           cwd=cwd, check=True)
            subprocess.run(["git", "config", "pull.rebase", "true"],
                           cwd=cwd, check=True)
            subprocess.run(["git", "config", "rebase.autoStash", "true"],
                           cwd=cwd, check=True)
            self._run_git(["rebase", "--abort"], cwd)
            head_before = self._run_git(["rev-parse", "HEAD"], cwd).stdout.strip()
            subprocess.run(["git", "fetch", "origin"], cwd=cwd, check=True)
            pull = self._run_git(["pull", "--rebase", "--autostash", "origin"], cwd)
            if pull.returncode != 0:
                logger.warning("git pull --rebase failed (rc=%s); resetting hard to origin",
                               pull.returncode)
                branch = (self._run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd)
                          .stdout.strip() or "main")
                subprocess.run(["git", "rebase", "--abort"], cwd=cwd, check=False)
                subprocess.run(["git", "reset", "--hard", f"origin/{branch}"],
                               cwd=cwd, check=True)
            head_after = self._run_git(["rev-parse", "HEAD"], cwd).stdout.strip()
            if head_after != head_before:
                if self._prepare_service_restart(reason="spoke-update"):
                    await self._flush_log_relay_async()
                    os._exit(3)
                return {"status": "SUCCESS",
                        "message": f"Updated {cwd} from {repo_url}; restart skipped"}
            logger.debug("SPOKE_UPDATE: %s already up to date.", cwd)
            return {"status": "SUCCESS", "message": "Already up to date"}
        except subprocess.CalledProcessError as e:
            detail = (e.stderr or e.stdout or str(e)).strip() if hasattr(e, "stderr") else str(e)
            logger.error("SPOKE_UPDATE failed for %s: %s", cwd, detail)
            return {"status": "ERROR", "message": f"git operation failed: {detail}"}
        except Exception as e:
            logger.error("SPOKE_UPDATE failed for %s: %s", cwd, e)
            return {"status": "ERROR", "message": str(e)}

    # ── Secret persistence: no-ops (see class docstring) ──────────────────────
    def _persist_session_secret(self, new_secret: str) -> None:  # noqa: D401
        """No-op: sub-spokes re-provision via parent-auto-approve on each boot;
        persisting here would clobber the base agent's SPOKE_SECRET line."""
        return

    def _persist_hub_secret(self, new_secret: str) -> None:  # noqa: D401
        """No-op for the same reason as _persist_session_secret."""
        return

    def _extra_auth_fields(self) -> dict:
        """Inject ``parent_spoke_id`` into the WS auth frame so the hub can
        auto-approve this sub-spoke via the parent agent. BaseControlPlane
        merges this dict into the auth_payload it sends on connect."""
        return {"parent_spoke_id": self.parent_spoke_id}


class AgentControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-agent"

    def __init__(self, spoke_id, secret, hub_secret="", hub_url="",
                 startup_roles: List[str] = None, startup_role: str = ""):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        # --role (single, backward-compat) is an alias for --roles (comma-list).
        cli_roles = list(startup_roles or [])
        if startup_role and startup_role not in cli_roles:
            cli_roles.append(startup_role)
        self._cli_roles = [r for r in cli_roles if r and r in _ROLE_MAP]
        # Base agent connection stays module_type "agent" permanently — the
        # agent no longer morphs into a role; it HOSTS role sub-connections
        # (RoleConnection). Routing/approval/signing/SPOKE_UPDATE all key on
        # spoke_id per sub-spoke, so the hub needs no core change.
        self.module_type = "agent"

    def _resolve_startup_roles(self) -> List[str]:
        """Durable loaded-roles set for boot.

        CLI ``--roles`` seeds ``LOADED_ROLES`` in .env on first install;
        thereafter ``LOADED_ROLES`` (.env) is the source of truth so roles
        loaded at runtime (via LOAD_ROLE) survive a self-update restart (the
        RoleConnection SPOKE_UPDATE handler exits the whole process; on reboot
        this list re-spawns every role's connection). CLI roles win only when
        ``LOADED_ROLES`` is empty (first boot of a fresh install)."""
        persisted = [r for r in self._read_env_value("LOADED_ROLES").split(",")
                     if r.strip()]
        if not persisted and self._cli_roles:
            self._persist_secret_to_env("LOADED_ROLES", ",".join(self._cli_roles))
            return list(self._cli_roles)
        return persisted

    async def run(self):
        startup_roles = self._resolve_startup_roles()
        logger.info("Starting Generic Agent → %s  (roles=%s)", self.hub_url,
                    ",".join(startup_roles) or "none")
        agent = GenericAgent(self.spoke_id, {})
        # Back-reference so GenericAgent can read hub_url + .env helpers and
        # spawn RoleConnection sub-spokes on this loop on LOAD_ROLE.
        agent.control_plane = self
        self.register_module("agent", agent)
        # Seed startup roles (boot --roles + persisted LOADED_ROLES). Each
        # LOAD_ROLE installs deps, loads the role instance, and opens a
        # RoleConnection sub-spoke. Run as a task so the base connect proceeds
        # concurrently; the hub auto-approves sub-spokes once the base agent is
        # approved (parent-auto-approve handles either connect ordering).
        if startup_roles:
            async def _seed_startup_roles():
                for role in startup_roles:
                    try:
                        res = await agent.handle_command("LOAD_ROLE", {"role": role})
                        if isinstance(res, dict) and res.get("status") == "SUCCESS":
                            logger.info("Startup role %s loaded → %s",
                                        role, res.get("sub_spoke_id"))
                        else:
                            logger.warning("Startup role %s failed: %s", role, res)
                    except Exception:
                        logger.exception("Startup role %s load failed", role)
            asyncio.create_task(_seed_startup_roles())
        await super().run()


if __name__ == "__main__":
    import socket as _socket
    parser = argparse.ArgumentParser()
    # --id defaults to this host's short hostname, re-evaluated on every start.
    # A clone-only unit (install_agent.sh --clone) bakes NO --id, so each cloned
    # disk derives its spoke id from its OWN hostname at runtime (parity with the
    # leaf agent's clone-name fix) instead of inheriting the template's pinned
    # id. A pinned --id (full install) stays frozen.
    parser.add_argument("--id",     default=None)
    parser.add_argument("--secret", default=None,
                        help="Session secret. Omit for zero-touch provisioning — the hub will send it after admin approval.")
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",    required=True)
    parser.add_argument("--role",   default=os.environ.get("STARTUP_ROLE", ""),
                        help="Pre-load a single role at startup (backward-compat alias for --roles).")
    parser.add_argument("--roles",  default=os.environ.get("STARTUP_ROLES", ""),
                        help="Pre-load multiple roles at startup: comma-list, e.g. dns,dhcp.")
    args = parser.parse_args()

    if not args.id:
        args.id = _socket.gethostname().split(".")[0]

    startup_roles = [r for r in (args.roles or "").split(",") if r.strip()]
    cp = AgentControlPlane(args.id, args.secret, args.hub_secret, args.hub,
                           startup_roles=startup_roles,
                           startup_role=args.role)
    asyncio.run(cp.run())