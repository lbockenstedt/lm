import asyncio
import argparse
import logging
import os
import subprocess
from pathlib import Path

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


class AgentControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-agent"

    def __init__(self, spoke_id, secret, hub_secret="", hub_url="", startup_role=""):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        self._startup_role = startup_role
        # Default module_type; overridden when a role is loaded
        self.module_type = "agent"
        if startup_role and startup_role in _ROLE_MAP:
            _, _, mtype = _ROLE_MAP[startup_role]
            self.module_type = mtype

    async def run(self):
        logger.info("Starting Generic Agent → %s  (role=%s)", self.hub_url,
                    self._startup_role or "none")
        config = {"role": self._startup_role} if self._startup_role else {}
        agent = GenericAgent(self.spoke_id, config)
        # Back-reference so the agent can request a module_type morph (LOAD/
        # UNLOAD_ROLE) → we update self.module_type and reconnect so the hub
        # re-registers it under the new type (see request_morph).
        agent.control_plane = self
        self.register_module("agent", agent)
        await super().run()

    # ── Morph: switch between "agent" and a role's module_type ────────────────

    def _lm_root(self) -> Path:
        """lm repo root: lm/agent/src/control_plane.py → up three."""
        return Path(__file__).resolve().parent.parent.parent

    async def request_morph(self, module_type: str) -> None:
        """Switch the agent's hub-visible module_type and reconnect so the hub
        re-registers it. Called by GenericAgent on LOAD_ROLE/UNLOAD_ROLE.

        module_type is the role's type (e.g. "firewall") or "agent" to revert.
        The reconnect is delayed so the in-flight command response (LOAD_ROLE
        SUCCESS / UNLOAD_ROLE SUCCESS) flushes before the WS closes; the close
        breaks _connect_and_serve's async-with → run() reconnects → the new
        auth_payload carries the new module_type → the hub overwrites
        spoke_module_types[spoke_id] (main.py:1511, approval keyed by spoke_id).
        """
        self.module_type = module_type or "agent"
        logger.info("Morphing module_type → %s; reconnecting to re-register.",
                    self.module_type)
        self._morph_task = asyncio.create_task(self._reconnect_after_morph())

    async def _reconnect_after_morph(self) -> None:
        try:
            await asyncio.sleep(0.2)  # let the command response send first
            ws = getattr(self, "_hub_ws", None)
            if ws is not None:
                await ws.close()
        except Exception as e:
            logger.warning("reconnect-after-morph close failed: %s", e)

    # ── SPOKE_UPDATE: pull the RIGHT repo for the active role ─────────────────

    async def handle_system_command(self, cmd_type: str, data: dict) -> object:
        """Intercept SPOKE_UPDATE so a morphed-as-sibling agent pulls its
        sibling repo (e.g. /opt/lm/opnsense), not /opt/lm (the lm repo) — the
        base handler pulls in CWD which resolves to /opt/lm and would corrupt
        it with the sibling's tree. No-role / in-repo roles (dns/dhcp) delegate
        to the base handler (pulls /opt/lm, which holds their code). Everything
        else delegates to base."""
        if cmd_type == "SPOKE_UPDATE":
            agent = self.modules.get("agent")
            role_name = getattr(agent, "_role_name", None) if agent else None
            repo_url = _ROLE_MAP[role_name][3] if role_name in _ROLE_MAP else None
            if role_name and repo_url:
                clone_dir = _ROLE_MAP[role_name][0].split("/")[0]
                return await self._update_sibling_repo(
                    repo_url, self._lm_root() / clone_dir)
            return await super().handle_system_command(cmd_type, data)
        return await super().handle_system_command(cmd_type, data)

    async def _update_sibling_repo(self, repo_url: str, repo_dir: Path) -> dict:
        """git pull a morphed role's sibling repo and restart lm-agent if it
        changed. Mirrors the base SPOKE_UPDATE handler's pull+exit(3) restart
        (core/src/messaging/control_plane.py:713) but with cwd=repo_dir."""
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--id",     required=True)
    parser.add_argument("--secret", default=None,
                        help="Session secret. Omit for zero-touch provisioning — the hub will send it after admin approval.")
    parser.add_argument("--hub-secret", nargs='?', default="", const="")
    parser.add_argument("--hub",    required=True)
    parser.add_argument("--role",   default=os.environ.get("STARTUP_ROLE", ""),
                        help="Pre-load a role at startup: dns, dhcp, ...")
    args = parser.parse_args()

    cp = AgentControlPlane(args.id, args.secret, args.hub_secret, args.hub, args.role)
    asyncio.run(cp.run())
