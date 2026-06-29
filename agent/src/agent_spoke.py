import asyncio
import importlib.util
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

logger = logging.getLogger("GenericAgent")

# Role directory is at <lm-repo-root>/<role-name>/src/
# e.g. /opt/lm/dns/src/dns_spoke.py → DNSSpoke
_ROLE_MAP = {
    "dns":  ("dns/src/dns_spoke.py",   "DNSSpoke",  "dns"),
    "dhcp": ("dhcp/src/dhcp_spoke.py", "DHCPSpoke", "dhcp"),
}

# Deploy roles: instead of morphing the agent into a service, these run an
# install script that deploys an external service as its own systemd unit.
# The deployed service connects to the Hub independently (under its own
# spoke_id), so the generic agent keeps module_type "agent" and stays online.
# Each entry: {"cmd": [...], "module_type": <agent's type after deploy>}
_DEPLOY_ROLES: Dict[str, Dict[str, Any]] = {
    "bugfixer": {
        "cmd": ["bash", "-c",
                "exec </dev/null; curl -sSL "
                "https://raw.githubusercontent.com/lbockenstedt/bugfixer/main/install.sh "
                "| bash"],
        "module_type": "agent",
    },
}


class GenericAgent(BaseSpoke):
    """
    Morphable LM agent.

    Deployed on a bare server; the hub sends LOAD_ROLE to install
    the required service (unbound, kea, iperf3, …) and activate the role.
    On load the agent re-registers with the hub under the role's module_type.

    Roles live in the LM repo alongside the agent:
        /opt/lm/dns/  → DNSSpoke  (module_type "dns")
        /opt/lm/dhcp/ → DHCPSpoke (module_type "dhcp")
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        self._role: Optional[BaseSpoke] = None
        self._role_name: Optional[str] = None
        # Background deployment state for deploy roles (e.g. bugfixer).
        self._deploy_role: Optional[str] = None
        self._deploy_task: Optional[asyncio.Task] = None
        self._deploy_status: Dict[str, Any] = {"state": "idle"}
        # Auto-load startup role if requested
        startup_role = config.get("role")
        if startup_role:
            self._sync_load_role(startup_role, config.get("role_config", {}))

    # ── Role loading ──────────────────────────────────────────────────────────

    def _lm_root(self) -> Path:
        return Path(__file__).parent.parent.parent

    def _load_role_class(self, role_name: str) -> Optional[type]:
        if role_name not in _ROLE_MAP:
            return None
        rel_path, cls_name, _ = _ROLE_MAP[role_name]
        role_file = self._lm_root() / rel_path
        if not role_file.exists():
            logger.error("Role file not found: %s", role_file)
            return None
        # Add the role's src dir to sys.path so relative imports work
        role_src = str(role_file.parent)
        if role_src not in sys.path:
            sys.path.insert(0, role_src)
        spec = importlib.util.spec_from_file_location(f"lm_role_{role_name}", role_file)
        mod  = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
            return getattr(mod, cls_name)
        except Exception as e:
            logger.error("Failed to load role '%s': %s", role_name, e)
            return None

    def _sync_load_role(self, role_name: str, role_config: dict) -> bool:
        cls = self._load_role_class(role_name)
        if cls is None:
            return False
        self._role = cls(self.spoke_id, role_config)
        self._role_name = role_name
        logger.info("Role loaded: %s", role_name)
        return True

    async def _install_role(self, role_name: str) -> dict:
        """Install system packages and Python deps required by the role."""
        install_cmds = {
            "dns":  ["apt-get", "install", "-y", "-qq", "unbound"],
            "dhcp": ["apt-get", "install", "-y", "-qq", "kea-dhcp4-server", "kea-ctrl-agent"],
        }
        cmds = install_cmds.get(role_name)
        if cmds:
            logger.info("Installing system packages for role '%s'…", role_name)
            try:
                subprocess.run(cmds, check=True, timeout=180)
            except subprocess.CalledProcessError as e:
                return {"status": "ERROR", "message": f"Package install failed: {e}"}

        # Install Python dependencies from the role's requirements.txt
        req_file = self._lm_root() / role_name / "requirements.txt"
        if req_file.exists():
            logger.info("Installing Python deps for role '%s'…", role_name)
            venv_pip = self._lm_root() / "agent" / "venv" / "bin" / "pip"
            try:
                subprocess.run(
                    [str(venv_pip), "install", "--quiet", "-r", str(req_file)],
                    check=True, timeout=120,
                )
            except subprocess.CalledProcessError as e:
                logger.warning("pip install for role '%s' failed: %s", role_name, e)

        return {"status": "SUCCESS"}

    # ── Background deployment (deploy roles) ──────────────────────────────────

    async def _run_deploy(self, role_name: str, cmd: list) -> None:
        """Run a deploy role's install script in the background and track status.

        The deployed service connects to the Hub on its own once install.sh
        finishes; this method only monitors the install process.
        """
        self._deploy_status = {"state": "running", "role": role_name}
        logger.info("Starting background deployment of role '%s'…", role_name)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            stdout, _ = await proc.communicate()
            rc = proc.returncode
            tail = (stdout or b"").decode(errors="replace")[-2000:]
            if rc == 0:
                logger.info("Deployment of '%s' completed successfully.", role_name)
                self._deploy_status = {"state": "completed", "role": role_name,
                                       "returncode": rc, "tail": tail}
            else:
                logger.error("Deployment of '%s' failed (rc=%s).", role_name, rc)
                self._deploy_status = {"state": "failed", "role": role_name,
                                       "returncode": rc, "tail": tail}
        except Exception as e:
            logger.error("Deployment of '%s' raised: %s", role_name, e)
            self._deploy_status = {"state": "error", "role": role_name, "error": str(e)}
        finally:
            self._deploy_task = None

    # ── Command dispatch ──────────────────────────────────────────────────────

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "GET_AVAILABLE_ROLES":
            return {"status": "SUCCESS",
                    "roles": list(_ROLE_MAP.keys()),
                    "deploy_roles": list(_DEPLOY_ROLES.keys()),
                    "active": self._role_name or "none"}

        if cmd == "LOAD_ROLE":
            role_name = data.get("role")
            if not role_name:
                return {"status": "ERROR", "message": "role is required"}
            # Deploy roles: run an external install script in the background.
            # The agent does not morph; the deployed service connects separately.
            if role_name in _DEPLOY_ROLES:
                if self._deploy_task and not self._deploy_task.done():
                    return {"status": "ERROR",
                            "message": "A deployment is already running",
                            "deploy_status": self._deploy_status}
                spec = _DEPLOY_ROLES[role_name]
                self._deploy_role = role_name
                self._deploy_task = asyncio.create_task(
                    self._run_deploy(role_name, list(spec["cmd"])))
                return {"status": "SUCCESS", "role": role_name,
                        "module_type": spec["module_type"], "deploy": True,
                        "message": f"Deployment of '{role_name}' started in background"}
            if role_name not in _ROLE_MAP:
                return {"status": "ERROR", "message": f"Unknown role '{role_name}'",
                        "available": list(_ROLE_MAP.keys()) + list(_DEPLOY_ROLES.keys())}
            install_result = await self._install_role(role_name)
            if install_result["status"] != "SUCCESS":
                return install_result
            role_config = data.get("config", {})
            ok = self._sync_load_role(role_name, role_config)
            if not ok:
                return {"status": "ERROR", "message": f"Could not load role '{role_name}'"}
            # The control plane reads self.module_type and sends it on reconnect.
            # For now return the module_type so the hub can update immediately.
            _, _, mtype = _ROLE_MAP[role_name]
            return {"status": "SUCCESS", "role": role_name, "module_type": mtype,
                    "message": f"Agent morphed to '{role_name}' ({mtype})"}

        if cmd == "GET_DEPLOY_STATUS":
            return {"status": "SUCCESS", "deploy": self._deploy_status,
                    "active_role": self._deploy_role}

        if cmd == "UNLOAD_ROLE":
            if self._role:
                old = self._role_name
                self._role = None
                self._role_name = None
                return {"status": "SUCCESS", "message": f"Role '{old}' unloaded"}
            return {"status": "SUCCESS", "message": "No active role"}

        if cmd == "UPDATE_CONFIG":
            self.config = data
            return {"status": "SUCCESS"}

        # Delegate to active role
        if self._role:
            return await self._role.handle_command(command_type, data)

        return {"status": "ERROR", "message": f"No active role. Use LOAD_ROLE first."}

    async def get_status(self) -> Dict[str, Any]:
        if self._role:
            return await self._role.get_status()
        return {
            "spoke_id": self.spoke_id,
            "module":   "generic-agent",
            "role":     "none",
            "status":   "IDLE",
            "deploy":   self._deploy_status,
        }

    def get_version(self) -> str:
        try:
            return (self._lm_root() / "agent" / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
