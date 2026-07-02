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

# Each entry: (rel_path, cls_name, module_type, repo_url_or_None)
#   rel_path   — spoke file under the lm-root (e.g. dns/src/dns_spoke.py);
#                the first path segment is also the clone target dir name.
#   repo_url   — None for roles that ship inside the lm repo (dns, dhcp);
#                otherwise the GitHub URL the agent shallow-clones on LOAD_ROLE
#                when the spoke code isn't already present on the node.
_ROLE_MAP = {
    "dns":        ("dns/src/dns_spoke.py",          "DNSSpoke",  "dns",        None),
    "dhcp":       ("dhcp/src/dhcp_spoke.py",        "DHCPSpoke", "dhcp",       None),
    "network":    ("nw/src/nw_spoke.py",            "NwSpoke",   "nw",         "https://github.com/lbockenstedt/nw.git"),
    "netbox":     ("netbox/src/netbox_spoke.py",    "NetboxSpoke", "ipam",     "https://github.com/lbockenstedt/netbox.git"),
    "opnsense":   ("opnsense/src/opn_spoke.py",     "OpnSpoke",  "firewall",   "https://github.com/lbockenstedt/opnsense.git"),
    "ldap":       ("ldap/src/ldap_spoke.py",        "LdapSpoke", "directory",  "https://github.com/lbockenstedt/ldap.git"),
    "simulation": ("cs/lm-spoke/src/cs_spoke.py",   "CSSpoke",   "simulation", "https://github.com/lbockenstedt/cs.git"),
    "cppm":       ("cppm/src/spoke.py",             "CPPMSpoke", "nac",        "https://github.com/lbockenstedt/cppm.git"),
    "proxmox":    ("pxmx/src/proxmox_spoke.py",     "ProxmoxSpoke", "hypervisor", "https://github.com/lbockenstedt/pxmx.git"),
    "le":         ("le/src/le_spoke.py",            "LESpoke",   "certificates", "https://github.com/lbockenstedt/le.git"),
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


class _RoleAdapter(BaseSpoke):
    """Adapter that lets a non-BaseSpoke spoke (e.g. cppm's CPPMSpoke) be loaded
    as a role. Delegates handle_command/get_version to the inner instance and
    supplies a get_status fallback when the inner class doesn't implement it,
    so GenericAgent.get_status() delegation never AttributeErrors."""

    def __init__(self, inner):
        super().__init__(getattr(inner, "spoke_id", "role"), getattr(inner, "config", {}))
        self._inner = inner

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._inner.handle_command(command_type, data)

    def get_version(self) -> str:
        return self._inner.get_version()

    async def get_status(self) -> Dict[str, Any]:
        try:
            return await self._inner.get_status()
        except AttributeError:
            # Inner spoke has no get_status (e.g. CPPMSpoke) — return a minimal
            # READY status so the hub sees the role as live.
            return {
                "spoke_id": getattr(self._inner, "spoke_id", self.spoke_id),
                "module":   getattr(self._inner, "module_type", "role"),
                "status":   "READY",
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
        # Set by AgentControlPlane after registration so LOAD/UNLOAD_ROLE can
        # request a module_type morph + reconnect (become a spoke / revert to agent).
        self.control_plane = None
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
        rel_path, cls_name, _, _ = _ROLE_MAP[role_name]
        role_file = self._lm_root() / rel_path
        if not role_file.exists():
            logger.error("Role file not found: %s", role_file)
            return None
        # Put the role's src dir on sys.path so FLAT imports resolve (e.g.
        # cppm's `from queries import CPPMQueries` / `from client import ...`).
        role_src = str(role_file.parent)
        if role_src not in sys.path:
            sys.path.insert(0, role_src)
        # Load the spoke as a PACKAGE (submodule_search_locations=[role_src])
        # so RELATIVE imports resolve even when the role's src/ has no
        # __init__.py — e.g. ldap's `from .ldap_manager import LdapManager`.
        # Registering the package in sys.modules BEFORE exec_module is what
        # lets `from .helper import X` find its sibling during exec.
        pkg_name = f"lm_role_{role_name}"
        spec = importlib.util.spec_from_file_location(
            pkg_name, role_file, submodule_search_locations=[role_src])
        mod = importlib.util.module_from_spec(spec)
        sys.modules[pkg_name] = mod
        try:
            spec.loader.exec_module(mod)
            return getattr(mod, cls_name)
        except Exception as e:
            logger.error("Failed to load role '%s': %s", role_name, e)
            sys.modules.pop(pkg_name, None)
            return None

    def _sync_load_role(self, role_name: str, role_config: dict) -> bool:
        cls = self._load_role_class(role_name)
        if cls is None:
            return False
        inst = cls(self.spoke_id, role_config)
        # Spokes that aren't BaseSpoke subclasses (cppm's CPPMSpoke) get wrapped
        # so handle_command/get_status delegation in GenericAgent stays uniform.
        if not isinstance(inst, BaseSpoke):
            inst = _RoleAdapter(inst)
        self._role = inst
        self._role_name = role_name
        logger.info("Role loaded: %s", role_name)
        return True

    async def _install_role(self, role_name: str) -> dict:
        """Clone the role repo (if external) and install its system + Python deps."""
        if role_name not in _ROLE_MAP:
            return {"status": "ERROR", "message": f"Unknown role '{role_name}'"}
        rel_path, _, _, repo_url = _ROLE_MAP[role_name]
        role_file = self._lm_root() / rel_path

        # 1. Sibling repos (dns/dhcp ship inside lm → repo_url None → skip).
        #    Clone shallowly into <lm-root>/<first-path-segment> on first use so
        #    the spoke code is present on a bare generic node; idempotent on
        #    re-load (skips if the dir already exists).
        if repo_url:
            clone_dir = self._lm_root() / rel_path.split("/")[0]
            if not clone_dir.exists():
                logger.info("Cloning role repo '%s' into %s…", role_name, clone_dir)
                try:
                    subprocess.run(
                        ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
                        check=True, timeout=300,
                    )
                except subprocess.CalledProcessError as e:
                    return {"status": "ERROR",
                            "message": f"git clone for role '{role_name}' failed: {e}"}
            else:
                logger.debug("Role repo already present at %s; skipping clone.", clone_dir)

        # 2. System packages (in-repo roles only today; siblings are pip-only).
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

        # 3. Python deps. requirements.txt sits at role_file.parent.parent for
        #    every role (repo root for most; cs/lm-spoke/ for simulation).
        req_file = role_file.parent.parent / "requirements.txt"
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
            _, _, mtype, _ = _ROLE_MAP[role_name]
            # Re-register with the hub under the role's module_type (become a
            # spoke of that type). request_morph updates control_plane.module_type
            # and reconnects; the response below is sent before the close fires.
            cp = getattr(self, "control_plane", None)
            if cp is not None:
                await cp.request_morph(mtype)
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
                # Revert to a plain agent (module_type "agent") + reconnect so
                # the hub re-registers it under Generic Nodes again.
                cp = getattr(self, "control_plane", None)
                if cp is not None:
                    await cp.request_morph("agent")
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
