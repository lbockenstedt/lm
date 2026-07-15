import asyncio
import importlib.util
import logging
import os
import shlex
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

# Root nginx cert-install helper dropped by netbox/install.sh --infra-only. Its
# presence marks this host as the NetBox web server (see the INSTALL_CERT handler
# + AgentControlPlane._extra_auth_fields).
_NETBOX_INSTALL_CERT_HELPER = "/usr/local/bin/lm-netbox-install-cert"

# NetBox app layout on a netbox-server host (deployed by netbox/install.sh
# --infra-only). Used by the NETBOX_APPLY_SSO handler to apply Entra SSO live
# (the agent runs as root here) without a full installer re-run.
_NETBOX_APP_DIR = "/opt/netbox-app"
_NETBOX_CONFIG_PY = "/opt/netbox-app/netbox/netbox/configuration.py"
_NETBOX_SSO_PIPELINE = "/opt/netbox-app/netbox/lm_sso_pipeline.py"
_NETBOX_VENV_PIP = "/opt/netbox-app/venv/bin/pip"
# Sentinel delimiters — MUST match netbox/install.sh's LMSSOCFG helper so a later
# install.sh --netbox-sso-* re-run sees the block as its own and replaces in place.
_NB_SSO_BEGIN = "# --- BEGIN LM SSO (Entra ID / OIDC) managed by install.sh --netbox-sso-* ---"
_NB_SSO_END = "# --- END LM SSO ---"

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

logger = logging.getLogger("GenericAgent")

# Set by control_plane.py right after its RoleConnection class is defined (both
# modules are fully loaded by then; see the assignment there for why). LOAD_ROLE
# reads this instead of doing `from control_plane import RoleConnection` at call
# time — that bare import is NOT safe once ANY role has been loaded:
# _load_role_class() below inserts the role's own src/ dir at sys.path[0] so its
# flat imports resolve (e.g. cppm's `from queries import ...`), and nearly every
# role repo also ships its own control_plane.py (its standalone spoke's own
# entrypoint), which then shadows the agent's control_plane module for any
# later bare `import control_plane` — surfacing as "cannot import name
# 'RoleConnection' from 'control_plane' (/opt/lm/<role>/src/control_plane.py)".
RoleConnection = None

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
    "console":    ("console/src/console_spoke.py",  "ConsoleSpoke", "console",   None),
    "statuspage": ("statuspage/src/statuspage_spoke.py", "StatusPageSpoke", "statuspage", None),
}

# Logger-name prefixes each role emits under. Used by the multi-role agent's
# log-relay scoping (see _SpokeLogRelayHandler in core/src/messaging/
# control_plane.py) so a shared/generic agent hosting several role sub-spokes
# relays each role's lines ONLY under that role's spoke_id — without this, every
# role sub-spoke + the base agent each relay the whole root stream under their
# own id, so CPPM logs land in the OPNSense bucket and vice versa.
#
# A record is relayed by a role's RoleConnection iff its logger name matches
# one of that role's prefixes (stem-style: ``name == p or name.startswith(p)``).
# The base agent's handler EXCLUDES the union of all these prefixes, so its
# bucket holds agent/process/non-role lines instead of duplicating every role.
#
# Roles whose modules share a clean stem (CPPM*, Opn*, Ldap*, Netbox*, Nw*,
# DHCP*+Kea, DNS*+Unbound, LE*+le.) need just that stem; roles with ad-hoc
# helper-module names list each stem. Shared logger names that live in BOTH
# lm/core AND a role repo — HubDiscovery, DepGuard, UpdateRecovery (core +
# pxmx) — are intentionally NOT listed: they're one global logger used by both
# shared infra and the role, so they can't be attributed by name and fall
# through to the base agent bucket (correct: they're process-infra logs).
# Third-party libs (httpx, httpcore, …) are likewise unlisted → base bucket.
# Adding a new top-level logger to a role repo: if it doesn't share one of the
# stems below, add it here or its lines fall to the base agent bucket (a
# discoverable mis-route, never cross-contamination between sibling roles).
_ROLE_LOG_PREFIXES: Dict[str, tuple] = {
    "dns":        ("DNS", "Unbound"),
    "dhcp":       ("DHCP", "Kea"),
    "network":    ("Nw",),
    "netbox":     ("Netbox",),
    "opnsense":   ("Opn",),
    "ldap":       ("Ldap",),
    "simulation": ("CS", "CentralPoller", "ClientRegistry", "client_sim_dashboard",
                   "ProxmoxDeploy", "SimulationEngine", "TokenStore", "LocalStore"),
    "cppm":       ("CPPM",),
    "proxmox":    ("Proxmox", "Pxmx"),
    "le":         ("LE", "le."),
    "console":    ("Console",),
    "statuspage": ("StatusPageSpoke",),
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
    # NetBox SERVER: deploy the NetBox application (PostgreSQL/Redis/gunicorn/
    # nginx + WebUI on :80) via the netbox installer's --infra-only mode, which
    # stands up the app but NOT an lm-netbox spoke unit. The IPAM module that
    # talks to this server is the SEPARATE "netbox" role (module_type "ipam")
    # in _ROLE_MAP — load that too and point its connection settings at this
    # server. Split so the heavy app deploy and the lightweight API spoke are
    # independent (server on one node, IPAM spoke here or elsewhere).
    "netbox-server": {
        "cmd": ["bash", "-c",
                "exec </dev/null; curl -sSL "
                "https://raw.githubusercontent.com/lbockenstedt/netbox/main/install.sh "
                "| bash -s -- --infra-only"],
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
        # Multi-role: the agent HOSTS zero or more role sub-spokes concurrently.
        # Each entry: {"instance": BaseSpoke, "conn": RoleConnection, "task": asyncio.Task}.
        # The base agent connection stays module_type "agent" (the Generic Node
        # control channel for LOAD/UNLOAD_ROLE); each role opens its own
        # RoleConnection under spoke_id {base}-{role} with the role's module_type.
        self._roles: Dict[str, Dict[str, Any]] = {}
        # Set by AgentControlPlane after registration so LOAD_ROLE can read
        # hub_url + .env helpers and spawn RoleConnection sub-spokes.
        self.control_plane = None
        # Background deployment state for deploy roles (e.g. bugfixer).
        self._deploy_role: Optional[str] = None
        self._deploy_task: Optional[asyncio.Task] = None
        self._deploy_status: Dict[str, Any] = {"state": "idle"}

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

    def _sync_load_role(self, role_name: str, role_config: dict,
                        sub_spoke_id: str = None) -> Optional[BaseSpoke]:
        """Load a role class + instantiate it for the given sub-spoke id.

        Returns the (possibly ``_RoleAdapter``-wrapped) role instance, or None
        on load failure. The instance is constructed with the SUB-SPOKE id
        (``{base}-{role}``) so its get_status / reporting carries the right
        identity — NOT the base agent's spoke_id (multi-role: the base stays
        "agent" and the role lives on its own connection)."""
        cls = self._load_role_class(role_name)
        if cls is None:
            return None
        inst = cls(sub_spoke_id or f"{self.spoke_id}-{role_name}", role_config)
        # Spokes that aren't BaseSpoke subclasses (cppm's CPPMSpoke) get wrapped
        # so handle_command/get_status delegation stays uniform.
        if not isinstance(inst, BaseSpoke):
            inst = _RoleAdapter(inst)
        logger.info("Role loaded: %s (sub-spoke %s)", role_name,
                    sub_spoke_id or f"{self.spoke_id}-{role_name}")
        return inst

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

        # 2. System packages. dns/dhcp need their daemons; le needs certbot +
        # the common DNS-01 plugins (the spoke itself creates /etc/lm-le and the
        # ledger dir on demand, and runs as root so it can bind :80 / write
        # /etc/letsencrypt — the generic-agent service is User=root). Other
        # siblings are pip-only (curl/requests-based).
        install_cmds = {
            "dns":  ["apt-get", "install", "-y", "-qq", "unbound"],
            "dhcp": ["apt-get", "install", "-y", "-qq", "kea-dhcp4-server", "kea-ctrl-agent"],
            "le":   ["apt-get", "install", "-y", "-qq", "certbot",
                     "python3-certbot-dns-cloudflare", "python3-certbot-dns-route53",
                     "openssl"],
            # ldap: BUILD deps for python-ldap (the pip wheel compiles against
            # these). Without them `pip install python-ldap` fails and the role
            # crashes on load with "No module named 'ldap.filter'" — the role
            # never loads. Must run BEFORE the pip step below. The slapd SERVER
            # (interactive debconf) is set up in _role_post_install, not here.
            "ldap": ["apt-get", "install", "-y", "-qq", "libldap2-dev", "libsasl2-dev"],
        }
        cmds = install_cmds.get(role_name)
        if cmds:
            logger.info("Installing system packages for role '%s'…", role_name)
            try:
                subprocess.run(cmds, check=True, timeout=180)
            except subprocess.CalledProcessError as e:
                return {"status": "ERROR", "message": f"Package install failed: {e}"}

        # 2b. Module-specific OS bootstrapping the DEDICATED installers used to
        #     do, so a freshly-loaded role reaches parity with install_<mod>.sh
        #     (dns needs unbound remote-control enabled+started; dhcp needs a
        #     non-interactive kea-ctrl-agent config + the kea daemons started).
        #     Idempotent + best-effort; a config hiccup must not fail the load.
        self._role_post_install(role_name)

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

    # kea-ctrl-agent config mirrored from dhcp/install_dhcp.sh — loopback-only,
    # port 8001, no auth (the default Debian package config may prompt for HTTP
    # auth; this replaces it so the role load is fully non-interactive).
    _KEA_CTRL_AGENT_CONF = (
        '{\n'
        '    "Control-agent": {\n'
        '        "http-host": "127.0.0.1",\n'
        '        "http-port": 8001,\n'
        '        "control-sockets": {\n'
        '            "dhcp4": {\n'
        '                "socket-type": "unix",\n'
        '                "socket-name": "/run/kea/kea4-ctrl-socket"\n'
        '            }\n'
        '        },\n'
        '        "loggers": [{\n'
        '            "name": "kea-ctrl-agent",\n'
        '            "output_options": [{"output": "syslog"}],\n'
        '            "severity": "WARN"\n'
        '        }]\n'
        '    }\n'
        '}\n'
    )

    def _role_post_install(self, role_name: str) -> None:
        """Module-specific OS config the dedicated installers did, so a loaded
        role reaches parity. Idempotent + best-effort (never fails the load).
        Pure-API roles (opnsense/netbox/cppm/ldap/le/nw/pxmx) need nothing here.
        Runs as root (the lm-agent unit is User=root)."""
        try:
            if role_name == "dns":
                conf = Path("/etc/unbound/unbound.conf")
                existing = conf.read_text() if conf.exists() else ""
                if "control-enable: yes" not in existing:
                    with conf.open("a") as f:
                        f.write("\n\nremote-control:\n    control-enable: yes\n"
                                "    control-interface: 127.0.0.1\n"
                                "    control-port: 8953\n")
                Path("/etc/unbound/conf.d").mkdir(parents=True, exist_ok=True)
                if "conf.d" not in existing:
                    with conf.open("a") as f:
                        f.write('include-toplevel: "/etc/unbound/conf.d/*.conf"\n')
                subprocess.run(["unbound-control-setup"], check=False, timeout=60,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["systemctl", "enable", "--now", "unbound"],
                               check=False, timeout=60)
            elif role_name == "dhcp":
                Path("/etc/kea").mkdir(parents=True, exist_ok=True)
                Path("/etc/kea/kea-ctrl-agent.conf").write_text(self._KEA_CTRL_AGENT_CONF)
                subprocess.run(["systemctl", "enable", "--now",
                                "kea-ctrl-agent", "kea-dhcp4-server"],
                               check=False, timeout=60)
            elif role_name in ("simulation", "proxmox"):
                # Heavy roles carry OS infra the dedicated installers set up (cs:
                # sim-client Kea/NIC + agent-listener cert; pxmx: agent-host prep).
                # Each installer exposes an idempotent, non-interactive --infra-only
                # mode that does JUST that host prep (no unit, no .env, no spoke
                # code) — invoke it. The role's runtime env (LM_CS_AGENT_LISTENER /
                # LM_PXMX_AGENT_LOOPBACK etc.) comes from the agent .env, inherited
                # by this in-process sub-spoke — see install_agent.sh.
                _script = {
                    "simulation": self._lm_root() / "cs" / "lm-spoke" / "install_cs.sh",
                    "proxmox":    self._lm_root() / "pxmx" / "install_pxmx.sh",
                }[role_name]
                if _script.exists():
                    logger.info("Running %s --infra-only for role '%s'…",
                                _script.name, role_name)
                    subprocess.run(["bash", str(_script), "--infra-only"],
                                   check=False, timeout=600)
        except Exception as e:  # noqa: BLE001
            logger.warning("post-install OS config for role '%s' failed "
                           "(non-fatal): %s", role_name, e)

    # ── Background deployment (deploy roles) ──────────────────────────────────

    def _build_deploy_cmd(self, role_name: str, spec: dict, config: dict) -> list:
        """Build a deploy role's command, injecting per-load config.

        For netbox-server the LM WebUI collects the desired admin username +
        password on role load and passes them in LOAD_ROLE `config`; append them
        as install.sh args (shlex.quoted so any characters are safe). Without a
        password the installer auto-generates one, as before.
        """
        cmd = list(spec["cmd"])
        if role_name == "netbox-server" and config:
            extra = ""
            user = config.get("admin_user") or config.get("admin_username")
            pw = config.get("admin_password")
            if user:
                extra += " --admin-user " + shlex.quote(str(user))
            if pw:
                extra += " --admin-password " + shlex.quote(str(pw))
            if extra and cmd and cmd[-1].rstrip().endswith("--infra-only"):
                cmd[-1] = cmd[-1] + extra
        return cmd

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
                # Dump the install script's own output to the log — without this
                # a failed deploy only recorded "rc=N" and the real cause (DNS,
                # apt, postgres, gunicorn…) lived only in _deploy_status["tail"],
                # which is lost the moment the agent reloads on a SPOKE_UPDATE.
                logger.error("Deployment of '%s' failed (rc=%s). Install output (last 2KB):\n%s",
                             role_name, rc, tail or "<no output captured>")
                self._deploy_status = {"state": "failed", "role": role_name,
                                       "returncode": rc, "tail": tail}
        except Exception as e:
            logger.error("Deployment of '%s' raised: %s", role_name, e)
            self._deploy_status = {"state": "error", "role": role_name, "error": str(e)}
        finally:
            self._deploy_task = None

    # ── Command dispatch ──────────────────────────────────────────────────────

    async def _install_netbox_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Install an LE cert onto this host's NetBox nginx via the root helper.
        Mirrors netbox_spoke's INSTALL_CERT: validate the fullchain+privkey pair
        in-process, then run /usr/local/bin/lm-netbox-install-cert <crt> <key>."""
        domain = data.get("domain", "") or ""
        fullchain = data.get("fullchain", "") or ""
        privkey = data.get("privkey", "") or ""
        if not os.path.exists(_NETBOX_INSTALL_CERT_HELPER):
            logger.warning("[cert] %s → netbox-server: FAILED — helper %s missing "
                           "(is this the netbox-server host?)", domain, _NETBOX_INSTALL_CERT_HELPER)
            return {"status": "ERROR",
                    "message": f"cert helper {_NETBOX_INSTALL_CERT_HELPER} not present on this host"}
        if not fullchain or not privkey:
            return {"status": "ERROR", "message": "missing cert material"}
        if "BEGIN CERTIFICATE" not in fullchain or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "fullchain/privkey not PEM"}
        crt_tmp = key_tmp = None
        try:
            with tempfile.NamedTemporaryFile("w", suffix=".crt.pem", delete=False) as cf:
                cf.write(fullchain); crt_tmp = cf.name
            with tempfile.NamedTemporaryFile("w", suffix=".key.pem", delete=False) as kf:
                kf.write(privkey); key_tmp = kf.name
            os.chmod(crt_tmp, 0o600); os.chmod(key_tmp, 0o600)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(crt_tmp, key_tmp)
            except Exception as e:  # noqa: BLE001
                logger.warning("[cert] %s → netbox-server: FAILED — validation: %s", domain, e)
                return {"status": "ERROR", "message": f"cert validation failed (helper not called): {e}"}
            # sudo -n works whether the agent runs as root or an unprivileged
            # user with the netbox sudoers grant; the helper re-validates + swaps.
            try:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "-n", _NETBOX_INSTALL_CERT_HELPER, crt_tmp, key_tmp,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=20.0)
            except asyncio.TimeoutError:
                try: proc.kill()
                except (ProcessLookupError, UnboundLocalError): pass
                return {"status": "ERROR", "message": "cert-install helper timed out"}
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"cert-install helper invocation failed: {e}"}
            out = (out_b or b"").decode(errors="replace").strip()
            err = (err_b or b"").decode(errors="replace").strip()
            if proc.returncode == 0 and out.startswith("OK"):
                logger.info("[cert] %s → netbox-server: installed — %s", domain, out[2:].strip() or out)
                return {"status": "SUCCESS", "message": out[2:].strip() or out or "installed on netbox-server"}
            msg = err or out or f"helper exit {proc.returncode}"
            logger.warning("[cert] %s → netbox-server: FAILED — %s", domain, msg)
            return {"status": "ERROR", "message": msg}
        finally:
            for p in (crt_tmp, key_tmp):
                if p:
                    try: os.unlink(p)
                    except OSError: pass

    def _render_netbox_sso_block(self, d: Dict[str, Any]) -> str:
        """Build the sentinel-delimited SSO block for configuration.py, byte-for-
        byte compatible with netbox/install.sh's LMSSOCFG helper."""
        import json as _json
        tenant = str(d.get("tenant") or "")
        endpoint = "https://login.microsoftonline.com/%s/v2.0" % tenant
        group_map = d.get("group_map") or {}
        if not isinstance(group_map, dict):
            group_map = {}
        group_map = {str(k): str(v) for k, v in group_map.items()}
        redirect_uri = str(d.get("redirect_uri") or "")
        lines = [
            _NB_SSO_BEGIN,
            "# Do not edit by hand — re-run install.sh with --netbox-sso-* flags to change.",
            "REMOTE_AUTH_ENABLED = True",
            "REMOTE_AUTH_BACKEND = ['social_core.backends.openid_connect.OpenIdConnectAuth']",
            "REMOTE_AUTH_AUTO_CREATE_USER = True",
            "REMOTE_AUTH_AUTO_CREATE_GROUPS = True",
            "SOCIAL_AUTH_OIDC_OIDC_ENDPOINT = %s" % repr(endpoint),
            "SOCIAL_AUTH_OIDC_KEY = %s" % repr(str(d.get("client_id") or "")),
            "SOCIAL_AUTH_OIDC_SECRET = %s" % repr(str(d.get("client_secret") or "")),
            "SOCIAL_AUTH_OIDC_SCOPE = ['openid', 'profile', 'email', 'offline_access']",
            "SOCIAL_AUTH_OIDC_USERNAME_KEY = 'preferred_username'",
            "NETBOX_SSO_GROUP_MAP = %s" % _json.dumps(group_map),
            "NETBOX_SSO_ALLOWED_GROUP = %s" % repr(str(d.get("allowed_group") or "")),
        ]
        if redirect_uri:
            lines.append("# Redirect URI registered in Entra: %s" % redirect_uri)
        lines += [
            "SOCIAL_AUTH_PIPELINE = (",
            "    'social_core.pipeline.social_auth.social_details',",
            "    'social_core.pipeline.social_auth.social_uid',",
            "    'social_core.pipeline.social_auth.auth_allowed',",
            "    'social_core.pipeline.social_auth.social_user',",
            "    'social_core.pipeline.user.get_username',",
            "    'social_core.pipeline.user.create_user',",
            "    'social_core.pipeline.social_auth.associate_user',",
            "    'social_core.pipeline.social_auth.load_extra_data',",
            "    'social_core.pipeline.user_details',",
            "    'lm_sso_pipeline.sync_entra_groups',",
            ")",
            _NB_SSO_END,
        ]
        return "\n".join(lines) + "\n"

    async def _apply_netbox_sso(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Write/replace/remove the Entra SSO block in NetBox's configuration.py
        and restart NetBox. Requires this to be a netbox-server host (the app +
        lm_sso_pipeline.py must exist — deployed via install.sh --infra-only)."""
        enabled = bool(data.get("enabled", True))
        if not os.path.exists(_NETBOX_CONFIG_PY):
            return {"status": "ERROR",
                    "message": f"{_NETBOX_CONFIG_PY} not found — is this the netbox-server host?"}
        if enabled:
            for f in ("tenant", "client_id", "client_secret"):
                if not str(data.get(f) or "").strip():
                    return {"status": "ERROR", "message": f"missing {f} (required to enable SSO)"}
            if not os.path.exists(_NETBOX_SSO_PIPELINE):
                return {"status": "ERROR",
                        "message": "lm_sso_pipeline.py missing — re-deploy the netbox-server role first"}
            # Ensure the OIDC extra is present (idempotent, best-effort — the
            # backend imports python-jose at load).
            try:
                proc = await asyncio.create_subprocess_exec(
                    _NETBOX_VENV_PIP, "install", "social-auth-core[openidconnect]", "--no-cache-dir",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
                await asyncio.wait_for(proc.wait(), timeout=120.0)
            except Exception as e:  # noqa: BLE001
                logger.warning("netbox-sso: pip extra install failed (continuing): %s", e)
        try:
            with open(_NETBOX_CONFIG_PY, "r") as f:
                cur = f.read()
        except OSError as e:
            return {"status": "ERROR", "message": f"cannot read configuration.py: {e}"}
        # Splice out any existing sentinel block first.
        b = cur.find(_NB_SSO_BEGIN)
        without = cur
        if b != -1:
            e = cur.find(_NB_SSO_END, b)
            if e != -1:
                e_end = cur.find("\n", e)
                e_end = len(cur) if e_end == -1 else e_end + 1
                without = cur[:b] + cur[e_end:]
        if enabled:
            new = without.rstrip() + "\n\n" + self._render_netbox_sso_block(data)
        else:
            new = without  # disable = remove the block
        if new == cur:
            return {"status": "SUCCESS", "message": "SSO config unchanged", "changed": False}
        try:
            tmp = _NETBOX_CONFIG_PY + ".lmtmp"
            with open(tmp, "w") as f:
                f.write(new)
            os.replace(tmp, _NETBOX_CONFIG_PY)
        except OSError as e:
            return {"status": "ERROR", "message": f"cannot write configuration.py: {e}"}
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "restart", "netbox", "netbox-rq",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
            _, err_b = await asyncio.wait_for(proc.communicate(), timeout=60.0)
            if proc.returncode != 0:
                return {"status": "ERROR",
                        "message": f"config written but restart failed: {(err_b or b'').decode(errors='replace')[:200]}"}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"config written but restart failed: {e}"}
        logger.info("netbox-sso: %s SSO on this NetBox host + restarted.",
                    "ENABLED" if enabled else "DISABLED")
        return {"status": "SUCCESS",
                "message": f"SSO {'enabled' if enabled else 'disabled'} on netbox-server + restarted",
                "changed": True}

    async def _test_netbox_sso(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Probe NetBox's OIDC begin URL (/oauth/login/oidc/) on localhost and
        confirm it redirects to Entra with the expected params. No browser / no
        real auth — just proves the backend is wired and the app values match."""
        import urllib.parse as _up
        if not os.path.exists(_NETBOX_CONFIG_PY):
            return {"status": "ERROR", "message": "not the netbox-server host"}
        exp_tenant = str(data.get("tenant") or "")
        exp_client = str(data.get("client_id") or "")
        exp_redirect = str(data.get("redirect_uri") or "")
        # Use the configured redirect host as the Host header so ALLOWED_HOSTS +
        # the generated redirect_uri match what a real login would produce.
        host_hdr = ""
        try:
            if exp_redirect:
                host_hdr = _up.urlparse(exp_redirect).netloc
        except Exception:  # noqa: BLE001
            host_hdr = ""

        def _probe():
            import ssl as _ssl, urllib.request as _ur, urllib.error as _ue
            ctx = _ssl._create_unverified_context()

            class _NoRedirect(_ur.HTTPRedirectHandler):
                def redirect_request(self, *a, **k):  # noqa: ANN001
                    return None
            opener = _ur.build_opener(_NoRedirect, _ur.HTTPSHandler(context=ctx))
            headers = {"Host": host_hdr} if host_hdr else {}
            for base in ("https://127.0.0.1", "http://127.0.0.1"):
                url = base + "/oauth/login/oidc/"
                try:
                    resp = opener.open(_ur.Request(url, headers=headers), timeout=8)
                    return {"code": resp.getcode(), "location": resp.headers.get("Location", "")}
                except _ue.HTTPError as e:
                    loc = e.headers.get("Location", "") if e.headers else ""
                    if e.code in (301, 302, 303, 307, 308) and loc:
                        return {"code": e.code, "location": loc}
                    # non-redirect HTTP error (e.g. 400 ALLOWED_HOSTS, 404 backend
                    # not mounted) — report it; try the other scheme first.
                    last = {"code": e.code, "location": "", "error": f"HTTP {e.code}"}
                    continue
                except Exception as ex:  # noqa: BLE001
                    last = {"code": 0, "location": "", "error": str(ex)}
                    continue
            return locals().get("last", {"code": 0, "location": "", "error": "no response"})

        try:
            r = await asyncio.to_thread(_probe)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"probe failed: {e}"}

        loc = r.get("location") or ""
        to_entra = "login.microsoftonline.com" in loc
        found = {"authorize_url": loc.split("?")[0] if loc else "",
                 "tenant": "", "client_id": "", "redirect_uri": ""}
        if to_entra:
            try:
                parsed = _up.urlparse(loc)
                found["tenant"] = parsed.path.strip("/").split("/")[0]
                q = _up.parse_qs(parsed.query)
                found["client_id"] = (q.get("client_id") or [""])[0]
                found["redirect_uri"] = (q.get("redirect_uri") or [""])[0]
            except Exception:  # noqa: BLE001
                pass
        matches = {
            "tenant": bool(exp_tenant) and found["tenant"] == exp_tenant,
            "client_id": bool(exp_client) and found["client_id"] == exp_client,
            "redirect_uri": (not exp_redirect) or found["redirect_uri"] == exp_redirect,
        }
        ok = to_entra and matches["tenant"] and matches["client_id"] and matches["redirect_uri"]
        if ok:
            msg = "OK — NetBox redirects to Entra with the expected tenant, client ID and redirect URI."
        elif to_entra:
            bad = [k for k in ("tenant", "client_id", "redirect_uri") if not matches[k]]
            msg = "Redirects to Entra but mismatched: " + ", ".join(bad) + \
                  " (check the app registration / redirect URI)."
        elif r.get("code") in (301, 302, 303, 307, 308):
            msg = f"Login redirected to {loc[:120] or '(none)'} — not Entra. Is the OIDC backend enabled?"
        elif r.get("code") == 404:
            msg = "OIDC begin URL 404 — the social-auth backend isn't mounted (SSO block not applied?)."
        elif r.get("code") == 400:
            msg = "HTTP 400 (ALLOWED_HOSTS?) — NetBox rejected the Host; add the redirect host to ALLOWED_HOSTS."
        else:
            msg = r.get("error") or f"unexpected response (HTTP {r.get('code')})"
        return {"status": "SUCCESS", "ok": ok, "redirects_to_entra": to_entra,
                "http_code": r.get("code"), "found": found, "matches": matches, "message": msg}

    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "INSTALL_CERT":
            # This host ran the netbox-server deploy role, so it has the NetBox
            # nginx + the root cert helper. LE distribution (hub-brokered) routes
            # the NetBox cert HERE (target "netbox-server") instead of the API-
            # only IPAM spoke. Validate the pair in-process, write 0600 temp
            # files, and hand them to the root helper (same contract as the
            # netbox spoke) which atomically swaps + reloads nginx.
            return await self._install_netbox_cert(data)

        if cmd == "NETBOX_TEST_SSO":
            # Verify the SSO wiring without a browser: hit NetBox's OIDC begin
            # URL on localhost and confirm it 302s to Entra with the expected
            # tenant/client_id/redirect_uri. Catches most misconfig (backend not
            # loaded, wrong tenant, mismatched client_id/redirect) short of a
            # real user auth.
            return await self._test_netbox_sso(data)

        if cmd == "NETBOX_APPLY_SSO":
            # Apply (or remove) Entra ID OIDC SSO on this host's NetBox live —
            # the agent is root here and the netbox-server deploy already placed
            # the app + SSO pipeline. Writes the SAME sentinel block install.sh
            # --netbox-sso-* writes (so a later installer re-run stays in sync),
            # then restarts NetBox. Reuses the LM hub's Entra app (tenant +
            # client_id) with a client secret the hub supplies.
            return await self._apply_netbox_sso(data)

        if cmd == "GET_AVAILABLE_ROLES":
            return {"status": "SUCCESS",
                    "roles": list(_ROLE_MAP.keys()),
                    "deploy_roles": list(_DEPLOY_ROLES.keys()),
                    "active": [{"role": r,
                                "sub_spoke_id": e["conn"].spoke_id,
                                "module_type": e["conn"].module_type}
                               for r, e in self._roles.items()]}

        if cmd == "LOAD_ROLE":
            role_name = data.get("role")
            if not role_name:
                return {"status": "ERROR", "message": "role is required"}
            # Deploy roles: run an external install script in the background.
            # The agent does not host a sub-spoke; the deployed service connects
            # separately under its own spoke_id.
            if role_name in _DEPLOY_ROLES:
                if self._deploy_task and not self._deploy_task.done():
                    return {"status": "ERROR",
                            "message": "A deployment is already running",
                            "deploy_status": self._deploy_status}
                spec = _DEPLOY_ROLES[role_name]
                self._deploy_role = role_name
                deploy_cmd = self._build_deploy_cmd(role_name, spec,
                                                    data.get("config") or {})
                self._deploy_task = asyncio.create_task(
                    self._run_deploy(role_name, deploy_cmd))
                return {"status": "SUCCESS", "role": role_name,
                        "module_type": spec["module_type"], "deploy": True,
                        "message": f"Deployment of '{role_name}' started in background"}
            if role_name not in _ROLE_MAP:
                return {"status": "ERROR", "message": f"Unknown role '{role_name}'",
                        "available": list(_ROLE_MAP.keys()) + list(_DEPLOY_ROLES.keys())}
            # Idempotent: re-loading an already-hosted role is a no-op success
            # (boot _seed + a runtime LOAD could otherwise double-spawn).
            if role_name in self._roles:
                return {"status": "SUCCESS", "role": role_name,
                        "sub_spoke_id": self._roles[role_name]["conn"].spoke_id,
                        "module_type": _ROLE_MAP[role_name][2],
                        "message": f"Role '{role_name}' already loaded"}
            install_result = await self._install_role(role_name)
            if install_result["status"] != "SUCCESS":
                return install_result
            role_config = data.get("config", {})
            sub_spoke_id = f"{self.spoke_id}-{role_name}"
            inst = self._sync_load_role(role_name, role_config, sub_spoke_id)
            if inst is None:
                return {"status": "ERROR", "message": f"Could not load role '{role_name}'"}
            _, _, mtype, _ = _ROLE_MAP[role_name]
            # Spawn a RoleConnection sub-spoke: an independent hub connection
            # under {base}-{role} with the role's module_type. The hub routes
            # role commands to it via get_spoke_by_type and auto-approves it via
            # the parent agent (parent_spoke_id). The base agent does NOT morph
            # — it stays "agent" and hosts this sub-spoke alongside any others.
            cp = getattr(self, "control_plane", None)
            if cp is None:
                return {"status": "ERROR",
                        "message": "Agent control plane not wired — cannot spawn role connection"}
            if RoleConnection is None:
                return {"status": "ERROR",
                        "message": "RoleConnection unavailable — control_plane module "
                                   "not fully loaded"}
            conn = RoleConnection(role_name, base_id=self.spoke_id,
                                  hub_url=cp.hub_url, role_instance=inst)
            task = asyncio.create_task(conn.run())
            self._roles[role_name] = {"instance": inst, "conn": conn, "task": task}
            self._persist_loaded_roles()
            return {"status": "SUCCESS", "role": role_name, "module_type": mtype,
                    "sub_spoke_id": sub_spoke_id,
                    "message": f"Role '{role_name}' hosted as sub-spoke {sub_spoke_id} ({mtype})"}

        if cmd == "GET_DEPLOY_STATUS":
            # netbox_installed survives an agent reload (which clears the live
            # _deploy_status), so the WebUI can persistently offer the "reset
            # NetBox admin password" knob on nodes that ran the netbox-server role.
            return {"status": "SUCCESS", "deploy": self._deploy_status,
                    "active_role": self._deploy_role,
                    "netbox_installed": os.path.exists("/opt/netbox-app/venv/bin/python3")}

        if cmd == "NETBOX_RESET_ADMIN_PASSWORD":
            # Reset the admin password on the NetBox app this agent deployed
            # (netbox-server role). Runs install.sh's fast --reset-admin-password
            # path (no reinstall) and returns the result inline for the WebUI.
            pw = data.get("password") or (data.get("config") or {}).get("admin_password")
            user = (data.get("username") or (data.get("config") or {}).get("admin_user")
                    or "admin")
            if not pw:
                return {"status": "ERROR", "message": "password is required"}
            reset_cmd = ["bash", "-c",
                         "exec </dev/null; curl -sSL "
                         "https://raw.githubusercontent.com/lbockenstedt/netbox/main/install.sh "
                         "| bash -s -- --reset-admin-password " + shlex.quote(str(pw))
                         + " --admin-user " + shlex.quote(str(user))]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *reset_cmd, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT)
                stdout, _ = await proc.communicate()
                rc = proc.returncode
                tail = (stdout or b"").decode(errors="replace")[-1500:]
                if rc == 0:
                    logger.info("NetBox admin password reset for '%s'.", user)
                    return {"status": "SUCCESS",
                            "message": f"Admin password reset for '{user}'.", "tail": tail}
                logger.error("NetBox admin password reset failed (rc=%s):\n%s", rc, tail)
                return {"status": "ERROR",
                        "message": f"Reset failed (rc={rc}) — is NetBox installed on this node?",
                        "tail": tail}
            except Exception as e:
                logger.error("NetBox admin password reset raised: %s", e)
                return {"status": "ERROR", "message": str(e)}

        if cmd == "UNLOAD_ROLE":
            role_name = data.get("role")
            # Backward-compat: no role arg + exactly one loaded role → that one.
            if not role_name:
                if len(self._roles) == 1:
                    role_name = next(iter(self._roles))
                elif not self._roles:
                    return {"status": "SUCCESS", "message": "No active role"}
                else:
                    return {"status": "ERROR",
                            "message": "Multiple roles loaded; specify 'role' to unload",
                            "active": list(self._roles.keys())}
            if role_name not in self._roles:
                return {"status": "ERROR", "message": f"Role '{role_name}' is not loaded",
                        "active": list(self._roles.keys())}
            await self._stop_role(role_name)
            return {"status": "SUCCESS", "role": role_name,
                    "message": f"Role '{role_name}' unloaded (sub-spoke disconnected)"}

        if cmd == "UPDATE_CONFIG":
            self.config = data
            return {"status": "SUCCESS"}

        # Role commands are NOT handled here: they arrive on each role's own
        # RoleConnection (routed by module_type), not on the base agent. The
        # base handles only its own commands above (+ deploy roles).

        return {"status": "ERROR",
                "message": f"Unknown agent command '{command_type}'. "
                           f"Loaded roles: {list(self._roles.keys()) or 'none'}"}

    async def _stop_role(self, role_name: str) -> None:
        """Tear down a loaded role: cancel its RoleConnection run loop (the
        async-with websockets.connect closes the socket on CancelledError),
        await cleanup, drop it from the registry, and persist LOADED_ROLES so
        the role is not re-spawned on the next boot."""
        entry = self._roles.pop(role_name, None)
        if entry is None:
            return
        conn = entry["conn"]
        task = entry["task"]
        try:
            ws = getattr(conn, "_hub_ws", None)
            if ws is not None:
                await ws.close()
        except Exception as e:
            logger.debug("close on unload of %s failed: %s", role_name, e)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        logger.info("Role unloaded: %s (sub-spoke %s)", role_name, conn.spoke_id)
        self._persist_loaded_roles()

    def _persist_loaded_roles(self) -> None:
        """Persist the loaded-role set to .env (LOADED_ROLES) so runtime-loaded
        roles survive a self-update restart (the RoleConnection SPOKE_UPDATE
        handler exits the whole process; AgentControlPlane re-spawns every role
        in LOADED_ROLES on the next boot). No-op if the control plane isn't
        wired yet (e.g. construction-time)."""
        cp = getattr(self, "control_plane", None)
        if cp is None:
            return
        roles = sorted(self._roles.keys())
        try:
            cp._persist_secret_to_env("LOADED_ROLES", ",".join(roles))
        except Exception as e:
            logger.warning("Could not persist LOADED_ROLES: %s", e)

    async def get_status(self) -> Dict[str, Any]:
        roles_status = []
        for role_name, entry in self._roles.items():
            conn = entry["conn"]
            roles_status.append({
                "role": role_name,
                "sub_spoke_id": conn.spoke_id,
                "module_type": conn.module_type,
                "connected": getattr(conn, "_hub_ws", None) is not None,
            })
        return {
            "spoke_id": self.spoke_id,
            "module":   "generic-agent",
            "roles":    roles_status,
            "status":   "IDLE" if not self._roles else "HOSTING",
            "deploy":   self._deploy_status,
        }

    def get_version(self) -> str:
        try:
            return (self._lm_root() / "agent" / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
