import asyncio
import importlib.util
import logging
import os
import shlex
import socket
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

# Root LDAPS cert-install helper dropped by ldap/install_ldap.sh --infra-only.
# Its presence marks this host as the LDAP (ldaps) server (see the INSTALL_CERT
# handler + AgentControlPlane._extra_auth_fields advertising "ldap_server").
_LDAP_INSTALL_CERT_HELPER = "/usr/local/bin/lm-ldap-install-cert"

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

# ── apt lock contention ───────────────────────────────────────────────────────
# By default apt takes /var/lib/dpkg/lock-frontend or dies instantly with
# rc=100 ("Could not get lock ... It is held by process N"). On a managed node
# there are several legitimate apt users — role deploys (install_dns.sh,
# install_dhcp.sh, ...), LM's own OS-update feature (core/src/os_update.py runs
# apt-get dist-upgrade), and the distro's unattended-upgrades timer — so a
# deploy that merely lands while another apt is mid-run FAILS, and the operator
# sees a package error for what is only a scheduling collision.
#
# DPkg::Lock::Timeout (apt >= 1.9.11, i.e. Debian 11 / Ubuntu 20.04 and newer)
# makes apt WAIT for the lock instead. Unknown -o keys are ignored by older
# apt, so setting it is safe on anything we might be running on.
_APT_LOCK_TIMEOUT_S = 600
# Written node-wide so EVERY apt invocation inherits the wait — the module
# install scripts and os_update shell out on their own and are not all reachable
# from here, and future ones would otherwise have to remember the flag.
_APT_CONF_DROPIN = "/etc/apt/apt.conf.d/99lm-lock-timeout"
_APT_LOCK_FLAGS = ["-o", f"DPkg::Lock::Timeout={_APT_LOCK_TIMEOUT_S}"]
# Must exceed the lock wait, or we would kill apt for doing exactly what we
# just asked it to do: wait. Lock wait + a slow mirror's install time.
_APT_INSTALL_TIMEOUT_S = _APT_LOCK_TIMEOUT_S + 600


def ensure_apt_lock_timeout(path: str = _APT_CONF_DROPIN,
                            timeout_s: int = _APT_LOCK_TIMEOUT_S) -> bool:
    """Drop a node-wide apt config making apt wait for the dpkg lock.

    Best-effort and idempotent. Applied at agent startup rather than only at
    install time so nodes provisioned before this existed self-heal as soon as
    the agent restarts, which it does on every SPOKE_UPDATE.
    """
    desired = (
        "// Managed by LM GenericAgent — do not edit.\n"
        "// Wait for the dpkg/apt lock instead of failing with rc=100 when a\n"
        "// role deploy collides with unattended-upgrades or an LM OS update.\n"
        f'DPkg::Lock::Timeout "{timeout_s}";\n'
    )
    try:
        p = Path(path)
        if p.read_text() == desired:
            return True
    except (OSError, UnicodeDecodeError):
        pass
    try:
        p = Path(path)
        if not p.parent.is_dir():
            # Not a Debian-family host (no apt at all) — nothing to configure.
            return False
        p.write_text(desired)
        logger.info("Configured apt to wait up to %ss for the dpkg lock (%s).",
                    timeout_s, path)
        return True
    except PermissionError:
        # The agent normally runs as root; if it does not, the explicit -o
        # flags on the calls below still cover the deploys we run ourselves.
        logger.warning("Cannot write %s (not root); apt lock waits will only "
                       "apply to package installs this agent runs directly.", path)
        return False
    except OSError as exc:
        logger.warning("Could not configure the apt lock timeout at %s: %s", path, exc)
        return False

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

logger = logging.getLogger("GenericAgent")


def _is_base_spoke(obj) -> bool:
    """Robust ``isinstance(obj, BaseSpoke)`` that survives base_spoke's
    dual-import identity split.

    The agent imports ``base_spoke`` (this module) while a role repo (e.g. cs's
    cs_spoke.py) imports ``core.src.base_spoke`` — SAME source file, but Python
    keys modules by name, so the two ``BaseSpoke`` classes are DISTINCT objects
    and a plain ``isinstance`` against one returns False for a spoke built
    against the other. That false-negative wrongly wraps a genuine BaseSpoke
    subclass (cs's CSSpoke) in ``_RoleAdapter``; RoleConnection then wires
    ``control_plane`` onto the ADAPTER, leaving the inner spoke's
    ``control_plane`` None — so its SPOKE_RELAY handler can never
    ``approve_pending_agent`` (hosted agents flap in "pending" forever). Match
    by isinstance first, then fall back to a name check across the MRO."""
    if isinstance(obj, BaseSpoke):
        return True
    return any(getattr(c, "__name__", "") == "BaseSpoke" for c in type(obj).__mro__)

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
#   repo_url   — None for roles that ship inside the lm repo (dns, dhcp, henet);
#                otherwise the GitHub URL the agent shallow-clones on LOAD_ROLE
#                when the spoke code isn't already present on the node.
_ROLE_MAP = {
    "dns":        ("dns/src/dns_spoke.py",          "DNSSpoke",  "dns",        None),
    "henet":      ("henet/src/henet_spoke.py",      "HENetSpoke", "henet",     None),
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
    "proxy":      ("proxy/src/proxy_spoke.py",      "ProxySpoke", "proxy",       None),
    "truenas":    ("truenas/src/truenas_spoke.py",  "TruenasSpoke", "storage",   "https://github.com/lbockenstedt/truenas.git"),
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
    "henet":      ("HENet",),
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
    "proxy":      ("ProxySpoke",),
    "truenas":    ("Truenas",),
}

# Deploy roles: instead of morphing the agent into a service, these run an
# install script that deploys an external service as its own systemd unit.
# The deployed service connects to the Hub independently (under its own
# spoke_id), so the generic agent keeps module_type "agent" and stays online.
# Each entry: {"cmd": [...], "module_type": <agent's type after deploy>}
def _infra_install_cmd(installer_url: str) -> list:
    """Background curl-fetch + run of a role installer's ``--infra-only`` mode
    (the same shape the netbox-server deploy role uses inline). Kept as a helper
    so a new deploy role is one line + a URL. ``_build_deploy_cmd`` appends the
    per-load flags after ``--infra-only``."""
    fetch = "exec </dev/null; curl -sSL " + shlex.quote(installer_url) + " "
    return ["bash", "-c", fetch + "| bash -s -- --infra-only"]


_LDAP_INSTALLER_URL = "https://raw.githubusercontent.com/lbockenstedt/ldap/main/install_ldap.sh"
# dns/dhcp installers live IN the lm repo (in-repo modules), so their deploy-role
# installer URL is the lm raw path (not a sibling repo like netbox/ldap).
_DNS_INSTALLER_URL = "https://raw.githubusercontent.com/lbockenstedt/lm/main/dns/install_dns.sh"
_DHCP_INSTALLER_URL = "https://raw.githubusercontent.com/lbockenstedt/lm/main/dhcp/install_dhcp.sh"

_DEPLOY_ROLES: Dict[str, Dict[str, Any]] = {
    "ab": {
        "cmd": ["bash", "-c",
                "exec </dev/null; curl -sSL "
                "https://raw.githubusercontent.com/lbockenstedt/ab/main/install.sh "
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
    # LDAP SERVER: deploy OpenLDAP (slapd + ldaps + optional 2-node delta-syncrepl
    # mirror + the lm-ldap-install-cert helper) via the ldap installer's
    # --infra-only mode. Stands up the server but NOT an lm-ldap spoke unit — the
    # directory MODULE that talks to it is the SEPARATE "ldap" role (module_type
    # "directory") in _ROLE_MAP. Per-load config (base-dn/admin-dn/admin-pw/
    # server-id/peer/server-url + hub-injected entra creds) is appended as
    # installer flags by _build_deploy_cmd/_ldap_server_install_args. Mirrors
    # netbox-server.
    "ldap-server": {
        "cmd": _infra_install_cmd(_LDAP_INSTALLER_URL),
        "module_type": "agent",
    },
    # DNS SERVER: deploy Unbound (server + remote-control + conf.d include) via the
    # dns installer's --infra-only mode — stands up the server but NOT an lm-dns
    # spoke unit. The DNS MODULE that manages it is the SEPARATE "dns" role
    # (module_type "dns") in _ROLE_MAP; load that too. Mirrors netbox-server/
    # ldap-server so the server deploy and the management spoke are independent.
    "dns-server": {
        "cmd": _infra_install_cmd(_DNS_INSTALLER_URL),
        "module_type": "agent",
    },
    # DHCP SERVER: deploy Kea (kea-dhcp4-server + kea-ctrl-agent on :8001) via the
    # dhcp installer's --infra-only mode — server only, NOT an lm-dhcp spoke unit.
    # The DHCP MODULE that manages it is the SEPARATE "dhcp" role (module_type
    # "dhcp") in _ROLE_MAP. Mirrors netbox-server/ldap-server.
    "dhcp-server": {
        "cmd": _infra_install_cmd(_DHCP_INSTALLER_URL),
        "module_type": "agent",
    },
}

_DEPLOY_ROLE_MARKERS = {
    "ab": "/etc/systemd/system/ab.service",
    "netbox-server": "/opt/netbox-app/venv/bin/python3",
    "ldap-server": "/usr/sbin/slapd",
    "dns-server": "/usr/sbin/unbound",
    "dhcp-server": "/usr/sbin/kea-dhcp4",
}

_DEPLOY_ROLE_UNITS = {
    "dns-server": ("unbound",),
    "dhcp-server": ("kea-dhcp4-server", "kea-ctrl-agent"),
}

# Units a cluster deploy ALSO leaves behind. They are stopped on unload but are
# deliberately NOT part of _DEPLOY_ROLE_UNITS: a single-host node never has them,
# and requiring them for the "is this role active" probe would report every
# non-clustered dns/dhcp server as inactive. Without stopping these, unloading a
# server role left the cluster worker (and the Kea HA control agent) running and
# still talking to a coordinator that no longer manages this node.
_DEPLOY_ROLE_EXTRA_UNITS = {
    "dns-server": ("lm-dns-worker",),
    "dhcp-server": ("lm-dhcp-worker", "kea-ha-agent"),
}


def _configured_service_workers() -> list:
    """Non-secret identity for configured DNS/DHCP worker sidecars."""
    out = []
    for role, path, prefix in (
        ("dns-server", "/etc/lm-dns-worker/worker.env", "LM_DNS"),
        ("dhcp-server", "/etc/lm-dhcp-worker/worker.env", "LM_DHCP"),
    ):
        if not os.path.exists(path):
            continue
        values = {}
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep and key in (f"{prefix}_MEMBER_ID",
                                   f"{prefix}_COORDINATOR"):
                    values[key] = value.strip()
        except OSError:
            pass
        out.append({
            "role": role,
            "member_id": values.get(f"{prefix}_MEMBER_ID", ""),
            "coordinator": values.get(f"{prefix}_COORDINATOR", ""),
        })
    return out


def _active_deploy_roles(installed_roles: list) -> list:
    active = []
    for role, units in _DEPLOY_ROLE_UNITS.items():
        if role not in installed_roles:
            continue
        try:
            enabled = all(
                subprocess.run(
                    ["systemctl", "is-enabled", "--quiet", unit],
                    capture_output=True, check=False, timeout=10,
                ).returncode == 0
                for unit in units
            )
        except (OSError, subprocess.SubprocessError):
            enabled = False
        if enabled:
            active.append(role)
    return active

class _RoleAdapter(BaseSpoke):
    """Adapter that lets a non-BaseSpoke spoke (e.g. cppm's CPPMSpoke) be loaded
    as a role. Delegates handle_command/get_version to the inner instance and
    supplies a get_status fallback when the inner class doesn't implement it,
    so GenericAgent.get_status() delegation never AttributeErrors."""

    def __init__(self, inner):
        super().__init__(getattr(inner, "spoke_id", "role"), getattr(inner, "config", {}))
        self._inner = inner

    # RoleConnection wires the sub-spoke's control plane via
    # ``role_instance.control_plane = self``. Forward that write (and reads) to
    # the INNER spoke so its command handlers — e.g. cs's SPOKE_RELAY →
    # ``self.control_plane.approve_pending_agent`` — see the wired plane. Without
    # this, an adapter-wrapped spoke's inner ``control_plane`` stays None and
    # hosted-agent approval silently no-ops. Defense-in-depth alongside
    # _is_base_spoke (which avoids wrapping genuine BaseSpokes in the first place).
    @property
    def control_plane(self):
        inner = getattr(self, "_inner", None)
        return getattr(inner, "control_plane", None) if inner is not None else None

    @control_plane.setter
    def control_plane(self, value):
        if hasattr(self, "_inner"):
            try:
                self._inner.control_plane = value
            except Exception:  # noqa: BLE001 - inner may forbid the attr
                pass

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
        # Background deployment state for deploy roles (e.g. ab).
        self._deploy_role: Optional[str] = None
        self._deploy_task: Optional[asyncio.Task] = None
        self._deploy_status: Dict[str, Any] = {"state": "idle"}
        # Roles with an _install_role currently running (installs are offloaded
        # to threads, so a second LOAD_ROLE for the same role could otherwise
        # start a concurrent apt/pip run mid-install → double-spawn).
        self._role_installs_inflight: set = set()
        # Make apt wait for the dpkg lock rather than failing a deploy that
        # merely collided with another apt run. Cheap, idempotent, best-effort.
        ensure_apt_lock_timeout()

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
        # so handle_command/get_status delegation stays uniform. Use the
        # dual-import-safe check so a genuine BaseSpoke subclass (cs's CSSpoke,
        # built against core.src.base_spoke) is NOT needlessly wrapped — which
        # would strand its control_plane on the adapter (see _is_base_spoke).
        if not _is_base_spoke(inst):
            inst = _RoleAdapter(inst)
        logger.info("Role loaded: %s (sub-spoke %s)", role_name,
                    sub_spoke_id or f"{self.spoke_id}-{role_name}")
        return inst

    async def _install_role(self, role_name: str) -> dict:
        """Clone the role repo (if external) and install its system + Python deps.

        The clone/apt/pip/installer subprocesses are offloaded via
        asyncio.to_thread — inline they froze the agent's event loop (and its
        heartbeats) for up to 600s on heavy roles. An in-progress guard rejects
        a second install of the same role while one runs (the offload means a
        concurrent LOAD_ROLE can now actually interleave here)."""
        if role_name not in _ROLE_MAP:
            return {"status": "ERROR", "message": f"Unknown role '{role_name}'"}
        if role_name in self._role_installs_inflight:
            return {"status": "ERROR",
                    "message": f"Install of role '{role_name}' already in progress"}
        self._role_installs_inflight.add(role_name)
        try:
            return await self._install_role_inner(role_name)
        finally:
            self._role_installs_inflight.discard(role_name)

    async def _install_role_inner(self, role_name: str) -> dict:
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
                    await asyncio.to_thread(
                        subprocess.run,
                        ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
                        check=True, timeout=300,
                    )
                except subprocess.CalledProcessError as e:
                    return {"status": "ERROR",
                            "message": f"git clone for role '{role_name}' failed: {e}"}
            else:
                logger.debug("Role repo already present at %s; skipping clone.", clone_dir)

        # 2. System packages. Management-only roles such as dns do not install
        # the service they coordinate; that belongs to the separate dns-server
        # deploy role. le needs certbot + common DNS-01 plugins.
        install_cmds = {
            "dhcp": ["apt-get", *_APT_LOCK_FLAGS, "install", "-y", "-qq",
                     "kea-dhcp4-server", "kea-ctrl-agent"],
            "le":   ["apt-get", *_APT_LOCK_FLAGS, "install", "-y", "-qq", "certbot",
                     "python3-certbot-dns-cloudflare", "python3-certbot-dns-route53",
                     "openssl"],
            # ldap: BUILD deps for python-ldap (the pip wheel compiles against
            # these). Without them `pip install python-ldap` fails and the role
            # crashes on load with "No module named 'ldap.filter'" — the role
            # never loads. Must run BEFORE the pip step below. The slapd SERVER
            # (interactive debconf) is set up in _role_post_install, not here.
            "ldap": ["apt-get", *_APT_LOCK_FLAGS, "install", "-y", "-qq",
                     "libldap2-dev", "libsasl2-dev"],
        }
        cmds = install_cmds.get(role_name)
        if cmds:
            logger.info("Installing system packages for role '%s'…", role_name)
            try:
                await asyncio.to_thread(subprocess.run, cmds, check=True,
                                        timeout=_APT_INSTALL_TIMEOUT_S)
            except subprocess.CalledProcessError as e:
                return {"status": "ERROR", "message": f"Package install failed: {e}"}

        # 2b. Module-specific OS bootstrapping the DEDICATED installers used to
        #     do where the hosted role still owns local infrastructure (dhcp
        #     needs a non-interactive kea-ctrl-agent config + daemons started).
        #     Idempotent + best-effort; a config hiccup must not fail the load.
        #     Offloaded whole: it shells out (up to 600s for --infra-only).
        await asyncio.to_thread(self._role_post_install, role_name)

        # 3. Python deps. requirements.txt sits at role_file.parent.parent for
        #    every role (repo root for most; cs/lm-spoke/ for simulation).
        req_file = role_file.parent.parent / "requirements.txt"
        if req_file.exists():
            logger.info("Installing Python deps for role '%s'…", role_name)
            venv_pip = self._lm_root() / "agent" / "venv" / "bin" / "pip"
            try:
                await asyncio.to_thread(
                    subprocess.run,
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
        Pure management/API roles (dns/opnsense/netbox/cppm/ldap/le/nw/pxmx)
        need nothing here.
        Runs as root (the lm-agent unit is User=root)."""
        try:
            if role_name == "dns":
                tls_dir = Path("/etc/lm-dns/tls")
                cert = tls_dir / "coordinator.crt"
                key = tls_dir / "coordinator.key"
                tls_dir.mkdir(parents=True, exist_ok=True)
                if not (cert.is_file() and key.is_file()):
                    hostname = socket.getfqdn() or socket.gethostname() or "lm-dns"
                    subprocess.run(
                        [
                            "openssl", "req", "-x509", "-newkey", "rsa:2048",
                            "-nodes", "-days", "3650",
                            "-keyout", str(key), "-out", str(cert),
                            "-subj", f"/CN={hostname}",
                            "-addext", f"subjectAltName=DNS:{hostname}",
                        ],
                        check=True, capture_output=True, timeout=30,
                    )
                os.chmod(cert, 0o644)
                os.chmod(key, 0o600)
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
        elif role_name == "ldap-server":
            extra = self._ldap_server_install_args(config or {})
            if extra and cmd and cmd[-1].rstrip().endswith("--infra-only"):
                cmd[-1] = cmd[-1] + extra
        elif role_name in ("dns-server", "dhcp-server"):
            extra = self._service_worker_install_args(role_name, config or {})
            if extra and cmd and cmd[-1].rstrip().endswith("--infra-only"):
                cmd[-1] = cmd[-1] + extra
        return cmd

    @staticmethod
    def _service_worker_install_args(role_name, config: dict = None) -> str:
        """Project a dns-server/dhcp-server LOAD_ROLE ``config`` into the
        cluster-worker installer flags appended after ``--infra-only``.

        Present → the installer also lays down the ``lm-dns-worker`` /
        ``lm-dhcp-worker`` unit that dials the managing module's coordinator
        listener, which is what turns two independently-deployed service hosts
        into one managed cluster. Absent (the pre-existing single-host flow) →
        nothing is appended and the deploy is byte-identical to before."""
        if config is None:
            config = role_name
            role_name = "dns-server"
        member_id = config.get("member_id") or config.get("id")
        coordinator = config.get("coordinator") or config.get("coordinator_url")
        secret = config.get("worker_secret") or config.get("secret")
        if not (member_id and coordinator and secret):
            return ""
        parts = ["", *(" --" + flag + " " + shlex.quote(str(value))
                       for flag, value in (("member-id", member_id),
                                           ("coordinator", coordinator),
                                           ("worker-secret", secret)))]
        # Coordinator trust anchor: the worker VERIFIES the coordinator's cert
        # before sending its secret, so the installer refuses to run without one.
        ca = config.get("ca_cert") or config.get("coordinator_ca")
        ca_pem = str(config.get("coordinator_ca_pem") or "").strip()
        if ca_pem:
            if ("-----BEGIN CERTIFICATE-----" not in ca_pem
                    or "-----END CERTIFICATE-----" not in ca_pem
                    or len(ca_pem) > 65536):
                raise ValueError("coordinator_ca_pem is not a valid PEM certificate")
            service = role_name.removesuffix("-server")
            ca_path = Path(f"/etc/lm-{service}-worker/coordinator-ca.pem")
            ca_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = ca_path.with_suffix(".tmp")
            tmp.write_text(ca_pem + "\n", encoding="utf-8")
            os.chmod(tmp, 0o644)
            os.replace(tmp, ca_path)
            ca = str(ca_path)
        if ca:
            parts.append(" --ca-cert " + shlex.quote(str(ca)))
        # Kea HA channel: credentials + peer scope + mutual-TLS material. These
        # are per-node install-time inputs; without forwarding them the deploy
        # role produced a node that could never join its pair.
        for flag, key in (("ha-user", "ha_user"), ("ha-password", "ha_password"),
                          ("ha-port", "ha_port"), ("ha-ca", "ha_ca"),
                          ("ha-cert", "ha_cert"), ("ha-key", "ha_key")):
            value = config.get(key)
            if value:
                parts.append(" --" + flag + " " + shlex.quote(str(value)))
        peers = config.get("ha_peers") or config.get("ha_peer") or []
        if isinstance(peers, str):
            peers = [p.strip() for p in peers.split(",") if p.strip()]
        for peer in peers:
            parts.append(" --ha-peer " + shlex.quote(str(peer)))
        return "".join(parts)

    @staticmethod
    def _ldap_server_install_args(config: dict) -> str:
        """Project the ldap-server LOAD_ROLE ``config`` into install_ldap.sh flags
        appended after ``--infra-only``. The WebUI collects the topology
        (base-dn, admin-dn, server-id 1|2, peer ldaps:// URLs, server-url); the
        HUB injects the Entra creds (entra_tenant/client/cert/key from
        get_oidc_config). Flags accepted by the installer (finalized contract):
        --base-dn --admin-dn --admin-pw --server-id --peer(repeatable)
        --entra-tenant --entra-client --entra-cert --entra-key --entra-scope
        (default "openid") --server-url. Auto-generates --admin-pw when the WebUI
        didn't collect one. All values shlex-quoted."""
        parts = []

        def _flag(name, value):
            if value not in (None, "", []):
                parts.append("--" + name + " " + shlex.quote(str(value)))

        _flag("base-dn", config.get("base_dn"))
        _flag("admin-dn", config.get("admin_dn"))
        pw = config.get("admin_pw") or config.get("admin_password")
        if not pw:
            import secrets as _secrets
            pw = _secrets.token_urlsafe(24)
        _flag("admin-pw", pw)
        _flag("server-id", config.get("server_id"))
        # --peer is repeatable, one per mirror peer (the OTHER node's ldaps:// URL).
        peers = config.get("peers") or config.get("peer") or []
        if isinstance(peers, str):
            peers = [peers]
        for p in peers:
            _flag("peer", p)
        _flag("server-url", config.get("server_url"))
        _flag("entra-tenant", config.get("entra_tenant"))
        _flag("entra-client", config.get("entra_client"))
        _flag("entra-cert", config.get("entra_cert"))
        _flag("entra-key", config.get("entra_key"))
        _flag("entra-scope", config.get("entra_scope") or "openid")
        return (" " + " ".join(parts)) if parts else ""

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

    async def _provision_netbox_cert_helper(self) -> bool:
        """Self-heal a missing ``/usr/local/bin/lm-netbox-install-cert`` by
        re-running the netbox installer's ``--provision-cert-helper`` mode
        (helper + sudoers ONLY — no Postgres/Redis/gunicorn/nginx, no service
        restart). Reuses the same curl-pipe-bash the netbox-server role deploy
        uses (``_DEPLOY_ROLES["netbox-server"]``). The generic agent unit is
        ``User=root`` so this writes ``/usr/local/bin`` + ``/etc/sudoers.d``
        directly — no sudo. Idempotent. Returns True iff the helper exists
        afterward. Only called on the rare missing-helper path, not every
        cert install — so the GitHub-fetch dependency is the same as the
        initial role deploy, not on the hot path."""
        cmd = ["bash", "-c",
               "exec </dev/null; curl -sSL "
               "https://raw.githubusercontent.com/lbockenstedt/netbox/main/install.sh "
               "| bash -s -- --provision-cert-helper"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=120.0)
            if proc.returncode != 0:
                logger.warning("[cert] netbox cert helper self-provision failed: %s",
                               (out or b"").decode(errors="replace")[-500:])
                return False
            return os.path.exists(_NETBOX_INSTALL_CERT_HELPER)
        except Exception as e:  # noqa: BLE001
            logger.warning("[cert] netbox cert helper self-provision exception: %s", e)
            return False

    async def _install_netbox_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Install an LE cert onto this host's NetBox nginx via the root helper.
        Mirrors netbox_spoke's INSTALL_CERT: validate the fullchain+privkey pair
        in-process, then run /usr/local/bin/lm-netbox-install-cert <crt> <key>."""
        domain = data.get("domain", "") or ""
        fullchain = data.get("fullchain", "") or ""
        privkey = data.get("privkey", "") or ""
        if not fullchain or not privkey:
            return {"status": "ERROR", "message": "missing cert material"}
        if "BEGIN CERTIFICATE" not in fullchain or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "fullchain/privkey not PEM"}
        # Self-heal: the netbox-server role provisions the cert helper at
        # install.sh --infra-only time, but if it's missing (deleted / drifted /
        # role reloaded partially) re-provision it on demand instead of failing
        # and requiring a manual reinstall. The generic agent unit is User=root
        # (install_agent.sh:476) so this can write /usr/local/bin + /etc/sudoers.d
        # directly — no sudo needed. Only hit on the rare missing-helper path.
        if not os.path.exists(_NETBOX_INSTALL_CERT_HELPER):
            logger.info("[cert] %s → netbox-server: helper %s missing — "
                        "self-provisioning…", domain, _NETBOX_INSTALL_CERT_HELPER)
            ok = await self._provision_netbox_cert_helper()
            if not ok or not os.path.exists(_NETBOX_INSTALL_CERT_HELPER):
                logger.warning("[cert] %s → netbox-server: FAILED — helper missing "
                               "and self-provision failed", domain)
                return {"status": "ERROR",
                        "message": ("cert helper missing and self-provision failed "
                                    "(re-load the netbox-server role)")}
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

    async def _install_ldap_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Install an LE cert onto this host's OpenLDAP (ldaps) via the root
        helper dropped by the ldap installer (--infra-only). Mirrors
        :meth:`_install_netbox_cert`: validate the fullchain+privkey pair
        in-process, then run ``sudo -n /usr/local/bin/lm-ldap-install-cert
        <crt> <key>`` which atomically swaps the slapd TLS material + reloads."""
        domain = data.get("domain", "") or ""
        fullchain = data.get("fullchain", "") or ""
        privkey = data.get("privkey", "") or ""
        if not fullchain or not privkey:
            return {"status": "ERROR", "message": "missing cert material"}
        if "BEGIN CERTIFICATE" not in fullchain or "PRIVATE KEY" not in privkey:
            return {"status": "ERROR", "message": "fullchain/privkey not PEM"}
        if not os.path.exists(_LDAP_INSTALL_CERT_HELPER):
            return {"status": "ERROR",
                    "message": (f"cert helper {_LDAP_INSTALL_CERT_HELPER} missing — "
                                "is this the ldap-server host? (re-load the "
                                "ldap-server role)")}
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
                logger.warning("[cert] %s → ldap-server: FAILED — validation: %s", domain, e)
                return {"status": "ERROR", "message": f"cert validation failed (helper not called): {e}"}
            try:
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "-n", _LDAP_INSTALL_CERT_HELPER, crt_tmp, key_tmp,
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
                logger.info("[cert] %s → ldap-server: installed — %s", domain, out[2:].strip() or out)
                return {"status": "SUCCESS", "message": out[2:].strip() or out or "installed on ldap-server"}
            msg = err or out or f"helper exit {proc.returncode}"
            logger.warning("[cert] %s → ldap-server: FAILED — %s", domain, msg)
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

        # ── Generic dumb-executor primitives ────────────────────────────────
        # The Agent runs whatever the spoke tells it — no product knowledge. The
        # spoke holds the logic; these are the hands. RUN_COMMAND (allowlist, or
        # allow_shell for spoke-trusted commands) + WRITE_FILE (place a file, e.g.
        # a TLS cert). Both return the raw runner/writer dict as ``result``.
        if cmd == "RUN_COMMAND":
            from command_runner import run_local_command
            res = await asyncio.to_thread(
                run_local_command,
                data.get("command", ""),
                bool(data.get("allow_shell", False)),
                float(data.get("timeout", 30.0) or 30.0))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}

        if cmd == "WRITE_FILE":
            from command_runner import write_local_file
            res = await asyncio.to_thread(
                write_local_file,
                data.get("path", ""),
                data.get("content", ""),
                b64=data.get("b64", ""),
                mode=int(data.get("mode", 0o600)),
                mkdirs=bool(data.get("mkdirs", True)),
                atomic=bool(data.get("atomic", True)))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}

        if cmd == "INSTALL_CERT":
            # A generic agent host that ran a *-server deploy role holds the root
            # cert helper for that service. The hub tags the target service in the
            # payload (module_type), so route to the matching helper: ldap-server
            # → OpenLDAP/ldaps, else netbox-server → NetBox nginx (the historical
            # default). Both validate the pair in-process then hand 0600 temp
            # files to the root helper that atomically swaps + reloads the service.
            if (data or {}).get("module_type") == "ldap-server":
                return await self._install_ldap_cert(data)
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
            installed_deploy_roles = [
                role for role, marker in _DEPLOY_ROLE_MARKERS.items()
                if os.path.exists(marker)
            ]
            active_deploy_roles = await asyncio.to_thread(
                _active_deploy_roles, installed_deploy_roles)
            configured_workers = _configured_service_workers()
            return {"status": "SUCCESS",
                    "roles": list(_ROLE_MAP.keys()),
                    "deploy_roles": list(_DEPLOY_ROLES.keys()),
                    "installed_deploy_roles": installed_deploy_roles,
                    "active_deploy_roles": active_deploy_roles,
                    "configured_worker_roles": [
                        item["role"] for item in configured_workers],
                    "configured_workers": configured_workers,
                    "deploy": self._deploy_status,
                    "active": [{"role": r,
                                "sub_spoke_id": e["conn"].spoke_id,
                                "module_type": e["conn"].module_type}
                               for r, e in self._roles.items()]}

        if cmd == "VOUCH_SUBSPOKE":
            # Parent attestation for parent-auto-approve (H3). The hub asks this
            # base agent — over the signed request_response channel — whether
            # <sub_spoke_id> is one of the role sub-spokes it actually spawned
            # and tracks. A signed yes lets the hub auto-approve + tenant-bind
            # the child WITHOUT trusting the child's self-claimed
            # parent_spoke_id (which is an unsigned WS-auth frame field); a no
            # (or an unknown id) leaves the child pending admin approval. This
            # closes the hostname-spoof sub-issue: identity is the parent's
            # signed vouch, not the child's string claim.
            #
            # Read-only over the in-memory role registry, so it's safe to
            # answer the moment the session key is pushed — the hub's vouch
            # request can land before this agent is fully approved, and signing
            # uses whatever current key the control plane holds. vouched=True
            # only for a sub_spoke_id this agent spawned (RoleConnection
            # registry keyed by sub_id = f"{base_id}-{role_name}").
            sub_id = (data or {}).get("sub_spoke_id", "")
            vouched = bool(sub_id) and any(
                e["conn"].spoke_id == sub_id for e in self._roles.values())
            return {"status": "SUCCESS",
                    "data": {"vouched": vouched, "sub_spoke_id": sub_id}}

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
            installed_deploy_roles = [
                role for role, marker in _DEPLOY_ROLE_MARKERS.items()
                if os.path.exists(marker)
            ]
            return {"status": "SUCCESS", "deploy": self._deploy_status,
                    "active_role": self._deploy_role,
                    "installed_deploy_roles": installed_deploy_roles,
                    "active_deploy_roles": await asyncio.to_thread(
                        _active_deploy_roles, installed_deploy_roles),
                    "netbox_installed": "netbox-server" in installed_deploy_roles}

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
            if role_name in _DEPLOY_ROLE_UNITS:
                module_role = role_name.removesuffix("-server")
                if module_role in self._roles:
                    return {
                        "status": "ERROR",
                        "message": (
                            f"Unload the '{module_role}' management role before "
                            f"stopping '{role_name}'."
                        ),
                    }
                if (self._deploy_task and not self._deploy_task.done()
                        and self._deploy_role == role_name):
                    return {
                        "status": "ERROR",
                        "message": f"Deployment of '{role_name}' is still running.",
                    }
                units = _DEPLOY_ROLE_UNITS[role_name]
                # Stop the cluster sidecars first (best-effort: a single-host
                # node has none). Leaving lm-*-worker running would keep a
                # removed node dialling its old coordinator, and kea-ha-agent
                # would keep the authenticated HA port open.
                extra = _DEPLOY_ROLE_EXTRA_UNITS.get(role_name, ())
                if extra:
                    await asyncio.to_thread(
                        subprocess.run,
                        ["systemctl", "disable", "--now", *extra],
                        capture_output=True, text=True, check=False, timeout=60,
                    )
                result = await asyncio.to_thread(
                    subprocess.run,
                    ["systemctl", "disable", "--now", *units],
                    capture_output=True, text=True, check=False, timeout=60,
                )
                if result.returncode != 0:
                    error = (result.stderr or result.stdout or "").strip()
                    return {
                        "status": "ERROR",
                        "message": error or f"Could not stop '{role_name}'.",
                    }
                self._deploy_status = {"state": "unloaded", "role": role_name}
                self._deploy_role = None
                return {
                    "status": "SUCCESS",
                    "role": role_name,
                    "deploy": True,
                    "message": (
                        f"Role '{role_name}' unloaded "
                        f"({', '.join(units)} stopped and disabled)"
                    ),
                }
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
        # The run task owns only the hub connection. A cluster-hosting role
        # (dns/dhcp) also holds a /ws/agent listener + module background loops
        # on separate tasks; without this the port stays bound and the role
        # cannot be re-loaded. Awaited here, outside the cancelled context.
        shutdown = getattr(conn, "shutdown", None)
        if callable(shutdown):
            try:
                await shutdown()
            except Exception as e:  # noqa: BLE001 — teardown is best-effort
                logger.warning("shutdown of role '%s' raised: %s", role_name, e)
        logger.info("Role unloaded: %s (sub-spoke %s)", role_name, conn.spoke_id)
        self._persist_loaded_roles(remove={role_name})

    def _persist_loaded_roles(self, *, remove: Optional[set] = None) -> None:
        """Persist the desired-role set to .env (LOADED_ROLES) so runtime-loaded
        roles survive a self-update restart (the RoleConnection SPOKE_UPDATE
        handler exits the whole process; AgentControlPlane re-spawns every role
        in LOADED_ROLES on the next boot). No-op if the control plane isn't
        wired yet (e.g. construction-time).

        The persisted set is the UNION of the roles already in .env and the
        roles currently loaded — a load never SHRINKS the durable set. This is
        critical during boot-seeding: roles load sequentially, and each one used
        to overwrite LOADED_ROLES with only the subset loaded so far, so a
        self-update restart landing mid-seed (e.g. while a later role's pip
        install runs) would freeze the persisted set at that partial subset and
        permanently evict every not-yet-loaded role. Removal happens ONLY via an
        explicit UNLOAD_ROLE (``remove=``), never as a side effect of a load."""
        cp = getattr(self, "control_plane", None)
        if cp is None:
            return
        try:
            existing = {r for r in cp._read_env_value("LOADED_ROLES").split(",")
                        if r.strip()}
            roles = (existing | set(self._roles.keys())) - (remove or set())
            cp._persist_secret_to_env("LOADED_ROLES", ",".join(sorted(roles)))
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
