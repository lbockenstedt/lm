import asyncio
import argparse
import json
import logging
import os
import secrets
import subprocess
import sys
import time
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
    from core.src.messaging.agent_hosting import AgentHostingControlPlane
except ImportError:
    from messaging.control_plane import BaseControlPlane
    from messaging.agent_hosting import AgentHostingControlPlane

import agent_spoke
from agent_spoke import GenericAgent, _ROLE_MAP, _ROLE_LOG_PREFIXES

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


# The base agent's checkout (INSTALL_DIR, e.g. /opt/lm) is ALWAYS the lm repo —
# it hosts role sub-spokes but its own code only ever comes from here. Its
# SPOKE_UPDATE self-update is pinned to this repo regardless of the repo_url the
# hub sends (see AgentControlPlane.handle_system_command).
_LM_REPO_URL = "https://github.com/lbockenstedt/lm.git"


class RoleConnection(AgentHostingControlPlane):
    """One independent hub connection per loaded role (multi-role agent).

    Subclasses ``AgentHostingControlPlane`` so the **proxmox** (hypervisor)
    role can serve a real ``/ws/agent`` listener — a pxmx node-agent dials the
    box running the pxmx role (``--spoke-ip <box>`` → ``ws://<box>:8766`` or
    ``wss://<box>:443``), and ``ProxmoxSpoke`` commands (``GET_AGENTS``,
    ``PXMX_LIST_VMS``, ``GET_NODE_STATS``, VNC…) read the inherited
    ``connected_agents`` / ``pending_agents`` / ``broadcast_to_agents`` /
    ``send_to_agent`` populated from that listener. Non-pxmx roles are gated
    off (``_agent_listener_enabled`` returns False) so they never bind a
    port; for them the agent-hosting state stays empty (inherited init), so
    any role module reading it still gets a clean empty result.

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
        # connected_agents / pending_agents / agent_signer / _agent_server_task
        # are initialized by AgentHostingControlPlane.__init__ (the mixin). The
        # pxmx (hypervisor) role binds a /ws/agent listener (see
        # _agent_listener_enabled + run); other roles never bind, so those
        # dicts stay empty — any role module reading them gets a clean empty
        # result.
        # Sub-spokes must NOT carry the base's install UUID (see class docstring).
        self.install_uuid = ""
        # Suppress the one-time "Hub secrets not configured" warning per role —
        # sub-spokes intentionally run zero-touch and re-provision via the parent.
        self._hub_secret_warned = True
        # Disk cache for the proxmox role's agent telemetry (survives a process
        # restart; served by ProxmoxSpoke as stale data until agents reconnect).
        # Mirrors PxmxControlPlane.__init__ (pxmx/src/control_plane.py);
        # harmless for non-pxmx roles (disk_cache stays {}).
        self._disk_cache_path = str(
            Path(__file__).resolve().parent.parent / "pxmx_agent_cache.json")
        self.disk_cache: dict = {}
        self._load_disk_cache()
        # The proxmox role authenticates inbound node-agents with an agent_secret
        # (the spoke-side PSK; approve_pending_agent provisions it to the agent on
        # approval). A standalone pxmx gets it from install_pxmx.sh writing
        # /etc/lm-agent/config.json; a generic-agent box loading the pxmx role has
        # no such install, so self-provision + persist one here. Without it the
        # zero-touch approval loop never completes (the agent only saves a truthy
        # provisioned secret — see pxmx agent _save_secret), pinning the agent in
        # APPROVAL_REQUIRED forever.
        if self._agent_listener_enabled():
            self._ensure_agent_secret()
        # The role instance handles this connection's commands; registered under
        # the role name so BaseControlPlane's first-module fallback routes to it.
        self.register_module(role_name, role_instance)
        # Multi-role log scoping: relay ONLY this role's loggers so the hub's
        # per-role agent_logs[spoke_id] bucket (keyed by this sub-spoke's
        # {base}-{role} id) holds just this role's lines — not every sibling's.
        # Without this, all N role sub-spokes + the base agent each relay the
        # full root stream under their own spoke_id, so CPPM logs appear under
        # OPNSense and vice versa. _ROLE_LOG_PREFIXES carries each role's
        # logger-name stems; names shared with lm/core (HubDiscovery/DepGuard/
        # UpdateRecovery) are NOT listed and fall through to the base bucket.
        self._log_relay_handler.set_include_prefixes(
            _ROLE_LOG_PREFIXES.get(role_name, ()))
        # Back-reference so the role can push UNSOLICITED signed frames to the hub
        # via send_to_hub — e.g. the console role's live serial output
        # (CONSOLE_DATA_UP) from its reader thread, or LE_CERT_RENEWED. Mirrors how
        # LEControlPlane / GenericAgent wire `.control_plane`; harmless for roles
        # that never use it.
        try:
            role_instance.control_plane = self
        except Exception:  # noqa: BLE001 - some inner instances may forbid attrs
            pass

    # ── Agent listener (proxmox role only) ───────────────────────────────────

    def _agent_listener_enabled(self) -> bool:
        """Only the pxmx (hypervisor) role hosts node-agents. Other roles
        (dns/dhcp/ldap/…) never bind a /ws/agent listener — the inherited
        AgentHostingControlPlane gate (always-on for pxmx) is overridden so a
        multi-role agent doesn't bind :8766/:443 for non-agent-hosting roles."""
        return self.role_name == "proxmox"

    async def run(self):
        """Start the hub WS connection (BaseControlPlane.run) and, for the
        proxmox role, the self-healing /ws/agent listener so pxmx node-agents
        can dial this box (``--spoke-ip <box>``). Mirrors
        PxmxControlPlane.run (pxmx/src/control_plane.py)."""
        if self._agent_listener_enabled():
            self._start_agent_server_task()
        await super().run()

    # ── Disk cache (proxmox role) — mirrors PxmxControlPlane ─────────────────

    def _load_disk_cache(self):
        """Load persisted agent telemetry from disk on startup."""
        try:
            if os.path.exists(self._disk_cache_path):
                with open(self._disk_cache_path) as f:
                    data = json.load(f)
                self.disk_cache = data.get("agents", {})
                age_h = (time.time() - data.get("saved_at", 0)) / 3600
                logger.info(
                    f"Loaded agent disk cache: {len(self.disk_cache)} agent(s), "
                    f"{age_h:.1f}h old")
        except Exception as e:
            logger.warning(f"Could not load agent disk cache: {e}")

    def _save_disk_cache(self):
        """Persist connected agent telemetry to disk (atomic write)."""
        try:
            payload = {
                "saved_at": time.time(),
                "agents": {
                    aid: {
                        "hostname":      info.get("hostname", aid),
                        "cluster_name":  info.get("cluster_name", aid),
                        "last_seen":     info.get("last_seen", 0),
                        "nodes":         info.get("nodes", []),
                        "vms":           info.get("vms", []),
                        "agent_metrics": info.get("agent_metrics", {}),
                    }
                    for aid, info in self.connected_agents.items()
                },
            }
            tmp = self._disk_cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(payload, f)
            os.replace(tmp, self._disk_cache_path)
            self.disk_cache = payload["agents"]
        except Exception as e:
            logger.warning(f"Could not write agent disk cache: {e}")

    def _ensure_agent_secret(self):
        """Self-provision + persist an ``agent_secret`` for the proxmox role's
        /ws/agent listener if none is configured.

        ``AgentHostingControlPlane.__init__`` loads ``agent_secret`` from
        ``AGENT_CONFIG_PATH`` (``/etc/lm-agent/config.json``). A standalone
        pxmx has install_pxmx.sh write that file; a generic-agent box loading
        the pxmx role does not, so ``agent_secret`` is None and the zero-touch
        approval loop never completes (the agent rejects a falsy provisioned
        secret). Generate a 32-byte token, persist it (chmod 600) so a process
        restart reuses the SAME secret and already-approved agents reconnect
        cleanly, and re-arm the HMAC signer. On any write failure fall back to
        an in-memory secret for this session (survives reconnects within the
        process; a restart re-provisions) — never fatal: the listener still
        binds, agents still connect zero-touch and would re-approve after a
        restart that lost the secret.
        """
        if self.agent_secret:
            return
        new_secret = secrets.token_urlsafe(32)
        config_path = self.AGENT_CONFIG_PATH
        try:
            os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
            existing: dict = {}
            if os.path.exists(config_path):
                try:
                    with open(config_path) as f:
                        existing = json.load(f)
                except Exception as e:  # noqa: BLE001
                    logger.warning(
                        f"Could not read existing {config_path} (will overwrite "
                        f"agent_secret only): {e}")
            existing["agent_secret"] = new_secret
            tmp = config_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(existing, f)
            os.replace(tmp, config_path)
            try:
                os.chmod(config_path, 0o600)
            except Exception:  # noqa: BLE001
                pass
            self.agent_secret = new_secret
            self.agent_signer = self._build_agent_signer(new_secret)
            self.config = existing
            logger.info(f"Self-provisioned proxmox agent_secret → {config_path}")
        except Exception as e:  # noqa: BLE001
            logger.warning(
                f"Could not persist proxmox agent_secret to {config_path} "
                f"(using in-memory secret for this session): {e}")
            self.agent_secret = new_secret
            self.agent_signer = self._build_agent_signer(new_secret)

    def _build_agent_signer(self, secret: str):
        """Rebuild the agent HMAC signer with ``secret`` (mirrors
        AgentHostingControlPlane.__init__'s ``MessageSigner(self.agent_secret)``).
        Imports MessageSigner the same way agent_hosting does."""
        try:
            from core.src.security.signer import MessageSigner
        except ImportError:
            from security.signer import MessageSigner  # type: ignore
        return MessageSigner(secret)

    # ── Subclass hooks (AgentHostingControlPlane) — proxmox telemetry ─────────

    async def _on_agent_registered(self, agent_id: str) -> None:
        """Re-push stored PVE credentials to a freshly-connected agent so a
        reconnect after a spoke restart picks up its saved config. Parameterized
        by self.role_name (the module is registered under the role name, not the
        hardcoded "pxmx" the standalone PxmxControlPlane uses)."""
        mod = self.modules.get(self.role_name)
        stored_cfg = mod.agent_configs.get(agent_id) if mod else None
        if stored_cfg:
            try:
                await self.send_to_agent("UPDATE_CONFIG", stored_cfg,
                                         agent_id=agent_id)
                logger.info(f"Re-pushed stored config to agent '{agent_id}'")
            except Exception as _e:
                logger.warning(
                    f"Failed to re-push config to agent '{agent_id}': {_e}")

    async def _on_agent_telemetry(self, agent_id: str, rec, data: dict) -> None:
        """Cache Proxmox nodes/vms/cluster + agent_metrics, persist the disk
        cache (proxmox role only), and mirror the raw telemetry into the role
        module's telemetry_cache (served for fast UI reads). Parameterized by
        self.role_name — mirrors PxmxControlPlane._on_agent_telemetry."""
        if rec is not None:
            rec["cluster_name"] = data.get("cluster_name", agent_id)
            rec["nodes"]        = data.get("nodes", {}).get("nodes", [])
            rec["vms"]          = data.get("vms", {}).get("vms", [])
            rec["agent_metrics"] = data.get("metrics", {})
            if self._agent_listener_enabled():  # proxmox role → persist
                self._save_disk_cache()
        mod = self.modules.get(self.role_name)
        if mod is not None and hasattr(mod, "telemetry_cache"):
            mod.telemetry_cache[agent_id] = data

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
            # In-repo role (dns/dhcp/console, repo_url None): its code ships in
            # the lm repo, so its self-update updates the shared /opt/lm checkout
            # via the base handler. Pin the repo_url to the lm repo (same
            # rationale as AgentControlPlane) so a mis-resolved hub repo_url — a
            # sub-spoke id like "lm-opnsense-dns" substring-mapping to
            # opnsense.git — can't repoint /opt/lm and wipe the tree.
            data = {**data, "repo_url": _LM_REPO_URL}
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


# Back-reference so agent_spoke.GenericAgent's LOAD_ROLE handler can use this
# class without a bare `from control_plane import RoleConnection` at call time.
# That bare import is unsafe once ANY role has been loaded (its src/ dir gets
# put at sys.path[0] and — for nearly every role — shadows this control_plane
# module with the role's OWN control_plane.py). Safe to set here: both modules
# are fully loaded by this point and no role's sys.path insert has happened yet.
agent_spoke.RoleConnection = RoleConnection


class AgentControlPlane(BaseControlPlane):
    def get_service_name(self) -> str:
        return "lm-agent"

    def __init__(self, spoke_id, secret, hub_secret="", hub_url="",
                 startup_roles: List[str] = None, startup_role: str = ""):
        super().__init__(spoke_id, secret, hub_secret, hub_url)
        # Base agent = process-wide catch-all: relay everything EXCEPT the
        # roles' loggers (each role's own RoleConnection relays those under
        # {base}-{role}). Without the exclude, the base bucket would duplicate
        # every role's lines. The union covers ALL roles whether loaded or not;
        # an unloaded role's stem never emits, so excluding it is a no-op.
        # Shared-infra loggers (HubDiscovery/DepGuard/UpdateRecovery) and
        # third-party libs aren't in any role's list → they land here, which is
        # correct (process-infra, not a sibling role's operational log).
        self._log_relay_handler.set_exclude_prefixes(
            {p for stems in _ROLE_LOG_PREFIXES.values() for p in stems})
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

    async def handle_system_command(self, cmd_type: str, data: dict) -> object:
        """Pin the base agent's SPOKE_UPDATE to the lm repo.

        The base handler updates ``os.getcwd()``'s git repo (the shared
        INSTALL_DIR checkout, e.g. /opt/lm) from ``data["repo_url"]``. If the hub
        ever resolves a role repo for this agent — the classic
        ``"lm-opnsense"`` spoke_id substring-mapping to ``opnsense.git`` when the
        agent's module_type isn't known (offline / post-hub-restart) — that
        repoints /opt/lm's origin and hard-resets it to the role tree, deleting
        ``agent/src/control_plane.py`` and crash-looping/flapping the agent. The
        base agent's checkout is ALWAYS the lm repo, so force the repo_url to it
        (mirrors RoleConnection forcing its sibling repo). Defense-in-depth for
        the hub-side resolver fix, and it drains a poison SPOKE_UPDATE already
        sitting in the durable mailbox: the next delivery becomes a correct
        lm-repo pull (a no-op once current) instead of a re-corruption."""
        if cmd_type == "SPOKE_UPDATE":
            sent = (data.get("repo_url") or "").strip()
            if sent and _LM_REPO_URL.removesuffix(".git") not in sent:
                logger.warning(
                    "SPOKE_UPDATE for base agent carried non-lm repo_url %r; "
                    "pinning self-update to the lm repo %s (agent checkout is "
                    "always the lm repo).", sent, _LM_REPO_URL)
            data = {**data, "repo_url": _LM_REPO_URL}
        return await super().handle_system_command(cmd_type, data)

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
        # The code-drift self-heal is armed by BaseControlPlane.run(); this agent
        # only widens the watch set (see _drift_watched_dirs) to include each
        # loaded role's sibling repo.
        await super().run()

    def _drift_watched_dirs(self) -> list:
        """Extend the base watch set (own repo + shared /opt/lm core) with each
        loaded role's sibling repo, so a role pulled-but-not-restarted also
        self-heals. The base watchdog (BaseControlPlane._code_drift_watchdog)
        calls this every cycle and baselines any repo that first appears here."""
        dirs = set(super()._drift_watched_dirs())
        agent = self.modules.get("agent")
        for role in list(getattr(agent, "_roles", {}) or {}):
            try:
                clone = _ROLE_MAP[role][0].split("/")[0]
                dirs.add(str(self._lm_root() / clone))
            except Exception:  # noqa: BLE001
                pass
        return [d for d in dirs if os.path.isdir(os.path.join(str(d), ".git"))]

if __name__ == "__main__":
    import socket as _socket
    parser = argparse.ArgumentParser()
    # --id defaults to this host's short hostname, re-evaluated on every start.
    # A clone-only unit (install_agent.sh --clone) bakes NO --id, so each cloned
    # disk derives its spoke id from its OWN hostname at runtime (parity with the
    # leaf agent's clone-name fix) instead of inheriting the template's pinned
    # id. A pinned --id (full install) stays frozen.
    parser.add_argument("--id",     default=None)
    # Default to the persisted SPOKE_SECRET from the systemd EnvironmentFile
    # (.env). After zero-touch approval the hub pushes a session key that gets
    # written there; without this env fallback the baked ExecStart (which has NO
    # --secret for a zero-touch install) meant every reload reconnected with no
    # secret → "zero-touch" again → the hub minted yet another key. Reading the
    # persisted key here makes reconnects authenticate with the existing key
    # (no re-negotiation, no key-window growth, no zero-touch event spam).
    parser.add_argument("--secret", default=(os.environ.get("SPOKE_SECRET") or None),
                        help="Session secret. Omit for zero-touch provisioning — the hub will send it after admin approval (persisted to SPOKE_SECRET and reused on restart).")
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