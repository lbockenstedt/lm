"""LM Hub orchestrator — ``LabManagerHub``.

The Hub is the central node of the zero-trust Hub-Spoke mesh. It:

- Owns the WebSocket **control plane** that spokes (cs, pxmx, dhcp, dns, …) and
  the pxmx host agents connect to, and routes signed messages between them
  (``send_to_spoke``/``send_to_agent``/``request_response``).
- Holds the JSON **state store** (tenants, modules, spokes, users, global
  config) and runs a periodic persistence loop.
- Performs mutual HMAC-SHA256 auth + challenge/response on every spoke
  connection (``handle_connection``), with PSK self-provisioning for first-time
  spokes (``_try_psk_self_provision`` mirrors the legacy
  ``cs/webui-local /api/spokes/register`` flow).
- Drives hub self-update from GitHub and, on success, schedules
  ``lm-self-restart`` via a transient systemd unit (after flushing sessions to
  disk via ``_save_sessions``).

This module also defines the per-connection rate limiter (``TokenBucket``) and
the log-redaction helpers for command types that transit a Proxmox token
secret (``_redact``, ``_REDACT_COMMANDS``). The HTTP/WS surface itself lives in
``api.py``; this module owns the long-running Hub coroutine and the spoke/agent
plumbing. Audience: Hub developers.
"""

# ── Dependency self-heal (must run BEFORE the third-party imports below) ──────
# If a declared requirement is missing from the hub venv (skewed update, partial
# install, wiped venv), install it now so the `import httpx`/`import psutil`/
# `import websockets` lines below don't crash at import time. Cheap when all deps
# are present (no I/O); best-effort never-raises. See dep_guard.py.
import os as _os
from dep_guard import ensure_requirements as _ensure_requirements
_ensure_requirements(_os.path.join(_os.path.dirname(__file__), "..", "requirements.txt"))
del _os, _ensure_requirements

import asyncio
import base64
import datetime as _dt
import hmac
import json
import logging
import time
import sys
import psutil
import os
import socket
import ssl
import uuid
import secrets
import shutil
from collections import deque
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import asdict
import websockets
from starlette.websockets import WebSocketDisconnect

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement
from messaging.mailbox import Mailbox
from messaging.heartbeat import HeartbeatManager
from security.key_manager import KeyManager
from security.signer import split_frame
from state.manager import StateManager
from simulations.broadcaster import SimulationsBroadcaster
from simulations.store import SimulationsStore
from simulations.central_hub_poller import CentralHubPoller
from security.auth_manager import AuthManager, LDAPAuthProvider
from security.threat_monitor import ThreatMonitor
from alert_engine import AlertEngine, run_alert_loop
from security.frame_crypto import (ENCRYPTED_TYPES, ENC_MARKER,
                                   encryption_enabled, is_encrypted, wrap)
from cryptography.exceptions import InvalidTag
from api import (build_server, _refresh_module_all_tenants,
                 _invalidate_tenant_module, _fetch_module)
from update_pipeline import UpdatePipelineMixin
from endpoint_sync import EndpointSyncMixin
from vm_sync import VmSyncMixin
from fw_discovery_sync import FwDiscoverySyncMixin
from nw_discovery_sync import NwDiscoverySyncMixin
from truenas_discovery_sync import TruenasDiscoverySyncMixin
from nw_cache import NwCacheMixin
from truenas_cache import TruenasCacheMixin
from le_cache import LeCacheMixin
from warm_cache import WarmCacheMixin
from dns_dhcp_sync import DnsDhcpSyncMixin
from realtime_ipam_nac_sync import RealtimeIpamNacSyncMixin
from staleness_sweep import StalenessSweepMixin
from self_backup import SelfBackupMixin
from key_vault import KeyVaultSchedulerMixin
from spoke_alert_sync import SpokeAlertMixin
from repo_sync import RepoSyncMixin
from hub_vnc_console import HubVncConsoleMixin
from hub_cert_distribution import HubCertDistributionMixin
from hub_identity import HubIdentityMixin
from hub_bug_store import HubBugStoreMixin
from hub_spoke_registry import SpokeRegistryMixin
from hub_statuspage import StatusPageMixin

# Shared logging config (lm/core/src/logging_setup.py). Two-tier import +
# inline fallback keep the hub booting even if /opt/lm/core is briefly stale
# (same deploy-order class as the base_spoke import). Single source of truth
# for format/level/destination across every hub/spoke/agent entrypoint.
try:
    from logging_setup import configure_logging, set_log_level, truncate_log_files
except ImportError:
    try:
        from core.src.logging_setup import configure_logging, set_log_level, truncate_log_files
    except ImportError:
        import logging as _logging
        _FMT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        _DFMT = '%Y-%m-%d %H:%M:%S'
        def configure_logging(default_level=_logging.INFO, *, log_file=None, **_):
            handlers = ([_logging.FileHandler(log_file), _logging.StreamHandler()]
                        if log_file else None)
            _logging.basicConfig(level=default_level, force=True,
                                 format=_FMT, datefmt=_DFMT, handlers=handlers)
        def set_log_level(enabled):
            lvl = _logging.DEBUG if enabled else _logging.INFO
            _logging.getLogger().setLevel(lvl)
            for _n in list(_logging.root.manager.loggerDict):
                _logging.getLogger(_n).setLevel(lvl)
            return lvl
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
                except Exception:  # noqa: BLE001
                    pass
            return truncated

configure_logging()
logger = logging.getLogger("Hub")

# Dedicated channel for generic-agent lifecycle diagnostics — the
# connected-but-never-authenticated signature of a protocol-incompatible
# legacy GenericLeafAgent or a crashed-on-startup agent-spoke (see
# LabManagerHub._maybe_log_unauthenticated_agent). Routing these through a
# named logger keeps them distinguishable from generic hub noise so the
# WebUI logs view / grep can surface "agent won't adopt its key" events
# without re-deriving them from Hub WARNING spam.
genAgentLogger = logging.getLogger("GenericAgent")

# Log-redaction helpers + the per-connection TokenBucket rate limiter live in
# log_redaction.py (pure, framework-free, no ``self``); imported back here so
# behavior is unchanged. ``_redact``/``_REDACT_COMMANDS`` gate secret-hygiene
# for DEBUG request_response logging; see that module for the full policy.
from log_redaction import (_redact, _REDACT_COMMANDS, _REDACT_FIELDS,
                           _LOGSAFE_COMMANDS, _FULLY_REDACT_COMMANDS,
                           _FULLY_REDACT_SUBSTRINGS, _SECRET_SUBSTRINGS,
                           _is_secret_field, _scrub_secret_fields,
                           _project_nw_devices, TokenBucket, _fit_log_payload,
                           _request_subject)

# H4 sentinel: ``_decrypt_inbound_payload`` returns this (instead of a secret)
# to signal "drop this frame" — an encrypted payload that won't AEAD-decrypt
# under the key that HMAC-verified it (tamper / wrong key) or a marked-encrypted
# frame the hub has no secret to decrypt with. The receive loop treats identity
# with this object as "do not dispatch ciphertext"; compared with ``is``.
_H4_DROP = object()


# Multi-instance config sources for modules migrated off the legacy
# single-config keys (cppm/netbox/ldap → nac_instances/ipam_instances/
# ldap_instances; see the _instance_crud registrations in api.py). Used by
# LabManagerHub.push_config_to_spoke so a spoke that (re)connects — e.g. after
# the hourly self-update restart — gets its bound instance re-pushed instead
# of coming up unconfigured (the legacy keys are cleared by the migration).
# `project` mirrors the payload_fn the Save path sends, so on-connect push and
# manual Save push identical shapes. Keyed by the module_key used in
# push_config_to_spoke (the _type_to_key map: nac→"cppm", ipam→"netbox",
# directory→"ldap").
_INSTANCE_CONFIG_SOURCES = {
    "cppm": ("nac_instances", lambda i: {
        "host": i.get("host"),
        "client_id": i.get("client_id"),
        "client_secret": i.get("client_secret"),
        "user": i.get("user"),
        "password": i.get("password"),
    }),
    "netbox": ("ipam_instances", lambda i: {
        "netbox_url": i.get("netbox_url") or i.get("url"),
        "api_token": i.get("api_token"),
    }),
    "ldap": ("ldap_instances", lambda i: {
        "LDAP_SERVER_URL": i.get("server_url"),
        "LDAP_BASE_DN": i.get("base_dn"),
        "LDAP_ADMIN_DN": i.get("admin_dn"),
        "LDAP_ADMIN_PW": i.get("admin_pw"),
    }),
}


# ── Module-type → key registries ───────────────────────────────────────────
# There are TWO distinct key spaces the hub maps module_type into, and they are
# NOT interchangeable. Keeping them as named module-level constants (instead of
# re-typing the literal at every call site) makes the distinction visible and
# prevents the "firewall maps to opn here but opnsense there" trap.
#
# 1) Branch-tag space — used by push_config_to_spoke to switch WHICH config
#    store to read. The values are short discriminators compared with `==` in
#    push_config's if/elif ("opn" → firewalls[], "cppm"/"netbox"/"ldap" →
#    _INSTANCE_CONFIG_SOURCES, else → global_config[module_key]).
# 2) Update-source config-key space — used by perform_update / update_spokes_only
#    to look up the repo URL in global_config["update_sources"]. Firewall is
#    "opnsense" here (with a legacy "opn" fallback at lookup time; see
#    update_spokes_only).
#
# A third map (module_type → spoke_id prefix substring) is used by the legacy
# spoke-resolution helpers for spokes that pre-date the module_type field.

# module_type → push_config branch tag (key space #1). NOTE "firewall" → "opn"
# here, NOT "opnsense". See _UPDATE_SOURCE_MODULE_KEY for the config-key space.
_PUSH_CONFIG_MODULE_KEY = {
    "hypervisor": "pxmx",
    "firewall":   "opn",
    "nac":        "cppm",
    "directory":  "ldap",
    "ipam":       "netbox",
    "simulation": "cs",
    "nw":         "nw",
    "certificates": "le",
    "storage":    "truenas",
}

# spoke_id substring → push_config branch tag. NOTE: the prefix-fallback loop
# in push_config_to_spoke iterates these KEYS (it sets module_key = key), so the
# values are NOT consumed there — they're kept aligned with _PUSH_CONFIG_MODULE_KEY
# ("opn" → "opn") purely so a reader isn't misled into thinking a firewall prefix
# resolves to the "opnsense" update-source config key (see _UPDATE_SOURCE_PREFIX_MAP,
# where "opn" → "opnsense" IS a real, used value).
_PUSH_CONFIG_PREFIX_MAP = {
    'pxmx': 'pxmx', 'opn': 'opn', 'cs': 'cs',
    'cppm': 'cppm', 'netbox': 'netbox', 'ldap': 'ldap', 'nw': 'nw',
    'le': 'le', 'truenas': 'truenas',
}

# _UPDATE_SOURCE_MODULE_KEY / _UPDATE_SOURCE_PREFIX_MAP moved to
# update_pipeline.py (used only by the update methods that now live there).


def _mdns_hub_properties(version_str: str, agent_port: int,
                         tls_port: int, advertise_tls: bool) -> Dict[str, str]:
    """Build the mDNS TXT records the hub advertises for ``_lm-hub._tcp.local.``.

    Pure (no ``self``) so the TLS-advertisement gate is unit-testable without
    constructing a LabManagerHub. ``advertise_tls`` (not ``tls_enabled``) gates
    ``tls_port`` so a reverse-proxy/TLS-termination deployment — where the hub
    serves plaintext behind the proxy (no cert → ``tls_enabled`` False) yet
    callers dial ``wss://<proxy>:443`` — can still tell discovery to use wss
    (set ``LM_HUB_ADVERTISE_TLS=1``). Without it, discovery returns
    ``ws://<ip>:443`` and a plaintext WebSocket handshake to a TLS port fails
    "did not receive a valid HTTP response".

    ``agent_port`` is the EXTERNAL dial port a pxmx agent uses to reach the
    agent-WS leg. Under the unified-443 merge that is the hub's single :443
    surface (``/ws/agent`` → byte-proxy to the co-located pxmx spoke's loopback
    ``LM_PXMX_AGENT_PORT``); the loopback port itself is NOT advertised. A
    standalone pxmx box (separate from the hub) serves ``/ws/agent`` on its own
    :443 and agents pin ``--spoke-url`` to it.
    """
    props = {"version": str(version_str),
             "agent_port": str(agent_port)}
    if advertise_tls:
        props["tls_port"] = str(tls_port)
    return props


class LabManagerHub(UpdatePipelineMixin, EndpointSyncMixin, VmSyncMixin, FwDiscoverySyncMixin, NwDiscoverySyncMixin, TruenasDiscoverySyncMixin, NwCacheMixin, TruenasCacheMixin, LeCacheMixin, WarmCacheMixin, DnsDhcpSyncMixin, RealtimeIpamNacSyncMixin, StalenessSweepMixin, SelfBackupMixin, KeyVaultSchedulerMixin, SpokeAlertMixin, RepoSyncMixin, HubVncConsoleMixin, HubCertDistributionMixin, HubIdentityMixin, HubBugStoreMixin, SpokeRegistryMixin, StatusPageMixin):
    """The LM Hub — central node of the zero-trust Hub-Spoke mesh.

    Owns the WebSocket control plane, the JSON state store, mutual auth/key
    management, the tenant cache, and the spoke/agent registry. Long-running
    coroutine host: ``run`` accepts spokes/agents, authenticates them, and
    routes signed messages between them. See the module docstring for the full
    responsibility map. Lifetime: one instance per Hub process.
    """

    def __init__(self, host="0.0.0.0", port=8765):
        self.host = host
        self.port = port
        # TLS for remote spokes/agents. When a cert is configured the hub serves
        # plaintext on 127.0.0.1:<port> (loopback-only — co-located spokes stay
        # plain and a remote host cannot reach it) AND wss on 0.0.0.0:<tls_port>
        # for off-box callers (discovery returns wss:// via the tls_port TXT).
        # No cert → legacy single plaintext server on self.host:self.port.
        self.tls_cert_path = os.environ.get("LM_TLS_CERT", "").strip()
        self.tls_key_path = os.environ.get("LM_TLS_KEY", "").strip()
        self.tls_port = int(os.environ.get("LM_TLS_PORT", "443"))
        # pxmx agent-listener port the hub advertises in mDNS (the pxmx spoke
        # binds this; 8443 by default so an all-in-one doesn't collide with the
        # hub's 443; a standalone pxmx spoke sets 443).
        self.pxmx_agent_port = int(os.environ.get("LM_PXMX_AGENT_PORT", "8443"))
        self.tls_enabled = bool(self.tls_cert_path and self.tls_key_path)
        # "The hub owns a TLS cert" (tls_enabled → it serves wss itself) is
        # distinct from "callers reach the hub over TLS" (advertise_tls → the
        # mDNS broadcast carries a tls_port TXT so discovery returns wss://).
        # They're the same when the hub terminates TLS itself, but diverge for a
        # reverse-proxy/TLS-termination deployment: the hub behind the proxy
        # serves plaintext (no cert → tls_enabled False) yet callers dial
        # wss://<proxy>:443. Without advertise_tls the broadcast omits tls_port
        # and discovery returns ws://...:443 → a plaintext WebSocket handshake
        # to a TLS port ("did not receive a valid HTTP response"). Opt in with
        # LM_HUB_ADVERTISE_TLS=1 for that deployment shape.
        self.advertise_tls = self.tls_enabled or os.environ.get(
            "LM_HUB_ADVERTISE_TLS", "").strip() in ("1", "true", "yes")
        self.mailbox = Mailbox()
        self.heartbeat = HeartbeatManager()
        self.key_manager = KeyManager()
        self.state = StateManager()

        # Initialize Auth with LDAP. Pass ``hub=self`` so the provider can relay
        # LDAP_GET_USER_GROUPS to the directory spoke and map a directory user's
        # membership onto hub permission groups (access.groups_for_ldap_membership,
        # the same mapping the Entra OIDC callback uses).
        self.auth = AuthManager(LDAPAuthProvider({"server": "ldap://localhost", "hub": self}))

        # State is now managed via StateManager methods
        self.approved_modules = self.state.get_approved_modules()
        self.known_modules = self.state.system_state.get("known_modules", [])
        # Re-seed the in-memory heartbeat last-seen from the persisted copy so
        # an approved spoke that WAS connected before this hub (re)start doesn't
        # flip to RED / "Never connected" — heartbeat.last_seen is in-memory and
        # wiped on restart, but spoke_last_seen survives in system.json. The
        # 15-min staleness threshold the UI uses tolerates the at-most-60s
        # granularity of the persisted copy (set via _mark_dirty, flushed by the
        # 60s persistence_loop). See state/manager.set_spoke_last_seen.
        for sid, ts in (self.state.get_spoke_last_seen() or {}).items():
            try:
                self.heartbeat.last_seen[sid] = float(ts)
            except (TypeError, ValueError):
                pass
        # install_uuid → id reverse index, rebuilt from persisted module_metadata +
        # agent_config on load and maintained on every connect. Lets the hub detect
        # a clone-and-rename (same install UUID, new spoke/agent id) and carry over
        # approval/tenant binding/config instead of treating it as a stranger.
        self.install_uuid_index: Dict[str, str] = {}
        self._rebuild_install_uuid_index()
        # Phase 2 guid-primary: once a spoke is lazily migrated to
        # guid-primary, spoke_id_alias maps the spoke_id it CONNECTS with →
        # the guid its routing/approval/crypto/mailbox state lives under.
        # _primary_key consults this first. Empty until the Phase 2b
        # migration trigger fires → _primary_key returns spoke_id for every
        # spoke (legacy, zero behavior change).
        self.spoke_id_alias: Dict[str, str] = {}
        # guid → recent reimage timestamps, for the clone-collision backstop
        # (_note_reimage_collision): a burst of reimages on one guid = multiple
        # cloned boxes presenting the same identity.
        self._recent_reimages: Dict[str, list] = {}

        # Phase 2b (B2) agent-relay guid-primary: once a relayed agent is lazily
        # migrated to guid-primary, agent_id_alias maps the agent_id it REPORTS
        # on AGENT_RELAY_UP → the guid its agent_config / agent_info / agent_logs
        # / {spoke}:{agent} composite / spoke_telemetry nested entry lives under.
        # _agent_primary_key consults this first. Empty until the B2 arm fires →
        # _agent_primary_key returns agent_id for every agent (legacy, zero
        # behavior change). The relay envelope target_agent_id stays the raw
        # name (option b); guid→name translation is via agent_info[guid]["agent_id"].
        self.agent_id_alias: Dict[str, str] = {}

        # { spoke_id: str } tracking spoke versions
        self.spoke_versions: Dict[str, str] = {}
        # { spoke_id: module_type } — e.g. {"pxmx-spoke-1": "hypervisor"}
        self.spoke_module_types: Dict[str, str] = {}
        # { spoke_id: parent_spoke_id } — for multi-role generic agents: each
        # loaded role opens a sub-spoke under {base}-{role} that claims the base
        # agent as its parent in the WS auth frame. The hub auto-approves such a
        # sub-spoke only when the parent signs a vouch for it (see
        # _parent_vouches / _auto_approve_pending_subspokes, H3), binding it to
        # the parent's tenant so a Generic Node hosting N roles needs only the
        # one base-agent approval.
        self.spoke_parent_map: Dict[str, str] = {}

        # Generic-agent hosts that ran the "netbox-server" deploy role (they have
        # nginx + the /usr/local/bin/lm-netbox-install-cert helper and run as
        # root). Advertised in the agent's WS auth frame ("netbox_server": true);
        # used to offer + resolve a "netbox-server" cert-distribution target so LE
        # certs land on the actual NetBox web server, not the API-only IPAM spoke.
        self.netbox_server_agents: set = set()

        # Generic-agent hosts that ran the "ldap-server" deploy role (they stood
        # up OpenLDAP + the /usr/local/bin/lm-ldap-install-cert helper and run as
        # root). Advertised in the agent's WS auth frame ("ldap_server": true);
        # used to offer + resolve an "ldap-server" cert-distribution target so an
        # LE cert lands on the actual LDAP (ldaps) host. Mirrors
        # netbox_server_agents.
        self.ldap_server_agents: set = set()

        # --- System Diagnostics ---
        self.logs = deque(maxlen=500)
        self.agent_logs = {} # { agent_id: deque(logs) }
        # Per-(tenant, hostname) remote client debug-log ring buffers — populated
        # by CS_DEBUG_LOG frames (a cs client flipped into debug mode from the
        # WebUI; its agent.sh tailer streams sim.log + debug logs up via the cs
        # spoke). Ephemeral in-memory deques (same contract as agent_logs): lost
        # on hub restart, capped per host. Read via GET /api/cs/clients/{host}/
        # debug-logs (routes/client_debug.py). client_debug_sessions tracks the
        # active session (enabled_at + level) per host for the auto-off window +
        # the WebUI "active until" indicator.
        self.client_debug_logs = {}      # {(tenant, hostname): deque(lines)}
        self.client_debug_sessions = {}  # {(tenant, hostname): {enabled_at, level}}
        # Hub-side cert-distribution activity (le.distribution logger) — merged
        # into GET /setup/logs/le so it surfaces under WebUI Logs → Certificates
        # alongside the le spoke's own relayed logs. See CertDistLogHandler below
        # + setup_admin.get_module_logs.
        self.cert_dist_logs = deque(maxlen=500)
        # Hub-side CS-bridge activity (the "CSBridge" logger in
        # gateway/cs_bridge.py — per-agent ACTIVE/SKIP decisions, relay
        # re-queue / give-up / ack-failed outcomes, cycle heartbeat). The bridge
        # runs ON THE HUB, so without this its [cs-bridge] lines only land in the
        # "Hub" log view; merge them into the "Simulations" (cs) view too so an
        # Azure-hub operator sees cs-spoke relay logs + bridge decisions in one
        # place. Mirrors cert_dist_logs → Certificates. See CSBridgeLogHandler
        # below + setup_admin.get_module_logs (module == "cs").
        self.cs_bridge_logs = deque(maxlen=500)
        self.max_log_size = 1000
        # Per-host cap for client_debug_logs rings (see init near agent_logs
        # above). Advanced level (journal+dmesg) is chatty; the deque cap is the
        # hub memory backstop on top of the 30-min client-side auto-off.
        self.client_debug_size = 2000
        # Per-agent index populated from AGENT_RELAY_UP: agent_id →
        # {spoke_id, hostname, last_seen}. Lets the hub route a command to the
        # spoke that owns the agent (pxmx-dialed → pxmx spoke, cs-dialed → cs
        # spoke) instead of assuming every agent is on the pxmx spoke. Evicted
        # when the owning spoke disconnects. See get_spoke_for_agent.
        self.agent_info: Dict[str, Dict[str, Any]] = {}
        # Per-tenant debounced VM-cache refresh (pxmx_vms + netbox_vms) for
        # agent-originated VM mutations. When an agent reports a VM-mutating
        # CS_COMMAND_RESULT (delete_vm / reclone_vm / clone_lxc /
        # provision_unassigned), the hub drops + re-fetches that tenant's cached
        # VM lists so the Hypervisors view doesn't stay stale up to the 300s TTL
        # tick. Coalesced to ≤1 refresh / _VM_REFRESH_MIN_INTERVAL (5s) with a
        # trailing refresh after a burst — a 100-delete storm collapses to a
        # refresh at t=0 then one every 5s + a final trailing refresh. See
        # _schedule_vm_cache_refresh / _run_vm_cache_refresh.
        self._vm_refresh_last: Dict[str, float] = {}      # tenant_id → last refresh ts
        self._vm_refresh_pending: Dict[str, bool] = {}    # tenant_id → refresh requested during inflight
        self._vm_refresh_inflight: set = set()            # tenant_ids with a refresh task running
        # Per-spoke connection lifecycle events. Lets the WebUI distinguish
        # "never dialed" / "flapping every few seconds" / "clean-exit after
        # self-update" / "auth failed" — all of which previously collapsed to a
        # single "OFFLINE / Never connected" string. Ring buffer per spoke.
        self.spoke_events: Dict[str, deque] = {}
        self.spoke_event_limit = 100
        # Per-spoke recovery state for the watchdog (run_spoke_recovery_loop):
        # { spoke_id: {attempts, last_attempt_ts, next_retry_ts, gave_up,
        #              manual_pause, last_crash_sig, last_action, last_error,
        #              in_progress} }. Surfaced via GET_SPOKE_STATUS + the
        # /setup/diagnostics route so the WebUI and bugfixer see recovery state.
        self.spoke_recovery: Dict[str, Dict[str, Any]] = {}
        # Spoke out-of-contact alerting (SpokeAlertMixin). Transient runtime state —
        # never persisted/committed; re-derives within one loop cycle after a hub
        # restart. _spoke_alerts is the active-alert store surfaced via /status +
        # /setup/diagnostics + /setup/spoke-alerts; _spoke_alert_tier tracks the last
        # emitted tier so alerts fire on TRANSITION only (no per-cycle log spam);
        # _spoke_absent_since seeds a clock for approved-but-never-seen spokes so
        # they still alert at 5/30 min. Decoupled from the recovery watchdog's 300s
        # RED — see spoke_alert_sync.py.
        self._spoke_alerts: Dict[str, Dict[str, Any]] = {}
        self._spoke_alert_tier: Dict[str, str] = {}
        self._spoke_absent_since: Dict[str, float] = {}
        # "File a Bug" reports from the WebUI footer button. The WebUI POSTs an
        # explanation + browser console + raw HTML + html2canvas screenshot to
        # /api/bug-report; the hub stores the full artifacts under data_dir/bugs/
        # <id>/ and keeps this in-memory index (id -> summary metadata) for
        # bugfixer to enumerate via GET_BUG_REPORTS. The [bug-report] marker line
        # in the hub log is what bugfixer filters on; the index avoids re-filing.
        self.bug_reports: Dict[str, Dict[str, Any]] = {}
        self.bug_report_limit = 50
        self.message_count = 0
        # Per-spoke count of messages dropped by the rate limiter (surfaced in
        # System → Hub Status so an aggressive limiter is visible, not silent).
        self.rate_limit_drops: Dict[str, int] = {}
        self.mps = 0.0
        self.bytes_count = 0 # Total bytes sent/received in the current window
        self.throughput_mbps = 0.0 # Throughput in Mbps (or MB/s)
        self.message_history = deque(maxlen=10) # Last 10 seconds of counts
        # Per-spoke inbound message rate: raw count in the current 1s window,
        # a 10s history deque per spoke, and the computed msg/s — surfaced in
        # the Spokes/Agents tiles alongside tenant + online/offline.
        self.spoke_msg_count: Dict[str, int] = {}
        self.spoke_msg_history: Dict[str, deque] = {}
        self.spoke_mps: Dict[str, float] = {}

        class HubLogHandler(logging.Handler):
            def __init__(self, hub):
                super().__init__()
                self.hub = hub
            def emit(self, record):
                # Canonical format (asctime + name + level + message) so the
                # in-memory hub log buffer is byte-identical in shape to the
                # /var/log/lm/hub.log stderr capture — uniform in the WebUI Logs
                # view and trivially de-duplicated against the disk file in
                # collect_error_logs/collect_all_logs (same record, same line).
                self.hub.logs.append(self.format(record))

        log_handler = HubLogHandler(self)
        log_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))
        logger.addHandler(log_handler)

        # Route hub-side cert-distribution activity (the le.distribution logger
        # in cert_distribution.py / hub_cert_distribution.py — per-target push
        # outcomes, hub self-install, LE_GET_CERT failures) into a dedicated
        # buffer merged into GET /setup/logs/le so it surfaces under WebUI Logs
        # → Certificates. The le spoke's own logs reach that tab via SPOKE_LOG
        # relay (agent_logs[le_sid]); this handler puts the hub's transport
        # activity in the same view. Same canonical format as HubLogHandler.
        class CertDistLogHandler(logging.Handler):
            def __init__(self, hub):
                super().__init__()
                self.hub = hub
            def emit(self, record):
                try:
                    self.hub.cert_dist_logs.append(self.format(record))
                except Exception:  # noqa: BLE001 — never block a log emit
                    pass
        cert_dist_handler = CertDistLogHandler(self)
        cert_dist_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))
        # Pin the le.distribution logger to INFO so distribution activity
        # (per-target push outcomes, no-targets / all-current skips, hub
        # self-install) is ALWAYS captured into cert_dist_logs regardless of
        # the root level — without this, flipping the root to WARNING (or a
        # stale LOG_LEVEL) would silently filter the INFO lines and the
        # Certificates tab would show no distribution activity at all.
        _le_dist_log = logging.getLogger("le.distribution")
        _le_dist_log.setLevel(logging.INFO)
        _le_dist_log.addHandler(cert_dist_handler)

        # Route hub-side CS-bridge activity (the "CSBridge" logger) into a
        # dedicated buffer merged into GET /setup/logs/cs so it surfaces under
        # WebUI Logs → Simulations alongside the cs spoke's own relayed logs.
        # The bridge poller runs on the hub; without this its per-agent
        # ACTIVE/SKIP decision + re-queue/give-up/ack-failed lines land ONLY in
        # the "Hub" view, invisible to an operator triaging a stuck agent from
        # the Simulations tab. Same canonical format as HubLogHandler. Pin the
        # logger to INFO so decisions/outcomes are ALWAYS captured regardless of
        # the root level (mirrors the le.distribution pin above).
        class CSBridgeLogHandler(logging.Handler):
            def __init__(self, hub):
                super().__init__()
                self.hub = hub
            def emit(self, record):
                try:
                    self.hub.cs_bridge_logs.append(self.format(record))
                except Exception:  # noqa: BLE001 — never block a log emit
                    pass
        cs_bridge_handler = CSBridgeLogHandler(self)
        cs_bridge_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))
        _cs_bridge_log = logging.getLogger("CSBridge")
        _cs_bridge_log.setLevel(logging.INFO)
        _cs_bridge_log.addHandler(cs_bridge_handler)
        # Route the hub-side Simulations ENGINE loggers (quota engine + central
        # poller + sim routes) into the Simulations (cs) log view too, so their
        # operational INFO lines surface under WebUI Logs → Simulations instead of
        # only the general Hub log. Reuses the CSBridge handler/deque — these are
        # all hub-side Simulations activity. (Verbose per-cycle diagnostics in
        # these modules are logged at DEBUG so they don't flood either view.)
        for _sim_logger_name in ("SimRoutes", "SimQuota", "CentralHubPoller"):
            logging.getLogger(_sim_logger_name).addHandler(cs_bridge_handler)

        # Route uncaught SYNC exceptions through the "Hub" logger so they land in
        # self.logs → Error Log tab (collect_error_logs) + BugFixer, instead of
        # only local stderr. The asyncio-task counterpart is set at the top of
        # start(). See logging-observability-contract.md req 4.
        _prev_excepthook = sys.excepthook

        def _hub_excepthook(exc_type, exc, tb):
            try:
                if not issubclass(exc_type, KeyboardInterrupt):
                    logger.error("Uncaught exception", exc_info=(exc_type, exc, tb))
            finally:
                _prev_excepthook(exc_type, exc, tb)

        sys.excepthook = _hub_excepthook

        # { spoke_id: websocket_connection } — StarletteWSAdapter wrapping a
        # FastAPI/uvicorn WebSocket on the unified :443 /ws/spoke route (the
        # former bare websockets.serve listener). Typed Any so the hub doesn't
        # depend on the websockets-lib Protocol type at the I/O boundary.
        self.active_connections: Dict[str, Any] = {}
        # { spoke_id: key_id last used to authenticate the active connection }
        # Used to reject a stale (rotated-out) session key reconnecting and
        # evicting a live current-key connection (zombie-after-outage guard).
        self.active_connection_key_ids: Dict[str, Optional[str]] = {}
        # { spoke_id: True once the spoke has proved it holds its session secret
        #   — either by presenting a valid secret in the connect auth frame OR by
        #   sending at least one hub-verified signed frame. Cleared on
        #   disconnect. Distinguishes a working spoke from a protocol-incompatible
        #   one (e.g. a legacy GenericLeafAgent) that connects but can NEVER adopt
        #   a session key, so LOAD_ROLE/GET_AVAILABLE_ROLES can fail fast instead
        #   of hanging to the request_response timeout. }
        self.spoke_authenticated: Dict[str, bool] = {}
        # { spoke_id: True once the spoke advertised ``enc="v1"`` in its auth
        #   frame AND app-layer encryption is enabled — the hub may AEAD-encrypt
        #   secret-bearing outbound frames to it. Cleared on disconnect. A
        #   legacy/non-capable spoke (or ``LM_APP_ENCRYPTION=0``) stays False →
        #   plaintext, so a new hub never sends ciphertext a legacy spoke can't
        #   decrypt (fail-safe, no fleet break). }
        self.spoke_enc_capable: Dict[str, bool] = {}
        # Spokes already diagnosed as connected-but-never-authenticated this
        # connection cycle (see _maybe_log_unauthenticated_agent). Cleared on
        # authenticate + disconnect so a re-trigger after a future regression
        # (or a reconnect that's still broken) emits a fresh ERROR rather than
        # silently suppressing it after the first one.
        self._unauth_warned_spokes: Set[str] = set()
        # Per-spoke last-re-delivery timestamp for _maybe_redeliver_session_key
        # (rate-limits re-pushing the current session key to a spoke that's
        # still signing with a previous/rotated-out key — missed rotation push).
        self._rotation_repush_at: Dict[str, float] = {}
        # NAC (CPPM) spokes that are CONNECTED but UNCONFIGURED — i.e. no
        # nac_instances entry is bound to this spoke (or the bound instance has
        # no 'host'), so push_config_to_spoke never delivered an UPDATE_CONFIG
        # with a usable host and the spoke's CPPMClient.host stays "". Querying
        # it every cycle returns "CPPM host not configured" forever, which the
        # endpoint_sync / realtime_ipam_nac_sync / cache_refresh loops would
        # otherwise spam into the hub log every cycle. Set in
        # push_config_to_spoke (the single point the gap is detectable); cleared
        # when a host-bearing config is pushed; read by the three nac query
        # loops to skip the spoke — one WARN at push time, not per-cycle INFO.
        self._nac_unconfigured_spokes: Set[str] = set()
        # { spoke_id: ConnectionTelemetry }
        self.spoke_telemetry: Dict[str, Dict[str, Any]] = {}
        # { spoke_id: TokenBucket } for rate limiting non-heartbeat messages
        self.rate_limiters: Dict[str, TokenBucket] = {}
        # { correlation_id: response_data } for request-response bridging
        self.response_cache: Dict[str, Any] = {}
        # Outstanding request_response msg_ids awaiting an ack. The dispatch
        # path only stores a response_cache entry while its msg_id is in this
        # set, and request_response removes it on response OR timeout — so a
        # late ack that arrives after the waiter already timed out is dropped
        # instead of leaking an entry that is never popped (unbounded growth at
        # scale with periodic commands + occasional spoke slowness).
        self._outstanding_requests: set = set()
        # request_response msg_ids whose waiter already returned without a reply
        # (timeout or cancel), retained briefly (TTL below) so a late ack arriving
        # after the waiter left can be recognized + logged as "late" (DEBUG) rather
        # than mislabeled "unknown message ID" (WARNING) by mailbox.acknowledge —
        # request_response ids are never in mailbox.pending_ack, so the mailbox
        # can't tell a late request/response reply from a genuinely stray ack.
        # { msg_id: expire_ts }
        self._recent_request_timeouts: Dict[str, float] = {}
        # Aligned with DRAIN_WINDOW_S (a spoke mid self-update can take up to
        # ~180s to git-pull, os._exit, relaunch, then flush its late FAILED
        # replies). A request that times out EARLY in that window gets its late
        # reply back MORE than 60s later; a 60s TTL let those fall through to
        # "unknown message ID" (WARNING). At 180s the late reply is recognized
        # + logged DEBUG ("late reply") instead. Entries are keyed by the
        # original msg_id, so a genuinely stray/spoofed ack with an unrelated
        # id still WARNs — no security-signal loss.
        self._RECENT_TIMEOUT_TTL = 180.0
        # Fire-and-forget broadcast command message_ids (SET_LOG_LEVEL,
        # CLEAR_LOGS, …) sent via the LOW-LEVEL send_to_spoke — NOT through
        # mailbox.push, so they're never in mailbox.pending_ack. The spoke still
        # returns a COMMAND_RESULT for each (every command acks), so without
        # this set those acks fall through to mailbox.acknowledge → "Received
        # acknowledgement for unknown message ID" WARNING on every broadcast
        # (e.g. every Clear-Logs click, every Enable-Debug toggle). Registering
        # them here lets the COMMAND_RESULT dispatch recognize a broadcast ack
        # and log it DEBUG (expected) instead of WARNING (stray). TTL-bounded
        # like _recent_request_timeouts; pruned on each new registration.
        # { msg_id: expire_ts }
        self._pending_broadcast_ids: Dict[str, float] = {}
        self._BROADCAST_ACK_TTL = 60.0
        # Spokes currently DRAINING (mid self-update — git pull then os._exit +
        # systemd relaunch). While draining the hub does NOT fire request/reply
        # commands (CS_CONFIG_UPDATE, ...) at the spoke: the spoke is about to
        # exit, so a request_response would just hang to its 5s timeout when the
        # WS drops mid-reply (the "Request Timeout: [CS_CONFIG_UPDATE] ... after
        # 5.0s" flood on Update). Instead config pushes are queued to the durable
        # mailbox (flush_mailbox delivers them on the next STABLE reconnect).
        # Marked three ways: (1) hub marks drain the instant it pushes SPOKE_UPDATE
        # (Update button — update_pipeline fan-out), (2) the spoke reports
        # ``draining: true`` in CS_TELEMETRY (refreshes/extends the window), and
        # (3) push_or_queue_to_spoke marks drain on a live-attempt timeout
        # (fallback for a missed signal). Cleared when the spoke reports
        # ``draining: false`` after its restart, or by the window expiring.
        # { spoke_id: drain_until_ts }
        self._draining_spokes: Dict[str, float] = {}
        self.DRAIN_WINDOW_S = 180.0
        # Outstanding app-layer liveness probes (HUB_PING message_ids awaiting a
        # HUB_PONG). The inbound dispatch resolves the sending adapter's ping
        # waiter when a reply carrying one of these ids arrives, BEFORE the
        # mailbox/unknown-ack branch so a probe reply isn't mislogged as a stray
        # ack. See StarletteWSAdapter.ping / _install_active_connection.
        self._pending_liveness_nonces: set = set()
        # Replay / freshness protection on inbound signed frames (item 8B). The
        # wire is HMAC-SIGNED, not encrypted, and the signature verifies over the
        # body bytes — so a captured signed frame replays verbatim (same bytes →
        # same HMAC → accepted). TLS-verify-ON (item 7) closes the *capture* path
        # but not application-level replay; a delayed/replayed frame can still
        # re-apply stale state (worst case a replayed SPOKE_UPDATE_SESSION_KEY
        # forcing a spoke back to an old secret → desync). Defense-in-depth:
        # (1) reject frames whose header.timestamp is older than the window (or
        # more than a small skew in the future), and (2) dedupe exact message_id
        # replays within a TTL-bounded seen-set. Applied AFTER signature
        # verification, only to signed frames, so unsigned heartbeats cost
        # nothing and an attacker can't use it as an unauth flood vector.
        # { msg_id: expire_ts }; bounded by _prune_seen_message_ids (time-gated
        # to at most once per second — see _seen_prune_last_mono).
        self._seen_message_ids: Dict[str, float] = {}
        # -inf (not 0.0): time.monotonic() starts near zero on some platforms
        # (macOS), so a 0.0 seed would gate off every prune in the process's
        # first second.
        self._seen_prune_last_mono = float("-inf")  # monotonic ts of last seen-set prune
        self._REPLAY_WINDOW_S = float(os.environ.get("LM_REPLAY_WINDOW_S", "120"))
        self._REPLAY_FUTURE_SKEW_S = 5.0  # accept up to Ns clock skew into the future
        self._REPLAY_SEEN_TTL = self._REPLAY_WINDOW_S  # seen-set lives for the window
        # Per-spoke throttle for replay/stale warnings so a replay flood doesn't
        # spam the log: { spoke_id: last_warn_ts }.
        self._replay_warn_last: Dict[str, float] = {}
        self._REPLAY_WARN_INTERVAL_S = 10.0
        # VNC console sessions (agent-terminates-WSS): session_id →
        # {queue, expires, ws_token, spoke_id, tenant_id, vmid, node, unique_id}.
        # The browser WS reads Proxmox→browser frames off ``queue`` (bytes) or
        # control tuples ("ready"/"error"/"disconnect"); VNC_FRAME_DOWN sends
        # the other way via send_to_spoke_command (fire-and-forget). 60s TTL.
        self.vnc_sessions: Dict[str, Dict[str, Any]] = {}
        # Host-shell (xterm terminal) sessions: session_id → {queue, expires,
        # connected, ws_token, spoke_id, agent_id, tenant_id}. Fed by SHELL_OUT
        # via _handle_agent_relay_up; browser keystrokes go down as SHELL_IN.
        self.shell_sessions: Dict[str, Dict[str, Any]] = {}
        # Console serial sessions (Console role): session_id →
        # {queue, expires, connected, ws_token, spoke_id, tenant_id, port_id}. The
        # browser /ws/console-serial relay reads device→browser bytes off ``queue``
        # (or control tuples "ready"/"error"/"disconnect"); keystrokes go the other
        # way via send_to_spoke_command (CONSOLE_DATA, fire-and-forget). The TTL
        # only reaps sessions minted by POST /open that the browser never connects;
        # once ``connected`` the session is long-lived (interactive terminals idle).
        self.console_sessions: Dict[str, Dict[str, Any]] = {}
        # { spoke_id: latest CS_TELEMETRY payload } — full Client-Sim data
        # (proxmox/clients/simulations/central/reclone) relayed by the combined
        # Client-Sim spoke over the LM websocket. Tenant-scoped at read time via
        # module_metadata[spoke_id]["tenant_id"]. Mirrors spoke_telemetry's
        # in-memory pattern; not persisted (spoke re-pushes on reconnect).
        self.simulations_cache: Dict[str, dict] = {}
        # Warm-load persistence for the Client-Sim telemetry cache: on a hub
        # restart the Clients + VM Server views were blank until EVERY spoke
        # reconnected and re-pushed CS_TELEMETRY (the cache was in-memory only).
        # Persist it (encrypted, debounced by run_sim_cache_flush_loop) and
        # reload here so those views seed from last-known data immediately —
        # parity with nw_cache_load() below and the mailbox warm start. Reloaded
        # rows read OFFLINE (spoke_online = not-in-active_connections) until the
        # spoke reconnects, so stale data is visibly stale, never shown as live.
        self._sim_cache_path = os.path.join(self.state.data_dir, "simulations_cache.json")
        self._sim_cache_dirty = False
        self._load_simulations_cache()
        # B3: one-shot persisted-blob guid migration. simulations_cache +
        # mailbox warm-start + spoke_last_seen are guid-keyed at read sites
        # but were RAW-keyed in the pre-guid era; fold OFFLINE spokes' entries
        # into the guid key space once at boot (sentinel-guarded, idempotent).
        # Runs after install_uuid_index rebuild (559) + mailbox load (531) +
        # simulations_cache load (above) so all three blobs are warm.
        self._migrate_persisted_blobs_to_guid()
        # Simulations module: tenant-scoped browser broadcast + slim cs-config store.
        self.simulations_broadcaster = SimulationsBroadcaster()
        self.simulations_store = SimulationsStore(self.state.data_dir)
        # API threat monitor: brute-force / faked-credential detection, security
        # audit log, and (opt-in) Azure NSG deny-rule auto-block.
        self.threat_monitor = ThreatMonitor(self)
        # Realtime alert engine (edge-triggered per-tenant alert-rule routing).
        self.alert_engine = AlertEngine(self)
        # Hub-local Proxmox template-backup repository (vzdump archives + metadata
        # on the hub's own disk). Populated by a Global-Admin-triggered backup
        # that the owning node's agent streams up. See routes/templates.py.
        from template_repo import TemplateRepo
        self.template_repo = TemplateRepo(self.state.data_dir)
        # Hub-side Aruba Central status for CENTRALIZED processing mode, keyed by
        # tenant_id. Populated by CentralHubPoller (the spoke has no Aruba client
        # in centralized mode); read by SimulationsService as a synthetic "Hub
        # (centralized)" spoke. See simulations/central_hub_poller.py.
        self.central_hub_status: Dict[str, dict] = {}
        # Warm-start persistence for the per-tenant Central status (the Checks /
        # Central / Hardware / Client-Count dashboards in centralized mode). Without
        # this the dict is empty on boot and stays blank until the 5-min poller
        # cycle completes (token fetch + Central API calls) — a visibly empty
        # dashboard for minutes after every reboot/update. Persisted encrypted each
        # poll cycle and reloaded here so the dashboards seed from last-known data
        # immediately (the block carries fetched_at so staleness is visible), then
        # the poller refreshes it. The 1h client-count baseline persists separately
        # in ClientCountTracker (client_count_*.json).
        self._central_status_path = os.path.join(self.state.data_dir, "central_hub_status.json")
        self._load_central_hub_status()
        self.central_hub_poller = CentralHubPoller(self)
        self.cache_dir = os.path.join(self.state.data_dir, "cache")
        # Network Devices (nw) module: in-memory fleet + per-device cache,
        # persisted to cache/nw_data.json and reloaded on startup so the
        # Network Devices UI seeds from last-known data on a restart instead
        # of 503-ing until the nw spoke reconnects. See nw_cache.NwCacheMixin.
        self.nw_cache_init()
        self.nw_cache_load()
        # TrueNAS (storage) cache twin — same atomic-persist + warm-start shape
        # as nw_cache (serves last-known data when the truenas spoke is offline).
        self.truenas_cache_init()
        self.truenas_cache_load()
        # Certificates warm cache — same pattern as nw_cache so the Certificates
        # page renders last-known certs instantly (stale) instead of blocking on
        # a live LE_LIST_CERTS round-trip or 503-ing until the le spoke reconnects.
        self.le_cache_init()
        self.le_cache_load()
        # Generic warm cache shared by the other read-heavy pages (IPAM/NetBox,
        # NAC/CPPM, Directory/LDAP) — same warm-start contract as nw/le.
        self.warm_cache_init()
        self.warm_cache_load()
        # Warm-start the per-tenant module cache (pxmx_vms/netbox/cppm/firewall) so
        # the Hypervisors/NetBox/CPPM/Firewall dashboards seed on boot instead of
        # blanking until a login-triggered preload lands. Stale-while-revalidate.
        try:
            from api import warm_load_tenant_cache
            warm_load_tenant_cache(self)
        except Exception as e:  # noqa: BLE001
            logger.debug("tenant_cache warm load skipped: %s", e)
        # Warm-start the per-device cert reports so the cert drill-down survives a
        # restart instead of blanking until the hourly distribution loop repopulates.
        try:
            self.warm_load_cert_device_reports()
        except Exception as e:  # noqa: BLE001
            logger.debug("cert_device_reports warm load skipped: %s", e)
        # Apply the configured session idle-timeout (minutes → seconds). Unset
        # leaves access.py's 60-minute default; 0 disables. A WebUI change
        # (/setup/session-timeout) re-applies this live.
        try:
            import access as _access
            _mins = (self.state.get_global_config() or {}).get("session_idle_timeout_minutes")
            if _mins is not None:
                _access.set_session_idle_timeout(float(_mins) * 60)
        except Exception as _e:  # noqa: BLE001 - never block startup on this
            logger.debug("apply session idle timeout at startup: %s", _e)
        # Apply the mTLS master switch from config (plumbed, default-off).
        try:
            from security import mtls as _mtls
            _mtls.set_runtime_enabled(
                (self.state.get_global_config() or {}).get("mtls_enabled"))
        except Exception as _e:  # noqa: BLE001
            logger.debug("apply mtls_enabled at startup: %s", _e)
        # Re-register the hub's mTLS material paths written by cert distribution
        # (the CA bundle path persisted into global_config["mtls"] by
        # _install_cert_on_hub) so the readiness check sees them immediately
        # after a restart, without waiting for the next distribution sweep.
        try:
            from security import mtls as _mtls
            _mcfg = ((self.state.get_global_config() or {}).get("mtls", {}) or {})
            if _mcfg.get("ca_path") or _mcfg.get("client_cert_path") or _mcfg.get("client_key_path"):
                _mtls.set_runtime_materials(
                    ca=_mcfg.get("ca_path"),
                    client_cert=_mcfg.get("client_cert_path"),
                    client_key=_mcfg.get("client_key_path"))
        except Exception as _e:  # noqa: BLE001
            logger.debug("re-register mtls materials at startup: %s", _e)
        # File-a-Bug artifact store: each report's console.log / dom.html /
        # screenshot.png / report.json live under data_dir/bugs/<id>/ so the
        # large payloads never bloat the 500-line self.logs deque or the hub
        # log file. Bugfixer pulls them back via GET_BUG_REPORT for fix context.
        self.bug_dir = os.path.join(self.state.data_dir, "bugs")
        try:
            os.makedirs(self.bug_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"[bug-report] could not create bug_dir {self.bug_dir}: {e}")
        # Rebuild the bug-report index from disk so GET_BUG_REPORTS isn't empty
        # after a restart (artifacts persist under bug_dir; the index didn't).
        try:
            self.warm_load_bug_reports()
        except Exception as e:  # noqa: BLE001
            logger.debug("bug_reports warm load skipped: %s", e)
        self.is_ready = False
        # Overload self-protection: when memory (or, later, loop-lag) crosses a
        # watermark the hub enters PROTECT MODE — it sheds heavy read endpoints
        # (503 + Retry-After so the WebUI backs off) and rejects NEW spoke
        # connections, instead of paging to death or hanging. Cleared with
        # hysteresis. Threshold configurable via global_config["protect"].
        self._protect_mode = False
        self._protect_reason = ""
        # In protect mode, shed inbound frames LARGER than this (bytes) BEFORE
        # the JSON parse — the parse of big telemetry frames is the CPU cost that
        # pegs the loop; heartbeats/acks are small and keep flowing. Tunable via
        # global_config["protect"].shed_bytes.
        self._protect_shed_bytes = 2048
        # Surgical-shed threshold: during protect, shed frames ONLY from spokes
        # whose TRUE offered rate is >= this (offenders); legit low-rate spokes'
        # telemetry flows through. Cached for the hot loop; refreshed each tick.
        self._protect_shed_min_mps = 50.0
        # Hub-process CPU sampler (its own state, independent of the box-wide
        # psutil.cpu_percent() in get_system_metrics). ~100%/core when the loop
        # is pegged — the direct "loop saturated" signal for protect mode.
        try:
            self._proc = psutil.Process()
            self._proc.cpu_percent(interval=None)  # prime the baseline
        except Exception:
            self._proc = None
        self._proc_cpu = 0.0   # last hub-process CPU% (set each tick; ladder reads it)

        # ── Graceful-degradation escalation ladder (backpressure control loop) ──
        # BEFORE the blunt protect-mode shed above, a softer ladder tries to keep
        # the fleet USABLE under a burst instead of dropping everything:
        #   Rung 1  throttle the OFFENDING spoke(s) first — signal LM_BACKPRESSURE
        #           to just the loud talkers; they coalesce/merge LOCALLY and slow
        #           their send rate (the work moves to the spoke, per design).
        #   Rung 2  if the aggregate is still hot after that, broadcast a fleet-
        #           wide slow-down so every spoke coalesces + slows.
        #   Rung 3  last resort — the hub itself coalesces inbound telemetry
        #           (latest-per-spoke, bounded drain) so must-process frames
        #           (acks/COMMAND_RESULT) still get serviced. Real merge work
        #           still belongs on the spoke; this is only the safety net.
        #   Rung 4  protect mode (existing) — OOM/CPU hard watermark, blunt shed.
        # Levels 0..3 map to "normal / offenders-throttled / fleet-throttled /
        # hub-coalescing". Signals are sent only on state CHANGE (hysteresis in
        # run_backpressure_loop) so we never spam LM_BACKPRESSURE every tick.
        self._load_level = 0
        self._spoke_backoff = set()       # spoke_ids currently told to slow down
        self._fleet_backoff = False       # rung-2 broadcast active
        self._fleet_interval = 0.0        # current adaptive fleet slow-down interval (s)
        self._backoff_signaled = {}       # spoke_id -> last level we told it (dedup)
        self._backoff_interval = {}       # spoke_id -> last min_interval we told it (adaptive re-signal)
        self._backoff_since = {}          # spoke_id -> monotonic ts throttle began (release dwell)
        # Spokes that hit their per-spoke TokenBucket (burst+refill) THIS tick.
        # The bucket is the earliest, per-frame offender detector — feeding it
        # into the ladder means a bucket breach TELLS the spoke to slow down
        # (LM_BACKPRESSURE) instead of just silently dropping its frames. Reset
        # each tick by the ladder.
        self._rl_breached = set()
        # Event-driven VM transient-state overlay for the Simulations VM Server
        # table: {tenant_id: {vmid_str: {"state": str, "ts": float}}}. Set from
        # CS_PROGRESS (deleting/recloning/provisioning) + CS_COMMAND_RESULT
        # terminals (delete completed => "deleted" so the row drops immediately
        # until telemetry catches up). Applied in service._build_proxmox_data and
        # TTL-expired so a missed terminal frame never sticks a stale state.
        self._vm_live_state = {}
        # Soft watermark (default 0.8): when a spoke has consumed ≥80% of its
        # burst bucket it is SIGNALLED to slow down (proactive). The hard limit
        # (100%) is still a HARD DROP. Cached here and refreshed each 1s tick so
        # the hot message loop reads an attribute, not a config dict, per frame.
        self._rl_soft_frac = 0.8
        # DDoS enforcement. A correct client honors the 80% signal and never hits
        # 100%. A client that KEEPS hard-dropping after being told to slow is
        # broken/hostile — track it and (if enabled) disconnect + quarantine so
        # the hub stops spending json.loads+verify on its flood. Per-tick hard-
        # drop counts + how long each has been non-compliant while signalled.
        self._rl_harddrops = {}           # spoke_id -> hard drops THIS tick
        self._noncompliant_since = {}     # spoke_id -> monotonic ts flood-after-signal began
        self._quarantine = {}             # spoke_id -> monotonic ts quarantine expires
        # TRUE offered frames per spoke, counted at the TOP of the message loop
        # BEFORE the protect pre-parse shed — so under protect (where shed frames
        # never reach spoke_msg_count) we can still identify the loudest talkers
        # to disconnect. _spoke_recv accumulates; run_mps_loop snapshots it into
        # _spoke_offered each tick for the protect source-shed.
        self._spoke_recv = {}
        self._spoke_offered = {}
        # Rung-3 receiver-side coalesce: latest-wins telemetry buffer, drained at
        # a bounded cadence by run_coalesce_drain_loop. Superseded snapshots are
        # merged away (counted) instead of each running the full ingest path.
        self._coalesce_pending = {}       # spoke_id -> (data, received_ts)
        self._telemetry_received = 0      # CS_TELEMETRY frames seen (rolling, per tick)
        self._telemetry_processed = 0     # CS_TELEMETRY frames actually ingested
        self._telemetry_coalesced = 0     # frames merged away (received but superseded)
        # MUST-PROCESS accounting — the load-test PROBE (and any correlation-
        # bearing ack) must survive every rung. Per-spoke last_seq + gap count
        # prove zero loss even while telemetry is being coalesced/shed.
        self._probe_state = {}            # spoke_id -> {"count":int,"last_seq":int,"gaps":int}

    # Message classes for the escalation ladder. Config-overridable via
    # global_config["backpressure"]["classes"] (type -> class) so the policy is
    # a knob, not a hardcode. Correlation-bearing frames are ALWAYS must-process
    # regardless of type (a reply someone is waiting on is never coalesced).
    _MSG_CLASS_DEFAULT = {
        "HEARTBEAT": "skippable",
        "CS_TELEMETRY": "coalesce",
        "SPOKE_LOG": "coalesce",
        "COMMAND_RESULT": "must",
        "LOADTEST_PROBE": "must",
    }

    def _classify_message(self, payload_type: str, has_corr: bool) -> str:
        """Declarative classification policy (must / coalesce / skippable) — the
        tested spec (test_backpressure_ladder.py) and the operator config-override
        surface (``backpressure.classes``). NOTE: the hot receive loop in
        ``handle_connection`` enforces this policy STRUCTURALLY inline via dedicated
        per-type branches (correlation_id→must, CS_TELEMETRY/SPOKE_LOG→coalesce,
        HEARTBEAT→skippable) rather than calling this per frame — so keep the two
        in lockstep when adding or reclassifying a message type.

        must → never dropped/coalesced (acks, replies, probes).
        coalesce → latest-wins, mergeable under pressure (telemetry, logs).
        skippable → a few may be dropped under pressure (heartbeats)."""
        if has_corr:
            return "must"
        try:
            classes = (self.state.get_global_config() or {}).get(
                "backpressure", {}).get("classes", {}) or {}
        except Exception:
            classes = {}
        return classes.get(payload_type) or self._MSG_CLASS_DEFAULT.get(payload_type, "coalesce")

    def _backpressure_params(self) -> dict:
        """Live knobs for the ladder (Setup → General later). Soft marks sit
        BELOW the protect hard watermarks so we throttle gracefully first."""
        try:
            cfg = (self.state.get_global_config() or {}).get("backpressure", {}) or {}
        except Exception:
            cfg = {}
        return {
            "enabled": bool(cfg.get("enabled", True)),
            # A single spoke over this msg/s is an "offender" (rung 1).
            "per_spoke_soft_mps": float(cfg.get("per_spoke_soft_mps", 50.0)),
            "per_spoke_clear_mps": float(cfg.get("per_spoke_clear_mps", 25.0)),
            # Aggregate signals that trip the fleet-wide rung-2 slow-down. These
            # sit BELOW the protect (blunt-shed) marks so the GRACEFUL slow-down
            # engages first. Calibrated from load data: a single node at ~6000
            # msg/s pegged the hub CPU at 100% while mps/lag were still under the
            # old 8000/0.30 marks — so nothing throttled and the loop ground at
            # 100%. Hub-process CPU is the earliest, truest saturation signal.
            # fleet_cpu_soft = engage the graceful slow-down here (well under the
            # 90% protect mark, so we THROTTLE spokes before we ever have to SHED).
            "fleet_cpu_soft": float(cfg.get("fleet_cpu_soft", 55.0)),   # %/core
            "fleet_cpu_clear": float(cfg.get("fleet_cpu_clear", 40.0)),
            # fleet_cpu_hard = the CPU at which we ask throttled spokes for the
            # MAXIMUM slow-down (coalesce_max_interval_s). Between soft and hard
            # the requested interval scales UP with CPU — the hotter it gets, the
            # slower we tell the spokes to send. Sits just under protect (90) so
            # the adaptive throttle keeps CPU out of protect entirely.
            "fleet_cpu_hard": float(cfg.get("fleet_cpu_hard", 85.0)),
            "fleet_lag_soft_s": float(cfg.get("fleet_lag_soft_s", 0.15)),
            "fleet_lag_clear_s": float(cfg.get("fleet_lag_clear_s", 0.06)),
            "fleet_soft_mps": float(cfg.get("fleet_soft_mps", 4000.0)),
            # In fleet mode, only throttle spokes ACTUALLY contributing load (mps
            # >= this). Quiet spokes (real infra at ~0.1/s) are NEVER throttled —
            # the slow-down targets the loud talkers, loudest-first, not everyone.
            "fleet_min_mps": float(cfg.get("fleet_min_mps", 5.0)),
            # ADAPTIVE throttle band: a throttled spoke is asked to conflate to an
            # interval scaled from _min (at fleet_cpu_soft) to _max (at
            # fleet_cpu_hard). Raise _max to push the fleet down harder when the
            # hub is hot (staler telemetry, but CPU stays out of protect).
            "coalesce_min_interval_s": float(cfg.get("coalesce_min_interval_s", 2.0)),
            "coalesce_max_interval_s": float(cfg.get("coalesce_max_interval_s", 15.0)),
            # Rung-3 hub drain cadence (process one latest snapshot per spoke).
            "hub_drain_interval_s": float(cfg.get("hub_drain_interval_s", 1.0)),
            # SAFETY CAPS (learned the hard way at ~800 spokes: the ladder's own
            # per-tick work must never compound the overload it's relieving).
            #  • drain_budget / drain_max_s — the rung-3 drain processes at most
            #    this many spokes, time-boxed; the rest stay superseded (that IS
            #    coalescing — we don't owe every snapshot). Bounds drain CPU.
            #  • max_signals_per_tick — cap LM_BACKPRESSURE sends per tick so a
            #    fleet-wide transition spreads over several ticks instead of
            #    signing 800 frames in one tick on the loop we're trying to free.
            "hub_drain_budget": int(cfg.get("hub_drain_budget", 100)),
            "hub_drain_max_s": float(cfg.get("hub_drain_max_s", 0.1)),
            "max_signals_per_tick": int(cfg.get("max_signals_per_tick", 100)),
            # DAMPING: once throttled, HOLD a spoke for at least this long before
            # even considering release — because a throttled spoke's MEASURED
            # rate collapses (it's coalescing to coalesce_min_interval_s), so
            # evaluating release on that suppressed rate would flap it every
            # window (throttle → rate drops → release → rate spikes → throttle).
            # Ramp down fast, release slow. 0 disables the hold.
            "release_dwell_s": float(cfg.get("release_dwell_s", 20.0)),
            # Soft-watermark fraction of the burst bucket at which we SIGNAL a
            # slow-down (0.8 = 80%). Hard drop still happens at 100%.
            "rl_soft_fraction": float(cfg.get("rl_soft_fraction", 0.8)),
            # DDoS enforcement — DEFAULT OFF: a legacy spoke that can't honor
            # LM_BACKPRESSURE would keep hard-dropping and get disconnected. Turn
            # on only once the fleet all speaks the backpressure protocol.
            #   ddos_disconnect      — enable disconnect+quarantine escalation
            #   ddos_grace_s         — how long a SIGNALLED spoke may keep
            #                          hard-dropping before it's disconnected
            #   ddos_min_harddrops   — min hard-drops/tick to count as flooding
            #   quarantine_s         — reconnect cooldown after a disconnect
            "ddos_disconnect": bool(cfg.get("ddos_disconnect", False)),
            "ddos_grace_s": float(cfg.get("ddos_grace_s", 30.0)),
            "ddos_min_harddrops": int(cfg.get("ddos_min_harddrops", 20)),
            "quarantine_s": float(cfg.get("quarantine_s", 120.0)),
            # PROTECT SOURCE-SHED (default ON): under protect the loop is pegged
            # just READING the flood; dropping-after-read can't free it. So the
            # loudest talkers are DISCONNECTED (bounded per tick) + briefly
            # quarantined, freeing loop time for real spokes' heartbeats (keeps
            # modules ONLINE) and /status (keeps the WebUI usable). Targets by
            # TRUE offered rate, so low-rate real modules are never touched.
            #   protect_shed_source    — enable it
            #   protect_shed_top_k     — max spokes disconnected per tick
            #   protect_shed_min_mps   — only spokes offering ≥ this (frames/s)
            #                            are eligible (spares real modules)
            #   protect_quarantine_s   — short reconnect cooldown for the shed
            "protect_shed_source": bool(cfg.get("protect_shed_source", True)),
            "protect_shed_top_k": int(cfg.get("protect_shed_top_k", 20)),
            "protect_shed_min_mps": float(cfg.get("protect_shed_min_mps", 50.0)),
            "protect_quarantine_s": float(cfg.get("protect_quarantine_s", 30.0)),
        }


    async def send_to_spoke(self, message: Message, signing_secret: Optional[str] = None):
        """
        The low-level send function used by the Mailbox.

        ``signing_secret`` overrides the key used to sign THIS one message. It
        is used ONLY for ``SPOKE_UPDATE_SESSION_KEY`` delivery, which must be
        signed with the PRE-rotation secret the spoke still holds — the spoke
        cannot verify a frame signed with the new secret it has not installed
        yet, so signing the key-delivery push with the new key makes it drop the
        push and permanently desync. When None, sign with the spoke's current
        key as usual.
        """
        spoke_id = message.header.destination_id
        pk = self._primary_key(spoke_id)  # state key (guid once 2b2 migrates; == spoke_id until then)
        ws = self.active_connections.get(pk)

        if ws:
            # Sign the message before sending
            header_dict = asdict(message.header)
            if "timestamp" in header_dict:
                header_dict["timestamp"] = round(header_dict["timestamp"], 6)

            payload_dict = asdict(message.payload)

            # H4: AEAD-encrypt payload.data of secret-bearing frames to a
            # capable spoke (encrypt data → build body → HMAC-sign the encrypted
            # body → send). The AEAD key is the same secret that signs this frame:
            # for SPOKE_UPDATE_SESSION_KEY that's signing_secret (the PRE-rotation
            # key the spoke still holds) — and on the FIRST-EVER push
            # signing_secret is None (the never-keyed spoke has no key to decrypt
            # with), so the bootstrap push stays plaintext (refinement #1). For
            # every other type signing_secret is None → fall back to the spoke's
            # current session key. Skipped entirely for non-secret types, a
            # non-capable (legacy / kill-switch) spoke, or when encryption is off
            # — the gate is cheap (a frozenset membership + dict get) and the hot
            # path (heartbeats/commands/replies) is untouched on the wire.
            _ptype = payload_dict.get("type")
            if (encryption_enabled() and self.spoke_enc_capable.get(pk)
                    and _ptype in ENCRYPTED_TYPES):
                if _ptype == "SPOKE_UPDATE_SESSION_KEY":
                    _aead_secret = signing_secret  # None on first-ever push → skip
                else:
                    _aead_secret = (signing_secret if signing_secret is not None
                                    else self.key_manager.current_session_secret(pk))
                if _aead_secret is not None:
                    wrap(_aead_secret, payload_dict)

            # Encode to the wire form <sig>.<body> (body serialized ONCE, signed
            # over those exact bytes) so the spoke verifies received bytes without
            # re-serializing. signing_secret path = SPOKE_UPDATE_SESSION_KEY.
            body = {"header": header_dict, "payload": payload_dict}
            if signing_secret is not None:
                wire = self.key_manager.encode_frame_with_secret(signing_secret, body)
            else:
                wire = self.key_manager.encode_frame(pk, body)
            self.bytes_count += len(wire.encode())
            try:
                # Bound the send: a half-open (black-holed ESTAB) socket makes
                # ws.send() block on a full write buffer indefinitely, and a
                # spoke mid-restart after SPOKE_UPDATE leaves its connection in
                # CLOSING state. Either can hang the caller (the repo_sync fan-out
                # stalled here when spokes reconnected). wait_for caps it.
                await asyncio.wait_for(ws.send(wire), timeout=10.0)
            except (websockets.ConnectionClosed, websockets.InvalidState,
                    RuntimeError, ConnectionError, asyncio.TimeoutError) as e:
                # The socket was closed/closing/black-holed between the
                # active_connections lookup above and this send (eviction swap,
                # duplicate-process flap, or a spoke mid-restart after SPOKE_UPDATE
                # whose connection is CLOSING → websockets InvalidState, or a wedged
                # write buffer → TimeoutError). Surface as a clean ConnectionError
                # so push_or_queue_to_spoke queues the message for redelivery on
                # reconnect instead of hanging the caller or bubbling up as a
                # traceback storm ("InvalidState: connection is closing").
                #
                # Proactively evict the wedged socket: without this, a black-holed
                # ESTAB ws lingers in active_connections (eviction normally happens
                # only in handle_connection's finally on recv() exit) and the NEXT
                # push re-fetches the same dead ws and blocks another 10s — a
                # recurring per-attempt stall across retry/fan-out cycles until the
                # keepalive finally tears the TCP connection down. Evicting here
                # makes the next push queue for reconnect immediately. The `is ws`
                # guard preserves the owns_slot invariant: a concurrent reconnect
                # that already replaced the slot is NOT evicted (we drop only OUR
                # dead ws); handle_connection's finally then sees owns_slot=False
                # and leaves the live replacement's sibling state intact.
                if self.active_connections.get(pk) is ws:
                    self.active_connections.pop(pk, None)
                    self.active_connection_key_ids.pop(pk, None)
                    try:
                        await ws.close()
                    except Exception:
                        pass
                raise ConnectionError(
                    f"Spoke {spoke_id} connection closed/blocked mid-send: {e}") from e
            self.message_count += 1
        else:
            raise ConnectionError(f"Spoke {spoke_id} is not connected")

    def _arm_liveness_probe(self, spoke_id: str, websocket) -> None:
        """Arm the app-layer liveness probe on a freshly installed connection.

        ``StarletteWSAdapter.ping()`` needs a signing context (the spoke's
        session key) to send a HUB_PING; the adapter itself is transport-only
        and knows nothing of keys. The hub attaches this sender once the
        connection is active so a later ``_install_active_connection`` probe of
        this socket can ping it. Best-effort: a non-adapter websocket (the test
        fakes define their own ``ping()``) is left untouched.
        """
        if hasattr(websocket, "set_probe_sender"):
            async def _sender(nonce):
                await self._send_liveness_ping(spoke_id, nonce)
            try:
                websocket.set_probe_sender(_sender)
            except Exception:  # noqa: BLE001 — never break install over probe wiring
                logger.debug("could not arm liveness probe for %s", spoke_id)

    async def _send_liveness_ping(self, spoke_id: str, nonce: str) -> None:
        """Send a signed HUB_PING to ``spoke_id``; the spoke's
        ``handle_system_command`` echoes the nonce in a COMMAND_RESULT whose
        ``correlation_id`` is this ping's ``message_id`` (= nonce), and the
        inbound dispatch resolves the adapter's ping waiter via
        ``resolve_pong(nonce)``. Raises if the spoke is not connected so the
        caller's probe treats it as dead."""
        msg = Message(
            header=MessageHeader(
                message_id=nonce,
                timestamp=round(time.time(), 6),
                sender_id="hub",
                destination_id=spoke_id,
            ),
            payload=MessagePayload(type="HUB_PING", data={"nonce": nonce}),
        )
        self._pending_liveness_nonces.add(nonce)
        try:
            await self.send_to_spoke(msg)
        except Exception:
            self._pending_liveness_nonces.discard(nonce)
            raise

    async def send_to_agent(self, spoke_id: str, agent_id: str, command_type: str, data: Dict[str, Any]):
        """
        Sends a command to a specific agent by relaying it through its parent spoke.
        """
        msg_id = str(uuid.uuid4())
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id
            ),
            payload=MessagePayload(
                type="SPOKE_RELAY",
                data={
                    "target_agent_id": self._agent_relay_name(agent_id),
                    "command_type": command_type,
                    "data": data
                }
            )
        )
        await self.send_to_spoke(msg)
        return msg_id

    async def request_response(self, spoke_id: str, command_type: str, data: Dict[str, Any], timeout: float = 5.0, signing_secret: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends a command to a spoke and waits for its acknowledgement.

        ``signing_secret`` is passed through to ``send_to_spoke`` and is used
        only for ``SPOKE_UPDATE_SESSION_KEY`` delivery (sign with the
        pre-rotation secret the spoke still holds).
        """
        msg_id = str(uuid.uuid4())
        logger.debug(f"Request: {msg_id} -> {spoke_id} [{command_type}] data={_redact(command_type, data)}")
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id
            ),
            payload=MessagePayload(type=command_type, data=data)
        )

        await self.send_to_spoke(msg, signing_secret=signing_secret)

        # Wait for the response in the mailbox
        self._outstanding_requests.add(msg_id)
        start_time = time.time()
        settled = False
        try:
            while time.time() - start_time < timeout:
                await asyncio.sleep(0.1)
                if msg_id in getattr(self, "response_cache", {}):
                    result = self.response_cache.pop(msg_id)
                    logger.debug(f"Response: {msg_id} received from {spoke_id}: {_redact(command_type, result)}")
                    settled = True
                    return result

            # Subject (the hostname/appliance/device the request operates on)
            # instead of the opaque msg_id UUID — the recurring "UUID instead
            # of a name" complaint. Falls back to a short req=<first8> hint for
            # correlation with the DEBUG request/response lines (full msg_id
            # stays there) when no subject is derivable from the payload.
            _subject = _request_subject(command_type, data) or f"req={msg_id[:8]}"
            logger.error(f"Request Timeout: [{command_type}] {_subject} from {self._spoke_label(spoke_id)} after {timeout}s")
            return {"status": "ERROR", "message": "Timed out waiting for spoke response"}
        finally:
            # Drop the waiter so a late ack can't leak a response_cache entry.
            self._outstanding_requests.discard(msg_id)
            if not settled:
                # Waiter returned without a reply (timeout or cancel). A late ack
                # may still arrive from the spoke; remember the id briefly so the
                # receive path can log it as "late" (DEBUG) instead of "unknown".
                self._recent_request_timeouts[msg_id] = time.time() + self._RECENT_TIMEOUT_TTL
                self._prune_recent_timeouts()

    async def push_or_queue_to_spoke(self, spoke_id: str, command_type: str,
                                     data: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """Best-effort synchronous push to a spoke, with a durable queue-on-
        reconnect fallback instead of an outright failure.

        Config-push routes (hub-config, central-api, sim-conf, ...) used a
        bare ``request_response`` — if the spoke happened to be mid-reconnect
        (self-update restart, brief network blip) ``send_to_spoke`` raises
        ``ConnectionError`` immediately and the caller reported "pushed to 0
        spokes" even though the spoke is genuinely approved and about to come
        back in a few seconds. This tries the live path first (the common
        case), and on failure — including a request_response timeout, which
        means "no reply", not "the spoke rejected it" — falls back to
        ``mailbox.push``, the SAME durable delivery SPOKE_UPDATE already
        relies on: the message becomes a real ``pending_ack`` entry
        (persisted to disk — survives a hub restart), retried on the
        exponential backoff schedule, and once the retry loop sees the spoke
        genuinely has no live connection, moved to its offline queue for
        delivery in full the moment it reconnects (``flush_mailbox``, called
        from ``handle_connection``). Applies equally to an agent-hosting
        spoke — an agent-targeted SPOKE_RELAY is just another command_type
        here, so the same fallback covers agent commands routed through it.

        Returns ``{"status": "ok", "queued": bool, "result"|"message": ...}``.
        Callers should surface ``queued`` distinctly (e.g. "queued — applies
        on reconnect") rather than claiming the change is live immediately.
        """
        try:
            result = await self.request_response(spoke_id, command_type, data, timeout=timeout)
            # A timeout return (no reply at all) means "unreachable", not "the
            # spoke rejected it" — queue it. A real ERROR reply from the spoke
            # is a genuine refusal; queuing that would just repeat the same
            # rejection forever, so only the timeout shape falls through.
            if (isinstance(result, dict) and result.get("status") == "ERROR"
                    and result.get("message") == "Timed out waiting for spoke response"):
                # A timeout means "no reply" — the spoke is likely mid self-update
                # (its loop free but about to os._exit, or already restarting) and
                # missed the drain signal (e.g. a non-cs spoke with no CS_TELEMETRY
                # path, or a spoke that exited before its first draining frame).
                # Mark it draining for a short window so subsequent pushes skip the
                # 5s live wait and queue directly instead of timing out again.
                self.mark_draining(spoke_id, window=90.0)
                raise TimeoutError("no reply — spoke may be reconnecting")
            return {"status": "ok", "queued": False, "result": result}
        except Exception as exc:
            logger.warning(
                f"push_or_queue_to_spoke: live push of {command_type} to {spoke_id} "
                f"failed ({exc}); queuing for delivery on reconnect."
            )
            msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id,
                ),
                payload=MessagePayload(type=command_type, data=data),
            )
            await self.mailbox.push(msg, self.send_to_spoke)
            return {
                "status": "ok", "queued": True,
                "message": f"{spoke_id} temporarily unreachable — queued for delivery on reconnect.",
            }

    def _prune_recent_timeouts(self) -> None:
        """Drop expired entries from ``_recent_request_timeouts`` (called on each
        new addition so the dict stays bounded)."""
        now = time.time()
        self._recent_request_timeouts = {k: v for k, v in self._recent_request_timeouts.items()
                                         if v > now}

    def _register_broadcast_ack(self, msg_id: str) -> None:
        """Register a fire-and-forget broadcast command id so its COMMAND_RESULT
        ack is recognized (logged DEBUG) instead of mislabeled "unknown message
        ID" (WARNING) by mailbox.acknowledge — broadcast sends go through the
        low-level send_to_spoke, NOT mailbox.push, so the id is never in
        pending_ack. TTL-bounded + pruned on each call."""
        if not msg_id:
            return
        now = time.time()
        self._pending_broadcast_ids[msg_id] = now + self._BROADCAST_ACK_TTL
        self._pending_broadcast_ids = {k: v for k, v in self._pending_broadcast_ids.items()
                                       if v > now}

    # ── spoke drain state (mid self-update) ─────────────────────────────────
    def mark_draining(self, spoke_id: str, window: float = None) -> None:
        """Mark a spoke as DRAINING (mid self-update) for ``window`` seconds
        (default DRAIN_WINDOW_S). While draining the hub queues config pushes to
        the durable mailbox instead of firing a 5s request_response that would
        time out when the spoke exits mid-reply. Idempotent + refreshes the
        window on each call (a spoke reporting ``draining: true`` every 10s
        keeps the window extended across a long git pull)."""
        if not spoke_id:
            return
        if window is None:
            window = self.DRAIN_WINDOW_S
        self._draining_spokes[spoke_id] = time.time() + window

    def is_draining(self, spoke_id: str) -> bool:
        """True if the spoke is within its drain window (mid self-update)."""
        if not spoke_id:
            return False
        until = self._draining_spokes.get(spoke_id)
        if until is None:
            return False
        if time.time() > until:
            # Window expired — the spoke never reported ``draining: false`` (e.g.
            # the update failed and it restarted on the old code, or it's gone).
            # Drop the entry so the hub resumes normal live pushes.
            self._draining_spokes.pop(spoke_id, None)
            return False
        return True

    def clear_draining(self, spoke_id: str) -> None:
        """Clear drain state (the spoke reported ``draining: false`` after its
        restart — it's back for good)."""
        if spoke_id and spoke_id in self._draining_spokes:
            self._draining_spokes.pop(spoke_id, None)

    async def _drain_aware_config_push(self, spoke_id: str, command_type: str,
                                       data: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """Config-push (CS_CONFIG_UPDATE) that respects spoke drain state.

        While the spoke is DRAINING (mid self-update — about to os._exit +
        relaunch), skip the 5s live ``request_response``: the spoke is about to
        drop its WS, so the request would just time out when it exits mid-reply
        (the "Request Timeout: [CS_CONFIG_UPDATE] ... after 5.0s" flood on
        Update). Queue straight to the durable mailbox instead — its immediate
        send still reaches an alive-but-draining spoke (whose loop is free: the
        update runs in asyncio.to_thread, so CS_CONFIG_UPDATE processes
        normally and writes config to disk before the restart), and if the
        spoke already exited the send fails + the message stays in pending_ack
        for flush_mailbox to deliver on the next STABLE reconnect. Either way
        the config lands once the spoke is back for good; no 5s hang, no ERROR
        log, no reconnect-flap storm.

        When NOT draining, a normal push_or_queue_to_spoke (live attempt with a
        queue-on-unreachable fallback)."""
        if self.is_draining(spoke_id):
            msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id,
                ),
                payload=MessagePayload(type=command_type, data=data),
            )
            await self.mailbox.push(msg, self.send_to_spoke)
            logger.info("%s draining — %s queued (skipped live request_response)",
                        spoke_id, command_type)
            return {"status": "ok", "queued": True, "draining": True}
        return await self.push_or_queue_to_spoke(spoke_id, command_type, data, timeout=timeout)

    def _prune_seen_message_ids(self) -> None:
        """Drop expired entries from ``_seen_message_ids`` (called on each new
        addition so the replay seen-set stays bounded — it never grows past the
        number of distinct message_ids received within the replay window).

        Time-gated to at most once per second: the rebuild is O(seen-set) and
        ran on the event loop for every inbound signed frame, which at scale
        was pure per-frame overhead. Worst case the set now carries one extra
        second of expired ids; replay-dedupe semantics are unchanged."""
        now = time.monotonic()
        if now - self._seen_prune_last_mono < 1.0:
            return
        self._seen_prune_last_mono = now
        wall = time.time()
        self._seen_message_ids = {k: v for k, v in self._seen_message_ids.items()
                                  if v > wall}

    def _replay_warn(self, spoke_id: str, reason: str) -> None:
        """Emit a replay/stale WARNING at most once per
        ``_REPLAY_WARN_INTERVAL_S`` per spoke so a replay flood doesn't spam."""
        now = time.time()
        sid = self._primary_key(spoke_id)
        last = self._replay_warn_last.get(sid, 0.0)
        if now - last >= self._REPLAY_WARN_INTERVAL_S:
            self._replay_warn_last[sid] = now
            logger.warning("Dropping frame from %s: %s", spoke_id, reason)
        else:
            logger.debug("Dropping frame from %s: %s (throttled)", spoke_id, reason)

    def _check_freshness_and_replay(self, spoke_id: str, msg_data: Dict[str, Any]) -> bool:
        """Replay/freshness gate for an inbound SIGNED frame (item 8B).

        Returns True to accept, False to drop. Two checks, both AFTER signature
        verification (only signed frames reach here):

        1. **Timestamp freshness**: ``header.timestamp`` must be within
           ``_REPLAY_WINDOW_S`` of now (and not more than
           ``_REPLAY_FUTURE_SKEW_S`` in the future). A frame older than the
           window is a replay candidate; a far-future timestamp is forged/skew.
           A signed frame with no timestamp (shouldn't happen — the protocol
           stamps every header) is allowed through with a debug log rather than
           dropped, so a weird-but-legitimate frame isn't bricked by v1.
        2. **message_id dedupe**: an exact message_id seen within the window is
           a verbatim replay → drop. New ids are recorded with a TTL.

        Both are cheap (dict ops) and the seen-set is pruned each add so it's
        bounded by the distinct-id count within the window."""
        header = msg_data.get("header") or {}
        ts = header.get("timestamp")
        if ts is not None:
            try:
                ts_f = float(ts)
            except (TypeError, ValueError):
                ts_f = None
            if ts_f is not None:
                now = time.time()
                age = now - ts_f
                if age > self._REPLAY_WINDOW_S:
                    self._replay_warn(spoke_id,
                                      f"stale timestamp (age {age:.0f}s > "
                                      f"{self._REPLAY_WINDOW_S:.0f}s window) — replay")
                    return False
                if ts_f - now > self._REPLAY_FUTURE_SKEW_S:
                    self._replay_warn(spoke_id,
                                      f"future timestamp (skew {ts_f - now:.0f}s) — forged/skew")
                    return False
            else:
                logger.debug("Signed frame from %s has non-numeric timestamp %r — "
                             "skipping freshness check", spoke_id, ts)
        else:
            logger.debug("Signed frame from %s has no timestamp — skipping "
                         "freshness check", spoke_id)
        msg_id = header.get("message_id")
        if msg_id:
            if msg_id in self._seen_message_ids:
                self._replay_warn(spoke_id, f"duplicate message_id {msg_id} — replay")
                return False
            self._seen_message_ids[msg_id] = time.time() + self._REPLAY_SEEN_TTL
            self._prune_seen_message_ids()
        return True

    async def send_to_spoke_command(self, spoke_id: str, command_type: str,
                                    data: Dict[str, Any]) -> None:
        """Fire-and-forget command to a spoke — sends a signed Message via
        ``send_to_spoke`` WITHOUT registering a pending request, so the spoke's
        COMMAND_RESULT ack is dropped by ``handle_connection`` (its msg_id is
        not in ``_outstanding_requests``). Used for VNC down-frames + control
        (VNC_FRAME_DOWN / VNC_START / VNC_DISCONNECT) where awaiting an ack
        would stall the browser WS. Never raises — a failed send just logs."""
        msg_id = str(uuid.uuid4())
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id,
            ),
            payload=MessagePayload(type=command_type, data=data),
        )
        try:
            await self.send_to_spoke(msg)
        except Exception as e:
            logger.warning(f"send_to_spoke_command {command_type} -> {spoke_id} failed: {e}")

    async def _install_pending_connection(self, spoke_id: str, websocket) -> None:
        """Track a pending (unauthenticated) connection in ``active_connections``.

        A prior PENDING (unauthenticated) connection for the same spoke_id is
        evicted — its socket is closed so its hub-side handler exits — and the
        new connection takes the slot. Without this, two agents running on the
        same box under one spoke_id (e.g. a leftover legacy
        ``lm-generic-agent`` alongside the new role-capable ``lm-agent``) race
        for the single ``active_connections`` slot and whichever connected first
        keeps it forever; ``approve_and_bind_spoke`` then pushes the session key
        to THAT (possibly legacy/incompatible) ws, the newer agent never adopts
        its key, and ``LOAD_ROLE`` 503s with "connected but not authenticated".
        Evicting lets the newest connection win; once one authenticates the
        ``not prior_authed`` guard here + the authenticated-path
        ``_install_active_connection`` both protect it from a stale unauthenticated
        reconnect (the original stale-process guard this replaced).

        A prior AUTHENTICATED connection is left untouched — the new pending
        connection proceeds through ``handle_connection`` as a non-slot ghost
        (same as before this helper existed) rather than tearing down a working
        live connection.
        """
        pk = self._primary_key(spoke_id)
        prior_authed = self.spoke_authenticated.get(pk, False)
        prior_ws = self.active_connections.get(pk)
        if prior_ws is not None and prior_ws is not websocket and prior_authed:
            # An authenticated connection owns the slot — leave it. The new
            # pending ws runs on as a ghost (no slot); it can't receive hub
            # pushes but won't disrupt the live connection.
            return
        if prior_ws is not None and prior_ws is not websocket:
            logger.info(
                f"Replacing prior pending connection for {spoke_id} with a "
                f"newer connection (the prior never authenticated).")
            self.record_spoke_event(spoke_id, "replaced_pending",
                                    "newer connection took over the unauthenticated slot")
            try:
                await prior_ws.close(1008, "Replaced by a newer connection")
            except Exception:
                pass
        self.active_connections[pk] = websocket
        self.active_connection_key_ids[pk] = None

    # Map unified-agent CS_* events to cs-spoke ingest/store commands. Keys are
    # the payload types the pxmx agent emits (see agent.send_cs_event); values are
    # the commands the cs spoke's handle_command implements.
    _CS_INGEST_MAP = {
        "CS_TELEMETRY":      "CS_INGEST_TELEMETRY",
        "CS_LOG":            "CS_INGEST_LOG",
        "CS_PROGRESS":       "CS_INGEST_PROGRESS",
        "CS_WATCHDOG_EVENT": "CS_INGEST_WATCHDOG_EVENT",
        "CS_HW_RESET_EVENT": "CS_INGEST_HW_RESET",
        "CS_COMMAND_RESULT": "CS_INGEST_COMMAND_RESULT",
        "CS_TOKEN_RESULT":   "CS_STORE_PROXMOX_TOKEN",
        # Pre-teardown expire: the agent fires this just before destroying a
        # sim VM so no stale queued command (e.g. reboot) is later delivered
        # to whatever guest reuses that vmid slot (cs_sim.destroy_vm ->
        # _expire_pending_commands). CS_CLEAR_COMMANDS already supports the
        # `target` scoping this needs (cs_spoke.py's CS_CLEAR_COMMANDS
        # handler).
        "CS_EXPIRE_PENDING_COMMANDS": "CS_CLEAR_COMMANDS",
    }

    # Agent CS_COMMAND_RESULT actions that mutate a tenant's Proxmox VM set and
    # therefore invalidate the hub's cached pxmx_vms (and the NetBox VM-sync
    # view, netbox_vms). Used by _schedule_vm_cache_refresh to gate the
    # debounced per-tenant refresh — non-mutating results (status beacons,
    # progress, failures) are ignored so a busy sim doesn't trigger refreshes.
    _VM_MUTATING_ACTIONS = frozenset({
        "delete_vm", "reclone_vm", "clone_lxc", "provision_unassigned",
    })
    # Coalesce VM-cache refreshes to at most one per tenant per this interval.
    _VM_REFRESH_MIN_INTERVAL = 5.0

    # ── VM Server live-state overlay ─────────────────────────────────────────
    # Map a mutating CS action to the transient state shown on the VM row while
    # the op is in flight (before the ~10-30s telemetry frame reflects reality).
    # Values match the prov_status vocabulary the pxmx agent already stamps and
    # the WebUI badge (csVmStatusBadge) already renders — tearing_down => "Deleting…",
    # recloning => "Recloning…", provisioning => "Provisioning/Configuring".
    _VM_ACTION_STATE = {
        "delete_vm": "tearing_down",
        "reclone_vm": "recloning",
        "clone_lxc": "provisioning",
        "provision_unassigned": "provisioning",
    }
    _VM_LIVE_TTL = 300.0       # in-progress state auto-expires after 5 min (safety)
    _VM_DELETED_TTL = 180.0    # a "deleted" prune persists 3 min until telemetry drops the vm

    @staticmethod
    def _vmid_key(vmid) -> str:
        try:
            return str(int(vmid))
        except (TypeError, ValueError):
            return str(vmid)

    def _vm_live_set(self, tenant_id, vmid, state) -> None:
        """Stamp a transient state for one vmid (best-effort; no-op on bad input)."""
        if not tenant_id or vmid in (None, ""):
            return
        self._vm_live_state.setdefault(str(tenant_id), {})[self._vmid_key(vmid)] = {
            "state": state, "ts": time.time()}

    def _vm_live_clear(self, tenant_id, vmid) -> None:
        t = self._vm_live_state.get(str(tenant_id))
        if not t:
            return
        t.pop(self._vmid_key(vmid), None)
        if not t:
            self._vm_live_state.pop(str(tenant_id), None)

    def vm_live_states(self, tenant_id) -> Dict[str, str]:
        """TTL-pruned {vmid_str: state} overlay for a tenant — read by
        service._build_proxmox_data to stamp/prune VM rows. Expired entries are
        dropped here so a missed terminal frame can never wedge a stale state."""
        t = self._vm_live_state.get(str(tenant_id))
        if not t:
            return {}
        now = time.time()
        out: Dict[str, str] = {}
        expired = []
        for k, v in t.items():
            state = (v or {}).get("state")
            ts = float((v or {}).get("ts", 0) or 0)
            ttl = self._VM_DELETED_TTL if state == "deleted" else self._VM_LIVE_TTL
            if now - ts > ttl:
                expired.append(k)
            elif state:
                out[k] = state
        for k in expired:
            t.pop(k, None)
        if not t:
            self._vm_live_state.pop(str(tenant_id), None)
        return out

    def vm_live_drop_reappeared(self, tenant_id, present_ts) -> None:
        """Drop ``deleted`` overlay entries whose vmid has REAPPEARED in a fresh
        telemetry frame captured AFTER the deletion was stamped.

        A reused/re-cloned vmid that the spoke reports again is authoritative: the
        deleted-overlay must not keep pruning (hiding) it for the remainder of
        ``_VM_DELETED_TTL``. ``present_ts`` maps vmid_str → the newest frame
        timestamp that still carries that vmid; a stale pre-delete cached frame
        (timestamp older than the deletion stamp) does NOT clear the overlay, so
        the bridge-prune of a genuinely-deleted vmid is preserved."""
        if not tenant_id or not present_ts:
            return
        t = self._vm_live_state.get(str(tenant_id))
        if not t:
            return
        for vmid, frame_ts in present_ts.items():
            key = self._vmid_key(vmid)
            entry = t.get(key)
            if not entry or (entry or {}).get("state") != "deleted":
                continue
            try:
                if float(frame_ts or 0) > float(entry.get("ts", 0) or 0):
                    t.pop(key, None)
            except (TypeError, ValueError):
                continue
        if not t:
            self._vm_live_state.pop(str(tenant_id), None)

    async def _relay_cs_event(self, spoke_id: str, agent_id: str,
                              cs_type: str, data: Dict[str, Any]) -> None:
        """Forward a relayed CS_* agent event to the tenant's cs spoke (best-effort).

        The unified pxmx agent emits CS_* events up through its pxmx spoke's
        AGENT_RELAY_UP relay; here we map each to a cs-spoke command and dispatch
        via request_response. Tenant resolution: the per-agent store
        (system_state['agent_config'][agent_id].client_simulation.tenant_id) is
        authoritative; we fall back to the relaying pxmx spoke's own tenant
        binding. Hostname comes from the relayed payload (the agent injects it).

        Security: the payload may carry a Proxmox token secret (CS_TOKEN_RESULT,
        Phase F). This method never logs ``data`` — only type/hostname/tenant —
        so secrets do not reach the hub log. Never raises: a missing/offline cs
        spoke or a dispatch failure must not break the agent→hub relay loop —
        this is enforced by an outer try/except because the caller fires the
        relay as a background task (see ``_handle_agent_relay_up``) and an
        unhandled exception there would only surface as a noisy "Task exception
        was never retrieved" warning.
        """
        try:
            await self._relay_cs_event_inner(spoke_id, agent_id, cs_type, data)
        except Exception as exc:  # noqa: BLE001 — never let a background relay task raise
            logger.debug("CS_* relay: %s from %s raised: %s", cs_type, agent_id, exc)

    async def _relay_cs_event_inner(self, spoke_id: str, agent_id: str,
                                    cs_type: str, data: Dict[str, Any]) -> None:
        """Guts of ``_relay_cs_event`` — see its docstring. Split so the outer
        wrapper can guarantee never-raises for the fire-and-forget caller."""
        mapped = self._CS_INGEST_MAP.get(cs_type)
        if not mapped:
            logger.debug("CS_* relay: no mapping for %s from %s — dropping", cs_type, agent_id)
            return
        hostname = (data or {}).get("hostname") or agent_id
        # Resolve tenant: per-agent store first, then the relaying spoke's binding.
        tenant_id = None
        try:
            ac = (self.state.system_state.get("agent_config", {}) or {}).get(
                self._agent_primary_key(agent_id), {})
            tenant_id = (ac.get("client_simulation") or {}).get("tenant_id")
        except Exception:
            tenant_id = None
        if not tenant_id:
            try:
                tenant_id = self.state.get_spoke_tenant(self._primary_key(spoke_id))
            except Exception:
                tenant_id = None
        # VM Server live state + browser live-op feed for the IN-PROGRESS phase.
        # Agent CS_PROGRESS reaches the hub HERE (via _handle_agent_relay_up →
        # AGENT_RELAY_UP), NOT the direct-spoke CS_PROGRESS handler in
        # handle_connection — so the overlay SET (tearing_down/recloning/
        # provisioning) and the /sim/ws broadcast must happen on THIS path too,
        # or a UI-initiated delete never shows "Deleting…" and the VM table
        # doesn't refresh until the next telemetry poll. Terminals are owned by
        # the CS_COMMAND_RESULT block below (delete completed => prune).
        if cs_type == "CS_PROGRESS":
            _pact = (data or {}).get("action")
            _pstat = str((data or {}).get("status") or "").lower()
            _pvmid = (data or {}).get("vmid")
            _pstate = self._VM_ACTION_STATE.get(_pact)
            if tenant_id and _pstate and _pvmid not in (None, "") \
                    and _pstat not in ("completed", "failed", "error"):
                try:
                    self._vm_live_set(tenant_id, _pvmid, _pstate)
                except Exception:  # noqa: BLE001 — overlay is best-effort
                    pass
            try:
                await self.simulations_broadcaster.broadcast(
                    spoke_id, {"type": "cs_progress", "data": data or {}}, tenant_id)
            except Exception:  # noqa: BLE001 — live feed is best-effort
                pass
        # A VM-mutating command result (delete_vm / reclone_vm / clone_lxc /
        # provision_unassigned) invalidates this tenant's cached pxmx_vms +
        # netbox_vms — the agent already changed Proxmox, so re-read the lists
        # instead of serving a stale view up to the 300s TTL tick. Triggered
        # before the cs-spoke dispatch so it fires even if the cs spoke is
        # offline (the VM mutation is independent of it). Best-effort + scoped
        # to the acting tenant + coalesced to ≤1 refresh / 5s (trailing refresh
        # after a burst). Skipped on explicit failures (status == "failed"):
        # a failed delete changed nothing, so a refresh would be wasted work.
        if cs_type == "CS_COMMAND_RESULT" and tenant_id:
            action = (data or {}).get("action")
            status = (data or {}).get("status")
            # VM Server live-state overlay (see _vm_live_set): a delete that
            # COMPLETED marks the vmid "deleted" so the table drops the row at
            # once (until telemetry catches up); any other terminal clears the
            # in-progress state so the row reverts to its real telemetry status.
            _vmid = (data or {}).get("vmid")
            _st = str(status or "").lower()
            if action in self._VM_MUTATING_ACTIONS and _vmid not in (None, ""):
                try:
                    if action == "delete_vm" and _st == "completed":
                        self._vm_live_set(tenant_id, _vmid, "deleted")
                    elif _st in ("completed", "failed", "error"):
                        self._vm_live_clear(tenant_id, _vmid)
                except Exception:  # noqa: BLE001 — overlay is best-effort
                    pass
                # Broadcast the terminal to the browser live-op feed so the VM
                # Server table re-fetches NOW (csHandleLiveOp treats completed/
                # failed as terminal → prompt refresh) — a completed delete's row
                # drops immediately instead of waiting for the ~15s op-burst tick.
                try:
                    await self.simulations_broadcaster.broadcast(
                        spoke_id, {"type": "cs_progress", "data": data or {}}, tenant_id)
                except Exception:  # noqa: BLE001 — live feed is best-effort
                    pass
            if action in self._VM_MUTATING_ACTIONS and status != "failed":
                try:
                    self._schedule_vm_cache_refresh(tenant_id)
                except Exception as e:  # noqa: BLE001
                    logger.debug("vm cache refresh schedule failed: %s", e)
        cs_spoke = self.get_client_sim_spoke(tenant_id)
        if not cs_spoke:
            logger.debug("CS_* relay: no cs spoke for tenant=%s (agent=%s, %s) — dropping",
                         tenant_id, agent_id, cs_type)
            return
        # Defense-in-depth: before forwarding a delete_vm "completed" (which the
        # cs spoke acks completed at CS_INGEST_COMMAND_RESULT), confirm the VM
        # is actually gone from the agent's live list. The agent already verifies
        # via wait_guest_gone before reporting completed; this catches the rare
        # case it's wrong. If still present, ack the original FAILED and ENQUEUE
        # A FRESH delete_vm — re-delivering the same cs_cmd_id would only re-ack
        # the cached terminal (the agent's liveness-dedup), not re-run, so a new
        # command is required. Bounded to ONE re-enqueue per (agent,vmid) within
        # a TTL so a genuinely-undeletable VM can't loop forever; on the second
        # still-present we accept the completed and log. Best-effort: on any
        # verify error/timeout fall through to ack (never wedge a delete on a
        # verify failure). delete_vm only — reclone's "completed" means a new VM
        # exists, not an absence to verify.
        if cs_type == "CS_COMMAND_RESULT":
            action = (data or {}).get("action")
            status = str((data or {}).get("status") or "").lower()
            if action == "delete_vm" and status == "completed":
                vmid = (data or {}).get("vmid")
                cs_cmd_id = (data or {}).get("cs_cmd_id")
                gone = await self._verify_delete_vm_gone(tenant_id, agent_id, vmid)
                if gone is False and cs_cmd_id is not None:
                    reran = await self._rerun_delete_if_needed(
                        cs_spoke, agent_id, hostname, vmid, cs_cmd_id)
                    if reran:
                        return  # fresh command owns the retry; original acked failed
                    # Already re-enqueued within the TTL — accept and log.
                    logger.warning(
                        "delete_vm cs_cmd_id=%s vmid=%s still present after "
                        "re-enqueue on agent=%s — accepting completed (bound)",
                        cs_cmd_id, vmid, agent_id)
                # gone True/None or accepted-above → fall through to ack.
        payload = {"hostname": hostname, **(data or {})}
        try:
            # 30s (not the 5s default): the cs spoke processes commands inline on
            # its event loop and CS_INGEST_COMMAND_RESULT does a blocking atomic
            # disk write (command_queue.ack_command) that can exceed 5s under
            # load — a too-tight timeout produces late replies the hub then warns
            # about as "unknown message ID". See request_response / dispatch.
            await self.request_response(cs_spoke, mapped, payload, timeout=30.0)
            logger.debug("CS_* relay: %s -> %s for %s (tenant=%s)",
                         cs_type, mapped, hostname, tenant_id)
        except Exception as exc:
            logger.debug("CS_* relay: %s -> %s failed for %s: %s",
                         cs_type, mapped, hostname, exc)

    def refresh_module_cache(self, key: str) -> None:
        """Drop + background re-fetch a tenant-cache module for ALL tenants.

        Thin hub-method wrapper around api._refresh_module_all_tenants so the
        background-sync mixins (endpoint_sync / vm_sync / realtime_ipam_nac /
        nw_discovery / fw_discovery) — which deliberately avoid importing api to
        dodge an import cycle — can refresh the cache at sync completion without
        a local import. Called after a sync cycle that actually changed spoke
        data so a non-admin viewer (whose list reads the tenant cache, not a
        live relay) sees the new state immediately instead of waiting up to 300s
        for the next cache tick.
        """
        try:
            _refresh_module_all_tenants(self, key)
        except Exception as e:  # noqa: BLE001 — never let a cache refresh kill a sync loop
            logger.debug("refresh_module_cache(%s) failed: %s", key, e)

    # --- Agent-result → debounced per-tenant VM-cache refresh ──────────────
    # An agent mass-delete (CS_COMMAND action=delete_vm) reports completion via
    # CS_COMMAND_RESULT up AGENT_RELAY_UP, but that path never invalidated the
    # hub's _tenant_cache[*]["pxmx_vms"] (only hub-originated routes did, via
    # _refresh_module_all_tenants). So the Hypervisors VM list stayed stale up
    # to the 300s TTL tick. This debounced refresh closes that gap, scoped to
    # the acting tenant (pxmx_vms + netbox_vms) and coalesced to ≤1 / 5s with a
    # trailing refresh after a burst. See _VM_MUTATING_ACTIONS.
    def _schedule_vm_cache_refresh(self, tenant_id: str) -> None:
        if not tenant_id:
            return
        if tenant_id in self._vm_refresh_inflight:
            # A refresh is already running — request one more trailing refresh
            # so the final state (after the whole burst) is re-read, then return.
            self._vm_refresh_pending[tenant_id] = True
            return
        # Mark inflight NOW (before create_task) so a rapid follow-up schedule
        # call — which runs synchronously before the coroutine even starts —
        # sees inflight set and coalesces into pending instead of spawning a
        # second task. Without this, a tight burst of N schedules would spawn N
        # tasks (each marks inflight only once its coroutine runs).
        self._vm_refresh_inflight.add(tenant_id)
        asyncio.create_task(self._run_vm_cache_refresh(tenant_id))

    async def _run_vm_cache_refresh(self, tenant_id: str) -> None:
        try:
            while True:
                # Rate-limit: never refresh more often than the min interval. The
                # first call (last unset) waits 0 → leading-edge immediate refresh.
                now = time.time()
                wait = self._VM_REFRESH_MIN_INTERVAL - (now - self._vm_refresh_last.get(tenant_id, 0.0))
                if wait > 0:
                    await asyncio.sleep(wait)
                for key in ("pxmx_vms", "netbox_vms"):
                    try:
                        _invalidate_tenant_module(tenant_id, key)
                        await _fetch_module(self, tenant_id, key)
                    except Exception as e:  # noqa: BLE001 — best-effort, never break the loop
                        logger.debug("vm cache refresh %s/%s failed: %s", tenant_id, key, e)
                self._vm_refresh_last[tenant_id] = time.time()
                # Trailing edge: if another mutating result arrived during this
                # refresh, loop once more (rate-limited by the interval above) so
                # the post-burst state is re-read. Else the task exits.
                if not self._vm_refresh_pending.pop(tenant_id, False):
                    break
        finally:
            self._vm_refresh_inflight.discard(tenant_id)

    async def _verify_delete_vm_gone(self, tenant_id: Optional[str],
                                     agent_id: str, vmid: Any) -> Optional[bool]:
        """Defense-in-depth post-completion check for delete_vm. Returns
        ``True`` if ``vmid`` is absent from the agent's live VM list, ``False``
        if still present, ``None`` on error/timeout (caller falls through to ack
        so a verify failure never wedges a delete). Scoped to the owning agent
        via PXMX_LIST_VMS{agent_id} — sim VMIDs can collide across hosts."""
        if vmid is None or vmid == "":
            return None
        try:
            vid = int(vmid)
        except (TypeError, ValueError):
            return None
        pxmx_spoke = None
        try:
            pxmx_spoke = self.get_hypervisor_spoke_for_tenant(tenant_id)
        except Exception:
            pxmx_spoke = None
        if not pxmx_spoke:
            try:
                pxmx_spoke = self.get_hypervisor_spoke()
            except Exception:
                pxmx_spoke = None
        if not pxmx_spoke:
            return None
        try:
            raw = await asyncio.wait_for(
                self.request_response(pxmx_spoke, "PXMX_LIST_VMS",
                                      {"agent_id": agent_id}),
                timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("delete verify PXMX_LIST_VMS agent=%s failed: %s",
                         agent_id, exc)
            return None
        data = raw.get("payload", {}).get("data", raw) if isinstance(raw, dict) else {}
        for v in (data or {}).get("vms") or []:
            try:
                if int(v.get("vmid")) == vid:
                    return False
            except (TypeError, ValueError):
                continue
        return True

    # One defense-in-depth re-enqueue per (agent, vmid) per TTL so a genuinely
    # undeletable VM can't loop: completed-but-present → fresh delete → if THAT
    # also completes-but-present we accept it (bound) and log. Re-delivering the
    # same cs_cmd_id would only re-ack the cached terminal (agent liveness-dedup),
    # so a fresh command is required to actually re-run the destroy.
    _DELETE_RERUN_TTL = 600.0

    async def _rerun_delete_if_needed(self, cs_spoke: str, agent_id: str,
                                       hostname: str, vmid: Any,
                                       cs_cmd_id: str) -> bool:
        """If this (agent, vmid) hasn't been re-enqueued within the TTL: ack the
        original command FAILED and enqueue a FRESH delete_vm. Returns True if a
        fresh command was enqueued (caller skips the completed ack); False if
        already re-enqueued within the TTL (caller accepts the completed)."""
        try:
            vid = int(vmid)
        except (TypeError, ValueError):
            return False
        key = f"{agent_id}|{vid}"
        now = time.time()
        reran = getattr(self, "_delete_verify_reran", None)
        if reran is None:
            reran = self._delete_verify_reran = {}
        for k in [k for k, ts in reran.items() if now - ts > self._DELETE_RERUN_TTL]:
            reran.pop(k, None)
        if key in reran:
            return False
        reran[key] = now
        logger.warning(
            "delete_vm cs_cmd_id=%s vmid=%s reported completed but still present "
            "on agent=%s — acking original failed + enqueuing fresh delete_vm",
            cs_cmd_id, vid, agent_id)
        try:
            await self.request_response(
                cs_spoke, "CS_ACK_COMMAND",
                {"id": cs_cmd_id, "status": "failed",
                 "message": "post-completion verify: VM still present — re-enqueued"},
                timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            logger.debug("delete verify ack-failed %s failed: %s", cs_cmd_id, exc)
        try:
            await self.request_response(
                cs_spoke, "CS_QUEUE_COMMAND",
                {"target": hostname or agent_id, "action": "delete_vm",
                 "args": {"vmid": vid}, "type": None},
                timeout=10.0)
        except Exception as exc:  # noqa: BLE001
            logger.warning("delete verify fresh enqueue vmid=%s failed: %s",
                           vid, exc)
        return True

    async def push_config_to_spoke(self, spoke_id: str):
        """Pushes the module-specific configuration from global state to the spoke."""
        try:
            # Always push the hub secret first so mutual auth works even when there
            # is no module config to send (e.g. cs-spoke before it is configured).
            hub_secret = self.key_manager.hub_secrets[0]
            secret_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=spoke_id
                ),
                payload=MessagePayload(type="SPOKE_SET_HUB_SECRET", data={"hub_secret": hub_secret})
            )
            await self.send_to_spoke(secret_msg)
            logger.info(f"Pushed hub secret to {spoke_id}")

            # Reconcile the operator-set hub URL on every (re)connect: if
            # global_config["hub"]["url"] is set, re-push SPOKE_SET_HUB_URL so a
            # spoke that was offline when the hub's DNS name changed (or that
            # is reconnecting after its own repoint restart) receives the
            # current desired address. Fire-and-forget (send_to_spoke, no ack):
            # the spoke's handler is idempotent — a spoke already on the URL
            # no-ops, a pinned remote spoke persists + restarts onto it, and a
            # loopback/auto spoke skips. This runs for EVERY spoke (agents and
            # dedicated modules) BEFORE the module_key early-return below (that
            # return is what otherwise skips agents, which have no module_key).
            try:
                hub_url = self.state.get_global_config().get("hub", {}).get("url")
                if hub_url:
                    url_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()),
                            timestamp=time.time(),
                            sender_id="hub",
                            destination_id=spoke_id,
                        ),
                        payload=MessagePayload(
                            type="SPOKE_SET_HUB_URL", data={"hub_url": hub_url}),
                    )
                    await self.send_to_spoke(url_msg)
                    logger.debug(f"Re-pushed hub URL to {spoke_id}")
            except Exception as e:
                logger.warning(f"Failed to re-push hub URL to {spoke_id}: {e}")

            # Push the fleet-wide hub-contact watchdog config to EVERY spoke/agent
            # on (re)connect (before the module_key early-return below, which skips
            # agents). The spoke persists it locally so it still applies when the
            # hub is later unreachable — the exact case the watchdog recovers from.
            try:
                wd = self.state.get_global_config().get("hub_contact_watchdog")
                if wd is not None:
                    wd_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()),
                            timestamp=time.time(),
                            sender_id="hub",
                            destination_id=spoke_id,
                        ),
                        payload=MessagePayload(type="SPOKE_SET_WATCHDOG", data=wd),
                    )
                    await self.send_to_spoke(wd_msg)
                    logger.debug(f"Pushed hub-contact watchdog config to {spoke_id}")
            except Exception as e:
                logger.warning(f"Failed to push watchdog config to {spoke_id}: {e}")

            # Resolve the push_config branch tag from the module_type registry
            # first, then fall back to a spoke_id prefix match for legacy spokes.
            # See _PUSH_CONFIG_MODULE_KEY / _PUSH_CONFIG_PREFIX_MAP (branch-tag
            # space — NOT the update-source config-key space).
            pk = self._primary_key(spoke_id)
            mtype = self.spoke_module_types.get(pk, "")
            module_key = _PUSH_CONFIG_MODULE_KEY.get(mtype)
            if not module_key:
                # Legacy prefix-based fallback: module_key = the matching KEY in
                # _PUSH_CONFIG_PREFIX_MAP (the dict values are unused here).
                for key in _PUSH_CONFIG_PREFIX_MAP:
                    if key in spoke_id:
                        module_key = key
                        break

            if not module_key:
                return

            if module_key == 'cs':
                # CS provisioning config (usb_vidpids, usb_ignored_vidpids,
                # usb_auto_provision, image1/image2 template ids, VLAN ranges,
                # watchdog knobs) is TENANT-scoped and delivered via
                # CS_CONFIG_UPDATE — NOT the UPDATE_CONFIG/global_config["cs"]
                # path below (the cs speak's UPDATE_CONFIG handler only writes
                # simulation.conf INI and ignores usb_vidpids). Re-push it on
                # every (re)connect so a cs speak that restarts — hourly
                # self-update, reboot, or the fresh-install base_spoke crash —
                # recovers its certified vidpids + templates instead of coming up
                # with usb_vidpids="[]" (→ the pxmx agent's _dongle_vidpids
                # reads 0 → "no dongle_vidpids configured" and auto-provision
                # never fires until an admin re-saves Setup/Proxmox). Mirrors
                # the NAC/IPAM reconnect re-push (multi-instance-spoke-config-
                # push), which was never extended to cs.
                await self.push_cs_hub_config(spoke_id)
                return

            # Handle Firewall multi-instance config
            if module_key == 'opn':
                firewalls = self.state.get_global_config().get("firewalls", [])
                fw_config = next((f for f in firewalls if f.get("spoke_id") == spoke_id), None)
                if fw_config:
                    config = fw_config
                else:
                    opn_fws = [f for f in firewalls if f.get("model") == "opnsense"]
                    config = opn_fws[0] if opn_fws else {}
            elif module_key == 'nw':
                # Network Devices fleet: one nw spoke manages many devices.
                # Push the devices bound to this spoke; fall back to unbound
                # devices (single-product deployments don't bind spoke_id).
                devices = self.state.get_global_config().get("nw_devices", []) or []
                mine = [d for d in devices if isinstance(d, dict) and d.get("spoke_id") == spoke_id]
                if not mine:
                    mine = [d for d in devices if isinstance(d, dict) and not d.get("spoke_id")]
                # default_poll_interval = module-level poll cadence; the spoke
                # uses it for devices that don't set their own (device wins).
                # shared_tenant_id = the shared tenant, so the spoke's spoke-side
                # tenant filter (Stage 1) returns shared devices to ANY tenant
                # reader (shared-tenant-flag invariant). Read via access (cached
                # at startup + tenant writes) to avoid a circular import here.
                import access as _access
                config = {"devices": _project_nw_devices(mine),
                          "shared_tenant_id": _access.shared_tenant_id() or "",
                          "default_poll_interval":
                              self.state.get_global_config().get("nw_poll_default_interval")}
            elif module_key == 'truenas':
                # TrueNAS (storage) fleet: one storage spoke manages many
                # appliances. Push the appliances bound to this spoke; fall back
                # to unbound appliances (single-product deployments). Mirrors
                # the nw branch.
                import access as _access
                import copy as _copy
                appliances = self.state.get_global_config().get("truenas_appliances", []) or []
                mine = [a for a in appliances if isinstance(a, dict) and a.get("spoke_id") == spoke_id]
                if not mine:
                    mine = [a for a in appliances if isinstance(a, dict) and not a.get("spoke_id")]
                config = {"appliances": [_copy.deepcopy(a) for a in mine],
                          "shared_tenant_id": _access.shared_tenant_id() or "",
                          "default_poll_interval":
                              self.state.get_global_config().get("truenas_poll_default_interval")}
            elif module_key == 'ldap':
                # Directory (LDAP) spoke: the bound instance's LDAP_* connection
                # settings PLUS this node's multi-instance mirror identity
                # (LDAP_SERVER_ID + LDAP_MIRROR_PEERS for the 2-node mirror) PLUS
                # the Entra app creds (ENTRA_*) sourced from the hub's OIDC config
                # so the spoke can authenticate Entra-backed directory users
                # (ROPC). Built here (not via _INSTANCE_CONFIG_SOURCES, which only
                # projects the LDAP_* base fields) because it needs hub-global
                # OIDC config + every instance to compute the peer list. Handled
                # BEFORE the generic instance branch (ldap is also a key there).
                config = self._ldap_config_for_spoke(spoke_id)
            elif module_key in _INSTANCE_CONFIG_SOURCES:
                # NAC / IPAM / Directory migrated to multi-instance storage
                # (nac_instances / ipam_instances / ldap_instances). The legacy
                # single-config keys (cppm/netbox/ldap) are cleared by that
                # migration, so reading them here — as this used to — yields an
                # empty dict and the spoke comes up UNCONFIGURED on every
                # reconnect (notably each hourly self-update restart), returning
                # "CPPM host not configured" / count=None for every query even
                # though the UI shows the server configured. Resolve the
                # instance bound to this spoke; fall back to the first unbound
                # instance (single-product deployments don't bind spoke_id),
                # then the first instance, then the legacy single-config key.
                # Project through the same field map the Save path uses so the
                # pushed shape matches a manual Save.
                storage_key, project = _INSTANCE_CONFIG_SOURCES[module_key]
                gc = self.state.get_global_config()
                instances = gc.get(storage_key, []) or []
                inst = next((x for x in instances
                             if isinstance(x, dict) and x.get("spoke_id") == spoke_id), None)
                if inst is None:
                    inst = next((x for x in instances
                                 if isinstance(x, dict) and not x.get("spoke_id")), None)
                if inst is None and instances and isinstance(instances[0], dict):
                    inst = instances[0]
                if inst is not None:
                    config = project(inst)
                else:
                    # Pre-multi-instance deployment: push the raw legacy config.
                    config = gc.get(module_key, {})
            else:
                config = self.state.get_global_config().get(module_key, {})

            # NAC/CPPM config-delivery gate. A connected-but-unconfigured CPPM
            # spoke (CPPMClient.host == "") returns "CPPM host not configured"
            # for EVERY query, and the three nac query loops would spam that
            # into the hub log every cycle. The gap is detectable right here —
            # the resolved instance has no usable 'host' (or no instance is
            # bound at all) — so mark the spoke unconfigured so those loops skip
            # it (one WARN here, not per-cycle INFO) and skip pushing a hostless
            # UPDATE_CONFIG (which would only keep the spoke returning the same
            # error). Clear the flag only when a host-bearing config is pushed.
            if module_key == "cppm":
                cppm_host = (config or {}).get("host") if isinstance(config, dict) else None
                if not cppm_host:
                    if spoke_id not in self._nac_unconfigured_spokes:
                        logger.warning(
                            "CPPM not configured for %s — no nac_instances entry "
                            "bound to this spoke, or the bound instance has no "
                            "'host'. NAC queries (endpoint sync, realtime NAC, "
                            "dashboard cache) will be skipped until an instance "
                            "with a host is bound in Setup → CPPM/NAC.",
                            spoke_id)
                        self._nac_unconfigured_spokes.add(spoke_id)
                    return  # nothing useful to push — hostless config would keep
                            # the spoke returning "CPPM host not configured"
                # A usable host is available — clear any prior unconfigured flag
                # so the query loops resume on the next cycle.
                self._nac_unconfigured_spokes.discard(spoke_id)

            if not config:
                return

            msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=spoke_id
                ),
                payload=MessagePayload(type="UPDATE_CONFIG", data=config)
            )
            await self.send_to_spoke(msg)
            logger.info(f"Pushed {module_key} config to {spoke_id}")
        except Exception as e:
            logger.error(f"Failed to push config to {spoke_id}: {e}")

    def _ldap_config_for_spoke(self, spoke_id: str):
        """Build the full UPDATE_CONFIG payload for a directory (LDAP) spoke.

        Combines three sources into the shared config contract the ldap spoke is
        built to consume:

        * the bound ``ldap_instances`` entry's connection settings —
          ``LDAP_SERVER_URL`` / ``LDAP_BASE_DN`` / ``LDAP_ADMIN_DN`` /
          ``LDAP_ADMIN_PW``;
        * this node's multi-instance mirror identity — ``LDAP_SERVER_ID`` (this
          instance's replication id) + ``LDAP_MIRROR_PEERS`` (a JSON list of the
          OTHER instances' ``{server_id, url}`` for the 2-node OpenLDAP mirror);
        * the Entra app credentials from the hub's OIDC config —
          ``ENTRA_TENANT_ID`` / ``ENTRA_CLIENT_ID`` / ``ENTRA_CLIENT_CERT`` /
          ``ENTRA_CLIENT_KEY`` / ``ENTRA_ROPC_SCOPE`` — so the spoke can
          password-authenticate Entra-backed directory users. The cert/key are
          pushed as PEM **content** (not the hub-local path, which is meaningless
          on the remote spoke), resolved via the credential store so a Key Vault
          ref works too.

        Returns None when no ldap instance is configured (nothing to push)."""
        gc = self.state.get_global_config()
        # Setup → Directory (LDAP) SERVER config (global_config["ldap"]) is the
        # Global-Admin-set source of truth. It takes PRECEDENCE over the legacy
        # ldap_instances entry (and the dc=example,dc=org install default) per
        # field via merge_ldap_connection, so the Setup values actually flow to
        # the spoke instead of the install-time fallback.
        gldap = gc.get("ldap") or {}
        instances = gc.get("ldap_instances", []) or []
        inst = next((x for x in instances
                     if isinstance(x, dict) and x.get("spoke_id") == spoke_id), None)
        if inst is None:
            inst = next((x for x in instances
                         if isinstance(x, dict) and not x.get("spoke_id")), None)
        if inst is None and instances and isinstance(instances[0], dict):
            inst = instances[0]
        # Nothing to push only when BOTH sources are empty.
        if inst is None and not gldap:
            return None
        from routes.ldap import merge_ldap_connection, normalize_mirror_peers
        inst = inst or {}
        cfg = merge_ldap_connection(gldap, inst)
        cfg["LDAP_SERVER_ID"] = str(gldap.get("server_id") or inst.get("server_id")
                                    or inst.get("id") or spoke_id)
        # Mirror peers: the Setup panel's list wins; otherwise derive the peer set
        # from the OTHER ldap_instances (legacy 2-node mirror wiring).
        gpeers = normalize_mirror_peers(gldap.get("mirror_peers"))
        if gpeers:
            peers = gpeers
        else:
            peers = []
            for other in instances:
                if not isinstance(other, dict) or other is inst:
                    continue
                purl = other.get("server_url")
                if purl:
                    peers.append({
                        "server_id": str(other.get("server_id") or other.get("id") or ""),
                        "url": purl,
                    })
        cfg["LDAP_MIRROR_PEERS"] = json.dumps(peers)
        try:
            from security.oidc import get_oidc_config
            from security.credential_store import resolve_private_key_material
            oc = get_oidc_config(self)
            cfg["ENTRA_TENANT_ID"] = oc.tenant_id
            cfg["ENTRA_CLIENT_ID"] = oc.client_id
            cert_pem = resolve_private_key_material(oc.cert_path) if oc.cert_path else None
            key_pem = resolve_private_key_material(oc.key_path) if oc.key_path else None
            cfg["ENTRA_CLIENT_CERT"] = cert_pem.decode("utf-8", "replace") if cert_pem else ""
            cfg["ENTRA_CLIENT_KEY"] = key_pem.decode("utf-8", "replace") if key_pem else ""
            cfg["ENTRA_ROPC_SCOPE"] = ((gc.get("oidc") or {}).get("ropc_scope")
                                       or "openid")
        except Exception as e:  # noqa: BLE001 — Entra optional; push LDAP anyway
            logger.warning("ldap config: could not source Entra creds from OIDC: %s", e)
            for k in ("ENTRA_TENANT_ID", "ENTRA_CLIENT_ID",
                      "ENTRA_CLIENT_CERT", "ENTRA_CLIENT_KEY"):
                cfg.setdefault(k, "")
            cfg.setdefault("ENTRA_ROPC_SCOPE", "openid")
        return cfg

    async def push_ldap_config_all(self) -> None:
        """Re-push the full LDAP + Entra config to EVERY connected directory
        spoke. Called on OIDC-config change so the directory mirror picks up new
        Entra creds immediately instead of waiting for a reconnect. Multi-instance
        aware — ``push_config_to_spoke`` resolves each node to its own instance
        (its ``LDAP_SERVER_ID`` + peer list)."""
        try:
            spokes = self.get_all_spokes_by_type("directory") or []
        except Exception:  # noqa: BLE001
            spokes = []
        for sid in spokes:
            try:
                await self.push_config_to_spoke(sid)
            except Exception as e:  # noqa: BLE001
                logger.warning("push_ldap_config_all: %s failed: %s", sid, e)

    async def provision_tenant_ou(self, tenant_id: str) -> None:
        """Provision (idempotently) a tenant's OU on every connected directory
        spoke: ``ou=<tenant_slug>,<base_dn>``. TENANT == OU, 1:1 — the tenant
        slug IS the OU RDN. Best-effort: a disconnected mirror node re-syncs the
        OU from its peer (or on the next touch). The spoke's
        ``LDAP_PROVISION_TENANT_OU`` is idempotent case-insensitively so a repeat
        never creates both ``LRB`` and ``lrb``."""
        from access import ldap_tenant_slug
        slug = ldap_tenant_slug(self, tenant_id)
        if not slug:
            return
        try:
            spokes = self.get_all_spokes_by_type("directory") or []
        except Exception:  # noqa: BLE001
            spokes = []
        for sid in spokes:
            try:
                await self.request_response(sid, "LDAP_PROVISION_TENANT_OU",
                                            {"tenant_slug": slug}, timeout=20.0)
            except Exception as e:  # noqa: BLE001
                logger.warning("provision_tenant_ou %s on %s: %s", slug, sid, e)

    async def push_cs_hub_config(self, spoke_id: str) -> None:
        """Re-push the tenant's hub-owned CS provisioning config
        (``usb_vidpids``/``usb_ignored_vidpids``/``usb_auto_provision``,
        image1/image2 template ids, VLAN ranges, watchdog knobs, ...) to a
        (re)connecting Client-Sim spoke as a ``CS_CONFIG_UPDATE``.

        The cs speak applies these via ``_apply_hub_config``
        (``CS_CONFIG_UPDATE``), NOT its ``UPDATE_CONFIG`` handler (which only
        writes ``simulation.conf`` INI and ignores ``usb_vidpids``). Without this
        re-push a cs speak that restarts comes up with ``usb_vidpids="[]"`` and
        no templates until an admin re-saves Setup/Proxmox, so the pxmx agent's
        ``_dongle_vidpids`` reads 0 and auto-provision never fires ("no
        dongle_vidpids configured"). Called from ``push_config_to_spoke`` on
        every cs (re)connect.

        USB certified/ignored are the EFFECTIVE (global + tenant) lists so a
        globally-certified vid:pid reaches the spoke even when the tenant's own
        ``usb_vidpids`` is empty; the remaining keys come straight from the
        tenant ``hub_config`` (mirrors ``PUT /sim/api/tenant/{t}/hub-config``).
        No-op when the spoke has no tenant binding or the tenant's hub_config
        isn't enabled, so an unbound/non-cs spoke is left untouched. Best-effort:
        a transport failure is logged, not raised (the spoke retries on the next
        reconnect and the cs_bridge still re-syncs usb_config every cycle)."""
        try:
            tenant_id = self.state.get_spoke_tenant(spoke_id)
        except Exception:
            tenant_id = None
        if not tenant_id:
            return
        # Hub is the sole GitHub client: for a github-managed tenant whose config
        # the hub hasn't pulled yet, pull it NOW so this reconnect delivers the
        # real config (not an empty hub-owned override) and the spoke never has
        # to touch GitHub itself. One central puller — see github_config_client.
        try:
            _sot = await self.simulations_store.get_source_of_truth(tenant_id)
            _have = bool((await self.simulations_store.get_sim_conf_content(tenant_id) or "").strip())
            if _sot == "github" and not _have:
                from simulations import github_config_client as _ghc
                _gh_cfg = await self.simulations_store.get_github_config(tenant_id) or {}
                if _ghc.is_configured(_gh_cfg):
                    _pulled = await _ghc.pull(_gh_cfg)
                    if _pulled:
                        if _pulled.get("sim_conf") is not None:
                            await self.simulations_store.set_sim_conf_content(
                                tenant_id, _pulled["sim_conf"])
                        if _pulled.get("user_overrides") is not None:
                            await self.simulations_store.set_user_overrides_content(
                                tenant_id, _pulled["user_overrides"])
        except Exception as exc:  # noqa: BLE001 — best-effort pull, never block reconnect
            logger.debug("push_cs_hub_config: github pull-if-empty for %s failed: %s",
                         tenant_id, exc)
        # Advertise follower mode to the (re)connecting spoke: 'hub' once the hub
        # has the config (hub-owned, or github pulled above) so repo_sync no-ops
        # and the spoke serves hub-delivered files as its whole config; 'github'
        # only in the brief bootstrap window before the hub's first pull lands.
        try:
            _sot2 = await self.simulations_store.get_source_of_truth(tenant_id)
            _have2 = bool((await self.simulations_store.get_sim_conf_content(tenant_id) or "").strip())
            _spoke_src = "hub" if (_sot2 == "hub" or _have2) else "github"
        except Exception:  # noqa: BLE001
            _spoke_src = "hub"
        # Re-push hub-managed sim/user config overrides (the Sim Config editor
        # saves these as sim_conf_override / user_conf_override INI text → the
        # spoke writes configs/hub-*-overrides.conf, merged on top of the repo
        # base files by sim_config.load_configs). Without this re-push a spoke
        # that restarts (hourly self-update, reboot, fresh-install base_spoke
        # crash) drops the override until an admin re-saves the Sim Config tab.
        # Independent of hub_config_enabled — overrides are their own bucket.
        try:
            sim_override = await self.simulations_store.get_sim_conf_content(tenant_id)
            user_override = await self.simulations_store.get_user_overrides_content(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("push_cs_hub_config: override read for %s failed: %s",
                         spoke_id, exc)
            sim_override = user_override = ""
        override_cfg: dict = {}
        if sim_override:
            override_cfg["sim_conf_override"] = sim_override
        if user_override:
            override_cfg["user_conf_override"] = user_override
        # Advertise follower mode ONLY alongside actual config delivery, so the
        # spoke serves the hub-delivered files as its whole config. A tenant with
        # no hub config adds nothing here (preserves the no-op-when-empty push).
        if sim_override or user_override:
            override_cfg["config_source"] = _spoke_src
        # Spoke-side agent-relay timeouts (Setup → General → global_config): push
        # to every (re)connecting cs spoke so its SPOKE_RELAY forward uses the
        # configured long-op / fast windows (WAN + busy-agent tuning). Global
        # for now; a per-tenant override can override these later.
        try:
            _gc = self.state.get_global_config() or {}
            for _rk in ("agent_relay_timeout_long_s", "agent_relay_timeout_fast_s"):
                if _gc.get(_rk) is not None:
                    override_cfg[_rk] = _gc.get(_rk)
        except Exception:  # noqa: BLE001 — best-effort
            pass
        # Re-deliver the in-memory github_config (repo_url/branch) so a spoke has
        # it back on reconnect. The PAT is stripped below for a follower spoke —
        # the hub is the sole GitHub client, so an attached spoke neither pulls
        # nor commits; the creds ride along only for the brief 'github' bootstrap
        # window (before the hub's first pull) and for repo_url/branch display.
        try:
            _gh = await self.simulations_store.get_github_config(tenant_id) or {}
        except Exception as exc:  # noqa: BLE001 — best-effort
            _gh = {}
        if _gh:
            # Follower spoke: strip the PAT — the hub is the sole GitHub client,
            # so an attached spoke must never pull/push GitHub. Kept only during
            # the brief 'github' bootstrap window (before the hub's first pull).
            if _spoke_src == "hub" and isinstance(_gh, dict) and _gh.get("github_token"):
                _gh = {k: v for k, v in _gh.items() if k != "github_token"}
            override_cfg["github_config"] = _gh
        # Re-deliver the tenant's effective sim quotas (global defaults merged
        # with tenant overrides, enabled-only) so a reconnecting cs spoke's
        # SimQuotaEngine reconciles immediately instead of waiting for the next
        # Config → Sim Quotas save. Mirrors the effective-USB re-push above.
        try:
            from simulations.routes import _effective_sim_quotas as _eff_sq
            eff_sq = await _eff_sq(tenant_id)
        except Exception as exc:  # noqa: BLE001 — best-effort
            eff_sq = []
            logger.debug("push_cs_hub_config: effective_sim_quotas for %s failed: %s",
                         spoke_id, exc)
        if eff_sq:
            override_cfg["effective_sim_quotas"] = eff_sq
        if override_cfg:
            try:
                outcome = await self._drain_aware_config_push(
                    spoke_id, "CS_CONFIG_UPDATE", override_cfg, timeout=30.0)
                if outcome.get("queued"):
                    logger.info("CS override re-push to %s %s (tenant %s)",
                                spoke_id,
                                "draining — queued" if outcome.get("draining")
                                else "queued (spoke unreachable)", tenant_id)
                else:
                    logger.info("Re-pushed CS sim/user overrides to %s (tenant %s)",
                                spoke_id, tenant_id)
            except Exception as exc:  # noqa: BLE001
                logger.warning("CS override re-push to %s failed: %s",
                               spoke_id, exc)
        try:
            hc = await self.simulations_store.get_hub_config(tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.debug("push_cs_hub_config: hub_config read for %s failed: %s",
                         spoke_id, exc)
            return
        if not isinstance(hc, dict) or not hc.get("hub_config_enabled"):
            return
        cfg = dict(hc.get("hub_config") or {})
        # Effective USB lists (global + tenant, deduped) — the cs speak
        # re-filters dongles on these, so a global-only certification still
        # reaches a spoke whose tenant hub_config.usb_vidpids is empty.
        try:
            from simulations.routes import (_normalize_usb_vidpids,
                                            _normalize_usb_ignored)
        except Exception:  # noqa: BLE001  (lazy import; routes pulls FastAPI)
            _normalize_usb_vidpids = None
            _normalize_usb_ignored = None
        if _normalize_usb_vidpids is not None:
            try:
                g_cert = await self.simulations_store.get_global_usb_vidpids()
            except Exception:  # noqa: BLE001
                g_cert = []
            try:
                g_ign = await self.simulations_store.get_global_usb_ignored_vidpids()
            except Exception:  # noqa: BLE001
                g_ign = []
            seen: set = set()
            cert: list = []
            for d in (_normalize_usb_vidpids(g_cert)
                      + _normalize_usb_vidpids(cfg.get("usb_vidpids"))):
                vp = d.get("vidpid", "") if isinstance(d, dict) else ""
                if vp and vp not in seen:
                    seen.add(vp)
                    cert.append(d)
            ign = sorted(set(_normalize_usb_ignored(g_ign))
                        | set(_normalize_usb_ignored(cfg.get("usb_ignored_vidpids"))))
            cfg["usb_vidpids"] = json.dumps(cert)
            cfg["usb_ignored_vidpids"] = json.dumps(ign)
        if not cfg:
            return
        try:
            outcome = await self._drain_aware_config_push(
                spoke_id, "CS_CONFIG_UPDATE", cfg, timeout=30.0)
            if outcome.get("queued"):
                logger.info("CS hub config re-push to %s %s (tenant %s)",
                            spoke_id,
                            "draining — queued" if outcome.get("draining")
                            else "queued (spoke unreachable)", tenant_id)
            else:
                logger.info("Re-pushed CS hub config to %s (tenant %s)",
                            spoke_id, tenant_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CS_CONFIG_UPDATE re-push to %s failed: %s",
                           spoke_id, exc)

    async def broadcast_log_level(self, enabled: bool):
        """Broadcasts the desired logging level to all connected spokes."""
        logger.info(f"Broadcasting debug mode: {'ENABLED' if enabled else 'DISABLED'}")
        msg_id = str(uuid.uuid4())
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id="broadcast" # Internal marker for broadcast
            ),
            payload=MessagePayload(type="SET_LOG_LEVEL", data={"enabled": enabled})
        )

        # We iterate over active connections and send to each specifically
        tasks = []
        for sid in list(self.active_connections.keys()):
            # Create a copy of the message for each spoke with the correct destination_id
            spoke_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=sid
                ),
                payload=MessagePayload(type="SET_LOG_LEVEL", data={"enabled": enabled})
            )
            # Fire-and-forget: send via low-level send_to_spoke (NOT mailbox.push),
            # and register the id so the spoke's COMMAND_RESULT ack is recognized
            # as an expected broadcast ack (DEBUG) instead of "unknown message ID"
            # (WARNING) — see the COMMAND_RESULT dispatch in handle_connection.
            self._register_broadcast_ack(spoke_msg.header.message_id)
            tasks.append(self.send_to_spoke(spoke_msg))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_clear_logs(self):
        """Broadcast ``CLEAR_LOGS`` to every connected spoke/agent so each box
        truncates its own on-disk ``/var/log/lm/*.log`` in place. Mirrors
        ``broadcast_log_level``. Fire-and-forget (no ack-wait): the hub clears
        its OWN in-memory view synchronously in ``clear_all_logs`` before this,
        so the UI is empty the instant the route returns; the spoke-side disk
        truncation lands whenever each spoke dispatches the command."""
        logger.info("Broadcasting CLEAR_LOGS to connected spokes/agents")
        tasks = []
        for sid in list(self.active_connections.keys()):
            spoke_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()),
                    timestamp=time.time(),
                    sender_id="hub",
                    destination_id=sid,
                ),
                payload=MessagePayload(type="CLEAR_LOGS", data={}),
            )
            # Fire-and-forget: low-level send (not mailbox.push) + register the id
            # so the spoke's COMMAND_RESULT ack is recognized as an expected
            # broadcast ack (DEBUG) instead of "unknown message ID" (WARNING) —
            # which fired on every Clear-Logs click before this.
            self._register_broadcast_ack(spoke_msg.header.message_id)
            tasks.append(self.send_to_spoke(spoke_msg))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def clear_all_logs(self):
        """Wipe every log source the Hub Log UI can show — the hub's own
        in-memory deque, every relayed agent/spoke deque in ``agent_logs``,
        and the on-disk ``/var/log/lm/*.log`` files on the hub box (the hub's
        own ``hub.log`` plus any co-located spoke files). Then broadcasts
        ``CLEAR_LOGS`` to every connected spoke so each remote box truncates
        its OWN on-disk logs too. Used by the WebUI "Clear Logs" button
        (``POST /setup/logs/clear``, admin-only).

        On-disk files are truncated in place (``O_TRUNC``, same inode) by
        ``truncate_log_files`` so each process's open ``RotatingFileHandler``
        keeps writing at offset 0 instead of detaching to a stale inode —
        see its docstring. Returns a summary dict for the route response."""
        # In-memory: hub's own deque + every relayed agent/spoke deque. Clear
        # each deque IN PLACE (not agent_logs.clear()) to preserve the keys
        # the UI keys its tabs on — a still-connected spoke keeps its buffer
        # entry, just empty, instead of dropping out of the agents list.
        hub_lines = len(self.logs)
        self.logs.clear()
        cert_dist_lines = len(self.cert_dist_logs)
        self.cert_dist_logs.clear()
        cs_bridge_lines = len(self.cs_bridge_logs)
        self.cs_bridge_logs.clear()
        agent_counts = {}
        for aid, dq in list(self.agent_logs.items()):
            agent_counts[aid] = len(dq)
            dq.clear()
        agent_lines = sum(agent_counts.values())

        # On-disk on this box (hub's own + co-located spokes). Off the hub
        # loop: os.listdir + N open()s shouldn't block heartbeats.
        files = await asyncio.to_thread(truncate_log_files)

        # Remote spokes' on-disk logs — best-effort broadcast; failures are
        # per-spoke (return_exceptions=True above) and don't fail the call.
        spoke_count = len(self.active_connections)
        await self.broadcast_clear_logs()

        logger.warning(
            "[diag] Clear Logs: hub deque %d + cert-dist %d + cs-bridge %d + "
            "agent/spoke %d lines across %d buffer(s); truncated %d on-disk "
            "file(s) on hub; broadcast to %d connected spoke(s)",
            hub_lines, cert_dist_lines, cs_bridge_lines, agent_lines,
            len(agent_counts), len(files), spoke_count)
        return {
            "status": "ok",
            "hub_lines": hub_lines,
            "cert_dist_lines": cert_dist_lines,
            "cs_bridge_lines": cs_bridge_lines,
            "agent_buffers": len(agent_counts),
            "agent_lines": agent_lines,
            "disk_files_truncated": files,
            "spokes_broadcast": spoke_count,
        }

    async def approve_and_bind_spoke(self, spoke_id: str, tenant_id: str) -> None:
        """Approve a spoke, bind it to a tenant, persist, and — if it is
        currently connected — push it the session key + APPROVED + config so it
        begins operating immediately. Shared by the admin
        ``/setup/approve_spoke`` flow and the PSK claim flow
        (``/sim/api/tenant/{t}/spokes/{id}/claim``). Mirrors the connected-push
        in api.py approve_spoke (561-592)."""
        pk = self._primary_key(spoke_id)
        self.state.register_module(pk, approved=True)
        self.state.set_spoke_tenant(pk, tenant_id)
        self.approved_modules[pk] = True
        await self.state.save_state_now()
        if pk in self.active_connections:
            session_secret = self.key_manager.generate_first_secret(pk)
            # Zero-touch provisioning MUST be plaintext. A newly-approved spoke
            # is pending (no secret); a re-approval of an already-authenticated
            # spoke holds its current secret. The hub's key_manager RETAINS a
            # spoke's secret server-side (keys[pk] is persisted by _save_keys),
            # so current_session_secret(pk) can be NON-None even for a zero-touch
            # role sub-spoke that connected before and never persisted the key
            # (RoleConnection._persist_session_secret is a no-op). If we signed
            # the SPOKE_UPDATE_SESSION_KEY push with that retained secret, the
            # spoke-side gate would AEAD-encrypt it with a key the sub-spoke no
            # longer holds → _decode_frame defers it (encrypted + no self.secret)
            # forever → the key never arms → the never-adopted outage. Force
            # plaintext (signing_secret=None) for zero-touch spokes so the frame
            # is accepted in bootstrap decode and arms; an authenticated spoke
            # keeps the signed re-key (it can verify the pre-rotation signature).
            # Fire-and-forget (NOT request_response): awaiting the ack in this
            # connect path is structurally unreachable — the message loop hasn't
            # started, so nothing populates response_cache → a 5s timeout every
            # connect that stalls push_config and flaps the WS. The spoke-side
            # deferral (_drain_pending_encrypted) closes the back-to-back
            # encrypted UPDATE_CONFIG race without the await.
            prev_secret = self.key_manager.current_session_secret(pk)
            key_sign = None if not self.spoke_authenticated.get(pk) else prev_secret
            key_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(
                    type="SPOKE_UPDATE_SESSION_KEY", data={"secret": session_secret}))
            await self.send_to_spoke(key_msg, signing_secret=key_sign)
            approval_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(type="APPROVED", data={}))
            await self.send_to_spoke(approval_msg)
            await self.push_config_to_spoke(spoke_id)
        # Multi-role generic agent: when a base agent (module_type "agent") gets
        # approved — by admin, PSK, or a connect-with-secret — sweep up any of
        # its role sub-spokes that connected first and are still pending. Covers
        # the sub-before-parent connect ordering; sub-after-parent is handled at
        # the sub-spoke's connect (parent-auto-approve block in handle_connection).
        if self.spoke_module_types.get(pk) == "agent":
            await self._auto_approve_pending_subspokes(spoke_id)

    async def rotate_spoke_secret_now(self, spoke_id: str) -> Dict[str, Any]:
        """On-demand, in-place session-secret rotation for one spoke (item 9b).

        Rotates the key and pushes the new secret to the spoke signed with the
        PRE-rotation secret — the same non-disruptive delivery path the 30-day
        background loop uses (``run_key_rotation_loop``). The spoke verifies +
        installs the new secret without re-onboarding and stays connected and
        approved; the old secret remains valid via the history window for
        in-flight frames until the next rotation.

        This is the routine / cyclical rotation lever. For a
        suspected-compromise rotation where the OLD secret must STOP working
        immediately, use ``revoke_spoke`` or ``reset_spoke_secret`` (wipe +
        re-onboard) instead — in-place rotation intentionally keeps the previous
        secret briefly valid, which is what makes it non-disruptive.

        If the spoke isn't connected, the key is still rotated; the new secret
        takes effect on next connect (the spoke presents the old secret, which
        is accepted via the history window, then is pushed the new key). Returns
        ``{"status", "spoke_id", "connected", "pushed", "message"}``.
        """
        pk = self._primary_key(spoke_id)
        if pk not in self.key_manager.keys:
            return {"status": "ERROR", "spoke_id": spoke_id, "connected": False,
                    "pushed": False, "message": "no key for this spoke — nothing to rotate"}
        prev_secret = self.key_manager.current_session_secret(pk)
        new_key = self.key_manager.rotate_key(pk)
        connected = pk in self.active_connections
        pushed = False
        if connected and prev_secret:
            msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(
                    type="SPOKE_UPDATE_SESSION_KEY", data={"secret": new_key.secret}))
            try:
                await self.send_to_spoke(msg, signing_secret=prev_secret)
                pushed = True
            except Exception as e:  # noqa: BLE001
                logger.error(f"On-demand rotation: failed to push new key to {spoke_id}: {e}")
        self.record_spoke_event(spoke_id, "secret_rotated",
                                f"on-demand; connected={connected} pushed={pushed}")
        logger.info(f"On-demand secret rotation for {spoke_id} "
                    f"(connected={connected} pushed={pushed}).")
        return {"status": "SUCCESS", "spoke_id": spoke_id, "connected": connected,
                "pushed": pushed,
                "message": f"secret rotated; {'new key pushed to spoke' if pushed else 'new key active on next connect'}"}

    async def _maybe_redeliver_session_key(self, spoke_id: str) -> None:
        """Re-push the CURRENT session key to a spoke still signing with a
        previous (rotated-out) key.

        The spoke missed the original ``SPOKE_UPDATE_SESSION_KEY`` push (transient
        disconnect/timing), so it authenticated via the history window but never
        adopted the current key — hub→spoke replies are signed with the current
        key, which the spoke can't verify, producing the ``Bytes signature
        mismatch`` / ``GET_AGENTS`` / ``CS_INGEST_TELEMETRY`` timeout skew. The
        redelivery is signed with the PREVIOUS secret (``history[0]``, which the
        spoke still holds — that's why auth passed via history) so the spoke can
        verify and install the current key without a full re-onboard.

        Rate-limited to once per 60s per spoke. Idempotent: re-installing the
        already-current secret is a no-op on the spoke side, so a frame signed
        with an in-flight pre-rotation key (legitimately mid-adoption) triggering
        this is harmless. If the spoke's secret is no longer in history (evicted
        by a later rotation, or wiped), auth would have failed and the spoke
        would self-heal via 1008 → zero-touch instead.
        """
        now = time.time()
        if now - self._rotation_repush_at.get(spoke_id, 0.0) < 60:
            return
        pk = self._primary_key(spoke_id)
        if pk not in self.active_connections:
            return
        current = self.key_manager.current_session_secret(pk)
        prev = self.key_manager.previous_session_secret(pk)
        if not current or not prev:
            return
        self._rotation_repush_at[spoke_id] = now
        msg = Message(
            header=MessageHeader(
                message_id=str(uuid.uuid4()), timestamp=time.time(),
                sender_id="hub", destination_id=spoke_id),
            payload=MessagePayload(
                type="SPOKE_UPDATE_SESSION_KEY", data={"secret": current}))
        try:
            await self.send_to_spoke(msg, signing_secret=prev)
            logger.info(f"Re-delivered current session key to {spoke_id} "
                        f"(was signing with previous key — missed rotation push).")
            self.record_spoke_event(spoke_id, "session_key_redelivered",
                                    "spoke on previous key — current key re-pushed")
        except Exception as e:  # noqa: BLE001
            logger.error(f"Re-deliver session key to {spoke_id} failed: {e}")

    async def rotate_all_spoke_secrets_now(self) -> Dict[str, Any]:
        """On-demand in-place rotation for every approved spoke with a key
        (item 9b) — the operator's "rotate everything after an incident" lever.
        Reuses ``rotate_spoke_secret_now`` per spoke (concurrent pushes), so each
        is non-disruptive and the old secret stays briefly valid via history.
        Returns ``{"status", "rotated": [...], "failed": [...]}``."""
        targets = [sid for sid, ap in self.approved_modules.items() if ap
                   and sid in self.key_manager.keys]

        async def _one(sid):
            try:
                r = await self.rotate_spoke_secret_now(sid)
                return sid if r.get("status") == "SUCCESS" else None
            except Exception as e:  # noqa: BLE001
                logger.error(f"rotate-all: failed for {sid}: {e}")
                return None

        results = await asyncio.gather(*(_one(sid) for sid in targets)) if targets else []
        rotated = [r for r in results if r]
        failed = [sid for sid in targets if sid not in rotated]
        logger.info(f"On-demand rotate-all: {len(rotated)} rotated, {len(failed)} failed.")
        return {"status": "SUCCESS", "rotated": rotated, "failed": failed}

    async def push_hub_url_to_all_spokes(self, hub_url: str) -> Dict[str, Any]:
        """Fan out a hub-URL change to every approved spoke immediately (the
        save-time path; the reconcile-on-every-connect path in
        ``push_config_to_spoke`` covers spokes that connect later). Uses
        ``push_or_queue_to_spoke`` so a spoke mid-reconnect (or that restarts
        onto the new URL before replying — the apply path os._exits) is queued
        in the durable mailbox and re-delivered on its next connect, where the
        idempotent handler no-ops (it's already on the new URL) and clears the
        ack. Loopback/auto spokes skip in-handler, so the fan-out is safe to
        send to everyone. Returns ``{"status","pushed","queued","failed"}``."""
        targets = [sid for sid, ap in self.approved_modules.items() if ap]

        async def _one(sid):
            try:
                r = await self.push_or_queue_to_spoke(
                    sid, "SPOKE_SET_HUB_URL", {"hub_url": hub_url})
                if r.get("queued"):
                    return sid, "queued"
                return sid, "pushed"
            except Exception as e:  # noqa: BLE001
                logger.error(f"push-hub-url: failed for {sid}: {e}")
                return sid, "failed"

        results = await asyncio.gather(*(_one(sid) for sid in targets)) if targets else []
        pushed = [sid for sid, kind in results if kind == "pushed"]
        queued = [sid for sid, kind in results if kind == "queued"]
        failed = [sid for sid, kind in results if kind == "failed"]
        logger.info(f"Hub-URL fan-out: {len(pushed)} pushed, {len(queued)} queued, "
                    f"{len(failed)} failed.")
        return {"status": "SUCCESS", "pushed": pushed, "queued": queued, "failed": failed}

    async def push_watchdog_to_all_spokes(self, wd_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Fan out the hub-contact watchdog config to every approved spoke/agent
        immediately (the save-time path; ``push_config_to_spoke`` reconciles it on
        every connect for spokes that connect later). Uses ``push_or_queue_to_spoke``
        so an offline spoke gets it from the durable mailbox on next connect. The
        handler is idempotent (just rewrites the local config file), so the fan-out
        is safe for everyone. Returns ``{"status","pushed","queued","failed"}``."""
        targets = [sid for sid, ap in self.approved_modules.items() if ap]

        async def _one(sid):
            try:
                r = await self.push_or_queue_to_spoke(sid, "SPOKE_SET_WATCHDOG", wd_cfg)
                return sid, ("queued" if r.get("queued") else "pushed")
            except Exception as e:  # noqa: BLE001
                logger.error(f"push-watchdog: failed for {sid}: {e}")
                return sid, "failed"

        results = await asyncio.gather(*(_one(sid) for sid in targets)) if targets else []
        pushed = [sid for sid, kind in results if kind == "pushed"]
        queued = [sid for sid, kind in results if kind == "queued"]
        failed = [sid for sid, kind in results if kind == "failed"]
        logger.info(f"Watchdog fan-out: {len(pushed)} pushed, {len(queued)} queued, {len(failed)} failed.")
        return {"status": "SUCCESS", "pushed": pushed, "queued": queued, "failed": failed}

    async def revoke_spoke(self, spoke_id: str) -> Dict[str, Any]:
        """Immediate, non-destructive revocation of a spoke (item 9c).

        The complement to on-demand rotation for the suspected-compromise case
        where the OLD secret must STOP working right now: closes the live
        WebSocket, drops approval (``approved=False`` — re-approval required to
        return), and wipes the crypto material so the old secret no longer
        verifies on reconnect (``get_valid_key`` returns None → auth-failed →
        close 1008). Unlike ``DELETE /setup/spokes/{id}``, the registration
        record is KEPT (the spoke remains in ``known_modules`` as a revoked /
        pending entry) so the operator can see it was revoked and re-onboard +
        re-approve the same id when ready. Also clears queued mail (the keyless
        spoke can't verify signed frames). Returns ``{"status", "spoke_id",
        "was_connected", "message"}``.
        """
        pk = self._primary_key(spoke_id)
        was_connected = pk in self.active_connections
        ws = self.active_connections.get(pk)
        if ws is not None:
            try:
                await ws.close(code=1008, reason="Revoked by admin")
            except Exception as e:  # noqa: BLE001
                logger.warning(f"revoke_spoke: could not close live WS for {spoke_id}: {e}")
        self.approved_modules[pk] = False
        self.state.register_module(pk, approved=False)
        await self.state.save_state_now()
        self.key_manager.delete_spoke_key(pk)
        # Mailbox is guid-keyed after arm — clear by pk so a revoked armed
        # spoke's stranded queue/pending-ack (under its guid) is actually dropped.
        await self.mailbox.clear_spoke(pk)
        self.record_spoke_event(spoke_id, "revoked",
                                f"admin revoke; was_connected={was_connected}")
        logger.warning(f"Spoke {spoke_id} revoked by admin "
                       f"(was_connected={was_connected}); re-onboard + re-approve to return.")
        return {"status": "SUCCESS", "spoke_id": spoke_id,
                "was_connected": was_connected,
                "message": f"revoked; old secret invalidated, approval dropped — "
                           f"re-onboard + re-approve to return"}

    async def _parent_vouches(self, spoke_id: str, parent_spoke_id: str) -> Tuple[bool, str]:
        """Signed parent attestation for parent-auto-approve (H3).

        Replaces the claim-based ``_can_parent_auto_approve`` gate. Instead of
        trusting the child's unsigned ``parent_spoke_id`` WS-auth claim, the hub
        asks the claimed parent — over the signed ``request_response`` channel —
        to vouch that ``spoke_id`` is one of the role sub-spokes it actually
        spawned (the parent's ``VOUCH_SUBSPOKE`` handler checks its in-memory
        role registry). The parent's reply is cryptographically authenticated by
        the existing inbound signature verification (HMAC-SHA256 session key),
        so a verified affirmative vouch binds auto-approve to the parent's
        identity — not the child's string claim. This closes the hostname-spoof
        sub-issue: an attacker who merely learns an approved base agent's
        observable spoke_id and connects as ``{base}-evil`` is NOT vouched for
        by the parent, so it stays pending admin approval (no session key, no
        tenant bind).

        Only a verified affirmative vouch authorizes auto-approve: status
        SUCCESS + ``vouched`` True + ``sub_spoke_id`` echo match. The echo match
        prevents a generic/replayed "yes" authorizing a different child. Anything
        else falls through to pending admin approval (today's non-auto path) —
        the connection is NOT closed. A parent that doesn't implement
        ``VOUCH_SUBSPOKE`` (older agent) returns ERROR/timeout → pending, so
        rolling this out doesn't break existing sub-spoke onboarding (they just
        need manual approval until upgraded); no fleet-wide break.

        Returns ``(True, "")`` on a verified vouch, else ``(False, reason)``
        where reason is one of ``prefix_mismatch`` / ``not_agent`` /
        ``not_connected`` / ``unauthenticated`` / ``timeout`` / ``denied`` /
        ``mismatch`` — surfaced as a ``parent_vouch_failed`` event for Setup
        diagnostics. The short 3s timeout is safe because the pre-flight guard
        already confirmed the parent can sign; it only blocks the child's
        ``handle_connection`` coroutine briefly.
        """
        # Fast local pre-filters (avoid a pointless round-trip): the child id
        # must be prefix-tied to the claimed parent (the agent's own
        # ``{parent}-{role}`` id-construction convention), and the parent must be
        # a generic agent — only agents implement VOUCH_SUBSPOKE. These no longer
        # authorize on their own; they only short-circuit an ask that can't
        # succeed.
        if not parent_spoke_id or not spoke_id.startswith(parent_spoke_id + "-"):
            return False, "prefix_mismatch"
        if self.spoke_module_types.get(self._primary_key(parent_spoke_id)) != "agent":
            return False, "not_agent"
        # Pre-flight: the parent must be connected AND hold its session key (can
        # sign a reply). A parent that structurally can't respond → immediate
        # fall-through (no 3s hang). A fresh parent still in its <10s grace
        # window passes and lets the round-trip timeout absorb a genuine failure.
        ok, reason = self.spoke_can_accept_commands(parent_spoke_id)
        if not ok:
            return False, reason  # "not_connected" or "unauthenticated"
        try:
            res = await self.request_response(
                parent_spoke_id, "VOUCH_SUBSPOKE",
                {"sub_spoke_id": spoke_id}, timeout=3.0)
        except Exception as e:  # noqa: BLE001 - never block onboarding on a vouch error
            logger.warning("VOUCH_SUBSPOKE round-trip to %s for %s raised: %s",
                           parent_spoke_id, spoke_id, e)
            return False, "timeout"
        # request_response returns the full wire frame on success, or
        # {"status":"ERROR","message":"Timed out..."} on timeout (no payload).
        # Distinguish the two: a timeout (no payload — the round-trip itself
        # failed, or an older agent that never implemented VOUCH_SUBSPOKE and
        # never replied) vs a real spoke ERROR reply (payload present, status
        # ERROR — e.g. a handler that ran but refused). unwrap_spoke extracts
        # payload.data (the handler's return dict) when the envelope is present.
        has_payload = isinstance(res, dict) and isinstance(res.get("payload"), dict)
        if not has_payload:
            return False, "timeout"
        try:
            import access as _access
            body = _access.unwrap_spoke(res)
        except Exception:  # noqa: BLE001 - never block onboarding on an unwrap error
            body = {}
        if not isinstance(body, dict) or body.get("status") != "SUCCESS":
            # Older agent without a VOUCH_SUBSPOKE handler → ERROR → pending.
            return False, "denied"
        d = body.get("data") or {}
        if d.get("vouched") is True and d.get("sub_spoke_id") == spoke_id:
            return True, ""
        return False, "mismatch"

    async def _auto_approve_pending_subspokes(self, parent_spoke_id: str) -> None:
        """Approve every still-pending role sub-spoke of an approved base agent.

        Called from ``approve_and_bind_spoke`` when a base agent (module_type
        ``"agent"``) is approved. Each pending sub-spoke that claimed this parent
        (``spoke_parent_map[sid] == parent``) and is **vouched for by the parent**
        (``_parent_vouches`` — a signed ``VOUCH_SUBSPOKE`` round-trip, H3) gets
        approved + bound to the parent's tenant on its already-open connection
        (``approve_and_bind_spoke`` pushes the session key + APPROVED + config
        to the live ws). Sub-spokes whose parent isn't this one — or that the
        parent doesn't vouch for — are left pending (a ``parent_vouch_failed``
        event records why). This sweep runs right after the parent's own
        ``approve_and_bind_spoke`` pushed its session key, so the parent is
        authenticated and can sign; the 3s vouch timeout absorbs the small race
        between key-push and the vouch request landing. This is the path that
        covers sub-before-parent connect order AND boot-seeded roles (the parent
        re-spawns roles at boot without a hub ``LOAD_ROLE`` — the live round-trip
        handles these with no prior hub state)."""
        parent_pk = self._primary_key(parent_spoke_id)
        tenant = self.state.get_spoke_tenant(parent_pk) or ""
        for sid in list(self.active_connections.keys()):
            if sid == parent_pk:
                continue
            if self.approved_modules.get(sid, False):
                continue
            if self._primary_key(self.spoke_parent_map.get(sid, "")) != parent_pk:
                continue
            vouched, reason = await self._parent_vouches(sid, parent_spoke_id)
            if not vouched:
                self.record_spoke_event(sid, "parent_vouch_failed",
                                        f"parent={parent_spoke_id} reason={reason}")
                continue
            logger.info(f"Parent auto-approve (sweep): {sid} via parent "
                        f"{parent_spoke_id} (tenant={tenant or 'unassigned'}).")
            await self.approve_and_bind_spoke(sid, tenant)
            self.record_spoke_event(sid, "parent_auto_approve",
                                    f"parent={parent_spoke_id}")
        self.known_modules = self.state.system_state["known_modules"]

    # Reasons returned by spoke_can_accept_commands for the False cases.
    _CMD_NOT_CONNECTED = "not_connected"
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def spoke_can_accept_commands(self, spoke_id: str) -> Tuple[bool, str]:
        """Whether a command/response round-trip to ``spoke_id`` can succeed.

        Returns ``(True, "")`` when the spoke is connected AND has proved it
        holds its session key (``spoke_authenticated`` flag — set when it
        presented a valid secret at connect or sent a hub-verified signed frame).

        Returns ``(False, "not_connected")`` when the spoke isn't connected.

        Returns ``(False, "unauthenticated")`` when the spoke IS connected but
        has been connected long enough to authenticate yet has never verified a
        signature — it never adopted a session key, so it structurally CANNOT
        respond to commands. This is the signature of a protocol-incompatible
        legacy GenericLeafAgent (installed before the installer repoint to
        agent/install_agent.sh): it connects and heartbeats but dispatches on
        top-level ``type`` instead of the hub's ``header/payload`` envelope, so
        it ignores SPOKE_UPDATE_SESSION_KEY / LOAD_ROLE and would otherwise hang
        the caller to its request_response timeout.

        The >10s grace window lets a fresh zero-touch spoke receive its pushed
        key + send its first signed frame before we declare it unauthenticated,
        so a just-approved spoke isn't falsely rejected.
        """
        pk = self._primary_key(spoke_id)
        if pk not in self.active_connections:
            return False, self._CMD_NOT_CONNECTED
        if self.spoke_authenticated.get(pk):
            return True, ""
        tel = self.spoke_telemetry.get(pk) or {}
        last_attempt = tel.get("last_attempt")
        if last_attempt is None:
            # No connect timestamp recorded -> treat as fresh (grace window),
            # NOT time.time() - 0 (which would look ancient and falsely fail-fast).
            conn_age = 0.0
        else:
            try:
                conn_age = time.time() - float(last_attempt)
            except (TypeError, ValueError):
                conn_age = 0.0
        if conn_age > 10.0:
            return False, self._CMD_UNAUTHENTICATED
        # Fresh connection still warming up — give it the benefit of the doubt
        # and let the request_response timeout handle a genuine failure.
        return True, ""

    # A connected-but-never-authenticated spoke is only diagnosed as a broken
    # agent after this many seconds — well past the >10s command-grace window
    # and the normal zero-touch key-push/first-signed-frame round-trip, so a
    # slow-but-healthy agent isn't falsely flagged. The lm-opnsense saga ran
    # for hours in this state; 30s catches it on the first diagnostic tick
    # without racing a legitimate cold start.
    _UNAUTH_DIAGNOSIS_THRESHOLD_S = 30.0

    def _maybe_log_unauthenticated_agent(self, spoke_id: str) -> None:
        """Emit a one-time ERROR diagnosing a connected-but-never-authenticated
        spoke — the legacy/incompatible-agent or crashed-on-startup signature.

        A protocol-compatible agent verifies a signature on its first non-
        heartbeat frame, setting ``spoke_authenticated``. A spoke that stays
        unauthenticated past the grace window AND keeps sending unsigned
        non-heartbeat frames is structurally unable to adopt a session key,
        so LOAD_ROLE / GET_AVAILABLE_ROLES will 503 (``spoke_can_accept_commands``
        returns ``_CMD_UNAUTHENTICATED``). Two root causes produce this:

        1. A legacy GenericLeafAgent (``generic_agent/src/agent.py``, service
           ``lm-generic-agent.service``) — dispatches on top-level ``type``
           and has no ``SPOKE_UPDATE_SESSION_KEY`` / ``LOAD_ROLE`` handlers, so
           it ignores the pushed key and can never sign a frame.
        2. A role-capable agent-spoke (``agent/src/control_plane.py``, service
           ``lm-agent.service``) that crash-loops on startup — typically a
           ``ModuleNotFoundError``/relative-import error from a bad PYTHONPATH
           on a fresh/updated box.

        Fires ONCE per connection (``_unauth_warned_spokes``), cleared on
        authenticate + disconnect, so the error log surfaces the condition
        once instead of flooding per-frame (a broken agent emits a frame on
        every heartbeat tick, all dropped here). Routed through the dedicated
        ``GenericAgent`` logger (``genAgentLogger``) so it's distinguishable
        from generic Hub WARNING noise and surfaceable in the WebUI logs view.
        """
        pk = self._primary_key(spoke_id)
        if pk in self._unauth_warned_spokes:
            return
        tel = self.spoke_telemetry.get(pk) or {}
        last_attempt = tel.get("last_attempt")
        if last_attempt is None:
            return
        try:
            conn_age = time.time() - float(last_attempt)
        except (TypeError, ValueError):
            return
        if conn_age < self._UNAUTH_DIAGNOSIS_THRESHOLD_S:
            return
        self._unauth_warned_spokes.add(pk)
        genAgentLogger.error(
            f"Agent {spoke_id} has been connected for {int(conn_age)}s without "
            f"adopting its session key — it never verified a signature, so it "
            f"cannot accept commands (LOAD_ROLE / GET_AVAILABLE_ROLES will 503 "
            f"with a reinstall hint). This is the signature of either a "
            f"protocol-incompatible legacy GenericLeafAgent or an agent-spoke "
            f"that crashed on startup. Remediation: check "
            f"/var/log/lm/lm-agent.log and /var/log/lm/lm-generic-agent.log "
            f"for a crash-loop / import error; if both lm-agent and "
            f"lm-generic-agent services are enabled, disable the legacy "
            f"lm-generic-agent.service (systemctl disable --now "
            f"lm-generic-agent) and reinstall the agent via install_menu.sh "
            f"(agent/install_agent.sh), approve the base generic node, then "
            f"retry role activation."
        )

    async def _try_psk_self_provision(self, spoke_id: str, tenant_hint: str, psk: str) -> bool:
        """Validate a spoke's onboarding PSK against the tenant's stored PSKs
        and, on a match, auto-approve + auto-bind the spoke to that tenant (PSK
        self-provisioning). Mirrors the legacy cs/webui-local
        ``/api/spokes/register`` PSK auto-approve (spokes.py:536-605).

        The PSK is a deploy-time secret presented in the WS auth frame; it is
        never logged and never persisted by the hub (compared once, then
        discarded). A spoke already approved but unbound (e.g. an approved cs
        spoke that was never tenant-bound) is re-bound on reconnect with a
        valid PSK. Idempotent: re-presenting a valid PSK re-affirms the same
        binding. Returns True on success, False on any mismatch/failure (the
        caller falls through to pending admin approval — never hard-closes)."""
        try:
            psks = await self.simulations_store.get_psks(tenant_hint)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"PSK self-provision: could not read PSKs for tenant {tenant_hint}: {e}")
            return False
        if not psks:
            return False
        # Constant-time compare against each stored PSK for the tenant.
        if not any(hmac.compare_digest(str(p), psk) for p in psks):
            return False
        pk = self._primary_key(spoke_id)
        self.state.register_module(pk, approved=True)
        self.state.set_spoke_tenant(pk, tenant_hint)
        self.approved_modules[pk] = True
        await self.state.save_state_now()
        logger.info(f"PSK self-provision: {spoke_id} auto-approved + bound to tenant {tenant_hint}.")
        self.record_spoke_event(spoke_id, "psk_self_provision", f"tenant={tenant_hint}")
        return True

    async def _handle_cs_telemetry(self, spoke_id: str, cs_data) -> None:
        """Ingest a CS_TELEMETRY frame from a combined cs / unified pxmx spoke.

        The combined Client-Sim spoke pushes a CS_TELEMETRY frame on its relay
        interval carrying proxmox/clients/simulations/central/reclone data (the
        same payload it used to send to cs/webui-hub). We cache the latest per
        spoke (``simulations_cache``); the Simulations read API serves from that
        cache, and we fan the frame out to browsers subscribed on /sim/ws
        (tenant-scoped) via ``SimulationsBroadcaster.broadcast``. Called from
        ``handle_connection``; only reached for approved spokes (unapproved are
        dropped before dispatch). The inner ``continue`` belongs to the
        ``for hh in proxmox_hosts`` loop, not the message loop.
        """
        if not isinstance(cs_data, dict):
            return
        pk = self._primary_key(spoke_id)
        # Stamp frame arrival so the Simulations warm-start can distinguish a
        # FRESH cache (< 5 min → served as current after a restart, no notice)
        # from a STALE one (→ "cached data — check Spoke and Agent" notice). This
        # survives the encrypted warm-load. See service._cache_fields.
        try:
            cs_data["fetched_at"] = time.time()
        except Exception:  # noqa: BLE001 — never let stamping break ingest
            pass
        # SIMPLE MODEL (was: skip the side-effects when the content-signature
        # matched the last frame): every fresh frame STORES, rebuilds the
        # shaped-read memo, and broadcasts (below). The old change-gating stranded
        # real updates whenever the signature failed to capture a change — or the
        # agent stalled — which the operator saw as a frozen view that only a manual
        # cache-clear would refresh. A per-frame rebuild is cheap for this fleet;
        # correctness beats the saved CPU. (The spoke still stamps ``_content_sig``;
        # the hub just no longer gates on it.)
        self.simulations_cache[pk] = cs_data
        self._sim_cache_dirty = True  # warm-load snapshot flushed by run_sim_cache_flush_loop
        # Spoke-reported drain state (mid self-update). ``draining: true`` keeps
        # the hub from firing request/reply commands at a spoke that's about to
        # os._exit+relaunch (config pushes queue to the mailbox instead). A
        # spoke that just restarted reports ``draining: false`` on its first
        # tick → clear drain so the hub resumes normal live pushes.
        try:
            if cs_data.get("draining"):
                self.mark_draining(spoke_id)
            else:
                self.clear_draining(spoke_id)
        except Exception:  # noqa: BLE001 — drain bookkeeping must never break ingest
            pass
        # Fan out to browsers subscribed on /sim/ws (tenant-scoped) on EVERY frame —
        # same rationale as the per-frame memo rebuild: never strand an update.
        try:
            await self.simulations_broadcaster.broadcast(
                spoke_id, cs_data, self.state.get_spoke_tenant(spoke_id))
        except Exception as exc:
            logger.debug("simulations broadcast failed: %s", exc)
        # USB-availability diagnostic: summarize which USB keys the cs spoke sent
        # and where they live, so a missing USB count in the tenant
        # Simulations/VM Server view can be localized to the spoke payload shape
        # vs. the hub mapping. Keys + counts only — never values (a CS payload
        # may carry Proxmox tokens in other frames).
        try:
            def _usb_sum(px):
                if not isinstance(px, dict):
                    return {}
                return {
                    "present_usb": len(px.get("present_usb") or []) if isinstance(px.get("present_usb"), list) else px.get("present_usb"),
                    "unknown_usb": len(px.get("unknown_usb") or []) if isinstance(px.get("unknown_usb"), list) else px.get("unknown_usb"),
                    "usb_state": len(px.get("usb_state") or []) if isinstance(px.get("usb_state"), list) else px.get("usb_state"),
                    "usb_count": px.get("usb_count"),
                }
            ph = cs_data.get("proxmox_hosts")
            if isinstance(ph, list) and ph:
                per = []
                for hh in ph:
                    if not isinstance(hh, dict):
                        continue
                    per.append({
                        "host": hh.get("hostname") or hh.get("spoke_name") or "?",
                        "proxmox.usb": _usb_sum(hh.get("proxmox")),
                        "top.usb_devices": len(hh.get("usb_devices") or []) if isinstance(hh.get("usb_devices"), list) else hh.get("usb_devices"),
                        "top.present_usb": len(hh.get("present_usb") or []) if isinstance(hh.get("present_usb"), list) else hh.get("present_usb"),
                    })
                logger.debug("CS_TELEMETRY cached for %s (multi-host usb=%s)", spoke_id, per)
            else:
                logger.debug("CS_TELEMETRY cached for %s (legacy usb=%s top.usb_devices=%s)",
                             spoke_id, _usb_sum(cs_data.get("proxmox")),
                             len(cs_data.get("usb_devices") or []) if isinstance(cs_data.get("usb_devices"), list) else cs_data.get("usb_devices"))
        except Exception as _ue:
            logger.debug("CS_TELEMETRY usb-diagnostic failed for %s: %s", spoke_id, _ue)

    async def _handle_spoke_log(self, spoke_id: str, payload) -> None:
        """Append a SPOKE_LOG frame's entries to the in-memory agent log buffer.

        Every spoke relays its captured log entries (INFO+) here every few
        seconds, plus a final flush before a self-update restart. We append them
        to ``agent_logs[spoke_id]`` so ``collect_all_logs`` /
        ``collect_error_logs`` surface them with module = spoke_id (and BugFixer's
        GET_LOGS). Previously SPOKE_LOG had no handler and fell through to the
        catch-all + discard, so spoke logs never reached the WebUI Logs view.
        Called from ``handle_connection``.

        Ephemeral by design: ``agent_logs[spoke_id]`` is an in-memory deque
        (``maxlen = max_log_size``) that is NOT persisted to disk and is lost on
        a hub restart (and dropped for a spoke by ``_evict_spoke`` when the spoke
        is deleted). It is a rolling recent-window view for the WebUI / bugfixer,
        not an audit log — the spoke's own journal is the durable record. Each
        entry is stamped with the hub receive time (the spoke's original timestamp
        is inside the entry text), and the deque caps total volume per spoke so a
        chatty spoke can't starve memory at 10k-client scale.
        """
        log_data = payload.get("data", {})
        entries = log_data.get("entries") if isinstance(log_data, dict) else None
        if isinstance(entries, list):
            pk = self._primary_key(spoke_id)
            if pk not in self.agent_logs:
                self.agent_logs[pk] = deque(maxlen=self.max_log_size)
            # Entries arrive already canonical-formatted by the spoke's
            # _SpokeLogRelayHandler (``<asctime> - <name> - <levelname> - <msg>``)
            # — store verbatim. Re-stamping with the hub receive time would
            # duplicate the timestamp (the record's original asctime is inside
            # the entry) and desync the WebUI view from the spoke's local log.
            for entry in entries:
                if isinstance(entry, str):
                    self.agent_logs[pk].append(entry)
            logger.debug(f"SPOKE_LOG: stored {len(entries)} entries for {spoke_id}")

    async def _handle_cs_debug_log(self, spoke_id: str, payload) -> None:
        """Append a CS_DEBUG_LOG frame's lines to the per-host client-debug buffer.

        Mirrors ``_handle_spoke_log`` but keyed by ``(tenant, hostname)`` instead
        of by spoke pk: a single cs spoke relays debug logs for many clients, so
        the spoke id is the wrong key. The cs spoke stamps ``hostname`` + the
        originating ``level`` on the frame (``server.py`` /ws/client →
        ``_relay_client_debug_log_to_hub``); the tenant comes from the spoke's
        binding (``state.get_spoke_tenant``).

        Ephemeral by design — same contract as ``agent_logs``: an in-memory
        ``deque(maxlen = client_debug_size)`` that is NOT persisted and is lost
        on hub restart. It is a rolling recent-window troubleshooting view served
        by ``GET /api/cs/clients/{host}/debug-logs`` (routes/client_debug.py),
        not an audit log. The 30-min client-side auto-off + the deque cap is the
        memory backstop; advanced level (journal/dmesg) is chatty.

        Also enforces a hub-side auto-off belt-and-suspenders: once a host's
        session is past the 30-min window (``enabled_at`` recorded by the POST
        route), new frames are dropped so a client that drops and re-streams past
        the window can't keep filling the buffer.
        """
        data = payload.get("data", {}) if isinstance(payload.get("data"), dict) else {}
        hostname = data.get("hostname")
        if not hostname:
            return
        try:
            tenant = self.state.get_spoke_tenant(self._primary_key(spoke_id)) or "default"
        except Exception:  # noqa: BLE001 — tenant resolution is best-effort
            tenant = "default"
        key = (tenant, str(hostname))

        # Hub-side auto-off: drop frames past the session window. ``enabled_at``
        # is recorded by the POST /debug route; the client tailer self-stops at
        # the same window, but this guards a reconnect/re-stream after the cut.
        sess = self.client_debug_sessions.get(key) or {}
        enabled_at = sess.get("enabled_at")
        if isinstance(enabled_at, (int, float)) and time.time() - float(enabled_at) > 30 * 60:
            return

        lines = data.get("lines") if isinstance(data.get("lines"), list) else []
        if not lines:
            return
        if key not in self.client_debug_logs:
            self.client_debug_logs[key] = deque(maxlen=self.client_debug_size)
        # Stamp each line with the hub receive time + originating level so the
        # WebUI panel can render/sort/group without needing client clocks.
        _ts = time.time()
        _lvl = str(data.get("level") or (sess.get("level") or "basic"))
        for line in lines:
            if isinstance(line, str):
                self.client_debug_logs[key].append({"ts": _ts, "level": _lvl, "line": line})
        logger.debug("CS_DEBUG_LOG: stored %d lines for %s/%s", len(lines), tenant, hostname)

    def _inherit_agent_tenant(self, agent_id: str, spoke_id: str) -> None:
        """Stamp the spoke's tenant onto the agent's ``client_simulation.tenant_id``.

        A pxmx agent's owning spoke can be tenant-assigned (``module_metadata``
        ``tenant_id``) while the agent's own ``agent_config[agent_id]`` entry
        has no tenant — or a stale one saved before the spoke was bound. Always
        overwrite to match (per the user's "always overwrite to match" choice):
        the spoke's binding is authoritative for the agent's tenant. Preserves
        ``enabled`` + ``usb_config``; only ``tenant_id`` is stamped. Tolerant
        (try/except + ``or {}``) like ``_relay_cs_event_inner`` / cs_bridge. A
        no-op when the spoke has no tenant (unassigned spoke) so the agent's
        existing tenant_id is left intact. Persisted via ``save_state``.
        Best-effort: never raises into the relay path."""
        if not agent_id:
            return
        try:
            spoke_tenant = self.state.get_spoke_tenant(self._primary_key(spoke_id))
        except Exception:
            spoke_tenant = None
        if not spoke_tenant:
            return
        try:
            store = self.state.system_state.setdefault("agent_config", {})
            agent_pk = self._agent_primary_key(agent_id)
            entry = store.get(agent_pk)
            if not isinstance(entry, dict):
                entry = {"display_name": agent_id}
                store[agent_pk] = entry
            cs_cfg = dict(entry.get("client_simulation") or {})
            if cs_cfg.get("tenant_id") != spoke_tenant:
                cs_cfg["tenant_id"] = spoke_tenant
                entry["client_simulation"] = cs_cfg
                self.state._mark_dirty()
        except Exception as _e:  # noqa: BLE001 — best-effort; never break relay
            logger.debug("agent tenant-inheritance write failed: %s", _e)

    async def _decrypt_inbound_payload(self, spoke_id: str, src: Optional[str],
                                       msg_data: dict) -> Any:
        """H4: AEAD-decrypt ``payload.data`` of an inbound secret-bearing frame
        AFTER HMAC verify + freshness have passed, before dispatch reads ``data``.

        Resolves the AEAD key from the signature source: ``src == "history"`` →
        the spoke signed with a PREVIOUS (rotated-out) key, so decrypt with
        ``previous_session_secret`` (the key the spoke still holds at decode time,
        mirroring the hub→spoke ``SPOKE_UPDATE_SESSION_KEY`` rule); otherwise the
        current session key. (Both sides derive the AEAD key from the *same
        secret that HMAC-signed the frame*, so the verify source is the decrypt
        source.)

        Returns the resolved secret (so the caller can thread it into the nested
        ``AGENT_RELAY_UP`` decrypt) on success — including the plaintext/legacy
        passthrough case, which is a no-op and returns the resolved secret
        unchanged. Returns the ``_H4_DROP`` sentinel when the frame is marked
        encrypted but cannot be decrypted: no secret on record, a tampered or
        wrong-key ciphertext (``InvalidTag``), or a malformed b64/JSON payload
        (``ValueError``, which covers ``binascii.Error`` and ``json`` failures).
        A frame that won't AEAD-decrypt under the key that HMAC-verified it is
        corrupted or hostile — it is dropped, never dispatched as ciphertext.
        """
        from security.frame_crypto import unwrap
        payload = msg_data.get("payload", {})
        pk = self._primary_key(spoke_id)
        if src == "history":
            dec_secret = self.key_manager.previous_session_secret(pk)
        else:
            dec_secret = self.key_manager.current_session_secret(pk)
        if not is_encrypted(payload):
            return dec_secret  # plaintext / legacy passthrough (may be None)
        if dec_secret is None:
            logger.warning("Encrypted frame from %s but no decrypt key on record — dropping", spoke_id)
            return _H4_DROP
        try:
            unwrap(dec_secret, payload)
        except (InvalidTag, ValueError) as e:
            logger.warning("Dropping tampered/undecryptable frame from %s: %s", spoke_id, e)
            return _H4_DROP
        return dec_secret

    async def _handle_agent_relay_up(self, spoke_id: str, msg_data, payload,
                                      _dec_secret: Optional[str] = None) -> bool:
        """Dispatch a relayed agent frame (AGENT_RELAY_UP) from a pxmx spoke.

        The spoke forwards ``original_payload`` from a unified agent. We branch on
        the inner payload's ``type``: AGENT_LOG → buffer per-agent log line,
        HEARTBEAT → update per-agent heartbeat, AGENT_TELEMETRY → store telemetry,
        CS_* → forward to the tenant's cs spoke via ``_relay_cs_event``.

        Fall-through contract (CRITICAL — preserve exactly):
            Returns True  → a sub-type matched and was handled; caller MUST
                ``continue`` (do not fall through to HUB_REQUEST / catch-all).
            Returns False → no sub-type matched; caller MUST NOT ``continue``.
                The frame falls through to the HUB_REQUEST check and the catch-all
                INFO log in ``handle_connection``, identical to the pre-extraction
                inline behavior. Unlike CS_TELEMETRY/SPOKE_LOG/HUB_REQUEST (which
                always continue), unmatched AGENT_RELAY_UP frames are intentionally
                allowed to fall through — do not change this.
        """
        relay_data = payload.get("data", {})
        agent_id = relay_data.get("agent_id")
        original_msg = relay_data.get("original_payload", {})

        # Reconcile agent identity (clone-and-rename detection) BEFORE any
        # per-agent processing, so a renamed node's agent_config/heartbeat/telemetry
        # are re-keyed to the new agent_id here. install_uuid/hostname ride the
        # relay envelope from the pxmx spoke's _relay_agent_msg_up.
        self._reconcile_spoke_identity(
            agent_id,
            (relay_data.get("install_uuid") or "").strip(),
            (relay_data.get("hostname") or "").strip(),
            is_agent=True,
            parent_spoke_id=spoke_id,
        )

        # The agent primary key (guid once B2 has armed it via the reconcile
        # above, else the raw name). All per-agent hub state below keys through
        # agent_pk; the relay envelope target_agent_id stays the raw name (option
        # b), translated from the guid via agent_info[guid]["agent_id"] where a
        # guid-keyed internal caller needs the wire name.
        agent_pk = self._agent_primary_key(agent_id) if agent_id else None

        # Index the agent → its owning spoke so command routing (CS bridge,
        # SET_AGENT_CONFIG) reaches the right spoke: a pxmx-dialed agent indexes
        # to the pxmx spoke, a cs-dialed agent indexes to the cs spoke. Updated
        # on every relayed frame (heartbeat/telemetry/log/CS_*), so the index is
        # fresh and the hostname tracks a rename. Evicted on spoke disconnect.
        # agent_id (raw name) is stored for guid→name relay translation; spoke_id
        # is the raw connect name (relay destinations resolve via _primary_key).
        if agent_id and agent_pk is not None:
            self.agent_info[agent_pk] = {
                "spoke_id":  self._primary_key(spoke_id),
                "agent_id":  agent_id,
                "hostname":  (relay_data.get("hostname") or "").strip() or agent_id,
                "last_seen": time.time(),
            }

        # Inherit the spoke's tenant onto the agent's client_simulation.tenant_id
        # so a pxmx server attached to a tenant-assigned cs spoke carries that
        # tenant — the agent's own config can drift from the spoke's binding.
        self._inherit_agent_tenant(agent_id, spoke_id)

        logger.debug(f"Relayed message from Agent {agent_id} via Spoke {spoke_id}: {original_msg.get('payload', {}).get('type')}")

        # Handle Agent Logs
        if original_msg.get("payload", {}).get("type") == "AGENT_LOG":
            log_data = original_msg.get("payload", {}).get("data", {})
            # The agent's WebSocketLogHandler sends ``message`` already
            # canonical-formatted (``<asctime> - <name> - <levelname> - <msg>``)
            # — store it verbatim so the line carries ONE timestamp (the
            # record's emit time) and the canonical shape, matching the
            # SPOKE_LOG path and the agent's local pxmx-agent.log. The prior
            # ``[hostname] (agent_type) LEVEL:`` prefix + hub receive-time
            # stamp duplicated the timestamp and the name/level already in the
            # canonical record; the WebUI prepends the ``[agent_id]`` source
            # label itself, so agent identity is not lost.
            msg = log_data.get('message') or ''
            if agent_pk not in self.agent_logs:
                self.agent_logs[agent_pk] = deque(maxlen=self.max_log_size)
            if msg:
                self.agent_logs[agent_pk].append(msg)
            return True

        # If the original message was a heartbeat, update heartbeat for that
        # specific agent (keyed spoke_pk:agent_pk — both guid-primary post-B2).
        # pxmx unified agents emit "AGENT_HEARTBEAT" (30s); accept the legacy
        # "HEARTBEAT" type too.
        _orig_type = original_msg.get("payload", {}).get("type")
        if _orig_type in ("HEARTBEAT", "AGENT_HEARTBEAT"):
            self.heartbeat.update_heartbeat(f"{self._primary_key(spoke_id)}:{agent_pk}")
            return True

        # Otherwise, process the original payload as if it came from the agent
        if original_msg.get("payload", {}).get("type") == "AGENT_TELEMETRY":
            pk = self._primary_key(spoke_id)
            if pk not in self.spoke_telemetry:
                self.spoke_telemetry[pk] = {}
            self.spoke_telemetry[pk][agent_pk] = original_msg.get("payload", {}).get("data")
            return True

        # --- Client-Simulation event relay (Phase D1) ---
        # A unified pxmx agent emits CS_* events (CS_TELEMETRY, CS_LOG,
        # CS_WATCHDOG_EVENT, CS_HW_RESET_EVENT, CS_PROGRESS,
        # CS_COMMAND_RESULT, CS_TOKEN_RESULT) up via its pxmx spoke's
        # AGENT_RELAY_UP relay. Forward each to the tenant's cs spoke,
        # which ingests it (CS_INGEST_*) and re-relays CS_TELEMETRY into
        # simulations_cache for the Simulations/VM Server view. The
        # payload already carries hostname + agent_id (the agent's
        # send_cs_event injects both), so we map type → cs-spoke command
        # and resolve the tenant from the per-agent store.
        _orig_type = original_msg.get("payload", {}).get("type")
        if _orig_type and _orig_type.startswith("CS_"):
            # H4 (refinement #2): the spoke's _encode_frame encrypted the NESTED
            # original_payload.payload (e.g. CS_TOKEN_RESULT, whose data carries a
            # Proxmox API token) while leaving the AGENT_RELAY_UP envelope
            # plaintext (so the hub can read agent_id/hostname routing fields).
            # Decrypt the inner payload (with the same verify-source secret)
            # BEFORE reading _cs_data — a tampered/undecryptable inner is dropped
            # (return True: AGENT_RELAY_UP matched, do not fall through).
            _inner_payload = original_msg.get("payload")
            if is_encrypted(_inner_payload):
                if _dec_secret is None:
                    logger.warning("Encrypted nested CS payload from %s but no decrypt key — dropping", spoke_id)
                    return True
                try:
                    from security.frame_crypto import unwrap
                    unwrap(_dec_secret, _inner_payload)
                except (InvalidTag, ValueError) as e:
                    logger.warning("Dropping tampered/undecryptable nested CS payload from %s: %s", spoke_id, e)
                    return True
                _orig_type = _inner_payload.get("type", _orig_type)
            _cs_data = original_msg.get("payload", {}).get("data", {}) or {}
            # Fire-and-forget — do NOT ``await``. ``_relay_cs_event`` dispatches to
            # the tenant's cs spoke via ``request_response`` (up to 30s) and a cs
            # spoke that also hosts cs-dialed agents (LM_CS_AGENT_LISTENER=1, the
            # install default) relays its OWN agent's CS_* events up this same
            # spoke's receive loop. Awaiting the relay inline blocks THIS loop up
            # to 30s waiting for the cs spoke's COMMAND_RESULT — but the very loop
            # that must read that reply is the one blocked waiting for it → a
            # self-deadlock that surfaces as the steady "Request Timeout:
            # [CS_INGEST_TELEMETRY] from <cs-spoke> after 30.0s" at the agent
            # telemetry cadence. Detaching lets the receive loop keep draining +
            # read the reply (populating response_cache) while the relay runs in a
            # background task. ``_relay_cs_event`` never raises, so the task is
            # safe to detach; the relay is best-effort (telemetry ingest does not
            # need its ack on the hot path). See spoke-update-storm memory: the
            # SPOKE_UPDATE storm (600s bursts) was a DIFFERENT failure mode; this
            # self-deadlock is what remains once that storm is gated.
            asyncio.create_task(self._relay_cs_event(spoke_id, agent_id, _orig_type, _cs_data))
            return True

        # --- VNC console relay (agent-terminates-WSS) ---
        # The agent emits VNC_FRAME_UP (Proxmox→browser bytes, b64), VNC_READY
        # (WSS open), VNC_ERROR (vncproxy/WSS failed), VNC_DISCONNECT (Proxmox
        # side closed). Route each to the session's queue; the browser WS reads
        # bytes off the queue and sends them to the client. Control signals are
        # tuples so the WS loop can distinguish them from frame bytes.
        if _orig_type and _orig_type.startswith("VNC_"):
            _vnc_data = original_msg.get("payload", {}).get("data", {}) or {}
            _sid = _vnc_data.get("session_id")
            _sess = self.get_vnc_session(_sid) if _sid else None
            if _orig_type == "VNC_FRAME_UP" and _sess:
                try:
                    raw = base64.b64decode(_vnc_data.get("data") or "")
                    await _sess["queue"].put(raw)
                except Exception:
                    pass
            elif _orig_type == "VNC_READY" and _sess:
                await _sess["queue"].put(("ready",))
            elif _orig_type == "VNC_ERROR" and _sess:
                await _sess["queue"].put(("error", str(_vnc_data.get("error", "vnc error"))[:300]))
            elif _orig_type == "VNC_DISCONNECT" and _sess:
                await _sess["queue"].put(("disconnect",))
            return True

        # --- Host-shell (xterm terminal) relay (agent-terminates-PTY) ---
        # Same shape as VNC: SHELL_OUT (PTY→browser bytes, b64), SHELL_READY
        # (PTY up), SHELL_ERROR, SHELL_DISCONNECT (bash exited / torn down).
        if _orig_type and _orig_type.startswith("SHELL_"):
            _sh_data = original_msg.get("payload", {}).get("data", {}) or {}
            _sid = _sh_data.get("session_id")
            _sess = self.get_shell_session(_sid) if _sid else None
            if _orig_type == "SHELL_OUT" and _sess:
                try:
                    await _sess["queue"].put(base64.b64decode(_sh_data.get("data") or ""))
                except Exception:
                    pass
            elif _orig_type == "SHELL_READY" and _sess:
                await _sess["queue"].put(("ready",))
            elif _orig_type == "SHELL_ERROR" and _sess:
                await _sess["queue"].put(("error", str(_sh_data.get("error", "shell error"))[:300]))
            elif _orig_type == "SHELL_DISCONNECT" and _sess:
                await _sess["queue"].put(("disconnect",))
            return True

        # Unmatched sub-type: return False so handle_connection falls through
        # to the HUB_REQUEST check and catch-all INFO log (see docstring).
        return False

    async def _handle_hub_request(self, spoke_id: str, msg_data, payload,
                                 peer_cert_identity=None) -> None:
        """Dispatch a spoke/agent-initiated HUB_REQUEST and reply with a signed
        HUB_RESPONSE.

        Used by agents that need something from the hub (e.g. BugFixer asking for
        logs or to trigger updates). The request carries NO top-level
        correlation_id (it uses ``header.message_id``) so it isn't consumed as an
        ack in the correlation_id branch of ``handle_connection``; we reply with a
        HUB_RESPONSE carrying that message_id as ``correlation_id``. Only approved
        senders reach here, so ``key_manager.sign_message`` will succeed.

        ``peer_cert_identity`` is the verified client-cert identity (SAN DNS
        names) captured for this connection by the ``/ws/spoke`` route (H1); it
        is the only thing ``handle_hub_request`` authorizes the channel on.
        """
        req = payload.get("data", {}) or {}
        req_id = msg_data.get("header", {}).get("message_id")
        result = await self.handle_hub_request(spoke_id, req, peer_cert_identity)
        resp_msg = Message(
            header=MessageHeader(
                message_id=str(uuid.uuid4()),
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id,
            ),
            payload=MessagePayload(
                type="HUB_RESPONSE",
                data={"correlation_id": req_id, "result": result},
            ),
        )
        try:
            await self.send_to_spoke(resp_msg)
        except Exception as e:
            logger.error(f"Failed to send HUB_RESPONSE to {spoke_id}: {e}")

    async def _install_active_connection(self, spoke_id: str, websocket, key_id: Optional[str]) -> bool:
        """Register ``websocket`` as the active connection for ``spoke_id``.

        Evicts a pre-existing connection for the same spoke_id (e.g. a zombie
        process left over from a prior outage / port-move crash-loop) so its
        inbound frame loop ends instead of continuing to emit signed frames
        that fail verification. Key-id aware: a stale (rotated-out, history)
        session key reconnecting while a *current-key* connection is already
        live is REJECTED (closed) rather than allowed to evict the live
        process — this prevents a zombie from displacing the real spoke and
        avoids reconnect ping-pong.

        Returns True if ``websocket`` is now the active connection, False if it
        was rejected as a stale-key reconnect (caller should return).
        """
        pk = self._primary_key(spoke_id)
        existing = self.active_connections.get(pk)
        if existing is not None and existing is not websocket:
            current = self.key_manager.keys.get(pk)
            current_kid = current.key_id if current else None
            new_is_current = key_id is not None and key_id == current_kid
            old_is_current = (
                current_kid is not None
                and self.active_connection_key_ids.get(pk) == current_kid
            )
            if old_is_current and not new_is_current:
                # Live current-key connection already active; this socket auth'd
                # with a stale history key — reject so the zombie can't take over.
                logger.warning(
                    f"Spoke {spoke_id} connected with a stale session key while a "
                    f"current-key connection is active; closing stale connection."
                )
                self.record_spoke_event(
                    spoke_id, "stale_key_rejected",
                    "history-key connect while current-key connection active",
                )
                try:
                    await websocket.close(1008, "Stale session key — current connection active")
                except Exception:
                    pass
                return False
            # Both auth'd with the same current key — this is either a normal
            # reconnect after a blip (the existing socket is a TCP-half-open
            # zombie whose process already moved on) OR a DUPLICATE spoke
            # process / clone sharing the same spoke_id + secret (the existing
            # socket is alive and actively serving). The two are
            # indistinguishable by key alone, so probe the existing connection's
            # liveness with a ping before deciding:
            #   • alive (pongs within 2s) → duplicate/needless reconnect. Keep
            #     the live existing connection and REJECT the new one, so the
            #     two processes can't mutually evict each other into a
            # reconnect flap (the "newer connection took over" repeats in the
            #     spoke event log). The rejected duplicate backs off and retries,
            #     but never displaces the live connection — flap stops.
            #   • dead (no pong) → zombie; evict it and take over.
            # Both auth'd with the same current key — either a normal reconnect
            # after a blip (the existing socket is a half-open zombie: TCP still
            # ESTABLISHED but the peer died, so no frames arrive and last_seen
            # goes stale) OR a DUPLICATE spoke process / clone sharing the same
            # secret (the existing socket is alive and actively serving, so
            # last_seen is fresh). Distinguish by last_seen freshness — a
            # stronger signal than a single ping pong: a pong only confirms the
            # peer's TCP stack replied, not that the spoke process is actively
            # handling requests, and during a hub freeze a live duplicate's pong
            # can be delayed >2s and false-evict it into a mutual-eviction flap
            # (the regression that got the earlier pong-only probe reverted).
            #   • last_seen fresh (<30s — a live spoke sends telemetry ~every
            #     10s) → live duplicate; keep the existing connection, REJECT
            #     the new one so the two processes can't mutually evict.
            #   • last_seen stale/absent → half-open zombie; confirm with a pong
            #     probe (awaiting the pong WAITER, not ping() — ping() returns
            #     the instant the frame is BUFFERED, false-alive on a half-open
            #     socket) and evict if no pong so the real reconnect takes over.
            alive = False
            last_seen = self.heartbeat.last_seen.get(spoke_id)
            if last_seen is not None and (time.time() - last_seen) < 30.0:
                alive = True
            else:
                try:
                    pong_waiter = await existing.ping()
                    await asyncio.wait_for(pong_waiter, timeout=2.0)
                    alive = True
                except Exception:
                    alive = False
            if alive:
                logger.warning(
                    f"Spoke {spoke_id} connected but an existing live connection "
                    f"is already active; rejecting the duplicate to prevent a "
                    f"mutual-eviction reconnect flap. This usually means a second "
                    f"spoke process or a cloned LXC is sharing {spoke_id}'s "
                    f"secret — find and remove it on the spoke host "
                    f"(pgrep -af control_plane; systemctl status lm-cs)."
                )
                self.record_spoke_event(
                    spoke_id, "duplicate_rejected",
                    "existing connection is live — rejecting duplicate connect "
                    "(likely a second spoke process / clone sharing the secret)",
                )
                try:
                    await websocket.close(1008, "Duplicate connection — existing is live")
                except Exception:
                    pass
                return False
            # Existing is a zombie — install the NEW connection FIRST so any
            # concurrent sender (push_config_to_spoke, flush_mailbox, mailbox
            # retry_loop, key-rotation push) reads the live socket from
            # active_connections instead of the one we're about to close. This
            # closes the read-then-send TOCTOU that surfaced as
            # "WebSocket is not connected. Need to call 'accept' first" errors
            # during the swap window.
            logger.warning(f"Spoke {spoke_id} reconnected; closing previous (zombie) connection.")
            self.record_spoke_event(
                spoke_id, "replaced_connection",
                "newer connection took over (previous was unresponsive)",
            )
            self.active_connections[pk] = websocket
            self.active_connection_key_ids[pk] = key_id
            self._arm_liveness_probe(spoke_id, websocket)
            try:
                await existing.close(1008, "Replaced by newer connection")
            except Exception:
                pass
            return True
        self.active_connections[pk] = websocket
        self.active_connection_key_ids[pk] = key_id
        self._arm_liveness_probe(spoke_id, websocket)
        return True

    async def handle_connection(self, websocket):
        """Handle the full lifecycle of a single Spoke/Agent connection.

        Performs the mutual-auth challenge/response handshake, registers the
        peer (spoke or pxmx agent), rate-limits it, then dispatches inbound
        signed messages to the right router until the socket closes. Cleans up
        the registry + per-spoke event buffer on exit (clean or crash).
        """
        spoke_id = None
        try:
            # 1. Authentication Handshake
            auth_json = await websocket.recv()
            auth_data = json.loads(auth_json)
            spoke_id = auth_data.get("spoke_id")
            secret = auth_data.get("secret")
            module_type = auth_data.get("module_type")
            # PSK self-provisioning fields (optional; absent on non-PSK spokes).
            onboarding_psk = (auth_data.get("onboarding_psk") or "").strip()
            tenant_id_hint = (auth_data.get("tenant_id_hint") or "").strip()
            # Install-UUID identity tracking: a stable per-install UUID + the
            # current OS hostname. Reconcile BEFORE the auth verify so a renamed
            # spoke's re-keyed material is in place for get_valid_key below.
            install_uuid = (auth_data.get("install_uuid") or "").strip()
            spoke_hostname = (auth_data.get("hostname") or "").strip()
            # Multi-role generic agent: a role sub-spoke (spoke_id {base}-{role})
            # claims its base agent as parent so the hub can auto-approve it via
            # the parent. Absent on every other spoke (no behavior change).
            parent_spoke_id = (auth_data.get("parent_spoke_id") or "").strip()
            # Cert-target capability: a generic agent that deployed netbox-server
            # (has the local nginx cert helper) advertises this so the hub can
            # route the NetBox cert to it. Recorded post-auth below.
            netbox_server_cap = bool(auth_data.get("netbox_server"))
            # LDAP web/ldaps server cert-target capability (mirrors netbox_server):
            # a generic agent that ran the ldap-server deploy role advertises this
            # so the hub can route an LE cert to it. Recorded post-auth below.
            ldap_server_cap = bool(auth_data.get("ldap_server"))
            # H4 app-layer-encryption capability: the spoke advertises ``enc="v1"``
            # in its auth frame. Combined with encryption_enabled() so
            # LM_APP_ENCRYPTION=0 makes a new spoke behave as legacy (don't
            # encrypt to it). Recorded post-auth below (unconditional — covers
            # zero-touch / secret-less connects too, mirroring netbox_server_cap).
            spoke_enc_capable = bool(auth_data.get("enc") == ENC_MARKER) and encryption_enabled()

            # DEBUG-only + length-only: a 64-char session key's 4+4 prefix/suffix
            # is a 12.5% entropy reduction, and this fires on EVERY connect
            # attempt, so the log would accumulate prefix/suffix for every spoke
            # over time. Length is enough to distinguish a real key from a
            # missing/short one for debugging without leaking key material.
            logger.debug(f"Auth attempt: spoke_id={spoke_id}, "
                         f"secret={'<%d chars>' % len(secret) if secret else '***'}")
            self.record_spoke_event(spoke_id, "auth_attempt", f"secret={'yes' if secret else 'no'} module_type={module_type}")

            if not spoke_id:
                await websocket.close(1008, "Missing spoke_id")
                return

            pk = self._primary_key(spoke_id)

            # DDoS quarantine: a spoke disconnected for ignoring the slow-down
            # signal and flooding is refused reconnect until its cooldown expires
            # — so it can't just reconnect and immediately resume the flood. 1013
            # = Try Again Later (the spoke's reconnect backoff honors it).
            if self._is_quarantined(spoke_id):
                self.record_spoke_event(spoke_id, "quarantine_reject",
                                        "reconnect refused — still in DDoS quarantine")
                await websocket.close(1013, "Quarantined (flooding) — retry later")
                return

            # Detect a clone-and-rename (same install UUID, new id) and migrate
            # approval/tenant binding + key material to the new id — but ONLY if
            # the caller proves it owns the OLD id's secret (CC2: a bare
            # install_uuid + a new spoke_id with NO secret used to migrate the
            # victim's approval + key material BEFORE any auth verify, then the
            # zero-touch re-key path minted the attacker a fresh session key —
            # full spoke/tenant takeover with no secret knowledge). Verify the
            # presented secret against the OLD id (the UUID's current owner)
            # first; only a proven rename is allowed to migrate. An unproven
            # rename is left as a fresh spoke (pending approval / PSK), never an
            # inheritance. get_valid_key is a pure constant-time compare — safe
            # to call on old_id as a proof check without consuming/rotating it.
            rename_proven = False
            if install_uuid and secret:
                _old_id = self.install_uuid_index.get(install_uuid)
                if _old_id and _old_id != spoke_id \
                        and self.key_manager.get_valid_key(self._primary_key(_old_id), secret):
                    rename_proven = True
            self._reconcile_spoke_identity(spoke_id, install_uuid, spoke_hostname,
                                           migrate_if=rename_proven)
            # Re-resolve the primary key: _reconcile_spoke_identity may have
            # armed guid-primary (spoke_id_alias[spoke_id]=install_uuid), so pk
            # now resolves name→guid. Every state op below keys through pk so
            # the spoke's routing/approval/crypto/mailbox state lands under the
            # guid (the stable primary key) instead of the connect-id name.
            pk = self._primary_key(spoke_id)
            # Recompute pk: the arm inside reconcile may have flipped the alias
            # name→guid, so the pre-reconcile pk computed above is now stale.
            pk = self._primary_key(spoke_id)

            # If secret is provided, verify it. If not, the spoke is in 'pending secret' state.
            is_authenticated = False
            if secret:
                key_id = self.key_manager.get_valid_key(pk, secret)
                if key_id:
                    is_authenticated = True
                    self.spoke_authenticated[pk] = True
                    # It adopted its key — clear any prior "never authenticated"
                    # diagnosis so a future regression re-triggers a fresh ERROR.
                    self._unauth_warned_spokes.discard(pk)
                    logger.info(f"Spoke {spoke_id} authenticated successfully with secret.")
                    self.record_spoke_event(spoke_id, "auth_ok", "secret verified")
                else:
                    logger.warning(f"Authentication failed for spoke {spoke_id}: Invalid secret.")
                    self.record_spoke_event(spoke_id, "auth_failed", "invalid secret — spoke will retry / fall back to zero-touch")
            else:
                logger.info(f"Spoke {spoke_id} connected without secret. Entering pending-negotiation state.")
                self.record_spoke_event(spoke_id, "pending_negotiation", "no secret — zero-touch")

            if not is_authenticated:
                # Register as known if not already
                if pk not in self.known_modules:
                    self.state.register_module(pk, approved=False)
                    self.known_modules = self.state.system_state["known_modules"]

                # Update telemetry
                self.spoke_telemetry[pk] = {
                    "last_attempt": time.time(),
                    "status": "PENDING_SECRET" if not secret else "AUTH_FAILED",
                    "error": None if not secret else "Invalid secret"
                }

                # If they provided a secret and it was wrong, we close.
                # If they provided no secret, we KEEP the connection open to negotiate one.
                if secret:
                    await websocket.close(1008, "Authentication failed")
                    return
            else:
                logger.info(f"Spoke {spoke_id} authenticated successfully.")
                # Evict any prior connection for this spoke_id (e.g. a zombie
                # left over from a prior outage / port-move crash-loop). A stale
                # (history-key) reconnect that would evict a live current-key
                # connection is rejected instead — see _install_active_connection.
                if not await self._install_active_connection(spoke_id, websocket, key_id):
                    return
                self.record_spoke_event(spoke_id, "connected", "authenticated with secret")
                # A history-key reconnect (missed a rotation push while offline)
                # is re-synced by _maybe_redeliver_session_key on the first
                # history-signed frame in the message loop (main.py ~3924) — no
                # connect-time push needed here.

            # --- Mutual Authentication (Hub Identity Proof) ---
            try:
                challenge = secrets.token_urlsafe(32)
                signature = self.key_manager.sign_hub_challenge(challenge.encode())

                proof = {
                    "status": "HUB_VERIFIED",
                    "challenge": challenge,
                    "signature": signature
                }
                # H4: advertise app-layer-encryption capability to the spoke. The
                # spoke verifies the signature over ``challenge`` ONLY (it never
                # re-serializes or re-signs this proof dict), so adding an
                # additive ``enc`` field is signature-safe. A new spoke reads it
                # and encrypts its outbound secret frames to the hub; a legacy
                # spoke ignores the unknown field (fail-safe → plaintext).
                if encryption_enabled():
                    proof["enc"] = ENC_MARKER
                await websocket.send(json.dumps(proof))

                # If the spoke has a secret, it will respond. If not, it might just ignore or respond HUB_OK.
                try:
                    hub_response_json = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                    hub_response = json.loads(hub_response_json)

                    if hub_response.get("status") != "HUB_OK":
                        logger.warning(f"Mutual auth failed: Spoke {spoke_id} rejected Hub identity.")
                        self.record_spoke_event(spoke_id, "mutual_auth_failed", "spoke rejected hub identity — likely stale HUB_SECRET after hub restart")
                        await websocket.close(1008, "Hub identity rejected")
                        return
                    logger.info(f"Mutual authentication complete for {spoke_id}.")
                    self.record_spoke_event(spoke_id, "mutual_auth_complete", "")
                except asyncio.TimeoutError:
                    if not secret:
                        logger.info(f"No response for Hub proof from {spoke_id} (expected for secret-less connection).")
                        self.record_spoke_event(spoke_id, "mutual_auth_skipped", "no secret — HUB_OK not required (zero-touch)")
                    else:
                        logger.error(f"Mutual authentication timed out for {spoke_id}")
                        self.record_spoke_event(spoke_id, "mutual_auth_timeout", "spoke did not respond to hub proof within 2s")
                        await websocket.close(1008, "Mutual authentication timed out")
                        return
            except Exception as e:
                logger.error(f"Mutual authentication error for {spoke_id}: {e}")
                await websocket.close(1008, "Mutual authentication failed")
                return

            # Ensure connection is tracked even if not fully auth'd (for negotiation).
            # See _install_pending_connection: a prior PENDING connection is
            # evicted (so a newer connection wins the slot), but a prior
            # AUTHENTICATED connection is NOT clobbered (stale-process guard).
            await self._install_pending_connection(spoke_id, websocket)

            # Update telemetry — capture remote IP so the UI can auto-fill service URLs
            remote_ip = None
            try:
                remote_ip = websocket.remote_address[0] if websocket.remote_address else None
            except Exception:
                pass
            self.spoke_telemetry[pk] = {
                "last_attempt": time.time(),
                "status": "CONNECTED",
                "error": None,
                "remote_ip": remote_ip,
            }

            # Track this module as known for approval lists
            if pk not in self.known_modules:
                self.state.register_module(pk, approved=False)
                self.known_modules = self.state.system_state["known_modules"]

            # Initialize the per-spoke rate limiter from config (applied on each
            # (re)connect, so a knob change propagates as spokes reconnect). The
            # default (burst=400 / 200 msg/s, from _rate_limit_params) is a FLOOD
            # guard sized well ABOVE a RELAY spoke's legit peak — it fans many
            # hosted agents and re-flushes its queue on reconnect — so normal
            # traffic is never dropped. Raise global_config["rate_limit"] as the
            # fleet/scale grows. Aggregate overload is the fleet layer's job, not
            # this bucket. See docs/backpressure-throttling.md §4.
            _rl_cap, _rl_rate = self._rate_limit_params()
            self.rate_limiters[pk] = TokenBucket(capacity=_rl_cap, fill_rate=_rl_rate)
            if module_type:
                self.spoke_module_types[pk] = module_type
                # Persist the type into module_metadata so the Spoke Management
                # list can show a cs/simulation spoke's type even while it is
                # offline (the in-memory spoke_module_types dict is popped on
                # disconnect). Free-form merge — no migration needed.
                #
                # DEFER the disk write: update_module_metadata already marks the
                # state dirty, and the (offloaded) 60s persistence flush writes
                # it. A synchronous save_state() HERE did a full-state
                # encrypt+write on the event loop on EVERY connect — under a
                # 600-spoke reconnect storm that repeatedly stalled the loop for
                # seconds (py-spy: save_state → _write_encrypted inside
                # handle_connection), delaying heartbeats enough to flip modules
                # offline. Durability to the next flush is fine: a reconnecting
                # spoke re-registers its type anyway. Only log/event on a genuinely
                # NEW type so a reconnect storm doesn't spam either.
                _prev_type = self.state.system_state.get("module_metadata", {}).get(
                    pk, {}).get("module_type")
                self.state.update_module_metadata(pk, {"module_type": module_type})
                if _prev_type != module_type:
                    logger.info(f"Spoke {spoke_id} registered as module type: {module_type}")
                    self.record_spoke_event(spoke_id, "registered", f"module_type={module_type}")

            # PSK self-provisioning: a spoke that presented the tenant's
            # predefined onboarding PSK (+ a tenant_id_hint) auto-approves and
            # auto-binds to that tenant without admin action (mirrors the legacy
            # cs/webui-local /api/spokes/register PSK flow). This runs AFTER the
            # register_module(approved=False) calls above so the approval wins,
            # and BEFORE the approval check so the approved branch handles
            # session-key/config push. A wrong/missing PSK is not fatal — the
            # spoke simply falls through to pending admin approval as today.
            if onboarding_psk and tenant_id_hint:
                if await self._try_psk_self_provision(spoke_id, tenant_id_hint, onboarding_psk):
                    self.known_modules = self.state.system_state["known_modules"]
                else:
                    logger.warning(
                        f"PSK self-provision failed for {spoke_id} "
                        f"(tenant_hint={tenant_id_hint}): invalid/missing PSK — pending admin approval.")
                    self.record_spoke_event(spoke_id, "psk_self_provision_failed",
                                            f"tenant_hint={tenant_id_hint}")

            # Multi-role generic agent — parent-auto-approve: a role sub-spoke
            # (spoke_id {base}-{role}) that claimed a parent agent in its auth
            # frame is auto-approved + tenant-bound when the parent is already
            # approved + connected + module_type "agent", reusing the same
            # approve_and_bind_spoke state machine as admin/PSK approval. This
            # runs alongside the PSK block (both are claim-based auto-approve)
            # and before the approval check so the approved branch pushes the
            # session key + config. Non-fatal: parent not approved/connected or
            # the id isn't prefix-tied to the claimed parent → fall through to
            # pending admin approval as today. Record the parent claim either way
            # so a later base-agent approval can sweep up waiting sub-spokes
            # (_auto_approve_pending_subspokes covers the sub-before-parent order).
            if netbox_server_cap:
                self.netbox_server_agents.add(pk)
            else:
                self.netbox_server_agents.discard(pk)
            if ldap_server_cap:
                self.ldap_server_agents.add(pk)
            else:
                self.ldap_server_agents.discard(pk)
            # H4: record encryption capability unconditionally (covers the
            # zero-touch / secret-less connect path too). A non-capable or
            # kill-switched spoke records False → outbound frames stay plaintext.
            self.spoke_enc_capable[pk] = spoke_enc_capable
            if parent_spoke_id:
                self.spoke_parent_map[pk] = parent_spoke_id
                # B4: persist the parent linkage + role name into the sub-spoke's
                # metadata so the WebUI can match a role sub-spoke to its parent
                # agent AFTER B1 re-keyed known_modules raw→guid (the pre-B1
                # ``{base}-{role}`` string-prefix match broke once both the base
                # and the sub-spoke became independent guid keys). Stamped raw
                # (the parent name the sub-spoke claimed) + resolved to the
                # parent's current primary key at emit time (``_primary_key``),
                # which matches whatever the parent's own pending_spokes row emits
                # as ``spoke_id`` (guid once armed, raw until then). Persisted →
                # the linkage survives the sub-spoke going offline (the in-memory
                # ``spoke_parent_map`` does not).
                if spoke_id.startswith(parent_spoke_id + "-"):
                    self.state.update_module_metadata(pk, {
                        "parent_name": parent_spoke_id,
                        "role_name": spoke_id[len(parent_spoke_id) + 1:],
                    })
                if not self.approved_modules.get(pk, False):
                    # Parent attestation (H3): ask the claimed parent to sign a
                    # vouch that this sub-spoke is one it spawned, instead of
                    # trusting the child's unsigned parent_spoke_id claim. On a
                    # verified vouch → auto-approve + tenant-bind (zero-touch
                    # preserved). On any failure (parent not connected /
                    # unauthenticated / timeout / denied / echo mismatch / not
                    # an agent / prefix mismatch) → fall through to pending admin
                    # approval below; do NOT close the connection. Record the
                    # parent claim either way so a later base-agent approval can
                    # sweep up waiting sub-spokes (the sweep covers the
                    # sub-before-parent connect order).
                    vouched, reason = await self._parent_vouches(spoke_id, parent_spoke_id)
                    if vouched:
                        tenant = self.state.get_spoke_tenant(self._primary_key(parent_spoke_id)) or ""
                        logger.info(f"Parent auto-approve: {spoke_id} via parent "
                                    f"{parent_spoke_id} (tenant={tenant or 'unassigned'}).")
                        await self.approve_and_bind_spoke(spoke_id, tenant)
                        self.known_modules = self.state.system_state["known_modules"]
                        self.record_spoke_event(spoke_id, "parent_auto_approve",
                                                f"parent={parent_spoke_id}")
                    else:
                        self.record_spoke_event(spoke_id, "parent_vouch_failed",
                                                f"parent={parent_spoke_id} reason={reason}")

            # Check if the module is already approved
            if not self.approved_modules.get(pk, False):
                logger.info(f"Module {spoke_id} is pending approval.")
                self.record_spoke_event(spoke_id, "pending_approval", "awaiting admin approval")
                # Send Approval Required message
                approval_msg = {
                    "header": {"message_id": str(uuid.uuid4()), "timestamp": time.time(),
                               "sender_id": "hub", "destination_id": spoke_id},
                    "payload": {"type": "APPROVAL_REQUIRED", "data": {}}
                }
                # Only sign if we have a key
                try:
                    approval_msg["signature"] = self.key_manager.sign_message(pk, {
                        "header": approval_msg["header"],
                        "payload": approval_msg["payload"]
                    })
                except Exception:
                    approval_msg["signature"] = None

                await websocket.send(json.dumps(approval_msg))
                # We don't return; we enter the loop but the loop will filter messages
            else:
                # MODULE IS APPROVED
                # If the spoke connected without a secret (zero-touch, already approved),
                # generate and push its session key before sending config.
                if not secret:
                    # Zero-touch reconnect (spoke connected with no secret).
                    # Provision PLAINTEXT: signing_secret=None → no AEAD wrap →
                    # accepted in the spoke's bootstrap decode (which ignores
                    # signatures when self.secret is unset). Never sign with a
                    # retained prev_secret here — the hub persists keys[pk] so
                    # current_session_secret(pk) can be a secret a prior-session
                    # sub-spoke armed but never persisted (RoleConnection no-op),
                    # and encrypting the push with it traps the sub-spoke in
                    # _decode_frame's defer-buffer forever (the never-adopted
                    # outage). Fire-and-forget (NOT request_response): the ack
                    # is unreachable in the connect path (the message loop
                    # hasn't started) → a 5s timeout every connect that stalls
                    # push_config and flaps the WS. The spoke-side deferral
                    # closes the back-to-back encrypted UPDATE_CONFIG race.
                    session_secret = self.key_manager.generate_first_secret(pk)
                    key_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()), timestamp=time.time(),
                            sender_id="hub", destination_id=spoke_id),
                        payload=MessagePayload(
                            type="SPOKE_UPDATE_SESSION_KEY",
                            data={"secret": session_secret}))
                    await self.send_to_spoke(key_msg, signing_secret=None)
                await self.push_config_to_spoke(spoke_id)

                # Request version AFTER the session key is established so the spoke
                # can sign its response and the hub can verify it.
                try:
                    version_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()),
                            timestamp=time.time(),
                            sender_id="hub",
                            destination_id=spoke_id
                        ),
                        payload=MessagePayload(type="get_version", data={})
                    )
                    await self.send_to_spoke(version_msg)
                except Exception as e:
                    logger.error(f"Failed to request version from {spoke_id}: {e}")

            # 2. Flush Mailbox — keyed by pk (guid once armed): _arm_guid_primary
            # in _reconcile_spoke_identity re-keyed the offline queue name→guid, so
            # flush must read the guid-keyed queue or a reconnecting spoke's
            # pending messages would be stranded under the stale name.
            await self.mailbox.flush_mailbox(pk, self.send_to_spoke)

            # 3. Message Loop
            async for message_json in websocket:
                # TRUE offered-rate tally (before ANY shed) so the protect
                # source-shed can find the loudest talkers to disconnect. One
                # dict op per frame — cheap. Counts frames we then drop, unlike
                # spoke_msg_count (which is post-shed).
                if spoke_id:
                    self._spoke_recv[pk] = self._spoke_recv.get(pk, 0) + 1
                # PROTECT MODE — early shed by SIZE, BEFORE the expensive JSON
                # parse. At a CPU-pegged loop the parse of large telemetry frames
                # IS the bottleneck, so dropping them here (not after parsing) is
                # what actually frees the loop. Small frames (heartbeats/acks,
                # < shed_bytes) still parse + flow, so liveness/acks are kept.
                # BUT dropping-after-read still costs the READ; a sustained flood
                # is only relieved by DISCONNECTING the source — see the protect
                # source-shed in run_mps_loop / _protect_source_shed.
                if self._protect_mode:
                    # SURGICAL shed: drop a large frame ONLY if this spoke is a
                    # high-offered-rate OFFENDER. Legit low-rate spokes' telemetry
                    # flows even during protect — the point is to shed the FLOOD,
                    # not everyone (that's why real modules were dropping traffic).
                    # _spoke_offered is the TRUE pre-shed per-tick count, so it
                    # isn't corrupted by the shedding itself.
                    try:
                        if (len(message_json) > self._protect_shed_bytes
                                and self._spoke_offered.get(pk, 0) >= self._protect_shed_min_mps):
                            self.rate_limit_drops[pk] = self.rate_limit_drops.get(pk, 0) + 1
                            continue
                    except Exception:
                        pass
                # Wire form is <sig>.<body>: split, verify the RECEIVED body bytes
                # DIRECTLY (no re-serialization — the per-frame json.dumps that
                # dominated ingest CPU is gone), and parse the body ONCE. sig == ""
                # means unsigned (a bootstrap heartbeat before the spoke has a key).
                sig, body_str = split_frame(message_json)
                try:
                    msg_data = json.loads(body_str)
                except Exception:
                    logger.debug("Unparseable frame from %s — dropping", spoke_id)
                    continue

                signature = sig or None
                # H4: the AEAD-decrypt secret for an inbound secret-bearing
                # frame. Resolved (and the payload decrypted) only on signed
                # frames after HMAC verify + freshness pass; None for unsigned
                # heartbeats (never encrypted). Threaded into _handle_agent_relay_up
                # for the nested CS_TOKEN_RESULT decrypt (refinement #2).
                _dec_secret = None
                if signature:
                    src = self.key_manager.verify_signature_source(pk, body_str.encode(), sig)
                    if src is None:
                        logger.warning(f"Invalid signature from spoke {spoke_id}")
                        continue
                    # A verified signature proves the spoke installed its session
                    # key. Mark it authenticated (idempotent — also set at connect
                    # when a secret was presented). A spoke that never reaches here
                    # (legacy/incompatible agent that can't adopt a key) stays
                    # unauthenticated, so command routes can fail fast.
                    self.spoke_authenticated[pk] = True
                    # The spoke is signing with a PREVIOUS (rotated-out) key — it
                    # authenticated via the history window but never adopted the
                    # current key (missed the SPOKE_UPDATE_SESSION_KEY push). That
                    # is exactly the skew that produces "Bytes signature mismatch"
                    # on hub→spoke replies + GET_AGENTS/telemetry timeouts: the
                    # spoke→hub direction verifies (history), hub→spoke does not
                    # (spoke lacks the current key). Re-deliver the current key
                    # signed with the previous secret so the spoke can adopt it
                    # without a full re-onboard. Rate-limited per spoke.
                    if src == "history":
                        await self._maybe_redeliver_session_key(pk)
                    # First signed frame clears any prior "never authenticated"
                    # diagnosis (idempotent with the connect-time discard).
                    self._unauth_warned_spokes.discard(pk)
                    # Replay/freshness gate (item 8B): drop a captured/delayed
                    # signed frame that replays verbatim (same bytes → same HMAC)
                    # or whose timestamp is outside the freshness window. Runs
                    # only on signed frames, after verification, so unsigned
                    # heartbeats cost nothing and it's not an unauth flood vector.
                    if not self._check_freshness_and_replay(pk, msg_data):
                        continue
                    # H4: AEAD-decrypt payload.data of secret-bearing inbound
                    # frames (after HMAC verify + freshness pass) BEFORE dispatch
                    # reads data. _decrypt_inbound_payload resolves the AEAD key
                    # from src (history → previous_session_secret, else current),
                    # is a no-op on plaintext/legacy frames, and returns _H4_DROP
                    # on tamper / wrong key / marked-encrypted-with-no-decrypt-key
                    # (the frame is dropped — ciphertext is never dispatched).
                    _dec_secret = await self._decrypt_inbound_payload(pk, src, msg_data)
                    if _dec_secret is _H4_DROP:
                        continue
                else:
                    # No signature provided. Allow ONLY heartbeats for unauthenticated spokes.
                    payload = msg_data.get("payload", {})
                    if payload.get("type") != "HEARTBEAT":
                        # A non-heartbeat frame from a spoke that never adopted
                        # its session key. If this persists past the grace
                        # window it's the signature of a legacy/incompatible or
                        # crashed-on-startup agent — emit ONE actionable ERROR
                        # via the GenericAgent logger (throttled per-connection)
                        # instead of flooding WARNING per frame.
                        self._maybe_log_unauthenticated_agent(pk)
                        logger.debug(
                            f"Unauthenticated non-heartbeat from {spoke_id} "
                            f"(only HEARTBEAT allowed). Dropping.")
                        continue

                # Process Heartbeat (Always allowed for pending spokes to maintain connection)
                payload = msg_data.get("payload", {})
                self.bytes_count += len(message_json) # Track received bytes
                # Per-spoke inbound rate (relayed agent frames count toward the
                # hosting spoke) — reset + averaged each 1s tick in run_mps_loop.
                if spoke_id:
                    self.spoke_msg_count[pk] = self.spoke_msg_count.get(pk, 0) + 1
                # Inbound trace: one line per frame so the full dispatch flow is
                # greppable when DEBUG is on. Heartbeats are the bulk of traffic,
                # so this stays at DEBUG (not INFO) to avoid flooding the log.
                logger.debug("inbound type=%s from spoke=%s", payload.get("type"), spoke_id)
                if payload.get("type") == "HEARTBEAT":
                    self.message_count += 1
                    self.heartbeat.update_heartbeat(pk)
                    # Persist last-contacted so a hub reboot doesn't reset this
                    # spoke to "Never connected / RED". _mark_dirty (no disk
                    # write here) — the 60s persistence_loop flushes. Cheap
                    # enough to run every heartbeat tick.
                    self.state.set_spoke_last_seen(pk, self.heartbeat.last_seen[pk])
                    # A heartbeat means the spoke is in contact — clear any
                    # never-seen absent clock so the alert loop doesn't keep a
                    # stale _spoke_absent_since entry around after first contact.
                    self._spoke_absent_since.pop(pk, None)
                    continue

                # If the module is not approved, ignore all other messages
                if not self.approved_modules.get(pk, False):
                    logger.debug(f"Dropping message from unapproved module {spoke_id}")
                    continue

                # Process Acknowledgement
                if "correlation_id" in msg_data:
                    corr_id = msg_data["correlation_id"]
                    # App-layer liveness probe reply (HUB_PING → COMMAND_RESULT
                    # whose correlation_id is the ping's message_id). Resolve the
                    # sending adapter's ping waiter BEFORE the mailbox/unknown-ack
                    # routing so a probe reply isn't mislogged as a stray ack.
                    # The spoke that REPLIED is the one whose socket holds the
                    # waiter (it echoed the nonce we sent it on that socket).
                    if corr_id in self._pending_liveness_nonces:
                        self._pending_liveness_nonces.discard(corr_id)
                        adapter = self.active_connections.get(pk)
                        if adapter is not None and hasattr(adapter, "resolve_pong"):
                            adapter.resolve_pong(corr_id)
                        self.message_count += 1
                        continue
                    # A reply's correlation_id is the hub's original message_id.
                    # Two send paths share the id space: ``mailbox.push`` (tracked
                    # in ``mailbox.pending_ack``) and ``request_response`` (tracked
                    # in ``_outstanding_requests``, or ``_recent_request_timeouts``
                    # if the waiter already timed out / was cancelled). Route
                    # accordingly so a late request/response reply is logged as
                    # "late" (DEBUG) instead of mislabeled "unknown message ID"
                    # (WARNING) — request_response ids are never in pending_ack,
                    # so mailbox.acknowledge can't tell a late reply from a stray.
                    in_flight = corr_id in self._outstanding_requests
                    late_reply = (not in_flight) and (corr_id in self._recent_request_timeouts)
                    if in_flight or late_reply:
                        if late_reply:
                            self._recent_request_timeouts.pop(corr_id, None)
                            logger.debug(
                                "Late reply for %s from %s (request_response already "
                                "timed out) — dropped (message_type=%s, source_ip=%s)",
                                corr_id, spoke_id, payload.get("type"), remote_ip)
                    elif corr_id in self._pending_broadcast_ids:
                        # Fire-and-forget broadcast command ack (SET_LOG_LEVEL,
                        # CLEAR_LOGS, …): sent via low-level send_to_spoke, not
                        # mailbox.push, so it's not in pending_ack. Expected —
                        # log DEBUG + drop instead of WARNING "unknown message ID"
                        # (which fired on every Clear-Logs click / debug toggle).
                        self._pending_broadcast_ids.pop(corr_id, None)
                        logger.debug(
                            "Broadcast command ack for %s from %s — dropped "
                            "(message_type=%s, source_ip=%s)",
                            corr_id, spoke_id, payload.get("type"), remote_ip)
                    else:
                        # mailbox.push reply, or a genuinely unknown ack. Status:
                        # spoke reply frames carry the real outcome in
                        # payload.data.status (not a top-level "status" key, which
                        # the control plane never sets) — read it from there so the
                        # "unknown ack" warning reflects reality instead of always
                        # printing the stale "FAILED" default.
                        _pdata = payload.get("data") if isinstance(payload, dict) else None
                        _rstatus = str(_pdata.get("status") or "").strip().upper() \
                            if isinstance(_pdata, dict) else ""
                        ack = Acknowledgement(
                            correlation_id=corr_id,
                            status="SUCCESS" if _rstatus == "SUCCESS" else "FAILED",
                            error=msg_data.get("error"),
                            # Thread the sender's identity + frame type + peer IP
                            # into the ack so the mailbox "unknown ack" warning can
                            # name the source of a stray/late ack (the envelope's
                            # own spoke_id is often None for these).
                            spoke_id=spoke_id,
                            message_type=payload.get("type"),
                            source_ip=remote_ip,
                        )
                        await self.mailbox.acknowledge(ack)

                    # Debug: Log this response is actually expected
                    if corr_id not in self.response_cache:
                        logger.debug(f"Received response for correlation_id: {corr_id}")

                    # Special case: if this was a version request, store the version
                    # (payload was already extracted at the top of the dispatch and
                    # msg_data is not mutated between there and here.)
                    if payload.get("type") == "COMMAND_RESULT":
                        data = payload.get("data", {})
                        if isinstance(data, dict) and "version" in data:
                            self.spoke_versions[pk] = data["version"]

                    # Store in response cache for API request bridging — but
                    # only if a waiter is still outstanding for this msg_id, so
                    # a late ack (after request_response already timed out and
                    # discarded the waiter) is dropped instead of leaked.
                    if hasattr(self, "response_cache") and corr_id in self._outstanding_requests:
                        self.response_cache[corr_id] = msg_data

                    self.message_count += 1
                    continue

                # MUST-PROCESS probe (load-test verification hook). Classified
                # 'must' but carries NO correlation_id, so handle it HERE — above
                # the rate limiter + protect shed — to PROVE must-process frames
                # survive every rung of the ladder while telemetry is coalesced.
                # Cheap: a per-spoke seq/gap counter, no ingest. A gap here would
                # be a real must-process LOSS (a bug); telemetry gaps are expected.
                if payload.get("type") == "LOADTEST_PROBE":
                    self.message_count += 1
                    st = self._probe_state.setdefault(
                        pk, {"count": 0, "last_seq": -1, "gaps": 0})
                    try:
                        seq = int((payload.get("data") or {}).get("seq", -1))
                    except (TypeError, ValueError):
                        seq = -1
                    if st["last_seq"] >= 0 and seq > st["last_seq"] + 1:
                        st["gaps"] += seq - st["last_seq"] - 1
                    st["count"] += 1
                    if seq > st["last_seq"]:
                        st["last_seq"] = seq
                    continue

                # Rate Limiting for non-heartbeat messages.
                # ACKs / replies (correlation_id present) are handled + `continue`
                # ABOVE this block, so they are NEVER rate-limited/dropped. Belt-
                # and-suspenders: even if reordered later, skip the limiter for a
                # correlation-bearing frame so a reply can never be dropped.
                if "correlation_id" not in msg_data:
                    # PROTECT MODE: SHED inbound telemetry/logs — but SURGICALLY,
                    # only from high-offered-rate OFFENDERS. A legit low-rate
                    # spoke's telemetry is processed even during protect, so real
                    # modules keep flowing while the flood is shed. Heartbeats
                    # (handled above) always flow. Survive > fresh, but spare the
                    # innocent.
                    if (self._protect_mode
                            and self._spoke_offered.get(pk, 0) >= self._protect_shed_min_mps):
                        self.rate_limit_drops[pk] = self.rate_limit_drops.get(pk, 0) + 1
                        continue
                    limiter = self.rate_limiters.get(pk)
                    if limiter:
                        ok = limiter.consume()
                        # SOFT WATERMARK (default 80% of burst consumed): flag the
                        # spoke so the ladder (next 1s tick) TELLS it to slow +
                        # coalesce locally — proactively, BEFORE the hard drop.
                        # Cheap set add (deduped); the ladder does the signalling
                        # with its dedup/dwell/cap. A correct client backs off here
                        # and never reaches the hard limit below.
                        if limiter.capacity and limiter.tokens <= (1.0 - self._rl_soft_frac) * limiter.capacity:
                            self._rl_breached.add(pk)
                        if not ok:
                            # HARD LIMIT (100%) → DROP the frame (enforcement). A
                            # client still hard-dropping here IGNORED the 80%
                            # slow-down — track the hard drops so the ladder can
                            # escalate a persistent flooder to disconnect+quarantine
                            # (DDoS defense: stop parsing its frames entirely).
                            self.rate_limit_drops[pk] = self.rate_limit_drops.get(pk, 0) + 1
                            self._rl_harddrops[pk] = self._rl_harddrops.get(pk, 0) + 1
                            logger.debug(
                                "Rate limit HARD-DROP for spoke %s (type=%s, total drops=%d).",
                                spoke_id, payload.get('type'), self.rate_limit_drops[pk])
                            continue

                # Handle other messages
                self.message_count += 1

                # --- Client-Sim telemetry (combined spoke relays its full state) ---
                # Ingest + fan-out + USB diagnostic live in _handle_cs_telemetry.
                # CS_TELEMETRY is the "coalesce" class — this branch IS the live
                # enforcement of _classify_message's policy; keep them in lockstep.
                if payload.get("type") == "CS_TELEMETRY":
                    self._telemetry_received += 1
                    # Rung-3: if this spoke is under backpressure, COALESCE its
                    # telemetry (latest-wins) into the drain buffer instead of
                    # running the full ingest inline. A prior un-drained snapshot
                    # for this spoke is merged away (counted). Keeps the main loop
                    # free for must-process frames while the spoke catches up to
                    # the slow-down signal. Not under pressure → ingest inline.
                    if pk in self._spoke_backoff:
                        if pk in self._coalesce_pending:
                            self._telemetry_coalesced += 1
                        self._coalesce_pending[pk] = (payload.get("data", {}), time.time())
                        continue
                    await self._handle_cs_telemetry(spoke_id, payload.get("data", {}))
                    self._telemetry_processed += 1
                    continue

                # --- Client-Sim per-op progress (realtime operations feed) ---
                # The agent emits CS_PROGRESS per phase (destroying/cloning/starting/
                # …) for reclone/provision/delete — far faster than the ~30s
                # CS_TELEMETRY frame. Fan these out to the tenant's /sim/ws browsers
                # for a live feed. Fire-and-forget passthrough (no ingest/state).
                if payload.get("type") == "CS_PROGRESS":
                    _pdata = payload.get("data", {}) or {}
                    try:
                        _ptenant = self.state.get_spoke_tenant(pk)
                    except Exception:  # noqa: BLE001
                        _ptenant = None
                    # Drive the VM Server table's per-VM live state from the op
                    # feed (instant, one vmid per event). Non-terminal progress
                    # sets the in-progress state; terminals are owned by the
                    # CS_COMMAND_RESULT handler above.
                    try:
                        _pstate = self._VM_ACTION_STATE.get(_pdata.get("action"))
                        _pstat = str(_pdata.get("status") or "").lower()
                        if _ptenant and _pstate and _pstat not in ("completed", "failed", "error"):
                            self._vm_live_set(_ptenant, _pdata.get("vmid"), _pstate)
                    except Exception:  # noqa: BLE001 — overlay is best-effort
                        pass
                    try:
                        await self.simulations_broadcaster.broadcast(
                            spoke_id, {"type": "cs_progress", "data": _pdata}, _ptenant)
                    except Exception:  # noqa: BLE001 — feed is best-effort
                        pass
                    continue

                # --- Spoke log forwarding (SPOKE_LOG) ---
                # See _handle_spoke_log for the ingest + agent_logs buffering.
                if payload.get("type") == "SPOKE_LOG":
                    await self._handle_spoke_log(spoke_id, payload)
                    continue

                # --- Remote client debug-log streaming (CS_DEBUG_LOG) ---
                # A cs client flipped into "debug mode" from the WebUI has its
                # agent.sh tailer stream sim.log + debug-* logs (advanced adds
                # journal/dmesg) up through the cs spoke, which relays them here.
                # Ingest into a per-(tenant,hostname) ring buffer (same ephemeral
                # deque contract as SPOKE_LOG/agent_logs) and serve via
                # GET /api/cs/clients/{host}/debug-logs (routes/client_debug.py).
                if payload.get("type") == "CS_DEBUG_LOG":
                    await self._handle_cs_debug_log(spoke_id, payload)
                    continue

                # --- Console serial relay (CONSOLE_DATA_UP / READY / ERROR / CLOSED) ---
                # The console role sub-spoke pushes live serial output + control
                # signals straight up its own connection (send_to_hub). Route each
                # to the browser session's queue; the /ws/console-serial relay reads
                # bytes off it. Control signals are tuples so the WS loop can tell
                # them from data bytes (mirrors the VNC ready/error/disconnect
                # discipline — a bare-return there once killed the queue consumer).
                _ctype = payload.get("type")
                if _ctype in ("CONSOLE_DATA_UP", "CONSOLE_READY", "CONSOLE_ERROR", "CONSOLE_CLOSED"):
                    _cdata = payload.get("data", {}) or {}
                    _csess = self.get_console_session(_cdata.get("session_id")) if _cdata.get("session_id") else None
                    if _csess:
                        if _ctype == "CONSOLE_DATA_UP":
                            try:
                                await _csess["queue"].put(base64.b64decode(_cdata.get("data") or ""))
                            except Exception:
                                pass
                        elif _ctype == "CONSOLE_READY":
                            await _csess["queue"].put(("ready",))
                        elif _ctype == "CONSOLE_ERROR":
                            await _csess["queue"].put(("error", str(_cdata.get("error", "console error"))[:300]))
                        elif _ctype == "CONSOLE_CLOSED":
                            await _csess["queue"].put(("disconnect",))
                    continue

                # --- Console auto-identify result → NetBox (event-driven) ---
                # A console spoke fingerprinted a device; match/create a NetBox
                # device from the harvested identity. Fire-and-forget so the
                # dispatch loop doesn't block on a NetBox round-trip.
                if payload.get("type") == "CONSOLE_PROBE_RESULT":
                    asyncio.create_task(self._handle_console_probe(pk, payload.get("data", {}) or {}))
                    continue

                # --- NW autonomous per-device poll result (spoke-driven) ---
                # An nw spoke polled a device on its configured poll_interval and
                # pushed the fused result. Fold it into the per-device nw cache so
                # every sub-view (info/arp/macs/interfaces/endpoints/vlans) serves
                # instantly without a live SSH round-trip. The payload's ``data``
                # is the flattened poll (device_info/arp/mac_table/interfaces/
                # endpoints/vlans at top level) — exactly what nw_cache_set_poll
                # reads. Fire-and-forget (must not block the dispatch loop).
                if payload.get("type") == "NW_POLL_RESULT":
                    _nwd = payload.get("data", {}) or {}
                    _nw_did = _nwd.get("device_id")
                    _nw_pdata = _nwd.get("data") if isinstance(_nwd.get("data"), dict) else _nwd
                    if _nw_did and isinstance(_nw_pdata, dict):
                        # Warm cache + per-device NetBox inventory sync.
                        asyncio.create_task(self.apply_nw_auto_poll(_nw_did, _nw_pdata))
                    continue

                # --- TrueNAS autonomous per-appliance poll result (spoke-driven)
                # A truenas spoke polled an appliance on its configured
                # poll_interval and pushed the fused result. Fold it into the
                # per-appliance truenas cache so every Storage sub-view
                # (info/pools/datasets/disks/shares/alerts/services/capacity)
                # serves instantly without a live WS JSON-RPC round-trip. The
                # payload's ``data`` is the flattened poll. Fire-and-forget.
                if payload.get("type") == "TRUENAS_POLL_RESULT":
                    _td = payload.get("data", {}) or {}
                    _tn_aid = _td.get("appliance_id")
                    _tn_pdata = _td.get("data") if isinstance(_td.get("data"), dict) else _td
                    if _tn_aid and isinstance(_tn_pdata, dict):
                        asyncio.create_task(self.truenas_cache_set_poll(_tn_aid, _tn_pdata))
                    continue

                # --- LE cert renewed (event-driven distribution) ---
                # A le spoke renewed a cert and emitted LE_CERT_RENEWED so we
                # re-push the material to its targets now instead of waiting up
                # to 1h for run_cert_distribution_loop. Fire-and-forget (the
                # inbound dispatch loop must not block on a LE_GET_CERT +
                # INSTALL_CERT round-trip); the hourly loop is the fallback.
                if payload.get("type") == "LE_CERT_RENEWED":
                    ev = payload.get("data", {}) or {}
                    _ev_domain = ev.get("domain")
                    _ev_targets = ev.get("targets") or []
                    if _ev_domain and _ev_targets:
                        asyncio.create_task(self._on_le_cert_renewed(
                            spoke_id, _ev_domain, _ev_targets))
                    else:
                        logger.debug("LE_CERT_RENEWED from %s missing "
                                     "domain/targets; hourly loop will cover it",
                                     spoke_id)
                    # A successful renew clears any prior cert-renew-failed alert
                    # edge (recovery email) — tenant from the spoke's binding,
                    # never the payload.
                    if _ev_domain:
                        _rn_tenant = self.state.get_spoke_tenant(spoke_id) or "default"
                        asyncio.create_task(self.alert_engine.evaluate(
                            _rn_tenant, "cert_renew_failed", _ev_domain, False,
                            "", severity="ok"))
                    continue

                # --- LE cert renewal FAILED (event-driven alert) ---
                # A le spoke's background (or on-demand) renewal failed and
                # emitted LE_CERT_RENEW_FAILED so we fire a realtime
                # cert-renewal-failed alert now (vs. the 60s pull loop scanning
                # le_cache). The ledger's last_error is the persisted record;
                # this event is the prompt transport. Tenant from the spoke's
                # binding (security: never trust the payload tenant).
                if payload.get("type") == "LE_CERT_RENEW_FAILED":
                    ev = payload.get("data", {}) or {}
                    _fr_domain = ev.get("domain")
                    if _fr_domain:
                        _fr_tenant = self.state.get_spoke_tenant(spoke_id) or "default"
                        asyncio.create_task(self.alert_engine.evaluate(
                            _fr_tenant, "cert_renew_failed", _fr_domain, True,
                            ev.get("message") or "renew failed", severity="error"))
                    else:
                        logger.debug("LE_CERT_RENEW_FAILED from %s missing domain",
                                     spoke_id)
                    continue

                # --- Status-page public demo trigger (event-driven relay) ---
                # A `statuspage` role sub-spoke relayed a PUBLIC demo click up
                # (send_to_hub). SECURITY: the sub-spoke holds NO tenant authority
                # — we resolve the tenant from ITS binding (get_spoke_tenant), NEVER
                # the payload, and validate the client belongs to that tenant before
                # driving the cs demo machinery (ephemeral, auto-reverts in 120 min).
                # Fire-and-forget so the dispatch loop never blocks on the cs round-trip.
                if payload.get("type") == "STATUS_RUN_DEMO":
                    asyncio.create_task(self._handle_status_run_demo(
                        spoke_id, payload.get("data", {}) or {}))
                    continue

                # --- Scale-Out Relay Logic ---
                # _handle_agent_relay_up returns True when it matched + handled a
                # sub-type (AGENT_LOG/HEARTBEAT/AGENT_TELEMETRY/CS_*), in which case
                # we `continue`. It returns False when the sub-type was unmatched —
                # CRITICAL: unmatched AGENT_RELAY_UP frames must NOT continue; they
                # fall through to the HUB_REQUEST check below and the catch-all INFO
                # log, matching the pre-extraction behavior. Do not add a `continue`
                # on the False path.
                if payload.get("type") == "AGENT_RELAY_UP":
                    if await self._handle_agent_relay_up(spoke_id, msg_data, payload,
                                                        _dec_secret=_dec_secret):
                        continue
                # --- End Relay Logic ---

                # Agent-initiated request (e.g. BugFixer asking for logs or to
                # trigger updates). See _handle_hub_request for the dispatch +
                # signed HUB_RESPONSE reply.
                if payload.get("type") == "HUB_REQUEST":
                    await self._handle_hub_request(
                        spoke_id, msg_data, payload,
                        getattr(websocket, "peer_cert_identity", None))
                    continue

                # Fallback for verified-but-unhandled message types: every known
                # type (HEARTBEAT, ack, CS_TELEMETRY, SPOKE_LOG, AGENT_RELAY_UP,
                # HUB_REQUEST) has already `continue`d by here, so this line is
                # reached ONLY for types the hub doesn't recognize. Logged at INFO
                # (not DEBUG) so a new/unknown spoke frame is visible by default.
                logger.info(f"Received verified message from {spoke_id}: {payload.get('type')}")

        except (websockets.ConnectionClosed, WebSocketDisconnect):
            logger.info(f"Connection closed for spoke {spoke_id}")
            # Only this connection's own belated exception may update telemetry —
            # an evicted/zombie connection (see _install_active_connection) can
            # still be blocked in recv() when it's replaced, and its eventual
            # ConnectionClosed/accept-first exception must not clobber the live
            # replacement connection's just-written CONNECTED telemetry. Same
            # guard as the `finally` cleanup below.
            if spoke_id and self.active_connections.get(self._primary_key(spoke_id)) is websocket:
                self._mark_spoke_disconnected(spoke_id)
                self.record_spoke_event(spoke_id, "connection_closed", "clean websocket close")
        except Exception as e:
            logger.error(f"Error handling connection for {spoke_id}: {e}")
            if spoke_id and self.active_connections.get(self._primary_key(spoke_id)) is websocket:
                pk = self._primary_key(spoke_id)
                self.spoke_telemetry[pk] = {
                    "last_attempt": time.time(),
                    "status": "ERROR",
                    "error": str(e)
                }
                self.record_spoke_event(spoke_id, "connection_error", str(e))
        finally:
            # Only clean up shared registry state if THIS websocket still owns the
            # spoke's slot. An evicted/zombie connection (replaced by a live
            # reconnect via _install_active_connection) whose recv() later unblocks
            # must NOT wipe the live replacement's module_type / auth / parent map /
            # hosted-agent index — that is the cs-spoke-1 zombie class, and the
            # `is websocket` guard below (previously only on active_connections)
            # now covers the sibling state too. Capture ownership BEFORE deleting
            # the entry (the delete would otherwise make the later check False).
            owns_slot = bool(spoke_id and self.active_connections.get(self._primary_key(spoke_id)) is websocket)
            if owns_slot:
                pk = self._primary_key(spoke_id)
                del self.active_connections[pk]
                self.active_connection_key_ids.pop(pk, None)
                self.spoke_module_types.pop(pk, None)
                self.spoke_parent_map.pop(pk, None)
                self.netbox_server_agents.discard(pk)
                self.ldap_server_agents.discard(pk)
                self.spoke_authenticated.pop(pk, None)
                self.spoke_enc_capable.pop(pk, None)
                # Drop the per-connection "never authenticated" diagnosis state
                # so a reconnect that's still broken re-emits the ERROR once
                # past the grace window (instead of staying suppressed).
                self._unauth_warned_spokes.discard(pk)
                # Evict every agent hosted by this spoke from the agent→spoke
                # index. They'll re-index on reconnect (next AGENT_RELAY_UP).
                # Iterate over a snapshot — mutating the dict during iteration
                # would otherwise raise RuntimeError.
                for aid in list(self.agent_info):
                    if self._primary_key(self.agent_info.get(aid, {}).get("spoke_id")) == pk:
                        self.agent_info.pop(aid, None)

    # ── Update pipeline (extracted) ───────────────────────────────────────
    # get_local_version / get_remote_version / _is_git_repo / _download_update /
    # _git_update / perform_update / update_spokes_only / update_agents_only now
    # live in core/src/update_pipeline.py as UpdatePipelineMixin (inherited via
    # the class bases below). They operate on `self` unchanged, so hub.perform_update
    # / self.get_local_version() etc. resolve exactly as before via inheritance.

    def collect_all_logs(self):
        """Aggregate every log source the Hub can see.

        Extracted from GET /setup/logs/all so the HTTP endpoint and the
        HUB_REQUEST GET_LOGS handler (used by the BugFixer agent) share one
        implementation. Returns {"logs": [{"module": str, "log": str}, ...]}.
        """
        all_logs = []
        for log in self.logs:
            all_logs.append({"module": "hub", "log": log})

        for agent_id, logs in self.agent_logs.items():
            for log in logs:
                all_logs.append({"module": agent_id, "log": log})

        try:
            log_dir = "/var/log/lm"
            if os.path.exists(log_dir):
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        module_name = filename.replace(".log", "")
                        with open(os.path.join(log_dir, filename), "r") as f:
                            # Stream only the tail (deque maxlen) instead of
                            # readlines() materialising the whole file — bounds
                            # memory as spoke count and log size grow.
                            for line in deque(f, maxlen=500):
                                all_logs.append({"module": module_name, "log": line.strip()})
        except Exception as e:
            logger.error(f"Error reading module logs from disk: {e}")

        # Defense-in-depth against the 16 MiB WS frame ceiling: if the
        # serialized payload would exceed GET_LOGS_MAX_BYTES (default 12 MiB —
        # safely under the 16 MiB max_size set on websockets.serve), trim to the
        # newest entries that fit. This keeps GET_LOGS responsive as spoke count
        # and per-module heartbeat lines grow, without ever tripping a 1009
        # "message too big" close on the bugfixer agent.
        #
        # The trim is a binary search over the tail length (O(log N) json.dumps
        # passes), NOT the prior `while ... pop(0)` loop which re-serialized the
        # whole list on every pop — O(N²) in log lines, which at 100s of spokes
        # × 1000-line deques stalled the event loop on every BugFixer poll.
        max_bytes = getattr(self, "get_logs_max_bytes", lambda: 12 * 1024 * 1024)()
        all_logs = _fit_log_payload(all_logs, max_bytes)

        return {"logs": all_logs}

    def collect_error_logs(self):
        """Aggregate ONLY error-level lines from every log source the Hub can see.

        Same sources as collect_all_logs (hub deque, agent_logs, /var/log/lm/*.log)
        but filtered to lines that read as errors — ERROR / CRITICAL / Exception /
        Traceback (case-insensitive). Each line is prefixed with its source module
        so the WebUI's Error Log tab and the BugFixer agent get one copy-pasteable
        list of everything that has gone wrong across the whole stack, without
        having to comb each spoke's logs by hand.
        """
        import re
        # Match an actual ERROR/CRITICAL *level*, not the word "error" in prose.
        # Our log format is ``… - LEVEL - msg`` and LEVEL is always UPPERCASE
        # (``%(levelname)s``), so keying ERROR/CRITICAL case-SENSITIVELY excludes
        # lowercase prose: the benign INFO summary
        # ``provisioning_repos: 10 ok, 0 error, 0 skipped`` (a COUNT of zero
        # errors) no longer lands in the Error Log, and the ``uvicorn.error``
        # logger name (lowercase, carrying INFO lifecycle lines) drops out for
        # free. The old ``\berror\b`` + IGNORECASE matched that bare lowercase
        # word despite the comment claiming otherwise. The ``[sync-error]`` family
        # of tags is lowercase by convention → matched explicitly; Traceback/
        # Exception (case-insensitive) catch Python failures whose header line
        # carries no level token.
        pat = re.compile(
            r"(?<!\.)\b(?:ERROR|CRITICAL)\b"        # uppercase level (not prose "error")
            r"|\[[a-z][a-z-]*-error\]"              # [sync-error] and kin
            r"|(?i:\btraceback\b|\bexception\b)")    # Python failure indicators
        errs = []
        for log in self.logs:
            if pat.search(log):
                errs.append(f"[hub] {log}")
        for agent_id, logs in self.agent_logs.items():
            for log in logs:
                if pat.search(log):
                    errs.append(f"[{agent_id}] {log}")
        try:
            log_dir = "/var/log/lm"
            if os.path.exists(log_dir):
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        module_name = filename.replace(".log", "")
                        try:
                            with open(os.path.join(log_dir, filename), "r") as f:
                                for line in deque(f, maxlen=500):
                                    if pat.search(line):
                                        errs.append(f"[{module_name}] {line.strip()}")
                        except Exception:
                            continue
        except Exception as e:
            logger.error(f"Error reading module logs from disk: {e}")
        # Globally newest-first in the WebUI Error Log tab. The WebUI does
        # `.slice().reverse()` on whatever we return (main.js), and the three
        # sources above are each oldest-first, so reversing alone only flips
        # each source independently — a newer hub line ends up below an older
        # disk line because the sources are concatenated, not interleaved. Sort
        # ascending by timestamp here so the WebUI reverse yields a globally
        # chronological-descending list across all sources. Lines are prefixed
        # "[source] <raw line>"; strip that prefix to reach the leading
        # "YYYY-MM-DD HH:MM:SS" timestamp. Lines with no parseable timestamp
        # (traceback continuations, agent relay preambles) sort first ascending
        # → land at the BOTTOM after the WebUI reverse, so they don't crowd the
        # top of the error log.
        ts_re = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

        def _ts_key(line: str):
            body = line.split("] ", 1)[1] if line.startswith("[") else line
            m = ts_re.search(body[:40])
            return (0, "") if not m else (1, m.group(1))

        errs.sort(key=_ts_key)

        # De-duplicate across sources. The hub's OWN records reach this list
        # twice: once from ``self.logs`` (the HubLogHandler buffer) and once
        # from ``/var/log/lm/hub.log`` (the root stderr capture) — same record,
        # now byte-identical since HubLogHandler adopted the canonical format.
        # Strip the leading ``[source] `` prefix and drop exact duplicates,
        # keeping the first (oldest after the ascending sort) so each error
        # appears once. Spoke/agent relayed logs (``agent_logs``) have no
        # on-disk counterpart on the hub, so they survive untouched.
        seen = set()
        deduped = []
        for line in errs:
            key = line.split("] ", 1)[1] if line.startswith("[") else line
            if key in seen:
                continue
            seen.add(key)
            deduped.append(line)
        return {"logs": deduped}

    def _hub_request_authorized(self, spoke_id: str,
                                peer_cert_identity=None) -> bool:
        """H1: is this connection allowed to use the reverse HUB_REQUEST channel?

        The channel is BugFixer's tool — it finds problems and fixes them, so it
        legitimately needs every tenant's logs (GET_LOGS), the full fleet roster
        (GET_SPOKE_STATUS), the bug-report handoff, and the fleet TRIGGER_*
        update actions (to push fixes). But "approved + signed" was the ONLY
        gate, so ANY approved spoke — a malicious tenant-added one, or a
        compromised box — inherited fleet-wide RCE (TRIGGER_ALL_UPDATES fans
        SPOKE_UPDATE to every spoke/agent) and cross-tenant log harvest.

        The gate is **cert-bound**, not ``spoke_id``-bound. ``spoke_id`` is
        hostname-derived and spoofable (name a box ``bugfixer``), and casing is a
        nuisance; identity is the verified TLS client cert instead. An operator
        labels a specific Let's Encrypt-issued cert as "the BugFixer cert" (the
        LE-module checkbox → ``global_config['bugfixer_cert_identities']``, a
        list of DNS names); the hub pins that cert's identity; a HUB_REQUEST is
        authorized **only** when the calling connection presented that cert over
        mTLS. mTLS off / no cert / extraction failed / mismatch → denied.

        Rule: ``BugFixer rights ⟺ mTLS on AND the connection's verified client
        cert matches the pinned BugFixer cert. Anything else → denied.``

        ``peer_cert_identity`` is the tuple of SAN DNS names (subject-CN fallback)
        captured for this connection by the ``/ws/spoke`` route (None when mTLS
        off / no cert presented / extraction failed). Fail-closed: None or no
        pinned cert → deny. Everything else is denied and logged so attempted
        abuse surfaces in diagnostics."""
        pinned = (self.state.get_global_config() or {}).get(
            "bugfixer_cert_identities", []) or []
        if not pinned:
            # No cert designated as BugFixer → the channel is closed (fail-closed
            # default). BugFixer is dormant until the operator issues + labels a
            # dedicated cert.
            return False
        if not peer_cert_identity:
            # mTLS off / no client cert presented / extraction failed → deny.
            return False
        return any(name in pinned for name in peer_cert_identity)

    async def handle_hub_request(self, spoke_id: str, req: Dict[str, Any],
                                 peer_cert_identity=None) -> Dict[str, Any]:
        """Dispatch a HUB_REQUEST from an approved agent and return a result dict.

        This is the reverse of the normal Hub->spoke command direction: an
        approved agent (e.g. BugFixer) asks the Hub to do something and
        receives a correlated, signed HUB_RESPONSE. Only approved, signed
        senders reach this method (the message loop drops everyone else),
        and only a connection presenting the pinned BugFixer client cert over
        mTLS is authorized to use the channel (H1) — see _hub_request_authorized.
        """
        req_type = req.get("type", "") if isinstance(req, dict) else ""
        # H1: the whole reverse channel (fleet RCE + cross-tenant logs + roster)
        # is BugFixer's tool. Deny every other approved spoke before dispatch so
        # a malicious/compromised spoke can't escalate to fleet-wide action.
        if not self._hub_request_authorized(spoke_id, peer_cert_identity):
            logger.warning(
                f"[H1] denied HUB_REQUEST '{req_type}' from {spoke_id}: not "
                f"authorized (BugFixer client cert required; label a cert in the "
                f"LE module and present it over mTLS).")
            self.record_spoke_event(spoke_id, "hub_request_denied",
                                    f"type={req_type} — BugFixer client cert required")
            return {"status": "error",
                    "message": "not authorized for HUB_REQUEST (BugFixer role required)"}
        try:
            if req_type == "GET_LOGS":
                return await asyncio.to_thread(self.collect_all_logs)

            if req_type == "GET_ERROR_LOGS":
                return await asyncio.to_thread(self.collect_error_logs)

            if req_type == "TRIGGER_UPDATE":
                return await self.perform_update(force=bool(req.get("force", False)))

            if req_type == "TRIGGER_SPOKE_UPDATES":
                return await self.update_spokes_only()

            if req_type == "TRIGGER_AGENT_UPDATES":
                return await self.update_agents_only()

            if req_type == "TRIGGER_ALL_UPDATES":
                hub = await self.perform_update(force=bool(req.get("force", False)))
                spokes = await self.update_spokes_only()
                agents = await self.update_agents_only()
                return {"hub": hub, "spokes": spokes, "agents": agents}

            if req_type == "GET_SPOKE_STATUS":
                return {
                    "active_connections": list(self.active_connections.keys()),
                    "approved": {sid: bool(approved) for sid, approved in self.approved_modules.items()},
                    "module_types": dict(self.spoke_module_types),
                    # Per-spoke recovery state for the watchdog. bugfixer reads
                    # this to suppress filing while the hub is recovering
                    # (in_progress) and to escalate only on give_up (so a human
                    # sees "venv/interpreter missing — needs reinstall", not a
                    # generic missing-heartbeat). The WebUI Diagnostics view
                    # renders the same fields.
                    "recovery": {
                        sid: {
                            "attempts": st.get("attempts", 0),
                            "in_progress": bool(st.get("in_progress", False)),
                            "gave_up": bool(st.get("gave_up", False)),
                            "manual_pause": bool(st.get("manual_pause", False)),
                            "last_action": st.get("last_action", ""),
                            "last_error": st.get("last_error", ""),
                            "last_crash_sig": st.get("last_crash_sig", ""),
                            "next_retry_ts": st.get("next_retry_ts", 0),
                            "last_attempt_ts": st.get("last_attempt_ts", 0),
                        }
                        for sid, st in self.spoke_recovery.items()
                    },
                }

            # "File a Bug" handoff: bugfixer enumerates filed reports, pulls the
            # full artifacts (console/HTML/screenshot) for AI-fix context, and
            # marks them filed so the same report is never filed twice. The
            # short [bug-report] marker line in the hub log is what bugfixer's
            # scan_bugs filters on; these handlers carry the payload.
            if req_type == "GET_BUG_REPORTS":
                reports = self._list_bug_reports()
                unfiled = sum(1 for r in reports if not r.get("filed"))
                logger.info(
                    f"[bug-report] GET_BUG_REPORTS from {spoke_id}: "
                    f"{len(reports)} total, {unfiled} unfiled"
                )
                return {"reports": reports}

            if req_type == "GET_BUG_REPORT":
                rid = req.get("id", "")
                rep = await asyncio.to_thread(self._get_bug_report, rid)
                logger.info(
                    f"[bug-report] GET_BUG_REPORT id={rid} from {spoke_id}: "
                    f"{'hit' if rep else 'miss'}"
                )
                return rep

            if req_type == "MARK_BUG_FILED":
                rid = req.get("id", "")
                issue_url = req.get("issue_url", "")
                ok = await asyncio.to_thread(self._mark_bug_filed, rid, issue_url)
                logger.info(
                    f"[bug-report] MARK_BUG_FILED id={rid} url={issue_url} "
                    f"from {spoke_id}: {'ok' if ok else 'not_found'}"
                )
                return {"status": "ok" if ok else "not_found"}

            # NetBox IPAM spoke (API-only, no cert helper) owns the cert-install
            # KNOWLEDGE and relays the actual install to the netbox-server agent
            # (the NetBox web host, which has nginx + the root sudoers helper).
            # The spoke validated the fullchain/privkey pair in-process before
            # sending; the hub resolves the agent from its netbox_server_agents
            # registry (no agent_id pushed to the spoke) and runs INSTALL_CERT
            # there, returning the agent's result. See _cert_target_spoke
            # (netbox-server branch) + request_response.
            if req_type == "RELAY_NETBOX_CERT":
                # DEPRECATED (tiered Hub→Spoke→Agent): the ipam spoke is now a
                # cert custodian + agent host — it installs the cert by driving
                # its OWN hosted Agent (WRITE_FILE + RUN_COMMAND), never bouncing
                # back to the hub. This handler stays only so a transitional
                # old spoke gets a clear message instead of an unknown-request
                # error. Update the netbox spoke to the agent-host build.
                logger.warning("[cert] RELAY_NETBOX_CERT from %s is DEPRECATED — "
                               "the ipam spoke now installs via its hosted Agent; "
                               "update the netbox spoke.", spoke_id)
                return {"status": "ERROR",
                        "message": ("RELAY_NETBOX_CERT is retired — the ipam spoke "
                                    "installs the cert via its hosted Agent now. "
                                    "Update the netbox spoke to the agent-host build.")}

            logger.warning(f"Unknown HUB_REQUEST type '{req_type}' from {spoke_id}")
            return {"status": "error", "message": f"unknown request type: {req_type}"}
        except Exception as e:
            logger.error(f"HUB_REQUEST '{req_type}' from {spoke_id} failed: {e}")
            return {"status": "error", "message": str(e)}

    _SIM_CACHE_FLUSH_INTERVAL_S = 30
    # Warm-load only bridges the seconds-long reconnect gap after a restart, so a
    # persisted telemetry frame older than this is dropped rather than shown —
    # stops a rename-orphaned "ghost" spoke frame from resurrecting on restart.
    _WARM_LOAD_MAX_AGE_S = 1800   # 30 min

    def _sim_cache_tenant_of(self, spoke_pk: str) -> str:
        """Group simulations_cache (keyed by spoke primary key) into per-tenant
        shards. Spokes with no tenant binding go to an ``_unassigned`` shard so
        they still persist/warm-load."""
        try:
            return self.state.get_spoke_tenant(spoke_pk) or "_unassigned"
        except Exception:  # noqa: BLE001
            return "_unassigned"

    def _load_simulations_cache(self) -> None:
        """Warm-start simulations_cache from per-tenant encrypted shards (best-
        effort) so the Clients/VM Server views seed on a restart instead of
        blank-until-reconnect. One-time migration from the legacy shared file."""
        try:
            from security.encryption import hub_encryption
            from tenant_sharded import migrate_legacy, shard_load
            _dec = lambda b: hub_encryption.decrypt(b)  # noqa: E731
            _enc = lambda s: hub_encryption.encrypt(s)  # noqa: E731
            migrate_legacy(self.state.data_dir, "simulations", "simulations_cache.json",
                           tenant_of=self._sim_cache_tenant_of, decrypt=_dec, encrypt=_enc)
            data = shard_load(self.state.data_dir, "simulations", "simulations_cache.json",
                              decrypt=_dec) or {}
            # Drop ANCIENT frames on warm-load. Warm-start only exists to bridge
            # the few-seconds reconnect gap after a restart, so a frame older than
            # _WARM_LOAD_MAX_AGE_S has no value — and worse, a spoke that was
            # renamed (e.g. the -spoke/-agent id change) leaves a stale entry
            # under its OLD id that the live spoke never overwrites; a restart
            # would warm-load that GHOST and show it (old agent version / VM
            # count) until the operator manually clears it. Dropping stale frames
            # here makes a restart never resurrect a ghost — the live relay
            # repopulates the real host within seconds.
            _now = time.time()
            loaded, _dropped = {}, 0
            for k, v in data.items():
                if not isinstance(v, dict):
                    continue
                _ft = v.get("fetched_at")
                if isinstance(_ft, (int, float)) and (_now - _ft) > self._WARM_LOAD_MAX_AGE_S:
                    _dropped += 1
                    continue
                loaded[str(k)] = v
            self.simulations_cache = loaded
            if self.simulations_cache or _dropped:
                logger.info("simulations_cache: warm-loaded %d spoke payload(s) from shards"
                            "%s", len(self.simulations_cache),
                            f" ({_dropped} stale ghost frame(s) dropped)" if _dropped else "")
        except Exception as e:  # noqa: BLE001
            logger.warning("simulations_cache warm load failed: %s — starting empty", e)

    def _save_simulations_cache(self) -> None:
        """Encrypted per-tenant shard write of simulations_cache. Never raises — a
        failed persist must not break telemetry ingest."""
        try:
            from security.encryption import hub_encryption
            from tenant_sharded import shard_save
            shard_save(self.state.data_dir, "simulations", "simulations_cache.json",
                       self.simulations_cache, tenant_of=self._sim_cache_tenant_of,
                       encrypt=lambda s: hub_encryption.encrypt(s))
        except Exception as e:  # noqa: BLE001
            logger.warning("simulations_cache persist failed: %s", e)

    def _load_central_hub_status(self) -> None:
        """Warm-start central_hub_status from per-tenant encrypted shards so the
        centralized-mode Checks/Central/Hardware dashboards seed on a restart
        instead of blank-until-first-poll. One-time migration from legacy file."""
        try:
            from security.encryption import hub_encryption
            from tenant_sharded import migrate_legacy, shard_load
            _dec = lambda b: hub_encryption.decrypt(b)  # noqa: E731
            _enc = lambda s: hub_encryption.encrypt(s)  # noqa: E731
            migrate_legacy(self.state.data_dir, "simulations", "central_hub_status.json",
                           tenant_of=lambda k: k, decrypt=_dec, encrypt=_enc)
            data = shard_load(self.state.data_dir, "simulations", "central_hub_status.json",
                              decrypt=_dec) or {}
            self.central_hub_status = {str(k): v for k, v in data.items()
                                       if isinstance(v, dict)}
            if self.central_hub_status:
                logger.info("central_hub_status: warm-loaded %d tenant status block(s) from shards",
                            len(self.central_hub_status))
        except Exception as e:  # noqa: BLE001
            logger.warning("central_hub_status warm load failed: %s — starting empty", e)

    def _save_central_hub_status(self) -> None:
        """Encrypted per-tenant shard write of central_hub_status. Never raises — a
        failed persist must not break the poll loop. Called once per poll cycle."""
        try:
            from security.encryption import hub_encryption
            from tenant_sharded import shard_save
            shard_save(self.state.data_dir, "simulations", "central_hub_status.json",
                       self.central_hub_status, tenant_of=lambda k: k,
                       encrypt=lambda s: hub_encryption.encrypt(s))
        except Exception as e:  # noqa: BLE001
            logger.warning("central_hub_status persist failed: %s", e)

    def reset_derived_cache(self, tenant: "Optional[str]" = None) -> dict:
        """Corruption recovery: wipe DERIVED/cache/history state — the sharded
        simulations stores (check_health, poll_window, client_count,
        simulations_cache, central_hub_status) — both the tenant shard FILES and
        the resident in-memory dicts, globally or for one tenant.

        INVARIANT: NEVER touches config/identity (state.json,
        simulations_store.json = tenant config + spoke PSKs, sessions, tokens), so
        a reset can't orphan a spoke or log anyone out. The derived data
        regenerates from the next poll/telemetry cycle. Clearing the in-memory
        dicts is essential — deleting files alone would let the next save re-write
        the (possibly corrupt) resident data straight back. Best-effort per store.
        """
        from tenant_sharded import reset_tenant_files, reset_all_tenant_files
        poller = getattr(self, "central_hub_poller", None)
        stores = [getattr(poller, a, None) for a in ("_health", "_cpw", "_cc")] if poller else []
        if tenant:
            t = str(tenant)
            try:
                self.central_hub_status.pop(t, None)
            except Exception:  # noqa: BLE001
                pass
            try:
                for pk in [pk for pk in list(self.simulations_cache)
                           if self._sim_cache_tenant_of(pk) == t]:
                    self.simulations_cache.pop(pk, None)
                self._sim_cache_dirty = True
            except Exception:  # noqa: BLE001
                pass
            for store in stores:
                try:
                    if store:
                        store.forget(t)
                except Exception:  # noqa: BLE001
                    pass
            files = reset_tenant_files(self.state.data_dir, t)
        else:
            try:
                self.central_hub_status.clear()
            except Exception:  # noqa: BLE001
                pass
            try:
                self.simulations_cache.clear()
                self._sim_cache_dirty = True
            except Exception:  # noqa: BLE001
                pass
            for store in stores:
                try:
                    if store:
                        store.clear()
                except Exception:  # noqa: BLE001
                    pass
            files = reset_all_tenant_files(self.state.data_dir)
        logger.warning("reset_derived_cache: scope=%s removed %d shard file(s)",
                       tenant or "ALL", files)
        return {"status": "ok", "scope": tenant or "all", "files_removed": files}

    async def run_sim_cache_flush_loop(self):
        """Persist simulations_cache to disk when dirty, off the event loop.
        Decoupled from the ~10s-per-spoke telemetry rate → one bounded write per
        interval; the sync write is offloaded via asyncio.to_thread so it can't
        reproduce the on-loop I/O starvation that stalled cs-svr-02's WS link."""
        while True:
            try:
                await asyncio.sleep(self._SIM_CACHE_FLUSH_INTERVAL_S)
                if self._sim_cache_dirty:
                    self._sim_cache_dirty = False
                    await asyncio.to_thread(self._save_simulations_cache)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001
                logger.debug("sim cache flush loop error: %s", e)

    def _update_gate_config(self) -> dict:
        """The WebUI-editable maintenance-window / idle gate for AUTO restarts
        (global_config.update_gate). Defaults to a 02:00 local-time window."""
        try:
            cfg = (self.state.system_state.get("global_config", {}) or {}).get("update_gate", {}) or {}
        except Exception:  # noqa: BLE001
            cfg = {}
        return {
            # window = STRICT maintenance window only (default, 2am — never on
            # daytime idle); idle_window = idle OR window; idle = when idle only;
            # immediate = always. AUTO restarts only; the footer Update is force.
            "mode": str(cfg.get("mode", "window")).lower(),
            "window_hour": int(cfg.get("window_hour", 2)),        # 0-23 local
            "window_duration_h": int(cfg.get("window_duration_h", 2)),
        }

    def _gate_allows_restart_now(self) -> bool:
        """Whether an AUTO-update restart may fire right now per update_gate.
        The footer Update button bypasses this (force sentinel). Fail-open."""
        g = self._update_gate_config()
        if g["mode"] == "immediate":
            return True
        # Idle = nobody actively logged into the WebUI (best-effort → treat
        # unknown as idle so we never strand an update).
        try:
            from api import _active_user_count
            idle = _active_user_count() == 0
        except Exception:  # noqa: BLE001
            idle = True
        if g["mode"] == "idle":
            return idle
        # "idle_window" (legacy permissive): restart as soon as nobody is logged
        # in OR during the maintenance window. An idle hub updates promptly.
        if g["mode"] == "idle_window" and idle:
            return True
        # "window" (default) is STRICT and INTENTIONALLY does NOT allow on idle:
        # AUTO restarts fire ONLY inside the maintenance window (e.g. 02:00). A
        # daytime idle must NOT trigger a restart — an operator who steps away for
        # a few minutes should never come back to a hub that restarted under them
        # (that surprise is exactly what this rule prevents). The footer Update
        # button (force sentinel) still applies on demand, any time. INVARIANT:
        # do NOT re-add an `if idle: return True` here for window mode — use
        # `idle_window` mode if promptly-on-idle behavior is wanted.
        try:  # window: local hour within [start, start+duration) mod 24
            h = _dt.datetime.now().hour
        except Exception:  # noqa: BLE001
            return True   # clock unreadable → fail-open so an update never strands
        start = g["window_hour"] % 24
        dur = max(1, min(24, g["window_duration_h"]))
        return any((start + i) % 24 == h for i in range(dur))

    def _compute_version_drift(self):
        """Footer version-indicator drift computation (called every watchdog
        bridge cycle). Returns ``(target_version, running_version, behind,
        update_available)``:

        - ``target_version``  — the on-disk VERSION file (latest pulled code).
        - ``running_version`` — what THIS process is actually running: the
          in-memory ``_startup_version`` captured once at boot from the same
          file. NOT a re-read of the file — a ``git pull`` rewrites VERSION, so
          re-reading it would make running == target even right after a pull
          (while the process still serves the old code) and ``behind`` would
          never flip. ``_startup_version`` only moves on a real restart, so
          disk-vs-_startup_version IS disk-vs-running. Falls back to the
          running-version FILE (written at boot) only if ``_startup_version`` is
          somehow unset.
        - ``behind``          — True when a newer VERSION is on disk but the hub
          hasn't restarted into it yet (disk != running). Both sides must be
          non-empty (never false-yellow on an unreadable file).
        - ``update_available`` — remote-ahead-not-pulled, cached by
          ``check_update_health`` (see update_pipeline). The dot is yellow on
          EITHER signal.
        """
        target_ver = ""
        try:
            vp = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(vp):
                vp = os.path.join(os.path.dirname(__file__), "../VERSION")
            # _live_watchdog_status() calls this on EVERY /status; read the VERSION
            # file through the mtime-keyed cache (_read_version_cached) so a
            # repeated poll doesn't re-open it each time. The cache re-reads only
            # when the file's mtime changes (a repo pull rewrites VERSION), so the
            # value stays correct — this is disk-vs-running drift detection, so it
            # MUST reflect a pull. Direct-read fallback when the cached reader is
            # unavailable (e.g. a stub hub in unit tests).
            _reader = getattr(self, "_read_version_cached", None)
            if _reader is not None:
                target_ver = _reader(vp) or ""
            else:
                with open(vp) as vf:
                    target_ver = vf.read().strip()
        except Exception:  # noqa: BLE001
            pass
        running_ver = getattr(self, "_startup_version", "") or ""
        if not running_ver:
            try:
                with open("/var/lib/lm/state/running-version") as rf:
                    running_ver = rf.read().strip()
            except Exception:  # noqa: BLE001
                pass
        behind = bool(target_ver and running_ver and target_ver != running_ver)
        update_avail = bool(getattr(self, "_update_available", False))
        return target_ver, running_ver, behind, update_avail

    def _live_watchdog_status(self):
        """The watchdog status dict for /status, with the version-drift keys
        recomputed LIVE on every call.

        The bridge loop (run_watchdog_bridge_loop) owns the observational keys
        it alone can produce — ``armed`` (systemctl timer state), ``heartbeat``,
        ``log_mtime`` — and caches them in ``_watchdog_status``. But the footer
        version dot must reflect disk-vs-running drift on EVERY /status, not just
        after that 20s loop has run past its 8s systemctl call. So we start from
        the cached dict (for armed/heartbeat/log_mtime) and overwrite the drift
        keys with a fresh ``_compute_version_drift`` — a cheap sync file read.
        """
        base = dict(getattr(self, "_watchdog_status", {}) or {})
        try:
            target_ver, running_ver, behind, update_avail = self._compute_version_drift()
            base["target_version"] = target_ver
            base["running_version"] = running_ver
            base["behind"] = behind
            base["update_available"] = update_avail
        except Exception:  # noqa: BLE001 — never let the dot break /status
            pass
        return base

    async def run_watchdog_bridge_loop(self):
        """Bridge the ROOT lm-watchdog to the hub, every ~20s:
          1. Write the active-user count to a file the watchdog reads before a
             (non-force) restart, so it holds off while users are logged in.
          2. Relay NEW watchdog.log lines into the hub log ([watchdog] …) so its
             events land in the centralized hub log + WebUI Logs view.
          3. Cache the watchdog heartbeat/status (last run + last action) so the
             WebUI can show that auto-heal is alive (via /status → get_system_metrics).
        Purely observational + best-effort; never fatal to the hub.
        """
        from api import write_active_users_file  # lazy: avoid module-level dep
        wlog = "/var/log/lm/watchdog.log"
        status_file = "/var/lib/lm/watchdog-status"
        self._watchdog_status = getattr(self, "_watchdog_status", {}) or {}
        self._watchdog_log_pos = getattr(self, "_watchdog_log_pos", None)
        await asyncio.sleep(20)  # stagger past boot
        while True:
            try:
                # 1. active-user count + restart-gate flag for the watchdog.
                # The gate flag (1/0) encodes the maintenance-window/idle policy
                # so the watchdog only auto-restarts when allowed (Update button
                # force-sentinel bypasses it). Fail-open: written every cycle.
                try:
                    write_active_users_file(self)
                    _allowed = "1" if self._gate_allows_restart_now() else "0"
                    _gp = os.environ.get("LM_RESTART_ALLOWED_FILE",
                                         "/var/lib/lm/state/restart-allowed")
                    os.makedirs(os.path.dirname(_gp), exist_ok=True)
                    with open(_gp, "w") as _f:
                        _f.write(_allowed + "\n")
                except Exception:  # noqa: BLE001
                    pass
                # 2. relay new watchdog.log lines into the hub log
                try:
                    if os.path.isfile(wlog):
                        size = os.path.getsize(wlog)
                        # First pass (pos None) or rotation (file shrank) → start at
                        # end / start so we don't replay the whole history into the hub log.
                        if self._watchdog_log_pos is None or self._watchdog_log_pos > size:
                            self._watchdog_log_pos = size
                        elif size > self._watchdog_log_pos:
                            with open(wlog, "r") as f:
                                f.seek(self._watchdog_log_pos)
                                new = f.read()
                                self._watchdog_log_pos = f.tell()
                            for line in new.splitlines():
                                line = line.strip()
                                if not line:
                                    continue
                                low = line.lower()
                                if "restart" in low or "force" in low or "stale" in low or "kill" in low or "purged" in low:
                                    logger.warning("[watchdog] %s", line)
                                else:
                                    logger.info("[watchdog] %s", line)
                except Exception as e:  # noqa: BLE001
                    logger.debug("watchdog log relay failed: %s", e)
                # 3. cache watchdog heartbeat/status for the WebUI
                try:
                    armed = False
                    if shutil.which("systemctl"):
                        proc = await asyncio.create_subprocess_exec(
                            "systemctl", "is-active", "lm-watchdog.timer",
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                        out, _ = await asyncio.wait_for(proc.communicate(), timeout=8.0)
                        armed = out.decode().strip() == "active"
                    hb = ""
                    if os.path.isfile(status_file):
                        with open(status_file, "r") as f:
                            hb = f.read().strip()
                    # Version-drift for the footer indicator (extracted into
                    # _compute_version_drift so the disk-vs-running logic is
                    # unit-testable without standing up the full watchdog loop).
                    _target_ver, _running_ver, _behind, _update_avail = (
                        self._compute_version_drift())
                    self._watchdog_status = {
                        "armed": armed,
                        "heartbeat": hb,
                        "log_mtime": (os.path.getmtime(wlog) if os.path.isfile(wlog) else 0),
                        "target_version": _target_ver,
                        "running_version": _running_ver,
                        "behind": _behind,
                        "update_available": _update_avail,
                    }
                except Exception as e:  # noqa: BLE001
                    logger.debug("watchdog status cache failed: %s", e)
            except Exception as e:  # noqa: BLE001 — never fatal
                logger.debug("watchdog bridge loop cycle failed: %s", e)
            await asyncio.sleep(20)

    async def run_mps_loop(self):
        """
        Calculates messages per second and throughput using a 10-second moving average.
        """
        logger.info("MPS and Throughput monitoring loop started.")
        _last_tick = time.time()
        while True:
            await asyncio.sleep(1.0)
            # LOOP LAG = how much longer than the 1s sleep this cycle actually
            # took. When the event loop is CPU-saturated by ingest (single core
            # pegged), even this sleep returns late — so the overrun is a direct
            # "loop is the bottleneck" signal, independent of memory.
            _now = time.time()
            _loop_lag = max(0.0, (_now - _last_tick) - 1.0)
            _last_tick = _now
            try:
                # ── Overload self-protection: memory OR loop-lag, w/ hysteresis ──
                # Enter above the high mark, leave below the low mark (no flap).
                # Memory guards OOM; loop-lag guards the single-core saturation
                # that hangs the UI. Shedding (reads + telemetry) relieves BOTH.
                try:
                    cfg = (self.state.get_global_config() or {}).get("protect", {}) or {}
                    mem_hi = float(cfg.get("mem_high_pct", 90))
                    mem_lo = float(cfg.get("mem_low_pct", 80))
                    lag_hi = float(cfg.get("loop_lag_high_s", 0.75))
                    lag_lo = float(cfg.get("loop_lag_low_s", 0.25))
                    cpu_hi = float(cfg.get("cpu_high_pct", 90))   # hub-process %/core
                    cpu_lo = float(cfg.get("cpu_low_pct", 70))
                    self._protect_shed_bytes = int(cfg.get("shed_bytes", 2048))
                    memp = psutil.virtual_memory().percent
                    cpup = self._proc.cpu_percent(interval=None) if self._proc else 0.0
                    # Stash for the ladder's fleet decision — hub-process CPU is
                    # the signal that actually pegs first (a distributed load of
                    # sub-offender spokes saturates the core well before mps/lag
                    # cross their marks). The graceful fleet slow-down keys off
                    # this at a LOWER threshold than protect.
                    self._proc_cpu = cpup
                    _over = memp >= mem_hi or _loop_lag >= lag_hi or cpup >= cpu_hi
                    _under = memp <= mem_lo and _loop_lag <= lag_lo and cpup <= cpu_lo
                    dwell = float(cfg.get("min_dwell_s", 15))
                    if not self._protect_mode and _over:
                        self._protect_mode = True
                        self._protect_entered_ts = _now
                        self._protect_reason = (f"memory {memp:.0f}%" if memp >= mem_hi
                                                else f"cpu {cpup:.0f}%/core" if cpup >= cpu_hi
                                                else f"loop lag {_loop_lag:.1f}s")
                        logger.error("[protect] ENTER — %s (mem %.0f%%, cpu %.0f%%, lag %.1fs); "
                                     "shedding heavy reads + telemetry (pre-parse)",
                                     self._protect_reason, memp, cpup, _loop_lag)
                    elif (self._protect_mode and _under
                          and (_now - getattr(self, "_protect_entered_ts", 0)) >= dwell):
                        # Min-dwell before exit so the pre-parse shed (which drops
                        # CPU fast) doesn't flap shed↔serve every second.
                        logger.warning("[protect] EXIT — mem %.0f%%, cpu %.0f%%, lag %.1fs",
                                       memp, cpup, _loop_lag)
                        self._protect_mode = False
                        self._protect_reason = ""
                except Exception as _pe:  # noqa: BLE001 — never let the guard crash the loop
                    logger.debug("[protect] guard sample failed: %s", _pe)

                self.message_history.append(self.message_count)

                if len(self.message_history) > 0:
                    self.mps = sum(self.message_history) / len(self.message_history)
                else:
                    self.mps = 0.0

                self.throughput_mbps = self.bytes_count / (1024 * 1024)

                # Keep the mailbox's backlog-expiry cap in sync with the live
                # config knob (global_config["backlog_expiry"].max_age_seconds,
                # default 3600s; 0 disables the cap → 24h ttl). Cheap dict read.
                try:
                    _be = (self.state.get_global_config().get("backlog_expiry", {}) or {})
                    self.mailbox.backlog_max_age_s = float(_be.get("max_age_seconds", 3600))
                except Exception:
                    pass

                # Refresh the soft-watermark fraction for the hot message loop
                # (so it reads an attribute, not a config dict, per frame).
                try:
                    _bpc = (self.state.get_global_config().get("backpressure", {}) or {})
                    self._rl_soft_frac = float(_bpc.get("rl_soft_fraction", 0.8))
                    self._protect_shed_min_mps = float(_bpc.get("protect_shed_min_mps", 50.0))
                except Exception:
                    pass

                # Per-spoke msg/s: push this tick's count into each spoke's 10s
                # history and average. Prune history for spokes with no traffic
                # and no live connection so the dicts don't grow unbounded.
                live = set(getattr(self, "active_connections", {}) or {})
                seen = set(self.spoke_msg_count) | set(self.spoke_msg_history)
                for sid in seen:
                    hist = self.spoke_msg_history.get(sid)
                    if hist is None:
                        hist = self.spoke_msg_history[sid] = deque(maxlen=10)
                    hist.append(self.spoke_msg_count.get(sid, 0))
                    if any(hist) or sid in live:
                        self.spoke_mps[sid] = sum(hist) / len(hist)
                    else:
                        # Idle + disconnected → drop it entirely.
                        self.spoke_msg_history.pop(sid, None)
                        self.spoke_mps.pop(sid, None)
                self.spoke_msg_count = {}
                # Snapshot the TRUE offered-frame counts for the protect source-
                # shed (per-tick ≈ frames/s), then reset for the next tick.
                self._spoke_offered = self._spoke_recv
                self._spoke_recv = {}

                # ── Escalation ladder: throttle offenders first, then fleet ──
                # Runs AFTER per-spoke mps is computed so it can name the loud
                # talkers. Sends LM_BACKPRESSURE on state-change only.
                try:
                    await self._apply_backpressure_ladder(_loop_lag)
                except Exception as _be:  # noqa: BLE001 — never crash the tick
                    logger.debug("[backpressure] ladder skipped: %s", _be)

                self.message_count = 0
                self.bytes_count = 0
            except Exception as e:
                logger.debug("[mps] loop iteration skipped: %s", e, exc_info=True)

    async def _apply_backpressure_ladder(self, loop_lag: float) -> None:
        """The graceful-degradation control loop (§7 of the spoke-heavy-lifting
        plan). Decides each 1s tick which spokes to slow down and signals only
        the DELTA (LM_BACKPRESSURE on level change), so it never spams.

        Rung 1 (offender-first): a spoke over ``per_spoke_soft_mps`` is told to
        slow + coalesce LOCALLY — the merge work lands on the spoke, not the hub.
        Rung 2 (fleet): only if the aggregate is STILL hot (loop-lag / mps over
        the fleet soft mark) does every spoke get the slow-down. This is the
        'throttle the loud one first, back off the whole fleet only if that
        wasn't enough' behaviour. See docs/backpressure-throttling.md §3
        (escalation ladder) for the full rung-by-rung contract."""
        # Snapshot + clear the per-tick bucket-breach set FIRST (so it clears
        # every tick even when we early-return under protect). A spoke that hit
        # its TokenBucket this tick is an instant offender — the earliest, most
        # precise detector, ahead of the 10s-average spoke_mps.
        breached = self._rl_breached
        self._rl_breached = set()
        harddrops = self._rl_harddrops
        self._rl_harddrops = {}

        # PROTECT TAKES PRECEDENCE. When protect mode is active the loop is
        # already parse-bound and shedding pre-parse — that is the ONLY relief at
        # this scale (coalescing happens AFTER json.loads, so it can't relieve a
        # parse-bound core). Doing the ladder's O(spokes) signalling + iteration
        # here would just compound the overload (this is what killed the hub at
        # ~800 spokes). So stand down and let protect shed; drop any buffered
        # coalesce work. The spoke slow-down signals we already sent still stand.
        if self._protect_mode:
            self._coalesce_pending = {}
            self._load_level = max(self._load_level, 3)
            p = self._backpressure_params()
            # Standing down ENTIRELY here was the bug the operator saw: under
            # protect the loud spokes got NO slow-down, so CPU stayed pegged and
            # only the early-throttled (now-quiet) spokes showed throttled. So
            # still THROTTLE the loudest talkers (bounded, loudest-first, to the
            # MAX interval) — cheap (sort + top-K signals), and it's exactly the
            # spokes that need slowing. Then source-shed disconnects any that
            # ignore it. Quiet spokes (< fleet_min) are never touched.
            try:
                _cap = max(1, p["max_signals_per_tick"])
                _fmin = p["fleet_min_mps"]
                _loud = sorted(getattr(self, "active_connections", {}) or {},
                               key=lambda s: self.spoke_mps.get(s, 0.0), reverse=True)
                _now = time.monotonic()
                _sigs = []
                for _sid in _loud[:_cap]:
                    if self.spoke_mps.get(_sid, 0.0) < _fmin:
                        break  # sorted desc → the rest are quieter still
                    if self._backoff_signaled.get(_sid, 0) != 2:
                        self._backoff_since.setdefault(_sid, _now)
                        self._spoke_backoff.add(_sid)
                        _sigs.append(self._signal_backoff(_sid, 2, p["coalesce_max_interval_s"]))
                if _sigs:
                    await asyncio.gather(*_sigs, return_exceptions=True)
            except Exception as _te:  # noqa: BLE001
                logger.debug("[protect] loud-throttle skipped: %s", _te)
            try:
                await self._protect_source_shed(p)
            except Exception as _se:  # noqa: BLE001
                logger.debug("[protect] source-shed skipped: %s", _se)
            return

        p = self._backpressure_params()
        live = list(getattr(self, "active_connections", {}) or {})
        # Signals are collected and fired CONCURRENTLY (gather) at the end — a
        # fleet-wide transition is hundreds of frames and must not stall the 1s
        # tick (that's the very core we're trying to relieve). CAPPED per tick.
        sigs = []
        if not p["enabled"]:
            for sid in [s for s, l in list(self._backoff_signaled.items()) if l]:
                sigs.append(self._signal_backoff(sid, 0, 0.0))
            self._spoke_backoff = set()
            self._fleet_backoff = False
            self._load_level = 0
            if sigs:
                await asyncio.gather(*sigs, return_exceptions=True)
            return

        # Rung 2 fleet decision (hysteresis). Three aggregate signals, ANY of
        # which trips it (the point is to catch a DISTRIBUTED load of individually
        # sub-offender spokes — none trip rung 1, but together they peg the core):
        #   • hub-process CPU  — the earliest, truest saturation signal;
        #   • loop-lag         — the single core can't keep up (tick returns late);
        #   • mps              — raw processed throughput near the ceiling.
        cpu = getattr(self, "_proc_cpu", 0.0)
        fleet_hot = (cpu >= p["fleet_cpu_soft"]
                     or loop_lag >= p["fleet_lag_soft_s"]
                     or self.mps >= p["fleet_soft_mps"])
        fleet_cool = (cpu <= p["fleet_cpu_clear"]
                      and loop_lag <= p["fleet_lag_clear_s"]
                      and self.mps < p["fleet_soft_mps"] * 0.6)
        if fleet_hot:
            self._fleet_backoff = True
        elif fleet_cool:
            self._fleet_backoff = False

        # Per-spoke desired level = 2 (fleet) else 1 (offender) else 0.
        #
        # DAMPING (release dwell): a THROTTLED spoke's measured mps is the
        # SUPPRESSED rate (it's coalescing to coalesce_min_interval_s), so it
        # naturally sits below the clear mark — evaluating release on it would
        # flap the spoke every window. So: once throttled, HOLD it for
        # release_dwell_s before we even consider releasing, and only release
        # then if it has genuinely gone quiet. New offenders still engage
        # instantly (ramp down fast); we only slow the RELEASE (ramp up slow).
        # ADAPTIVE slow-down interval: the hotter the CPU (soft→hard), the LARGER
        # the interval we ask FLEET-throttled spokes to conflate to — push the
        # fleet down HARDER as it heats up so CPU stays out of protect. Linear
        # from coalesce_min (at fleet_cpu_soft) to coalesce_max (at fleet_cpu_hard).
        imin, imax = p["coalesce_min_interval_s"], p["coalesce_max_interval_s"]
        _soft, _hard = p["fleet_cpu_soft"], p["fleet_cpu_hard"]
        if cpu <= _soft or _hard <= _soft:
            fleet_interval = imin
        else:
            frac = min(1.0, (cpu - _soft) / (_hard - _soft))
            fleet_interval = imin + frac * (imax - imin)
        self._fleet_interval = round(fleet_interval, 1)

        now = time.monotonic()
        dwell = p["release_dwell_s"]
        fmin = p["fleet_min_mps"]
        new_backoff = set()
        # LOUDEST-FIRST: process spokes by measured rate descending so the per-
        # tick signal cap throttles the LOUD talkers first (not front-of-dict /
        # connection order — that was throttling quiet early spokes while loud
        # late-connecting ones kept blasting).
        for sid in sorted(live, key=lambda s: self.spoke_mps.get(s, 0.0), reverse=True):
            mps = self.spoke_mps.get(sid, 0.0)
            was = self._backoff_signaled.get(sid, 0)
            if was:  # currently throttled → release dwell (measured rate is suppressed)
                held = now - self._backoff_since.get(sid, now)
                if held < dwell or mps >= p["per_spoke_clear_mps"] or sid in breached:
                    desired = was          # hold (damp the flap)
                elif self._fleet_backoff and mps >= fmin:
                    desired = 2            # still contributing under fleet → keep throttled
                else:
                    desired = 0            # quiet past the dwell → release
            else:
                # Offender (rung 1) if over the mps soft mark or a bucket breach;
                # else FLEET (rung 2) only if it's actually LOUD (>= fleet_min) —
                # quiet spokes are spared even when the fleet is backing off.
                if mps >= p["per_spoke_soft_mps"] or sid in breached:
                    desired = 1
                elif self._fleet_backoff and mps >= fmin:
                    desired = 2
                else:
                    desired = 0
            if desired:
                new_backoff.add(sid)
            # Fleet spokes get the adaptive interval; offenders get the min.
            want_interval = (fleet_interval if desired == 2
                             else imin if desired == 1 else 0.0)
            was_interval = self._backoff_interval.get(sid, 0.0)
            # Re-signal on a level change OR a MATERIAL interval change (so the
            # fleet actually slows further as CPU climbs — not just a one-shot).
            interval_changed = bool(desired) and abs(want_interval - was_interval) >= max(1.0, 0.25 * max(was_interval, imin))
            if desired != was or interval_changed:
                if desired and not was:
                    self._backoff_since[sid] = now   # stamp when throttling began
                sigs.append(self._signal_backoff(sid, desired, want_interval))
        self._spoke_backoff = new_backoff
        # Forget signal state for spokes that have disconnected.
        for sid in [s for s in list(self._backoff_signaled) if s not in live]:
            self._backoff_signaled.pop(sid, None)
            self._backoff_since.pop(sid, None)
            self._backoff_interval.pop(sid, None)
        self._load_level = 2 if self._fleet_backoff else (1 if self._spoke_backoff else 0)
        if sigs:
            # Cap sends per tick so a fleet-wide transition (hundreds of spokes)
            # spreads over several ticks instead of signing every frame in one
            # tick. Un-fired spokes just re-qualify next tick (was != desired
            # still holds because _backoff_signaled wasn't updated for them).
            cap = max(1, p["max_signals_per_tick"])
            fire, defer = sigs[:cap], sigs[cap:]
            for c in defer:
                c.close()  # don't leave un-awaited coroutines (ResourceWarning)
            await asyncio.gather(*fire, return_exceptions=True)

        # ── WebUI-visible summary log (WARNING → HubLogHandler → Logs view) ──
        # One line on any CHANGE of the throttled set or fleet state, naming the
        # offending spokes — this is what the operator sees in the Logs view and
        # drives the "throttled" badges. No change → silent (no flood).
        prev = getattr(self, "_bp_last_summary", (frozenset(), False))
        cur = (frozenset(new_backoff), self._fleet_backoff)
        if cur != prev:
            self._bp_last_summary = cur
            if self._fleet_backoff:
                logger.warning(
                    "[backpressure] FLEET slow-down ACTIVE — %d spoke(s) throttled "
                    "(aggregate over ceiling: cpu %.0f%%, loop-lag %.2fs, %.0f msg/s). "
                    "Spokes are coalescing locally.",
                    len(new_backoff), getattr(self, "_proc_cpu", 0.0), loop_lag, self.mps)
            elif new_backoff:
                logger.warning(
                    "[backpressure] throttling %d offending spoke(s): %s — over the "
                    "%.0f msg/s mark or their burst bucket; told to slow + coalesce "
                    "locally (vs silently dropping).",
                    len(new_backoff), ", ".join(sorted(new_backoff)[:10]),
                    p["per_spoke_soft_mps"])
            else:
                logger.warning("[backpressure] CLEARED — all spokes back to normal cadence.")

        # ── DDoS enforcement: disconnect + quarantine a persistent flooder ──
        # A spoke we've ALREADY told to slow down (level>0) that KEEPS hard-
        # dropping frames is not honoring backpressure — broken or hostile. Once
        # it has flooded for ddos_grace_s it's disconnected and quarantined, so
        # the hub stops spending parse+verify on it (dropping AFTER parse doesn't
        # stop a DDoS — only closing the socket does). DEFAULT OFF (a legacy
        # spoke that can't honor the signal would keep hard-dropping too).
        if p["ddos_disconnect"]:
            min_hd = max(1, p["ddos_min_harddrops"])
            grace = p["ddos_grace_s"]
            offenders = []
            for sid, hd in harddrops.items():
                # Count spokes that are BOTH flooding (hard-drops this tick) AND
                # under throttle this tick (new_backoff) — i.e. we've told them to
                # slow and they're still over the hard limit. The grace clock
                # below requires this to persist, so a compliant spoke's brief
                # burst self-corrects and never disconnects. (Uses new_backoff, not
                # _backoff_signaled, so a spoke released THIS tick can't slip past.)
                if hd >= min_hd and sid in new_backoff:
                    self._noncompliant_since.setdefault(sid, now)
                    if (now - self._noncompliant_since[sid]) >= grace:
                        offenders.append((sid, hd))
                else:
                    self._noncompliant_since.pop(sid, None)
            # drop non-compliance clocks for anyone who stopped flooding
            for sid in [s for s in list(self._noncompliant_since) if s not in harddrops]:
                self._noncompliant_since.pop(sid, None)
            for sid, hd in offenders:
                await self._disconnect_and_quarantine(sid, hd, p["quarantine_s"])

    async def _disconnect_and_quarantine(self, spoke_id: str, hard_drops: int,
                                         quarantine_s: float) -> None:
        """Close a persistent flooder's socket and refuse its reconnect for
        ``quarantine_s`` (checked in handle_connection). This is the DDoS
        backstop — dropping frames after parse still costs the hub; closing the
        socket stops the cost. Logged at ERROR (WebUI Logs view)."""
        self._quarantine[spoke_id] = time.monotonic() + max(0.0, quarantine_s)
        self._noncompliant_since.pop(spoke_id, None)
        self._backoff_signaled.pop(spoke_id, None)
        self.record_spoke_event(spoke_id, "ddos_quarantine",
                                f"ignored slow-down; {hard_drops} hard-drops/s → "
                                f"disconnected + quarantined {quarantine_s:.0f}s")
        logger.error("[backpressure] DDoS DEFENSE — spoke %s ignored the slow-down "
                     "and kept flooding (%d hard-drops/s); DISCONNECTED + quarantined "
                     "for %.0fs.", spoke_id, hard_drops, quarantine_s)
        ws = self.active_connections.get(self._primary_key(spoke_id))
        if ws is not None:
            try:
                await ws.close(1013, "Flooding after slow-down — quarantined")
            except Exception as e:  # noqa: BLE001
                logger.debug("quarantine close of %s failed: %s", spoke_id, e)

    def _is_quarantined(self, spoke_id: str) -> bool:
        """True while ``spoke_id`` is inside its DDoS quarantine cooldown.
        Expired entries are pruned on read so the dict stays bounded."""
        sid = self._primary_key(spoke_id)
        until = self._quarantine.get(sid)
        if until is None:
            return False
        if time.monotonic() >= until:
            self._quarantine.pop(sid, None)
            return False
        return True

    async def _protect_source_shed(self, p: dict) -> None:
        """Under protect, DISCONNECT the loudest talkers so the loop stops
        spending 100% CPU just reading their flood. This is the aggressive lever
        that pre-parse shedding lacks: dropping-after-read still costs the READ;
        closing the socket stops the cost, freeing loop time for real spokes'
        heartbeats (modules stay ONLINE) and /status (WebUI stays usable).

        Cheap + bounded: top-K by TRUE offered rate (``_spoke_offered``, counted
        before the shed) above a floor, so low-rate real modules are never
        touched. Shed spokes get a SHORT quarantine and reconnect after it — a
        sustained flood self-limits into a sawtooth the hub survives."""
        if not p["protect_shed_source"]:
            return
        floor = p["protect_shed_min_mps"]
        cands = [(sid, n) for sid, n in (self._spoke_offered or {}).items()
                 if n >= floor and self._primary_key(sid) in self.active_connections
                 and not self._is_quarantined(sid)]
        if not cands:
            return
        cands.sort(key=lambda x: x[1], reverse=True)
        topk = cands[:max(1, p["protect_shed_top_k"])]
        q = max(0.0, p["protect_quarantine_s"])
        now = time.monotonic()
        for sid, n in topk:
            self._quarantine[sid] = now + q
            self.record_spoke_event(sid, "protect_shed",
                                    f"protect: loudest talker (~{n}/s) disconnected to "
                                    f"relieve the loop; quarantined {q:.0f}s")
            ws = self.active_connections.get(self._primary_key(sid))
            if ws is not None:
                try:
                    await ws.close(1013, "Hub overloaded — shedding loudest talkers")
                except Exception as e:  # noqa: BLE001
                    logger.debug("[protect] source-shed close of %s failed: %s", sid, e)
        logger.error("[protect] SOURCE-SHED — disconnected %d loudest talker(s) "
                     "(%s) + quarantined %.0fs to free the loop for real spokes.",
                     len(topk), ", ".join(f"{s}:{n}/s" for s, n in topk[:5]), q)

    async def _signal_backoff(self, spoke_id: str, level: int, min_interval: float) -> None:
        """Send one LM_BACKPRESSURE notification to a spoke (fire-and-forget).
        level 0 = resume, 1 = offender slow-down, 2 = fleet slow-down. The CALLER
        decides when to (re-)signal — on a level change OR a material change in
        the adaptive interval — so no level dedup here (that would swallow an
        interval escalation). Records both so the caller can diff next tick."""
        self._backoff_signaled[spoke_id] = level
        self._backoff_interval[spoke_id] = min_interval
        await self.send_to_spoke_command(spoke_id, "LM_BACKPRESSURE", {
            "level": level,
            "coalesce": level > 0,
            "min_interval_s": min_interval,
            "reason": {0: "clear", 1: "offender", 2: "fleet"}.get(level, "slow"),
        })
        # Per-spoke detail at DEBUG — the ladder emits a human-readable SUMMARY
        # line at WARNING (flows to the WebUI Logs view via HubLogHandler) so a
        # fleet-wide transition doesn't flood Logs with one line per spoke.
        logger.debug("[backpressure] %s spoke=%s level=%d min_interval=%.1fs",
                     "SLOW" if level else "RESUME", spoke_id, level, min_interval)

    async def run_coalesce_drain_loop(self):
        """Rung-3 safety net (last resort). Process at most ONE latest telemetry
        snapshot per spoke each cycle; frames that arrived and were superseded
        before their turn were already merged away (latest-wins) in the message
        loop. Work is bounded by spoke-count, not inbound rate — so must-process
        frames on the main loop keep getting serviced while a burst drains.

        The REAL merge work belongs on the spoke (it coalesces before sending);
        this only catches the in-flight burst before the slow-down signal lands."""
        logger.info("Coalesce drain loop started (rung-3 backpressure safety net).")
        while True:
            try:
                p = self._backpressure_params()
                await asyncio.sleep(max(0.2, p["hub_drain_interval_s"]))
                # If protect is active the loop is parse-bound; running hundreds
                # of ingests here just compounds it. Drop the buffer (snapshots
                # are superseded anyway) and let protect shed. This is the fix for
                # the drain becoming a CPU sink at ~800 spokes.
                if self._protect_mode or not self._coalesce_pending:
                    if self._coalesce_pending:
                        self._telemetry_coalesced += len(self._coalesce_pending)
                        self._coalesce_pending = {}
                    continue
                pending = self._coalesce_pending
                self._coalesce_pending = {}
                # BUDGET + TIME-BOX: process at most drain_budget spokes and never
                # spend more than drain_max_s on the loop. The remainder are
                # counted as coalesced (superseded) — bounded work regardless of
                # how many spokes are throttled.
                budget = max(1, p["hub_drain_budget"])
                deadline = time.monotonic() + max(0.01, p["hub_drain_max_s"])
                done = 0
                for sid, (data, _ts) in pending.items():
                    if done >= budget or time.monotonic() >= deadline:
                        self._telemetry_coalesced += 1  # dropped/superseded
                        continue
                    try:
                        await self._handle_cs_telemetry(sid, data)
                        self._telemetry_processed += 1
                        done += 1
                    except Exception as e:  # noqa: BLE001
                        logger.debug("[coalesce] drain %s failed: %s", sid, e)
            except Exception as e:  # noqa: BLE001 — never let the drain die
                logger.debug("[coalesce] drain loop iteration skipped: %s", e)

    async def run_tenant_sync_loop(self):
        """Periodically pull tenants from the NetBox spoke and upsert into hub state."""
        await asyncio.sleep(30)  # let spokes connect first
        while True:
            try:
                spoke_id = self.get_spoke_by_type("ipam")
                if spoke_id:
                    result = await self.request_response(spoke_id, "NETBOX_GET_TENANTS", {}, timeout=30.0)
                    data = result.get("payload", {}).get("data", result) if isinstance(result, dict) else {}
                    if isinstance(data, dict) and data.get("status") == "SUCCESS":
                        for t in data.get("tenants", []):
                            slug = t["slug"]
                            cfg = self.state.get_tenant(slug) or {}
                            self.state.update_tenant(slug, {
                                "name": t["name"],
                                "netbox_tenant_slug": slug,
                                "netbox_id": t["id"],
                                "description": t.get("description", ""),
                                **{k: v for k, v in cfg.items() if k not in ("name", "netbox_tenant_slug", "netbox_id", "description")},
                            })
                        self.state._mark_dirty()
                        logger.debug(f"Tenant sync: {len(data.get('tenants', []))} tenant(s) from NetBox")
            except Exception as e:
                logger.debug(f"Tenant sync skipped: {e}")
            await asyncio.sleep(300)  # every 5 minutes

    # ── IPAM → CPPM endpoint sync → core/src/endpoint_sync.py (EndpointSyncMixin) ──
    # IPAM_SOURCES, _endpoint_sync_cfg/_source/_tenants/_next_delay, _ipam_scope_for_tenant,
    # tenant_id_for_ipam_scope, sync_tenant_endpoints, trigger_endpoint_sync, run_endpoint_sync_loop
    # moved to EndpointSyncMixin (added to LabManagerHub bases); all hub.* call sites unchanged.

    async def run_pxmx_diag_loop(self):
        """Emit spoke-health diagnostics into the hub log (the logging telemetry).

        The hub log flows to BOTH the WebUI (/setup/logs/all) and the BugFixer
        agent (HUB_REQUEST GET_LOGS -> collect_all_logs) via HubLogHandler, so
        anything logged here is visible to a human in the Logs view and to
        bugfixer over the same channel — no separate file, no CLI curl. This
        replaces hitting the auth-protected /api/pxmx/* endpoints from the
        command line (a bare curl just gets {"detail":"Authentication required"}
        and tells you nothing) and gives bugfixer the same view it needs to fix
        things.

        Snapshot each cycle (~30s) and emit a [spoke-diag] line on meaningful
        state change (spoke connect/disconnect, hypervisor VM source/count/agent
        change, an expected spoke going missing, or the split-brain signature of
        pxmx connected but not registered as the hypervisor module) plus a
        ~10-minute heartbeat so a recent snapshot is always present. Event-driven
        to avoid flooding the 500-line hub log buffer.
        """
        # "expected" spokes are computed per-cycle from the APPROVED set (was a
        # static dedicated-id list — permanent false "missing" alerts in the
        # agent+role model, where ids are dynamic: {base} + {base}-{role}).
        await asyncio.sleep(20)  # let spokes connect first
        last: Dict[str, Any] = {}
        last_usb: List[str] = []
        cycle = 0
        while True:
            cycle += 1
            try:
                conns = list(self.active_connections.keys())
                mtypes = dict(self.spoke_module_types)
                hyp_sid = self.get_spoke_by_type("hypervisor")
                pxmx_sid = next((s for s in conns if "pxmx" in s), None)
                expected = sorted(s for s, ok in self.approved_modules.items() if ok)
                snap: Dict[str, Any] = {
                    "conns": conns,
                    "hyp": hyp_sid,
                    "pxmx_type": mtypes.get(pxmx_sid) if pxmx_sid else None,
                    "missing": [s for s in expected if s not in conns],
                    "src": None,
                    "agents": None,
                    "stale": None,
                    "vms": 0,
                }
                if hyp_sid:
                    try:
                        res = await self.request_response(hyp_sid, "PXMX_LIST_VMS", {}, timeout=8.0)
                        data = res.get("payload", {}).get("data", res) if isinstance(res, dict) else {}
                        snap["src"] = data.get("source")
                        snap["agents"] = data.get("agent_count")
                        snap["stale"] = data.get("stale")
                        snap["vms"] = len(data.get("vms", []))
                    except Exception as e:
                        snap["vms_err"] = str(e)
                    if pxmx_sid and mtypes.get(pxmx_sid) != "hypervisor":
                        snap["split_brain"] = True
                elif pxmx_sid:
                    # pxmx websocket is up but get_spoke_by_type("hypervisor")
                    # returned None — the module_type mapping is missing, i.e.
                    # the split-brain / unregistered-module signature.
                    snap["split_brain"] = True

                # Emit on change, or a ~10min heartbeat (cycle % 20 == 0).
                changed = snap != last
                if changed or cycle % 20 == 0:
                    parts = [
                        f"conns={','.join(conns) or '-'}",
                        f"hyp={hyp_sid or 'none'}",
                        f"src={snap.get('src')}",
                        f"vms={snap.get('vms')}",
                        f"agents={snap.get('agents')}",
                    ]
                    if snap.get("stale"):
                        parts.append("stale=true")
                    if snap.get("vms_err"):
                        parts.append(f"vms_err={snap['vms_err']}")
                    if snap["missing"]:
                        parts.append(f"missing={','.join(snap['missing'])}")
                    if snap.get("split_brain"):
                        parts.append("SPLIT_BRAIN=pxmx_connected_but_not_hypervisor")
                    if changed:
                        logger.info("[spoke-diag] " + " ".join(parts))
                    else:
                        logger.debug("[spoke-diag] (heartbeat) " + " ".join(parts))
                    last = snap

                # USB-availability telemetry: where each cached cs spoke put USB
                # data this cycle, so a missing USB count in the tenant VM Server
                # Overview/USB tab is diagnosable from System → Logs → hub (and
                # bugfixer GET_LOGS) instead of CLI curl. Emits a [usb-telemetry]
                # line on change + a ~10min heartbeat. One compact entry per cs
                # spoke host; lengths only (a CS payload may carry Proxmox tokens
                # in other frames, so never values).
                usb_parts: List[str] = []
                for sid, data in (getattr(self, "simulations_cache", {}) or {}).items():
                    try:
                        tid = self.state.get_spoke_tenant(sid)
                    except Exception:
                        tid = None
                    data = data or {}

                    def _len(v):
                        return len(v) if isinstance(v, list) else 0

                    hosts = data.get("proxmox_hosts")
                    if isinstance(hosts, list) and hosts:
                        for hh in hosts:
                            hh = hh or {}
                            hpx = hh.get("proxmox") or {}
                            vms = _len(hh.get("proxmox_vms"))
                            pres = _len(hpx.get("present_usb"))
                            unk = _len(hpx.get("unknown_usb"))
                            devs = _len(hh.get("usb_devices"))
                            usb_parts.append(
                                f"cs={sid} tenant={tid} host={hh.get('hostname') or '?'} "
                                f"vms={vms} present={pres} unknown={unk} usb_devices={devs}"
                                + ("" if (pres or unk or devs) else " NO_USB_DATA"))
                    else:
                        px = data.get("proxmox") or {}
                        vms = _len(data.get("proxmox_vms"))
                        pres = _len(px.get("present_usb"))
                        unk = _len(px.get("unknown_usb"))
                        devs = _len(data.get("usb_devices"))
                        usb_parts.append(
                            f"cs={sid} tenant={tid} host=legacy "
                            f"vms={vms} present={pres} unknown={unk} usb_devices={devs}"
                            + ("" if (pres or unk or devs) else " NO_USB_DATA"))
                if not usb_parts:
                    usb_parts = ["none (no cached cs spoke)"]
                if usb_parts != last_usb:
                    logger.info("[usb-telemetry] " + " | ".join(usb_parts)
                                + (" | NO_USB_DATA means the cs spoke reports VMs but no USB — "
                                   "it is not aggregating USB into its CS_TELEMETRY payload"
                                   if any("NO_USB_DATA" in p for p in usb_parts) else ""))
                    last_usb = usb_parts
                elif cycle % 20 == 0:
                    logger.debug("[usb-telemetry] (heartbeat) " + " | ".join(usb_parts))
            except Exception as e:
                logger.warning(f"[spoke-diag] loop error: {e}")
            await asyncio.sleep(30)

    # spoke_id prefix -> systemd unit, mirroring the spoke-side
    # get_service_name() (control_plane.py: returns lm-<module>). Used by the
    # recovery watchdog to map an approved-but-disconnected spoke to the unit
    # the root helper restarts. In-repo spokes lm-dns/lm-dhcp are covered here
    # too (the hub already restarts them on its own update at main.py:1058; the
    # watchdog also recovers them if they strand independently).
    _SPOKE_UNIT_PREFIX = {
        "cs": "lm-cs", "pxmx": "lm-pxmx", "opn": "lm-opnsense",
        "cppm": "lm-cppm", "netbox": "lm-netbox", "ldap": "lm-ldap",
        "dns": "lm-dns", "dhcp": "lm-dhcp",
    }

    def _spoke_unit(self, spoke_id: str) -> str:
        """spoke_id -> systemd unit, or '' if it has no own unit.

        Agent-spoke model: a generic agent (module_type 'agent') runs a single
        ``lm-agent`` unit that hosts all its role sub-spokes IN-PROCESS, so the
        agent maps to lm-agent and a role sub-spoke ``{base}-{role}`` has NO own
        unit — it doesn't match a dedicated prefix, returns '', and the parent
        agent's lm-agent recovery covers it. Legacy dedicated spokes still map
        by id prefix to lm-<module> (e.g. 'cs-spoke-1' -> 'lm-cs'). module_type
        is read live, then from persisted metadata so an offline agent still
        resolves to lm-agent.
        """
        mt = self.spoke_module_types.get(spoke_id) or \
            (self.state.system_state.get("module_metadata", {}).get(spoke_id, {}) or {}).get("module_type")
        if mt == "agent":
            return "lm-agent"
        for prefix, unit in self._SPOKE_UNIT_PREFIX.items():
            if spoke_id.startswith(prefix):
                return unit
        return ""

    async def _recovery_inspect(self, unit: str) -> dict:
        """Read-only unit state via the root helper. Returns {} on error.

        Async so the sudo call (up to ~10s) doesn't block the event loop — the
        watchdog runs alongside live spoke WebSocket traffic, and a blocking
        subprocess.run would stall heartbeats/relays for every stranded spoke
        it inspects in a pass.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", "/usr/local/bin/lm-spoke-recover", "--inspect", unit,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                logger.warning(f"[recovery] inspect timed out for {unit}")
                return {}
            stdout = (stdout_b or b"").decode(errors="replace")
            if proc.returncode != 0 or not stdout.strip():
                return {}
            return json.loads(stdout.strip())
        except Exception as e:
            logger.warning(f"[recovery] inspect failed for {unit}: {e}")
            return {}

    async def run_spoke_recovery_loop(self):
        """Watchdog: recover approved-but-stranded spokes and surface it.

        Restart=always self-heals a clean exit, but it CANNOT revive a unit that
        crash-looped into systemd `failed` (e.g. cs status=203/EXEC when the
        venv/interpreter was missing) — `restart` won't start a `failed` unit
        without `reset-failed`. This loop detects an approved spoke that is
        disconnected AND heartbeat-stale (RED, >= ~300s — long enough that a
        spoke mid-SPOKE_UPDATE self-restart, which takes ~1-2s, is never
        mistaken for a strand) and recovers its unit via the
        /usr/local/bin/lm-spoke-recover root helper (inspect -> reset-failed if
        SubState==failed -> restart). Backoff 60/120/180s.

        Give up (and hand off to bugfixer to file an issue) on any of:
          - 3 failed restarts (still disconnected across the backoff schedule),
          - the SAME crash signature repeating (a restart structurally can't
            fix it — e.g. a missing venv — so don't burn all 3 retries),
          - StartLimitBurst (unit failed with high NRestarts and re-failing),
          - a manual_pause flag (set from the WebUI Diagnostics "Pause" button).

        Every action is recorded as a spoke_event (WebUI timeline) AND a
        greppable [recovery] log line (hub log -> WebUI Logs + bugfixer GET_LOGS)
        so the whole recovery is visible without CLI. Per-spoke recovery state is
        exposed via GET_SPOKE_STATUS + /setup/diagnostics so bugfixer can suppress
        filing while the hub is recovering and escalate only on give_up.
        """
        await asyncio.sleep(30)  # let spokes connect + first heartbeats arrive
        backoff = (60, 120, 180)
        while True:
            try:
                now = time.time()
                approved = {s for s, a in self.approved_modules.items() if a}
                conns = set(self.active_connections.keys())

                # Clear recovery state for spokes that came back online.
                for sid in list(self.spoke_recovery.keys()):
                    st0 = self.spoke_recovery[sid]
                    if sid in conns and (st0.get("attempts") or st0.get("gave_up")):
                        self.spoke_recovery[sid] = {"attempts": 0}
                        self.record_spoke_event(sid, "recovery_cleared", "spoke reconnected")
                        logger.info(f"[recovery] spoke_id={sid} action=cleared reason=reconnected")

                for sid in sorted(approved - conns):
                    # Only act on a TRUE strand: disconnected AND heartbeat RED
                    # (>=300s stale or never seen). A spoke mid-self-restart is
                    # only down ~1-2s, so its heartbeat is still fresh -> skipped.
                    if str(self.heartbeat.get_status(sid)) != "RED":
                        continue
                    unit = self._spoke_unit(sid)
                    if not unit:
                        continue
                    st = self.spoke_recovery.setdefault(sid, {"attempts": 0})
                    if st.get("manual_pause") or st.get("gave_up"):
                        continue
                    if now < st.get("next_retry_ts", 0):
                        continue

                    info = await self._recovery_inspect(unit)
                    sub = info.get("SubState", "")
                    result = info.get("Result", "")
                    ems = info.get("ExecMainStatus", "")
                    nrest = info.get("NRestarts", "0")
                    try:
                        nrest_i = int(nrest) if str(nrest).lstrip("-").isdigit() else 0
                    except Exception:
                        nrest_i = 0
                    # Unit not installed/loaded -> not a recoverable strand; skip
                    # without burning attempts (e.g. an approved-but-undeployed spoke).
                    if not info.get("ActiveState"):
                        continue
                    crash_sig = f"{sub}/{result}/{ems}"
                    attempts = int(st.get("attempts", 0))

                    # --- Give-up classification (checked BEFORE recovering) ---
                    give_up, reason = False, ""
                    if attempts >= 1 and st.get("last_crash_sig") == crash_sig and crash_sig != "//":
                        give_up, reason = True, f"same crash signature {crash_sig}"
                    elif sub == "failed" and nrest_i >= 5 and attempts >= 1:
                        give_up, reason = True, f"StartLimitBurst (NRestarts={nrest_i})"
                    elif attempts >= 3:
                        give_up, reason = True, "3 failed restarts"

                    if give_up:
                        st.update({"gave_up": True, "in_progress": False,
                                   "last_action": "gave_up", "last_error": reason,
                                   "last_crash_sig": crash_sig})
                        self.record_spoke_event(sid, "recovery_gave_up", reason)
                        logger.warning(
                            f"[recovery] spoke_id={sid} unit={unit} GAVE_UP "
                            f'reason="{reason}" last_crash_sig={crash_sig}')
                        continue

                    # --- Recover: reset-failed (if failed) + restart ---
                    # Async subprocess so the sudo call (up to ~15s) doesn't
                    # block the event loop while the restart runs.
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "sudo", "-n", "/usr/local/bin/lm-spoke-recover", unit,
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                        )
                        try:
                            stdout_b, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                        except asyncio.TimeoutError:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                            stdout_b = b""
                        stdout = (stdout_b or b"").decode(errors="replace")
                        rec = json.loads(stdout.strip()) if stdout.strip() else {}
                        reset = bool(rec.get("reset", False))
                    except Exception as e:
                        reset = False
                        rec = {"error": str(e)}
                    attempts += 1
                    st.update({
                        "attempts": attempts,
                        "last_attempt_ts": now,
                        "next_retry_ts": now + backoff[min(attempts - 1, len(backoff) - 1)],
                        "last_crash_sig": crash_sig,
                        "last_action": "restart",
                        "last_error": "",
                        "gave_up": False,
                        "in_progress": True,
                    })
                    detail = f"attempt={attempts}/3 reset={reset} pre={crash_sig}"
                    self.record_spoke_event(sid, "recovery_restart", detail)
                    logger.info(
                        f"[recovery] spoke_id={sid} unit={unit} action=restart "
                        f"reason=stranded attempt={attempts}/3 pre={crash_sig} reset={reset}")
            except Exception as e:
                logger.warning(f"[recovery] loop error: {e}")
            await asyncio.sleep(30)

    def record_spoke_event(self, spoke_id: str, event: str, detail: str = "") -> None:
        """
        Append a structured connection-lifecycle event for a spoke.

        Called at every handshake/loop/disconnect point in handle_connection
        so the WebUI can render a per-spoke timeline instead of guessing from
        a single OFFLINE flag. Also mirrored to the hub log for journalctl.
        """
        if not spoke_id:
            return
        sid = self._primary_key(spoke_id)
        buf = self.spoke_events.setdefault(sid, deque(maxlen=self.spoke_event_limit))
        buf.append({
            "ts": time.time(),
            "event": event,
            "detail": detail,
        })
        logger.info(f"[spoke-event] {spoke_id} {event}" + (f": {detail}" if detail else ""))

    def get_spoke_events(self, spoke_id: str, limit: int = 50) -> list:
        """Most-recent-first lifecycle events for a spoke (for the WebUI)."""
        buf = self.spoke_events.get(self._primary_key(spoke_id))
        if not buf:
            return []
        out = list(buf)[-limit:]
        out.reverse()
        return out

    def get_spoke_log_events(self, spoke_id: str, limit: int = 30) -> list:
        """Most-recent WARNING/ERROR/CRITICAL RELAYED LOG lines for a spoke — the
        operational errors/warnings surfaced in the per-spoke events panel so an
        operator sees actual failures, not just connection-lifecycle events. Parses
        the relayed log format ``<asctime> - <name> - <levelname> - <msg>`` from
        ``agent_logs[spoke_id]``; lines that don't parse or are below WARNING are
        skipped. Newest first, capped at ``limit``."""
        buf = self.agent_logs.get(self._primary_key(spoke_id))
        if not buf:
            return []
        levels = {"WARNING", "ERROR", "CRITICAL"}
        out = []
        for entry in list(buf):
            line = entry if isinstance(entry, str) else str(entry)
            parts = line.split(" - ", 3)
            if len(parts) < 4:
                continue
            level = parts[2].strip()
            if level not in levels:
                continue
            out.append({"ts_str": parts[0].strip(), "level": level,
                        "name": parts[1].strip(), "msg": parts[3].strip()})
        out.reverse()
        return out[:limit]

    def _rate_limit_params(self) -> tuple:
        """(capacity, fill_rate) for the per-spoke TokenBucket, read fresh from
        ``global_config["rate_limit"]`` so the knob can be tuned for scale /
        system resources without a code change.

        Defaults 400 / 200 (burst 400, 200 msg/s). This is a FLOOD guard, NOT a
        normal-operation shaper: it must sit well ABOVE any legitimate spoke's
        peak (a relay spoke fanning many hosted agents + a reconnect re-flush can
        legitimately burst to tens of msg/s) so normal traffic is NEVER dropped
        and NEVER mistaken for an offender. The old 10/5 default was far below a
        real relay spoke's rate. Aggregate overload (many spokes each UNDER this
        limit) is the FLEET layer's job (rung 2) + surgical protect shed, NOT
        this per-spoke bucket. Clamped to sane minimums so a bad config can't
        wedge delivery."""
        try:
            cfg = (self.state.get_global_config() or {}).get("rate_limit", {}) or {}
            cap = float(cfg.get("capacity", 400))
            rate = float(cfg.get("fill_rate", 200))
        except Exception:
            cap, rate = 400.0, 200.0
        return (max(1.0, cap), max(0.1, rate))

    async def get_system_metrics(self) -> Dict[str, Any]:
        """
        Collects CPU, Memory, and Disk metrics.
        """
        try:
            # cpu_percent(interval=None) is non-blocking (delta since the last
            # call) so it stays live. virtual_memory() + disk_usage('/') are
            # statvfs/sysctl syscalls on the event loop; /status is polled every
            # ~10s by every open tab, so cache their result for ~5s. Host RAM/disk
            # don't move meaningfully within a 5s window, and this keeps the
            # blocking syscalls off the hot path when many tabs poll at once.
            cpu = psutil.cpu_percent(interval=None)
            _mnow = time.time()
            _hm = getattr(self, "_host_metrics_cache", None)
            if _hm is not None and (_mnow - _hm[0]) < 5.0:
                mem, disk = _hm[1], _hm[2]
            else:
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                self._host_metrics_cache = (_mnow, mem, disk)
            # The footer version is what THIS process is RUNNING, not what's on
            # disk: get_local_version() re-reads the VERSION file every /status
            # call, so right after a `git pull` bumps VERSION it would show the
            # new version while the hub is still serving the OLD code — a
            # misleading "I'm on .573" while the running process is .572. The
            # in-memory _startup_version (captured once at boot from the same
            # file) is the running version; it only moves when the process
            # actually restarts. Fall back to the disk read only before start()
            # sets _startup_version (a pre-ready /status poll).
            version = getattr(self, "_startup_version", None) or await self.get_local_version()

            # get_all_pending() is O(backlog); queue_size and backlog are the same
            # count, so scan ONCE and reuse len() for both (was scanning twice).
            # backlog_stats() below is its own pass — it produces the by-type/
            # by-spoke/oldest breakdown that can't be derived from the flat list —
            # and is skipped entirely in protect mode.
            _pending_count = len(self.mailbox.get_all_pending())

            return {
                "cpu_util": cpu,
                "mem_util": mem.percent,
                "disk_util": disk.percent,
                "disk_free": disk.free // (1024 * 1024), # MB
                "disk_total": disk.total // (1024 * 1024), # MB
                "queue_size": _pending_count,
                "backlog": _pending_count,
                # Backlog breakdown (by type / by spoke / oldest age) so a
                # stuck backlog is diagnosable in System → Hub Status. Skipped in
                # protect mode — it iterates the mailbox (O(backlog)) and /status
                # must stay CHEAP so it's readable while the loop is saturated.
                "backlog_stats": ({} if self._protect_mode else self.mailbox.backlog_stats()),
                # Overload self-protection state (shed heavy reads + telemetry).
                "protect": bool(self._protect_mode),
                "protect_reason": self._protect_reason,
                # Per-spoke inbound msg/s (for the Spokes/Agents tiles).
                "spoke_mps": {sid: round(v, 1) for sid, v in self.spoke_mps.items()},
                # Rate-limit drop counters (per spoke) + the live knob values.
                "rate_limit_drops": dict(self.rate_limit_drops),
                "rate_limit_drops_total": sum(self.rate_limit_drops.values()),
                "rate_limit": {"capacity": self._rate_limit_params()[0],
                               "fill_rate": self._rate_limit_params()[1]},
                # Escalation-ladder state (cheap dicts — safe to include even in
                # protect mode). load_level: 0 normal / 1 offenders-throttled /
                # 2 fleet-throttled. telemetry_* prove coalescing (not dropping);
                # probe_* prove must-process frames survive with zero gaps.
                "load_level": self._load_level,
                "backpressure": {
                    "level": self._load_level,
                    "fleet": bool(self._fleet_backoff),
                    # Current adaptive slow-down interval (s) the fleet is asked to
                    # conflate to — climbs with CPU. Visible so you can see the
                    # hub pushing the fleet down HARDER as it heats up.
                    "fleet_interval_s": round(self._fleet_interval, 1),
                    "spokes_throttled": sorted(self._spoke_backoff),
                    # Per-spoke level (1 = offending, 2 = fleet-throttled) so the
                    # WebUI can badge each spoke/agent tile distinctly.
                    "spoke_levels": {sid: lvl for sid, lvl in self._backoff_signaled.items() if lvl},
                    # DDoS: spokes currently disconnected + in reconnect cooldown.
                    "quarantined": [s for s in list(self._quarantine) if self._is_quarantined(s)],
                    "coalesce_pending": len(self._coalesce_pending),
                    "telemetry_received": self._telemetry_received,
                    "telemetry_processed": self._telemetry_processed,
                    "telemetry_coalesced": self._telemetry_coalesced,
                },
                "probe_counts": {sid: st["count"] for sid, st in self._probe_state.items()},
                "probe_gaps": {sid: st["gaps"] for sid, st in self._probe_state.items() if st["gaps"]},
                "mps": self.mps,
                "throughput": self.throughput_mbps,
                "version": version,
                # Auto-heal watchdog status (armed / last heartbeat) so the WebUI
                # can show it's alive — populated by run_watchdog_bridge_loop.
                # The version-drift keys (behind / target_version / running_version /
                # update_available) are recomputed LIVE here and merged OVER the
                # cached dict so the footer dot is correct on EVERY /status, not
                # just after the 20s bridge loop has run. The cached copy alone was
                # insufficient: it is empty {} for the first ~20-40s after a restart
                # (dot green while disk may already be ahead), only refreshes every
                # 20s, and shares a try-block with an 8s `systemctl` subprocess — so
                # a systemctl hang/failure aborts the whole status update and the
                # drift keys never get written → dot stuck green. _compute_version_drift
                # is a cheap sync file-read; safe to call inline on /status.
                "watchdog": self._live_watchdog_status(),
            }
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            return {
                "cpu_util": 0,
                "mem_util": 0,
                "disk_util": 0,
                "disk_free": 0,
                "disk_total": 0,
                "queue_size": len(self.mailbox.get_all_pending()) if hasattr(self, 'mailbox') else 0,
                "backlog": len(self.mailbox.get_all_pending()) if hasattr(self, 'mailbox') else 0,
                "mps": getattr(self, 'mps', 0.0),
                "throughput": getattr(self, 'throughput_mbps', 0.0),
                "version": "unknown"
            }

    async def poll_opnsense_rules(self, firewall_id: str = None):
        """
        Polls OPNsense for all firewall rules and caches them locally and in-memory.
        """
        logger.info(f"Polling OPNsense firewall rules (ID: {firewall_id or 'Default'})...")

        if firewall_id:
            spoke_id = self.get_spoke_for_firewall(firewall_id)
            if not spoke_id:
                logger.error(f"OPNsense polling failed: No spoke found for firewall {firewall_id}")
                return False
        else:
            opn_spoke = next((sid for sid in self.active_connections if "opn" in sid), None)
            if not opn_spoke:
                logger.error("OPNsense polling failed: No OPNsense spoke connected")
                return False
            spoke_id = opn_spoke

        # CRITICAL FIX: Only attempt polling if the spoke is actually connected
        if self._primary_key(spoke_id) not in self.active_connections:
            logger.warning(f"Skipping OPNsense polling: Spoke {spoke_id} is not currently connected")
            return False

        try:
            # 30s, not the 5.0s default: the spoke answers via a curl subprocess
            # with --max-time 15, so the 5s default guaranteed a timeout on any
            # cold/WAN spoke and left the forensic cache empty.
            result = await self.request_response(spoke_id, "OPNSENSE_GET_ALL_RULES", {}, timeout=30.0)

            data = {}
            if isinstance(result, dict):
                if "data" in result:
                    data = result["data"]
                elif "payload" in result and isinstance(result["payload"], dict):
                    data = result["payload"].get("data", {})
                else:
                    data = result
            else:
                data = result

            if not data:
                logger.warning(f"OPNsense polling returned empty data for {spoke_id}")
                return False

            cache_key = firewall_id or spoke_id

            # Forensic on-disk snapshot only — the firewall routes always fetch
            # live from the spoke (OPNSENSE_GET_RULES_BY_IP), so nothing in the
            # app reads this back. Kept so an operator can `cat` the last-known
            # ruleset for a firewall after a spoke goes down. The previous
            # in-memory `firewall_caches`/`opnsense_cache` dicts were write-only
            # dead state and have been removed.
            try:
                cache_filename = f"rules_{cache_key}.json"
                cache_path = os.path.join(self.cache_dir, cache_filename)

                def _write_cache():
                    if not os.path.exists(self.cache_dir):
                        os.makedirs(self.cache_dir, exist_ok=True)
                    with open(cache_path, "w") as f:
                        json.dump(data, f)

                # Offload the synchronous makedirs + json.dump off the hub loop
                # (a large ruleset can take long enough to stall heartbeats /
                # request_response — same class as the cs-svr-02 I/O starvation).
                await asyncio.to_thread(_write_cache)
                logger.info(f"OPNsense rules cached to {cache_path}")
            except Exception as e:
                logger.error(f"Failed to persist OPNsense cache to disk for {cache_key}: {e}")

            return True
        except Exception as e:
            logger.error(f"Error during OPNsense rule polling for {spoke_id}: {e}")
            return False

    async def run_key_rotation_loop(self):
        """
        Background loop that monitors and executes the periodic rotation of
        cryptographic secrets for both spokes and the Hub.
        """
        logger.info("Key rotation monitoring loop started.")
        while True:
            try:
                due_spokes = self.key_manager.get_keys_due_for_rotation(days=30)
                # Rotate keys (local crypto — fast, sequential) then push the new
                # secrets to all due spokes concurrently. Sequential sends at
                # hundreds of spokes made a rotation pass take N round-trips.
                rotated = []
                for sid in due_spokes:
                    if sid in self.active_connections:
                        logger.info(f"Rotating session key for spoke {sid} (due for rotation)")
                        # Capture the secret the spoke currently holds BEFORE
                        # rotate_key flips current to the new one, so we can
                        # sign the delivery push with it (the spoke can't verify
                        # a frame signed with the new secret it hasn't installed).
                        prev_secret = self.key_manager.current_session_secret(sid)
                        new_key = self.key_manager.rotate_key(sid)
                        msg = Message(
                            header=MessageHeader(
                                message_id=str(uuid.uuid4()),
                                timestamp=time.time(),
                                sender_id="hub",
                                destination_id=sid
                            ),
                            payload=MessagePayload(type="SPOKE_UPDATE_SESSION_KEY", data={"secret": new_key.secret})
                        )
                        rotated.append((sid, msg, prev_secret))

                async def _push_session_key(sid, msg, prev_secret):
                    try:
                        await self.send_to_spoke(msg, signing_secret=prev_secret)
                        logger.info(f"New session key pushed to {sid}")
                    except Exception as e:
                        logger.error(f"Failed to push session key to {sid}: {e}")

                if rotated:
                    await asyncio.gather(*(_push_session_key(sid, msg, prev) for sid, msg, prev in rotated))

                global_config = self.state.get_global_config()
                last_root_rot = global_config.get("last_hub_root_rotation", 0)

                if (time.time() - last_root_rot) > (30 * 24 * 3600):
                    logger.info("Rotating Hub root secret (30-day interval)...")
                    new_root_secret = self.key_manager.rotate_hub_secret()

                    global_config["last_hub_root_rotation"] = time.time()
                    self.state.system_state["global_config"] = global_config
                    await self.state.save_state_now()

                    root_msgs = [
                        (sid, Message(
                            header=MessageHeader(
                                message_id=str(uuid.uuid4()),
                                timestamp=time.time(),
                                sender_id="hub",
                                destination_id=sid
                            ),
                            payload=MessagePayload(type="SPOKE_SET_HUB_SECRET", data={"hub_secret": new_root_secret})
                        ))
                        for sid, approved in self.approved_modules.items() if approved
                    ]

                    async def _push_root_secret(sid, msg):
                        try:
                            await self.send_to_spoke(msg)
                        except Exception as e:
                            logger.error(f"Failed to push new hub secret to {sid}: {e}")

                    if root_msgs:
                        await asyncio.gather(*(_push_root_secret(sid, msg) for sid, msg in root_msgs))

                    logger.info("Hub root secret rotated and pushed to all approved spokes.")

            except Exception as e:
                logger.error(f"Error in key rotation loop: {e}", exc_info=True)

            await asyncio.sleep(3600) # Check every hour
    async def run_opnsense_polling_loop(self):
        """
        Background loop that polls OPNsense rules at the configured interval for all configured firewalls.
        """
        logger.info("OPNsense polling loop started.")
        while True:
            try:
                config = self.state.get_global_config()
                # Clamp >= 1h: a 0 (or negative) config value would make the
                # loop sleep(0) and busy-loop poll_opnsense_rules across every
                # firewall as fast as the event loop allows. Every sync mixin
                # clamps >= 60s; this loop is the lone one that didn't.
                try:
                    interval_hours = max(1, int(config.get("opnsense_poll_interval", 1)))
                except (TypeError, ValueError):
                    interval_hours = 1

                firewalls = config.get("firewalls", [])
                opn_firewalls = [fw for fw in firewalls if fw.get("model") == "opnsense"]

                if not opn_firewalls:
                    logger.info("No OPNsense firewalls configured to poll.")
                else:
                    for fw in opn_firewalls:
                        await self.poll_opnsense_rules(firewall_id=fw["id"])

                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                logger.error(f"Error in OPNsense polling loop: {e}")
                await asyncio.sleep(300) # Retry after 5 mins on error

    # ── mDNS hub broadcast ──────────────────────────────────────────────────
    # Advertise _lm-hub._tcp.local. on the spoke-WS port so spokes/agents on the
    # same LAN auto-locate the hub with zero config (see messaging.hub_discovery).
    # zeroconf is an optional dep: a missing import or any registration failure
    # is logged once and skipped — it must never break the hub.
    _mdns_zconf = None
    _mdns_info = None
    _mdns_warned = False

    def _local_ipv4s(self) -> List[str]:
        """Non-loopback IPv4s of this host, primary LAN IP first.

        Uses the UDP-connect trick to find the primary outbound interface, then
        adds any other non-loopback IPv4s psutil sees (multi-homed hubs advertise
        all reachable addresses)."""
        ips: List[str] = []
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("223.255.255.1", 1))  # RFC 5737 — never routed
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127.") and ip not in ips:
                    ips.append(ip)
            finally:
                s.close()
        except Exception:
            pass
        try:
            for _name, addrs in psutil.net_if_addrs().items():
                for a in addrs:
                    fam = getattr(a, "family", None)
                    addr = getattr(a, "address", "")
                    if fam == socket.AF_INET and addr and not addr.startswith("127.") and addr not in ips:
                        ips.append(addr)
        except Exception:
            pass
        return ips or ["127.0.0.1"]

    def _hub_version_str(self) -> str:
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")
            with open(version_path, "r") as f:
                return f.read().strip() or "unknown"
        except Exception:
            return "unknown"

    def _build_hub_service_info(self):
        """Construct the zeroconf ServiceInfo for the hub (or None if zeroconf
        is unavailable). Caller handles registration on a daemon thread."""
        try:
            from zeroconf import ServiceInfo, Zeroconf  # noqa: F401
        except ImportError:
            if not LabManagerHub._mdns_warned:
                LabManagerHub._mdns_warned = True
                logger.warning("zeroconf not installed — hub will not broadcast "
                               "mDNS; spokes must use the lm-hub DNS name or --hub.")
            return None
        import socket as _sock
        ips = self._local_ipv4s()
        addresses = [_sock.inet_aton(ip) for ip in ips]
        # TXT records:
        #   agent_port — the EXTERNAL dial port a pxmx agent uses to reach the
        #     agent-WS leg. Under the unified-443 merge that is the hub's single
        #     :443 surface (/ws/agent → byte-proxy to the co-located pxmx spoke's
        #     loopback LM_PXMX_AGENT_PORT, which is NOT advertised). Lets a pxmx
        #     agent discover its target port instead of hardcoding it.
        #   tls_port   — present when callers reach the hub over TLS (the hub
        #     serves wss itself, OR LM_HUB_ADVERTISE_TLS=1 for a proxy-TLS
        #     deployment); a remote caller's discovery switches to
        #     wss://<ip>:<tls_port>. Absent → plaintext.
        properties = _mdns_hub_properties(
            self._hub_version_str(),
            int(getattr(self, "external_agent_port", self.tls_port)),
            self.tls_port,
            getattr(self, "advertise_tls", self.tls_enabled))
        # Under the unified-443 merge the hub serves the spoke-WS on the SAME
        # 0.0.0.0:443 uvicorn as the WebUI/REST (/ws/spoke route), so the SRV
        # port a spoke-leg caller dials is tls_port (443 w/ TLS, 443 plain) —
        # NOT the retired 8765 bare-listener port. The agent leg dials the SAME
        # :443 surface (/ws/agent), which the hub byte-proxies to the co-located
        # pxmx spoke's loopback LM_PXMX_AGENT_PORT (8443, NOT advertised).
        srv_port = int(self.tls_port)
        return ServiceInfo(
            type_="_lm-hub._tcp.local.",
            name="lm-hub._lm-hub._tcp.local.",
            port=srv_port,
            addresses=addresses,
            server="lm-hub.local.",
            properties=properties,
        )

    def _start_mdns_broadcast(self) -> None:
        """Register the hub's mDNS service on a daemon thread (best-effort)."""
        try:
            from zeroconf import Zeroconf
        except ImportError:
            self._build_hub_service_info()  # emits the one-time warning
            return
        try:
            info = self._build_hub_service_info()
            if info is None:
                return
            zconf = Zeroconf()
            zconf.register_service(info)
            self._mdns_zconf = zconf
            self._mdns_info = info
            logger.info(f"mDNS: broadcasting _lm-hub._tcp.local. on port {self.port} "
                        f"(addresses={self._local_ipv4s()})")
        except Exception as e:
            logger.warning(f"mDNS broadcast failed (hub still runs, spokes must use "
                           f"--hub or the lm-hub DNS name): {e}")
            # Clean up any half-initialized registrar.
            self._stop_mdns_broadcast()

    def _stop_mdns_broadcast(self) -> None:
        """Unregister + close the mDNS broadcaster (best-effort, idempotent)."""
        zconf = self._mdns_zconf
        info = self._mdns_info
        self._mdns_zconf = None
        self._mdns_info = None
        if zconf is None:
            return
        try:
            if info is not None:
                zconf.unregister_service(info)
        except Exception:
            pass
        try:
            zconf.close()
        except Exception:
            pass

    def _asyncio_exception_relay(self, loop, context) -> None:
        """asyncio loop exception handler — logs unhandled task exceptions via
        the Hub logger (→ self.logs → Error Log + BugFixer) then defers to the
        default handler. See logging-observability-contract.md req 4."""
        from messaging.log_relay import format_asyncio_context
        exc = context.get("exception")
        msg = context.get("message") or "unhandled asyncio exception"
        detail = format_asyncio_context(context)
        if exc is not None:
            logger.error("Uncaught asyncio exception: %s%s", msg, detail, exc_info=exc)
        else:
            logger.error("asyncio error: %s%s", msg, detail)
        loop.default_exception_handler(context)

    async def start(self):
        """
        Starts the WebSocket server and background tasks.
        """
        # Route unhandled asyncio-task exceptions through the Hub logger → its
        # error log (sync excepthook installed in __init__). See req 4.
        try:
            _loop = asyncio.get_running_loop()
            _loop.set_exception_handler(self._asyncio_exception_relay)
            # Opt-in deep diagnosis: asyncio debug mode captures a source_traceback
            # for every task, so a "Task was destroyed but it is pending!" names the
            # CREATION site (the relay handler surfaces it). OFF by default — it
            # wraps every callback + emits slow-callback warnings, real overhead on
            # a busy hub — so gate it behind LM_ASYNCIO_DEBUG for a targeted hunt.
            if str(os.getenv("LM_ASYNCIO_DEBUG", "")).strip().lower() in ("1", "true", "yes", "on"):
                _loop.set_debug(True)
                logger.warning("asyncio debug mode ON (LM_ASYNCIO_DEBUG) — task "
                               "creation tracebacks captured; expect slow-callback overhead")
        except Exception:  # noqa: BLE001
            pass
        version = "unknown"
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")

            with open(version_path, "r") as f:
                version = f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load version file: {e}")

        # Unified :443 surface: ONE uvicorn server (HTTP/WebUI + /ws/spoke +
        # /ws/console + /ws/agent) on 0.0.0.0:<tls_port> (443), wss when a cert
        # is configured, plaintext on the same port otherwise. Server.serve() is
        # awaitable, so it runs as a task in THIS event loop — the /ws/spoke
        # route (handle_connection via StarletteWSAdapter), HTTP routes, and all
        # the hub background loops below share one loop (no cross-loop hazard
        # that the old daemon-thread uvicorn + main-loop websockets.serve split
        # had). Mirrors the cs spoke's in-loop uvicorn pattern.
        if self.tls_enabled:
            # Fail fast + loud on a broken cert so systemd surfaces a crash-loop
            # instead of silently serving plaintext on 0.0.0.0:443.
            _ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                _ctx.load_cert_chain(self.tls_cert_path, self.tls_key_path)
            except Exception as e:
                logger.error("TLS cert load failed: %s (cert=%s key=%s) — "
                             "hub NOT starting; fix the cert or unset "
                             "LM_TLS_CERT/LM_TLS_KEY to fall back to plaintext.",
                             e, self.tls_cert_path, self.tls_key_path)
                raise
            del _ctx
        listen_port = self.tls_port  # single unified port (443 w/ TLS, 443 plain)
        self._api_server = build_server(
            self, host=self.host, port=listen_port,
            tls_cert=self.tls_cert_path, tls_key=self.tls_key_path)
        self._api_task = asyncio.create_task(self._api_server.serve())
        _scheme = "wss" if self.tls_enabled else "ws"
        logger.info(f"Hub {version} unified surface on {_scheme}://{self.host}:{listen_port} "
                    f"(/ws/spoke, /ws/agent, /ws/console + WebUI/REST)")
        # Capture the VERSION this process booted with so the update-health check
        # can detect process-vs-disk drift (code updated on disk but not restarted).
        self._startup_version = version
        # Publish the RUNNING version to a file the watchdog reads for its
        # stale-detection — robust vs log-parsing the startup line, which can
        # rotate out of hub.log (the failure that left a stale hub undetected).
        try:
            _rvp = os.environ.get("LM_RUNNING_VERSION_FILE",
                                  "/var/lib/lm/state/running-version")
            os.makedirs(os.path.dirname(_rvp), exist_ok=True)
            with open(_rvp, "w") as _f:
                _f.write(str(version))
        except Exception:  # noqa: BLE001
            pass
        # Fresh process is current → satisfy + clear any pending watchdog restart
        # sentinel so a successful restart doesn't get restarted again.
        try:
            self._clear_watchdog_restart_sentinel()
        except Exception:  # noqa: BLE001
            pass

        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())
        repo_sync_task = asyncio.create_task(self.run_repo_sync_loop())
        watchdog_bridge_task = asyncio.create_task(self.run_watchdog_bridge_loop())
        statuspage_push_task = asyncio.create_task(self.run_statuspage_push_loop())
        mps_task = asyncio.create_task(self.run_mps_loop())
        coalesce_drain_task = asyncio.create_task(self.run_coalesce_drain_loop())
        opnsense_poll_task = asyncio.create_task(self.run_opnsense_polling_loop())
        rotation_task = asyncio.create_task(self.run_key_rotation_loop())
        threat_sweep_task = asyncio.create_task(self.run_threat_sweep_loop())
        alert_engine_task = asyncio.create_task(run_alert_loop(self))
        tenant_sync_task = asyncio.create_task(self.run_tenant_sync_loop())
        # NetBox → CPPM endpoint sync: pulls each tenant's endpoints from the
        # NetBox spoke and pushes them to the CPPM (ClearPass) spoke so
        # ClearPass Device Inventory is populated with tenant-tagged endpoints.
        # Also fired on-demand from the WebUI ("Sync now") and after any NetBox
        # edit via the LM module (trigger_endpoint_sync). See run_endpoint_sync_loop.
        endpoint_sync_task = asyncio.create_task(self.run_endpoint_sync_loop())
        # Hypervisor → NetBox VM sync: pulls each tenant's VMs from the pxmx
        # (Proxmox) spoke and pushes them to the NetBox spoke so NetBox's
        # virtualization records mirror live VMs (vCPUs/disk/cluster/primary_ip4,
        # tenant-tagged, replace-with-delete). Also fired on-demand from the
        # WebUI ("Sync now") and after a pxmx VM lifecycle edit
        # (trigger_vm_sync). See run_vm_sync_loop.
        vm_sync_task = asyncio.create_task(self.run_vm_sync_loop())
        # Firewall → NetBox device-discovery sync: pulls DHCP leases + the ARP
        # table from an OPNsense spoke, attributes each discovered device to a
        # tenant by prefix containment, and pushes per-tenant to the NetBox spoke
        # via NETBOX_SYNC_DEVICES (DCIM devices + IP records carrying
        # custom_fields.mac_address — which feeds the IPAM→CPPM endpoint sync for
        # static-IP devices DHCP can't see). Also fired on-demand from the WebUI
        # ("Sync now"). See run_fw_discovery_sync_loop (FwDiscoverySyncMixin).
        fw_discovery_sync_task = asyncio.create_task(self.run_fw_discovery_sync_loop())
        # Network Devices → NetBox device-discovery sync: per schedule (or
        # on-demand "Sync now") pull NW_GET_ARP from every device on every
        # connected nw spoke, attribute IP↔MAC records to tenants by prefix
        # containment, and push per-tenant to the netbox spoke via
        # NETBOX_SYNC_DEVICES (source="Network Devices" so the sink tags records
        # nw-owned). See run_nw_discovery_sync_loop (NwDiscoverySyncMixin).
        nw_discovery_sync_task = asyncio.create_task(self.run_nw_discovery_sync_loop())
        # NetBox → NW fleet import (reverse; NetBox = source of truth): imports
        # NetBox devices whose role matches the configured category into the nw
        # fleet, and prunes NetBox-sourced nw devices that no longer match. Manual
        # nw adds are written back to NetBox (add_nw_device). Config-gated;
        # on-demand "Sync now" via /setup/nw-netbox-import/run. See
        # run_nw_netbox_import_loop (NwDiscoverySyncMixin).
        nw_netbox_import_task = asyncio.create_task(self.run_nw_netbox_import_loop())
        # TrueNAS → NetBox inventory-discovery sync: per schedule (or on-demand
        # "Sync now") pull the TrueNAS appliance fleet from every connected
        # storage spoke, map each appliance to a NetBox dcim.device record
        # (tenant-tagged by the appliance's own tenant_id), and push per-tenant
        # to the netbox spoke via NETBOX_SYNC_DEVICES (source="TrueNAS" so the
        # sink tags records truenas-owned). Minimal counterpart to the nw
        # ARP-topology sync — appliances, not neighbors. See
        # run_truenas_discovery_sync_loop (TruenasDiscoverySyncMixin).
        truenas_discovery_sync_task = asyncio.create_task(self.run_truenas_discovery_sync_loop())
        # Realtime NAC → IPAM reverse sync: every ~1 min pull ClearPass Access
        # Tracker sessions (last 2 min) from the CPPM spoke, attribute by prefix,
        # and add to NetBox the MACs not already present (only-add-missing —
        # NetBox stays source of truth). The bidirectional counterpart to the
        # forward endpoint-sync loop above. See run_realtime_nac_sync_loop
        # (RealtimeIpamNacSyncMixin). Also fired on-demand from the WebUI.
        realtime_nac_sync_task = asyncio.create_task(self.run_realtime_nac_sync_loop())
        # NetBox → Unbound/Kea auto-sync: every ~5 min (global_config.dns_dhcp_sync
        # .interval) reconcile the DNS (Unbound) and DHCP (Kea) spokes to NetBox —
        # NetBox is the IPAM source of truth, so a reservation/DNS name added there
        # lands in Kea/Unbound without a manual "Sync now". Only-add-missing +
        # skips quietly when NetBox/DNS/DHCP spokes are offline. Shares its
        # extraction helpers with POST /api/dns/sync and /api/dhcp/sync so the
        # loop and the button can't diverge. See run_dns_dhcp_sync_loop
        # (DnsDhcpSyncMixin).
        dns_dhcp_sync_task = asyncio.create_task(self.run_dns_dhcp_sync_loop())
        # NetBox staleness sweep (cluster-wide): ages out sync-owned devices/VMs
        # not seen for stale_days → offline, and offline + decommissioned_at older
        # than delete_days → deleted (IPs free automatically). The lifecycle
        # counterpart to the last_seen custom field every sync stamps on each
        # detection. See run_staleness_sweep_loop (StalenessSweepMixin). Also
        # fired on-demand from the WebUI ("Sweep now").
        # Seed enabled=True defaults once so the registry's cleanup job actually
        # runs on a never-configured hub (the loop otherwise defaults disabled).
        self.seed_staleness_sweep_defaults()
        staleness_sweep_task = asyncio.create_task(self.run_staleness_sweep_loop())
        # Hub self-backup (SelfBackupMixin): on a schedule (backup_interval_hours)
        # takes a rotated, optionally Fernet-encrypted tarball of hub state +
        # the key/secret stores under <state_dir>/self-backup/, and optionally
        # pushes it to a remote host over scp using an admin-placed key file.
        # All config in global_config["self_backup"] (WebUI Setup → Self-Backup);
        # disabled by default — opt-in. See run_self_backup_loop.
        self.seed_self_backup_defaults()
        self_backup_task = asyncio.create_task(self.run_self_backup_loop())
        # Azure Key Vault DR (KeyVaultSchedulerMixin): rotate the local admin
        # password every rotate_days (break-glass → vault-only) and push a daily
        # min bootstrap backup, keeping `retain` days. Off until configured in
        # Setup → Azure → Key Vault. See run_key_vault_loop.
        key_vault_task = asyncio.create_task(self.run_key_vault_loop())
        pxmx_diag_task = asyncio.create_task(self.run_pxmx_diag_loop())
        # Per-module health heartbeat for the Hub itself. Emits a greppable
        # [heartbeat] line into self.logs (module="hub" in collect_all_logs)
        # every ~60s so BugFixer can confirm the Hub is alive and triage when
        # it is not — mirrors the spoke-side _health_heartbeat_task so every
        # module in the stack, including the Hub, emits the same signal.
        hub_hb_task = asyncio.create_task(self.run_hub_heartbeat_loop())
        # Spoke-recovery watchdog: detects approved-but-stranded spokes and
        # restarts their unit (reset-failed + restart via the root helper), with
        # backoff + give-up/escalation to bugfixer. See run_spoke_recovery_loop.
        recovery_task = asyncio.create_task(self.run_spoke_recovery_loop())
        # Spoke out-of-contact alerting: forgiving 5 min → warning / 30 min → error
        # tiers, decoupled from the recovery watchdog above (which still acts at
        # 300s RED). Emits on transition only; ERROR tier surfaces in GET_ERROR_LOGS.
        # See run_spoke_alert_loop (SpokeAlertMixin).
        spoke_alert_task = asyncio.create_task(self.run_spoke_alert_loop())
        # CS bridge: polls the cs (Client-Simulation) spoke's command inbox for
        # every CS-enabled connected pxmx agent and relays commands to the agent
        # as CS_COMMAND (one-socket invariant — the agent never talks to the cs
        # spoke directly), acks terminal results, and syncs USB config down via
        # SET_AGENT_CONFIG. See gateway/cs_bridge.py (Phase D2).
        cs_bridge_task = asyncio.create_task(self.run_cs_bridge_loop())
        # Warm-load persistence: periodically flush simulations_cache to disk so
        # the Clients + VM Server views seed from last-known data on a hub
        # restart instead of blanking until every spoke reconnects. Parity with
        # nw_cache. See run_sim_cache_flush_loop.
        sim_cache_task = asyncio.create_task(self.run_sim_cache_flush_loop())
        # Hub-side Aruba Central poll loop for CENTRALIZED processing mode: the
        # hub holds the creds and the cs spoke has no Aruba client, so this loop
        # produces the central_status the Checks/Hardware/Client-Count/Central
        # tabs render (distributed mode gets it from the spoke's CentralPoller
        # via CS_TELEMETRY instead). See simulations/central_hub_poller.py.
        central_hub_poll_task = asyncio.create_task(self.central_hub_poller.run_loop())
        # Scheduled email health report: fires each tenant's Checks + Client Count
        # report on its configured cadence via the tenant's SMTP (Setup →
        # Notifications → Email Reports). Off unless enabled per tenant.
        try:
            from simulations import email_report as _email_report
            asyncio.create_task(_email_report.run_loop(self))
        except Exception as _er_exc:  # noqa: BLE001 — never let the report loop block startup
            logger.warning("email report loop not started: %s", _er_exc)
        # Adaptive sim-quota controller: modulates each adaptive quota's count
        # between min/max to keep its alert firing (ramp/decay/learn — design §9).
        # Registered on the Hub by register_simulations_routes.
        _adaptive_loop = getattr(self, "_adaptive_controller_loop", None)
        if _adaptive_loop is not None:
            asyncio.create_task(_adaptive_loop())
        # Config-value learner: for each learn_knobs quota, ratchets the sim's
        # [simulation] intensity knobs (e.g. dns_fail_rate/duration) down to the
        # floor that still fires the alert. Registered by register_simulations_routes.
        _knob_loop = getattr(self, "_knob_learner_loop", None)
        if _knob_loop is not None:
            asyncio.create_task(_knob_loop())
        # Sim-quota reconcile-push backstop: every 15m, re-push a tenant's
        # effective sim quotas when its cs spoke's effective set has drifted
        # from the hub's (missing or count-mismatched). The 45s adaptive
        # controller also runs a reconcile pass each tick; this loop is the
        # decoupled safety net for a stable-but-stale spoke that missed a push
        # while continuously online. Registered by register_simulations_routes.
        _reconcile_loop = getattr(self, "_reconcile_push_loop", None)
        if _reconcile_loop is not None:
            asyncio.create_task(_reconcile_loop())
        # Hub-as-sole-GitHub-client: ONE central puller that syncs each
        # github-managed tenant's simulation.conf / user-overrides.conf from its
        # repo and pushes changes down to that tenant's spokes (replaces the
        # per-spoke repo_sync — spokes attached to a hub never touch GitHub).
        # Registered by register_simulations_routes. See github_config_client.
        _gh_sync_loop = getattr(self, "_github_config_sync_loop", None)
        if _gh_sync_loop is not None:
            asyncio.create_task(_gh_sync_loop())
        # Certificate distribution: the hub is the transport for cert material
        # from the le (Let's Encrypt) spoke to each cert's target spokes. For
        # every managed cert with stale targets it pulls fullchain+key from le
        # (LE_GET_CERT) and pushes INSTALL_CERT to the target spoke (resolved by
        # module_type); each target applies the cert to its own device via its
        # SSH/REST/console access, then LE_MARK_DISTRIBUTED records the push on
        # the le ledger. Also fired inline on /api/le/issue + /api/le/renew.
        # See run_cert_distribution_loop / _distribute_one_cert.
        # Virtual hub-self spoke (agent-rework #5 / Phase 4): a loopback
        # ``/ws/agent`` listener + an in-process dumb agent INSIDE the hub
        # process, so ``_install_cert_on_hub`` routes the server-cert write +
        # ``lm-self-restart`` through the SAME WRITE_FILE + RUN_COMMAND
        # primitives spoke-side cert deploys use. NOT a separate unit, NOT a
        # spoke in the hub registry (invisible to WebUI Spokes). The hub's own
        # cert-install path falls back to direct inline writes if the hub-self
        # agent is down. ``LM_HUB_SELF_AGENT=0`` disables the feature entirely.
        # See ``core/src/hub_self.py`` + ``docs/hub-direct-ops.md``.
        self._hub_self = None
        self._hub_self_task = None
        if os.environ.get("LM_HUB_SELF_AGENT", "1").strip() not in ("0", "false", "False"):
            try:
                from hub_self import HubSelfControlPlane
                self._hub_self = HubSelfControlPlane("hub-self")
                # Store the task so the shutdown finally below can cancel it —
                # run() blocks on asyncio.Event().wait() (serve forever), and
                # an uncancelled pending task logs "Task was destroyed but it
                # is pending!" when the loop closes on hub restart.
                self._hub_self_task = asyncio.create_task(self._hub_self.run())
                logger.info("hub-self loopback agent-host started")
            except Exception as e:  # noqa: BLE001 — never fatal to the hub
                logger.warning("hub-self agent-host disabled (non-fatal): %s", e)
                self._hub_self = None

        cert_dist_task = asyncio.create_task(self.run_cert_distribution_loop())

        # compression=None disables permessage-deflate. The hub's core venv and
        # each spoke's venv pin `websockets` to nothing, so a spoke self-update's
        # `pip install` can drift its websockets version out of sync with the
        # hub's, and a version skew across the two ends breaks deflate
        # interoperability — the spoke then crash-loops its hub link with
        # "decompression failed; no close frame received" / "Extra data" JSON
        # errors every ~60s, dropping spoke_connected to False between
        # reconnects. With deflate off, neither side compresses, so there is
        # nothing to decompress and the link is stable across any version skew.
        # max_size: default is 1 MiB. collect_all_logs() (GET_LOGS) routinely
        # exceeds that once a few spokes + their per-module heartbeat lines are
        # relaying, which closed the bugfixer agent with code 1009 "message too
        # big". 16 MiB ceiling pairs with the total-char cap in collect_all_logs
        # so the serialized payload stays safely under the frame limit.
        self._start_mdns_broadcast()
        self.is_ready = True
        try:
            # Block forever, but surface an immediate unified-server failure
            # (e.g. :443 already in use) instead of hanging silently with a
            # dead hub — the old websockets.serve raised on bind; a task just
            # stores the exception, so check it on first completion.
            _blocker = asyncio.Future()
            await asyncio.wait(
                {asyncio.ensure_future(_blocker), self._api_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if self._api_task.done() and not self._api_task.cancelled():
                exc = self._api_task.exception()
                if exc is not None:
                    logger.error("Hub unified :443 server exited unexpectedly: %s", exc)
                    raise exc
        finally:
            self._api_server.should_exit = True
            try:
                await self._api_task
            except Exception as exc:  # noqa: BLE001
                logger.debug("Hub API server shutdown: %s", exc)
            self._stop_mdns_broadcast()
            # Cancel the background tasks created in start() so the loop
            # doesn't close with them pending (the "Task was destroyed but it
            # is pending!" warning on hub restart — hub_self.run() blocks on
            # an asyncio.Event forever, cert_dist is a long poll loop).
            for _t in (self._hub_self_task, cert_dist_task):
                if _t is None or _t.done():
                    continue
                _t.cancel()
            for _t in (self._hub_self_task, cert_dist_task):
                if _t is None or _t.done():
                    continue
                try:
                    await _t
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass


    async def run_hub_heartbeat_loop(self):
        """Emit a greppable [heartbeat] line into self.logs every ~60s so
        BugFixer (which reads Hub logs via GET_LOGS) can confirm the Hub is
        alive and triage a missing/stale entry. The HubLogHandler feeds
        logger output into self.logs, which collect_all_logs returns as
        module="hub" — so this is the Hub's counterpart to the spoke-side
        BaseControlPlane._health_heartbeat_task."""
        interval = 60
        try:
            interval = max(10, int(os.environ.get("LM_HEARTBEAT_INTERVAL_S", "60")))
        except Exception:
            pass
        start = time.time()
        while True:
            try:
                uptime = int(time.time() - start)
                logger.debug(
                    "[heartbeat] ok module=hub spoke_id=hub hub=ok uptime_s=%s spokes=%d",
                    uptime, len(self.active_connections),
                )
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.warning("Hub heartbeat loop error: %s", e)
                await asyncio.sleep(interval)

    async def run_cs_bridge_loop(self):
        """Bridge the cs spoke's command queue to unified pxmx agents (D2).

        Delegates to ``CSBridgePoller`` (gateway/cs_bridge.py): every
        ``CS_POLL_INTERVAL_S`` (5s) it polls each CS-enabled connected pxmx
        agent's inbox on the tenant's cs spoke, relays pending commands to the
        agent as ``CS_COMMAND`` through the pxmx spoke's ``SPOKE_RELAY``, acks
        terminal results, and every ``CS_USB_CONFIG_INTERVAL_S`` (60s) pushes
        USB-config changes down via ``SET_AGENT_CONFIG``. Best-effort; never
        raises out of the loop.
        """
        from gateway.cs_bridge import CSBridgePoller
        # Store the instance on the hub so a REST handler (the WebUI "CS Bridge
        # Status" panel) can read hub.cs_bridge.status_snapshot() without SSH —
        # the poller takes hub in its constructor, so the back-ref is symmetric.
        # Guarded so a loop restart doesn't clobber a live instance mid-cycle.
        if not getattr(self, "cs_bridge", None):
            self.cs_bridge = CSBridgePoller(self)
        await self.cs_bridge.run()

    async def run_threat_sweep_loop(self):
        """Every 60s: expire TTL blocks in the threat monitor and reconcile the
        Azure NSG deny rule with the current blocked-IP set (a no-op when nothing
        changed / auto-block is off). Boot re-pushes once so Azure matches state."""
        while True:
            try:
                self.threat_monitor.sweep()
                await self.threat_monitor.reconcile_nsg()
            except Exception as e:  # noqa: BLE001
                logger.debug("threat sweep loop: %s", e)
            await asyncio.sleep(60)

    async def run_retry_loop(self):
        class ConnectionMap(dict):
            def get(self, spoke_id):
                # NOTE: ConnectionMap intentionally ignores any dict contents.
                # Mailbox.retry_loop's contract is `{spoke_id: send_func}`; we
                # satisfy it by delegation: re-look up the active connection via
                # hub.active_connections and route through hub.send_to_spoke
                # (which resolves the live websocket itself), so retries always
                # hit the current connection rather than a stale send_func.
                hub = self.hub_instance
                if hub._primary_key(spoke_id) not in hub.active_connections:
                    return None
                async def _send(msg):
                    await hub.send_to_spoke(msg)
                return _send

        conn_map = ConnectionMap()
        conn_map.hub_instance = self
        await self.mailbox.retry_loop(conn_map)

def _preflight() -> int:
    """Prove this code can boot WITHOUT serving — the update safety gate.

    Constructs the hub and builds the uvicorn Server (which runs ``create_app``,
    the exact synchronous path that has crash-looped the hub on bad deploys:
    a removed FastAPI method, a missing dependency, a duplicated launch block).
    ``build_server`` does NOT bind the port — binding happens in ``.serve()``,
    which we never call — so this is side-effect-light and never touches :443.

    Exit 0 = the new code boots; the watchdog may adopt/restart into it.
    Exit 1 = it would crash-loop; the watchdog must NOT restart into it.
    """
    try:
        hub = LabManagerHub()
        srv = build_server(
            hub, host="127.0.0.1", port=hub.tls_port,
            tls_cert=hub.tls_cert_path, tls_key=hub.tls_key_path,
        )
        del srv
        print("PREFLIGHT OK")
        return 0
    except BaseException:  # noqa: BLE001 — report ANY startup failure to the gate
        import traceback
        traceback.print_exc()
        print("PREFLIGHT FAILED")
        return 1


if __name__ == "__main__":
    if "--preflight" in sys.argv:
        sys.exit(_preflight())
    hub = LabManagerHub()
    try:
        asyncio.run(hub.start())
    except KeyboardInterrupt:
        pass