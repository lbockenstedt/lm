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
import threading
import time
import sys
import subprocess
import httpx
import psutil
import os
import socket
import ssl
import uuid
import secrets
import tarfile
import io
import shutil
import tempfile
from contextlib import AsyncExitStack
from collections import deque
from typing import Dict, Any, Optional, List, Tuple, Set
from dataclasses import asdict
import websockets
from starlette.websockets import WebSocketDisconnect

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement
from messaging.mailbox import Mailbox
from messaging.heartbeat import HeartbeatManager
from security.key_manager import KeyManager
from state.manager import StateManager
from simulations.broadcaster import SimulationsBroadcaster
from simulations.store import SimulationsStore
from security.auth_manager import AuthManager, LDAPAuthProvider
from api import (build_server, _save_sessions, _refresh_module_all_tenants,
                 _invalidate_tenant_module, _fetch_module)
from update_recovery import (
    snapshot_code, write_pending, clear_pending,
    is_version_bad, clear_bad_versions_older_than,
)
from update_pipeline import UpdatePipelineMixin
from endpoint_sync import EndpointSyncMixin
from vm_sync import VmSyncMixin
from fw_discovery_sync import FwDiscoverySyncMixin
from nw_discovery_sync import NwDiscoverySyncMixin
from nw_cache import NwCacheMixin
from dns_dhcp_sync import DnsDhcpSyncMixin
from realtime_ipam_nac_sync import RealtimeIpamNacSyncMixin
from staleness_sweep import StalenessSweepMixin
from spoke_alert_sync import SpokeAlertMixin
from repo_sync import RepoSyncMixin
from hub_vnc_console import HubVncConsoleMixin
from hub_cert_distribution import HubCertDistributionMixin
from hub_identity import HubIdentityMixin
from hub_bug_store import HubBugStoreMixin

# Shared logging config (lm/core/src/logging_setup.py). Two-tier import +
# inline fallback keep the hub booting even if /opt/lm/core is briefly stale
# (same deploy-order class as the base_spoke import). Single source of truth
# for format/level/destination across every hub/spoke/agent entrypoint.
try:
    from logging_setup import configure_logging, set_log_level
except ImportError:
    try:
        from core.src.logging_setup import configure_logging, set_log_level
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

# Command types whose request data / response payload may carry a Proxmox API
# token secret (Phase F: CS_STORE_PROXMOX_TOKEN relays the agent-provisioned
# root@pam!cs-hub token to the cs spoke for sim-tag sync). The token transits
# the hub (unavoidable — the cs spoke must store it), so request_response must
# NOT log the data or the raw result for these types. The redacted log line
# preserves traceability (msg_id, spoke, type) without leaking the secret.
_REDACT_COMMANDS = frozenset({"CS_STORE_PROXMOX_TOKEN", "CS_CREATE_PROXMOX_TOKEN",
                              "CS_TOKEN_RESULT"})


def _redact(command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a log-safe view of ``data`` for token-bearing command types.

    Drops the ``token``/``secret``/``result.token`` fields outright (the value
    is still forwarded to the spoke — only the log line is redacted). For
    non-redacted types returns the data unchanged so normal telemetry/commands
    keep their full debug trail."""
    ct = (command_type or "").upper()
    if ct not in _REDACT_COMMANDS:
        return data
    safe = dict(data or {})
    for k in ("token", "secret", "password", "api_token"):
        safe.pop(k, None)
    res = safe.get("result")
    if isinstance(res, dict):
        r = dict(res)
        for k in ("token", "secret", "password", "api_token"):
            r.pop(k, None)
        safe["result"] = r
    return safe


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


def _project_nw_devices(devices):
    """Project the nw_devices list into the UPDATE_CONFIG payload for a spoke.

    One nw spoke manages a fleet (many devices), unlike the per-instance
    modules above. Credentials are kept — the spoke needs them to reach the
    devices, and ``system.json`` (where nw_devices lives) is runtime-only and
    never committed. This helper is the single place to normalize the device
    shape on push so the on-connect push and a manual Save push identical
    payloads (mirrors the _INSTANCE_CONFIG_SOURCES project contract).
    """
    if not isinstance(devices, list):
        return []
    return [d for d in devices if isinstance(d, dict)]


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

# module_type → spoke_id prefix substring, for legacy spoke resolution.
# Used by get_spoke_by_type / get_all_spokes_by_type. The prefix is matched as
# a substring of the spoke_id (e.g. an "opn-edge-1" spoke → firewall).
_MODULE_TYPE_PREFIX = {
    "hypervisor": "pxmx",
    "firewall":   "opn",
    "nac":        "cppm",
    "directory":  "ldap",
    "ipam":       "netbox",
    "simulation": "cs",
    "dns":        "dns",
    "dhcp":       "dhcp",
    "agent":      "agent",
    "nw":         "nw",
    "certificates": "le",
}

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
    'le': 'le',
}

# _UPDATE_SOURCE_MODULE_KEY / _UPDATE_SOURCE_PREFIX_MAP moved to
# update_pipeline.py (used only by the update methods that now live there).


class TokenBucket:
    """Simple thread-safe-ish token bucket for per-connection rate limiting.

    Refills ``fill_rate`` tokens/sec up to ``capacity``; ``consume`` returns
    True when ``amount`` tokens are available (and debits them), else False.
    Used to throttle noisy spokes/agents on the control plane.
    """

    def __init__(self, capacity: float, fill_rate: float):
        self.capacity = capacity
        self.fill_rate = fill_rate
        self.tokens = capacity
        self.last_update = time.time()

    def consume(self, amount: float = 1.0) -> bool:
        """Return True and debit ``amount`` tokens if available, else False."""
        now = time.time()
        delta = now - self.last_update
        self.tokens = min(self.capacity, self.tokens + delta * self.fill_rate)
        self.last_update = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False


def _fit_log_payload(all_logs: list, max_bytes: int) -> list:
    """Trim ``all_logs`` to the newest entries whose ``{"logs": …}`` JSON fits
    under ``max_bytes``. Used by ``collect_all_logs`` to cap the GET_LOGS payload
    below the 16 MiB WS frame ceiling.

    Binary-searches the tail length (O(log N) json.dumps passes) instead of the
    prior `while … pop(0)` loop, which re-serialized the whole list on every pop
    (O(N²) in log lines — at 100s of spokes × 1000-line deques this stalled the
    event loop on every BugFixer poll). Keeps the newest entries (drops oldest).
    """
    try:
        if len(json.dumps({"logs": all_logs})) <= max_bytes:
            return all_logs
        lo, hi = 0, len(all_logs)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if len(json.dumps({"logs": all_logs[-mid:]})) <= max_bytes:
                lo = mid
            else:
                hi = mid - 1
        return all_logs[-lo:] if lo else []
    except Exception as e:
        logger.warning(f"_fit_log_payload size-cap failed: {e}")
        return all_logs[-1000:]  # safe fallback


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


class LabManagerHub(UpdatePipelineMixin, EndpointSyncMixin, VmSyncMixin, FwDiscoverySyncMixin, NwDiscoverySyncMixin, NwCacheMixin, DnsDhcpSyncMixin, RealtimeIpamNacSyncMixin, StalenessSweepMixin, SpokeAlertMixin, RepoSyncMixin, HubVncConsoleMixin, HubCertDistributionMixin, HubIdentityMixin, HubBugStoreMixin):
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

        # Initialize Auth with LDAP
        self.auth = AuthManager(LDAPAuthProvider({"server": "ldap://localhost"}))

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

        # { spoke_id: str } tracking spoke versions
        self.spoke_versions: Dict[str, str] = {}
        # { spoke_id: module_type } — e.g. {"pxmx-spoke-1": "hypervisor"}
        self.spoke_module_types: Dict[str, str] = {}
        # { spoke_id: parent_spoke_id } — for multi-role generic agents: each
        # loaded role opens a sub-spoke under {base}-{role} that claims the base
        # agent as its parent in the WS auth frame. The hub auto-approves such a
        # sub-spoke when its parent agent is already approved + connected (see
        # _can_parent_auto_approve / _auto_approve_pending_subspokes), binding it
        # to the parent's tenant so a Generic Node hosting N roles needs only the
        # one base-agent approval.
        self.spoke_parent_map: Dict[str, str] = {}

        # --- System Diagnostics ---
        self.logs = deque(maxlen=500)
        self.agent_logs = {} # { agent_id: deque(logs) }
        self.max_log_size = 1000
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
        self.mps = 0.0
        self.bytes_count = 0 # Total bytes sent/received in the current window
        self.throughput_mbps = 0.0 # Throughput in Mbps (or MB/s)
        self.message_history = deque(maxlen=10) # Last 10 seconds of counts

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
        # Spokes already diagnosed as connected-but-never-authenticated this
        # connection cycle (see _maybe_log_unauthenticated_agent). Cleared on
        # authenticate + disconnect so a re-trigger after a future regression
        # (or a reconnect that's still broken) emits a fresh ERROR rather than
        # silently suppressing it after the first one.
        self._unauth_warned_spokes: Set[str] = set()
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
        self._RECENT_TIMEOUT_TTL = 60.0
        # VNC console sessions (agent-terminates-WSS): session_id →
        # {queue, expires, ws_token, spoke_id, tenant_id, vmid, node, unique_id}.
        # The browser WS reads Proxmox→browser frames off ``queue`` (bytes) or
        # control tuples ("ready"/"error"/"disconnect"); VNC_FRAME_DOWN sends
        # the other way via send_to_spoke_command (fire-and-forget). 60s TTL.
        self.vnc_sessions: Dict[str, Dict[str, Any]] = {}
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
        # Simulations module: tenant-scoped browser broadcast + slim cs-config store.
        self.simulations_broadcaster = SimulationsBroadcaster()
        self.simulations_store = SimulationsStore(self.state.data_dir)
        self.cache_dir = os.path.join(self.state.data_dir, "cache")
        # Network Devices (nw) module: in-memory fleet + per-device cache,
        # persisted to cache/nw_data.json and reloaded on startup so the
        # Network Devices UI seeds from last-known data on a restart instead
        # of 503-ing until the nw spoke reconnects. See nw_cache.NwCacheMixin.
        self.nw_cache_init()
        self.nw_cache_load()
        # File-a-Bug artifact store: each report's console.log / dom.html /
        # screenshot.png / report.json live under data_dir/bugs/<id>/ so the
        # large payloads never bloat the 500-line self.logs deque or the hub
        # log file. Bugfixer pulls them back via GET_BUG_REPORT for fix context.
        self.bug_dir = os.path.join(self.state.data_dir, "bugs")
        try:
            os.makedirs(self.bug_dir, exist_ok=True)
        except Exception as e:
            logger.warning(f"[bug-report] could not create bug_dir {self.bug_dir}: {e}")
        self.is_ready = False


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
        ws = self.active_connections.get(spoke_id)

        if ws:
            # Sign the message before sending
            header_dict = asdict(message.header)
            if "timestamp" in header_dict:
                header_dict["timestamp"] = round(header_dict["timestamp"], 6)

            payload_dict = asdict(message.payload)

            # Sign the structured data (KeyManager now handles canonicalization)
            body = {"header": header_dict, "payload": payload_dict}
            if signing_secret is not None:
                message.signature = self.key_manager.sign_with_secret(signing_secret, body)
            else:
                message.signature = self.key_manager.sign_message(spoke_id, body)

            payload = {
                "header": header_dict,
                "payload": payload_dict,
                "signature": message.signature
            }
            json_payload = json.dumps(payload, separators=(',', ':'))
            self.bytes_count += len(json_payload.encode())
            try:
                await ws.send(json_payload)
            except (websockets.ConnectionClosed, RuntimeError, ConnectionError) as e:
                # The socket was closed/evicted between the active_connections
                # lookup above and this send (the eviction path swaps sockets;
                # a concurrent sender can catch the closing one mid-swap, or a
                # duplicate-process flap can replace it). Surface as a clean
                # ConnectionError so push_or_queue_to_spoke queues the message
                # for redelivery on reconnect instead of bubbling up as a
                # "connection_error — Need to call accept first" event.
                raise ConnectionError(
                    f"Spoke {spoke_id} connection closed mid-send: {e}") from e
            self.message_count += 1
        else:
            raise ConnectionError(f"Spoke {spoke_id} is not connected")

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
                    "target_agent_id": agent_id,
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

            logger.error(f"Request Timeout: {msg_id} from {spoke_id} after {timeout}s")
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

    def _evict_spoke(self, spoke_id: str) -> None:
        """Drop ALL per-spoke in-memory state for ``spoke_id``.

        Called when an admin deletes a spoke (api.delete_spoke) so the
        per-spoke dicts (simulations_cache, spoke_telemetry, rate_limiters,
        spoke_events, spoke_recovery, agent_logs) don't accumulate entries for
        ids that no longer exist — unbounded growth as spokes are deleted/recreated
        over time at scale. NOT called on a transient disconnect: spoke_telemetry
        must keep its DISCONNECTED status for the WebUI, and spoke_recovery is
        needed by the watchdog if the spoke is flapping. Reconnect re-creates
        rate_limiters / re-pushes simulations_cache, so eviction on delete is safe.
        """
        self.simulations_cache.pop(spoke_id, None)
        self.spoke_telemetry.pop(spoke_id, None)
        self.rate_limiters.pop(spoke_id, None)
        self.spoke_events.pop(spoke_id, None)
        self.spoke_recovery.pop(spoke_id, None)
        self.agent_logs.pop(spoke_id, None)
        self.heartbeat.last_seen.pop(spoke_id, None)  # else grows unbounded across delete/recreate
        # Also drop the persisted last-seen so a deleted spoke doesn't keep a
        # stale timestamp that would surface as a ghost "last seen" entry.
        self.state.clear_spoke_last_seen(spoke_id)

    def _mark_spoke_disconnected(self, spoke_id: str) -> None:
        """Record a clean-WS-close disconnect in ``spoke_telemetry``.

        A spoke deleted via ``DELETE /setup/spokes/{id}`` is evicted
        (``_evict_spoke`` pops ``spoke_telemetry``) BEFORE that socket's 1008
        "Removed by admin" close fires the disconnect handler, so the entry
        may already be gone — re-create a minimal ``DISCONNECTED`` stub rather
        than ``KeyError`` on the index. A transient disconnect (entry still
        present) just updates the status in place.
        """
        tel = self.spoke_telemetry.get(spoke_id)
        if tel is None:
            self.spoke_telemetry[spoke_id] = {
                "last_attempt": time.time(),
                "status": "DISCONNECTED",
            }
        else:
            tel["status"] = "DISCONNECTED"

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
        prior_authed = self.spoke_authenticated.get(spoke_id, False)
        prior_ws = self.active_connections.get(spoke_id)
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
        self.active_connections[spoke_id] = websocket
        self.active_connection_key_ids[spoke_id] = None

    def get_spoke_by_type(self, module_type: str) -> Optional[str]:
        """Return the first connected, approved spoke that advertised the given module_type."""
        for sid, mtype in self.spoke_module_types.items():
            if mtype == module_type and sid in self.active_connections:
                return sid
        # Legacy fallback: derive type from known spoke_id prefixes for spokes that
        # pre-date the module_type system and never sent the field. See _MODULE_TYPE_PREFIX.
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return next((sid for sid in self.active_connections if prefix in sid), None)
        return None

    def get_spoke_for_agent(self, agent_id: str, fallback_hypervisor: bool = True) -> Optional[str]:
        """Return the connected spoke_id that owns ``agent_id``.

        ``agent_info`` is populated from every ``AGENT_RELAY_UP`` frame, so a
        pxmx-dialed agent indexes to the pxmx spoke and a cs-dialed agent
        indexes to the cs spoke. Returns None when the agent is not connected
        / not yet heartbeat-indexed (e.g. the first ~30s after connect, before
        any relayed frame arrives).

        When ``fallback_hypervisor`` is True, a missing index falls back to the
        pxmx (``hypervisor``) spoke — correct for the all-in-one path where
        every agent is on the pxmx spoke. Callers that must NOT misroute a
        cs-dialed agent (e.g. the CS bridge relaying commands) pass
        ``fallback_hypervisor=False`` and skip when None is returned.
        """
        info = self.agent_info.get(agent_id)
        if info:
            sid = info.get("spoke_id")
            if sid and sid in self.active_connections:
                return sid
        if fallback_hypervisor:
            return self.get_hypervisor_spoke()
        return None

    def get_hypervisor_spoke(self) -> Optional[str]:
        """Return a connected spoke that can answer Proxmox-agent commands —
        either a dedicated hypervisor (pxmx) spoke, or, in the split-topology
        case, a simulation (cs) spoke hosting its own agent listener with no
        separate pxmx spoke at all. Prefers a real hypervisor spoke if one is
        connected.

        Drop-in replacement for the ~18 call sites across api.py that called
        ``get_spoke_by_type("hypervisor")`` directly (VM/console/node/pool/
        ISO/storage/template browsing, agent removal, endpoint/NAC sync's
        Proxmox enrichment, the pxmx_vms cache refresh, ...) — every one of
        them silently returned nothing for an all-cs-hosted deployment like
        this one, the same blind spot cs_bridge.py's CSBridgePoller had (see
        that fix's commit) before it was taught to check every agent-hosting
        spoke type instead of only "hypervisor". Doesn't replace
        get_spoke_for_agent, which is still the right choice wherever a
        specific agent_id is already in scope — this is for the handful of
        callers that only ever assumed a single global hypervisor spoke."""
        return self.get_spoke_by_type("hypervisor") or self.get_spoke_by_type("simulation")

    def get_all_spokes_by_type(self, module_type: str):
        """Return all connected spoke IDs that advertised the given module_type."""
        # Legacy fallback: same prefix map as get_spoke_by_type. See
        # _MODULE_TYPE_PREFIX.
        by_registry = [sid for sid, mt in self.spoke_module_types.items()
                       if mt == module_type and sid in self.active_connections]
        if by_registry:
            return by_registry
        prefix = _MODULE_TYPE_PREFIX.get(module_type)
        if prefix:
            return [sid for sid in self.active_connections if prefix in sid]
        return []

    def get_client_sim_spoke(self, tenant_id: str = None) -> Optional[str]:
        """Return the approved, connected Client-Sim spoke for a tenant.

        Tenant binding lives in module_metadata[spoke_id]["tenant_id"], set by
        an admin at approval time. Returns None if no Client-Sim spoke is
        connected+approved.

        Tenant isolation (IMPORTANT): the cs speak holds a SINGLE CSSettings
        store per spoke, so a spoke shared across tenants = one tenant's
        hub-config push / auto-provision toggle clobbers another's. When a
        tenant_id is given we therefore return ONLY a spoke bound to that
        tenant, or — if none is bound — an UNASSIGNED spoke (no tenant_id in its
        metadata) that the tenant implicitly claims. We NEVER fall back to a
        spoke bound to a different tenant. When tenant_id is None (admin/global
        view) any connected spoke is fine.
        """
        # Connected Client-Sim spokes; fall back to legacy "simulation" type for
        # older combined-spoke builds that haven't adopted "Client-Sim" yet.
        cands = self.get_all_spokes_by_type("Client-Sim") or self.get_all_spokes_by_type("simulation")
        # Only approved spokes carry cached telemetry (unapproved frames are dropped).
        cands = [sid for sid in cands if self.approved_modules.get(sid, False)]
        if not cands:
            return None
        if tenant_id:
            md = self.state.system_state.get("module_metadata", {})
            bound = [sid for sid in cands if md.get(sid, {}).get("tenant_id") == tenant_id]
            if bound:
                return bound[0]
            # No spoke bound to this tenant — claim an UNASSIGNED one (no
            # tenant_id in metadata). Never cands[0] blindly: that may be a
            # spoke bound to another tenant, whose CSSettings this tenant's
            # push would overwrite (cross-tenant leak).
            unassigned = [sid for sid in cands if not md.get(sid, {}).get("tenant_id")]
            if unassigned:
                return unassigned[0]
            return None
        # tenant_id is None: admin / global view — any connected spoke.
        return cands[0]

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
        spoke or a dispatch failure must not break the agent→hub relay loop.
        """
        mapped = self._CS_INGEST_MAP.get(cs_type)
        if not mapped:
            logger.debug("CS_* relay: no mapping for %s from %s — dropping", cs_type, agent_id)
            return
        hostname = (data or {}).get("hostname") or agent_id
        # Resolve tenant: per-agent store first, then the relaying spoke's binding.
        tenant_id = None
        try:
            ac = (self.state.system_state.get("agent_config", {}) or {}).get(agent_id, {})
            tenant_id = (ac.get("client_simulation") or {}).get("tenant_id")
        except Exception:
            tenant_id = None
        if not tenant_id:
            try:
                tenant_id = self.state.get_spoke_tenant(spoke_id)
            except Exception:
                tenant_id = None
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

    def get_spoke_for_firewall(self, firewall_id: str) -> Optional[str]:
        """Finds the spoke associated with a given firewall ID."""
        firewalls = self.state.get_global_config().get("firewalls", [])
        fw = next((f for f in firewalls if f["id"] == firewall_id), None)
        return fw.get("spoke_id") if fw else None

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

            # Resolve the push_config branch tag from the module_type registry
            # first, then fall back to a spoke_id prefix match for legacy spokes.
            # See _PUSH_CONFIG_MODULE_KEY / _PUSH_CONFIG_PREFIX_MAP (branch-tag
            # space — NOT the update-source config-key space).
            mtype = self.spoke_module_types.get(spoke_id, "")
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
                config = {"devices": _project_nw_devices(mine)}
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
        if override_cfg:
            try:
                await self.request_response(spoke_id, "CS_CONFIG_UPDATE",
                                             override_cfg, timeout=5.0)
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
            await self.request_response(spoke_id, "CS_CONFIG_UPDATE", cfg, timeout=5.0)
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
            tasks.append(self.send_to_spoke(spoke_msg))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def approve_and_bind_spoke(self, spoke_id: str, tenant_id: str) -> None:
        """Approve a spoke, bind it to a tenant, persist, and — if it is
        currently connected — push it the session key + APPROVED + config so it
        begins operating immediately. Shared by the admin
        ``/setup/approve_spoke`` flow and the PSK claim flow
        (``/sim/api/tenant/{t}/spokes/{id}/claim``). Mirrors the connected-push
        in api.py approve_spoke (561-592)."""
        self.state.register_module(spoke_id, approved=True)
        self.state.set_spoke_tenant(spoke_id, tenant_id)
        self.approved_modules[spoke_id] = True
        self.state.save_state()
        if spoke_id in self.active_connections:
            # Capture the secret the spoke currently holds BEFORE generating the
            # new one, then sign the key-delivery push with it — the spoke can't
            # verify a frame signed with the new secret it hasn't installed yet.
            prev_secret = self.key_manager.current_session_secret(spoke_id)
            session_secret = self.key_manager.generate_first_secret(spoke_id)
            key_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(
                    type="SPOKE_UPDATE_SESSION_KEY", data={"secret": session_secret}))
            await self.send_to_spoke(key_msg, signing_secret=prev_secret)
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
        if self.spoke_module_types.get(spoke_id) == "agent":
            await self._auto_approve_pending_subspokes(spoke_id)

    def _can_parent_auto_approve(self, spoke_id: str, parent_spoke_id: str) -> bool:
        """True if ``spoke_id`` may be auto-approved via ``parent_spoke_id``:
        the sub-spoke id is prefix-tied to the claimed parent (``{parent}-…``,
        the agent's own id-construction convention), the parent is approved +
        currently connected, and the parent is a generic agent
        (module_type ``"agent"``). Same deploy-claim trust class as PSK
        (the claim transits the WS but is never logged as a secret)."""
        if not parent_spoke_id or not spoke_id.startswith(parent_spoke_id + "-"):
            return False
        return (parent_spoke_id in self.approved_modules
                and parent_spoke_id in self.active_connections
                and self.spoke_module_types.get(parent_spoke_id) == "agent")

    async def _auto_approve_pending_subspokes(self, parent_spoke_id: str) -> None:
        """Approve every still-pending role sub-spoke of an approved base agent.

        Called from ``approve_and_bind_spoke`` when a base agent (module_type
        ``"agent"``) is approved. Each pending sub-spoke that claimed this parent
        (``spoke_parent_map[sid] == parent``) and is prefix-tied to it gets
        approved + bound to the parent's tenant on its already-open connection
        (``approve_and_bind_spoke`` pushes the session key + APPROVED + config
        to the live ws). Sub-spokes whose parent isn't this one — or that share
        the prefix by coincidence — are left untouched."""
        tenant = self.state.get_spoke_tenant(parent_spoke_id) or ""
        for sid in list(self.active_connections.keys()):
            if sid == parent_spoke_id:
                continue
            if self.approved_modules.get(sid, False):
                continue
            if self.spoke_parent_map.get(sid) != parent_spoke_id:
                continue
            if not self._can_parent_auto_approve(sid, parent_spoke_id):
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
        if spoke_id not in self.active_connections:
            return False, self._CMD_NOT_CONNECTED
        if self.spoke_authenticated.get(spoke_id):
            return True, ""
        tel = self.spoke_telemetry.get(spoke_id) or {}
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
        if spoke_id in self._unauth_warned_spokes:
            return
        tel = self.spoke_telemetry.get(spoke_id) or {}
        last_attempt = tel.get("last_attempt")
        if last_attempt is None:
            return
        try:
            conn_age = time.time() - float(last_attempt)
        except (TypeError, ValueError):
            return
        if conn_age < self._UNAUTH_DIAGNOSIS_THRESHOLD_S:
            return
        self._unauth_warned_spokes.add(spoke_id)
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
        self.state.register_module(spoke_id, approved=True)
        self.state.set_spoke_tenant(spoke_id, tenant_hint)
        self.approved_modules[spoke_id] = True
        self.state.save_state()
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
        self.simulations_cache[spoke_id] = cs_data
        # Fan out to browsers subscribed on /sim/ws (tenant-scoped).
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
            if spoke_id not in self.agent_logs:
                self.agent_logs[spoke_id] = deque(maxlen=self.max_log_size)
            # Entries arrive already canonical-formatted by the spoke's
            # _SpokeLogRelayHandler (``<asctime> - <name> - <levelname> - <msg>``)
            # — store verbatim. Re-stamping with the hub receive time would
            # duplicate the timestamp (the record's original asctime is inside
            # the entry) and desync the WebUI view from the spoke's local log.
            for entry in entries:
                if isinstance(entry, str):
                    self.agent_logs[spoke_id].append(entry)
            logger.debug(f"SPOKE_LOG: stored {len(entries)} entries for {spoke_id}")

    async def _handle_agent_relay_up(self, spoke_id: str, msg_data, payload) -> bool:
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

        # Index the agent → its owning spoke so command routing (CS bridge,
        # SET_AGENT_CONFIG) reaches the right spoke: a pxmx-dialed agent indexes
        # to the pxmx spoke, a cs-dialed agent indexes to the cs spoke. Updated
        # on every relayed frame (heartbeat/telemetry/log/CS_*), so the index is
        # fresh and the hostname tracks a rename. Evicted on spoke disconnect.
        if agent_id:
            self.agent_info[agent_id] = {
                "spoke_id":  spoke_id,
                "hostname":  (relay_data.get("hostname") or "").strip() or agent_id,
                "last_seen": time.time(),
            }

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
            if agent_id not in self.agent_logs:
                self.agent_logs[agent_id] = deque(maxlen=self.max_log_size)
            if msg:
                self.agent_logs[agent_id].append(msg)
            return True

        # If the original message was a heartbeat, update heartbeat for that
        # specific agent (keyed spoke_id:agent_id). pxmx unified agents emit
        # "AGENT_HEARTBEAT" (30s); accept the legacy "HEARTBEAT" type too.
        _orig_type = original_msg.get("payload", {}).get("type")
        if _orig_type in ("HEARTBEAT", "AGENT_HEARTBEAT"):
            self.heartbeat.update_heartbeat(f"{spoke_id}:{agent_id}")
            return True

        # Otherwise, process the original payload as if it came from the agent
        if original_msg.get("payload", {}).get("type") == "AGENT_TELEMETRY":
            if spoke_id not in self.spoke_telemetry:
                self.spoke_telemetry[spoke_id] = {}
            self.spoke_telemetry[spoke_id][agent_id] = original_msg.get("payload", {}).get("data")
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
            _cs_data = original_msg.get("payload", {}).get("data", {}) or {}
            await self._relay_cs_event(spoke_id, agent_id, _orig_type, _cs_data)
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

        # Unmatched sub-type: return False so handle_connection falls through
        # to the HUB_REQUEST check and catch-all INFO log (see docstring).
        return False

    async def _handle_hub_request(self, spoke_id: str, msg_data, payload) -> None:
        """Dispatch a spoke/agent-initiated HUB_REQUEST and reply with a signed
        HUB_RESPONSE.

        Used by agents that need something from the hub (e.g. BugFixer asking for
        logs or to trigger updates). The request carries NO top-level
        correlation_id (it uses ``header.message_id``) so it isn't consumed as an
        ack in the correlation_id branch of ``handle_connection``; we reply with a
        HUB_RESPONSE carrying that message_id as ``correlation_id``. Only approved
        senders reach here, so ``key_manager.sign_message`` will succeed.
        """
        req = payload.get("data", {}) or {}
        req_id = msg_data.get("header", {}).get("message_id")
        result = await self.handle_hub_request(spoke_id, req)
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
        existing = self.active_connections.get(spoke_id)
        if existing is not None and existing is not websocket:
            current = self.key_manager.keys.get(spoke_id)
            current_kid = current.key_id if current else None
            new_is_current = key_id is not None and key_id == current_kid
            old_is_current = (
                current_kid is not None
                and self.active_connection_key_ids.get(spoke_id) == current_kid
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
            alive = False
            try:
                await asyncio.wait_for(existing.ping(), timeout=2.0)
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
            self.active_connections[spoke_id] = websocket
            self.active_connection_key_ids[spoke_id] = key_id
            try:
                await existing.close(1008, "Replaced by newer connection")
            except Exception:
                pass
            return True
        self.active_connections[spoke_id] = websocket
        self.active_connection_key_ids[spoke_id] = key_id
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

            logger.info(f"Auth attempt: spoke_id={spoke_id}, secret={f'{secret[:4]}...{secret[-4:]}' if secret and len(secret) > 8 else '***'}")
            self.record_spoke_event(spoke_id, "auth_attempt", f"secret={'yes' if secret else 'no'} module_type={module_type}")

            if not spoke_id:
                await websocket.close(1008, "Missing spoke_id")
                return

            # Detect a clone-and-rename (same install UUID, new id) and migrate
            # approval/tenant binding + key material to the new id BEFORE auth.
            self._reconcile_spoke_identity(spoke_id, install_uuid, spoke_hostname)

            # If secret is provided, verify it. If not, the spoke is in 'pending secret' state.
            is_authenticated = False
            if secret:
                key_id = self.key_manager.get_valid_key(spoke_id, secret)
                if key_id:
                    is_authenticated = True
                    self.spoke_authenticated[spoke_id] = True
                    # It adopted its key — clear any prior "never authenticated"
                    # diagnosis so a future regression re-triggers a fresh ERROR.
                    self._unauth_warned_spokes.discard(spoke_id)
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
                if spoke_id not in self.known_modules:
                    self.state.register_module(spoke_id, approved=False)
                    self.known_modules = self.state.system_state["known_modules"]

                # Update telemetry
                self.spoke_telemetry[spoke_id] = {
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

            # --- Mutual Authentication (Hub Identity Proof) ---
            try:
                challenge = secrets.token_urlsafe(32)
                signature = self.key_manager.sign_hub_challenge(challenge.encode())

                proof = {
                    "status": "HUB_VERIFIED",
                    "challenge": challenge,
                    "signature": signature
                }
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
            self.spoke_telemetry[spoke_id] = {
                "last_attempt": time.time(),
                "status": "CONNECTED",
                "error": None,
                "remote_ip": remote_ip,
            }

            # Track this module as known for approval lists
            if spoke_id not in self.known_modules:
                self.state.register_module(spoke_id, approved=False)
                self.known_modules = self.state.system_state["known_modules"]

            # Initialize rate limiter (e.g., 5 messages/sec burst of 10)
            self.rate_limiters[spoke_id] = TokenBucket(capacity=10, fill_rate=5)
            if module_type:
                self.spoke_module_types[spoke_id] = module_type
                # Persist the type into module_metadata so the Spoke Management
                # list can show a cs/simulation spoke's type even while it is
                # offline (the in-memory spoke_module_types dict is popped on
                # disconnect). Free-form merge — no migration needed.
                self.state.update_module_metadata(spoke_id, {"module_type": module_type})
                self.state.save_state()
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
            if parent_spoke_id:
                self.spoke_parent_map[spoke_id] = parent_spoke_id
                if (not self.approved_modules.get(spoke_id, False)
                        and self._can_parent_auto_approve(spoke_id, parent_spoke_id)):
                    tenant = self.state.get_spoke_tenant(parent_spoke_id) or ""
                    logger.info(f"Parent auto-approve: {spoke_id} via parent "
                                f"{parent_spoke_id} (tenant={tenant or 'unassigned'}).")
                    await self.approve_and_bind_spoke(spoke_id, tenant)
                    self.known_modules = self.state.system_state["known_modules"]
                    self.record_spoke_event(spoke_id, "parent_auto_approve",
                                            f"parent={parent_spoke_id}")

            # Check if the module is already approved
            if not self.approved_modules.get(spoke_id, False):
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
                    approval_msg["signature"] = self.key_manager.sign_message(spoke_id, {
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
                    # Sign the key-delivery push with the secret the spoke
                    # currently holds (None here = pending, it accepts anyway)
                    # so it can verify and install the new secret.
                    prev_secret = self.key_manager.current_session_secret(spoke_id)
                    session_secret = self.key_manager.generate_first_secret(spoke_id)
                    key_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()), timestamp=time.time(),
                            sender_id="hub", destination_id=spoke_id),
                        payload=MessagePayload(
                            type="SPOKE_UPDATE_SESSION_KEY",
                            data={"secret": session_secret}))
                    await self.send_to_spoke(key_msg, signing_secret=prev_secret)
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

            # 2. Flush Mailbox
            await self.mailbox.flush_mailbox(spoke_id, self.send_to_spoke)

            # 3. Message Loop
            async for message_json in websocket:
                msg_data = json.loads(message_json)

                # Signature Verification
                signature = msg_data.get("signature")
                data_to_verify = {k: v for k, v in msg_data.items() if k != "signature"}
                message_bytes = json.dumps(data_to_verify, sort_keys=True, separators=(',', ':')).encode()

                if signature:
                    if not self.key_manager.verify_signature(spoke_id, message_bytes, signature):
                        logger.warning(f"Invalid signature from spoke {spoke_id}")
                        continue
                    # A verified signature proves the spoke installed its session
                    # key. Mark it authenticated (idempotent — also set at connect
                    # when a secret was presented). A spoke that never reaches here
                    # (legacy/incompatible agent that can't adopt a key) stays
                    # unauthenticated, so command routes can fail fast.
                    self.spoke_authenticated[spoke_id] = True
                    # First signed frame clears any prior "never authenticated"
                    # diagnosis (idempotent with the connect-time discard).
                    self._unauth_warned_spokes.discard(spoke_id)
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
                        self._maybe_log_unauthenticated_agent(spoke_id)
                        logger.debug(
                            f"Unauthenticated non-heartbeat from {spoke_id} "
                            f"(only HEARTBEAT allowed). Dropping.")
                        continue

                # Process Heartbeat (Always allowed for pending spokes to maintain connection)
                payload = msg_data.get("payload", {})
                self.bytes_count += len(message_json) # Track received bytes
                # Inbound trace: one line per frame so the full dispatch flow is
                # greppable when DEBUG is on. Heartbeats are the bulk of traffic,
                # so this stays at DEBUG (not INFO) to avoid flooding the log.
                logger.debug("inbound type=%s from spoke=%s", payload.get("type"), spoke_id)
                if payload.get("type") == "HEARTBEAT":
                    self.message_count += 1
                    self.heartbeat.update_heartbeat(spoke_id)
                    # Persist last-contacted so a hub reboot doesn't reset this
                    # spoke to "Never connected / RED". _mark_dirty (no disk
                    # write here) — the 60s persistence_loop flushes. Cheap
                    # enough to run every heartbeat tick.
                    self.state.set_spoke_last_seen(spoke_id, self.heartbeat.last_seen[spoke_id])
                    # A heartbeat means the spoke is in contact — clear any
                    # never-seen absent clock so the alert loop doesn't keep a
                    # stale _spoke_absent_since entry around after first contact.
                    self._spoke_absent_since.pop(spoke_id, None)
                    continue

                # If the module is not approved, ignore all other messages
                if not self.approved_modules.get(spoke_id, False):
                    logger.debug(f"Dropping message from unapproved module {spoke_id}")
                    continue

                # Process Acknowledgement
                if "correlation_id" in msg_data:
                    corr_id = msg_data["correlation_id"]
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
                            self.spoke_versions[spoke_id] = data["version"]

                    # Store in response cache for API request bridging — but
                    # only if a waiter is still outstanding for this msg_id, so
                    # a late ack (after request_response already timed out and
                    # discarded the waiter) is dropped instead of leaked.
                    if hasattr(self, "response_cache") and corr_id in self._outstanding_requests:
                        self.response_cache[corr_id] = msg_data

                    self.message_count += 1
                    continue

                # Rate Limiting for non-heartbeat messages
                limiter = self.rate_limiters.get(spoke_id)
                if limiter and not limiter.consume():
                    logger.warning(f"Rate limit exceeded for spoke {spoke_id}. Dropping message.")
                    continue

                # Handle other messages
                self.message_count += 1

                # --- Client-Sim telemetry (combined spoke relays its full state) ---
                # Ingest + fan-out + USB diagnostic live in _handle_cs_telemetry.
                if payload.get("type") == "CS_TELEMETRY":
                    await self._handle_cs_telemetry(spoke_id, payload.get("data", {}))
                    continue

                # --- Spoke log forwarding (SPOKE_LOG) ---
                # See _handle_spoke_log for the ingest + agent_logs buffering.
                if payload.get("type") == "SPOKE_LOG":
                    await self._handle_spoke_log(spoke_id, payload)
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
                    asyncio.create_task(self._handle_console_probe(spoke_id, payload.get("data", {}) or {}))
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
                    if await self._handle_agent_relay_up(spoke_id, msg_data, payload):
                        continue
                # --- End Relay Logic ---

                # Agent-initiated request (e.g. BugFixer asking for logs or to
                # trigger updates). See _handle_hub_request for the dispatch +
                # signed HUB_RESPONSE reply.
                if payload.get("type") == "HUB_REQUEST":
                    await self._handle_hub_request(spoke_id, msg_data, payload)
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
            if spoke_id and self.active_connections.get(spoke_id) is websocket:
                self._mark_spoke_disconnected(spoke_id)
                self.record_spoke_event(spoke_id, "connection_closed", "clean websocket close")
        except Exception as e:
            logger.error(f"Error handling connection for {spoke_id}: {e}")
            if spoke_id and self.active_connections.get(spoke_id) is websocket:
                self.spoke_telemetry[spoke_id] = {
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
            owns_slot = bool(spoke_id and self.active_connections.get(spoke_id) is websocket)
            if owns_slot:
                del self.active_connections[spoke_id]
                self.active_connection_key_ids.pop(spoke_id, None)
                self.spoke_module_types.pop(spoke_id, None)
                self.spoke_parent_map.pop(spoke_id, None)
                self.spoke_authenticated.pop(spoke_id, None)
                # Drop the per-connection "never authenticated" diagnosis state
                # so a reconnect that's still broken re-emits the ERROR once
                # past the grace window (instead of staying suppressed).
                self._unauth_warned_spokes.discard(spoke_id)
                # Evict every agent hosted by this spoke from the agent→spoke
                # index. They'll re-index on reconnect (next AGENT_RELAY_UP).
                # Iterate over a snapshot — mutating the dict during iteration
                # would otherwise raise RuntimeError.
                for aid in list(self.agent_info):
                    if self.agent_info.get(aid, {}).get("spoke_id") == spoke_id:
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
        # Match the LEVEL keyword, not the bare word "error" anywhere — the
        # latter false-positives on uvicorn's ``uvicorn.error`` logger name
        # (which carries INFO lifecycle lines like "connection open"), landing
        # benign INFO lines in the error log. The negative lookbehind ``(?<!\.)``
        # excludes dotted-logger-name matches (``uvicorn.error``, ``cs.error``,
        # …) while still matching `` - ERROR - `` / ``[ERROR]`` / ``ERROR:`` /
        # ``[sync-error]`` (hyphen is not a dot) and the ``Traceback`` /
        # ``Exception`` continuation lines.
        pat = re.compile(r"(?<!\.)(\berror\b|\bexception\b|\btraceback\b|\bcritical\b)",
                         re.IGNORECASE)
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

    async def handle_hub_request(self, spoke_id: str, req: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a HUB_REQUEST from an approved agent and return a result dict.

        This is the reverse of the normal Hub->spoke command direction: an
        approved agent (e.g. BugFixer) asks the Hub to do something and
        receives a correlated, signed HUB_RESPONSE. Only approved, signed
        senders reach this method (the message loop drops everyone else).
        """
        req_type = req.get("type", "") if isinstance(req, dict) else ""
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

            logger.warning(f"Unknown HUB_REQUEST type '{req_type}' from {spoke_id}")
            return {"status": "error", "message": f"unknown request type: {req_type}"}
        except Exception as e:
            logger.error(f"HUB_REQUEST '{req_type}' from {spoke_id} failed: {e}")
            return {"status": "error", "message": str(e)}

    async def run_mps_loop(self):
        """
        Calculates messages per second and throughput using a 10-second moving average.
        """
        logger.info("MPS and Throughput monitoring loop started.")
        while True:
            await asyncio.sleep(1.0)
            try:
                self.message_history.append(self.message_count)

                if len(self.message_history) > 0:
                    self.mps = sum(self.message_history) / len(self.message_history)
                else:
                    self.mps = 0.0

                self.throughput_mbps = self.bytes_count / (1024 * 1024)

                self.message_count = 0
                self.bytes_count = 0
            except Exception as e:
                logger.debug("[mps] loop iteration skipped: %s", e, exc_info=True)

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
                        self.state.save_state()
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
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({
            "ts": time.time(),
            "event": event,
            "detail": detail,
        })
        logger.info(f"[spoke-event] {spoke_id} {event}" + (f": {detail}" if detail else ""))

    def get_spoke_events(self, spoke_id: str, limit: int = 50) -> list:
        """Most-recent-first lifecycle events for a spoke (for the WebUI)."""
        buf = self.spoke_events.get(spoke_id)
        if not buf:
            return []
        out = list(buf)[-limit:]
        out.reverse()
        return out

    async def get_system_metrics(self) -> Dict[str, Any]:
        """
        Collects CPU, Memory, and Disk metrics.
        """
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            version = await self.get_local_version()

            return {
                "cpu_util": cpu,
                "mem_util": mem.percent,
                "disk_util": disk.percent,
                "disk_free": disk.free // (1024 * 1024), # MB
                "disk_total": disk.total // (1024 * 1024), # MB
                "queue_size": len(self.mailbox.get_all_pending()),
                "backlog": len(self.mailbox.get_all_pending()),
                "mps": self.mps,
                "throughput": self.throughput_mbps,
                "version": version
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
        if spoke_id not in self.active_connections:
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
                    self.state.save_state()

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
        exc = context.get("exception")
        msg = context.get("message") or "unhandled asyncio exception"
        if exc is not None:
            logger.error("Uncaught asyncio exception: %s", msg, exc_info=exc)
        else:
            logger.error("asyncio error: %s", msg)
        loop.default_exception_handler(context)

    async def start(self):
        """
        Starts the WebSocket server and background tasks.
        """
        # Route unhandled asyncio-task exceptions through the Hub logger → its
        # error log (sync excepthook installed in __init__). See req 4.
        try:
            asyncio.get_running_loop().set_exception_handler(self._asyncio_exception_relay)
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

        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())
        repo_sync_task = asyncio.create_task(self.run_repo_sync_loop())
        mps_task = asyncio.create_task(self.run_mps_loop())
        opnsense_poll_task = asyncio.create_task(self.run_opnsense_polling_loop())
        rotation_task = asyncio.create_task(self.run_key_rotation_loop())
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
        # Certificate distribution: the hub is the transport for cert material
        # from the le (Let's Encrypt) spoke to each cert's target spokes. For
        # every managed cert with stale targets it pulls fullchain+key from le
        # (LE_GET_CERT) and pushes INSTALL_CERT to the target spoke (resolved by
        # module_type); each target applies the cert to its own device via its
        # SSH/REST/console access, then LE_MARK_DISTRIBUTED records the push on
        # the le ledger. Also fired inline on /api/le/issue + /api/le/renew.
        # See run_cert_distribution_loop / _distribute_one_cert.
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
        await CSBridgePoller(self).run()

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
                if spoke_id not in hub.active_connections:
                    return None
                async def _send(msg):
                    await hub.send_to_spoke(msg)
                return _send

        conn_map = ConnectionMap()
        conn_map.hub_instance = self
        await self.mailbox.retry_loop(conn_map)

if __name__ == "__main__":
    hub = LabManagerHub()
    try:
        asyncio.run(hub.start())
    except KeyboardInterrupt:
        pass