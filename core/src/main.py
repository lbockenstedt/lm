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

import asyncio
import base64
import datetime as _dt
import hmac
import json
import logging
import threading
import time
import subprocess
import httpx
import psutil
import os
import uuid
import secrets
import tarfile
import io
import shutil
import tempfile
from collections import deque
from typing import Dict, Any, Optional, List
from dataclasses import asdict
import websockets

from messaging.protocol import Message, MessageHeader, MessagePayload, Acknowledgement
from messaging.mailbox import Mailbox
from messaging.heartbeat import HeartbeatManager
from security.key_manager import KeyManager
from state.manager import StateManager
from simulations.broadcaster import SimulationsBroadcaster
from simulations.store import SimulationsStore
from security.auth_manager import AuthManager, LDAPAuthProvider
from api import run_api_server, _save_sessions
from update_recovery import (
    snapshot_code, write_pending, clear_pending,
    is_version_bad, clear_bad_versions_older_than,
)
from update_pipeline import UpdatePipelineMixin
from endpoint_sync import EndpointSyncMixin
from vm_sync import VmSyncMixin

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("Hub")

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
}

# spoke_id substring → push_config branch tag. NOTE: the prefix-fallback loop
# in push_config_to_spoke iterates these KEYS (it sets module_key = key), so the
# values are NOT consumed there — they're kept aligned with _PUSH_CONFIG_MODULE_KEY
# ("opn" → "opn") purely so a reader isn't misled into thinking a firewall prefix
# resolves to the "opnsense" update-source config key (see _UPDATE_SOURCE_PREFIX_MAP,
# where "opn" → "opnsense" IS a real, used value).
_PUSH_CONFIG_PREFIX_MAP = {
    'pxmx': 'pxmx', 'opn': 'opn', 'cs': 'cs',
    'cppm': 'cppm', 'netbox': 'netbox', 'ldap': 'ldap',
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

class LabManagerHub(UpdatePipelineMixin, EndpointSyncMixin, VmSyncMixin):
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
        self.mailbox = Mailbox()
        self.heartbeat = HeartbeatManager()
        self.key_manager = KeyManager()
        self.state = StateManager()

        # Initialize Auth with LDAP
        self.auth = AuthManager(LDAPAuthProvider({"server": "ldap://localhost"}))

        # State is now managed via StateManager methods
        self.approved_modules = self.state.get_approved_modules()
        self.known_modules = self.state.system_state.get("known_modules", [])

        # { spoke_id: str } tracking spoke versions
        self.spoke_versions: Dict[str, str] = {}
        # { spoke_id: module_type } — e.g. {"pxmx-spoke-1": "hypervisor"}
        self.spoke_module_types: Dict[str, str] = {}

        # --- System Diagnostics ---
        self.logs = deque(maxlen=500)
        self.agent_logs = {} # { agent_id: deque(logs) }
        self.max_log_size = 1000
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
                msg = self.format(record)
                self.hub.logs.append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}")

        log_handler = HubLogHandler(self)
        log_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(log_handler)

        # { spoke_id: websocket_connection }
        self.active_connections: Dict[str, websockets.WebSocketServerProtocol] = {}
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
        # VNC console sessions (agent-terminates-WSS): session_id →
        # {queue, expires, ws_token, spoke_id, tenant_id, vmid, node, unique_id}.
        # The browser WS reads Proxmox→browser frames off ``queue`` (bytes) or
        # control tuples ("ready"/"error"/"disconnect"); VNC_FRAME_DOWN sends
        # the other way via send_to_spoke_command (fire-and-forget). 60s TTL.
        self.vnc_sessions: Dict[str, Dict[str, Any]] = {}
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


    async def send_to_spoke(self, message: Message):
        """
        The low-level send function used by the Mailbox.
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
            message.signature = self.key_manager.sign_message(spoke_id, {
                "header": header_dict,
                "payload": payload_dict
            })

            payload = {
                "header": header_dict,
                "payload": payload_dict,
                "signature": message.signature
            }
            json_payload = json.dumps(payload, separators=(',', ':'))
            self.bytes_count += len(json_payload.encode())
            await ws.send(json_payload)
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

    async def request_response(self, spoke_id: str, command_type: str, data: Dict[str, Any], timeout: float = 5.0) -> Dict[str, Any]:
        """
        Sends a command to a spoke and waits for its acknowledgement.
        """
        msg_id = str(uuid.uuid4())
        logger.info(f"Request: {msg_id} -> {spoke_id} [{command_type}] data={_redact(command_type, data)}")
        msg = Message(
            header=MessageHeader(
                message_id=msg_id,
                timestamp=time.time(),
                sender_id="hub",
                destination_id=spoke_id
            ),
            payload=MessagePayload(type=command_type, data=data)
        )

        await self.send_to_spoke(msg)

        # Wait for the response in the mailbox
        self._outstanding_requests.add(msg_id)
        start_time = time.time()
        try:
            while time.time() - start_time < timeout:
                await asyncio.sleep(0.1)
                if msg_id in getattr(self, "response_cache", {}):
                    result = self.response_cache.pop(msg_id)
                    logger.info(f"Response: {msg_id} received from {spoke_id}: {_redact(command_type, result)}")
                    return result

            logger.error(f"Request Timeout: {msg_id} from {spoke_id} after {timeout}s")
            return {"status": "ERROR", "message": "Timed out waiting for spoke response"}
        finally:
            # Drop the waiter so a late ack can't leak a response_cache entry.
            self._outstanding_requests.discard(msg_id)

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

    # ── VNC console sessions (agent-terminates-WSS) ───────────────────────────
    # The browser opens /ws/console/{session_id}; Proxmox→browser frames land on
    # the session queue via _handle_agent_relay_up (VNC_FRAME_UP), and browser→
    # Proxmox frames go out via send_to_spoke_command (VNC_FRAME_DOWN). 60s TTL
    # so an unclaimed session (browser never connects) is reaped.

    VNC_SESSION_TTL = 60

    def register_vnc_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        """Create the session's frame queue and store its metadata."""
        self.vnc_sessions[session_id] = {
            "queue": asyncio.Queue(),
            "expires": time.time() + self.VNC_SESSION_TTL,
            **meta,
        }

    def get_vnc_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Return a live session dict (queue + meta) or None if absent/expired.
        Expired sessions are reaped on read."""
        sess = self.vnc_sessions.get(session_id)
        if not sess:
            return None
        if sess.get("expires", 0) < time.time():
            self.vnc_sessions.pop(session_id, None)
            return None
        return sess

    def unregister_vnc_session(self, session_id: str) -> None:
        self.vnc_sessions.pop(session_id, None)

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
        an admin at approval time. Falls back to the first available Client-Sim
        spoke when there is no binding for the tenant (admin/global view, or a
        spoke that hasn't been tenant-assigned yet). Returns None if no Client-Sim
        spoke is connected+approved.
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
        # Fallback: first available (admin / unassigned).
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
    }

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
        cs_spoke = self.get_client_sim_spoke(tenant_id)
        if not cs_spoke:
            logger.debug("CS_* relay: no cs spoke for tenant=%s (agent=%s, %s) — dropping",
                         tenant_id, agent_id, cs_type)
            return
        payload = {"hostname": hostname, **(data or {})}
        try:
            await self.request_response(cs_spoke, mapped, payload, timeout=5.0)
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

            # Handle Firewall multi-instance config
            if module_key == 'opn':
                firewalls = self.state.get_global_config().get("firewalls", [])
                fw_config = next((f for f in firewalls if f.get("spoke_id") == spoke_id), None)
                if fw_config:
                    config = fw_config
                else:
                    opn_fws = [f for f in firewalls if f.get("model") == "opnsense"]
                    config = opn_fws[0] if opn_fws else {}
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
            session_secret = self.key_manager.generate_first_secret(spoke_id)
            key_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(
                    type="SPOKE_UPDATE_SESSION_KEY", data={"secret": session_secret}))
            await self.send_to_spoke(key_msg)
            approval_msg = Message(
                header=MessageHeader(
                    message_id=str(uuid.uuid4()), timestamp=time.time(),
                    sender_id="hub", destination_id=spoke_id),
                payload=MessagePayload(type="APPROVED", data={}))
            await self.send_to_spoke(approval_msg)
            await self.push_config_to_spoke(spoke_id)

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
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            for entry in entries:
                if isinstance(entry, str):
                    self.agent_logs[spoke_id].append(f"{ts} - {entry}")
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

        logger.info(f"Relayed message from Agent {agent_id} via Spoke {spoke_id}: {original_msg.get('payload', {}).get('type')}")

        # Handle Agent Logs
        if original_msg.get("payload", {}).get("type") == "AGENT_LOG":
            log_data = original_msg.get("payload", {}).get("data", {})
            log_msg = f"[{log_data.get('hostname', 'unknown')}] ({log_data.get('agent_type', 'agent')}) {log_data.get('level', 'INFO')}: {log_data.get('message')}"

            if agent_id not in self.agent_logs:
                self.agent_logs[agent_id] = deque(maxlen=self.max_log_size)
            self.agent_logs[agent_id].append(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {log_msg}")
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

            logger.info(f"Auth attempt: spoke_id={spoke_id}, secret={f'{secret[:4]}...{secret[-4:]}' if secret and len(secret) > 8 else '***'}")
            self.record_spoke_event(spoke_id, "auth_attempt", f"secret={'yes' if secret else 'no'} module_type={module_type}")

            if not spoke_id:
                await websocket.close(1008, "Missing spoke_id")
                return

            # If secret is provided, verify it. If not, the spoke is in 'pending secret' state.
            is_authenticated = False
            if secret:
                key_id = self.key_manager.get_valid_key(spoke_id, secret)
                if key_id:
                    is_authenticated = True
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
                self.active_connections[spoke_id] = websocket
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

            # Ensure connection is tracked even if not fully auth'd (for negotiation)
            self.active_connections[spoke_id] = websocket

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
                    session_secret = self.key_manager.generate_first_secret(spoke_id)
                    key_msg = Message(
                        header=MessageHeader(
                            message_id=str(uuid.uuid4()), timestamp=time.time(),
                            sender_id="hub", destination_id=spoke_id),
                        payload=MessagePayload(
                            type="SPOKE_UPDATE_SESSION_KEY",
                            data={"secret": session_secret}))
                    await self.send_to_spoke(key_msg)
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
                else:
                    # No signature provided. Allow ONLY heartbeats for unauthenticated spokes.
                    payload = msg_data.get("payload", {})
                    if payload.get("type") != "HEARTBEAT":
                        logger.warning(f"Unauthenticated message from {spoke_id} (only HEARTBEAT allowed). Dropping.")
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
                    continue

                # If the module is not approved, ignore all other messages
                if not self.approved_modules.get(spoke_id, False):
                    logger.debug(f"Dropping message from unapproved module {spoke_id}")
                    continue

                # Process Acknowledgement
                if "correlation_id" in msg_data:
                    corr_id = msg_data["correlation_id"]
                    ack = Acknowledgement(
                        correlation_id=corr_id,
                        status=msg_data.get("status", "FAILED"),
                        error=msg_data.get("error")
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

        except websockets.ConnectionClosed:
            logger.info(f"Connection closed for spoke {spoke_id}")
            if spoke_id:
                self.spoke_telemetry[spoke_id]["status"] = "DISCONNECTED"
            self.record_spoke_event(spoke_id, "connection_closed", "clean websocket close")
        except Exception as e:
            logger.error(f"Error handling connection for {spoke_id}: {e}")
            if spoke_id:
                self.spoke_telemetry[spoke_id] = {
                    "last_attempt": time.time(),
                    "status": "ERROR",
                    "error": str(e)
                }
            self.record_spoke_event(spoke_id, "connection_error", str(e))
        finally:
            if spoke_id and spoke_id in self.active_connections:
                del self.active_connections[spoke_id]
            if spoke_id:
                self.spoke_module_types.pop(spoke_id, None)

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
        pat = re.compile(r"\b(error|exception|traceback|critical)\b", re.IGNORECASE)
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
        return {"logs": errs}

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
                return self.collect_all_logs()

            if req_type == "GET_ERROR_LOGS":
                return self.collect_error_logs()

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
                rep = self._get_bug_report(rid)
                logger.info(
                    f"[bug-report] GET_BUG_REPORT id={rid} from {spoke_id}: "
                    f"{'hit' if rep else 'miss'}"
                )
                return rep

            if req_type == "MARK_BUG_FILED":
                rid = req.get("id", "")
                issue_url = req.get("issue_url", "")
                ok = self._mark_bug_filed(rid, issue_url)
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
        expected = ["pxmx-spoke-1", "netbox-spoke-1", "opn-spoke-1", "cppm-spoke-1", "cs-spoke-1"]
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
                if snap != last or cycle % 20 == 0:
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
                    logger.info("[spoke-diag] " + " ".join(parts))
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
                if usb_parts != last_usb or cycle % 20 == 0:
                    logger.info("[usb-telemetry] " + " | ".join(usb_parts)
                                + (" | NO_USB_DATA means the cs spoke reports VMs but no USB — "
                                   "it is not aggregating USB into its CS_TELEMETRY payload"
                                   if any("NO_USB_DATA" in p for p in usb_parts) else ""))
                    last_usb = usb_parts
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
        """spoke_id (e.g. 'cs-spoke-1') -> systemd unit (e.g. 'lm-cs'), or ''."""
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

    # ── "File a Bug" report store ────────────────────────────────────────────
    # The WebUI footer button POSTs an explanation + console + HTML + screenshot
    # to /api/bug-report. The full artifacts are written under data_dir/bugs/<id>/
    # and a short [bug-report] marker line is logged (so bugfixer's GET_LOGS scan
    # finds it). bugfixer enumerates via GET_BUG_REPORTS, pulls full artifacts via
    # GET_BUG_REPORT (for AI-fix context), and marks filed via MARK_BUG_FILED so
    # the same report is never filed twice.
    def _store_bug_report(self, payload: dict) -> str:
        rid = uuid.uuid4().hex[:12]
        d = os.path.join(self.bug_dir, rid)
        try:
            os.makedirs(d, exist_ok=True)
        except Exception as e:
            logger.warning(f"[bug-report] could not create report dir {d}: {e}")
            return ""
        explanation = str(payload.get("explanation") or "")
        severity = str(payload.get("severity") or "medium")
        context = payload.get("context") or {}
        # Persist the structured metadata + the captured text artifacts.
        report_json = {
            "id": rid, "explanation": explanation, "severity": severity,
            "context": context, "filed": False, "issue_url": "",
            "ts": time.time(),
        }
        try:
            with open(os.path.join(d, "report.json"), "w") as f:
                json.dump(report_json, f, indent=2)
            with open(os.path.join(d, "console.log"), "w") as f:
                f.write(str(payload.get("console_logs") or ""))
            with open(os.path.join(d, "dom.html"), "w") as f:
                f.write(str(payload.get("html") or ""))
        except Exception as e:
            logger.warning(f"[bug-report] failed writing artifacts for {rid}: {e}")
        # Screenshot is a data URL; decode to bytes so it's a real PNG/JPEG file.
        shot = payload.get("screenshot")
        if isinstance(shot, str) and shot.startswith("data:"):
            try:
                header, b64 = shot.split(",", 1)
                ext = "png" if "image/png" in header else "jpg"
                with open(os.path.join(d, f"screenshot.{ext}"), "wb") as f:
                    f.write(base64.b64decode(b64))
                report_json["screenshot_file"] = f"screenshot.{ext}"
            except Exception as e:
                logger.warning(f"[bug-report] failed decoding screenshot for {rid}: {e}")
        # In-memory index (capped). Holds the metadata bugfixer lists; full
        # artifacts are read from disk on demand by _get_bug_report.
        self.bug_reports[rid] = {
            "id": rid, "summary": explanation[:120], "severity": severity,
            "ts": report_json["ts"], "filed": False, "issue_url": "",
            "context": context, "has_screenshot": "screenshot_file" in report_json,
        }
        while len(self.bug_reports) > self.bug_report_limit:
            oldest = min(self.bug_reports, key=lambda k: self.bug_reports[k].get("ts", 0))
            self.bug_reports.pop(oldest, None)
        # Authoritative "report is on disk and ready for bugfixer" trace line.
        logger.info(
            f"[bug-report] stored id={rid} severity={severity} "
            f"console={len(str(payload.get('console_logs') or ''))} "
            f"html={len(str(payload.get('html') or ''))} "
            f"screenshot={report_json.get('screenshot_file') or 'none'} "
            f"dir={d} index_size={len(self.bug_reports)}"
        )
        return rid

    def _list_bug_reports(self) -> list:
        return [dict(v) for v in self.bug_reports.values()]

    def _get_bug_report(self, rid: str) -> dict:
        meta = self.bug_reports.get(rid)
        d = os.path.join(self.bug_dir, rid)
        if not meta or not os.path.isdir(d):
            return {}
        out = {
            "id": rid, "summary": meta.get("summary", ""), "severity": meta.get("severity", ""),
            "ts": meta.get("ts", 0), "filed": meta.get("filed", False),
            "issue_url": meta.get("issue_url", ""), "context": meta.get("context", {}),
        }
        for name in ("report.json", "console.log", "dom.html"):
            p = os.path.join(d, name)
            if os.path.exists(p):
                try:
                    with open(p, "r") as f:
                        out[name.replace(".json", "_json").replace(".log", "").replace(".html", "")] = f.read()
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
        # Screenshot back as a data URL so bugfixer can pass it to the AI as
        # context if useful (kept out of the public GitHub issue).
        for ext in ("png", "jpg"):
            p = os.path.join(d, f"screenshot.{ext}")
            if os.path.exists(p):
                try:
                    with open(p, "rb") as f:
                        b64 = base64.b64encode(f.read()).decode()
                    mime = "image/png" if ext == "png" else "image/jpeg"
                    out["screenshot_b64"] = f"data:{mime};base64,{b64}"
                except Exception:
                    logger.debug("bug-report: failed reading %s for %s", p, rid, exc_info=True)
                break
        return out

    def _mark_bug_filed(self, rid: str, issue_url: str) -> bool:
        meta = self.bug_reports.get(rid)
        if not meta:
            return False
        meta["filed"] = True
        meta["issue_url"] = issue_url or ""
        # Persist to report.json too so the filed flag survives a hub restart.
        p = os.path.join(self.bug_dir, rid, "report.json")
        try:
            with open(p, "r") as f:
                rpt = json.load(f)
            rpt["filed"] = True
            rpt["issue_url"] = issue_url or ""
            with open(p, "w") as f:
                json.dump(rpt, f, indent=2)
        except Exception as e:
            logger.warning(f"[bug-report] could not persist filed flag for {rid}: {e}")
        return True

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

    async def run_autoupdate_loop(self):
        """
        Background loop that checks for updates based on global configuration.
        """
        logger.info("Auto-update loop started.")
        while True:
            try:
                config = self.state.get_global_config()
                enabled = config.get("autoupdate", True) # Default to enabled
                interval_hours = config.get("update_interval", 1) # Default to 1 hour

                if enabled:
                    logger.info(f"Auto-update enabled. Checking for updates every {interval_hours} hours.")
                    logger.info("Performing scheduled auto-update check...")
                    await self.perform_update()
                    await asyncio.sleep(interval_hours * 3600)
                else:
                    await asyncio.sleep(300)
            except Exception as e:
                logger.error(f"Error in auto-update loop: {e}", exc_info=True)
                await asyncio.sleep(300)

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
            result = await self.request_response(spoke_id, "OPNSENSE_GET_ALL_RULES", {})

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
                if not os.path.exists(self.cache_dir):
                    os.makedirs(self.cache_dir, exist_ok=True)

                cache_filename = f"rules_{cache_key}.json"
                cache_path = os.path.join(self.cache_dir, cache_filename)
                with open(cache_path, "w") as f:
                    json.dump(data, f)
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
                        rotated.append((sid, msg))

                async def _push_session_key(sid, msg):
                    try:
                        await self.send_to_spoke(msg)
                        logger.info(f"New session key pushed to {sid}")
                    except Exception as e:
                        logger.error(f"Failed to push session key to {sid}: {e}")

                if rotated:
                    await asyncio.gather(*(_push_session_key(sid, msg) for sid, msg in rotated))

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
                interval_hours = config.get("opnsense_poll_interval", 1)

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

    async def start(self):
        """
        Starts the WebSocket server and background tasks.
        """
        version = "unknown"
        try:
            version_path = os.path.join(os.path.dirname(__file__), "../../VERSION")
            if not os.path.exists(version_path):
                version_path = os.path.join(os.path.dirname(__file__), "../VERSION")

            with open(version_path, "r") as f:
                version = f.read().strip()
        except Exception as e:
            logger.debug(f"Could not load version file: {e}")

        api_thread = threading.Thread(target=run_api_server, args=(self,), daemon=True)
        api_thread.start()

        retry_task = asyncio.create_task(self.run_retry_loop())
        persistence_task = asyncio.create_task(self.state.persistence_loop())
        autoupdate_task = asyncio.create_task(self.run_autoupdate_loop())
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
        # CS bridge: polls the cs (Client-Simulation) spoke's command inbox for
        # every CS-enabled connected pxmx agent and relays commands to the agent
        # as CS_COMMAND (one-socket invariant — the agent never talks to the cs
        # spoke directly), acks terminal results, and syncs USB config down via
        # SET_AGENT_CONFIG. See gateway/cs_bridge.py (Phase D2).
        cs_bridge_task = asyncio.create_task(self.run_cs_bridge_loop())

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
        async with websockets.serve(self.handle_connection, self.host, self.port, compression=None, max_size=16 * 1024 * 1024) as server:
            self.is_ready = True
            logger.info(f"Lab Manager Hub {version} started on ws://{self.host}:{self.port}")
            logger.info(f"Hub API started on port 8000")
            await asyncio.Future()


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
                logger.info(
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