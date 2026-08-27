"""Durable per-agent role registry + reconnect re-adoption (hub side).

A WebUI ``LOAD_ROLE`` makes a base ``agent`` spoke host a role sub-spoke
(``{base}-{role}``). If the agent later loses its spoke-side ``.env``
``LOADED_ROLES`` record it boots ``roles=none`` and the role silently vanishes
until a human re-loads it (the recurring console-vanished outage). The hub now
keeps a durable ``agent_roles`` registry (``system_state``, keyed by the agent's
primary key) and, on the agent's reconnect, re-pushes ``LOAD_ROLE`` for every
assigned role whose sub-spoke isn't currently connected.

These tests exercise the registry accessors + ``_readopt_agent_roles`` against a
minimal fake hub that forwards to the REAL ``LabManagerHub`` /
``SpokeRegistryMixin`` implementations (only the WS round-trip is stubbed).
"""

import asyncio
import os
import sys
from collections import deque

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402


class _State:
    def __init__(self):
        self.system_state = {}
        self.dirty = 0

    def _mark_dirty(self):
        self.dirty += 1


class _ReadoptHub:
    """Forwards the registry + re-adopt methods to the real implementations."""

    def __init__(self, command_ready=True):
        self.state = _State()
        self.active_connections = {}
        self.spoke_events = {}
        self.spoke_event_limit = 100
        self._command_ready = command_ready
        self.load_role_calls = []  # (spoke_id, role)

    def _primary_key(self, spoke_id):
        return spoke_id

    def record_spoke_event(self, spoke_id, event, detail=""):
        buf = self.spoke_events.setdefault(spoke_id, deque(maxlen=self.spoke_event_limit))
        buf.append({"event": event, "detail": detail})

    def spoke_can_accept_commands(self, spoke_id):
        return (True, "") if self._command_ready else (False, "unauthenticated")

    async def request_response(self, spoke_id, command_type, data, timeout=5.0,
                               signing_secret=None):
        assert command_type == "LOAD_ROLE", command_type
        await asyncio.sleep(0)  # yield so overlapping re-adopts can interleave
        self.load_role_calls.append((spoke_id, (data or {}).get("role")))
        return {"payload": {"type": "COMMAND_RESULT", "data": {"status": "SUCCESS"}}}

    # ── forwarded real implementations ──
    def _agent_roles_store(self):
        return main.LabManagerHub._agent_roles_store(self)

    def agent_assigned_roles(self, agent_id):
        return main.LabManagerHub.agent_assigned_roles(self, agent_id)

    def _record_agent_role(self, agent_id, role):
        return main.LabManagerHub._record_agent_role(self, agent_id, role)

    def _forget_agent_role(self, agent_id, role):
        return main.LabManagerHub._forget_agent_role(self, agent_id, role)

    def _readopt_agent_roles(self, agent_id):
        return main.LabManagerHub._readopt_agent_roles(self, agent_id)

    def _track_role_rpc(self, spoke_id, command_type, data, result):
        return main.LabManagerHub._track_role_rpc(self, spoke_id, command_type, data, result)


_LOAD_OK = {"payload": {"type": "COMMAND_RESULT", "data": {"status": "SUCCESS"}}}
_ERR = {"payload": {"type": "COMMAND_RESULT", "data": {"status": "ERROR"}}}


def test_track_rpc_records_on_load_success_and_forgets_on_unload():
    hub = _ReadoptHub()
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "console"}, _LOAD_OK)
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "dns"}, _LOAD_OK)
    assert hub.agent_assigned_roles("agent-r11") == ["console", "dns"]
    hub._track_role_rpc("agent-r11", "UNLOAD_ROLE", {"role": "dns"}, _LOAD_OK)
    assert hub.agent_assigned_roles("agent-r11") == ["console"]


def test_track_rpc_ignores_failed_load_and_other_commands():
    hub = _ReadoptHub()
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "console"}, _ERR)
    hub._track_role_rpc("agent-r11", "GET_VERSION", {}, _LOAD_OK)
    assert hub.agent_assigned_roles("agent-r11") == []


def test_record_is_durable_and_deduped():
    hub = _ReadoptHub()
    hub._record_agent_role("agent-r11", "console")
    hub._record_agent_role("agent-r11", "console")  # dup → no churn
    hub._record_agent_role("agent-r11", "dns")
    assert hub.agent_assigned_roles("agent-r11") == ["console", "dns"]
    # Persisted into system_state so it survives a hub restart.
    assert hub.state.system_state["agent_roles"]["agent-r11"] == ["console", "dns"]
    # dirty marked once per genuinely-new role (dup was a no-op).
    assert hub.state.dirty == 2


def test_forget_removes_role_and_prunes_empty():
    hub = _ReadoptHub()
    hub._record_agent_role("agent-r11", "console")
    hub._record_agent_role("agent-r11", "dns")
    hub._forget_agent_role("agent-r11", "console")
    assert hub.agent_assigned_roles("agent-r11") == ["dns"]
    hub._forget_agent_role("agent-r11", "dns")
    # Last role gone → the agent's key is pruned entirely.
    assert "agent-r11" not in hub.state.system_state["agent_roles"]


def test_readopt_repushes_only_offline_roles():
    hub = _ReadoptHub()
    hub._record_agent_role("agent-r11", "console")
    hub._record_agent_role("agent-r11", "dns")
    # dns is already live (its sub-spoke is connected); console is offline.
    hub.active_connections["agent-r11-dns"] = object()
    asyncio.run(hub._readopt_agent_roles("agent-r11"))
    assert hub.load_role_calls == [("agent-r11", "console")]
    # A re-adopt event was recorded for the healed role.
    events = [e["detail"] for e in hub.spoke_events.get("agent-r11", [])]
    assert "role=console" in events


def test_readopt_noop_without_recorded_roles():
    hub = _ReadoptHub()
    asyncio.run(hub._readopt_agent_roles("agent-r11"))
    assert hub.load_role_calls == []


def test_readopt_skips_when_never_command_ready():
    hub = _ReadoptHub(command_ready=False)
    hub._record_agent_role("agent-r11", "console")
    asyncio.run(hub._readopt_agent_roles("agent-r11"))
    assert hub.load_role_calls == []


def test_readopt_single_flight_per_agent():
    hub = _ReadoptHub()
    hub._record_agent_role("agent-r11", "console")

    async def _drive():
        # Two overlapping re-adopts for the same agent — only one may push.
        await asyncio.gather(hub._readopt_agent_roles("agent-r11"),
                             hub._readopt_agent_roles("agent-r11"))

    asyncio.run(_drive())
    assert hub.load_role_calls == [("agent-r11", "console")]
