"""Hub side of UNINSTALL_ROLE — role-registry bookkeeping + the relay routes.

``UNLOAD_ROLE`` only stops and disables a deploy role's units, so the node keeps
reporting it as "installed (stopped)" forever. ``UNINSTALL_ROLE`` purges it for
real. On the hub that has two consequences:

  1. the durable agent→role registry must FORGET the assignment, exactly as it
     does for an unload — otherwise the hub re-pushes ``LOAD_ROLE`` on the next
     reconnect and silently redeploys the thing the operator just removed;
  2. a failed uninstall (the service binary survived the purge) must NOT forget
     it, or the node stops being managed while still advertising the role.

The registry tests forward to the REAL ``LabManagerHub`` implementations; only
the WS round-trip is stubbed.
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


class _Hub:
    """Forwards the registry methods to the real implementations."""

    def __init__(self):
        self.state = _State()
        self.active_connections = {}
        self.spoke_events = {}
        self.spoke_event_limit = 100

    def _primary_key(self, spoke_id):
        return spoke_id

    def record_spoke_event(self, spoke_id, event, detail=""):
        self.spoke_events.setdefault(spoke_id, deque(maxlen=100)).append(event)

    def _agent_roles_store(self):
        return main.LabManagerHub._agent_roles_store(self)

    def agent_assigned_roles(self, agent_id):
        return main.LabManagerHub.agent_assigned_roles(self, agent_id)

    def _record_agent_role(self, agent_id, role):
        return main.LabManagerHub._record_agent_role(self, agent_id, role)

    def _forget_agent_role(self, agent_id, role):
        return main.LabManagerHub._forget_agent_role(self, agent_id, role)

    def _track_role_rpc(self, spoke_id, command_type, data, result):
        return main.LabManagerHub._track_role_rpc(self, spoke_id, command_type, data, result)


_OK = {"payload": {"type": "COMMAND_RESULT", "data": {"status": "SUCCESS"}}}
_ERR = {"payload": {"type": "COMMAND_RESULT", "data": {"status": "ERROR"}}}


# ── registry bookkeeping ─────────────────────────────────────────────────────

def test_successful_uninstall_forgets_the_role_assignment():
    """Otherwise the hub re-pushes LOAD_ROLE on the next reconnect and quietly
    redeploys the server the operator just uninstalled."""
    hub = _Hub()
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "dhcp-server"}, _OK)
    assert hub.agent_assigned_roles("agent-r11") == ["dhcp-server"]

    hub._track_role_rpc("agent-r11", "UNINSTALL_ROLE", {"role": "dhcp-server"}, _OK)
    assert hub.agent_assigned_roles("agent-r11") == []


def test_failed_uninstall_keeps_the_role_assignment():
    """A surviving binary means the node still HAS the role; forgetting it would
    leave a managed service with nothing managing it."""
    hub = _Hub()
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "dhcp-server"}, _OK)
    hub._track_role_rpc("agent-r11", "UNINSTALL_ROLE", {"role": "dhcp-server"}, _ERR)
    assert hub.agent_assigned_roles("agent-r11") == ["dhcp-server"]


def test_uninstall_only_forgets_the_named_role():
    hub = _Hub()
    for role in ("dhcp-server", "dns-server", "console"):
        hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": role}, _OK)

    hub._track_role_rpc("agent-r11", "UNINSTALL_ROLE", {"role": "dhcp-server"}, _OK)

    assert hub.agent_assigned_roles("agent-r11") == ["console", "dns-server"]


def test_uninstall_without_a_role_is_a_no_op():
    hub = _Hub()
    hub._track_role_rpc("agent-r11", "LOAD_ROLE", {"role": "dhcp-server"}, _OK)
    hub._track_role_rpc("agent-r11", "UNINSTALL_ROLE", {}, _OK)
    assert hub.agent_assigned_roles("agent-r11") == ["dhcp-server"]


def test_uninstall_of_an_unassigned_role_does_not_crash():
    hub = _Hub()
    hub._track_role_rpc("agent-r11", "UNINSTALL_ROLE", {"role": "dns-server"}, _OK)
    assert hub.agent_assigned_roles("agent-r11") == []


# ── the tenant route: mounted, guarded, relays only UNINSTALL_ROLE ───────────

from types import SimpleNamespace  # noqa: E402

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from routes import agents  # noqa: E402


class _RouteState:
    def __init__(self, spoke_tenant):
        self._spoke_tenant = spoke_tenant
        self.system_state = {"module_metadata": {}, "module_names": {},
                             "known_modules": []}

    def get_spoke_tenant(self, module_id):
        return self._spoke_tenant


class _RouteHub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self, spoke_tenant):
        self.state = _RouteState(spoke_tenant)
        self.active_connections = {"spoke-1"}
        self.spoke_module_types = {"spoke-1": "agent"}
        self.relayed = []
        self.timeouts = []

    def _primary_key(self, sid):
        return sid

    def spoke_can_accept_commands(self, sid):
        return True, "ok"

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.relayed.append((cmd, payload))
        self.timeouts.append(timeout)
        return {"payload": {"data": {"status": "SUCCESS",
                                     "message": "uninstalled"}}}


def _client(hub, sess):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: (s or {}).get("user", {}).get("permissions", {}).get("role") == "admin",
    )
    agents.register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


def _sess(role, tenants):
    return {"user": {"permissions": {"role": role}, "tenants": tenants}}


def test_uninstall_route_relays_only_uninstall_role():
    hub = _RouteHub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/uninstall-role", json={"role": "dhcp-server"})
    assert r.status_code == 200
    assert hub.relayed == [("UNINSTALL_ROLE", {"role": "dhcp-server"})]
    assert r.json().get("status") == "SUCCESS"


def test_uninstall_route_enforces_tenant_ownership():
    hub = _RouteHub(spoke_tenant="other")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/uninstall-role", json={"role": "dhcp-server"})
    assert r.status_code == 403
    assert hub.relayed == []  # never reached the relay


def test_uninstall_route_forbids_shared_infra_for_a_tenant_admin():
    hub = _RouteHub(spoke_tenant="shared")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/uninstall-role", json={"role": "dhcp-server"})
    assert r.status_code == 403
    assert hub.relayed == []


def test_uninstall_route_forbids_a_plain_user():
    hub = _RouteHub(spoke_tenant="acme")
    c = _client(hub, _sess("user", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/uninstall-role", json={"role": "dhcp-server"})
    assert r.status_code == 403
    assert hub.relayed == []


def test_uninstall_route_requires_a_role():
    hub = _RouteHub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.post("/tenant/agent/spoke-1/uninstall-role", json={})
    assert r.status_code == 400
    assert hub.relayed == []


def test_uninstall_route_allows_a_long_purge():
    """apt may sit on the dpkg lock for up to 10 minutes before it even starts,
    so unload's 60s timeout would abort a perfectly healthy uninstall."""
    hub = _RouteHub(spoke_tenant="acme")
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    c.post("/tenant/agent/spoke-1/uninstall-role", json={"role": "dhcp-server"})
    assert hub.timeouts and hub.timeouts[0] >= 600
