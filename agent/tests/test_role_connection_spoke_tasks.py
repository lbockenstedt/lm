"""``RoleConnection._create_spoke_tasks`` must surface any per-connection tasks
the hosted role module exposes via a ``create_spoke_tasks(websocket)`` hook, on
top of the base agent-hosting plane's own tasks.

This is the role-hosting half of the fix that makes a role-hosted simulation
(cs) spoke emit ``CS_TELEMETRY`` — its ``CSSpoke.create_spoke_tasks`` relay task
only runs because ``RoleConnection`` invokes this hook. A role WITHOUT the hook
(most roles) must still work, returning just the base tasks and never raising.
"""
import control_plane as cp_module


class _FakeRoleInstance:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


class _HookRoleInstance(_FakeRoleInstance):
    def create_spoke_tasks(self, websocket):
        return ["relay-task"]


class _BrokenHookRoleInstance(_FakeRoleInstance):
    def create_spoke_tasks(self, websocket):
        raise RuntimeError("boom")


def _conn(role, inst):
    return cp_module.RoleConnection(
        role, base_id="agent-1", hub_url="ws://hub:8765", role_instance=inst)


def test_role_connection_surfaces_module_task_hook():
    inst = _HookRoleInstance("agent-1-dns", {})
    conn = _conn("dns", inst)
    tasks = conn._create_spoke_tasks(websocket=object())
    assert "relay-task" in tasks


def test_role_connection_without_hook_returns_base_tasks_only():
    inst = _FakeRoleInstance("agent-1-dns", {})
    conn = _conn("dns", inst)
    # No create_spoke_tasks on the module → just the (empty) base tasks, no raise.
    assert conn._create_spoke_tasks(websocket=object()) == []


def test_role_connection_broken_hook_is_best_effort():
    inst = _BrokenHookRoleInstance("agent-1-dns", {})
    conn = _conn("dns", inst)
    # A raising hook must NOT take down the hub connection setup.
    assert conn._create_spoke_tasks(websocket=object()) == []
