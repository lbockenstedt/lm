"""``RoleConnection._start_role_local_services`` must invoke the hosted role
module's PROCESS-scoped startup hooks (``start_background_loops`` +
``start_client_api_server``) once, and ``_stop_role_local_services`` must signal
the module's ``stop_client_api_server`` on teardown.

This is the role-hosting half of the fix that makes a generic-agent-hosted
simulation (cs) spoke actually open its 8080 client check-in API and run its
pollers/quota engine — the exact set the standalone ``CSControlPlane.run``
starts. Without it a role-hosted cs spoke's sim VMs get DHCP but have nowhere to
check in (every one shows "never checked in"). Roles that expose neither hook
(dns/ldap/…) must no-op and never raise.
"""
import control_plane as cp_module


class _FakeRoleInstance:
    def __init__(self, spoke_id, config):
        self.spoke_id = spoke_id
        self.config = config


class _LocalServicesRoleInstance(_FakeRoleInstance):
    control_plane = None

    def __init__(self, spoke_id, config):
        super().__init__(spoke_id, config)
        self.calls = []

    def start_background_loops(self):
        self.calls.append("loops")

    def start_client_api_server(self):
        self.calls.append("api")

    def stop_client_api_server(self):
        self.calls.append("stop")


class _BrokenLocalServicesRoleInstance(_FakeRoleInstance):
    def start_background_loops(self):
        raise RuntimeError("boom")

    def start_client_api_server(self):
        raise RuntimeError("boom")


def _conn(role, inst):
    return cp_module.RoleConnection(
        role, base_id="agent-1", hub_url="ws://hub:8765", role_instance=inst)


def test_start_role_local_services_invokes_both_hooks_and_sets_backref():
    inst = _LocalServicesRoleInstance("agent-1-simulation", {})
    conn = _conn("simulation", inst)
    conn._start_role_local_services()
    # Both process-scoped hooks fired, in order (loops before the listener).
    assert inst.calls == ["loops", "api"]
    # control_plane back-ref wired (was None → set to the connection).
    assert inst.control_plane is conn


def test_stop_role_local_services_signals_api_shutdown():
    inst = _LocalServicesRoleInstance("agent-1-simulation", {})
    conn = _conn("simulation", inst)
    conn._start_role_local_services()
    conn._stop_role_local_services()
    assert inst.calls == ["loops", "api", "stop"]


def test_role_without_local_service_hooks_is_noop():
    inst = _FakeRoleInstance("agent-1-dns", {})
    conn = _conn("dns", inst)
    # No hooks on the module → both calls are silent no-ops, never raise.
    conn._start_role_local_services()
    conn._stop_role_local_services()


def test_broken_local_service_hook_is_best_effort():
    inst = _BrokenLocalServicesRoleInstance("agent-1-simulation", {})
    conn = _conn("simulation", inst)
    # A raising hook must NOT take down role startup.
    conn._start_role_local_services()
