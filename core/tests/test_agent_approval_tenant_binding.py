"""_perform_agent_approval's tenant binding.

An ``explicit_tenant`` (an already-validated tenant, e.g. from a matched
onboarding PSK — see main.py's ``_try_psk_agent_auto_approve``) always WINS,
even overriding an existing pin — the credential is authoritative. Absent
that, the existing spoke-tenant-inherit behavior applies, EXCEPT a spoke bound
to the SHARED tenant is no longer auto-inherited: a shared spoke can serve
agents belonging to different tenants, so inheriting it would silently
mis-tag every agent as "shared" instead of leaving it for an admin (or a
tenant-scoped onboarding PSK) to route explicitly.

Companion to test_approve_relay_durable.py, which covers the mailbox delivery
leg this reuses unchanged (a minimal FakeHub, same shape, proves that leg
works with no live spoke connection).
"""
import asyncio

import access
from routes.setup import _perform_agent_approval


class _FakeMailbox:
    def __init__(self):
        self.pushed = []
        self.queued = []

    async def push(self, msg, send_func):
        self.pushed.append((msg, send_func))

    async def queue_for_spoke(self, pk, msg):
        self.queued.append((pk, msg))


class _FakeState:
    def __init__(self):
        self.system_state = {"approved_modules": {}, "known_modules": [], "agent_config": {}}
        self._tenants = {}
        self.dirty = False
        self.saved = 0

    def get_spoke_tenant(self, spoke_id):
        return self._tenants.get(spoke_id)

    def set_spoke_tenant(self, spoke_id, tenant):
        self._tenants[spoke_id] = tenant

    def _mark_dirty(self):
        self.dirty = True

    async def save_state_now(self):
        self.saved += 1


class FakeHub:
    def __init__(self):
        self.state = _FakeState()
        self.approved_modules = {}
        self.mailbox = _FakeMailbox()
        self.active_connections = {}
        self.agent_info = {}

    def _primary_key(self, sid):
        return sid

    def _agent_primary_key(self, aid):
        return aid

    def _agent_relay_name(self, aid):
        return aid

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=False):
        return self.agent_info.get(agent_id)

    async def send_to_spoke(self, msg):
        pass


def _run(coro):
    return asyncio.run(coro)


def test_explicit_tenant_wins_over_spoke_binding():
    hub = FakeHub()
    hub.state.set_spoke_tenant("spoke-1", "tenantA")
    summary = _run(_perform_agent_approval(hub, "spoke-1", "agent-1", explicit_tenant="tenantB"))
    assert summary["tenant_inherited"] == "tenantB"
    cfg = hub.state.system_state["agent_config"]["agent-1"]
    assert cfg["client_simulation"]["tenant_id"] == "tenantB"


def test_explicit_tenant_overrides_an_existing_pin():
    hub = FakeHub()
    hub.state.system_state["agent_config"]["agent-1"] = {"client_simulation": {"tenant_id": "old"}}
    _run(_perform_agent_approval(hub, "spoke-1", "agent-1", explicit_tenant="new-tenant"))
    cfg = hub.state.system_state["agent_config"]["agent-1"]
    assert cfg["client_simulation"]["tenant_id"] == "new-tenant"


def test_inherits_spoke_tenant_when_no_explicit_tenant_and_no_existing_pin():
    hub = FakeHub()
    hub.state.set_spoke_tenant("spoke-1", "tenantA")
    summary = _run(_perform_agent_approval(hub, "spoke-1", "agent-1"))
    assert summary["tenant_inherited"] == "tenantA"
    cfg = hub.state.system_state["agent_config"]["agent-1"]
    assert cfg["client_simulation"]["tenant_id"] == "tenantA"


def test_inherit_does_not_override_an_existing_pin():
    hub = FakeHub()
    hub.state.set_spoke_tenant("spoke-1", "tenantA")
    hub.state.system_state["agent_config"]["agent-1"] = {"client_simulation": {"tenant_id": "keep-me"}}
    _run(_perform_agent_approval(hub, "spoke-1", "agent-1"))
    cfg = hub.state.system_state["agent_config"]["agent-1"]
    assert cfg["client_simulation"]["tenant_id"] == "keep-me"


def test_shared_tenant_spoke_is_not_auto_inherited(monkeypatch):
    hub = FakeHub()
    hub.state.set_spoke_tenant("spoke-1", "shared-tid")
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "shared-tid")
    summary = _run(_perform_agent_approval(hub, "spoke-1", "agent-1"))
    assert summary["tenant_inherited"] is None
    assert "agent-1" not in hub.state.system_state["agent_config"]


def test_shared_tenant_spoke_still_honors_explicit_tenant(monkeypatch):
    """A PSK-validated tenant_hint wins even when the RELAYING spoke happens
    to be the shared one — the credential is authoritative, not the spoke."""
    hub = FakeHub()
    hub.state.set_spoke_tenant("spoke-1", "shared-tid")
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", "shared-tid")
    summary = _run(_perform_agent_approval(hub, "spoke-1", "agent-1", explicit_tenant="tenantC"))
    assert summary["tenant_inherited"] == "tenantC"


def test_no_spoke_tenant_and_no_explicit_tenant_leaves_agent_unbound():
    hub = FakeHub()
    summary = _run(_perform_agent_approval(hub, "spoke-1", "agent-1"))
    assert summary["tenant_inherited"] is None
    assert "agent-1" not in hub.state.system_state["agent_config"]


def test_approval_flag_and_known_modules_cleanup_unaffected_by_tenant_path():
    """The approval-persist + known_modules cleanup at the top of the function
    is unrelated to the tenant path — pin it stays intact regardless."""
    hub = FakeHub()
    hub.state.system_state["known_modules"] = ["agent-1", "other-spoke"]
    _run(_perform_agent_approval(hub, "spoke-1", "agent-1", explicit_tenant="tenantB"))
    assert hub.approved_modules["agent-1"] is True
    assert "agent-1" not in hub.state.system_state["known_modules"]
    assert "other-spoke" in hub.state.system_state["known_modules"]
