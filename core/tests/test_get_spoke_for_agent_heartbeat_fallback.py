"""``get_spoke_for_agent`` (``hub_spoke_registry.py``) — durable heartbeat
fallback for the ``fallback_hypervisor=False`` path.

Reported bug: a Proxmox host correctly PINNED to a tenant via
``agent_config[agent].client_simulation.tenant_id`` still had its VMs missing
from that tenant's Hypervisors page. ``_merge_pinned_agent_vms``
(``routes/pxmx.py``) calls ``get_spoke_for_agent(agent_id,
fallback_hypervisor=False)`` to resolve which spoke to query for that pinned
agent's VMs — but the pre-fix implementation consulted ONLY ``agent_info``
(in-memory, wiped on hub restart / evicted on spoke disconnect, lags connect
~30s). When ``agent_info`` has no entry for an otherwise-healthy agent, the
resolver returned ``None``, and the pinned agent was silently skipped from the
merge entirely — the agent_config pin was correct, but the VM merge couldn't
even find which spoke to ask.

``_spoke_effective_tenants`` already solves the identical staleness problem
for Overview/node visibility via the DURABLE composite heartbeat key
``{spoke_pk}:{agent_pk}`` (persisted through ``spoke_last_seen``, re-seeded
into ``heartbeat.last_seen`` on boot). This fix adds the same fallback to
``get_spoke_for_agent``.
"""
from main import LabManagerHub


class _HB:
    def __init__(self, last_seen):
        self.last_seen = last_seen or {}


class _FakeHub:
    def __init__(self, active, agent_info=None, heartbeat_last_seen=None):
        self.active_connections = set(active)
        self.agent_info = agent_info or {}
        self.heartbeat = _HB(heartbeat_last_seen)

    def _primary_key(self, sid):
        return sid

    def _agent_primary_key(self, agent_id):
        return agent_id

    def get_hypervisor_spoke(self):
        return None


def test_resolves_via_agent_info_when_fresh():
    hub = _FakeHub(
        active=["pxmx-shared"],
        agent_info={"ag-1": {"spoke_id": "pxmx-shared"}})
    assert LabManagerHub.get_spoke_for_agent(
        hub, "ag-1", fallback_hypervisor=False) == "pxmx-shared"


def test_falls_back_to_durable_heartbeat_key_when_agent_info_is_empty():
    """agent_info wiped (hub restart / spoke disconnect-reconnect) — the
    DURABLE composite heartbeat key must still resolve the owning spoke so a
    pinned agent's VMs aren't silently dropped from the merge."""
    hub = _FakeHub(
        active=["pxmx-shared"],
        agent_info={},  # wiped
        heartbeat_last_seen={"pxmx-shared:ag-1": 123.0})
    assert LabManagerHub.get_spoke_for_agent(
        hub, "ag-1", fallback_hypervisor=False) == "pxmx-shared"


def test_returns_none_when_neither_signal_has_the_agent():
    hub = _FakeHub(active=["pxmx-shared"], agent_info={}, heartbeat_last_seen={})
    assert LabManagerHub.get_spoke_for_agent(
        hub, "ag-1", fallback_hypervisor=False) is None


def test_heartbeat_fallback_ignores_a_disconnected_spoke():
    """A composite key for a spoke that is no longer connected must not
    resolve — never widen visibility to a dead spoke."""
    hub = _FakeHub(
        active=["other-spoke"],
        agent_info={},
        heartbeat_last_seen={"pxmx-shared:ag-1": 123.0})
    assert LabManagerHub.get_spoke_for_agent(
        hub, "ag-1", fallback_hypervisor=False) is None


def test_fallback_hypervisor_true_still_applies_when_nothing_resolves():
    hub = _FakeHub(active=["pxmx-shared"], agent_info={}, heartbeat_last_seen={})
    hub.get_hypervisor_spoke = lambda: "pxmx-shared"
    assert LabManagerHub.get_spoke_for_agent(
        hub, "ag-1", fallback_hypervisor=True) == "pxmx-shared"
