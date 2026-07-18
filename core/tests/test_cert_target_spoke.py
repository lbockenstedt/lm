"""LabManagerHub._cert_target_spoke — cert-distribution target resolution.

In the split topology the pxmx agents dial the cs (simulation) spoke, NOT the
pxmx (hypervisor) spoke. A ``hypervisor`` cert target routed to
``get_spoke_by_type("hypervisor")`` therefore reached a connected-but-agent-less
pxmx spoke and returned ``No agent resolved for cert install`` — a cert that
WAS deployed (via the simulation target / cs relay) showed red on the UI.

``_cert_target_spoke`` routes agent-hosting targets (hypervisor/simulation) to
the spoke that actually OWNS the target agent (via ``agent_info``), so a
hypervisor target reaches the cs spoke that has the agent. Non-agent-hosting
types resolve by module_type unchanged.
"""
from main import LabManagerHub


class _FakeHub:
    """Stands up only the bits _cert_target_spoke touches: the module_type
    registry, the active-connection set, the agent_info index, and the two
    resolvers it delegates to (get_spoke_by_type + get_spoke_for_agent)."""

    def __init__(self, module_types, active, agent_info):
        self.spoke_module_types = module_types        # {sid: module_type}
        self.active_connections = active              # set/list of connected sids
        self.agent_info = agent_info                  # {agent_id: {"spoke_id": sid}}
        # Phase 2: _cert_target_spoke resolves state keys via _primary_key.
        # Alias empty -> returns spoke_id (pre-2b2-trigger).
        self.spoke_id_alias = {}

    def _primary_key(self, spoke_id):
        return self.spoke_id_alias.get(spoke_id, spoke_id)

    def get_spoke_by_type(self, module_type):
        for sid, mt in self.spoke_module_types.items():
            if mt == module_type and sid in self.active_connections:
                return sid
        return None

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        info = self.agent_info.get(agent_id)
        sid = (info or {}).get("spoke_id")
        if sid and sid in self.active_connections:
            return sid
        if fallback_hypervisor:
            return self.get_spoke_by_type("hypervisor") or self.get_spoke_by_type("simulation")
        return None


def test_hypervisor_target_routes_to_the_agent_owning_spoke():
    """Split topology: a pxmx agent dials the cs spoke. A hypervisor target
    whose identifier is that agent_id must route to the cs spoke, NOT the
    agent-less pxmx spoke (the 'No agent resolved' failure)."""
    hub = _FakeHub(
        module_types={"pxmx-spoke-1": "hypervisor", "cs-spoke-1": "simulation"},
        active={"pxmx-spoke-1", "cs-spoke-1"},
        agent_info={"pxmx-agent-7": {"spoke_id": "cs-spoke-1"}})
    assert LabManagerHub._cert_target_spoke(hub, "hypervisor", "pxmx-agent-7") == "cs-spoke-1"


def test_hypervisor_target_routes_to_pxmx_spoke_when_it_owns_the_agent():
    """All-in-one topology: the agent dials the pxmx spoke → a hypervisor target
    still routes there (no regression for the non-split case)."""
    hub = _FakeHub(
        module_types={"pxmx-spoke-1": "hypervisor"},
        active={"pxmx-spoke-1"},
        agent_info={"pxmx-agent-7": {"spoke_id": "pxmx-spoke-1"}})
    assert LabManagerHub._cert_target_spoke(hub, "hypervisor", "pxmx-agent-7") == "pxmx-spoke-1"


def test_all_nodes_target_picks_an_agent_hosting_spoke_with_indexed_agents():
    """Empty identifier (the 'all nodes' broadcast target): resolve to any
    connected agent-hosting spoke that has an indexed agent — in the split
    topology that's the cs spoke, not the agent-less pxmx spoke."""
    hub = _FakeHub(
        module_types={"pxmx-spoke-1": "hypervisor", "cs-spoke-1": "simulation"},
        active={"pxmx-spoke-1", "cs-spoke-1"},
        agent_info={"pxmx-agent-7": {"spoke_id": "cs-spoke-1"}})
    assert LabManagerHub._cert_target_spoke(hub, "hypervisor", "") == "cs-spoke-1"


def test_all_nodes_target_falls_back_to_simulation_when_agent_index_empty():
    """Right after connect the agent_info index is still empty (~30s lag). The
    fallback must prefer simulation (where split-topology agents live) over a
    bare pxmx spoke that may have no agents — the exact case that produced
    'No agent resolved for cert install'."""
    hub = _FakeHub(
        module_types={"pxmx-spoke-1": "hypervisor", "cs-spoke-1": "simulation"},
        active={"pxmx-spoke-1", "cs-spoke-1"},
        agent_info={})
    assert LabManagerHub._cert_target_spoke(hub, "hypervisor", "") == "cs-spoke-1"


def test_simulation_target_routes_to_the_agent_owning_spoke():
    hub = _FakeHub(
        module_types={"cs-spoke-1": "simulation"},
        active={"cs-spoke-1"},
        agent_info={"pxmx-agent-7": {"spoke_id": "cs-spoke-1"}})
    assert LabManagerHub._cert_target_spoke(hub, "simulation", "pxmx-agent-7") == "cs-spoke-1"


def test_non_agent_hosting_type_resolves_by_module_type_unchanged():
    """firewall/ipam/directory/nac/nw ignore the identifier and resolve by
    module_type exactly as before — no behavior change for the fast targets."""
    hub = _FakeHub(
        module_types={"fw-1": "firewall"},
        active={"fw-1"},
        agent_info={})
    assert LabManagerHub._cert_target_spoke(hub, "firewall", "anything") == "fw-1"


def test_unknown_agent_identifier_falls_back_to_all_nodes_resolution():
    """An identifier that isn't in agent_info (agent not yet heartbeat-indexed)
    falls through to the 'all nodes' branch rather than None."""
    hub = _FakeHub(
        module_types={"pxmx-spoke-1": "hypervisor", "cs-spoke-1": "simulation"},
        active={"pxmx-spoke-1", "cs-spoke-1"},
        agent_info={"other-agent": {"spoke_id": "cs-spoke-1"}})
    # 'pxmx-agent-7' isn't indexed, but cs-spoke-1 has an indexed agent.
    assert LabManagerHub._cert_target_spoke(hub, "hypervisor", "pxmx-agent-7") == "cs-spoke-1"