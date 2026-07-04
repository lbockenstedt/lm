"""LabManagerHub.get_hypervisor_spoke — ~18 call sites across api.py (VM/
console/node/pool/ISO/storage/template browsing, agent removal, endpoint/NAC
sync's Proxmox enrichment, the pxmx_vms cache refresh, vmid_alloc, ...) called
hub.get_spoke_by_type("hypervisor") directly, so every one of them silently
found nothing for an all-cs-hosted deployment (no dedicated pxmx spoke at
all — the agent dials a cs spoke's own /ws/agent listener). Same blind spot
CSBridgePoller had before it was taught to check every agent-hosting spoke
type instead of only "hypervisor" (see test_cs_bridge_agent_host_spokes.py).
"""
from main import LabManagerHub


class _FakeHub:
    def __init__(self, by_type):
        self._by_type = by_type

    def get_spoke_by_type(self, module_type):
        return self._by_type.get(module_type)


def test_prefers_a_real_hypervisor_spoke_when_one_exists():
    hub = _FakeHub({"hypervisor": "pxmx-spoke-1", "simulation": "cs-svr-02-spoke"})
    assert LabManagerHub.get_hypervisor_spoke(hub) == "pxmx-spoke-1"


def test_falls_back_to_a_simulation_spoke_with_no_dedicated_hypervisor():
    hub = _FakeHub({"hypervisor": None, "simulation": "cs-svr-02-spoke"})
    assert LabManagerHub.get_hypervisor_spoke(hub) == "cs-svr-02-spoke"


def test_none_when_neither_type_is_connected():
    hub = _FakeHub({"hypervisor": None, "simulation": None})
    assert LabManagerHub.get_hypervisor_spoke(hub) is None
