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


# ── get_hypervisor_spoke_for_tenant — per-tenant VM-count isolation ──────────

class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _TenantHub:
    """Fake hub for get_hypervisor_spoke_for_tenant: stands up the bits the
    method touches (all-spokes-by-type, active connections, approval flags,
    module_metadata tenant bindings, and the global get_hypervisor_spoke
    fallback for the admin default/None view)."""

    def __init__(self, hypervisors, metadata, approved=None, active=None,
                 global_hypervisor=None):
        self._hypervisors = hypervisors            # list returned by get_all_spokes_by_type
        self._metadata = metadata                  # {sid: {"tenant_id": tid}}
        self.approved_modules = approved or {sid: True for sid in hypervisors}
        self.active_connections = active or set(hypervisors)
        self.state = _FakeState(metadata)
        self._global_hypervisor = global_hypervisor

    def get_all_spokes_by_type(self, module_type):
        return list(self._hypervisors) if module_type == "hypervisor" else []

    def get_hypervisor_spoke(self):
        return self._global_hypervisor


def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _TenantHub(["pxmx-1", "pxmx-2"],
                     {"pxmx-1": {"tenant_id": "tenantA"},
                      "pxmx-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantA") == "pxmx-1"
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantB") == "pxmx-2"


def test_for_tenant_returns_none_when_no_hypervisor_is_bound_to_it():
    """The fix: a tenant with no pxmx agent assigned gets 0 VMs, NOT the global
    hypervisor's whole VM list (the prior cross-tenant leak)."""
    hub = _TenantHub(["pxmx-1"], {"pxmx-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantC") is None


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    hub = _TenantHub(["pxmx-1"], {"pxmx-1": {"tenant_id": "tenantA"}})
    # tenantB has no bound hypervisor — must NOT fall back to tenantA's spoke.
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_no_unassigned_fallback_leak():
    """An UNASSIGNED hypervisor is NOT attributed to every asking tenant (that
    would put the same VMs on every row). Strict-bound: no binding → None."""
    hub = _TenantHub(["pxmx-unbound"], {"pxmx-unbound": {}})  # no tenant_id
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_default_falls_back_to_global_hypervisor():
    """Admin unscoped/default view preserved: still shows a global count."""
    hub = _TenantHub(["pxmx-1"], {"pxmx-1": {"tenant_id": "tenantA"}},
                     global_hypervisor="pxmx-1")
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "default") == "pxmx-1"


def test_for_tenant_none_falls_back_to_global_hypervisor():
    hub = _TenantHub(["pxmx-1"], {"pxmx-1": {"tenant_id": "tenantA"}},
                     global_hypervisor="pxmx-1")
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, None) == "pxmx-1"


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _TenantHub(["pxmx-1", "pxmx-2"],
                     {"pxmx-1": {"tenant_id": "tenantA"},
                      "pxmx-2": {"tenant_id": "tenantA"}},
                     approved={"pxmx-1": True, "pxmx-2": False})
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub, "tenantA") == "pxmx-1"
    # If the only bound spoke is unapproved, the tenant gets None (not the
    # unapproved spoke).
    hub2 = _TenantHub(["pxmx-1"], {"pxmx-1": {"tenant_id": "tenantA"}},
                     approved={"pxmx-1": False})
    assert LabManagerHub.get_hypervisor_spoke_for_tenant(hub2, "tenantA") is None
