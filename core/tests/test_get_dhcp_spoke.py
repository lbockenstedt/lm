"""HubSpokeRegistry.get_dhcp_spoke_for_tenant / get_dhcp_spoke_for_shared —
the per-tenant DHCP (Kea) spoke resolver.

Mirrors test_get_nw_spoke.py / test_get_dns_spoke.py exactly (same strict-
bound, no-unassigned-fallback contract): a real tenant_id returns ONLY a
connected, approved "dhcp" spoke BOUND to that tenant. Admin / None /
"default" falls back to the global get_spoke_by_type("dhcp") (legacy
behavior preserved). get_dhcp_spoke_for_shared resolves the shared-tenant
dhcp spoke via access.shared_tenant_id so a tenant with no dedicated DHCP
spoke of its own falls back to the shared one.
"""
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _DhcpHub:
    def __init__(self, dhcp_spokes, metadata, approved=None, active=None,
                 global_dhcp=None):
        self._dhcp_spokes = dhcp_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in dhcp_spokes}
        self.active_connections = active or set(dhcp_spokes)
        self.state = _FakeState(metadata)
        self._global_dhcp = global_dhcp

    def get_all_spokes_by_type(self, module_type):
        return list(self._dhcp_spokes) if module_type == "dhcp" else []

    def get_spoke_by_type(self, module_type):
        return self._global_dhcp if module_type == "dhcp" else None

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return LabManagerHub.get_dhcp_spoke_for_tenant(self, tenant_id)


# ── get_dhcp_spoke_for_tenant ────────────────────────────────────────────────

def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _DhcpHub(["dhcp-1", "dhcp-2"],
                   {"dhcp-1": {"tenant_id": "tenantA"},
                    "dhcp-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantA") == "dhcp-1"
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantB") == "dhcp-2"


def test_for_tenant_returns_none_when_no_dhcp_spoke_is_bound_to_it():
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantC") is None


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_no_unassigned_fallback_leak():
    hub = _DhcpHub(["dhcp-unbound"], {"dhcp-unbound": {}})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_default_falls_back_to_global_dhcp_spoke():
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}},
                   global_dhcp="dhcp-1")
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "default") == "dhcp-1"


def test_for_tenant_none_falls_back_to_global_dhcp_spoke():
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}},
                   global_dhcp="dhcp-1")
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, None) == "dhcp-1"


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _DhcpHub(["dhcp-1", "dhcp-2"],
                   {"dhcp-1": {"tenant_id": "tenantA"},
                    "dhcp-2": {"tenant_id": "tenantA"}},
                   approved={"dhcp-1": True, "dhcp-2": False})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub, "tenantA") == "dhcp-1"
    hub2 = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}},
                    approved={"dhcp-1": False})
    assert LabManagerHub.get_dhcp_spoke_for_tenant(hub2, "tenantA") is None


# ── get_dhcp_spoke_for_shared ────────────────────────────────────────────────

def test_for_shared_resolves_the_shared_tenant_spoke(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _DhcpHub(["dhcp-1", "dhcp-shared"],
                   {"dhcp-1": {"tenant_id": "tenantA"},
                    "dhcp-shared": {"tenant_id": "shared-tenant"}})
    assert LabManagerHub.get_dhcp_spoke_for_shared(hub) == "dhcp-shared"


def test_for_shared_no_shared_tenant_falls_back_to_global(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}},
                   global_dhcp="dhcp-1")
    assert LabManagerHub.get_dhcp_spoke_for_shared(hub) == "dhcp-1"


def test_for_shared_shared_tenant_unbound_returns_none(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _DhcpHub(["dhcp-1"], {"dhcp-1": {"tenant_id": "tenantA"}},
                   global_dhcp="dhcp-1")
    assert LabManagerHub.get_dhcp_spoke_for_shared(hub) is None
