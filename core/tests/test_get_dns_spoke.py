"""HubSpokeRegistry.get_dns_spoke_for_tenant / get_dns_spoke_for_shared —
the per-tenant DNS (Unbound) spoke resolver.

Mirrors test_get_nw_spoke.py exactly (same strict-bound, no-unassigned-
fallback contract): a real tenant_id returns ONLY a connected, approved
"dns" spoke BOUND to that tenant. Admin / None / "default" falls back to
the global get_spoke_by_type("dns") (legacy behavior preserved).
get_dns_spoke_for_shared resolves the shared-tenant dns spoke via
access.shared_tenant_id so a tenant with no dedicated DNS spoke of its own
falls back to the shared one.
"""
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _DnsHub:
    def __init__(self, dns_spokes, metadata, approved=None, active=None,
                 global_dns=None):
        self._dns_spokes = dns_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in dns_spokes}
        self.active_connections = active or set(dns_spokes)
        self.state = _FakeState(metadata)
        self._global_dns = global_dns

    def get_all_spokes_by_type(self, module_type):
        return list(self._dns_spokes) if module_type == "dns" else []

    def get_spoke_by_type(self, module_type):
        return self._global_dns if module_type == "dns" else None

    def get_dns_spoke_for_tenant(self, tenant_id=None):
        return LabManagerHub.get_dns_spoke_for_tenant(self, tenant_id)


# ── get_dns_spoke_for_tenant ─────────────────────────────────────────────────

def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _DnsHub(["dns-1", "dns-2"],
                  {"dns-1": {"tenant_id": "tenantA"},
                   "dns-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantA") == "dns-1"
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantB") == "dns-2"


def test_for_tenant_returns_none_when_no_dns_spoke_is_bound_to_it():
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantC") is None


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_no_unassigned_fallback_leak():
    hub = _DnsHub(["dns-unbound"], {"dns-unbound": {}})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_default_falls_back_to_global_dns_spoke():
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}},
                  global_dns="dns-1")
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "default") == "dns-1"


def test_for_tenant_none_falls_back_to_global_dns_spoke():
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}},
                  global_dns="dns-1")
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, None) == "dns-1"


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _DnsHub(["dns-1", "dns-2"],
                  {"dns-1": {"tenant_id": "tenantA"},
                   "dns-2": {"tenant_id": "tenantA"}},
                  approved={"dns-1": True, "dns-2": False})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub, "tenantA") == "dns-1"
    hub2 = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}},
                   approved={"dns-1": False})
    assert LabManagerHub.get_dns_spoke_for_tenant(hub2, "tenantA") is None


# ── get_dns_spoke_for_shared ─────────────────────────────────────────────────

def test_for_shared_resolves_the_shared_tenant_spoke(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _DnsHub(["dns-1", "dns-shared"],
                  {"dns-1": {"tenant_id": "tenantA"},
                   "dns-shared": {"tenant_id": "shared-tenant"}})
    assert LabManagerHub.get_dns_spoke_for_shared(hub) == "dns-shared"


def test_for_shared_no_shared_tenant_falls_back_to_global(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}},
                  global_dns="dns-1")
    assert LabManagerHub.get_dns_spoke_for_shared(hub) == "dns-1"


def test_for_shared_shared_tenant_unbound_returns_none(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _DnsHub(["dns-1"], {"dns-1": {"tenant_id": "tenantA"}},
                  global_dns="dns-1")
    assert LabManagerHub.get_dns_spoke_for_shared(hub) is None
