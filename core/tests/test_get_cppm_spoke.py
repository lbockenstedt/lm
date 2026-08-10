"""HubSpokeRegistry.get_cppm_spoke_for_tenant / get_cppm_spoke_for_shared —
the per-tenant NAC (ClearPass/cppm) spoke resolver.

Mirrors test_get_nw_spoke.py exactly (same strict-bound, no-unassigned-
fallback contract): a real tenant_id returns ONLY a connected, approved
"nac" spoke BOUND to that tenant (never one bound to a different tenant,
never an unassigned fallback — both would answer a tenant's NAC query from
another tenant's ClearPass appliance). Admin / None / "default" falls back
to the global get_spoke_by_type("nac") (legacy behavior preserved).
get_cppm_spoke_for_shared resolves the shared-tenant nac spoke via
access.shared_tenant_id (lazy import, cycle-safe) so a tenant with no
dedicated NAC spoke of its own falls back to the shared one.
"""
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _CppmHub:
    """Fake hub for get_cppm_spoke_for_tenant / _for_shared — mirrors
    test_get_nw_spoke.py's _NwHub."""

    def __init__(self, nac_spokes, metadata, approved=None, active=None,
                 global_nac=None):
        self._nac_spokes = nac_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in nac_spokes}
        self.active_connections = active or set(nac_spokes)
        self.state = _FakeState(metadata)
        self._global_nac = global_nac

    def get_all_spokes_by_type(self, module_type):
        return list(self._nac_spokes) if module_type == "nac" else []

    def get_spoke_by_type(self, module_type):
        return self._global_nac if module_type == "nac" else None

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        return LabManagerHub.get_cppm_spoke_for_tenant(self, tenant_id)


# ── get_cppm_spoke_for_tenant ────────────────────────────────────────────────

def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _CppmHub(["cppm-1", "cppm-2"],
                   {"cppm-1": {"tenant_id": "tenantA"},
                    "cppm-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantB") == "cppm-2"


def test_for_tenant_returns_none_when_no_nac_spoke_is_bound_to_it():
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantC") is None


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}})
    # tenantB has no bound cppm spoke — must NOT fall back to tenantA's spoke
    # (that would answer tenantB's ClearPass query from tenantA's appliance).
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_no_unassigned_fallback_leak():
    """An UNASSIGNED cppm spoke is NOT attributed to every asking tenant."""
    hub = _CppmHub(["cppm-unbound"], {"cppm-unbound": {}})  # no tenant_id
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_default_falls_back_to_global_nac_spoke():
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "default") == "cppm-1"


def test_for_tenant_none_falls_back_to_global_nac_spoke():
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, None) == "cppm-1"


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _CppmHub(["cppm-1", "cppm-2"],
                   {"cppm-1": {"tenant_id": "tenantA"},
                    "cppm-2": {"tenant_id": "tenantA"}},
                   approved={"cppm-1": True, "cppm-2": False})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"
    hub2 = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                    approved={"cppm-1": False})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub2, "tenantA") is None


# ── get_cppm_spoke_for_shared ────────────────────────────────────────────────

def test_for_shared_resolves_the_shared_tenant_spoke(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(["cppm-1", "cppm-shared"],
                   {"cppm-1": {"tenant_id": "tenantA"},
                    "cppm-shared": {"tenant_id": "shared-tenant"}})
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) == "cppm-shared"


def test_for_shared_no_shared_tenant_falls_back_to_global(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) == "cppm-1"


def test_for_shared_shared_tenant_unbound_returns_none(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None
