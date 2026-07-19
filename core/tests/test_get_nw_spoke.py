"""HubSpokeRegistry.get_nw_spoke_for_tenant / get_nw_spoke_for_shared — the
per-tenant nw spoke resolver for the nw module's tenant-scoping (Stage 2).

Mirrors get_hypervisor_spoke_for_tenant: a real tenant_id returns ONLY a
connected, approved nw spoke BOUND to that tenant (never one bound to a
different tenant, never an unassigned fallback — both would leak another
tenant's devices onto this tenant's Network Devices surface). Admin /
None / "default" falls back to the global get_spoke_by_type("nw") (legacy
behavior preserved). get_nw_spoke_for_shared resolves the shared-tenant nw
spoke via access.shared_tenant_id (lazy import, cycle-safe) so shared
devices — visible to every tenant per the shared-tenant-flag invariant —
relay to the spoke that owns them.
"""
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _NwHub:
    """Fake hub for get_nw_spoke_for_tenant / _for_shared: stands up exactly
    the bits the methods touch (all-spokes-by-type, active connections,
    approval flags, module_metadata tenant bindings, and the global
    get_spoke_by_type("nw") fallback for the admin default/None view)."""

    def __init__(self, nw_spokes, metadata, approved=None, active=None,
                 global_nw=None):
        self._nw_spokes = nw_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in nw_spokes}
        self.active_connections = active or set(nw_spokes)
        self.state = _FakeState(metadata)
        self._global_nw = global_nw

    def get_all_spokes_by_type(self, module_type):
        return list(self._nw_spokes) if module_type == "nw" else []

    def get_spoke_by_type(self, module_type):
        return self._global_nw if module_type == "nw" else None

    def get_nw_spoke_for_tenant(self, tenant_id=None):
        # Delegate to the real method so get_nw_spoke_for_shared can chain
        # through this fake hub (mirrors how a real LabManagerHub calls itself).
        return LabManagerHub.get_nw_spoke_for_tenant(self, tenant_id)


# ── get_nw_spoke_for_tenant ──────────────────────────────────────────────────

def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _NwHub(["nw-1", "nw-2"],
                {"nw-1": {"tenant_id": "tenantA"},
                 "nw-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantA") == "nw-1"
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantB") == "nw-2"


def test_for_tenant_returns_none_when_no_nw_spoke_is_bound_to_it():
    """A tenant with no bound nw spoke gets no live devices (caller falls back
    to the offline cache / empty) — NOT another tenant's fleet (the
    cross-tenant leak the nw tenant-scoping closes)."""
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantC") is None


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}})
    # tenantB has no bound nw spoke — must NOT fall back to tenantA's spoke.
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_no_unassigned_fallback_leak():
    """An UNASSIGNED nw spoke is NOT attributed to every asking tenant (that
    would put the same fleet on every row). Strict-bound: no binding → None.
    Unassigned spokes stay admin-only — the hub filter is authoritative."""
    hub = _NwHub(["nw-unbound"], {"nw-unbound": {}})  # no tenant_id
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantB") is None


def test_for_tenant_default_falls_back_to_global_nw_spoke():
    """Admin unscoped/default view preserved: still shows the global fleet."""
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}},
                 global_nw="nw-1")
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "default") == "nw-1"


def test_for_tenant_none_falls_back_to_global_nw_spoke():
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}},
                 global_nw="nw-1")
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, None) == "nw-1"


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _NwHub(["nw-1", "nw-2"],
                {"nw-1": {"tenant_id": "tenantA"},
                 "nw-2": {"tenant_id": "tenantA"}},
                approved={"nw-1": True, "nw-2": False})
    assert LabManagerHub.get_nw_spoke_for_tenant(hub, "tenantA") == "nw-1"
    # If the only bound spoke is unapproved, the tenant gets None.
    hub2 = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}},
                 approved={"nw-1": False})
    assert LabManagerHub.get_nw_spoke_for_tenant(hub2, "tenantA") is None


# ── get_nw_spoke_for_shared ──────────────────────────────────────────────────

def test_for_shared_resolves_the_shared_tenant_spoke(monkeypatch):
    """Shared devices are visible to every tenant; the hub relays to the nw
    spoke bound to the shared tenant (via access.shared_tenant_id)."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _NwHub(["nw-1", "nw-shared"],
                {"nw-1": {"tenant_id": "tenantA"},
                 "nw-shared": {"tenant_id": "shared-tenant"}})
    assert LabManagerHub.get_nw_spoke_for_shared(hub) == "nw-shared"


def test_for_shared_no_shared_tenant_falls_back_to_global(monkeypatch):
    """No shared tenant configured → admin/global nw spoke (not None)."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}},
                 global_nw="nw-1")
    assert LabManagerHub.get_nw_spoke_for_shared(hub) == "nw-1"


def test_for_shared_shared_tenant_unbound_returns_none(monkeypatch):
    """Shared tenant set but no nw spoke bound to it → None (no leaky fallback
    to a tenant-specific or unassigned spoke)."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _NwHub(["nw-1"], {"nw-1": {"tenant_id": "tenantA"}},
                 global_nw="nw-1")
    assert LabManagerHub.get_nw_spoke_for_shared(hub) is None