"""HubSpokeRegistry.get_directory_spoke_for_tenant — the per-tenant directory
(LDAP) spoke resolver for the Directory module's tenant-scoping.

Mirrors ``get_nw_spoke_for_tenant`` with ONE key difference: the directory's
tenancy is OU-partitioning on a SHARED server (``ou=<slug>,<base_dn>``), not
per-tenant spokes. A typical deploy is a single (mirror-pair) directory spoke
that is UNASSIGNED and serves every tenant via its OU — so the resolver FALLS
BACK to an unassigned directory spoke (nw/hypervisor return ``None`` here).
This fallback is INTENTIONAL — do not "fix" it to match nw.
"""
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _DirHub:
    """Fake hub for get_directory_spoke_for_tenant: stands up exactly the bits
    the method touches (all-spokes-by-type, active connections, approval flags,
    module_metadata tenant bindings, and the global get_spoke_by_type fallback
    for the admin default/None view)."""

    def __init__(self, dir_spokes, metadata, approved=None, active=None,
                 global_dir=None):
        self._dir_spokes = dir_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in dir_spokes}
        self.active_connections = active or set(dir_spokes)
        self.state = _FakeState(metadata)
        self._global_dir = global_dir

    def get_all_spokes_by_type(self, module_type):
        return list(self._dir_spokes) if module_type == "directory" else []

    def get_spoke_by_type(self, module_type):
        return self._global_dir if module_type == "directory" else None

    def get_directory_spoke_for_tenant(self, tenant_id=None):
        return LabManagerHub.get_directory_spoke_for_tenant(self, tenant_id)


# ── prefer-bound ─────────────────────────────────────────────────────────────

def test_for_tenant_returns_the_spoke_bound_to_that_tenant():
    hub = _DirHub(["dir-1", "dir-2"],
                 {"dir-1": {"tenant_id": "tenantA"},
                  "dir-2": {"tenant_id": "tenantB"}})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") == "dir-1"
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantB") == "dir-2"


def test_for_tenant_never_returns_a_spoke_bound_to_a_different_tenant():
    """A tenant with no bound directory spoke must NOT be relayed to another
    tenant's spoke (the cross-tenant leak this closes in a multi-spoke deploy)."""
    hub = _DirHub(["dir-1"], {"dir-1": {"tenant_id": "tenantA"}})
    # tenantB has no bound spoke AND no unassigned fallback → None (not dir-1).
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantB") is None


# ── the KEY difference from nw: unassigned fallback ───────────────────────────

def test_for_tenant_falls_back_to_an_unassigned_directory_spoke():
    """The shared OU-partitioned server: an UNASSIGNED directory spoke serves
    every tenant via ou=<slug>,<base>. Unlike nw (which returns None here), the
    directory resolver returns the unassigned spoke. This is INTENTIONAL — the
    common deploy is one unassigned directory spoke serving all tenants."""
    hub = _DirHub(["dir-shared"], {"dir-shared": {}})  # no tenant_id
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") == "dir-shared"
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantB") == "dir-shared"


def test_for_tenant_prefers_bound_over_unassigned():
    """If a tenant has a bound directory spoke, that wins over the unassigned
    shared server (a tenant-specific directory, if deployed, takes precedence)."""
    hub = _DirHub(["dir-bound", "dir-shared"],
                 {"dir-bound": {"tenant_id": "tenantA"},
                  "dir-shared": {}})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") == "dir-bound"
    # tenantB has no bound spoke → falls back to the unassigned shared server.
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantB") == "dir-shared"


def test_for_tenant_no_cands_returns_none():
    hub = _DirHub([], {})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") is None


# ── admin / default / None → global spoke ─────────────────────────────────────

def test_for_tenant_default_falls_back_to_global_directory_spoke():
    """Admin unscoped/default view preserved: still resolves the global
    directory spoke (a Global Admin sees / manages every tenant's OU)."""
    hub = _DirHub(["dir-1"], {"dir-1": {"tenant_id": "tenantA"}},
                 global_dir="dir-1")
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "default") == "dir-1"


def test_for_tenant_none_falls_back_to_global_directory_spoke():
    hub = _DirHub(["dir-1"], {"dir-1": {"tenant_id": "tenantA"}},
                 global_dir="dir-1")
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, None) == "dir-1"


# ── skips unapproved / disconnected ───────────────────────────────────────────

def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _DirHub(["dir-1", "dir-2"],
                 {"dir-1": {"tenant_id": "tenantA"},
                  "dir-2": {"tenant_id": "tenantA"}},
                 approved={"dir-1": True, "dir-2": False})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") == "dir-1"
    # If the only bound spoke is unapproved, the tenant falls back to unassigned
    # (none here) → None.
    hub2 = _DirHub(["dir-1"], {"dir-1": {"tenant_id": "tenantA"}},
                   approved={"dir-1": False})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub2, "tenantA") is None


def test_for_tenant_unassigned_must_be_connected_and_approved():
    """An unassigned spoke that is disconnected or unapproved is NOT a fallback
    — the tenant gets None rather than a spoke that can't actually serve it."""
    hub = _DirHub(["dir-shared"], {"dir-shared": {}},
                  approved={"dir-shared": False})
    assert LabManagerHub.get_directory_spoke_for_tenant(hub, "tenantA") is None
    hub2 = _DirHub(["dir-shared"], {"dir-shared": {}},
                   active={"other"})  # dir-shared not in active → disconnected
    assert LabManagerHub.get_directory_spoke_for_tenant(hub2, "tenantA") is None