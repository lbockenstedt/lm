"""``LabManagerHub.get_client_sim_spoke`` must be tenant-isolated: a tenant with
no bound cs spoke must NEVER resolve to a spoke bound to a different tenant.

The cs speak holds a SINGLE ``CSSettings`` store per spoke. If tenantB's
hub-config push / auto-provision toggle resolved to tenantA's spoke, tenantB's
values would overwrite tenantA's settings in that shared store — "one tenant's
auto-provisioning affecting all the others." The fix: when a tenant_id is given,
return only a spoke bound to that tenant, or (if none) an UNASSIGNED spoke;
never ``cands[0]`` blindly.
"""

import main  # noqa: E402  (core/src on sys.path via conftest)


class _State:
    def __init__(self, metadata):
        self.system_state = {"module_metadata": metadata}


class _Hub:
    """Minimal stub exposing only what get_client_sim_spoke touches."""

    def __init__(self, by_type, approved, metadata):
        self._by_type = by_type
        self.approved_modules = approved
        self.state = _State(metadata)

    def get_all_spokes_by_type(self, t):
        return self._by_type.get(t, [])


def test_tenant_without_bound_spoke_does_not_clobber_other_tenant():
    # cs-spoke-1 is bound to tenantA; tenantB has no bound spoke and no unassigned.
    hub = _Hub({"Client-Sim": ["cs-spoke-1"]},
               {"cs-spoke-1": True},
               {"cs-spoke-1": {"tenant_id": "tenantA"}})
    # tenantB must NOT resolve to tenantA's spoke (would overwrite its settings).
    assert main.LabManagerHub.get_client_sim_spoke(hub, "tenantB") is None


def test_tenant_resolves_to_own_bound_spoke():
    hub = _Hub({"Client-Sim": ["cs-spoke-1", "cs-spoke-2"]},
               {"cs-spoke-1": True, "cs-spoke-2": True},
               {"cs-spoke-1": {"tenant_id": "tenantA"},
                "cs-spoke-2": {"tenant_id": "tenantB"}})
    assert main.LabManagerHub.get_client_sim_spoke(hub, "tenantA") == "cs-spoke-1"
    assert main.LabManagerHub.get_client_sim_spoke(hub, "tenantB") == "cs-spoke-2"


def test_unassigned_spoke_is_claimable_by_unbound_tenant():
    # cs-spoke-2 has no tenant_id in metadata → unassigned → tenantB may claim it.
    hub = _Hub({"Client-Sim": ["cs-spoke-1", "cs-spoke-2"]},
               {"cs-spoke-1": True, "cs-spoke-2": True},
               {"cs-spoke-1": {"tenant_id": "tenantA"}})
    assert main.LabManagerHub.get_client_sim_spoke(hub, "tenantB") == "cs-spoke-2"


def test_admin_global_view_returns_any_connected_spoke():
    # tenant_id None = admin/global view — first available is fine.
    hub = _Hub({"Client-Sim": ["cs-spoke-1"]},
               {"cs-spoke-1": True},
               {"cs-spoke-1": {"tenant_id": "tenantA"}})
    assert main.LabManagerHub.get_client_sim_spoke(hub, None) == "cs-spoke-1"


def test_unapproved_spoke_is_never_returned():
    hub = _Hub({"Client-Sim": ["cs-spoke-1"]},
               {"cs-spoke-1": False},  # not approved
               {"cs-spoke-1": {"tenant_id": "tenantA"}})
    assert main.LabManagerHub.get_client_sim_spoke(hub, "tenantA") is None