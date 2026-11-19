"""HubSpokeRegistry.get_cppm_spoke_for_tenant / get_cppm_spoke_for_shared —
the per-tenant NAC (ClearPass/cppm) spoke resolver.

Mirrors test_get_nw_spoke.py exactly (same strict-bound, no-unassigned-
fallback contract): a real tenant_id returns ONLY a connected, approved
"nac" spoke BOUND to that tenant (never one bound to a different tenant,
never an unassigned fallback — both would answer a tenant's NAC query from
another tenant's ClearPass appliance). Admin / None / "default" resolves only
the configured shared or an unbound NAC spoke. get_cppm_spoke_for_shared
resolves the shared-tenant NAC spoke via access.shared_tenant_id (lazy import,
cycle-safe); with no shared tenant configured it resolves only an unbound
(unassigned, shared or admin) spoke, never one bound to a real tenant.
"""
from hub_spoke_registry import _nac_spoke_records, nac_push_key
from main import LabManagerHub


class _FakeState:
    def __init__(self, metadata, nac_instances=None, cppm=None):
        self.system_state = {"module_metadata": metadata}
        self._nac_instances = nac_instances or []
        # The legacy single ClearPass config (global_config["cppm"]).
        self.cppm = cppm or {}
        self.dirty = 0

    def get_global_config(self):
        return {"nac_instances": self._nac_instances, "cppm": self.cppm}

    def _mark_dirty(self):
        """Count the saves record_nac_push asks for."""
        self.dirty += 1

    def get_spoke_tenant(self, spoke_id):
        """Return the fixture's tenant binding for one spoke."""
        return self.system_state["module_metadata"].get(spoke_id, {}).get("tenant_id", "")


class _CppmHub:
    """Fake hub for get_cppm_spoke_for_tenant / _for_shared — mirrors
    test_get_nw_spoke.py's _NwHub."""

    def __init__(self, nac_spokes, metadata, approved=None, active=None,
                 global_nac=None, nac_instances=None, alias=None, cppm=None):
        self._nac_spokes = nac_spokes
        self._metadata = metadata
        self.approved_modules = approved or {sid: True for sid in nac_spokes}
        self.active_connections = active or set(nac_spokes)
        self.state = _FakeState(metadata, nac_instances, cppm)
        self._global_nac = global_nac
        self.spoke_id_alias = alias or {}
        # Steady state: each NAC record has a host and the hub sent each
        # spoke the record that configures it (the legacy config when there
        # is no record), so no spoke is stale (nac_spoke_stale). The ledger
        # tests at the end set nac_config_pushed themselves.
        records = self.state._nac_instances
        for rec in records:
            rec.setdefault("host", "cp.example")
        pushed = self.state.system_state.setdefault("nac_config_pushed", {})
        for sid in nac_spokes:
            mine = _nac_spoke_records(self, sid)
            if mine:
                pushed[self._primary_key(sid)] = nac_push_key(mine[0])

    def _primary_key(self, spoke_id):
        """Delegate to the production identity resolver."""
        return LabManagerHub._primary_key(self, spoke_id)

    def get_all_spokes_by_type(self, module_type):
        return list(self._nac_spokes) if module_type == "nac" else []

    def get_spoke_by_type(self, module_type):
        return self._global_nac if module_type == "nac" else None

    def get_spoke_tenant(self, spoke_id):
        """Return the fixture's tenant binding for one spoke."""
        return self._metadata.get(spoke_id, {}).get("tenant_id", "")

    def get_nac_live_spokes(self):
        """Delegate to the production live-spoke list."""
        return LabManagerHub.get_nac_live_spokes(self)

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        """Delegate to the production tenant resolver."""
        return LabManagerHub.get_cppm_spoke_for_tenant(self, tenant_id)

    def get_cppm_spoke_for_global(self):
        """Delegate to the production global resolver."""
        return LabManagerHub.get_cppm_spoke_for_global(self)

    def _unbound_cppm_spoke(self):
        """Delegate to the production unbound-spoke pick."""
        return LabManagerHub._unbound_cppm_spoke(self)

    def get_cppm_spokes_for_tenant(self, tenant_id=None):
        """Delegate to the production combined-view resolver."""
        return LabManagerHub.get_cppm_spokes_for_tenant(self, tenant_id)

    def get_cppm_spoke_for_scope(self, tenant_id=None):
        """Delegate to the production one-spoke resolver."""
        return LabManagerHub.get_cppm_spoke_for_scope(self, tenant_id)

    def get_nac_spoke_owner(self, spoke_id):
        """Delegate to the production NAC owner lookup (access.spoke_data_owner)."""
        return LabManagerHub.get_nac_spoke_owner(self, spoke_id)


def _no_shared_tenant(monkeypatch):
    """Configure no shared tenant (both the getter and tenant_is_shared's id)."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", None)


def _shared_tenant(monkeypatch, tenant_id="shared-tenant"):
    """Configure ``tenant_id`` as the shared tenant everywhere access reads it."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: tenant_id)
    monkeypatch.setattr(access, "_SHARED_TENANT_ID", tenant_id)


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


def test_for_tenant_default_uses_only_an_unassigned_global_spoke():
    """A default/global lookup must not return another tenant's NAC spoke."""
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "default") is None


def test_for_tenant_none_uses_only_an_unassigned_global_spoke():
    """An unscoped lookup must not return another tenant's NAC spoke."""
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, None) is None


def test_global_resolver_prefers_configured_shared_spoke(monkeypatch):
    """The configured shared source wins over unassigned and tenant spokes."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(
        ["cppm-other", "cppm-unassigned", "cppm-shared"],
        {"cppm-other": {"tenant_id": "tenantA"},
         "cppm-shared": {"tenant_id": "shared-tenant"}},
        nac_instances=[{"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}],
    )
    assert LabManagerHub.get_cppm_spoke_for_global(hub) == "cppm-shared"


def test_global_resolver_falls_back_only_to_an_unassigned_spoke(monkeypatch):
    """Without a shared source, tenant-bound spokes are never global fallback."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub(
        ["cppm-tenant", "cppm-unassigned"],
        {"cppm-tenant": {"tenant_id": "tenantA"}, "cppm-unassigned": {}},
    )
    assert LabManagerHub.get_cppm_spoke_for_global(hub) == "cppm-unassigned"


def test_global_resolver_returns_none_when_only_tenant_spokes_are_connected(monkeypatch):
    """A global route fails closed when there is no shared or unassigned source."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub(["cppm-tenant"], {"cppm-tenant": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_cppm_spoke_for_global(hub) is None


def test_for_tenant_skips_unapproved_and_disconnected_spokes():
    hub = _CppmHub(["cppm-1", "cppm-2"],
                   {"cppm-1": {"tenant_id": "tenantA"},
                    "cppm-2": {"tenant_id": "tenantA"}},
                   approved={"cppm-1": True, "cppm-2": False})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"
    hub2 = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                    approved={"cppm-1": False})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub2, "tenantA") is None


# ── two nac instances, same tenant: must PIN, never hop ─────────────────────
# Regression: with two ClearPass appliances bound to the SAME tenant (each
# only reachable from its own spoke), the old bound[0]-over-
# get_all_spokes_by_type() pick depended on connection/reconnect ORDER, not
# any stable assignment, so a query could land on either spoke unpredictably
# — including one with no network route to the OTHER instance's ClearPass
# host. Resolution must instead pin to the SAME spoke every time via the
# tenant's own config-ordered nac_instances list.

def test_two_instances_same_tenant_pins_to_the_bound_instance_regardless_of_module_metadata_order():
    # module_metadata (connection-order-derived) says cppm-2 first, but the
    # config-ordered nac_instances list says cppm-1 is this tenant's FIRST
    # bound instance — the fix must follow nac_instances, not module_metadata
    # iteration order.
    hub = _CppmHub(
        ["cppm-2", "cppm-1"],  # get_all_spokes_by_type order (connection order)
        {"cppm-2": {"tenant_id": "tenantA"}, "cppm-1": {"tenant_id": "tenantA"}},
        nac_instances=[
            {"tenant_id": "tenantA", "spoke_id": "cppm-1"},
            {"tenant_id": "tenantA", "spoke_id": "cppm-2"},
        ],
    )
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"


def test_two_instances_same_tenant_resolution_is_stable_across_reconnect_order_flips():
    """The exact reported symptom: simulate cppm-2 reconnecting (moving to the
    end of connection-order bookkeeping) and confirm the resolved spoke does
    NOT change — it must stay pinned to whatever nac_instances says, not flip
    with connection timing."""
    instances = [
        {"tenant_id": "tenantA", "spoke_id": "cppm-1"},
        {"tenant_id": "tenantA", "spoke_id": "cppm-2"},
    ]
    metadata = {"cppm-1": {"tenant_id": "tenantA"}, "cppm-2": {"tenant_id": "tenantA"}}
    before = _CppmHub(["cppm-1", "cppm-2"], metadata, nac_instances=instances)
    after_reconnect = _CppmHub(["cppm-2", "cppm-1"], metadata, nac_instances=instances)
    assert (LabManagerHub.get_cppm_spoke_for_tenant(before, "tenantA")
            == LabManagerHub.get_cppm_spoke_for_tenant(after_reconnect, "tenantA")
            == "cppm-1")


def test_pinned_instance_offline_falls_back_to_the_other_bound_spoke():
    hub = _CppmHub(
        ["cppm-2"],  # cppm-1 (the pinned instance) is disconnected
        {"cppm-2": {"tenant_id": "tenantA"}},
        nac_instances=[
            {"tenant_id": "tenantA", "spoke_id": "cppm-1"},
            {"tenant_id": "tenantA", "spoke_id": "cppm-2"},
        ],
    )
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-2"


def test_instance_with_no_bound_spoke_id_is_skipped_not_treated_as_a_match():
    hub = _CppmHub(
        ["cppm-2"],
        {"cppm-2": {"tenant_id": "tenantA"}},
        nac_instances=[
            {"tenant_id": "tenantA", "spoke_id": ""},  # unbound instance record
            {"tenant_id": "tenantA", "spoke_id": "cppm-2"},
        ],
    )
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-2"


def test_nac_instances_never_leaks_across_tenants():
    hub = _CppmHub(
        ["cppm-1", "cppm-2"],
        {"cppm-1": {"tenant_id": "tenantA"}, "cppm-2": {"tenant_id": "tenantB"}},
        nac_instances=[
            {"tenant_id": "tenantA", "spoke_id": "cppm-1"},
            {"tenant_id": "tenantB", "spoke_id": "cppm-2"},
        ],
    )
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantB") == "cppm-2"


# ── get_cppm_spoke_for_shared ────────────────────────────────────────────────

def test_for_shared_resolves_the_shared_tenant_spoke(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(["cppm-1", "cppm-shared"],
                   {"cppm-1": {"tenant_id": "tenantA"},
                    "cppm-shared": {"tenant_id": "shared-tenant"}})
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) == "cppm-shared"


def test_for_shared_no_shared_tenant_never_picks_a_tenant_bound_spoke(monkeypatch):
    """A missing shared tenant must not select another tenant's ClearPass."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None


def test_for_shared_no_shared_tenant_uses_the_unassigned_hub_clearpass(monkeypatch):
    """The single-ClearPass deployment registers the hub's ClearPass
    unassigned; shared writes (endpoint sync, NAD registration, 802.1X JIT
    for the shared tenant) must still reach it."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-tenant", "cppm-hub"],
                   {"cppm-tenant": {"tenant_id": "tenantA"}, "cppm-hub": {}},
                   global_nac="cppm-tenant")
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) == "cppm-hub"
    assert LabManagerHub.get_cppm_spoke_for_global(hub) == "cppm-hub"


def test_admin_bound_spoke_counts_as_unbound(monkeypatch):
    """An admin-bound ClearPass is the hub's own, like an unassigned one."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-admin"], {"cppm-admin": {"tenant_id": "default"}})
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) == "cppm-admin"
    assert LabManagerHub.get_cppm_spoke_for_global(hub) == "cppm-admin"


def test_unbound_pick_does_not_flip_with_connection_order(monkeypatch):
    """Two unbound spokes resolve to the same one whatever connected first."""
    _no_shared_tenant(monkeypatch)
    md = {"cppm-a": {}, "cppm-b": {}}
    first = _CppmHub(["cppm-a", "cppm-b"], md)
    flipped = _CppmHub(["cppm-b", "cppm-a"], md)
    assert (LabManagerHub.get_cppm_spoke_for_shared(first)
            == LabManagerHub.get_cppm_spoke_for_shared(flipped) == "cppm-a")


def test_for_shared_configured_but_offline_is_not_substituted(monkeypatch):
    """A configured shared ClearPass that is offline is not replaced by an
    unassigned one for shared writes; global reads may still use it."""
    _shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-shared", "cppm-unassigned"],
                   {"cppm-shared": {"tenant_id": "shared-tenant"}, "cppm-unassigned": {}},
                   active={"cppm-unassigned"})
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None
    assert LabManagerHub.get_cppm_spoke_for_global(hub) == "cppm-unassigned"


def test_for_shared_shared_tenant_unbound_returns_none(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantA"}},
                   global_nac="cppm-1")
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None


# ── get_cppm_spokes_for_tenant (combined own + shared view) ─────────────────

def test_spokes_for_tenant_own_only_shared_hidden(monkeypatch):
    """A tenant with its own ClearPass is out of the shared NAC environment."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(
        ["cppm-a", "cppm-shared"],
        {"cppm-a": {"tenant_id": "tenantA"}, "cppm-shared": {"tenant_id": "shared-tenant"}},
        nac_instances=[
            {"tenant_id": "tenantA", "spoke_id": "cppm-a"},
            {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"},
        ],
    )
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-a"]


def test_spokes_for_tenant_own_offline_never_falls_back_to_shared(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    md = {"cppm-a": {"tenant_id": "tenantA", "module_type": "cppm"},
          "cppm-shared": {"tenant_id": "shared-tenant", "module_type": "nac"}}
    hub = _CppmHub(["cppm-shared"], md,
                   nac_instances=[{"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}])
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == []
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantB") == ["cppm-shared"]


def test_spokes_for_tenant_own_only_when_no_shared_tenant_configured(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub(
        ["cppm-a"], {"cppm-a": {"tenant_id": "tenantA"}},
        nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"}],
    )
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-a"]


def test_spokes_for_tenant_never_falls_back_to_an_unrelated_global_spoke(monkeypatch):
    """The dangerous case get_cppm_spoke_for_shared() has: no shared tenant
    configured must NOT pull in some unrelated connected nac spoke via
    get_spoke_by_type("nac")."""
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub(
        ["cppm-a", "cppm-unrelated"],
        {"cppm-a": {"tenant_id": "tenantA"}, "cppm-unrelated": {"tenant_id": "tenantZ"}},
        nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"}],
        global_nac="cppm-unrelated",
    )
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-a"]


def test_spokes_for_tenant_shared_only_when_tenant_has_no_own_instance(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(
        ["cppm-shared"], {"cppm-shared": {"tenant_id": "shared-tenant"}},
        nac_instances=[{"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}],
    )
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-shared"]


def test_spokes_for_tenant_deduplicates_when_shared_tenant_is_the_tenant_itself(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "tenantA")
    hub = _CppmHub(
        ["cppm-a"], {"cppm-a": {"tenant_id": "tenantA"}},
        nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"}],
    )
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-a"]


def test_spokes_for_tenant_empty_for_admin_unscoped(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "shared-tenant")
    hub = _CppmHub(["cppm-a"], {"cppm-a": {"tenant_id": "tenantA"}})
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, None) == []
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "default") == []


def test_spokes_for_tenant_empty_when_neither_own_nor_shared_bound(monkeypatch):
    import access
    monkeypatch.setattr(access, "shared_tenant_id", lambda: "")
    hub = _CppmHub([], {})
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == []


# ── get_cppm_spoke_for_scope (one-spoke reads: dashboard, search, VM detail) ─

def test_for_scope_admin_unscoped_uses_the_global_source(monkeypatch):
    """None / "default" read the shared or unbound ClearPass, never a tenant's."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-a", "cppm-hub"],
                   {"cppm-a": {"tenant_id": "tenantA"}, "cppm-hub": {}})
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, None) == "cppm-hub"
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, "default") == "cppm-hub"


def test_for_scope_tenant_uses_its_own_then_the_shared_spoke(monkeypatch):
    _shared_tenant(monkeypatch)
    hub = _CppmHub(
        ["cppm-a", "cppm-shared"],
        {"cppm-a": {"tenant_id": "tenantA"}, "cppm-shared": {"tenant_id": "shared-tenant"}},
        nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"},
                       {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}],
    )
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, "tenantA") == "cppm-a"
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, "tenantB") == "cppm-shared"


def test_for_scope_tenant_never_gets_another_tenant_or_unbound_spoke(monkeypatch):
    """With no shared tenant, a tenant's view has no shared source: neither an
    unassigned ClearPass nor another tenant's answers its single-spoke reads."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-a", "cppm-hub"],
                   {"cppm-a": {"tenant_id": "tenantA"}, "cppm-hub": {}},
                   global_nac="cppm-a")
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, "tenantB") is None


# ── ownership from NAC instance records, not only the spoke's binding ───────
# Regression: the unbound pick read only module_metadata. An instance keeps
# its tenant when Setup → NAC moves it to another spoke, and a spoke with no
# instance of its own is pushed the first spoke-less one, so an "unassigned"
# spoke could be serving a tenant's ClearPass and still answer global reads
# and shared writes.

def test_spoke_serving_a_tenant_instance_is_not_the_global_or_shared_source(monkeypatch):
    """An unassigned spoke configured by tenantA's instance is tenantA's only."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-a"], {},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"}])
    assert LabManagerHub.get_cppm_spoke_for_global(hub) is None
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, None) is None
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-a"
    # A configured but offline shared tenant does not open it up either.
    _shared_tenant(monkeypatch)
    assert LabManagerHub.get_cppm_spoke_for_global(hub) is None


def test_spokeless_instance_owns_only_the_spokes_the_push_sends_it_to(monkeypatch):
    """A spoke with no instance of its own is pushed the first spoke-less one
    (main.py push_config_to_spoke); a spoke with its own instance is not."""
    _no_shared_tenant(monkeypatch)
    tenant_owned = _CppmHub(["cppm-x"], {},
                            nac_instances=[{"tenant_id": "tenantA", "spoke_id": ""}])
    assert LabManagerHub.get_cppm_spoke_for_global(tenant_owned) is None
    assert LabManagerHub.get_cppm_spoke_for_shared(tenant_owned) is None
    # cppm-y has its own unassigned instance, so tenantA's never reaches it.
    mixed = _CppmHub(["cppm-x", "cppm-y"], {},
                     nac_instances=[{"tenant_id": "tenantA", "spoke_id": ""},
                                    {"tenant_id": "", "spoke_id": "cppm-y"}])
    assert LabManagerHub.get_cppm_spoke_for_global(mixed) == "cppm-y"
    # The single-ClearPass deployment: an admin (any case) or unassigned
    # spoke-less instance owns nothing, so the hub's ClearPass stays global.
    for tenant in ("", "Default", "shared"):
        single = _CppmHub(["cppm-hub"], {},
                          nac_instances=[{"tenant_id": tenant, "spoke_id": ""}])
        assert LabManagerHub.get_cppm_spoke_for_global(single) == "cppm-hub", tenant


def test_tenant_fallback_skips_a_spoke_serving_another_tenants_instance():
    """A spoke bound to tenantB but configured by tenantA's instance serves
    tenantA's ClearPass; tenantB's metadata fallback must not pick it."""
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantB"}},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-1"}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantB") is None
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-1"
    # Its own instance, recorded with different capitalisation, still counts.
    own = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantB"}},
                   nac_instances=[{"tenant_id": "TenantB", "spoke_id": "cppm-1"}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(own, "tenantB") == "cppm-1"


def test_instance_saved_under_the_pre_migration_spoke_id_still_owns_it(monkeypatch):
    """An instance saved before the spoke's guid migration keeps the old id;
    ownership compares primary keys, as the reconnect push does."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["guid-1"], {},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-old"}],
                   alias={"cppm-old": "guid-1"})
    assert LabManagerHub.get_cppm_spoke_for_global(hub) is None


# ── the records a spoke is pushed decide whose ClearPass it serves ──────────
# A tenant's own spoke is read without the tenant's subnet filter, so the
# NAC records that configure a spoke, not its binding, decide whether it is
# the tenant's own, the shared ClearPass, or admin-only.

def test_offline_own_record_keeps_the_tenant_off_the_shared_clearpass(monkeypatch):
    """A record of the tenant's own takes it out of the shared ClearPass even
    while that record's spoke is offline, so its view does not fall back to
    the shared ClearPass whenever its own spoke drops."""
    _shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-shared"], {"cppm-shared": {"tenant_id": "shared-tenant"}},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-a"},
                                  {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == []
    # A tenant with no ClearPass of its own still reads the shared one.
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantB") == ["cppm-shared"]


def test_spokeless_own_record_resolves_to_the_unassigned_spoke_it_is_pushed_to(monkeypatch):
    """A Global Admin can give a spoke-less record a tenant. The reconnect
    push sends it to every NAC spoke no record is bound to, so that spoke
    serves the tenant's ClearPass: it is the tenant's own, with no shared
    ClearPass beside it."""
    _shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-x", "cppm-shared"], {"cppm-shared": {"tenant_id": "shared-tenant"}},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": ""},
                                  {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-x"
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == ["cppm-x"]
    assert LabManagerHub.get_nac_spoke_owner(hub, "cppm-x") == "tenantA"


def test_spokeless_record_that_is_not_first_is_served_by_no_spoke(monkeypatch):
    """Only the first spoke-less record is pushed, so a later one configures
    no spoke. Its tenant resolves to no spoke, and still does not read the
    shared ClearPass: it has a ClearPass of its own."""
    _shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-x", "cppm-shared"], {"cppm-shared": {"tenant_id": "shared-tenant"}},
                   nac_instances=[{"tenant_id": "", "spoke_id": ""},
                                  {"tenant_id": "tenantA", "spoke_id": ""},
                                  {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == []
    # cppm-x is pushed the hub's record: the hub's ClearPass, owned by no tenant.
    assert LabManagerHub.get_nac_spoke_owner(hub, "cppm-x") is None


def test_record_saved_under_a_pre_migration_id_resolves_to_the_migrated_spoke(monkeypatch):
    """The tenant resolver compares primary keys too, so a record saved
    before its spoke's guid migration still finds that spoke."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["guid-1"], {},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-old"}],
                   alias={"cppm-old": "guid-1"})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "guid-1"
    assert LabManagerHub.get_nac_spoke_owner(hub, "guid-1") == "tenantA"


def test_record_tenant_ids_compare_case_insensitively(monkeypatch):
    """A record saved as "TenantA" is tenanta's own ClearPass, both for the
    resolver and for leaving the shared ClearPass."""
    import access
    _shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-a", "cppm-shared"], {"cppm-shared": {"tenant_id": "shared-tenant"}},
                   nac_instances=[{"tenant_id": "TenantA", "spoke_id": "cppm-a"},
                                  {"tenant_id": "shared-tenant", "spoke_id": "cppm-shared"}])
    assert access.tenant_left_shared(hub, "tenanta", "nac") is True
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenanta") == "cppm-a"
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenanta") == ["cppm-a"]


def test_two_spokes_pushed_the_same_record_resolve_to_the_same_one_every_time(monkeypatch):
    """Both unassigned spokes receive the tenant's spoke-less record; the pick
    goes by sorted id, not connection order, so it does not flip on a
    reconnect."""
    _no_shared_tenant(monkeypatch)
    records = [{"tenant_id": "tenantA", "spoke_id": ""}]
    for order in (["cppm-b", "cppm-a"], ["cppm-a", "cppm-b"]):
        hub = _CppmHub(order, {}, nac_instances=records)
        assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") == "cppm-a", order


def test_tenant_bound_spoke_pushed_the_hubs_record_is_not_the_tenants_own(monkeypatch):
    """A spoke bound to tenantA with no record of its own is pushed the hub's
    spoke-less record, so it serves the hub's ClearPass. Reading it as
    tenantA's own would show tenantA every tenant's sessions unfiltered."""
    import access
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-t"], {"cppm-t": {"tenant_id": "tenantA", "module_type": "nac"}},
                   nac_instances=[{"tenant_id": "", "spoke_id": ""}])
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenantA") is None
    assert LabManagerHub.get_cppm_spokes_for_tenant(hub, "tenantA") == []
    assert LabManagerHub.get_cppm_spoke_for_scope(hub, "tenantA") is None
    assert LabManagerHub.get_nac_spoke_owner(hub, "cppm-t") == access.ADMIN_ONLY_OWNER


def test_jit_creates_users_only_on_a_clearpass_the_tenant_owns_alone(monkeypatch):
    """802.1X JIT picks the ClearPass the way the NAC pages do. Its old local
    lookup took the tenant's first record's spoke whenever it was connected,
    so a JIT user landed on a ClearPass another tenant's record also
    configures, or on an unapproved spoke."""
    import dot1x_jit
    _no_shared_tenant(monkeypatch)

    def _hub(records, approved=None):
        """A hub with ``records``, readable where both the resolver and the old lookup read them."""
        hub = _CppmHub(["cppm-1"], {}, approved=approved, nac_instances=records)
        hub.state.system_state["global_config"] = {"nac_instances": records}
        return hub

    a, b = {"tenant_id": "tenantA", "spoke_id": "cppm-1"}, {"tenant_id": "tenantB", "spoke_id": "cppm-1"}
    assert dot1x_jit._nac_spoke(_hub([a, b]), "tenantA") is None
    assert dot1x_jit._nac_spoke(_hub([a]), "tenantA") == "cppm-1"
    assert dot1x_jit._nac_spoke(_hub([a], approved={"cppm-1": False}), "tenantA") is None


def test_nac_spoke_owner_follows_the_records_the_spoke_is_pushed(monkeypatch):
    """get_nac_spoke_owner: the records decide whatever the binding says; a
    spoke serving no one tenant alone is admin-only; a shared record is the
    shared ClearPass; with no record, the binding decides."""
    import access
    _shared_tenant(monkeypatch, "lab")

    def owner(binding, records):
        """The owner of one NAC spoke with this binding and these records."""
        hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": binding}}, nac_instances=records)
        return LabManagerHub.get_nac_spoke_owner(hub, "cppm-1")

    a_rec = {"tenant_id": "tenantA", "spoke_id": "cppm-1"}
    b_rec = {"tenant_id": "tenantB", "spoke_id": "cppm-1"}
    shared_rec = {"tenant_id": "lab", "spoke_id": "cppm-1"}
    hub_rec = {"tenant_id": "", "spoke_id": ""}
    # A tenant's record makes the spoke that tenant's, whatever its binding.
    for binding in ("", "default", "tenantB", "lab"):
        assert owner(binding, [a_rec]) == "tenantA", binding
    # No record: the binding decides.
    assert owner("tenantA", []) == "tenantA"
    assert owner("", []) is None
    assert owner("default", []) == "default"
    # The hub's spoke-less record: the hub's ClearPass, never a tenant's own.
    assert owner("", [hub_rec]) is None
    assert owner("default", [hub_rec]) == "default"
    assert owner("tenantA", [hub_rec]) == access.ADMIN_ONLY_OWNER
    # Serving several tenants, or a tenant next to shared or the hub: admin-only.
    assert owner("", [a_rec, b_rec]) == access.ADMIN_ONLY_OWNER
    assert owner("", [a_rec, shared_rec]) == access.ADMIN_ONLY_OWNER
    assert owner("", [a_rec, {"tenant_id": "", "spoke_id": "cppm-1"}]) == access.ADMIN_ONLY_OWNER
    # Shared records only: the shared ClearPass, subnet-filtered for everyone.
    assert owner("", [shared_rec]) is None
    assert owner("tenantA", [shared_rec]) is None


def test_spoke_data_owner_reads_records_for_nac_and_the_binding_for_other_modules(monkeypatch):
    import access
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "tenantB", "module_type": "nac"},
                                "nw-1": {"tenant_id": "tenantB", "module_type": "nw"}},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-1"}])
    assert access.spoke_data_owner(hub, "cppm-1") == "tenantA"
    assert access.spoke_data_owner(hub, "nw-1") == "tenantB"


def _sessions(**users):
    """One live session per name. ``None`` makes a Global Admin; a list
    makes a non-admin user of those tenants (the first is primary)."""
    import time
    out = {}
    for name, tenants in users.items():
        user = ({"permissions": {"admin": True}} if tenants is None else
                {"permissions": {}, "tenants": list(tenants), "tenant_id": tenants[0]})
        out[name] = {"expires": time.time() + 3600, "user": user}
    return out


class _Req:
    """A request carrying one session cookie and no query string."""

    def __init__(self, token):
        self.cookies = {"lm_session": token}
        self.query_params = {}


def test_spoke_serving_two_tenants_is_read_and_written_only_by_an_unscoped_admin(monkeypatch):
    """ADMIN_ONLY_OWNER: neither tenant, nor a non-admin member of the ADMIN
    tenant, reads or writes a spoke serving two tenants' ClearPass, and a
    Global Admin reads it only with no tenant selected."""
    import asyncio
    import access
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"module_type": "nac"}},
                   nac_instances=[{"tenant_id": "tenantA", "spoke_id": "cppm-1"},
                                  {"tenant_id": "tenantB", "spoke_id": "cppm-1"}])
    sessions = _sessions(admin=None, a_user=["tenantA"], admin_tenant_user=["default"])

    def visible(who, tenant=None):
        """Read visibility of cppm-1's data for one session."""
        return access._owned_spoke_visible(hub, sessions, _Req(who), "cppm-1", tenant)

    assert visible("admin") is True
    assert visible("admin", "tenantA") is False
    assert visible("a_user") is False
    assert visible("admin_tenant_user") is False
    # The single-record gate the NAC routes use agrees.
    rec = {"ip": "10.0.0.5"}
    for who, expected in (("admin", rec), ("a_user", None), ("admin_tenant_user", None)):
        got = asyncio.run(access.gate_record_tenant(
            hub, sessions, _Req(who), rec, "nac", ["ip"], spoke_id="cppm-1"))
        assert got == expected, who
    # Writes: a Global Admin only.
    assert access._owned_spoke_writable(hub, sessions["admin"], "cppm-1") is True
    assert access._owned_spoke_writable(hub, sessions["a_user"], "cppm-1") is False
    assert access._owned_spoke_writable(hub, sessions["admin_tenant_user"], "cppm-1") is False


def _ledger_hub(pushed, records):
    """Two unassigned NAC spokes, cppm-1 and cppm-2, with these NAC records
    and this ledger of the config the hub last sent each
    (``system_state["nac_config_pushed"]``)."""
    hub = _CppmHub(["cppm-1", "cppm-2"], {"cppm-1": {}, "cppm-2": {}}, nac_instances=records)
    hub.state.system_state["nac_config_pushed"] = dict(pushed)
    return hub


def test_spoke_a_record_moved_off_still_holds_it_so_it_serves_no_one(monkeypatch):
    """A cppm spoke keeps the last config it was sent, so after Setup → NAC
    moves tenant A's record from cppm-1 to cppm-2, cppm-1 still answers from
    A's ClearPass. It must not serve the global or shared view (it looks
    unassigned and owns no record), and only an unscoped admin may read it."""
    import access
    _no_shared_tenant(monkeypatch)
    rec_a = {"id": "rec-a", "tenant_id": "tenantA", "spoke_id": "cppm-2", "host": "cp-a"}
    hub = _ledger_hub({"cppm-1": "rec-a@cp-a", "cppm-2": "rec-a@cp-a"}, [rec_a])
    assert hub.get_cppm_spoke_for_global() is None
    assert LabManagerHub.get_cppm_spoke_for_shared(hub) is None
    assert hub.get_nac_spoke_owner("cppm-1") == access.ADMIN_ONLY_OWNER
    assert hub.get_cppm_spoke_for_tenant("tenantA") == "cppm-2"
    assert hub.get_nac_live_spokes() == ["cppm-2"]


def test_spoke_whose_record_was_deleted_is_skipped_but_a_never_sent_spoke_serves(monkeypatch):
    """Deleting tenant A's record leaves cppm-1 holding A's ClearPass, so it
    is skipped. cppm-2 was never sent a config by the hub (set up through its
    own .env), so it is not stale and still serves the global view."""
    import access
    _no_shared_tenant(monkeypatch)
    hub = _ledger_hub({"cppm-1": "rec-a@cp-a"}, [])
    assert hub.get_cppm_spoke_for_global() == "cppm-2"
    assert hub.get_nac_spoke_owner("cppm-1") == access.ADMIN_ONLY_OWNER
    assert hub.get_nac_live_spokes() == ["cppm-2"]


def test_stale_spoke_serves_again_once_sent_its_record_and_a_host_edit_makes_it_stale(monkeypatch):
    """cppm-1 was sent tenant A's record, which then moved away, and tenant
    B's record was bound to it. Until the hub sends it B's config it may
    still answer from A's ClearPass, so B is not given it; once sent, it is
    B's. Editing B's host in place makes it stale until the next send. The
    ledger is saved only when it changes. Dropping the entry (deleting the
    spoke from the hub does) leaves it stale while B's record still
    configures cppm-1, until it is sent that record."""
    from hub_spoke_registry import nac_spoke_stale, record_nac_push
    _no_shared_tenant(monkeypatch)
    rec_b = {"id": "rec-b", "tenant_id": "tenantB", "spoke_id": "cppm-1", "host": "cp-b"}
    hub = _ledger_hub({"cppm-1": "rec-a@cp-a"}, [rec_b])
    assert hub.get_cppm_spoke_for_tenant("tenantB") is None
    record_nac_push(hub, "cppm-1", rec_b)
    record_nac_push(hub, "cppm-1", rec_b)
    assert hub.state.dirty == 1
    assert hub.get_cppm_spoke_for_tenant("tenantB") == "cppm-1"
    rec_b["host"] = "cp-b2"
    assert nac_spoke_stale(hub, "cppm-1") is True
    assert hub.get_cppm_spoke_for_tenant("tenantB") is None
    record_nac_push(hub, "cppm-1", None)
    assert "cppm-1" not in hub.state.system_state["nac_config_pushed"]
    assert hub.state.dirty == 2
    assert nac_spoke_stale(hub, "cppm-1") is True


def test_spoke_a_record_configures_is_stale_until_sent_that_record(monkeypatch):
    """A spoke set up through its own .env may answer from any ClearPass,
    so once tenant B's record is bound to it, B is not given it until the
    hub has sent it that record. A record with no host is never sent, so its
    spoke stays stale."""
    from hub_spoke_registry import nac_spoke_stale, record_nac_push
    _no_shared_tenant(monkeypatch)
    rec_b = {"id": "rec-b", "tenant_id": "tenantB", "spoke_id": "cppm-1", "host": "cp-b"}
    hub = _ledger_hub({}, [rec_b])
    assert nac_spoke_stale(hub, "cppm-1") is True
    assert hub.get_cppm_spoke_for_tenant("tenantB") is None
    record_nac_push(hub, "cppm-1", rec_b)
    assert hub.get_cppm_spoke_for_tenant("tenantB") == "cppm-1"
    rec_b["host"] = " "
    assert nac_spoke_stale(hub, "cppm-1") is True


def test_legacy_config_is_the_hubs_own_record(monkeypatch):
    """With no NAC record, every NAC spoke is sent the legacy single config
    (global_config["cppm"]), the hub's own ClearPass, as Setup → NAC's
    migration later makes it: a spoke-less record with no tenant. A spoke
    bound to tenantA that holds it is not tenantA's own, and a host change
    makes every spoke stale until it confirms the new host. With no legacy
    host nothing is sent, so a spoke's binding decides as before."""
    import access
    from hub_spoke_registry import LEGACY_NAC_RECORD_ID, nac_spoke_stale, record_nac_push
    _no_shared_tenant(monkeypatch)
    meta = {"cppm-t": {"tenant_id": "tenantA"}, "cppm-u": {}}
    hub = _CppmHub(["cppm-t", "cppm-u"], meta, cppm={"host": "cp-legacy"})
    assert hub.get_nac_spoke_owner("cppm-t") == access.ADMIN_ONLY_OWNER
    assert hub.get_cppm_spoke_for_tenant("tenantA") is None
    assert hub.get_cppm_spokes_for_tenant("tenantA") == []
    assert hub.get_nac_spoke_owner("cppm-u") is None
    assert hub.get_cppm_spoke_for_global() == "cppm-u"
    # A host change: no spoke is used until it confirms the new host.
    hub.state.cppm["host"] = "cp-new"
    assert nac_spoke_stale(hub, "cppm-u") is True
    assert hub.get_cppm_spoke_for_global() is None
    assert hub.get_nac_live_spokes() == []
    record_nac_push(hub, "cppm-u", {"id": LEGACY_NAC_RECORD_ID, "host": "cp-new"})
    assert hub.get_cppm_spoke_for_global() == "cppm-u"
    # No legacy host: the spoke keeps its own .env ClearPass.
    hub = _CppmHub(["cppm-t", "cppm-u"], meta, cppm={"host": ""})
    assert hub.get_nac_spoke_owner("cppm-t") == "tenantA"
    assert hub.get_cppm_spoke_for_tenant("tenantA") == "cppm-t"
    assert nac_spoke_stale(hub, "cppm-u") is False


class _BindHub:
    """Spokes bound to tenants, recording the cache namespaces dropped."""

    bind_spoke_tenant = LabManagerHub.bind_spoke_tenant
    _primary_key = LabManagerHub._primary_key

    def __init__(self, module_types, metadata):
        from types import SimpleNamespace
        tenants = {sid: m.get("tenant_id", "") for sid, m in metadata.items()}
        self.spoke_module_types = dict(module_types)
        self.spoke_id_alias = {}
        self.dropped = []
        self.state = SimpleNamespace(
            system_state={"module_metadata": metadata},
            get_spoke_tenant=lambda sid: tenants.get(sid, ""),
            set_spoke_tenant=tenants.__setitem__)

    def warm_drop(self, namespace, key_prefixes):
        """Record a dropped cache namespace."""
        self.dropped.append(namespace)
        return 0


def test_binding_a_nac_spoke_to_another_tenant_drops_the_nac_caches():
    """A NAC spoke no record configures serves the tenant it is bound to, so
    binding it to another tenant drops the cached NAC reads. Re-binding the
    same tenant (every PSK reconnect does) keeps them, and so does binding
    any other module. A spoke that is not connected is known by the type
    saved when it registered."""
    from routes.cppm import NAC_CACHE_NAMESPACES
    hub = _BindHub({"cppm-1": "nac", "pxmx-1": "pxmx"},
                   {"cppm-1": {"tenant_id": "tenantA"}, "pxmx-1": {"tenant_id": "tenantA"},
                    "cppm-off": {"tenant_id": "tenantA", "module_type": "nac"}})
    hub.bind_spoke_tenant("cppm-1", "TENANTA")
    hub.bind_spoke_tenant("pxmx-1", "tenantB")
    assert hub.dropped == []
    hub.bind_spoke_tenant("cppm-1", "tenantB")
    assert hub.dropped == list(NAC_CACHE_NAMESPACES)
    assert hub.state.get_spoke_tenant("cppm-1") == "tenantB"
    hub.dropped.clear()
    hub.bind_spoke_tenant("cppm-off", "tenantB")
    assert hub.dropped == list(NAC_CACHE_NAMESPACES)


def test_for_tenant_matches_the_spoke_tag_in_any_case():
    hub = _CppmHub(["cppm-1"], {"cppm-1": {"tenant_id": "TenantA"}})
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "tenanta") == "cppm-1"


def test_for_tenant_default_in_any_case_is_the_admin_view(monkeypatch):
    """Any spelling of "default" is the built-in ADMIN tenant, not a tenant
    with no NAC spoke: it reads the global source, never a tenant's spoke."""
    _no_shared_tenant(monkeypatch)
    hub = _CppmHub(["cppm-a", "cppm-hub"],
                   {"cppm-a": {"tenant_id": "tenantA"}, "cppm-hub": {}})
    for spelling in ("default", "Default", " DEFAULT "):
        assert LabManagerHub.get_cppm_spoke_for_tenant(hub, spelling) == "cppm-hub"
        assert LabManagerHub.get_cppm_spoke_for_scope(hub, spelling) == "cppm-hub"


def test_nac_spoke_owner_keeps_a_padded_twins_spelling(monkeypatch):
    """With legacy twins "ACME" and " ACME " stored, a spoke whose only
    record is " ACME "'s serves " ACME " alone. Its owner was the stripped
    "ACME", the other twin, which then failed the serves-only check."""
    import access
    _no_shared_tenant(monkeypatch)
    monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS", frozenset({"acme"}))
    hub = _CppmHub(["cppm-1"], {}, nac_instances=[{"tenant_id": " ACME ", "spoke_id": "cppm-1"}])
    assert LabManagerHub.get_nac_spoke_owner(hub, "cppm-1") == " ACME "
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, " ACME ") == "cppm-1"
    assert LabManagerHub.get_cppm_spoke_for_tenant(hub, "ACME") is None
