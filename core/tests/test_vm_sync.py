"""Critical path — VM sync (Hypervisor → NetBox) source registry.

Mirrors ``test_endpoint_sync.py``. The sync is modular: ``VmSyncMixin
.HYPERVISOR_SOURCES`` maps a source name → how the hub talks to that
hypervisor product, and ``_vm_sync_source`` resolves the configured source
(falling back to Proxmox). These tests lock in the registry shape + the
fallback so adding/swapping a source stays a one-entry change.

TODO (integration): a ``FakeHub`` whose ``request_response`` returns canned
PXMX_LIST_VMS + NETBOX_SYNC_VMS payloads, then assert ``sync_tenant_vms``
extracts VMs and pushes replace=True per tenant (needs a fuller harness — see
``test_relay_contract.py``; ``FakeHub`` can't yet drive ``request_response``).
"""

from vm_sync import VmSyncMixin
from _fakes import FakeState


REQUIRED_SOURCE_KEYS = {"module_type", "list_command", "tenant_scope_field",
                        "request_filter_key", "response_key", "label"}


def test_hypervisor_sources_registry_shape():
    """Every registered source carries the full contract key set."""
    for name, entry in VmSyncMixin.HYPERVISOR_SOURCES.items():
        assert REQUIRED_SOURCE_KEYS <= set(entry), \
            f"source {name} missing keys: {REQUIRED_SOURCE_KEYS - set(entry)}"
    assert "proxmox" in VmSyncMixin.HYPERVISOR_SOURCES


def test_proxmox_source_contract():
    """The Proxmox source talks to the hypervisor spoke via PXMX_LIST_VMS,
    scoped by proxmox_tag (sent as tag_filter), returning the 'vms' list."""
    se = VmSyncMixin.HYPERVISOR_SOURCES["proxmox"]
    assert se["module_type"] == "hypervisor"
    assert se["list_command"] == "PXMX_LIST_VMS"
    assert se["tenant_scope_field"] == "proxmox_tag"
    assert se["request_filter_key"] == "tag_filter"
    assert se["response_key"] == "vms"


def test_default_source_is_proxmox_when_unconfigured():
    m = VmSyncMixin()
    m.state = FakeState(global_config={})
    src = m._vm_sync_source()
    assert src is VmSyncMixin.HYPERVISOR_SOURCES["proxmox"]


def test_explicit_proxmox_source_resolves():
    m = VmSyncMixin()
    m.state = FakeState(global_config={"pxmx_netbox_vm_sync": {"source": "proxmox"}})
    assert m._vm_sync_source() is VmSyncMixin.HYPERVISOR_SOURCES["proxmox"]


def test_unknown_source_falls_back_to_proxmox():
    m = VmSyncMixin()
    m.state = FakeState(global_config={"pxmx_netbox_vm_sync": {"source": "vmware-someday"}})
    assert m._vm_sync_source() is VmSyncMixin.HYPERVISOR_SOURCES["proxmox"]


def test_source_name_is_case_insensitive():
    m = VmSyncMixin()
    m.state = FakeState(global_config={"pxmx_netbox_vm_sync": {"source": "  PROXMOX  "}})
    assert m._vm_sync_source() is VmSyncMixin.HYPERVISOR_SOURCES["proxmox"]


def test_cfg_key_and_target_are_fixed():
    """The config key + netbox push target are stable contract, not config."""
    assert VmSyncMixin._VM_SYNC_CFG_KEY == "pxmx_netbox_vm_sync"
    assert VmSyncMixin._VM_SYNC_TARGET_MODULE == "ipam"
    assert VmSyncMixin._VM_SYNC_PUSH_COMMAND == "NETBOX_SYNC_VMS"


def test_vm_sync_sot_defaults_external_and_reads_config():
    # Default source of truth for VMs is "external" (Proxmox owns → overwrite).
    m = VmSyncMixin()
    m.state = FakeState(global_config={})
    assert m._vm_sync_sot() == "external"
    # Configured netbox → only-add-missing.
    m.state = FakeState(system_state={"global_config":
        {"source_of_truth": {"vm_sync": "netbox"}}})
    assert m._vm_sync_sot() == "netbox"
    # Unknown / blank falls back to external.
    m.state = FakeState(system_state={"global_config":
        {"source_of_truth": {"vm_sync": "  ???  "}}})
    assert m._vm_sync_sot() == "external"


def test_vm_sync_tenants_filters_by_proxmox_tag():
    """Only tenants carrying the source's scope field (proxmox_tag) sync."""
    m = VmSyncMixin()
    m.state = FakeState(tenants={
        "t1": {"name": "Alpha", "proxmox_tag": "alpha"},
        "t2": {"name": "Beta"},  # no proxmox_tag → not bound
        "t3": {"name": "Gamma", "proxmox_tag": "gamma", "netbox_tenant_slug": "g"},
    })
    bound = set(m._vm_sync_tenants())
    assert bound == {"t1", "t3"}


def test_tenant_id_for_vm_sync_scope_reverse_maps():
    m = VmSyncMixin()
    m.state = FakeState(tenants={
        "t1": {"name": "Alpha", "proxmox_tag": "alpha"},
        "t2": {"name": "Beta", "proxmox_tag": "beta"},
    })
    assert m.tenant_id_for_vm_sync_scope("alpha") == "t1"
    assert m.tenant_id_for_vm_sync_scope("beta") == "t2"
    assert m.tenant_id_for_vm_sync_scope("nope") is None
    assert m.tenant_id_for_vm_sync_scope("") is None


# ── Case-insensitive tag → tenant attribution (name / slug / proxmox_tag) ─────
#
# A VM's Proxmox label can be the tenant's display NAME or its NetBox slug, not
# just the configured proxmox_tag. _vm_sync_tag_to_tid keys on all three
# (lowercased; proxmox_tag wins on collision) and _vm_sync_resolve_tenant emits
# the configured slug, falling back to the tenant name so the netbox spoke can
# resolve it case-insensitively by slug OR name.

def test_tag_to_tid_matches_proxmox_tag_case_insensitive():
    m = VmSyncMixin()
    tenants = {"t1": {"name": "Alpha", "proxmox_tag": "alpha"}}
    t2t, _ = m._vm_sync_tag_to_tid(tenants)
    assert t2t == {"alpha": "t1"}
    tid, tslug = m._vm_sync_resolve_tenant(["ALPHA"], t2t, {"t1": tenants["t1"]})
    assert tid == "t1"
    # no netbox_tenant_slug configured → tenant name flows through as the slug
    # so the netbox spoke can resolve it case-insensitively by name.
    assert tslug == "Alpha"


def test_tag_to_tid_matches_tenant_display_name_case_insensitive():
    # VM labeled with the tenant's display NAME (different case, no proxmox_tag
    # match) must attribute. This is the clone-from-template / manual-label case.
    m = VmSyncMixin()
    tenants = {"t1": {"name": "Alpha", "proxmox_tag": "alpha",
                      "netbox_tenant_slug": "alpha"}}
    t2t, cfgs = m._vm_sync_tag_to_tid(tenants)
    # name "alpha" lowercased fills in (equals proxmox_tag here, no collision)
    assert t2t["alpha"] == "t1"
    tid, tslug = m._vm_sync_resolve_tenant(["AlPhA"], t2t, cfgs)
    assert tid == "t1"
    assert tslug == "alpha"


def test_tag_to_tid_matches_tenant_name_when_proxmox_tag_absent():
    # Tenant has NO proxmox_tag, only a display name — a VM labeled with that
    # name (any case) must still attribute, and the name flows through as the
    # tenant_slug fallback so netbox can resolve it by name.
    m = VmSyncMixin()
    tenants = {"t1": {"name": "LRB Labs"}}  # no proxmox_tag, no slug
    t2t, cfgs = m._vm_sync_tag_to_tid(tenants)
    assert t2t == {"lrb labs": "t1"}
    tid, tslug = m._vm_sync_resolve_tenant(["LRB LABS"], t2t, cfgs)
    assert tid == "t1"
    assert tslug == "LRB Labs"  # name passed through → netbox resolves by name


def test_tag_to_tid_matches_netbox_slug_case_insensitive():
    m = VmSyncMixin()
    tenants = {"t1": {"name": "Alpha Corp", "proxmox_tag": "px-alpha",
                      "netbox_tenant_slug": "Alpha"}}  # slug in mixed case
    t2t, cfgs = m._vm_sync_tag_to_tid(tenants)
    assert t2t["px-alpha"] == "t1"   # proxmox_tag
    assert t2t["alpha"] == "t1"      # slug lowercased
    assert t2t["alpha corp"] == "t1"  # name lowercased
    tid, tslug = m._vm_sync_resolve_tenant(["alpha"], t2t, cfgs)
    assert tid == "t1" and tslug == "Alpha"


def test_proxmox_tag_wins_on_collision_with_name_or_slug():
    # t1 proxmox_tag "x" ; t2 name "X" — a VM tag "x" must attribute to t1
    # (proxmox_tag is the stronger signal), not t2.
    m = VmSyncMixin()
    tenants = {
        "t1": {"name": "One", "proxmox_tag": "x", "netbox_tenant_slug": "one"},
        "t2": {"name": "X", "netbox_tenant_slug": "two"},  # name collides with t1 tag
    }
    t2t, cfgs = m._vm_sync_tag_to_tid(tenants)
    assert t2t["x"] == "t1"
    tid, _ = m._vm_sync_resolve_tenant(["X"], t2t, cfgs)
    assert tid == "t1"


def test_resolve_tenant_no_match_returns_unassigned():
    m = VmSyncMixin()
    t2t, cfgs = m._vm_sync_tag_to_tid({"t1": {"name": "Alpha", "proxmox_tag": "alpha"}})
    assert m._vm_sync_resolve_tenant(["unrelated"], t2t, cfgs) == (None, None)
    assert m._vm_sync_resolve_tenant([], t2t, cfgs) == (None, None)
    assert m._vm_sync_resolve_tenant([""], t2t, cfgs) == (None, None)


def test_trigger_vm_sync_noop_when_disabled_or_no_target():
    """trigger_vm_sync must never raise and must be a no-op when disabled or
    when the netbox spoke isn't connected (no running loop / no spoke)."""
    m = VmSyncMixin()
    m.state = FakeState(global_config={"pxmx_netbox_vm_sync": {"enabled": False}})
    m.get_spoke_by_type = lambda mt: None
    # disabled → no-op
    m.trigger_vm_sync("t1")
    # enabled but no netbox spoke → no-op
    m.state = FakeState(global_config={"pxmx_netbox_vm_sync": {"enabled": True}})
    m.trigger_vm_sync("t1")
    # blank tenant → no-op
    m.trigger_vm_sync("")