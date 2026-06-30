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