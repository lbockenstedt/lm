"""Critical path 4/4 — endpoint sync (IPAM → CPPM) source registry.

The sync is modular: ``EndpointSyncMixin.IPAM_SOURCES`` maps a source name →
how the hub talks to that IPAM product, and ``_endpoint_sync_source`` resolves
the configured source (falling back to NetBox). These tests lock in the
registry shape + the fallback so adding/swapping a source stays a one-entry
change (the contract documented in ``docs/modules/cppm.md``).

TODO (integration): a ``FakeHub`` whose ``request_response`` returns canned
NETBOX_GET_IPS + CPPM_SYNC_ENDPOINTS payloads, then assert
``sync_tenant_endpoints`` extracts IPs/MACs and pushes replace=True per tenant.
"""

from endpoint_sync import EndpointSyncMixin
from _fakes import FakeState


REQUIRED_SOURCE_KEYS = {"module_type", "get_ips_command", "tenant_scope_field",
                        "response_key", "label"}


def test_ipam_sources_registry_shape():
    """Every registered source carries the full contract key set."""
    for name, entry in EndpointSyncMixin.IPAM_SOURCES.items():
        assert REQUIRED_SOURCE_KEYS <= set(entry), f"source {name} missing keys: {REQUIRED_SOURCE_KEYS - set(entry)}"
    assert "netbox" in EndpointSyncMixin.IPAM_SOURCES


def test_default_source_is_netbox_when_unconfigured():
    m = EndpointSyncMixin()
    m.state = FakeState(global_config={})
    src = m._endpoint_sync_source()
    assert src is EndpointSyncMixin.IPAM_SOURCES["netbox"]


def test_explicit_netbox_source_resolves():
    m = EndpointSyncMixin()
    m.state = FakeState(global_config={"netbox_cppm_sync": {"source": "netbox"}})
    assert m._endpoint_sync_source() is EndpointSyncMixin.IPAM_SOURCES["netbox"]


def test_unknown_source_falls_back_to_netbox():
    m = EndpointSyncMixin()
    m.state = FakeState(global_config={"netbox_cppm_sync": {"source": "phpipam-deleted"}})
    assert m._endpoint_sync_source() is EndpointSyncMixin.IPAM_SOURCES["netbox"]


def test_source_name_is_case_insensitive():
    m = EndpointSyncMixin()
    m.state = FakeState(global_config={"netbox_cppm_sync": {"source": "  NETBOX  "}})
    assert m._endpoint_sync_source() is EndpointSyncMixin.IPAM_SOURCES["netbox"]