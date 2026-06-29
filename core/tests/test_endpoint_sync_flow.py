"""Integration test — sync_tenant_endpoints (IPAM → CPPM) with canned payloads.

``test_endpoint_sync.py`` locks in the source registry shape + fallback; this
file exercises the actual per-tenant loop with a FakeHub whose
``request_response`` returns canned NETBOX_GET_IPS + CPPM_SYNC_ENDPOINTS
payloads — proving the hub extracts address/MAC/hostname from the IPAM
response, posts replace=True to CPPM, and records a ``success`` status with the
right pushed/errors counts. Also covers the spoke-offline (503-ish) and
tenant-unbound (skipped) branches.
"""

import pytest

from endpoint_sync import EndpointSyncMixin
from _fakes import FakeState


class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = {}

    async def set_endpoint_sync_status(self, tenant_id, status):
        self.recorded[tenant_id] = status


class _SyncHub(EndpointSyncMixin):
    """Minimal hub stand-in: canned request_response + spoke routing."""

    def __init__(self, ipam_spoke="netbox-spoke-1", nac_spoke="cppm-spoke-1",
                 tenants=None, responses=None):
        self.state = FakeState(
            global_config={},
            tenants=tenants or {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        )
        self.simulations_store = _FakeSimulationsStore()
        self._ipam_spoke = ipam_spoke
        self._nac_spoke = nac_spoke
        self._responses = responses or {}
        self.request_log = []

    def get_spoke_by_type(self, module_type: str):
        if module_type == "ipam":
            return self._ipam_spoke
        if module_type == "nac":
            return self._nac_spoke
        return None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]


def _netbox_ips_payload():
    return {"payload": {"data": {"status": "SUCCESS", "ip_addresses": [
        {"address": "10.20.0.5/24", "dns_name": "host1", "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:01"}},
        {"address": "10.20.0.6/24", "dns_name": "host2", "custom_fields": {}},
        {"address": None, "dns_name": "", "custom_fields": {}},  # nothing to sync → skipped
    ]}}}


def _cppm_ok_payload():
    return {"payload": {"data": {"status": "SUCCESS", "pushed": 2, "errors": 0,
                                 "skipped": 0, "skipped_details": [], "message": "ok"}}}


@pytest.mark.asyncio
async def test_sync_extracts_and_pushes_replace_true():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"): _cppm_ok_payload(),
    })
    status = await hub.sync_tenant_endpoints("acme")

    # IPAM fetch used the tenant's scope; CPPM push was replace=True with 2 endpoints
    ipam_call = hub.request_log[0]
    cppm_call = hub.request_log[1]
    assert ipam_call[1] == "NETBOX_GET_IPS" and ipam_call[2] == {"tenant": "acme"}
    assert cppm_call[1] == "CPPM_SYNC_ENDPOINTS"
    assert cppm_call[2]["replace"] is True
    assert cppm_call[2]["tenant_id"] == "acme"
    assert cppm_call[2]["tenant_slug"] == "acme"
    eps = cppm_call[2]["endpoints"]
    assert {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:01", "hostname": "host1"} in eps
    assert {"ip": "10.20.0.6", "mac": "", "hostname": "host2"} in eps
    assert len(eps) == 2  # the empty record was dropped

    assert status["status"] == "success"
    assert status["pushed"] == 2
    assert status["endpoints_total"] == 2
    assert hub.simulations_store.recorded["acme"] is status


@pytest.mark.asyncio
async def test_sync_skipped_when_tenant_unbound():
    # No netbox_tenant_slug → tenant not bound to the IPAM source → skipped
    hub = _SyncHub(tenants={"free": {"name": "Free"}}, responses={})
    status = await hub.sync_tenant_endpoints("free")
    assert status["status"] == "skipped"
    assert hub.request_log == []  # no spokes were called


@pytest.mark.asyncio
async def test_sync_error_when_spoke_offline():
    # No IPAM spoke connected → error, no crash
    hub = _SyncHub(ipam_spoke=None, responses={})
    status = await hub.sync_tenant_endpoints("acme")
    assert status["status"] == "error"
    assert "not connected" in status["message"]


@pytest.mark.asyncio
async def test_sync_error_when_ipam_returns_error():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"):
            {"payload": {"data": {"status": "ERROR", "message": "auth failed"}}},
    })
    status = await hub.sync_tenant_endpoints("acme")
    assert status["status"] == "error"
    assert "auth failed" in status["message"]
    # CPPM was never called because IPAM errored
    assert all(cmd != "CPPM_SYNC_ENDPOINTS" for _, cmd, _ in hub.request_log)


@pytest.mark.asyncio
async def test_sync_propagates_cppm_error_counts():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"):
            {"payload": {"data": {"status": "ERROR", "pushed": 0, "errors": 3,
                                  "skipped": 0, "skipped_details": [], "message": "boom"}}},
    })
    status = await hub.sync_tenant_endpoints("acme")
    assert status["status"] == "error"
    assert status["errors"] == 3
    assert status["endpoints_total"] == 2  # still extracted from IPAM