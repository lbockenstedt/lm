"""Integration test — sync_tenant_endpoints (IPAM → CPPM) with canned payloads.

``test_endpoint_sync.py`` locks in the source registry shape + fallback; this
file exercises the actual per-tenant loop with a FakeHub whose
``request_response`` returns canned NETBOX_GET_IPS + CPPM_SYNC_ENDPOINTS
payloads — proving the hub extracts address/MAC/hostname from the IPAM
response, posts replace=True to CPPM, and records a ``success`` status with the
right pushed/errors counts. Also covers the spoke-offline (503-ish) and
tenant-unbound (skipped) branches.
"""

import logging

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
                 tenants=None, responses=None, shared_nac_spoke=None):
        self.state = FakeState(
            global_config={},
            tenants=tenants or {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}},
        )
        self.simulations_store = _FakeSimulationsStore()
        self._ipam_spoke = ipam_spoke
        self._nac_spoke = nac_spoke
        self._shared_nac_spoke = shared_nac_spoke or nac_spoke
        self._responses = responses or {}
        self.request_log = []
        self._nac_unconfigured_spokes = set()

    def get_spoke_by_type(self, module_type: str):
        if module_type == "ipam":
            return self._ipam_spoke
        if module_type == "nac":
            return self._nac_spoke
        return None

    def get_cppm_spoke_for_tenant(self, tenant_id=None):
        return self._nac_spoke

    def get_cppm_spoke_for_shared(self):
        return self._shared_nac_spoke

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]


def _netbox_ips_payload():
    return {"payload": {"data": {"status": "SUCCESS", "ip_addresses": [
        {"address": "10.20.0.5/24", "dns_name": "host1",
         "custom_fields": {"mac_address": "aa:bb:cc:dd:ee:01", "nac_role": "SSPLM-DMZ"}},
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
    assert "tenant_slug" not in cppm_call[2]
    eps = cppm_call[2]["endpoints"]
    assert {"ip": "10.20.0.5", "mac": "aa:bb:cc:dd:ee:01", "hostname": "host1",
            "nac_role": "SSPLM-DMZ"} in eps
    assert {"ip": "10.20.0.6", "mac": "", "hostname": "host2", "nac_role": ""} in eps
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


@pytest.mark.asyncio
async def test_sync_error_emits_sync_error_marker_with_message(caplog):
    """A per-tenant push with errors must emit a [sync-error] WARNING carrying
    the sink's message — so the cause lands in the hub log + GET_ERROR_LOGS
    (ab) instead of an opaque "errors=N" INFO line."""
    with caplog.at_level(logging.WARNING, logger="Hub"):
        hub = _SyncHub(responses={
            ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
            ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"):
                {"payload": {"data": {"status": "SUCCESS", "pushed": 1, "errors": 180,
                                      "skipped": 0, "skipped_details": [],
                                      "message": "1 upserted, 180 errors — first error: mac required"}}},
        })
        status = await hub.sync_tenant_endpoints("acme")
    # batch SUCCESS with per-record errors is exactly the case that used to slip
    # past collect_error_logs (errors=180 doesn't match \berror\b).
    assert status["status"] == "success"
    assert status["errors"] == 180
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("[sync-error]" in r.getMessage() and "first error: mac required" in r.getMessage()
               and "tenant=acme" in r.getMessage() for r in warns), \
        "expected a [sync-error] WARNING with the sink's first-error message"

@pytest.mark.asyncio
async def test_empty_ipam_tenant_skips_replace_and_is_not_an_error(caplog):
    """A tenant with no IPs in NetBox: an empty replace batch is always refused
    by the CPPM mass-delete guard, so it is not sent at all and the cycle is
    recorded as a clean success — no [sync-error] every cycle (LM-HUB had
    'shared' and 'stme-cordelia' erroring every run)."""
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"):
            {"payload": {"data": {"status": "SUCCESS", "ip_addresses": []}}},
    })
    with caplog.at_level(logging.INFO):
        status = await hub.sync_tenant_endpoints("acme")
    assert status["status"] == "success"
    assert status["endpoints_total"] == 0 and status["errors"] == 0
    assert all(cmd != "CPPM_SYNC_ENDPOINTS" for _, cmd, _ in hub.request_log)
    assert "[sync-error]" not in caplog.text
    assert hub.simulations_store.recorded["acme"] is status


@pytest.mark.asyncio
async def test_only_unsyncable_records_also_skips_replace():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): {"payload": {"data": {
            "status": "SUCCESS",
            "ip_addresses": [{"address": None, "custom_fields": {}}]}}},
    })
    status = await hub.sync_tenant_endpoints("acme")
    assert status["status"] == "success" and status["hub_skipped"] == 1
    assert all(cmd != "CPPM_SYNC_ENDPOINTS" for _, cmd, _ in hub.request_log)


@pytest.mark.asyncio
async def test_scheduled_sync_never_sends_allow_mass_remove():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"): _cppm_ok_payload(),
    })
    await hub.sync_tenant_endpoints("acme")
    cppm_call = [c for c in hub.request_log if c[1] == "CPPM_SYNC_ENDPOINTS"][0]
    assert "allow_mass_remove" not in cppm_call[2]


@pytest.mark.asyncio
async def test_operator_sync_passes_allow_mass_remove_to_cppm():
    hub = _SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"): _cppm_ok_payload(),
    })
    await hub.sync_tenant_endpoints("acme", allow_mass_remove=True)
    cppm_call = [c for c in hub.request_log if c[1] == "CPPM_SYNC_ENDPOINTS"][0]
    assert cppm_call[2]["allow_mass_remove"] is True


async def _nad_hub(monkeypatch, secrets, prefixes):
    import access
    import cred_vault

    async def _list(hub, stype, buckets):
        assert stype == "radius"
        return [s for s in secrets if s["bucket"] in buckets]

    async def _prefixes(hub, tid):
        return prefixes

    monkeypatch.setattr(cred_vault, "automation_list_by_type", _list)
    monkeypatch.setattr(access, "fetch_tenant_prefixes", _prefixes)
    return _SyncHub(responses={("cppm-spoke-1", "CPPM_SYNC_NADS"): {
        "status": "SUCCESS", "created": 2, "updated": 0, "removed": 0}})


@pytest.mark.asyncio
async def test_nad_sync_sends_collapsed_subnets_and_tenant_secret(monkeypatch):
    hub = await _nad_hub(
        monkeypatch,
        [{"bucket": "acme", "value": {"radius_secret": "r1", "tacacs_secret": "t1"}}],
        ["10.1.0.0/16", "10.1.5.0/24", "192.168.1.0/24", "bogus"])
    res = await hub.sync_tenant_nads("acme")
    assert res["status"] == "SUCCESS"
    (_, cmd, payload), = hub.request_log
    assert cmd == "CPPM_SYNC_NADS"
    assert payload["subnets"] == ["10.1.0.0/16", "192.168.1.0/24"]
    assert payload["radius_secret"] == "r1" and payload["tacacs_secret"] == "t1"
    assert payload["tenant_name"] == "Acme"


@pytest.mark.asyncio
async def test_nad_sync_skips_without_secret(monkeypatch):
    hub = await _nad_hub(monkeypatch, [{"bucket": "other", "value": {"radius_secret": "x"}}],
                         ["10.1.0.0/16"])
    res = await hub.sync_tenant_nads("acme")
    assert res["status"] == "skipped"
    assert hub.request_log == []


@pytest.mark.asyncio
async def test_tenant_with_its_own_clearpass_is_never_synced_into_the_shared_one(monkeypatch):
    """A tenant with a NAC record of its own has left the shared ClearPass
    (shared access ``auto``). While its own spoke is offline, or also serves
    another tenant, its endpoints and NADs are skipped, not written to the
    shared ClearPass. A tenant still on shared NAC syncs there."""
    import access
    import cred_vault

    async def _list(hub, stype, buckets):
        return [{"bucket": "acme", "value": {"radius_secret": "r1"}}]

    async def _prefixes(hub, tid):
        return ["10.1.0.0/16"]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", _list)
    monkeypatch.setattr(access, "fetch_tenant_prefixes", _prefixes)
    hub = _SyncHub(nac_spoke=None, shared_nac_spoke="cppm-shared", responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-shared", "CPPM_SYNC_ENDPOINTS"): _cppm_ok_payload(),
        ("cppm-shared", "CPPM_SYNC_NADS"): {"status": "SUCCESS"}})
    hub.state.update_global_config({"nac_instances": [{"tenant_id": "acme", "spoke_id": "cppm-acme"}]})
    status = await hub.sync_tenant_endpoints("acme")
    nads = await hub.sync_tenant_nads("acme")
    assert status["status"] == "error" and nads["status"] == "skipped"
    assert hub.request_log == []
    # Without a record of its own, the tenant still uses the shared ClearPass.
    hub.state.update_global_config({"nac_instances": []})
    await hub.sync_tenant_endpoints("acme")
    await hub.sync_tenant_nads("acme")
    assert [(s, c) for s, c, _ in hub.request_log if c.startswith("CPPM_")] == [
        ("cppm-shared", "CPPM_SYNC_ENDPOINTS"), ("cppm-shared", "CPPM_SYNC_NADS")]


@pytest.mark.asyncio
async def test_ipam_edit_syncs_through_the_tenants_own_usable_clearpass():
    """trigger_endpoint_sync checks the tenant's own (or still shared)
    ClearPass spoke, not the hub's first NAC spoke: another tenant's
    unconfigured spoke does not block it, and an unconfigured spoke of its
    own does."""
    import asyncio
    hub = _SyncHub(nac_spoke="cppm-acme")
    hub.state.system_state["global_config"] = {hub._ENDPOINT_SYNC_CFG_KEY: {"enabled": True}}
    hub.get_spoke_by_type = lambda module_type: "cppm-other" if module_type == "nac" else None
    started = []

    async def _sync(tenant_id, allow_mass_remove=False):
        """Record the tenant whose sync started."""
        started.append(tenant_id)

    hub.sync_tenant_endpoints = _sync
    hub._nac_unconfigured_spokes = {"cppm-other"}
    hub.trigger_endpoint_sync("acme")
    await asyncio.sleep(0)
    assert started == ["acme"]
    hub._nac_unconfigured_spokes = {"cppm-acme"}
    hub.trigger_endpoint_sync("acme")
    await asyncio.sleep(0)
    assert started == ["acme"]
# ── a sync goes under the stored tenant id the target names ──────────────────

def _acme_hub(hub, **twins):
    """``hub`` with the stored tenant "ACME" (plus ``twins``), looked up as
    StateManager looks tenants up."""
    from _fakes import bind_state_tenant_lookups
    hub.state = bind_state_tenant_lookups(FakeState(
        global_config={},
        tenants={"ACME": {"name": "Acme", "netbox_tenant_slug": "acme"}, **twins}))
    return hub


_TWIN = {" ACME ": {"name": "Acme legacy", "netbox_tenant_slug": "acme-old"}}


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["acme", " ACME "])
async def test_sync_in_another_spelling_goes_under_the_stored_id(target):
    """'Sync now' for another spelling of "ACME" syncs ACME under "ACME".
    Before, "acme" was skipped as unbound, and " ACME " was pushed and
    recorded under " ACME "."""
    hub = _acme_hub(_SyncHub(responses={
        ("netbox-spoke-1", "NETBOX_GET_IPS"): _netbox_ips_payload(),
        ("cppm-spoke-1", "CPPM_SYNC_ENDPOINTS"): _cppm_ok_payload(),
    }))
    status = await hub.sync_tenant_endpoints(target)
    (_, _, ipam), (_, _, push) = hub.request_log
    assert ipam == {"tenant": "acme"}
    assert push["tenant_id"] == "ACME" and len(push["endpoints"]) == 2
    assert status["status"] == "success"
    assert list(hub.simulations_store.recorded) == ["ACME"]


@pytest.mark.asyncio
@pytest.mark.parametrize("target", [" ACME", "   "])
async def test_sync_for_an_id_naming_no_single_tenant_calls_no_spoke(target):
    """A target that names both stored twins, or is blank, calls no spoke and
    records no status. Before, " ACME" read "ACME"'s endpoints (get_tenant
    ignores surrounding spaces) and pushed them with replace=True to the
    ClearPass spoke the picker fell back to."""
    hub = _acme_hub(_SyncHub(responses={}), **_TWIN)
    status = await hub.sync_tenant_endpoints(target)
    assert status["status"] == "skipped"
    assert hub.request_log == []
    assert hub.simulations_store.recorded == {}


@pytest.mark.asyncio
async def test_nad_sync_in_another_spelling_uses_the_stored_tenant(monkeypatch):
    """Network devices for "acme" come from the stored "ACME"'s vault bucket
    and are registered under "ACME" (before, the bucket searched was "acme")."""
    hub = _acme_hub(await _nad_hub(
        monkeypatch, [{"bucket": "ACME", "value": {"radius_secret": "r1"}}], ["10.1.0.0/16"]))
    res = await hub.sync_tenant_nads("acme")
    assert res["status"] == "SUCCESS"
    (_, _, payload), = hub.request_log
    assert payload["tenant_id"] == "ACME" and payload["radius_secret"] == "r1"


@pytest.mark.asyncio
async def test_nad_sync_for_an_id_naming_both_twins_registers_nothing(monkeypatch):
    """" ACME" names both stored twins, so nothing is registered for it, even
    from a vault bucket spelt " ACME" (the prefixes stand in for "ACME"'s,
    which get_tenant's slug lookup would return for it)."""
    hub = _acme_hub(await _nad_hub(
        monkeypatch, [{"bucket": " ACME", "value": {"radius_secret": "r1"}}], ["10.1.0.0/16"]),
        **_TWIN)
    res = await hub.sync_tenant_nads(" ACME")
    assert res["status"] == "skipped"
    assert hub.request_log == []
