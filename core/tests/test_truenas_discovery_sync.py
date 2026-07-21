"""TrueNAS → NetBox inventory-discovery sync — ``TruenasDiscoverySyncMixin``.

Mirrors test_nw_cache.py's minimal-stand-in style. Verifies the one cycle:
pull the appliance fleet + a light pool summary from every connected storage
spoke, map each appliance to a NETBOX_SYNC_DEVICES record (tenant-tagged by the
appliance's own tenant_id, no prefix attribution), group by tenant, drop
unattributed appliances, and push per-tenant to the netbox (IPAM) spoke with
``source="TrueNAS"`` + ``replace=True``. Best-effort: a spoke/appliance that
fails is skipped (errors list), never raised.
"""

import asyncio

from truenas_discovery_sync import TruenasDiscoverySyncMixin


def _env(appliance):
    """Canned ``TRUENAS_LIST_APPLIANCES`` response for one spoke."""
    return {"status": "SUCCESS", "data": appliance}


def _pools(pools):
    return {"status": "SUCCESS", "data": pools}


class _Store:
    def __init__(self):
        self.saved = {}

    async def set_truenas_discovery_sync_status(self, tenant_id, status):
        self.saved[tenant_id] = status

    def get_all_truenas_discovery_sync_status(self):
        return {tid: dict(s) for tid, s in self.saved.items()}


class _Tenant:
    def __init__(self, tid, name, slug):
        self.tid, self.name, self.slug = tid, name, slug


class _State:
    def __init__(self, gc):
        self.system_state = {"global_config": gc}
        self._tenants = {}

    def get_tenant(self, tid):
        return self._tenants.get(tid)


class _Hub(TruenasDiscoverySyncMixin):
    """Minimal stand-in: records request_response round-trips and serves canned
    appliance + pool payloads. Only the methods the mixin touches are wired."""

    def __init__(self, gc, appliances_by_spoke, pools_by_appliance,
                 netbox_spoke="netbox-1", storage_spokes=("truenas-1",)):
        self.state = _State(gc)
        self.simulations_store = _Store()
        self._appliances_by_spoke = appliances_by_spoke
        self._pools_by_appliance = pools_by_appliance
        self._netbox = netbox_spoke
        self._storage_spokes = list(storage_spokes)
        self.pushed = []  # (spoke_id, command, payload)

    # registry helpers
    def get_all_spokes_by_type(self, t):
        return self._storage_spokes if t == "storage" else ([self._netbox] if t == "ipam" else [])

    def get_spoke_by_type(self, t):
        if t == "ipam" and self._netbox:
            return self._netbox
        return None

    async def request_response(self, sid, cmd, body, timeout=30.0):
        if cmd == "TRUENAS_LIST_APPLIANCES":
            return _env(self._appliances_by_spoke.get(sid, []))
        if cmd == "TRUENAS_GET_POOLS":
            aid = (body or {}).get("appliance_id")
            return _pools(self._pools_by_appliance.get(aid, []))
        if cmd == "NETBOX_SYNC_DEVICES":
            self.pushed.append((sid, cmd, body))
            return {"status": "SUCCESS", "pushed": len(body.get("devices", [])),
                    "errors": 0, "skipped": 0, "deleted": 0}
        return {"status": "ERROR", "message": f"unhandled {cmd}"}


async def _restore_loop():
    """Py3.9 asyncio.run poisoning: each test's autouse fixture leaves a
    current open loop; close it so the next asyncio.run is clean."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            return
        loop.close()
    except Exception:
        pass


async def test_pull_maps_appliances_to_device_records_and_groups_by_tenant():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={
            "truenas-1": [
                {"id": "nas1", "name": "nas-01", "host": "10.0.0.50",
                 "tenant_id": "acme"},
                {"id": "nas2", "name": "nas-02", "host": "10.0.0.51",
                 "tenant_id": "globex"},
                {"id": "nas3", "name": "no-tenant", "host": "10.0.0.52",
                 "tenant_id": ""},  # dropped — NetBox stays tenant-authoritative
            ],
        },
        pools_by_appliance={
            "nas1": [{"name": "tank", "status": "ONLINE"}],
            "nas2": [{"name": "tank", "status": "DEGRADED"}],
            "nas3": [],
        },
    )
    hub.state._tenants = {
        "acme": {"name": "Acme", "netbox_tenant_slug": "acme"},
        "globex": {"name": "Globex", "netbox_tenant_slug": "globex"},
    }
    agg = await hub.run_truenas_discovery_sync_all()
    assert set(agg["tenants"]) == {"acme", "globex"}
    assert agg["discovered_total"] == 3
    assert agg["pushed_tenants"] == 2
    assert agg["pull_errors"] == []
    # Two tenant pushes (acme + globex), each to the netbox spoke.
    assert len(hub.pushed) == 2
    cmds = {(sid, cmd) for sid, cmd, _ in hub.pushed}
    assert ("netbox-1", "NETBOX_SYNC_DEVICES") in cmds
    for _sid, _cmd, payload in hub.pushed:
        assert payload["source"] == "TrueNAS"
        assert payload["replace"] is True
        assert payload["tenant_slug"] in ("acme", "globex")
        for dev in payload["devices"]:
            assert dev["role"] == "storage"
            assert dev["manufacturer"] == "TrueNAS"
            assert dev["custom_fields"]["discovered_from"] == "TrueNAS"


async def test_device_record_carries_product_version_health_pool_count():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50",
             "tenant_id": "acme", "info": {"product_name": "TrueNAS SCALE",
                                            "version": "25.04"}}]},
        pools_by_appliance={"nas1": [
            {"name": "tank", "status": "ONLINE"},
            {"name": "ssd", "status": "ONLINE"}]},
    )
    hub.state._tenants = {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}}
    await hub.run_truenas_discovery_sync_all()
    _sid, _cmd, payload = hub.pushed[0]
    dev = payload["devices"][0]
    assert dev["hostname"] == "nas-01"
    assert dev["ip"] == "10.0.0.50"
    assert dev["custom_fields"]["product"] == "TrueNAS SCALE"
    assert dev["custom_fields"]["version"] == "25.04"
    assert dev["custom_fields"]["healthy"] == "true"
    assert dev["custom_fields"]["pool_count"] == "2"


async def test_degraded_pool_marks_appliance_unhealthy():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50",
             "tenant_id": "acme"}]},
        pools_by_appliance={"nas1": [{"name": "tank", "status": "DEGRADED"}]},
    )
    hub.state._tenants = {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}}
    await hub.run_truenas_discovery_sync_all()
    dev = hub.pushed[0][2]["devices"][0]
    assert dev["custom_fields"]["healthy"] == "false"


async def test_tenant_without_netbox_slug_is_skipped_not_pushed():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50",
             "tenant_id": "acme"}]},
        pools_by_appliance={"nas1": []},
    )
    # tenant exists but has NO netbox_tenant_slug → skipped
    hub.state._tenants = {"acme": {"name": "Acme", "netbox_tenant_slug": ""}}
    agg = await hub.run_truenas_discovery_sync_all()
    assert hub.pushed == []  # no NETBOX_SYNC_DEVICES sent
    assert agg["per_tenant"]["acme"]["status"] == "skipped"
    assert "netbox_tenant_slug" in agg["per_tenant"]["acme"]["message"]


async def test_netbox_down_records_error_status_no_push():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50",
             "tenant_id": "acme"}]},
        pools_by_appliance={"nas1": []},
        netbox_spoke=None,  # no IPAM sink connected
    )
    hub.state._tenants = {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}}
    agg = await hub.run_truenas_discovery_sync_all()
    assert hub.pushed == []
    assert agg["per_tenant"]["acme"]["status"] == "error"
    assert "not connected" in agg["per_tenant"]["acme"]["message"]


async def test_sync_one_tenant_only_pushes_that_tenant():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50", "tenant_id": "acme"},
            {"id": "nas2", "name": "nas-02", "host": "10.0.0.51", "tenant_id": "globex"},
        ]},
        pools_by_appliance={"nas1": [], "nas2": []},
    )
    hub.state._tenants = {
        "acme": {"name": "Acme", "netbox_tenant_slug": "acme"},
        "globex": {"name": "Globex", "netbox_tenant_slug": "globex"},
    }
    res = await hub.sync_tenant_truenas_devices("acme")
    assert res["status"] == "success"
    assert len(hub.pushed) == 1
    assert hub.pushed[0][2]["tenant_slug"] == "acme"
    assert len(hub.pushed[0][2]["devices"]) == 1


async def test_status_persisted_to_store():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={"truenas-1": [
            {"id": "nas1", "name": "nas-01", "host": "10.0.0.50", "tenant_id": "acme"}]},
        pools_by_appliance={"nas1": []},
    )
    hub.state._tenants = {"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}}
    await hub.run_truenas_discovery_sync_all()
    saved = hub.simulations_store.get_all_truenas_discovery_sync_status()
    assert "acme" in saved
    assert saved["acme"]["status"] == "success"
    assert saved["acme"]["pushed"] == 1


async def test_guard_disabled_when_no_storage_spokes():
    hub = _Hub(
        gc={"truenas_discovery_sync": {"enabled": True}},
        appliances_by_spoke={}, pools_by_appliance={},
        storage_spokes=(), netbox_spoke="netbox-1",
    )
    # The loop guard checks storage spokes exist; the pull itself short-circuits.
    records, errors = await hub._truenas_pull_appliances()
    assert records == []
    assert errors == []