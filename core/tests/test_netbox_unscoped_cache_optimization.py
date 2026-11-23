"""Tests for Issue #2054: NetBox unscoped device cache pull optimization.

Verifies:
1. nb_cache_feed yields netbox_devices with NB_DEVICES_REFRESH_S (900s).
2. nb_cache_feed does not yield redundant unscoped jobs for slug-less tenants.
3. run_nw_netbox_import_all prefers warm cache over live WebSocket request.
"""
import asyncio
import pytest

from _fakes import FakeState
from routes.netbox import (
    NB_DEVICES_REFRESH_S,
    NB_LIST_REFRESH_S,
    nb_cache_feed,
    nb_cache_job,
)
from access import ADMIN_TENANT_ID, netbox_tenant_scope


class _FakeHub:
    def __init__(self, tenants=None, cached_devices=None):
        self.state = FakeState(tenants=tenants or {})
        self._cached = {}
        if cached_devices is not None:
            self._cached[("nb_devices", "_all_")] = cached_devices
        self.spoke_calls = []

    def get_spoke_by_type(self, module_type):
        return "netbox-spoke-1" if module_type == "ipam" else None

    def get_all_spokes_by_type(self, module_type):
        return ["nw-spoke-1"] if module_type == "nw" else []

    def warm_get(self, namespace, key="_"):
        return self._cached.get((namespace, key))

    async def request_response(self, spoke_id, command, payload, timeout=60.0):
        self.spoke_calls.append((spoke_id, command, payload))
        return {
            "payload": {
                "data": {
                    "status": "SUCCESS",
                    "devices": [
                        {"name": "sw-live-1", "role": "access", "ip": "10.0.0.1"}
                    ]
                }
            }
        }


def test_nb_cache_feed_skips_redundant_slugless_tenants():
    """Ensure nb_cache_feed only yields unscoped list for admin view,
    preventing duplicate ~9500-device queries for slug-less tenants."""
    tenants = {
        "tenant-with-slug": {
            "name": "Tenant With Slug",
            "netbox_tenant_slug": "cust-slug",
        },
        "tenant-no-slug-1": {
            "name": "Tenant No Slug 1",
        },
        "tenant-no-slug-2": {
            "name": "Tenant No Slug 2",
        },
    }
    hub = _FakeHub(tenants=tenants)
    jobs = list(nb_cache_feed(hub))
    keys_by_ns = {}
    for j in jobs:
        keys_by_ns.setdefault(j.ns, []).append(j.key)

    # Tenant with slug has its own scoped entry
    assert "cust-slug" in keys_by_ns["nb_devices"]
    # Default admin tenant is present
    assert "default" in keys_by_ns["nb_devices"]
    # Slug-less tenants are NOT duplicated into independent unscoped pulls
    assert "_all_:tenant-no-slug-1" not in keys_by_ns["nb_devices"]
    assert "_all_:tenant-no-slug-2" not in keys_by_ns["nb_devices"]
    assert "tenant-no-slug-1" not in keys_by_ns["nb_devices"]
    assert "tenant-no-slug-2" not in keys_by_ns["nb_devices"]

    # Verify device refresh cadence is 900s
    device_jobs = [j for j in jobs if j.ns == "nb_devices"]
    for dj in device_jobs:
        assert dj.refresh_s == NB_DEVICES_REFRESH_S
        assert dj.refresh_s == 900.0


def test_run_nw_netbox_import_prefers_warm_cache():
    """Verify run_nw_netbox_import_all reuses cached nb_devices without WebSocket call."""
    cached_payload = {
        "devices": [
            {"name": "sw-cached-1", "role": "gateway", "address": "10.1.1.1"}
        ]
    }

    from nw_discovery_sync import NwDiscoverySyncMixin
    class _TestHub(NwDiscoverySyncMixin, _FakeHub):
        def _nw_import_cfg(self):
            return {
                "enabled": True,
                "roles": ["gateway"],
                "spoke_id": "nw-spoke-1",
                "interval": 60,
                "object_type_map": {},
                "default_object_type": "gateway",
            }
        def _nw_role_norm(self, role):
            return str(role).lower()
        def _nw_fleet(self):
            return {}
        def _save_nw_fleet(self, fleet):
            pass
        async def _push_nw_fleet_to_spokes(self):
            pass

    test_hub = _TestHub(cached_devices=cached_payload)
    res = asyncio.run(test_hub.run_nw_netbox_import_all())

    assert res.get("status") == "SUCCESS"
    assert res.get("added") == 1
    # Spoke request_response was NOT called because cache was warm
    assert len(test_hub.spoke_calls) == 0


def test_run_nw_netbox_import_falls_back_when_cache_empty():
    """Verify run_nw_netbox_import_all falls back to live query when cache is empty."""
    from nw_discovery_sync import NwDiscoverySyncMixin
    class _TestHub(NwDiscoverySyncMixin, _FakeHub):
        def _nw_import_cfg(self):
            return {
                "enabled": True,
                "roles": ["access"],
                "spoke_id": "nw-spoke-1",
                "interval": 60,
                "object_type_map": {},
                "default_object_type": "gateway",
            }
        def _nw_role_norm(self, role):
            return str(role).lower()
        def _nw_fleet(self):
            return {}
        def _save_nw_fleet(self, fleet):
            pass
        async def _push_nw_fleet_to_spokes(self):
            pass

    test_hub = _TestHub(cached_devices=None)
    res = asyncio.run(test_hub.run_nw_netbox_import_all())

    assert res.get("status") == "SUCCESS"
    assert res.get("added") == 1
    # Live request was called as fallback
    assert len(test_hub.spoke_calls) == 1
    assert test_hub.spoke_calls[0][1] == "NETBOX_GET_DEVICES"
