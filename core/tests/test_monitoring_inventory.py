import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import cred_vault  # noqa: E402
import instance_vault  # noqa: E402
from routes import monitoring  # noqa: E402


def test_inventory_devices_resolves_vault_and_shapes_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        if storage_key == "nw_scan_credentials":
            return records
        return [dict(r, snmp_community="s3cret") for r in records]

    async def no_snmp(hub, sec_type, buckets=None):
        return []

    monkeypatch.setattr(cred_vault, "automation_list_by_type", no_snmp)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {"nw_devices": [
        {"name": "sw1", "address": "10.0.0.1/24", "tenant": "t1", "type": "switch"},
        {"name": "no-address"},
    ]}}))
    devices = asyncio.run(monitoring.inventory_devices(hub))
    assert devices == [{"tenant": "t1", "name": "sw1", "type": "switch", "ip": "10.0.0.1",
                        "snmp": True, "snmp_community": "s3cret"}]


def test_scanned_device_inherits_tenant_scan_snmp_community(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def no_snmp(hub, sec_type, buckets=None):
        return []

    monkeypatch.setattr(cred_vault, "automation_list_by_type", no_snmp)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "sw1", "address": "10.0.0.1", "tenant_id": "t1",
                        "object_type": "cx_switch", "transport": "ssh"}],
        "nw_scan_credentials": [{"tenant_id": "t1", "snmp_community": "pub"}]}}))
    (d,) = asyncio.run(monitoring.inventory_devices(hub))
    assert d["type"] == "cx_switch" and d["snmp"] and d["snmp_community"] == "pub"


def test_vault_snmp_secret_applies_to_tenant_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        return records

    async def snmp_secrets(hub, sec_type, buckets=None):
        assert sec_type == "snmp"
        return [{"bucket": "t1", "name": "SNMP", "value": {"snmp_community": "vaulted"}}]

    monkeypatch.setattr(cred_vault, "automation_list_by_type", snmp_secrets)
    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {
        "nw_devices": [{"name": "a", "address": "10.0.0.1", "tenant_id": "t1"},
                       {"name": "b", "address": "10.0.0.2", "tenant_id": "t2"}]}}))
    a, b = asyncio.run(monitoring.inventory_devices(hub))
    assert a["snmp_community"] == "vaulted" and a["snmp"]
    assert not b["snmp"]
