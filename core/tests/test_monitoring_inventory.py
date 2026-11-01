import asyncio
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import instance_vault  # noqa: E402
from routes import monitoring  # noqa: E402


def test_inventory_devices_resolves_vault_and_shapes_devices(monkeypatch):
    async def fake_overlay_many(hub, records, storage_key):
        assert storage_key == "nw_devices"
        return [dict(r, snmp_community="s3cret") for r in records]

    monkeypatch.setattr(instance_vault, "overlay_many", fake_overlay_many)
    hub = SimpleNamespace(state=SimpleNamespace(system_state={"global_config": {"nw_devices": [
        {"name": "sw1", "address": "10.0.0.1/24", "tenant": "t1", "type": "switch"},
        {"name": "no-address"},
    ]}}))
    devices = asyncio.run(monitoring.inventory_devices(hub))
    assert devices == [{"tenant": "t1", "name": "sw1", "type": "switch", "ip": "10.0.0.1",
                        "snmp": True, "snmp_community": "s3cret"}]
