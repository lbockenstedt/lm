"""The admin device lists Managed Devices groups by tenant (/setup/firewalls,
/setup/nw-devices, /setup/truenas-appliances) carry the hub's tenant_key on
each row, and never store it."""
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import nw, setup, truenas


@pytest.mark.parametrize("module, path, store", [
    (setup, "/setup/firewalls", "firewalls"),
    (nw, "/setup/nw-devices", "nw_devices"),
    (truenas, "/setup/truenas-appliances", "truenas_appliances"),
])
def test_admin_device_lists_carry_the_hub_tenant_key(module, path, store):
    # The hub's key folds as access._norm_tenant_id does (" Straße " is
    # "strasse"), which JS toLowerCase() cannot; no tenant is "".
    rows = [{"id": "d1", "tenant_id": " Straße "}, {"id": "d2"}]
    hub = SimpleNamespace(state=SimpleNamespace(
        system_state={"global_config": {store: [dict(r) for r in rows]}},
        get_spoke_tenant=lambda sid: None, _mark_dirty=lambda: None))
    app = FastAPI()
    app.state.hub = hub
    module.register(app, hub, SimpleNamespace(
        _session_user=lambda r: {"user": {"permissions": {"admin": True}}},
        _is_admin=lambda s: True, _is_tenant_admin=lambda s: False,
        _filter_nw=lambda *a, **k: []))
    listed = TestClient(app).get(path).json()[store]
    assert [(r["id"], r["tenant_key"]) for r in listed] == [("d1", "strasse"), ("d2", "")]
    assert all("tenant_key" not in r for r in hub.state.system_state["global_config"][store])
