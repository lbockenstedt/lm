"""``/sim/api/{tenant}/toggle-auto-provision`` must push to EVERY bound cs spoke,
not just the first.

Regression: ``_push_config`` hardcoded ``_PushResult(1)`` and ``get_client_sim_spoke``
returned only ``bound[0]``. A tenant with 3 bound cs spokes (cs-svr-02/03/04) toggled
auto-provisioning and the toast read "Pushed to 1 spoke(s)" while 3 were connected.

The fix: ``_push_config`` now fans out to all spokes from the plural
``hub.get_client_sim_spokes`` via ``asyncio.gather`` and returns
``_PushResult(<count>)``. This pins the end-to-end count: 3 bound spokes →
``pushed_to_spokes == 3`` and the push is invoked once per spoke.
"""

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes


class _Store:
    """In-memory simulations_store: get/set_hub_config round-trip."""

    def __init__(self):
        self._cfg = {}

    async def get_hub_config(self, tenant_id):
        return self._cfg.get(tenant_id, {"hub_config": {}, "hub_config_enabled": False})

    async def set_hub_config(self, tenant_id, enabled, cfg):
        self._cfg[tenant_id] = {"hub_config": cfg, "hub_config_enabled": enabled}


class MultiSpokeHub:
    """Hub with 3 bound cs spokes + a recording push_or_queue_to_spoke."""

    def __init__(self, spoke_ids):
        self._spokes = list(spoke_ids)
        self.simulations_store = _Store()
        self.active_connections = set(spoke_ids)
        self.pushed = []  # (sid, cmd, payload) per push
        self.state = type("State", (), {"system_state": {}})()

    def get_client_sim_spokes(self, tenant_id):
        return list(self._spokes)

    def get_client_sim_spoke(self, tenant_id):
        return self._spokes[0] if self._spokes else None

    async def push_or_queue_to_spoke(self, sid, cmd_type, payload, timeout=5.0):
        self.pushed.append((sid, cmd_type, payload))
        return {"queued": False, "message": ""}


def _build(spoke_ids):
    app = FastAPI()
    hub = MultiSpokeHub(spoke_ids)
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return TestClient(app), hub


def test_toggle_auto_provision_pushes_to_all_bound_spokes():
    """3 bound cs spokes → pushed_to_spokes == 3, push invoked once per spoke."""
    c, hub = _build(["cs-svr-02", "cs-svr-03", "cs-svr-04"])
    r = c.post("/sim/api/10/toggle-auto-provision?tenant_id=10",
               json={"enabled": True})
    assert r.status_code == 200
    body = r.json()
    assert body["pushed_to_spokes"] == 3
    assert body["usb_auto_provision"] == "on"
    # One CS_CONFIG_UPDATE per spoke, all carrying usb_auto_provision=on.
    assert len(hub.pushed) == 3
    sids = sorted(sid for sid, _cmd, _pl in hub.pushed)
    assert sids == ["cs-svr-02", "cs-svr-03", "cs-svr-04"]
    for _sid, cmd, pl in hub.pushed:
        assert cmd == "CS_CONFIG_UPDATE"
        assert pl == {"usb_auto_provision": "on"}


def test_toggle_auto_provision_off_still_counts_all_spokes():
    """Disabling must also fan out to every spoke (not short-circuit to 1)."""
    c, hub = _build(["cs-svr-02", "cs-svr-03", "cs-svr-04"])
    r = c.post("/sim/api/10/toggle-auto-provision?tenant_id=10",
               json={"enabled": False})
    assert r.status_code == 200
    assert r.json()["pushed_to_spokes"] == 3
    assert len(hub.pushed) == 3


def test_toggle_auto_provision_single_spoke_still_one():
    """1-spoke tenant is unchanged — count 1 (no regression for the common case)."""
    c, hub = _build(["cs-spoke-1"])
    r = c.post("/sim/api/10/toggle-auto-provision?tenant_id=10",
               json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["pushed_to_spokes"] == 1
    assert len(hub.pushed) == 1


def test_toggle_auto_provision_no_spokes_pushes_zero():
    """No bound/connected spokes → count 0 (graceful, not a 500)."""
    c, hub = _build([])
    r = c.post("/sim/api/10/toggle-auto-provision?tenant_id=10",
               json={"enabled": True})
    assert r.status_code == 200
    assert r.json()["pushed_to_spokes"] == 0
    assert hub.pushed == []