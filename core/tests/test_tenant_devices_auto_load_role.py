"""Integration: /tenant/devices/nac-instances (etc.) auto-loads the matching
coordinator role on bind and auto-unloads it when no instance references the
spoke anymore — end-to-end through the real routes, not just role_pool's
unit tests. Fake-hub pattern mirrors test_tenant_devices_spoke_guid.py.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.tenant_devices as tenant_devices
from routes.role_pool import PRODUCT_ROLE


def _sess(*, tenants=None, tenant_id=None, user_id="caller"):
    return {"user": {
        "user_id": user_id, "tenants": tenants or [], "tenant_id": tenant_id,
        "permissions": {"role": "tenant_admin"},
    }}


class _State:
    def __init__(self):
        self.system_state = {
            "known_modules": [], "module_names": {}, "module_metadata": {},
            "approved_modules": {}, "global_config": {},
        }

    def get_spoke_tenant(self, sid):
        return self.system_state.get("module_metadata", {}).get(sid, {}).get("tenant_id")

    def _mark_dirty(self):
        pass


class _Hub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self):
        self.state = _State()
        self.approved_modules = {}
        self.spoke_module_types = {}
        self.active_connections = {}
        self.sent = []
        self.load_role_calls = []
        self.unload_role_calls = []

    def _primary_key(self, sid):
        return sid

    def spoke_can_accept_commands(self, sid):
        return True, None

    async def send_to_spoke(self, msg):
        self.sent.append(msg)

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        if cmd == "LOAD_ROLE":
            self.load_role_calls.append((spoke_id, payload))
            role = payload["role"]
            sub_id = f"{spoke_id}-{role}"
            module_type = {r: m for r, m in PRODUCT_ROLE.values()}[role]
            self.active_connections[sub_id] = object()
            self.spoke_module_types[sub_id] = module_type
            self.state.system_state["module_metadata"][sub_id] = {"module_type": module_type}
            return {"payload": {"data": {
                "status": "SUCCESS", "sub_spoke_id": sub_id, "module_type": module_type}}}
        if cmd == "UNLOAD_ROLE":
            self.unload_role_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")


class _Ctx:
    def __init__(self, holder):
        self._session_user = lambda req: holder.current


class _Holder:
    def __init__(self):
        self.current = None


def _build():
    hub = _Hub()
    holder = _Holder()
    app = FastAPI()
    app.state.hub = hub
    tenant_devices.register(app, hub, _Ctx(holder))
    return TestClient(app), hub, holder


def _connect_base_agent(hub, sid, tenant="acme"):
    hub.active_connections[sid] = object()
    hub.spoke_module_types[sid] = "agent"
    hub.state.system_state["module_metadata"][sid] = {"tenant_id": tenant, "module_type": "agent"}


def _connect_role_subspoke(hub, sid, module_type, tenant="acme"):
    """Simulate a role sub-spoke that already went through the full connect +
    tenant-assignment flow (i.e. an existing, previously-loaded role) —
    distinct from a freshly auto-loaded one, which this PR does NOT stamp a
    tenant onto (auth is checked against the base agent's tenant instead)."""
    hub.active_connections[sid] = object()
    hub.spoke_module_types[sid] = module_type
    hub.state.system_state["module_metadata"][sid] = {"tenant_id": tenant, "module_type": module_type}


def test_add_nac_instance_bound_to_bare_agent_auto_loads_cppm():
    c, hub, holder = _build()
    _connect_base_agent(hub, "spokeA")
    holder.current = _sess(tenants=["acme"], tenant_id="acme")

    r = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA", "host": "cppm.local"}})
    assert r.status_code == 200
    body = r.json()
    assert body["pushed"] is True
    assert body["instance"]["spoke_id"] == "spokeA-cppm"
    assert hub.load_role_calls == [("spokeA", {"role": "cppm", "config": {}})]
    # UPDATE_CONFIG went to the resolved sub-spoke, not the base agent.
    assert hub.sent[-1].header.destination_id == "spokeA-cppm"


def test_add_nac_instance_bound_to_already_loaded_subspoke_skips_auto_load():
    c, hub, holder = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_role_subspoke(hub, "spokeA-cppm", "nac")
    holder.current = _sess(tenants=["acme"], tenant_id="acme")

    r = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA-cppm", "host": "cppm.local"}})
    assert r.status_code == 200
    assert r.json()["instance"]["spoke_id"] == "spokeA-cppm"
    assert hub.load_role_calls == []


def test_delete_last_nac_instance_auto_unloads_cppm():
    c, hub, holder = _build()
    _connect_base_agent(hub, "spokeA")
    holder.current = _sess(tenants=["acme"], tenant_id="acme")
    add = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA", "host": "cppm.local"}})
    rid = add.json()["instance"]["id"]

    r = c.delete(f"/tenant/devices/nac-instances/{rid}")
    assert r.status_code == 200
    assert hub.unload_role_calls == [("spokeA", {"role": "cppm"})]


def test_delete_one_of_two_nac_instances_on_same_spoke_does_not_unload():
    c, hub, holder = _build()
    _connect_base_agent(hub, "spokeA")
    holder.current = _sess(tenants=["acme"], tenant_id="acme")
    add1 = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "CPPM-1", "spoke_id": "spokeA", "host": "a.local"}})
    rid1 = add1.json()["instance"]["id"]
    # Second instance binds directly to the now-loaded sub-spoke (auto-load
    # already stamped it as connected+nac; give it a tenant like a real
    # freshly-connected sub-spoke would end up with).
    hub.state.system_state["module_metadata"]["spokeA-cppm"] = {
        "tenant_id": "acme", "module_type": "nac"}
    add2 = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "CPPM-2", "spoke_id": "spokeA-cppm", "host": "b.local"}})
    assert add2.status_code == 200

    r = c.delete(f"/tenant/devices/nac-instances/{rid1}")
    assert r.status_code == 200
    assert hub.unload_role_calls == []  # the other instance still references spokeA-cppm


def test_reassign_nac_instance_to_a_new_spoke_loads_new_and_unloads_old():
    c, hub, holder = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_base_agent(hub, "spokeB")
    holder.current = _sess(tenants=["acme"], tenant_id="acme")
    add = c.post("/tenant/devices/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA", "host": "cppm.local"}})
    rid = add.json()["instance"]["id"]
    assert hub.load_role_calls == [("spokeA", {"role": "cppm", "config": {}})]

    r = c.put(f"/tenant/devices/nac-instances/{rid}", json={"config": {"spoke_id": "spokeB"}})
    assert r.status_code == 200
    assert hub.load_role_calls[-1] == ("spokeB", {"role": "cppm", "config": {}})
    assert hub.unload_role_calls == [("spokeA", {"role": "cppm"})]
