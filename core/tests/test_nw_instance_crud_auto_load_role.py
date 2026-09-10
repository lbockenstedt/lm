"""Integration: /setup/nac-instances (admin-scoped _instance_crud in nw.py)
auto-loads/auto-unloads the matching coordinator role, mirroring
test_tenant_devices_auto_load_role.py's tenant-scoped twin — the two files
must share this behavior per nw.py's own "MIRROR tenant_devices.py" comment.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.nw as nw


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def get_spoke_tenant(self, sid):
        return self.system_state.get("_tenant_meta", {}).get(sid)

    def _mark_dirty(self):
        pass


class _Hub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    def __init__(self):
        self.state = _State()
        self.state.system_state["_tenant_meta"] = {}
        self.spoke_module_types = {}
        self.active_connections = {}
        self.sent = []
        self.load_role_calls = []
        self.unload_role_calls = []
        self.dns_cluster_calls = []

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
            module_type = {"cppm": "nac", "netbox": "ipam", "ldap": "directory"}[role]
            self.active_connections[sub_id] = object()
            self.spoke_module_types[sub_id] = module_type
            return {"payload": {"data": {
                "status": "SUCCESS", "sub_spoke_id": sub_id, "module_type": module_type}}}
        if cmd == "UNLOAD_ROLE":
            self.unload_role_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        if cmd == "DNS_CLUSTER_CONFIG":
            self.dns_cluster_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd}")


def _admin_sess():
    return {"user": {"user_id": "admin", "tenants": [], "permissions": {"admin": True}}}


def _build():
    hub = _Hub()
    app = FastAPI()
    app.state.hub = hub
    ctx = SimpleNamespace(
        _session_user=lambda req: _admin_sess(),
        _is_admin=lambda sess: True,
        _is_tenant_admin=lambda sess: False,
        _filter_nw=lambda *a, **k: [],
    )
    nw.register(app, hub, ctx)
    return TestClient(app), hub


def _connect_base_agent(hub, sid):
    hub.active_connections[sid] = object()
    hub.spoke_module_types[sid] = "agent"


def test_admin_add_nac_instance_bound_to_bare_agent_auto_loads_cppm():
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")

    r = c.post("/setup/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA", "host": "cppm.local"}})
    assert r.status_code == 200
    body = r.json()
    assert body["pushed"] is True
    assert hub.load_role_calls == [("spokeA", {"role": "cppm", "config": {}})]
    assert hub.sent[-1].header.destination_id == "spokeA-cppm"


def test_admin_delete_last_nac_instance_auto_unloads_cppm():
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    add = c.post("/setup/nac-instances", json={
        "instance": {"name": "ClearPass", "spoke_id": "spokeA", "host": "cppm.local"}})
    instances = c.get("/setup/nac-instances").json()["instances"]
    rid = instances[0]["id"]

    r = c.delete(f"/setup/nac-instances/{rid}")
    assert r.status_code == 200
    assert hub.unload_role_calls == [("spokeA", {"role": "cppm"})]


def test_admin_reassign_ipam_instance_loads_new_and_unloads_old():
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_base_agent(hub, "spokeB")
    add = c.post("/setup/ipam-instances", json={
        "instance": {"name": "NetBox", "spoke_id": "spokeA", "url": "https://nb.local"}})
    instances = c.get("/setup/ipam-instances").json()["instances"]
    rid = instances[0]["id"]
    assert hub.load_role_calls == [("spokeA", {"role": "netbox", "config": {}})]

    r = c.put(f"/setup/ipam-instances/{rid}", json={"config": {"spoke_id": "spokeB"}})
    assert r.status_code == 200
    assert hub.load_role_calls[-1] == ("spokeB", {"role": "netbox", "config": {}})
    assert hub.unload_role_calls == [("spokeA", {"role": "netbox"})]


def test_admin_dns_instances_push_the_complete_worker_topology():
    c, hub = _build()
    hub.active_connections["dns-management"] = object()
    hub.spoke_module_types["dns-management"] = "dns"

    first = c.post("/setup/dns-instances", json={"instance": {
        "name": "Primary DNS",
        "member_id": "dns-a",
        "host": "10.0.0.11",
        "spoke_id": "dns-management",
        "worker_secret": "write-only-secret",
    }})
    assert first.status_code == 200
    assert hub.dns_cluster_calls[-1] == ("dns-management", {
        "members": [{"id": "dns-a", "host": "10.0.0.11"}],
        "worker_secret": "write-only-secret",
    })

    second = c.post("/setup/dns-instances", json={"instance": {
        "name": "Secondary DNS",
        "member_id": "dns-b",
        "host": "10.0.0.12",
        "spoke_id": "dns-management",
    }})
    assert second.status_code == 200
    assert hub.dns_cluster_calls[-1] == ("dns-management", {
        "members": [
            {"id": "dns-a", "host": "10.0.0.11"},
            {"id": "dns-b", "host": "10.0.0.12"},
        ],
    })
    stored = hub.state.system_state["global_config"]["dns_instances"]
    assert all("worker_secret" not in item for item in stored)


def test_admin_delete_dns_instance_pushes_reduced_topology():
    c, hub = _build()
    hub.active_connections["dns-management"] = object()
    hub.spoke_module_types["dns-management"] = "dns"
    for member_id in ("dns-a", "dns-b"):
        c.post("/setup/dns-instances", json={"instance": {
            "name": member_id,
            "member_id": member_id,
            "host": f"{member_id}.example",
            "spoke_id": "dns-management",
            "worker_secret": "secret",
        }})
    rid = c.get("/setup/dns-instances").json()["instances"][0]["id"]

    deleted = c.delete(f"/setup/dns-instances/{rid}")
    assert deleted.status_code == 200
    assert hub.dns_cluster_calls[-1][1]["members"] == [
        {"id": "dns-b", "host": "dns-b.example"},
    ]
