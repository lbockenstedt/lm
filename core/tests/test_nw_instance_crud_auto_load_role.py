"""Integration: /setup/nac-instances (admin-scoped _instance_crud in nw.py)
auto-loads/auto-unloads the matching coordinator role, mirroring
test_tenant_devices_auto_load_role.py's tenant-scoped twin — the two files
must share this behavior per nw.py's own "MIRROR tenant_devices.py" comment.
"""
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.nw as nw
from hub_spoke_registry import SpokeRegistryMixin
from main import LabManagerHub
from messaging.protocol import Message, MessageHeader, MessagePayload


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def get_global_config(self):
        """The saved global config the routes write to."""
        return self.system_state.setdefault("global_config", {})

    def get_spoke_tenant(self, sid):
        return self.system_state.get("_tenant_meta", {}).get(sid)

    def _mark_dirty(self):
        pass


class _Hub:
    _CMD_UNAUTHENTICATED = "unauthenticated"

    # The production NAC push, so ``pushed`` reflects what reconcile really sends.
    get_all_spokes_by_type = SpokeRegistryMixin.get_all_spokes_by_type
    push_nac_config = LabManagerHub.push_nac_config
    reconcile_nac_spokes = LabManagerHub.reconcile_nac_spokes

    def __init__(self):
        self.state = _State()
        self.state.system_state["_tenant_meta"] = {}
        self.spoke_module_types = {}
        self.active_connections = {}
        self.approved_modules = {}
        self._nac_unconfigured_spokes = set()
        # One NAC push per spoke at a time (push_nac_config).
        self._nac_push_locks = {}
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
            # A role sub-spoke is approved through its parent agent's vouch.
            self.approved_modules[sub_id] = True
            return {"payload": {"data": {
                "status": "SUCCESS", "sub_spoke_id": sub_id, "module_type": module_type}}}
        if cmd == "UNLOAD_ROLE":
            self.unload_role_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        if cmd == "DNS_CLUSTER_CONFIG":
            self.dns_cluster_calls.append((spoke_id, payload))
            return {"payload": {"data": {"status": "SUCCESS"}}}
        if cmd == "UPDATE_CONFIG":
            # The NAC push: recorded like send_to_spoke; CPPMSpoke answers SUCCESS.
            self.sent.append(Message(header=MessageHeader(sender_id="hub", destination_id=spoke_id),
                                     payload=MessagePayload(type=cmd, data=payload)))
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


# ── NAC: every save re-sends every NAC spoke its config ─────────────────────

def _last_config(hub, sid):
    """The last UPDATE_CONFIG payload sent to ``sid``, or None."""
    sent = [m.payload.data for m in hub.sent
            if m.header.destination_id == sid and m.payload.type == "UPDATE_CONFIG"]
    return sent[-1] if sent else None


def _add_nac(c, **record):
    """Add a NAC instance through Setup → NAC and return the reply body."""
    r = c.post("/setup/nac-instances", json={"instance": {"name": "ClearPass", **record}})
    assert r.status_code == 200
    return r.json()


def test_moving_a_nac_record_resends_the_old_spoke_the_hub_clearpass():
    """With a spoke-less (hub) ClearPass configured, moving record A from
    spokeA to spokeB re-sends spokeA the hub's ClearPass, so spokeA no
    longer holds A's and is not stale; spokeB gets A."""
    import hub_spoke_registry
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_base_agent(hub, "spokeB")
    _add_nac(c, host="cp-hub")
    rid = _add_nac(c, spoke_id="spokeA", host="cp-a")["instance"]["id"]
    assert _last_config(hub, "spokeA-cppm")["host"] == "cp-a"

    r = c.put(f"/setup/nac-instances/{rid}", json={"config": {"spoke_id": "spokeB"}})
    assert r.status_code == 200
    assert r.json()["pushed"] is True
    assert _last_config(hub, "spokeA-cppm")["host"] == "cp-hub"
    assert _last_config(hub, "spokeB-cppm")["host"] == "cp-a"
    assert hub_spoke_registry.nac_spoke_stale(hub, "spokeA-cppm") is False
    assert SpokeRegistryMixin.get_nac_live_spokes(hub) == ["spokeA-cppm", "spokeB-cppm"]


def test_moving_a_nac_record_leaves_the_old_spoke_stale_when_nothing_replaces_it():
    """With no other record for spokeA, the hub has nothing to send it, so
    spokeA keeps answering from A's ClearPass. It is stale, marked
    unconfigured, and gets no NAC reads or writes; spokeB serves A."""
    import hub_spoke_registry
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_base_agent(hub, "spokeB")
    rid = _add_nac(c, spoke_id="spokeA", host="cp-a")["instance"]["id"]

    r = c.put(f"/setup/nac-instances/{rid}", json={"config": {"spoke_id": "spokeB"}})
    assert r.json()["pushed"] is True
    assert hub_spoke_registry.nac_spoke_stale(hub, "spokeA-cppm") is True
    assert "spokeA-cppm" in hub._nac_unconfigured_spokes
    assert SpokeRegistryMixin.get_nac_live_spokes(hub) == ["spokeB-cppm"]


def test_deleting_a_nac_record_reports_whether_its_spoke_got_a_new_config():
    """Deleting the only record leaves its spoke holding it (stale, not
    pushed). With a hub ClearPass configured, the spoke is re-sent that
    instead, so the delete reports pushed and the spoke is not stale."""
    import hub_spoke_registry
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    rid = _add_nac(c, spoke_id="spokeA", host="cp-a")["instance"]["id"]
    r = c.delete(f"/setup/nac-instances/{rid}")
    assert r.json()["pushed"] is False
    assert hub.state.system_state["nac_config_pushed"] == {"spokeA-cppm": f"{rid}@cp-a"}
    assert hub_spoke_registry.nac_spoke_stale(hub, "spokeA-cppm") is True

    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    _add_nac(c, host="cp-hub")
    rid = _add_nac(c, spoke_id="spokeA", host="cp-a")["instance"]["id"]
    r = c.delete(f"/setup/nac-instances/{rid}")
    assert r.json()["pushed"] is True
    assert _last_config(hub, "spokeA-cppm")["host"] == "cp-hub"
    assert hub_spoke_registry.nac_spoke_stale(hub, "spokeA-cppm") is False


def test_deleting_a_spoke_less_nac_record_resends_the_spokes_that_held_it():
    """A spoke-less record configures every NAC spoke with no record of its
    own. Deleting it re-sends those spokes the next spoke-less record and
    drops the cached NAC lists, so they are not left stale on the deleted
    record's ClearPass. It has no spoke of its own, so pushed is false."""
    import hub_spoke_registry
    c, hub = _build()
    for sid in ("cppm-a", "cppm-b"):
        hub.active_connections[sid] = object()
        hub.spoke_module_types[sid] = "nac"
        hub.approved_modules[sid] = True
    first = _add_nac(c, host="cp-1")["instance"]["id"]
    second = _add_nac(c, host="cp-2")["instance"]["id"]
    assert _last_config(hub, "cppm-a")["host"] == "cp-1"
    dropped = []
    hub.warm_drop = lambda ns, prefixes: dropped.append(ns) or 0

    r = c.delete(f"/setup/nac-instances/{first}")
    assert r.status_code == 200
    assert r.json()["pushed"] is False
    assert _last_config(hub, "cppm-a")["host"] == "cp-2"
    assert _last_config(hub, "cppm-b")["host"] == "cp-2"
    assert hub.state.system_state["nac_config_pushed"] == {
        "cppm-a": f"{second}@cp-2", "cppm-b": f"{second}@cp-2"}
    assert hub_spoke_registry.nac_spoke_stale(hub, "cppm-a") is False
    assert SpokeRegistryMixin.get_nac_live_spokes(hub) == ["cppm-a", "cppm-b"]
    assert dropped


def test_nac_pushed_means_the_records_own_config_was_sent():
    """A spoke is sent only its first record, so a second record bound to
    the same spoke is saved but not pushed. A record whose id is not a
    string is still recognised when it is sent."""
    c, hub = _build()
    _connect_base_agent(hub, "spokeA")
    _connect_base_agent(hub, "spokeC")
    assert _add_nac(c, spoke_id="spokeA", host="cp-a")["pushed"] is True
    second = _add_nac(c, spoke_id="spokeA", host="cp-a2")
    assert second["pushed"] is False
    assert second["message"] == "Instance added; no spoke confirmed it."
    assert _last_config(hub, "spokeA-cppm")["host"] == "cp-a"
    assert _add_nac(c, id=5, spoke_id="spokeC", host="cp-c")["pushed"] is True


def test_opening_setup_nac_sends_the_migrated_legacy_config_to_the_nac_spokes():
    """Opening Setup → NAC moves the legacy single ClearPass config into a
    spoke-less record, which now configures every NAC spoke that ran on the
    legacy config. The page load sends it to them, so they are not left
    stale until their next reconnect or a save."""
    import hub_spoke_registry
    c, hub = _build()
    hub.active_connections["cppm-a"] = object()
    hub.spoke_module_types["cppm-a"] = "nac"
    hub.approved_modules["cppm-a"] = True
    hub.state.get_global_config()["cppm"] = {"host": "cp-legacy", "client_id": "cid"}
    instances = c.get("/setup/nac-instances").json()["instances"]
    assert [i["host"] for i in instances] == ["cp-legacy"]
    assert _last_config(hub, "cppm-a")["host"] == "cp-legacy"
    assert hub_spoke_registry.nac_spoke_stale(hub, "cppm-a") is False
