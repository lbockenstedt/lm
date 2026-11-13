"""POST /api/pxmx/server/maintenance and /reboot — the Hypervisors → Nodes
"Maintenance" switch and "Reboot" button (routes/pxmx.py). Gated like Delete (Global Admin); the node must be
in the caller's scoped node list and pass the name regex; the request is
relayed as PXMX_NODE_MAINTENANCE to the agent that reports the node; agent
errors (HA not configured, an agent too old for the command) come back as a
non-2xx with the message for the UI toast."""

import tempfile
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx
from warm_cache import WarmCacheMixin


class _State:
    def __init__(self):
        self.system_state = {}

    def _mark_dirty(self):
        pass


class _Hub(WarmCacheMixin):
    """Hub stub: one hypervisor spoke reporting pve1/pve2 via agent ag-1."""

    def __init__(self, reply=None):
        self.state = _State()
        self.cache_dir = tempfile.mkdtemp(prefix="pxmx-maint-")
        self.warm_cache_init()
        self.calls = []
        self.reply = reply if reply is not None else {"status": "SUCCESS"}
        self.agent_spoke = "pxmx-1"

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        return ["pxmx-1"]

    def get_all_spokes_by_type(self, module_type):
        return ["pxmx-1"] if module_type == "hypervisor" else []

    def get_hypervisor_spoke(self):
        return "pxmx-1"

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=False):
        return self.agent_spoke

    def _agent_relay_name(self, agent_id):
        return agent_id

    async def request_response(self, sid, cmd, payload, timeout=30.0, signing_secret=None):
        self.calls.append((sid, cmd, payload))
        if cmd == "GET_NODE_STATS":
            return {"payload": {"data": {"nodes": [
                {"node": "pve1", "status": "online", "cluster": "lab", "agent_id": "ag-1",
                 "maintenance": True},
                {"node": "pve2", "status": "online", "cluster": "lab", "agent_id": "ag-1",
                 "maintenance": False}]}}}
        return {"payload": {"data": self.reply}}


def _client(hub, admin=True):
    ctx = SimpleNamespace(
        _session_user=lambda request: {"user": {"username": "op"}},
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: explicit,
        _filter_tenant=None,
    )
    app = FastAPI()
    app.state.hub = hub
    pxmx.register(app, hub, ctx)
    return TestClient(app)


def _relays(hub):
    return [c for c in hub.calls if c[1] == "SPOKE_RELAY"]


def test_admin_enable_relays_to_the_nodes_agent():
    hub = _Hub()
    r = _client(hub).post("/api/pxmx/server/maintenance?tenant=acme",
                          json={"node": "pve2", "enable": True})
    assert r.status_code == 200, r.text
    assert r.json()["maintenance"] is True
    assert _relays(hub) == [("pxmx-1", "SPOKE_RELAY", {
        "target_agent_id": "ag-1", "command": "PXMX_NODE_MAINTENANCE",
        "data": {"node": "pve2", "enable": True}})]


def test_non_admin_is_refused_before_any_relay():
    hub = _Hub()
    r = _client(hub, admin=False).post("/api/pxmx/server/maintenance?tenant=acme",
                                       json={"node": "pve1", "enable": True})
    assert r.status_code == 403
    assert hub.calls == []


def test_bad_or_unknown_node_is_rejected():
    hub = _Hub()
    c = _client(hub)
    for body in ({"node": "pve1; reboot", "enable": True}, {"node": "pve1\n", "enable": True},
                 {"node": "pve1", "enable": "yes"}, {"enable": True}):
        assert c.post("/api/pxmx/server/maintenance?tenant=acme", json=body).status_code == 400
    r = c.post("/api/pxmx/server/maintenance?tenant=acme", json={"node": "pve9", "enable": False})
    assert r.status_code == 404
    r = c.post("/api/pxmx/server/maintenance?tenant=acme",
               json={"node": "pve1", "cluster": "other", "enable": True})
    assert r.status_code == 404
    assert _relays(hub) == []


def test_agent_error_is_returned_for_the_toast():
    hub = _Hub(reply={"status": "ERROR", "message": "ha-manager node-maintenance enable failed: no quorum"})
    r = _client(hub).post("/api/pxmx/server/maintenance?tenant=acme",
                          json={"node": "pve1", "enable": True})
    assert r.status_code == 502 and "no quorum" in r.json()["detail"]


def test_old_agent_unknown_command_is_explained():
    hub = _Hub(reply={"status": "ERROR", "message": "Unknown agent command 'PXMX_NODE_MAINTENANCE'"})
    r = _client(hub).post("/api/pxmx/server/maintenance?tenant=acme",
                          json={"node": "pve1", "enable": False})
    assert r.status_code == 502 and "too old" in r.json()["detail"]


def test_node_list_is_fetched_live_not_trusted_from_cache():
    hub = _Hub()
    c = _client(hub)
    c.get("/api/pxmx/nodes?tenant=acme")
    # An old cached copy still lists pve3; the live list does not.
    entries = list(hub.warm_cache.get("pxmx_nodes", {}).values())
    assert entries
    for entry in entries:
        entry["data"]["nodes"].append({"node": "pve3", "cluster": "lab", "agent_id": "ag-1"})
    r = c.post("/api/pxmx/server/maintenance?tenant=acme", json={"node": "pve3", "enable": True})
    assert r.status_code == 404
    assert _relays(hub) == []


def test_unconnected_agent_is_not_routed_through_another_spoke():
    hub = _Hub()
    hub.agent_spoke = None
    r = _client(hub).post("/api/pxmx/server/maintenance?tenant=acme",
                          json={"node": "pve1", "enable": True})
    assert r.status_code == 503 and "not connected" in r.json()["detail"]
    assert _relays(hub) == []


def test_hidden_node_is_not_actionable():
    hub = _Hub()
    hub.state.system_state["pxmx_hidden_nodes"] = ["pve2"]
    r = _client(hub).post("/api/pxmx/server/maintenance?tenant=acme",
                          json={"node": "pve2", "enable": True})
    assert r.status_code == 404
    assert _relays(hub) == []


def test_maintenance_request_does_not_fake_the_reported_state():
    hub = _Hub()
    c = _client(hub)
    r = c.post("/api/pxmx/server/maintenance?tenant=acme", json={"node": "pve2", "enable": True})
    assert r.status_code == 200, r.text
    # The switch must keep showing the agent-reported state until telemetry confirms.
    nodes = c.get("/api/pxmx/nodes?tenant=acme").json()["nodes"]
    assert next(n for n in nodes if n["node"] == "pve2")["maintenance"] is False


# ── Reboot (only for a node the agent reports in maintenance) ───────────────

def test_admin_reboot_of_node_in_maintenance_relays_reboot():
    hub = _Hub(reply={"status": "SUCCESS", "message": "pve1: reboot requested"})
    r = _client(hub).post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve1"})
    assert r.status_code == 200, r.text
    assert r.json()["message"] == "pve1: reboot requested"
    assert _relays(hub) == [("pxmx-1", "SPOKE_RELAY", {
        "target_agent_id": "ag-1", "command": "PXMX_NODE_REBOOT", "data": {"node": "pve1"}})]


def test_reboot_refused_when_node_not_in_maintenance():
    hub = _Hub()
    r = _client(hub).post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve2"})
    assert r.status_code == 409 and "not in maintenance" in r.json()["detail"]
    assert _relays(hub) == []


def test_reboot_is_admin_only_and_scoped():
    hub = _Hub()
    r = _client(hub, admin=False).post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve1"})
    assert r.status_code == 403 and hub.calls == []
    c = _client(hub)
    assert c.post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve1;id"}).status_code == 400
    assert c.post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve9"}).status_code == 404
    hub.state.system_state["pxmx_hidden_nodes"] = ["pve1"]
    assert c.post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve1"}).status_code == 404
    assert _relays(hub) == []


def test_reboot_refusal_from_agent_is_returned():
    hub = _Hub(reply={"status": "ERROR",
                      "message": "refusing to reboot: 2 guest(s) still running on pve1 (qemu:101, qemu:102)"})
    r = _client(hub).post("/api/pxmx/server/reboot?tenant=acme", json={"node": "pve1"})
    assert r.status_code == 502 and "2 guest(s) still running" in r.json()["detail"]
