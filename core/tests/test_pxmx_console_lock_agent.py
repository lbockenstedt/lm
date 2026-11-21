"""The VNC console's write lock and viewer list belong to a VM on its own
agent, through the real hub routes (``create_app``) and the real lock
(``HubVncConsoleMixin``).

A VM's unique_id ("<cluster>/<node>/<vmid>") names no agent, so two tenants'
separate clusters can share one (default node name, same VM ID). The routes
therefore:

* store the agent with the session when a console opens, and take the lock
  of the VM on that agent, so two agents' VMs that share a unique_id each
  get their own first writer;
* list the viewers of the VM on the agent the request names, after the same
  ownership check on that agent;
* take control of the VM the session was opened on: ownership is checked
  against the agent stored in the session, never one the request names.
"""
import asyncio
import time

import pytest
from fastapi.testclient import TestClient

import access as access_mod
import api as api_mod
from hub_vnc_console import HubVncConsoleMixin

UID = "pve/pve/100"
# One hypervisor spoke per agent: each tenant's cluster has its own agent.
SPOKES = {"agent-a": "spoke-a", "agent-b": "spoke-b"}
ADMIN = {"role": "admin", "admin": True}
# A non-admin write user of the Hypervisors module.
WRITER = {"pxmx": True, "edit": True}


class _FakeState:
    """The hub state create_app and the console routes read."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.system_state = {}

    def ensure_admin_lockout(self):
        return False

    def save_state(self):
        pass

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        self.save_state()

    def get_tenant(self, tid):
        return None

    def get_spoke_tenant(self, spoke_id):
        return ""


class _Hub(HubVncConsoleMixin):
    """A hub with the real VNC session registry and write lock, and one
    hypervisor spoke per agent."""

    def __init__(self, data_dir):
        self.state = _FakeState(data_dir)
        self.vnc_sessions = {}
        # create_app's other route modules read these at build time.
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = set()

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return SPOKES.get(agent_id)

    def get_hypervisor_spoke(self):
        return None

    def get_spoke_by_type(self, module_type):
        return None

    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_relay_name(self, agent_id):
        return agent_id

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        """VNC_START succeeds with a ticket; GET_VM_INFO knows nothing about
        the VM, so ownership rests on the checks the tests set."""
        if cmd == "VNC_START":
            return {"payload": {"data": {"status": "SUCCESS", "ticket": "t"}}}
        return {}


@pytest.fixture
def client_hub(tmp_path):
    """A test client on create_app around ``_Hub``, with no sessions."""
    api_mod._sessions.clear()
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())
    hub = _Hub(str(tmp_path))
    yield TestClient(api_mod.create_app(hub)), hub
    api_mod._sessions.clear()


@pytest.fixture
def owns_only_agent_b(monkeypatch):
    """The caller owns agent-b's host and nothing else: every ownership
    check _assert_vm_owned makes passes for agent-b's spoke only."""
    def owned(spoke):
        """True for agent-b's spoke only."""
        return spoke == SPOKES["agent-b"]

    async def no_tenant_admin_console(hub, sess, spoke):
        """No tenant-admin console opt-in on any host."""
        return False

    async def in_scope(hub, sess, vm_record, spoke_id=None):
        """A VM is attributed to the caller only on agent-b's host."""
        return owned(spoke_id)

    monkeypatch.setattr(access_mod, "hypervisor_owned_by_caller", lambda hub, sess, spoke: owned(spoke))
    monkeypatch.setattr(access_mod, "tenant_admin_console_allowed", no_tenant_admin_console)
    monkeypatch.setattr(access_mod, "last_known_vm_record", lambda *a, **k: None)
    monkeypatch.setattr(access_mod, "vm_in_tenant_scope", in_scope)


def _login(hub, uid, permissions, tenant=None):
    """A live session cookie for ``uid`` (no password round trip)."""
    token = api_mod._record_session(hub, {
        "user_id": uid, "auth_type": "local", "permissions": permissions,
        "tenants": [tenant] if tenant else [], "tenant_id": tenant, "protected": False})
    return {"lm_session": token}


def _viewer(hub, sid, agent, username):
    """A connected console session ``sid`` of ``username`` on UID, opened
    through ``agent``, attached to that VM's lock as the open route does."""
    hub.register_vnc_session(sid, {"unique_id": UID, "agent_id": agent,
                                    "spoke_id": SPOKES[agent], "username": username})
    hub.vnc_sessions[sid]["connected"] = True
    hub.vnc_sessions[sid]["connected_at"] = time.time()
    hub.vnc_attach(UID, sid, agent)


def test_open_stores_the_agent_and_locks_the_vm_on_it(client_hub):
    """Two agents' VMs that share a unique_id each get a first writer; a
    second viewer of agent-b's VM opens read-only."""
    client, hub = client_hub
    cookies = _login(hub, "admin", ADMIN)

    def open_on(agent):
        """Open UID's console through ``agent``; the route's answer."""
        r = client.post("/api/pxmx/console", cookies=cookies, json={
            "unique_id": UID, "vmid": 100, "node": "pve", "agent_id": agent})
        assert r.status_code == 200, r.text
        return r.json()

    a, b, b2 = open_on("agent-a"), open_on("agent-b"), open_on("agent-b")
    assert [a["read_only"], b["read_only"], b2["read_only"]] == [False, False, True]
    assert hub.vnc_sessions[a["session_id"]].get("agent_id") == "agent-a"
    assert hub.vnc_sessions[b["session_id"]].get("agent_id") == "agent-b"


def test_viewers_lists_only_the_named_agents_viewers(client_hub):
    """A Global Admin asking for agent-b's VM sees bob only, never alice on
    agent-a's VM with the same unique_id; and the reverse."""
    client, hub = client_hub
    cookies = _login(hub, "admin", ADMIN)
    _viewer(hub, "a1", "agent-a", "alice")
    _viewer(hub, "b1", "agent-b", "bob")

    def viewers(agent):
        """[username, is_writer] of each viewer the route lists for ``agent``."""
        r = client.get("/api/pxmx/console/viewers", cookies=cookies,
                       params={"unique_id": UID, "agent_id": agent})
        assert r.status_code == 200, r.text
        return [[v["username"], v["is_writer"]] for v in r.json()["viewers"]]

    assert viewers("agent-b") == [["bob", True]]
    assert viewers("agent-a") == [["alice", True]]


def test_takeover_checks_the_vm_the_session_was_opened_on(client_hub, owns_only_agent_b):
    """A write user who owns only agent-b's host cannot take control of a
    console opened on agent-a's VM by naming agent-b in the body: 403, and
    agent-a's writer keeps the lock."""
    client, hub = client_hub
    _viewer(hub, "a1", "agent-a", "alice")
    _viewer(hub, "a2", "agent-a", "bea")
    cookies = _login(hub, "bea", WRITER, "tenant-b")
    r = client.post("/api/pxmx/console/a2/takeover", cookies=cookies, json={"agent_id": "agent-b"})
    assert r.status_code == 403, r.text
    assert r.json()["detail"] == "not authorized for this VM's tenant"
    assert hub.vnc_is_writer(UID, "a1", "agent-a") is True
    assert hub.vnc_is_writer(UID, "a2", "agent-a") is False


def test_takeover_on_the_callers_own_vm_evicts_only_that_vms_writer(client_hub, owns_only_agent_b):
    """The same user takes control of a console opened on agent-b's VM (the
    WebUI still sends its agent in the body): bob is evicted and told so,
    and alice keeps the lock of agent-a's VM with the same unique_id."""
    client, hub = client_hub
    _viewer(hub, "a1", "agent-a", "alice")
    _viewer(hub, "b1", "agent-b", "bob")
    _viewer(hub, "b2", "agent-b", "bea")
    cookies = _login(hub, "bea", WRITER, "tenant-b")
    r = client.post("/api/pxmx/console/b2/takeover", cookies=cookies, json={"agent_id": "agent-b"})
    assert r.status_code == 200, r.text
    assert r.json()["previous_writer"] == "b1"
    assert hub.vnc_is_writer(UID, "b2", "agent-b") is True
    assert hub.vnc_is_writer(UID, "a1", "agent-a") is True
    assert hub.vnc_sessions["b1"]["queue"].get_nowait() == ("downgraded",)
    assert hub.vnc_sessions["a1"]["queue"].empty()
