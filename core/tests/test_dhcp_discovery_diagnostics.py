"""Kea HA discovery must say WHY it could not form the pair.

Discovery counts, per tenant, the connected agents whose ``dhcp-server`` deploy
role is both installed and active. It needs exactly two. Both failure answers
used to be dead ends for the operator:

* fewer than two -> "Two active DHCP Server roles are required for Kea HA."
* more than two  -> a count and a tenant, but not WHICH nodes.

The first is the one that bites. Observed on a live fleet: four hosts had an
active ``dhcp-server`` role and two of them were a healthy running Kea pair, yet
discovery reported ``discovered_count: 1`` with that one sentence. Nothing in it
says which tenant was searched, how many agents were looked at, or why the nodes
the operator can plainly see running Kea were passed over -- and the answer was
that they sit in a different tenant from the DHCP spoke.

These tests pin the diagnosis into both answers.
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.net_services import register


class FakeState:
    def __init__(self, tenants=None):
        self.system_state = {"global_config": {}, "module_names": {}}
        self._tenants = tenants or {}

    def get_spoke_tenant(self, sid):
        return self._tenants.get(sid, "shared")

    def _mark_dirty(self):
        pass


class FakeHub:
    def __init__(self, replies=None, tenants=None):
        self.active_connections = {"dhcp-1"}
        self.approved_modules = {"dhcp-1": True}
        self.state = FakeState(tenants)
        self.replies = replies or {}
        self.forwarded = []
        self.spoke_module_types = {}
        self.spoke_parent_map = {}
        self.spoke_telemetry = {}

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return {"dhcp": "dhcp-1"}.get(module_type)

    def get_all_spokes_by_type(self, module_type):
        return [self.get_spoke_by_type(module_type)]

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return "dhcp-1"

    def get_dhcp_spoke_for_shared(self):
        return "dhcp-1"

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        data = (self.replies.get(sid) or {}).get(cmd, {"status": "SUCCESS"})
        return {"payload": {"data": data}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


def _client(sess, hub):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s.get("user", {}).get("is_admin")),
        _effective_tenant=lambda request, explicit=None: explicit,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


ADMIN = {"user": {"is_admin": True}}


def _agent(hub, sid, installed=(), active=(), address="10.0.0.11", answers=True):
    hub.spoke_module_types[sid] = "agent"
    hub.active_connections.add(sid)
    hub.spoke_telemetry[sid] = {"remote_ip": address}
    hub.replies[sid] = {"GET_AVAILABLE_ROLES": ({
        "status": "SUCCESS",
        "installed_deploy_roles": list(installed),
        "active_deploy_roles": list(active),
        "configured_worker_roles": [],
        "configured_workers": [],
        "service_addresses": [address],
    } if answers else {})}


def _discover(hub):
    r = _client(ADMIN, hub).post("/api/dhcp/ha/discover")
    return r


# ── fewer than two ──────────────────────────────────────────────────────────

def test_short_pair_reports_the_tenant_and_how_many_agents_were_searched():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}})
    _agent(hub, "kea-a", installed=["dhcp-server"], active=["dhcp-server"])
    _agent(hub, "idle-b", installed=[], active=[])

    body = _discover(hub).json()

    assert body["cluster_ready"] is False
    assert body["discovered_count"] == 1
    assert body["candidate_count"] == 2, (
        "say how many agents were actually looked at")
    assert "shared" in body["message"], "name the tenant that was searched"


def test_short_pair_explains_why_each_agent_was_passed_over():
    """The live case: the node runs Kea but its role is not active, so it is
    invisible to discovery for a reason the operator cannot otherwise see."""
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}})
    _agent(hub, "kea-a", installed=["dhcp-server"], active=["dhcp-server"])
    _agent(hub, "stopped-b", installed=["dhcp-server"], active=[])
    _agent(hub, "bare-c", installed=[], active=[])

    body = _discover(hub).json()

    reasons = {item["spoke_id"]: item["reason"] for item in body["skipped"]}
    assert "installed but not active" in reasons["stopped-b"]
    assert "not installed" in reasons["bare-c"]
    assert "stopped-b" not in reasons.get("kea-a", "")
    # and the human-readable line carries it too
    assert "stopped-b" in body["message"] or "not active" in body["message"]


def test_an_agent_that_never_answered_is_reported_rather_than_silently_dropped():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}})
    _agent(hub, "kea-a", installed=["dhcp-server"], active=["dhcp-server"])
    _agent(hub, "mute-b", answers=False)

    body = _discover(hub).json()

    reasons = {item["spoke_id"]: item["reason"] for item in body["skipped"]}
    assert "did not answer" in reasons["mute-b"]


def test_no_candidates_at_all_tells_the_operator_what_to_do_next():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}})

    body = _discover(hub).json()

    assert body["discovered_count"] == 0
    assert "Load the DHCP Server role" in body["message"]


def test_agents_in_another_tenant_are_not_counted_as_candidates():
    """This is the whole reason the original message was mystifying: a healthy
    pair existed on the fleet, just not in this spoke's tenant."""
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}},
        tenants={"other-a": "somewhere-else", "other-b": "somewhere-else"})
    _agent(hub, "other-a", installed=["dhcp-server"], active=["dhcp-server"])
    _agent(hub, "other-b", installed=["dhcp-server"], active=["dhcp-server"])

    body = _discover(hub).json()

    assert body["discovered_count"] == 0
    assert body["candidate_count"] == 0


# ── more than two ───────────────────────────────────────────────────────────

def test_too_many_active_roles_names_the_competing_nodes():
    hub = FakeHub({"dhcp-1": {"DHCP_HA_STATUS": {
        "status": "SUCCESS", "enabled": False, "members": []}}})
    for i, sid in enumerate(("kea-a", "kea-b", "kea-c")):
        _agent(hub, sid, installed=["dhcp-server"], active=["dhcp-server"],
               address="10.0.0.%d" % (11 + i))

    r = _discover(hub)

    assert r.status_code == 409
    detail = r.json()["detail"]
    for sid in ("kea-a", "kea-b", "kea-c"):
        assert sid in detail, "name every node competing for the pair"
    assert "exactly two" in detail
