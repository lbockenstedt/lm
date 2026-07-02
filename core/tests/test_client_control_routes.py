"""Hub routes for the per-client override Control Panel
(``/sim/api/{tenant}/clients/{hostname}/control`` + ``/clients/control-all``).

These forward to the cs spoke's CS_GET/SET/CLEAR/SET_ALL_CLIENT_OVERRIDES
handlers (the persisted registry store — sticky across reconnects/reboots,
unlike the ephemeral demo flags). The GET route degrades to an empty-override
payload when the spoke is offline so the UI still renders.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from simulations.routes import register_simulations_routes


class FakeHub:
    """Minimal hub: records forwarded CS_* commands + returns canned replies."""

    def __init__(self, replies=None, connected=True):
        self.replies = replies or {}
        self.forwarded = []
        self._connected = connected
        self.simulations_cache = {}
        self.active_connections = {"cs-spoke-1"} if connected else set()
        self.simulations_store = type("Store", (), {})()
        self.state = type("State", (),
                          {"get_spoke_tenant": lambda sid: "10"})()

    def get_client_sim_spoke(self, tenant_id):
        return "cs-spoke-1" if self._connected else None

    async def request_response(self, sid, cmd_type, payload, timeout=8.0):
        self.forwarded.append((cmd_type, payload))
        return {"payload": {"data": self.replies.get(cmd_type, {"status": "SUCCESS"})}}


def _build(replies=None, connected=True):
    app = FastAPI()
    hub = FakeHub(replies=replies, connected=connected)
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


def test_set_client_control_forwards_with_overrides_map():
    c, hub = _build({"CS_SET_CLIENT_OVERRIDES":
                     {"status": "SUCCESS", "hostname": "host-a",
                      "overrides": {"dns_fail": "on"}}})
    r = c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
               json={"overrides": {"dns_fail": "on", "kill_switch": "off"}})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_CLIENT_OVERRIDES"
    assert payload["hostname"] == "host-a"
    assert payload["overrides"] == {"dns_fail": "on", "kill_switch": "off"}


def test_set_client_control_accepts_inline_flags():
    """Parity with the spoke's HTTP client_api: flags may be sent inline."""
    c, hub = _build()
    r = c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
               json={"dhcp_fail": "on"})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_CLIENT_OVERRIDES"
    assert payload["overrides"] == {"dhcp_fail": "on"}


def test_get_client_control_forwards_hostname():
    c, hub = _build({"CS_GET_CLIENT_OVERRIDES":
                     {"status": "SUCCESS", "hostname": "host-a",
                      "overrides": {"sim_load": "50"}}})
    r = c.get("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_GET_CLIENT_OVERRIDES"
    assert payload["hostname"] == "host-a"
    assert r.json()["overrides"] == {"sim_load": "50"}


def test_get_client_control_offline_returns_empty_overrides():
    c, hub = _build(connected=False)
    r = c.get("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    assert r.json()["overrides"] == {}
    assert hub.forwarded == []  # nothing forwarded when spoke is down


def test_clear_client_control_forwards():
    c, hub = _build({"CS_CLEAR_CLIENT_OVERRIDES":
                     {"status": "SUCCESS", "hostname": "host-a", "cleared": True}})
    r = c.delete("/sim/api/10/clients/host-a/control?tenant_id=10")
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_CLEAR_CLIENT_OVERRIDES"
    assert payload["hostname"] == "host-a"


def test_control_all_forwards_to_set_all():
    c, hub = _build({"CS_SET_ALL_CLIENT_OVERRIDES":
                     {"status": "SUCCESS", "applied": 3,
                      "overrides": {"dhcp_fail": "on"}}})
    r = c.post("/sim/api/10/clients/control-all?tenant_id=10",
               json={"overrides": {"dhcp_fail": "on"}})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_ALL_CLIENT_OVERRIDES"
    assert payload["overrides"] == {"dhcp_fail": "on"}
    assert r.json()["applied"] == 3


def test_control_all_does_not_collide_with_hostname_route():
    """``control-all`` is one segment; ``{hostname}/control`` is two — registered
    in that order so Starlette never captures 'control-all' as a hostname."""
    c, hub = _build()
    c.post("/sim/api/10/clients/control-all?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    assert hub.forwarded[-1][0] == "CS_SET_ALL_CLIENT_OVERRIDES"
    c.post("/sim/api/10/clients/host-a/control?tenant_id=10",
           json={"overrides": {"dns_fail": "on"}})
    assert hub.forwarded[-1][0] == "CS_SET_CLIENT_OVERRIDES"