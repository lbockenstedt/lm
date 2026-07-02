"""Hub routes for per-host USB VMID overrides
(``/sim/api/{tenant}/cs/host-usb-override``).

These forward to the cs spoke's CS_GET/SET/CLEAR_HOST_USB_OVERRIDE handlers —
the persisted per-host ``vmid_start``/``vmid_end``/``vm_set_override`` pins that
override the pxmx agent's hostname-suffix batch derivation for one proxmox host.
The hub only forwards; the cs spoke owns the store (cs_settings.json
``host_usb_overrides``). Mirrors the ``/clients/{hostname}/control`` test pattern.
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


def test_get_host_usb_overrides_forwards():
    c, hub = _build({"CS_GET_HOST_USB_OVERRIDES": {
        "status": "SUCCESS",
        "overrides": {"pxmx-cs-svr-02": {"vmid_start": 91000, "vmid_end": 91999}},
    }})
    r = c.get("/sim/api/10/cs/host-usb-override?tenant_id=10")
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_GET_HOST_USB_OVERRIDES"
    assert payload == {}
    assert r.json()["overrides"]["pxmx-cs-svr-02"]["vmid_start"] == 91000


def test_set_host_usb_override_forwards_with_knobs_map():
    c, hub = _build({"CS_SET_HOST_USB_OVERRIDE": {
        "status": "SUCCESS", "hostname": "pxmx-cs-svr-02",
        "knobs": {"vmid_start": 91000, "vmid_end": 91999},
    }})
    r = c.post("/sim/api/10/cs/host-usb-override/pxmx-cs-svr-02?tenant_id=10",
               json={"knobs": {"vmid_start": 91000, "vmid_end": 91999,
                               "vm_set_override": 0}})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_HOST_USB_OVERRIDE"
    assert payload["hostname"] == "pxmx-cs-svr-02"
    assert payload["knobs"] == {"vmid_start": 91000, "vmid_end": 91999,
                                "vm_set_override": 0}


def test_set_host_usb_override_accepts_inline_knobs():
    """Inline knobs (no ``knobs`` wrapper) for parity with the spoke handler."""
    c, hub = _build()
    r = c.post("/sim/api/10/cs/host-usb-override/pxmx-cs-svr-02?tenant_id=10",
               json={"vmid_start": 91000, "vmid_end": 91999})
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_SET_HOST_USB_OVERRIDE"
    assert payload["hostname"] == "pxmx-cs-svr-02"
    assert payload["knobs"] == {"vmid_start": 91000, "vmid_end": 91999}


def test_clear_host_usb_override_forwards():
    c, hub = _build({"CS_CLEAR_HOST_USB_OVERRIDE": {
        "status": "SUCCESS", "hostname": "pxmx-cs-svr-02", "cleared": True,
    }})
    r = c.delete("/sim/api/10/cs/host-usb-override/pxmx-cs-svr-02?tenant_id=10")
    assert r.status_code == 200
    cmd, payload = hub.forwarded[-1]
    assert cmd == "CS_CLEAR_HOST_USB_OVERRIDE"
    assert payload["hostname"] == "pxmx-cs-svr-02"