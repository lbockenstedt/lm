"""lm-976 / lm-984 regression coverage for the drive-health fan-out.

lm-976: each (spoke, node) request must fan out concurrently — sequential
awaits meant N slow/unresponsive agents cost up to 30s * N.

lm-984: a spoke that does not own a node replies with an ERROR envelope
carrying no ``node`` key (real agent behavior: "No agent resolved for
node"). That reply must never claim the node ahead of the spoke that
actually owns it, and a node that gets ONLY error replies must still
surface instead of silently vanishing.
"""
import asyncio
import time

from routes import pxmx

from test_pxmx_drive_health_route import _MockHub, _build_client


def setup_function(_):
    pxmx._NODES_CACHE.clear()
    pxmx._DRIVE_HEALTH_CACHE.clear()


def teardown_function(_):
    pxmx._NODES_CACHE.clear()
    pxmx._DRIVE_HEALTH_CACHE.clear()


class _MultiSpokeHub(_MockHub):
    """Two hypervisor spokes bound to one tenant; only ``owner_sid`` owns
    the requested node."""

    def __init__(self, owner_sid="spoke-owner", other_sid="spoke-other", delay=0.0):
        super().__init__(bound_spoke=None, global_spoke=None)
        self._owner_sid = owner_sid
        self._other_sid = other_sid
        self._delay = delay

    def get_hypervisor_spokes_for_tenant(self, tid=None):
        return [self._other_sid, self._owner_sid]

    async def request_response(self, sid, cmd, payload, timeout=30.0, signing_secret=None):
        self.calls.append({"sid": sid, "cmd": cmd, "payload": payload, "timeout": timeout, "t": time.time()})
        if cmd != "PXMX_DRIVE_HEALTH":
            return {"payload": {"data": {}}}
        if self._delay:
            await asyncio.sleep(self._delay)
        if sid == self._other_sid:
            # No "node" key, matching the real agent's reply for a node it
            # doesn't manage.
            return {"payload": {"data": {"status": "ERROR", "message": "No agent resolved for node"}}}
        return {
            "payload": {
                "data": {
                    "status": "SUCCESS",
                    "node": payload.get("node"),
                    "cluster": "lab-cluster",
                    "drives": [{"block_device": "/dev/sda", "wear_level": 5,
                                "health_status": "healthy"}],
                    "summary": {"total_drives": 1, "healthy": 1, "warning": 0,
                                "critical": 0, "unknown": 0},
                }
            }
        }


class _AllErrorHub(_MultiSpokeHub):
    """Every spoke returns an ERROR for the node."""

    async def request_response(self, sid, cmd, payload, timeout=30.0, signing_secret=None):
        self.calls.append({"sid": sid, "cmd": cmd, "payload": payload, "timeout": timeout})
        if cmd != "PXMX_DRIVE_HEALTH":
            return {"payload": {"data": {}}}
        return {"payload": {"data": {"status": "ERROR", "message": "agent unreachable"}}}


def test_non_owning_spoke_error_does_not_shadow_real_reply():
    hub = _MultiSpokeHub()
    client = _build_client(hub, tenant="acme")
    res = client.get("/api/pxmx/drive-health?tenant=acme&node=pve1")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == 1
    node = data["nodes"][0]
    assert node["node"] == "pve1"
    assert node["status"] == "SUCCESS"
    assert node["drives"], "the owning spoke's real reply was dropped"


def test_node_with_only_error_replies_still_surfaces():
    hub = _AllErrorHub()
    client = _build_client(hub, tenant="acme")
    res = client.get("/api/pxmx/drive-health?tenant=acme&node=pve1")
    assert res.status_code == 200
    data = res.json()
    assert len(data["nodes"]) == 1
    node = data["nodes"][0]
    assert node["node"] == "pve1"
    assert node["status"] == "ERROR"
    assert node["error"] == "agent unreachable"


def test_requests_fan_out_concurrently_not_sequentially():
    hub = _MultiSpokeHub(delay=0.2)
    client = _build_client(hub, tenant="acme")

    t0 = time.time()
    res = client.get("/api/pxmx/drive-health?tenant=acme&node=pve1")
    elapsed = time.time() - t0

    assert res.status_code == 200
    dh_calls = [c for c in hub.calls if c["cmd"] == "PXMX_DRIVE_HEALTH"]
    assert len(dh_calls) == 2
    spread = max(c["t"] for c in dh_calls) - min(c["t"] for c in dh_calls)
    assert spread < 0.05, f"fan-out not concurrent (spread={spread:.3f}s)"
    assert elapsed < 0.35, f"request took {elapsed:.3f}s (sequential?)"
