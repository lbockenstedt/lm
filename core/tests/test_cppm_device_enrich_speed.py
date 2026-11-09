"""NAC device detail took about a minute: /api/cppm/device-enrich asked each
firewall for its DHCP leases one at a time on the default timeout, so one
slow firewall held the modal open. It now asks them all at once with a short
timeout, and skips DHCP when ClearPass already has the IP and hostname.
The route is lifted out of routes/cppm.py with ``ast``."""
import ast
import asyncio
import os
import time

_SRC = os.path.join(os.path.dirname(__file__), "..", "src", "routes", "cppm.py")


class _Hub:
    def __init__(self, ep):
        self.ep = ep
        self.lease_calls = []

    def get_all_spokes_by_type(self, _t):
        return ["fw-1", "fw-2"]

    async def request_response(self, sid, cmd, data, timeout=None):
        if cmd == "GET_ENDPOINT_DETAIL":
            return {"payload": {"data": dict(self.ep)}}
        self.lease_calls.append((sid, timeout))
        await asyncio.sleep(0.5)
        leases = [{"mac": "08:76:71:08:7d:81", "ip": "10.1.1.9", "hostname": "cam"}] if sid == "fw-2" else []
        return {"payload": {"data": leases}}


def _route(hub):
    async def _gate(_req, ep, *_a, **_k):
        return ep

    ns = {"asyncio": asyncio, "hub": hub, "Request": object,
          "app": type("A", (), {"state": type("S", (), {"hub": hub})})(),
          "_nac_spoke_for_request": lambda _r, _t: "cppm-1",
          "_cppm_unwrap": lambda raw: raw["payload"]["data"],
          "_gate_record_tenant": _gate}
    for node in ast.walk(ast.parse(open(_SRC).read())):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in (
                "_norm_mac", "get_cppm_device_enrich"):
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), _SRC, "exec"), ns)
    return ns["get_cppm_device_enrich"]


def test_firewalls_are_queried_in_parallel_with_short_timeout():
    hub = _Hub({"mac": "087671087d81"})
    # Parse/compile the route before starting the clock: on a busy CI runner
    # that alone took >0.15s and made this test flaky.
    route = _route(hub)
    t0 = time.monotonic()
    ep = asyncio.run(route(object(), "087671087d81"))
    assert time.monotonic() - t0 < 0.7           # both firewalls at once (0.5s), not one after another (1.0s)
    assert ep["ip"] == "10.1.1.9" and ep["sources"]["ip"] == "DHCP"
    assert all(t and t <= 10 for _, t in hub.lease_calls)


def test_dhcp_skipped_when_clearpass_has_ip_and_hostname():
    hub = _Hub({"ip": "10.1.1.9", "hostname": "cam"})
    asyncio.run(_route(hub)(object(), "087671087d81"))
    assert hub.lease_calls == []
