"""All-tenants Overview fan-out: timeout skip, single-flight, prefer_cache.

Live evidence (LM-HUB hub.log, 2026-10-25): each all-tenants refresh logged
about 20 "Request Timeout: [PXMX_LIST_VMS]" at the same instant, about 200 a
day. There were two causes:

1. The wedged-spoke skip (commit 0e83c65b) only fired on an exception, but
   ``request_response`` RETURNS ``{"status":"ERROR","message":"Timed out
   waiting for spoke response"}`` on a timeout. So every tenant re-asked
   the same slow spoke.
2. Every tenant sent its own identical request (e.g. ``PXMX_LIST_VMS {}``
   to a shared hypervisor spoke), and every pinned-agent count ran a 10-15s
   live PVE query against a 5s budget.

These lock in:
* a timeout now marks the spoke failed, so later tenants skip it;
* an agent-scoped timeout does NOT mark the whole spoke failed;
* identical requests across tenants are sent once and every tenant
  still gets the counts;
* pinned-agent count requests carry ``prefer_cache``;
* the single-tenant summary is unchanged (no shared state, a timeout is 0).
"""

import asyncio
import types

from routes.dashboard import register

_TIMEOUT = {"status": "ERROR", "message": "Timed out waiting for spoke response"}


class _State:
    def __init__(self, tenants, agent_config=None):
        self.tenant_state = {"tenants": tenants}
        self.system_state = {"active_tenant": "default",
                             "module_metadata": {"hv": {"tenant_id": "shared"}},
                             "agent_config": agent_config or {}}
        self._tenants = tenants

    def get_tenant(self, tid):
        return self._tenants.get(tid)


class _Hub:
    """Records every request. ``reply(spoke, cmd, payload)`` returns
    ``(delay_s, response)``."""

    def __init__(self, tenants, reply, agent_config=None, agent_spokes=None):
        self.state = _State(tenants, agent_config)
        self._reply = reply
        self._agent_spokes = agent_spokes or {}
        self.active_connections = {}
        self.calls = []

    def get_spoke_by_type(self, t):
        return {"ipam": "ipam", "nac": "nac"}.get(t)

    def _agent_relay_name(self, agent_id):
        return agent_id

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=True):
        return self._agent_spokes.get(agent_id)

    def get_hypervisor_spokes_for_tenant(self, tid):
        return ["hv"]

    def get_hypervisor_spoke(self):
        return "hv"

    async def request_response(self, spoke, cmd, payload=None, timeout=None):
        payload = payload or {}
        self.calls.append((spoke, cmd, dict(payload)))
        delay, resp = self._reply(spoke, cmd, payload)
        await asyncio.sleep(delay)
        return resp

    def count(self, spoke, cmd, pred=lambda p: True):
        return sum(1 for s, c, p in self.calls if s == spoke and c == cmd and pred(p))


class _App:
    def __init__(self, hub):
        self.state = types.SimpleNamespace(hub=hub)
        self.routes = {}

    def get(self, path):
        def deco(fn):
            self.routes[("GET", path)] = fn
            return fn
        return deco

    def post(self, path):
        return self.get(path)


def _ctx():
    async def _resolve_prefixes_for_tenant(hub, tid):
        return []  # no prefixes: VM counts are not subnet-filtered

    return types.SimpleNamespace(
        _session_user=lambda request: {"tenant": "t1", "admin": True},
        _is_admin=lambda sess: True,
        _resolve_tenant=lambda request, explicit=None: explicit or "t1",
        _resolve_prefixes_for_tenant=_resolve_prefixes_for_tenant,
        _filter_enabled=lambda hub, module: True,
    )


def _route(hub, path):
    app = _App(hub)
    register(app, hub, _ctx())
    return app.routes[("GET", path)]


def _all_tenants(hub):
    handler = _route(hub, "/api/dashboard/all-tenants")
    rows = asyncio.run(handler(types.SimpleNamespace(), refresh=1))
    rows = rows.get("tenants", rows) if isinstance(rows, dict) else rows
    return {r["id"]: r for r in rows}


def _tenants(n, tag=lambda i: ""):
    return {f"t{i}": {"netbox_tenant_slug": f"t{i}", "proxmox_tag": tag(i)}
            for i in range(1, n + 1)}


def _vm(vmid, status="running"):
    return {"unique_id": f"c/n/{vmid}", "vmid": vmid, "node": "n", "status": status}


def test_identical_requests_are_sent_once_and_shared():
    """8 untagged tenants share hypervisor spoke hv: ONE PXMX_LIST_VMS {} is
    sent and every tenant still counts its 2 running VMs."""
    def reply(spoke, cmd, payload):
        if cmd == "PXMX_LIST_VMS":
            return 0.01, {"vms": [_vm(1), _vm(2), _vm(3, "stopped")]}
        return 0, {}
    hub = _Hub(_tenants(8), reply)
    rows = _all_tenants(hub)
    assert hub.count("hv", "PXMX_LIST_VMS") == 1
    assert {tid: r["vms"] for tid, r in rows.items()} == {f"t{i}": 2 for i in range(1, 9)}


def test_timeout_marks_spoke_failed_for_later_tenants():
    """The ipam spoke times out. Requests are per-tenant (different slug),
    so single-flight can't help. The first 5 tenants (semaphore width) are
    already in flight, but the 3 after them must skip ipam instead of
    re-waiting the timeout."""
    def reply(spoke, cmd, payload):
        if spoke == "ipam":
            return 0.02, dict(_TIMEOUT)
        return 0, {}
    hub = _Hub(_tenants(8), reply)
    rows = _all_tenants(hub)
    assert len(rows) == 8
    assert hub.count("ipam", "NETBOX_GET_DEVICES") == 5
    assert all(r["devices"] == 0 for r in rows.values())


def test_real_error_reply_does_not_mark_spoke_failed():
    """A genuine ERROR answer (spoke alive, refused) is not a wedge: later
    tenants still ask."""
    def reply(spoke, cmd, payload):
        if spoke == "ipam":
            return 0.01, {"status": "ERROR", "message": "netbox said no"}
        return 0, {}
    hub = _Hub(_tenants(8), reply)
    _all_tenants(hub)
    assert hub.count("ipam", "NETBOX_GET_DEVICES") == 8


def test_agent_scoped_timeout_does_not_skip_spoke():
    """Tenants t1..t5 each pin a host on hv, and those pinned calls time out
    (slow host / older spoke). t6 starts afterwards with its own tag
    (a distinct request), and it must still be asked and counted. Marking hv
    failed on an agent timeout would zero t6."""
    tenants = _tenants(6, tag=lambda i: "t6tag" if i == 6 else "")
    agent_config = {f"ag{i}": {"client_simulation": {"tenant_id": f"t{i}"}}
                    for i in range(1, 6)}
    agent_spokes = {f"ag{i}": "hv" for i in range(1, 6)}

    def reply(spoke, cmd, payload):
        if cmd == "PXMX_LIST_VMS" and payload.get("agent_id"):
            return 0.02, dict(_TIMEOUT)
        if cmd == "PXMX_LIST_VMS" and payload.get("tag_filter") == "t6tag":
            return 0, {"vms": [_vm(60), _vm(61)]}
        if cmd == "PXMX_LIST_VMS":
            return 0, {"vms": []}
        return 0, {}
    hub = _Hub(tenants, reply, agent_config, agent_spokes)
    rows = _all_tenants(hub)
    assert hub.count("hv", "PXMX_LIST_VMS", lambda p: p.get("tag_filter") == "t6tag") == 1
    assert rows["t6"]["vms"] == 2


def test_pinned_count_requests_carry_prefer_cache():
    agent_config = {"ag1": {"client_simulation": {"tenant_id": "t1"}}}

    def reply(spoke, cmd, payload):
        if cmd == "PXMX_LIST_VMS" and payload.get("agent_id"):
            return 0, {"vms": [_vm(7)]}
        return 0, {}
    hub = _Hub(_tenants(1), reply, agent_config, {"ag1": "hv"})
    rows = _all_tenants(hub)
    pinned = [p for s, c, p in hub.calls if c == "PXMX_LIST_VMS" and p.get("agent_id")]
    assert pinned == [{"agent_id": "ag1", "prefer_cache": True}]
    assert rows["t1"]["vms"] == 1


def test_single_tenant_summary_timeout_is_zero_not_crash():
    """The single-tenant summary passes no shared state: a timeout just
    yields 0 for that leg and the other legs still count."""
    def reply(spoke, cmd, payload):
        if spoke == "ipam":
            return 0, dict(_TIMEOUT)
        if cmd == "PXMX_LIST_VMS":
            return 0, {"vms": [_vm(1)]}
        return 0, {}
    hub = _Hub(_tenants(1), reply)
    out = asyncio.run(_route(hub, "/api/dashboard/summary")(
        types.SimpleNamespace(), tenant="t1"))
    assert out["devices"] == 0
    assert out["vms"] == 1

