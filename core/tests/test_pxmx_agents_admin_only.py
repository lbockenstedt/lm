"""Tenant-scoping guard for the Hypervisor SERVER + per-agent CONFIG routes
(``routes/pxmx.py``).

A server/agent is a cross-tenant object; its per-agent config even sets the
agent's OWNING tenant, so managing it is inherently a Global-Admin operation
(the documented "/api/pxmx/agents/* stay Global-Admin-only" rule, mirroring the
already-gated decommission/restore/delete_server siblings). A tenant-scoped
``pxmx``-right user must NOT be able to revoke / rename / reconfigure / delete /
fast-command an agent, read its config, reveal the add-a-server install command,
or delete a hypervisor host.

These lock the in-handler ``_is_admin`` gate on every such endpoint: a non-admin
gets 403 and never reaches the hub relay; an admin passes the gate.
"""

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes import pxmx


class _State:
    def __init__(self):
        self.system_state = {"agent_config": {}, "agent_display_names": {}}

    def _mark_dirty(self):
        pass


class _Hub:
    """Minimal hub: records any relay so a leaked call past the gate is visible."""

    def __init__(self):
        self.state = _State()
        self.relayed = []

    def get_hypervisor_spoke(self):
        return "pxmx-1"

    def get_spoke_for_agent(self, agent_id, fallback_hypervisor=False):
        return "pxmx-1"

    def _agent_primary_key(self, agent_id):
        return agent_id

    def _agent_relay_name(self, agent_id):
        return agent_id

    async def request_response(self, sid, cmd, payload, timeout=8.0):
        self.relayed.append((cmd, payload))
        return {"payload": {"data": {"status": "SUCCESS"}}}


def _ctx(admin):
    return SimpleNamespace(
        _session_user=lambda request: {"user": {"tenant_id": "acme"},
                                       "tenant_id": "acme"},
        _is_admin=lambda sess: admin,
        _resolve_tenant=lambda request, explicit=None: explicit or "acme",
        _filter_tenant=lambda *a, **k: None,
        _trigger_vm_sync_after_pxmx_edit=lambda hub, request, body: None,
    )


def _build(admin):
    app = FastAPI()
    hub = _Hub()
    app.state.hub = hub
    pxmx.register(app, hub, _ctx(admin=admin))
    # raise_server_exceptions=False: the admin path passes the gate and then
    # exercises real relay/purge logic our minimal fake hub can't fully satisfy
    # (a downstream 500 is fine — these tests assert only the AUTH gate, i.e.
    # 403-or-not, not the handler's full success path).
    return TestClient(app, raise_server_exceptions=False), hub


# Each entry: (http_method, path, json_body_or_None)
_MANAGEMENT_ROUTES = [
    ("post", "/api/pxmx/agents/a1/revoke", None),
    ("post", "/api/pxmx/agents/a1/ack-change", None),
    ("post", "/api/pxmx/agents/a1/rename", {"display_name": "x"}),
    ("get", "/api/pxmx/agents/a1/config", None),
    ("post", "/api/pxmx/agents/a1/config", {"client_simulation": {"tenant_id": "victim"}}),
    ("post", "/api/pxmx/agents/a1/cs-command", {"action": "start_vms"}),
    ("delete", "/api/pxmx/agents/a1", None),
    ("get", "/api/pxmx/agent-install-cmd", None),
]


def _call(client, method, path, body):
    fn = getattr(client, method)
    return fn(path, json=body) if body is not None else fn(path)


def test_non_admin_blocked_from_every_server_and_config_route():
    client, hub = _build(admin=False)
    for method, path, body in _MANAGEMENT_ROUTES:
        r = _call(client, method, path, body)
        assert r.status_code == 403, f"{method.upper()} {path} should be 403 for non-admin, got {r.status_code}"
    # A denied request must never reach the hub relay (fail-closed, no side effect).
    assert hub.relayed == []
    # A denied config write must never persist a tenant reassignment.
    assert hub.state.system_state["agent_config"] == {}


def test_admin_passes_the_gate_on_every_route():
    client, hub = _build(admin=True)
    for method, path, body in _MANAGEMENT_ROUTES:
        r = _call(client, method, path, body)
        assert r.status_code != 403, f"{method.upper()} {path} should pass the admin gate, got 403"
