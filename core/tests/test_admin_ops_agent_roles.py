"""``/admin/ops/agent-roles`` — the read-only loopback lever that reports what
an agent actually says about its roles.

Why this exists: the Agents tile and the Roles dialog derive their badges from
two different agent RPCs and once disagreed — a node running Unbound and Kea
showed "no roles" in the tile while the dialog listed both. Neither RPC is
reachable from a loopback operator (they ride session-authenticated
``/api/agent/*`` routes), so the disagreement could only be guessed at. This
lever relays both commands and surfaces the agent's raw answer next to the
hub's own record.

The properties pinned here are the ones that make it trustworthy as a
diagnostic: it must never mutate (only the two GET_* commands are ever sent),
and one failing command must not hide the other's answer.
"""
import asyncio
import os
import tempfile

import pytest
from fastapi import HTTPException

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _RoleHub:
    """Minimal hub double recording every RPC it is asked to send."""

    def __init__(self, data_dir, responses=None, recorded=None):
        self.state = _State(data_dir)
        self.active_connections = {"agent-1": object()}
        self.sent = []
        self._responses = responses or {}
        self._recorded = recorded or []

    def _primary_key(self, spoke_id):
        return spoke_id

    def agent_assigned_roles(self, agent_id):
        return list(self._recorded)

    async def request_response(self, spoke_id, command, payload, timeout=None):
        self.sent.append((spoke_id, command, payload))
        resp = self._responses.get(command)
        if isinstance(resp, Exception):
            raise resp
        return resp


def _mk(tmp, **kw):
    app = _FakeApp()
    hub = _RoleHub(tmp, **kw)
    admin_ops.register(app, hub, ctx=None)
    tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
    return app.routes[("POST", "/admin/ops/agent-roles")], hub, tok


def _req(tok, body):
    r = _FakeRequest("127.0.0.1", tok)
    r.url = type("U", (), {"path": "/admin/ops/agent-roles"})()

    async def _json():
        return body
    r.json = _json
    return r


def _wrap(data):
    """The envelope ``request_response`` returns for an agent reply."""
    return {"payload": {"data": data}}


# The shape the real agent returns: durable deploy-role markers, and an empty
# ``active`` list because deploy roles are installs, not hosted sub-spokes.
_DEPLOY_ONLY = _wrap({
    "status": "SUCCESS",
    "active": [],
    "installed_deploy_roles": ["dhcp-server", "dns-server"],
    "active_deploy_roles": ["dhcp-server", "dns-server"],
})


def test_reports_the_agents_deploy_roles():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp, responses={
            "GET_AVAILABLE_ROLES": _DEPLOY_ONLY,
            "GET_DEPLOY_STATUS": _wrap({"dns-server": "installed"}),
        })
        out = asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        assert out["status"] == "ok"
        assert out["roles"]["installed_deploy_roles"] == ["dhcp-server", "dns-server"]
        assert out["deploy_status"] == {"dns-server": "installed"}


def test_ui_view_exposes_the_tile_dialog_disagreement():
    """The whole point of the lever: ``hosted_active`` is empty while the
    deploy-role lists are populated -- exactly the state that rendered as
    "no roles" in the tile but listed both roles in the dialog."""
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp, responses={
            "GET_AVAILABLE_ROLES": _DEPLOY_ONLY,
            "GET_DEPLOY_STATUS": _wrap({}),
        })
        out = asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        ui = out["ui_view"]
        assert ui["hosted_active"] == []
        assert ui["installed_deploy_roles"] == ["dhcp-server", "dns-server"]
        assert ui["active_deploy_roles"] == ["dhcp-server", "dns-server"]


def test_hosted_roles_are_named_not_echoed_raw():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp, responses={
            "GET_AVAILABLE_ROLES": _wrap({"active": [{"role": "netbox-server"}]}),
            "GET_DEPLOY_STATUS": _wrap({}),
        })
        out = asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        assert out["ui_view"]["hosted_active"] == ["netbox-server"]


def test_includes_the_hubs_own_record_for_comparison():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp, recorded=["dhcp-server", "dns-server"], responses={
            "GET_AVAILABLE_ROLES": _DEPLOY_ONLY,
            "GET_DEPLOY_STATUS": _wrap({}),
        })
        out = asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        assert out["hub_recorded_roles"] == ["dhcp-server", "dns-server"]


def test_only_read_only_commands_are_ever_sent():
    """A diagnostic must not be a mutation surface."""
    with tempfile.TemporaryDirectory() as tmp:
        fn, hub, tok = _mk(tmp, responses={
            "GET_AVAILABLE_ROLES": _DEPLOY_ONLY,
            "GET_DEPLOY_STATUS": _wrap({}),
        })
        asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        sent = [c for _, c, _ in hub.sent]
        assert sent == ["GET_AVAILABLE_ROLES", "GET_DEPLOY_STATUS"]
        assert all(c.startswith("GET_") for c in sent)


def test_one_failing_command_does_not_hide_the_other():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp, responses={
            "GET_AVAILABLE_ROLES": _DEPLOY_ONLY,
            "GET_DEPLOY_STATUS": RuntimeError("timed out waiting for spoke response"),
        })
        out = asyncio.run(fn(_req(tok, {"spoke_id": "agent-1"})))
        assert out["roles"]["installed_deploy_roles"] == ["dhcp-server", "dns-server"]
        assert "timed out" in out["deploy_status"]["error"]


def test_missing_spoke_id_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp)
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_req(tok, {})))
        assert ei.value.status_code == 400


def test_disconnected_agent_returns_503_without_sending_anything():
    with tempfile.TemporaryDirectory() as tmp:
        fn, hub, tok = _mk(tmp)
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_req(tok, {"spoke_id": "not-connected"})))
        assert ei.value.status_code == 503
        assert hub.sent == []


def test_requires_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        fn, _, tok = _mk(tmp)
        off_box = _req(tok, {"spoke_id": "agent-1"})
        off_box.client.host = "10.0.0.5"
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(off_box))
        assert ei.value.status_code == 403
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_req("wrong-token", {"spoke_id": "agent-1"})))
        assert ei.value.status_code in (401, 403)
