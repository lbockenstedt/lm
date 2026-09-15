"""``/admin/ops/dhcp-ha-discover`` — re-form a Kea HA pair from loopback.

Why this exists: when the DHCP spoke loses its cluster members it falls back
to its own ``localhost:8001``, which on a management-only host has no Kea at
all. Every DHCP view then errors ("Kea CA unreachable"), so the WebUI's own
discover button — the thing that would fix it — is unreachable. Recovery has
to be possible without a browser session.

The important property is that this is not a REIMPLEMENTATION: it calls the
same ``_dhcp_discover_locked`` the UI route calls, so the two share the
per-spoke lock and the "exactly two active dhcp-server roles" guard. A second
enrollment path that drifted from the first would be worse than none.
"""
import asyncio
import os

import pytest
from fastapi import HTTPException

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _HaHub:
    def __init__(self, data_dir, spokes=("dhcp-1",)):
        self.state = _State(data_dir)
        self.active_connections = {}
        self._spokes = list(spokes)

    def _primary_key(self, spoke_id):
        return spoke_id

    def get_all_spokes_by_type(self, t):
        return list(self._spokes) if t == "dhcp" else []

    def get_spoke_by_type(self, t):
        return self._spokes[0] if (t == "dhcp" and self._spokes) else None

    async def request_response(self, *a, **kw):  # pragma: no cover - guard
        raise AssertionError("must go through the shared discovery path")


def _mk(tmp, spokes=("dhcp-1",), discover=None, attach=True):
    app = _FakeApp()
    # The real app carries a Starlette ``app.state``; _FakeApp does not.
    app.state = type("S", (), {})()
    hub = _HaHub(tmp, spokes)
    admin_ops.register(app, hub, ctx=None)
    calls = []

    async def _default(spoke_id):
        calls.append(spoke_id)
        return {"status": "SUCCESS", "discovered_count": 2, "cluster_ready": True}

    if attach:
        app.state.dhcp_discover_locked = discover or _default
    tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
    return app.routes[("POST", "/admin/ops/dhcp-ha-discover")], hub, tok, calls


def _req(tok, body):
    r = _FakeRequest("127.0.0.1", tok)
    r.url = type("U", (), {"path": "/admin/ops/dhcp-ha-discover"})()

    async def _json():
        return body
    r.json = _json
    return r


def _run(route, req):
    return asyncio.get_event_loop().run_until_complete(route(req))


def test_enrollment_runs_against_the_default_dhcp_spoke(tmp_path):
    route, _hub, tok, calls = _mk(str(tmp_path))
    out = _run(route, _req(tok, {}))
    assert calls == ["dhcp-1"]
    assert out["spoke_id"] == "dhcp-1"
    assert out["result"]["cluster_ready"] is True


def test_an_explicit_spoke_is_honoured(tmp_path):
    route, _hub, tok, calls = _mk(str(tmp_path), spokes=("dhcp-1", "dhcp-2"))
    out = _run(route, _req(tok, {"spoke_id": "dhcp-2"}))
    assert calls == ["dhcp-2"]
    assert out["spoke_id"] == "dhcp-2"


def test_an_unknown_spoke_is_refused_before_any_enrollment(tmp_path):
    """Enrolling the wrong cluster is not a recoverable mistake."""
    route, _hub, tok, calls = _mk(str(tmp_path))
    with pytest.raises(HTTPException) as ei:
        _run(route, _req(tok, {"spoke_id": "not-a-dhcp-spoke"}))
    assert ei.value.status_code == 400
    assert calls == []


def test_no_dhcp_spoke_connected_is_a_503(tmp_path):
    route, _hub, tok, _calls = _mk(str(tmp_path), spokes=())
    with pytest.raises(HTTPException) as ei:
        _run(route, _req(tok, {}))
    assert ei.value.status_code == 503


def test_it_reuses_the_ui_discovery_path_rather_than_reimplementing(tmp_path):
    """If the shared helper is absent the route must refuse, NOT fall back to
    a private copy that could drift from the UI's guards."""
    route, _hub, tok, _calls = _mk(str(tmp_path), attach=False)
    with pytest.raises(HTTPException) as ei:
        _run(route, _req(tok, {}))
    assert ei.value.status_code == 503


def test_a_discovery_failure_is_propagated_not_swallowed(tmp_path):
    """"Exactly two dhcp-server roles" is enforced in the shared path; the
    operator must see that verdict verbatim."""
    async def _boom(spoke_id):
        raise HTTPException(status_code=409,
                            detail="Found 3 active DHCP Server roles")
    route, _hub, tok, _calls = _mk(str(tmp_path), discover=_boom)
    with pytest.raises(HTTPException) as ei:
        _run(route, _req(tok, {}))
    assert ei.value.status_code == 409
    assert "3 active" in str(ei.value.detail)


def test_a_waiting_result_is_reported_as_is(tmp_path):
    """One worker present is not a cluster — must not be dressed up."""
    async def _one(spoke_id):
        return {"status": "SUCCESS", "discovered_count": 1,
                "cluster_ready": False,
                "message": "Two active DHCP Server roles are required for Kea HA."}
    route, _hub, tok, _calls = _mk(str(tmp_path), discover=_one)
    out = _run(route, _req(tok, {}))
    assert out["result"]["cluster_ready"] is False
    assert out["result"]["discovered_count"] == 1


def test_a_malformed_body_is_treated_as_empty(tmp_path):
    route, _hub, tok, calls = _mk(str(tmp_path))
    r = _FakeRequest("127.0.0.1", tok)
    r.url = type("U", (), {"path": "/admin/ops/dhcp-ha-discover"})()

    async def _bad():
        raise ValueError("not json")
    r.json = _bad
    out = _run(route, r)
    assert calls == ["dhcp-1"]
    assert out["spoke_id"] == "dhcp-1"


def test_route_is_loopback_and_token_gated(tmp_path):
    route, _hub, tok, calls = _mk(str(tmp_path))
    remote = _req(tok, {})
    remote.client = type("C", (), {"host": "10.0.0.9"})()
    with pytest.raises(HTTPException):
        _run(route, remote)

    bad = _req("not-the-token", {})
    with pytest.raises(HTTPException):
        _run(route, bad)
    # Neither unauthorized call may have touched the cluster.
    assert calls == []
