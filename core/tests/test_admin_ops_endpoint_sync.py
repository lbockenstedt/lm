"""``/admin/ops/endpoint-sync`` — operator one-off IPAM -> CPPM endpoint sync.

``allow_mass_remove`` must only reach the sync when the operator sends a
literal ``true``; anything else keeps the CPPM 50% removal guard in place.
"""
import asyncio
import os
import tempfile

import pytest
from fastapi import HTTPException

from routes import admin_ops

from test_admin_ops_guard import _FakeApp, _FakeRequest, _State


class _Hub:
    def __init__(self, data_dir):
        self.state = _State(data_dir)
        self.active_connections = {}
        self.calls = []

    def _primary_key(self, spoke_id):
        return spoke_id

    async def sync_tenant_endpoints(self, tenant_id, allow_mass_remove=False):
        self.calls.append((tenant_id, allow_mass_remove))
        return {"tenant_id": tenant_id, "status": "success"}


def _run(body):
    with tempfile.TemporaryDirectory() as tmp:
        app = _FakeApp()
        hub = _Hub(tmp)
        admin_ops.register(app, hub, ctx=None)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        req = _FakeRequest("127.0.0.1", tok)
        req.url = type("U", (), {"path": "/admin/ops/endpoint-sync"})()

        async def _json():
            return body
        req.json = _json
        route = app.routes[("POST", "/admin/ops/endpoint-sync")]
        out = asyncio.new_event_loop().run_until_complete(route(req))
        return out, hub


def test_allow_mass_remove_passed_when_true():
    out, hub = _run({"tenant_id": "lrb", "allow_mass_remove": True})
    assert hub.calls == [("lrb", True)]
    assert out["result"]["status"] == "success"


def test_default_keeps_guard():
    _, hub = _run({"tenant_id": "lrb"})
    assert hub.calls == [("lrb", False)]


def test_truthy_string_does_not_bypass_guard():
    _, hub = _run({"tenant_id": "lrb", "allow_mass_remove": "yes"})
    assert hub.calls == [("lrb", False)]


def test_tenant_required():
    with pytest.raises(HTTPException) as ei:
        _run({})
    assert ei.value.status_code == 400
