"""The loopback admin-ops API (`/admin/ops/*`) must be reachable ONLY from a
loopback peer AND only with the root-minted bearer token. Pin both gates plus
the mint-once-0600 token behaviour, so a regression can't silently expose these
privileged, side-effecting routes off-box or tokenless."""
import os
import stat
import asyncio
import tempfile

import pytest
from fastapi import HTTPException

from routes import admin_ops


class _FakeApp:
    """Captures the handlers register() attaches, keyed by path."""
    def __init__(self):
        self.routes = {}

    def get(self, path):
        def deco(fn):
            self.routes[("GET", path)] = fn
            return fn
        return deco

    def post(self, path):
        def deco(fn):
            self.routes[("POST", path)] = fn
            return fn
        return deco


class _State:
    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.system_state = {}


class _FakeHub:
    def __init__(self, data_dir):
        self.state = _State(data_dir)
        self.active_connections = {}


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, host, token=None):
        self.client = _FakeClient(host)
        self.headers = {"x-lm-admin-token": token} if token is not None else {}
        self.url = type("U", (), {"path": "/admin/ops/ping"})()


def _register(tmp):
    app = _FakeApp()
    hub = _FakeHub(tmp)
    admin_ops.register(app, hub, ctx=None)
    return app, hub


def test_token_minted_0600_on_register():
    with tempfile.TemporaryDirectory() as tmp:
        _register(tmp)
        path = os.path.join(tmp, "admin_ops_token")
        assert os.path.exists(path)
        assert os.stat(path).st_mode & 0o777 == 0o600
        assert open(path).read().strip()  # non-empty


def test_ping_ok_with_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, _ = _register(tmp)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        ping = app.routes[("GET", "/admin/ops/ping")]
        out = asyncio.run(ping(_FakeRequest("127.0.0.1", tok)))
        assert out["status"] == "ok"


def test_rejects_non_loopback_peer():
    with tempfile.TemporaryDirectory() as tmp:
        app, _ = _register(tmp)
        tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
        ping = app.routes[("GET", "/admin/ops/ping")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(ping(_FakeRequest("10.0.0.5", tok)))
        assert ei.value.status_code == 403


def test_rejects_missing_or_wrong_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, _ = _register(tmp)
        ping = app.routes[("GET", "/admin/ops/ping")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(ping(_FakeRequest("127.0.0.1", None)))
        assert ei.value.status_code == 403
        with pytest.raises(HTTPException) as ei2:
            asyncio.run(ping(_FakeRequest("127.0.0.1", "nope")))
        assert ei2.value.status_code == 403


def test_env_token_overrides_file(monkeypatch):
    monkeypatch.setenv("LM_ADMIN_OPS_TOKEN", "env-secret-123")
    with tempfile.TemporaryDirectory() as tmp:
        app, _ = _register(tmp)
        ping = app.routes[("GET", "/admin/ops/ping")]
        out = asyncio.run(ping(_FakeRequest("::1", "env-secret-123")))
        assert out["status"] == "ok"
