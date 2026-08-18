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


# ── Diagnostics fan-out: /admin/ops/exec + /admin/ops/spoke-diag ──────────────
# These reuse the same loopback+token _guard (covered above) and MUST relay with
# allow_shell=False so only the spoke-side command allowlist can run.

class _BodyRequest(_FakeRequest):
    """A _FakeRequest that also carries a JSON body."""
    def __init__(self, host, token=None, body=None):
        super().__init__(host, token)
        self._body = body or {}

    async def json(self):
        return self._body


class _RelayHub(_FakeHub):
    """Records the last relayed (command, data) and returns a canned result."""
    def __init__(self, data_dir, connected=("cs-svr-06",)):
        super().__init__(data_dir)
        for sid in connected:
            self.active_connections[sid] = object()
        self.relayed = []

    def _primary_key(self, sid):
        return sid

    async def request_response(self, sid, command, data, timeout=None):
        self.relayed.append((sid, command, dict(data)))
        return {"payload": {"data": {"result": {
            "ok": True, "rc": 0, "stdout": f"ran:{data.get('command')}",
            "stderr": "", "truncated": False}}}}


def _reg_relay(tmp, **kw):
    app = _FakeApp()
    hub = _RelayHub(tmp, **kw)
    admin_ops.register(app, hub, ctx=None)
    tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
    return app, hub, tok


def test_exec_spoke_relays_run_command_without_shell():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        exec_fn = app.routes[("POST", "/admin/ops/exec")]
        out = asyncio.run(exec_fn(_BodyRequest("127.0.0.1", tok, {
            "target": "cs-svr-06", "command": "systemctl is-active lm-agent"})))
        assert out["status"] == "ok"
        assert out["result"]["ok"] is True
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "RUN_COMMAND"
        assert data["allow_shell"] is False           # security-critical
        assert data["command"] == "systemctl is-active lm-agent"


def test_exec_agent_relays_agent_run_command_without_shell():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        exec_fn = app.routes[("POST", "/admin/ops/exec")]
        out = asyncio.run(exec_fn(_BodyRequest("127.0.0.1", tok, {
            "target": "agent:cs-svr-06:pxmx-01", "command": "uptime"})))
        assert out["result"]["ok"] is True
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "AGENT_RUN_COMMAND"
        assert data["agent_id"] == "pxmx-01" and data["allow_shell"] is False


def test_exec_spoke_not_connected_is_404():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        exec_fn = app.routes[("POST", "/admin/ops/exec")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(exec_fn(_BodyRequest("127.0.0.1", tok, {
                "target": "cs-svr-99", "command": "uptime"})))
        assert ei.value.status_code == 404


def test_exec_missing_command_is_400():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        exec_fn = app.routes[("POST", "/admin/ops/exec")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(exec_fn(_BodyRequest("127.0.0.1", tok, {"target": "cs-svr-06"})))
        assert ei.value.status_code == 400


def test_exec_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        exec_fn = app.routes[("POST", "/admin/ops/exec")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(exec_fn(_BodyRequest("10.0.0.5", tok, {
                "target": "cs-svr-06", "command": "uptime"})))
        assert ei.value.status_code == 403
        with pytest.raises(HTTPException) as ei2:
            asyncio.run(exec_fn(_BodyRequest("127.0.0.1", "wrong", {
                "target": "cs-svr-06", "command": "uptime"})))
        assert ei2.value.status_code == 403


def test_spoke_diag_runs_full_bundle_no_shell():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        diag_fn = app.routes[("POST", "/admin/ops/spoke-diag")]
        out = asyncio.run(diag_fn(_BodyRequest("127.0.0.1", tok, {
            "target": "cs-svr-06", "unit": "lm-agent", "lines": 25})))
        assert out["status"] == "ok"
        assert set(out["checks"].keys()) == {
            "is_active", "service_state", "git_head", "uptime", "journal", "log_tail"}
        # Every bundled command relayed with allow_shell False.
        assert all(d["allow_shell"] is False for _, _, d in hub.relayed)
        cmds = [d["command"] for _, _, d in hub.relayed]
        assert "systemctl is-active lm-agent" in cmds
        assert "journalctl -u lm-agent -n 25 --no-pager" in cmds


def test_spoke_diag_clamps_lines_and_validates_args():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        diag_fn = app.routes[("POST", "/admin/ops/spoke-diag")]
        # lines clamped to 200
        out = asyncio.run(diag_fn(_BodyRequest("127.0.0.1", tok, {
            "target": "cs-svr-06", "lines": 99999})))
        assert out["lines"] == 200
        # a unit with a shell metacharacter is rejected before any relay
        with pytest.raises(HTTPException) as ei:
            asyncio.run(diag_fn(_BodyRequest("127.0.0.1", tok, {
                "target": "cs-svr-06", "unit": "lm-agent;reboot"})))
        assert ei.value.status_code == 400
