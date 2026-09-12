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


# ── Self-service ops added for the Kea HA-TLS deploy-verification loop:
# /admin/ops/restart-service (restart a unit without an off-box shell/Azure
# round-trip) and /admin/ops/force-dhcp-dns-sync (force an immediate NetBox
# reconcile instead of waiting on the loop's skip-if-unchanged hash cache).

class _SyncHub(_RelayHub):
    """Adds the dns_dhcp_sync surface restart-service/force-sync touch."""
    def __init__(self, data_dir, connected=("cs-svr-06",)):
        super().__init__(data_dir, connected=connected)
        self._last_sync_hashes = {"dns": "stale", "dhcp": "stale"}
        self.synced = 0
        self._dns_dhcp_sync_status = {
            "dns": {"status": "ok"}, "dhcp": {"status": "ok"}}

    async def _sync_dns_dhcp_once(self):
        self.synced += 1
        # Prove the hash cache really was reset before this ran.
        assert self._last_sync_hashes == {}
        self._dns_dhcp_sync_status = {
            "dns": {"status": "ok", "records_synced": 3},
            "dhcp": {"status": "ok", "subnets_synced": 1}}

    @property
    def dns_dhcp_sync_status(self):
        return self._dns_dhcp_sync_status


def _reg_sync(tmp, **kw):
    app = _FakeApp()
    hub = _SyncHub(tmp, **kw)
    admin_ops.register(app, hub, ctx=None)
    tok = open(os.path.join(tmp, "admin_ops_token")).read().strip()
    return app, hub, tok


def test_force_dhcp_dns_sync_resets_hash_cache_and_runs_once():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_sync(tmp)
        fn = app.routes[("POST", "/admin/ops/force-dhcp-dns-sync")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {})))
        assert out["status"] == "ok"
        assert hub.synced == 1
        assert out["dhcp"]["subnets_synced"] == 1


def test_force_dhcp_dns_sync_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_sync(tmp)
        fn = app.routes[("POST", "/admin/ops/force-dhcp-dns-sync")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("10.0.0.5", tok, {})))
        assert ei.value.status_code == 403


def test_restart_service_spoke_relays_systemctl_restart_no_shell():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/restart-service")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
            "target": "cs-svr-06", "unit": "lm-dhcp-worker"})))
        assert out["status"] == "ok"
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "RUN_COMMAND"
        assert data["allow_shell"] is False
        assert data["command"] == "systemctl restart lm-dhcp-worker"


def test_restart_service_rejects_unknown_unit():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/restart-service")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
                "target": "cs-svr-06", "unit": "sshd"})))
        assert ei.value.status_code == 400


def test_restart_service_hub_only_supports_unit_lm():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/restart-service")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
                "target": "hub", "unit": "lm-dhcp-worker"})))
        assert ei.value.status_code == 400


def test_restart_service_hub_uses_sudo_self_restart_helper(monkeypatch):
    import subprocess as _subprocess
    calls = []

    class _Proc:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(argv, **kw):
        calls.append(argv)
        return _Proc()

    monkeypatch.setattr(_subprocess, "run", _fake_run)
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/restart-service")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
            "target": "hub", "unit": "lm"})))
        assert out["status"] == "ok"
        assert calls[-1] == ["sudo", "-n", "/usr/local/bin/lm-self-restart"]


def test_restart_service_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/restart-service")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("10.0.0.5", tok, {
                "target": "cs-svr-06", "unit": "lm-agent"})))
        assert ei.value.status_code == 403


# ── unload-role: no WebUI affordance for a role loaded outside the caller's
# tenant (e.g. a stray dhcp role picked up by get_spoke_by_type("dhcp") ahead
# of the real cluster) ───────────────────────────────────────────────────────

def test_unload_role_relays_unload_role_rpc():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/unload-role")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
            "spoke_id": "cs-svr-06", "role": "dhcp"})))
        assert out["status"] == "ok"
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "UNLOAD_ROLE"
        assert data["role"] == "dhcp"


def test_unload_role_requires_spoke_id_and_role():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/unload-role")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {"spoke_id": "cs-svr-06"})))
        assert ei.value.status_code == 400
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {"role": "dhcp"})))
        assert ei.value.status_code == 400


def test_unload_role_rejects_disconnected_spoke():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/unload-role")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
                "spoke_id": "not-connected-agent", "role": "dhcp"})))
        assert ei.value.status_code == 503


def test_unload_role_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/unload-role")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("10.0.0.5", tok, {
                "spoke_id": "cs-svr-06", "role": "dhcp"})))
        assert ei.value.status_code == 403


# ── clear-deploy-status: force-dismiss a stuck deploy-role badge (e.g.
# "NetBox Server: failed") when the WebUI's own × button is unreachable or
# the badge keeps reappearing ────────────────────────────────────────────────

def test_clear_deploy_status_relays_clear_deploy_status_rpc():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/clear-deploy-status")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
            "spoke_id": "cs-svr-06", "role": "netbox-server"})))
        assert out["status"] == "ok"
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "CLEAR_DEPLOY_STATUS"
        assert data["role"] == "netbox-server"


def test_clear_deploy_status_requires_spoke_id_and_role():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/clear-deploy-status")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {"spoke_id": "cs-svr-06"})))
        assert ei.value.status_code == 400
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {"role": "netbox-server"})))
        assert ei.value.status_code == 400


def test_clear_deploy_status_rejects_disconnected_spoke():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/clear-deploy-status")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
                "spoke_id": "not-connected-agent", "role": "netbox-server"})))
        assert ei.value.status_code == 503


def test_clear_deploy_status_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/clear-deploy-status")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("10.0.0.5", tok, {
                "spoke_id": "cs-svr-06", "role": "netbox-server"})))
        assert ei.value.status_code == 403


# ── dhcp-diagnostics: force a DHCP module's Kea diagnostics (and its
# self-heal side effect) to run immediately via loopback, bypassing the
# session-authenticated /api/dhcp/diagnostics when the operator is locked
# out ─────────────────────────────────────────────────────────────────────

def test_dhcp_diagnostics_relays_dhcp_diagnostics_rpc():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/dhcp-diagnostics")]
        out = asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
            "spoke_id": "cs-svr-06"})))
        assert out["status"] == "ok"
        sid, cmd, data = hub.relayed[-1]
        assert sid == "cs-svr-06" and cmd == "DHCP_DIAGNOSTICS"
        assert data == {}


def test_dhcp_diagnostics_requires_spoke_id():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/dhcp-diagnostics")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {})))
        assert ei.value.status_code == 400


def test_dhcp_diagnostics_rejects_disconnected_spoke():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/dhcp-diagnostics")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("127.0.0.1", tok, {
                "spoke_id": "not-connected-agent"})))
        assert ei.value.status_code == 503


def test_dhcp_diagnostics_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("POST", "/admin/ops/dhcp-diagnostics")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_BodyRequest("10.0.0.5", tok, {
                "spoke_id": "cs-svr-06"})))
        assert ei.value.status_code == 403


def test_dhcp_ha_status_no_spoke_returns_disabled():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        hub.get_spoke_by_type = lambda t: None
        fn = app.routes[("GET", "/admin/ops/dhcp-ha-status")]
        out = asyncio.run(fn(_FakeRequest("127.0.0.1", tok)))
        assert out["enabled"] is False


def test_dhcp_ha_status_relays_dhcp_ha_status_rpc():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        hub.get_spoke_by_type = lambda t: "cs-svr-06" if t == "dhcp" else None

        async def _rr(sid, cmd, data, timeout=None):
            assert sid == "cs-svr-06" and cmd == "DHCP_HA_STATUS"
            return {"payload": {"data": {"status": "SUCCESS", "enabled": True,
                                        "members": ["a", "b"]}}}
        hub.request_response = _rr
        fn = app.routes[("GET", "/admin/ops/dhcp-ha-status")]
        out = asyncio.run(fn(_FakeRequest("127.0.0.1", tok)))
        assert out["status"] == "ok"
        assert out["result"]["enabled"] is True


def test_dhcp_ha_status_enforces_loopback_and_token():
    with tempfile.TemporaryDirectory() as tmp:
        app, hub, tok = _reg_relay(tmp)
        fn = app.routes[("GET", "/admin/ops/dhcp-ha-status")]
        with pytest.raises(HTTPException) as ei:
            asyncio.run(fn(_FakeRequest("10.0.0.5", tok)))
        assert ei.value.status_code == 403
