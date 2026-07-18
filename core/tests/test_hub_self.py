"""Tests for the hub-self routing helpers added in agent-rework #5 / Phase 4
(``HubCertDistributionMixin._hub_self_write`` / ``_hub_self_restart``).

These verify the routing + fallback contract WITHOUT spinning up the real
loopback WS or the real ``_install_cert_on_hub`` (which needs a valid cert pair
for its ssl-context validation):

* cert/key writes route to the in-process hub-self agent's ``WRITE_FILE``;
* a non-SUCCESS agent response (or no ``_hub_self`` at all) falls back to the
  direct inline atomic write — identical to what the agent would have run;
* ``lm-self-restart`` routes to the agent's ``RUN_COMMAND`` BACKGROUNDED (so the
  agent responds before the restart kills the hub), with a direct
  ``subprocess.Popen`` fallback when the agent is absent.

The full ``_install_cert_on_hub`` path (cert validation → these helpers) is
covered end-to-end in the lab (3.10+); here we pin the helper contract.
"""
import asyncio
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_cert_distribution import HubCertDistributionMixin, _LM_SELF_RESTART  # noqa: E402


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeHubSelf:
    """Stand-in for ``HubSelfControlPlane`` — records calls, returns canned
    AGENT_RESPONSE data dicts (``{status, result, message}``)."""

    def __init__(self, write_resp=None, run_resp=None):
        self.write_calls = []
        self.run_calls = []
        self._write_resp = write_resp or {"status": "SUCCESS", "result": {"ok": True}}
        self._run_resp = run_resp or {"status": "SUCCESS"}

    async def write_file(self, path, content, mode=0o600, timeout=20.0):
        self.write_calls.append({"path": path, "content": content, "mode": mode})
        return self._write_resp

    async def run_command(self, command, allow_shell=True, timeout=10.0):
        self.run_calls.append({"command": command, "allow_shell": allow_shell})
        return self._run_resp


class _Distro(HubCertDistributionMixin):
    """Minimal host carrying the two helpers + an injectable ``_atomic_write``
    (the mixin's is a staticmethod; an instance attr overrides it for tests)."""

    def __init__(self, hub_self=None, atomic=None):
        self._hub_self = hub_self
        if atomic is not None:
            self._atomic_write = atomic


# ── _hub_self_write ──────────────────────────────────────────────────────────

def test_hub_self_write_routes_to_agent():
    fake = _FakeHubSelf()
    atomic = []
    d = _Distro(hub_self=fake, atomic=lambda p, c, m: atomic.append((p, c, m)))
    ok = _run(d._hub_self_write("/opt/lm/tls/fullchain.pem", "DATA", 0o644))
    assert ok is True
    assert fake.write_calls == [{"path": "/opt/lm/tls/fullchain.pem",
                                 "content": "DATA", "mode": 0o644}]
    assert atomic == []          # no fallback when the agent succeeds


def test_hub_self_write_falls_back_on_agent_error():
    fake = _FakeHubSelf(write_resp={"status": "ERROR", "message": "agent down"})
    atomic = []
    d = _Distro(hub_self=fake, atomic=lambda p, c, m: atomic.append((p, c, m)))
    ok = _run(d._hub_self_write("/opt/lm/tls/privkey.pem", "KEY", 0o600))
    assert ok is True
    assert atomic == [("/opt/lm/tls/privkey.pem", "KEY", 0o600)]


def test_hub_self_write_falls_back_when_no_hub_self():
    atomic = []
    d = _Distro(hub_self=None, atomic=lambda p, c, m: atomic.append((p, c, m)))
    ok = _run(d._hub_self_write("/x/y", "C", 0o600))
    assert ok is True
    assert atomic == [("/x/y", "C", 0o600)]


def test_hub_self_write_direct_failure_returns_false():
    def boom(p, c, m):
        raise OSError("disk full")
    d = _Distro(hub_self=None, atomic=boom)
    ok = _run(d._hub_self_write("/x/y", "C", 0o600))
    assert ok is False


# ── _hub_self_restart ────────────────────────────────────────────────────────

def test_hub_self_restart_routes_to_agent_backgrounded(monkeypatch):
    # Guard: a stray Popen must NOT fire when the agent handles the restart.
    popped = []
    monkeypatch.setattr("hub_cert_distribution.subprocess.Popen",
                        lambda *a, **k: popped.append((a, k)))
    fake = _FakeHubSelf(run_resp={"status": "SUCCESS"})
    d = _Distro(hub_self=fake, atomic=lambda *a: None)
    msg = _run(d._hub_self_restart())
    assert msg == "lm.service restarting to apply"
    assert fake.run_calls, "RUN_COMMAND should have been issued to the agent"
    cmd = fake.run_calls[0]["command"]
    assert "sudo -n" in cmd and _LM_SELF_RESTART in cmd
    assert cmd.rstrip().endswith("&"), "restart must be backgrounded (avoid await-then-kill)"
    assert fake.run_calls[0]["allow_shell"] is True
    assert popped == []         # no direct fallback when the agent succeeds


def test_hub_self_restart_falls_back_to_popen(monkeypatch):
    popped = []
    monkeypatch.setattr("hub_cert_distribution.subprocess.Popen",
                        lambda *a, **k: popped.append((a, k)))
    d = _Distro(hub_self=None, atomic=lambda *a: None)
    msg = _run(d._hub_self_restart())
    assert msg == "lm.service restarting to apply"
    assert popped and popped[0][0] == (["sudo", "-n", _LM_SELF_RESTART],) \
        and popped[0][1] == {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}


def test_hub_self_restart_fallback_failure_message(monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("no sudo")
    monkeypatch.setattr("hub_cert_distribution.subprocess.Popen", _boom)
    d = _Distro(hub_self=None, atomic=lambda *a: None)
    msg = _run(d._hub_self_restart())
    assert "could not schedule self-restart" in msg