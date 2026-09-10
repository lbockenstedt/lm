"""``AgentHostingControlPlane`` service-cluster helpers.

Three behaviors the clustered dns/dhcp modules depend on:

* ``_cluster_listener_required`` asks the HOSTED MODULE whether a multi-host
  cluster exists, so enabling a cluster at runtime is enough — no env flag, no
  restart, and a single-host module never opens a port.
* ``set_agent_secret`` replaces + persists the listener PSK (0600) so the same
  value can be handed to each service worker's installer.
* ``ensure_cluster_listener`` mints the PSK when needed and rebinds, so a
  freshly-configured cluster becomes reachable without a restart.
"""

import asyncio
import json
import os
import stat

import pytest

from messaging.agent_hosting import AgentHostingControlPlane


class _Plane(AgentHostingControlPlane):
    MODULE_TYPE = "dns"
    AGENT_PORT_ENV = "LM_TEST_AH_PORT"
    AGENT_LOOPBACK_ENV = "LM_TEST_AH_LOOPBACK"
    AGENT_LISTENER_ENV = "LM_TEST_AH_LISTENER"
    AGENT_LISTENER_OPT_IN = True

    def _agent_listener_enabled(self):
        return self._cluster_listener_required()


class _Module:
    def __init__(self, required):
        self._required = required

    def cluster_listener_required(self):
        if self._required == "boom":
            raise RuntimeError("module is broken")
        return self._required


def _plane(tmp_path, module=None):
    plane = _Plane.__new__(_Plane)
    plane.AGENT_CONFIG_PATH = str(tmp_path / "agent.json")
    plane.config = {}
    plane.agent_secret = None
    plane.modules = {}
    from security.signer import MessageSigner
    plane.agent_signer = MessageSigner("")
    plane._agent_server_task = None
    plane._agent_server_ready = None
    plane._agent_server_error = ""
    plane._agent_server_endpoint = ""
    if module is not None:
        plane.modules["dns"] = module
    return plane


def test_no_module_means_no_listener(tmp_path):
    assert _plane(tmp_path)._cluster_listener_required() is False


def test_a_single_host_module_does_not_ask_for_a_listener(tmp_path):
    assert _plane(tmp_path, _Module(False))._cluster_listener_required() is False


def test_a_clustered_module_asks_for_a_listener(tmp_path):
    assert _plane(tmp_path, _Module(True))._cluster_listener_required() is True


def test_a_module_without_the_hook_is_ignored(tmp_path):
    plane = _plane(tmp_path)
    plane.modules["other"] = object()
    assert plane._cluster_listener_required() is False


def test_a_broken_module_never_causes_a_port_to_be_bound(tmp_path):
    plane = _plane(tmp_path, _Module("boom"))
    assert plane._cluster_listener_required() is False


def test_set_agent_secret_persists_0600_and_rekeys_the_signer(tmp_path):
    plane = _plane(tmp_path)
    assert plane.set_agent_secret("worker-psk") is True
    assert plane.agent_secret == "worker-psk"
    path = tmp_path / "agent.json"
    assert json.loads(path.read_text())["agent_secret"] == "worker-psk"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # The signer must be rebuilt, or frames signed with the old key are dropped.
    frame = plane.agent_signer.encode_frame({"payload": {"type": "X", "data": {}}})
    sig, body = frame.split(".", 1)
    assert plane.agent_signer.verify_bytes(body.encode(), sig)


def test_set_agent_secret_ignores_an_empty_value(tmp_path):
    plane = _plane(tmp_path)
    plane.set_agent_secret("keep-me")
    assert plane.set_agent_secret("   ") is False
    assert plane.agent_secret == "keep-me"


def test_ensure_cluster_listener_mints_a_secret_when_a_cluster_appears(tmp_path):
    """It now WAITS for readiness and returns a structured verdict (round 3,
    #2), so a bind/TLS failure can no longer surface after a reported success."""
    plane = _plane(tmp_path, _Module(True))
    rebinds = []

    def _rebind():
        # Stand in for a listener that came up: signal readiness the way
        # run_agent_server does once the socket is actually serving.
        plane._agent_server_endpoint = "wss://0.0.0.0:8769"
        plane._signal_listener_failure()
        return _noop(rebinds)

    plane._rebind_agent_server = _rebind
    plane._provision_listener_cert = lambda: None
    result = asyncio.run(plane.ensure_cluster_listener(timeout=2.0))
    assert result["ok"] is True and result["serving"] is True
    assert result["endpoint"] == "wss://0.0.0.0:8769"
    assert plane.agent_secret, "a listener without a PSK can never authenticate a worker"
    assert json.loads((tmp_path / "agent.json").read_text())["agent_secret"]
    assert rebinds == [1]


def test_ensure_cluster_listener_reports_a_listener_that_never_came_up(tmp_path):
    plane = _plane(tmp_path, _Module(True))

    def _rebind():
        plane._agent_server_error = "could not bind 0.0.0.0:8769: address in use"
        plane._signal_listener_failure()
        return _noop([])

    plane._rebind_agent_server = _rebind
    plane._provision_listener_cert = lambda: None
    result = asyncio.run(plane.ensure_cluster_listener(timeout=2.0))
    assert result["ok"] is False and result["serving"] is False
    assert "address in use" in result["error"]


def test_ensure_cluster_listener_times_out_rather_than_claiming_success(tmp_path):
    plane = _plane(tmp_path, _Module(True))
    plane._rebind_agent_server = lambda: _noop([])   # never signals readiness
    plane._provision_listener_cert = lambda: None
    result = asyncio.run(plane.ensure_cluster_listener(timeout=0.2))
    assert result["ok"] is False
    assert "did not start" in result["error"]


def test_ensure_cluster_listener_on_a_single_host_binds_nothing(tmp_path):
    plane = _plane(tmp_path, _Module(False))
    rebinds = []
    plane._rebind_agent_server = lambda: _noop(rebinds)
    result = asyncio.run(plane.ensure_cluster_listener())
    assert result == {"ok": True, "serving": False, "endpoint": "", "error": ""}
    assert plane.agent_secret is None
    assert not (tmp_path / "agent.json").exists()


async def _noop(sink):
    sink.append(1)
