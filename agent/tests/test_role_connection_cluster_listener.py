"""``RoleConnection`` service-cluster listener gating (dns / dhcp roles).

The dns and dhcp roles now host their own service workers (two Unbound
resolvers, a two-node Kea HA pair) on the SAME inherited ``/ws/agent`` listener
pxmx/cs use. Two things must hold or a generic agent regresses:

1. **Distinct ports and config paths.** dns 8769 / dhcp 8770, never pxmx's 8766
   or cs's 8767/443, and never the shared ``/etc/lm-agent/config.json`` PSK — so
   both roles can be co-loaded and a resolver worker's secret is not the pxmx
   node-agent's secret.
2. **Off unless a cluster exists.** A single-host dns/dhcp role must bind
   nothing at all, exactly as before this feature. The env flag is the only
   override.
"""
import os

import pytest

import control_plane as cp_module
from control_plane import _CLUSTER_ROLE_LISTENERS


class _FakeModule:
    def __init__(self, required):
        self._required = required

    def cluster_listener_required(self):
        return self._required


def _role_conn(role_name, module=None, monkeypatch=None):
    """A RoleConnection with __init__ bypassed — this test is about the
    listener knobs + gating, not the hub connection."""
    conn = cp_module.RoleConnection.__new__(cp_module.RoleConnection)
    conn.role_name = role_name
    conn.modules = {role_name: module} if module is not None else {}
    conn.hub_url = "wss://hub.example.com:443"
    for attr, value in _CLUSTER_ROLE_LISTENERS.get(role_name, {}).items():
        setattr(conn, attr, value)
    return conn


def test_dns_and_dhcp_get_distinct_ports_and_config_paths():
    dns = _CLUSTER_ROLE_LISTENERS["dns"]
    dhcp = _CLUSTER_ROLE_LISTENERS["dhcp"]
    assert dns["AGENT_WSS_PORT"] == 8769 and dhcp["AGENT_WSS_PORT"] == 8770
    for spec in (dns, dhcp):
        ports = {spec["AGENT_WSS_PORT"], spec["AGENT_LOOPBACK_PORT"],
                 spec["AGENT_FALLBACK_PORT"]}
        assert ports.isdisjoint({443, 8443, 8765, 8766, 8767, 8768}), \
            "a cluster role must not collide with the hub/pxmx/cs/hub-self ports"
    assert dns["AGENT_CONFIG_PATH"] != dhcp["AGENT_CONFIG_PATH"]
    assert "/etc/lm-agent/" not in dns["AGENT_CONFIG_PATH"], \
        "the worker PSK must not be the shared pxmx/cs node-agent secret"
    assert "/etc/lm-agent/" not in dhcp["AGENT_CONFIG_PATH"]
    assert dns["AGENT_PORT_ENV"] != dhcp["AGENT_PORT_ENV"]


def test_knobs_are_applied_to_the_instance():
    conn = _role_conn("dhcp")
    assert conn.AGENT_PORT_ENV == "LM_DHCP_AGENT_PORT"
    assert conn.AGENT_WSS_PORT == 8770
    assert conn.AGENT_CONFIG_PATH == "/etc/lm-dhcp/agent.json"


@pytest.mark.parametrize("role", ["dns", "dhcp"])
def test_single_host_role_binds_nothing(role, monkeypatch):
    monkeypatch.delenv(_CLUSTER_ROLE_LISTENERS[role]["AGENT_LISTENER_ENV"],
                       raising=False)
    conn = _role_conn(role, _FakeModule(False))
    assert conn._agent_listener_enabled() is False


@pytest.mark.parametrize("role", ["dns", "dhcp"])
def test_role_with_no_module_yet_binds_nothing(role, monkeypatch):
    monkeypatch.delenv(_CLUSTER_ROLE_LISTENERS[role]["AGENT_LISTENER_ENV"],
                       raising=False)
    assert _role_conn(role)._agent_listener_enabled() is False


@pytest.mark.parametrize("role", ["dns", "dhcp"])
def test_clustered_role_enables_the_listener(role, monkeypatch):
    monkeypatch.delenv(_CLUSTER_ROLE_LISTENERS[role]["AGENT_LISTENER_ENV"],
                       raising=False)
    conn = _role_conn(role, _FakeModule(True))
    assert conn._agent_listener_enabled() is True


@pytest.mark.parametrize("role", ["dns", "dhcp"])
def test_env_flag_overrides_in_both_directions(role, monkeypatch):
    env = _CLUSTER_ROLE_LISTENERS[role]["AGENT_LISTENER_ENV"]
    monkeypatch.setenv(env, "1")
    assert _role_conn(role, _FakeModule(False))._agent_listener_enabled() is True
    monkeypatch.setenv(env, "off")
    assert _role_conn(role, _FakeModule(True))._agent_listener_enabled() is False


def test_other_roles_are_unaffected(monkeypatch):
    """The pre-existing gating (pxmx always on, everything else off) must not
    change just because dns/dhcp learned to host workers."""
    assert _role_conn("proxmox")._agent_listener_enabled() is True
    for role in ("ldap", "netbox", "network", "le"):
        assert _role_conn(role, _FakeModule(True))._agent_listener_enabled() is False, \
            f"{role} must never bind a port"


def test_cs_role_gating_is_unchanged(monkeypatch):
    monkeypatch.delenv("LM_CS_AGENT_LISTENER", raising=False)
    conn = _role_conn("simulation")
    conn.AGENT_LISTENER_ENV = "LM_CS_AGENT_LISTENER"
    conn.hub_url = "wss://localhost:443"          # colocated → suppressed
    assert conn._agent_listener_enabled() is False
    conn.hub_url = "wss://172.16.1.31:443"        # standalone → on
    assert conn._agent_listener_enabled() is True


def test_service_worker_install_args_are_only_added_when_complete():
    """A dns-server/dhcp-server deploy with no cluster config must produce the
    byte-identical command it produced before this feature."""
    from agent_spoke import GenericAgent
    build = GenericAgent._service_worker_install_args
    assert build({}) == ""
    assert build({"member_id": "dns-a"}) == ""
    assert build({"member_id": "dns-a", "coordinator": "10.0.1.9"}) == ""
    out = build({"member_id": "dns-a", "coordinator": "10.0.1.9",
                 "worker_secret": "p s k"})
    assert out == " --member-id dns-a --coordinator 10.0.1.9 --worker-secret 'p s k'"


# ── Unloading a cluster role must free its port + loops (review #11) ────────

class _FakeTask:
    """Minimal awaitable task stand-in that records cancel()/await."""

    def __init__(self):
        self.cancelled = False
        self.awaited = False
        self._done = False

    def done(self):
        return self._done

    def cancel(self):
        self.cancelled = True

    def __await__(self):
        self.awaited = True
        self._done = True
        yield from ()
        return None


class _ClusterModule:
    def __init__(self):
        self.stopped = 0
        self.loop_task = _FakeTask()
        self.api_stopped = 0

    def cluster_listener_required(self):
        return True

    def stop_background_loops(self):
        self.stopped += 1
        return self.loop_task

    def stop_client_api_server(self):
        self.api_stopped += 1


def test_shutdown_cancels_the_listener_and_the_module_loops():
    """REGRESSION: unloading only cancelled the run() task, so the cluster port
    stayed bound and the reconcile loop kept pushing to workers."""
    import asyncio

    module = _ClusterModule()
    conn = _role_conn("dns", module)
    server = _FakeTask()
    conn._agent_server_task = server

    asyncio.run(conn.shutdown())

    assert module.stopped == 1
    assert module.loop_task.cancelled is False, \
        "the module cancels its own task; shutdown only awaits it"
    assert module.loop_task.awaited is True
    assert server.cancelled is True and server.awaited is True
    assert conn._agent_server_task is None, "the port must be released"


def test_shutdown_is_safe_for_a_role_with_no_listener_or_loops():
    import asyncio

    conn = _role_conn("ldap")
    conn._agent_server_task = None
    asyncio.run(conn.shutdown())     # must not raise


def test_shutdown_survives_a_module_whose_stop_hook_raises():
    import asyncio

    class _Broken(_ClusterModule):
        def stop_background_loops(self):
            raise RuntimeError("module is broken")

    conn = _role_conn("dhcp", _Broken())
    server = _FakeTask()
    conn._agent_server_task = server
    asyncio.run(conn.shutdown())
    assert server.cancelled is True, \
        "a broken module must not strand the listener port"


def test_stop_role_awaits_the_connection_shutdown():
    """The unload path must reach shutdown(), or the port is never released."""
    import asyncio

    import agent_spoke as agent_spoke_module

    calls = []

    class _Conn:
        spoke_id = "agent-1-dns"
        _hub_ws = None

        async def shutdown(self):
            calls.append("shutdown")

    class _RunTask:
        def cancel(self):
            calls.append("cancel")

        def __await__(self):
            yield from ()
            return None

    agent = agent_spoke_module.GenericAgent.__new__(agent_spoke_module.GenericAgent)
    agent._roles = {"dns": {"conn": _Conn(), "task": _RunTask(), "instance": None}}
    agent._persist_loaded_roles = lambda **_kw: calls.append("persist")

    asyncio.run(agent._stop_role("dns"))

    assert calls == ["cancel", "shutdown", "persist"], calls
    assert "dns" not in agent._roles


# ── Review round 2, #1: cluster listeners require TLS ──────────────────────

@pytest.mark.parametrize("role", ["dns", "dhcp"])
def test_cluster_roles_require_tls_on_the_listener(role):
    """REGRESSION: a cert-less cluster listener must leave the port CLOSED, not
    fall back to plaintext on 0.0.0.0 where the worker PSK would be published."""
    assert _CLUSTER_ROLE_LISTENERS[role]["AGENT_LISTENER_REQUIRE_TLS"] is True
    conn = _role_conn(role, _FakeModule(True))
    assert conn.AGENT_LISTENER_REQUIRE_TLS is True


def test_pxmx_and_cs_keep_their_plaintext_fallback():
    """The requirement is opt-in per role; existing cert-less pxmx/cs installs
    are untouched."""
    from core.src.messaging.agent_hosting import AgentHostingControlPlane
    assert AgentHostingControlPlane.AGENT_LISTENER_REQUIRE_TLS is False
    assert "AGENT_LISTENER_REQUIRE_TLS" not in _CLUSTER_ROLE_LISTENERS.get(
        "simulation", {})


# ── Review round 2, #3: deploy args forward the HA + trust material ────────

def test_service_worker_install_args_forward_the_ha_material():
    from agent_spoke import GenericAgent
    build = GenericAgent._service_worker_install_args
    out = build({"member_id": "kea-a", "coordinator": "10.0.1.9",
                 "worker_secret": "psk", "ca_cert": "/etc/lm/co.pem",
                 "ha_user": "kea-ha", "ha_password": "p a s s",
                 "ha_ca": "/etc/kea/ha-tls/ha-ca.pem",
                 "ha_cert": "/etc/kea/ha-tls/node.crt",
                 "ha_key": "/etc/kea/ha-tls/node.key",
                 "ha_peers": ["10.0.1.10", "10.0.1.11"]})
    assert " --ca-cert /etc/lm/co.pem" in out
    assert " --ha-user kea-ha" in out
    assert " --ha-password 'p a s s'" in out
    assert " --ha-ca /etc/kea/ha-tls/ha-ca.pem" in out
    assert " --ha-cert /etc/kea/ha-tls/node.crt" in out
    assert " --ha-key /etc/kea/ha-tls/node.key" in out
    assert out.count(" --ha-peer ") == 2
    assert " --ha-peer 10.0.1.10" in out and " --ha-peer 10.0.1.11" in out


def test_ha_peers_accept_a_comma_separated_string():
    from agent_spoke import GenericAgent
    out = GenericAgent._service_worker_install_args(
        {"member_id": "kea-a", "coordinator": "h", "worker_secret": "s",
         "ha_peer": "10.0.1.10, 10.0.1.11"})
    assert out.count(" --ha-peer ") == 2


def test_no_cluster_config_still_produces_the_legacy_command():
    from agent_spoke import GenericAgent
    assert GenericAgent._service_worker_install_args({}) == ""


# ── Review round 2, #13: unload stops the worker + HA units ────────────────

def test_deploy_role_extra_units_cover_the_cluster_sidecars():
    from agent_spoke import _DEPLOY_ROLE_EXTRA_UNITS, _DEPLOY_ROLE_UNITS
    assert _DEPLOY_ROLE_EXTRA_UNITS["dns-server"] == ("lm-dns-worker",)
    assert _DEPLOY_ROLE_EXTRA_UNITS["dhcp-server"] == ("lm-dhcp-worker",
                                                       "kea-ha-agent")
    # They must NOT be part of the active-probe set: a single-host node has none
    # of them and would otherwise be reported inactive.
    for role, extra in _DEPLOY_ROLE_EXTRA_UNITS.items():
        assert not set(extra) & set(_DEPLOY_ROLE_UNITS[role])


def test_unload_dhcp_server_stops_the_worker_and_ha_agent(monkeypatch):
    import asyncio
    import types

    import agent_spoke as agent_spoke_module
    from agent_spoke import GenericAgent

    agent = GenericAgent("agent-1", {})
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(agent_spoke_module.subprocess, "run", run)
    result = asyncio.run(
        agent.handle_command("UNLOAD_ROLE", {"role": "dhcp-server"}))
    assert result["status"] == "SUCCESS"
    assert calls == [
        ["systemctl", "disable", "--now", "lm-dhcp-worker", "kea-ha-agent"],
        ["systemctl", "disable", "--now", "kea-dhcp4-server", "kea-ctrl-agent"],
    ]


# ── Round 4, #3: co-loaded roles get their own TLS material ───────────────

@pytest.mark.parametrize("role,cert_env,key_env", [
    ("dns", "LM_DNS_TLS_CERT", "LM_DNS_TLS_KEY"),
    ("dhcp", "LM_DHCP_TLS_CERT", "LM_DHCP_TLS_KEY"),
])
def test_each_cluster_role_declares_its_own_tls_env(role, cert_env, key_env):
    assert _CLUSTER_ROLE_LISTENERS[role]["AGENT_TLS_CERT_ENV"] == cert_env
    assert _CLUSTER_ROLE_LISTENERS[role]["AGENT_TLS_KEY_ENV"] == key_env
    conn = _role_conn(role, _FakeModule(True))
    assert conn.AGENT_TLS_CERT_ENV == cert_env
    assert conn.AGENT_TLS_KEY_ENV == key_env


def test_the_two_cluster_roles_never_share_tls_material():
    dns = _CLUSTER_ROLE_LISTENERS["dns"]
    dhcp = _CLUSTER_ROLE_LISTENERS["dhcp"]
    assert dns["AGENT_TLS_CERT_ENV"] != dhcp["AGENT_TLS_CERT_ENV"]
    assert dns["AGENT_TLS_KEY_ENV"] != dhcp["AGENT_TLS_KEY_ENV"]
    # ...and their cert dirs follow their (already distinct) config paths.
    assert dns["AGENT_CONFIG_PATH"] != dhcp["AGENT_CONFIG_PATH"]
