"""``routes/agents.py::_auto_cluster_ldap_server_config`` — when a SECOND
``ldap-server`` is loaded in the same tenant as an already-installed one, the
hub should assign distinct server-ids, wire each node's peer URL, copy the
existing node's base_dn/admin_dn/admin_pw (read back from its live ``.env``
so both nodes share one bind identity), and re-push a forced ``LOAD_ROLE`` to
the existing node so the mirror is wired on BOTH sides from one action.

Explicit ``server_id``/``peers`` must never be second-guessed, and an
ambiguous (0 or 2+ peer) topology must be left untouched for manual setup.
"""
import asyncio

from routes import agents


class _State:
    def __init__(self, tenants):
        self._tenants = tenants  # {pk: tenant_id}

    def get_spoke_tenant(self, pk):
        return self._tenants.get(pk)


class _Hub:
    def __init__(self, tenants, agent_roles, connections, env_by_pk=None,
                addr_by_pk=None):
        self.state = _State(tenants)
        self._agent_roles = dict(agent_roles)
        self.active_connections = set(connections)
        self._env_by_pk = env_by_pk or {}
        self._addr_by_pk = addr_by_pk or {}
        self.relayed = []  # (target, cmd, payload)

    def _primary_key(self, sid):
        return sid

    def _agent_roles_store(self):
        return self._agent_roles

    async def request_response(self, target, cmd, payload=None, timeout=None):
        self.relayed.append((target, cmd, payload))
        if cmd == "GET_AVAILABLE_ROLES":
            addr = self._addr_by_pk.get(target)
            return {"payload": {"data": {"service_addresses": [addr] if addr else []}}}
        if cmd == "RUN_COMMAND":
            env_text = self._env_by_pk.get(target)
            if env_text is None:
                return {"payload": {"data": {"result": {"ok": False}}}}
            return {"payload": {"data": {"result": {"ok": True, "stdout": env_text}}}}
        if cmd == "LOAD_ROLE":
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected RPC {cmd}")


def _env(base_dn="dc=orange-tme,dc=com", admin_dn="cn=Administrator,dc=orange-tme,dc=com",
        admin_pw="Aruba123!", server_id="1"):
    return (
        f"LDAP_BASE_DN={base_dn}\n"
        f"LDAP_ADMIN_DN={admin_dn}\n"
        f"LDAP_ADMIN_PW={admin_pw}\n"
        f"LDAP_SERVER_ID={server_id}\n"
    )


def _no_entra(monkeypatch):
    # _enrich_ldap_server_config (called on the re-push to the peer) imports
    # security.oidc lazily; stub it out so the test doesn't need real OIDC
    # state. Uses monkeypatch.setitem so sys.modules is restored afterward —
    # a bare assignment would leak the stub into every later test in the run.
    import types
    import sys
    mod = types.ModuleType("security.oidc")
    mod.get_oidc_config = lambda hub: (_ for _ in ()).throw(RuntimeError("no oidc in test"))
    monkeypatch.setitem(sys.modules, "security.oidc", mod)


def test_first_node_in_tenant_is_untouched():
    hub = _Hub(tenants={}, agent_roles={}, connections=set())
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(hub, "svcs01", {"base_dn": "dc=x,dc=y"}))
    assert cfg == {"base_dn": "dc=x,dc=y"}
    assert hub.relayed == []  # no RPCs when there's no existing peer to detect


def test_explicit_server_id_and_peer_is_never_overridden():
    hub = _Hub(tenants={}, agent_roles={"svcs01": ["ldap-server"]}, connections={"svcs01"})
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(
        hub, "svcs02", {"server_id": "2", "peers": ["ldap://1.2.3.4:389"]}))
    assert cfg == {"server_id": "2", "peers": ["ldap://1.2.3.4:389"]}
    assert hub.relayed == []  # caller fully specified topology — no auto-detection at all


def test_second_node_same_tenant_pairs_with_existing_peer(monkeypatch):
    _no_entra(monkeypatch)
    hub = _Hub(
        tenants={"svcs01": "acme", "svcs02": "acme"},
        agent_roles={"svcs01": ["ldap-server"]},
        connections={"svcs01", "svcs02"},
        env_by_pk={"svcs01": _env(server_id="1")},
        addr_by_pk={"svcs01": "172.16.1.11", "svcs02": "172.16.1.12"},
    )
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(hub, "svcs02", {}))

    assert cfg["server_id"] == "2"
    assert cfg["peers"] == ["ldap://172.16.1.11:389"]
    assert cfg["server_url"] == "ldap://172.16.1.12:389"
    # Shared bind identity copied from the existing node's live .env, not guessed.
    assert cfg["base_dn"] == "dc=orange-tme,dc=com"
    assert cfg["admin_dn"] == "cn=Administrator,dc=orange-tme,dc=com"
    assert cfg["admin_pw"] == "Aruba123!"

    # The existing node must have been re-pushed a FORCED LOAD_ROLE pointing
    # back at the new node, with its OWN admin_pw echoed unchanged (never reset).
    load_role_calls = [p for (t, c, p) in hub.relayed if c == "LOAD_ROLE"]
    assert len(load_role_calls) == 1
    pushed = load_role_calls[0]
    assert pushed["force"] is True
    assert pushed["role"] == "ldap-server"
    assert pushed["config"]["server_id"] == "1"
    assert pushed["config"]["peers"] == ["ldap://172.16.1.12:389"]
    assert pushed["config"]["admin_pw"] == "Aruba123!"


def test_different_tenant_peer_is_ignored():
    hub = _Hub(
        tenants={"svcs01": "acme", "svcs02": "widgets"},
        agent_roles={"svcs01": ["ldap-server"]},
        connections={"svcs01", "svcs02"},
    )
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(hub, "svcs02", {}))
    assert "server_id" not in cfg
    assert hub.relayed == []  # the GET_AVAILABLE_ROLES/RUN_COMMAND probes never fire


def test_ambiguous_three_node_topology_left_manual():
    hub = _Hub(
        tenants={"svcs01": "acme", "svcs02": "acme", "svcs03": "acme"},
        agent_roles={"svcs01": ["ldap-server"], "svcs02": ["ldap-server"]},
        connections={"svcs01", "svcs02", "svcs03"},
    )
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(hub, "svcs03", {}))
    assert "server_id" not in cfg
    assert hub.relayed == []


def test_disconnected_peer_is_ignored():
    hub = _Hub(
        tenants={"svcs01": "acme", "svcs02": "acme"},
        agent_roles={"svcs01": ["ldap-server"]},
        connections={"svcs02"},  # svcs01 recorded but NOT currently connected
    )
    cfg = asyncio.run(agents._auto_cluster_ldap_server_config(hub, "svcs02", {}))
    assert "server_id" not in cfg
    assert hub.relayed == []
