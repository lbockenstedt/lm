"""``ldap_cluster`` — one-form LDAP setup (domain + admin account).

The hub must find every ldap-server node itself, keep their existing
replication ids, peer each node with all the others, reset the admin password
on all of them (stored in the Credential Vault), and point the Directory spoke
at every server. A node loaded later joins with the stored identity.
"""
import asyncio
import sys
import types

import pytest

import ldap_cluster as lc


class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}
        self.dirty = 0

    def _mark_dirty(self):
        self.dirty += 1


class _Hub:
    def __init__(self, roles, connected, addr, env):
        self.state = _State()
        self._roles = roles
        self.active_connections = set(connected)
        self._addr = addr
        self._env = env
        self.spoke_id_alias = {"mipbe-svcs01": "g1", "mipbe-svcs02": "g2"}
        self.load_roles = []
        self.pushed_client = 0

    def _primary_key(self, sid):
        return self.spoke_id_alias.get(sid, sid)

    def _agent_roles_store(self):
        return self._roles

    async def push_ldap_config_all(self):
        self.pushed_client += 1

    async def request_response(self, target, cmd, payload=None, timeout=None):
        if cmd == "GET_AVAILABLE_ROLES":
            a = self._addr.get(target)
            return {"payload": {"data": {"service_addresses": [a] if a else []}}}
        if cmd == "RUN_COMMAND":
            return {"payload": {"data": {"result": {"ok": True, "stdout": self._env.get(target, "")}}}}
        if cmd == "LOAD_ROLE":
            self.load_roles.append((target, payload))
            return {"payload": {"data": {"status": "SUCCESS", "message": "deploying"}}}
        raise AssertionError(cmd)


@pytest.fixture
def vault(monkeypatch):
    stored = {}

    class CredVaultError(Exception):
        pass

    async def put_secret(hub, bucket, name, value, **kw):
        if kw.get("psk") == "wrong":
            raise CredVaultError("bad pass-phrase")
        stored[(bucket, name)] = (value, kw.get("mode"))

    mod = types.ModuleType("cred_vault")
    mod.ADMIN_BUCKET = "__admin__"
    mod.CredVaultError = CredVaultError
    mod.put_secret = put_secret
    monkeypatch.setitem(sys.modules, "cred_vault", mod)
    oidc = types.ModuleType("security.oidc")
    oidc.get_oidc_config = lambda hub: (_ for _ in ()).throw(RuntimeError("no oidc"))
    monkeypatch.setitem(sys.modules, "security.oidc", oidc)
    return stored


def _two_node_hub():
    return _Hub(roles={"g1": ["dns-server", "ldap-server"], "g2": ["ldap-server"],
                       "g3": ["ldap"]},
                connected={"g1", "g2", "g3"},
                addr={"g1": "172.21.1.11", "g2": "172.21.1.12"},
                env={"g1": "LDAP_SERVER_ID=1\n", "g2": "LDAP_SERVER_ID=2\n"})


def test_dns_derived_from_domain():
    assert lc.base_dn_from_domain(" Orange-TME.com ") == "dc=orange-tme,dc=com"
    assert lc.admin_dn_for("Administrator", "dc=a,dc=b") == "cn=Administrator,dc=a,dc=b"
    for bad in ("", "localhost", "a..b", "a b.com", "x=y.com"):
        with pytest.raises(lc.LdapSetupError):
            lc.base_dn_from_domain(bad)
    with pytest.raises(lc.LdapSetupError):
        lc.admin_dn_for("cn=evil,dc=x", "dc=a,dc=b")


def test_server_ids_keep_existing_and_fill_gaps():
    ids = lc.assign_server_ids([
        {"spoke_id": "a", "server_id": "2"},
        {"spoke_id": "b", "server_id": "2"},   # duplicate → reassigned
        {"spoke_id": "c", "server_id": ""},
        {"spoke_id": "d", "server_id": "junk"},
    ])
    assert ids["a"] == "2"
    assert sorted(ids.values()) == ["1", "2", "3", "4"]


def test_apply_resets_password_peers_all_nodes_and_points_spoke(vault):
    hub = _two_node_hub()
    res = asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", actor="lrb"))

    assert res["base_dn"] == "dc=orange-tme,dc=com"
    assert [s["status"] for s in res["servers"]] == ["SUCCESS", "SUCCESS"]
    pushed = {t: p["config"] for t, p in hub.load_roles}
    assert set(pushed) == {"g1", "g2"}  # the "ldap" management agent is not a server
    assert all(p["force"] for _, p in hub.load_roles)
    assert pushed["g1"]["server_id"] == "1" and pushed["g2"]["server_id"] == "2"
    assert pushed["g1"]["peers"] == ["ldap://172.21.1.12:389"]
    assert pushed["g2"]["peers"] == ["ldap://172.21.1.11:389"]
    pw = pushed["g1"]["admin_pw"]
    assert len(pw) >= 24 and pushed["g2"]["admin_pw"] == pw  # one shared, generated password

    (value, mode), = vault.values()
    assert value["password"] == pw and value["bind_dn"] == "cn=Administrator,dc=orange-tme,dc=com"
    assert mode == "hub"  # automation-readable

    gl = hub.state.system_state["global_config"]["ldap"]
    assert gl["server_url"] == "ldap://172.21.1.11:389 ldap://172.21.1.12:389"
    assert gl["admin_pw"] == pw and gl["domain"] == "orange-tme.com"
    assert hub.pushed_client == 1
    assert [s["name"] for s in res["servers"]] == ["mipbe-svcs01", "mipbe-svcs02"]


def test_apply_uses_given_password(vault):
    hub = _two_node_hub()
    asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", admin_pw="S3cret!pw"))
    assert all(p["config"]["admin_pw"] == "S3cret!pw" for _, p in hub.load_roles)


def test_apply_refuses_when_a_server_is_offline(vault):
    hub = _two_node_hub()
    hub.active_connections.discard("g2")
    with pytest.raises(lc.LdapSetupError, match="mipbe-svcs02"):
        asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator"))
    assert hub.load_roles == [] and not vault


def test_vault_refusal_changes_nothing(vault):
    hub = _two_node_hub()
    with pytest.raises(lc.LdapSetupError, match="vault"):
        asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", psk="wrong"))
    assert hub.load_roles == []
    assert "ldap" not in hub.state.system_state["global_config"]


def test_new_node_joins_stored_directory(vault):
    hub = _two_node_hub()
    asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", admin_pw="pw1"))
    hub.load_roles.clear()
    hub.active_connections.add("g4")
    hub._addr["g4"] = "172.21.1.13"

    cfg = asyncio.run(lc.join_config(hub, "g4", {}))

    assert cfg["server_id"] == "3" and cfg["admin_pw"] == "pw1"
    assert sorted(cfg["peers"]) == ["ldap://172.21.1.11:389", "ldap://172.21.1.12:389"]
    # existing nodes are re-pushed with the newcomer as a peer, same password
    repushed = {t: p["config"] for t, p in hub.load_roles}
    assert set(repushed) == {"g1", "g2"}
    assert "ldap://172.21.1.13:389" in repushed["g1"]["peers"]
    assert repushed["g1"]["admin_pw"] == "pw1"
    assert hub.state.system_state["global_config"]["ldap"]["server_url"].endswith("ldap://172.21.1.13:389")


def test_join_is_skipped_before_setup(vault):
    hub = _two_node_hub()
    assert asyncio.run(lc.join_config(hub, "g4", {"base_dn": "dc=x,dc=y"})) is None


def test_role_load_uses_stored_directory_once_set_up(vault):
    from routes import agents
    hub = _two_node_hub()
    hub.state.get_spoke_tenant = lambda pk: ""
    asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", admin_pw="pw1"))
    hub.active_connections.add("g4")
    hub._addr["g4"] = "172.21.1.13"
    cfg = asyncio.run(agents._ldap_server_load_config(hub, "g4", {}))
    assert cfg["base_dn"] == "dc=orange-tme,dc=com" and cfg["server_id"] == "3"


def test_role_load_falls_back_to_legacy_before_setup(vault, monkeypatch):
    from routes import agents
    hub = _two_node_hub()
    called = []

    async def legacy(h, sid, cfg):
        called.append(sid)
        return cfg
    monkeypatch.setattr(agents, "_auto_cluster_ldap_server_config", legacy)
    cfg = asyncio.run(agents._ldap_server_load_config(hub, "g4", {"base_dn": "dc=x,dc=y"}))
    assert called == ["g4"] and cfg["base_dn"] == "dc=x,dc=y"


def test_join_with_offline_server_loads_standalone(vault):
    hub = _two_node_hub()
    asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", admin_pw="pw1"))
    hub.load_roles.clear()
    hub.active_connections.discard("g2")
    hub.active_connections.add("g4")
    hub._addr["g4"] = "172.21.1.13"
    url_before = lc.stored_setup(hub)["server_url"]
    cfg = asyncio.run(lc.join_config(hub, "g4", {}))
    assert cfg["admin_pw"] == "pw1" and "server_id" not in cfg and "peers" not in cfg
    assert hub.load_roles == [] and lc.stored_setup(hub)["server_url"] == url_before


def test_reapply_keeps_password_and_skips_vault(vault):
    hub = _two_node_hub()
    asyncio.run(lc.apply_setup(hub, "orange-tme.com", "Administrator", admin_pw="pw1"))
    hub.load_roles.clear()
    vault.clear()
    res = asyncio.run(lc.reapply(hub))
    assert {t for t, _ in hub.load_roles} == {"g1", "g2"}
    assert all(p["config"]["admin_pw"] == "pw1" and p["force"] for _, p in hub.load_roles)
    assert vault == {} and len(res["servers"]) == 2


def test_reapply_requires_setup(vault):
    with pytest.raises(lc.LdapSetupError):
        asyncio.run(lc.reapply(_two_node_hub()))
