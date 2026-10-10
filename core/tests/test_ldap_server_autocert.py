"""``routes/agents.py::_auto_request_ldap_server_cert`` — once an
``ldap-server`` LOAD_ROLE succeeds, the hub should automatically get it a
real Let's Encrypt cert instead of leaving it on install_ldap.sh's bootstrap
self-signed one, using the SAME ``*.ext.<domain>`` / HE.NET DNS-01 convention
already used for this tenant's other certs (see the live ledger entries for
``appbuilder.ext.orange-tme.com`` / ``labmanager.ext.orange-tme.com``).

Every prerequisite gap (no LE spoke connected, no sibling cert to source a
registration email from, no HE.NET vault credential) must degrade to a no-op
— the self-signed cert is still functional, just untrusted, so this must
never raise or block the caller.
"""
import asyncio

from routes import agents


class _State:
    def __init__(self, tenant=None):
        self.system_state = {"module_metadata": {}}
        self._tenant = tenant
        self.saved = 0

    def get_spoke_tenant(self, pk):
        return self._tenant

    async def save_state_now(self):
        self.saved += 1


class _Hub:
    def __init__(self, tenant=None, le_sid="le-1", certs=None, vault_creds=None,
                vault_error=None, distribute_error=None):
        self.state = _State(tenant)
        self._le_sid = le_sid
        self._certs = certs if certs is not None else {"certs": []}
        self._vault_creds = vault_creds
        self._vault_error = vault_error
        self.relayed = []
        self.distributed = []
        self._distribute_error = distribute_error

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return self._le_sid if module_type == "certificates" else None

    async def request_response(self, target, cmd, payload=None, timeout=None):
        self.relayed.append((target, cmd, payload))
        if cmd == "LE_LIST_CERTS":
            return {"payload": {"data": {"status": "SUCCESS", "data": self._certs}}}
        if cmd == "LE_ADD_TARGET":
            return {"payload": {"data": {"status": "SUCCESS",
                                        "data": {"domain": payload["domain"], "target": payload["target"]}}}}
        if cmd == "LE_ISSUE_CERT":
            return {"payload": {"data": {"status": "SUCCESS", "data": {
                "domain": payload["domain"], "targets": payload["targets"],
                "material_hash": "sha256:deadbeef"}}}}
        raise AssertionError(f"unexpected RPC {cmd}")

    async def _distribute_one_cert(self, le_sid, domain, targets, material_hash=None):
        if self._distribute_error:
            raise RuntimeError(self._distribute_error)
        self.distributed.append((le_sid, domain, targets, material_hash))
        return []


def _fake_vault_module(creds=None, error=None):
    import types
    mod = types.ModuleType("cred_vault")

    async def automation_get(hub, bucket, name):
        if error:
            raise RuntimeError(error)
        return creds or {}
    mod.automation_get = automation_get
    return mod


def _install_vault(monkeypatch, creds=None, error=None):
    import sys
    monkeypatch.setitem(sys.modules, "cred_vault", _fake_vault_module(creds, error))


def test_no_base_dn_is_a_noop():
    hub = _Hub()
    asyncio.run(agents._auto_request_ldap_server_cert(hub, "svcs01", {}))
    assert hub.relayed == []


def test_no_le_spoke_connected_is_a_noop():
    hub = _Hub(le_sid=None)
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))
    assert hub.relayed == []


def test_already_targeted_cert_is_a_noop():
    hub = _Hub(certs={"certs": [{
        "domain": "ldap.ext.orange-tme.com", "email": "lrb@hpe.com",
        "targets": [{"module_type": "ldap-server", "identifier": "svcs01"}],
    }]})
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))
    assert [c for (_t, c, _p) in hub.relayed] == ["LE_LIST_CERTS"]
    assert hub.distributed == []


def test_existing_cert_gets_second_node_added_as_target():
    hub = _Hub(certs={"certs": [{
        "domain": "ldap.ext.orange-tme.com", "email": "lrb@hpe.com",
        "material_hash": "sha256:abc123",
        "targets": [{"module_type": "ldap-server", "identifier": "svcs01"}],
    }]})
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs02", {"base_dn": "dc=orange-tme,dc=com"}))

    cmds = [c for (_t, c, _p) in hub.relayed]
    assert cmds == ["LE_LIST_CERTS", "LE_ADD_TARGET"]
    add_target_call = hub.relayed[1][2]
    assert add_target_call["domain"] == "ldap.ext.orange-tme.com"
    assert add_target_call["target"] == {"module_type": "ldap-server", "identifier": "svcs02"}
    assert len(hub.distributed) == 1
    _le_sid, domain, targets, material_hash = hub.distributed[0]
    assert domain == "ldap.ext.orange-tme.com"
    assert {"module_type": "ldap-server", "identifier": "svcs01"} in targets
    assert {"module_type": "ldap-server", "identifier": "svcs02"} in targets
    assert material_hash == "sha256:abc123"


def test_no_sibling_cert_to_source_email_from_skips_issue():
    hub = _Hub(certs={"certs": []})
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))
    assert [c for (_t, c, _p) in hub.relayed] == ["LE_LIST_CERTS"]
    assert hub.distributed == []


def test_missing_vault_credential_skips_issue(monkeypatch):
    _install_vault(monkeypatch, error="secret 'HE.NET' not found")
    hub = _Hub(certs={"certs": [
        {"domain": "appbuilder.ext.orange-tme.com", "email": "lrb@hpe.com", "targets": []},
    ]})
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))
    assert [c for (_t, c, _p) in hub.relayed] == ["LE_LIST_CERTS"]
    assert hub.distributed == []


def test_first_node_issues_new_shared_cert_and_distributes(monkeypatch):
    _install_vault(monkeypatch, creds={"he_username": "lrb@hpe.com", "he_password": "s3cret"})
    hub = _Hub(tenant="acme", certs={"certs": [
        {"domain": "appbuilder.ext.orange-tme.com", "email": "lrb@hpe.com", "targets": []},
    ]})
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))

    cmds = [c for (_t, c, _p) in hub.relayed]
    assert cmds == ["LE_LIST_CERTS", "LE_ISSUE_CERT"]
    issue_call = hub.relayed[1][2]
    assert issue_call["domain"] == "ldap.ext.orange-tme.com"
    assert issue_call["email"] == "lrb@hpe.com"  # sourced from the sibling cert
    assert issue_call["challenge"] == "dns"
    assert issue_call["dns_provider"] == "he-login"
    assert issue_call["he_username"] == "lrb@hpe.com"
    assert issue_call["he_password"] == "s3cret"
    assert issue_call["tenant_id"] == "acme"
    assert issue_call["targets"] == [{"module_type": "ldap-server", "identifier": "svcs01"}]

    # Tenant ownership recorded + persisted, and the new cert distributed.
    assert hub.state.system_state["global_config"]["le_cert_tenants"]["ldap.ext.orange-tme.com"] == ["acme"]
    assert hub.state.saved == 1
    assert len(hub.distributed) == 1
    _le_sid, domain, targets, material_hash = hub.distributed[0]
    assert domain == "ldap.ext.orange-tme.com"
    assert targets == [{"module_type": "ldap-server", "identifier": "svcs01"}]
    assert material_hash == "sha256:deadbeef"


def test_distribution_failure_after_issue_is_swallowed(monkeypatch):
    _install_vault(monkeypatch, creds={"he_username": "lrb@hpe.com", "he_password": "s3cret"})
    hub = _Hub(certs={"certs": [
        {"domain": "appbuilder.ext.orange-tme.com", "email": "lrb@hpe.com", "targets": []},
    ]}, distribute_error="spoke unreachable")
    # Must not raise even though _distribute_one_cert blows up.
    asyncio.run(agents._auto_request_ldap_server_cert(
        hub, "svcs01", {"base_dn": "dc=orange-tme,dc=com"}))
    assert hub.state.saved == 1  # ownership was still recorded before the distribute attempt
