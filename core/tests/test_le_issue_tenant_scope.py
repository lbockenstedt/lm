"""Tenant scope of POST /api/le/issue in routes/net_services.py.

A tenant-admin may issue a certificate only for names, targets and DNS
credentials of their own tenant: no le-box paths (webroot, dns_creds_ini), no
AppBuilder-pinned names, no foreign targets (requested or carried forward by a
re-issue), and only a DNS challenge carrying the tenant's own credential
(otherwise the le spoke falls back to the admin's Hurricane Electric login).
HTTP-01 and TLS-ALPN-01 are admin-only: a tenant can write DNS records for any
name in its own prefix, so its DNS names prove nothing about ownership.
A Global Admin is not restricted.
"""
import os
import sys
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import routes.net_services as ns  # noqa: E402
from routes.net_services import register  # noqa: E402
from hub_spoke_registry import SpokeRegistryMixin  # noqa: E402

SPOKE_TENANTS = {"nac-acme": "acme", "nac-other": "other",
                 "sim-acme": "acme", "sim-other": "other"}
# Agent (Proxmox node) -> the spoke it is connected through.
AGENT_SPOKES = {"node-acme": "sim-acme", "node-other": "sim-other"}
# One name in acme's prefix, one (the hub's) outside it.
DNS_RECORDS = [{"name": "www.acme.example", "type": "A", "value": "10.0.0.5"},
               {"name": "hub.corp.example", "type": "A", "value": "10.9.9.9"}]


@pytest.fixture(autouse=True)
def _acme_prefixes(monkeypatch):
    """acme owns 10.0.0.0/24 (normally read from NetBox)."""
    async def owned(hub, sess, shared=False):
        return ["10.0.0.0/24"]
    monkeypatch.setattr(ns.access, "resolve_owned_prefixes", owned)


class FakeHub:
    CERT_CAPABLE_MODULES = {"nac", "hub", "simulation"}

    def __init__(self, dns_up=True):
        self.spoke_module_types = {sid: ("simulation" if sid.startswith("sim-") else "nac")
                                   for sid in SPOKE_TENANTS}
        self.spoke_module_types["le-1"] = "certificates"
        self.spoke_module_types["dns-1"] = "dns"
        self.active_connections = set(self.spoke_module_types)
        self.agent_info = {}
        self.netbox_server_agents = set()
        self.ldap_server_agents = set()
        self.dns_up = dns_up
        self.dns_records = list(DNS_RECORDS)
        self.sent = []
        self.pushed = []
        # The le spoke's ledger: domain -> targets.
        self.ledger = {}
        self.state = SimpleNamespace(
            system_state={"module_names": {}, "global_config": {
                "ab_cert_identities": ["ab.acme.example"]}},
            get_spoke_tenant=lambda sid: SPOKE_TENANTS.get(sid, ""),
            save_state_now=self._noop)

    async def _noop(self, *a, **k):
        return None

    _le_refresh_certs_cache = _noop
    _le_sync_vault_dns_creds = _noop

    def _primary_key(self, sid):
        return sid

    # The real recipient picker, so the tests follow distribution's routing.
    _cert_target_spoke = SpokeRegistryMixin._cert_target_spoke

    def get_all_spokes_by_type(self, module_type):
        return [s for s, t in self.spoke_module_types.items() if t == module_type]

    def get_spoke_by_type(self, module_type):
        return next(iter(self.get_all_spokes_by_type(module_type)), None)

    def get_spoke_for_agent(self, aid, fallback_hypervisor=False):
        return AGENT_SPOKES.get(aid, "")

    def _agent_primary_key(self, aid):
        return aid

    async def request_response(self, sid, command, payload=None, timeout=None):
        if command == "DNS_LIST":
            if not self.dns_up:
                raise RuntimeError("dns spoke down")
            return {"status": "SUCCESS", "records": self.dns_records}
        self.sent.append((command, dict(payload or {})))
        if command == "LE_LIST_CERTS":
            return {"status": "SUCCESS", "data": {"certs": [
                {"domain": d, "targets": t} for d, t in self.ledger.items()]}}
        if command == "LE_ISSUE_CERT":
            # Like le_spoke._issue: a re-issue keeps the previous targets.
            targets = self.ledger.get(payload["domain"], []) + (payload.get("targets") or [])
            return {"status": "SUCCESS", "data": {
                "domain": payload["domain"], "targets": targets}}
        return {"status": "SUCCESS", "data": {}}

    async def _distribute_one_cert(self, le_sid, domain, targets, material_hash=None):
        self.pushed.append(targets)
        return []


def _client(admin=False, dns_up=True):
    hub = FakeHub(dns_up=dns_up)
    sess = {"user": {"tenants": ["acme"], "tenant_id": "acme"}}
    app = FastAPI()
    ctx = SimpleNamespace(_session_user=lambda request: sess, _is_admin=lambda s: admin,
                          _filter_session=None, _filter_tenant=None,
                          _effective_tenant=lambda request, explicit=None: "acme")
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app), hub


# A DNS-01 issue with the tenant's own saved credential: passes the name and
# credential checks, so a refusal comes from the check under test.
DNS = {"challenge": "dns", "dns_credential": "mine"}


def _issued(hub):
    return [b for c, b in hub.sent if c == "LE_ISSUE_CERT"]


def test_http_and_tls_alpn_are_admin_only():
    # Even for a name in the tenant's own DNS, and after the tenant writes a
    # record for the hub's name into its own prefix (as POST /api/dns/record
    # allows), which puts that name in its suggestion list.
    c, hub = _client()
    hub.dns_records.append({"name": "hub.corp.example", "type": "A", "value": "10.0.0.9"})
    assert "hub.corp.example" in c.get("/api/le/eligible-domains").json()["hosts"]
    for body in ({"domain": "www.acme.example", "challenge": "http"},
                 {"domain": "www.acme.example"},
                 {"domain": "hub.corp.example", "challenge": "http-01"},
                 {"domain": "www.acme.example", "challenge": "tls-alpn"},
                 {"domain": "www.acme.example", "challenge": "bogus"}):
        r = c.post("/api/le/issue", json=body)
        assert r.status_code == 403, body
    assert _issued(hub) == []


def test_extra_names_are_checked_too():
    c, hub = _client()
    r = c.post("/api/le/issue", json={"domain": "www.acme.example",
                                      "domains": ["AB.acme.example"], **DNS})
    assert r.status_code == 403
    assert _issued(hub) == []


def test_comma_joined_names_are_each_checked():
    # certbot -d reads "a,b" as two names, so each one must pass.
    c, hub = _client()
    for domain in ("any.example,AB.acme.example", "any.example, ab.acme.example."):
        r = c.post("/api/le/issue", json={"domain": domain, **DNS})
        assert r.status_code == 403, domain
    assert _issued(hub) == []


def test_le_box_paths_are_admin_only():
    c, hub = _client()
    for extra in ({"webroot": "/etc"}, {"dns_creds_ini": "/root/creds.ini"}):
        r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS, **extra})
        assert r.status_code == 403, extra
    assert _issued(hub) == []


def test_dns_issue_without_own_credential_is_refused():
    c, hub = _client()
    for body in ({"challenge": "dns", "dns_provider": "he-login"},
                 {"challenge": "DNS-01", "dns_provider": "he-login", "he_username": "u"},
                 {"challenge": "dns01", "dns_provider": "cloudflare", "dns_creds": "  "},
                 # A field the provider does not read must not count: the spoke
                 # would fall back to the admin's HE login / the box's AWS keys.
                 {"challenge": "dns", "dns_provider": "he-login", "dns_creds": "x"},
                 {"challenge": "dns", "dns_provider": "route53",
                  "he_username": "a", "he_password": "b"},
                 {"challenge": "dns", "dns_provider": "route53", "dns_creds": "x"},
                 {"challenge": "dns", "dns_creds": "x"}):
        r = c.post("/api/le/issue", json={"domain": "any.example", **body})
        assert r.status_code == 403, body
    # A saved credential with per-request overrides is refused too: the
    # overrides would replace parts of it on the spoke.
    r = c.post("/api/le/issue", json={"domain": "any.example", "challenge": "dns",
                                      "dns_credential": "mine", "dns_provider": "he-login"})
    assert r.status_code == 400
    assert _issued(hub) == []


def test_dns_issue_with_own_credential_is_relayed():
    c, hub = _client()
    for body in ({"dns_credential": "mine"},
                 {"dns_provider": "he-login", "he_username": "u", "he_password": "p"},
                 {"dns_provider": "cloudflare", "dns_creds": "dns_cloudflare_api_token = x"}):
        r = c.post("/api/le/issue", json={"domain": "any.example", "challenge": "dns", **body})
        assert r.status_code == 200, (body, r.text)
    assert len(_issued(hub)) == 3


def test_ab_pinned_name_is_admin_only():
    c, hub = _client()
    r = c.post("/api/le/issue", json={"domain": "AB.acme.example", "challenge": "dns",
                                      "dns_credential": "mine"})
    assert r.status_code == 403
    r = c.post("/api/le/certs/ab.acme.example/targets",
               json={"module_type": "nac", "identifier": "nac-acme"})
    assert r.status_code == 403
    r = c.post("/api/le/certs/ab.acme.example/devices/sw1/deploy")
    assert r.status_code == 403
    assert hub.sent == []


def test_issue_targets_must_be_the_callers_own():
    c, hub = _client()
    base = {"domain": "www.acme.example", **DNS}
    r = c.post("/api/le/issue", json={**base, "targets": [
        {"module_type": "nac", "identifier": "nac-acme"},
        {"module_type": "nac", "identifier": "nac-other"}]})
    assert r.status_code == 403
    r = c.post("/api/le/issue", json={**base, "targets": [{"module_type": "hub"}]})
    assert r.status_code == 403
    r = c.post("/api/le/issue", json={**base, "targets": ["nac-acme"]})
    assert r.status_code == 400
    assert _issued(hub) == []
    r = c.post("/api/le/issue", json={**base, "targets": [
        {"module_type": "nac", "identifier": "nac-acme"}]})
    assert r.status_code == 200, r.text
    assert hub.pushed == [[{"module_type": "nac", "identifier": "nac-acme"}]]


def test_global_admin_is_not_restricted():
    c, hub = _client(admin=True)
    r = c.post("/api/le/issue", json={"domain": "ab.acme.example", "challenge": "http",
                                      "webroot": "/var/www", "targets": [{"module_type": "hub"}]})
    assert r.status_code == 200, r.text
    r = c.post("/api/le/issue", json={"domain": "x.example", "challenge": "dns",
                                      "dns_provider": "he-login"})
    assert r.status_code == 200, r.text
    assert len(_issued(hub)) == 2


def test_suggested_names_are_scoped_even_with_the_le_filter_off():
    # The le subnet filter defaults off; the dialog must still list only the
    # tenant's own names, not the fleet's.
    assert not ns.access.filter_enabled(FakeHub(), "le")
    c, hub = _client()
    r = c.get("/api/le/eligible-domains")
    assert r.json()["hosts"] == ["www.acme.example"]


def test_target_spoke_id_cannot_vouch_for_another_spoke():
    # Distribution routes by identifier, so a matching spoke_id is not enough.
    c, hub = _client()
    base = {"domain": "www.acme.example", **DNS}
    for t in ({"module_type": "nac", "identifier": "nac-other", "spoke_id": "nac-acme"},
              {"module_type": "nac", "identifier": "", "spoke_id": "nac-acme"},
              # Own spoke of the wrong type: routing falls back to the first
              # nac spoke, which may be another tenant's.
              {"module_type": "nac", "identifier": "sim-acme"},
              {"module_type": "simulation", "identifier": "node-other", "spoke_id": "sim-acme"},
              {"module_type": "simulation", "identifier": "node-gone", "spoke_id": "sim-acme"},
              {"module_type": "simulation", "identifier": "", "spoke_id": "sim-acme"},
              # Whitespace: the spoke stores and routing uses the raw value,
              # which misses the index and falls back to another spoke.
              {"module_type": "nac", "identifier": "nac-acme "},
              {"module_type": "nac ", "identifier": "nac-acme"},
              {"module_type": "simulation", "identifier": " node-acme", "spoke_id": "sim-acme"}):
        r = c.post("/api/le/issue", json={**base, "targets": [t]})
        assert r.status_code == 403, t
        r = c.post("/api/le/certs/www.acme.example/targets", json=t)
        assert r.status_code == 403, t
    assert _issued(hub) == [] and hub.pushed == []


def test_pinned_node_on_another_tenants_spoke_is_refused(monkeypatch):
    # A node pinned to acme counts as acme's, but the key goes to the spoke
    # hosting it: another tenant's spoke must not receive it; a shared one may.
    c, hub = _client()
    monkeypatch.setitem(AGENT_SPOKES, "node-pinned", "sim-other")
    monkeypatch.setitem(SPOKE_TENANTS, "sim-shared", "")
    hub.spoke_module_types["sim-shared"] = "simulation"
    hub.active_connections.add("sim-shared")
    hub.state.system_state["agent_config"] = {
        "node-pinned": {"client_simulation": {"tenant_id": "acme"}}}
    t = {"module_type": "simulation", "identifier": "node-pinned"}
    base = {"domain": "www.acme.example", **DNS}
    assert c.post("/api/le/issue", json={**base, "targets": [t]}).status_code == 403
    assert c.post("/api/le/certs/www.acme.example/targets", json=t).status_code == 403
    assert _issued(hub) == [] and hub.pushed == []
    AGENT_SPOKES["node-pinned"] = "sim-shared"
    r = c.post("/api/le/issue", json={**base, "targets": [t]})
    assert r.status_code == 200, r.text
    assert hub.pushed == [[t]]


def test_targets_must_be_a_list():
    c, hub = _client()
    for bad in ({}, "nac-other", {"module_type": "nac"}):
        r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS, "targets": bad})
        assert r.status_code == 400, bad
    assert _issued(hub) == []


def test_reissue_with_a_foreign_carried_target_is_refused():
    # The spoke keeps the old targets on a re-issue, so the new key would be
    # pushed to them even though the request names none.
    c, hub = _client()
    hub.ledger["www.acme.example"] = [{"module_type": "nac", "identifier": "nac-other"}]
    r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS})
    assert r.status_code == 403
    assert _issued(hub) == [] and hub.pushed == []
    # Own carried targets are fine.
    hub.ledger["www.acme.example"] = [{"module_type": "nac", "identifier": "nac-acme"}]
    r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS})
    assert r.status_code == 200, r.text
    assert hub.pushed == [[{"module_type": "nac", "identifier": "nac-acme"}]]


def test_foreign_target_returned_by_the_spoke_is_not_pushed():
    # A target added after the check is still not pushed at a tenant's request.
    c, hub = _client()
    real = hub.request_response

    async def racing(sid, command, payload=None, timeout=None):
        if command == "LE_ISSUE_CERT":
            hub.ledger[payload["domain"]] = [{"module_type": "nac", "identifier": "nac-other"}]
        return await real(sid, command, payload, timeout)
    hub.request_response = racing
    r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS})
    assert r.status_code == 200, r.text
    assert hub.pushed == [[]]
    # It is also removed from the ledger, so the hourly sweep skips it.
    assert ("LE_REMOVE_TARGET", {"domain": "www.acme.example", "idx": 0}) in hub.sent


def test_own_target_offline_during_the_issue_is_kept():
    # Unroutable now is not foreign: skip the push but keep it for the sweep.
    c, hub = _client()
    hub.ledger["www.acme.example"] = [{"module_type": "nac", "identifier": "nac-acme"}]
    hub.state.system_state["known_modules"] = ["nac-acme"]
    real = hub.request_response

    async def offline(sid, command, payload=None, timeout=None):
        if command == "LE_ISSUE_CERT":
            hub.active_connections.discard("nac-acme")
        return await real(sid, command, payload, timeout)
    hub.request_response = offline
    r = c.post("/api/le/issue", json={"domain": "www.acme.example", **DNS})
    assert r.status_code == 200, r.text
    assert hub.pushed == [[]]
    assert not [s for s in hub.sent if s[0] == "LE_REMOVE_TARGET"]


def test_own_targets_by_routed_spoke_are_allowed():
    c, hub = _client()
    r = c.post("/api/le/issue", json={
        "domain": "www.acme.example", **DNS, "targets": [
            {"module_type": "nac", "identifier": "nac-acme", "spoke_id": "nac-acme"},
            {"module_type": "simulation", "identifier": "node-acme", "spoke_id": "sim-acme"}]})
    assert r.status_code == 200, r.text
