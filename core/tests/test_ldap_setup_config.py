"""Setup → Directory (LDAP) SERVER connection config.

Covers the pure config helpers in ``routes.ldap`` (precedence merge of
``global_config["ldap"]`` over the legacy ``ldap_instances`` entry, mirror-peer
normalization/parsing, and the GET password-mask) plus the ``/setup/ldap-config``
GET/POST routes end-to-end through ``create_app`` (admin gate, persist, and the
re-push to connected directory spokes).

Models the route stand-in on ``test_oidc.py`` (create_app + a minimal fake hub +
an admin login for the ``/setup/*`` middleware gate).
"""
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import api as api_mod
from routes.ldap import (
    merge_ldap_connection, normalize_mirror_peers, parse_mirror_peers_input,
    mask_ldap_config,
)


# ── fakes ────────────────────────────────────────────────────────────────────

class _FakeState:
    def __init__(self, system_state=None):
        self.system_state = system_state or {}
        self.tenant_state = {"tenants": {}}
        self.data_dir = None

    def save_state(self):
        pass

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        pass

    def ensure_admin_lockout(self):
        return False

    def get_global_config(self):
        return self.system_state.setdefault("global_config", {})


class _KM:
    def __init__(self):
        self.hub_secrets = ["hub-secret-test"]


class _FakeHub:
    def __init__(self, system_state=None, directory_spokes=None):
        self.state = _FakeState(system_state)
        self.key_manager = _KM()
        self.simulations_store = type("_Store", (), {})()
        self.simulations_cache = {}
        self.active_connections = set()
        self.approved_modules = {}
        self.spoke_module_types = {}
        self._spokes_by_type = {}
        self._directory_spokes = list(directory_spokes or [])
        self.push_calls = 0

    def get_spoke_by_type(self, t):
        return self._spokes_by_type.get(t)

    def get_all_spokes_by_type(self, t):
        return list(self._directory_spokes) if t == "directory" else []

    async def push_ldap_config_all(self):
        self.push_calls += 1

    async def request_response(self, spoke_id, cmd, data, timeout=30.0):
        return {"payload": {"data": []}}


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    api_mod._sessions.clear()
    for v in ("LM_TLS_CERT", "LM_TLS_KEY", "LM_CORS_ORIGINS", "LM_FERNET_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("LM_FERNET_KEY", "z" * 44)


def _build(system_state, directory_spokes=None):
    hub = _FakeHub(system_state, directory_spokes)
    app = api_mod.create_app(hub)
    return TestClient(app), hub


def _admin_login(client):
    r = client.post("/auth/login", json={"username": "admin", "password": "pass1234"})
    assert r.status_code == 200, r.text
    return r.cookies.get("lm_session")


def _admin_state(**global_config):
    st = {"users": {"admin": {
        "auth_type": "local",
        "password_hash": api_mod._hash_password("pass1234"),
        "permissions": {"role": "admin", "admin": True},
        "tenants": [], "protected": False}}}
    if global_config:
        st["global_config"] = dict(global_config)
    return st


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_merge_prefers_global_config_over_instance_defaults():
    """Setup values (global_config["ldap"]) WIN over the ldap_instances entry /
    dc=example install default, per field."""
    gldap = {"base_dn": "dc=lab,dc=corp", "admin_dn": "cn=admin,dc=lab,dc=corp",
             "admin_pw": "s3cret", "server_url": "ldap://ldap-1.corp:389"}
    inst = {"base_dn": "dc=example,dc=org", "admin_dn": "cn=admin,dc=example,dc=org",
            "admin_pw": "admin", "server_url": "ldap://localhost:389"}
    cfg = merge_ldap_connection(gldap, inst)
    assert cfg["LDAP_BASE_DN"] == "dc=lab,dc=corp"
    assert cfg["LDAP_ADMIN_DN"] == "cn=admin,dc=lab,dc=corp"
    assert cfg["LDAP_ADMIN_PW"] == "s3cret"
    assert cfg["LDAP_SERVER_URL"] == "ldap://ldap-1.corp:389"


def test_merge_falls_back_to_instance_when_global_field_blank():
    """A blank/absent Setup field falls through to the instance value (so a
    partially-filled panel doesn't wipe the install-time config)."""
    gldap = {"base_dn": "dc=lab,dc=corp", "admin_dn": "   ", "admin_pw": ""}
    inst = {"base_dn": "dc=example,dc=org", "admin_dn": "cn=admin,dc=example,dc=org",
            "admin_pw": "admin", "server_url": "ldap://localhost:389"}
    cfg = merge_ldap_connection(gldap, inst)
    assert cfg["LDAP_BASE_DN"] == "dc=lab,dc=corp"          # global wins
    assert cfg["LDAP_ADMIN_DN"] == "cn=admin,dc=example,dc=org"  # blank → instance
    assert cfg["LDAP_ADMIN_PW"] == "admin"                 # blank → instance
    assert cfg["LDAP_SERVER_URL"] == "ldap://localhost:389"  # absent → instance


def test_merge_handles_empty_inputs():
    assert merge_ldap_connection(None, None) == {
        "LDAP_SERVER_URL": None, "LDAP_BASE_DN": None,
        "LDAP_ADMIN_DN": None, "LDAP_ADMIN_PW": None}


def test_parse_and_normalize_mirror_peers():
    parsed = parse_mirror_peers_input("ldap://a:389, ldap://b:389\nldap://c:389")
    assert parsed == ["ldap://a:389", "ldap://b:389", "ldap://c:389"]
    peers = normalize_mirror_peers(parsed)
    assert peers == [{"server_id": "", "url": "ldap://a:389"},
                     {"server_id": "", "url": "ldap://b:389"},
                     {"server_id": "", "url": "ldap://c:389"}]
    # dict entries keep their server_id; blanks dropped.
    assert normalize_mirror_peers([{"server_id": "2", "url": "ldap://b:389"},
                                   {"url": ""}, "  "]) == \
        [{"server_id": "2", "url": "ldap://b:389"}]


def test_mask_never_echoes_admin_password():
    masked = mask_ldap_config({"base_dn": "dc=x", "admin_dn": "cn=a,dc=x",
                               "admin_pw": "topsecret", "server_url": "ldap://h:389",
                               "server_id": "1",
                               "mirror_peers": ["ldap://b:389"]})
    assert "admin_pw" not in masked
    assert masked["admin_pw_set"] is True
    assert masked["base_dn"] == "dc=x"
    assert masked["mirror_peers"] == [{"server_id": "", "url": "ldap://b:389"}]
    # No stored pw → admin_pw_set False, still no value echoed.
    assert mask_ldap_config({})["admin_pw_set"] is False


# ── routes end-to-end ────────────────────────────────────────────────────────

def test_get_requires_admin_and_masks_password():
    client, hub = _build(_admin_state(ldap={
        "base_dn": "dc=lab,dc=corp", "admin_dn": "cn=admin,dc=lab,dc=corp",
        "admin_pw": "s3cret", "server_url": "ldap://h:389"}))
    # Unauthenticated → 401 (the /setup/* middleware gate).
    assert client.get("/setup/ldap-config").status_code == 401
    ck = _admin_login(client)
    got = client.get("/setup/ldap-config", cookies={"lm_session": ck})
    assert got.status_code == 200
    body = got.json()
    assert body["config"]["base_dn"] == "dc=lab,dc=corp"
    assert body["config"]["admin_pw_set"] is True
    assert "admin_pw" not in body["config"]  # never echoed


def test_post_persists_validates_and_pushes():
    client, hub = _build(_admin_state(), directory_spokes=["ldap-spoke-1", "ldap-spoke-2"])
    ck = _admin_login(client)
    # Missing base DN → 400.
    r = client.post("/setup/ldap-config", cookies={"lm_session": ck},
                    json={"config": {"admin_dn": "cn=admin,dc=x"}})
    assert r.status_code == 400
    # Valid save → stored + pushed to both connected directory spokes.
    r = client.post("/setup/ldap-config", cookies={"lm_session": ck},
                    json={"config": {"base_dn": "dc=lab,dc=corp",
                                     "admin_dn": "cn=admin,dc=lab,dc=corp",
                                     "admin_pw": "s3cret",
                                     "server_url": "ldap://h:389",
                                     "mirror_peers": "ldap://b:389, ldap://c:389"}})
    assert r.status_code == 200
    body = r.json()
    assert body["pushed_to_spokes"] == 2
    assert body["admin_pw_set"] is True
    assert hub.push_calls == 1
    stored = hub.state.system_state["global_config"]["ldap"]
    assert stored["base_dn"] == "dc=lab,dc=corp"
    assert stored["admin_pw"] == "s3cret"
    assert stored["mirror_peers"] == [{"server_id": "", "url": "ldap://b:389"},
                                      {"server_id": "", "url": "ldap://c:389"}]


def test_post_blank_password_keeps_existing():
    client, hub = _build(_admin_state(ldap={
        "base_dn": "dc=old", "admin_dn": "cn=admin,dc=old", "admin_pw": "keepme"}))
    ck = _admin_login(client)
    r = client.post("/setup/ldap-config", cookies={"lm_session": ck},
                    json={"config": {"base_dn": "dc=new", "admin_dn": "cn=admin,dc=new"}})
    assert r.status_code == 200
    stored = hub.state.system_state["global_config"]["ldap"]
    assert stored["base_dn"] == "dc=new"
    assert stored["admin_pw"] == "keepme"  # blank submission kept the old pw
    assert r.json()["admin_pw_set"] is True


def test_push_route_repushes_without_change():
    client, hub = _build(_admin_state(ldap={"base_dn": "dc=x", "admin_dn": "cn=a,dc=x"}),
                         directory_spokes=["ldap-spoke-1"])
    ck = _admin_login(client)
    r = client.post("/setup/ldap-config/push", cookies={"lm_session": ck})
    assert r.status_code == 200
    assert r.json()["pushed_to_spokes"] == 1
    assert hub.push_calls == 1
