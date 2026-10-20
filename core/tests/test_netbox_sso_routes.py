"""Settings → Azure → NetBox SSO (``routes/netbox_sso.py``).

NetBox SSO is ported from the hub's Entra connection: the push to the
netbox-server agent carries tenant/client_id, the hub's client cert + key (no
client secret needed), the hub's allowed group, the Permission Groups' Entra
group map, and the Global Admin groups (→ NetBox superuser).
"""
import os
import sys
import tempfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from routes import netbox_sso  # noqa: E402
from security.oidc import generate_client_cert  # noqa: E402


class _State:
    def __init__(self, system_state):
        self.system_state = system_state
        self.data_dir = tempfile.mkdtemp(prefix="lm-nbsso-test-")

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, system_state, agents=("agent-nb",)):
        self.state = _State(system_state)
        self.netbox_server_agents = set(agents)
        self.active_connections = set(agents)
        self.pushes = []

    async def push_or_queue_to_spoke(self, sid, msg_type, payload):
        self.pushes.append((sid, msg_type, payload))
        return {"queued": False}


@pytest.fixture
def cert(tmp_path):
    return generate_client_cert(key_path=str(tmp_path / "k.pem"),
                                cert_path=str(tmp_path / "c.pem"))


def _state(cert=None, oidc_extra=None):
    oidc = {"enabled": True, "tenant_id": "tid-1", "client_id": "cid-1",
            "allowed_group": "hub-allowed"}
    if cert:
        oidc.update(cert_path=cert["cert_path"], key_path=cert["key_path"])
    else:
        oidc.update(cert_path="/nonexistent/c.pem", key_path="/nonexistent/k.pem")
    oidc.update(oidc_extra or {})
    return {
        "global_config": {"oidc": oidc},
        "permission_groups": {
            "g1": {"name": "Global Admins", "ldap_group": "entra-admins",
                   "permissions": {"admin": True}},
            "g2": {"name": "Operators", "ldap_group": "entra-ops",
                   "permissions": {"role": "operator"}},
            "g3": {"name": "No Entra", "permissions": {"admin": True}},
        },
    }


def _client(hub):
    app = FastAPI()
    netbox_sso.register(app, hub, None)
    return TestClient(app)


def test_enable_ports_hub_entra_connection_with_cert(cert, monkeypatch):
    for k in ("LM_OIDC_CLIENT_CERT", "LM_OIDC_CLIENT_KEY", "LM_OIDC_ALLOWED_GROUP"):
        monkeypatch.delenv(k, raising=False)
    hub = _Hub(_state(cert))
    r = _client(hub).post("/setup/netbox-sso", json={"config": {
        "enabled": True, "redirect_uri": "https://nb.example/oauth/complete/oidc/"}})
    assert r.status_code == 200, r.text
    assert r.json()["auth_mode"] == "certificate"
    (sid, mtype, p), = hub.pushes
    assert (sid, mtype) == ("agent-nb", "NETBOX_APPLY_SSO")
    assert p["tenant"] == "tid-1" and p["client_id"] == "cid-1"
    assert p["client_secret"] == ""
    assert "BEGIN CERTIFICATE" in p["client_cert_pem"]
    assert "PRIVATE KEY" in p["client_key_pem"]
    # Inherited from the hub's Azure SSO + Permission Groups.
    assert p["allowed_group"] == "hub-allowed"
    assert p["group_map"] == {"entra-admins": "Global Admins", "entra-ops": "Operators"}
    assert p["superuser_groups"] == ["entra-admins"]


def test_explicit_netbox_values_override_inherited(cert, monkeypatch):
    monkeypatch.delenv("LM_OIDC_ALLOWED_GROUP", raising=False)
    hub = _Hub(_state(cert))
    _client(hub).post("/setup/netbox-sso", json={"config": {
        "enabled": True, "allowed_group": "nb-only", "group_map": {"x": "NB X"}}})
    p = hub.pushes[-1][2]
    assert p["allowed_group"] == "nb-only"
    assert p["group_map"] == {"x": "NB X"}


def test_enable_without_cert_or_secret_is_rejected(monkeypatch):
    for k in ("LM_OIDC_CLIENT_CERT", "LM_OIDC_CLIENT_KEY"):
        monkeypatch.delenv(k, raising=False)
    hub = _Hub(_state(None))
    r = _client(hub).post("/setup/netbox-sso", json={"config": {"enabled": True}})
    assert r.status_code == 400
    assert "certificate" in r.json()["detail"]
    assert not hub.pushes


def test_secret_fallback_when_hub_has_no_cert(monkeypatch):
    for k in ("LM_OIDC_CLIENT_CERT", "LM_OIDC_CLIENT_KEY"):
        monkeypatch.delenv(k, raising=False)
    hub = _Hub(_state(None))
    r = _client(hub).post("/setup/netbox-sso", json={"config": {
        "enabled": True, "client_secret": "s3cret"}})
    assert r.status_code == 200 and r.json()["auth_mode"] == "secret"
    p = hub.pushes[-1][2]
    assert p["client_secret"] == "s3cret" and "client_key_pem" not in p


def test_disable_pushes_no_key_material(cert):
    hub = _Hub(_state(cert))
    r = _client(hub).post("/setup/netbox-sso", json={"config": {"enabled": False}})
    assert r.status_code == 200
    p = hub.pushes[-1][2]
    assert p["enabled"] is False and "client_key_pem" not in p


def test_get_reports_cert_mode_and_never_leaks_key(cert, monkeypatch):
    for k in ("LM_OIDC_CLIENT_CERT", "LM_OIDC_CLIENT_KEY"):
        monkeypatch.delenv(k, raising=False)
    hub = _Hub(_state(cert))
    r = _client(hub).get("/setup/netbox-sso")
    d = r.json()
    assert d["auth_mode"] == "certificate"
    assert d["oidc"]["cert_available"] is True
    assert d["effective"]["superuser_groups"] == ["entra-admins"]
    assert "PRIVATE KEY" not in r.text


def test_hub_hooks_drive_same_apply_for_admin_ops(cert, monkeypatch):
    """/admin/ops/netbox-sso calls hub.netbox_sso_apply — same push as the UI."""
    import asyncio
    for k in ("LM_OIDC_CLIENT_CERT", "LM_OIDC_CLIENT_KEY", "LM_OIDC_ALLOWED_GROUP"):
        monkeypatch.delenv(k, raising=False)
    hub = _Hub(_state(cert))
    _client(hub)
    res = asyncio.run(hub.netbox_sso_apply(
        {"enabled": True, "redirect_uri": "https://nb.example/oauth/complete/oidc/"}))
    assert res["auth_mode"] == "certificate" and res["pushed"] == ["agent-nb"]
    payload = hub.pushes[-1][2]
    assert payload["client_key_pem"] and payload["superuser_groups"] == ["entra-admins"]
    status = asyncio.run(hub.netbox_sso_status())
    assert status["config"]["enabled"] is True and "client_key_pem" not in str(status)
