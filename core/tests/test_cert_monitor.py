"""Cert Expiry Monitor: cert parsing, red/yellow/green thresholds, sorting,
host-list config, daily due check, atomic JSON store, and the Global-Admin-only
/api/certmon/* routes."""
import datetime as _dt
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import FastAPI
from fastapi.testclient import TestClient

import cert_monitor as cm

NOW = _dt.datetime(2026, 10, 22, 12, 0, tzinfo=_dt.timezone.utc)


def _der(days_valid=45, cn="api.mist.com", issuer_org="Example CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
                        x509.NameAttribute(NameOID.COMMON_NAME, "Example Issuing CA")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(0xABC)
            .not_valid_before(NOW - _dt.timedelta(days=10))
            .not_valid_after(NOW + _dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName(cn), x509.DNSName("*.mist.com")]), critical=False)
            .add_extension(x509.CertificatePolicies([x509.PolicyInformation(
                x509.ObjectIdentifier("2.23.140.1.2.2"), None)]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_cert_fields():
    info = cm.parse_cert(_der(45), now=NOW)
    assert info["subject_cn"] == "api.mist.com"
    assert info["provider"] == "Example CA"
    assert info["issuer_cn"] == "Example Issuing CA"
    assert info["key_type"] == "ECDSA secp256r1"
    assert info["cert_type"] == "OV wildcard"
    assert info["days_left"] == 45
    assert info["serial"] == "ABC"
    assert "*.mist.com" in info["san"]


@pytest.mark.parametrize("days,status", [
    (-3, "red"), (0, "red"), (29, "red"), (30, "yellow"), (89, "yellow"),
    (90, "green"), (400, "green")])
def test_classify_thresholds(days, status):
    assert cm.classify(days) == status


def test_classify_error_and_unknown():
    assert cm.classify(None, "DNS: nope") == "error"
    assert cm.classify(None) == "unknown"


def test_sort_red_first_then_yellow_then_green():
    rows = [{"host": "g", "status": "green", "days_left": 200},
            {"host": "y", "status": "yellow", "days_left": 60},
            {"host": "e", "status": "error", "days_left": None},
            {"host": "r2", "status": "red", "days_left": 20},
            {"host": "r1", "status": "red", "days_left": 5}]
    assert [r["host"] for r in cm.sort_results(rows)] == ["r1", "r2", "y", "e", "g"]


def test_builtin_hosts_cover_mist_and_central():
    names = {h["host"] for h in cm.BUILTIN_HOSTS}
    for h in ("api.mist.com", "manage.mist.com", "api.gc1.mist.com", "api.eu.mist.com",
              "ep-terminator.mistsys.net", "portal.central.arubanetworks.com",
              "apigw-prod2.central.arubanetworks.com", "us1.api.central.arubanetworks.com",
              "sso.common.cloud.hpe.com"):
        assert h in names
    assert len(names) == len(cm.BUILTIN_HOSTS), "duplicate built-in host"


@pytest.mark.parametrize("raw,expected", [
    ("example.com", ("example.com", 443)),
    ("https://Example.com:8443/path", ("example.com", 8443)),
    ("a.b.c:443", ("a.b.c", 443)),
    ("bad host", None), ("x.com:99999", None), ("", None), ("-a.com", None),
    ("a..b", None), ("x.com;rm", None)])
def test_parse_host_entry(raw, expected):
    assert cm.parse_host_entry(raw) == expected


def test_effective_hosts_custom_and_disabled():
    cfg = {"custom_hosts": ["my.example.com", "my.example.com", "api.mist.com", "x.io:8443"],
           "disabled_builtin": ["manage.mist.com", "not-a-builtin.com"]}
    norm = cm.normalize_config(cfg)
    assert norm["disabled_builtin"] == ["manage.mist.com"]
    assert norm["custom_hosts"] == ["my.example.com", "api.mist.com", "x.io:8443"]
    hosts = cm.effective_hosts(cfg)
    names = [(h["host"], h["port"]) for h in hosts]
    assert ("manage.mist.com", 443) not in names
    assert names.count(("api.mist.com", 443)) == 1
    assert ("x.io", 8443) in names
    assert ("my.example.com", 443) in names


def test_is_due_once_a_day():
    assert cm.is_due({}, now=NOW)
    recent = {"last_run": (NOW - _dt.timedelta(hours=23)).isoformat()}
    old = {"last_run": (NOW - _dt.timedelta(hours=24, minutes=1)).isoformat()}
    assert not cm.is_due(recent, now=NOW)
    assert cm.is_due(old, now=NOW)


def test_save_and_load_roundtrip(tmp_path):
    data = {"last_run": NOW.isoformat(), "results": [{"host": "a"}]}
    cm.save_results(data, state_dir=str(tmp_path))
    assert cm.load_results(state_dir=str(tmp_path)) == data
    assert [p.name for p in tmp_path.iterdir()] == ["cert_monitor.json"]


def test_probe_dns_failure_is_error(monkeypatch):
    import socket

    def boom(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(cm.socket, "getaddrinfo", boom)
    r = cm.probe_host({"host": "nope.invalid", "service": "Custom"})
    assert r["status"] == "error" and r["error"].startswith("DNS")


def test_probe_untrusted_cert_still_recorded(monkeypatch):
    import ssl
    der = _der(10)
    monkeypatch.setattr(cm.socket, "getaddrinfo", lambda *a, **k: [()])

    def hs(host, port, verify, timeout):
        if verify:
            raise ssl.SSLCertVerificationError("unable to get local issuer certificate")
        return der, "TLSv1.3"
    monkeypatch.setattr(cm, "_handshake", hs)
    r = cm.probe_host({"host": "ep-terminator.mist.com"})
    assert r["trusted"] is False and r["verify_error"]
    assert r["status"] == "red" and r["provider"] == "Example CA"
    assert r["error"] == ""


# ── routes ──────────────────────────────────────────────────────────────────

class _State:
    def __init__(self):
        self.system_state = {"global_config": {}}

    def _mark_dirty(self):
        pass

    async def save_state_now(self):
        pass


def _client(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(cm, "STATE_DIR", str(tmp_path))
    import routes.cert_monitor as rcm
    hub = SimpleNamespace(state=_State())
    sess = {"user": {"is_admin": admin}}
    ctx = SimpleNamespace(_session_user=lambda request: sess,
                          _is_admin=lambda s: bool(s and s["user"]["is_admin"]))
    app = FastAPI()
    rcm.register(app, hub, ctx)
    return TestClient(app), hub


@pytest.mark.parametrize("method,path", [
    ("get", "/api/certmon/status"), ("get", "/api/certmon/overview"),
    ("put", "/api/certmon/config"), ("post", "/api/certmon/run")])
def test_routes_admin_only(method, path, tmp_path, monkeypatch):
    client, _ = _client(False, tmp_path, monkeypatch)
    kw = {"json": {"enabled": True}} if method == "put" else {}
    assert getattr(client, method)(path, **kw).status_code == 403


def test_config_roundtrip_and_overview(tmp_path, monkeypatch):
    client, hub = _client(True, tmp_path, monkeypatch)
    assert client.get("/api/certmon/status").json()["enabled"] is False
    assert client.post("/api/certmon/run").status_code == 409

    r = client.put("/api/certmon/config", json={"custom_hosts": ["bad host!"]})
    assert r.status_code == 400
    r = client.put("/api/certmon/config", json={"custom_hosts": "a.example.com\nb.example.com:8443"})
    assert r.status_code == 200
    assert hub.state.system_state["global_config"]["cert_monitor"]["custom_hosts"] == [
        "a.example.com", "b.example.com:8443"]

    # Stored results: overview recomputes days_left from not_after, sorts red first.
    na_soon = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=10, hours=1)).isoformat()
    na_late = (_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=200, hours=1)).isoformat()
    cm.save_results({"last_run": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "results": [{"host": "late", "not_after": na_late, "status": "green", "days_left": 200},
                                 {"host": "soon", "not_after": na_soon, "status": "green", "days_left": 999}]})
    ov = client.get("/api/certmon/overview").json()
    assert [r["host"] for r in ov["results"]] == ["soon", "late"]
    assert ov["results"][0]["status"] == "red" and ov["results"][0]["days_left"] == 10
    assert ov["counts"]["red"] == 1 and ov["counts"]["green"] == 1
    assert ov["config"]["enabled"] is False


def test_enable_triggers_first_check_when_due(tmp_path, monkeypatch):
    client, hub = _client(True, tmp_path, monkeypatch)
    monkeypatch.setattr(cm, "run_checks", lambda hosts: {
        "last_run": NOW.isoformat(), "duration_s": 0.1, "counts": {}, "results": []})
    r = client.put("/api/certmon/config", json={"enabled": True})
    assert r.status_code == 200 and r.json()["config"]["enabled"] is True
    assert r.json()["check_started"] is True
    assert client.get("/api/certmon/status").json()["enabled"] is True
