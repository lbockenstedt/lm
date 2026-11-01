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


def test_is_due_hourly_while_a_cert_expires_within_a_day():
    def data(expires_in, ran_ago=_dt.timedelta(hours=2)):
        return {"last_run": (NOW - ran_ago).isoformat(),
                "results": [{"host": "a.io", "port": 443, "not_after": (NOW + expires_in).isoformat()}]}
    assert not cm.is_due(data(_dt.timedelta(days=5)), now=NOW)
    assert cm.is_due(data(_dt.timedelta(hours=20)), now=NOW)
    assert cm.is_due(data(-_dt.timedelta(days=3)), now=NOW)  # expired
    assert not cm.is_due(data(_dt.timedelta(hours=20), _dt.timedelta(minutes=30)), now=NOW)
    # an ignored cert does not speed up the schedule
    assert not cm.is_due(data(_dt.timedelta(hours=20)), now=NOW, ignored={"a.io:443": {}})


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


def test_ignored_helpers_flag_sort_and_count():
    res = [{"host": "a", "port": 443, "status": "red"},
           {"host": "b", "port": 8443, "status": "red"},
           {"host": "c", "port": 443, "status": "green"}]
    ign = cm.normalize_ignored({"a:443": {"by": "ops", "at": "2026-01-01"},
                                "bad host!:443": {}, "nope": {}})
    assert list(ign) == ["a:443"]
    out = cm.apply_ignored(res, ign)
    assert [r["host"] for r in out] == ["b", "c", "a"]
    assert out[-1]["ignored"] is True and out[-1]["ignored_by"] == "ops"
    assert out[-1]["status"] == "red"  # real status kept
    assert [r["host"] for r in cm.active_results(out)] == ["b", "c"]
    c = cm.count_statuses(out)
    assert c["red"] == 1 and c["green"] == 1 and c["ignored"] == 1
    # host:port identity — same host on another port is a different cert.
    assert cm.apply_ignored(res, {"b:443": {}})[0]["ignored"] is False


def test_ignore_route_roundtrip(tmp_path, monkeypatch):
    client, hub = _client(True, tmp_path, monkeypatch)
    na = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=5)).isoformat()
    cm.save_results({"last_run": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                     "results": [{"host": "old.example.com", "port": 443, "not_after": na},
                                 {"host": "api.mist.com", "port": 443, "status": "error"}]})
    assert client.post("/api/certmon/ignore", json={"host": "bad host!"}).status_code == 400
    assert client.post("/api/certmon/ignore", json={"host": "nowhere.example"}).status_code == 404

    r = client.post("/api/certmon/ignore", json={"host": "old.example.com", "port": 443})
    assert r.status_code == 200 and r.json()["key"] == "old.example.com:443"
    stored = hub.state.system_state["global_config"][cm.IGNORE_KEY]
    assert set(stored) == {"old.example.com:443"} and stored["old.example.com:443"]["at"]
    # A built-in host is monitored even before it shows up in results.
    assert client.post("/api/certmon/ignore", json={"host": "manage.mist.com"}).status_code == 200

    ov = client.get("/api/certmon/overview").json()
    row = next(r for r in ov["results"] if r["host"] == "old.example.com")
    assert row["ignored"] is True and row["status"] == "red" and row["days_left"] < 0
    assert ov["results"][-1]["host"] == "old.example.com"
    assert ov["counts"]["red"] == 0 and ov["counts"]["error"] == 1 and ov["counts"]["ignored"] == 1
    assert "old.example.com:443" in ov["ignored"]

    # Config saves don't touch the ignore list.
    assert client.put("/api/certmon/config", json={"custom_hosts": []}).status_code == 200
    assert "old.example.com:443" in hub.state.system_state["global_config"][cm.IGNORE_KEY]

    r = client.post("/api/certmon/ignore", json={"host": "old.example.com:443", "ignored": False})
    assert r.status_code == 200 and r.json()["ignored"] is False
    ov = client.get("/api/certmon/overview").json()
    assert ov["counts"]["red"] == 1 and ov["counts"]["ignored"] == 0
    assert list(ov["ignored"]) == ["manage.mist.com:443"]  # no result row yet


def test_ignore_route_admin_only(tmp_path, monkeypatch):
    client, _ = _client(False, tmp_path, monkeypatch)
    assert client.post("/api/certmon/ignore", json={"host": "a.example.com"}).status_code == 403


# ── host list auto-update ───────────────────────────────────────────────────

_MIST_PAGE = """<table><tr><td>manage.gc1.mist.com</td></tr>
<tr><td>ep-terminator.gc1.mist.com (TCP 443)</td></tr>
<tr><td>oc-term.gc1.mist.com (TCP 2200)</td></tr>
<tr><td>srx-log-terminator.gc1.mist.com (TCP 6514)</td></tr>
<tr><td>radsec.nac.mist.com (TCP 2083)</td></tr>
<tr><td>www.mist.com</td><td>manage.gc1.mist.com</td></tr></table>"""


def _mist():
    return next(s for s in cm.SOURCES if s["id"] == "mist")


def test_parse_source_ports_and_skips():
    got = {(h["host"], h["port"]): h for h in cm.parse_source(_mist(), _MIST_PAGE)}
    assert set(got) == {("manage.gc1.mist.com", 443), ("ep-terminator.gc1.mist.com", 443),
                        ("srx-log-terminator.gc1.mist.com", 6514), ("radsec.nac.mist.com", 2083)}
    assert got[("manage.gc1.mist.com", 443)]["region"] == "Global 02"
    assert got[("manage.gc1.mist.com", 443)]["service"] == "Juniper Mist"


def test_parse_source_central_filters_internal():
    src = next(s for s in cm.SOURCES if s["id"] == "new-central")
    page = "us1.api.central.arubanetworks.com internal.api.central.arubanetworks.com cn1.api.central.arubanetworks.com.cn"
    assert [h["host"] for h in cm.parse_source(src, page)] == [
        "us1.api.central.arubanetworks.com", "cn1.api.central.arubanetworks.com.cn"]


def _fake_fetch(pages):
    def fetch(url):
        for sid, page in pages.items():
            if next(s for s in cm.SOURCES if s["id"] == sid)["url"] == url:
                if isinstance(page, Exception):
                    raise page
                return page
        raise OSError("unreachable")
    return fetch


def test_refresh_sources_add_remove_and_swap(tmp_path):
    hosts = [f"h{i}.gc1.mist.com" for i in range(60)]
    page = " ".join(hosts)
    seed_mist = [h for h in cm.BUILTIN_HOSTS if h["service"] == "Juniper Mist"]
    data = cm.refresh_sources(str(tmp_path), fetch=_fake_fetch({"mist": page}))
    mist = data["mist"]
    assert len(mist["hosts"]) == 60 and mist["error"] == ""
    assert "h0.gc1.mist.com:443" in mist["added"]
    assert "www.mist.com:443" in mist["removed"]
    # unreachable sources keep the seed and record the error
    assert data["new-central"]["error"] and "hosts" not in data["new-central"]
    live = cm.builtin_hosts(str(tmp_path))
    mist_live = [h for h in live if h["service"] == "Juniper Mist"]
    # hosts the page stopped listing stay, flagged deprecated; current ones are not
    assert {h["host"] for h in mist_live if not h.get("deprecated")} == set(hosts)
    assert {h["host"] for h in mist_live if h.get("deprecated")} == {h["host"] for h in seed_mist}
    assert len(live) == len(cm.BUILTIN_HOSTS) - len(seed_mist) + 60 + len(seed_mist)


def test_deprecated_hosts_are_not_alerted_or_counted_and_expire():
    import datetime as dt
    import cert_monitor_alerts as ca
    row = {"host": "old.mist.com", "port": 443, "status": "red", "days_left": 3,
           "service": "Juniper Mist", "deprecated": True}
    breached, _, bad = ca.evaluate_rule({"trigger": "expiring", "threshold_days": 30}, [row], [])
    assert breached == [] and bad == []
    assert cm.active_results([row]) == [] and cm.count_statuses([row])["red"] == 0
    live = {**row, "host": "live.mist.com", "deprecated": False}
    assert ca.evaluate_rule({"trigger": "expiring", "threshold_days": 30}, [live], [])[0] == [live]
    now = dt.datetime.now(dt.timezone.utc)
    assert cm._past_keep_window((now - dt.timedelta(days=31)).isoformat())
    assert not cm._past_keep_window(now.isoformat())


def test_catalog_is_data_driven(tmp_path):
    import json
    p = tmp_path / "cat.json"
    p.write_text(json.dumps({"hosts": [{"host": "a.example.com", "port": 443, "service": "X", "region": "", "role": "r"}],
                             "sources": [{"id": "x", "service": "X", "role": None, "url": "https://e/x",
                                          "pattern": "{host}\\.example\\.com",
                                          "labels": [{"re": "^([^.]+)\\.", "region": "{1}", "role": "Svc"}]}]}))
    cat = cm.load_catalog(str(p))
    assert cat["hosts"][0]["host"] == "a.example.com"
    got = cm.parse_source(cat["sources"][0], "see b.example.com")
    assert got == [{"host": "b.example.com", "port": 443, "service": "X", "region": "B", "role": "Svc"}]


def test_refresh_sources_keeps_list_when_page_shrinks(tmp_path):
    page = " ".join(f"h{i}.gc1.mist.com" for i in range(60))
    cm.refresh_sources(str(tmp_path), fetch=_fake_fetch({"mist": page}))
    data = cm.refresh_sources(str(tmp_path), fetch=_fake_fetch({"mist": "h1.gc1.mist.com h2.gc1.mist.com"}))
    assert len(data["mist"]["hosts"]) == 60
    assert "only 2 host(s)" in data["mist"]["error"]
    data = cm.refresh_sources(str(tmp_path), fetch=_fake_fetch({"mist": OSError("timeout")}))
    assert len(data["mist"]["hosts"]) == 60 and "timeout" in data["mist"]["error"]


def test_sources_due_daily():
    now = _dt.datetime(2026, 1, 2, tzinfo=_dt.timezone.utc)
    fresh = {s["id"]: {"checked_at": (now - _dt.timedelta(hours=2)).isoformat()} for s in cm.SOURCES}
    assert cm.sources_due({}, now) is True
    assert cm.sources_due(fresh, now) is False
    fresh["mist"]["checked_at"] = (now - _dt.timedelta(hours=25)).isoformat()
    assert cm.sources_due(fresh, now) is True
