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


# ── LE deployment verification ───────────────────────────────────────────────

def _le_cert(domain="netbox.example.com", not_after="2027-02-14T02:22:00+00:00",
             status="SUCCESS", message=""):
    """One cached LE cert with a single target in a given push status."""
    return {"domain": domain, "not_after": not_after, "tenant_id": "t1",
            "targets": [{"module_type": "ipam", "identifier": "agent-a",
                         "last_status": status, "last_message": message}]}


def test_le_cert_list_reads_flat_and_enveloped():
    """le_cert_list accepts the flat, the enveloped and the empty shapes."""
    c = _le_cert()
    assert cm.le_cert_list({"certs": [c]}) == [c]
    assert cm.le_cert_list({"status": "SUCCESS", "data": {"certs": [c]}}) == [c]
    assert cm.le_cert_list(None) == []


def test_le_hosts_only_pushed_certs():
    """A cert with no attempted push is never listed; pushed one adds its host."""
    unpushed = _le_cert(status="")
    assert cm.le_hosts([unpushed]) == []
    e = cm.le_hosts([_le_cert()])[0]
    assert (e["host"], e["port"]) == ("netbox.example.com", 443)
    assert e["service"] == cm.LE_SERVICE and e["le"]["wildcard"] is False
    assert cm.le_hosts([_le_cert(domain="*.example.com")])[0]["le"]["wildcard"] is True


def test_merge_le_hosts_attaches_to_existing():
    """An endpoint already monitored keeps its entry and gains the LE comparison."""
    hosts = [{"host": "netbox.example.com", "port": 443, "service": "Custom",
              "region": "", "role": "Custom"}]
    merged = cm.merge_le_hosts(hosts, cm.le_hosts([_le_cert()]))
    assert len(merged) == 1 and merged[0]["service"] == "Custom"
    assert "le" in merged[0] and "le" not in hosts[0]


def test_verify_le_verified():
    """Serving the issued cert within tolerance verifies it and stays green."""
    row = {"host": "netbox.example.com", "port": 443, "error": "",
           "not_after": "2027-02-14T02:22:00+00:00", "status": "green", "days_left": 100,
           "san": ["netbox.example.com"]}
    entry = cm.le_hosts([_le_cert()])[0]
    out = cm.verify_le(row, entry["le"])
    assert out["deploy_state"] == "verified" and out["status"] == "green"


def test_verify_le_stale_is_red_and_quotes_deferred():
    """A served cert earlier than the issued one is stale, red, and quotes the push."""
    row = {"host": "netbox.example.com", "port": 443, "error": "",
           "not_after": "2026-11-16T02:22:00+00:00", "status": "green", "san": ["netbox.example.com"]}
    out = cm.verify_le(row, cm.le_hosts([_le_cert(status="DEFERRED",
                    message="cached but NOT installed")])[0]["le"])
    assert out["deploy_state"] == "stale" and out["status"] == "red"
    assert "DEFERRED" in out["deploy_detail"]
    assert "cached but NOT installed" in out["deploy_detail"]


def test_verify_le_unreachable():
    """A probe error means the endpoint is unreachable and the status stays error."""
    row = {"host": "netbox.example.com", "port": 443, "error": "TimeoutError: timed out",
           "status": "error"}
    out = cm.verify_le(row, cm.le_hosts([_le_cert()])[0]["le"])
    assert out["deploy_state"] == "unreachable" and out["status"] == "error"
    assert "timed out" in out["deploy_detail"]


def test_check_host_wildcard_not_probed(monkeypatch):
    """A wildcard LE entry is listed as unverifiable without a network probe."""
    monkeypatch.setattr(cm, "probe_host",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("probed")))
    entry = cm.le_hosts([_le_cert(domain="*.example.com")])[0]
    row = cm.check_host(entry)
    assert row["deploy_state"] == "unverifiable" and row["status"] == "unknown"


def test_le_retry_hourly_without_hourly_full_scan():
    """A failing LE endpoint is re-checked hourly on its own; the full scan stays daily."""
    def data(state, mins_ago=61):
        return {"last_run": (NOW - _dt.timedelta(minutes=mins_ago)).isoformat(),
                "results": [{"host": "a.example.com", "port": 443, "deploy_state": state,
                             "not_after": (NOW + _dt.timedelta(days=200)).isoformat()}]}
    assert cm.check_interval(data("stale"), now=NOW) == cm.CHECK_INTERVAL_S
    assert cm.le_retry_due(data("stale"), now=NOW) is True
    assert cm.le_retry_due(data("stale", mins_ago=30), now=NOW) is False
    assert cm.le_retry_due(data("verified"), now=NOW) is False
    assert cm.le_retry_due(data("stale"), ignored={"a.example.com:443": {}}, now=NOW) is False


def test_expired_le_only_row_keeps_full_scan_daily():
    """An LE-only row serving an expired cert is retried on its own; it must
    not make the full scan hourly (that would pre-empt the LE-only retry)."""
    expired = (NOW - _dt.timedelta(days=3)).isoformat()
    row = {"host": "a.example.com", "port": 443, "deploy_state": "stale", "not_after": expired}
    data = {"last_run": (NOW - _dt.timedelta(minutes=61)).isoformat(),
            "results": [{**row, "service": cm.LE_SERVICE}]}
    assert cm.check_interval(data, now=NOW) == cm.CHECK_INTERVAL_S
    assert cm.is_due(data, now=NOW) is False and cm.le_retry_due(data, now=NOW) is True
    # A monitored endpoint (not LE-only) expiring still goes hourly.
    data["results"][0]["service"] = "Custom"
    assert cm.check_interval(data, now=NOW) == cm.URGENT_CHECK_S


def test_le_target_labels_use_names_not_uuids():
    """Target ids are shown by name; an unresolved UUID is left out."""
    sid = "0b8f6a52-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
    c = _le_cert()
    c["targets"] = [{"module_type": "netbox-server", "identifier": sid, "last_status": "SUCCESS"},
                    {"module_type": "ipam", "identifier": "9a8b7c6d-1c2d-4e5f-8a9b-0c1d2e3f4a5b",
                     "last_status": "SUCCESS"}]
    e = cm.le_hosts([c], {sid: "LM-NETBOX"})[0]
    assert e["role"] == "netbox-server/LM-NETBOX, ipam"
    assert [t["target"] for t in e["le"]["targets"]] == ["netbox-server/LM-NETBOX", "ipam"]
    # An agent with no hostname resolves to its own UUID id: still not shown.
    assert cm.le_target_label({"module_type": "ipam", "identifier": "a"},
                              {"a": "9a8b7c6d-1c2d-4e5f-8a9b-0c1d2e3f4a5b"}) == "ipam"


def test_le_hosts_probe_port_per_target_type():
    """Proxmox targets are checked on pveproxy's 8006, the rest on 443."""
    c = _le_cert()
    c["targets"].append({"module_type": "hypervisor", "identifier": "pve1", "last_status": "SUCCESS"})
    ports = {e["port"]: e["role"] for e in cm.le_hosts([c])}
    assert ports == {443: "ipam/agent-a", 8006: "hypervisor/pve1"}


def test_verify_le_newer_and_mismatch():
    """A newer served cert (the ledger copy lags) is not a failure; one that
    does not cover the domain is a mismatch."""
    le = cm.le_hosts([_le_cert()])[0]["le"]
    row = {"host": "netbox.example.com", "port": 443, "error": "", "status": "green",
           "not_after": "2027-05-14T02:22:00+00:00", "san": ["netbox.example.com"]}
    out = cm.verify_le(dict(row), le)
    assert out["deploy_state"] == "newer" and out["deploy_state"] not in cm.DEPLOY_BAD
    out = cm.verify_le(dict(row, san=["*.other.com"], subject_cn="*.other.com"), le)
    assert out["deploy_state"] == "mismatch" and out["status"] == "red"
    assert cm.verify_le(dict(row, san=["*.example.com"]), le)["deploy_state"] == "newer"
    # A cert with no SAN at all is never the issued LE cert, whatever its expiry.
    for na in ("2027-05-14T02:22:00+00:00", le["issued_not_after"]):
        assert cm.verify_le(dict(row, san=[], not_after=na, subject_cn="localhost"), le)["deploy_state"] == "mismatch"


def test_merge_le_results_keeps_full_scan_rows():
    """An LE-only run replaces its rows, drops LE rows no longer pushed and keeps the full scan's schedule."""
    prev = {"last_run": "2026-11-01T00:00:00+00:00", "scope": "all", "results": [
        {"host": "mist.com", "port": 443, "status": "green", "service": "Juniper Mist"},
        {"host": "nb.example.com", "port": 443, "status": "red", "service": cm.LE_SERVICE,
         "deploy_state": "stale"},
        {"host": "gone.example.com", "port": 443, "status": "red", "service": cm.LE_SERVICE},
        {"host": "own.example.com", "port": 443, "status": "green", "service": "Custom",
         "le_domain": "own.example.com", "deploy_state": "stale"}]}
    run = {"last_run": "2026-11-01T05:00:00+00:00", "duration_s": 1.0, "results": [
        {"host": "nb.example.com", "port": 443, "status": "green", "service": cm.LE_SERVICE,
         "deploy_state": "verified"}]}
    out = cm.merge_le_results(prev, run)
    rows = {r["host"]: r for r in out["results"]}
    assert set(rows) == {"mist.com", "nb.example.com", "own.example.com"}
    assert rows["nb.example.com"]["deploy_state"] == "verified"
    assert "deploy_state" not in rows["own.example.com"]
    assert out["last_run"] == prev["last_run"] and out["le_checked_at"] == run["last_run"]
    assert out["counts"]["green"] == 3


def test_le_fingerprint_changes_with_status():
    """The fingerprint changes with a target's push status and is stable for equal input."""
    base = cm.le_fingerprint(cm.le_hosts([_le_cert()]))
    deferred = cm.le_fingerprint(cm.le_hosts([_le_cert(status="DEFERRED")]))
    assert base != deferred
    assert base == cm.le_fingerprint(cm.le_hosts([_le_cert()]))


def test_same_domain_two_tenants_each_get_a_verdict():
    """Two tenants' certs for one domain share a probe but each gets its own verdict."""
    a = _le_cert(not_after="2027-02-14T02:22:00+00:00")
    b = dict(_le_cert(not_after="2026-12-01T00:00:00+00:00"), tenant_id="t2")
    entries = cm.le_hosts([a, b])
    assert len(entries) == 1 and len(entries[0]["le"]["others"]) == 1
    row = {"host": "netbox.example.com", "port": 443, "error": "", "status": "green",
           "not_after": "2027-02-14T02:22:00+00:00", "san": ["netbox.example.com"]}
    out = cm.verify_le(row, entries[0]["le"])
    assert out["deploy_state"] == "verified"
    va = cm.le_served_verdict([out], {**a, "domain": "netbox.example.com"})
    vb = cm.le_served_verdict([out], {**b, "domain": "netbox.example.com"})
    assert va["deploy_state"] == "verified" and vb["deploy_state"] == "newer"
    assert cm.le_served_verdict([out], {**a, "tenant_id": "t3"}) is None
    assert cm.le_fingerprint(entries) != cm.le_fingerprint(cm.le_hosts([a]))



def test_scope_le_rows_hides_other_tenants_verdicts():
    """The global page/rules see only the viewing tenant's and shared LE
    verdicts, and a scoped row's colour, targets and tenant come only from them."""
    import cert_monitor as cm

    def v(tenant, state, target):
        """One verdict for ``tenant`` pushed to ``target``."""
        return {"tenant_id": tenant, "issued_not_after": "2027-02-14", "deploy_state": state,
                "deploy_detail": state, "role": target, "targets": [f"{target}: SUCCESS"]}
    ok = {"days_left": 200, "error": "", "status": "red"}
    rows = [
        {"host": "a.example", "service": cm.LE_SERVICE, "le_domain": "a.example", **ok,
         "le_verdicts": [v("acme", "stale", "ipam/acme-nb")]},
        {"host": "b.example", "service": cm.LE_SERVICE, "le_domain": "b.example", **ok,
         "deploy_state": "stale", "le_tenant_id": "acme", "le_targets": ["ipam/acme-nb: SUCCESS"],
         "le_verdicts": [v("acme", "stale", "ipam/acme-nb"), v("Globex", "verified", "firewall/gx")]},
        {"host": "c.example", "service": "custom", "role": "web", "le_domain": "c.example", **ok,
         "deploy_state": "stale", "le_verdicts": [v("acme", "stale", "ipam/acme-nb")]},
        {"host": "d.example", "service": "custom", "status": "green"},
    ]
    shared = cm.scope_le_rows(rows)
    assert [r["host"] for r in shared] == ["c.example", "d.example"]
    assert shared[0]["status"] == "green" and shared[0]["role"] == "web"
    assert not any(k.startswith(("le_", "deploy_")) for k in shared[0])
    globex = cm.scope_le_rows(rows, "globex")
    b = globex[0]
    assert [r["host"] for r in globex] == ["b.example", "c.example", "d.example"]
    assert (b["deploy_state"], b["status"], b["le_tenant_id"]) == ("verified", "green", "Globex")
    assert b["le_targets"] == ["firewall/gx: SUCCESS"] and b["role"] == "firewall/gx"
    acme = cm.scope_le_rows(rows, "ACME")
    assert [r["host"] for r in acme] == ["a.example", "b.example", "c.example", "d.example"]
    assert acme[1]["deploy_state"] == "stale" and acme[1]["status"] == "red"


def test_log_deploy_problems_logs_each_failing_cert(caplog):
    """Two certs failing on one shared endpoint log one warning each, with their tenant."""
    import cert_monitor as cm
    row = {"host": "nb.example", "port": 443, "le_domain": "nb.example", "le_verdicts": [
        {"tenant_id": "acme", "deploy_state": "stale", "deploy_detail": "old acme"},
        {"tenant_id": "globex", "deploy_state": "unreachable", "deploy_detail": "down"},
        {"tenant_id": "initech", "deploy_state": "verified", "deploy_detail": ""}]}
    with caplog.at_level("WARNING"):
        cm.log_deploy_problems([row])
    lines = [r.getMessage() for r in caplog.records]
    assert lines == ["[cert-verify] nb.example:443 STALE (tenant acme): old acme",
                     "[cert-verify] nb.example:443 UNREACHABLE (tenant globex): down"]


def test_keep_le_results_holds_le_state_on_full_scan():
    """A full scan made while the LE list is unreadable keeps the last LE rows,
    verdicts (and the red they imply) and fingerprint."""
    prev = {"le_fingerprint": "fp", "le_checked_at": "t0", "results": [
        {"host": "le.example.com", "port": 443, "service": cm.LE_SERVICE, "status": "red",
         "deploy_state": "stale"},
        {"host": "nb.example.com", "port": 443, "service": "Custom", "status": "red",
         "deploy_state": "mismatch", "le_domain": "nb.example.com"}]}
    run = {"last_run": "t1", "results": [{"host": "nb.example.com", "port": 443, "service": "Custom",
                                          "status": "green", "days_left": 80}]}
    out = cm.keep_le_results(prev, run)
    rows = {r["host"]: r for r in out["results"]}
    assert rows["le.example.com"]["deploy_state"] == "stale"
    assert rows["nb.example.com"]["deploy_state"] == "mismatch" and rows["nb.example.com"]["status"] == "red"
    assert (out["le_fingerprint"], out["le_checked_at"], out["last_run"]) == ("fp", "t0", "t1")


def test_le_fingerprint_keys_targets_by_id_not_label():
    """Swapping one unresolved target UUID for another is an LE change even
    though both labels drop the UUID."""
    def fp(ident):
        c = _le_cert()
        c["targets"][0]["identifier"] = ident
        return cm.le_fingerprint(cm.le_hosts([c]))
    a, b = "0b8f6a52-1c2d-4e5f-8a9b-0c1d2e3f4a5b", "1c9f6a52-1c2d-4e5f-8a9b-0c1d2e3f4a5b"
    assert fp(a) != fp(b)
