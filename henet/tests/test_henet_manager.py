"""Unit tests for ``HENetManager`` — the HE.NET dyndns record manager.

The manager pushes A/AAAA records to Hurricane Electric over its dynamic-DNS
update endpoint and tracks the managed set in a local JSON state file. Every
test injects a fake ``http_post`` so nothing touches the network, and asserts:
  * A/AAAA records are pushed with the right dyndns form (hostname/password/myip)
  * a per-record ``key`` overrides the shared ``ddns_key``
  * HE's ``good``/``nochg`` are success, anything else is an error
  * non-A/AAAA types, bad IPs, and a missing key are rejected WITHOUT a push
  * list/delete round-trip through the local state file
  * the HE DDNS key is NEVER persisted to the state file (secrets stay off-spoke)
"""

import json

import pytest

from henet_manager import HENetManager


class FakePoster:
    """Records every (url, form) push and returns a scripted HE response body.

    ``responses`` maps hostname -> body; a default of ``"good 1.2.3.4"`` is used
    when a hostname isn't scripted. A keyless probe (``status``) posts an empty
    form and just needs to not raise."""

    def __init__(self, responses=None, raise_on=None):
        self.calls = []
        self.responses = responses or {}
        self.raise_on = raise_on or set()

    def __call__(self, url, form):
        self.calls.append((url, dict(form)))
        host = form.get("hostname", "")
        if host in self.raise_on:
            raise OSError("boom")
        return self.responses.get(host, "good 192.0.2.1")


def _mgr(tmp_path, **kw):
    return HENetManager(state_path=str(tmp_path / "records.json"), http_post=FakePoster(**kw))


def test_add_pushes_a_record(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.add_record("host.example.com", "A", "203.0.113.5", 300, ddns_key="KEY123")
    assert res["status"] == "SUCCESS"
    assert res["pushed"] == 1
    assert len(poster.calls) == 1
    url, form = poster.calls[0]
    assert "dyn.dns.he.net" in url
    assert form == {"hostname": "host.example.com", "password": "KEY123", "myip": "203.0.113.5"}


def test_per_record_key_overrides_shared(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.sync([{"name": "a.example.com", "type": "A", "value": "203.0.113.1", "key": "PERKEY"}],
             ddns_key="SHARED")
    _, form = poster.calls[0]
    assert form["password"] == "PERKEY"


def test_aaaa_supported(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.add_record("v6.example.com", "AAAA", "2001:db8::1", ddns_key="K")
    assert res["pushed"] == 1
    _, form = poster.calls[0]
    assert form["myip"] == "2001:db8::1"


def test_nochg_is_success(tmp_path):
    poster = FakePoster(responses={"h.example.com": "nochg 203.0.113.9"})
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.add_record("h.example.com", "A", "203.0.113.9", ddns_key="K")
    assert res["status"] == "SUCCESS" and res["pushed"] == 1


def test_badauth_is_error_and_recorded(tmp_path):
    poster = FakePoster(responses={"h.example.com": "badauth"})
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.add_record("h.example.com", "A", "203.0.113.9", ddns_key="WRONG")
    assert res["status"] == "PARTIAL"
    assert res["pushed"] == 0
    assert any("badauth" in e for e in res["errors"])
    rec = mgr.list_records()[0]
    assert rec["last_push_status"] == "error"
    assert "badauth" in rec["last_push_detail"]


def test_non_a_aaaa_rejected_without_push(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.sync([{"name": "c.example.com", "type": "CNAME", "value": "target.example.com"}],
                   ddns_key="K")
    assert res["status"] == "PARTIAL"
    assert poster.calls == []  # nothing pushed
    assert "A/AAAA" in mgr.list_records()[0]["last_push_detail"]


def test_bad_ip_rejected_without_push(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.sync([{"name": "h.example.com", "type": "A", "value": "not-an-ip"}], ddns_key="K")
    assert res["status"] == "PARTIAL"
    assert poster.calls == []


def test_missing_key_rejected_without_push(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.add_record("h.example.com", "A", "203.0.113.9", ddns_key="")
    assert res["status"] == "PARTIAL"
    assert poster.calls == []
    assert "DDNS key" in mgr.list_records()[0]["last_push_detail"]


def test_list_and_delete_roundtrip(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("a.example.com", "A", "203.0.113.1", ddns_key="K")
    mgr.add_record("b.example.com", "A", "203.0.113.2", ddns_key="K")
    assert {r["name"] for r in mgr.list_records()} == {"a.example.com", "b.example.com"}
    out = mgr.delete_record("a.example.com")
    assert out["status"] == "SUCCESS"
    assert {r["name"] for r in mgr.list_records()} == {"b.example.com"}


def test_update_replaces_same_name_type(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K")
    mgr.update_record("h.example.com", "A", "203.0.113.2", ddns_key="K")
    recs = [r for r in mgr.list_records() if r["name"] == "h.example.com"]
    assert len(recs) == 1
    assert recs[0]["value"] == "203.0.113.2"


def test_tenant_id_persisted_on_add(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K", tenant_id="lrb")
    recs = mgr.list_records()
    assert recs[0]["tenant_id"] == "lrb"


def test_tenant_id_defaults_to_empty_string_when_unset(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K")
    recs = mgr.list_records()
    assert recs[0]["tenant_id"] == ""


def test_tenant_id_preserved_across_update(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K", tenant_id="lrb")
    mgr.update_record("h.example.com", "A", "203.0.113.2", ddns_key="K", tenant_id="lrb")
    recs = [r for r in mgr.list_records() if r["name"] == "h.example.com"]
    assert len(recs) == 1
    assert recs[0]["tenant_id"] == "lrb"
    assert recs[0]["value"] == "203.0.113.2"


def test_set_tenant_rehomes_without_pushing(tmp_path):
    """set_tenant changes ownership only — no HE push (poster untouched), the
    IP/last-push status are preserved. Lets records be organised onto per-tenant
    tabs even when the dyndns endpoint is unreachable."""
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K")  # global
    pushes_before = len(poster.calls) if hasattr(poster, "calls") else None
    res = mgr.set_tenant("h.example.com", "A", "lrb")
    assert res == {"status": "SUCCESS", "updated": 1, "tenant_id": "lrb"}
    rec = [r for r in mgr.list_records() if r["name"] == "h.example.com"][0]
    assert rec["tenant_id"] == "lrb"
    assert rec["value"] == "203.0.113.1"  # IP untouched (no push)
    if pushes_before is not None:
        assert len(poster.calls) == pushes_before  # set_tenant never pushes


def test_set_tenant_back_to_global(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K", tenant_id="lrb")
    mgr.set_tenant("h.example.com", "A", "")
    rec = [r for r in mgr.list_records() if r["name"] == "h.example.com"][0]
    assert rec["tenant_id"] == ""


def test_set_tenant_no_match_updates_zero(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K")
    res = mgr.set_tenant("nope.example.com", "A", "lrb")
    assert res["updated"] == 0


def test_ddns_key_never_persisted(tmp_path):
    state = tmp_path / "r.json"
    mgr = HENetManager(state_path=str(state), http_post=FakePoster())
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="SUPERSECRET", key="ALSOSECRET")
    raw = state.read_text()
    assert "SUPERSECRET" not in raw
    assert "ALSOSECRET" not in raw
    assert "password" not in json.loads(raw)[0]


def test_status_reports_reachable(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("h.example.com", "A", "203.0.113.1", ddns_key="K")
    s = mgr.status()
    assert s["reachable"] is True
    assert s["record_count"] == 1
    assert "dyn.dns.he.net" in s["endpoint"]


def test_status_unreachable_when_probe_raises(tmp_path):
    class Boom:
        def __call__(self, url, form):
            raise OSError("no network")
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=Boom())
    assert mgr.status()["reachable"] is False


def test_status_reachable_when_probe_returns_http_401(tmp_path):
    """Regression: HE now answers the keyless probe with HTTP 401 (Authorization
    Required) instead of a 200 ``badauth`` body. A 401 is a response FROM the
    endpoint — it's reachable, only the (absent) credential was rejected — so the
    status line must NOT read "unreachable (HTTP Error 401 …)"."""
    from urllib.error import HTTPError

    class Unauthorized:
        def __call__(self, url, form):
            raise HTTPError(url, 401, "Authorization Required", {}, None)
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=Unauthorized())
    s = mgr.status()
    assert s["reachable"] is True
    assert s["detail"] == ""


def test_status_detail_surfaces_reason_when_unreachable(tmp_path):
    """Regression: an unreachable endpoint must explain WHY (transport error
    string) so the operator can tell an egress/TLS block apart from auth."""
    class Boom:
        def __call__(self, url, form):
            raise OSError("no route to host")
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=Boom())
    s = mgr.status()
    assert s["reachable"] is False
    assert "no route to host" in s["detail"]
    assert "OSError" in s["detail"]


def test_status_detail_empty_when_reachable(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    assert mgr.status()["detail"] == ""


# ── import_records: merge scraped zone records without pushing ────────────────

def test_import_records_adds_new_a_aaaa_without_pushing(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    res = mgr.import_records([
        {"name": "www.example.com", "type": "A", "value": "203.0.113.10", "ttl": 300},
        {"name": "home.example.com", "type": "AAAA", "value": "2001:db8::1", "ttl": 600},
    ])
    assert res["status"] == "SUCCESS"
    assert res["imported"] == 2
    # imported records are registered but NEVER pushed (no dyndns round-trip)
    assert poster.calls == []
    recs = {r["name"]: r for r in mgr.list_records()}
    assert recs["www.example.com"]["last_push_status"] == "imported"
    assert recs["www.example.com"]["source"] == "he-import"


def test_import_records_skips_already_managed(tmp_path):
    poster = FakePoster()
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=poster)
    mgr.add_record("www.example.com", "A", "203.0.113.5", ddns_key="K")
    res = mgr.import_records([
        {"name": "www.example.com", "type": "A", "value": "203.0.113.10"},
        {"name": "new.example.com", "type": "A", "value": "203.0.113.11"},
    ])
    assert res["imported"] == 1 and res["skipped"] == 1
    recs = {r["name"]: r for r in mgr.list_records()}
    # LM's existing copy (and its pushed value) is untouched by the import
    assert recs["www.example.com"]["value"] == "203.0.113.5"
    assert recs["www.example.com"]["last_push_status"] == "ok"
    assert recs["new.example.com"]["last_push_status"] == "imported"


def test_import_records_skips_non_a_aaaa_and_bad_rows(tmp_path):
    mgr = HENetManager(state_path=str(tmp_path / "r.json"), http_post=FakePoster())
    res = mgr.import_records([
        {"name": "example.com", "type": "MX", "value": "10 mail.example.com"},
        {"name": "", "type": "A", "value": "203.0.113.1"},
        {"name": "ok.example.com", "type": "A", "value": "203.0.113.2"},
    ])
    assert res["imported"] == 1 and res["skipped"] == 2
    assert [r["name"] for r in mgr.list_records()] == ["ok.example.com"]
