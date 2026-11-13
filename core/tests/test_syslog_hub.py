"""Syslog hub side: settings validation, archive record masking, tenant scoping,
query merge, the syslog role hooks and the /api/syslog routes (docs/syslog.md).

Uses a small in-memory hub: the real tenant resolver
(``SpokeRegistryMixin.get_logging_spokes_for_tenant``), the real overview cache
mixin, and a stubbed ``request_response`` that records every command sent.
"""

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import syslog_archive as sa
from _fakes import FakeState
from hub_spoke_registry import SpokeRegistryMixin
from routes import syslog as syslog_routes
from syslog_cache import SyslogCacheMixin


def _run(coro):
    """Run a coroutine on the current loop."""
    return asyncio.get_event_loop().run_until_complete(coro)


class _Hub(SyslogCacheMixin):
    """Two tenants: acme has collectors c1+c2, other has c3. agent-gl is acme's
    archive host (a plain agent, no logging spoke)."""

    def __init__(self, tmp_path, replies=None):
        md = {
            "c1": {"tenant_id": "acme", "display_name": "col-a1"},
            "c2": {"tenant_id": "acme", "display_name": "col-a2"},
            "c3": {"tenant_id": "other", "display_name": "col-o1"},
            "agent-gl": {"tenant_id": "acme", "display_name": "gl-host"},
            "agent-c": {"tenant_id": "acme", "display_name": "col-host"},
        }
        self.state = FakeState(system_state={"module_metadata": md},
                               spoke_tenants={k: v["tenant_id"] for k, v in md.items()})
        self.spoke_module_types = {"c1": "logging", "c2": "logging", "c3": "logging",
                                   "agent-gl": "agent", "agent-c": "agent"}
        self.active_connections = set(self.spoke_module_types)
        self.approved_modules = {k: True for k in self.spoke_module_types}
        self.cache_dir = str(tmp_path)
        self.replies = replies or {}
        self.sent = []
        self.syslog_cache_init()

    def _primary_key(self, sid):
        """Identity: ids are already primary keys here."""
        return sid

    def get_all_spokes_by_type(self, module_type):
        """Connected spokes of a module type."""
        return [s for s, t in self.spoke_module_types.items() if t == module_type]

    def get_logging_spokes_for_tenant(self, tenant_id):
        """The real tenant resolver."""
        return SpokeRegistryMixin.get_logging_spokes_for_tenant(self, tenant_id)

    async def request_response(self, sid, cmd, data=None, timeout=None):
        """Record the command; reply from ``replies[(sid, cmd)]`` or SUCCESS."""
        self.sent.append((sid, cmd, data))
        reply = self.replies.get((sid, cmd), {"status": "SUCCESS"})
        if isinstance(reply, Exception):
            raise reply
        return {"payload": {"data": reply}}


@pytest.fixture(autouse=True)
def _fake_ca(monkeypatch):
    """Hub CA without touching disk."""
    from security import mtls_ca
    monkeypatch.setattr(mtls_ca, "issue_service_cert",
                        lambda cn, sans=None, days=397: ("LEAF-" + cn, "KEY", "CA"))
    monkeypatch.setattr(mtls_ca, "ca_cert_pem", lambda: "HUB-CA")


# ── settings validation ──────────────────────────────────────────────────────

def test_drop_rules_valid_rules_are_normalised():
    rules = sa.validate_drop_rules([
        {"field": "program", "op": "equals", "value": "CRON"},
        {"field": "severity", "op": "gte", "value": "7", "note": "debug"},
        {"field": "msg", "op": "regex", "value": r"^link (up|down)", "enabled": False},
    ])
    assert [r["field"] for r in rules] == ["program", "severity", "msg"]
    assert rules[1]["value"] == 7 and rules[2]["enabled"] is False


@pytest.mark.parametrize("bad", [
    [{"field": "nope", "op": "equals", "value": "x"}],
    [{"field": "msg", "op": "starts", "value": "x"}],
    [{"field": "msg", "op": "regex", "value": "(unclosed"}],
    [{"field": "severity", "op": "gte", "value": 9}],
    [{"field": "host", "op": "gte", "value": 3}],
    [{"field": "host", "op": "equals", "value": ""}],
    [{"field": "host", "op": "equals", "value": f"h{i}"} for i in range(sa.MAX_DROP_RULES + 1)],
    "not a list",
])
def test_drop_rules_invalid_rules_are_rejected(bad):
    with pytest.raises(ValueError):
        sa.validate_drop_rules(bad)


def test_settings_ranges_are_enforced():
    cur = dict(sa.DEFAULT_SETTINGS)
    assert sa.validate_settings({"retention_hours": 48}, cur)["retention_hours"] == 48
    for body in ({"retention_hours": 0}, {"retention_hours": 500}, {"max_mb": 1}):
        with pytest.raises(ValueError):
            sa.validate_settings(body, cur)


# ── archive record masking ───────────────────────────────────────────────────

def test_public_archive_never_carries_a_secret():
    rec = {"backend": "graylog", "managed_by_role": "syslog-graylog", "host": "10.0.0.5",
           "input_port": 1514, "tls": True, "tls_name": "syslog-graylog-acme",
           "api_url": "https://10.0.0.5:9000/api", "user": "lm-reader",
           "password_ref": {"key": "acme:reader", "store": "local"}, "ca_pem": "PEM"}
    out = sa.public_archive(rec)
    assert out["password_set"] is True and out["ca_pem_set"] is True
    assert "password_ref" not in out and "password" not in out and "ca_pem" not in out
    assert "ui_url" not in out
    assert sa.public_archive(rec, include_ui=True)["ui_url"] == "https://10.0.0.5:9000/"


# ── tenant scoping ───────────────────────────────────────────────────────────

def test_logging_spokes_are_tenant_scoped(tmp_path):
    hub = _Hub(tmp_path)
    assert sorted(hub.get_logging_spokes_for_tenant("acme")) == ["c1", "c2"]
    assert hub.get_logging_spokes_for_tenant("other") == ["c3"]
    assert hub.get_logging_spokes_for_tenant("") == []
    hub.approved_modules["c2"] = False
    assert hub.get_logging_spokes_for_tenant("acme") == ["c1"]


# ── query merge ──────────────────────────────────────────────────────────────

def test_merge_is_newest_first_cut_to_limit_and_keeps_errors():
    rows = [
        {"collector": "a", "reply": {"source": "local", "messages": [{"ts": 1}, {"ts": 5}]}},
        {"collector": "b", "reply": {"source": "local-partial", "error": "archive down",
                                     "messages": [{"ts": 3}]}},
        {"collector": "c", "reply": None, "error": "timeout"},
    ]
    out = syslog_routes.merge_results(rows, limit=2)
    assert [m["ts"] for m in out["messages"]] == [5, 3]
    assert [m["collector"] for m in out["messages"]] == ["a", "b"]
    assert out["truncated"] is True
    assert out["sources"] == {"local": 1, "local-partial": 1}
    assert {e["collector"] for e in out["errors"]} == {"b", "c"}


def test_archive_cutoff_is_newest_oldest_of_asked_collectors():
    cols = [{"spoke_id": "c1", "collector": {"oldest_ts": 100}},
            {"spoke_id": "c2", "collector": {"oldest_ts": 200}},
            {"spoke_id": "c3", "collector": {"oldest_ts": 900}},
            {"spoke_id": "c4", "collector": {}}]
    assert syslog_routes.archive_cutoff(cols, ["c1", "c2", "c4"]) == 200
    assert syslog_routes.archive_cutoff(cols, ["c4"]) is None


def test_drop_preview_sums():
    rows = [{"collector": "a", "reply": {"scanned": 10, "dropped": 2, "per_rule": [2, 0]}},
            {"collector": "b", "reply": {"scanned": 5, "dropped": 1, "per_rule": [0, 1]}}]
    out = syslog_routes.sum_previews(rows, 2)
    assert (out["scanned"], out["dropped"], out["per_rule"]) == (15, 3, [2, 1])


# ── role hooks ───────────────────────────────────────────────────────────────

def test_collector_load_adds_tenant_and_cert(tmp_path):
    hub = _Hub(tmp_path)
    cfg = _run(sa.pre_load_role(hub, "agent-c", "syslog-collector", {}))
    assert cfg["tenant"] == "acme"
    assert cfg["tls_subject"] == "syslog-collector-col-host"
    assert cfg["tls_cert_pem"].startswith("LEAF-") and cfg["tls_ca_pem"] == "CA"


def test_collector_success_loads_the_syslog_spoke_role(tmp_path):
    hub = _Hub(tmp_path)
    sa.save_settings(hub, "acme", {"drop_rules": [], "retention_hours": 12, "max_mb": 512})
    _run(sa.post_load_role(hub, "agent-c", "syslog-collector", {"status": "SUCCESS"}))
    loads = [d for sid, cmd, d in hub.sent if cmd == "LOAD_ROLE"]
    assert hub.sent[0][0] == "agent-c"
    assert loads == [{"role": "syslog", "config": {"tenant": "acme", "archive": None,
                                                    "drop_rules": [], "retention_hours": 12,
                                                    "max_mb": 512}}]


def test_failed_collector_load_has_no_follow_up(tmp_path):
    hub = _Hub(tmp_path)
    _run(sa.post_load_role(hub, "agent-c", "syslog-collector", {"status": "ERROR"}))
    assert hub.sent == []


def test_other_roles_pass_through_untouched(tmp_path):
    hub = _Hub(tmp_path)
    cfg = {"x": 1}
    assert _run(sa.pre_load_role(hub, "agent-c", "dns-server", cfg)) is cfg
    _run(sa.post_load_role(hub, "agent-c", "dns-server", {"status": "SUCCESS"}))
    assert hub.sent == []


def _install_graylog(hub):
    """Pre-hook + post-hook of a successful syslog-graylog load on agent-gl."""
    cfg = _run(sa.pre_load_role(hub, "agent-gl", "syslog-graylog", {}))
    _run(sa.post_load_role(hub, "agent-gl", "syslog-graylog", {"status": "SUCCESS"}))
    return cfg


def test_graylog_load_saves_archive_and_pushes_to_own_tenant_only(tmp_path):
    hub = _Hub(tmp_path, replies={("agent-gl", "GET_PRIMARY_IP"):
                                  {"ip": "10.1.1.9", "hostname": "gl"}})
    cfg = _install_graylog(hub)
    # Generated passwords + cert in the load config, stored (not in the record).
    assert len(cfg["admin_password"]) >= 24 and len(cfg["reader_password"]) >= 24
    assert cfg["tls_subject"] == "syslog-graylog-acme"
    rec = sa.get_archive(hub, "acme")
    assert rec["host"] == "10.1.1.9" and rec["input_port"] == 1514
    assert rec["tls_name"] == "syslog-graylog-acme"
    assert rec["api_url"] == "https://10.1.1.9:9000/api"
    assert cfg["reader_password"] not in repr(hub.state.system_state.get("syslog"))
    # Pushed to acme's collectors only, with the resolved password and the hub CA.
    pushes = [(sid, d) for sid, cmd, d in hub.sent if cmd == "SYSLOG_CONFIG"]
    assert sorted(sid for sid, _ in pushes) == ["c1", "c2"]
    arch = pushes[0][1]["archive"]
    assert arch["password"] == cfg["reader_password"]
    assert arch["ca_pem"] == "HUB-CA" and arch["tls_name"] == "syslog-graylog-acme"
    # The browser view stays masked.
    assert cfg["reader_password"] not in repr(sa.public_archive(rec, include_ui=True))


def test_second_archive_for_a_tenant_is_refused(tmp_path):
    hub = _Hub(tmp_path, replies={("agent-gl", "GET_PRIMARY_IP"): {"ip": "10.1.1.9"}})
    _install_graylog(hub)
    hub.state.system_state["module_metadata"]["agent-c"]["tenant_id"] = "acme"
    with pytest.raises(sa.ArchiveConflict):
        _run(sa.pre_load_role(hub, "agent-c", "syslog-graylog", {}))
    # Re-installing on the same node reuses the stored passwords.
    again = _run(sa.pre_load_role(hub, "agent-gl", "syslog-graylog", {}))
    assert again["reader_password"]


def test_archive_unload_removes_record_and_pushes_none(tmp_path):
    hub = _Hub(tmp_path, replies={("agent-gl", "GET_PRIMARY_IP"): {"ip": "10.1.1.9"}})
    _install_graylog(hub)
    hub.sent.clear()
    # An unload elsewhere does nothing.
    _run(sa.on_role_removed(hub, "agent-c", "syslog-graylog", {"status": "SUCCESS"}))
    assert sa.get_archive(hub, "acme") and hub.sent == []
    _run(sa.on_role_removed(hub, "agent-gl", "syslog-graylog", {"status": "SUCCESS"}))
    assert sa.get_archive(hub, "acme") is None
    assert sorted((sid, d["archive"]) for sid, cmd, d in hub.sent if cmd == "SYSLOG_CONFIG") \
        == [("c1", None), ("c2", None)]


# ── routes ───────────────────────────────────────────────────────────────────

def _client(hub, sess):
    """FastAPI app with only the syslog routes."""
    import access
    app = FastAPI()
    ctx = SimpleNamespace(_session_user=lambda request: sess,
                          _is_admin=access.is_admin, _is_tenant_admin=access.is_tenant_admin)
    syslog_routes.register(app, hub, ctx)
    return TestClient(app)


def _sess(role, tenants):
    """A session dict for ``role`` in ``tenants`` (first = primary)."""
    return {"user": {"permissions": {"role": role}, "tenants": tenants,
                     "tenant_id": tenants[0] if tenants else None}}


_ADMIN = {"user": {"permissions": {"admin": True}, "tenants": []}}


def test_query_only_asks_own_tenant_collectors(tmp_path):
    hub = _Hub(tmp_path, replies={
        ("c1", "SYSLOG_QUERY"): {"status": "SUCCESS", "source": "local",
                                 "messages": [{"ts": 2, "msg": "a"}]},
        ("c2", "SYSLOG_QUERY"): {"status": "SUCCESS", "source": "local",
                                 "messages": [{"ts": 3, "msg": "b"}]},
    })
    r = _client(hub, _sess("user", ["acme"])).post("/api/syslog/query", json={"limit": 10})
    assert r.status_code == 200
    assert {sid for sid, _c, _d in hub.sent} == {"c1", "c2"}
    assert [m["collector"] for m in r.json()["messages"]] == ["col-a2", "col-a1"]
    # Every collector answers locally; only one may search the archive.
    assert sorted(d["use_archive"] for _sid, _c, d in hub.sent) == [False, True]


def test_query_reports_a_failing_collector_by_name(tmp_path):
    hub = _Hub(tmp_path, replies={("c2", "SYSLOG_QUERY"): TimeoutError("timed out")})
    r = _client(hub, _sess("user", ["acme"])).post("/api/syslog/query", json={})
    assert r.json()["errors"] == [{"collector": "col-a2", "error": "timed out"}]


def test_other_tenant_is_forbidden(tmp_path):
    hub = _Hub(tmp_path)
    c = _client(hub, _sess("user", ["acme"]))
    # A non-admin naming another tenant falls back to their own; nothing of "other" is asked.
    assert c.post("/api/syslog/query?tenant=other", json={}).status_code == 200
    assert {sid for sid, _c, _d in hub.sent} == {"c1", "c2"}
    # A user with no tenant at all gets 400, not someone else's data.
    assert _client(hub, _sess("user", [])).get("/api/syslog/overview").status_code == 400


def test_admin_must_pick_a_tenant(tmp_path):
    hub = _Hub(tmp_path)
    assert _client(hub, _ADMIN).get("/api/syslog/settings").status_code == 400
    assert _client(hub, _ADMIN).get("/api/syslog/settings?tenant=other").status_code == 200


def test_settings_put_needs_tenant_admin_and_pushes(tmp_path):
    hub = _Hub(tmp_path)
    body = {"drop_rules": [{"field": "program", "op": "equals", "value": "CRON"}]}
    assert _client(hub, _sess("user", ["acme"])).put("/api/syslog/settings",
                                                     json=body).status_code == 403
    r = _client(hub, _sess("tenant_admin", ["acme"])).put("/api/syslog/settings", json=body)
    assert r.status_code == 200
    assert sorted(x["collector"] for x in r.json()["results"]) == ["col-a1", "col-a2"]
    assert all("spoke_id" not in x for x in r.json()["results"])
    bad = {"drop_rules": [{"field": "msg", "op": "regex", "value": "("}]}
    assert _client(hub, _sess("tenant_admin", ["acme"])).put(
        "/api/syslog/settings", json=bad).status_code == 400


def test_overview_hides_ui_url_from_tenants(tmp_path):
    hub = _Hub(tmp_path, replies={("agent-gl", "GET_PRIMARY_IP"): {"ip": "10.1.1.9"}})
    _install_graylog(hub)
    tenant_view = _client(hub, _sess("tenant_admin", ["acme"])).get("/api/syslog/overview").json()
    admin_view = _client(hub, _ADMIN).get("/api/syslog/overview?tenant=acme").json()
    assert "ui_url" not in tenant_view["archive"]
    assert admin_view["archive"]["ui_url"] == "https://10.1.1.9:9000/"
    assert {c["name"] for c in tenant_view["collectors"]} == {"col-a1", "col-a2"}
    assert "password" not in repr(tenant_view["archive"]).replace("password_set", "")


def test_external_archive_put_and_conflict(tmp_path):
    hub = _Hub(tmp_path)
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    ext = {"backend": "syslog", "host": "logs.example.com", "input_port": 6514, "tls": True,
           "tls_name": "logs.example.com"}
    r = c.put("/api/syslog/archive", json=ext)
    assert r.status_code == 200 and r.json()["archive"]["tls_name"] == "logs.example.com"
    # Plain-text forwarding is refused (fleet rule 5.4) and nothing is saved.
    assert c.put("/api/syslog/archive", json={**ext, "tls": False}).status_code == 400
    # An IP host needs tls_name, else only the CA chain could be checked.
    assert c.put("/api/syslog/archive", json={**ext, "host": "10.1.1.9", "tls_name": None}).status_code == 400
    # The Graylog API URL must be https and not link-local (cloud metadata).
    for url in ("https://169.254.169.254/api", "http://10.1.1.9:9000/api", "https://0.0.0.0/api"):
        bad = {**ext, "backend": "graylog", "api_url": url}
        assert c.put("/api/syslog/archive", json=bad).status_code == 400
    # A lab-internal Graylog is the normal case and is accepted.
    lab = {**ext, "backend": "graylog", "api_url": "https://10.1.1.9:9000/api", "user": "r",
           "password": "pw"}
    assert c.put("/api/syslog/archive", json=lab).status_code == 200
    assert c.delete("/api/syslog/archive").status_code == 200
    # An LM-installed archive cannot be replaced or removed here.
    hub.replies[("agent-gl", "GET_PRIMARY_IP")] = {"ip": "10.1.1.9"}
    _install_graylog(hub)
    assert c.put("/api/syslog/archive", json=ext).status_code == 409
    assert c.delete("/api/syslog/archive").status_code == 409


def test_diagnostics_relays_to_named_collector(tmp_path):
    hub = _Hub(tmp_path, replies={("c2", "SYSLOG_DIAG"): {"status": "SUCCESS", "rsyslog": {}}})
    c = _client(hub, _sess("tenant_admin", ["acme"]))
    r = c.get("/api/syslog/diagnostics?collector=col-a2")
    assert r.status_code == 200 and r.json()["collector"] == "col-a2"
    assert [(sid, cmd) for sid, cmd, _d in hub.sent] == [("c2", "SYSLOG_DIAG")]
    # Another tenant's collector name is simply not found.
    assert c.get("/api/syslog/diagnostics?collector=col-o1").status_code == 404
    assert _client(hub, _sess("user", ["acme"])).get(
        "/api/syslog/diagnostics?collector=col-a2").status_code == 403


# ── maps and secret storage ──────────────────────────────────────────────────

def test_logging_module_is_in_the_push_and_update_maps():
    import main
    import update_pipeline
    assert main._PUSH_CONFIG_MODULE_KEY["logging"] == "syslog"
    assert update_pipeline._UPDATE_SOURCE_MODULE_KEY["logging"] == "syslog"
    assert update_pipeline._MODULE_REPO_DIR["logging"] == "syslog"


def test_hub_secret_store_round_trip_keeps_value_out_of_the_record(tmp_path):
    import hub_secret_store
    hub, blobs, rec = _Hub(tmp_path), {}, {}
    _run(hub_secret_store.put(hub, blobs, "acme:reader", rec, "s3cret-value", "syslog-"))
    assert rec["store"] == "local" and "s3cret-value" not in repr(rec)
    assert "s3cret-value" not in repr(blobs)
    assert _run(hub_secret_store.get(hub, blobs, "acme:reader", rec)) == "s3cret-value"
    _run(hub_secret_store.delete(hub, blobs, "acme:reader", rec))
    assert _run(hub_secret_store.get(hub, blobs, "acme:reader", rec)) is None


def test_spoke_config_for_reconnect_push(tmp_path):
    hub = _Hub(tmp_path)
    cfg = _run(sa.spoke_config(hub, "acme"))
    assert set(cfg) == {"tenant", "archive", "drop_rules", "retention_hours", "max_mb"}
