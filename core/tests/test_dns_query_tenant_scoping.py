"""DNS query telemetry (``/api/dns/stats`` + ``/api/dns/client-queries``) is
tenant-scoped by client source IP, like every other module behind the tenant
picker — and, unlike DNS records, NOT gated on the records-only ``dns``
subnet-filter toggle (which defaults OFF). The hub re-filters the spoke's reply
so an older/clustered spoke that ignores or drops ``source_prefixes`` cannot
leak another tenant's queries, and the server-wide headline counters are
re-derived from the tenant's own rows.
"""
import copy
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.net_services as ns
from routes.net_services import (
    _dns_rescope_client_queries, _dns_rescope_stats, register,
)

TENANT_PREFIXES = {"t-a": ["10.1.0.0/24"], "t-b": ["10.2.0.0/24"], "t-empty": []}

# What an OLD spoke returns: unfiltered, regardless of source_prefixes.
STATS_REPLY = {
    "status": "SUCCESS",
    "global": {"total_queries": 9999, "cache_hits": 5000, "cache_misses": 4999,
               "cache_hit_ratio": 50.0, "num_recursive": 4000,
               "recursion_time_avg": 0.1, "prefetch": 1},
    "query_types": {"A": 9000, "AAAA": 999},
    "query_names_tracked": 42,
    "members": {"m1": {"query_names": ["raw"]}},
    "query_names": [
        {"name": "a.example", "type": "A", "count": 5,
         "sources": [{"ip": "10.1.0.5", "count": 3}, {"ip": "10.2.0.9", "count": 2}]},
        {"name": "b.example", "type": "AAAA", "count": 4,
         "sources": [{"ip": "10.2.0.9", "count": 4}]},
    ],
}
CLIENT_REPLY = {
    "status": "SUCCESS", "client": "", "minutes": 10, "total": 3,
    "queries": [
        {"time": 3, "client": "10.1.0.5", "name": "a.example", "type": "A"},
        {"time": 2, "client": "10.2.0.9", "name": "b.example", "type": "AAAA"},
        {"time": 1, "client": "10.1.0.6", "name": "a.example", "type": "A"},
    ],
    "top_names": [{"name": "secret.other", "type": "A", "count": 99}],
}


class FakeState:
    def __init__(self):
        self.system_state = {"global_config": {"dns_instances": [], "dhcp_instances": []},
                             "module_metadata": {}, "subnet_filter_modules": {}}

    def get_spoke_tenant(self, sid):
        return ""


class FakeHub:
    def __init__(self):
        self.active_connections = {"dns-a"}
        self.approved_modules = {"dns-a": True}
        self.state = FakeState()
        self.forwarded = []

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return "dns-a" if module_type == "dns" else None

    def get_all_spokes_by_type(self, module_type):
        return ["dns-a"] if module_type == "dns" else []

    def get_dns_spoke_for_tenant(self, tid):
        return "dns-a"

    def get_dns_spoke_for_shared(self):
        return "dns-a"

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return None

    def get_dhcp_spoke_for_shared(self):
        return None

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((cmd, copy.deepcopy(payload)))
        reply = {"DNS_STATS": STATS_REPLY, "DNS_CLIENT_QUERIES": CLIENT_REPLY}.get(
            cmd, {"status": "SUCCESS"})
        return {"payload": {"data": copy.deepcopy(reply)}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


@pytest.fixture(autouse=True)
def _prefixes(monkeypatch):
    async def by_tenant(hub, tid):
        return TENANT_PREFIXES.get(tid, [])

    async def by_session_tenant(hub, sess, tid):
        return TENANT_PREFIXES.get(tid, [])

    monkeypatch.setattr(ns.access, "resolve_prefixes_for_tenant", by_tenant)
    monkeypatch.setattr(ns.access, "resolve_prefixes_for_session_tenant", by_session_tenant)


def _build(admin=True, session_tenant=None, allowed=()):
    hub = FakeHub()
    sess = {"user": {"is_admin": admin, "tenant_id": session_tenant,
                     "tenants": list(allowed)}}

    def eff(request, explicit=None):
        if admin:
            return explicit
        if explicit and explicit in allowed:
            return explicit
        return session_tenant

    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: sess,
        _is_admin=lambda s: bool(s and s["user"]["is_admin"]),
        _effective_tenant=eff,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app), hub


def _sent(hub, cmd):
    return next(p for c, p in hub.forwarded if c == cmd)


def test_admin_with_tenant_selected_is_scoped_even_with_dns_toggle_off():
    c, hub = _build(admin=True)
    d = c.get("/api/dns/stats", params={"tenant": "t-a"}).json()
    assert _sent(hub, "DNS_STATS")["source_prefixes"] == ["10.1.0.0/24"]
    assert [r["name"] for r in d["query_names"]] == ["a.example"]
    row = d["query_names"][0]
    assert [s["ip"] for s in row["sources"]] == ["10.1.0.5"]
    assert row["count"] == 3
    assert d["global"]["total_queries"] == 3
    assert d["global"]["cache_hit_ratio"] is None
    assert d["query_types"] == {"A": 3}
    assert "members" not in d and "query_names_tracked" not in d
    assert d["tenant_scoped"] is True


def test_search_is_scoped_too():
    c, hub = _build(admin=True)
    d = c.get("/api/dns/stats", params={"tenant": "t-b", "search": "example"}).json()
    sent = _sent(hub, "DNS_STATS")
    assert sent["search"] == "example" and sent["source_prefixes"] == ["10.2.0.0/24"]
    assert {r["name"]: r["count"] for r in d["query_names"]} == {"b.example": 4, "a.example": 2}


def test_admin_without_tenant_is_unscoped():
    c, hub = _build(admin=True)
    d = c.get("/api/dns/stats").json()
    assert "source_prefixes" not in _sent(hub, "DNS_STATS")
    assert d["global"]["total_queries"] == 9999
    assert len(d["query_names"]) == 2
    assert "tenant_scoped" not in d


def test_non_admin_uses_session_tenant_and_cannot_escape():
    c, hub = _build(admin=False, session_tenant="t-a", allowed=("t-a",))
    d = c.get("/api/dns/stats", params={"tenant": "t-b"}).json()
    assert _sent(hub, "DNS_STATS")["source_prefixes"] == ["10.1.0.0/24"]
    assert all(s["ip"].startswith("10.1.") for r in d["query_names"] for s in r["sources"])


def test_tenant_without_prefixes_fails_closed():
    c, hub = _build(admin=True)
    d = c.get("/api/dns/stats", params={"tenant": "t-empty"}).json()
    assert _sent(hub, "DNS_STATS")["source_prefixes"] == []
    assert d["query_names"] == [] and d["global"]["total_queries"] == 0


def test_non_admin_without_tenant_fails_closed():
    c, hub = _build(admin=False, session_tenant=None)
    d = c.get("/api/dns/client-queries").json()
    assert _sent(hub, "DNS_CLIENT_QUERIES")["source_prefixes"] == []
    assert d["queries"] == [] and d["total"] == 0


def test_client_queries_scoped_and_summary_rederived():
    c, hub = _build(admin=True)
    d = c.get("/api/dns/client-queries", params={"tenant": "t-a"}).json()
    assert _sent(hub, "DNS_CLIENT_QUERIES")["source_prefixes"] == ["10.1.0.0/24"]
    assert [q["client"] for q in d["queries"]] == ["10.1.0.5", "10.1.0.6"]
    assert d["total"] == 2
    assert d["top_names"] == [{"name": "a.example", "type": "A", "count": 2}]


def test_rescope_helpers_noop_when_unscoped():
    assert _dns_rescope_stats(STATS_REPLY, None) is STATS_REPLY
    assert _dns_rescope_client_queries(CLIENT_REPLY, None) is CLIENT_REPLY
