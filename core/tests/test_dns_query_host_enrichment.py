"""``GET /api/dns/stats`` enriches each per-name query's source IPs with a
best-effort ``host`` (the DHCP lease hostname for that client IP, falling
back to the raw IP when no lease matches), and accepts an optional ``host``
query-string filter (case-insensitive substring, mirrors the existing
``search`` param for domain names) — this is the "by what host" half of
"DNS server should show the DNS domain names being queried and by what host".

Follows the same FakeHub/register() harness as test_dns_tenant_routing.py,
extended with a fake DHCP spoke so ``_dns_stats_ip_to_host`` has leases to
enrich against.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient
from types import SimpleNamespace

from routes.net_services import register


class FakeState:
    def __init__(self):
        self.system_state = {"global_config": {"dns_instances": [], "dhcp_instances": []},
                             "module_metadata": {}}

    def get_spoke_tenant(self, sid):
        return ""


class FakeHub:
    def __init__(self, dns_replies=None, dhcp_replies=None,
                has_dhcp_spoke=True):
        self.active_connections = {"dns-a"} | ({"dhcp-a"} if has_dhcp_spoke else set())
        self.approved_modules = {sid: True for sid in self.active_connections}
        self.state = FakeState()
        self.dns_replies = dns_replies or {}
        self.dhcp_replies = dhcp_replies or {}
        self.forwarded = []
        self._has_dhcp_spoke = has_dhcp_spoke

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        if module_type == "dns":
            return "dns-a"
        if module_type == "dhcp" and self._has_dhcp_spoke:
            return "dhcp-a"
        return None

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return None

    def get_dhcp_spoke_for_shared(self):
        return None

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        import copy
        self.forwarded.append((sid, cmd, payload))
        replies = self.dns_replies if sid == "dns-a" else self.dhcp_replies
        # Deep-copy: the route handler mutates the returned dict in place
        # (adding "host" to each source, filtering "query_names") — without
        # copying, that mutation would leak into the shared reply fixture and
        # corrupt subsequent calls/tests reusing the same DNS_STATS_REPLY object.
        data = copy.deepcopy(replies.get(cmd, {"status": "SUCCESS"}))
        return {"payload": {"data": data}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


def _build(hub):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: {"user": {"is_admin": True}},
        _is_admin=lambda s: True,
        _effective_tenant=lambda request, explicit=None: explicit,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


DNS_STATS_REPLY = {
    "status": "SUCCESS",
    "global": {}, "query_types": {},
    "query_names": [
        {"name": "www.example.com", "type": "A", "count": 5,
         "sources": [{"ip": "10.0.0.5", "count": 3},
                    {"ip": "10.0.0.9", "count": 2}]},
        {"name": "www.other.net", "type": "A", "count": 1,
         "sources": [{"ip": "10.0.0.9", "count": 1}]},
    ],
}

DHCP_LEASES_REPLY = {
    "status": "SUCCESS",
    "leases": [
        {"ip-address": "10.0.0.5", "hostname": "laptop-01"},
        {"ip-address": "10.0.0.9", "hostname": ""},
    ],
}


def test_query_name_sources_are_enriched_with_dhcp_lease_hostname():
    hub = FakeHub(dns_replies={"DNS_STATS": DNS_STATS_REPLY},
                  dhcp_replies={"DHCP_LIST_LEASES": DHCP_LEASES_REPLY})
    c = _build(hub)
    r = c.get("/api/dns/stats")
    assert r.status_code == 200
    names = r.json()["query_names"]
    row = next(n for n in names if n["name"] == "www.example.com")
    sources_by_ip = {s["ip"]: s for s in row["sources"]}
    assert sources_by_ip["10.0.0.5"]["host"] == "laptop-01"
    # No lease hostname for .9 -> falls back to the raw IP, never blank.
    assert sources_by_ip["10.0.0.9"]["host"] == "10.0.0.9"


def test_host_filter_matches_substring_case_insensitively():
    hub = FakeHub(dns_replies={"DNS_STATS": DNS_STATS_REPLY},
                  dhcp_replies={"DHCP_LIST_LEASES": DHCP_LEASES_REPLY})
    c = _build(hub)
    r = c.get("/api/dns/stats", params={"host": "LAPTOP"})
    assert r.status_code == 200
    names = r.json()["query_names"]
    # Only the row with a source resolving to "laptop-01" survives.
    assert [n["name"] for n in names] == ["www.example.com"]


def test_host_filter_falls_back_to_raw_ip_when_unresolved():
    hub = FakeHub(dns_replies={"DNS_STATS": DNS_STATS_REPLY},
                  dhcp_replies={"DHCP_LIST_LEASES": DHCP_LEASES_REPLY})
    c = _build(hub)
    r = c.get("/api/dns/stats", params={"host": "10.0.0.9"})
    assert r.status_code == 200
    names = {n["name"] for n in r.json()["query_names"]}
    assert names == {"www.example.com", "www.other.net"}


def test_missing_dhcp_spoke_leaves_raw_ip_as_host_without_erroring():
    hub = FakeHub(dns_replies={"DNS_STATS": DNS_STATS_REPLY}, has_dhcp_spoke=False)
    c = _build(hub)
    r = c.get("/api/dns/stats")
    assert r.status_code == 200
    row = r.json()["query_names"][0]
    assert all(s["host"] == s["ip"] for s in row["sources"])
