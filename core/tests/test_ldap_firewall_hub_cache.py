"""Directory (LDAP) and firewall pages on the hub data cache.

* LDAP: users/groups lists are cached per tenant OU (key = OU slug, owner =
  the tenant); a second read makes no spoke call; a spoke ERROR is never
  cached; a directory write refreshes that OU's lists (the next read shows
  the change) and never touches another tenant's entry.
* Firewall: one cache entry per firewall + endpoint, shared by every reader
  and narrowed by ``_filter_fw`` on EVERY read; a write refreshes exactly
  that firewall's entry (not ``fw-10`` when ``fw-1`` changed).
"""
import asyncio
import tempfile
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

from warm_cache import WarmCacheMixin


class _State:
    def __init__(self, tenants=None, system_state=None):
        self.tenant_state = {"tenants": dict(tenants or {})}
        self.system_state = system_state or {}

    def get_tenant(self, tid):
        return self.tenant_state["tenants"].get(tid)


class _Hub(WarmCacheMixin):
    def __init__(self, replies, tenants=None, system_state=None, spokes=None):
        self.state = _State(tenants, system_state)
        self.cache_dir = tempfile.mkdtemp(prefix="ldapfw-cache-")
        self.warm_cache_init()
        self.replies = replies        # (spoke, cmd) -> reply, or callable(payload)
        self.calls = []
        self.active_connections = {s: object() for s in (spokes or [])}
        self._dir_spokes = {}

    def _primary_key(self, sid):
        return sid

    def get_directory_spoke_for_tenant(self, tid):
        return self._dir_spokes.get(tid)

    async def request_response(self, sid, cmd, payload, timeout=30.0, **kw):
        self.calls.append((sid, cmd, dict(payload or {})))
        r = self.replies.get((sid, cmd))
        return r(payload) if callable(r) else r


# ═════════════════════════ LDAP ══════════════════════════════════════════════

def _ldap_client(hub, sess):
    from routes import ldap
    app = FastAPI()
    ldap.register(app, hub, SimpleNamespace(_session_user=lambda r: sess))
    app.state.hub = hub
    return TestClient(app)


_ADMIN = {"user": {"permissions": {"admin": True}}}


def _ldap_hub():
    users = {"a": [{"uid": "alice"}], "b": [{"uid": "bob"}]}

    def lister(slug):
        return lambda p: {"status": "SUCCESS", "data": {"users": list(users[slug])}}

    def create(p):
        users[p["tenant_slug"]].append({"uid": p["uid"]})
        return {"status": "SUCCESS", "data": {"uid": p["uid"]}}
    hub = _Hub({("dir-a", "LDAP_LIST_USERS"): lister("a"),
                ("dir-b", "LDAP_LIST_USERS"): lister("b"),
                ("dir-a", "LDAP_CREATE_USER"): create},
               tenants={"a": {}, "b": {}})
    hub._dir_spokes = {"a": "dir-a", "b": "dir-b"}
    return hub


def test_ldap_list_is_cached_per_tenant_ou():
    hub = _ldap_hub()
    c = _ldap_client(hub, _ADMIN)
    assert c.get("/api/ldap/users?tenant=a").json()["users"] == [{"uid": "alice"}]
    assert c.get("/api/ldap/users?tenant=b").json()["users"] == [{"uid": "bob"}]
    n = len(hub.calls)
    r = c.get("/api/ldap/users?tenant=a").json()
    assert len(hub.calls) == n                      # served from cache
    assert r["cached_at"]
    assert hub.warm_cache["ldap_list_users"]["a|a"]["tenants"] == ["a"]
    assert hub.warm_cache["ldap_list_users"]["b|b"]["tenants"] == ["b"]


def test_ldap_write_refreshes_only_that_ou():
    hub = _ldap_hub()
    c = _ldap_client(hub, _ADMIN)
    c.get("/api/ldap/users?tenant=a")
    c.get("/api/ldap/users?tenant=b")
    r = c.post("/api/ldap/users", json={"tenant_id": "a", "uid": "carol"})
    assert r.status_code == 200
    assert {u["uid"] for u in c.get("/api/ldap/users?tenant=a").json()["users"]} \
        == {"alice", "carol"}
    b_lists = [x for x in hub.calls if x[:2] == ("dir-b", "LDAP_LIST_USERS")]
    assert len(b_lists) == 1                        # tenant b untouched


def test_ldap_spoke_error_is_never_cached():
    hub = _ldap_hub()
    hub.replies[("dir-a", "LDAP_LIST_USERS")] = {"status": "ERROR", "message": "SERVER_DOWN"}
    c = _ldap_client(hub, _ADMIN)
    r = c.get("/api/ldap/users?tenant=a")
    assert r.status_code == 502 and "SERVER_DOWN" in r.json()["detail"]
    assert hub.warm_cache.get("ldap_list_users", {}) == {}


def test_ldap_feed_covers_tenants_with_a_directory_spoke_only():
    hub = _ldap_hub()
    hub.state.tenant_state["tenants"]["c"] = {}     # no directory spoke
    _ldap_client(hub, _ADMIN)
    keys = {(j.ns, j.key) for j in hub._cache_collect_jobs()}
    assert keys == {("ldap_list_users", "a|a"), ("ldap_list_groups", "a|a"),
                    ("ldap_list_users", "b|b"), ("ldap_list_groups", "b|b")}


def test_two_tenants_with_the_same_ou_slug_never_share_an_entry():
    # Both tenants map to OU "corp" but are bound to different directory
    # spokes: each must be served its OWN spoke's users.
    hub = _Hub({("dir-a", "LDAP_LIST_USERS"): {"status": "SUCCESS", "data": {"users": [{"uid": "a"}]}},
                ("dir-b", "LDAP_LIST_USERS"): {"status": "SUCCESS", "data": {"users": [{"uid": "b"}]}}},
               tenants={"a": {"slug": "corp"}, "b": {"slug": "corp"}})
    hub._dir_spokes = {"a": "dir-a", "b": "dir-b"}
    c = _ldap_client(hub, _ADMIN)
    assert c.get("/api/ldap/users?tenant=a").json()["users"] == [{"uid": "a"}]
    assert c.get("/api/ldap/users?tenant=b").json()["users"] == [{"uid": "b"}]
    assert set(hub.warm_cache["ldap_list_users"]) == {"a|corp", "b|corp"}


# ═════════════════════════ firewall ══════════════════════════════════════════

def _fw_client(hub, sess, filt=None):
    from routes import firewall

    async def _filter_fw(request, payload, endpoint, fw_id, tenant=None):
        return filt(payload) if filt else payload
    ctx = SimpleNamespace(
        _session_user=lambda r: sess,
        _is_admin=lambda s: bool(s and s["user"].get("permissions", {}).get("admin")),
        _is_tenant_admin=lambda s: False,
        _filter_fw=_filter_fw,
    )
    app = FastAPI()
    firewall.register(app, hub, ctx)
    app.state.hub = hub
    return TestClient(app)


def _fw_hub():
    rules = {"fw-1": [{"uuid": "r1"}], "fw-10": [{"uuid": "r10"}]}
    hub = _Hub(
        {("sp-1", "OPNSENSE_GET_ALL_RULES"): lambda p: {"status": "SUCCESS",
                                                        "data": list(rules["fw-1"])},
         ("sp-10", "OPNSENSE_GET_ALL_RULES"): lambda p: {"status": "SUCCESS",
                                                         "data": list(rules["fw-10"])}},
        system_state={"global_config": {"firewalls": [
            {"id": "fw-1", "spoke_id": "sp-1"}, {"id": "fw-10", "spoke_id": "sp-10"}]}},
        spokes=["sp-1", "sp-10"])
    return hub, rules


def test_firewall_list_cached_once_per_firewall():
    hub, _ = _fw_hub()
    c = _fw_client(hub, _ADMIN)
    first = c.get("/api/firewall/fw-1/rules").json()
    n = len(hub.calls)
    second = c.get("/api/firewall/fw-1/rules").json()
    assert len(hub.calls) == n
    assert first == second and hub.warm_get("fw_rules", "fw-1") == [{"uuid": "r1"}]


def test_firewall_filter_runs_on_every_cached_read_and_never_mutates_cache():
    hub, _ = _fw_hub()
    _fw_client(hub, _ADMIN).get("/api/firewall/fw-1/rules")      # warm it (full view)
    shared = {"user": {"tenants": ["shared"]}}
    import access
    orig = access.tenant_is_shared
    access.tenant_is_shared = lambda t: True
    try:
        hub.state.system_state["global_config"]["firewalls"][0]["tenant_id"] = "shared"
        c = _fw_client(hub, shared, filt=lambda p: [])
        r = c.get("/api/firewall/fw-1/rules")
    finally:
        access.tenant_is_shared = orig
    assert r.status_code == 200
    assert hub.warm_get("fw_rules", "fw-1") == [{"uuid": "r1"}]


def test_unknown_firewall_or_endpoint():
    hub, _ = _fw_hub()
    c = _fw_client(hub, _ADMIN)
    assert c.get("/api/firewall/nope/rules").status_code == 404
    assert c.get("/api/firewall/fw-1/bogus").status_code == 400
    assert hub.calls == []


def test_firewall_write_refresh_is_exact_to_that_firewall():
    hub, rules = _fw_hub()
    c = _fw_client(hub, _ADMIN)
    c.get("/api/firewall/fw-1/rules")
    c.get("/api/firewall/fw-10/rules")
    rules["fw-1"].append({"uuid": "r2"})
    rules["fw-10"].append({"uuid": "r11"})

    async def go():
        hub.cache_refresh("fw_rules", ("fw-1",), exact=True)
        await hub.cache_wait_idle(2)
    asyncio.run(go())
    assert hub.warm_get("fw_rules", "fw-1") == [{"uuid": "r1"}, {"uuid": "r2"}]
    assert hub.warm_get("fw_rules", "fw-10") == [{"uuid": "r10"}]


# ═════════════════════════ firewall: network impairment ══════════════════════

def test_impairment_spoke_error_is_shown_and_read_is_cached():
    hub, _ = _fw_hub()
    hub.replies[("sp-1", "OPNSENSE_ADD_IMPAIRMENT")] = lambda p: {
        "status": "ERROR", "message": "The os-netimpair plugin is not installed"}
    hub.replies[("sp-1", "OPNSENSE_GET_IMPAIRMENTS")] = lambda p: {
        "status": "SUCCESS", "data": [{"uuid": "i1", "target": "10.0.0.5"}]}
    c = _fw_client(hub, _ADMIN)
    r = c.post("/api/firewall/fw-1/impair", json={"target": "10.0.0.5", "delay": 50})
    assert r.status_code == 400 and "os-netimpair" in r.json()["detail"]
    assert c.get("/api/firewall/fw-1/impair").json()[0]["uuid"] == "i1"


def test_impairment_on_shared_firewall_must_be_inside_tenant_subnet():
    import access
    hub, _ = _fw_hub()
    hub.replies[("sp-1", "OPNSENSE_ADD_IMPAIRMENT")] = lambda p: {"status": "SUCCESS", "uuid": "i2"}
    tenant = {"user": {"tenant_id": "t1"}}
    saved = (access.write_scope, access.resolve_owned_prefixes, access.fw_rule_in_tenant_scope)

    async def owned(hub_, sess):
        return ["10.1.0.0/24"]

    async def overlaps(*a):
        return True
    access.write_scope = lambda sess, tid: "constrained"
    access.resolve_owned_prefixes = owned
    access.fw_rule_in_tenant_scope = overlaps
    try:
        c = _fw_client(hub, tenant)
        assert c.post("/api/firewall/fw-1/impair", json={"target": "10.0.0.0/8"}).status_code == 403
        assert c.post("/api/firewall/fw-1/impair", json={"target": "10.2.0.5"}).status_code == 403
        assert c.post("/api/firewall/fw-1/impair", json={"target": "10.1.0.5"}).status_code == 200
    finally:
        access.write_scope, access.resolve_owned_prefixes, access.fw_rule_in_tenant_scope = saved
    assert [cmd for _, cmd, _ in hub.calls] == ["OPNSENSE_ADD_IMPAIRMENT"]
