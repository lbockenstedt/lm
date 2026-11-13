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

    def get_global_config(self):
        return self.system_state.get("global_config", {})

    def _mark_dirty(self):
        pass

    def get_tenant(self, tid):
        return self.tenant_state["tenants"].get(tid)


class _Hub(WarmCacheMixin):
    def __init__(self, replies, tenants=None, system_state=None, spokes=None):
        self.state = _State(tenants, system_state)
        self.cache_dir = tempfile.mkdtemp(prefix="ldapfw-cache-")
        self.warm_cache_init()
        self.replies = replies        # (spoke, cmd) -> reply, or callable(payload)
        self.calls = []
        self.sent = []
        self.active_connections = {s: object() for s in (spokes or [])}
        self._dir_spokes = {}

    def _primary_key(self, sid):
        return sid

    def get_directory_spoke_for_tenant(self, tid):
        return self._dir_spokes.get(tid)

    async def send_to_spoke(self, msg):
        self.sent.append((msg.header.destination_id, msg.payload.type, msg.payload.data))

    async def opn_config_for_spoke(self, sid):
        from main import LabManagerHub
        return await LabManagerHub.opn_config_for_spoke(self, sid)

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
    assert keys == {(ns, f"{t}|{t}") for t in "ab"
                    for ns in ("ldap_list_users", "ldap_list_groups", "ldap_list_ous")}


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


def test_two_firewalls_on_one_spoke_each_name_their_firewall():
    """Both boxes of an HA pair share one spoke; every command must carry its
    firewall_id or the spoke runs it on the first box."""
    hub = _Hub({("sp-1", "OPNSENSE_ADD_IMPAIRMENT"): lambda p: {"status": "SUCCESS", "uuid": "i1"},
                ("sp-1", "OPNSENSE_GET_ALL_RULES"): lambda p: {"status": "SUCCESS", "data": []}},
               system_state={"global_config": {"firewalls": [
                   {"id": "fw-a", "spoke_id": "sp-1"}, {"id": "fw-b", "spoke_id": "sp-1"}]}},
               spokes=["sp-1"])
    c = _fw_client(hub, _ADMIN)
    assert c.post("/api/firewall/fw-b/impair", json={"target": "10.0.0.5"}).status_code == 200
    c.get("/api/firewall/fw-a/rules")
    c.get("/api/firewall/fw-b/rules")
    sent = [(cmd, p.get("firewall_id")) for _, cmd, p in hub.calls]
    assert ("OPNSENSE_ADD_IMPAIRMENT", "fw-b") in sent
    assert ("OPNSENSE_GET_ALL_RULES", "fw-a") in sent and ("OPNSENSE_GET_ALL_RULES", "fw-b") in sent


def test_impairment_reply_without_success_is_an_error():
    """A timeout or an unrecognised reply must not be shown as 'added'."""
    hub, _ = _fw_hub()
    hub.replies[("sp-1", "OPNSENSE_ADD_IMPAIRMENT")] = lambda p: None
    c = _fw_client(hub, _ADMIN)
    r = c.post("/api/firewall/fw-1/impair", json={"target": "10.0.0.5"})
    assert r.status_code == 400


def _pair_hub():
    """Two boxes of a pair bound to sp-1, one on sp-2; sp-1 and sp-2 online."""
    return _Hub({}, system_state={"global_config": {"firewalls": [
        {"id": "fw-a", "spoke_id": "sp-1", "model": "opnsense", "host": "10.0.0.5",
         "api_key": "k", "api_secret": "s"},
        {"id": "fw-b", "spoke_id": "sp-1", "model": "opnsense", "host": "10.0.0.6",
         "api_key": "k", "api_secret": "s"},
        {"id": "fw-c", "spoke_id": "sp-2", "model": "opnsense", "host": "10.0.0.7",
         "api_key": "k", "api_secret": "s"}]}}, spokes=["sp-1", "sp-2"])


def _pushed_lists(hub):
    """Spoke -> firewall ids in each UPDATE_CONFIG the hub sent."""
    return [(sid, [f["id"] for f in d["firewalls"]]) for sid, t, d in hub.sent if t == "UPDATE_CONFIG"]


def test_editing_one_box_of_a_pair_pushes_both():
    """A Setup save must send the spoke its whole list, not just the edited
    box, or the spoke forgets the other one until it reconnects."""
    hub = _pair_hub()
    r = _fw_client(hub, _ADMIN).put("/setup/firewalls/fw-b", json={"config": {"name": "B2"}})
    assert r.json()["pushed"] is True
    assert _pushed_lists(hub) == [("sp-1", ["fw-a", "fw-b"])]


def test_moving_a_box_to_another_spoke_updates_both_spokes():
    """The old spoke drops the box and the new spoke picks it up."""
    hub = _pair_hub()
    _fw_client(hub, _ADMIN).put("/setup/firewalls/fw-b", json={"config": {"spoke_id": "sp-2"}})
    assert _pushed_lists(hub) == [("sp-1", ["fw-a"]), ("sp-2", ["fw-b", "fw-c"])]


def test_deleting_one_box_of_a_pair_repushes_its_spoke():
    """The spoke drops the deleted box (and its credentials)."""
    hub = _pair_hub()
    assert _fw_client(hub, _ADMIN).delete("/setup/firewalls/fw-a").status_code == 200
    assert _pushed_lists(hub) == [("sp-1", ["fw-b"])]


def test_moving_the_last_box_off_a_spoke_clears_that_spoke():
    """The old spoke gets an empty list (it forgets the box and its
    credentials) instead of nothing."""
    hub = _pair_hub()
    _fw_client(hub, _ADMIN).put("/setup/firewalls/fw-c", json={"config": {"spoke_id": "sp-1"}})
    assert _pushed_lists(hub) == [("sp-2", []), ("sp-1", ["fw-a", "fw-b", "fw-c"])]


def test_unbinding_a_box_repushes_its_spoke_and_reports_pushed():
    """Unbinding leaves no new spoke to push: the old spoke's smaller list is
    the whole push, so the save is "ok", not "partial_success"."""
    hub = _pair_hub()
    r = _fw_client(hub, _ADMIN).put("/setup/firewalls/fw-b", json={"config": {"spoke_id": ""}})
    assert r.json()["pushed"] is True
    assert _pushed_lists(hub) == [("sp-1", ["fw-a"])]


def _frame(data):
    """A reply as the real hub returns it: the whole COMMAND_RESULT frame."""
    return {"header": {}, "payload": {"type": "COMMAND_RESULT", "data": data}}


def test_impairment_result_is_read_inside_the_real_reply_envelope():
    """The spoke's status sits in payload.data: a SUCCESS there is a 200 and an
    ERROR there is a 400 carrying the spoke's own message."""
    hub, _ = _fw_hub()
    c = _fw_client(hub, _ADMIN)
    hub.replies[("sp-1", "OPNSENSE_ADD_IMPAIRMENT")] = lambda p: _frame({"status": "SUCCESS", "uuid": "i1"})
    assert c.post("/api/firewall/fw-1/impair", json={"target": "10.0.0.5"}).status_code == 200
    hub.replies[("sp-1", "OPNSENSE_ADD_IMPAIRMENT")] = lambda p: _frame(
        {"status": "ERROR", "message": "pipe add failed"})
    r = c.post("/api/firewall/fw-1/impair", json={"target": "10.0.0.5"})
    assert r.status_code == 400 and r.json()["detail"] == "pipe add failed"


def test_cached_read_surfaces_an_enveloped_spoke_error():
    """A spoke ERROR inside the frame is a 502, never cached as data."""
    hub, _ = _fw_hub()
    hub.replies[("sp-1", "OPNSENSE_GET_ALL_RULES")] = lambda p: _frame(
        {"status": "ERROR", "message": "no API scope"})
    r = _fw_client(hub, _ADMIN).get("/api/firewall/fw-1/rules")
    assert r.status_code == 502 and "no API scope" in r.text


def test_unbinding_the_last_box_clears_its_spoke():
    """Once bindings are in use an unbound box was unbound on purpose: the
    legacy unbound fallback must not send it straight back to the old spoke."""
    hub = _pair_hub()
    r = _fw_client(hub, _ADMIN).put("/setup/firewalls/fw-c", json={"config": {"spoke_id": ""}})
    assert r.json()["pushed"] is True
    assert _pushed_lists(hub) == [("sp-2", [])]


def test_unbinding_does_not_redeploy_certs(monkeypatch):
    """An unbind has no new spoke; a cert re-deploy for spoke "" would hit
    every firewall spoke. A move still re-deploys to the new spoke."""
    import asyncio
    real, redeploys = asyncio.create_task, []

    def _create_task(coro, *a, **k):
        if "_redeploy_certs_soon" in coro.__qualname__:
            redeploys.append(coro.cr_frame.f_locals.get("spoke_id"))
            coro.close()
            return None
        return real(coro, *a, **k)
    monkeypatch.setattr(asyncio, "create_task", _create_task)
    hub = _pair_hub()
    c = _fw_client(hub, _ADMIN)
    c.put("/setup/firewalls/fw-b", json={"config": {"spoke_id": ""}})
    assert redeploys == []
    c.put("/setup/firewalls/fw-a", json={"config": {"spoke_id": "sp-2"}})
    assert redeploys == ["sp-2"]
