"""Directory → Entra accounts and groups (``directory_entra`` + its routes).

The engine's Graph calls are pinned against a mock transport; the routes run
against a small in-memory Entra. The routes may touch only the groups
registered on the caller's tenant and the accounts in its base group, a create
never takes over an existing account, and a half-done create is rolled back.
"""
import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import directory_entra as de  # noqa: E402
from cloud_nac import CloudNacError  # noqa: E402
from routes import directory_entra as routes  # noqa: E402

G = "https://graph.microsoft.com/v1.0"
G1 = "11111111-1111-1111-1111-111111111111"
U1 = "22222222-2222-2222-2222-222222222222"


def oid(n):
    """The fake Entra's n-th object id."""
    return f"00000000-0000-0000-0000-{n:012d}"


# ── Engine: Graph call shapes ──────────────────────────────────────────────

def _run(coro_fn, handler, monkeypatch):
    """Run an engine call against a mock Graph; return (result, requests)."""
    seen = []

    async def token(*a, **k):
        return "tok"
    monkeypatch.setattr(de, "fetch_app_token", token)

    def record(req):
        seen.append(req)
        return handler(req)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(record)) as http:
            return await coro_fn(http)
    return asyncio.run(go()), seen


def test_list_group_users_follows_paging_and_404_is_an_error(monkeypatch):
    pages = {
        "first": {"value": [{"id": U1, "userPrincipalName": "a@x.com",
                             "displayName": "A", "accountEnabled": True}],
                  "@odata.nextLink": f"{G}/groups/{G1}/members/microsoft.graph.user?$skiptoken=2"},
        "second": {"value": [{"id": oid(2), "userPrincipalName": "b@x.com",
                              "accountEnabled": False}]},
    }

    def handler(req):
        return httpx.Response(200, json=pages["second" if "skiptoken" in str(req.url) else "first"])
    users, seen = _run(lambda h: de.list_group_users(SimpleNamespace(), G1, http=h),
                       handler, monkeypatch)
    assert [u["id"] for u in users] == [U1, oid(2)]
    assert users[1]["enabled"] is False
    assert len(seen) == 2

    with pytest.raises(CloudNacError):
        _run(lambda h: de.list_group_users(SimpleNamespace(), G1, http=h),
             lambda req: httpx.Response(404, text="not found"), monkeypatch)


def test_create_user_refuses_an_existing_account_and_never_resets_it(monkeypatch):
    def handler(req):
        if req.method == "GET":
            return httpx.Response(200, json={"id": U1, "userPrincipalName": "a@x.com"})
        return httpx.Response(500)
    with pytest.raises(de.EntraConflict):
        _, seen = _run(lambda h: de.create_user(SimpleNamespace(), "a@x.com", http=h),
                       handler, monkeypatch)


def test_create_user_generates_a_password_only_when_none_is_typed(monkeypatch):
    bodies = []

    def handler(req):
        if req.method == "GET":
            return httpx.Response(404)
        bodies.append(json.loads(req.content))
        return httpx.Response(201, json={"id": U1})
    typed, _ = _run(lambda h: de.create_user(SimpleNamespace(), "a@x.com", "Al", "S3cret!pass",
                                             http=h), handler, monkeypatch)
    made, _ = _run(lambda h: de.create_user(SimpleNamespace(), "b@x.com", http=h),
                   handler, monkeypatch)
    assert typed["generated"] is False and typed["password"] == "S3cret!pass"
    assert made["generated"] is True and len(made["password"]) >= 8
    assert bodies[0]["passwordProfile"] == {"password": "S3cret!pass",
                                            "forceChangePasswordNextSignIn": False}
    assert bodies[1]["displayName"] == "b"


def test_membership_is_direct_only_and_calls_are_idempotent(monkeypatch):
    def handler(req):
        return httpx.Response(200, json={"value": [{"id": U1}]})
    member, seen = _run(lambda h: de.is_member(SimpleNamespace(), G1, U1, http=h),
                        handler, monkeypatch)
    assert member is True
    # Direct members, never transitiveMembers / checkMemberGroups.
    assert seen[0].url.path == f"/v1.0/groups/{G1}/members/microsoft.graph.user"
    other, _ = _run(lambda h: de.is_member(SimpleNamespace(), G1, oid(9), http=h),
                    handler, monkeypatch)
    assert other is False
    # Already a member / already removed / already deleted are all success.
    _run(lambda h: de.add_member(SimpleNamespace(), G1, U1, http=h),
         lambda req: httpx.Response(400, text="One or more added object references "
                                    "already exist"), monkeypatch)
    _run(lambda h: de.remove_member(SimpleNamespace(), G1, U1, http=h),
         lambda req: httpx.Response(404), monkeypatch)
    _run(lambda h: de.delete_group(SimpleNamespace(), G1, http=h),
         lambda req: httpx.Response(404), monkeypatch)


def test_a_malformed_object_id_never_reaches_graph(monkeypatch):
    """"../../../users/<victim>#" in a path would make Graph act on another
    object (httpx resolves the dot segments), so every id is checked."""
    hostile = "../../../users/victim#"
    for call in (lambda h: de.remove_member(SimpleNamespace(), G1, hostile, http=h),
                 lambda h: de.add_member(SimpleNamespace(), hostile, U1, http=h),
                 lambda h: de.delete_user(SimpleNamespace(), hostile, http=h),
                 lambda h: de.delete_group(SimpleNamespace(), hostile, http=h),
                 lambda h: de.list_group_users(SimpleNamespace(), hostile, http=h)):
        with pytest.raises(CloudNacError):
            _, seen = _run(call, lambda req: httpx.Response(204), monkeypatch)


def test_names_are_validated():
    assert de.group_name_arg(" Lab Ops ") == "Lab Ops"
    for bad in ("", "-x", "a/b", "x" * 41, "users"):
        with pytest.raises(ValueError):
            de.group_name_arg(bad)
    assert de.upn_arg("al.b@lab.example.com") == "al.b@lab.example.com"
    for bad in ("al", "al@", "al@host", "a b@x.com"):
        with pytest.raises(ValueError):
            de.upn_arg(bad)


# ── Routes against an in-memory Entra ──────────────────────────────────────

class _Entra:
    """Tiny Entra: groups -> member ids, users by id."""

    def __init__(self):
        self.groups, self.users, self.n = {}, {}, 0
        self.fail_add = False

    def _id(self, p):
        self.n += 1
        return f"00000000-0000-0000-0000-{self.n:012d}"

    def install(self, monkeypatch):
        async def create_group(cfg, display):
            gid = self._id("g")
            self.groups[gid] = {"name": display, "members": set()}
            return {"id": gid, "name": display}

        async def delete_group(cfg, gid):
            self.groups.pop(gid, None)

        async def list_group_users(cfg, gid):
            if gid not in self.groups:
                raise CloudNacError("Graph list group members failed: HTTP 404")
            return [{"id": u, **self.users[u]} for u in sorted(self.groups[gid]["members"])]

        async def is_member(cfg, gid, uid):
            return uid in self.groups.get(gid, {}).get("members", set())

        async def add_member(cfg, gid, uid):
            if self.fail_add:
                raise self.fail_add
            self.groups[gid]["members"].add(uid)

        async def remove_member(cfg, gid, uid):
            self.groups[gid]["members"].discard(uid)

        async def create_user(cfg, upn, name="", password=""):
            if any(u["upn"] == upn for u in self.users.values()):
                raise de.EntraConflict(f"{upn} already exists in Entra")
            uid = self._id("u")
            self.users[uid] = {"upn": upn, "name": name or upn.split("@")[0], "enabled": True}
            return {"id": uid, "upn": upn, "name": self.users[uid]["name"],
                    "password": password or "Gen3rated!", "generated": not password}

        async def delete_user(cfg, uid):
            self.users.pop(uid, None)
            for g in self.groups.values():
                g["members"].discard(uid)

        for fn in (create_group, delete_group, list_group_users, is_member, add_member,
                   remove_member, create_user, delete_user):
            monkeypatch.setattr(de, fn.__name__, fn)
        monkeypatch.setattr(routes, "get_oidc_config",
                            lambda hub: SimpleNamespace(ready=True))


class _Hub:
    """Fake hub: two tenants, a pass-through cache, a counted save."""

    def __init__(self):
        self.tenants = {"acme": {"name": "Acme"}, "beta": {"name": "Beta"}}
        self.saves = 0
        self.fail_save = False
        self.refreshed = []
        hub = self

        async def save_state_now():
            if hub.fail_save:
                raise OSError("disk full")
            hub.saves += 1
        self.state = SimpleNamespace(get_tenant=self.tenants.get,
                                     tenant_state={"tenants": self.tenants},
                                     save_state_now=save_state_now)

    async def cache_read(self, ns, key, fetch, tenants=None, lane=None):
        return await fetch()

    def cache_annotate(self, data, ns, key):
        return data

    def cache_refresh(self, ns, keys, exact=False):
        self.refreshed.append((ns, keys))


def _client(monkeypatch, sess=None, raise_server_exceptions=True):
    entra = _Entra()
    entra.install(monkeypatch)
    hub = _Hub()
    app = FastAPI()
    sess = sess or {"user": {"permissions": {"admin": True}}}
    routes.register(app, hub, SimpleNamespace(_session_user=lambda r: sess))
    return TestClient(app, raise_server_exceptions=raise_server_exceptions), hub, entra


def test_first_account_creates_the_base_group_and_joins_it(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    assert c.get("/api/ldap/entra?tenant=acme").json() == {
        "configured": True, "groups": [], "users": []}
    r = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"})
    assert r.status_code == 200
    assert r.json()["password"] == "Gen3rated!"
    base = hub.tenants["acme"][de.TENANT_KEY]
    assert base == [{"id": oid(1), "name": "LM-Acme-Users", "base": True}]
    assert hub.saves == 1
    listing = c.get("/api/ldap/entra?tenant=acme").json()
    assert [u["upn"] for u in listing["users"]] == ["al@x.com"]
    assert listing["groups"][0]["member_count"] == 1
    # A typed password is never echoed back; a second create reuses the base group.
    r = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "bo@x.com",
                                              "password": "Typed!pass9"})
    assert "password" not in r.json()
    assert len(hub.tenants["acme"][de.TENANT_KEY]) == 1
    assert ("ldap_entra", ("acme",)) in hub.refreshed


def test_existing_account_is_409_and_failed_join_rolls_back(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"})
    assert c.post("/api/ldap/entra/users",
                  json={"tenant_id": "acme", "upn": "al@x.com"}).status_code == 409
    # A Graph refusal and an unreachable Graph both undo the new account.
    for err in (CloudNacError("Graph add group member failed: HTTP 403"),
                httpx.ConnectError("refused")):
        entra.fail_add = err
        r = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "cy@x.com"})
        assert r.status_code == 502, r.text
        assert [u["upn"] for u in entra.users.values()] == ["al@x.com"]


def test_groups_create_list_members_and_delete(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    uid = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"}).json()["id"]
    g = c.post("/api/ldap/entra/groups", json={"tenant_id": "acme", "name": "Lab Ops"}).json()
    assert g["name"] == "LM-Acme-Lab Ops" and g["base"] is False
    assert c.post("/api/ldap/entra/groups",
                  json={"tenant_id": "acme", "name": "lab ops"}).status_code == 409
    assert c.post("/api/ldap/entra/groups", json={"tenant_id": "acme",
                                                  "name": "Users"}).status_code == 400
    assert c.post("/api/ldap/entra/groups/members",
                  json={"tenant_id": "acme", "group_id": g["id"], "user_id": uid}).status_code == 200
    listing = c.get("/api/ldap/entra?tenant=acme").json()
    assert [m["upn"] for m in listing["groups"][1]["members"]] == ["al@x.com"]
    assert c.request("DELETE", "/api/ldap/entra/groups/members",
                     json={"tenant_id": "acme", "group_id": g["id"],
                           "user_id": uid}).status_code == 200
    assert c.request("DELETE", "/api/ldap/entra/groups",
                     json={"tenant_id": "acme", "id": g["id"]}).status_code == 200
    assert g["id"] not in entra.groups
    assert [x["base"] for x in hub.tenants["acme"][de.TENANT_KEY]] == [True]


def test_base_group_and_other_tenants_objects_are_out_of_reach(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    al = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"}).json()["id"]
    bo = c.post("/api/ldap/entra/users", json={"tenant_id": "beta", "upn": "bo@x.com"}).json()["id"]
    acme_base = hub.tenants["acme"][de.TENANT_KEY][0]["id"]
    beta_group = c.post("/api/ldap/entra/groups",
                        json={"tenant_id": "beta", "name": "Ops"}).json()["id"]
    acme_group = c.post("/api/ldap/entra/groups",
                        json={"tenant_id": "acme", "name": "Ops"}).json()["id"]
    # The base group can't be deleted or edited directly.
    assert c.request("DELETE", "/api/ldap/entra/groups",
                     json={"tenant_id": "acme", "id": acme_base}).status_code == 400
    assert c.post("/api/ldap/entra/groups/members", json={
        "tenant_id": "acme", "group_id": acme_base, "user_id": bo}).status_code == 400
    # Another tenant's group or account is not found from this tenant.
    assert c.request("DELETE", "/api/ldap/entra/groups",
                     json={"tenant_id": "acme", "id": beta_group}).status_code == 404
    assert c.post("/api/ldap/entra/groups/members", json={
        "tenant_id": "acme", "group_id": acme_group, "user_id": bo}).status_code == 404
    assert c.request("DELETE", "/api/ldap/entra/users",
                     json={"tenant_id": "acme", "id": bo}).status_code == 404
    assert bo in entra.users
    assert c.request("DELETE", "/api/ldap/entra/users",
                     json={"tenant_id": "acme", "id": al}).status_code == 200
    assert al not in entra.users


def test_tenant_admin_cannot_name_another_tenant(monkeypatch):
    ta = {"user": {"tenants": ["acme"], "permissions": {"role": "tenant_admin"}}}
    c, hub, entra = _client(monkeypatch, sess=ta)
    assert c.post("/api/ldap/entra/users",
                  json={"tenant_id": "beta", "upn": "x@x.com"}).status_code == 403
    assert c.get("/api/ldap/entra?tenant=beta").status_code == 403
    assert entra.users == {}


def test_entra_not_configured_lists_nothing_and_refuses_writes(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    monkeypatch.setattr(routes, "get_oidc_config", lambda hub: SimpleNamespace(ready=False))
    assert c.get("/api/ldap/entra?tenant=acme").json()["configured"] is False
    assert c.post("/api/ldap/entra/users",
                  json={"tenant_id": "acme", "upn": "al@x.com"}).status_code == 503


def test_routes_refuse_ids_that_are_not_object_ids(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"})
    g = c.post("/api/ldap/entra/groups", json={"tenant_id": "acme", "name": "Ops"}).json()["id"]
    hostile = "../../../users/" + oid(1) + "#"
    calls = [("DELETE", "/api/ldap/entra/groups/members", {"group_id": g, "user_id": hostile}),
             ("POST", "/api/ldap/entra/groups/members", {"group_id": g, "user_id": hostile}),
             ("DELETE", "/api/ldap/entra/users", {"id": hostile}),
             ("DELETE", "/api/ldap/entra/groups", {"id": hostile})]
    for method, path, body in calls:
        r = c.request(method, path, json={"tenant_id": "acme", **body})
        assert r.status_code == 400, (path, r.text)
    assert len(entra.users) == 1 and len(entra.groups) == 2


def test_group_lists_show_only_the_tenants_own_accounts(monkeypatch):
    c, hub, entra = _client(monkeypatch)
    uid = c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"}).json()["id"]
    g = c.post("/api/ldap/entra/groups", json={"tenant_id": "acme", "name": "Ops"}).json()["id"]
    c.post("/api/ldap/entra/groups/members", json={"tenant_id": "acme", "group_id": g,
                                                   "user_id": uid})
    # Someone outside the tenant, added to the tenant's group by hand in Entra.
    outsider = entra._id("u")
    entra.users[outsider] = {"upn": "ceo@org.com", "name": "CEO", "enabled": True}
    entra.groups[g]["members"].add(outsider)
    groups = c.get("/api/ldap/entra?tenant=acme").json()["groups"]
    ops = next(x for x in groups if x["id"] == g)
    assert [m["upn"] for m in ops["members"]] == ["al@x.com"]


def test_group_registry_stays_consistent_when_the_save_fails(monkeypatch):
    c, hub, entra = _client(monkeypatch, raise_server_exceptions=False)
    c.post("/api/ldap/entra/users", json={"tenant_id": "acme", "upn": "al@x.com"})
    # Create: an unsaved group is deleted again in Entra, not left an orphan.
    hub.fail_save = True
    assert c.post("/api/ldap/entra/groups",
                  json={"tenant_id": "acme", "name": "Ops"}).status_code == 500
    assert len(entra.groups) == 1 and len(hub.tenants["acme"][de.TENANT_KEY]) == 1
    # Delete: a failed save keeps the record, so the delete can be retried.
    hub.fail_save = False
    g = c.post("/api/ldap/entra/groups", json={"tenant_id": "acme", "name": "Ops"}).json()["id"]
    hub.fail_save = True
    assert c.request("DELETE", "/api/ldap/entra/groups",
                     json={"tenant_id": "acme", "id": g}).status_code == 500
    assert any(x["id"] == g for x in hub.tenants["acme"][de.TENANT_KEY])
    hub.fail_save = False
    assert c.request("DELETE", "/api/ldap/entra/groups",
                     json={"tenant_id": "acme", "id": g}).status_code == 200
    assert all(x["id"] != g for x in hub.tenants["acme"][de.TENANT_KEY])
