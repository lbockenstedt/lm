"""GET/PUT /admin/common-vrfs and the ``common_vrf_ids`` key of POST
/setup/config (lm#1992): a Global Admin names the NetBox VRFs that shared
infrastructure serves besides the global table.

Only a Global Admin reads or sets them. A bad value is refused (400) before
anything is stored, so a typo cannot change what every tenant sees on shared
infrastructure, and both routes store the same normalized list. The VRFs to
pick from come by name from the NetBox cache feed's copies of the tenants'
prefixes, never from a live NetBox read.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
_ROUTES = os.path.join(os.path.dirname(__file__), "..", "src", "routes")
if _ROUTES not in sys.path:
    sys.path.append(_ROUTES)

import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import setup_misc  # noqa: E402
from _fakes import FakeHub, FakeState  # noqa: E402


class _FakeCtx:
    """Route context whose caller is a Global Admin unless ``admin`` is False."""

    def __init__(self, admin=True):
        self.admin = admin

    def _session_user(self, request):
        """The caller's session."""
        return {"user_id": "alice", "user": {"permissions": {"admin": self.admin}}}

    def _is_admin(self, sess):
        """True for a Global Admin."""
        return self.admin


class _FeedHub(FakeHub):
    """A hub whose NetBox cache feed holds lab1's and lab2's prefixes: both
    use VRF 3, and lab2 alone uses VRF 2."""

    _FEED = {"lab1": [{"prefix": "172.31.200.0/22", "vrf_id": 3, "vrf": "Shared"}],
             "lab2": [{"prefix": "172.21.0.0/24", "vrf_id": 3, "vrf": "Shared"},
                      {"prefix": "10.0.0.0/8", "vrf_id": 2, "vrf": "LAB2-OWN"}]}

    def __init__(self, global_config):
        super().__init__(FakeState(system_state={"global_config": global_config},
                                   tenants={t: {"netbox_tenant_slug": t} for t in self._FEED}))
        self.dirty = 0
        self.state._mark_dirty = self._count_dirty

    def _count_dirty(self):
        """Count the saves the routes ask for."""
        self.dirty += 1

    def warm_get(self, ns, key="_"):
        """The feed's copy of scope ``key``'s prefixes; the hub caches nothing else."""
        rows = self._FEED.get(key) if ns == "nb_prefixes" else None
        return None if rows is None else {"status": "SUCCESS", "prefixes": rows}

    def warm_last_fetched_at(self, ns, key="_"):
        """When the feed stored its copy of scope ``key``."""
        return 1 if ns == "nb_prefixes" and key in self._FEED else None


class _Lab1ActiveHub(_FeedHub):
    """lab1 is the hub's active tenant, and the built-in Admin tenant
    ("default") has no stored record. The hub cache holds only what the NetBox
    cache feed stores, from a NetBox where the default tenant alone uses VRF 9."""

    _NETBOX = dict(_FeedHub._FEED, default=[{"prefix": "192.168.9.0/24", "vrf_id": 9, "vrf": "ADMIN-OWN"}])

    def __init__(self):
        super().__init__({})
        self.state.system_state["active_tenant"] = "lab1"
        self.cache = {}

    def get_spoke_by_type(self, module_type):
        """The NetBox spoke."""
        return "netbox" if module_type == "ipam" else None

    async def request_response(self, spoke_id, cmd, payload, timeout=None):
        """NetBox's answer to a list read: the tenant's prefixes, no other rows."""
        if cmd != "NETBOX_GET_PREFIXES":
            return {"status": "SUCCESS"}
        return {"status": "SUCCESS", "prefixes": self._NETBOX.get(payload["tenant"], [])}

    def warm_get(self, ns, key="_"):
        """What the feed stored for (``ns``, ``key``)."""
        return self.cache.get((ns, key))

    def warm_last_fetched_at(self, ns, key="_"):
        """When the feed stored it."""
        return 1 if (ns, key) in self.cache else None


def _client(admin=True, hub=None, **global_config):
    """A TestClient on the setup_misc routes, and its hub."""
    app = FastAPI()
    hub = hub or _FeedHub(dict(global_config))
    app.state.hub = hub
    setup_misc.register(app, hub, _FakeCtx(admin))
    return TestClient(app), hub


def _stored(hub):
    """The common VRF ids the hub config holds (None when never set)."""
    return hub.state.system_state["global_config"].get("common_vrf_ids")


_VRFS = [{"id": "2", "name": "LAB2-OWN"}, {"id": "3", "name": "Shared"}]


def test_get_lists_the_cached_vrfs_by_name_and_infers_when_unset():
    c, _ = _client()
    r = c.get("/admin/common-vrfs")
    assert r.status_code == 200
    assert r.json() == {"vrf_ids": [], "mode": "automatic", "common": ["3"], "vrfs": _VRFS}


def test_the_feed_keeps_the_admin_tenants_vrfs_listed_while_another_tenant_is_active():
    """The NetBox cache feed also refreshes the built-in Admin tenant, which has
    no stored record while lab1 is the active tenant, so the card lists (and an
    admin can tick) a VRF only the Admin tenant has prefixes in."""
    from routes.netbox import nb_cache_feed
    hub = _Lab1ActiveHub()
    jobs = list(nb_cache_feed(hub))
    assert ("nb_prefixes", "default") in {(j.ns, j.key) for j in jobs}

    async def run_feed():
        """Store each job's NetBox read as the hub cache's copy, as the feed does."""
        for job in jobs:
            hub.cache[(job.ns, job.key)] = await job.fetch()

    asyncio.run(run_feed())
    c, _ = _client(hub=hub)
    r = c.get("/admin/common-vrfs")
    assert r.status_code == 200
    assert r.json() == {"vrf_ids": [], "mode": "automatic", "common": ["3"],
                        "vrfs": [{"id": "9", "name": "ADMIN-OWN"}] + _VRFS}


def test_put_stores_the_normalized_ids_and_an_empty_list_infers_again():
    c, hub = _client()
    r = c.put("/admin/common-vrfs", json={"vrf_ids": [2, " 3", "2"]})
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "vrf_ids": ["2", "3"], "mode": "configured",
                        "common": ["2", "3"], "vrfs": _VRFS}
    assert _stored(hub) == ["2", "3"] and hub.dirty == 1
    r = c.put("/admin/common-vrfs", json={"vrf_ids": []})
    assert r.status_code == 200
    assert (r.json()["mode"], r.json()["common"]) == ("automatic", ["3"])
    assert _stored(hub) == [] and hub.dirty == 2


@pytest.mark.parametrize("body", [{}, [3], {"vrf_ids": None}, {"vrf_ids": "3"},
                                  {"vrf_ids": ["x"]}, {"vrf_ids": [3, 0]}, {"vrf_ids": [True]}])
def test_put_refuses_a_bad_body_and_stores_nothing(body):
    c, hub = _client(common_vrf_ids=["3"])
    r = c.put("/admin/common-vrfs", json=body)
    assert r.status_code == 400
    assert _stored(hub) == ["3"] and hub.dirty == 0


def test_put_refuses_a_body_that_is_not_json():
    c, hub = _client()
    r = c.put("/admin/common-vrfs", content=b"{", headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert _stored(hub) is None and hub.dirty == 0


def test_only_a_global_admin_reads_or_sets_the_common_vrfs():
    c, hub = _client(admin=False)
    assert c.get("/admin/common-vrfs").status_code == 403
    assert c.put("/admin/common-vrfs", json={"vrf_ids": ["2"]}).status_code == 403
    assert _stored(hub) is None and hub.dirty == 0


def test_setup_config_checks_and_normalizes_the_common_vrfs():
    c, hub = _client(common_vrf_ids=["3"])
    r = c.post("/setup/config", json={"config": {"common_vrf_ids": ["abc"]}})
    assert r.status_code == 400 and "common_vrf_ids" in r.json()["detail"]
    assert _stored(hub) == ["3"]
    r = c.post("/setup/config", json={"config": {"common_vrf_ids": [7, "2"]}})
    assert r.status_code == 200 and _stored(hub) == ["2", "7"]
