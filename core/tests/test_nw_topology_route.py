"""GET/POST /api/nw/topology — tenant scoping and graph assembly.

Reuses the real fake-hub harness from ``test_nw_tenant_scoping`` (the nw routes
registered on a minimal app with the real middleware gate) so the topology route
is exercised through the same authorization path as every other nw read.

The scoping cases matter more than the graph ones: a topology map fuses data
from LLDP, NetBox and MAC tables, which is exactly the kind of cross-source
aggregation that leaks another tenant's gear if the per-device authorization is
skipped anywhere.
"""
import pytest  # noqa: F401

from test_nw_tenant_scoping import _build, _mint


def _seed(hub, per_device):
    """Make the fake spoke answer NW_GET_* per device id.

    ``per_device`` is ``{device_id: {command: [rows]}}``. Anything unlisted
    falls through to the harness's canned behaviour.
    """
    original = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        did = (data or {}).get("device_id")
        rows = (per_device.get(did) or {}).get(cmd)
        if rows is not None:
            hub.calls.append((spoke_id, cmd, data))
            return {"payload": {"data": {"status": "SUCCESS", "data": list(rows)}}}
        return await original(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr


def _names(graph):
    return {n["name"] for n in graph["nodes"]}


def _edge_names(graph):
    by_id = {n["id"]: n["name"] for n in graph["nodes"]}
    return {frozenset((by_id.get(e["a"]), by_id.get(e["b"]))) for e in graph["edges"]}


# ── tenant scoping ──────────────────────────────────────────────────────────

def test_admin_in_the_default_scope_maps_only_the_default_tenant(monkeypatch, tmp_path):
    """The ADMIN scope is the default tenant itself: it must not fuse every
    tenant's gear into one mesh, and it is no longer a "select a tenant" dead end."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/topology?tenant=default", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert not body.get("select_tenant")
    assert not ({"acme", "other"} & _names(body))


def test_admin_acting_as_a_tenant_sees_only_that_tenants_devices(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert _names(r.json()) == {"acme"}   # NOT "other"; NOT "shared" (acme owns an nw spoke)
    r = c.get("/api/nw/topology?tenant=beta", cookies={"lm_session": tok})
    assert _names(r.json()) == {"shared"}


def test_admin_acting_as_a_legacy_case_twin_maps_only_its_own(monkeypatch, tmp_path):
    """With legacy tenants "acme" and "ACME" both stored, tenant ids compare by
    exact spelling (access._AMBIGUOUS_TENANT_IDS), so one's map never shows
    the other's device."""
    import access
    from test_nw_tenant_scoping import _ACME_SW, _OTHER_SW
    c, hub = _build(monkeypatch, tmp_path,
                    gc_extra={"nw_devices": [_ACME_SW, {**_OTHER_SW, "tenant_id": "ACME"}]})
    tok = _mint(hub, "admin", tenants=[], admin=True)
    hub.state.tenant_state["tenants"]["ACME"] = {"netbox_tenant_slug": "acme-upper"}
    monkeypatch.setattr(access, "_AMBIGUOUS_TENANT_IDS",
                        access._case_collisions(hub.state.tenant_state["tenants"]))
    for tenant, names in (("acme", {"acme"}), ("ACME", {"other"})):
        r = c.get(f"/api/nw/topology?tenant={tenant}", cookies={"lm_session": tok})
        assert r.status_code == 200, r.text
        assert _names(r.json()) == names


def test_admin_acting_as_only_spaces_maps_no_unassigned_device(monkeypatch, tmp_path):
    """An acting tenant of only spaces names no tenant, so the map shows no
    unassigned device (those belong to the ADMIN scope, ?tenant=default)."""
    from test_nw_tenant_scoping import _ACME_SW, _OTHER_SW
    c, hub = _build(monkeypatch, tmp_path,
                    gc_extra={"nw_devices": [_ACME_SW, {**_OTHER_SW, "tenant_id": ""}]})
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/topology?tenant=%20%20", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert _names(r.json()) == set()


def test_a_tenant_user_never_sees_another_tenants_device(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert _names(body) == {"acme"}
    tok = _mint(hub, "b", tenants=["beta"])
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert _names(body) == {"shared"}


def test_an_unauthenticated_call_is_rejected(monkeypatch, tmp_path):
    c, _hub = _build(monkeypatch, tmp_path)
    assert c.get("/api/nw/topology").status_code == 401


# ── graph assembly ──────────────────────────────────────────────────────────

def test_lldp_adjacency_becomes_a_link(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": [
        {"local_port": "1", "remote_chassis": "00:0b:86:bc:49:87",
         "remote_port": "24", "remote_name": "acme-edge-1",
         "remote_mgmt_ip": "10.0.0.9"}]}})
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok}).json()
    assert "acme-edge-1" in _names(body)
    assert frozenset(("acme", "acme-edge-1")) in _edge_names(body)
    assert body["stats"]["edges_by_source"] == {"lldp": 1}


def test_the_graph_is_built_off_the_event_loop(monkeypatch, tmp_path):
    """Building a big tenant's map is CPU work; it must not stall the loop."""
    import asyncio
    from routes import nw as nw_routes
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": []}})
    threads, real = [], nw_routes.build_topology

    def spy(**kw):
        # A worker thread has no running loop; the loop's own thread does.
        try:
            asyncio.get_running_loop()
            threads.append("loop")
        except RuntimeError:
            threads.append("worker")
        return real(**kw)
    monkeypatch.setattr(nw_routes, "build_topology", spy)
    tok = _mint(hub, "u", tenants=["acme"])
    assert c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok}).status_code == 200
    assert threads and set(threads) == {"worker"}


def test_a_refreshed_graph_is_then_served_from_cache(monkeypatch, tmp_path):
    """The page load must not re-SSH every device: after one refresh the graph
    rebuilds from the warm per-device cache with no further relay calls."""
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": [
        {"local_port": "1", "remote_chassis": "", "remote_port": "24",
         "remote_name": "acme-edge-1", "remote_mgmt_ip": "10.0.0.9"}]}})
    tok = _mint(hub, "u", tenants=["acme"])
    c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok})
    hub.calls.clear()
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert "acme-edge-1" in _names(body)
    assert not [c_ for c_ in hub.calls if c_[1] == "NW_GET_LLDP_NEIGHBORS"]


def test_an_unknown_mac_becomes_a_non_infra_endpoint(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_MAC_TABLE": [
        {"mac": "aa:bb:cc:dd:ee:77", "interface": "5"}]}})
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok}).json()
    assert _names(body) == {"acme", "aa:bb:cc:dd:ee:77"}
    ep = next(n for n in body["nodes"] if n["name"] == "aa:bb:cc:dd:ee:77")
    assert ep["infra"] is False
    assert len(body["edges"]) == 1 and body["edges"][0]["source"] == "mac"


def test_declaring_a_device_makes_its_mac_a_named_link(monkeypatch, tmp_path):
    """The headline workflow: gear that speaks no LLDP is only a MAC on a port
    until an operator declares it."""
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_MAC_TABLE": [
        {"mac": "aa:bb:cc:dd:ee:77", "interface": "5"}]}})
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
               json={"tenant": "acme", "devices": [
                   {"name": "acme-camera-1", "mac": "aa:bb:cc:dd:ee:77"}]})
    assert r.status_code == 200, r.text
    body = c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok}).json()
    assert frozenset(("acme", "acme-camera-1")) in _edge_names(body)
    assert body["stats"]["edges_by_source"] == {"mac": 1}


def test_inference_can_be_turned_off(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_MAC_TABLE": [
        {"mac": "aa:bb:cc:dd:ee:77", "interface": "5"}]}})
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme",
                 "devices": [{"name": "cam", "mac": "aa:bb:cc:dd:ee:77"}]})
    body = c.get("/api/nw/topology?refresh=1&infer=0",
                 cookies={"lm_session": tok}).json()
    assert body["edges"] == []
    # The declared device is still a node; only the GUESS is suppressed.
    assert "cam" in _names(body)


def test_a_declared_link_is_drawn(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme",
                 "devices": [{"name": "patch-sw", "kind": "switch"}],
                 "links": [{"a": "acme-sw", "a_port": "7", "b": "patch-sw",
                            "b_port": "uplink", "note": "rack B12"}]})
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert frozenset(("acme", "patch-sw")) in _edge_names(body)
    assert body["edges"][0]["source"] == "manual"
    assert body["edges"][0]["detail"] == "rack B12"


def test_an_offline_device_does_not_blank_the_map(monkeypatch, tmp_path):
    """One switch failing to answer must degrade to "no links from that box",
    never a 500 that takes the whole view down."""
    c, hub = _build(monkeypatch, tmp_path)

    async def _boom(spoke_id, cmd, data, timeout=30.0):
        raise RuntimeError("ssh timeout")

    hub.request_response = _boom
    tok = _mint(hub, "u", tenants=["acme"])
    r = c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert _names(r.json()) == {"acme"}


# ── declared-topology persistence ───────────────────────────────────────────

def test_declared_topology_persists_under_the_tenant(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme", "devices": [{"name": "pdu-1", "ip": "10.0.0.50"}]})
    gc = hub.state.system_state["global_config"]
    saved = gc["nw_tenant_cfg"]["acme"]["topology"]["devices"]
    assert [d["name"] for d in saved] == ["pdu-1"]
    assert saved[0]["id"]           # server-assigned stable id
    got = c.get("/api/nw/topology/manual", cookies={"lm_session": tok}).json()
    assert [d["name"] for d in got["devices"]] == ["pdu-1"]


def test_omitting_a_list_leaves_that_half_untouched(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme", "devices": [{"name": "pdu-1"}],
                 "links": [{"a": "acme-sw", "b": "pdu-1"}]})
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme", "devices": [{"name": "pdu-1"}, {"name": "pdu-2"}]})
    got = c.get("/api/nw/topology/manual", cookies={"lm_session": tok}).json()
    assert len(got["devices"]) == 2 and len(got["links"]) == 1


def test_nameless_devices_and_half_links_are_dropped(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
           json={"tenant": "acme", "devices": [{"mac": "aa:bb:cc:dd:ee:77"}, "junk"],
                 "links": [{"a": "acme-sw"}, {"b": "x"}]})
    got = c.get("/api/nw/topology/manual", cookies={"lm_session": tok}).json()
    assert got["devices"] == [] and got["links"] == []


def test_a_tenant_admin_cannot_declare_topology_for_another_tenant(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "ta", tenants=["acme"], role="tenant_admin")
    r = c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
               json={"tenant": "othercorp", "devices": [{"name": "x"}]})
    assert r.status_code == 403


def test_a_plain_user_cannot_declare_topology(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "u", tenants=["acme"])
    r = c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
               json={"tenant": "acme", "devices": [{"name": "x"}]})
    assert r.status_code == 403


def test_one_tenants_declared_gear_never_appears_on_anothers_map(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    admin = _mint(hub, "admin", tenants=[], admin=True)
    c.post("/api/nw/topology/manual", cookies={"lm_session": admin},
           json={"tenant": "othercorp", "devices": [{"name": "secret-pdu"}]})
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert "secret-pdu" not in _names(body)


# ── NetBox inventory ────────────────────────────────────────────────────────

def _with_netbox(hub, rows):
    original = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_DEVICES":
            return {"payload": {"data": {"devices": list(rows)}}}
        if cmd == "NETBOX_GET_CABLES":
            return {"payload": {"data": {"status": "SUCCESS", "cables": []}}}
        return await original(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr


def test_netbox_inventory_adds_devices_the_fleet_never_logs_into(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24",
                        "role": "pdu"}])
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert "acme-pdu" in _names(body)
    assert body["netbox"] is True


def test_netbox_rows_outside_the_tenants_prefixes_are_dropped(monkeypatch, tmp_path):
    """NetBox is fleet-wide with no LM tenant stamp, so it is the one input that
    could leak another tenant's inventory onto a scoped reader's map."""
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"},
                       {"name": "other-pdu", "primary_ip": "192.168.1.50/24"},
                       {"name": "no-ip-device"}])
    tok = _mint(hub, "u", tenants=["acme"])
    names = _names(c.get("/api/nw/topology", cookies={"lm_session": tok}).json())
    assert "acme-pdu" in names
    assert "other-pdu" not in names
    assert "no-ip-device" not in names   # unplaceable → fails closed


def test_netbox_inventory_is_fetched_once_per_window_and_still_filtered_per_reader(monkeypatch, tmp_path):
    """lm#1876: every map load waited ~6 s on the full NetBox device list."""
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"},
                       {"name": "other-pdu", "primary_ip": "192.168.1.50/24"}])
    fetches = []
    counted = hub.request_response

    async def _count(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_DEVICES":
            fetches.append(cmd)
        return await counted(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _count
    for user in ("a", "b"):
        tok = _mint(hub, user, tenants=["acme"])
        names = _names(c.get("/api/nw/topology", cookies={"lm_session": tok}).json())
        assert "acme-pdu" in names and "other-pdu" not in names  # cached rows are still filtered
    assert len(fetches) == 1


def test_a_failed_cable_list_keeps_the_devices_and_is_not_cached(monkeypatch, tmp_path):
    """A failed list is not cached as "no cables", and is retried once its
    hourly floor has passed, not on every load (fleet rule 4.8)."""
    import time
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"}])
    calls = []
    inner = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_CABLES":
            calls.append(cmd)
            raise TimeoutError("no reply")
        return await inner(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "u", tenants=["acme"])
    for _ in range(2):
        body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
        assert "acme-pdu" in _names(body)
    assert len(calls) == 1  # held back by the floor
    assert "cables" not in (hub.warm_cache.get("nw_topo_netbox") or {})
    key = ("nw_topo_netbox", "cables")
    hub._cache_failed[key] = (time.time() - 3601,) + hub._cache_failed[key][1:]
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert "acme-pdu" in _names(body)
    assert len(calls) == 2  # retried after the floor


def test_netbox_being_down_degrades_instead_of_failing(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    original = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_DEVICES":
            raise RuntimeError("netbox unreachable")
        return await original(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "u", tenants=["acme"])
    r = c.get("/api/nw/topology", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert r.json()["netbox"] is False


# ── pre-built map ───────────────────────────────────────────────────────────

def _count_builds(monkeypatch):
    """Count build_topology calls made by the nw routes."""
    from routes import nw as nw_routes
    builds = []
    real = nw_routes.build_topology

    def _counted(**kw):
        builds.append(1)
        return real(**kw)

    monkeypatch.setattr(nw_routes, "build_topology", _counted)
    return builds


def test_the_map_is_prebuilt_once_and_shared_by_every_reader_of_the_tenant(monkeypatch, tmp_path):
    """The Topology tab used to wait 34-42 s while every load rebuilt the map
    and fetched NetBox. A tenant's map is now built once, in the hub cache,
    and every reader acting as that tenant gets the same copy."""
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"},
                       {"name": "other-pdu", "primary_ip": "192.168.1.50/24"}])
    builds = _count_builds(monkeypatch)
    admin = _mint(hub, "admin", tenants=[], admin=True)
    user = _mint(hub, "u", tenants=["acme"])
    with c:
        bodies = [c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json()
                  for tok in (admin, user, admin)]
    assert len(builds) == 1
    for body in bodies:
        assert _names(body) == {"acme", "acme-pdu"}
        assert "_authz" not in body and body["cached_at"]
    assert bodies[0]["nodes"] == bodies[1]["nodes"]


def test_a_filter_change_is_applied_before_the_prebuilt_map_is_served(monkeypatch, tmp_path):
    """A map built (or restored from disk) before a tenant's filter state
    changed must not be served: here the subnet filter is turned on, and a
    shared switch's neighbour outside the tenant's prefixes must vanish on
    the very next load, not after the next rebuild."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    _seed(hub, {"shared-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
    hub.state.system_state["subnet_filter_modules"] = {"nw": False}
    tok = _mint(hub, "admin", tenants=[], admin=True)
    with c:
        c.get("/api/nw/topology?tenant=beta&refresh=1", cookies={"lm_session": tok})
        names = _names(c.get("/api/nw/topology?tenant=beta",
                             cookies={"lm_session": tok}).json())
        assert "other-edge-1" in names
        hub.state.system_state["subnet_filter_modules"] = {"nw": True}
        names = _names(c.get("/api/nw/topology?tenant=beta",
                             cookies={"lm_session": tok}).json())
    assert "acme-edge-1" in names
    assert "other-edge-1" not in names


def test_a_device_reassigned_away_leaves_the_prebuilt_map_at_once(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    with c:
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": tok}).json()) == {"acme"}
        devs = hub.state.system_state["global_config"]["nw_devices"]
        devs[:] = [{**d, "tenant_id": "othercorp"} if d["id"] == "acme-sw" else d
                   for d in devs]
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": tok}).json()) == set()


def test_a_reader_with_narrower_rights_builds_live_without_restarting_the_tenants_build(
        monkeypatch, tmp_path):
    """A reader whose rights hide some of the tenant's devices can't use the
    tenant's map, but the map is still right for the tenant: it is not
    rebuilt on that reader's every load."""
    import access
    c, hub = _build(monkeypatch, tmp_path)
    builds = _count_builds(monkeypatch)
    admin = _mint(hub, "admin", tenants=[], admin=True)
    user = _mint(hub, "u", tenants=["acme"])
    real = access.read_scope
    monkeypatch.setattr(access, "read_scope", lambda sess, tid: (
        real(sess, tid) if access.is_admin(sess) else "deny"))
    with c:
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": admin}).json()) == {"acme"}
        for _ in range(2):
            assert _names(c.get("/api/nw/topology?tenant=acme",
                                cookies={"lm_session": user}).json()) == set()
        c.portal.call(hub.cache_wait_idle)
        assert len(builds) == 3  # the pre-build, then one live build per load
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": admin}).json()) == {"acme"}
    assert len(builds) == 3


def test_a_reader_never_gets_another_tenants_prebuilt_map(monkeypatch, tmp_path):
    """A reader naming a tenant they don't hold is refused, even once that
    tenant's map is cached, and without ?tenant= gets their own map."""
    c, hub = _build(monkeypatch, tmp_path)
    admin = _mint(hub, "admin", tenants=[], admin=True)
    other = _mint(hub, "o", tenants=["othercorp"])
    with c:
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": admin}).json()) == {"acme"}
        assert c.get("/api/nw/topology?tenant=acme",
                     cookies={"lm_session": other}).status_code == 403
        body = c.get("/api/nw/topology", cookies={"lm_session": other}).json()
    assert _names(body) == {"other"}


def test_a_manual_edit_shows_on_the_next_load(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    with c:
        c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok})
        r = c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
                   json={"tenant": "acme", "devices": [{"name": "dumb-switch"}]})
        assert r.status_code == 200, r.text
        names = _names(c.get("/api/nw/topology?tenant=acme",
                             cookies={"lm_session": tok}).json())
    assert "dumb-switch" in names


@pytest.mark.parametrize("change", ["manual", "refresh"])
def test_a_cached_infer_off_map_is_rebuilt_after_a_change(monkeypatch, tmp_path, change):
    """The infer-off map is not fed, only kept while it is read. A manual
    edit or Refresh from devices drops it, and it must be rebuilt in the
    background, not left for the next infer-off load to build cold."""
    import asyncio
    from routes import nw as nw_routes
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "admin", tenants=[], admin=True)

    async def _settle():
        """Wait for nw's background tasks and the cache fetches they start."""
        while nw_routes._NW_BG_TASKS:
            await asyncio.sleep(0.01)
        await hub.cache_wait_idle()

    with c:
        c.get("/api/nw/topology?tenant=acme&infer=0", cookies={"lm_session": tok})
        c.portal.call(_settle)
        if change == "manual":
            r = c.post("/api/nw/topology/manual", cookies={"lm_session": tok},
                       json={"tenant": "acme", "devices": [{"name": "dumb-switch"}]})
            assert r.status_code == 200, r.text
        else:
            _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
            c.get("/api/nw/topology?tenant=acme&infer=0&refresh=1",
                  cookies={"lm_session": tok})
        c.portal.call(_settle)
        assert "acme" in hub.warm_cache.get("nw_topology_off", {})
        builds = _count_builds(monkeypatch)
        names = _names(c.get("/api/nw/topology?tenant=acme&infer=0",
                             cookies={"lm_session": tok}).json())
    assert builds == []
    assert ("dumb-switch" if change == "manual" else "acme-edge-1") in names


def test_a_tenant_named_like_an_infer_off_key_keeps_its_own_map(monkeypatch, tmp_path):
    """Tenant ids are free text. Tenant "acme|noinfer"'s map and tenant
    "acme"'s infer-off map are both kept, neither overwriting the other."""
    from routes import nw as nw_routes
    c, hub = _build(monkeypatch, tmp_path)

    async def _build_for(hub_, tid, infer):
        return {"status": "SUCCESS", "nodes": [], "links": [], "who": [tid, infer]}

    monkeypatch.setattr(nw_routes, "_nw_topology_build_for", _build_for)
    off = nw_routes._nw_topology_job(hub, "acme", False)
    on = nw_routes._nw_topology_job(hub, "acme|noinfer", True)

    async def _build_both():
        for job in (off, on):
            hub.cache_fetch_later(job.ns, job.key, job.fetch, tenants=job.tenants,
                                  lane=job.lane, refresh_s=job.refresh_s)
        await hub.cache_wait_idle()

    with c:
        c.portal.call(_build_both)
    assert hub.warm_get(off.ns, off.key)["who"] == ["acme", False]
    assert hub.warm_get(on.ns, on.key)["who"] == ["acme|noinfer", True]


def test_rebuilding_many_infer_off_maps_is_bounded(monkeypatch, tmp_path):
    """A shared device's refresh rebuilds every tenant's cached infer-off map.
    Those builds queue in the map lane rather than all starting at once (each
    can ask NetBox for prefixes), and every map is still rebuilt."""
    import asyncio
    from routes import nw as nw_routes
    from warm_cache import LANE_CONCURRENCY
    c, hub = _build(monkeypatch, tmp_path)
    live = {"now": 0, "peak": 0, "built": []}

    async def _build_for(hub_, tid, infer):
        live["now"] += 1
        live["peak"] = max(live["peak"], live["now"])
        await asyncio.sleep(0.02)
        live["now"] -= 1
        live["built"].append(tid)
        return {"status": "SUCCESS", "nodes": [], "links": []}

    monkeypatch.setattr(nw_routes, "_nw_topology_build_for", _build_for)
    tids = [f"t{i}" for i in range(6)]

    async def _rebuild_all():
        for tid in tids:
            nw_routes._nw_topology_rebuild_off(hub, tid)
        await hub.cache_wait_idle()

    with c:
        c.portal.call(_rebuild_all)
    assert live["peak"] <= LANE_CONCURRENCY
    assert sorted(live["built"]) == tids


def test_refresh_from_devices_is_not_undone_by_a_build_already_running(monkeypatch, tmp_path):
    """A pre-build that read the device rows before Refresh from devices
    must not store its map afterwards: the refresh would be silently undone
    until the next rebuild (the digest does not cover row contents)."""
    import asyncio
    from routes import nw as nw_routes
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    gate = {"hold": False, "held": 0}
    real = nw_routes._nw_topology_assemble

    async def _slow(hub_, fleet, infer, tid, scoped, filter_netbox, **kw):
        # A background build (not the route's live one) reads the rows now,
        # then stalls until the live refresh has finished.
        graph = await real(hub_, fleet, infer, tid, scoped, filter_netbox, **kw)
        if gate["hold"] and scoped.__name__ == "scoped":
            gate["held"] += 1
            while gate["hold"]:
                await asyncio.sleep(0.01)
        return graph

    async def _until_held():
        """Wait for the background build to have read its rows."""
        while not gate["held"]:
            await asyncio.sleep(0.01)

    monkeypatch.setattr(nw_routes, "_nw_topology_assemble", _slow)
    with c:
        assert _names(c.get("/api/nw/topology?tenant=acme",
                            cookies={"lm_session": tok}).json()) == {"acme"}
        # Start a rebuild that reads the old (LLDP-less) rows and holds.
        gate["hold"] = True
        c.portal.call(lambda: hub.cache_refresh("nw_topology", ("acme",), exact=True))
        c.portal.call(_until_held)
        _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
        live = _names(c.get("/api/nw/topology?tenant=acme&refresh=1",
                            cookies={"lm_session": tok}).json())
        assert "acme-edge-1" in live
        gate["hold"] = False
        c.portal.call(hub.cache_wait_idle)
        names = _names(c.get("/api/nw/topology?tenant=acme",
                             cookies={"lm_session": tok}).json())
    assert "acme-edge-1" in names


def test_a_refresh_without_a_tenant_rebuilds_the_callers_map(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "u", tenants=["acme"])
    with c:
        c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok})
        _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
        c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok})
        names = _names(c.get("/api/nw/topology?tenant=acme",
                             cookies={"lm_session": tok}).json())
    assert "acme-edge-1" in names


def test_a_refresh_rebuilds_every_map_that_shows_a_shared_device(monkeypatch, tmp_path):
    """A shared switch is on every tenant's map, so refreshing it (here by an
    admin with no tenant selected) rebuilds every map that shows it."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    hub.state.system_state["subnet_filter_modules"] = {"nw": False}
    tok = _mint(hub, "admin", tenants=[], admin=True)
    with c:
        c.get("/api/nw/topology?tenant=beta", cookies={"lm_session": tok})
        _seed(hub, {"shared-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
        c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok})
        names = _names(c.get("/api/nw/topology?tenant=beta",
                             cookies={"lm_session": tok}).json())
    assert "acme-edge-1" in names


def test_a_prebuilt_map_is_rebuilt_at_most_hourly(monkeypatch, tmp_path):
    """Owner-set: the environment changes little, so a page read rebuilds a
    map only once it is an hour old (it used to be every 60 s), to keep the
    load off NetBox."""
    c, hub = _build(monkeypatch, tmp_path)
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"}])
    builds = _count_builds(monkeypatch)
    tok = _mint(hub, "u", tenants=["acme"])

    def load_aged(seconds):
        """Age acme's map by ``seconds``, load it, and wait for any refresh."""
        if seconds:
            hub.warm_cache["nw_topology"]["acme"]["fetched_at"] -= seconds
        assert "acme-pdu" in _names(
            c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())
        c.portal.call(hub.cache_wait_idle)

    with c:
        load_aged(0)
        assert len(builds) == 1
        load_aged(600)   # 10 minutes old: served, not rebuilt
        assert len(builds) == 1
        load_aged(3600)  # over an hour old: rebuilt in the background
        assert len(builds) == 2


def test_an_hourly_rebuild_uses_the_netbox_list_refreshed_on_the_same_tick(
        monkeypatch, tmp_path):
    """When the map and the NetBox list are both due, the map build waits for
    the list refresh instead of caching the hour-old list for another hour.
    Inside the list's floor it asks NetBox nothing."""
    c, hub = _build(monkeypatch, tmp_path)
    rows = [{"name": "acme-old", "primary_ip": "10.0.0.50/24"}]
    _with_netbox(hub, rows)
    asked = []
    inner = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        asked.append(cmd)
        return await inner(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "u", tenants=["acme"])

    def load():
        """Names on acme's pre-built map."""
        return _names(c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())

    def rebuild():
        """Rebuild acme's map in the background, as the refresher does."""
        c.portal.call(lambda: hub.cache_refresh("nw_topology", ("acme",), exact=True))
        c.portal.call(hub.cache_wait_idle)

    with c:
        assert "acme-old" in load()
        rows[:] = [{"name": "acme-new", "primary_ip": "10.0.0.51/24"}]
        for key in ("devices", "cables"):
            hub.warm_cache["nw_topo_netbox"][key]["fetched_at"] -= 3700
        rebuild()
        assert "acme-new" in load()
        before = asked.count("NETBOX_GET_DEVICES")
        rebuild()  # inside the hourly floor: no NetBox call
        assert asked.count("NETBOX_GET_DEVICES") == before


def test_a_netbox_write_through_lm_rebuilds_every_map_after_one_list_read(
        monkeypatch, tmp_path):
    """A device readdressed out of a tenant's prefixes from LM's NetBox page
    leaves that tenant's map once the spoke's list cache has run out, not up
    to an hour later. A burst of writes costs one NetBox list read, and
    nothing is read before the delay."""
    import asyncio
    from routes import nw as nw_routes
    monkeypatch.setattr(nw_routes, "_NW_TOPO_NB_WRITE_DELAY_S", 1.0)
    c, hub = _build(monkeypatch, tmp_path)
    rows = [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"}]
    _with_netbox(hub, rows)
    asked = []
    inner = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        asked.append(cmd)
        return await inner(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "u", tenants=["acme"])

    def load():
        """Names on acme's pre-built map."""
        return _names(c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())

    with c:
        assert "acme-pdu" in load()
        c.portal.call(hub.cache_wait_idle)
        builds = _count_builds(monkeypatch)
        before = asked.count("NETBOX_GET_DEVICES")
        rows[:] = [{"name": "acme-pdu", "primary_ip": "192.168.1.50/24"}]
        for _ in range(3):
            c.portal.call(lambda: nw_routes.nw_topology_netbox_changed(hub))
        assert asked.count("NETBOX_GET_DEVICES") == before
        c.portal.call(asyncio.sleep, 2.0)
        c.portal.call(hub.cache_wait_idle)
        assert asked.count("NETBOX_GET_DEVICES") == before + 1
        assert len(builds) == len(nw_routes._nw_topology_tenants(hub))
        assert "acme-pdu" not in load()


def test_a_page_load_never_waits_on_netbox_for_the_tenants_prefixes(monkeypatch, tmp_path):
    """A load checks the map's digest against the prefixes the hub already
    holds, even past their 5-minute TTL, so it never waits on
    NETBOX_GET_PREFIXES. The background build refreshes them, and a changed
    prefix list then shows on the next load."""
    import access
    c, hub = _build(monkeypatch, tmp_path)
    hub.state.system_state["subnet_filter_modules"] = {"nw": True}
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"},
                       {"name": "acme-pdu-2", "primary_ip": "10.0.1.50/24"}])
    prefix = {"now": "10.0.0.0/24"}
    original = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_PREFIXES":
            hub.calls.append((spoke_id, cmd, data))
            return {"payload": {"data": {"prefixes": [{"prefix": prefix["now"]}]}}}
        return await original(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "admin", tenants=[], admin=True)

    def asked():
        """NETBOX_GET_PREFIXES requests so far."""
        return len([1 for _s, cmd, _d in hub.calls if cmd == "NETBOX_GET_PREFIXES"])

    def load():
        """Names on acme's map."""
        return _names(c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())

    with c:
        assert "acme-pdu-2" not in load()
        assert asked() == 1
        # NetBox's answer changes and the hub's copy expires.
        prefix["now"] = "10.0.0.0/23"
        cache = access._hub_prefix_cache(hub)
        for k, (rows, _exp) in list(cache.items()):
            cache[k] = (rows, 0)
        for _ in range(3):
            assert "acme-pdu-2" not in load()
        assert asked() == 1
        # The background build asks once; the next load shows the change.
        c.portal.call(lambda: hub.cache_refresh("nw_topology", ("acme",), exact=True))
        c.portal.call(hub.cache_wait_idle)
        assert asked() == 2
        assert "acme-pdu-2" in load()
    assert asked() == 2


def test_a_prefix_write_is_not_undone_by_the_feeds_invalidated_copy(monkeypatch, tmp_path):
    """A prefix write clears the hub's prefix answers and invalidates the
    NetBox feed's copy, which keeps the old rows until its refresh lands
    (or for good, when it fails). The next load must not take the old rows
    as the tenant's prefixes: they would match the old map's digest, and a
    prefix just moved away would stay on the map."""
    import time
    import access
    from api import _refresh_module_all_tenants
    c, hub = _build(monkeypatch, tmp_path)
    hub.state.system_state["subnet_filter_modules"] = {"nw": True}
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"},
                       {"name": "acme-pdu-2", "primary_ip": "10.0.1.50/24"}])
    prefix = {"now": "10.0.0.0/23"}
    original = hub.request_response

    async def _rr(spoke_id, cmd, data, timeout=30.0):
        if cmd == "NETBOX_GET_PREFIXES":
            return {"payload": {"data": {"prefixes": [{"prefix": prefix["now"]}]}}}
        return await original(spoke_id, cmd, data, timeout=timeout)

    hub.request_response = _rr
    tok = _mint(hub, "admin", tenants=[], admin=True)

    def load():
        """Names on acme's map."""
        return _names(c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())

    with c:
        hub.warm_cache.setdefault(access._PREFIX_FEED_NS, {})["acme"] = {
            "data": {"prefixes": [{"prefix": "10.0.0.0/23"}]},
            "fetched_at": time.time(), "tenants": ["acme"]}
        assert "acme-pdu-2" in load()
        c.portal.call(hub.cache_wait_idle)
        prefix["now"] = "10.0.0.0/24"
        c.portal.call(lambda: _refresh_module_all_tenants(hub, "netbox_prefixes"))
        assert hub.warm_get(access._PREFIX_FEED_NS, "acme") is not None
        assert "acme-pdu-2" not in load()


@pytest.mark.parametrize("persisted", [False, True])
def test_a_map_built_before_the_netbox_spoke_connects_gets_its_gear_once_it_does(
        monkeypatch, tmp_path, persisted):
    """Right after a hub restart the NetBox spoke has not reconnected. Asking
    for the lists then never reaches NetBox, so it must not start the hourly
    floor, and the maps built meanwhile (with no NetBox gear, or from the
    lists persisted before the restart, now past their hour) must not be
    kept for the hour once the lists arrive. The tenant's prefixes are known
    throughout (the feed's copy is kept on disk), so only the lists change."""
    import time
    import access
    c, hub = _build(monkeypatch, tmp_path)
    hub.state.system_state["subnet_filter_modules"] = {"nw": True}
    _with_netbox(hub, [{"name": "acme-pdu", "primary_ip": "10.0.0.50/24"}])
    connected = {"ipam": False}
    real = hub.get_spoke_by_type
    hub.get_spoke_by_type = lambda t: (real(t) if t != "ipam" or connected["ipam"]
                                       else None)
    tok = _mint(hub, "u", tenants=["acme"])

    def load():
        """Names on acme's map."""
        return _names(c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok}).json())

    def tick():
        """One refresher tick, run to the end."""
        c.portal.call(hub.cache_refresh_tick)
        c.portal.call(hub.cache_wait_idle)

    with c:
        hub.warm_cache.setdefault(access._PREFIX_FEED_NS, {})["acme"] = {
            "data": {"prefixes": [{"prefix": "10.0.0.0/24"}]},
            "fetched_at": time.time() + 3600, "tenants": ["acme"]}
        if persisted:
            old = [{"name": "acme-oldpdu", "primary_ip": "10.0.0.60/24"}]
            for key, rows in (("devices", old), ("cables", [])):
                hub.warm_cache.setdefault("nw_topo_netbox", {})[key] = {
                    "data": rows, "fetched_at": time.time() - 7200}
        tick()
        assert "acme-pdu" not in load()
        assert ("acme-oldpdu" in load()) is persisted
        assert hub.warm_get("nw_topology", "acme") is not None
        connected["ipam"] = True
        tick()
        assert hub.warm_get("nw_topo_netbox", "devices") is not None
        assert "acme-pdu" in load()
        assert "acme-oldpdu" not in load()


def test_the_feed_keeps_every_tenants_map_and_the_netbox_lists_warm(monkeypatch, tmp_path):
    from routes import nw as nw_routes
    _c, hub = _build(monkeypatch, tmp_path)
    keys = {(j.ns, j.key, j.tenants) for j in nw_routes.nw_topology_feed(hub)}
    assert ("nw_topo_netbox", "devices", None) in keys
    assert ("nw_topology", "acme", ("acme",)) in keys
    assert ("nw_topology", "default", ("default",)) in keys
    assert all(j.min_interval_s == 3600 for j in nw_routes.nw_topology_feed(hub)
               if j.ns == "nw_topo_netbox")


@pytest.mark.parametrize("endpoint", ["lldp", "macs", "netbox_devices"])
def test_the_request_free_filter_matches_filter_nw_for_a_reader_acting_as_the_tenant(
        monkeypatch, tmp_path, endpoint):
    """The pre-built map uses filter_nw_for_tenant; filter_nw must give a
    logged-in reader acting as the tenant exactly the same rows, whoever the
    reader is, for owned, shared, foreign and spoke-less data."""
    import asyncio
    from types import SimpleNamespace
    import access
    import api as api_mod
    _c, hub = _build(monkeypatch, tmp_path, shared=True)
    rows = [{"remote_mgmt_ip": "10.0.0.9", "ip": "10.0.0.9", "mac": "aa:00:00:00:00:01"},
            {"remote_mgmt_ip": "192.168.1.9", "ip": "192.168.1.9", "mac": "aa:00:00:00:00:02"},
            {"mac": "aa:00:00:00:00:03"}]
    readers = {"acme": [_mint(hub, "admin", tenants=[], admin=True),
                        _mint(hub, "u", tenants=["acme", "beta"])],
               "beta": [_mint(hub, "admin2", tenants=[], admin=True),
                        _mint(hub, "b", tenants=["beta"])],
               "shared": [_mint(hub, "admin3", tenants=[], admin=True)]}
    loop = asyncio.new_event_loop()
    try:
        for filt in (True, False):
            hub.state.system_state["subnet_filter_modules"] = {"nw": filt}
            for tenant, toks in readers.items():
                for spoke in (None, "nw-acme", "nw-other", "nw-shared"):
                    want = loop.run_until_complete(access.filter_nw_for_tenant(
                        hub, {"data": list(rows)}, endpoint, tenant, spoke))
                    for tok in toks:
                        req = SimpleNamespace(cookies={"lm_session": tok}, query_params={})
                        got = loop.run_until_complete(access.filter_nw(
                            hub, api_mod._sessions, req, {"data": list(rows)}, endpoint,
                            tenant, spoke_id=spoke))
                        assert got == want, (filt, tenant, spoke, tok)
    finally:
        loop.close()


def test_the_lldp_endpoint_is_reachable_per_device(monkeypatch, tmp_path):
    """The map's data source is also a first-class per-device view."""
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": [
        {"local_port": "1", "remote_name": "acme-edge-1"}]}})
    tok = _mint(hub, "u", tenants=["acme"])
    r = c.get("/api/nw/acme-sw/lldp", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert r.json()["data"][0]["remote_name"] == "acme-edge-1"


def test_another_tenants_lldp_is_denied(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    tok = _mint(hub, "u", tenants=["acme"])
    assert c.get("/api/nw/other-sw/lldp",
                 cookies={"lm_session": tok}).status_code == 403


# ── shared-device subnet filtering ──────────────────────────────────────────

_MIXED_LLDP = [
    {"local_port": "1", "remote_chassis": "", "remote_port": "24",
     "remote_name": "acme-edge-1", "remote_mgmt_ip": "10.0.0.9"},
    {"local_port": "2", "remote_chassis": "", "remote_port": "24",
     "remote_name": "other-edge-1", "remote_mgmt_ip": "192.168.1.9"},
]


def test_a_shared_switchs_lldp_is_narrowed_to_the_readers_prefixes(monkeypatch, tmp_path):
    """LLDP carries the REMOTE device's management IP, so an unfiltered map
    built from a SHARED switch would hand a tenant another tenant's gear."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    _seed(hub, {"shared-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
    tok = _mint(hub, "u", tenants=["beta"])
    names = _names(c.get("/api/nw/topology?refresh=1",
                         cookies={"lm_session": tok}).json())
    assert "acme-edge-1" in names
    assert "other-edge-1" not in names


def test_a_dedicated_switchs_lldp_is_not_narrowed(monkeypatch, tmp_path):
    """A device bound to ONE tenant owns its whole dataset — subnet-filtering it
    would blank the map for a tenant whose prefixes don't cover its neighbours."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    _seed(hub, {"acme-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
    tok = _mint(hub, "u", tenants=["acme"])
    names = _names(c.get("/api/nw/topology?refresh=1",
                         cookies={"lm_session": tok}).json())
    assert {"acme-edge-1", "other-edge-1"} <= names


def test_the_per_device_lldp_view_is_filtered_the_same_way(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    _seed(hub, {"shared-sw": {"NW_GET_LLDP_NEIGHBORS": _MIXED_LLDP}})
    tok = _mint(hub, "u", tenants=["beta"])
    rows = c.get("/api/nw/shared-sw/lldp", cookies={"lm_session": tok}).json()["data"]
    assert [r["remote_name"] for r in rows] == ["acme-edge-1"]
