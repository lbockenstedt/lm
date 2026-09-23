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

def test_admin_in_the_default_scope_is_asked_to_pick_a_tenant(monkeypatch, tmp_path):
    """The ADMIN scope must not fuse every tenant's gear into one mesh — the
    same rule the device inventory follows."""
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/topology?tenant=default", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["select_tenant"] is True
    assert body["nodes"] == [] and body["edges"] == []


def test_admin_acting_as_a_tenant_sees_only_that_tenants_devices(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "admin", tenants=[], admin=True)
    r = c.get("/api/nw/topology?tenant=acme", cookies={"lm_session": tok})
    assert r.status_code == 200, r.text
    assert _names(r.json()) == {"acme", "shared"}   # NOT "other"


def test_a_tenant_user_never_sees_another_tenants_device(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path, shared=True)
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology", cookies={"lm_session": tok}).json()
    assert _names(body) == {"acme", "shared"}


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


def test_an_unknown_mac_does_not_become_a_device(monkeypatch, tmp_path):
    c, hub = _build(monkeypatch, tmp_path)
    _seed(hub, {"acme-sw": {"NW_GET_MAC_TABLE": [
        {"mac": "aa:bb:cc:dd:ee:77", "interface": "5"}]}})
    tok = _mint(hub, "u", tenants=["acme"])
    body = c.get("/api/nw/topology?refresh=1", cookies={"lm_session": tok}).json()
    assert _names(body) == {"acme"}
    assert body["edges"] == []


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
    tok = _mint(hub, "u", tenants=["acme"])
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
    tok = _mint(hub, "u", tenants=["acme"])
    rows = c.get("/api/nw/shared-sw/lldp", cookies={"lm_session": tok}).json()["data"]
    assert [r["remote_name"] for r in rows] == ["acme-edge-1"]
