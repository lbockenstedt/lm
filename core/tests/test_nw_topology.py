"""Topology graph assembly from LLDP, NetBox inventory and MAC tables.

The interesting failures here are all about IDENTITY. One switch arrives as a
chassis MAC over LLDP, as a name + primary_ip from NetBox, and as a UUID in the
nw fleet; if those do not collapse to a single node the map sprouts phantom
devices and every link lands on the wrong one. Most of these tests are really
assertions about that collapse.

The fixture data mirrors what the live fleet actually returns (checked against
the hub's nw cache): an ArubaOS gateway whose MAC table is mostly against the
pseudo-port "local", an AOS-S switch with numeric ports, and IEEE control
addresses (01:80:c2:...) littered through both.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest  # noqa: E402

from nw_topology import build_topology  # noqa: E402


FLEET = [
    {"id": "sw1", "name": "OLKS-MGMTSW", "object_type": "aos_switch",
     "address": "172.16.1.90", "tenant_id": "lrb"},
    {"id": "gw1", "name": "GATEWAY", "object_type": "gateway",
     "address": "172.16.1.1", "tenant_id": "lrb"},
]


def _edge_between(graph, name_a, name_b):
    ids = {n["name"]: n["id"] for n in graph["nodes"]}
    a, b = ids.get(name_a), ids.get(name_b)
    for e in graph["edges"]:
        if {e["a"], e["b"]} == {a, b}:
            return e
    return None


def _node(graph, name):
    for n in graph["nodes"]:
        if n["name"] == name:
            return n
    return None


# ── Empty / degenerate ──────────────────────────────────────────────────────

def test_no_inputs_yields_an_empty_graph():
    g = build_topology()
    assert g["nodes"] == [] and g["edges"] == []
    assert g["stats"]["nodes"] == 0


def test_fleet_alone_yields_nodes_but_no_links():
    g = build_topology(fleet=FLEET)
    assert {n["name"] for n in g["nodes"]} == {"OLKS-MGMTSW", "GATEWAY"}
    assert g["edges"] == []
    # Nothing has told us these speak LLDP yet.
    assert g["stats"]["nodes_without_lldp"] == 2


def test_junk_records_are_skipped_not_fatal():
    g = build_topology(fleet=["nope", None, {}, {"id": "x", "name": "X"}],
                       netbox_devices=["nope", 7],
                       netbox_cables=["nope", 7],
                       manual_devices=[None], manual_links=["bad"],
                       lldp_by_device={"x": ["junk", None]},
                       macs_by_device={"x": ["junk"]})
    assert {n["name"] for n in g["nodes"]} == {"X"}


# ── LLDP ────────────────────────────────────────────────────────────────────

def test_lldp_creates_an_edge_and_a_neighbour_node():
    g = build_topology(fleet=FLEET, lldp_by_device={"sw1": [
        {"local_port": "1", "remote_chassis": "00:0b:86:bc:49:87",
         "remote_port": "2", "remote_name": "OLKS-EDGE-1",
         "remote_mgmt_ip": "172.16.1.91", "remote_descr": "Aruba 2930F"},
    ]})
    edge = _edge_between(g, "OLKS-MGMTSW", "OLKS-EDGE-1")
    assert edge and edge["source"] == "lldp"
    assert {edge["a_port"], edge["b_port"]} == {"1", "2"}
    assert _node(g, "OLKS-EDGE-1")["lldp_capable"] is True


def test_both_ends_reporting_the_same_adjacency_draw_one_link():
    """Switch A names B and B names A. Without undirected collapse the map
    draws every infrastructure link twice."""
    g = build_topology(
        fleet=FLEET + [{"id": "sw2", "name": "OLKS-EDGE-1",
                        "object_type": "aos_switch", "address": "172.16.1.91"}],
        lldp_by_device={
            "sw1": [{"local_port": "1", "remote_chassis": "",
                     "remote_port": "2", "remote_name": "OLKS-EDGE-1",
                     "remote_mgmt_ip": "172.16.1.91"}],
            "sw2": [{"local_port": "2", "remote_chassis": "",
                     "remote_port": "1", "remote_name": "OLKS-MGMTSW",
                     "remote_mgmt_ip": "172.16.1.90"}],
        })
    assert len(g["edges"]) == 1


def test_a_neighbour_already_in_the_fleet_is_not_duplicated_as_a_new_node():
    """LLDP reports it by IP; the fleet knows it by UUID. One node, not two."""
    g = build_topology(
        fleet=FLEET + [{"id": "sw2", "name": "OLKS-EDGE-1",
                        "object_type": "aos_switch", "address": "172.16.1.91"}],
        lldp_by_device={"sw1": [
            {"local_port": "1", "remote_chassis": "", "remote_port": "2",
             "remote_name": "OLKS-EDGE-1", "remote_mgmt_ip": "172.16.1.91"}]})
    assert len(g["nodes"]) == 3
    assert _node(g, "OLKS-EDGE-1")["kind"] == "switch"  # fleet kind wins


def test_lldp_for_an_unknown_device_id_is_ignored():
    g = build_topology(fleet=FLEET, lldp_by_device={"ghost": [
        {"local_port": "1", "remote_name": "X", "remote_chassis": ""}]})
    assert g["edges"] == []


# ── NetBox inventory ────────────────────────────────────────────────────────

def test_netbox_adds_devices_the_fleet_never_logged_into():
    g = build_topology(fleet=FLEET, netbox_devices=[
        {"name": "OLKS-PDU-1", "primary_ip": "172.16.1.200/24", "role": "pdu",
         "site": "OLKS", "model": "AP8959"}])
    pdu = _node(g, "OLKS-PDU-1")
    assert pdu and pdu["role"] == "pdu" and pdu["site"] == "OLKS"
    assert "172.16.1.200" in pdu["addresses"]  # the /24 is stripped


def test_netbox_and_lldp_views_of_one_device_merge():
    """NetBox has name+IP, LLDP has MAC+name. Only together do we learn the MAC
    and the IP belong to the same box."""
    g = build_topology(
        fleet=FLEET,
        netbox_devices=[{"name": "OLKS-EDGE-1", "primary_ip": "172.16.1.91/24"}],
        lldp_by_device={"sw1": [
            {"local_port": "1", "remote_chassis": "00:0b:86:bc:49:87",
             "remote_port": "2", "remote_name": "OLKS-EDGE-1"}]})
    edge1 = _node(g, "OLKS-EDGE-1")
    assert "172.16.1.91" in edge1["addresses"]
    assert "00:0b:86:bc:49:87" in edge1["macs"]
    assert len(g["nodes"]) == 3


# ── NetBox cables ────────────────────────────────────────────────────────────

def test_netbox_cable_links_two_netbox_only_devices():
    """The PDU and the patch panel the nw fleet never logs into are the whole
    point of NetBox cables: with no SSH spoke for either end, LLDP and MAC
    inference can say nothing about them at all."""
    g = build_topology(
        fleet=FLEET,
        netbox_devices=[
            {"name": "OLKS-PDU-1", "primary_ip": "172.16.1.200/24"},
            {"name": "OLKS-PATCH-1", "primary_ip": "172.16.1.201/24"},
        ],
        netbox_cables=[{"a_device": "OLKS-PDU-1", "a_port": "1",
                       "b_device": "OLKS-PATCH-1", "b_port": "A3",
                       "label": "cable-42"}])
    edge = _edge_between(g, "OLKS-PDU-1", "OLKS-PATCH-1")
    assert edge and edge["source"] == "netbox"
    assert {edge["a_port"], edge["b_port"]} == {"1", "A3"}
    assert edge["detail"] == "cable-42"


def test_netbox_cable_can_link_into_the_fleet_by_name():
    """A cable naming a device the nw fleet already manages (same name as the
    fleet record) resolves onto that SAME node, not a phantom duplicate."""
    g = build_topology(
        fleet=FLEET,
        netbox_devices=[{"name": "OLKS-PDU-1", "primary_ip": "172.16.1.200/24"}],
        netbox_cables=[{"a_device": "OLKS-MGMTSW", "a_port": "48",
                       "b_device": "OLKS-PDU-1", "b_port": "1"}])
    edge = _edge_between(g, "OLKS-MGMTSW", "OLKS-PDU-1")
    assert edge and edge["source"] == "netbox"
    assert len(g["nodes"]) == 3  # sw1, gw1, OLKS-PDU-1 — no phantom node


def test_netbox_cable_to_a_device_not_on_the_map_is_dropped():
    """A cable end the caller's NetBox fetch didn't return (e.g. filtered to
    another tenant) must not invent an endpoint."""
    g = build_topology(fleet=FLEET, netbox_cables=[
        {"a_device": "OLKS-MGMTSW", "a_port": "1", "b_device": "GHOST-DEV"}])
    assert g["edges"] == []


def test_netbox_cable_loses_to_lldp_on_the_same_port():
    """A stale cable record and a live LLDP adjacency disagreeing about the
    same port: LLDP, being LIVE, wins."""
    g = build_topology(
        fleet=FLEET + [{"id": "sw2", "name": "OLKS-EDGE-1",
                        "object_type": "aos_switch", "address": "172.16.1.91"}],
        lldp_by_device={"sw1": [
            {"local_port": "1", "remote_chassis": "", "remote_port": "2",
             "remote_name": "OLKS-EDGE-1", "remote_mgmt_ip": "172.16.1.91"}]},
        netbox_cables=[{"a_device": "OLKS-MGMTSW", "a_port": "1",
                       "b_device": "OLKS-EDGE-1", "b_port": "2"}])
    assert len(g["edges"]) == 1
    assert g["edges"][0]["source"] == "lldp"


def test_manual_link_beats_a_netbox_cable_on_the_same_port():
    g = build_topology(
        fleet=FLEET,
        netbox_devices=[{"name": "OLKS-PDU-1", "primary_ip": "172.16.1.200/24"}],
        manual_links=[{"a": "sw1", "a_port": "48", "b": "OLKS-PDU-1",
                       "b_port": "1", "note": "verified by hand"}],
        netbox_cables=[{"a_device": "OLKS-MGMTSW", "a_port": "48",
                       "b_device": "OLKS-PDU-1", "b_port": "1"}])
    edge = _edge_between(g, "OLKS-MGMTSW", "OLKS-PDU-1")
    assert edge["source"] == "manual"
    assert edge["detail"] == "verified by hand"


# ── MAC inference ───────────────────────────────────────────────────────────

def test_a_port_with_one_known_mac_becomes_an_inferred_link():
    g = build_topology(
        fleet=FLEET,
        manual_devices=[{"name": "OLKS-CAMERA-1", "mac": "aa:bb:cc:dd:ee:01"}],
        macs_by_device={"sw1": [
            {"mac": "aa:bb:cc:dd:ee:01", "vlan": "1", "interface": "5"}]})
    edge = _edge_between(g, "OLKS-MGMTSW", "OLKS-CAMERA-1")
    assert edge and edge["source"] == "mac"
    assert edge["a_port"] == "5" or edge["b_port"] == "5"


def test_an_unknown_mac_does_not_conjure_a_device():
    """Every switch learns hundreds of MACs. Turning each into a node would
    bury the topology under anonymous endpoints."""
    g = build_topology(fleet=FLEET, macs_by_device={"sw1": [
        {"mac": "aa:bb:cc:dd:ee:99", "interface": "5"}]})
    assert g["edges"] == []
    assert len(g["nodes"]) == 2


def test_a_trunk_port_is_reported_not_guessed_at():
    """Many MACs on one port means a downstream segment, which says nothing
    about what is DIRECTLY attached. It becomes a hint for the operator to
    declare, never an invented link."""
    rows = [{"mac": "aa:bb:cc:dd:ee:%02x" % i, "interface": "100"}
            for i in range(1, 6)]
    g = build_topology(fleet=FLEET, macs_by_device={"sw1": rows})
    assert g["edges"] == []
    assert g["stats"]["trunk_ports"] == 1
    assert g["trunks"][0]["port"] == "100" and g["trunks"][0]["mac_count"] == 5
    assert g["trunks"][0]["node_name"] == "OLKS-MGMTSW"


def test_control_and_local_rows_from_real_hardware_are_ignored():
    """Straight from the live gateway: most of its table is against the pseudo
    port "local", peppered with IEEE control addresses."""
    g = build_topology(fleet=FLEET, macs_by_device={"gw1": [
        {"mac": "01:80:c2:00:00:0e", "interface": "local"},
        {"mac": "00:0b:86:00:00:00", "interface": "local"},
        {"mac": "01:00:5e:00:00:fb", "interface": "0/0/1"},
        {"mac": "33:33:00:00:00:01", "interface": "0/0/1"},
    ]})
    assert g["edges"] == [] and g["stats"]["trunk_ports"] == 0


def test_lldp_wins_over_inference_on_the_same_port():
    """A port with an LLDP neighbour that has also learned that neighbour's MAC
    must not gain a second, redundant inferred link."""
    g = build_topology(
        fleet=FLEET,
        lldp_by_device={"sw1": [
            {"local_port": "1", "remote_chassis": "00:0b:86:bc:49:87",
             "remote_port": "2", "remote_name": "OLKS-EDGE-1"}]},
        macs_by_device={"sw1": [
            {"mac": "00:0b:86:bc:49:87", "interface": "1"}]})
    assert len(g["edges"]) == 1
    assert g["edges"][0]["source"] == "lldp"


def test_inference_can_be_turned_off():
    g = build_topology(
        fleet=FLEET,
        manual_devices=[{"name": "CAM", "mac": "aa:bb:cc:dd:ee:01"}],
        macs_by_device={"sw1": [{"mac": "aa:bb:cc:dd:ee:01", "interface": "5"}]},
        infer_from_macs=False)
    assert g["edges"] == []


def test_trunk_threshold_is_tunable():
    rows = [{"mac": "aa:bb:cc:dd:ee:%02x" % i, "interface": "9"} for i in (1, 2)]
    assert build_topology(fleet=FLEET, macs_by_device={"sw1": rows},
                          trunk_threshold=2)["stats"]["trunk_ports"] == 1


# ── Operator-declared devices and links (the no-LLDP case) ──────────────────

def test_a_declared_device_appears_even_with_no_lldp_and_no_macs():
    g = build_topology(fleet=FLEET, manual_devices=[
        {"name": "OLKS-UNMANAGED-SW", "kind": "switch"}])
    node = _node(g, "OLKS-UNMANAGED-SW")
    assert node and node["manual"] is True and node["kind"] == "switch"


def test_a_declared_link_connects_two_devices():
    g = build_topology(
        fleet=FLEET,
        manual_devices=[{"name": "OLKS-UNMANAGED-SW"}],
        manual_links=[{"a": "sw1", "a_port": "7", "b": "OLKS-UNMANAGED-SW",
                       "b_port": "uplink", "note": "patch panel B12"}])
    edge = _edge_between(g, "OLKS-MGMTSW", "OLKS-UNMANAGED-SW")
    assert edge and edge["source"] == "manual"
    assert edge["detail"] == "patch panel B12"


def test_a_declared_link_may_reference_a_device_by_name_or_ip():
    g = build_topology(fleet=FLEET, manual_links=[
        {"a": "OLKS-MGMTSW", "a_port": "1", "b": "172.16.1.1", "b_port": "0/0/1"}])
    assert _edge_between(g, "OLKS-MGMTSW", "GATEWAY") is not None


def test_a_declared_link_to_an_unknown_device_is_dropped():
    """Rather than inventing an endpoint for a typo'd name."""
    g = build_topology(fleet=FLEET, manual_links=[
        {"a": "sw1", "a_port": "1", "b": "does-not-exist"}])
    assert g["edges"] == []


def test_a_declared_link_beats_an_inferred_one_on_the_same_port():
    g = build_topology(
        fleet=FLEET,
        manual_devices=[{"name": "CAM", "mac": "aa:bb:cc:dd:ee:01"}],
        manual_links=[{"a": "sw1", "a_port": "5", "b": "CAM", "b_port": "eth0"}],
        macs_by_device={"sw1": [{"mac": "aa:bb:cc:dd:ee:01", "interface": "5"}]})
    assert len(g["edges"]) == 1
    assert g["edges"][0]["source"] == "manual"


def test_declaring_a_device_turns_anonymous_macs_into_a_named_node():
    """The headline workflow: a camera speaks no LLDP, so the switch only knows
    its MAC. Declaring the device is what lets inference name the far end."""
    macs = {"sw1": [{"mac": "aa:bb:cc:dd:ee:01", "interface": "5"}]}
    before = build_topology(fleet=FLEET, macs_by_device=macs)
    assert before["edges"] == []
    after = build_topology(fleet=FLEET, macs_by_device=macs, manual_devices=[
        {"name": "OLKS-CAMERA-1", "mac": "aa:bb:cc:dd:ee:01"}])
    assert len(after["edges"]) == 1
    assert _node(after, "OLKS-CAMERA-1") is not None


# ── Output contract ─────────────────────────────────────────────────────────

def test_stats_count_edges_by_source():
    g = build_topology(
        fleet=FLEET,
        manual_devices=[{"name": "CAM", "mac": "aa:bb:cc:dd:ee:01"},
                        {"name": "PDU"}],
        manual_links=[{"a": "sw1", "a_port": "9", "b": "PDU"}],
        lldp_by_device={"sw1": [
            {"local_port": "1", "remote_chassis": "00:0b:86:bc:49:87",
             "remote_port": "2", "remote_name": "EDGE"}]},
        macs_by_device={"sw1": [{"mac": "aa:bb:cc:dd:ee:01", "interface": "5"}]})
    assert g["stats"]["edges_by_source"] == {"manual": 1, "lldp": 1, "mac": 1}
    assert g["stats"]["edges"] == 3


def test_every_node_carries_the_full_shape():
    g = build_topology(fleet=FLEET, netbox_devices=[{"name": "P"}],
                       manual_devices=[{"name": "M"}])
    want = {"id", "name", "kind", "sources", "addresses", "macs", "device_id",
            "tenant_id", "object_type", "model", "site", "role",
            "lldp_capable", "manual", "infra"}
    for n in g["nodes"]:
        assert set(n) == want


def test_a_self_link_is_never_drawn():
    g = build_topology(fleet=FLEET, lldp_by_device={"sw1": [
        {"local_port": "1", "remote_chassis": "", "remote_port": "2",
         "remote_name": "OLKS-MGMTSW", "remote_mgmt_ip": "172.16.1.90"}]})
    assert g["edges"] == []


def test_output_is_deterministic():
    kwargs = dict(fleet=FLEET, netbox_devices=[{"name": "Z"}, {"name": "A"}],
                  manual_devices=[{"name": "M", "mac": "aa:bb:cc:dd:ee:01"}],
                  macs_by_device={"sw1": [{"mac": "aa:bb:cc:dd:ee:01",
                                           "interface": "5"}]})
    assert build_topology(**kwargs) == build_topology(**kwargs)


def test_netbox_row_rerooting_fleet_node_does_not_break_lldp_or_macs():
    """A NetBox row with its own ``id`` matching a fleet switch by IP re-roots
    the alias set, so the fleet id cached at inventory time goes stale. This
    used to raise KeyError (HTTP 500 on /api/nw/topology) and drop MAC edges."""
    netbox = [{"id": 42, "name": "OLKS-MGMTSW", "primary_ip": "172.16.1.90/24"},
              {"id": 43, "name": "printer", "mac": "00:11:22:33:44:55"}]
    lldp = {"sw1": [{"local_port": "24", "remote_chassis": "00:0b:86:aa:bb:cc",
                     "remote_name": "GATEWAY", "remote_mgmt_ip": "172.16.1.1",
                     "remote_port": "0/0/1"}]}
    macs = {"sw1": [{"mac": "00:11:22:33:44:55", "interface": "5", "vlan": "1"}]}
    g = build_topology(fleet=FLEET, lldp_by_device=lldp, macs_by_device=macs,
                       netbox_devices=netbox)
    ids = {n["id"] for n in g["nodes"]}
    assert all(e["a"] in ids and e["b"] in ids for e in g["edges"])
    sw = [n for n in g["nodes"] if n["name"] == "OLKS-MGMTSW"]
    assert len(sw) == 1 and sw[0]["lldp_capable"]
    assert _edge_between(g, "OLKS-MGMTSW", "GATEWAY")["source"] == "lldp"
    assert _edge_between(g, "OLKS-MGMTSW", "printer")["source"] == "mac"


@pytest.mark.parametrize("node,expected", [
    ({"kind": "switch", "sources": ["fleet"]}, True),
    ({"kind": "device", "sources": ["fleet"], "name": "172.21.0.11"}, True),
    ({"kind": "manual", "manual": True, "name": "pdu"}, True),
    ({"kind": "device", "name": "mipbe-ssplm-n31-ilo-pxmx00", "sources": ["netbox"]}, True),
    ({"kind": "neighbor", "name": "core-sw-2", "sources": ["lldp"], "addresses": ["10.0.0.2"]}, True),
    # Live CRSW1 neighbours with NetBox unavailable and no mgmt address.
    ({"kind": "neighbor", "name": "MIPBE-SSPLM-N31-TOR-AGG", "sources": ["lldp"]}, True),
    ({"kind": "neighbor", "name": "mipbe-ssplm-pxmx02.orange-tme.com", "sources": ["lldp"]}, True),
    ({"kind": "neighbor", "name": "Broadcom P225p NetXtreme-E Dual-...", "sources": ["lldp"]}, False),
    # Live junk: NetBox auto-discovery placeholders, MAC-only and garbled LLDP names.
    ({"kind": "device", "name": "device-bc2411aeef4b", "sources": ["netbox"],
      "addresses": ["172.21.1.14"]}, False),
    ({"kind": "device", "name": "CP2102N USB to UART Bridge Controller", "sources": ["netbox"]}, False),
    ({"kind": "neighbor", "name": "84:16:0c:54:af:21", "sources": ["lldp"]}, False),
    ({"kind": "neighbor", "name": "x86_64", "sources": ["lldp"]}, False),
    ({"kind": "neighbor", "name": "fw_version:AFW_214.0.192.0", "sources": ["lldp"]}, False),
    ({"kind": "neighbor", "name": "", "sources": ["lldp"], "addresses": ["10.0.0.9"]}, False),
    ({"sources": None, "name": None}, False),
])
def test_is_infra(node, expected):
    from nw_topology import _is_infra
    assert _is_infra(node) is expected


def test_render_flags_infra_and_counts_it():
    lldp = {"sw1": [{"local_port": "3", "remote_chassis": "84:16:0c:54:af:21",
                     "remote_name": "84:16:0c:54:af:21"}]}
    g = build_topology(fleet=FLEET, lldp_by_device=lldp)
    by_name = {n["name"]: n for n in g["nodes"]}
    assert by_name["OLKS-MGMTSW"]["infra"] and by_name["GATEWAY"]["infra"]
    assert not by_name["84:16:0c:54:af:21"]["infra"]
    assert g["stats"]["infra_nodes"] == 2


def test_fleet_name_survives_merge_with_mac_named_lldp_neighbour():
    """Live shape (MIPBE-SSPLM-N31-CRSW2): another switch's LLDP names this
    switch only by chassis MAC, a second row then ties that MAC to the fleet
    switch's IP. The merged node must keep the fleet hostname, not the MAC."""
    fleet = FLEET + [{"id": "crsw2", "name": "MIPBE-SSPLM-N31-CRSW2",
                      "object_type": "cx_switch", "address": "172.21.0.10"}]
    lldp = {"sw1": [{"local_port": "1", "remote_chassis": "ec:50:aa:f4:5b:00",
                     "remote_name": "ec:50:aa:f4:5b:00"}],
            "gw1": [{"local_port": "2", "remote_chassis": "ec:50:aa:f4:5b:00",
                     "remote_name": "ec:50:aa:f4:5b:00",
                     "remote_mgmt_ip": "172.21.0.10"}]}
    g = build_topology(fleet=fleet, lldp_by_device=lldp)
    names = [n["name"] for n in g["nodes"]]
    assert "MIPBE-SSPLM-N31-CRSW2" in names
    assert "ec:50:aa:f4:5b:00" not in names
    sw = next(n for n in g["nodes"] if n["name"] == "MIPBE-SSPLM-N31-CRSW2")
    assert sw["kind"] == "switch" and sw["device_id"] == "crsw2"


def test_ip_named_fleet_device_is_not_renamed_by_lldp_junk():
    fleet = [{"id": "s9", "name": "172.21.0.11", "object_type": "cx_switch",
              "address": "172.21.0.11"}]
    lldp = {"s9": [{"local_port": "1", "remote_chassis": "20:26:09:18:07:31",
                    "remote_name": "x86_64", "remote_mgmt_ip": "172.21.0.11"}]}
    g = build_topology(fleet=fleet, lldp_by_device=lldp)
    assert [n["name"] for n in g["nodes"]] == ["172.21.0.11"]


def test_ip_named_fleet_switch_takes_lldp_hostname_and_merges_netbox_row():
    # Live admin/default shape: fleet switches are added by address and named
    # after it; the hostname only arrives via a neighbour's LLDP, and NetBox
    # holds the same box under its lowercase hostname with no primary IP.
    fleet = [{"id": "agg", "name": "172.21.0.11", "object_type": "cx_switch",
              "address": "172.21.0.11"},
             {"id": "tor", "name": "172.21.1.1", "object_type": "cx_switch",
              "address": "172.21.1.1"}]
    lldp = {"tor": [{"local_port": "1/1/49", "remote_chassis": "ec:50:aa:00:00:11",
                     "remote_port": "1/1/1", "remote_name": "MIPBE-SSPLM-N31-TOR-AGG",
                     "remote_mgmt_ip": "172.21.0.11"}]}
    netbox = [{"id": 7, "name": "mipbe-ssplm-n31-tor-agg"}]
    g = build_topology(fleet=fleet, lldp_by_device=lldp, netbox_devices=netbox)
    names = sorted(n["name"].casefold() for n in g["nodes"])
    assert names == ["172.21.1.1", "mipbe-ssplm-n31-tor-agg"]
    assert len(g["edges"]) == 1


def _cx_lldp(*ports):
    return [{"local_port": lp, "remote_chassis": mac, "remote_port": rp,
             "remote_name": name, "remote_mgmt_ip": ""}
            for lp, mac, rp, name in ports]


def test_same_switch_scanned_under_several_svis_is_one_node():
    # Live: CRSW2 was in the fleet 9 times (each SVI + the VSX virtual IP),
    # all returning the same LLDP table.
    table = _cx_lldp(("1/1/49", "ec:50:aa:00:00:11", "1/1/1", "AGG"),
                     ("1/1/50", "ec:50:aa:00:00:22", "1/1/1", "TOR"))
    fleet = [{"id": "a", "name": "172.21.0.2", "object_type": "cx_switch", "address": "172.21.0.2"},
             {"id": "b", "name": "MIPBE-SSPLM-N31-CRSW2", "object_type": "cx_switch", "address": "172.21.1.2"},
             {"id": "c", "name": "172.21.10.254", "object_type": "cx_switch", "address": "172.21.10.254"}]
    g = build_topology(fleet=fleet, lldp_by_device={"a": table, "b": table, "c": table})
    switches = [n for n in g["nodes"] if "fleet" in n["sources"]]
    assert [n["name"] for n in switches] == ["MIPBE-SSPLM-N31-CRSW2"]
    assert {"172.21.0.2", "172.21.1.2", "172.21.10.254"} <= set(switches[0]["addresses"])
    assert len(g["edges"]) == 2


def test_different_switches_and_junk_lldp_are_not_merged():
    junk = [{"local_port": ":", "remote_chassis": "84:16:0c:54:af:20", "remote_port": "",
             "remote_name": "84:16:0c:54:af:20"},
            {"local_port": ":", "remote_chassis": "b0:26:28:2d:52:90", "remote_port": "",
             "remote_name": "b0:26:28:2d:52:90"}]
    fleet = [{"id": "g1", "name": "172.21.2.3", "object_type": "gateway", "address": "172.21.2.3"},
             {"id": "g2", "name": "172.21.2.4", "object_type": "gateway", "address": "172.21.2.4"},
             {"id": "s1", "name": "sw1", "object_type": "cx_switch", "address": "10.0.0.1"},
             {"id": "s2", "name": "sw2", "object_type": "cx_switch", "address": "10.0.0.2"}]
    lldp = {"g1": junk, "g2": junk,
            "s1": _cx_lldp(("1/1/1", "ec:50:aa:00:00:11", "1/1/1", "X"),
                           ("1/1/2", "ec:50:aa:00:00:22", "1/1/1", "Y")),
            "s2": _cx_lldp(("1/1/1", "ec:50:aa:00:00:11", "1/1/2", "X"),
                           ("1/1/2", "ec:50:aa:00:00:22", "1/1/2", "Y"))}
    g = build_topology(fleet=fleet, lldp_by_device=lldp)
    assert sorted(n["name"] for n in g["nodes"] if "fleet" in n["sources"]) == [
        "172.21.2.3", "172.21.2.4", "sw1", "sw2"]


def test_gateways_reporting_capability_as_remote_port_stay_separate():
    # Live: both VPNCs' LLDP came back with remote_port "B:R" (the capability
    # column) for CRSW1 and CRSW2 -- identical tables, different boxes.
    rows = [{"local_port": "GE0/0/2", "remote_chassis": "18:7a:3b:d8:6e:00",
             "remote_port": "B:R", "remote_name": "MIPBE-SSPLM-N31-CRSW1"},
            {"local_port": "GE0/0/3", "remote_chassis": "ec:50:aa:f4:5b:00",
             "remote_port": "B:R", "remote_name": "MIPBE-SSPLM-N31-CRSW2"}]
    fleet = [{"id": "v1", "name": "172.21.2.3", "object_type": "gateway", "address": "172.21.2.3"},
             {"id": "v2", "name": "172.21.2.4", "object_type": "gateway", "address": "172.21.2.4"}]
    g = build_topology(fleet=fleet, lldp_by_device={"v1": rows, "v2": list(rows)})
    assert sorted(n["name"] for n in g["nodes"] if "fleet" in n["sources"]) == [
        "172.21.2.3", "172.21.2.4"]
    assert all("B:R" not in (e["a_port"], e["b_port"]) for e in g["edges"])


def test_ip_named_gateway_takes_hostname_from_switch_lldp():
    # Live: VPNCs are in the fleet as 172.21.2.3/.4; CRSW1 advertises them by
    # name on 1/1/43 and 1/1/44, and each VPNC says GE0/0/2 -> 1/1/43|44.
    crsw1 = _cx_lldp(("1/1/43", "00:1a:1e:04:2f:00", "GE0/0/2", "MIPBE-SSPLM-N31-VPNC1"),
                     ("1/1/44", "00:1a:1e:04:2d:50", "GE0/0/2", "MIPBE-SSPLM-N31-VPNC2"))
    v1 = [{"local_port": "GE0/0/2", "remote_chassis": "18:7a:3b:d8:6e:00",
           "remote_port": "1/1/43", "remote_name": "MIPBE-SSPLM-N31-CRSW1"}]
    v2 = [{"local_port": "GE0/0/2", "remote_chassis": "18:7a:3b:d8:6e:00",
           "remote_port": "1/1/44", "remote_name": "MIPBE-SSPLM-N31-CRSW1"}]
    fleet = [{"id": "c1", "name": "MIPBE-SSPLM-N31-CRSW1", "object_type": "cx_switch", "address": "172.21.0.1"},
             {"id": "v1", "name": "172.21.2.3", "object_type": "gateway", "address": "172.21.2.3"},
             {"id": "v2", "name": "172.21.2.4", "object_type": "gateway", "address": "172.21.2.4"}]
    g = build_topology(fleet=fleet, lldp_by_device={"c1": crsw1, "v1": v1, "v2": v2})
    names = sorted(n["name"] for n in g["nodes"])
    assert names == ["MIPBE-SSPLM-N31-CRSW1", "MIPBE-SSPLM-N31-VPNC1", "MIPBE-SSPLM-N31-VPNC2"]
    assert len(g["edges"]) == 2
    assert {(e["a_port"], e["b_port"]) for e in g["edges"]} <= {
        ("1/1/43", "GE0/0/2"), ("GE0/0/2", "1/1/43"), ("1/1/44", "GE0/0/2"), ("GE0/0/2", "1/1/44")}


def test_ip_named_switches_name_each_other_by_port_pair():
    crsw1 = _cx_lldp(("1/1/47", "ec:50:aa:f4:5b:00", "1/1/48", "MIPBE-SSPLM-N31-CRSW2"))
    crsw2 = _cx_lldp(("1/1/48", "18:7a:3b:d8:6e:00", "1/1/47", "MIPBE-SSPLM-N31-CRSW1"))
    fleet = [{"id": "a", "name": "172.21.0.1", "object_type": "cx_switch", "address": "172.21.0.1"},
             {"id": "b", "name": "172.21.0.2", "object_type": "cx_switch", "address": "172.21.0.2"}]
    g = build_topology(fleet=fleet, lldp_by_device={"a": crsw1, "b": crsw2})
    assert sorted(n["name"] for n in g["nodes"]) == ["MIPBE-SSPLM-N31-CRSW1", "MIPBE-SSPLM-N31-CRSW2"]
    assert len(g["edges"]) == 1


def test_lldp_fqdn_matches_netbox_short_name_case_insensitively():
    crsw1 = _cx_lldp(("1/1/2", "b0:26:28:2d:52:90", "nic1", "mipbe-ssplm-pxmx02.orange-tme.com"))
    fleet = [{"id": "c1", "name": "MIPBE-SSPLM-N31-CRSW1", "object_type": "cx_switch", "address": "172.21.0.1"}]
    nb = [{"name": "MIPBE-SSPLM-PXMX02", "primary_ip": "172.21.5.12/24", "role": "Hypervisor"}]
    g = build_topology(fleet=fleet, lldp_by_device={"c1": crsw1}, netbox_devices=nb)
    hosts = [n for n in g["nodes"] if "fleet" not in n["sources"]]
    assert len(hosts) == 1
    assert set(hosts[0]["sources"]) >= {"netbox", "lldp"}
    assert "172.21.5.12" in hosts[0]["addresses"]


def test_short_hostname_ignores_ip_mac_and_free_text():
    from nw_topology import _short_hostname
    assert _short_hostname("Host.Example.com") == "host"
    assert _short_hostname("172.21.2.3") == ""
    assert _short_hostname("aabb.ccdd.eeff") == ""
    assert _short_hostname("Broadcom P225p Dual-...") == ""
    assert _short_hostname("plainname") == ""
