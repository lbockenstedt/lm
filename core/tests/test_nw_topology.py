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
            "lldp_capable", "manual"}
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
