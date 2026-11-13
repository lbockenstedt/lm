"""Hardware-serial stitching: matcher, junk-serial rejection and hub refresh."""
from types import SimpleNamespace

from hw_serial_links import (HW_HEALTH_STALE_S, controller_link_for, hw_health_for_nodes,
                             match_links, normalize_serial, refresh_hw_serial_links)


def test_normalize_rejects_junk_and_vm_serials():
    assert normalize_serial("  2m292101k3 ") == "2M292101K3"
    for bad in ("", None, "Not Specified", "To Be Filled By O.E.M.", "None", "Default string",
                "0000000", "abc", "VMware-42 1a 2b", "System Serial Number", "N/A"):
        assert normalize_serial(bad) == "", bad


def _ctl(i, serial, name="ilo"):
    return {"id": i, "name": name, "address": "10.0.0.1", "serial": serial}


def _host(kind, i, serial, name="srv"):
    return {"kind": kind, "id": i, "name": name, "serial": serial}


def test_links_exactly_one_controller_and_one_host():
    rep = match_links([_ctl("c1", "2M292101K3")], [_host("truenas", "t1", "2m292101k3", "TNAS")])
    assert rep["links"] == [{"serial": "2M292101K3",
                             "controller": {"id": "c1", "name": "ilo", "address": "10.0.0.1"},
                             "host": {"kind": "truenas", "id": "t1", "name": "TNAS"}}]
    assert not rep["ambiguous"]


def test_same_machine_from_two_sources_counts_once():
    rep = match_links([_ctl("c1", "ABCDE12345")],
                      [_host("agent", "a1", "ABCDE12345", "tnas.lab"),
                       _host("truenas", "t1", "ABCDE12345", "TNAS")])
    assert len(rep["links"]) == 1 and rep["links"][0]["host"]["kind"] == "truenas"


def test_ambiguity_is_reported_not_linked():
    rep = match_links([_ctl("c1", "ABCDE12345"), _ctl("c2", "ABCDE12345")],
                      [_host("agent", "a1", "ABCDE12345")])
    assert not rep["links"] and rep["ambiguous"][0]["serial"] == "ABCDE12345"
    rep = match_links([_ctl("c1", "ABCDE12345")],
                      [_host("agent", "a1", "ABCDE12345", "one"), _host("agent", "a2", "ABCDE12345", "two")])
    assert not rep["links"] and len(rep["ambiguous"]) == 1


def test_junk_serials_never_link():
    rep = match_links([_ctl("c1", "Not Specified")], [_host("agent", "a1", "Not Specified")])
    assert not rep["links"] and not rep["ambiguous"]


def _hub(devices, appliances, cache=None, agents=None):
    st = SimpleNamespace(system_state={"global_config": {
        "nw_devices": devices, "truenas_appliances": appliances}}, dirty=0)
    st._mark_dirty = lambda: setattr(st, "dirty", st.dirty + 1)
    return SimpleNamespace(state=st, truenas_appliance_cache=cache or {}, agent_info=agents or {})


def test_refresh_persists_both_sides_and_is_idempotent():
    dev = {"id": "c1", "name": "ILO-TNAS", "address": "10.0.0.1", "object_type": "ipmi"}
    app = {"id": "t1", "name": "TNAS"}
    hub = _hub([dev, {"id": "sw", "object_type": "cx_switch", "serial": "ABCDE12345"}], [app],
               cache={"t1": {"info": {"status": "SUCCESS", "data": {"system_serial": "2M292101K3"}}}})
    rep = refresh_hw_serial_links(hub, {"c1": "2M292101K3"})
    assert rep["changed"] and dev["serial"] == "2M292101K3"
    assert dev["host_link"]["name"] == "TNAS" and dev["host_link"]["kind"] == "truenas"
    assert app["linked_controller"]["id"] == "c1"
    assert controller_link_for(dev)["name"] == "TNAS"
    assert not refresh_hw_serial_links(hub, {"c1": "2M292101K3"})["changed"]


def test_refresh_keeps_link_when_host_unreported_but_drops_it_on_serial_change():
    dev = {"id": "c1", "name": "ILO", "object_type": "ipmi", "serial": "2M292101K3",
           "host_link": {"kind": "agent", "id": "a", "name": "pve1", "serial": "2M292101K3"}}
    hub = _hub([dev], [])
    refresh_hw_serial_links(hub)
    assert dev["host_link"]["name"] == "pve1"
    refresh_hw_serial_links(hub, {"c1": "ZZZZZ99999"})
    assert "host_link" not in dev and controller_link_for(
        {**dev, "host_link": {"name": "x", "serial": "OLD12345"}}, "ZZZZZ99999") == {}


def test_refresh_links_agent_host():
    dev = {"id": "c1", "name": "ILO-PVE", "object_type": "ipmi"}
    hub = _hub([dev], [], agents={"g1": {"hostname": "pve1", "hw_serial": "CZ12345678"}})
    refresh_hw_serial_links(hub, {"c1": "cz12345678"})
    assert dev["host_link"] == {**dev["host_link"], "kind": "agent", "id": "g1", "name": "pve1"}


def _ilo(i, node, tenant="acme", kind="agent"):
    return {"id": i, "name": "ilo-" + node, "address": "192.0.2.10", "object_type": "ipmi",
            "tenant_id": tenant, "host_link": {"kind": kind, "id": "g1", "name": node + ".lab"}}


def test_hw_health_follows_the_serial_link_to_the_node():
    health = {"overall": "failed", "source": "snmp", "polled_at": 1000.0,
              "components": {"memory": [{"name": "DIMM 3", "condition": "failed"}]}}
    hub = _hub([_ilo("c1", "pve1"), _ilo("c2", "nas", kind="truenas"),
                {"id": "sw", "object_type": "cx_switch", "host_link": {"kind": "agent", "name": "pve2"}}], [])
    hub.nw_device_cache = {"c1": {"hw_health": health}}
    out = hw_health_for_nodes(hub, ["PVE1", "pve2", "nas"], now=1000.0 + 60)
    assert set(out) == {"PVE1"}
    assert out["PVE1"]["controller"] == {"id": "c1", "name": "ilo-pve1", "address": "192.0.2.10"}
    assert out["PVE1"]["health"]["overall"] == "failed" and "stale" not in out["PVE1"]
    assert hw_health_for_nodes(hub, ["pve1"], now=1000.0 + HW_HEALTH_STALE_S + 1)["pve1"]["stale"]
    assert hw_health_for_nodes(hub, ["pve1"], visible=lambda t: t == "other") == {}


def test_hw_health_linked_but_not_reported_and_error_states():
    hub = _hub([_ilo("c1", "pve1"), _ilo("c2", "pve2")], [])
    hub.nw_device_cache = {"c2": {"hw_health": {"error": "SNMP timeout", "error_at": 5.0}}}
    out = hw_health_for_nodes(hub, ["pve1", "pve2"])
    assert out["pve1"]["health"] is None and "error" not in out["pve1"]
    assert out["pve2"]["health"] is None and out["pve2"]["error"] == "SNMP timeout"


def test_hw_health_with_components_but_no_overall_is_still_a_reading():
    hub = _hub([_ilo("c1", "pve1")], [])
    hub.nw_device_cache = {"c1": {"hw_health": {"components": {"fans": [{"name": "Fan 1", "condition": "ok"}]}}}}
    assert hw_health_for_nodes(hub, ["pve1"])["pve1"]["health"]["components"]["fans"]


def test_hw_health_bad_polled_at_spoils_only_that_node():
    hub = _hub([_ilo("c1", "pve1"), _ilo("c2", "pve2")], [])
    hub.nw_device_cache = {"c1": {"hw_health": {"overall": "ok", "polled_at": "soon"}},
                           "c2": {"hw_health": {"overall": "failed", "polled_at": 10 ** 9 - 60}}}
    got = hw_health_for_nodes(hub, ["pve1", "pve2"], now=10 ** 9)
    # Age unknown is flagged like stale; the other node is untouched.
    assert got["pve1"]["health"]["overall"] == "ok" and got["pve1"]["stale"] is True
    assert got["pve2"]["health"]["overall"] == "failed" and "stale" not in got["pve2"]
