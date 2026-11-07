"""Hardware-serial stitching: matcher, junk-serial rejection and hub refresh."""
from types import SimpleNamespace

from hw_serial_links import (controller_link_for, match_links, normalize_serial,
                             refresh_hw_serial_links)


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
