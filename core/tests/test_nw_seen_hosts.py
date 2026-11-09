import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nw_seen_hosts as seen  # noqa: E402


def test_record_merges_without_erasing_known_facts():
    reg = {}
    seen.record(reg, [{"address": "10.0.0.5/24", "hostname": "pdu-a", "snmp_ok": True,
                       "profile": {"sys_descr": "Rack PDU"}}], now=100)
    seen.record(reg, [{"address": "10.0.0.5", "hostname": "",
                       "profile": {"ssh_banner": "SSH-2.0-x"}},
                      {"address": "fe80::1"}, {"address": "10.0.0.6", "hostname": "10.0.0.6"}],
                now=200)
    e = reg["10.0.0.5"]
    assert (e["first_seen"], e["last_seen"], e["hostname"], e["snmp_ok"]) == (100, 200, "pdu-a", True)
    assert e["profile"] == {"sys_descr": "Rack PDU", "ssh_banner": "SSH-2.0-x"}
    assert set(reg) == {"10.0.0.5", "10.0.0.6"} and "hostname" not in reg["10.0.0.6"]
    assert [x["address"] for x in seen.unidentified(reg)] == ["10.0.0.6"]


def test_prune_and_monitor_window():
    day = 86400
    reg = {"10.0.0.1": {"address": "10.0.0.1", "last_seen": 0},
           "10.0.0.2": {"address": "10.0.0.2", "last_seen": 38 * day - 2 * day},
           "10.0.0.3": {"address": "10.0.0.3", "hostname": "sw1", "last_seen": 38 * day}}
    assert seen.prune(reg, now=38 * day) == 1 and "10.0.0.1" not in reg
    rows = seen.monitor_rows({"t": reg}, 38 * day, skip_addresses=set(), skip_names={"sw1"})
    # .2 is two days stale; .3 is ping-only, so nothing is monitored.
    assert rows == []
    reg["10.0.0.3"].update(snmp_ok=True, snmp_credential_id="snmp:t:S")
    rows = seen.monitor_rows({"t": reg}, 38 * day, skip_addresses=set(), skip_names={"sw1"})
    # .3 is sw1 at another address: the same box, so it is not added again.
    assert rows == []
    reg["10.0.0.4"] = {"address": "10.0.0.4", "last_seen": 38 * day, "snmp_ok": True,
                       "snmp_credential_id": "snmp:t:S"}
    reg["10.0.0.5"] = {**reg["10.0.0.4"], "address": "10.0.0.5", "hostname": "pdu-a"}
    rows = seen.monitor_rows({"t": reg}, 38 * day, skip_addresses=set(), skip_names={"sw1"})
    # .4 has no sysName and is not monitored; .5 is named by its sysName.
    assert rows == [{"tenant_id": "t", "name": "pdu-a", "address": "10.0.0.5",
                     "type": "host", "snmp_ok": True, "snmp_secret": "snmp:t:S"}]
    # A TrueNAS sysDescr types the host for its Zabbix template.
    reg["10.0.0.5"]["profile"] = {"sys_descr": "TrueNAS-25.10.7. Hardware: x86_64"}
    rows = seen.monitor_rows({"t": reg}, 38 * day, skip_addresses=set(), skip_names={"sw1"})
    assert rows[0]["type"] == "truenas"


def test_unchanged_hosts_are_pushed_at_most_every_interval():
    reg = {}
    seen.record(reg, [{"address": "10.0.0.1"}, {"address": "10.0.0.2"}], 0)
    assert seen.due_for_push(reg, ["10.0.0.2", "10.0.0.1"], 0) == ["10.0.0.1", "10.0.0.2"]
    seen.mark_pushed(reg, ["10.0.0.1", "10.0.0.2"], 0)
    seen.record(reg, [{"address": "10.0.0.1"}, {"address": "10.0.0.2", "hostname": "sw2"}], 60)
    # Only the host whose details changed is due; the other waits for the interval.
    assert seen.due_for_push(reg, ["10.0.0.1", "10.0.0.2"], 60) == ["10.0.0.2"]
    assert seen.due_for_push(reg, ["10.0.0.1"], seen.PUSH_EVERY) == ["10.0.0.1"]
