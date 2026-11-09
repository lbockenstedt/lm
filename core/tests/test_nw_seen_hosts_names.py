import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import nw_seen_hosts  # noqa: E402


def _in(t, g):
    return g == "group:ssplm" and t == "ssplm"


def test_seen_host_at_an_appliance_address_takes_the_lm_name():
    rows = [{"tenant_id": "group:ssplm", "name": "MIPBE-SSPLM-N31-TNAS", "address": "172.21.0.5", "snmp_ok": True},
            {"tenant_id": "group:ssplm", "name": "sw1", "address": "172.21.0.9", "snmp_ok": True}]
    apps = [{"name": "MIPBE-SSPLM-TNAS", "host": "https://172.21.0.5:443", "tenant_id": "ssplm"}]
    nw_seen_hosts.apply_appliance_names(rows, apps, _in)
    assert [r["name"] for r in rows] == ["MIPBE-SSPLM-TNAS", "sw1"]


def test_other_tenants_appliance_is_ignored():
    rows = [{"tenant_id": "group:ssplm", "name": "x", "address": "10.0.0.1", "snmp_ok": True}]
    nw_seen_hosts.apply_appliance_names(rows, [{"name": "Y", "host": "10.0.0.1", "tenant_id": "mip"}], _in)
    assert rows[0]["name"] == "x"
