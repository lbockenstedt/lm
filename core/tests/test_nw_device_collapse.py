"""Network module: one row per physical box.

A core switch answers SSH/SNMP on every SVI, so discovery adds it once per IP.
``_nwCollapse`` (``WebUI/js/nw.js``) folds rows that are the same hardware —
same serial, else base MAC, else same name/hostname + type — within a tenant,
keeping every address the box answered on. These run the real function under
node.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

NW_JS = Path(__file__).resolve().parents[2] / "WebUI" / "js" / "nw.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None,
                                reason="node is required to execute the WebUI helper")


def _collapse(rows):
    src = NW_JS.read_text()
    start = src.index("function _nwCollapse")
    fn = src[start:src.index("\n}\n", start) + 3]
    harness = fn + f"\nconsole.log(JSON.stringify(_nwCollapse({json.dumps(rows)})));"
    out = subprocess.run(["node", "-e", harness], capture_output=True, text=True,
                         check=True)
    return json.loads(out.stdout)


def _row(i, name, addr, **kw):
    return dict({"id": str(i), "name": name, "address": addr, "tenant_id": "t1",
                 "object_type": "cx_switch", "reachable": True}, **kw)


def test_same_box_at_several_addresses_collapses_to_one_row():
    out = _collapse([
        _row(1, "CORE-SW1", "10.0.0.1", reachable=False),
        _row(2, "core-sw1", "10.0.1.1"),
        _row(3, "CORE-SW1", "10.0.2.1"),
    ])
    assert len(out) == 1
    # A reachable member is the primary (opened on click / polled).
    assert out[0]["id"] == "2" and out[0]["reachable"] is True
    assert out[0]["_addresses"] == ["10.0.0.1", "10.0.1.1", "10.0.2.1"]


def test_serial_merges_even_when_names_differ():
    out = _collapse([_row(1, "SW2", "10.0.0.2", serial="SG1"),
                     _row(2, "10.9.9.9", "10.9.9.9", serial="SG1")])
    assert len(out) == 1 and out[0]["serial"] == "SG1"


def test_different_serials_or_tenants_never_merge():
    out = _collapse([
        _row(1, "DUP", "1.1.1.1", serial="S1"),
        _row(2, "DUP", "1.1.1.2", serial="S2"),
        _row(3, "DUP", "1.1.1.1", serial="S1", tenant_id="t2"),
    ])
    assert len(out) == 3


def test_vsx_peers_sharing_a_system_mac_stay_two_rows():
    out = _collapse([
        _row(1, "CORE-SW1", "10.0.0.1", mac="02:00:00:00:00:01"),
        _row(2, "CORE-SW2", "10.0.0.2", mac="02:00:00:00:00:01"),
    ])
    assert [r["id"] for r in out] == ["1", "2"]


# ── hub side: one NetBox device / one Zabbix host per box ────────────────────

from nw_discovery_sync import nw_hardware_primaries  # noqa: E402


def _dev(i, name, addr, tenant="t1", otype="cx_switch"):
    return {"id": str(i), "name": name, "address": addr, "tenant_id": tenant,
            "object_type": otype}


def test_hub_primaries_fold_aliases_but_keep_vsx_peers():
    devs = [_dev(1, "CRSW1", "10.21.0.1"), _dev(2, "crsw1.example.com", "172.21.0.1"),
            _dev(3, "CRSW2", "172.21.0.2"), _dev(4, "CRSW2", "172.21.0.10"),
            _dev(5, "10.9.9.9", "10.9.9.9"), _dev(6, "CRSW1", "172.21.0.1", tenant="t2")]
    ident = {"2": {"serial": "SG1"}, "5": {"serial": "SG1"},
             "3": {"serial": "SG2"}, "4": {"serial": "SG2"}}
    p = nw_hardware_primaries(devs, ident)
    # Primary = first row with poll data; IP-named row joins by serial.
    assert p["1"] == p["2"] == p["5"] == "2"
    assert p["3"] == p["4"] == "3"        # VSX peer of CRSW1 stays separate
    assert p["6"] == "6"                  # other tenant never merges


def test_hub_primaries_same_name_conflicting_serials_stay_apart():
    p = nw_hardware_primaries([_dev(1, "DUP", "1.1.1.1"), _dev(2, "DUP", "1.1.1.2")],
                              {"1": {"serial": "A"}, "2": {"serial": "B"}})
    assert p == {"1": "1", "2": "2"}


@pytest.mark.asyncio
async def test_alias_row_is_not_pushed_to_netbox():
    from nw_discovery_sync import NwDiscoverySyncMixin

    class _State:
        system_state = {"global_config": {"nw_devices": [
            _dev(1, "CRSW1", "172.21.0.1"), _dev(2, "CRSW1", "10.21.0.1")]}}

    class _Hub(NwDiscoverySyncMixin):
        state = _State()

        def nw_cache_get_device(self, did, ep):
            return {"data": {"serial": "SG1"}}

        def get_spoke_by_type(self, t):
            raise AssertionError("alias must not reach NetBox")

    res, errors, _ = await _Hub().push_nw_device_inventory(
        _dev(2, "CRSW1", "10.21.0.1"), {}, [])
    assert res["status"] == "SKIPPED" and not errors
