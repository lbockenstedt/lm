"""Kea DHCPv4 ``authoritative`` is coordinator-owned (dhcp/src).

A client that moved VLANs and reboots sends an INIT-REBOOT DHCPREQUEST for its
OLD address. Kea's default (``authoritative: false``) silently drops that when
it has no lease for the client, so the client retries the stale address until
its lease expires. LM pushes ``authoritative: true`` on every v4 sync path so
Kea NAKs it and the client falls back to DISCOVER.
"""
import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DHCP_SRC = os.path.join(ROOT, "dhcp", "src")
if DHCP_SRC not in sys.path:
    sys.path.insert(0, DHCP_SRC)

import kea_cluster  # noqa: E402
import kea_ha  # noqa: E402
import kea_manager  # noqa: E402
import kea_packet_trace as pt  # noqa: E402

MEMBERS = [
    {"id": "node-a", "host": "10.0.0.1", "role": "primary"},
    {"id": "node-b", "host": "10.0.0.2", "role": "standby"},
]


class _Transport:
    enabled = True
    members = MEMBERS


def _coordinator():
    paths = []
    for _ in range(2):
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        paths.append(tmp.name)
    return kea_cluster.KeaHACoordinator(
        _Transport(), mode="hot-standby", state_path=paths[0], state_path6=paths[1])


def test_standalone_sync_sets_authoritative_and_keeps_node_keys():
    mgr = kea_manager.KeaManager()
    written = {}
    mgr.get_config = lambda: {"authoritative": False,
                              "interfaces-config": {"interfaces": ["ens18"]}}
    mgr._set_config = lambda cfg: written.update(cfg)
    assert mgr.sync([], [])["status"] == "SUCCESS"
    assert written["authoritative"] is True
    assert written["interfaces-config"] == {"interfaces": ["ens18"]}


def test_ha_render_sets_authoritative_on_every_node():
    coord = _coordinator()
    node = {"authoritative": False, "lease-database": {"type": "memfile"}}
    plan = coord.render([], [], node_configs={"node-a": node, "node-b": {}})
    for cfg in plan["configs"].values():
        assert cfg["authoritative"] is True
    assert plan["configs"]["node-a"]["lease-database"] == {"type": "memfile"}
    assert "authoritative" in kea_ha.COORDINATOR_OWNED_KEYS


def test_dhcpv6_render_has_no_authoritative():
    plan = _coordinator().render6([], [])
    for cfg in plan["configs"].values():
        assert "authoritative" not in cfg


MAC = "bc:0f:fe:29:75:ff"
INIT_REBOOT_LOG = [
    f"2026-10-17T18:28:27-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_QUERY_LABEL received query: [hwtype=1 {MAC}], cid=[no info], tid=0x36aa229a",
    f"2026-10-17T18:28:27-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_PACKET_RECEIVED [hwtype=1 {MAC}], cid=[no info], tid=0x36aa229a: DHCPREQUEST (type 3) received from 172.21.10.1 to 172.21.1.11 on interface ens18",
    f"2026-10-17T18:28:27-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_INIT_REBOOT [hwtype=1 {MAC}], cid=[no info], tid=0x36aa229a: client is in INIT-REBOOT state and requests address 172.21.0.41",
]


def test_trace_verdict_explains_ignored_init_reboot():
    events = [e for e in (pt.parse_kea_log_line(ln) for ln in INIT_REBOOT_LOG) if e]
    v = pt.verdict_for_client(MAC, events, {"packets": []}, 30, ["*"], ["172.21.1.11"])
    assert v["code"] == "INIT_REBOOT_IGNORED"
    assert "172.21.0.41" in v["message"]
