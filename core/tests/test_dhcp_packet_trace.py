"""DHCPv4 client request/error trace (dhcp/src/kea_packet_trace.py,
KeaManager.packet_trace, DHCPSpoke DHCP_PACKET_TRACE)."""
import asyncio
import os
import socket
import struct
import sys
from unittest.mock import AsyncMock

import pytest

DHCP_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dhcp", "src"))
if DHCP_SRC not in sys.path:
    sys.path.insert(0, DHCP_SRC)

import dhcp_spoke  # noqa: E402
import kea_manager  # noqa: E402
import kea_packet_trace as pt  # noqa: E402

MAC = "98:f2:b3:b8:e7:e0"
LOG = [
    f"2026-10-17T17:31:03-07:00 svcs01 kea-dhcp4[678]: INFO  COMMAND_RECEIVED Received command 'config-get'",
    f"2026-10-17T17:31:03-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_QUERY_LABEL received query: [hwtype=1 {MAC}], cid=[no info], tid=0x73cbc2f6",
    f"2026-10-17T17:31:03-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_PACKET_RECEIVED [hwtype=1 {MAC}], cid=[no info], tid=0x73cbc2f6: DHCPREQUEST (type 3) received from 172.21.0.1 to 172.21.1.11 on interface ens18",
    f"2026-10-17T17:31:03-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_LEASE_ALLOC [hwtype=1 {MAC}], cid=[no info], tid=0x73cbc2f6: lease 172.21.0.30 has been allocated for 2419200 seconds",
    f"2026-10-17T17:31:03-07:00 svcs01 kea-dhcp4[678]: INFO  DHCP4_PACKET_SEND [hwtype=1 {MAC}], cid=[no info], tid=0x73cbc2f6: trying to send packet DHCPACK (type 5) from 172.21.1.11:67 to 172.21.0.30:68 on interface ens18",
]


def _events(lines):
    return [e for e in (pt.parse_kea_log_line(ln) for ln in lines) if e]


def test_normalize_mac_accepts_common_forms_and_rejects_text():
    assert pt.normalize_mac("98-F2-B3-B8-E7-E0") == MAC
    assert pt.normalize_mac("98f2.b3b8.e7e0") == MAC
    assert pt.normalize_mac("") == ""
    for bad in ("98:f2:b3", "98:f2:b3:b8:e7:e0; rm -rf /", "zz:f2:b3:b8:e7:e0"):
        with pytest.raises(ValueError):
            pt.normalize_mac(bad)


def test_parse_kea_log_line_extracts_packet_fields_and_skips_noise():
    events = _events(LOG)
    assert [e["msg_id"] for e in events] == [
        "DHCP4_QUERY_LABEL", "DHCP4_PACKET_RECEIVED", "DHCP4_LEASE_ALLOC", "DHCP4_PACKET_SEND"]
    rx = events[1]
    assert rx["kind"] == "received" and rx["type"] == "REQUEST"
    assert rx["mac"] == MAC and rx["tid"] == "0x73cbc2f6"
    assert (rx["from"], rx["interface"]) == ("172.21.0.1", "ens18")
    assert events[2]["kind"] == "allocated" and events[2]["lease"] == "172.21.0.30"
    assert events[3]["kind"] == "sent" and events[3]["type"] == "ACK"


def test_verdict_acked_on_latest_transaction():
    v = pt.verdict_for_client(MAC, _events(LOG), {"packets": []}, 30, ["*"], ["172.21.1.11"])
    assert v["code"] == "ACKED"
    assert "172.21.0.30" in v["message"]


def test_verdict_no_offer_when_discover_unanswered_and_latest_tid_wins():
    lines = LOG + [
        f"2026-10-17T18:00:00-07:00 h kea-dhcp4[1]: INFO  DHCP4_PACKET_RECEIVED [hwtype=1 {MAC}], cid=[no info], tid=0x1: DHCPDISCOVER (type 1) received from 172.21.9.1 to 172.21.1.11 on interface ens18",
        f"2026-10-17T18:00:00-07:00 h kea-dhcp4[1]: WARN  ALLOC_ENGINE_V4_ALLOC_FAIL_SUBNET [hwtype=1 {MAC}], cid=[no info], tid=0x1: failed to allocate an IPv4 address in the subnet 172.21.9.0/24",
    ]
    v = pt.verdict_for_client(MAC, _events(lines), {"packets": []}, 30, ["*"], [])
    assert v["code"] == "NO_OFFER"
    assert any("ALLOC_ENGINE_V4_ALLOC_FAIL_SUBNET" in f for f in v["findings"])


def test_verdict_no_request_seen_vs_not_processed():
    v = pt.verdict_for_client(MAC, [], {"ran": True, "seconds": 10, "packets": []},
                              30, ["ens18"], ["10.0.0.5"])
    assert v["code"] == "NO_REQUEST_SEEN" and "10.0.0.5" in v["message"]
    pkt = {"op": "request", "direction": "in", "interface": "ens19", "type": "DISCOVER",
           "giaddr": "0.0.0.0", "chaddr": MAC}
    v = pt.verdict_for_client(MAC, [], {"ran": True, "seconds": 10, "packets": [pkt]},
                              30, ["ens18"], ["10.0.0.5"])
    assert v["code"] == "NOT_PROCESSED" and "ens19" in v["message"]


def _dhcp_frame(msg_type, giaddr="0.0.0.0", vlan=False):
    bootp = bytearray(240)
    bootp[0], bootp[1], bootp[2] = 1, 1, 6
    bootp[4:8] = struct.pack("!I", 0xDEADBEEF)
    bootp[24:28] = socket.inet_aton(giaddr)
    bootp[28:34] = bytes.fromhex(MAC.replace(":", ""))
    bootp[236:240] = b"\x63\x82\x53\x63"
    bootp += bytes([53, 1, msg_type, 50, 4]) + socket.inet_aton("10.0.0.9") + b"\xff"
    udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton("0.0.0.0"), socket.inet_aton("255.255.255.255")) + udp
    eth = b"\xff" * 6 + bytes.fromhex(MAC.replace(":", ""))
    eth += (b"\x81\x00\x00\x0a" if vlan else b"") + b"\x08\x00"
    return eth + ip


def test_parse_dhcp_frame_decodes_bootp_and_vlan_tag():
    pkt = pt.parse_dhcp_frame(_dhcp_frame(1, giaddr="172.21.9.1", vlan=True))
    assert pkt["type"] == "DISCOVER" and pkt["chaddr"] == MAC
    assert pkt["giaddr"] == "172.21.9.1" and pkt["requested_ip"] == "10.0.0.9"
    assert pkt["xid"] == "0xdeadbeef" and pkt["op"] == "request"
    assert pt.parse_dhcp_frame(b"\x00" * 60) is None


def test_counter_delta_reports_only_changes():
    raw_a = {"pkt4-received": [[10, "t"]], "pkt4-discover-received": [[4, "t"]],
             "subnet[1].total-addresses": [[100, "t"]]}
    raw_b = {"pkt4-received": [[13, "t"]], "pkt4-discover-received": [[4, "t"]]}
    a, b = pt.packet_counters(raw_a), pt.packet_counters(raw_b)
    assert "subnet[1].total-addresses" not in a
    assert pt.counter_delta(a, b) == {"pkt4-received": 3}


def test_keamanager_packet_trace_combines_evidence(monkeypatch):
    mgr = kea_manager.KeaManager()

    def rpc(service, command, args=None):
        if command == "statistic-get-all":
            return {"pkt4-received": [[5, "t"]]}
        if command == "lease4-get-by-hw-address":
            assert args == {"hw-address": MAC}
            return {"leases": [{"ip-address": "172.21.0.30", "subnet-id": 7}]}
        raise AssertionError(command)

    monkeypatch.setattr(mgr, "_rpc", rpc)
    monkeypatch.setattr(mgr, "get_config", lambda: {
        "interfaces-config": {"interfaces": ["ens18"]},
        "subnet4": [{"id": 7, "subnet": "172.21.0.0/24", "reservations": [
            {"hw-address": "98-F2-B3-B8-E7-E0", "ip-address": "172.21.0.30"}]}]})
    monkeypatch.setattr(pt, "read_kea_journal", lambda minutes, mac: {
        "events": _events(LOG), "problems": [], "error": ""})
    monkeypatch.setattr(pt, "local_ipv4s", lambda: ["172.21.1.11"])

    out = mgr.packet_trace("98-F2-B3-B8-E7-E0", minutes=5000, capture_seconds=0)
    assert out["status"] == "SUCCESS" and out["mac"] == MAC
    assert out["minutes"] == pt.MAX_LOOKBACK_MINUTES
    assert out["verdict"]["code"] == "ACKED"
    assert out["leases"][0]["ip"] == "172.21.0.30"
    assert out["reservations"][0]["subnet"] == "172.21.0.0/24"
    assert out["summary"]["kea_received"] == {"REQUEST": 1}
    assert out["capture"]["ran"] is False

    assert mgr.packet_trace("not-a-mac")["status"] == "ERROR"


def test_spoke_ha_packet_trace_prefers_node_that_got_furthest():
    spoke = dhcp_spoke.DHCPSpoke.__new__(dhcp_spoke.DHCPSpoke)
    spoke._transport = AsyncMock()
    spoke._transport.fanout.return_value = {"results": {
        "standby": {"status": "SUCCESS", "verdict": {"code": "NOT_PROCESSED"}},
        "primary": {"status": "SUCCESS", "verdict": {"code": "ACKED"}},
    }}
    out = asyncio.run(spoke._ha_packet_trace({"mac": MAC, "capture_seconds": 999}))
    assert out["trace_source"] == "primary" and out["verdict"]["code"] == "ACKED"
    assert set(out["members"]) == {"standby", "primary"}
    args, kwargs = spoke._transport.fanout.call_args
    assert args[0] == "KEAW_PACKET_TRACE"
    assert args[1]["capture_seconds"] == pt.MAX_CAPTURE_SECONDS
    assert kwargs["timeout"] == pt.MAX_CAPTURE_SECONDS + 30.0


def test_spoke_ha_packet_trace_errors_when_no_node_answers():
    spoke = dhcp_spoke.DHCPSpoke.__new__(dhcp_spoke.DHCPSpoke)
    spoke._transport = AsyncMock()
    spoke._transport.fanout.return_value = {"results": {
        "a": {"status": "ERROR", "message": "unknown op KEAW_PACKET_TRACE"}}}
    out = asyncio.run(spoke._ha_packet_trace({"mac": MAC}))
    assert out["status"] == "ERROR" and "unknown op" in out["message"]


def test_worker_exposes_packet_trace_op_and_ha_allowlist():
    import dhcp_worker
    import kea_ha
    assert "KEAW_PACKET_TRACE" in kea_ha.DHCP_WORKER_OPS
    ops = dhcp_worker.DhcpWorkerOps(kea_manager.KeaManager()).op_table()
    assert "KEAW_PACKET_TRACE" in ops
