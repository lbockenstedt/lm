"""DHCPv4 request/error tracing for a Kea node.

Answers "is the DHCP server even seeing my client?" with three independent
pieces of evidence, all gathered on the Kea host itself:

* **Kea's own log** (journal of ``kea-dhcp4-server``). Kea logs
  ``DHCP4_PACKET_RECEIVED`` / ``DHCP4_PACKET_SEND`` / ``DHCP4_LEASE_ALLOC`` at
  INFO, so every packet Kea actually *processed* for a client is there.
* **A short raw capture** of UDP/67-68 on every interface (``AF_PACKET``, no
  tcpdump dependency — the Kea nodes don't ship it). This is what tells
  "never reached the box" apart from "reached the NIC but Kea ignored it"
  (wrong interface, HA standby, dropped before logging).
* **Kea's packet/drop counters** (``statistic-get-all``), as a before/after
  delta around the capture window.

Everything here is read-only: no Kea config or logging level is changed.
"""

import ipaddress
import logging
import re
import select
import socket
import struct
import subprocess
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger("KeaPacketTrace")

MAX_CAPTURE_SECONDS = 60
MAX_LOOKBACK_MINUTES = 24 * 60
MAX_EVENTS = 200
MAX_PACKETS = 200
_JOURNAL_OUTPUT_CAP = 4 * 1024 * 1024

DHCP_MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
                  5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

#: Verdicts from "nothing happened" up to "server finished its side", used to
#: pick the most informative node's answer in an HA pair.
VERDICT_RANK = {
    "NO_REQUEST_SEEN": 0,
    "NOT_PROCESSED": 1,
    "RECEIVED": 2,
    "NO_OFFER": 3,
    "OFFER_NOT_ACCEPTED": 4,
    "REQUEST_UNANSWERED": 5,
    "DECLINED": 6,
    "NAKED": 7,
    "ACKED": 8,
}

_RELEVANT_PREFIXES = ("DHCP4_", "ALLOC_ENGINE_", "DHCPSRV_", "HA_", "HOSTS_")
_NOISE_IDS = {"COMMAND_RECEIVED"}
_LINE_RE = re.compile(
    r"(?P<level>FATAL|ERROR|WARN|INFO|DEBUG)\s+(?P<msgid>[A-Z][A-Z0-9_]{3,})\s*(?P<text>.*)$")
_MAC_RE = re.compile(r"hwtype=\d+\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")
_TID_RE = re.compile(r"tid=(0x[0-9a-fA-F]+)")
_TYPE_RE = re.compile(r"DHCP(DISCOVER|OFFER|REQUEST|DECLINE|ACK|NAK|RELEASE|INFORM)\b")
_RX_RE = re.compile(r"received from (\S+) to (\S+) on interface (\S+)")
_LEASE_RE = re.compile(r"lease (\d+\.\d+\.\d+\.\d+)")


def normalize_mac(mac: Any) -> str:
    """``aa:bb:cc:dd:ee:ff`` for any common MAC spelling; ``""`` for empty.

    Raises ``ValueError`` for anything that isn't 12 hex digits — the MAC is
    used as a journal search term, so it must never be arbitrary text.
    """
    if mac is None or not str(mac).strip():
        return ""
    clean = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    if len(clean) != 12 or len(re.sub(r"[0-9a-fA-F:.\-\s]", "", str(mac))):
        raise ValueError(f"invalid MAC address: {mac!r}")
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    """Parse ``value`` as an int clamped to ``[lo, hi]`` (``default`` if unparsable)."""
    try:
        n = int(float(value))
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


# ── Kea log (journal) ────────────────────────────────────────────────────

def parse_kea_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Kea log line into an event dict, or None if not DHCP-relevant."""
    m = _LINE_RE.search(line or "")
    if not m:
        return None
    msgid = m.group("msgid")
    level = m.group("level")
    if msgid in _NOISE_IDS:
        return None
    if not msgid.startswith(_RELEVANT_PREFIXES) and level not in ("WARN", "ERROR", "FATAL"):
        return None
    text = m.group("text").strip()
    head = line[:m.start()].strip()
    event: Dict[str, Any] = {
        "ts": head.split()[0] if head else "",
        "level": level,
        "msg_id": msgid,
        "text": text[:500],
    }
    mac = _MAC_RE.search(text)
    if mac:
        event["mac"] = mac.group(1).lower()
    tid = _TID_RE.search(text)
    if tid:
        event["tid"] = tid.group(1).lower()
    mtype = _TYPE_RE.search(text)
    if mtype:
        event["type"] = mtype.group(1)
    rx = _RX_RE.search(text)
    if rx:
        event["from"], event["to"], event["interface"] = rx.groups()
    lease = _LEASE_RE.search(text)
    if lease:
        event["lease"] = lease.group(1)
    if msgid == "DHCP4_PACKET_RECEIVED":
        event["kind"] = "received"
    elif msgid == "DHCP4_PACKET_SEND":
        event["kind"] = "sent"
    elif msgid == "DHCP4_LEASE_ALLOC":
        event["kind"] = "allocated"
    elif msgid.startswith("DHCP4_LEASE_OFFER") or msgid == "DHCP4_LEASE_ADVERT":
        event["kind"] = "offered"
    elif (level in ("WARN", "ERROR", "FATAL")
          or any(k in msgid for k in ("DROP", "FAIL", "NAK", "DECLINE", "CONFLICT"))):
        event["kind"] = "problem"
    else:
        event["kind"] = "info"
    return event


def _run(cmd: List[str], timeout: float) -> Dict[str, Any]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, errors="replace")
        return {"ok": result.returncode == 0, "rc": result.returncode,
                "stdout": (result.stdout or "")[-_JOURNAL_OUTPUT_CAP:],
                "stderr": (result.stderr or "").strip()[:500]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": None, "stdout": "", "stderr": str(e)}


def read_kea_journal(minutes: int, mac: str = "",
                     unit: str = "kea-dhcp4-server") -> Dict[str, Any]:
    """Return ``{events, problems, error, source}`` from Kea's journal.

    ``events`` = this client's packet events (or every client's if no MAC);
    ``problems`` = server-wide warnings/errors/drops in the same window.
    """
    since = time.strftime("%Y-%m-%d %H:%M:%S",
                          time.localtime(time.time() - minutes * 60))
    base = ["journalctl", "-u", unit, "--since", since,
            "--no-pager", "-o", "short-iso"]
    error = ""
    if mac:
        res = _run(base + ["--grep", mac, "--case-sensitive=false"], timeout=20)
        if not res["ok"] and res["rc"] != 1:
            # Older journalctl without PCRE2 support rejects --grep — filter here.
            res = _run(base, timeout=30)
            lines = [ln for ln in res["stdout"].splitlines() if mac in ln.lower()]
        else:
            lines = res["stdout"].splitlines()
    else:
        res = _run(base + ["-n", "5000"], timeout=30)
        lines = res["stdout"].splitlines()
    if res["rc"] not in (0, 1):
        error = res["stderr"] or "journalctl failed"
    events = [e for e in (parse_kea_log_line(ln) for ln in lines) if e]
    if mac:
        events = [e for e in events if e.get("mac", mac) == mac]
    else:
        events = [e for e in events if e.get("mac")]

    prob = _run(base + ["-p", "warning", "-n", "300"], timeout=20)
    problems = [e for e in (parse_kea_log_line(ln) for ln in prob["stdout"].splitlines())
                if e and e["kind"] in ("problem", "info")]
    return {"events": events, "problems": problems[-50:], "error": error}


# ── Raw capture ──────────────────────────────────────────────────────────

def parse_dhcp_frame(data: bytes, hatype: int = 1) -> Optional[Dict[str, Any]]:
    """Decode an Ethernet (or raw-IP) frame carrying a DHCPv4/BOOTP packet."""
    off = 0
    if hatype in (1, 772):  # ARPHRD_ETHER / ARPHRD_LOOPBACK
        if len(data) < 14:
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:
            ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if ethertype != 0x0800:
            return None
    if len(data) < off + 20 or data[off] >> 4 != 4:
        return None
    ihl = (data[off] & 0x0F) * 4
    if data[off + 9] != 17:
        return None
    if struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF:
        return None  # non-first fragment
    src = socket.inet_ntoa(data[off + 12:off + 16])
    dst = socket.inet_ntoa(data[off + 16:off + 20])
    u = off + ihl
    if len(data) < u + 8:
        return None
    sport, dport = struct.unpack("!HH", data[u:u + 4])
    if not ({sport, dport} & {67, 68}):
        return None
    b = u + 8
    if len(data) < b + 240:
        return None
    op, _htype, hlen = data[b], data[b + 1], data[b + 2]
    xid = struct.unpack("!I", data[b + 4:b + 8])[0]
    ciaddr, yiaddr, siaddr, giaddr = (socket.inet_ntoa(data[b + i:b + i + 4])
                                      for i in (12, 16, 20, 24))
    hlen = min(hlen or 6, 16)
    chaddr = ":".join(f"{x:02x}" for x in data[b + 28:b + 28 + hlen])
    pkt: Dict[str, Any] = {
        "src": f"{src}:{sport}", "dst": f"{dst}:{dport}",
        "op": "request" if op == 1 else "reply",
        "xid": f"0x{xid:08x}", "chaddr": chaddr,
        "ciaddr": ciaddr, "yiaddr": yiaddr, "siaddr": siaddr, "giaddr": giaddr,
        "type": "BOOTP",
    }
    if data[b + 236:b + 240] == b"\x63\x82\x53\x63":
        i = b + 240
        while i < len(data):
            code = data[i]
            if code == 255:
                break
            if code == 0:
                i += 1
                continue
            if i + 1 >= len(data):
                break
            ln = data[i + 1]
            val = data[i + 2:i + 2 + ln]
            if code == 53 and ln >= 1:
                pkt["type"] = DHCP_MSG_TYPES.get(val[0], f"type{val[0]}")
            elif code == 50 and ln == 4:
                pkt["requested_ip"] = socket.inet_ntoa(val)
            elif code == 54 and ln == 4:
                pkt["server_id"] = socket.inet_ntoa(val)
            elif code == 12:
                pkt["hostname"] = val.decode("utf-8", "replace")[:64]
            elif code == 82:
                pkt["relay_agent_info"] = True
            i += 2 + ln
    return pkt


def capture_dhcp(seconds: int, mac: str = "",
                 max_packets: int = MAX_PACKETS) -> Dict[str, Any]:
    """Sniff UDP/67-68 on every interface for ``seconds`` (needs root/CAP_NET_RAW)."""
    out: Dict[str, Any] = {"ran": False, "seconds": seconds, "packets": [],
                           "truncated": False, "error": ""}
    if seconds <= 0:
        return out
    if not hasattr(socket, "AF_PACKET"):
        out["error"] = "raw packet capture is only supported on Linux"
        return out
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    except (PermissionError, OSError) as e:
        out["error"] = f"cannot open raw socket (needs root/CAP_NET_RAW): {e}"
        return out
    out["ran"] = True
    deadline = time.monotonic() + seconds
    start = time.time()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([sock], [], [], min(remaining, 1.0))
            if not ready:
                continue
            data, addr = sock.recvfrom(65535)
            # addr = (ifname, proto, pkttype, hatype, hwaddr); 4 = PACKET_OUTGOING
            pkt = parse_dhcp_frame(data, addr[3] if len(addr) > 3 else 1)
            if not pkt or (mac and pkt["chaddr"] != mac):
                continue
            pkt["t"] = round(time.time() - start, 3)
            pkt["interface"] = addr[0]
            pkt["direction"] = "out" if len(addr) > 2 and addr[2] == 4 else "in"
            if len(out["packets"]) >= max_packets:
                out["truncated"] = True
                break
            out["packets"].append(pkt)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"capture failed: {e}"
    finally:
        sock.close()
    return out


# ── Counters ─────────────────────────────────────────────────────────────

def packet_counters(raw_stats: Dict[str, Any]) -> Dict[str, int]:
    """Latest value of every global ``pkt4-*`` / ``v4-*`` Kea counter."""
    out = {}
    for key, samples in (raw_stats or {}).items():
        if key.startswith("subnet[") or not key.startswith(("pkt4-", "v4-")):
            continue
        if isinstance(samples, list) and samples and isinstance(samples[0], list) and samples[0]:
            val = samples[0][0]
            if isinstance(val, (int, float)):
                out[key] = int(val)
    return out


def counter_delta(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
    """Non-zero ``after - before`` per counter."""
    return {k: after.get(k, 0) - before.get(k, 0)
            for k in sorted(set(before) | set(after))
            if after.get(k, 0) - before.get(k, 0)}


# ── Verdict ──────────────────────────────────────────────────────────────

def _count(items, key_fn) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        if k:
            counts[k] = counts.get(k, 0) + 1
    return counts


def summarize_client(events: List[Dict[str, Any]],
                     packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Totals for one client across the log window + capture."""
    received = _count([e for e in events if e["kind"] == "received"], lambda e: e.get("type"))
    sent = _count([e for e in events if e["kind"] == "sent"], lambda e: e.get("type"))
    cap_in = _count([p for p in packets if p["op"] == "request"], lambda p: p["type"])
    cap_out = _count([p for p in packets if p["op"] == "reply"], lambda p: p["type"])
    leases = [e["lease"] for e in events if e["kind"] == "allocated" and e.get("lease")]
    relays = sorted({p["giaddr"] for p in packets
                     if p["op"] == "request" and p["giaddr"] != "0.0.0.0"})
    relays += sorted({e["from"].split(":")[0] for e in events
                      if e["kind"] == "received" and e.get("from")
                      and e.get("from") != "0.0.0.0"} - set(relays))
    return {
        "first_seen": events[0]["ts"] if events else "",
        "last_seen": events[-1]["ts"] if events else "",
        "kea_received": received,
        "kea_sent": sent,
        "kea_problems": len([e for e in events if e["kind"] == "problem"]),
        "captured_from_client": cap_in,
        "captured_to_client": cap_out,
        "interfaces": sorted({e["interface"] for e in events if e.get("interface")}
                             | {p["interface"] for p in packets if p["op"] == "request"}),
        "relays_or_sources": relays,
        "last_lease_allocated": leases[-1] if leases else "",
    }


def verdict_for_client(mac: str, events: List[Dict[str, Any]],
                       capture: Dict[str, Any], minutes: int,
                       interfaces_configured: List[str],
                       local_ips: List[str]) -> Dict[str, Any]:
    """Classify where the client's DHCP exchange stops, from THIS node's view.

    Judged on the most recent transaction (the latest Kea transaction id seen
    for the client) so an old successful ACK doesn't mask a current failure.
    """
    packets = capture.get("packets") or []
    last_tid = next((e["tid"] for e in reversed(events)
                     if e["kind"] == "received" and e.get("tid")), "")
    recent = [e for e in events if e.get("tid") == last_tid] if last_tid else []
    rx = {e.get("type") for e in recent if e["kind"] == "received"}
    tx = {e.get("type") for e in recent if e["kind"] == "sent"}
    problems = [e for e in recent if e["kind"] == "problem"]
    allocated = [e.get("lease") for e in recent if e["kind"] == "allocated"]
    cap_in = [p for p in packets if p["op"] == "request" and p["direction"] == "in"]
    servers = ", ".join(local_ips) or "this server"
    findings: List[str] = []

    if "DECLINE" in rx:
        code, msg = "DECLINED", (
            f"Client sent DHCPDECLINE — it detected that the offered address "
            f"is already in use (ARP conflict). Find the device squatting on "
            f"{allocated[-1] if allocated else 'the address'} or exclude it from the pool.")
    elif "ACK" in tx:
        lease = f" lease {allocated[-1]}" if allocated else ""
        code, msg = "ACKED", (
            f"Kea ACKed{lease} — the server side completed. If the client "
            f"still has no address, the ACK is not reaching it (relay return "
            f"path / client-side firewall) or the client rejected it.")
    elif "NAK" in tx:
        code, msg = "NAKED", (
            "Kea sent DHCPNAK — the client asked for an address that is not "
            "valid on the subnet it is now on (moved VLANs, stale lease, or "
            "subnet selection picked a different scope). The client should "
            "restart with DISCOVER; if it keeps NAKing, check which subnet "
            "the relay address/interface maps to.")
    elif "REQUEST" in rx:
        code, msg = "REQUEST_UNANSWERED", (
            "Kea received DHCPREQUEST but sent no ACK/NAK. In HA hot-standby "
            "only the primary answers; otherwise the request may target "
            "another server's offer (server-id) or failed allocation.")
    elif "OFFER" in tx:
        code, msg = "OFFER_NOT_ACCEPTED", (
            "Kea sent DHCPOFFER but the client never followed with "
            "DHCPREQUEST. The offer is likely not reaching the client (relay "
            "not forwarding replies back, ACL/firewall on UDP/68) or the "
            "client accepted another DHCP server's offer.")
    elif "DISCOVER" in rx:
        code, msg = "NO_OFFER", (
            "Kea received DHCPDISCOVER but made no offer. Usual causes: no "
            "configured subnet matches the relay address (giaddr) / receiving "
            "interface, the pool is exhausted, or the client is excluded by a "
            "class/reservation rule.")
    elif rx:
        code, msg = "RECEIVED", (
            f"Kea received {', '.join(sorted(t for t in rx if t))} from the "
            f"client; no DISCOVER/REQUEST in the latest exchange.")
    elif cap_in:
        ifaces = sorted({p["interface"] for p in cap_in})
        code, msg = "NOT_PROCESSED", (
            f"{len(cap_in)} DHCP packet(s) from the client reached this host "
            f"on {', '.join(ifaces)} but Kea logged nothing for them. Check "
            f"that the interface is in Kea's interfaces-config "
            f"({', '.join(interfaces_configured) or 'none configured'}); on "
            f"an HA standby this is expected (only the primary answers).")
    else:
        ran = capture.get("ran")
        code, msg = "NO_REQUEST_SEEN", (
            f"No DHCP packet from {mac} reached this server in the last "
            f"{minutes} min of Kea logs"
            + (f" or during the {capture.get('seconds')}s capture" if ran else "")
            + f". The request is not getting here: check the client is on "
              f"the expected VLAN, that the VLAN's gateway has a DHCP relay / "
              f"ip helper-address pointing at {servers}, and that UDP/67 is "
              f"not filtered between them.")
        if not ran:
            findings.append("Re-run with a capture window while the client "
                            "retries to confirm at packet level.")

    for e in problems[-5:]:
        findings.append(f"Kea {e['level']} {e['msg_id']}: {e['text'][:300]}")
    relays = sorted({p["giaddr"] for p in cap_in if p["giaddr"] != "0.0.0.0"})
    if relays:
        findings.append("Request(s) arrived via relay " + ", ".join(relays)
                        + " — Kea selects the subnet containing that address.")
    if cap_in and any(p.get("server_id") and p["server_id"] not in local_ips
                      for p in cap_in if p["type"] == "REQUEST"):
        other = sorted({p["server_id"] for p in cap_in
                        if p.get("server_id") and p["server_id"] not in local_ips})
        findings.append("Client is REQUESTing an offer from another DHCP "
                        "server (server-id " + ", ".join(other)
                        + ") — a rogue/second DHCP server is answering.")
    return {"code": code, "message": msg, "findings": findings,
            "latest_transaction": last_tid}


def summarize_all_clients(events: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    """Per-MAC rollup for a no-MAC trace (most recently active first)."""
    by_mac: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        by_mac.setdefault(e["mac"], []).append(e)
    rows = []
    for mac, evs in by_mac.items():
        rx = _count([e for e in evs if e["kind"] == "received"], lambda e: e.get("type"))
        tx = _count([e for e in evs if e["kind"] == "sent"], lambda e: e.get("type"))
        leases = [e["lease"] for e in evs if e["kind"] == "allocated" and e.get("lease")]
        rows.append({"mac": mac, "last_seen": evs[-1]["ts"], "received": rx,
                     "sent": tx, "last_lease": leases[-1] if leases else "",
                     "problems": len([e for e in evs if e["kind"] == "problem"])})
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return rows[:limit]


def local_ipv4s() -> List[str]:
    """Non-loopback IPv4 addresses on this host (for relay/ip-helper hints)."""
    res = _run(["ip", "-4", "-o", "addr", "show"], timeout=5)
    ips = []
    for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", res["stdout"]):
        try:
            if not ipaddress.ip_address(m.group(1)).is_loopback:
                ips.append(m.group(1))
        except ValueError:
            continue
    return ips
