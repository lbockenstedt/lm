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

# ipaddress filters loopback addresses out of the host's IP list.
import ipaddress
# Standard-library logging (logger defined below).
import logging
# re parses Kea log lines and command output.
import re
# select waits for captured packets with a timeout.
import select
# socket opens the raw capture socket and formats IPv4 addresses.
import socket
# struct unpacks binary Ethernet/IP/UDP/DHCP header fields.
import struct
# subprocess runs journalctl and ip.
import subprocess
# time computes log windows and capture deadlines.
import time
# Type hints only; they document the shapes of events and results.
from typing import Any, Dict, List, Optional

# One named logger so all packet-trace messages can be filtered together.
logger = logging.getLogger("KeaPacketTrace")

# Safety caps: longest capture (60 s), longest log lookback (1 day), most events and
# packets returned, and the most journal output kept in memory (4 MiB).
MAX_CAPTURE_SECONDS = 60
MAX_LOOKBACK_MINUTES = 24 * 60
MAX_EVENTS = 200
MAX_PACKETS = 200
_JOURNAL_OUTPUT_CAP = 4 * 1024 * 1024

# DHCP option 53 message-type numbers mapped to readable names.
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

# Kea message-id prefixes that relate to DHCP processing; anything else is skipped.
_RELEVANT_PREFIXES = ("DHCP4_", "ALLOC_ENGINE_", "DHCPSRV_", "HA_", "HOSTS_")
# Message ids that are pure noise (control-channel chatter) and always ignored.
_NOISE_IDS = {"COMMAND_RECEIVED"}
# Matches the level, message id and free text of a Kea log line.
_LINE_RE = re.compile(
    r"(?P<level>FATAL|ERROR|WARN|INFO|DEBUG)\s+(?P<msgid>[A-Z][A-Z0-9_]{3,})\s*(?P<text>.*)$")
# Extract the client MAC, transaction id, DHCP message type, receive path and leased
# IP from a log line's text.
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
    # Empty/None input means "no MAC filter".
    if mac is None or not str(mac).strip():
        return ""
    # Keep only hex digits, lower-cased.
    clean = re.sub(r"[^0-9a-fA-F]", "", str(mac)).lower()
    # Must be exactly 12 hex digits, and the original may contain only hex digits and
    # common separators (colon, dot, dash, space).
    if len(clean) != 12 or len(re.sub(r"[0-9a-fA-F:.\-\s]", "", str(mac))):
        raise ValueError(f"invalid MAC address: {mac!r}")
    # Rebuild in the canonical colon-separated form.
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    """Parse ``value`` as an int clamped to ``[lo, hi]`` (``default`` if unparsable)."""
    # Accept "5", 5, or "5.0"; anything unparsable uses the default.
    try:
        n = int(float(value))
    # Not a number at all: fall back to the default.
    except (TypeError, ValueError):
        n = default
    # Clamp into the allowed range.
    return max(lo, min(hi, n))


# ── Kea log (journal) ────────────────────────────────────────────────────

def parse_kea_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse one Kea log line into an event dict, or None if not DHCP-relevant."""
    # Find the level/message-id portion; lines without one are not Kea log entries.
    m = _LINE_RE.search(line or "")
    if not m:
        return None
    # Pull out the message id and severity.
    msgid = m.group("msgid")
    level = m.group("level")
    # Skip known-noise messages.
    if msgid in _NOISE_IDS:
        return None
    # Keep DHCP-related ids, plus any warning/error regardless of id.
    if not msgid.startswith(_RELEVANT_PREFIXES) and level not in ("WARN", "ERROR", "FATAL"):
        return None
    # The free text after the message id, and the journal prefix before it (timestamp).
    text = m.group("text").strip()
    head = line[:m.start()].strip()
    # Base event: timestamp (first word of the prefix), level, id, and text capped at 500 chars.
    event: Dict[str, Any] = {
        "ts": head.split()[0] if head else "",
        "level": level,
        "msg_id": msgid,
        "text": text[:500],
    }
    # Add each optional field only when the text contains it.
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
    # Classify the event by message id so later code can count packets in vs out.
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
    """Run a command and return ok/rc/stdout/stderr without ever raising.

    Args:
        cmd: Command and arguments.
        timeout: Seconds before the command is killed.

    Returns:
        Dict with ok, rc, stdout (tail-capped) and stderr (first 500 chars).
    """
    # Run the command, capturing text output; bad bytes are replaced rather than raising.
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, errors="replace")
        # Keep only the tail of stdout (newest journal lines) and a short stderr.
        return {"ok": result.returncode == 0, "rc": result.returncode,
                "stdout": (result.stdout or "")[-_JOURNAL_OUTPUT_CAP:],
                "stderr": (result.stderr or "").strip()[:500]}
    # Command missing or timed out: report it as a failure with the error text.
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "rc": None, "stdout": "", "stderr": str(e)}


def read_kea_journal(minutes: int, mac: str = "",
                     unit: str = "kea-dhcp4-server") -> Dict[str, Any]:
    """Return ``{events, problems, error, source}`` from Kea's journal.

    ``events`` = this client's packet events (or every client's if no MAC);
    ``problems`` = server-wide warnings/errors/drops in the same window.
    """
    # journalctl --since wants local time; compute the start of the window.
    since = time.strftime("%Y-%m-%d %H:%M:%S",
                          time.localtime(time.time() - minutes * 60))
    # Base journalctl command for the Kea unit, in ISO timestamp format, no pager.
    base = ["journalctl", "-u", unit, "--since", since,
            "--no-pager", "-o", "short-iso"]
    # Error text to report (empty if journalctl worked).
    error = ""
    # With a MAC, let journalctl filter lines for us (case-insensitive).
    if mac:
        res = _run(base + ["--grep", mac, "--case-sensitive=false"], timeout=20)
        # rc 1 just means "no matches", so only other failures trigger the fallback.
        if not res["ok"] and res["rc"] != 1:
            # Older journalctl without PCRE2 support rejects --grep — filter here.
            res = _run(base, timeout=30)
            lines = [ln for ln in res["stdout"].splitlines() if mac in ln.lower()]
        # grep worked (or found nothing): use its output.
        else:
            lines = res["stdout"].splitlines()
    # No MAC: take the last 5000 lines for every client.
    else:
        res = _run(base + ["-n", "5000"], timeout=30)
        lines = res["stdout"].splitlines()
    # Any rc other than 0/1 is a real journalctl failure; report it.
    if res["rc"] not in (0, 1):
        error = res["stderr"] or "journalctl failed"
    # Parse every line, dropping those that are not relevant.
    events = [e for e in (parse_kea_log_line(ln) for ln in lines) if e]
    # With a MAC, keep this client's events (and events without a MAC); otherwise keep
    # only events that name a client.
    if mac:
        events = [e for e in events if e.get("mac", mac) == mac]
    else:
        events = [e for e in events if e.get("mac")]

    # Separately read the last 300 warning-or-worse lines as server-wide problems.
    prob = _run(base + ["-p", "warning", "-n", "300"], timeout=20)
    problems = [e for e in (parse_kea_log_line(ln) for ln in prob["stdout"].splitlines())
                if e and e["kind"] in ("problem", "info")]
    # Return the events plus the 50 most recent problems.
    return {"events": events, "problems": problems[-50:], "error": error}


# ── Raw capture ──────────────────────────────────────────────────────────

def parse_dhcp_frame(data: bytes, hatype: int = 1) -> Optional[Dict[str, Any]]:
    """Decode an Ethernet (or raw-IP) frame carrying a DHCPv4/BOOTP packet."""
    # Byte offset where the IP header starts (0 for raw-IP interfaces).
    off = 0
    if hatype in (1, 772):  # ARPHRD_ETHER / ARPHRD_LOOPBACK
        # Ethernet header is 14 bytes; shorter frames cannot be valid.
        if len(data) < 14:
            return None
        # Read the EtherType and move past the Ethernet header.
        ethertype = struct.unpack("!H", data[12:14])[0]
        off = 14
        # Skip any VLAN tags (802.1Q / 802.1ad) to find the real EtherType.
        while ethertype in (0x8100, 0x88A8) and len(data) >= off + 4:
            ethertype = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        # Only IPv4 frames can carry DHCPv4.
        if ethertype != 0x0800:
            return None
    # Need a full IPv4 header with version 4.
    if len(data) < off + 20 or data[off] >> 4 != 4:
        return None
    # IP header length in bytes (IHL is in 32-bit words).
    ihl = (data[off] & 0x0F) * 4
    # Protocol 17 is UDP; ignore anything else.
    if data[off + 9] != 17:
        return None
    # Only the first fragment has the UDP header, so skip later fragments.
    if struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF:
        return None  # non-first fragment
    # Source and destination IPv4 addresses.
    src = socket.inet_ntoa(data[off + 12:off + 16])
    dst = socket.inet_ntoa(data[off + 16:off + 20])
    # Byte offset where the UDP header starts; it must be complete (8 bytes).
    u = off + ihl
    if len(data) < u + 8:
        return None
    # Read UDP ports; DHCP uses 67 (server) and 68 (client).
    sport, dport = struct.unpack("!HH", data[u:u + 4])
    if not ({sport, dport} & {67, 68}):
        return None
    # Byte offset of the BOOTP/DHCP payload; its fixed part is 240 bytes incl. magic cookie.
    b = u + 8
    if len(data) < b + 240:
        return None
    # Fixed BOOTP fields: op code, hardware address length, transaction id and the four
    # IP address fields (client, your, server, relay).
    op, _htype, hlen = data[b], data[b + 1], data[b + 2]
    xid = struct.unpack("!I", data[b + 4:b + 8])[0]
    ciaddr, yiaddr, siaddr, giaddr = (socket.inet_ntoa(data[b + i:b + i + 4])
                                      for i in (12, 16, 20, 24))
    # Hardware address length (default 6, max 16) and the client MAC built from it.
    hlen = min(hlen or 6, 16)
    chaddr = ":".join(f"{x:02x}" for x in data[b + 28:b + 28 + hlen])
    # Base packet description; type stays "BOOTP" unless a DHCP message-type option is found.
    pkt: Dict[str, Any] = {
        "src": f"{src}:{sport}", "dst": f"{dst}:{dport}",
        "op": "request" if op == 1 else "reply",
        "xid": f"0x{xid:08x}", "chaddr": chaddr,
        "ciaddr": ciaddr, "yiaddr": yiaddr, "siaddr": siaddr, "giaddr": giaddr,
        "type": "BOOTP",
    }
    # The DHCP magic cookie means DHCP options follow; walk them.
    if data[b + 236:b + 240] == b"\x63\x82\x53\x63":
        i = b + 240
        # Walk each option until the end option or the end of the data.
        while i < len(data):
            code = data[i]
            # Option 255 marks the end of the options.
            if code == 255:
                break
            # Option 0 is a single padding byte.
            if code == 0:
                i += 1
                continue
            # Truncated option (no length byte): stop.
            if i + 1 >= len(data):
                break
            # Option length and value bytes.
            ln = data[i + 1]
            val = data[i + 2:i + 2 + ln]
            # Pick out the options useful for troubleshooting: message type (53), requested IP
            # (50), server id (54), hostname (12) and relay agent info (82).
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
            # Skip the code and length bytes plus the value.
            i += 2 + ln
    return pkt


def capture_dhcp(seconds: int, mac: str = "",
                 max_packets: int = MAX_PACKETS) -> Dict[str, Any]:
    """Sniff UDP/67-68 on every interface for ``seconds`` (needs root/CAP_NET_RAW)."""
    # Result skeleton; "ran" stays False unless the capture actually starts.
    out: Dict[str, Any] = {"ran": False, "seconds": seconds, "packets": [],
                           "truncated": False, "error": ""}
    # A zero-length window means no capture was requested.
    if seconds <= 0:
        return out
    # AF_PACKET raw sockets exist only on Linux.
    if not hasattr(socket, "AF_PACKET"):
        out["error"] = "raw packet capture is only supported on Linux"
        return out
    # Open a raw socket receiving every protocol (ETH_P_ALL = 0x0003) on every interface.
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    # Not root / missing CAP_NET_RAW: explain instead of crashing.
    except (PermissionError, OSError) as e:
        out["error"] = f"cannot open raw socket (needs root/CAP_NET_RAW): {e}"
        return out
    # Mark the capture as started and set its end time.
    out["ran"] = True
    deadline = time.monotonic() + seconds
    start = time.time()
    # Always close the socket, even if parsing fails mid-capture.
    try:
        # Read packets until the window ends.
        while True:
            # Stop when the deadline passes.
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # Wait at most 1 s for a packet so the deadline is checked regularly.
            ready, _, _ = select.select([sock], [], [], min(remaining, 1.0))
            if not ready:
                continue
            # Read one frame plus its link-layer address info.
            data, addr = sock.recvfrom(65535)
            # addr = (ifname, proto, pkttype, hatype, hwaddr); 4 = PACKET_OUTGOING
            # Decode it (hatype tells us Ethernet vs raw IP); skip non-DHCP or other clients'
            # packets.
            pkt = parse_dhcp_frame(data, addr[3] if len(addr) > 3 else 1)
            if not pkt or (mac and pkt["chaddr"] != mac):
                continue
            # Annotate with offset from capture start, interface, and direction.
            pkt["t"] = round(time.time() - start, 3)
            pkt["interface"] = addr[0]
            pkt["direction"] = "out" if len(addr) > 2 and addr[2] == 4 else "in"
            # Stop once the packet cap is reached and flag the result as truncated.
            if len(out["packets"]) >= max_packets:
                out["truncated"] = True
                break
            # Keep the packet.
            out["packets"].append(pkt)
    # Unexpected socket error: report it with whatever was captured so far.
    except Exception as e:  # noqa: BLE001
        out["error"] = f"capture failed: {e}"
    # Release the raw socket.
    finally:
        sock.close()
    return out


# ── Counters ─────────────────────────────────────────────────────────────

def packet_counters(raw_stats: Dict[str, Any]) -> Dict[str, int]:
    """Latest value of every global ``pkt4-*`` / ``v4-*`` Kea counter."""
    # Collect the latest value of each global v4 counter.
    out = {}
    # Walk every statistic; skip per-subnet entries and non-v4 packet counters.
    for key, samples in (raw_stats or {}).items():
        if key.startswith("subnet[") or not key.startswith(("pkt4-", "v4-")):
            continue
        # Kea returns [[value, timestamp], ...] newest first; take the newest numeric value.
        if isinstance(samples, list) and samples and isinstance(samples[0], list) and samples[0]:
            val = samples[0][0]
            if isinstance(val, (int, float)):
                out[key] = int(val)
    return out


def counter_delta(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
    """Non-zero ``after - before`` per counter."""
    # Only counters that changed, in name order.
    return {k: after.get(k, 0) - before.get(k, 0)
            for k in sorted(set(before) | set(after))
            if after.get(k, 0) - before.get(k, 0)}


# ── Verdict ──────────────────────────────────────────────────────────────

def _count(items, key_fn) -> Dict[str, int]:
    """Count items by key_fn(item), ignoring items whose key is empty.

    Args:
        items: Things to count.
        key_fn: Returns the grouping key for an item.

    Returns:
        Mapping of key to count.
    """
    # Tally each item under its key, skipping falsy keys.
    counts: Dict[str, int] = {}
    for item in items:
        k = key_fn(item)
        if k:
            counts[k] = counts.get(k, 0) + 1
    return counts


def summarize_client(events: List[Dict[str, Any]],
                     packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Totals for one client across the log window + capture."""
    # Count Kea-logged received and sent packets, by DHCP type.
    received = _count([e for e in events if e["kind"] == "received"], lambda e: e.get("type"))
    sent = _count([e for e in events if e["kind"] == "sent"], lambda e: e.get("type"))
    # Count captured requests from and replies to the client, by DHCP type.
    cap_in = _count([p for p in packets if p["op"] == "request"], lambda p: p["type"])
    cap_out = _count([p for p in packets if p["op"] == "reply"], lambda p: p["type"])
    # Every lease Kea allocated to this client.
    leases = [e["lease"] for e in events if e["kind"] == "allocated" and e.get("lease")]
    # Relay (giaddr) addresses seen in captured requests, then any extra source addresses
    # from Kea's log.
    relays = sorted({p["giaddr"] for p in packets
                     if p["op"] == "request" and p["giaddr"] != "0.0.0.0"})
    relays += sorted({e["from"].split(":")[0] for e in events
                      if e["kind"] == "received" and e.get("from")
                      and e.get("from") != "0.0.0.0"} - set(relays))
    # Bundle everything into one summary for the UI.
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
    # Captured packets for this client.
    packets = capture.get("packets") or []
    # Find the latest transaction id Kea received, and keep only that exchange's events.
    last_tid = next((e["tid"] for e in reversed(events)
                     if e["kind"] == "received" and e.get("tid")), "")
    recent = [e for e in events if e.get("tid") == last_tid] if last_tid else []
    # Which DHCP types were received and sent in that exchange, plus problems and leases.
    rx = {e.get("type") for e in recent if e["kind"] == "received"}
    tx = {e.get("type") for e in recent if e["kind"] == "sent"}
    problems = [e for e in recent if e["kind"] == "problem"]
    allocated = [e.get("lease") for e in recent if e["kind"] == "allocated"]
    # Captured packets that came in from the client.
    cap_in = [p for p in packets if p["op"] == "request" and p["direction"] == "in"]
    # This server's IPs for use in advice text, and extra findings to attach.
    servers = ", ".join(local_ips) or "this server"
    findings: List[str] = []

    # Walk the outcomes from most to least advanced; the first match is the verdict.
    # Client declined the address: an IP conflict.
    if "DECLINE" in rx:
        code, msg = "DECLINED", (
            f"Client sent DHCPDECLINE — it detected that the offered address "
            f"is already in use (ARP conflict). Either another device holds "
            f"{allocated[-1] if allocated else 'the address'} (exclude it from the pool), "
            f"or the client already had it up and answered its own probe "
            f"(give it a reservation for that address).")
    # Kea ACKed: the server side finished.
    elif "ACK" in tx:
        lease = f" lease {allocated[-1]}" if allocated else ""
        code, msg = "ACKED", (
            f"Kea ACKed{lease} — the server side completed. If the client "
            f"still has no address, the ACK is not reaching it (relay return "
            f"path / client-side firewall) or the client rejected it.")
    # Kea NAKed: the client asked for an address not valid on its subnet.
    elif "NAK" in tx:
        code, msg = "NAKED", (
            "Kea sent DHCPNAK — the client asked for an address that is not "
            "valid on the subnet it is now on (moved VLANs, stale lease, or "
            "subnet selection picked a different scope). The client should "
            "restart with DISCOVER; if it keeps NAKing, check which subnet "
            "the relay address/interface maps to.")
    # INIT-REBOOT request (client wants to keep an old address) with no answer.
    elif "REQUEST" in rx and any(e.get("msg_id") == "DHCP4_INIT_REBOOT" for e in recent):
        # Extract which address the client asked to keep from the log text.
        asked = next((m.group(1) for e in reversed(recent)
                      if e.get("msg_id") == "DHCP4_INIT_REBOOT"
                      for m in [re.search(r"requests address (\S+)", e.get("text", ""))]
                      if m), "its previous address")
        code, msg = "INIT_REBOOT_IGNORED", (
            f"Client is in INIT-REBOOT asking to keep {asked} and Kea sent no "
            f"ACK/NAK. A non-authoritative Kea silently drops this when it has "
            f"no lease for the client (typically the device moved VLANs and "
            f"still holds an address from the old subnet), so the client keeps "
            f"retrying until that lease expires. LM keeps Kea non-authoritative "
            f"(NAKing makes devices that already hold their address decline "
            f"it); release/renew on the client or give it a reservation.")
    # Plain REQUEST with no ACK/NAK.
    elif "REQUEST" in rx:
        code, msg = "REQUEST_UNANSWERED", (
            "Kea received DHCPREQUEST but sent no ACK/NAK. In HA hot-standby "
            "only the primary answers; otherwise the request may target "
            "another server's offer (server-id) or failed allocation.")
    # OFFER sent but the client never REQUESTed it.
    elif "OFFER" in tx:
        code, msg = "OFFER_NOT_ACCEPTED", (
            "Kea sent DHCPOFFER but the client never followed with "
            "DHCPREQUEST. The offer is likely not reaching the client (relay "
            "not forwarding replies back, ACL/firewall on UDP/68) or the "
            "client accepted another DHCP server's offer.")
    # DISCOVER received but no OFFER made.
    elif "DISCOVER" in rx:
        code, msg = "NO_OFFER", (
            "Kea received DHCPDISCOVER but made no offer. Usual causes: no "
            "configured subnet matches the relay address (giaddr) / receiving "
            "interface, the pool is exhausted, or the client is excluded by a "
            "class/reservation rule.")
    # Kea saw other packet types but no DISCOVER/REQUEST.
    elif rx:
        code, msg = "RECEIVED", (
            f"Kea received {', '.join(sorted(t for t in rx if t))} from the "
            f"client; no DISCOVER/REQUEST in the latest exchange.")
    # Packets reached the host but Kea never logged them.
    elif cap_in:
        ifaces = sorted({p["interface"] for p in cap_in})
        code, msg = "NOT_PROCESSED", (
            f"{len(cap_in)} DHCP packet(s) from the client reached this host "
            f"on {', '.join(ifaces)} but Kea logged nothing for them. Check "
            f"that the interface is in Kea's interfaces-config "
            f"({', '.join(interfaces_configured) or 'none configured'}); on "
            f"an HA standby this is expected (only the primary answers).")
    # Nothing seen at all: the request is not reaching this server.
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
        # Without a capture we only have the log; suggest capturing to be sure.
        if not ran:
            findings.append("Re-run with a capture window while the client "
                            "retries to confirm at packet level.")

    # Attach the last 5 problem log entries.
    for e in problems[-5:]:
        findings.append(f"Kea {e['level']} {e['msg_id']}: {e['text'][:300]}")
    # Mention relays so the operator knows which subnet Kea will pick.
    relays = sorted({p["giaddr"] for p in cap_in if p["giaddr"] != "0.0.0.0"})
    if relays:
        findings.append("Request(s) arrived via relay " + ", ".join(relays)
                        + " — Kea selects the subnet containing that address.")
    # A REQUEST naming another server's id means a second DHCP server is answering.
    if cap_in and any(p.get("server_id") and p["server_id"] not in local_ips
                      for p in cap_in if p["type"] == "REQUEST"):
        other = sorted({p["server_id"] for p in cap_in
                        if p.get("server_id") and p["server_id"] not in local_ips})
        findings.append("Client is REQUESTing an offer from another DHCP "
                        "server (server-id " + ", ".join(other)
                        + ") — a rogue/second DHCP server is answering.")
    # Return the verdict code, explanation, extra findings and the transaction judged.
    return {"code": code, "message": msg, "findings": findings,
            "latest_transaction": last_tid}


def summarize_all_clients(events: List[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    """Per-MAC rollup for a no-MAC trace (most recently active first)."""
    # Group events by client MAC.
    by_mac: Dict[str, List[Dict[str, Any]]] = {}
    for e in events:
        by_mac.setdefault(e["mac"], []).append(e)
    # Build one summary row per client.
    rows = []
    for mac, evs in by_mac.items():
        # Count received/sent packet types and find the latest lease.
        rx = _count([e for e in evs if e["kind"] == "received"], lambda e: e.get("type"))
        tx = _count([e for e in evs if e["kind"] == "sent"], lambda e: e.get("type"))
        leases = [e["lease"] for e in evs if e["kind"] == "allocated" and e.get("lease")]
        # Add the client's row.
        rows.append({"mac": mac, "last_seen": evs[-1]["ts"], "received": rx,
                     "sent": tx, "last_lease": leases[-1] if leases else "",
                     "problems": len([e for e in evs if e["kind"] == "problem"])})
    # Newest activity first, capped at limit rows.
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return rows[:limit]


def local_ipv4s() -> List[str]:
    """Non-loopback IPv4 addresses on this host (for relay/ip-helper hints)."""
    # List IPv4 addresses with "ip -o" (one line per address).
    res = _run(["ip", "-4", "-o", "addr", "show"], timeout=5)
    # Collect each address that is not loopback.
    ips = []
    for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/", res["stdout"]):
        try:
            if not ipaddress.ip_address(m.group(1)).is_loopback:
                ips.append(m.group(1))
        # Unparsable address: skip it.
        except ValueError:
            continue
    return ips
