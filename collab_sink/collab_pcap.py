#!/usr/bin/env python3
"""collab_pcap.py — stdlib pcap/pcapng reader + direction splitter for the
collaboration-app traffic simulation.

A single capture of a REAL Teams/Zoom/WebEx session holds both halves of the
conversation. This module extracts the UDP datagrams and splits them into the
two one-way streams the collab sim needs:

  * client -> server  — what the simulation CLIENT (cs collab.py) replays at the
    hub sink, so a DPI/AppRF classifier sees genuine STUN/RTP/SRTP bytes on the
    real media ports instead of random filler.
  * server -> client  — what the hub COLLAB MODULE (collab_sink/sink.py) sends
    back, so the flow is bidirectional and looks like a live call. The sink
    "knows what to respond with" because the response payloads come straight
    out of the same uploaded pcap.

Design constraints (match sink.py / collab.py): stdlib only, no venv, runs on
system python3, no root. Supports classic pcap (both byte orders, us/ns) and
pcapng (SHB/IDB/EPB/SPB). Decodes IPv4/UDP over Ethernet (incl. 802.1Q),
raw-IP, Linux SLL, and NULL/LOOP link types; anything else is skipped.

NOTE: this file is kept BYTE-IDENTICAL with cs/clients/linux/collab_pcap.py
(hub sink + client sender share one parser). Edit one, copy to the other.
"""
# Postpone evaluation of type hints so annotations stay plain strings at runtime.
from __future__ import annotations

# struct unpacks the binary pcap/IP/UDP headers and packs the synthetic capture.
import struct
# namedtuple gives each decoded packet readable field names at tuple cost.
from collections import namedtuple
# Type hints only; they document the shapes of values passed around.
from typing import Dict, List, Optional, Sequence, Tuple

# Canonical media ports used by the sim (mirror COLLAB_APP_PORTS / APP_PROFILES).
# Used only to disambiguate which capture endpoint is the "server" side.
DEFAULT_MEDIA_PORTS = frozenset(
    {3478, 3481, 3479, 8801, 8802, 8803, 9000, 5004, 5006}
)

# Link-layer types (libpcap DLT_*). These numeric ids sit in the capture header
# and say how each frame is wrapped before the IP packet starts:
# NULL/LOOP = BSD loopback (4-byte family prefix), EN10MB = Ethernet,
# RAW / RAW_ALT1 / RAW_ALT2 / IPV4 = bare IP with no link header (ids vary by OS),
# LINUX_SLL = Linux "cooked" capture (16-byte pseudo header).
_DLT_NULL = 0
_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LOOP = 108
_DLT_LINUX_SLL = 113
_DLT_RAW_ALT1 = 12
_DLT_RAW_ALT2 = 14
_DLT_IPV4 = 228

# One decoded UDP datagram: capture timestamp (seconds), both endpoints, and the
# UDP payload bytes.
Packet = namedtuple("Packet", "ts src_ip src_port dst_ip dst_port payload")


class PcapError(Exception):
    """Raised when a capture can't be parsed as pcap/pcapng."""


# ── link/IP/UDP decode ───────────────────────────────────────────────────────

def _decode_ipv4_udp(ip: bytes) -> Optional[Tuple[str, int, str, int, bytes]]:
    """(src_ip, src_port, dst_ip, dst_port, payload) for an IPv4/UDP packet,
    else None. ``ip`` starts at the IPv4 header."""
    # Reject anything shorter than a minimal IPv4 header or whose version
    # nibble (top 4 bits of byte 0) is not 4.
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    # Header length lives in the low nibble, counted in 4-byte words.
    ihl = (ip[0] & 0x0F) * 4
    # Bogus header length, or too short to also hold the 8-byte UDP header.
    if ihl < 20 or len(ip) < ihl + 8:
        return None
    # Byte 9 is the protocol number; 17 means UDP, everything else is skipped.
    if ip[9] != 17:  # not UDP
        return None
    # Bytes 12-15 / 16-19 are the source / destination addresses; render dotted-quad.
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    # The UDP header starts right after the (possibly option-extended) IP header.
    udp = ip[ihl:]
    # UDP header: source port, destination port, length (big-endian 16-bit each).
    src_port, dst_port, ulen = struct.unpack_from(">HHH", udp, 0)
    # Everything after the 8-byte UDP header is the application payload.
    payload = udp[8:]
    # Trust the UDP length field when it's sane (trailing capture padding, FCS).
    body = ulen - 8
    # Only trim when the declared length fits inside what was captured.
    if 0 <= body <= len(payload):
        payload = payload[:body]
    return src_ip, src_port, dst_ip, dst_port, payload


def _link_to_ipv4(linktype: int, frame: bytes) -> Optional[bytes]:
    """Strip the link layer, returning the IPv4 packet bytes (or None)."""
    # Ethernet: 14-byte header (dst MAC, src MAC, EtherType).
    if linktype == _DLT_EN10MB:
        # Truncated frame: not even a full Ethernet header.
        if len(frame) < 14:
            return None
        # EtherType at offset 12 says what follows the header.
        etype = struct.unpack_from(">H", frame, 12)[0]
        # Payload starts right after the basic Ethernet header.
        off = 14
        # 802.1Q / QinQ VLAN tags.
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        # 0x0800 is IPv4; IPv6, ARP, etc. are not decoded.
        return frame[off:] if etype == 0x0800 else None
    # Raw-IP link types: the frame already IS the IP packet.
    if linktype in (_DLT_RAW, _DLT_RAW_ALT1, _DLT_RAW_ALT2, _DLT_IPV4):
        return frame
    # BSD loopback: skip the 4-byte address-family prefix.
    if linktype in (_DLT_NULL, _DLT_LOOP):
        if len(frame) < 4:
            return None
        return frame[4:]
    # Linux cooked capture: 16-byte pseudo header whose protocol field is at offset 14.
    if linktype == _DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        return frame[16:] if struct.unpack_from(">H", frame, 14)[0] == 0x0800 else None
    # Unsupported link type: skip the frame.
    return None


# ── classic pcap ─────────────────────────────────────────────────────────────

def _parse_classic(data: bytes) -> List[Tuple[float, int, bytes]]:
    """Parse a classic libpcap file into (timestamp, linktype, frame) records.

    Raises PcapError if the magic number is not a classic pcap one.
    """
    # The 4-byte magic number reveals byte order and timestamp precision.
    magic = data[:4]
    # Big-endian file; the a1b23c4d variant stores nanosecond timestamps.
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nsec = ">", magic == b"\xa1\xb2\x3c\x4d"
    # Little-endian file (byte-swapped magic); same microsecond/nanosecond split.
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nsec = "<", magic == b"\x4d\x3c\xb2\xa1"
    # Any other magic means this is not a classic pcap at all.
    else:
        raise PcapError("not a classic pcap")
    # The global header's last field (offset 20) is the link type for every packet.
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    out: List[Tuple[float, int, bytes]] = []
    # Records start after the 24-byte global header.
    off, n = 24, len(data)
    # Per-record header: seconds, sub-second fraction, captured length, original length.
    rec = struct.Struct(endian + "IIII")
    # Walk records while a full 16-byte record header remains.
    while off + 16 <= n:
        ts_sec, ts_frac, incl, _orig = rec.unpack_from(data, off)
        off += 16
        # A truncated final record (file cut mid-write) ends parsing cleanly.
        if off + incl > n:
            break
        # Slice out the captured frame bytes and advance past them.
        frame = data[off:off + incl]
        off += incl
        # Combine seconds + fraction using the precision the magic number declared.
        ts = ts_sec + (ts_frac / 1e9 if nsec else ts_frac / 1e6)
        out.append((ts, linktype, frame))
    return out


# ── pcapng ───────────────────────────────────────────────────────────────────

def _parse_pcapng(data: bytes) -> List[Tuple[float, int, bytes]]:
    """Parse a pcapng file into (timestamp, linktype, frame) records.

    Handles Interface Description, Enhanced Packet and Simple Packet blocks;
    other block types are skipped. Raises PcapError if not a pcapng file.
    """
    # Every pcapng file starts with the Section Header Block type 0x0A0D0D0A.
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PcapError("not a pcapng")
    # Byte order + first-IDB tsresol come from the section header block.
    # The byte-order magic reads as 0x1A2B3C4D only when decoded in the file's order.
    bom = struct.unpack_from("<I", data, 8)[0]
    endian = "<" if bom == 0x1A2B3C4D else ">"
    out: List[Tuple[float, int, bytes]] = []
    # Per-interface link type and timestamp resolution, indexed by interface id.
    if_linktypes: List[int] = []
    if_tsresol: List[float] = []
    off, n = 0, len(data)
    # Walk blocks while at least a minimal 12-byte block (type, len, trailing len) fits.
    while off + 12 <= n:
        # Each block begins with its type and total length.
        btype, blen = struct.unpack_from(endian + "II", data, off)
        # Corrupt length or truncated block: stop rather than read garbage.
        if blen < 12 or off + blen > n:
            break
        # Block body sits between the 8-byte header and the 4-byte trailing length.
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            # Default resolution is microseconds unless an if_tsresol option says otherwise.
            tsresol = 1e-6
            # Options follow snaplen (body: linktype(2) resv(2) snaplen(4) opts).
            opos = 8
            # Scan the option list (code, length, value) for the timestamp resolution.
            while opos + 4 <= len(body):
                ocode, olen = struct.unpack_from(endian + "HH", body, opos)
                opos += 4
                # Option code 0 is opt_endofopt: no more options.
                if ocode == 0:
                    break
                if ocode == 9 and olen >= 1:  # if_tsresol
                    raw = body[opos]
                    # High bit set = power-of-2 resolution, clear = power-of-10;
                    # the low 7 bits are the (negative) exponent.
                    tsresol = (1.0 / (2 ** (raw & 0x7F))) if (raw & 0x80) \
                        else (10.0 ** -(raw & 0x7F))
                # Skip the option value, which is padded to a 4-byte boundary.
                opos += olen + ((4 - olen % 4) % 4)
            # Register this interface; its index is the id later packet blocks refer to.
            if_linktypes.append(linktype)
            if_tsresol.append(tsresol)
        elif btype == 0x00000006:  # Enhanced Packet Block
            # Interface id, 64-bit timestamp (high/low), captured and original length.
            ifid, tsh, tsl, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            frame = body[20:20 + cap]
            # Look up the interface's settings; fall back to usec/Ethernet if unknown.
            res = if_tsresol[ifid] if ifid < len(if_tsresol) else 1e-6
            lt = if_linktypes[ifid] if ifid < len(if_linktypes) else _DLT_EN10MB
            # Rebuild the 64-bit tick count and scale it to seconds.
            ts = ((tsh << 32) | tsl) * res
            out.append((ts, lt, frame))
        elif btype == 0x00000003:  # Simple Packet Block (no ts, uses IDB 0)
            # Original length is read but unused; the frame is the rest of the body.
            _orig = struct.unpack_from(endian + "I", body, 0)[0]
            frame = body[4:]
            lt = if_linktypes[0] if if_linktypes else _DLT_EN10MB
            out.append((0.0, lt, frame))
        # Advance to the next block (other block types are simply skipped).
        off += blen
    return out


# ── public API ───────────────────────────────────────────────────────────────

def parse_udp_packets(path: str) -> List[Packet]:
    """Read ``path`` and return its IPv4/UDP datagrams in capture order."""
    # Load the whole capture; uploaded call captures are small enough for memory.
    with open(path, "rb") as fh:
        data = fh.read()
    # 24 bytes is the classic pcap global header; anything smaller cannot be a capture.
    if len(data) < 24:
        raise PcapError("file too small to be a capture")
    # Pick the parser from the leading magic: pcapng SHB, else try classic pcap.
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raw = _parse_pcapng(data)
    else:
        raw = _parse_classic(data)
    packets: List[Packet] = []
    # Decode each frame down to UDP, dropping anything that is not IPv4/UDP.
    for ts, linktype, frame in raw:
        ip = _link_to_ipv4(linktype, frame)
        # Unsupported link type or non-IPv4 frame.
        if ip is None:
            continue
        dec = _decode_ipv4_udp(ip)
        # Not UDP, or a malformed header.
        if dec is None:
            continue
        s_ip, s_port, d_ip, d_port, payload = dec
        packets.append(Packet(ts, s_ip, s_port, d_ip, d_port, payload))
    return packets


def _pick_server(packets: Sequence[Packet],
                 media_ports: frozenset) -> Optional[str]:
    """Best guess at the capture's server-side IP: the endpoint most often seen
    on a canonical media port; ties (or no media port) fall back to the busiest
    talker so we still split a two-host capture sensibly."""
    # Per-IP counts: appearances on a media port, and total appearances.
    media_hits: Dict[str, int] = {}
    seen: Dict[str, int] = {}
    # Tally every packet's endpoints.
    for p in packets:
        seen[p.src_ip] = seen.get(p.src_ip, 0) + 1
        seen[p.dst_ip] = seen.get(p.dst_ip, 0) + 1
        # The side that owns a well-known media port is most likely the server.
        if p.src_port in media_ports:
            media_hits[p.src_ip] = media_hits.get(p.src_ip, 0) + 1
        if p.dst_port in media_ports:
            media_hits[p.dst_ip] = media_hits.get(p.dst_ip, 0) + 1
    # Prefer the media-port evidence when there is any.
    if media_hits:
        return max(media_hits, key=media_hits.get)
    # Otherwise fall back to the busiest endpoint.
    if seen:
        return max(seen, key=seen.get)
    # Empty capture: no server can be guessed.
    return None


# A one-way replay stream: each entry is (delay before sending, UDP port, payload).
Stream = List[Tuple[float, int, bytes]]  # (delta_seconds, port, payload)


def split_directions(
    packets: Sequence[Packet],
    media_ports: frozenset = DEFAULT_MEDIA_PORTS,
) -> Tuple[Optional[str], Optional[str], Stream, Stream]:
    """Split UDP packets into (client_ip, server_ip, c2s, s2c).

    ``c2s`` (client->server) carries the DESTINATION port (what the client sends
    to) — the sim client replays these onto the sink. ``s2c`` (server->client)
    carries the SOURCE port (what the server sends from) — the hub sink replays
    these back to the client, so its responses land on the same media ports the
    real server used. Each stream's timestamp is the inter-packet delta (seconds)
    from the previous packet in THAT stream, so a replayer just sleeps the delta.
    """
    # Decide which IP is the server first; everything else is relative to it.
    server = _pick_server(packets, media_ports)
    # No packets: nothing to split.
    if server is None:
        return None, None, [], []
    # The client is the first peer seen talking to/from the server.
    client: Optional[str] = None
    for p in packets:
        # The other end of this packet if the server is one side, else None.
        other = p.dst_ip if p.src_ip == server else (
            p.src_ip if p.dst_ip == server else None)
        # Ignore server-to-itself traffic; the first real peer wins.
        if other and other != server:
            client = other
            break

    c2s: Stream = []
    s2c: Stream = []
    # Timestamp of the previous packet in each direction, for computing deltas.
    last_c = last_s = None
    # Route each packet into the matching direction; unrelated hosts are dropped.
    for p in packets:
        # Client -> server: keep the destination (server) port.
        if p.dst_ip == server and (client is None or p.src_ip == client):
            # First packet sends immediately; clamp negative gaps (reordered capture) to 0.
            d = 0.0 if last_c is None else max(0.0, p.ts - last_c)
            c2s.append((d, p.dst_port, p.payload))
            last_c = p.ts
        # Server -> client: keep the source (server) port.
        elif p.src_ip == server and (client is None or p.dst_ip == client):
            d = 0.0 if last_s is None else max(0.0, p.ts - last_s)
            s2c.append((d, p.src_port, p.payload))
            last_s = p.ts
    return client, server, c2s, s2c


def summarize(path: str, media_ports: frozenset = DEFAULT_MEDIA_PORTS) -> Dict:
    """Parse ``path`` and return a small stats dict for the UI / logs. Never
    raises for a parseable-but-empty capture; raises PcapError for a bad file."""
    # Parse and split the capture exactly as the replayers will.
    packets = parse_udp_packets(path)
    client, server, c2s, s2c = split_directions(packets, media_ports)
    # Capture duration: first to last non-zero timestamp (Simple Packet Blocks have 0).
    span = 0.0
    if packets:
        ts = [p.ts for p in packets if p.ts]
        span = (max(ts) - min(ts)) if len(ts) >= 2 else 0.0
    # Payload volume in each direction.
    c2s_bytes = sum(len(pl) for _, _, pl in c2s)
    s2c_bytes = sum(len(pl) for _, _, pl in s2c)
    # JSON-friendly stats; server_ports lists the distinct ports the sink will send from.
    return {
        "udp_packets": len(packets),
        "client_ip": client,
        "server_ip": server,
        "c2s_packets": len(c2s),
        "s2c_packets": len(s2c),
        "c2s_bytes": c2s_bytes,
        "s2c_bytes": s2c_bytes,
        "duration_s": round(span, 3),
        "server_ports": sorted({port for _, port, _ in s2c}),
    }


# ── synthetic capture writer (test fixture + placeholder generator) ──────────

def write_synthetic_pcap(path: str, app: str = "teams", seconds: float = 2.0,
                         hz: float = 50.0, payload_size: int = 160) -> Dict:
    """Write a small BIDIRECTIONAL classic-pcap of RTP-shaped UDP between a fake
    client (10.10.10.10) and server (10.20.20.20) on the app's media ports. Not
    a real Teams/Zoom/WebEx signature — a stand-in so the feature is testable and
    has a placeholder until a real capture is uploaded."""
    # Imported but unused; kept as-is (code is vendored byte-identical).
    import os
    # Media ports per app (mirrors DEFAULT_MEDIA_PORTS); unknown apps get Teams ports.
    app_ports = {
        "teams": [3478, 3481, 3479],
        "zoom": [8801, 8802, 8803],
        "webex": [9000, 5004, 5006],
    }.get(app, [3478, 3481, 3479])
    # Fixed fake endpoints, plus their 4-byte binary forms for the IP header.
    cli, srv = "10.10.10.10", "10.20.20.20"
    cli_b = bytes(int(x) for x in cli.split("."))
    srv_b = bytes(int(x) for x in srv.split("."))
    # Accumulates the packed per-packet records.
    recs = bytearray()
    # Number of send ticks (at least one); each tick emits one packet each way.
    n = max(1, int(seconds * hz))
    # RTP sequence number shared by both directions.
    seq = 0
    for i in range(n):
        # Tick time in seconds at the requested packet rate.
        ts = i / hz
        # Emit a client->server packet then its server->client reply.
        for outbound in (True, False):
            # Rotate across the app's media ports so all of them appear.
            port = app_ports[i % len(app_ports)]
            payload = _rtp_shaped(payload_size, seq); seq += 1
            # Client uses one of three ephemeral ports; server answers from the media port.
            if outbound:
                pkt = _build_eth_ip_udp(cli_b, srv_b, 40000 + (i % 3), port, payload)
            else:
                pkt = _build_eth_ip_udp(srv_b, cli_b, port, 40000 + (i % 3), payload)
            # Split the timestamp into whole seconds + microseconds for the record header.
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            recs += struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt
    # Little-endian classic pcap global header: magic, v2.4, tz 0, sigfigs 0,
    # snaplen 65535, Ethernet link type.
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, _DLT_EN10MB)
    with open(path, "wb") as fh:
        fh.write(hdr + recs)
    # Re-read what we wrote so the caller gets the same stats as a real upload.
    return summarize(path)


def _rtp_shaped(size: int, seq: int) -> bytes:
    """Build a ``size``-byte payload with a valid-looking RTP header and filler body."""
    # An RTP header alone is 12 bytes, so never go smaller than that.
    size = max(12, size)
    # RTP v2 (0x80), payload type 96 (0x60), sequence, timestamp (160 samples/packet
    # like 20 ms of 8 kHz audio), and a fixed SSRC.
    hdr = struct.pack(">BBHII", 0x80, 0x60, seq & 0xFFFF, seq * 160, 0x1A2B3C4D)
    # Deterministic, sequence-varying filler so packets are not all identical.
    return hdr + bytes((i * 7 + seq) & 0xFF for i in range(size - 12))


def _build_eth_ip_udp(src_ip: bytes, dst_ip: bytes, src_port: int,
                      dst_port: int, payload: bytes) -> bytes:
    """Wrap ``payload`` in UDP, IPv4 and Ethernet headers and return the frame bytes."""
    # Ethernet: fake locally-administered dst/src MACs and EtherType 0x0800 (IPv4).
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    # UDP header (checksum 0 = "not computed", which is legal for IPv4) + payload.
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    # IPv4 header: version 4 / 20-byte header (0x45), total length, TTL 64,
    # protocol 17 (UDP); header checksum left at 0 since parsers here ignore it.
    total = 20 + udp_len
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0) + src_ip + dst_ip
    return eth + ip + udp


# Command-line entry point for manual inspection / placeholder generation.
if __name__ == "__main__":
    # argparse for the CLI; json to pretty-print the stats dict.
    import argparse
    import json
    ap = argparse.ArgumentParser(description="collab pcap inspector / generator")
    # Two sub-commands; one of them is mandatory.
    sub = ap.add_subparsers(dest="cmd", required=True)
    # "inspect PATH": print summarize() output for an existing capture.
    p_i = sub.add_parser("inspect", help="print stats for a capture")
    p_i.add_argument("path")
    # "gen PATH [--app] [--seconds]": write a synthetic capture.
    p_g = sub.add_parser("gen", help="write a synthetic placeholder capture")
    p_g.add_argument("path")
    p_g.add_argument("--app", default="teams")
    p_g.add_argument("--seconds", type=float, default=2.0)
    args = ap.parse_args()
    # Dispatch on the chosen sub-command and print the resulting stats as JSON.
    if args.cmd == "inspect":
        print(json.dumps(summarize(args.path), indent=2))
    else:
        print(json.dumps(write_synthetic_pcap(args.path, args.app, args.seconds), indent=2))
