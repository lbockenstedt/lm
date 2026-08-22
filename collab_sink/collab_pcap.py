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
from __future__ import annotations

import struct
from collections import namedtuple
from typing import Dict, List, Optional, Sequence, Tuple

# Canonical media ports used by the sim (mirror COLLAB_APP_PORTS / APP_PROFILES).
# Used only to disambiguate which capture endpoint is the "server" side.
DEFAULT_MEDIA_PORTS = frozenset(
    {3478, 3481, 3479, 8801, 8802, 8803, 9000, 5004, 5006}
)

# Link-layer types (libpcap DLT_*).
_DLT_NULL = 0
_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LOOP = 108
_DLT_LINUX_SLL = 113
_DLT_RAW_ALT1 = 12
_DLT_RAW_ALT2 = 14
_DLT_IPV4 = 228

Packet = namedtuple("Packet", "ts src_ip src_port dst_ip dst_port payload")


class PcapError(Exception):
    """Raised when a capture can't be parsed as pcap/pcapng."""


# ── link/IP/UDP decode ───────────────────────────────────────────────────────

def _decode_ipv4_udp(ip: bytes) -> Optional[Tuple[str, int, str, int, bytes]]:
    """(src_ip, src_port, dst_ip, dst_port, payload) for an IPv4/UDP packet,
    else None. ``ip`` starts at the IPv4 header."""
    if len(ip) < 20 or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ihl < 20 or len(ip) < ihl + 8:
        return None
    if ip[9] != 17:  # not UDP
        return None
    src_ip = ".".join(str(b) for b in ip[12:16])
    dst_ip = ".".join(str(b) for b in ip[16:20])
    udp = ip[ihl:]
    src_port, dst_port, ulen = struct.unpack_from(">HHH", udp, 0)
    payload = udp[8:]
    # Trust the UDP length field when it's sane (trailing capture padding, FCS).
    body = ulen - 8
    if 0 <= body <= len(payload):
        payload = payload[:body]
    return src_ip, src_port, dst_ip, dst_port, payload


def _link_to_ipv4(linktype: int, frame: bytes) -> Optional[bytes]:
    """Strip the link layer, returning the IPv4 packet bytes (or None)."""
    if linktype == _DLT_EN10MB:
        if len(frame) < 14:
            return None
        etype = struct.unpack_from(">H", frame, 12)[0]
        off = 14
        # 802.1Q / QinQ VLAN tags.
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:
            etype = struct.unpack_from(">H", frame, off + 2)[0]
            off += 4
        return frame[off:] if etype == 0x0800 else None
    if linktype in (_DLT_RAW, _DLT_RAW_ALT1, _DLT_RAW_ALT2, _DLT_IPV4):
        return frame
    if linktype in (_DLT_NULL, _DLT_LOOP):
        if len(frame) < 4:
            return None
        return frame[4:]
    if linktype == _DLT_LINUX_SLL:
        if len(frame) < 16:
            return None
        return frame[16:] if struct.unpack_from(">H", frame, 14)[0] == 0x0800 else None
    return None


# ── classic pcap ─────────────────────────────────────────────────────────────

def _parse_classic(data: bytes) -> List[Tuple[float, int, bytes]]:
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian, nsec = ">", magic == b"\xa1\xb2\x3c\x4d"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian, nsec = "<", magic == b"\x4d\x3c\xb2\xa1"
    else:
        raise PcapError("not a classic pcap")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    out: List[Tuple[float, int, bytes]] = []
    off, n = 24, len(data)
    rec = struct.Struct(endian + "IIII")
    while off + 16 <= n:
        ts_sec, ts_frac, incl, _orig = rec.unpack_from(data, off)
        off += 16
        if off + incl > n:
            break
        frame = data[off:off + incl]
        off += incl
        ts = ts_sec + (ts_frac / 1e9 if nsec else ts_frac / 1e6)
        out.append((ts, linktype, frame))
    return out


# ── pcapng ───────────────────────────────────────────────────────────────────

def _parse_pcapng(data: bytes) -> List[Tuple[float, int, bytes]]:
    if data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PcapError("not a pcapng")
    # Byte order + first-IDB tsresol come from the section header block.
    bom = struct.unpack_from("<I", data, 8)[0]
    endian = "<" if bom == 0x1A2B3C4D else ">"
    out: List[Tuple[float, int, bytes]] = []
    if_linktypes: List[int] = []
    if_tsresol: List[float] = []
    off, n = 0, len(data)
    while off + 12 <= n:
        btype, blen = struct.unpack_from(endian + "II", data, off)
        if blen < 12 or off + blen > n:
            break
        body = data[off + 8:off + blen - 4]
        if btype == 0x00000001:  # Interface Description Block
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            tsresol = 1e-6
            # Options follow snaplen (body: linktype(2) resv(2) snaplen(4) opts).
            opos = 8
            while opos + 4 <= len(body):
                ocode, olen = struct.unpack_from(endian + "HH", body, opos)
                opos += 4
                if ocode == 0:
                    break
                if ocode == 9 and olen >= 1:  # if_tsresol
                    raw = body[opos]
                    tsresol = (1.0 / (2 ** (raw & 0x7F))) if (raw & 0x80) \
                        else (10.0 ** -(raw & 0x7F))
                opos += olen + ((4 - olen % 4) % 4)
            if_linktypes.append(linktype)
            if_tsresol.append(tsresol)
        elif btype == 0x00000006:  # Enhanced Packet Block
            ifid, tsh, tsl, cap, _orig = struct.unpack_from(endian + "IIIII", body, 0)
            frame = body[20:20 + cap]
            res = if_tsresol[ifid] if ifid < len(if_tsresol) else 1e-6
            lt = if_linktypes[ifid] if ifid < len(if_linktypes) else _DLT_EN10MB
            ts = ((tsh << 32) | tsl) * res
            out.append((ts, lt, frame))
        elif btype == 0x00000003:  # Simple Packet Block (no ts, uses IDB 0)
            _orig = struct.unpack_from(endian + "I", body, 0)[0]
            frame = body[4:]
            lt = if_linktypes[0] if if_linktypes else _DLT_EN10MB
            out.append((0.0, lt, frame))
        off += blen
    return out


# ── public API ───────────────────────────────────────────────────────────────

def parse_udp_packets(path: str) -> List[Packet]:
    """Read ``path`` and return its IPv4/UDP datagrams in capture order."""
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise PcapError("file too small to be a capture")
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        raw = _parse_pcapng(data)
    else:
        raw = _parse_classic(data)
    packets: List[Packet] = []
    for ts, linktype, frame in raw:
        ip = _link_to_ipv4(linktype, frame)
        if ip is None:
            continue
        dec = _decode_ipv4_udp(ip)
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
    media_hits: Dict[str, int] = {}
    seen: Dict[str, int] = {}
    for p in packets:
        seen[p.src_ip] = seen.get(p.src_ip, 0) + 1
        seen[p.dst_ip] = seen.get(p.dst_ip, 0) + 1
        if p.src_port in media_ports:
            media_hits[p.src_ip] = media_hits.get(p.src_ip, 0) + 1
        if p.dst_port in media_ports:
            media_hits[p.dst_ip] = media_hits.get(p.dst_ip, 0) + 1
    if media_hits:
        return max(media_hits, key=media_hits.get)
    if seen:
        return max(seen, key=seen.get)
    return None


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
    server = _pick_server(packets, media_ports)
    if server is None:
        return None, None, [], []
    client: Optional[str] = None
    for p in packets:
        other = p.dst_ip if p.src_ip == server else (
            p.src_ip if p.dst_ip == server else None)
        if other and other != server:
            client = other
            break

    c2s: Stream = []
    s2c: Stream = []
    last_c = last_s = None
    for p in packets:
        if p.dst_ip == server and (client is None or p.src_ip == client):
            d = 0.0 if last_c is None else max(0.0, p.ts - last_c)
            c2s.append((d, p.dst_port, p.payload))
            last_c = p.ts
        elif p.src_ip == server and (client is None or p.dst_ip == client):
            d = 0.0 if last_s is None else max(0.0, p.ts - last_s)
            s2c.append((d, p.src_port, p.payload))
            last_s = p.ts
    return client, server, c2s, s2c


def summarize(path: str, media_ports: frozenset = DEFAULT_MEDIA_PORTS) -> Dict:
    """Parse ``path`` and return a small stats dict for the UI / logs. Never
    raises for a parseable-but-empty capture; raises PcapError for a bad file."""
    packets = parse_udp_packets(path)
    client, server, c2s, s2c = split_directions(packets, media_ports)
    span = 0.0
    if packets:
        ts = [p.ts for p in packets if p.ts]
        span = (max(ts) - min(ts)) if len(ts) >= 2 else 0.0
    c2s_bytes = sum(len(pl) for _, _, pl in c2s)
    s2c_bytes = sum(len(pl) for _, _, pl in s2c)
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
    import os
    app_ports = {
        "teams": [3478, 3481, 3479],
        "zoom": [8801, 8802, 8803],
        "webex": [9000, 5004, 5006],
    }.get(app, [3478, 3481, 3479])
    cli, srv = "10.10.10.10", "10.20.20.20"
    cli_b = bytes(int(x) for x in cli.split("."))
    srv_b = bytes(int(x) for x in srv.split("."))
    recs = bytearray()
    n = max(1, int(seconds * hz))
    seq = 0
    for i in range(n):
        ts = i / hz
        for outbound in (True, False):
            port = app_ports[i % len(app_ports)]
            payload = _rtp_shaped(payload_size, seq); seq += 1
            if outbound:
                pkt = _build_eth_ip_udp(cli_b, srv_b, 40000 + (i % 3), port, payload)
            else:
                pkt = _build_eth_ip_udp(srv_b, cli_b, port, 40000 + (i % 3), payload)
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            recs += struct.pack("<IIII", sec, usec, len(pkt), len(pkt)) + pkt
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, _DLT_EN10MB)
    with open(path, "wb") as fh:
        fh.write(hdr + recs)
    return summarize(path)


def _rtp_shaped(size: int, seq: int) -> bytes:
    size = max(12, size)
    hdr = struct.pack(">BBHII", 0x80, 0x60, seq & 0xFFFF, seq * 160, 0x1A2B3C4D)
    return hdr + bytes((i * 7 + seq) & 0xFF for i in range(size - 12))


def _build_eth_ip_udp(src_ip: bytes, dst_ip: bytes, src_port: int,
                      dst_port: int, payload: bytes) -> bytes:
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    udp_len = 8 + len(payload)
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    total = 20 + udp_len
    ip = struct.pack(">BBHHHBBH", 0x45, 0, total, 0, 0, 64, 17, 0) + src_ip + dst_ip
    return eth + ip + udp


if __name__ == "__main__":
    import argparse
    import json
    ap = argparse.ArgumentParser(description="collab pcap inspector / generator")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_i = sub.add_parser("inspect", help="print stats for a capture")
    p_i.add_argument("path")
    p_g = sub.add_parser("gen", help="write a synthetic placeholder capture")
    p_g.add_argument("path")
    p_g.add_argument("--app", default="teams")
    p_g.add_argument("--seconds", type=float, default=2.0)
    args = ap.parse_args()
    if args.cmd == "inspect":
        print(json.dumps(summarize(args.path), indent=2))
    else:
        print(json.dumps(write_synthetic_pcap(args.path, args.app, args.seconds), indent=2))
