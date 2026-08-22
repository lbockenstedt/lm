#!/usr/bin/env python3
"""lm-collab-sink — hub-side UDP responder for collaboration-app traffic sim.

Receives raw UDP on the Teams/Zoom/WebEx media ports so simulation clients
(cs/clients/linux/collab.py) can "call" the hub over the wired/USB network
path, AND responds back so the flow is bidirectional — a real call, not a
one-way blast. This is the hub-side counterpart to the client collab sender.

WHAT IT RESPONDS WITH: if a capture has been uploaded to the Collab module
(LM_COLLAB_PCAP points at it), the sink replays that capture's SERVER->CLIENT
datagrams back to each active client — so its answers carry the same real
STUN/RTP/SRTP bytes the actual server sent, on the same media ports. With no
capture it falls back to synthetic RTP-shaped filler ("fake data"), so the sim
still produces a two-way flow.

NON-AMPLIFYING BY DESIGN: the sink only answers a flow that has sent a sustained
burst (>= MIN_INBOUND datagrams), never sends more datagrams than it has
received on that flow (1:1 ceiling), caps payload size, and expires idle flows
fast — so an internet-exposed sink can't be used as a reflection/amplification
vector.

WHY a standalone process and not part of uvicorn: the unified :443 surface is
HTTP/WebSocket only. Raw UDP media has no place in uvicorn, and iperf3 -u would
negotiate its data port. A plain UDP responder puts the flow on exactly the
ports a DPI/NetFlow monitor classifies by.

Stdlib only → no venv, runs on system python3. Reads the uploaded capture via
the shared parser collab_pcap.py (kept identical with the cs client copy).
"""
import os
import random
import select
import signal
import socket
import sys
import time

try:
    import collab_pcap
except Exception:  # noqa: BLE001 — parser optional; synthetic fallback still works
    collab_pcap = None

# Union of all app media ports. Override with LM_COLLAB_PORTS="3478,8801,..."
DEFAULT_PORTS = "3478,3481,3479,8801,8802,8803,9000,5004,5006"

BIND = os.environ.get("LM_COLLAB_BIND", "0.0.0.0")
PORTS = [int(p) for p in os.environ.get("LM_COLLAB_PORTS", DEFAULT_PORTS)
         .replace(" ", "").split(",") if p]
LOG_INTERVAL = int(os.environ.get("LM_COLLAB_LOG_INTERVAL", "30"))

# Responder knobs.
RESPOND = os.environ.get("LM_COLLAB_RESPOND", "1") not in ("0", "false", "off", "")
PCAP_PATH = os.environ.get("LM_COLLAB_PCAP", "").strip()
MIN_INBOUND = int(os.environ.get("LM_COLLAB_MIN_INBOUND", "3"))   # anti-reflection
IDLE_TIMEOUT = float(os.environ.get("LM_COLLAB_IDLE_TIMEOUT", "10"))
MAX_FLOWS = int(os.environ.get("LM_COLLAB_MAX_FLOWS", "512"))
MAX_RESP_BYTES = int(os.environ.get("LM_COLLAB_MAX_RESP_BYTES", "2000"))
PCAP_RELOAD_S = float(os.environ.get("LM_COLLAB_PCAP_RELOAD_S", "15"))


def _load_response_stream(path):
    """Return (payloads, deltas) — the server->client datagrams to echo back —
    from an uploaded capture, or ([], []) if unavailable/unparseable."""
    if not path or collab_pcap is None or not os.path.isfile(path):
        return [], []
    try:
        packets = collab_pcap.parse_udp_packets(path)
        _cli, _srv, _c2s, s2c = collab_pcap.split_directions(packets)
    except Exception as e:  # noqa: BLE001
        print(f"collab-sink: WARN could not parse pcap {path}: {e}", flush=True)
        return [], []
    payloads = [pl[:MAX_RESP_BYTES] for _d, _p, pl in s2c if pl]
    deltas = [max(0.0, min(1.0, d)) for (d, _p, pl) in s2c if pl]
    return payloads, deltas


def _synthetic_payload(size):
    size = max(12, min(size or 160, MAX_RESP_BYTES))
    return bytes(random.getrandbits(8) for _ in range(size))


class _Flow:
    """Per-client response state. Keyed by (client_ip, client_port, local_port)."""
    __slots__ = ("last_seen", "in_count", "out_count", "next_send", "idx", "last_size")

    def __init__(self, now):
        self.last_seen = now
        self.in_count = 0
        self.out_count = 0
        self.next_send = now
        self.idx = 0
        self.last_size = 160


def main() -> int:
    socks = []
    sock_by_port = {}
    for p in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        try:
            s.bind((BIND, p))
            s.setblocking(False)
            socks.append(s)
            sock_by_port[p] = s
        except OSError as e:
            print(f"collab-sink: WARN could not bind {BIND}:{p} — {e}", flush=True)

    if not socks:
        print("collab-sink: no sockets bound — exiting", flush=True)
        return 1

    bound = [s.getsockname()[1] for s in socks]
    resp_payloads, resp_deltas = ([], [])
    pcap_mtime = 0.0
    if RESPOND:
        resp_payloads, resp_deltas = _load_response_stream(PCAP_PATH)
        try:
            pcap_mtime = os.path.getmtime(PCAP_PATH) if PCAP_PATH and os.path.isfile(PCAP_PATH) else 0.0
        except OSError:
            pcap_mtime = 0.0
    mode = ("pcap" if resp_payloads else "synthetic") if RESPOND else "off"
    print(f"collab-sink: listening on {BIND} ports {bound}; responder={mode}"
          + (f" ({len(resp_payloads)} s2c frames)" if resp_payloads else ""),
          flush=True)

    counts = {s: 0 for s in socks}
    byte_total = {s: 0 for s in socks}
    resp_sent = 0
    flows = {}          # (cip, cport, lport) -> _Flow
    last_log = time.monotonic()
    last_reload = time.monotonic()
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while running:
        try:
            # Short timeout so the responder scheduler runs even without inbound.
            r, _, _ = select.select(socks, [], [], 0.2)
        except OSError:
            break

        now = time.monotonic()
        for s in r:
            lport = s.getsockname()[1]
            # Drain everything queued on this socket this tick.
            while True:
                try:
                    data, addr = s.recvfrom(65535)
                except (BlockingIOError, OSError):
                    break
                counts[s] += 1
                byte_total[s] += len(data)
                if not RESPOND:
                    continue
                key = (addr[0], addr[1], lport)
                fl = flows.get(key)
                if fl is None:
                    if len(flows) >= MAX_FLOWS:
                        oldest = min(flows, key=lambda k: flows[k].last_seen)
                        flows.pop(oldest, None)
                    fl = flows[key] = _Flow(now)
                fl.last_seen = now
                fl.in_count += 1
                fl.last_size = len(data)

        # ── responder scheduler ──────────────────────────────────────────────
        if RESPOND and flows:
            stale = []
            for key, fl in flows.items():
                cip, cport, lport = key
                if now - fl.last_seen > IDLE_TIMEOUT:
                    stale.append(key)
                    continue
                # Anti-reflection: need a sustained inbound burst, and never
                # answer more than we've received on this flow (1:1 ceiling).
                if fl.in_count < MIN_INBOUND or fl.out_count >= fl.in_count:
                    continue
                if now < fl.next_send:
                    continue
                sock = sock_by_port.get(lport)
                if sock is None:
                    continue
                if resp_payloads:
                    payload = resp_payloads[fl.idx % len(resp_payloads)]
                    delta = resp_deltas[fl.idx % len(resp_deltas)] if resp_deltas else 0.02
                    fl.idx += 1
                else:
                    payload = _synthetic_payload(fl.last_size)
                    delta = 0.02
                try:
                    sock.sendto(payload, (cip, cport))
                    fl.out_count += 1
                    resp_sent += 1
                except OSError:
                    pass
                # Cadence from the capture, floored so an idle-gap can't stall us.
                fl.next_send = now + (delta if delta > 0 else 0.02)
            for key in stale:
                flows.pop(key, None)

        # ── periodic pcap hot-reload (an upload takes effect w/o a restart) ──
        if RESPOND and PCAP_PATH and (now - last_reload) >= PCAP_RELOAD_S:
            last_reload = now
            try:
                mt = os.path.getmtime(PCAP_PATH) if os.path.isfile(PCAP_PATH) else 0.0
            except OSError:
                mt = 0.0
            if mt != pcap_mtime:
                pcap_mtime = mt
                resp_payloads, resp_deltas = _load_response_stream(PCAP_PATH)
                for fl in flows.values():
                    fl.idx = 0
                print(f"collab-sink: reloaded responder pcap "
                      f"({len(resp_payloads)} s2c frames)", flush=True)

        if now - last_log >= LOG_INTERVAL:
            parts = [f"{s.getsockname()[1]}:{counts[s]}/{byte_total[s]}B" for s in socks]
            print(f"collab-sink: rx {' '.join(parts)} | flows={len(flows)} "
                  f"resp_sent={resp_sent}", flush=True)
            last_log = now

    for s in socks:
        s.close()
    print("collab-sink: stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
