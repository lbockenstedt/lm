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
# os reads environment-variable settings and checks/stats the capture file.
import os
# random generates filler bytes for synthetic responses.
import random
# select waits on many UDP sockets at once without busy-looping.
import select
# signal lets SIGTERM/SIGINT stop the main loop cleanly.
import signal
# socket creates the UDP listeners and sends responses.
import socket
# sys passes main()'s return value to the process exit code.
import sys
# time.monotonic() drives flow timeouts, logging and reload intervals.
import time

# The capture parser is optional; without it the sink still answers with synthetic data.
try:
    import collab_pcap
except Exception:  # noqa: BLE001 — parser optional; synthetic fallback still works
    # Parser missing or broken: None tells the rest of the code to skip pcap replay.
    collab_pcap = None

# Union of all app media ports. Override with LM_COLLAB_PORTS="3478,8801,..."
DEFAULT_PORTS = "3478,3481,3479,8801,8802,8803,9000,5004,5006"

# Interface address to listen on; 0.0.0.0 means all interfaces.
BIND = os.environ.get("LM_COLLAB_BIND", "0.0.0.0")
# Parse the comma-separated port list, ignoring spaces and empty entries.
PORTS = [int(p) for p in os.environ.get("LM_COLLAB_PORTS", DEFAULT_PORTS)
         .replace(" ", "").split(",") if p]
# Seconds between periodic traffic-counter log lines.
LOG_INTERVAL = int(os.environ.get("LM_COLLAB_LOG_INTERVAL", "30"))

# Responder knobs.
# Responder on unless explicitly disabled; PCAP_PATH is the uploaded capture to replay.
RESPOND = os.environ.get("LM_COLLAB_RESPOND", "1") not in ("0", "false", "off", "")
PCAP_PATH = os.environ.get("LM_COLLAB_PCAP", "").strip()
# Datagrams a flow must send before we answer it (prevents reflection abuse).
MIN_INBOUND = int(os.environ.get("LM_COLLAB_MIN_INBOUND", "3"))   # anti-reflection
# Seconds of silence after which a flow is forgotten.
IDLE_TIMEOUT = float(os.environ.get("LM_COLLAB_IDLE_TIMEOUT", "10"))
# Cap on tracked flows so memory stays bounded; oldest is evicted past this.
MAX_FLOWS = int(os.environ.get("LM_COLLAB_MAX_FLOWS", "512"))
# Largest response payload we will send, so replies never amplify traffic.
MAX_RESP_BYTES = int(os.environ.get("LM_COLLAB_MAX_RESP_BYTES", "2000"))
# Seconds between checks for a newly uploaded capture file.
PCAP_RELOAD_S = float(os.environ.get("LM_COLLAB_PCAP_RELOAD_S", "15"))


def _load_response_stream(path):
    """Return (payloads, deltas) — the server->client datagrams to echo back —
    from an uploaded capture, or ([], []) if unavailable/unparseable."""
    # Nothing to load: no path, no parser, or the file does not exist.
    if not path or collab_pcap is None or not os.path.isfile(path):
        return [], []
    # Parse the capture and keep only the server->client datagrams.
    try:
        packets = collab_pcap.parse_udp_packets(path)
        _cli, _srv, _c2s, s2c = collab_pcap.split_directions(packets)
    # Unreadable/corrupt capture: warn and fall back to synthetic responses.
    except Exception as e:  # noqa: BLE001
        print(f"collab-sink: WARN could not parse pcap {path}: {e}", flush=True)
        return [], []
    # Keep non-empty payloads (truncated to the size cap) and their inter-packet gaps
    # clamped to 0..1 s so replay timing stays sane.
    payloads = [pl[:MAX_RESP_BYTES] for _d, _p, pl in s2c if pl]
    deltas = [max(0.0, min(1.0, d)) for (d, _p, pl) in s2c if pl]
    return payloads, deltas


def _synthetic_payload(size):
    """Build a random payload roughly the size of the client's last datagram.

    Args:
        size: Size of the last inbound datagram (None/0 means use 160 bytes).

    Returns:
        Random bytes, clamped between 12 bytes (an RTP header) and MAX_RESP_BYTES.
    """
    # Clamp size: at least an RTP header (12 bytes), at most the response cap.
    size = max(12, min(size or 160, MAX_RESP_BYTES))
    # Fill the payload with random bytes so it looks like encrypted media.
    return bytes(random.getrandbits(8) for _ in range(size))


class _Flow:
    """Per-client response state. Keyed by (client_ip, client_port, local_port)."""
    # __slots__ keeps per-flow objects small, since there can be hundreds of them.
    __slots__ = ("last_seen", "in_count", "out_count", "next_send", "idx", "last_size")

    def __init__(self, now):
        """Start a new flow seen at time now with zeroed counters.

        Args:
            now: time.monotonic() timestamp of the first datagram.
        """
        # When we last heard from the client; used for idle expiry and eviction.
        self.last_seen = now
        # Datagrams received from and sent to this client (enforces the 1:1 ceiling).
        self.in_count = 0
        self.out_count = 0
        # Earliest time the next response may go out; send immediately at first.
        self.next_send = now
        # Position in the capture's response stream for this flow.
        self.idx = 0
        # Size of the client's last datagram, used to size synthetic replies (160 = typical RTP).
        self.last_size = 160


def main() -> int:
    """Bind the UDP ports and run the receive/respond loop until signalled.

    Returns:
        Process exit code: 0 on clean shutdown, 1 if no port could be bound.
    """
    # All bound sockets, plus a port->socket lookup used when replying.
    socks = []
    sock_by_port = {}
    # Open one non-blocking UDP socket per configured media port.
    for p in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow fast restarts without waiting for the old socket to be released.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # SO_REUSEPORT is not available on every platform; ignore it if missing.
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        # Platform lacks SO_REUSEPORT: carry on with just SO_REUSEADDR.
        except (AttributeError, OSError):
            pass
        # Bind the port; a failure (port in use, no permission) only skips that port.
        try:
            s.bind((BIND, p))
            s.setblocking(False)
            socks.append(s)
            sock_by_port[p] = s
        # Could not bind this port: warn and keep going with the others.
        except OSError as e:
            print(f"collab-sink: WARN could not bind {BIND}:{p} — {e}", flush=True)

    # Nothing bound at all means there is nothing to do, so exit with an error.
    if not socks:
        print("collab-sink: no sockets bound — exiting", flush=True)
        return 1

    # Actual port numbers we are listening on, for the startup message.
    bound = [s.getsockname()[1] for s in socks]
    # Response stream from the capture (empty until loaded) and the capture's last mtime.
    resp_payloads, resp_deltas = ([], [])
    pcap_mtime = 0.0
    # When responding is enabled, load the capture and remember its modification time.
    if RESPOND:
        resp_payloads, resp_deltas = _load_response_stream(PCAP_PATH)
        # Record mtime so the hot-reload check can spot a new upload.
        try:
            pcap_mtime = os.path.getmtime(PCAP_PATH) if PCAP_PATH and os.path.isfile(PCAP_PATH) else 0.0
        # File vanished between checks: treat as no capture.
        except OSError:
            pcap_mtime = 0.0
    # Describe the responder mode (pcap, synthetic or off) in the startup log.
    mode = ("pcap" if resp_payloads else "synthetic") if RESPOND else "off"
    print(f"collab-sink: listening on {BIND} ports {bound}; responder={mode}"
          + (f" ({len(resp_payloads)} s2c frames)" if resp_payloads else ""),
          flush=True)

    # Per-socket datagram and byte counters for the periodic log.
    counts = {s: 0 for s in socks}
    byte_total = {s: 0 for s in socks}
    # Total responses sent, active flows, and timers for logging and pcap reload.
    resp_sent = 0
    flows = {}          # (cip, cport, lport) -> _Flow
    last_log = time.monotonic()
    last_reload = time.monotonic()
    # Main loop keeps running until a stop signal clears this flag.
    running = True

    def stop(*_):
        """Signal handler: ask the main loop to exit after the current iteration."""
        # Modify the enclosing main()'s flag rather than creating a local one.
        nonlocal running
        running = False

    # Stop cleanly on service stop (SIGTERM) or Ctrl+C (SIGINT).
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    # Each iteration: receive datagrams, send due responses, maybe reload, maybe log.
    while running:
        try:
            # Short timeout so the responder scheduler runs even without inbound.
            r, _, _ = select.select(socks, [], [], 0.2)
        # select fails if a socket was closed underneath us; stop the loop.
        except OSError:
            break

        # Single timestamp for this iteration so all flow math is consistent.
        now = time.monotonic()
        # Handle each socket that has data waiting; lport is the media port it listens on.
        for s in r:
            lport = s.getsockname()[1]
            # Drain everything queued on this socket this tick.
            while True:
                # Read one datagram; the buffer is the largest possible UDP payload.
                try:
                    data, addr = s.recvfrom(65535)
                # Socket drained (or a transient error): move to the next socket.
                except (BlockingIOError, OSError):
                    break
                # Count the datagram and its bytes for the periodic log.
                counts[s] += 1
                byte_total[s] += len(data)
                # Responder disabled: just count traffic, never reply.
                if not RESPOND:
                    continue
                # Each client address/port on each local port is its own flow.
                key = (addr[0], addr[1], lport)
                fl = flows.get(key)
                # New flow: if at capacity, evict the least recently seen flow first.
                if fl is None:
                    if len(flows) >= MAX_FLOWS:
                        oldest = min(flows, key=lambda k: flows[k].last_seen)
                        flows.pop(oldest, None)
                    fl = flows[key] = _Flow(now)
                # Refresh the flow's activity time, inbound count and last datagram size.
                fl.last_seen = now
                fl.in_count += 1
                fl.last_size = len(data)

        # ── responder scheduler ──────────────────────────────────────────────
        if RESPOND and flows:
            # Collect idle flows to drop after the loop (cannot delete while iterating).
            stale = []
            for key, fl in flows.items():
                cip, cport, lport = key
                # Client went quiet: mark the flow for removal and skip it.
                if now - fl.last_seen > IDLE_TIMEOUT:
                    stale.append(key)
                    continue
                # Anti-reflection: need a sustained inbound burst, and never
                # answer more than we've received on this flow (1:1 ceiling).
                if fl.in_count < MIN_INBOUND or fl.out_count >= fl.in_count:
                    continue
                # Not time for this flow's next response yet.
                if now < fl.next_send:
                    continue
                # Reply from the same port the client sent to; skip if that socket is gone.
                sock = sock_by_port.get(lport)
                if sock is None:
                    continue
                # Capture loaded: replay its next server datagram and use its original timing gap.
                if resp_payloads:
                    payload = resp_payloads[fl.idx % len(resp_payloads)]
                    delta = resp_deltas[fl.idx % len(resp_deltas)] if resp_deltas else 0.02
                    fl.idx += 1
                # No capture: send random filler sized like the client's last datagram at 20 ms
                # pacing.
                else:
                    payload = _synthetic_payload(fl.last_size)
                    delta = 0.02
                # Send the response and count it; a send error just skips this response.
                try:
                    sock.sendto(payload, (cip, cport))
                    fl.out_count += 1
                    resp_sent += 1
                # Send failed (e.g. network unreachable); ignore and try again next time.
                except OSError:
                    pass
                # Cadence from the capture, floored so an idle-gap can't stall us.
                fl.next_send = now + (delta if delta > 0 else 0.02)
            # Drop the idle flows found above.
            for key in stale:
                flows.pop(key, None)

        # ── periodic pcap hot-reload (an upload takes effect w/o a restart) ──
        if RESPOND and PCAP_PATH and (now - last_reload) >= PCAP_RELOAD_S:
            # Restart the reload timer, then read the capture's current modification time.
            last_reload = now
            try:
                mt = os.path.getmtime(PCAP_PATH) if os.path.isfile(PCAP_PATH) else 0.0
            # Capture file is unreadable/missing: treat as no capture.
            except OSError:
                mt = 0.0
            # File changed (new upload or deletion): reload it and restart every flow's replay.
            if mt != pcap_mtime:
                pcap_mtime = mt
                resp_payloads, resp_deltas = _load_response_stream(PCAP_PATH)
                for fl in flows.values():
                    fl.idx = 0
                print(f"collab-sink: reloaded responder pcap "
                      f"({len(resp_payloads)} s2c frames)", flush=True)

        # Every LOG_INTERVAL seconds, log per-port counts/bytes, flow count and responses sent.
        if now - last_log >= LOG_INTERVAL:
            parts = [f"{s.getsockname()[1]}:{counts[s]}/{byte_total[s]}B" for s in socks]
            print(f"collab-sink: rx {' '.join(parts)} | flows={len(flows)} "
                  f"resp_sent={resp_sent}", flush=True)
            last_log = now

    # Shutdown: close all sockets and log that we stopped.
    for s in socks:
        s.close()
    print("collab-sink: stopped", flush=True)
    return 0


# Run as a script: exit with main()'s return code.
if __name__ == "__main__":
    sys.exit(main())
