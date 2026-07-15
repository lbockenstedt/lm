#!/usr/bin/env python3
"""lm-collab-sink — passive UDP sink for collaboration-app traffic simulation.

Receives raw UDP on the Teams/Zoom/WebEx media ports so simulation clients
(cs/clients/linux/collab.py) can "call" the hub over the wired/USB network
path. recv + discard + log counts. This is the hub-side counterpart to the
client collab sender.

WHY a standalone process and not part of uvicorn: the unified :443 surface
is HTTP/WebSocket only (core/src/api.py). Raw UDP media has no place in
uvicorn, and iperf3 -u would negotiate its data port (media would never land
on the requested platform port). A plain UDP sink puts the flow on exactly
the ports a DPI/NetFlow monitor classifies by.

Network-bound: binds 0.0.0.0 by default (or LM_COLLAB_BIND) — NOT loopback —
so it is reachable from the client subnet over the physical interface. The
OPNsense alias/rule (applied via /setup/collab/apply) gates which sources are
allowed through; the sink itself just receives whatever reaches it.

No privileged ports (all >1024) → runs as svc_lm with no ambient capabilities.
Stdlib only → no venv, runs on system python3.
"""
import os
import select
import signal
import socket
import sys
import time

# Union of all app media ports. Override with LM_COLLAB_PORTS="3478,8801,..."
DEFAULT_PORTS = "3478,3481,3479,8801,8802,8803,9000,5004,5006"

BIND = os.environ.get("LM_COLLAB_BIND", "0.0.0.0")
PORTS = [int(p) for p in os.environ.get("LM_COLLAB_PORTS", DEFAULT_PORTS)
         .replace(" ", "").split(",") if p]
LOG_INTERVAL = int(os.environ.get("LM_COLLAB_LOG_INTERVAL", "30"))


def main() -> int:
    socks = []
    for p in PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Allows clean restart without TIME_WAIT bind failures.
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        try:
            s.bind((BIND, p))
            socks.append(s)
        except OSError as e:
            print(f"collab-sink: WARN could not bind {BIND}:{p} — {e}", flush=True)

    if not socks:
        print("collab-sink: no sockets bound — exiting", flush=True)
        return 1

    bound = [s.getsockname()[1] for s in socks]
    print(f"collab-sink: listening on {BIND} ports {bound}", flush=True)

    counts = {s: 0 for s in socks}
    byte_total = {s: 0 for s in socks}
    last = time.monotonic()
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while running:
        try:
            r, _, _ = select.select(socks, [], [], 5.0)
        except OSError:
            break
        for s in r:
            try:
                _data, _addr = s.recvfrom(65535)
                counts[s] += 1
                byte_total[s] += len(_data)
            except OSError:
                pass
        now = time.monotonic()
        if now - last >= LOG_INTERVAL:
            parts = [f"{s.getsockname()[1]}:{counts[s]}/{byte_total[s]}B"
                     for s in socks]
            print("collab-sink: " + " ".join(parts), flush=True)
            last = now

    for s in socks:
        s.close()
    print("collab-sink: stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())