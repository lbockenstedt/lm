#!/usr/bin/env python3
"""Hub load-test harness — spin up N synthetic spokes hammering telemetry.

Measures the hub's real capacity (msg/s, CPU, mem, backlog) under a controlled
number of connected spokes each sending signed CS_TELEMETRY at a chosen rate.

It REUSES the real client (``BaseControlPlane``) so auth, mutual-auth, session-key
rotation, signing, and keepalive are byte-for-byte what a real spoke does — a
hand-rolled client would risk signature mismatches and measure the wrong thing.
The dangerous side-effects are neutralised: no ``.env`` writes, no healthy-marker
files, and SPOKE_UPDATE is a NO-OP (a synthetic spoke must never git-pull /opt/lm).

WHERE TO RUN: on a lab box that can reach the hub AND has the lm core on disk
(any spoke host, or the hub itself). It imports from /opt/lm/core/src.

USAGE (auto-approve via the tenant onboarding PSK — needed so telemetry is
accepted; without approval a spoke is 'pending' and only heartbeats count):

    PYTHONPATH=/opt/lm/core/src python3 scripts/loadtest_spokes.py \
        --hub wss://172.16.1.31:443 \
        --count 200 --rate 1.0 --duration 120 \
        --psk <TENANT_ONBOARDING_PSK> --tenant <TENANT_ID>

Ramp gently (``--ramp``) so 200 TLS handshakes don't land in one tick. Watch the
printed table: when mps plateaus while cpu_util pins ~100% and backlog climbs,
you've found the ceiling for this hardware.

CLEANUP: synthetic spokes are approved in hub state and will show as offline
after the run. They're all prefixed (``--prefix``, default 'loadtest-') so you
can bulk-delete them from Setup -> Spokes & Agents (or DELETE /setup/spokes/<id>).
"""
import argparse
import asyncio
import json
import os
import random
import ssl
import sys
import time
import urllib.request
import uuid

# ── locate the lm core + spoke venv (turnkey on an existing spoke) ───────────
# /opt/lm on the path resolves `core.src.messaging.*` (PEP-420 namespace pkgs);
# /opt/lm/core/src resolves the bare `messaging.*` form. A real cs spoke tries
# both, so we do too — one of them matches whichever layout this box has.
_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in ("/opt/lm", "/opt/lm/core/src", _repo, os.path.join(_repo, "core", "src")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)


def _add_spoke_venv():
    """Add an existing spoke's venv site-packages so `websockets` (and the rest
    of the client deps) import even when this is launched with the SYSTEM python
    — so you can just `python3 scripts/loadtest_spokes.py` on a spoke box."""
    import glob
    try:
        import websockets  # noqa: F401 — already importable, nothing to do
        return
    except Exception:
        pass
    for base in ("/opt/lm/cs/venv", "/opt/lm/core/venv", "/opt/lm/venv"):
        for sp in glob.glob(os.path.join(base, "lib", "python*", "site-packages")):
            if os.path.isdir(sp) and sp not in sys.path:
                sys.path.insert(0, sp)


_add_spoke_venv()


def _load_env_file(path):
    """Best-effort parse of a spoke .env (KEY=VALUE lines) → dict."""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out
BaseControlPlane = None
_imp_err = None
for _mod in ("core.src.messaging.control_plane", "messaging.control_plane"):
    try:
        BaseControlPlane = __import__(_mod, fromlist=["BaseControlPlane"]).BaseControlPlane
        break
    except Exception as e:  # pragma: no cover
        _imp_err = e
if BaseControlPlane is None:
    sys.exit("Cannot import BaseControlPlane — run on a box with /opt/lm/core "
             f"(e.g. PYTHONPATH=/opt/lm/core/src). Last error: {_imp_err}")


class LoadSpoke(BaseControlPlane):
    """A real spoke client with side-effects neutralised + a synthetic telemetry
    sender. One asyncio task per instance; hundreds run concurrently in-process."""

    _PLATFORMS = ("linux", "windows", "macos")
    _SSIDS = ("corp-wifi", "guest-wifi", "lab-5g", "eng-2g")
    _TIERS = ("t1", "t2", "t3")
    _NAMES = ("kbell", "ibennett", "xmendoza", "tstewart", "qwu", "jlee", "amorgan", "dkhan")

    def __init__(self, spoke_id, stats, rate, payload_bytes, clients_n=20, vms_n=3, **kw):
        super().__init__(spoke_id=spoke_id, **kw)
        self.module_type = "simulation"  # cs-like → exercises the telemetry path
        self._stats = stats
        self._rate = max(0.01, float(rate))
        self._pad = "x" * max(0, int(payload_bytes))
        # Stable synthetic roster: client + VM identities persist across cycles
        # like real clients (so the hub does dedup/cache/persist against a
        # consistent set); only volatile fields vary each cycle. This drives the
        # full CS_TELEMETRY path incl. the hub writing simulations_cache.json.
        self._vmbase = 90000 + (abs(hash(spoke_id)) % 9000)
        self._clients = [self._mk_client(i) for i in range(max(0, int(clients_n)))]
        self._vms = [self._mk_vm(i) for i in range(max(0, int(vms_n)))]
        try:
            import logging
            logging.getLogger().removeHandler(self._log_relay_handler)
        except Exception:
            pass

    def _mk_client(self, i):
        vmid = self._vmbase + i
        return {
            "id": f"{self.spoke_id}-c{i:03d}",
            "hostname": f"{random.choice(self._NAMES)}{i}",
            "platform": random.choice(self._PLATFORMS),
            "hw_type": random.choice(self._PLATFORMS),
            "connected_ssid": random.choice(self._SSIDS),
            "simulation_id": f"s{i % 10}",
            "active_simulations": [f"sim-{i % 5}"],
            "has_usb": bool(i % 3 == 0),
            "vmid": vmid,
            "tier": random.choice(self._TIERS),
            "config": {"wsite": f"site-{i % 4}", "sim_phy": f"phy-{i % 3}"},
            "overrides": {},
        }

    def _mk_vm(self, i):
        vmid = self._vmbase + i
        return {"vmid": vmid, "name": f"sim-{vmid}", "status": "running",
                "ostype": "l26", "type": "qemu"}

    def _build_telemetry_data(self):
        """Realistic CS_TELEMETRY body — a full clients/VM/USB snapshot so the hub
        runs its real ingest → fan-out → cache → persist (simulations_cache.json)
        path, not a no-op on an empty frame. Volatile fields vary each cycle."""
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for c in self._clients:
            c["online"] = random.random() > 0.05
            c["last_seen"] = now_iso
            c["error_count"] = random.randint(0, 2)
        usb = [{"vid": "0bda", "pid": "8812", "bus": f"{i + 1}-1"}
               for i in range(min(4, len(self._vms)))]
        data = {
            "host": self.spoke_id,
            "clients": self._clients,
            "proxmox_vms": self._vms,
            "usb_devices": usb,
            "vm_count": len(self._vms),
            "usb_count": len(usb),
        }
        if self._pad:
            data["_pad"] = self._pad
        return data

    # ── neutralise side-effects (no disk writes for a throwaway spoke) ────────
    def _ensure_install_uuid(self):
        return uuid.uuid4().hex           # in-memory only; never touch .env

    def _persist_session_secret(self, new_secret):  # no-op
        pass

    def _persist_hub_secret(self, new_secret):       # no-op
        pass

    def _touch_healthy_marker(self):                 # no-op (no marker files)
        pass

    def _clear_healthy_marker(self):                 # no-op
        pass

    async def handle_system_command(self, cmd_type, data):
        # NEVER let a synthetic spoke act on SPOKE_UPDATE (it would git-pull
        # /opt/lm and restart). Everything else — crucially SPOKE_UPDATE_SESSION_KEY,
        # which rotates the signing key — flows to the real handler.
        if cmd_type == "SPOKE_UPDATE":
            return {"status": "SUCCESS", "message": "loadtest: SPOKE_UPDATE ignored"}
        return await super().handle_system_command(cmd_type, data)

    # ── the load: one signed CS_TELEMETRY every 1/rate seconds ───────────────
    def _create_spoke_tasks(self, websocket):
        return [asyncio.create_task(self._telemetry_loop(websocket))]

    async def _telemetry_loop(self, websocket):
        period = 1.0 / self._rate
        while True:
            try:
                msg = {
                    "header": {"message_id": str(uuid.uuid4()),
                               "timestamp": round(time.time(), 6),
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "CS_TELEMETRY",
                                "data": self._build_telemetry_data()},
                }
                sig = self._sign(msg)
                if sig is not None:
                    msg["signature"] = sig
                await websocket.send(json.dumps(msg, separators=(",", ":")))
                self._stats["sent"] += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                self._stats["send_err"] += 1
                return  # let the reconnect loop take over
            await asyncio.sleep(period)

    async def run_forever(self, stop_evt):
        """Minimal reconnect loop — like BaseControlPlane.run() but WITHOUT the
        updater worker (a synthetic spoke must not self-update)."""
        await self._resolve_hub_url()
        delay = 1
        while not stop_evt.is_set():
            t0 = time.time()
            try:
                self._stats["connects"] += 1
                await self._connect_and_serve()
                delay = 1
            except Exception:
                self._stats["conn_err"] += 1
                delay = 5 if (time.time() - t0) >= 30 else min(delay * 2, 30)
            if not stop_evt.is_set():
                await asyncio.sleep(delay)


def _fetch_status(status_url):
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(status_url, timeout=5, context=ctx) as r:
        return json.loads(r.read().decode())


async def _monitor(status_url, stop_evt, interval, stats, total):
    peak = {"mps": 0.0, "cpu": 0.0, "mem": 0.0, "backlog": 0, "conns": 0}
    last_sent = 0
    print(f"\n{'t(s)':>5} {'conns':>6} {'client/s':>9} {'hub mps':>8} "
          f"{'cpu%':>6} {'mem%':>6} {'backlog':>8}")
    print("-" * 58)
    t_start = time.time()
    while not stop_evt.is_set():
        await asyncio.sleep(interval)
        elapsed = time.time() - t_start
        client_rate = (stats["sent"] - last_sent) / interval
        last_sent = stats["sent"]
        m = {}
        try:
            data = await asyncio.to_thread(_fetch_status, status_url)
            m = data.get("metrics", {}) or {}
            conns = len(data.get("active_connections", []) or [])
        except Exception:
            conns = -1
        mps = float(m.get("mps", 0) or 0)
        cpu = float(m.get("cpu_util", 0) or 0)
        mem = float(m.get("mem_util", 0) or 0)
        backlog = int(m.get("backlog", 0) or 0)
        peak["mps"] = max(peak["mps"], mps); peak["cpu"] = max(peak["cpu"], cpu)
        peak["mem"] = max(peak["mem"], mem); peak["backlog"] = max(peak["backlog"], backlog)
        peak["conns"] = max(peak["conns"], conns)
        print(f"{elapsed:5.0f} {conns:6d} {client_rate:9.0f} {mps:8.0f} "
              f"{cpu:6.1f} {mem:6.1f} {backlog:8d}")
    print("-" * 58)
    print(f"PEAK: conns={peak['conns']} hub_mps={peak['mps']:.0f} "
          f"cpu={peak['cpu']:.1f}% mem={peak['mem']:.1f}% backlog={peak['backlog']}")
    print(f"client sent total={stats['sent']} send_err={stats['send_err']} "
          f"conn_err={stats['conn_err']} (target {total} spokes)")


async def main():
    ap = argparse.ArgumentParser(description="Hub load test — N synthetic spokes.")
    ap.add_argument("--hub", default="", help="wss://HOST:PORT (default: from --env-file HUB_URL)")
    ap.add_argument("--env-file", default="/opt/lm/cs/.env",
                    help="existing spoke .env to pull hub/PSK/tenant defaults from")
    ap.add_argument("--count", type=int, default=100, help="number of synthetic spokes")
    ap.add_argument("--rate", type=float, default=1.0, help="telemetry msg/s PER spoke")
    ap.add_argument("--duration", type=int, default=120, help="run seconds")
    ap.add_argument("--ramp", type=float, default=10.0, help="seconds to stagger all connects over")
    ap.add_argument("--payload-bytes", type=int, default=0, help="extra pad bytes per telemetry msg")
    ap.add_argument("--clients-per-spoke", type=int, default=20, help="synthetic clients per spoke (realistic payload)")
    ap.add_argument("--vms-per-spoke", type=int, default=3, help="synthetic proxmox VMs per spoke")
    ap.add_argument("--psk", default="", help="tenant onboarding PSK (auto-approves the spokes)")
    ap.add_argument("--tenant", default="", help="tenant id hint (with --psk)")
    ap.add_argument("--secret", default="", help="pre-provisioned spoke secret (else zero-touch)")
    ap.add_argument("--prefix", default="loadtest-", help="spoke id prefix (for cleanup)")
    ap.add_argument("--status-url", default="", help="override; default derives https://HOST:PORT/status")
    ap.add_argument("--sample-interval", type=float, default=5.0)
    args = ap.parse_args()

    # Fill hub / PSK / tenant from an existing spoke's .env when not given, so on
    # a spoke box you can just run the script with --count/--rate.
    _env = _load_env_file(args.env_file)
    if not args.hub:
        args.hub = (_env.get("HUB_URL") or _env.get("LM_HUB_URL") or "").strip()
    if not args.psk:
        args.psk = (_env.get("LM_ONBOARDING_PSK") or "").strip()
    if not args.tenant:
        args.tenant = (_env.get("LM_TENANT_ID_HINT") or "").strip()
    if not args.hub:
        sys.exit("No --hub given and none found in --env-file. Pass --hub wss://HOST:PORT")
    if _env:
        print(f"(loaded defaults from {args.env_file}: "
              f"hub={'yes' if args.hub else 'no'}, psk={'yes' if args.psk else 'no'}, "
              f"tenant={args.tenant or '-'})")

    if not args.psk:
        print("WARNING: no --psk → spokes stay PENDING (unapproved); only heartbeats\n"
              "         are accepted, telemetry is dropped. Pass --psk/--tenant to test\n"
              "         the full telemetry path.", file=sys.stderr)

    status_url = args.status_url or (
        args.hub.replace("wss://", "https://").replace("ws://", "http://").rstrip("/") + "/status")

    stats = {"sent": 0, "send_err": 0, "connects": 0, "conn_err": 0}
    stop_evt = asyncio.Event()

    spokes = [
        LoadSpoke(
            spoke_id=f"{args.prefix}{i:05d}", stats=stats, rate=args.rate,
            payload_bytes=args.payload_bytes, clients_n=args.clients_per_spoke,
            vms_n=args.vms_per_spoke, hub_url=args.hub,
            secret=(args.secret or None),
            onboarding_psk=(args.psk or None), tenant_id_hint=(args.tenant or None),
        )
        for i in range(args.count)
    ]

    print(f"Load test: {args.count} spokes → {args.hub} @ {args.rate} msg/s each "
          f"(~{args.count * args.rate:.0f} msg/s aggregate), {args.duration}s, "
          f"ramp {args.ramp}s. Status: {status_url}")

    tasks = []
    per = args.ramp / max(1, args.count)
    for s in spokes:
        tasks.append(asyncio.create_task(s.run_forever(stop_evt)))
        if per > 0:
            await asyncio.sleep(per)

    mon = asyncio.create_task(_monitor(status_url, stop_evt, args.sample_interval, stats, args.count))
    await asyncio.sleep(args.duration)
    stop_evt.set()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await mon
    print(f"\nDone. Clean up synthetic spokes (prefix '{args.prefix}') from "
          f"Setup → Spokes & Agents, or: for i in $(seq 0 {args.count-1}); do "
          f"curl -sk -X DELETE https://HOST/setup/spokes/{args.prefix}$(printf %05d $i); done")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
