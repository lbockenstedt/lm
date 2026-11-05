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
# argparse: CLI flags; asyncio: run hundreds of spoke clients concurrently in one process.
import argparse
import asyncio
# json: parse the hub /status response.
import json
# os/sys: locate the lm code and venv and extend the import path.
import os
# random: vary synthetic client fields so payloads look realistic.
import random
# socket: this box's hostname, folded into spoke ids to keep them unique.
import socket
# ssl: talk to the hub's self-signed /status endpoint without verification.
import ssl
import sys
# time: timestamps and rate pacing; urllib.request: fetch hub status.
import time
import urllib.request
# uuid: message ids and throwaway install ids.
import uuid

# ── locate the lm core + spoke venv (turnkey on an existing spoke) ───────────
# /opt/lm on the path resolves `core.src.messaging.*` (PEP-420 namespace pkgs);
# /opt/lm/core/src resolves the bare `messaging.*` form. A real cs spoke tries
# both, so we do too — one of them matches whichever layout this box has.
# This repo's root (one level above scripts/).
_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Prepend each existing candidate path once so both import layouts work.
for _p in ("/opt/lm", "/opt/lm/core/src", _repo, os.path.join(_repo, "core", "src")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)


def _add_spoke_venv():
    """Add an existing spoke's venv site-packages so `websockets` (and the rest
    of the client deps) import even when this is launched with the SYSTEM python
    — so you can just `python3 scripts/loadtest_spokes.py` on a spoke box."""
    # glob finds python*/site-packages folders inside each candidate venv.
    import glob
    # If websockets already imports, the current interpreter has what we need.
    try:
        import websockets  # noqa: F401 — already importable, nothing to do
        return
    except Exception:
        pass
    # Otherwise add the first spoke venv(s) found on this box.
    for base in ("/opt/lm/cs/venv", "/opt/lm/core/venv", "/opt/lm/venv"):
        for sp in glob.glob(os.path.join(base, "lib", "python*", "site-packages")):
            if os.path.isdir(sp) and sp not in sys.path:
                sys.path.insert(0, sp)


# Run the venv lookup at import time, before importing the control plane.
_add_spoke_venv()


def _load_env_file(path):
    """Best-effort parse of a spoke .env (KEY=VALUE lines) → dict."""
    # Parsed KEY -> VALUE pairs; a missing/unreadable file returns {}.
    out = {}
    try:
        with open(path) as f:
            # Skip blanks, comments and lines without "=".
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                # Split on the first "=" and strip whitespace and surrounding quotes from the value.
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out
# Import the real spoke client class, trying both package layouts.
BaseControlPlane = None
_imp_err = None
for _mod in ("core.src.messaging.control_plane", "messaging.control_plane"):
    try:
        BaseControlPlane = __import__(_mod, fromlist=["BaseControlPlane"]).BaseControlPlane
        break
    except Exception as e:  # pragma: no cover
        _imp_err = e
# Neither layout worked: this box lacks the lm core, so stop with a hint.
if BaseControlPlane is None:
    sys.exit("Cannot import BaseControlPlane — run on a box with /opt/lm/core "
             f"(e.g. PYTHONPATH=/opt/lm/core/src). Last error: {_imp_err}")


class LoadSpoke(BaseControlPlane):
    """A real spoke client with side-effects neutralised + a synthetic telemetry
    sender. One asyncio task per instance; hundreds run concurrently in-process."""

    # Pools of values used to generate plausible synthetic client records.
    _PLATFORMS = ("linux", "windows", "macos")
    _SSIDS = ("corp-wifi", "guest-wifi", "lab-5g", "eng-2g")
    _TIERS = ("t1", "t2", "t3")
    _NAMES = ("kbell", "ibennett", "xmendoza", "tstewart", "qwu", "jlee", "amorgan", "dkhan")

    def __init__(self, spoke_id, stats, rate, payload_bytes, clients_n=20, vms_n=3,
                 probe_rate=2.0, offender=False, defiant=False, **kw):
        """Configure one synthetic spoke.

        Args:
            spoke_id: unique id this spoke registers with.
            stats: shared counters dict updated by every spoke.
            rate: telemetry messages per second.
            payload_bytes: extra padding added to every telemetry message.
            clients_n / vms_n: size of the synthetic client and VM roster.
            probe_rate: must-process probe messages per second (0 disables).
            offender / defiant: mark the spoke as a high-rate sender / one that ignores slow-downs.
            **kw: passed to BaseControlPlane (hub_url, secret, onboarding PSK, tenant hint).
        """
        # Initialise the real client; report as a simulation (cs-like) module.
        super().__init__(spoke_id=spoke_id, **kw)
        self.module_type = "simulation"  # cs-like → exercises the telemetry path
        # Shared stats and the send rate (never below 0.01/s so the period stays finite).
        self._stats = stats
        self._rate = max(0.01, float(rate))
        # Per-spoke profile so the harness can prove OFFENDER-ONLY throttling:
        #   offender → sends at a high rate (should get throttled).
        #   defiant  → additionally IGNORES the slow-down signal (should get
        #              hard-dropped / quarantined if ddos_disconnect is on).
        # A well-behaved spoke (low rate, honors backpressure) must NOT be touched.
        self._offender = bool(offender)
        self._defiant = bool(defiant)
        self._probe_rate = max(0.0, float(probe_rate))
        self._probe_seq = 0               # monotonic per-spoke must-process seq
        # Padding string added to each telemetry message to raise payload size.
        self._pad = "x" * max(0, int(payload_bytes))
        # Stable synthetic roster: client + VM identities persist across cycles
        # like real clients (so the hub does dedup/cache/persist against a
        # consistent set); only volatile fields vary each cycle. This drives the
        # full CS_TELEMETRY path incl. the hub writing simulations_cache.json.
        # VM ids start at a per-spoke offset so different spokes do not share ids.
        self._vmbase = 90000 + (abs(hash(spoke_id)) % 9000)
        self._clients = [self._mk_client(i) for i in range(max(0, int(clients_n)))]
        self._vms = [self._mk_vm(i) for i in range(max(0, int(vms_n)))]
        # Cache the fully-signed serialized frame; rebuilding + json.dumps +
        # signing a large payload every message would bottleneck the GENERATOR
        # (one core) and STARVE the hub instead of stressing it.
        self._cached_frame = None
        self._cached_at = 0.0
        # Detach the base class's log-relay handler so hundreds of spokes do not ship their
        # logs to the hub and skew the measurement.
        try:
            import logging
            logging.getLogger().removeHandler(self._log_relay_handler)
        except Exception:
            pass

    def _mk_client(self, i):
        """Return a synthetic client record (index i) with stable identity fields."""
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
        """Return a synthetic running Proxmox VM record (index i)."""
        vmid = self._vmbase + i
        return {"vmid": vmid, "name": f"sim-{vmid}", "status": "running",
                "ostype": "l26", "type": "qemu"}

    def _build_telemetry_data(self):
        """Realistic CS_TELEMETRY body — a full clients/VM/USB snapshot so the hub
        runs its real ingest → fan-out → cache → persist (simulations_cache.json)
        path, not a no-op on an empty frame. Volatile fields vary each cycle."""
        # Refresh the volatile per-client fields for this cycle.
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        for c in self._clients:
            c["online"] = random.random() > 0.05
            c["last_seen"] = now_iso
            c["error_count"] = random.randint(0, 2)
        # A few fake USB devices (at most 4, one per VM).
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
        # Optional padding to raise the payload size.
        if self._pad:
            data["_pad"] = self._pad
        return data

    # ── neutralise side-effects (no disk writes for a throwaway spoke) ────────
    def _ensure_install_uuid(self):
        """Return a random in-memory install id instead of reading/writing .env."""
        return uuid.uuid4().hex           # in-memory only; never touch .env

    def _persist_session_secret(self, new_secret):  # no-op
        """Do not persist rotated session secrets (throwaway spoke)."""
        pass

    def _persist_hub_secret(self, new_secret):       # no-op
        """Do not persist the hub secret (throwaway spoke)."""
        pass

    def _touch_healthy_marker(self):                 # no-op (no marker files)
        """Do not create the healthy marker file."""
        pass

    def _clear_healthy_marker(self):                 # no-op
        """Do not remove a healthy marker file (none exists)."""
        pass

    async def handle_system_command(self, cmd_type, data):
        """Handle a hub system command, ignoring SPOKE_UPDATE so nothing is pulled or restarted."""
        # NEVER let a synthetic spoke act on SPOKE_UPDATE (it would git-pull
        # /opt/lm and restart). Everything else — crucially SPOKE_UPDATE_SESSION_KEY,
        # which rotates the signing key — flows to the real handler.
        if cmd_type == "SPOKE_UPDATE":
            return {"status": "SUCCESS", "message": "loadtest: SPOKE_UPDATE ignored"}
        return await super().handle_system_command(cmd_type, data)

    # ── honor the hub's slow-down signal by doing the merge work HERE ─────────
    def apply_backpressure(self, level, coalesce=False, min_interval_s=0.0):
        """Record the signal (base) + count that we received it, so the test can
        prove the control loop CLOSED (hub signalled → spoke honored). The actual
        conflation happens in the telemetry loop, which slows to
        ``self._bp_min_interval`` and MERGES the snapshots it skips (latest-wins)
        into the next send — this is the 'combine msg 1 & 2' behaviour, on the
        spoke, so the hub is relieved of the work."""
        # Let the base class record the level/interval, then count signals received.
        super().apply_backpressure(level, coalesce=coalesce, min_interval_s=min_interval_s)
        if level:
            self._stats["backoff_recv"] += 1
        else:
            self._stats["resume_recv"] += 1
        # A DEFIANT offender ignores the slow-down entirely (simulates a broken /
        # hostile spoke) — reset the interval so its send loop keeps blasting.
        # The hub should then hard-drop it and, with ddos_disconnect on, quarantine
        # it — while well-behaved spokes it never signalled are untouched.
        if self._defiant:
            self._bp_min_interval = 0.0

    # ── the load: signed CS_TELEMETRY (coalesce class) + must-process PROBE ───
    def _create_spoke_tasks(self, websocket):
        """Return the per-connection tasks: telemetry loop, plus the probe loop if enabled."""
        tasks = [asyncio.create_task(self._telemetry_loop(websocket))]
        if self._probe_rate > 0:
            tasks.append(asyncio.create_task(self._probe_loop(websocket)))
        return tasks

    async def _telemetry_loop(self, websocket):
        """Send signed CS_TELEMETRY at the configured rate, slowing down when the hub asks."""
        # Time between sends at the normal rate.
        base_period = 1.0 / self._rate
        # Send until cancelled or the connection fails.
        while True:
            try:
                now = time.time()
                # Reuse the cached signed frame; rebuild every 30s to pick up a
                # session-key rotation. A repeated message_id is fine — inbound
                # CS_TELEMETRY is a state snapshot, not ack-tracked/deduped by id,
                # and the hub still runs its full ingest/fan-out/cache/persist per
                # frame. This keeps the GENERATOR cheap so IT isn't the bottleneck.
                if self._cached_frame is None or (now - self._cached_at) > 30:
                    # Signed message envelope: header (id, time, sender, destination) and telemetry
                    # payload.
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()),
                                   "timestamp": round(now, 6),
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "CS_TELEMETRY",
                                    "data": self._build_telemetry_data()},
                    }
                    # New wire form <sig>.<body> (base _encode_frame) — matches
                    # the hub's verify-received-bytes path.
                    self._cached_frame = self._encode_frame(msg)
                    self._cached_at = now
                # Send the cached frame and count it.
                await websocket.send(self._cached_frame)
                self._stats["sent"] += 1
            # Cancellation must propagate so the task stops.
            except asyncio.CancelledError:
                raise
            # Send failed (connection dropped): count it and end; the reconnect loop restarts us.
            except Exception:
                self._stats["send_err"] += 1
                return  # let the reconnect loop take over
            # Under backpressure, slow to the hub-requested min interval and
            # ACCOUNT for the snapshots we merged away (latest-wins) — this ONE
            # send now represents `merged+1` ticks. That's the local coalescing
            # the hub asked for, measured so the test can show it happening.
            # Period requested by the hub's backpressure (or the base period).
            period = self._bp_send_interval(base_period)
            # Count how many sends were skipped/merged because of the slower period.
            if period > base_period:
                merged = int(period / base_period) - 1
                if merged > 0:
                    self._stats["coalesced_local"] += merged
            # Wait until the next send.
            await asyncio.sleep(period)

    async def _probe_loop(self, websocket):
        """Emit a low-rate MUST-PROCESS frame with a monotonic per-spoke seq. The
        hub counts these + detects gaps; the test asserts ZERO loss even while
        telemetry is being coalesced/shed — proving the ladder keeps must-process
        flowing. NOT throttled by backpressure (that's the whole point)."""
        # Time between probes; never slowed by backpressure.
        period = 1.0 / self._probe_rate
        while True:
            try:
                now = time.time()
                # Probe message carrying the next sequence number.
                msg = {
                    "header": {"message_id": str(uuid.uuid4()),
                               "timestamp": round(now, 6),
                               "sender_id": self.spoke_id, "destination_id": "hub"},
                    "payload": {"type": "LOADTEST_PROBE",
                                "data": {"seq": self._probe_seq}},
                }
                # Sign, send and advance the sequence counter.
                await websocket.send(self._encode_frame(msg))
                self._probe_seq += 1
                self._stats["probes_sent"] += 1
            # Cancellation must propagate.
            except asyncio.CancelledError:
                raise
            except Exception:
                return  # reconnect loop takes over; seq continues where it left off
            await asyncio.sleep(period)

    async def run_forever(self, stop_evt):
        """Minimal reconnect loop — like BaseControlPlane.run() but WITHOUT the
        updater worker (a synthetic spoke must not self-update)."""
        # Work out the actual hub URL (may involve discovery).
        await self._resolve_hub_url()
        # Reconnect back-off delay in seconds.
        delay = 1
        # Keep reconnecting until the run is stopped.
        while not stop_evt.is_set():
            t0 = time.time()
            # Connect, authenticate and serve until the connection ends; reset back-off after a
            # clean run.
            try:
                self._stats["connects"] += 1
                await self._connect_and_serve()
                delay = 1
            # Failure: count it. If the session lasted 30s+ retry soon; otherwise back off up to
            # 30s.
            except Exception:
                self._stats["conn_err"] += 1
                delay = 5 if (time.time() - t0) >= 30 else min(delay * 2, 30)
            # Wait before reconnecting unless the run is ending.
            if not stop_evt.is_set():
                await asyncio.sleep(delay)


def _fetch_status(status_url):
    """GET the hub /status JSON (self-signed cert accepted) and return it as a dict."""
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(status_url, timeout=5, context=ctx) as r:
        return json.loads(r.read().decode())


async def _monitor(status_url, stop_evt, interval, stats, total,
                   our_ids=None, offender_ids=None):
    """Print hub metrics every interval until stopped, then print pass/fail verification results.

    Args:
        status_url: hub /status URL.
        stop_evt: event set when the run ends.
        interval: seconds between samples.
        stats: shared client-side counters.
        total: number of synthetic spokes (for the summary line).
        our_ids / offender_ids: spoke ids in this run, and which of them are offenders.
    """
    # Peak values seen during the run, client "sent" count at the last sample, last metrics.
    peak = {"mps": 0.0, "cpu": 0.0, "mem": 0.0, "backlog": 0, "conns": 0, "lvl": 0}
    last_sent = 0
    last_m = {}
    # lvl = escalation level (0 normal / 1 offenders / 2 fleet); thr = spokes told
    # to slow down; coal = telemetry frames the HUB merged away (rung-3 safety).
    # Hub telemetry_*/probe counters are CUMULATIVE across runs — snapshot a
    # baseline so the end-of-test numbers reflect only THIS run.
    base = {"tr": 0, "tp": 0, "coal": 0, "probes": 0, "gaps": 0}
    # Baseline snapshot; if /status is unreachable, the baseline stays 0.
    try:
        _b = (await asyncio.to_thread(_fetch_status, status_url)).get("metrics", {}) or {}
        _bp0 = _b.get("backpressure", {}) or {}
        base["tr"] = int(_bp0.get("telemetry_received", 0) or 0)
        base["tp"] = int(_bp0.get("telemetry_processed", 0) or 0)
        base["coal"] = int(_bp0.get("telemetry_coalesced", 0) or 0)
        base["probes"] = sum(int(v) for v in (_b.get("probe_counts", {}) or {}).values())
        base["gaps"] = sum(int(v) for v in (_b.get("probe_gaps", {}) or {}).values())
    except Exception:
        pass
    # Table header for the periodic samples.
    print(f"\n{'t(s)':>5} {'conns':>6} {'client/s':>9} {'hub mps':>8} "
          f"{'cpu%':>6} {'mem%':>6} {'lvl':>3} {'thr':>4} {'hub-coal':>8}")
    print("-" * 72)
    t_start = time.time()
    # Sample until the run ends.
    while not stop_evt.is_set():
        await asyncio.sleep(interval)
        # Client-side send rate since the previous sample.
        elapsed = time.time() - t_start
        client_rate = (stats["sent"] - last_sent) / interval
        last_sent = stats["sent"]
        m = {}
        # Read hub metrics; -1 connections marks a failed fetch.
        try:
            data = await asyncio.to_thread(_fetch_status, status_url)
            m = data.get("metrics", {}) or {}
            conns = len(data.get("active_connections", []) or [])
            last_m = m
        except Exception:
            conns = -1
        # Pull the numbers we display; missing values count as 0.
        mps = float(m.get("mps", 0) or 0)
        cpu = float(m.get("cpu_util", 0) or 0)
        mem = float(m.get("mem_util", 0) or 0)
        backlog = int(m.get("backlog", 0) or 0)
        bp = m.get("backpressure", {}) or {}
        lvl = int(m.get("load_level", 0) or 0)
        thr = len(bp.get("spokes_throttled", []) or [])
        coal = int(bp.get("telemetry_coalesced", 0) or 0)
        # Track peaks.
        peak["mps"] = max(peak["mps"], mps); peak["cpu"] = max(peak["cpu"], cpu)
        peak["mem"] = max(peak["mem"], mem); peak["backlog"] = max(peak["backlog"], backlog)
        peak["conns"] = max(peak["conns"], conns); peak["lvl"] = max(peak["lvl"], lvl)
        # One table row per sample.
        print(f"{elapsed:5.0f} {conns:6d} {client_rate:9.0f} {mps:8.0f} "
              f"{cpu:6.1f} {mem:6.1f} {lvl:3d} {thr:4d} {coal:8d}")
    # End-of-run summary of peaks and client counters.
    print("-" * 72)
    print(f"PEAK: conns={peak['conns']} hub_mps={peak['mps']:.0f} "
          f"cpu={peak['cpu']:.1f}% mem={peak['mem']:.1f}% backlog={peak['backlog']} "
          f"max_level={peak['lvl']}")
    print(f"client sent telemetry={stats['sent']} probes={stats['probes_sent']} "
          f"send_err={stats['send_err']} conn_err={stats['conn_err']} (target {total} spokes)")

    # ── VERIFICATION: prove the ladder did the RIGHT thing, not just survive ──
    print("\n=== backpressure verification ===")
    # Final hub metrics, minus the baseline, for the checks below.
    bp = (last_m.get("backpressure", {}) or {})
    probe_counts = (last_m.get("probe_counts", {}) or {})
    probe_gaps = (last_m.get("probe_gaps", {}) or {})
    hub_probes = sum(int(v) for v in probe_counts.values()) - base["probes"]
    gap_total = sum(int(v) for v in probe_gaps.values()) - base["gaps"]

    # 1. Throttling engaged? (hub reached rung 1/2 AND spokes received the signal)
    engaged = (peak["lvl"] > 0) or (stats["backoff_recv"] > 0)
    print(f"[{'PASS' if engaged else 'n/a '}] throttling triggered — "
          f"max escalation level {peak['lvl']} "
          f"({'offenders' if peak['lvl'] == 1 else 'fleet' if peak['lvl'] >= 2 else 'none'}); "
          f"spokes honored slow-down {stats['backoff_recv']}x, resumed {stats['resume_recv']}x")

    # 2. Spoke did the work locally? (frames merged on the spoke before sending)
    hub_coal = int(bp.get("telemetry_coalesced", 0)) - base["coal"]
    print(f"[{'PASS' if stats['coalesced_local'] else 'n/a '}] spoke coalesced LOCALLY — "
          f"{stats['coalesced_local']} telemetry snapshots merged on the spokes; "
          f"hub also merged {hub_coal} (rung-3 safety)")

    # 3. Must-process survived? (zero probe gaps — the hard assertion)
    if stats["probes_sent"] == 0:
        print("[n/a ] must-process probe disabled (--probe-rate 0)")
    elif gap_total == 0 and hub_probes > 0:
        print(f"[PASS] must-process ZERO loss — hub received {hub_probes} probes, "
              f"0 seq gaps across {len(probe_counts)} spokes (sent ~{stats['probes_sent']})")
    else:
        print(f"[FAIL] must-process LOSS — {gap_total} seq gaps detected "
              f"(hub received {hub_probes}, spokes sent {stats['probes_sent']}); "
              f"gapped spokes: {list(probe_gaps)[:5]}")
    # Telemetry (coalesce class) is ALLOWED to gap — that's the point. Report the
    # ratio so it's visible the hub processed fewer than it received under load.
    tr = int(bp.get("telemetry_received", 0)) - base["tr"]
    tp = int(bp.get("telemetry_processed", 0)) - base["tp"]
    if tr > 0:
        print(f"[info] telemetry received={tr} processed={tp} "
              f"({100.0 * tp / tr:.0f}% — coalescing expected under load, not loss)")

    # 4. OFFENDER-ONLY: with a mixed fleet, prove the hub throttled/quarantined the
    #    offenders and left the WELL-BEHAVED spokes untouched (no throttle, no drops).
    if offender_ids:
        # Split our spokes into offenders and well-behaved ones.
        our_ids = our_ids or set()
        good_ids = our_ids - offender_ids
        # Hub's view: currently throttled spokes, quarantined spokes, and per-spoke drop counts.
        levels = (bp.get("spoke_levels", {}) or {})          # sid -> level (throttled now)
        quarantined = set(bp.get("quarantined", []) or [])
        drops = (last_m.get("rate_limit_drops", {}) or {})
        def _hit(sid):   # throttled, quarantined, or actively dropped
            """Return True if the hub throttled, quarantined or dropped messages from spoke sid."""
            return sid in levels or sid in quarantined or int(drops.get(sid, 0) or 0) > 0
        # Which offenders and which well-behaved spokes were affected.
        off_hit = sorted(s for s in offender_ids if _hit(s))
        good_hit = sorted(s for s in good_ids if _hit(s))
        # Offenders should be hit; well-behaved spokes should not.
        print(f"\n=== offender-only targeting ({len(offender_ids)} offenders / "
              f"{len(good_ids)} well-behaved) ===")
        print(f"[{'PASS' if off_hit else 'FAIL'}] offenders throttled/quarantined: "
              f"{len(off_hit)}/{len(offender_ids)}"
              + (f" (quarantined {len([s for s in off_hit if s in quarantined])})" if quarantined else ""))
        if not good_hit:
            print(f"[PASS] well-behaved spokes UNTOUCHED — 0/{len(good_ids)} throttled or dropped")
        else:
            print(f"[FAIL] {len(good_hit)}/{len(good_ids)} WELL-BEHAVED spokes were throttled/dropped "
                  f"(should be 0): {good_hit[:8]}"
                  + ("  ← likely PROTECT shedding everyone: lower the load or raise offender rate so "
                     "the ladder isolates offenders before protect trips" if peak["lvl"] >= 3 else ""))


async def main():
    """Parse arguments, start the synthetic spokes and monitor, run for the duration, then stop."""
    # Command-line options (see each help text).
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
    ap.add_argument("--probe-rate", type=float, default=2.0,
                    help="must-process LOADTEST_PROBE msg/s PER spoke (seq-tracked; hub asserts zero loss). 0 disables.")
    ap.add_argument("--offenders", type=int, default=0,
                    help="how many spokes are OFFENDERS (high rate). The rest are well-behaved (--rate). "
                         "Spread evenly across the fleet. Proves offender-ONLY throttling: only these should be throttled.")
    ap.add_argument("--offender-rate", type=float, default=100.0,
                    help="telemetry msg/s for offender spokes (should exceed the hub's per-spoke offender mark).")
    ap.add_argument("--offender-defiant", action="store_true",
                    help="offenders IGNORE the slow-down signal (simulate a hostile spoke) → hub should hard-drop + quarantine them.")
    ap.add_argument("--psk", default="", help="tenant onboarding PSK (auto-approves the spokes)")
    ap.add_argument("--tenant", default="", help="tenant id hint (with --psk)")
    ap.add_argument("--secret", default="", help="pre-provisioned spoke secret (else zero-touch)")
    ap.add_argument("--prefix", default="loadtest-", help="spoke id prefix (for cleanup)")
    ap.add_argument("--tag", default="", help="uniquifier folded into each id (default: this box's hostname) — keeps ids unique when running the harness on several boxes at once")
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

    # Hub status endpoint derived from the hub WebSocket URL unless given explicitly.
    status_url = args.status_url or (
        args.hub.replace("wss://", "https://").replace("ws://", "http://").rstrip("/") + "/status")

    # Counters shared by all spokes, and the event that stops the run.
    stats = {"sent": 0, "send_err": 0, "connects": 0, "conn_err": 0,
             "probes_sent": 0, "coalesced_local": 0,
             "backoff_recv": 0, "resume_recv": 0}
    stop_evt = asyncio.Event()

    # Fold this box's hostname (or --tag) into every id so running the harness on
    # all 4 spoke boxes at once produces UNIQUE spoke ids (colliding ids would
    # mutual-evict on the hub). Purge still matches on the --prefix.
    tag = (args.tag or socket.gethostname().split(".")[0] or "gen").strip()
    # Pick which indices are offenders — spread evenly across the fleet (not
    # clustered) so throttling one doesn't just look like "first N".
    n_off = max(0, min(int(args.offenders), args.count))
    # Offender indices spaced "stride" apart across the fleet.
    offender_idx = set()
    if n_off:
        stride = args.count / n_off
        offender_idx = {int(k * stride) for k in range(n_off)}
    # Build every synthetic spoke; offenders get the high rate (and maybe defiance).
    spokes = []
    offender_ids = set()
    for i in range(args.count):
        sid = f"{args.prefix}{tag}-{i:05d}"
        is_off = i in offender_idx
        if is_off:
            offender_ids.add(sid)
        spokes.append(LoadSpoke(
            spoke_id=sid, stats=stats,
            rate=(args.offender_rate if is_off else args.rate),
            payload_bytes=args.payload_bytes, clients_n=args.clients_per_spoke,
            vms_n=args.vms_per_spoke, probe_rate=args.probe_rate,
            offender=is_off, defiant=(is_off and args.offender_defiant),
            hub_url=args.hub, secret=(args.secret or None),
            onboarding_psk=(args.psk or None), tenant_id_hint=(args.tenant or None),
        ))

    # Describe the run before starting.
    if n_off:
        print(f"Load test: {args.count} spokes → {args.hub} — {n_off} OFFENDERS @ "
              f"{args.offender_rate} msg/s{' (DEFIANT)' if args.offender_defiant else ''} + "
              f"{args.count - n_off} well-behaved @ {args.rate} msg/s. "
              f"{args.duration}s, ramp {args.ramp}s. Expect: ONLY the {n_off} offenders throttled.")
    else:
        print(f"Load test: {args.count} spokes → {args.hub} @ {args.rate} msg/s each "
              f"(~{args.count * args.rate:.0f} msg/s aggregate), {args.duration}s, "
              f"ramp {args.ramp}s. Status: {status_url}")

    # Start the spokes, spaced "per" seconds apart so the ramp lasts --ramp seconds.
    tasks = []
    per = args.ramp / max(1, args.count)
    for s in spokes:
        tasks.append(asyncio.create_task(s.run_forever(stop_evt)))
        if per > 0:
            await asyncio.sleep(per)

    # Start the monitor, run for the requested time, then stop everything.
    mon = asyncio.create_task(_monitor(status_url, stop_evt, args.sample_interval, stats, args.count,
                                       our_ids={s.spoke_id for s in spokes}, offender_ids=offender_ids))
    await asyncio.sleep(args.duration)
    stop_evt.set()
    # Cancel the spoke tasks and wait for them, ignoring their cancellation errors.
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    # Wait for the monitor to print its final verification.
    await mon
    # Print cleanup instructions for the synthetic spokes left in hub state.
    print(f"\nDone. Clean up synthetic spokes (prefix '{args.prefix}') from "
          f"Setup → Spokes & Agents, or: for i in $(seq 0 {args.count-1}); do "
          f"curl -sk -X DELETE https://HOST/setup/spokes/{args.prefix}$(printf %05d $i); done")


# Run main(); Ctrl-C exits quietly.
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
