"""Console role spoke — serial console access for lm.

A ``BaseSpoke`` loaded IN-REPO by the generic agent (``_ROLE_MAP`` repo_url=None,
module_type "console"). It enumerates the host's serial ports, relays an
interactive byte stream to the hub (browser xterm.js over the hub↔spoke WS), and
(Phase F) auto-identifies attached devices. This module owns the CONSOLE_*
command envelope that the hub relay + WebUI build on.

Byte relay: keystrokes arrive as ``CONSOLE_DATA`` (fire-and-forget) and are
written to the serial handle; device output is pushed up unsolicited as
``CONSOLE_DATA_UP`` via ``self.control_plane.send_to_hub`` — the reader runs in a
thread, so it schedules that coroutine back onto the event loop.
"""
# asyncio: event loop and locks; base64: byte payloads; logging.
import asyncio
import base64
import logging
# os: env overrides; time: timestamps and back-off timers.
import os
import time
# Path for state files; typing helpers.
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Spoke base class, from whichever layout is installed.
try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

# Serial, fingerprint and DPA helpers, imported flat or relative to this package.
try:
    from serial_manager import (
        PortStore, HealthStore, PortChannel, SessionManager, enumerate_ports, detect_baud,
        open_raw, DEFAULT_BAUD_CANDIDATES, DEFAULT_BAUD, score_sample, device_cache,
    )
    from fingerprint import (run_identify, read_running_config, push_config, PROFILES,
                             passive_identify, run_commands, merge_credentials,
                             sanitize_console_text, _extract_profile_fields, prompt_hostname,
                             looks_like_prompt, boot_fault, current_boot_fault, is_recovery_prompt,
                             count_line_reconnects, set_patience,
                             check_line_responsive, FACTORY_DEFAULT_CREDENTIALS,
                             os_up_marker, scrub_identity, vendor_should_replace, vendor_is_upgrade,
                             is_cx_misfiled_as_procurve, detect_vendor, is_placeholder_hostname)
    from dpa import DpaManager
    from dpa_config import DpaConfigStore, detect_advertise_host
    import dpa_ssh
except ImportError:  # loaded as a package (agent role loader) or from repo root
    from .serial_manager import (  # type: ignore
        PortStore, HealthStore, PortChannel, SessionManager, enumerate_ports, detect_baud,
        open_raw, DEFAULT_BAUD_CANDIDATES, DEFAULT_BAUD, score_sample, device_cache,
    )
    from .fingerprint import (run_identify, read_running_config, push_config, PROFILES,  # type: ignore
                              passive_identify, run_commands, merge_credentials,
                              sanitize_console_text, _extract_profile_fields, prompt_hostname,
                              looks_like_prompt, boot_fault, current_boot_fault, is_recovery_prompt,
                              count_line_reconnects, set_patience,
                              check_line_responsive, FACTORY_DEFAULT_CREDENTIALS,
                              os_up_marker, scrub_identity, vendor_should_replace, vendor_is_upgrade,
                              is_cx_misfiled_as_procurve, detect_vendor, is_placeholder_hostname)
    from .dpa import DpaManager  # type: ignore
    from .dpa_config import DpaConfigStore, detect_advertise_host  # type: ignore
    from . import dpa_ssh  # type: ignore

# Module logger.
logger = logging.getLogger("ConsoleSpoke")


def _real_hostname(value: Any) -> str:
    """``value`` stripped, or '' if empty or a placeholder/factory-default name."""
    # Strip, then blank out placeholder names.
    h = str(value or "").strip()
    return "" if is_placeholder_hostname(h) else h


class ConsoleSpoke(BaseSpoke):
    """Serial console spoke.

    Commands:
      CONSOLE_LIST_PORTS   — inventory (ports + settings + probe + in-use)
      CONSOLE_GET_SETTINGS — per-port settings
      CONSOLE_SET_SETTINGS — set baud/bytesize/parity/stopbits/flow
      CONSOLE_SET_ALIAS    — friendly name
      CONSOLE_DETECT_BAUD  — sweep + lock the baud rate (decision #5)
      CONSOLE_OPEN         — open a session (writer lock or read-only observer)
      CONSOLE_DATA         — write keystrokes (fire-and-forget)
      CONSOLE_SEND_BREAK   — serial BREAK (ROMMON etc.)
      CONSOLE_RESIZE       — no-op (serial has no window size)
      CONSOLE_CLOSE        — tear down a session + release the writer lock
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Set up stores, session manager, probe state, health records and DPA state.

        Args:
            spoke_id: this spoke's id.
            config: role configuration (patience, credentials, LLM and DPA options).
        """
        # Base set-up.
        super().__init__(spoke_id, config)
        # Set by RoleConnection after registration so the reader thread can push
        # CONSOLE_DATA_UP frames to the hub (mirrors the LE/GenericAgent pattern).
        self.control_plane = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Per-port settings and the device-identity cache.
        self.store = PortStore()
        # Device-identity-keyed warm cache (survives a port_id derivation change
        # or a "lame" cable moved to a different physical port — see
        # DeviceCache's docstring). Process-wide singleton so every ConsoleSpoke
        # instance on this host shares one devices.json.
        self.devices = device_cache()
        # Live serial sessions; device output goes to _on_serial_data.
        self.sessions = SessionManager(on_data=self._on_serial_data)
        # Serial-port enumeration cache. enumerate_ports() calls pyserial
        # comports() + a sysfs walk, which BLOCKS and — on a host with a wedged
        # USB-serial adapter — can stall for many seconds. Running it directly on
        # the asyncio loop froze the whole spoke (heartbeats + every CONSOLE_*
        # command), so CONSOLE_LIST_PORTS blew past the hub's 15s timeout and the
        # console "errored out". Enumeration is now always offloaded off-loop (via
        # asyncio.to_thread / the monitor thread); the cache holds the last result
        # so the synchronous helpers never touch the bus on the event loop.
        self._ports_cache: Optional[List[Dict[str, Any]]] = None
        self._ports_cache_ts: float = 0.0
        self._enum_lock: Optional[asyncio.Lock] = None
        # Auto-identify (fingerprint) state. Credentials are pushed (signed) by
        # the hub via CONSOLE_SET_CREDENTIALS and held in memory only (never
        # logged/persisted). The background loop probes each newly-seen port once.
        self._credentials: list = []
        # How long the fingerprinter waits for a device to answer. Serial gear
        # varies wildly (a loaded chassis can pause several seconds mid-reply),
        # and being impatient reports a healthy switch as "unknown", so the
        # defaults are already generous — this only exists for sites with gear
        # that is slower still. Applied process-wide because fingerprint's
        # windows are module constants.
        # Probe timing scale and auto-probe bookkeeping.
        set_patience(config.get("console_probe_patience", 1.0))
        self._autoprobe_task = None
        self._probe_attempts: Dict[str, float] = {}  # port_id → last attempt (monotonic)
        self._probe_delay: Dict[str, float] = {}      # port_id → current login-retry backoff (s)
        self._probe_fails: Dict[str, int] = {}        # port_id → consecutive failed identify attempts
        self._seen_ports: set = set()                 # port_ids seen last scan (for first-seen detection)
        self._probing: set = set()
        # port_id → last time an ALREADY-identified port was actively re-checked
        # (monotonic). In-memory only (not persisted) so it starts empty every
        # process lifetime — a restart/reboot therefore always re-verifies every
        # previously-known port on its first scan, since a reboot can reshuffle
        # port_ids. See _reverify_due.
        self._identify_verify_ts: Dict[str, float] = {}
        # Boot watcher: per-port last-observed capture byte count (to spot NEW
        # output between scans) and last baud-relock attempt (monotonic), so we
        # don't re-sweep a garbled line every cycle. Boot state itself lives in
        # ``self._health[pid]["boot"]``.
        self._mon_bytes: Dict[str, int] = {}
        self._mon_new_at: Dict[str, float] = {}
        self._baud_relock_at: Dict[str, float] = {}
        # Boot watcher: last time we actively nudged a port that LOOKED stuck to
        # confirm it (wall-clock time.time()), so a chatty device isn't re-poked
        # every scan.
        self._boot_nudge_at: Dict[str, float] = {}
        # Ports that have a confirming nudge dispatched but not yet resolved; the
        # watcher defers (never marks stuck) while one is pending.
        self._boot_nudge_pending: set = set()
        # Passive monitor: keep a read-only serial handle open per port so we
        # capture whatever a device emits even with NO user attached, and glean
        # identity from it opportunistically (config console_monitor, default on).
        self._monitor_task = None
        # Ports the automated system currently can't even OPEN (faulty/non-real
        # /dev/ttyS* → "Could not configure port", I/O error, etc.). Hidden from
        # the UI so operators never see a broken port or its raw error — but we
        # keep probing, so one that starts working reappears on its own.
        self._unopenable: Dict[str, Dict[str, Any]] = {}  # port_id → {error, since}
        # Per-port failure/disconnect history for the diagnostics report: open
        # failures (faulty/non-real ports), reader deaths (device pulled), and
        # recovery cycles (flapping). PERSISTED to disk (health.json) and
        # rehydrated here, so a service restart keeps the history an operator
        # needs to spot a flapping port instead of starting empty.
        # Persistent health records.
        self._health_store = HealthStore()
        self._health: Dict[str, Dict[str, Any]] = self._health_store.load()
        # Direct Port Access (DPA): per-port SSH (and optional telnet) terminal
        # server. OFF by default; the knob is persisted on this host (dpa.json,
        # see dpa_config.py) and changed live via CONSOLE_SET_DPA. Bytes for a
        # DPA session go to a local sink (the TCP client), not to the hub.
        # Local DPA session sinks, DPA config and listener state.
        self._local_sinks: Dict[str, Any] = {}  # session_id → callable(bytes)
        self._dpa_cfg = DpaConfigStore(self.store.path.parent / "dpa.json", config)
        self._dpa: Optional[DpaManager] = None      # telnet transport
        self._dpa_ssh: Optional[DpaManager] = None  # ssh transport
        self._dpa_ssh_status: Dict[str, Any] = {"available": None, "error": None,
                                                "fingerprint": None}
        self._dpa_advertise_auto = ""
        self._dpa_task = None
        self._dpa_applied = False
        self._dpa_apply_lock: Optional[asyncio.Lock] = None

    # ── reader-thread → hub bridge ────────────────────────────────────────────
    def _on_serial_data(self, session_id: str, data: bytes) -> None:
        """Called from a PortChannel reader THREAD. Schedule the unsolicited push
        back onto the event loop (send_to_hub is a coroutine)."""
        # Control plane and loop for pushing data up.
        cp, loop = self.control_plane, self._loop
        # DPA: a local TCP client owns this session — deliver bytes to its sink
        # (empty read == serial EOF) and skip the hub push entirely.
        sink = self._local_sinks.get(session_id)
        # Local DPA sink: hand it the bytes and stop.
        if sink is not None:
            try:
                sink(data)
            except Exception as e:  # noqa: BLE001
                logger.debug("DPA sink %s failed: %s", session_id, e)
            return
        # No way to push yet.
        if cp is None or loop is None:
            return
        # Data goes up as CONSOLE_DATA_UP; an empty read means the port closed.
        if data:
            ptype = "CONSOLE_DATA_UP"
            payload = {"session_id": session_id, "data": base64.b64encode(data).decode()}
        else:
            # Empty read → the device/handle went away; tell the browser leg.
            ptype = "CONSOLE_ERROR"
            payload = {"session_id": session_id, "error": "serial read ended"}

        async def _push():
            """Send the frame via the edge proxy if one owns the session, else to the hub."""
            # Phase 2: if an edge proxy owns this session, deliver straight to it
            # (hub out of the byte path); otherwise up to the hub → browser (normal).
            routed = False
            if hasattr(cp, "_route_console_up"):
                try:
                    routed = await cp._route_console_up(ptype, payload)
                except Exception:  # noqa: BLE001
                    routed = False
            if not routed:
                await cp.send_to_hub(ptype, payload)

        # Run the push on the event loop from this reader thread.
        try:
            asyncio.run_coroutine_threadsafe(_push(), loop)
        except Exception as e:  # noqa: BLE001
            logger.debug("push %s failed: %s", ptype, e)

    async def _serial_relay_down(self, cmd: str, data: Dict[str, Any]) -> None:
        """DOWN frames from an edge-proxy relay leg → the local serial port (serial
        has NO agent, so the console spoke is the endpoint). CONSOLE_DATA writes
        bytes; CONSOLE_CLOSE closes the session."""
        # Need a session id.
        sid = data.get("session_id")
        if not sid:
            return
        # Data: decode and write to the port.
        if cmd == "CONSOLE_DATA":
            raw = data.get("data", "")
            try:
                payload = base64.b64decode(raw) if raw else b""
            except Exception:  # noqa: BLE001
                return
            self.sessions.write(sid, payload)
        # Close: end the session.
        elif cmd == "CONSOLE_CLOSE":
            self.sessions.close(sid)

    def _enumerate_ports_sync(self) -> List[Dict[str, Any]]:
        """Blocking serial enumeration + cache refresh. MUST run off the event
        loop (worker thread) — see the cache note in __init__."""
        # Enumerate, cache with a timestamp, return.
        ports = enumerate_ports()
        self._ports_cache = ports
        self._ports_cache_ts = time.monotonic()
        return ports

    async def _enumerate_ports(self, max_age: float = 0.0) -> List[Dict[str, Any]]:
        """Serial-port inventory WITHOUT blocking the event loop. pyserial's
        ``comports()`` blocks (and, on a host with a wedged USB-serial adapter,
        can stall for many seconds), so the actual enumeration is offloaded to a
        worker thread via ``asyncio.to_thread`` — a hung bus can slow *this*
        request but can never freeze the spoke's asyncio loop (heartbeats + every
        other CONSOLE_* command), which is what made CONSOLE_LIST_PORTS blow past
        the hub's 15s timeout. Defaults to always-fresh (``max_age=0``); pass a
        ``max_age`` to accept a recent cached result and coalesce bursts. The
        result is stashed in ``self._ports_cache`` for the sync helpers.

        A concurrent enumeration is serialised (never two ``comports()`` on the
        bus at once); a waiter that acquires the lock after a just-completed fresh
        enumeration reuses it."""
        # Fresh enough cache: use it.
        if self._ports_cache is not None and (time.monotonic() - self._ports_cache_ts) <= max_age:
            return self._ports_cache
        # Create the lock on first use (inside the loop).
        if self._enum_lock is None:
            self._enum_lock = asyncio.Lock()
        # One enumeration at a time; re-check the cache after waiting.
        async with self._enum_lock:
            if self._ports_cache is not None and (time.monotonic() - self._ports_cache_ts) <= max_age:
                return self._ports_cache
            return await asyncio.to_thread(self._enumerate_ports_sync)

    def _enum_cached(self) -> List[Dict[str, Any]]:
        """Last-known port list from the warm cache, without touching the serial
        bus. Falls back to a one-off blocking enumeration only on a cold start
        (cache never populated yet) — safe because that only happens before the
        first list/monitor cycle."""
        # Use the cache if we have one.
        if self._ports_cache is not None:
            return self._ports_cache
        return self._enumerate_ports_sync()

    def _dpa_ports(self) -> List[Dict[str, Any]]:
        """Ports that get a DPA listener: the same set the port list shows, so a
        dead built-in UART that can't be opened gets no listener."""
        # Skip unopenable ports unless a user is on them.
        return [p for p in self._enum_cached()
                if p["port_id"] not in self._unopenable
                or self.sessions.has_user_sessions(p["port_id"])]

    def _port_device(self, port_id: str) -> Optional[str]:
        """Return the device path for a port id, or None."""
        # Look the port up in the cached list.
        for p in self._enum_cached():
            if p["port_id"] == port_id:
                return p["device"]
        return None

    def _port_product(self, port_id: str) -> str:
        """The USB/adapter product string for a port (e.g. 'USB Serial
        Controller') — a friendlier fallback name than the raw port id."""
        # Look the port up in the cached list.
        for p in self._enum_cached():
            if p["port_id"] == port_id:
                return (p.get("product") or "").strip()
        return ""

    # ── command dispatch ──────────────────────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one CONSOLE_* (or GET_VERSION) command from the hub and return its reply."""
        # Normalise the command and make sure the background loops are running.
        cmd = command_type.upper()
        self._ensure_autoprobe_task()  # start the fully-automatic identify loop once
        self._ensure_monitor_task()    # start the passive keep-alive capture loop once
        self._ensure_dpa_task()        # start the Direct Port Access listeners (if enabled)

        # Version query.
        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        # Port inventory with saved settings, probe data and live state.
        if cmd == "CONSOLE_LIST_PORTS":
            ports = []
            # Hide unopenable ports unless a user is on them.
            for p in await self._enumerate_ports():
                pid = p["port_id"]
                # Hide ports the automated system can't open (faulty/non-real
                # serial devices) so the operator never sees a broken port or its
                # raw error — unless a live session is somehow attached to it.
                if pid in self._unopenable and not self.sessions.has_user_sessions(pid):
                    continue
                # Saved record and live state.
                saved = self.store.get(pid)
                snap = self.sessions.snapshot(pid)
                ports.append({
                    **p,
                    "alias": saved.get("alias", ""),
                    "tenant_id": saved.get("tenant_id", ""),  # per-port override; hub fills effective
                    "settings": self.store.settings(pid),
                    "probe": saved.get("probe", {}),
                    "in_use": snap["has_user"],          # a HUMAN/relay is attached (not the monitor)
                    "writer": snap["writer"],
                    "monitoring": snap["monitoring"],    # passive keep-alive capture is holding the port
                    "last_activity": snap["last_activity"],  # epoch of last byte seen (0 = never)
                    "capture_bytes": snap["capture_bytes"],  # total bytes captured (persisted across restarts)
                    "pending_out": snap["pending_out"],  # bytes of a paste still draining
                    "dpa": self._dpa_info(pid),          # Direct Port Access endpoint (None if off)
                    "boot": self._boot_info(pid),        # boot/wake cycle status (None if never seen)
                    "present": True,                     # physically enumerated right now
                })
            # A port that isn't physically enumerated right now is just gone from
            # this list — no ghost/offline row. Its alias/identity stays in the
            # store and reattaches automatically if the same DEVICE reappears
            # under a new port_id (see the reconcile step in _emit_probe_result);
            # it never lingers here as a stale duplicate.
            # Return the list.
            return {"status": "SUCCESS", "ports": ports}

        # Recorded output for a port.
        if cmd == "CONSOLE_GET_CAPTURE":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            # Live channel and requested size (default: in-memory capture size).
            chan = self.sessions.channel(pid)
            try:
                limit = int(data.get("bytes") or 0) or None
            except (TypeError, ValueError):
                limit = None
            # Bound an unlimited request: the durable log holds up to 5 MiB, but
            # this view previously served the 64 KiB in-memory tail — keep that
            # envelope size so an unbounded read can't flood the hub leg.
            limit = limit or PortChannel.CAPTURE_MAX
            # Prefer the DURABLE on-disk recording: the live in-memory tail is
            # empty right after a service restart, which made the capture view go
            # blank even though the full 5 MiB log was sitting on disk.
            # Live channel tail, else the disk log, else the last stored banner; strip escapes.
            text = chan.persisted_tail(limit).decode("utf-8", "replace") if chan else ""
            if not text:  # no live channel — read the persistent log directly
                text = self.sessions.persisted_capture(pid, limit).decode("utf-8", "replace")
            if not text:  # nothing recorded — fall back to the last stored banner
                text = (self.store.get(pid).get("probe") or {}).get("banner", "")
            text = sanitize_console_text(text)  # strip VT100/ANSI for readable view + LLM
            # Reply with the text and live counters.
            snap = self.sessions.snapshot(pid)
            return {"status": "SUCCESS", "port_id": pid, "capture": text,
                    "monitoring": snap["monitoring"], "last_activity": snap["last_activity"],
                    "capture_bytes": snap["capture_bytes"]}


        # Per-port health report.
        if cmd == "CONSOLE_DIAGNOSTICS":
            # Serial-connection health report: ports that keep failing to open
            # (faulty/non-real), get disconnected (device pulled), or flap.
            return {"status": "SUCCESS", "spoke_id": self.spoke_id,
                    "generated": time.time(), "summary": self._diagnostics_summary(),
                    "diagnostics": self._diagnostics()}

        # Clear all health records.
        if cmd == "CONSOLE_DIAGNOSTICS_PURGE":
            # Wipe ALL collected serial-health / identify telemetry for this spoke.
            # Only accumulated history is cleared (failure/disconnect counts,
            # identify attempts, transcript tails); live "currently failing" state
            # re-derives on the next probe cycle, so nothing operational is lost.
            n = len(self._health)
            self._health.clear()
            self._health_store.clear()
            logger.info("console: purged diagnostics telemetry for %d port(s)", n)
            return {"status": "SUCCESS", "spoke_id": self.spoke_id, "purged": n}

        # Read a port's line settings.
        if cmd == "CONSOLE_GET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            return {"status": "SUCCESS", "port_id": pid, "settings": self.store.settings(pid)}

        # Update a port's line settings.
        if cmd == "CONSOLE_SET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            # Keep only known setting keys.
            fields = {k: data[k] for k in ("baud", "bytesize", "parity", "stopbits", "flow",
                                           "paste_line_delay_ms", "paste_chunk", "paste_char_delay_ms")
                      if k in data}
            self.store.update(pid, settings=fields)
            # An explicit baud pins the rate so auto-detect leaves it alone.
            if "baud" in fields:
                # An operator-chosen rate is authoritative: pin it so a later
                # auto-detect/boot relock can never roll the port back.
                self.store.update(pid, probe={"baud_pinned": True, "baud_confident": True,
                                              "detected_baud": int(fields["baud"])})
            return {"status": "SUCCESS", "port_id": pid, "settings": self.store.settings(pid)}

        # Set a port's friendly name.
        if cmd == "CONSOLE_SET_ALIAS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            self.store.update(pid, alias=data.get("alias", ""))
            return {"status": "SUCCESS", "port_id": pid, "alias": data.get("alias", "")}

        # Set a port's tenant override.
        if cmd == "CONSOLE_SET_TENANT":
            # Per-PORT tenant override (a single console host can serve ports to
            # different tenants). Empty tenant_id clears the override so the port
            # falls back to the agent's tenant (resolved hub-side).
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            self.store.update(pid, tenant_id=data.get("tenant_id", ""))
            return {"status": "SUCCESS", "port_id": pid, "tenant_id": data.get("tenant_id", "")}

        # Replace the auto-identify credential list.
        if cmd == "CONSOLE_SET_CREDENTIALS":
            # Global credential list, pushed (signed) by the hub. In memory only;
            # never logged or persisted. Order = attempt order for auto-login.
            creds = data.get("credentials") or []
            self._credentials = [{"username": c.get("username", ""), "password": c.get("password", "")}
                                 for c in creds if isinstance(c, dict)]
            logger.info("console: loaded %d credential(s) for auto-identify", len(self._credentials))
            return {"status": "SUCCESS", "count": len(self._credentials)}

        # Turn LLM-assisted identify on or off.
        if cmd == "CONSOLE_SET_LLM_IDENTIFY":
            # Runtime toggle for LLM-driven identify (pushed by the hub when an
            # admin flips the UI switch), so it can be enabled without restarting
            # the agent to change static config.
            enabled = bool(data.get("enabled"))
            self.config["console_llm_identify"] = enabled
            logger.info("console: LLM-assisted identify %s", "enabled" if enabled else "disabled")
            return {"status": "SUCCESS", "enabled": enabled}

        # Show the DPA config and status.
        if cmd == "CONSOLE_GET_DPA":
            return {"status": "SUCCESS", **self._dpa_describe()}

        # Update the DPA config and apply it.
        if cmd == "CONSOLE_SET_DPA":
            # Runtime DPA knob (Console page → Direct Port Access). Persisted on
            # this host so it survives agent restarts; applied immediately.
            ok, err = self._dpa_cfg.update(data or {})
            if not ok:
                return {"status": "ERROR", "message": err}
            logger.info("console: DPA config updated (enabled=%s)", self._dpa_cfg.effective()["enabled"])
            await self._dpa_apply()
            self._ensure_dpa_task()  # hot-plug reconcile loop (no-op if off/running)
            return {"status": "SUCCESS", **self._dpa_describe()}

        # Set one port's DPA options.
        if cmd == "CONSOLE_SET_DPA_PORT":
            # Per-serial-port TCP port override (null/"" clears → auto-assign).
            return await self._dpa_set_port(data or {})

        # Run an identify now on a free port.
        if cmd == "CONSOLE_AUTOPROBE":
            # Port must exist and be free.
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            # Identify with exclusive access, record the result and send it up.
            res = await self._exclusive_probe(pid, self._identify_blocking, pid, dev)
            self._record_identify_telemetry(pid, res, method="login")
            await self._emit_probe_result(pid, res)
            # Reply with vendor and identity, plus IP candidates when ambiguous.
            reply = {"status": "SUCCESS", "port_id": pid,
                     "vendor": res.get("vendor"), "logged_in": bool(res.get("logged_in")),
                     "identity": res.get("identity") or {}}
            if res.get("ambiguous_fields"):
                # The fingerprint found 2+ distinct device addresses for "ip" —
                # pass the candidates so the hub can ask the LLM which is the
                # device's own (see fingerprint.ip_ambiguity).
                reply["ambiguous_fields"] = list(res["ambiguous_fields"])
                reply["ip_candidates"] = list(res.get("ip_candidates") or [])
                reply["ip_candidate_context"] = dict(res.get("ip_candidate_context") or {})
            return reply

        # Run LLM-proposed read-only commands on a free port.
        if cmd == "CONSOLE_LLM_COLLECT":
            # Log in (generically) and run a validated set of READ-ONLY commands,
            # returning the raw output for the hub's LLM-driven identify to parse.
            # Gated off by default; every command is re-validated in run_commands.
            # Feature must be on; port must exist and be free.
            if not self.config.get("console_llm_identify", False):
                return {"status": "ERROR", "message": "LLM-assisted identify is disabled"}
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            # Commands and extra credentials from the hub.
            cmds = data.get("commands") or []
            extra_creds = data.get("credentials") or []
            # Run them with exclusive access; track open failures.
            res = await self._exclusive_probe(pid, self._collect_blocking, pid, dev, cmds, extra_creds)
            if str(res.get("error", "")).lower().startswith("open failed"):
                self._mark_unopenable(pid, res["error"])
            else:
                self._clear_unopenable(pid)
            self._record_identify_telemetry(pid, res, method="llm")
            return {"status": "SUCCESS", "port_id": pid, **res}

        # Store an LLM-derived identity for a port.
        if cmd == "CONSOLE_LLM_STORE":
            # Persist a device identity the hub's LLM-driven identify determined,
            # so it surfaces in the port list / NetBox like a fingerprint identify.
            # Feature must be on; need a port id.
            if not self.config.get("console_llm_identify", False):
                return {"status": "ERROR", "message": "LLM-assisted identify is disabled"}
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            # Save and report it like a normal probe result.
            await self._emit_probe_result(pid, {
                "banner": data.get("banner", ""),
                "vendor": data.get("vendor"),
                "identity": data.get("identity") or {},
                "logged_in": bool(data.get("logged_in")),
            }, method="llm")
            return {"status": "SUCCESS", "port_id": pid,
                    "vendor": data.get("vendor"), "identity": data.get("identity") or {}}

        # Read the device's running config.
        if cmd == "CONSOLE_GET_CONFIG":
            # Port must exist and be free.
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            return await self._exclusive_probe(pid, self._read_config_blocking, pid, dev)

        # Push config to the device.
        if cmd == "CONSOLE_PUSH_CONFIG":
            # Port must exist and be free.
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            # Need non-empty config; read save and rollback options.
            config = data.get("config") or ""
            if not config.strip():
                return {"status": "ERROR", "message": "config is empty"}
            save = bool(data.get("save", True))
            rollback = data.get("rollback") or "negate"
            return await self._exclusive_probe(pid, self._push_config_blocking, pid, dev, config, save, rollback)

        # Detect the baud rate on a free port.
        if cmd == "CONSOLE_DETECT_BAUD":
            # Port must exist and be free.
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions before baud detection"}
            # Sweep rates with exclusive access.
            try:
                result = await self._exclusive_probe(pid, detect_baud, dev, DEFAULT_BAUD_CANDIDATES)
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"baud detect failed: {e}"}
            # Save a confident result unless the user pinned the baud.
            if result.get("confident") and not (self.store.get(pid).get("probe") or {}).get("baud_pinned"):
                # Only a CONFIDENT sweep may change the port's rate — a guess
                # would strand the session on the wrong baud — and an operator
                # pin always outranks auto-detection.
                self.store.update(pid, settings={"baud": result["baud"]},
                                  probe={"detected_baud": result["baud"],
                                         "banner": result.get("sample", ""),
                                         "baud_confident": True})
            return {"status": "SUCCESS", "port_id": pid, **result}

        # Open a session.
        if cmd == "CONSOLE_OPEN":
            return await self._cmd_open(data)

        # Keystrokes from a session.
        if cmd == "CONSOLE_DATA":
            # Need a session id; decode the data.
            sid = data.get("session_id")
            raw = data.get("data", "")
            if not sid:
                return {"status": "ERROR", "message": "session_id is required"}
            try:
                payload = base64.b64decode(raw) if raw else b""
            except Exception:
                return {"status": "ERROR", "message": "data must be base64"}
            # Write it if this session is the writer.
            ok = self.sessions.write(sid, payload)
            return {"status": "SUCCESS" if ok else "ERROR",
                    "written": ok, "message": "" if ok else "not the writer / no session"}

        # Take the writer lock from another session.
        if cmd == "CONSOLE_TAKEOVER":
            sid = data.get("session_id")
            if not sid:
                return {"status": "ERROR", "message": "session_id is required"}
            # Take over; tell the hub who lost it.
            prev = self.sessions.takeover(sid)
            if prev and self.control_plane is not None:
                try:
                    await self.control_plane.send_to_hub("CONSOLE_DOWNGRADED", {"session_id": prev})
                except Exception:  # noqa: BLE001
                    pass
            return {"status": "SUCCESS", "writer": sid, "previous_writer": prev}

        # Send a serial break.
        if cmd == "CONSOLE_SEND_BREAK":
            sid = data.get("session_id")
            ok = self.sessions.send_break(sid) if sid else False
            return {"status": "SUCCESS" if ok else "ERROR", "sent": ok}

        # Resize is a no-op for serial.
        if cmd == "CONSOLE_RESIZE":
            return {"status": "SUCCESS"}  # serial has no window size; accepted, no-op

        # Close a session and drop any relay registration.
        if cmd == "CONSOLE_CLOSE":
            sid = data.get("session_id")
            if sid:
                self.sessions.close(sid)
                if self.control_plane is not None and hasattr(
                        self.control_plane, "unregister_console_relay"):
                    self.control_plane.unregister_console_relay(sid)
            return {"status": "SUCCESS"}

        # Anything else.
        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    def _open_user_session(self, session_id, port_id, dev, settings, writable):
        """Open a session unless a boot liveness check holds the port; return the open info."""
        # Both browser and DPA opens run on the event loop. Reserve the port
        # until the nudge's worker has released its transient serial handle.
        if port_id in self._boot_nudge_pending:
            raise RuntimeError("boot liveness check in progress; retry shortly")
        return self.sessions.open(session_id, port_id, dev, settings, writable)

    async def _cmd_open(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Open a browser/relay session on a port and replay recent output to it.

        Args:
            data: session_id, port_id, mode ("rw" or "ro") and optional relay_token.

        Returns:
            dict with status, session id, settings, writer flag and read_only flag.
        """
        # Read the request.
        sid = data.get("session_id")
        pid = data.get("port_id")
        mode = (data.get("mode") or "rw").lower()
        # Need a session and port.
        if not sid or not pid:
            return {"status": "ERROR", "message": "session_id and port_id are required"}
        # Port must exist.
        dev = self._port_device(pid)
        if not dev:
            return {"status": "ERROR", "message": f"port {pid} not found"}
        # Capture the loop so the reader thread can push CONSOLE_DATA_UP back onto it.
        # Remember the loop for the reader thread, then open with saved settings.
        self._loop = asyncio.get_running_loop()
        settings = self.store.settings(pid)
        try:
            info = self._open_user_session(sid, pid, dev, settings, writable=(mode != "ro"))
        except Exception as e:  # noqa: BLE001
            logger.warning("open %s (%s) failed: %s", pid, dev, e)
            return {"status": "ERROR", "message": f"could not open {dev}: {e}"}
        logger.info("console session %s opened on %s (%s) writer=%s",
                    sid, pid, dev, info.get("writer"))
        # Phase 2: register the relay token so a co-located edge proxy can attach a
        # /ws/console-relay leg. Serial has no agent — DOWN frames go to our own
        # serial-write via down_handler. Requires LM_CONSOLE_RELAY_LISTENER=1 so the
        # console role runs the listener; otherwise the proxy falls back to the hub.
        # Register an edge-proxy relay leg when a token is given.
        relay_token = data.get("relay_token")
        cp = self.control_plane
        if relay_token and cp is not None and hasattr(cp, "register_console_relay"):
            try:
                cp.register_console_relay(sid, relay_token, "", "serial",
                                          down_handler=self._serial_relay_down)
            except Exception:  # noqa: BLE001
                pass
        # Tell the browser leg the stream is live (relay consumes CONSOLE_READY).
        # Tell the hub the session is ready.
        if self.control_plane is not None:
            await self.control_plane.send_to_hub("CONSOLE_READY", {"session_id": sid})
        # Streaming handoff: replay the recent persistent-capture tail so a user
        # who connects mid-stream (or after a spoke restart) immediately sees the
        # context the monitor already recorded (banner/prompt/output) instead of a
        # blank screen. The hub buffers these CONSOLE_DATA_UP frames in the session
        # queue until the browser WS drains them, so nothing is lost to the connect
        # race. No-ops when there is nothing recorded for this port.
        # Replay recent capture, then reply.
        await self._replay_capture(sid, pid)
        return {"status": "SUCCESS", "session_id": sid, "port_id": pid,
                "settings": settings, "writer": info.get("writer"),
                "read_only": bool(info.get("busy"))}

    async def _push_console_up(self, sid: str, data_bytes: bytes) -> None:
        """Push device→browser bytes for a session (edge-proxy route if present,
        else up to the hub). Shared by the reader thread bridge and the replay."""
        # Need a control plane and data.
        cp = self.control_plane
        if cp is None or not data_bytes:
            return
        # Encode; try the edge-proxy route, else the hub.
        payload = {"session_id": sid, "data": base64.b64encode(data_bytes).decode()}
        routed = False
        if hasattr(cp, "_route_console_up"):
            try:
                routed = await cp._route_console_up("CONSOLE_DATA_UP", payload)
            except Exception:  # noqa: BLE001
                routed = False
        if not routed:
            await cp.send_to_hub("CONSOLE_DATA_UP", payload)

    async def _replay_capture(self, sid: str, pid: str) -> None:
        """Warm-start a connecting user with the recorded scrollback. Replays the
        tail of the persistent per-device capture (up to ``console_replay_bytes``,
        default 1 MiB, override via LM_CONSOLE_REPLAY_BYTES) so a user — or a
        second concurrent viewer — sees the device's recent history instead of a
        blank screen. The full log is retained/persisted; the replay is capped to
        keep the connect burst light for the browser terminal."""
        # Need a live channel.
        chan = self.sessions.channel(pid)
        if not chan:
            return
        # Replay size: env, then config, default 1 MiB.
        try:
            cap = int(os.environ.get("LM_CONSOLE_REPLAY_BYTES", "")
                      or self.config.get("console_replay_bytes", 1 << 20))
        except Exception:  # noqa: BLE001
            cap = 1 << 20
        # Read the tail from disk (or memory).
        tail = chan.persisted_tail(cap) if cap > 0 else chan.persisted_tail(8192)
        if not tail:
            return
        # Send a dim header line followed by the tail.
        header = b"\r\n\x1b[2m--- recent console capture (replayed) ---\x1b[0m\r\n"
        await self._push_console_up(sid, header + tail)

    # ── auto-identify / fingerprint ───────────────────────────────────────────
    def _effective_credentials(self, extra: Optional[list] = None) -> list:
        """Credential list used for auto-identify: operator-supplied credentials
        first, then any caller-supplied extras (e.g. LLM-proposed guesses), then
        the well-known factory-default set (unless disabled via config). Deduped,
        order preserved — so we try what the operator configured before falling
        back to defaults, and never retry the same pair twice."""
        # Operator credentials, extras, then factory defaults (unless disabled).
        groups = [self._credentials]
        if extra:
            groups.append(extra)
        if self.config.get("console_factory_default_creds", True):
            groups.append(FACTORY_DEFAULT_CREDENTIALS)
        return merge_credentials(*groups)

    def _resolve_baud(self, port_id: str, dev: str):
        """Auto-resolve the baud rate for an identify attempt, sweeping until the
        line yields actual readable text. Returns ``(baud_to_use, locked_baud)``
        where ``locked_baud`` is non-None only when this sweep CONFIDENTLY found
        the rate (real text) and it should be persisted.

        Fully automatic — no operator action. A port with a confidently-locked
        baud is used as-is (no re-sweep); a port that has never yielded readable
        text (silent/wrong-baud/newly-plugged) is re-swept across all candidate
        rates every cycle until real output appears, at which point the rate is
        locked and reused."""
        # Saved probe data and line settings.
        probe = self.store.get(port_id).get("probe") or {}
        settings = self.store.settings(port_id)
        # A confirmed baud is used as-is.
        if probe.get("baud_confident") and settings.get("baud"):
            return settings.get("baud"), None
        # Otherwise sweep the candidate rates.
        try:
            d = detect_baud(dev, DEFAULT_BAUD_CANDIDATES)
        except Exception as e:  # noqa: BLE001
            logger.debug("baud auto-detect failed on %s: %s", dev, e)
            return settings.get("baud"), None
        # Confident result: use it and report it for saving.
        if d.get("confident") and d.get("baud"):
            return d["baud"], d["baud"]
        # No readable text yet: use the best-scoring rate as a hint for THIS
        # attempt but DON'T lock it, so the next cycle sweeps the others again.
        # Not confident: best guess, nothing to save.
        return d.get("baud") or settings.get("baud"), None

    def _identify_blocking(self, port_id: str, dev: str) -> Dict[str, Any]:
        """Blocking read-only identify on a transient serial handle (run via
        asyncio.to_thread). Auto-resolves the baud rate first (sweeping until the
        line yields real text), then logs in / fingerprints at that rate."""
        # Pick the baud, then open the port.
        baud, locked = self._resolve_baud(port_id, dev)
        try:
            ser = open_raw(dev, baud or DEFAULT_BAUD, timeout=0.3)
        except Exception as e:  # noqa: BLE001
            return {"error": f"open failed: {e}"}
        # Run the identify; always close the port.
        try:
            res = run_identify(lambda: ser.read(256), ser.write, self._effective_credentials())
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass
        # Mark a newly confirmed baud on the result.
        if locked:
            res["detected_baud"] = locked
            res["baud_confident"] = True
        return res

    def _collect_blocking(self, port_id: str, dev: str, commands, extra_creds=None) -> Dict[str, Any]:
        """Blocking generic-login + read-only command run on a transient handle
        (for LLM-driven identify). Commands are re-validated inside run_commands.
        ``extra_creds`` are LLM-proposed credential guesses tried after the
        operator's own creds (and before the factory-default fallback)."""
        # Open at the saved baud.
        baud = self.store.settings(port_id).get("baud") or DEFAULT_BAUD
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"error": f"open failed: {e}"}
        # Log in and run the commands; always close the port.
        try:
            return run_commands(lambda: ser.read(256), ser.write,
                                self._effective_credentials(extra_creds), commands or [])
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    def _profile_for(self, port_id: str):
        """The vendor profile a port was last identified as (None if never
        identified — config read/push requires a known device type)."""
        # Need a stored vendor.
        vendor = (self.store.get(port_id).get("probe") or {}).get("vendor")
        if not vendor:
            return None
        # Find its profile.
        return next((p for p in PROFILES if p["name"] == vendor), None)

    def _read_config_blocking(self, port_id: str, dev: str) -> Dict[str, Any]:
        """Read the running config from an identified device over a short-lived handle.

        Returns:
            dict with status and either the config text or an error message.
        """
        # Need a known device type.
        prof = self._profile_for(port_id)
        if not prof:
            return {"status": "ERROR", "message": "device not identified — run Identify first", "config": ""}
        # Open at the saved baud.
        baud = self.store.settings(port_id).get("baud") or DEFAULT_BAUD
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"open failed: {e}", "config": ""}
        # Read the config; always close the port.
        try:
            return read_running_config(lambda: ser.read(256), ser.write, prof, self._credentials)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    def _push_config_blocking(self, port_id: str, dev: str, config: str,
                              save: bool, rollback: str) -> Dict[str, Any]:
        """Push config lines to an identified device over a short-lived handle.

        Args:
            port_id: port to use.
            dev: serial device path.
            config: config text to apply.
            save: save the config after applying.
            rollback: rollback mode on error.

        Returns:
            dict with status and push details or an error message.
        """
        # Need a known device type.
        prof = self._profile_for(port_id)
        if not prof:
            return {"status": "ERROR", "message": "device not identified — run Identify first"}
        # Open at the saved baud.
        baud = self.store.settings(port_id).get("baud") or DEFAULT_BAUD
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"open failed: {e}"}
        # Push the config; always close the port.
        try:
            return push_config(lambda: ser.read(256), ser.write, prof, self._credentials,
                               config, save=save, rollback=rollback)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    @staticmethod
    def _stored_vendor(probe: Dict[str, Any]) -> Optional[str]:
        """The port's stored vendor, re-checked if it is "linux". Older versions
        tagged any bare "login:" prompt as linux (AOS-CX switches and SSRs
        included), so a stored "linux" is re-derived from the saved banner with
        the current rules; it becomes unknown if no rule matches."""
        # Re-check a stored "linux" against the current rules.
        vendor = probe.get("vendor")
        if vendor == "linux":
            prof = detect_vendor(probe.get("banner") or "")
            vendor = prof["name"] if prof else None
        return vendor

    async def _emit_probe_result(self, port_id: str, res: Dict[str, Any], method: str = "login") -> None:
        """Persist the probe + push CONSOLE_PROBE_RESULT up (hub → NetBox).

        ``method`` records provenance ("login" for the fingerprint identify,
        "llm" for hub LLM-driven identify). ``source`` stays "active" for both —
        a logged-in identity is authoritative and outranks passive glean."""
        # Earlier probe record.
        prev = self.store.get(port_id).get("probe") or {}
        # scrub_identity also cleans junk stored by older versions (hostname
        # "hostname"/"standby", a prompt stored as the serial).
        # Clean identities, old and new.
        prev_ident = scrub_identity({k: v for k, v in (prev.get("identity") or {}).items()
                                     if v not in (None, "", [], {})})
        new_ident = scrub_identity({k: v for k, v in (res.get("identity") or {}).items()
                                    if v not in (None, "", [], {})})
        # Keep the old vendor unless the new one should replace it.
        prev_vendor = self._stored_vendor(prev)
        # A weaker verdict (e.g. "linux" or unknown from a login-locked switch)
        # must not overwrite a confident one learned earlier (see
        # vendor_should_replace).
        vendor = res.get("vendor") if vendor_should_replace(prev_vendor, res.get("vendor")) \
            else prev_vendor
        # MERGE, never blank: a probe that learns nothing (silent device, idle
        # timeout, creds not pushed yet — routine right after an update restart
        # re-verifies every port) must not wipe the last-known name/serial/type.
        # A probe that DOES learn identity refreshes it field-by-field, unless it
        # is provably a different device on this cable (serial/MAC changed), in
        # which case the old identity is dropped wholesale.
        # New identity: replace if it is a different device, else merge.
        if new_ident:
            if self._different_device(prev_ident, new_ident):
                identity, vendor = new_ident, res.get("vendor")
            else:
                identity = {**prev_ident, **new_ident}
            source, stale = "active", False
        # No new identity: keep the old one and mark it stale.
        else:
            identity = prev_ident
            source = (prev.get("source") or "active") if prev_ident else "active"
            stale = bool(prev_ident)
        # Build the new probe record.
        probe = {
            "banner": ((res.get("banner") or "") or (prev.get("banner") or ""))[-2000:],
            "vendor": vendor,
            "identity": identity,
            "logged_in": bool(res.get("logged_in")),
            "error": res.get("error", ""),
            "source": source,  # "active" = logged-in identify (authoritative; beats passive)
            "method": method,
        }
        # "stale" = shown as last-known: this attempt didn't re-confirm the
        # identity. Always written (PortStore.update merges keys, so an omitted
        # flag would leave an old True behind after a successful re-identify).
        # Stale flag, restore origin and identify time.
        probe["stale"] = stale
        probe["restored_from"] = (prev.get("restored_from") or "") if stale else ""
        if new_ident:
            probe["identified_at"] = time.time()
        elif prev.get("identified_at"):
            probe["identified_at"] = prev["identified_at"]
        # VSF stack membership, when the device is stacked. Absent entirely for a
        # standalone switch so the UI has nothing to render for the common case.
        # Keep stack details if present.
        stack = res.get("stack") or {}
        if stack.get("is_stack"):
            probe["stack"] = stack
        # Preserve the auto-detected baud LOCK across probe rebuilds: only a
        # confident sweep sets a fresh one (res.detected_baud); otherwise carry
        # forward what a prior sweep already locked so we don't lose it and
        # needlessly re-sweep a known-good port.
        # Keep the detected baud; save it as the line setting when newly found.
        detected = res.get("detected_baud") or prev.get("detected_baud")
        if detected:
            probe["detected_baud"] = detected
            if res.get("baud_confident") or prev.get("baud_confident"):
                probe["baud_confident"] = True
            if res.get("detected_baud"):
                self.store.update(port_id, settings={"baud": res["detected_baud"]})
        # A garbled line at an automatically locked rate means the lock is wrong
        # (or the device changed rate): drop it so the next identify re-sweeps.
        # Garbled output means the baud is not confirmed.
        if (res.get("diag") or {}).get("garbled") and not prev.get("baud_pinned"):
            probe["baud_confident"] = False
        # Reconcile: this identity (serial/MAC learned from the DEVICE, not the
        # USB adapter) may already be known under a different, now-absent
        # port_id — e.g. a reboot renumbered /dev/ttyUSBn, or the cable moved
        # to a different port. Carry the operator's alias/tenant assignment
        # forward onto this port_id and drop the orphan so it never lingers in
        # the list as a stale duplicate.
        # Only a probe that actually learned identity reconciles / refreshes the
        # cache — re-running it on a kept last-known identity every failed retry
        # could retire a different port's record on a stale match.
        # For a known identity, carry over names from an earlier record.
        identity = (probe.get("identity") or {}) if new_ident else {}
        if identity:
            fields: Dict[str, Any] = {}
            # Same device on a different port: move alias and tenant, drop the old entry.
            old_pid = self.store.find_by_identity(identity, exclude_port_id=port_id)
            if old_pid:
                old = self.store.get(old_pid)
                if old.get("alias") and not self.store.get(port_id).get("alias"):
                    fields["alias"] = old["alias"]
                if old.get("tenant_id") and not self.store.get(port_id).get("tenant_id"):
                    fields["tenant_id"] = old["tenant_id"]
                self.store.delete(old_pid)
                logger.info("console: device %s reappeared on port %s (was %s) — carried "
                            "alias/tenant forward, dropped the old port record",
                            identity.get("hostname") or identity.get("serial")
                            or identity.get("mac") or "?", port_id, old_pid)
            # Otherwise fill gaps from the device cache.
            else:
                # No live port_id matched — but the DEVICE itself may still be
                # remembered in the identity-keyed warm cache, which survives a
                # ports.json wipe (a derive_port_id format change on upgrade, or
                # the whole file simply never having been written yet on a
                # freshly loaded agent). This is what lets alias/tenant survive
                # a "the console code was updated" restart, not just an
                # ordinary one.
                cached = self.devices.lookup(identity)
                if cached:
                    if cached.get("alias") and not self.store.get(port_id).get("alias"):
                        fields["alias"] = cached["alias"]
                    if cached.get("tenant_id") and not self.store.get(port_id).get("tenant_id"):
                        fields["tenant_id"] = cached["tenant_id"]
                    # Backfill the profile itself (name/type/model…) the probe
                    # didn't re-learn this time — gap-fill only, never override.
                    for k, v in scrub_identity(cached.get("identity") or {}).items():
                        if v and not identity.get(k):
                            identity[k] = v
                    # A cached "linux" is a legacy bare-"login:" guess; don't revive it.
                    if cached.get("vendor") not in (None, "", "linux") and not probe.get("vendor"):
                        probe["vendor"] = cached["vendor"]
            # Save carried-over fields, then the probe.
            if fields:
                self.store.update(port_id, **fields)
        self.store.update(port_id, probe=probe)
        # Refresh the warm cache with whatever we now know, so the NEXT restart
        # (or a future port_id derivation change) has somewhere to recover
        # alias/tenant/identity from even if this port_id's ports.json record is
        # gone by then.
        # Remember the device in the cache.
        if identity:
            saved = self.store.get(port_id)
            self.devices.remember(
                identity, port_id=port_id, vendor=str(probe.get("vendor") or ""),
                product=self._port_product(port_id),
                alias=saved.get("alias", ""), tenant_id=saved.get("tenant_id", ""),
            )
        # Record the attempt time.
        self._probe_attempts[port_id] = time.monotonic()
        # Nothing new learned about an already-known device → no NetBox
        # round-trip (a silent device is retried hourly; don't re-push its
        # unchanged last-known identity each time).
        # Report to the hub when something new was found or on errors.
        if self.control_plane is not None and (new_ident or not prev_ident):
            await self.control_plane.send_to_hub("CONSOLE_PROBE_RESULT", {
                "spoke_id": self.spoke_id, "port_id": port_id,
                "tenant_id": self.store.get(port_id).get("tenant_id", ""),  # per-port override
                "vendor": probe["vendor"], "identity": probe["identity"],
                "banner": probe["banner"][-500:], "logged_in": probe["logged_in"],
                "method": method, "product": self._port_product(port_id),
            })

    def _ensure_autoprobe_task(self) -> None:
        """Start the auto-identify loop once (fully automatic on detection —
        decision #9), unless disabled via config auto_identify=False."""
        # Run only once and only if enabled.
        if self._autoprobe_task is not None or not self.config.get("auto_identify", True):
            return
        # Need a running loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        # Start the loop task.
        self._loop = self._loop or loop
        self._autoprobe_task = loop.create_task(self._autoprobe_loop())

    async def _autoprobe_loop(self) -> None:
        """Run the auto-identify scan forever at the configured interval, logging any errors."""
        # Short start-up delay, then scan in a loop.
        await asyncio.sleep(10)  # let credentials/settings arrive first
        while True:
            try:
                await self._autoprobe_scan()
            except Exception:  # noqa: BLE001
                logger.exception("console autoprobe scan failed")
            # Poll cadence (configurable). A short poll auto-profiles a newly
            # connected console cable quickly; per-port retry backoff still gates
            # how often a FAILED port is re-attempted, so this doesn't hammer.
            await asyncio.sleep(self._identify_cfg()["scan_interval"])

    def _identify_cfg(self) -> Dict[str, Any]:
        """Operator-tunable auto-identify retry policy (all optional, safe
        defaults preserve prior behaviour):
          console_identify_retry_secs      floor backoff after a failed attempt (300)
          console_identify_retry_max_secs  cap the escalating backoff (3600)
          console_identify_reverify_secs   how often an ALREADY-identified port is
                                            actively re-checked (default once/day,
                                            86400) — never fully trust a cable
                                            stayed put; a device silently swapped
                                            onto the same port/cable must not keep
                                            reporting the old identity forever.
                                            Also effectively fires on every restart
                                            (reboot can reshuffle port_ids) since
                                            the last-checked timestamp is in-memory
                                            only. See _reverify_due.
          console_identify_max_attempts    give up after N consecutive failures,
                                            0 = never give up (0)
          console_autoprobe_interval       scan/first-seen poll cadence secs (30)
        """
        # Read values from the role config.
        c = self.config

        def _pos(key: str, default: float) -> float:
            """Return a positive float config value, or the default if missing or invalid."""
            try:
                v = float(c.get(key, default))
            except (TypeError, ValueError):
                return default
            return v if v > 0 else default

        def _nonneg(key: str, default: int) -> int:
            """Return a non-negative int config value, or the default if missing or invalid."""
            try:
                v = int(c.get(key, default))
            except (TypeError, ValueError):
                return default
            return v if v >= 0 else default

        # Build the policy with defaults.
        return {
            "retry_min": _pos("console_identify_retry_secs", 300.0),
            "retry_max": _pos("console_identify_retry_max_secs", 3600.0),
            "reverify": _pos("console_identify_reverify_secs", 86400.0),
            "max_attempts": _nonneg("console_identify_max_attempts", 0),
            "scan_interval": _pos("console_autoprobe_interval", 30.0),
        }

    @staticmethod
    def _different_device(prev: Dict[str, Any], new: Dict[str, Any]) -> bool:
        """True when ``new`` is provably a DIFFERENT device than ``prev`` (a
        cable swapped onto another box): its serial or MAC is known on both
        sides and differs. Hostname alone never decides it (renames happen)."""
        # Serial or MAC known on both sides and different means a different device.
        for k in ("serial", "mac"):
            a = str(prev.get(k) or "").strip().lower()
            b = str(new.get(k) or "").strip().lower()
            if a and b and a != b:
                return True
        return False

    @staticmethod
    def _probe_identified(probe: Dict[str, Any]) -> bool:
        """True once a port is PROFILED: an active login/identify has confirmed a
        hostname for it, and the latest attempt didn't fail to re-confirm it
        (``stale``). Only then do the auto-identify loops stop the 5 min → 1 h
        retry backoff and fall back to the daily re-verify
        (``console_identify_reverify_secs``). A vendor/banner, a bare login, a
        passive glean or a last-known name restored after a restart is NOT
        enough — such a port keeps being retried until it yields a name."""
        # Must be an active, non-stale result with a real hostname.
        if probe.get("source") != "active" or probe.get("stale"):
            return False
        return bool(_real_hostname((probe.get("identity") or {}).get("hostname")))

    def _restore_last_known(self) -> None:
        """One-time (per process) backfill of ports whose stored profile is
        blank — e.g. wiped by an older build's failed re-verify after an update
        — from the per-port last-known record in devices.json, else the newest
        hostname in health.json's identify history. Shown as last-known
        (``stale``) and NOT counted as profiled, so the port is still actively
        retried until a live identify re-confirms it."""
        # Run once per process.
        if getattr(self, "_restored_last_known", False):
            return
        self._restored_last_known = True
        # Pass 1: names held by live identities, and a restore candidate for every
        # blank (or previously restored) port.
        # Real hostnames already held by live ports, and candidates for restore.
        held = set()
        candidates: Dict[str, Tuple[Dict[str, Any], Dict[str, Any], Any, str]] = {}
        # Ports with a real identity count as held; others get a last-known candidate.
        for pid, saved in self.store.all_items().items():
            probe = dict(saved.get("probe") or {})
            ident = probe.get("identity") or {}
            if probe.get("source") != "restored" and any(v for v in ident.values()):
                host = _real_hostname(ident.get("hostname"))
                if host:
                    held.add(host.lower())
                continue
            identity, vendor, origin = self._last_known_identity(pid)
            candidates[pid] = (probe, identity, vendor, origin)
        # Count how many ports claim each hostname.
        claims: Dict[str, int] = {}
        for _probe, identity, _vendor, _origin in candidates.values():
            host = _real_hostname(identity.get("hostname")).lower()
            if host:
                claims[host] = claims.get(host, 0) + 1
        # Pass 2: a port id can drift onto another cable (USB bus renumbering),
        # so a name another port already holds, or that several ports claim, is
        # ambiguous and is not restored. The live identify will name it.
        # Restore each candidate unless its name is held or claimed twice.
        for pid, (probe, identity, vendor, origin) in candidates.items():
            host = _real_hostname(identity.get("hostname")).lower()
            if host and (host in held or claims.get(host, 0) > 1):
                identity = {}
            # Nothing to restore: clear an old restored record and move on.
            if not identity:
                if probe.get("source") == "restored":  # drop an earlier bad restore
                    probe.update({"identity": {}, "source": "active",
                                  "stale": False, "restored_from": ""})
                    self.store.update(pid, probe=probe)
                continue
            # Save the restored identity as stale.
            probe.update({"identity": identity, "vendor": probe.get("vendor") or vendor,
                          "source": "restored", "stale": True, "restored_from": origin})
            self.store.update(pid, probe=probe)
            logger.info("console: restored last-known profile for %s from %s (%s)",
                        pid, origin, identity.get("hostname") or identity.get("serial") or "?")

    def _last_known_identity(self, pid: str) -> Tuple[Dict[str, Any], Any, str]:
        """(identity, vendor, origin) for a port from devices.json's last-known
        record, else the newest real hostname in its identify history."""
        # Port's entry in the device cache.
        cached = self.devices.lookup_port(pid)
        cached_ident = (cached or {}).get("identity") or {}
        # Use it if it has a real name or other fields.
        if _real_hostname(cached_ident.get("hostname")) or any(
                v for k, v in cached_ident.items() if k != "hostname"):
            return {k: v for k, v in cached_ident.items() if v}, cached.get("vendor") or None, "device_cache"
        # Else newest real hostname from identify history.
        hist = ((self._health.get(pid) or {}).get("identify") or {}).get("hostname_history") or []
        host = next((h for h in (_real_hostname((e or {}).get("host")) for e in reversed(hist)) if h), "")
        if host:
            return {"hostname": host}, None, "hostname_history"
        return {}, None, ""

    async def _autoprobe_scan(self) -> None:
        """Probe each newly-seen port with the stored credentials. Guardrails:
        global toggle; skip ports a human holds or already identified actively;
        honour the shared login-retry backoff (:meth:`_identify_due`) so we keep
        trying to learn from a device without hammering its credentials. A port
        that has just appeared (new console cable) is profiled immediately; a port
        that has vanished has its retry state cleared so re-plugging starts fresh."""
        # Only when enabled; restore names first, then list ports.
        if not self.config.get("auto_identify", True):
            return
        self._restore_last_known()
        live = {p["port_id"]: p for p in await self._enumerate_ports()}
        # First-seen / re-plug: reset retry state so a freshly connected cable is
        # attempted right away instead of inheriting a stale backoff.
        # Forget retry state for ports that went away.
        for pid in set(self._seen_ports) - set(live):
            self._probe_attempts.pop(pid, None)
            self._probe_delay.pop(pid, None)
            self._probe_fails.pop(pid, None)
            # A disappear+reappear cycle under this SAME port_id might be a
            # different device swapped onto the same cable, not the original
            # coming back — force an immediate re-verify rather than trusting
            # the old identity until the next daily cycle.
            self._identify_verify_ts.pop(pid, None)
        # Check each live port.
        self._seen_ports = set(live)
        for pid, p in live.items():
            # Skip ports in use, being probed, or unopenable.
            if self.sessions.has_user_sessions(pid) or pid in self._probing:
                continue
            if pid in self._unopenable:  # can't open at all — monitor_scan handles recovery
                continue
            # Identified ports wait for re-verify; others wait for their back-off.
            probe = self.store.get(pid).get("probe") or {}
            if self._probe_identified(probe):
                # Never fully trust a cable/port stayed put: periodically
                # re-verify an already-identified port too (default once/day),
                # so a device silently swapped onto the SAME port/cable can't
                # keep reporting the old identity forever.
                if not self._reverify_due(pid):
                    continue
            elif not self._identify_due(pid):
                continue
            # Identify it.
            await self._active_identify(pid, p["device"])

    def _reverify_due(self, pid: str) -> bool:
        """True once ``console_identify_reverify_secs`` has elapsed since an
        already-identified ``pid`` was last actively re-checked — or it has
        never been checked THIS process lifetime (the timestamp is in-memory
        only), which makes every previously-known port due on the first scan
        after any restart, since a reboot can reshuffle port_ids."""
        # Never checked: due now.
        last = self._identify_verify_ts.get(pid)
        if last is None:
            return True
        # Due once the re-verify period has passed.
        return (time.monotonic() - last) >= self._identify_cfg()["reverify"]

    def _identify_due(self, pid: str) -> bool:
        """True when the shared login-retry backoff has elapsed for ``pid`` (or it
        has never been attempted), so an active identify may run again. Honours the
        configurable max-attempts cap: once a port has failed that many times in a
        row we stop retrying (until it is re-plugged or manually probed)."""
        # Stop after the attempt cap.
        cfg = self._identify_cfg()
        cap = cfg["max_attempts"]
        if cap and self._probe_fails.get(pid, 0) >= cap:
            return False
        # Never tried: due now.
        last = self._probe_attempts.get(pid, 0.0)
        if not last:
            return True
        # Due once the back-off has passed.
        return (time.monotonic() - last) >= self._probe_delay.get(pid, cfg["retry_max"])

    async def _active_identify(self, pid: str, dev: str) -> Dict[str, Any]:
        """Run the login-based identify on a port (releasing the passive monitor
        handle for the exclusive op), persist/emit the result, and update the
        shared retry backoff: a success (identity/login) backs off to an
        occasional re-verify; a failure escalates (retry_min→…→retry_max) so we
        keep trying to learn what the stored credentials reveal without provoking
        a lockout. Backoff bounds + the give-up cap are operator-configurable
        (:meth:`_identify_cfg`)."""
        # Note attempt and verify times.
        cfg = self._identify_cfg()
        self._probe_attempts[pid] = time.monotonic()
        self._identify_verify_ts[pid] = time.monotonic()

        def _fail_backoff() -> None:
            """Count a failure and double the back-off, within the configured bounds."""
            self._probe_fails[pid] = self._probe_fails.get(pid, 0) + 1
            self._probe_delay[pid] = min(
                max(self._probe_delay.get(pid, 0.0) * 2, cfg["retry_min"]), cfg["retry_max"])

        # Run the identify with exclusive access.
        try:
            res = await self._exclusive_probe(pid, self._identify_blocking, pid, dev)
        except Exception:  # noqa: BLE001
            logger.exception("active identify %s failed", pid)
            _fail_backoff()
            return {"error": "identify failed"}
        # A bare "open failed" (not a login/parse issue) means the port itself is
        # unusable → hide it (still retried next cycle); otherwise it's healthy.
        # Track whether the port can be opened.
        if str(res.get("error", "")).lower().startswith("open failed"):
            self._mark_unopenable(pid, res["error"])
        else:
            self._clear_unopenable(pid)
        # Record and report the result.
        self._record_identify_telemetry(pid, res, method="login")
        await self._emit_probe_result(pid, res)
        # Hostname found: reset failures and wait for re-verify; else back off.
        if _real_hostname((res.get("identity") or {}).get("hostname")):
            self._probe_fails[pid] = 0                 # success clears the give-up counter
            self._probe_delay[pid] = cfg["reverify"]   # profiled → daily re-verify only
        else:
            # No hostname (silent, banner/vendor only, or logged in but nothing
            # parsed) → not profiled yet: keep retrying on the escalating backoff.
            _fail_backoff()
        return res

    async def _exclusive_probe(self, pid, fn, *args):
        """Run a blocking op that needs the EXCLUSIVE serial handle (identify,
        detect-baud, config get/push). Pauses the passive monitor to release the
        OS handle and marks the port ``probing`` so the monitor loop won't grab
        it back mid-op; the monitor loop re-establishes capture afterward."""
        # One lock per port.
        locks = self.__dict__.setdefault("_probe_locks", {})
        lock = locks.get(pid)
        if lock is None:
            lock = locks[pid] = asyncio.Lock()
        # One shared per-port reservation: concurrent exclusive ops serialize
        # instead of opening the device twice.
        # Under the lock, stop the monitor and run the op in a thread.
        async with lock:
            self._probing.add(pid)
            self.sessions.stop_monitor(pid)
            try:
                return await asyncio.to_thread(fn, *args)
            finally:
                self._probing.discard(pid)

    # ── passive monitor (keep-alive capture + opportunistic identity) ─────────
    def _ensure_monitor_task(self) -> None:
        """Start the passive keep-alive capture loop once (config console_monitor,
        default on). It holds a read-only serial handle per idle port so we catch
        whatever a device emits whenever it decides to talk."""
        # Run only once and only if enabled.
        if self._monitor_task is not None or not self.config.get("console_monitor", True):
            return
        # Need a running loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        # Start the loop task.
        self._loop = self._loop or loop
        self._monitor_task = loop.create_task(self._monitor_loop())

    # ── Direct Port Access (reverse Telnet terminal-server) ───────────────────
    def _register_local_sink(self, session_id: str, cb) -> None:
        """Send a local DPA session's serial output to the given callback."""
        self._local_sinks[session_id] = cb

    def _unregister_local_sink(self, session_id: str) -> None:
        """Stop sending a session's output to a local callback."""
        self._local_sinks.pop(session_id, None)

    def _port_device(self, port_id: str):
        """Return the device path for a port id, or None (overrides the earlier definition)."""
        # Look the port up in the cached list.
        for p in self._enum_cached():
            if p["port_id"] == port_id:
                return p["device"]
        return None

    def _port_name(self, port_id: str) -> str:
        """Return a display name for a port: alias, then hostname, then product, then id."""
        # Alias first.
        saved = self.store.get(port_id)
        alias = saved.get("alias")
        if alias:
            return alias
        # Then the identified hostname.
        ident = (saved.get("probe") or {}).get("identity") or {}
        if ident.get("hostname"):
            return ident["hostname"]
        # Then the adapter product name.
        for p in self._enum_cached():
            if p["port_id"] == port_id:
                return p.get("product") or port_id
        return port_id

    def _dpa_info(self, port_id: str):
        """DPA endpoint descriptor for the port list (None when DPA is off or no
        listener is up for this port). ``telnet_port``/``bind``/``proto`` keep
        the original telnet-only shape for older WebUIs."""
        # Nothing when DPA is off.
        if not self._dpa_cfg.effective().get("enabled"):
            return None
        # Start with the advertised host.
        rec = self.store.get(port_id)
        out: Dict[str, Any] = {"host": self._dpa_advertise_host()}
        # Add the SSH listener if this port has one.
        if self._dpa_ssh is not None:
            tcp = self._dpa_ssh.assignment(port_id)
            if tcp:
                out.update(ssh_port=tcp, ssh_bind=self._dpa_ssh.bind,
                           ssh_override=isinstance(rec.get("dpa_ssh_port_override"), int))
        # Add the telnet listener if this port has one.
        if self._dpa is not None:
            tcp = self._dpa.assignment(port_id)
            if tcp:
                out.update(telnet_port=tcp, bind=self._dpa.bind,
                           telnet_override=isinstance(rec.get("dpa_port_override"), int))
        # No listener: nothing to show.
        if "ssh_port" not in out and "telnet_port" not in out:
            return None
        # SSH is preferred when both exist.
        out["proto"] = "ssh" if "ssh_port" in out else "telnet"
        return out

    def _dpa_advertise_host(self) -> str:
        """Return the host name DPA clients should connect to (configured or detected)."""
        return self._dpa_cfg.effective().get("advertise_host") or self._dpa_advertise_auto

    def _dpa_hub_url(self) -> str:
        """Return the hub URL from the control plane, or from config."""
        return str(getattr(self.control_plane, "hub_url", "") or os.environ.get("LM_HUB_URL", "")
                   or self.config.get("hub_url", "") or "")

    def _dpa_describe(self) -> Dict[str, Any]:
        """Return the public DPA config plus runtime listener status."""
        # Build config and runtime sections.
        st = self._dpa_ssh_status
        return {
            "config": self._dpa_cfg.public(),
            "runtime": {
                "ssh_available": st.get("available"),
                "ssh_error": st.get("error"),
                "host_key_fingerprint": st.get("fingerprint"),
                "advertise_host": self._dpa_advertise_host(),
                "ssh_listeners": len(self._dpa_ssh._servers) if self._dpa_ssh else 0,
                "telnet_listeners": len(self._dpa._servers) if self._dpa else 0,
            },
        }

    def _dpa_manager(self, *, proto: str, bind: str, base: int, allow, loop) -> DpaManager:
        """Build a DpaManager for one transport, wired to this spoke's sessions.

        Args:
            proto: "ssh" or "telnet".
            bind: listen address.
            base: first TCP port to assign.
            allow: allowed client networks.
            loop: event loop for the listeners.
        """
        return DpaManager(
            store=self.store,
            enumerate_ports=self._dpa_ports,
            open_session=self._open_user_session,
            write_session=self.sessions.write,
            close_session=self.sessions.close,
            register_sink=self._register_local_sink,
            unregister_sink=self._unregister_local_sink,
            port_device=self._port_device,
            port_name=self._port_name,
            bind=bind, base=base,
            span=int(self.config.get("console_dpa_span", 200)),
            allow=allow, loop=loop,
            proto=proto, store_key="dpa_ssh_port" if proto == "ssh" else "dpa_port",
        )

    def _dpa_send_break(self, sid: str) -> None:
        """Send a serial break for a DPA session without blocking the loop."""
        asyncio.ensure_future(asyncio.to_thread(self.sessions.send_break, sid))

    def _dpa_lock(self) -> asyncio.Lock:
        """Serialises every listener mutation (apply, periodic reconcile, port
        override) so a stale manager can never be reconciled after a rebuild."""
        # Create the lock on first use.
        if self._dpa_apply_lock is None:
            self._dpa_apply_lock = asyncio.Lock()
        return self._dpa_apply_lock

    async def _dpa_apply(self) -> None:
        """(Re)build the transport managers from the effective config and bring
        listeners up immediately. Live sessions on a torn-down listener stay
        attached until the client disconnects."""
        # Under the lock: note the apply and read the effective config.
        async with self._dpa_lock():
            self._dpa_applied = True
            loop = asyncio.get_running_loop()
            self._loop = self._loop or loop
            cfg = self._dpa_cfg.effective()
            # Stop existing listeners.
            for mgr in (self._dpa, self._dpa_ssh):
                if mgr is not None:
                    await mgr.stop()
            self._dpa = self._dpa_ssh = None
            # Stop here when DPA is off.
            if not cfg["enabled"]:
                logger.info("console: Direct Port Access disabled")
                return
            # Detect the host to advertise if none is set.
            if not cfg.get("advertise_host"):
                self._dpa_advertise_auto = await asyncio.to_thread(
                    detect_advertise_host, self._dpa_hub_url())
            # Telnet manager.
            if cfg["telnet_enabled"]:
                self._dpa = self._dpa_manager(proto="telnet", bind=cfg["telnet_bind"],
                                              base=cfg["telnet_base"], allow=cfg["allow"], loop=loop)
            # SSH manager: needs the SSH library and a host key.
            if cfg["ssh_enabled"]:
                mod, err = await asyncio.to_thread(dpa_ssh.ensure_asyncssh)
                self._dpa_ssh_status = {"available": mod is not None, "error": err, "fingerprint": None}
                if mod is not None:
                    try:
                        key = await asyncio.to_thread(dpa_ssh.load_or_create_host_key, mod,
                                                      self.store.path.parent / "dpa_ssh_host_key")
                    except Exception as e:  # noqa: BLE001
                        self._dpa_ssh_status.update(available=False, error=f"host key: {e}")
                        key = None
                    if key is not None:
                        self._dpa_ssh_status["fingerprint"] = dpa_ssh.host_key_fingerprint(key)
                        mgr = self._dpa_manager(proto="ssh", bind=cfg["ssh_bind"],
                                                base=cfg["ssh_base"], allow=cfg["allow"], loop=loop)
                        mgr.listen = dpa_ssh.make_listen(
                            mgr, mod, key, auth=self._dpa_cfg.effective,
                            send_break=self._dpa_send_break)
                        self._dpa_ssh = mgr
                else:
                    logger.warning("console: DPA SSH unavailable: %s", err)
            # Bring listeners up.
            for mgr in (self._dpa_ssh, self._dpa):
                if mgr is not None:
                    try:
                        await mgr.reconcile()
                    except Exception:  # noqa: BLE001
                        logger.exception("console DPA %s reconcile failed", mgr.proto)
            logger.info("console: Direct Port Access enabled (ssh=%s on %s:%d+, telnet=%s on %s:%d+, host=%s)",
                        self._dpa_ssh is not None, cfg["ssh_bind"], cfg["ssh_base"],
                        self._dpa is not None, cfg["telnet_bind"], cfg["telnet_base"],
                        self._dpa_advertise_host() or "?")

    async def _dpa_set_port(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Set or clear one port's fixed DPA TCP port.

        Args:
            data: port_id, proto ("ssh" or "telnet") and port (empty or 0 clears it).

        Returns:
            dict with status and the port's DPA info, or an error message.
        """
        # Check port id and protocol.
        pid = data.get("port_id")
        proto = (data.get("proto") or "ssh").lower()
        if not pid:
            return {"status": "ERROR", "message": "port_id is required"}
        if proto not in ("ssh", "telnet"):
            return {"status": "ERROR", "message": "proto must be ssh or telnet"}
        # Parse the TCP port; empty means clear.
        raw = data.get("port")
        if raw in (None, "", 0, "0"):
            tcp = None
        else:
            try:
                tcp = int(raw)
            except (TypeError, ValueError):
                return {"status": "ERROR", "message": "port must be an integer"}
        # Under the lock: pick the manager and store key.
        async with self._dpa_lock():
            mgr = self._dpa_ssh if proto == "ssh" else self._dpa
            key = "dpa_ssh_port_override" if proto == "ssh" else "dpa_port_override"
            # Check the port is valid and not used by the other transport.
            if tcp is not None:
                err = (mgr.validate_override(pid, tcp) if mgr is not None
                       else (None if 1024 <= tcp <= 65535 else "port must be 1024-65535"))
                other = self._dpa if proto == "ssh" else self._dpa_ssh
                if not err and other is not None and tcp in other._assigned.values():
                    err = f"port {tcp} is in use by the other DPA transport"
                if err:
                    return {"status": "ERROR", "message": err}
            # Save, then apply and check the port took effect.
            self.store.update(pid, **{key: tcp})
            if mgr is not None:
                await mgr.reconcile()
                if tcp is not None and mgr.assignment(pid) != tcp:
                    return {"status": "ERROR", "port_id": pid, "proto": proto,
                            "message": f"override saved but port {tcp} could not be bound (in use on this host?)"}
            return {"status": "SUCCESS", "port_id": pid, "proto": proto, "port": tcp,
                    "dpa": self._dpa_info(pid)}

    def _ensure_dpa_task(self) -> None:
        """Start the DPA supervisor once. It applies the persisted/role config
        (OFF by default) and then reconciles listeners as ports come and go;
        CONSOLE_SET_DPA re-applies live."""
        # Run only once and only if DPA is on.
        if self._dpa_task is not None or not self._dpa_cfg.effective().get("enabled"):
            return
        # Need a running loop.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        # Start the loop task.
        self._loop = self._loop or loop
        self._dpa_task = loop.create_task(self._dpa_loop())

    async def _dpa_loop(self) -> None:
        """Apply the DPA config once, then reconcile listeners every 15 seconds."""
        # Short delay, then apply if nobody has yet.
        await asyncio.sleep(5)
        if not self._dpa_applied:
            try:
                await self._dpa_apply()
            except Exception:  # noqa: BLE001
                logger.exception("console DPA apply failed")
        # Reconcile listeners in a loop.
        while True:
            async with self._dpa_lock():  # never race a live CONSOLE_SET_DPA rebuild
                for mgr in (self._dpa_ssh, self._dpa):
                    if mgr is None:
                        continue
                    try:
                        await mgr.reconcile()  # start/stop listeners as ports appear/vanish
                    except Exception:  # noqa: BLE001
                        logger.exception("console DPA reconcile failed")
            await asyncio.sleep(15)

    async def _monitor_loop(self) -> None:
        """Run the passive capture scan and the login scan every 15 seconds."""
        # Short delay, then scan in a loop.
        await asyncio.sleep(5)
        while True:
            try:
                await asyncio.to_thread(self._monitor_scan)
                await self._monitor_login_scan()
            except Exception:  # noqa: BLE001
                logger.exception("console monitor scan failed")
            await asyncio.sleep(15)

    async def _monitor_login_scan(self) -> None:
        """While monitoring, also try to LOG IN with the stored credentials and
        learn what we can — a silent device reveals nothing to a passive listen,
        so we actively drive an identify. Skips ports a user holds, ones mid-probe,
        ones we can't even open, and any already identified authoritatively; the
        shared backoff (:meth:`_identify_due`) keeps us from hammering creds."""
        # Only when auto-identify and monitoring are on.
        if not self.config.get("auto_identify", True) or not self._credentials:
            return
        # Check each port.
        for p in await self._enumerate_ports():
            pid = p["port_id"]
            # Skip ports in use, being probed, or unopenable.
            if self.sessions.has_user_sessions(pid) or pid in self._probing:
                continue
            if pid in self._unopenable:  # can't open at all — monitor_scan handles recovery
                continue
            # Skip identified ports and ports still in back-off.
            probe = self.store.get(pid).get("probe") or {}
            if self._probe_identified(probe):
                continue
            if not self._identify_due(pid):
                continue
            # Identify it.
            await self._active_identify(pid, p["device"])

    def _monitor_scan(self) -> None:
        """Ensure a passive capture handle on each idle port and glean identity
        from what has scrolled by (no login, read-only). Runs in a thread. A port
        the system can't open is flagged unopenable (hidden from the UI) but keeps
        being retried here so it recovers if it ever starts working."""
        # Only when monitoring is on.
        if not self.config.get("console_monitor", True):
            return
        # Check each port.
        for p in self._enumerate_ports_sync():
            pid = p["port_id"]
            # A human/relay owns the handle, or an exclusive probe is mid-flight —
            # don't interfere; the live session already fans bytes into capture.
            if pid in self._probing:
                self._clear_unopenable(pid)  # it opened for the session → healthy
                continue
            if self.sessions.has_user_sessions(pid):
                self._clear_unopenable(pid)
                self._passive_glean(pid)
                self._boot_watch(pid, self.sessions.snapshot(pid), p["device"])
                continue
            # A live monitor channel whose reader thread has died = the device was
            # pulled / the handle dropped: count a disconnect before we reopen.
            # Count a disconnect when the monitor reader died.
            existing = self.sessions.channel(pid)
            if existing is not None and not existing.reader_alive():
                h = self._health_rec(pid)
                h["disconnects"] += 1
                h["last_disconnect"] = time.time()
                self._health_save(force=True)
            # Open or keep the monitor; flag ports that can't open.
            chan = self.sessions.ensure_monitor(pid, p["device"], self.store.settings(pid))
            if chan is None:
                self._mark_unopenable(pid, self.sessions.monitor_error(pid) or "cannot open port")
                continue
            # Opened: glean identity and watch for boots.
            self._clear_unopenable(pid)
            self._passive_glean(pid)
            self._boot_watch(pid, self.sessions.snapshot(pid), p["device"])

    def _boot_cfg(self) -> Dict[str, Any]:
        """Tunables for the boot watcher (all optional; sane defaults). Boot
        capture is passive — we watch what already scrolls into the rolling
        buffer; the active steps are an opportunistic baud re-lock on a garbled
        line and a single confirming CR nudge before condemning a port as
        "stuck" (neither ever runs on a port a user holds)."""
        # Read values from the role config.
        c = self.config

        def _pos(key: str, default: float) -> float:
            """Return a positive float config value, or the default if missing or invalid."""
            try:
                v = float(c.get(key, default))
            except (TypeError, ValueError):
                return default
            return v if v > 0 else default

        # Build the settings with defaults.
        return {
            "enabled": bool(c.get("console_boot_watch", True)),
            "wake_secs": _pos("console_boot_wake_secs", 45.0),
            "idle_secs": _pos("console_boot_idle_secs", 12.0),
            "stuck_secs": _pos("console_boot_stuck_secs", 150.0),
            "relock_secs": _pos("console_boot_relock_secs", 30.0),
            # How often we're allowed to actively nudge a port that LOOKS stuck to
            # confirm it before believing the passive read. Once an hour is plenty
            # — a device that's genuinely hung stays hung, so there's no rush, and
            # it keeps a noisy/flapping line from being poked constantly.
            "nudge_cooldown_secs": _pos("console_boot_nudge_cooldown_secs", 3600.0),
            "garbage_score": float(c.get("console_boot_garbage_score", 0.55) or 0.55),
        }

    def _boot_watch(self, pid: str, snap: Dict[str, Any], dev: str) -> None:
        """Passively watch a port for a boot/wake cycle and classify it.

        A burst of NEW output after the line has been quiet for a while is treated
        as a device powering on (or resetting). We snapshot the boot transcript,
        and follow it to one of two terminal states:
          • ``booted`` — a login/shell/CLI prompt appeared (device came up), or
          • ``stuck``  — a boot-fault signature (kernel panic, watchdog loop, bad
            image…) appeared, or the boot produced output then stalled with no
            prompt past ``stuck_secs`` (likely a hardware/boot problem to flag).
        If the line is garbled (wrong baud), we opportunistically kick off a baud
        re-lock so the boot is captured legibly. Only a no-prompt timeout may
        trigger a single CR liveness check; positive fault signatures stand.
        No login attempts. Even a CR can interrupt a bootloader's 'press any key'
        countdown, so it is gated by stuck_secs (150s by default) and cooldown."""
        # Only when the boot watcher is on.
        cfg = self._boot_cfg()
        if not cfg["enabled"]:
            return
        # How many new bytes arrived since the last scan.
        now = time.time()
        cur = int(snap.get("capture_bytes") or 0)
        prev = self._mon_bytes.get(pid)
        self._mon_bytes[pid] = cur
        # A channel reopen (baud relock / device re-plug) resets bytes_seen to 0;
        # treat that as "no new output this tick" so we don't misfire.
        new_bytes = (cur - prev) if (prev is not None and cur >= prev) else 0
        talking = new_bytes > 0

        # Health record and current boot episode.
        h = self._health_rec(pid)
        boot = h.get("boot")
        # Re-check an old "stuck" verdict against its saved transcript.
        if boot is not None and boot.get("state") == "stuck":
            stored = boot.get("transcript_tail") or ""
            if not stored.strip():
                # The episode never produced readable text: it was started by line
                # noise (baud mismatch / unplugged adapter bytes), not a boot. With
                # nothing to show, "boot stuck" is a false alarm that otherwise
                # never expires on a silent line, so drop back to idle.
                boot["state"] = "idle"
                boot["stuck_reason"] = ""
                boot["reason"] = "line noise only — no readable boot output"
            elif os_up_marker(stored) and not current_boot_fault(stored):
                # The stored episode already shows a running OS (e.g. an idle
                # logout message) that an older rule set missed. A silent line
                # never produces new output to heal it, so re-judge it here.
                boot["state"] = "booted"
                boot["prompt_seen"] = True
                boot["stuck_reason"] = ""
                boot["reason"] = "recovered: transcript shows a running OS"

        # Recent capture text and how readable it is.
        chan = self.sessions.channel(pid)
        if chan is not None and getattr(chan, "capture", None):
            raw = chan.capture_tail(8192)
            tail = raw.decode("utf-8", "replace")
            score = score_sample(raw)
        else:
            raw, tail, score = b"", "", 1.0

        # New output arrived.
        if talking:
            # Time since the previous new output.
            last_new = self._mon_new_at.get(pid, 0.0)
            gap = (now - last_new) if last_new else 1e9
            self._mon_new_at[pid] = now
            # Start a fresh boot episode only if none is active and the line had
            # been quiet long enough that this really is a (re)boot/wake — not a
            # device that merely chats periodically.
            if (boot is None or boot.get("state") in ("idle", "booted", "stuck")) \
                    and gap >= cfg["wake_secs"]:
                boot = {
                    "state": "booting", "started_at": now, "last_output_at": now,
                    "prompt_seen": False, "relocked": False,
                    "reason": "output after silence — capturing boot cycle",
                    "stuck_reason": "", "transcript_tail": "", "reconnects": 0,
                    # Capture offset where this episode began, so booted-OS
                    # markers are only looked for in THIS episode's output.
                    "start_bytes": cur - new_bytes,
                }
                h["boot"] = boot
            elif boot is not None and boot.get("state") == "stuck" and not current_boot_fault(tail) \
                    and self._boot_reached_os(tail, raw[-new_bytes:].decode("utf-8", "replace")):
                # A "stuck" verdict is not final: if the device later shows a
                # login/CLI/setup prompt in new output (and no current fault),
                # it did boot. Before this, a passing benign fault phrase or a
                # slow boot stayed "stuck" until the next power cycle.
                boot["state"] = "booted"
                boot["prompt_seen"] = True
                boot["reason"] = "recovered: reached a prompt after '%s'" % (
                    boot.get("stuck_reason") or "stuck")
                boot["stuck_reason"] = ""
                boot["booted_at"] = now
            # During a boot: save the transcript and check how it is going.
            if boot is not None and boot.get("state") == "booting":
                boot["last_output_at"] = now
                boot["transcript_tail"] = sanitize_console_text(tail)[-1600:]
                # Some firmware (HPE/Aruba console lines) reprints "Connected at
                # <N> baud" + its full startup banner on EVERY fresh serial
                # handshake — including our own baud sweeps/relocks and a
                # reconnect after the device's own idle-session logout — not
                # only on a real power-on/reset. Each replay is an independent
                # boot/login cycle that can reach a prompt on its own, so treat
                # a NEW replay as the start of a fresh cycle (reset the "stuck"
                # clock) instead of letting several genuine cycles' elapsed time
                # sum into one false "stuck" verdict.
                reconnects = count_line_reconnects(raw.decode("utf-8", "replace"))
                if reconnects > boot.get("reconnects", 0):
                    boot["reconnects"] = reconnects
                    boot["started_at"] = now
                    boot["reason"] = "line reconnected — restarting boot cycle clock"
                self._boot_maybe_relock(pid, dev, score, cfg, boot, now)
                # A fault, an OS prompt, or long repetitive output decide the result.
                fault = current_boot_fault(tail)
                if fault:
                    # A loader/recovery prompt can be responsive without having
                    # booted successfully. Never nudge away a positive fault.
                    boot["state"] = "stuck"
                    boot["stuck_reason"] = fault
                    boot["reason"] = "boot fault detected: %s" % fault
                    boot["stuck_at"] = now
                elif self._boot_reached_os(tail, self._boot_episode_text(boot, raw, cur)):
                    boot["state"] = "booted"
                    boot["prompt_seen"] = True
                    boot["reason"] = "reached a login/shell prompt"
                    boot["booted_at"] = now
                elif (now - boot.get("started_at", now) >= cfg["stuck_secs"]
                      and self._boot_output_repetitive(tail)):
                    # Only REPETITIVE chatter (the same banner over and over) is
                    # treated as a timeout while output flows; varied output is
                    # still boot progress and waits for the quiet path.
                    # Continuously chatty line: output never stops, so the quiet
                    # path can't run. Confirm actively once past the timeout.
                    reason = boot.get("stuck_reason") or "no prompt within boot timeout"
                    if self._boot_maybe_confirm_stuck(pid, dev, cfg, boot, now, reason):
                        boot["state"] = "stuck"
                        boot["stuck_reason"] = reason
                        boot["reason"] = "continuous output without a prompt"
                        boot["stuck_at"] = now
        elif boot is not None and boot.get("state") == "booting":
            # Output stopped. Once it's been quiet a moment, decide the outcome.
            # No new output during a boot: decide once the line has been quiet long enough.
            since_out = now - boot.get("last_output_at", now)
            elapsed = now - boot.get("started_at", now)
            if since_out >= cfg["idle_secs"]:
                if self._boot_reached_os(tail, self._boot_episode_text(boot, raw, cur)):
                    boot["state"] = "booted"
                    boot["prompt_seen"] = True
                    boot["reason"] = "reached a login/shell prompt"
                    boot["booted_at"] = now
                elif elapsed >= cfg["stuck_secs"]:
                    reason = boot.get("stuck_reason") or "no prompt within boot timeout"
                    if self._boot_maybe_confirm_stuck(pid, dev, cfg, boot, now, reason):
                        boot["state"] = "stuck"
                        boot["stuck_reason"] = reason
                        boot["reason"] = "boot output stopped before a prompt appeared"
                        boot["stuck_at"] = now
        # Save health records.
        self._health_save()

    @staticmethod
    def _boot_episode_text(boot: Dict[str, Any], raw: bytes, cur: int) -> str:
        """The part of the capture tail written since this boot episode began
        (the whole tail if the episode predates start-offset tracking)."""
        # Keep only the bytes written since the episode began.
        start = boot.get("start_bytes")
        n = cur - start if isinstance(start, int) else 0
        if 0 < n < len(raw):
            raw = raw[-n:]
        return raw.decode("utf-8", "replace")

    @staticmethod
    def _boot_reached_os(tail: str, episode_text: str) -> bool:
        """True if the device has evidently booted its OS: the tail ends at a
        login/CLI/setup prompt, or this episode's output contains text only a
        running OS prints (see fingerprint.os_up_marker: "Login incorrect",
        "<host> login: admin", the ArubaOS setup dialog, ...). The marker check
        matters because the passive tail often ends in an echoed username, a
        retry message or idle chatter after the prompt, and those booted
        devices were reported "stuck". A bootloader prompt at the tail still
        means not booted."""
        # A bootloader prompt means not booted.
        if is_recovery_prompt(tail):
            return False
        return looks_like_prompt(tail) or bool(os_up_marker(episode_text))

    @staticmethod
    def _boot_output_repetitive(tail: str) -> bool:
        """True if the recent output is dominated by a few repeated lines
        (chatter), as opposed to varied boot-progress output."""
        # Last 20 non-empty lines; repetitive if few are distinct.
        lines = [ln.strip() for ln in sanitize_console_text(tail or "").splitlines()
                 if ln.strip()][-20:]
        return len(lines) >= 4 and len(set(lines)) * 4 <= len(lines)

    def _user_recently_active(self, pid: str, cfg: Dict[str, Any]) -> bool:
        """True if a session attached to ``pid`` wrote a keystroke recently
        enough to count as genuine, ongoing human activity (as opposed to a
        session that's merely attached — an idle browser tab, an abandoned
        relay leg, or a stale record). Gated on the same ``stuck_secs`` window
        the boot watcher already uses, so a human slowly reading a long banner
        between retries is still "recent" without inventing a second tunable."""
        # Needs an attached session that typed recently.
        if not self.sessions.has_user_sessions(pid):
            return False
        last = self.sessions.last_user_write_at(pid)
        return bool(last) and (time.time() - last) <= cfg["stuck_secs"]

    def _boot_maybe_confirm_stuck(self, pid: str, dev: str, cfg: Dict[str, Any],
                                  boot: Dict[str, Any], now: float, reason: str) -> bool:
        """Gate before condemning a boot episode as "stuck".

        The passive read alone can't tell a genuinely hung boot from a device
        that's already sitting at a live prompt but buried behind unrelated
        console chatter — e.g. a switch endlessly repeating its own console
        idle-timeout banner ("Console terminated due to inactivity.") never lets
        the prompt underneath scroll back into the capture tail. Rather than
        trust that, actively confirm with a single CR nudge (see
        :func:`check_line_responsive`) — but never while a human is actively
        typing into the port (their own keystrokes already prove it's live —
        see :meth:`_user_recently_active`) and no more than once per
        ``nudge_cooldown_secs`` (a genuinely dead device stays dead; there's no
        rush, and it keeps a flapping line from being poked constantly).

        Returns True for the passive-stuck fallback when a nudge cannot run
        (probe holds the port, an ATTACHED-BUT-IDLE session holds it, loop
        unavailable, or the per-port cooldown blocks a new nudge); such
        verdicts are tagged ``verdict_basis='passive'``. Returns False while a
        nudge is pending (its result decides the episode), AND whenever a
        session is actively typing into the port right now (a human's own
        recent keystrokes are direct evidence of liveness, so the episode is
        deferred rather than condemned — merely HOLDING the port with no
        recent activity is not enough on its own, or a stale/abandoned session
        would hide a genuinely hung boot forever)."""
        # Wait for a nudge already in flight; defer while a user is typing.
        if pid in self._boot_nudge_pending:
            return False  # a nudge is in flight — wait for its verdict
        if self._user_recently_active(pid, cfg):
            # A human (or relay) is actively typing into this port right now —
            # e.g. retrying a login after a typo, working through a long
            # security banner, or re-entering credentials after a lockout
            # message. Their own recent keystrokes ARE proof the line is live
            # and responsive; it is the opposite of a hung/unresponsive boot.
            # Falling through to the passive "stuck" verdict here previously
            # flagged a perfectly healthy, human-supervised login session as a
            # failed boot the moment the repetitive-banner + timeout heuristic
            # tripped underneath them. Never condemn this as stuck — defer
            # (this episode resolves once a clean prompt shows, via the
            # ordinary looks_like_prompt checks, or once activity stops and the
            # line settles) — and never interject our own CR into their input.
            boot["reason"] = "user actively typing — deferring stuck verdict"
            return False
        # An attached but idle session: use the passive verdict.
        if self.sessions.has_user_sessions(pid):
            # A session is attached but hasn't typed recently (idle tab,
            # abandoned relay leg, stale record) — that's no evidence either
            # way, so fall back to the prior passive-stuck behavior exactly as
            # before this fix (never send our own CR into ANY attached
            # session, active or not) rather than deferring indefinitely.
            boot["verdict_basis"] = "passive"
            return True
        # A probe holds the port: use the passive verdict.
        if pid in self._probing:
            boot["verdict_basis"] = "passive"
            return True
        # No usable loop: use the passive verdict.
        loop = self._loop
        if loop is None:
            boot["verdict_basis"] = "passive"
            return True
        # A stopped/closed loop accepts scheduling but never runs it, which would
        # leave the port pending forever — treat it as "no nudge available".
        if getattr(loop, "is_closed", lambda: False)() or \
                not getattr(loop, "is_running", lambda: True)():
            boot["verdict_basis"] = "passive"
            return True
        # Nudged too recently: use the passive verdict.
        last_nudge = self._boot_nudge_at.get(pid)
        if last_nudge is not None and now - last_nudge < cfg["nudge_cooldown_secs"]:
            boot["verdict_basis"] = "passive"
            return True
        # Schedule a nudge and wait for its result.
        self._boot_nudge_at[pid] = now
        self._boot_nudge_pending.add(pid)
        boot["reason"] = "confirming responsiveness before flagging stuck: %s" % reason
        check = self._boot_liveness_check(pid, dev, reason)
        try:
            asyncio.run_coroutine_threadsafe(check, loop)
        except Exception:  # noqa: BLE001 - loop shutting down / not running
            check.close()
            logger.debug("boot liveness-check dispatch failed for %s", pid)
            self._boot_nudge_pending.discard(pid)
            return True
        return False

    async def _boot_liveness_check(self, pid: str, dev: str, reason: str) -> None:
        """Single confirming CR nudge before condemning a boot episode as stuck
        (scheduled by :meth:`_boot_maybe_confirm_stuck`, rate-limited). If the
        device answers with a live prompt, the passive tail was just buried in
        noise — resolve the episode as booted instead of stuck."""
        # Skip when the port got busy; else nudge with exclusive access.
        try:
            if pid in self._probing or self.sessions.has_user_sessions(pid):
                self._boot_liveness_apply(pid, reason, {"error": "port became busy"})
                return
            try:
                res = await self._exclusive_probe(pid, self._boot_liveness_blocking, pid, dev)
            except Exception as e:  # noqa: BLE001
                logger.exception("console: boot liveness check failed on %s", pid)
                res = {"responsive": False, "tail": "", "error": str(e) or "probe failed"}
            self._boot_liveness_apply(pid, reason, res or {})
        # Always clear the pending flag.
        finally:
            self._boot_nudge_pending.discard(pid)

    def _boot_liveness_apply(self, pid: str, reason: str, res: Dict[str, Any]) -> None:
        """Apply a liveness-check result to the port's current boot episode.

        Args:
            pid: port id.
            reason: the passive stuck reason being confirmed.
            res: check result (responsive, tail, error).
        """
        # Only a boot still in progress is updated.
        h = self._health_rec(pid)
        boot = h.get("boot")
        if not boot or boot.get("state") != "booting":
            return  # episode already resolved (or superseded) while we were probing
        # Save the transcript from the nudge.
        now = time.time()
        tail = res.get("tail") or ""
        if tail:
            boot["transcript_tail"] = sanitize_console_text(tail)[-1600:]
        # A boot fault in the reply settles it as stuck.
        fault = current_boot_fault(tail)
        if fault:
            # A hard fault signature bypasses everything below unconditionally —
            # never nudged/deferred away, active typing or not.
            boot["verdict_basis"] = "active"
            boot["state"] = "stuck"
            boot["stuck_reason"] = fault
            boot["reason"] = "boot fault detected: %s" % fault
            boot["stuck_at"] = now
            self._health_save(force=True)
            return
        # Boot settings.
        cfg = self._boot_cfg()

        def _defer_for_active_user() -> bool:
            """Return True (and note why) if a user typed recently, so the verdict waits."""
            # Defense-in-depth, not a currently-reachable race: today
            # _open_user_session() refuses every new open while pid is in
            # _boot_nudge_pending, and a nudge is only ever scheduled when NO
            # session was attached at schedule time (_boot_maybe_confirm_stuck
            # takes the idle/passive branch instead whenever one already is).
            # So a session cannot actually attach between the sync gate and
            # this coroutine finishing today. This check exists so that
            # invariant staying true isn't a silent precondition of correctness
            # — if a future relay/DPA open path, or a loosened
            # _boot_nudge_pending guard, ever lets an attach slip into that
            # window, the single point that writes a verdict still won't
            # condemn someone who is actively typing. Gated on
            # _user_recently_active (not mere attachment) for consistency with
            # _boot_maybe_confirm_stuck's sync gate: an idle/abandoned session
            # must NOT be able to hide a genuine hang here either. Only
            # consulted below when we're about to write a STUCK verdict — a
            # genuine BOOTED result is never thrown away just because someone
            # is attached.
            if not self._user_recently_active(pid, cfg):
                return False
            boot["reason"] = "user actively typing during confirmation — deferring stuck verdict"
            return True

        # Responsive: bootloader prompt means stuck, anything else means booted.
        if res.get("responsive") and not res.get("error"):
            if is_recovery_prompt(tail):
                # Responsive, but at a BOOTLOADER — the device answered our nudge
                # from rommon/loader/u-boot and never reached its OS. A bootloader
                # can sit there indefinitely printing nothing, so there may be no
                # fault text for current_boot_fault() to find; without this check
                # the generic prompt shape below would score it "booted", which is
                # exactly the hang this watcher exists to report.
                if _defer_for_active_user():
                    return
                boot["verdict_basis"] = "active"
                boot["state"] = "stuck"
                boot["stuck_reason"] = "stopped at bootloader prompt"
                boot["reason"] = ("confirmed stuck: device answered at a "
                                  "bootloader/recovery prompt, not a booted OS")
                boot["stuck_at"] = now
            else:
                boot["verdict_basis"] = "active"
                boot["state"] = "booted"
                boot["prompt_seen"] = True
                boot["reason"] = ("active liveness check found a live prompt — the "
                                  "port wasn't stuck, console chatter was burying it")
                boot["booted_at"] = now
                boot["stuck_reason"] = ""
        # No response: stuck, unless a user is typing.
        else:
            if _defer_for_active_user():
                return
            boot["verdict_basis"] = "active"
            boot["state"] = "stuck"
            boot["stuck_reason"] = reason
            if res.get("error"):
                # Fall back to the passive verdict, not a confirmed hang.
                # Retain the attempt timestamp even when no CR could be sent.
                boot["verdict_basis"] = "passive"
                boot["reason"] = ("passive stuck verdict: %s (liveness check "
                                  "unavailable: %s)" % (reason, res["error"]))
            else:
                boot["reason"] = ("confirmed stuck: %s (no recognized prompt "
                                  "after a wake nudge)" % reason)
            boot["stuck_at"] = now
        # Save now.
        self._health_save(force=True)

    def _boot_liveness_blocking(self, port_id: str, dev: str) -> Dict[str, Any]:
        """Blocking single-CR liveness nudge on a transient serial handle (run via
        asyncio.to_thread): read-only, no credentials spent (see
        :func:`check_line_responsive`)."""
        # Open at the saved baud.
        baud = self.store.settings(port_id).get("baud") or DEFAULT_BAUD
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"responsive": False, "tail": "", "error": "open failed: %s" % (e or "error")}
        # Send a CR and read the reply; always close the port.
        try:
            responsive, transcript = check_line_responsive(lambda: ser.read(256), ser.write)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass
        # Reply.
        return {"responsive": responsive, "tail": transcript}

    def _boot_maybe_relock(self, pid: str, dev: str, score: float,
                           cfg: Dict[str, Any], boot: Dict[str, Any],
                           now: float) -> None:
        """During a boot, if the line reads as garbage (likely wrong baud), schedule
        ONE exclusive baud re-lock (rate-limited) so we capture the boot legibly.
        No-op when a user holds the port, or when an operator pinned the rate."""
        # Only for a garbled line on a free port.
        if score >= cfg["garbage_score"]:
            return
        if self.sessions.has_user_sessions(pid) or pid in self._probing:
            return
        # Not when the user pinned the baud.
        probe = self.store.get(pid).get("probe") or {}
        # Only an operator pin blocks a re-sweep. An AUTOMATIC lock does not: a
        # port that confidently locked onto the wrong rate would otherwise stay
        # there forever, which is exactly how sessions got stranded on 9600.
        # The sweep restarts at 115200, so a garbled line comes back to it.
        if probe.get("baud_pinned"):
            return
        # At most once per relock period.
        if now - self._baud_relock_at.get(pid, 0.0) < cfg["relock_secs"]:
            return
        # Note it and schedule the sweep on the loop.
        self._baud_relock_at[pid] = now
        boot["relocked"] = True
        loop = self._loop
        if loop is None:
            return
        try:
            asyncio.run_coroutine_threadsafe(self._relock_baud(pid, dev), loop)
        except Exception:  # noqa: BLE001 - loop shutting down / not running
            logger.debug("boot baud-relock dispatch failed for %s", pid)

    async def _relock_baud(self, pid: str, dev: str) -> None:
        """Sweep baud rates on a garbled line and, if we lock on confidently,
        persist the new rate + mark it confident. The passive monitor then reopens
        the channel at the correct baud on its next pass (ensure_monitor)."""
        # Only for a free port without a pinned baud.
        if pid in self._probing or self.sessions.has_user_sessions(pid):
            return
        # An operator-pinned rate is never auto-relocked.
        if (self.store.get(pid).get("probe") or {}).get("baud_pinned"):
            return
        # Sweep rates with exclusive access.
        try:
            d = await self._exclusive_probe(pid, detect_baud, dev, DEFAULT_BAUD_CANDIDATES)
        except Exception:  # noqa: BLE001
            logger.exception("console: baud relock failed on %s", pid)
            return
        # Save a confident result.
        if not (d and d.get("confident") and d.get("baud")):
            return
        probe = dict(self.store.get(pid).get("probe") or {})
        probe["detected_baud"] = d["baud"]
        probe["baud_confident"] = True
        self.store.update(pid, settings={"baud": d["baud"]}, probe=probe)
        logger.info("console: locked baud %d on %s from boot capture", d["baud"], pid)

    # Substrings that indicate a KNOWN-faulty/non-real port (for clearer logs).
    # We hide on ANY open failure regardless; these just classify the message.
    _UNOPENABLE_HINTS = (
        "could not configure port", "input/output error", "errno 5",
        "no such file or directory", "errno 2", "device or resource busy",
        "errno 16", "permission denied", "errno 13", "open failed",
        "could not open", "device disconnected", "errno 6",
    )

    def _record_identify_telemetry(self, pid: str, res: Dict[str, Any], method: str = "login") -> None:
        """Fold the outcome of an identify / AI-identify attempt into the port's
        health record so the diagnostics report can explain WHY a device isn't
        being identified (login prompt seen? creds tried? what did the line say?).
        Nothing sensitive is stored — only prompt-detection flags + a printable
        transcript tail (control bytes stripped)."""
        # Health record and identify counters.
        h = self._health_rec(pid)
        diag = dict(res.get("diag") or {})
        rec = h.setdefault("identify", {
            "attempts": 0, "logins_ok": 0, "identifies_ok": 0,
        })
        # Count the attempt and its outcome.
        rec["attempts"] += 1
        if res.get("logged_in"):
            rec["logins_ok"] += 1
        if res.get("identity") or res.get("vendor"):
            rec["identifies_ok"] += 1
        # Last attempt details.
        rec["last_attempt"] = time.time()
        rec["method"] = method
        rec["logged_in"] = bool(res.get("logged_in"))
        rec["vendor"] = res.get("vendor")
        rec["error"] = res.get("error", "")
        rec["login_prompt_seen"] = bool(diag.get("login_prompt_seen"))
        rec["password_prompt_seen"] = bool(diag.get("password_prompt_seen"))
        rec["shell_prompt_seen"] = bool(diag.get("shell_prompt_seen"))
        rec["any_output"] = bool(diag.get("any_output"))
        rec["bytes"] = diag.get("bytes", 0)
        rec["creds_tried"] = diag.get("creds_tried", 0)
        rec["creds_available"] = diag.get("creds_available", len(self._credentials))
        # Operator-supplied vs factory-default split: creds_tried==factory-only
        # with operator_creds==0 is the tell-tale "operator credentials never
        # reached this spoke" case (seed/deploy gap), not a wrong-password case.
        rec["operator_creds"] = len(self._credentials)
        rec["logged_out"] = bool(diag.get("logged_out"))
        rec["reason"] = diag.get("reason", "")
        rec["tail"] = diag.get("tail", "")
        # Hostname history, LLM command details, save.
        self._track_hostname(rec, res, method)
        if method == "llm":
            rec["commands_run"] = res.get("commands_run") or list((res.get("outputs") or {}).keys())
            rec["rejected"] = res.get("rejected") or []
        self._health_save()

    def _track_hostname(self, rec: Dict[str, Any], res: Dict[str, Any], method: str) -> None:
        """Track the identified hostname over successive attempts so diagnostics
        can show WHY a name is unstable: a rolling history of DISTINCT hostnames
        (with when/how each was seen), a change counter, and the source (parsed
        from a command output vs gleaned from the CLI prompt vs the LLM). A port
        whose hostname flaps — e.g. a noisy line producing garbled prompts, or a
        prompt-sourced name that differs from the command-sourced one — stands out
        immediately, vs a stable single-value port."""
        # Hostname found and where it came from.
        host = str((res.get("identity") or {}).get("hostname") or "").strip()
        source = res.get("hostname_source") or ("llm" if method == "llm" else "")
        hist = rec.setdefault("hostname_history", [])
        # New distinct name: count the change and add it to history.
        if host:
            prev = hist[-1]["host"] if hist else None
            if host != prev:
                if prev is not None:
                    rec["hostname_changes"] = rec.get("hostname_changes", 0) + 1
                hist.append({"host": host, "ts": time.time(),
                             "method": method, "source": source})
                del hist[:-10]  # keep the last 10 distinct observations
            rec["hostname"] = host
            rec["hostname_source"] = source
        # Summary fields.
        rec.setdefault("hostname_changes", 0)
        rec["hostname_distinct"] = len({h["host"] for h in hist})
        rec["hostname_stable"] = rec["hostname_changes"] == 0

    def _health_save(self, force: bool = False) -> None:
        """Persist the diagnostics history. Debounced by default (this is called
        on every probe/monitor tick); ``force`` writes immediately for the rare
        state transitions worth surviving an abrupt shutdown."""
        # Write now, or debounced.
        if force:
            self._health_store.flush(self._health)
        else:
            self._health_store.save(self._health)

    def _health_rec(self, pid: str) -> Dict[str, Any]:
        """Get-or-create the failure/disconnect history record for a port."""
        # Create a blank record on first use.
        h = self._health.get(pid)
        if h is None:
            h = {"open_failures": 0, "disconnects": 0, "recoveries": 0,
                 "last_error": "", "first_failure": 0.0, "last_failure": 0.0,
                 "last_disconnect": 0.0, "last_recovery": 0.0, "currently_failing": False}
            self._health[pid] = h
            self._health_save(force=True)  # first sighting of a port — rare, persist now
        return h

    def _boot_info(self, pid: str) -> Optional[Dict[str, Any]]:
        """Compact boot/wake status for the UI + diagnostics (None if this port has
        never been seen booting). Ages are seconds-since for easy display; the
        transcript tail is a short, ANSI-stripped snippet of the boot output."""
        # Nothing if never seen booting.
        boot = (self._health.get(pid) or {}).get("boot")
        if not boot:
            return None
        # Compact status with ages in seconds.
        now = time.time()
        started = boot.get("started_at", 0.0)
        last_out = boot.get("last_output_at", 0.0)
        return {
            "state": boot.get("state", "idle"),
            "reason": boot.get("reason", ""),
            "stuck_reason": boot.get("stuck_reason", ""),
            "prompt_seen": bool(boot.get("prompt_seen")),
            "relocked": bool(boot.get("relocked")),
            "started_at": started,
            "age_s": round(now - started) if started else 0,
            "since_output_s": round(now - last_out) if last_out else 0,
            "transcript_tail": (boot.get("transcript_tail") or "")[-1200:],
            # How the verdict was reached: "active" if a wake nudge actually
            # answered, "passive" if it was inferred from the capture alone
            # because no nudge could run. An operator reading a "stuck" port
            # needs to know which — a passive verdict is a strong suspicion, an
            # active one is confirmed.
            "verdict_basis": boot.get("verdict_basis", ""),
        }

    def _mark_unopenable(self, pid: str, err: str) -> None:
        """Hide a port that failed to open and record the failure in its health record."""
        # Count only the change from healthy to failing.
        now = time.time()
        h = self._health_rec(pid)
        if pid not in self._unopenable:  # transition healthy → failing = a new episode
            known = any(hint in (err or "").lower() for hint in self._UNOPENABLE_HINTS)
            logger.info("console: hiding port %s from UI — %s serial port (%s)",
                        pid, "faulty/non-real" if known else "unopenable", err)
            h["open_failures"] += 1
            h["currently_failing"] = True
            if not h["first_failure"]:
                h["first_failure"] = now
        # Always note the latest error.
        h["last_failure"] = now
        h["last_error"] = err
        self._unopenable[pid] = {"error": err, "since": now}
        self._health_save()

    def _clear_unopenable(self, pid: str) -> None:
        """Unhide a port that opened again and record the recovery."""
        if self._unopenable.pop(pid, None) is not None:
            logger.info("console: port %s is openable again — restoring to UI", pid)
            h = self._health_rec(pid)
            h["recoveries"] += 1
            h["last_recovery"] = time.time()
            h["currently_failing"] = False
            self._health_save(force=True)

    def _diagnostics_summary(self) -> Dict[str, Any]:
        """Spoke-level context for the diagnostics report: whether the agent is
        even trying to log in (auto-identify on/off), how many operator
        credentials it has (0 ⇒ only the factory-default set is tried), and
        whether passive monitoring is on. This explains the whole-agent 'why it
        isn't logging in' case that no per-port row can show."""
        # Gather spoke-level settings.
        auto = bool(self.config.get("auto_identify", True))
        creds = len(self._credentials)
        factory = bool(self.config.get("console_factory_default_creds", True))
        return {
            "auto_identify": auto,
            "credentials_loaded": creds,
            "factory_default_creds": factory,
            "monitor": bool(self.config.get("console_monitor", True)),
            "port_count": len(self._enum_cached()),
            # Login is only ever attempted when auto-identify is on AND there is at
            # least one credential to try (operator creds or the factory defaults).
            "login_enabled": auto and (creds > 0 or factory),
        }

    def _identify_status(self, pid: str, present: bool) -> Dict[str, Any]:
        """Explain whether an active login/identify is being attempted for a port
        and when the next attempt is due — the missing piece for the 'system isn't
        trying to login' case, since a port that is never probed otherwise has no
        telemetry row at all."""
        # Retry policy and this port's back-off state.
        now = time.monotonic()
        cfg = self._identify_cfg()
        cap = cfg["max_attempts"]
        fails = self._probe_fails.get(pid, 0)
        given_up = bool(cap) and fails >= cap
        last = self._probe_attempts.get(pid, 0.0)
        delay = self._probe_delay.get(pid, 0.0)
        attempted = bool(last)
        next_in = 0.0 if not attempted else max(0.0, delay - (now - last))
        # Identified ports wait for re-verify.
        probe = self.store.get(pid).get("probe") or {}
        active_id = self._probe_identified(probe)
        if active_id:
            last_v = self._identify_verify_ts.get(pid)
            next_in = 0.0 if last_v is None else max(0.0, cfg["reverify"] - (now - last_v))
        # Pick the reason text.
        if not self.config.get("auto_identify", True):
            reason = "auto-identify is disabled for this agent (config auto_identify=false)"
        elif not present:
            reason = "device not currently present"
        elif self.sessions.has_user_sessions(pid):
            reason = "a user session holds this port — auto-probe is paused"
        elif pid in self._probing:
            reason = "identify in progress"
        elif active_id:
            reason = ("profiled via active login (hostname confirmed) — re-verified "
                      f"every {round(cfg['reverify'] / 3600, 1):g}h "
                      "(use Profile Device to re-check now)")
        elif probe.get("stale") and (probe.get("identity") or {}).get("hostname") and next_in > 0:
            reason = ("last-known name kept, but the latest attempt didn't re-confirm it — "
                      "retrying on backoff")
        elif given_up:
            reason = (f"gave up after {fails} consecutive failed attempts "
                      f"(console_identify_max_attempts={cap}) — replug or probe manually")
        elif not attempted:
            reason = "not attempted yet — will try on the next scan"
        elif next_in > 0:
            reason = "waiting for retry backoff after a failed attempt"
        else:
            reason = "due — will attempt on the next scan"
        # Reply.
        return {"attempted": attempted, "backoff_s": round(delay),
                "next_attempt_in": round(next_in), "skip_reason": reason,
                "consecutive_fails": fails, "max_attempts": cap, "given_up": given_up,
                "active_identity": active_id}

    def _diagnostics(self) -> List[Dict[str, Any]]:
        """Health rows for the serial-connection diagnostics report: every port
        with a failure story (open failures, disconnects, currently failing, OR a
        recorded identify/login attempt), plus any present port not yet identified
        via active login (so the operator can see WHY it isn't being logged into
        and when the next attempt is due). Newest/worst first. Includes ports that
        have vanished from enumeration (``present=False`` — device pulled)."""
        # Live ports.
        live = {p["port_id"]: p for p in self._enum_cached()}
        rows: List[Dict[str, Any]] = []
        # One row per port with history or present now.
        for pid in set(self._health) | set(live):
            h = self._health.get(pid, {})
            ident = h.get("identify") or {}
            p = live.get(pid, {})
            saved = self.store.get(pid)
            probe = saved.get("probe") or {}
            # Skip ports with nothing to show.
            has_story = (h.get("open_failures") or h.get("disconnects")
                         or h.get("currently_failing") or ident.get("attempts"))
            # Surface EVERY present port — identified or not. The identify-attempt
            # counters live in the in-memory health record, which resets on an
            # agent restart, so gating on them (or on "not yet actively identified")
            # would hide already-identified ports until their next re-verify. The
            # operator wants to see every device (e.g. to debug why one that IS
            # identified still isn't getting a hostname), so any live port counts.
            candidate = pid in live
            if not (has_story or candidate):
                continue
            # Build the row.
            snap = self.sessions.snapshot(pid)
            rows.append({
                "port_id": pid,
                "device": p.get("device", ""),
                "present": pid in live,
                "alias": saved.get("alias", ""),
                "tenant_id": saved.get("tenant_id", ""),
                "currently_failing": bool(h.get("currently_failing")),
                "open_failures": h.get("open_failures", 0),
                "disconnects": h.get("disconnects", 0),
                "recoveries": h.get("recoveries", 0),
                "last_error": h.get("last_error", ""),
                "first_failure": h.get("first_failure", 0.0),
                "last_failure": h.get("last_failure", 0.0),
                "last_disconnect": h.get("last_disconnect", 0.0),
                "last_recovery": h.get("last_recovery", 0.0),
                "monitoring": snap["monitoring"],
                "in_use": snap["has_user"],
                "last_activity": snap["last_activity"],
                "identified": bool(probe.get("identity") or probe.get("vendor")),
                "vendor": probe.get("vendor"),
                "identify": ident,   # login/AI-identify telemetry (why it did/didn't work)
                "schedule": self._identify_status(pid, pid in live),  # why/when it (isn't) logging in
                "boot": self._boot_info(pid),  # boot/wake cycle status (None if never observed)
            })
        # Worst first.
        rows.sort(key=lambda d: (d["currently_failing"],
                                 d["open_failures"] + d["disconnects"],
                                 (d.get("identify") or {}).get("attempts", 0)), reverse=True)
        return rows

    def _passive_glean(self, pid: str) -> None:
        """Merge best-effort identity gleaned from the console into the stored
        probe — WITHOUT clobbering an authoritative active-probe result.

        Parses the live passive capture AND the port's SAVED identify banner: an
        already-identified but silent device (e.g. a switch sitting at a bare
        prompt) emits nothing new, yet its saved banner may still hold un-parsed
        identity — notably a hostname an older identify never extracted. Since we
        already know the vendor, we also apply that profile's field regexes
        directly, so a missing name is recovered from the saved banner with NO
        re-probe (respecting the 'don't re-login identified devices' rule)."""
        # Saved probe plus live capture text.
        probe = dict(self.store.get(pid).get("probe") or {})
        chan = self.sessions.channel(pid)
        live = chan.capture_tail(65536).decode("utf-8", "replace") if (chan and chan.capture) else ""
        text = "\n".join(t for t in (probe.get("banner") or "", live) if t)
        if not text:
            return
        # Glean from the text.
        res = passive_identify(text)
        gleaned = dict(res.get("identity") or {})
        stored_vendor = self._stored_vendor(probe)
        # We already know the vendor → apply that profile's anchored field regexes
        # directly (detect_vendor can fail to re-recognize a truncated banner) to
        # backfill any missing fields, e.g. an AOS-S "System Name : <host>".
        # Apply the known vendor's fields too.
        if stored_vendor:
            prof = next((p for p in PROFILES if p["name"] == stored_vendor), None)
            if prof:
                for k, v in _extract_profile_fields(prof, text).items():
                    gleaned.setdefault(k, v)
        # Fall back to the prompt for a hostname.
        if not gleaned.get("hostname"):
            hn = prompt_hostname(text)
            if hn:
                gleaned["hostname"] = hn
        # Clean gleaned and stored identities.
        gleaned = scrub_identity(gleaned)
        stored_ident = probe.get("identity") or {}
        merged = scrub_identity(stored_ident)
        # Junk stored by an older version (or a legacy "linux" verdict) is
        # corrected even when nothing new was gleaned.
        changed = merged != stored_ident or stored_vendor != probe.get("vendor")
        probe["vendor"] = stored_vendor
        # Nothing new: stop.
        if not (gleaned or res.get("vendor") or changed):
            return
        # Merge: fill gaps; overwrite only when not from an active login.
        active = probe.get("source") == "active"
        for k, v in gleaned.items():
            if not v:
                continue
            # Active-login identity is authoritative: passive only fills its gaps.
            # For a passively-sourced probe, a device's name/type/etc. can legitimately
            # change (rename, re-role, swap), so let a differing gleaned value update it.
            if not merged.get(k):
                merged[k] = v
                changed = True
            elif not active and merged.get(k) != v:
                merged[k] = v
                changed = True
        # A passive verdict may refine a passive one, but never downgrade a
        # confident vendor to a weaker one. Even a logged-in (active) verdict is
        # corrected when it was unknown/"linux", or when it says hp-procurve but
        # the device's own model / login-history line is AOS-CX.
        # Fix the vendor when the evidence says so.
        cand = res.get("vendor")
        if is_cx_misfiled_as_procurve(stored_vendor, merged, text):
            probe["vendor"] = "aruba-cx"
            changed = True
        elif (not active and vendor_should_replace(stored_vendor, cand)) \
                or vendor_is_upgrade(stored_vendor, cand):
            probe["vendor"] = cand
            changed = True
        # Refresh the banner tail with LIVE output (never overwrite it with itself)
        # so the port shows recent console output.
        # Keep the latest banner.
        if live:
            tail = live[-2000:]
            if tail and probe.get("banner") != tail:
                probe["banner"] = tail
                changed = True
        # Save only if something changed.
        if not changed:
            return
        probe["identity"] = merged
        if not active:
            probe.setdefault("source", "passive")
        self.store.update(pid, probe=probe)

    async def get_status(self) -> Dict[str, Any]:
        """Return spoke health: port counts, sessions, monitored ports and credentials."""
        # Make sure the loops are running, then count ports.
        self._ensure_autoprobe_task()
        self._ensure_monitor_task()
        ports = await self._enumerate_ports()
        return {
            "spoke_id": self.spoke_id,
            "module": "console",
            "port_count": len(ports),
            "open_ports": sum(1 for p in ports if self.sessions.has_user_sessions(p["port_id"])),
            "monitored_ports": sum(1 for p in ports if self.sessions.snapshot(p["port_id"]).get("monitoring")),
            "credentials_loaded": len(self._credentials),
            "status": "HEALTHY",
        }

    def get_version(self) -> str:
        """Return the version from the VERSION file, or "unknown"."""
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
