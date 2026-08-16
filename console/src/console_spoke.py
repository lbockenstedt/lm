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
import asyncio
import base64
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from serial_manager import (
        PortStore, SessionManager, enumerate_ports, detect_baud, open_raw, DEFAULT_BAUD_CANDIDATES,
    )
    from fingerprint import run_identify, read_running_config, push_config, PROFILES, passive_identify, run_commands
except ImportError:  # loaded as a package (agent role loader) or from repo root
    from .serial_manager import (  # type: ignore
        PortStore, SessionManager, enumerate_ports, detect_baud, open_raw, DEFAULT_BAUD_CANDIDATES,
    )
    from .fingerprint import run_identify, read_running_config, push_config, PROFILES, passive_identify, run_commands  # type: ignore

logger = logging.getLogger("ConsoleSpoke")


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
        super().__init__(spoke_id, config)
        # Set by RoleConnection after registration so the reader thread can push
        # CONSOLE_DATA_UP frames to the hub (mirrors the LE/GenericAgent pattern).
        self.control_plane = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.store = PortStore()
        self.sessions = SessionManager(on_data=self._on_serial_data)
        # Auto-identify (fingerprint) state. Credentials are pushed (signed) by
        # the hub via CONSOLE_SET_CREDENTIALS and held in memory only (never
        # logged/persisted). The background loop probes each newly-seen port once.
        self._credentials: list = []
        self._autoprobe_task = None
        self._probe_attempts: Dict[str, float] = {}  # port_id → last attempt (monotonic)
        self._probe_delay: Dict[str, float] = {}      # port_id → current login-retry backoff (s)
        self._probing: set = set()
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
        # recovery cycles (flapping). In memory (since process start).
        self._health: Dict[str, Dict[str, Any]] = {}

    # ── reader-thread → hub bridge ────────────────────────────────────────────
    def _on_serial_data(self, session_id: str, data: bytes) -> None:
        """Called from a PortChannel reader THREAD. Schedule the unsolicited push
        back onto the event loop (send_to_hub is a coroutine)."""
        cp, loop = self.control_plane, self._loop
        if cp is None or loop is None:
            return
        if data:
            ptype = "CONSOLE_DATA_UP"
            payload = {"session_id": session_id, "data": base64.b64encode(data).decode()}
        else:
            # Empty read → the device/handle went away; tell the browser leg.
            ptype = "CONSOLE_ERROR"
            payload = {"session_id": session_id, "error": "serial read ended"}

        async def _push():
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

        try:
            asyncio.run_coroutine_threadsafe(_push(), loop)
        except Exception as e:  # noqa: BLE001
            logger.debug("push %s failed: %s", ptype, e)

    async def _serial_relay_down(self, cmd: str, data: Dict[str, Any]) -> None:
        """DOWN frames from an edge-proxy relay leg → the local serial port (serial
        has NO agent, so the console spoke is the endpoint). CONSOLE_DATA writes
        bytes; CONSOLE_CLOSE closes the session."""
        sid = data.get("session_id")
        if not sid:
            return
        if cmd == "CONSOLE_DATA":
            raw = data.get("data", "")
            try:
                payload = base64.b64decode(raw) if raw else b""
            except Exception:  # noqa: BLE001
                return
            self.sessions.write(sid, payload)
        elif cmd == "CONSOLE_CLOSE":
            self.sessions.close(sid)

    def _port_device(self, port_id: str) -> Optional[str]:
        for p in enumerate_ports():
            if p["port_id"] == port_id:
                return p["device"]
        return None

    # ── command dispatch ──────────────────────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()
        self._ensure_autoprobe_task()  # start the fully-automatic identify loop once
        self._ensure_monitor_task()    # start the passive keep-alive capture loop once

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "CONSOLE_LIST_PORTS":
            ports = []
            for p in enumerate_ports():
                pid = p["port_id"]
                # Hide ports the automated system can't open (faulty/non-real
                # serial devices) so the operator never sees a broken port or its
                # raw error — unless a live session is somehow attached to it.
                if pid in self._unopenable and not self.sessions.has_user_sessions(pid):
                    continue
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
                    "capture_bytes": snap["capture_bytes"],  # total bytes captured this channel life
                    "pending_out": snap["pending_out"],  # bytes of a paste still draining
                })
            return {"status": "SUCCESS", "ports": ports}

        if cmd == "CONSOLE_GET_CAPTURE":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            chan = self.sessions.channel(pid)
            try:
                limit = int(data.get("bytes") or 0) or None
            except (TypeError, ValueError):
                limit = None
            text = chan.capture_tail(limit).decode("utf-8", "replace") if chan else ""
            if not text:  # no live channel — fall back to the last stored banner
                text = (self.store.get(pid).get("probe") or {}).get("banner", "")
            snap = self.sessions.snapshot(pid)
            return {"status": "SUCCESS", "port_id": pid, "capture": text,
                    "monitoring": snap["monitoring"], "last_activity": snap["last_activity"],
                    "capture_bytes": snap["capture_bytes"]}


        if cmd == "CONSOLE_DIAGNOSTICS":
            # Serial-connection health report: ports that keep failing to open
            # (faulty/non-real), get disconnected (device pulled), or flap.
            return {"status": "SUCCESS", "spoke_id": self.spoke_id,
                    "generated": time.time(), "diagnostics": self._diagnostics()}

        if cmd == "CONSOLE_GET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            return {"status": "SUCCESS", "port_id": pid, "settings": self.store.settings(pid)}

        if cmd == "CONSOLE_SET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            fields = {k: data[k] for k in ("baud", "bytesize", "parity", "stopbits", "flow",
                                           "paste_line_delay_ms", "paste_chunk", "paste_char_delay_ms")
                      if k in data}
            self.store.update(pid, settings=fields)
            return {"status": "SUCCESS", "port_id": pid, "settings": self.store.settings(pid)}

        if cmd == "CONSOLE_SET_ALIAS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            self.store.update(pid, alias=data.get("alias", ""))
            return {"status": "SUCCESS", "port_id": pid, "alias": data.get("alias", "")}

        if cmd == "CONSOLE_SET_TENANT":
            # Per-PORT tenant override (a single console host can serve ports to
            # different tenants). Empty tenant_id clears the override so the port
            # falls back to the agent's tenant (resolved hub-side).
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            self.store.update(pid, tenant_id=data.get("tenant_id", ""))
            return {"status": "SUCCESS", "port_id": pid, "tenant_id": data.get("tenant_id", "")}

        if cmd == "CONSOLE_SET_CREDENTIALS":
            # Global credential list, pushed (signed) by the hub. In memory only;
            # never logged or persisted. Order = attempt order for auto-login.
            creds = data.get("credentials") or []
            self._credentials = [{"username": c.get("username", ""), "password": c.get("password", "")}
                                 for c in creds if isinstance(c, dict)]
            logger.info("console: loaded %d credential(s) for auto-identify", len(self._credentials))
            return {"status": "SUCCESS", "count": len(self._credentials)}

        if cmd == "CONSOLE_AUTOPROBE":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            res = await self._exclusive_probe(pid, self._identify_blocking, pid, dev)
            await self._emit_probe_result(pid, res)
            return {"status": "SUCCESS", "port_id": pid,
                    "vendor": res.get("vendor"), "logged_in": bool(res.get("logged_in")),
                    "identity": res.get("identity") or {}}

        if cmd == "CONSOLE_LLM_COLLECT":
            # Log in (generically) and run a validated set of READ-ONLY commands,
            # returning the raw output for the hub's LLM-driven identify to parse.
            # Gated off by default; every command is re-validated in run_commands.
            if not self.config.get("console_llm_identify", False):
                return {"status": "ERROR", "message": "LLM-assisted identify is disabled"}
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            cmds = data.get("commands") or []
            res = await self._exclusive_probe(pid, self._collect_blocking, pid, dev, cmds)
            if str(res.get("error", "")).lower().startswith("open failed"):
                self._mark_unopenable(pid, res["error"])
            else:
                self._clear_unopenable(pid)
            return {"status": "SUCCESS", "port_id": pid, **res}

        if cmd == "CONSOLE_GET_CONFIG":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            return await self._exclusive_probe(pid, self._read_config_blocking, pid, dev)

        if cmd == "CONSOLE_PUSH_CONFIG":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            config = data.get("config") or ""
            if not config.strip():
                return {"status": "ERROR", "message": "config is empty"}
            save = bool(data.get("save", True))
            rollback = data.get("rollback") or "negate"
            return await self._exclusive_probe(pid, self._push_config_blocking, pid, dev, config, save, rollback)

        if cmd == "CONSOLE_DETECT_BAUD":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.has_user_sessions(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions before baud detection"}
            try:
                result = await self._exclusive_probe(pid, detect_baud, dev, DEFAULT_BAUD_CANDIDATES)
            except Exception as e:  # noqa: BLE001
                return {"status": "ERROR", "message": f"baud detect failed: {e}"}
            if result.get("baud"):
                self.store.update(pid, settings={"baud": result["baud"]},
                                  probe={"detected_baud": result["baud"], "banner": result.get("sample", "")})
            return {"status": "SUCCESS", "port_id": pid, **result}

        if cmd == "CONSOLE_OPEN":
            return await self._cmd_open(data)

        if cmd == "CONSOLE_DATA":
            sid = data.get("session_id")
            raw = data.get("data", "")
            if not sid:
                return {"status": "ERROR", "message": "session_id is required"}
            try:
                payload = base64.b64decode(raw) if raw else b""
            except Exception:
                return {"status": "ERROR", "message": "data must be base64"}
            ok = self.sessions.write(sid, payload)
            return {"status": "SUCCESS" if ok else "ERROR",
                    "written": ok, "message": "" if ok else "not the writer / no session"}

        if cmd == "CONSOLE_SEND_BREAK":
            sid = data.get("session_id")
            ok = self.sessions.send_break(sid) if sid else False
            return {"status": "SUCCESS" if ok else "ERROR", "sent": ok}

        if cmd == "CONSOLE_RESIZE":
            return {"status": "SUCCESS"}  # serial has no window size; accepted, no-op

        if cmd == "CONSOLE_CLOSE":
            sid = data.get("session_id")
            if sid:
                self.sessions.close(sid)
                if self.control_plane is not None and hasattr(
                        self.control_plane, "unregister_console_relay"):
                    self.control_plane.unregister_console_relay(sid)
            return {"status": "SUCCESS"}

        return {"status": "ERROR", "error": f"Unknown command: {command_type}"}

    async def _cmd_open(self, data: Dict[str, Any]) -> Dict[str, Any]:
        sid = data.get("session_id")
        pid = data.get("port_id")
        mode = (data.get("mode") or "rw").lower()
        if not sid or not pid:
            return {"status": "ERROR", "message": "session_id and port_id are required"}
        dev = self._port_device(pid)
        if not dev:
            return {"status": "ERROR", "message": f"port {pid} not found"}
        # Capture the loop so the reader thread can push CONSOLE_DATA_UP back onto it.
        self._loop = asyncio.get_running_loop()
        settings = self.store.settings(pid)
        try:
            info = self.sessions.open(sid, pid, dev, settings, writable=(mode != "ro"))
        except Exception as e:  # noqa: BLE001
            logger.warning("open %s (%s) failed: %s", pid, dev, e)
            return {"status": "ERROR", "message": f"could not open {dev}: {e}"}
        logger.info("console session %s opened on %s (%s) writer=%s",
                    sid, pid, dev, info.get("writer"))
        # Phase 2: register the relay token so a co-located edge proxy can attach a
        # /ws/console-relay leg. Serial has no agent — DOWN frames go to our own
        # serial-write via down_handler. Requires LM_CONSOLE_RELAY_LISTENER=1 so the
        # console role runs the listener; otherwise the proxy falls back to the hub.
        relay_token = data.get("relay_token")
        cp = self.control_plane
        if relay_token and cp is not None and hasattr(cp, "register_console_relay"):
            try:
                cp.register_console_relay(sid, relay_token, "", "serial",
                                          down_handler=self._serial_relay_down)
            except Exception:  # noqa: BLE001
                pass
        # Tell the browser leg the stream is live (relay consumes CONSOLE_READY).
        if self.control_plane is not None:
            await self.control_plane.send_to_hub("CONSOLE_READY", {"session_id": sid})
        # Streaming handoff: replay the recent passive-capture tail so a user who
        # connects mid-stream immediately sees the context the monitor already
        # captured (banner/prompt/output) instead of a blank screen. The hub
        # buffers these CONSOLE_DATA_UP frames in the session queue until the
        # browser WS drains them, so nothing is lost to the connect race.
        if info.get("had_capture"):
            await self._replay_capture(sid, pid)
        return {"status": "SUCCESS", "session_id": sid, "port_id": pid,
                "settings": settings, "writer": info.get("writer"),
                "read_only": bool(info.get("busy"))}

    async def _push_console_up(self, sid: str, data_bytes: bytes) -> None:
        """Push device→browser bytes for a session (edge-proxy route if present,
        else up to the hub). Shared by the reader thread bridge and the replay."""
        cp = self.control_plane
        if cp is None or not data_bytes:
            return
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
        chan = self.sessions.channel(pid)
        tail = chan.capture_tail(8192) if chan else b""
        if not tail:
            return
        header = b"\r\n\x1b[2m--- recent console capture (replayed) ---\x1b[0m\r\n"
        await self._push_console_up(sid, header + tail)

    # ── auto-identify / fingerprint ───────────────────────────────────────────
    def _identify_blocking(self, port_id: str, dev: str) -> Dict[str, Any]:
        """Blocking read-only identify on a transient serial handle (run via
        asyncio.to_thread). Detects baud first if none is locked yet."""
        settings = self.store.settings(port_id)
        baud = settings.get("baud")
        detected = None
        if not (self.store.get(port_id).get("probe") or {}).get("detected_baud"):
            try:
                d = detect_baud(dev, DEFAULT_BAUD_CANDIDATES)
                if d.get("baud"):
                    detected = d["baud"]
                    baud = d["baud"]
            except Exception as e:  # noqa: BLE001
                logger.debug("probe baud-detect failed on %s: %s", dev, e)
        try:
            ser = open_raw(dev, baud or 9600, timeout=0.3)
        except Exception as e:  # noqa: BLE001
            return {"error": f"open failed: {e}"}
        try:
            res = run_identify(lambda: ser.read(256), ser.write, self._credentials)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass
        if detected:
            res["detected_baud"] = detected
        return res

    def _collect_blocking(self, port_id: str, dev: str, commands) -> Dict[str, Any]:
        """Blocking generic-login + read-only command run on a transient handle
        (for LLM-driven identify). Commands are re-validated inside run_commands."""
        baud = self.store.settings(port_id).get("baud") or 9600
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"error": f"open failed: {e}"}
        try:
            return run_commands(lambda: ser.read(256), ser.write, self._credentials, commands or [])
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    def _profile_for(self, port_id: str):
        """The vendor profile a port was last identified as (None if never
        identified — config read/push requires a known device type)."""
        vendor = (self.store.get(port_id).get("probe") or {}).get("vendor")
        if not vendor:
            return None
        return next((p for p in PROFILES if p["name"] == vendor), None)

    def _read_config_blocking(self, port_id: str, dev: str) -> Dict[str, Any]:
        prof = self._profile_for(port_id)
        if not prof:
            return {"status": "ERROR", "message": "device not identified — run Identify first", "config": ""}
        baud = self.store.settings(port_id).get("baud") or 9600
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"open failed: {e}", "config": ""}
        try:
            return read_running_config(lambda: ser.read(256), ser.write, prof, self._credentials)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    def _push_config_blocking(self, port_id: str, dev: str, config: str,
                              save: bool, rollback: str) -> Dict[str, Any]:
        prof = self._profile_for(port_id)
        if not prof:
            return {"status": "ERROR", "message": "device not identified — run Identify first"}
        baud = self.store.settings(port_id).get("baud") or 9600
        try:
            ser = open_raw(dev, baud, 0.3)
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": f"open failed: {e}"}
        try:
            return push_config(lambda: ser.read(256), ser.write, prof, self._credentials,
                               config, save=save, rollback=rollback)
        finally:
            try:
                ser.close()
            except Exception:  # noqa: BLE001
                pass

    async def _emit_probe_result(self, port_id: str, res: Dict[str, Any]) -> None:
        """Persist the probe + push CONSOLE_PROBE_RESULT up (hub → NetBox)."""
        probe = {
            "banner": (res.get("banner") or "")[-2000:],
            "vendor": res.get("vendor"),
            "identity": res.get("identity") or {},
            "logged_in": bool(res.get("logged_in")),
            "error": res.get("error", ""),
            "source": "active",  # logged-in identify (authoritative; beats passive)
        }
        if res.get("detected_baud"):
            probe["detected_baud"] = res["detected_baud"]
            self.store.update(port_id, settings={"baud": res["detected_baud"]})
        self.store.update(port_id, probe=probe)
        self._probe_attempts[port_id] = time.monotonic()
        if self.control_plane is not None:
            await self.control_plane.send_to_hub("CONSOLE_PROBE_RESULT", {
                "spoke_id": self.spoke_id, "port_id": port_id,
                "tenant_id": self.store.get(port_id).get("tenant_id", ""),  # per-port override
                "vendor": probe["vendor"], "identity": probe["identity"],
                "banner": probe["banner"][-500:], "logged_in": probe["logged_in"],
            })

    def _ensure_autoprobe_task(self) -> None:
        """Start the auto-identify loop once (fully automatic on detection —
        decision #9), unless disabled via config auto_identify=False."""
        if self._autoprobe_task is not None or not self.config.get("auto_identify", True):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._loop = self._loop or loop
        self._autoprobe_task = loop.create_task(self._autoprobe_loop())

    async def _autoprobe_loop(self) -> None:
        await asyncio.sleep(10)  # let credentials/settings arrive first
        while True:
            try:
                await self._autoprobe_scan()
            except Exception:  # noqa: BLE001
                logger.exception("console autoprobe scan failed")
            await asyncio.sleep(120)

    async def _autoprobe_scan(self) -> None:
        """Probe each newly-seen port with the stored credentials. Guardrails:
        global toggle; skip ports a human holds or already identified actively;
        honour the shared login-retry backoff (:meth:`_identify_due`) so we keep
        trying to learn from a device without hammering its credentials."""
        if not self.config.get("auto_identify", True):
            return
        for p in enumerate_ports():
            pid = p["port_id"]
            if self.sessions.has_user_sessions(pid) or pid in self._probing:
                continue
            probe = self.store.get(pid).get("probe") or {}
            # An ACTIVE (logged-in) identity is authoritative — don't re-probe.
            if probe.get("identity") and probe.get("source") == "active":
                continue
            if not self._identify_due(pid):
                continue
            await self._active_identify(pid, p["device"])

    def _identify_due(self, pid: str) -> bool:
        """True when the shared login-retry backoff has elapsed for ``pid`` (or it
        has never been attempted), so an active identify may run again."""
        last = self._probe_attempts.get(pid, 0.0)
        if not last:
            return True
        return (time.monotonic() - last) >= self._probe_delay.get(pid, 3600.0)

    async def _active_identify(self, pid: str, dev: str) -> Dict[str, Any]:
        """Run the login-based identify on a port (releasing the passive monitor
        handle for the exclusive op), persist/emit the result, and update the
        shared retry backoff: a success (identity/login) backs off to an
        occasional re-verify; a failure escalates 5m→…→1h so we keep trying to
        learn what the stored credentials reveal without provoking a lockout."""
        self._probe_attempts[pid] = time.monotonic()
        try:
            res = await self._exclusive_probe(pid, self._identify_blocking, pid, dev)
        except Exception:  # noqa: BLE001
            logger.exception("active identify %s failed", pid)
            self._probe_delay[pid] = min(max(self._probe_delay.get(pid, 0.0) * 2, 300.0), 3600.0)
            return {"error": "identify failed"}
        # A bare "open failed" (not a login/parse issue) means the port itself is
        # unusable → hide it (still retried next cycle); otherwise it's healthy.
        if str(res.get("error", "")).lower().startswith("open failed"):
            self._mark_unopenable(pid, res["error"])
        else:
            self._clear_unopenable(pid)
        await self._emit_probe_result(pid, res)
        if res.get("identity") or res.get("logged_in"):
            self._probe_delay[pid] = 1800.0  # known → re-verify occasionally
        else:
            self._probe_delay[pid] = min(max(self._probe_delay.get(pid, 0.0) * 2, 300.0), 3600.0)
        return res

    async def _exclusive_probe(self, pid, fn, *args):
        """Run a blocking op that needs the EXCLUSIVE serial handle (identify,
        detect-baud, config get/push). Pauses the passive monitor to release the
        OS handle and marks the port ``probing`` so the monitor loop won't grab
        it back mid-op; the monitor loop re-establishes capture afterward."""
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
        if self._monitor_task is not None or not self.config.get("console_monitor", True):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._loop = self._loop or loop
        self._monitor_task = loop.create_task(self._monitor_loop())

    async def _monitor_loop(self) -> None:
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
        if not self.config.get("auto_identify", True) or not self._credentials:
            return
        for p in enumerate_ports():
            pid = p["port_id"]
            if self.sessions.has_user_sessions(pid) or pid in self._probing:
                continue
            if pid in self._unopenable:  # can't open at all — monitor_scan handles recovery
                continue
            probe = self.store.get(pid).get("probe") or {}
            if probe.get("identity") and probe.get("source") == "active":
                continue
            if not self._identify_due(pid):
                continue
            await self._active_identify(pid, p["device"])

    def _monitor_scan(self) -> None:
        """Ensure a passive capture handle on each idle port and glean identity
        from what has scrolled by (no login, read-only). Runs in a thread. A port
        the system can't open is flagged unopenable (hidden from the UI) but keeps
        being retried here so it recovers if it ever starts working."""
        if not self.config.get("console_monitor", True):
            return
        for p in enumerate_ports():
            pid = p["port_id"]
            # A human/relay owns the handle, or an exclusive probe is mid-flight —
            # don't interfere; the live session already fans bytes into capture.
            if pid in self._probing:
                self._clear_unopenable(pid)  # it opened for the session → healthy
                continue
            if self.sessions.has_user_sessions(pid):
                self._clear_unopenable(pid)
                self._passive_glean(pid)
                continue
            # A live monitor channel whose reader thread has died = the device was
            # pulled / the handle dropped: count a disconnect before we reopen.
            existing = self.sessions.channel(pid)
            if existing is not None and not existing.reader_alive():
                h = self._health_rec(pid)
                h["disconnects"] += 1
                h["last_disconnect"] = time.time()
            chan = self.sessions.ensure_monitor(pid, p["device"], self.store.settings(pid))
            if chan is None:
                self._mark_unopenable(pid, self.sessions.monitor_error(pid) or "cannot open port")
                continue
            self._clear_unopenable(pid)
            self._passive_glean(pid)
    # Substrings that indicate a KNOWN-faulty/non-real port (for clearer logs).
    # We hide on ANY open failure regardless; these just classify the message.
    _UNOPENABLE_HINTS = (
        "could not configure port", "input/output error", "errno 5",
        "no such file or directory", "errno 2", "device or resource busy",
        "errno 16", "permission denied", "errno 13", "open failed",
        "could not open", "device disconnected", "errno 6",
    )

    def _health_rec(self, pid: str) -> Dict[str, Any]:
        """Get-or-create the failure/disconnect history record for a port."""
        h = self._health.get(pid)
        if h is None:
            h = {"open_failures": 0, "disconnects": 0, "recoveries": 0,
                 "last_error": "", "first_failure": 0.0, "last_failure": 0.0,
                 "last_disconnect": 0.0, "last_recovery": 0.0, "currently_failing": False}
            self._health[pid] = h
        return h

    def _mark_unopenable(self, pid: str, err: str) -> None:
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
        h["last_failure"] = now
        h["last_error"] = err
        self._unopenable[pid] = {"error": err, "since": now}

    def _clear_unopenable(self, pid: str) -> None:
        if self._unopenable.pop(pid, None) is not None:
            logger.info("console: port %s is openable again — restoring to UI", pid)
            h = self._health_rec(pid)
            h["recoveries"] += 1
            h["last_recovery"] = time.time()
            h["currently_failing"] = False

    def _diagnostics(self) -> List[Dict[str, Any]]:
        """Health rows for the serial-connection diagnostics report: every port
        with a failure story (open failures, disconnects, or currently failing),
        newest/worst first. Includes ports that have vanished from enumeration
        (``present=False`` — device pulled)."""
        live = {p["port_id"]: p for p in enumerate_ports()}
        rows: List[Dict[str, Any]] = []
        for pid in set(self._health) | set(live):
            h = self._health.get(pid, {})
            if not (h.get("open_failures") or h.get("disconnects") or h.get("currently_failing")):
                continue
            p = live.get(pid, {})
            saved = self.store.get(pid)
            probe = saved.get("probe") or {}
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
            })
        rows.sort(key=lambda d: (d["currently_failing"],
                                 d["open_failures"] + d["disconnects"]), reverse=True)
        return rows

    def _passive_glean(self, pid: str) -> None:
        """Merge best-effort identity gleaned from the passive capture into the
        stored probe — WITHOUT clobbering an authoritative active-probe result."""
        chan = self.sessions.channel(pid)
        if not chan or not chan.capture:
            return
        text = chan.capture_tail(65536).decode("utf-8", "replace")
        res = passive_identify(text)
        gleaned = res.get("identity") or {}
        if not (gleaned or res.get("vendor")):
            return
        probe = dict(self.store.get(pid).get("probe") or {})
        active = probe.get("source") == "active"
        merged = dict(probe.get("identity") or {})
        changed = False
        for k, v in gleaned.items():
            # Passive fills only MISSING fields; active values are never replaced.
            if v and not merged.get(k):
                merged[k] = v
                changed = True
        if not active and res.get("vendor") and probe.get("vendor") != res["vendor"]:
            probe["vendor"] = res["vendor"]
            changed = True
        # Always refresh the banner tail so the port shows recent console output.
        tail = text[-2000:]
        if tail and probe.get("banner") != tail:
            probe["banner"] = tail
            changed = True
        if not changed:
            return
        probe["identity"] = merged
        if not active:
            probe.setdefault("source", "passive")
        self.store.update(pid, probe=probe)

    async def get_status(self) -> Dict[str, Any]:
        self._ensure_autoprobe_task()
        self._ensure_monitor_task()
        ports = enumerate_ports()
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
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
