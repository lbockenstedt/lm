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
from typing import Any, Dict, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from serial_manager import (
        PortStore, SessionManager, enumerate_ports, detect_baud, open_raw, DEFAULT_BAUD_CANDIDATES,
    )
    from fingerprint import run_identify, read_running_config, push_config, PROFILES
except ImportError:  # loaded as a package (agent role loader) or from repo root
    from .serial_manager import (  # type: ignore
        PortStore, SessionManager, enumerate_ports, detect_baud, open_raw, DEFAULT_BAUD_CANDIDATES,
    )
    from .fingerprint import run_identify, read_running_config, push_config, PROFILES  # type: ignore

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
        self._probing: set = set()

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
        try:
            asyncio.run_coroutine_threadsafe(cp.send_to_hub(ptype, payload), loop)
        except Exception as e:  # noqa: BLE001
            logger.debug("push %s failed: %s", ptype, e)

    def _port_device(self, port_id: str) -> Optional[str]:
        for p in enumerate_ports():
            if p["port_id"] == port_id:
                return p["device"]
        return None

    # ── command dispatch ──────────────────────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        cmd = command_type.upper()
        self._ensure_autoprobe_task()  # start the fully-automatic identify loop once

        if cmd == "GET_VERSION":
            return {"status": "SUCCESS", "version": self.get_version()}

        if cmd == "CONSOLE_LIST_PORTS":
            ports = []
            for p in enumerate_ports():
                pid = p["port_id"]
                saved = self.store.get(pid)
                ports.append({
                    **p,
                    "alias": saved.get("alias", ""),
                    "tenant_id": saved.get("tenant_id", ""),  # per-port override; hub fills effective
                    "settings": self.store.settings(pid),
                    "probe": saved.get("probe", {}),
                    "in_use": self.sessions.is_open(pid),
                    "writer": self.sessions.writer_of(pid),
                })
            return {"status": "SUCCESS", "ports": ports}

        if cmd == "CONSOLE_GET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            return {"status": "SUCCESS", "port_id": pid, "settings": self.store.settings(pid)}

        if cmd == "CONSOLE_SET_SETTINGS":
            pid = data.get("port_id")
            if not pid:
                return {"status": "ERROR", "message": "port_id is required"}
            fields = {k: data[k] for k in ("baud", "bytesize", "parity", "stopbits", "flow")
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
            if self.sessions.is_open(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            res = await asyncio.to_thread(self._identify_blocking, pid, dev)
            await self._emit_probe_result(pid, res)
            return {"status": "SUCCESS", "port_id": pid,
                    "vendor": res.get("vendor"), "logged_in": bool(res.get("logged_in")),
                    "identity": res.get("identity") or {}}

        if cmd == "CONSOLE_GET_CONFIG":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.is_open(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            return await asyncio.to_thread(self._read_config_blocking, pid, dev)

        if cmd == "CONSOLE_PUSH_CONFIG":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.is_open(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions first"}
            config = data.get("config") or ""
            if not config.strip():
                return {"status": "ERROR", "message": "config is empty"}
            save = bool(data.get("save", True))
            rollback = data.get("rollback") or "negate"
            return await asyncio.to_thread(self._push_config_blocking, pid, dev, config, save, rollback)

        if cmd == "CONSOLE_DETECT_BAUD":
            pid = data.get("port_id")
            dev = self._port_device(pid) if pid else None
            if not dev:
                return {"status": "ERROR", "message": f"port {pid} not found"}
            if self.sessions.is_open(pid):
                return {"status": "ERROR", "message": "port is in use; close sessions before baud detection"}
            try:
                result = await asyncio.to_thread(detect_baud, dev, DEFAULT_BAUD_CANDIDATES)
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
        # Tell the browser leg the stream is live (relay consumes CONSOLE_READY).
        if self.control_plane is not None:
            await self.control_plane.send_to_hub("CONSOLE_READY", {"session_id": sid})
        return {"status": "SUCCESS", "session_id": sid, "port_id": pid,
                "settings": settings, "writer": info.get("writer"),
                "read_only": bool(info.get("busy"))}

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
        """Probe each newly-seen port once. Guardrails: global toggle; skip ports
        a human holds; probe once then cool down 1h on failure (no re-hammering
        credentials)."""
        if not self.config.get("auto_identify", True):
            return
        for p in enumerate_ports():
            pid = p["port_id"]
            if self.sessions.is_open(pid) or pid in self._probing:
                continue
            probe = self.store.get(pid).get("probe") or {}
            last = self._probe_attempts.get(pid, 0.0)
            if probe.get("identity") or (last and (time.monotonic() - last) < 3600):
                continue
            self._probing.add(pid)
            try:
                res = await asyncio.to_thread(self._identify_blocking, pid, p["device"])
                await self._emit_probe_result(pid, res)
            except Exception:  # noqa: BLE001
                logger.exception("autoprobe %s failed", pid)
                self._probe_attempts[pid] = time.monotonic()
            finally:
                self._probing.discard(pid)

    async def get_status(self) -> Dict[str, Any]:
        self._ensure_autoprobe_task()
        ports = enumerate_ports()
        return {
            "spoke_id": self.spoke_id,
            "module": "console",
            "port_count": len(ports),
            "open_ports": sum(1 for p in ports if self.sessions.is_open(p["port_id"])),
            "credentials_loaded": len(self._credentials),
            "status": "HEALTHY",
        }

    def get_version(self) -> str:
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
