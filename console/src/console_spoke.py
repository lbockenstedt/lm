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
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:
    from core.src.base_spoke import BaseSpoke

try:
    from serial_manager import (
        PortStore, SessionManager, enumerate_ports, detect_baud, DEFAULT_BAUD_CANDIDATES,
    )
except ImportError:  # loaded as a package (agent role loader) or from repo root
    from .serial_manager import (  # type: ignore
        PortStore, SessionManager, enumerate_ports, detect_baud, DEFAULT_BAUD_CANDIDATES,
    )

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

    async def get_status(self) -> Dict[str, Any]:
        ports = enumerate_ports()
        return {
            "spoke_id": self.spoke_id,
            "module": "console",
            "port_count": len(ports),
            "open_ports": sum(1 for p in ports if self.sessions.is_open(p["port_id"])),
            "status": "HEALTHY",
        }

    def get_version(self) -> str:
        try:
            return (Path(__file__).parent.parent / "VERSION").read_text().strip()
        except Exception:
            return "unknown"
