"""Serial layer for the lm Console role.

Enumerates serial adapters (USB + on-board UART), derives a stable *software*
``port_id`` (no udev rules — decision #1), persists per-port settings + probe
results, auto-detects baud (decision #5), and runs read/write sessions under a
one-writer / many-read-only-observer model (decision #4).

Design notes:
- One OS serial handle per physical port lives in a :class:`PortChannel`; N
  browser sessions attach to it. The reader thread reads once and fans the bytes
  out to every attached session, so two admins can watch the same console while
  only the writer can type. This is the only way to honor "many observers" —
  Linux won't let two processes open the same ``/dev/tty*`` twice.
- Pure helpers (:func:`derive_port_id`, :func:`score_sample`) import cleanly
  WITHOUT pyserial so they stay unit-testable on a node that hasn't installed the
  role deps yet (the agent pip-installs pyserial on LOAD_ROLE).
"""
from __future__ import annotations

import glob
import json
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:  # pyserial is installed on the node by the agent's LOAD_ROLE (requirements.txt)
    import serial
    from serial.tools import list_ports as _list_ports
except Exception:  # pragma: no cover - absent until the role is installed
    serial = None
    _list_ports = None

logger = logging.getLogger("ConsoleSpoke")

# 8N1 baud candidates, ordered by real-world frequency on console gear.
DEFAULT_BAUD_CANDIDATES = [9600, 115200, 38400, 19200, 57600, 4800, 2400, 230400]

# Prompt/banner signatures that boost a baud-detect score (the device is talking
# sense at this rate, not emitting line noise).
_PROMPT_HINTS = re.compile(
    rb"(login:|[Uu]sername:|[Pp]assword:|[\w.\-]+[>#]\s*$|Press RETURN|"
    rb"Escape character|[Bb]ooting|U-Boot|ROMMON|Cisco|Aruba|ProCurve|HP|"
    rb"Juniper|localhost|Last login)",
    re.MULTILINE,
)

_DEFAULT_SETTINGS = {"baud": 9600, "bytesize": 8, "parity": "N", "stopbits": 1, "flow": "none"}


# ── Pure helpers (pyserial-free, unit-testable) ─────────────────────────────────

def derive_port_id(dev: str, serial_number: Optional[str] = None,
                   vid: Optional[int] = None, pid: Optional[int] = None,
                   location: Optional[str] = None) -> str:
    """Stable software id for a serial port (survives replug/reboot).

    USB adapters key on serial#/vid:pid+location; on-board UARTs key on the fixed
    device path (hardware position is stable). Deliberately avoids udev.
    """
    base = os.path.basename(dev)
    if serial_number:
        return f"usb-{serial_number}"
    if vid is not None and pid is not None and location:
        return f"usb-{vid:04x}:{pid:04x}@{location}"
    if vid is not None and pid is not None:
        return f"usb-{vid:04x}:{pid:04x}-{base}"
    return f"uart-{base}"


def score_sample(sample: bytes) -> float:
    """Heuristic 'is this baud right?' score: printable-ASCII ratio + a prompt bonus."""
    if not sample:
        return 0.0
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    score = printable / len(sample)
    if _PROMPT_HINTS.search(sample):
        score += 0.5
    return score


def _uart_present(dev: str) -> bool:
    """True if an on-board tty is a real device (drops the dozens of phantom
    ``/dev/ttyS*`` stubs that have no backing hardware)."""
    base = os.path.basename(dev)
    return os.path.exists(f"/sys/class/tty/{base}/device")


def _by_id_map() -> Dict[str, str]:
    """Map each real /dev path → its /dev/serial/by-id stable symlink name."""
    out: Dict[str, str] = {}
    for link in glob.glob("/dev/serial/by-id/*"):
        try:
            out[os.path.realpath(link)] = os.path.basename(link)
        except OSError:
            continue
    return out


def enumerate_ports() -> List[Dict[str, Any]]:
    """Discover serial ports (USB adapters + on-board UARTs) with a stable port_id."""
    ports: List[Dict[str, Any]] = []
    seen: set = set()
    byid = _by_id_map()

    if _list_ports is not None:
        for p in _list_ports.comports():
            dev = p.device
            seen.add(dev)
            sn = getattr(p, "serial_number", None)
            vid = getattr(p, "vid", None)
            pid = getattr(p, "pid", None)
            loc = getattr(p, "location", None)
            stable = byid.get(os.path.realpath(dev))
            port_id = f"byid-{stable}" if stable else derive_port_id(dev, sn, vid, pid, loc)
            is_usb = bool(vid) or "ttyUSB" in dev or "ttyACM" in dev
            ports.append({
                "port_id": port_id,
                "device": dev,
                "kind": "usb" if is_usb else "uart",
                "vendor": (getattr(p, "manufacturer", None) or "").strip(),
                "product": (getattr(p, "product", None) or getattr(p, "description", "") or "").strip(),
                "serial": sn or "",
                "vid": f"{vid:04x}" if vid is not None else "",
                "pid": f"{pid:04x}" if pid is not None else "",
            })

    # On-board UARTs frequently aren't reported by comports(); add real ttys.
    for dev in sorted(glob.glob("/dev/ttyAMA*") + glob.glob("/dev/ttyS*") + glob.glob("/dev/ttyO*")):
        if dev in seen or not _uart_present(dev):
            continue
        ports.append({
            "port_id": derive_port_id(dev), "device": dev, "kind": "uart",
            "vendor": "", "product": "on-board UART", "serial": "", "vid": "", "pid": "",
        })
    return ports


def open_raw(dev: str, baud: int = 9600, timeout: float = 0.3):
    """Open a transient serial handle (for baud-detect / fingerprint), bypassing
    the session machinery. Caller must close it."""
    if serial is None:
        raise RuntimeError("pyserial not installed")
    return serial.Serial(dev, int(baud or 9600), timeout=timeout)


def detect_baud(dev: str, candidates: Optional[List[int]] = None,
                read_secs: float = 1.5) -> Dict[str, Any]:
    """Sweep candidate baud rates (8N1), press Enter, score the reply; return the
    best. Blocking — callers run it via ``asyncio.to_thread``."""
    if serial is None:
        raise RuntimeError("pyserial not installed")
    candidates = candidates or DEFAULT_BAUD_CANDIDATES
    best = {"baud": None, "score": -1.0, "sample": b""}
    for baud in candidates:
        try:
            with serial.Serial(dev, baud, timeout=0.3) as ser:
                ser.reset_input_buffer()
                ser.write(b"\r\n")
                deadline = time.monotonic() + read_secs
                buf = b""
                while time.monotonic() < deadline and len(buf) < 4096:
                    chunk = ser.read(256)
                    if chunk:
                        buf += chunk
            s = score_sample(buf)
            if s > best["score"]:
                best = {"baud": baud, "score": s, "sample": buf}
            if s >= 1.3:  # confidently good — stop sweeping
                break
        except Exception as e:  # noqa: BLE001
            logger.debug("baud probe %s@%d failed: %s", dev, baud, e)
    return {
        "baud": best["baud"],
        "score": round(best["score"], 3),
        "sample": best["sample"].decode("utf-8", "replace"),
    }


# ── Persistence ────────────────────────────────────────────────────────────────

def _state_dir() -> Path:
    """A writable dir for the port registry: /var/lib/lm/console, falling back to
    a repo-local .lm-state/console when /var/lib/lm isn't writable (mirrors
    BaseControlPlane._spoke_state_dir)."""
    candidates = [
        Path("/var/lib/lm/console"),
        Path(__file__).resolve().parent.parent / ".lm-state" / "console",
        Path("/tmp/lm-console"),
    ]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".w"
            probe.write_text("1")
            probe.unlink()
            return p
        except Exception:  # noqa: BLE001
            continue
    return Path("/tmp")


class PortStore:
    """Per-port settings + probe results, persisted atomically to JSON keyed by
    ``port_id`` (survives restart/replug)."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or (_state_dir() / "ports.json")
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        try:
            self._data = json.loads(self.path.read_text())
        except Exception:  # noqa: BLE001 - missing/corrupt → start empty
            self._data = {}

    def _save(self) -> None:
        tmp = self.path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(self._data, indent=2))
            os.replace(tmp, self.path)  # atomic
        except Exception as e:  # noqa: BLE001
            logger.warning("PortStore save failed: %s", e)

    def get(self, port_id: str) -> Dict[str, Any]:
        return self._data.get(port_id, {})

    def settings(self, port_id: str) -> Dict[str, Any]:
        return {**_DEFAULT_SETTINGS, **self._data.get(port_id, {}).get("settings", {})}

    def update(self, port_id: str, **fields) -> Dict[str, Any]:
        entry = self._data.setdefault(port_id, {})
        for k, v in fields.items():
            if isinstance(v, dict) and isinstance(entry.get(k), dict):
                entry[k].update(v)
            else:
                entry[k] = v
        self._save()
        return entry


# ── Live sessions (one-writer / many-observer) ─────────────────────────────────

class PortChannel:
    """One OS serial handle per physical port, shared by N attached sessions.

    The reader thread reads bytes once and fans them to every attached session
    via ``on_data(session_id, data)``. Exactly one session may hold the writer
    lock; others are read-only observers.
    """

    def __init__(self, port_id: str, dev: str, settings: Dict[str, Any],
                 on_data: Callable[[str, bytes], None]):
        if serial is None:
            raise RuntimeError("pyserial not installed")
        self.port_id = port_id
        self.dev = dev
        self.on_data = on_data
        self.sessions: set = set()
        self.writer: Optional[str] = None
        self._stop = threading.Event()
        self._reader: Optional[threading.Thread] = None
        parity = {"N": serial.PARITY_NONE, "E": serial.PARITY_EVEN, "O": serial.PARITY_ODD}
        self.ser = serial.Serial(
            port=dev,
            baudrate=int(settings.get("baud", 9600)),
            bytesize=int(settings.get("bytesize", 8)),
            parity=parity.get(str(settings.get("parity", "N")).upper(), serial.PARITY_NONE),
            stopbits=int(settings.get("stopbits", 1)),
            rtscts=(settings.get("flow") == "rtscts"),
            xonxoff=(settings.get("flow") == "xonxoff"),
            timeout=0.2,
        )

    def start(self) -> None:
        self._reader = threading.Thread(target=self._read_loop, name=f"console-{self.port_id}", daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.ser.read(1024)
            except Exception as e:  # noqa: BLE001 - device pulled / error
                logger.info("read loop ended for %s: %s", self.port_id, e)
                for sid in list(self.sessions):
                    self.on_data(sid, b"")  # empty → caller may emit CONSOLE_ERROR
                return
            if data:
                for sid in list(self.sessions):
                    self.on_data(sid, data)

    def attach(self, session_id: str, writable: bool) -> bool:
        """Attach a session. Returns True if it got the writer lock."""
        self.sessions.add(session_id)
        if writable and self.writer is None:
            self.writer = session_id
            return True
        return False

    def detach(self, session_id: str) -> bool:
        """Detach a session. Returns True if the channel is now empty (closeable)."""
        self.sessions.discard(session_id)
        if self.writer == session_id:
            self.writer = None
        return not self.sessions

    def write(self, session_id: str, data: bytes) -> bool:
        if self.writer != session_id:
            return False
        try:
            self.ser.write(data)
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("write to %s failed: %s", self.port_id, e)
            return False

    def send_break(self, session_id: str) -> bool:
        if self.writer != session_id or serial is None:
            return False
        try:
            self.ser.send_break(duration=0.25)
            return True
        except Exception as e:  # noqa: BLE001
            logger.warning("break on %s failed: %s", self.port_id, e)
            return False

    def close(self) -> None:
        self._stop.set()
        try:
            self.ser.close()
        except Exception:  # noqa: BLE001
            pass


class SessionManager:
    """Owns the live :class:`PortChannel` objects keyed by port_id and maps
    session_id → the channel it's attached to."""

    def __init__(self, on_data: Callable[[str, bytes], None]):
        self._on_data = on_data
        self._channels: Dict[str, PortChannel] = {}
        self._session_port: Dict[str, str] = {}

    def open(self, session_id: str, port_id: str, dev: str,
             settings: Dict[str, Any], writable: bool) -> Dict[str, Any]:
        chan = self._channels.get(port_id)
        created = False
        if chan is None:
            chan = PortChannel(port_id, dev, settings, self._on_data)
            chan.start()
            self._channels[port_id] = chan
            created = True
        got_writer = chan.attach(session_id, writable)
        self._session_port[session_id] = port_id
        return {"writer": got_writer, "busy": (writable and not got_writer),
                "created": created, "settings": settings}

    def write(self, session_id: str, data: bytes) -> bool:
        port_id = self._session_port.get(session_id)
        chan = self._channels.get(port_id) if port_id else None
        return bool(chan and chan.write(session_id, data))

    def send_break(self, session_id: str) -> bool:
        port_id = self._session_port.get(session_id)
        chan = self._channels.get(port_id) if port_id else None
        return bool(chan and chan.send_break(session_id))

    def close(self, session_id: str) -> None:
        port_id = self._session_port.pop(session_id, None)
        chan = self._channels.get(port_id) if port_id else None
        if chan and chan.detach(session_id):
            chan.close()
            self._channels.pop(port_id, None)

    def writer_of(self, port_id: str) -> Optional[str]:
        chan = self._channels.get(port_id)
        return chan.writer if chan else None

    def is_open(self, port_id: str) -> bool:
        return port_id in self._channels
