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

# A baud sweep is only trustworthy — and the rate worth LOCKING — when the reply
# is mostly printable text (the line is really talking at this rate, not emitting
# framing noise). Below this we treat the port as "still unknown" and keep
# sweeping on the next cycle rather than sticking on a dead guess.
_BAUD_CONFIDENT_SCORE = 0.8

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
        # Only a mostly-printable reply means we truly locked onto the line's
        # rate; a silent/garbled best-guess is reported but NOT confident, so
        # callers keep sweeping instead of committing to a wrong baud.
        "confident": bool(best["sample"]) and best["score"] >= _BAUD_CONFIDENT_SCORE,
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

    def all_items(self) -> Dict[str, Dict[str, Any]]:
        """Shallow copy of every persisted port record (used to enumerate stable
        assignments such as DPA TCP ports across all known ports)."""
        return dict(self._data)

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

    # Rolling passive-capture buffer size (bytes). The reader always records the
    # tail of everything the device emits — even with NO attached user — so the
    # port section can surface identity/banner and a user connecting later can be
    # replayed recent context (the "we never know when a device will talk" case).
    CAPTURE_MAX = 65536
    # Outbound write-pacing defaults. A 1000-line paste must stream WITHOUT
    # overrunning a slow console-server/device UART (which silently drops chars).
    # We drain a per-channel outbound buffer in small chunks, pausing after each
    # newline (and optionally between chars). Single-key typing is unaffected —
    # the line-delay only fires on newlines. Overridable via port settings.
    PACE_CHUNK = 64          # bytes written per drain slice
    PACE_LINE_DELAY = 0.015  # seconds paused after a newline (device digests it)
    PACE_CHAR_DELAY = 0.0    # seconds paused per chunk (usually unneeded)
    OUTBUF_MAX = 1 << 20     # 1 MiB safety cap on the pending paste buffer

    def __init__(self, port_id: str, dev: str, settings: Dict[str, Any],
                 on_data: Callable[[str, bytes], None]):
        if serial is None:
            raise RuntimeError("pyserial not installed")
        self.port_id = port_id
        self.dev = dev
        self.on_data = on_data
        self.baud = int(settings.get("baud", 9600) or 9600)
        self.sessions: set = set()
        self.writer: Optional[str] = None
        self.monitored: bool = False  # kept open for passive capture w/o a user
        self._stop = threading.Event()
        self._reader: Optional[threading.Thread] = None
        self._reader_alive: bool = True  # cleared when the read loop exits (device pulled/error)
        # Passive-capture state (updated by the reader thread).
        self.capture = bytearray()
        self.last_activity: float = 0.0
        self.bytes_seen: int = 0
        # Outbound write-pacing state (drained by the writer thread).
        self._outbuf = bytearray()
        self._outlock = threading.Lock()
        self._outwake = threading.Event()
        self._writer_thread: Optional[threading.Thread] = None
        self._pace_chunk = max(1, int(settings.get("paste_chunk", self.PACE_CHUNK)))
        self._pace_line = max(0.0, float(settings.get("paste_line_delay_ms", self.PACE_LINE_DELAY * 1000)) / 1000.0)
        self._pace_char = max(0.0, float(settings.get("paste_char_delay_ms", self.PACE_CHAR_DELAY * 1000)) / 1000.0)
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
        self._writer_thread = threading.Thread(target=self._write_loop, name=f"console-tx-{self.port_id}", daemon=True)
        self._writer_thread.start()

    def _record(self, data: bytes) -> None:
        """Append to the rolling capture tail + update liveness telemetry."""
        self.capture += data
        if len(self.capture) > self.CAPTURE_MAX:
            del self.capture[:-self.CAPTURE_MAX]
        self.bytes_seen += len(data)
        self.last_activity = time.time()

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = self.ser.read(1024)
            except Exception as e:  # noqa: BLE001 - device pulled / error
                logger.info("read loop ended for %s: %s", self.port_id, e)
                self._reader_alive = False
                for sid in list(self.sessions):
                    self.on_data(sid, b"")  # empty → caller may emit CONSOLE_ERROR
                return
            if data:
                self._record(data)  # always capture, even with no attached user
                for sid in list(self.sessions):
                    self.on_data(sid, data)
        self._reader_alive = False

    def reader_alive(self) -> bool:
        """False once the read loop has exited (serial handle died)."""
        return self._reader_alive

    def _write_loop(self) -> None:
        """Drain the outbound buffer with pacing so large pastes don't overrun a
        slow device/console-server UART. Writes up to ``_pace_chunk`` bytes at a
        time, breaking each slice at the next newline, then pauses ``_pace_line``
        after a line (or ``_pace_char`` per chunk). Blocks on ``_outwake`` when
        idle so interactive typing incurs no extra latency."""
        while not self._stop.is_set():
            self._outwake.wait(timeout=0.5)
            if self._stop.is_set():
                return
            while True:
                with self._outlock:
                    if not self._outbuf:
                        self._outwake.clear()
                        break
                    nl = self._outbuf.find(b"\n")
                    if nl != -1 and nl + 1 <= self._pace_chunk:
                        cut = nl + 1
                    else:
                        cut = min(self._pace_chunk, len(self._outbuf))
                    chunk = bytes(self._outbuf[:cut])
                    del self._outbuf[:cut]
                try:
                    self.ser.write(chunk)
                    self.ser.flush()
                except Exception as e:  # noqa: BLE001
                    logger.warning("paced write to %s failed: %s", self.port_id, e)
                    with self._outlock:
                        self._outbuf.clear()
                    break
                if chunk.endswith(b"\n") and self._pace_line:
                    time.sleep(self._pace_line)
                elif self._pace_char:
                    time.sleep(self._pace_char)

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
        """Enqueue writer bytes for paced draining. Non-blocking: a big paste is
        buffered and streamed out by ``_write_loop`` at a device-safe rate."""
        if self.writer != session_id:
            return False
        if not data:
            return True
        with self._outlock:
            if len(self._outbuf) + len(data) > self.OUTBUF_MAX:
                logger.warning("outbound buffer full on %s; dropping %d bytes",
                               self.port_id, len(data))
                return False
            self._outbuf += data
        self._outwake.set()
        return True

    def pending_out(self) -> int:
        """Bytes still queued to be paced out (how far behind a big paste is)."""
        with self._outlock:
            return len(self._outbuf)

    def capture_tail(self, n: Optional[int] = None) -> bytes:
        """Last ``n`` bytes of everything the device has emitted (all if None)."""
        buf = bytes(self.capture)
        return buf[-n:] if n else buf

    def snapshot(self) -> Dict[str, Any]:
        """Live telemetry for the port listing."""
        return {
            "monitoring": self.monitored,
            "last_activity": self.last_activity,
            "capture_bytes": self.bytes_seen,
            "pending_out": self.pending_out(),
            "has_user": bool(self.sessions),
            "writer": self.writer,
            "baud": self.baud,
        }

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
        self._outwake.set()  # wake the writer thread so it can exit
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
        self._monitor_errors: Dict[str, str] = {}  # port_id → last open failure reason

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
        # A user attaching to a channel a passive monitor already holds = the
        # "stream the existing session to the user" handoff (they share the one
        # OS handle and the monitor's live output); the caller replays the tail.
        return {"writer": got_writer, "busy": (writable and not got_writer),
                "created": created, "settings": settings,
                "had_capture": bool(chan.capture)}

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
            # Empty of users — but keep the handle open if a passive monitor
            # still wants it (so capture continues after the user leaves).
            if chan.monitored:
                return
            chan.close()
            self._channels.pop(port_id, None)

    # ── passive monitor (keep-alive capture with no attached user) ────────────
    def ensure_monitor(self, port_id: str, dev: str,
                       settings: Dict[str, Any]) -> Optional[PortChannel]:
        """Keep a channel open purely to capture whatever the device emits, even
        with no user connected. Idempotent; returns the channel, or None if the
        port can't be opened right now (faulty/absent — see :meth:`monitor_error`).
        A channel whose reader has died (device pulled) is torn down and reopened
        so a port that starts working again recovers on its own."""
        chan = self._channels.get(port_id)
        if chan is not None and not chan.sessions and not chan.reader_alive():
            chan.close()
            self._channels.pop(port_id, None)
            chan = None
        # A newly auto-detected/locked baud must actually take effect: if no user
        # holds the handle and the requested baud differs from the open one, tear
        # down and reopen at the new rate (so a wrong-baud garbage capture becomes
        # readable — critical for catching a device that just powered on).
        if chan is not None and not chan.sessions:
            want_baud = int(settings.get("baud", 9600) or 9600)
            if want_baud != getattr(chan, "baud", want_baud):
                logger.info("monitor %s: re-opening at baud %d (was %d)",
                            port_id, want_baud, getattr(chan, "baud", 0))
                chan.close()
                self._channels.pop(port_id, None)
                chan = None
        if chan is None:
            try:
                chan = PortChannel(port_id, dev, settings, self._on_data)
                chan.start()
            except Exception as e:  # noqa: BLE001 - port busy/absent/faulty; retry later
                self._monitor_errors[port_id] = str(e)
                logger.debug("monitor open %s failed: %s", port_id, e)
                return None
            self._channels[port_id] = chan
        self._monitor_errors.pop(port_id, None)  # opened cleanly → healthy
        chan.monitored = True
        return chan

    def monitor_error(self, port_id: str) -> Optional[str]:
        """Last passive-open failure for a port (None once it opens cleanly)."""
        return self._monitor_errors.get(port_id)

    def stop_monitor(self, port_id: str) -> None:
        """Release the passive hold. Closes the OS handle unless a user is on it
        (used to hand the exclusive handle to an active probe/detect/config op)."""
        chan = self._channels.get(port_id)
        if not chan:
            return
        chan.monitored = False
        if not chan.sessions:
            chan.close()
            self._channels.pop(port_id, None)

    def channel(self, port_id: str) -> Optional[PortChannel]:
        return self._channels.get(port_id)

    def has_user_sessions(self, port_id: str) -> bool:
        """A human/relay session is attached (as opposed to only the monitor)."""
        chan = self._channels.get(port_id)
        return bool(chan and chan.sessions)

    def snapshot(self, port_id: str) -> Dict[str, Any]:
        chan = self._channels.get(port_id)
        if not chan:
            return {"monitoring": False, "last_activity": 0.0,
                    "capture_bytes": 0, "pending_out": 0, "has_user": False,
                    "writer": None, "baud": 0}
        return chan.snapshot()

    def writer_of(self, port_id: str) -> Optional[str]:
        chan = self._channels.get(port_id)
        return chan.writer if chan else None

    def is_open(self, port_id: str) -> bool:
        return port_id in self._channels
