"""Unit tests for the Console serial layer's pyserial-free logic.

These run without pyserial installed (the module guards its import), covering
stable port_id derivation, baud-detect scoring, and the port settings store.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import serial_manager as m  # noqa: E402


def test_derive_port_id_usb_serial():
    assert m.derive_port_id("/dev/ttyUSB0", serial_number="FTX1") == "usb-FTX1"


def test_derive_port_id_vidpid_location():
    assert m.derive_port_id("/dev/ttyUSB1", vid=0x0403, pid=0x6001, location="1-1.2") == "usb-0403:6001@1-1.2"


def test_derive_port_id_uart_by_path():
    # On-board UARTs key on the fixed device path (stable hardware position).
    assert m.derive_port_id("/dev/ttyAMA0") == "uart-ttyAMA0"


def test_derive_port_id_is_stable_across_calls():
    a = m.derive_port_id("/dev/ttyUSB9", serial_number="ABC")
    b = m.derive_port_id("/dev/ttyUSB3", serial_number="ABC")  # different dev, same adapter
    assert a == b  # id follows the adapter, not the kernel-assigned ttyUSB number


def test_score_sample_prefers_printable_with_prompt():
    good = m.score_sample(b"Switch> \r\nlogin: ")
    noise = m.score_sample(bytes([0xFF, 0xFE, 0x00, 0x81, 0x9A]))
    empty = m.score_sample(b"")
    assert good > 1.0  # printable ratio (~1.0) + prompt bonus (0.5)
    assert noise == 0.0
    assert empty == 0.0


def test_port_store_roundtrip(tmp_path):
    store = m.PortStore(path=tmp_path / "ports.json")
    store.update("usb-FTX1", alias="core-sw-1", settings={"baud": 115200})
    # Defaults merge with saved overrides.
    s = store.settings("usb-FTX1")
    assert s["baud"] == 115200 and s["bytesize"] == 8 and s["parity"] == "N"
    assert store.get("usb-FTX1")["alias"] == "core-sw-1"
    # Persisted across instances.
    store2 = m.PortStore(path=tmp_path / "ports.json")
    assert store2.settings("usb-FTX1")["baud"] == 115200
    assert store2.get("usb-FTX1")["alias"] == "core-sw-1"


def test_port_store_partial_settings_update_keeps_others(tmp_path):
    store = m.PortStore(path=tmp_path / "ports.json")
    store.update("p1", settings={"baud": 9600, "flow": "rtscts"})
    store.update("p1", settings={"baud": 38400})  # change only baud
    s = store.settings("p1")
    assert s["baud"] == 38400 and s["flow"] == "rtscts"


# ── PortChannel capture + paced writes + SessionManager monitor lifecycle ────
# These exercise the pieces that need a serial handle, using a fake serial module
# injected into serial_manager (pyserial isn't installed in CI).
import threading  # noqa: E402
import time as _time  # noqa: E402


class _FakeSerial:
    """Minimal pyserial stand-in. ``feed`` bytes are handed out by read()."""
    PARITY_NONE = "N"
    PARITY_EVEN = "E"
    PARITY_ODD = "O"

    class SerialException(Exception):
        pass

    class Serial:
        instances = []

        def __init__(self, **kw):
            port = kw.get("port", "")
            if "bad" in port:  # simulate a faulty/non-real port
                raise _FakeSerial.SerialException(
                    "Could not configure port: (5, 'Input/output error')")
            self.kw = kw
            self.written = bytearray()
            self.closed = False
            self._feed = bytearray()
            self._lock = threading.Lock()
            _FakeSerial.Serial.instances.append(self)

        def feed(self, data: bytes):
            with self._lock:
                self._feed += data

        def read(self, n):
            _time.sleep(0.005)
            with self._lock:
                if not self._feed:
                    return b""
                out = bytes(self._feed[:n])
                del self._feed[:n]
                return out

        def write(self, b):
            self.written += b

        def flush(self):
            pass

        def send_break(self, duration=0.25):
            pass

        def close(self):
            self.closed = True


def _use_fake_serial(monkeypatch):
    monkeypatch.setattr(m, "serial", _FakeSerial)
    _FakeSerial.Serial.instances = []


def _wait(cond, timeout=2.0):
    end = _time.time() + timeout
    while _time.time() < end:
        if cond():
            return True
        _time.sleep(0.01)
    return False


def test_channel_records_capture_and_rolls(monkeypatch):
    _use_fake_serial(monkeypatch)
    chan = m.PortChannel("p1", "/dev/ttyUSB0", {"baud": 9600}, lambda sid, d: None)
    chan._record(b"hello ")
    chan._record(b"world")
    assert chan.capture_tail() == b"hello world"
    assert chan.bytes_seen == 11
    assert chan.last_activity > 0
    # Rolling cap keeps only the tail.
    chan.CAPTURE_MAX = 8
    chan._record(b"1234567890")
    assert len(chan.capture) == 8
    assert chan.capture_tail(4) == b"7890"


def test_channel_paced_write_streams_full_paste_in_order(monkeypatch):
    _use_fake_serial(monkeypatch)
    # Zero delays so the test is fast; correctness = all bytes, in order.
    chan = m.PortChannel("p1", "/dev/ttyUSB0",
                         {"baud": 9600, "paste_line_delay_ms": 0, "paste_chunk": 16},
                         lambda sid, d: None)
    chan.start()
    chan.attach("s1", writable=True)
    paste = ("".join(f"line-{i}\n" for i in range(200))).encode()
    assert chan.write("s1", paste) is True
    assert _wait(lambda: bytes(chan.ser.written) == paste), "paste did not fully drain"
    assert chan.pending_out() == 0
    chan.close()


def test_channel_write_requires_writer_lock(monkeypatch):
    _use_fake_serial(monkeypatch)
    chan = m.PortChannel("p1", "/dev/ttyUSB0", {"baud": 9600}, lambda sid, d: None)
    chan.start()
    chan.attach("reader", writable=False)  # observer, no writer lock
    assert chan.write("reader", b"nope") is False
    chan.close()


def test_session_manager_monitor_keepalive_and_handoff(monkeypatch):
    _use_fake_serial(monkeypatch)
    sm = m.SessionManager(on_data=lambda sid, d: None)
    # Passive monitor holds the port open with no user attached.
    chan = sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 9600})
    assert chan is not None and chan.monitored is True
    assert sm.is_open("p1") and not sm.has_user_sessions("p1")
    # A user attaches to the SAME channel (streaming handoff), gets writer lock.
    info = sm.open("u1", "p1", "/dev/ttyUSB0", {"baud": 9600}, writable=True)
    assert info["writer"] is True and info["created"] is False
    assert sm.has_user_sessions("p1")
    # User leaves — channel stays open because the monitor still wants it.
    sm.close("u1")
    assert sm.is_open("p1") and not sm.has_user_sessions("p1")
    # Dropping the monitor with no users finally closes it.
    sm.stop_monitor("p1")
    assert not sm.is_open("p1")


def test_ensure_monitor_reopens_on_baud_change(monkeypatch):
    """A newly auto-detected baud must actually take effect: ensure_monitor tears
    down and reopens an idle (no-user) channel when the requested baud differs,
    so a boot captured at the wrong rate becomes legible."""
    _use_fake_serial(monkeypatch)
    sm = m.SessionManager(on_data=lambda sid, d: None)
    chan1 = sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 9600})
    assert chan1 is not None and chan1.baud == 9600
    # Same baud → same channel (idempotent, no reopen).
    assert sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 9600}) is chan1
    # New baud with no user attached → reopen at the new rate.
    chan2 = sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 115200})
    assert chan2 is not None and chan2 is not chan1
    assert chan2.baud == 115200 and chan1.ser.closed is True
    assert chan2.snapshot()["baud"] == 115200


def test_ensure_monitor_no_reopen_while_user_attached(monkeypatch):
    """A baud change must NOT yank the handle out from under a live user session."""
    _use_fake_serial(monkeypatch)
    sm = m.SessionManager(on_data=lambda sid, d: None)
    chan1 = sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 9600})
    sm.open("u1", "p1", "/dev/ttyUSB0", {"baud": 9600}, writable=True)
    chan2 = sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 115200})
    assert chan2 is chan1 and chan1.ser.closed is False  # user keeps their channel


def test_session_manager_records_open_error_for_faulty_port(monkeypatch):
    _use_fake_serial(monkeypatch)
    sm = m.SessionManager(on_data=lambda sid, d: None)
    chan = sm.ensure_monitor("bad1", "/dev/ttyS2-bad", {"baud": 9600})
    assert chan is None
    err = sm.monitor_error("bad1")
    assert err and "input/output error" in err.lower()
    assert not sm.is_open("bad1")


def test_stop_monitor_keeps_channel_if_user_present(monkeypatch):
    _use_fake_serial(monkeypatch)
    sm = m.SessionManager(on_data=lambda sid, d: None)
    sm.ensure_monitor("p1", "/dev/ttyUSB0", {"baud": 9600})
    sm.open("u1", "p1", "/dev/ttyUSB0", {"baud": 9600}, writable=True)
    sm.stop_monitor("p1")  # release passive hold, but a user is on it
    assert sm.is_open("p1") and sm.has_user_sessions("p1")
    sm.close("u1")
    assert not sm.is_open("p1")  # now truly empty


# ── detect_baud confidence flag ──────────────────────────────────────────────
# Auto-baud must only LOCK a rate when the line yields readable text; a silent or
# garbled sweep reports a best-guess but flags confident=False so callers keep
# sweeping instead of committing to a wrong rate.
class _BaudFakeSerial:
    """Serial stand-in whose readable rate is configurable via ``good_baud``."""
    good_baud = None

    class SerialException(Exception):
        pass

    class Serial:
        def __init__(self, dev, baud, timeout=0.3):
            self.baud = baud
            self._buf = (b"Switch> \r\nlogin: "
                         if baud == _BaudFakeSerial.good_baud else b"")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def reset_input_buffer(self):
            pass

        def write(self, b):
            pass

        def read(self, n):
            out, self._buf = self._buf[:n], self._buf[n:]
            return out

        def close(self):
            pass


def test_detect_baud_confident_when_line_is_readable(monkeypatch):
    _BaudFakeSerial.good_baud = 115200
    monkeypatch.setattr(m, "serial", _BaudFakeSerial)
    res = m.detect_baud("/dev/ttyUSB0", [9600, 115200, 38400])
    assert res["baud"] == 115200
    assert res["confident"] is True


def test_detect_baud_not_confident_when_silent(monkeypatch):
    _BaudFakeSerial.good_baud = None  # every rate stays silent
    monkeypatch.setattr(m, "serial", _BaudFakeSerial)
    res = m.detect_baud("/dev/ttyUSB0", [9600, 115200, 38400])
    # A best-guess baud may still be returned, but it must NOT be locked.
    assert res["confident"] is False
