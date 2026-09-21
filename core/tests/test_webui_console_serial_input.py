"""Unit tests for console serial input, terminal EOL conversion, and write timeout.

Addresses Issue #440:
1. Ensure terminal instances in WebUI/main.js use convertEol: true to prevent staircase output.
2. Ensure read-only feedback warnings inform the operator when typing in a locked console session.
3. Ensure PortChannel configures write_timeout=2.0 on pyserial handles to prevent blocking.
4. Verify PortChannel write pacing, buffer overflow handling, and writer-lock constraints.
"""
import os
import re
import sys
import threading
import time
import pytest

# Ensure console/src is importable
CONSOLE_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "console", "src"))
if CONSOLE_SRC not in sys.path:
    sys.path.insert(0, CONSOLE_SRC)

import serial_manager as sm

MAIN_JS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "WebUI", "main.js"))
SERIAL_MANAGER_PY = os.path.abspath(os.path.join(CONSOLE_SRC, "serial_manager.py"))


def _extract_fn(src: str, name: str) -> str:
    """Extract brace-balanced function body for <name> from JavaScript source."""
    start = src.index(f"function {name}(")
    depth = 0
    for i in range(src.index("{", start), len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
    raise AssertionError(f"unbalanced function {name}")


class _MockSerial:
    PARITY_NONE = "N"
    PARITY_EVEN = "E"
    PARITY_ODD = "O"

    class SerialException(Exception):
        pass

    class Serial:
        instances = []

        def __init__(self, **kw):
            self.kw = kw
            self.written = bytearray()
            self.closed = False
            self._feed = bytearray()
            self._lock = threading.Lock()
            _MockSerial.Serial.instances.append(self)

        @property
        def in_waiting(self):
            with self._lock:
                return len(self._feed)

        def reset_input_buffer(self):
            with self._lock:
                self._feed.clear()

        def reset_output_buffer(self):
            with self._lock:
                self.written.clear()

        def feed(self, data: bytes):
            with self._lock:
                self._feed += data

        def read(self, n):
            time.sleep(0.005)
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


@pytest.fixture
def mock_serial(monkeypatch):
    monkeypatch.setattr(sm, "serial", _MockSerial)
    monkeypatch.setenv("LM_CONSOLE_CAPTURE_BYTES", "0")
    _MockSerial.Serial.instances.clear()
    return _MockSerial


def test_webui_serial_add_console_tab_convert_eol():
    """Assert convertEol: true is present in serialAddConsoleTab terminal instantiation."""
    src = open(MAIN_JS, encoding="utf-8").read()
    body = _extract_fn(src, "serialAddConsoleTab")
    assert "new Terminal(" in body
    # Verify convertEol: true is present in Terminal options
    term_match = re.search(r"new Terminal\(\{([\s\S]*?)\}\);", body)
    assert term_match is not None, "new Terminal({...}); block not found"
    opts = term_match.group(1)
    assert "convertEol: true" in opts, f"convertEol: true missing from Terminal options: {opts}"


def test_webui_serial_add_console_tab_ro_warning():
    """Assert read-only feedback check entry.ro warning toast is present in term.onData."""
    src = open(MAIN_JS, encoding="utf-8").read()
    body = _extract_fn(src, "serialAddConsoleTab")
    assert "term.onData(" in body
    assert "entry.ro" in body
    assert "showToast" in body
    assert "read-only mode" in body
    assert "Take Over" in body
    assert "_lastRoToast" in body


def test_serial_manager_source_has_write_timeout():
    """Assert write_timeout=2.0 is present in PortChannel serial instantiation in serial_manager.py."""
    src = open(SERIAL_MANAGER_PY, encoding="utf-8").read()
    assert "write_timeout=2.0" in src


def test_port_channel_init_passes_write_timeout(mock_serial):
    """Assert PortChannel passes write_timeout=2.0 to serial.Serial."""
    chan = sm.PortChannel("test-port", "/dev/ttyTest0", {"baud": 115200}, lambda sid, d: None)
    try:
        assert chan.ser.kw.get("write_timeout") == 2.0
    finally:
        chan.close()


def test_port_channel_write_pacing_and_buffering(mock_serial):
    """Test PortChannel write pacing, buffering, and lock control with mock serial."""
    chan = sm.PortChannel(
        "p1",
        "/dev/ttyMock1",
        {"baud": 9600, "paste_line_delay_ms": 0, "paste_chunk": 16},
        lambda sid, d: None,
    )
    chan.start()
    try:
        # Non-attached session cannot write
        assert chan.write("stranger", b"hello") is False

        # Read-only session (not writer) cannot write
        assert chan.attach("reader", writable=False) is False
        assert chan.write("reader", b"hello") is False

        # Attaching writer succeeds
        assert chan.attach("writer", writable=True) is True
        assert chan.writer == "writer"

        # Sending empty data returns True immediately without queuing
        assert chan.write("writer", b"") is True
        assert chan.pending_out() == 0

        # Sending data enqueues and drains through pacing thread
        test_payload = b"line 1\nline 2\nline 3\n"
        assert chan.write("writer", test_payload) is True

        end = time.time() + 2.0
        while time.time() < end and bytes(chan.ser.written) != test_payload:
            time.sleep(0.01)

        assert bytes(chan.ser.written) == test_payload
        assert chan.pending_out() == 0

        # Buffer overflow test: writing more than OUTBUF_MAX drops data
        huge_data = b"X" * (chan.OUTBUF_MAX + 10)
        assert chan.write("writer", huge_data) is False
    finally:
        chan.close()
