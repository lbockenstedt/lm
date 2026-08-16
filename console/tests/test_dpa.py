"""Unit tests for Direct Port Access (DPA) — the reverse Telnet terminal-server.

Covers the pure port allocator, the Telnet IAC stripping state machine, and the
connection bridge (with fully faked serial session + socket streams, so no
pyserial / real sockets are needed).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import dpa  # noqa: E402


# ── allocator ────────────────────────────────────────────────────────────────
def test_allocate_first_port_is_base():
    assert dpa.allocate_port({}, "p1", base=2200, span=200) == 2200


def test_allocate_is_stable_for_known_port():
    assert dpa.allocate_port({"p1": 2205}, "p1", base=2200, span=200) == 2205


def test_allocate_skips_taken_ports():
    existing = {"p1": 2200, "p2": 2201}
    assert dpa.allocate_port(existing, "p3", base=2200, span=200) == 2202


def test_allocate_reuses_lowest_gap():
    existing = {"p1": 2200, "p2": 2202}
    assert dpa.allocate_port(existing, "p3", base=2200, span=200) == 2201


def test_allocate_out_of_window_reassigns():
    # A persisted port outside the current window is treated as unassigned.
    assert dpa.allocate_port({"p1": 9999}, "p1", base=2200, span=10) == 2200


def test_allocate_exhausted_raises():
    existing = {f"p{i}": 2200 + i for i in range(3)}
    try:
        dpa.allocate_port(existing, "new", base=2200, span=3)
        assert False, "expected RuntimeError"
    except RuntimeError:
        pass


# ── telnet IAC stripping ─────────────────────────────────────────────────────
def test_strip_telnet_passthrough():
    clean, state = dpa.strip_telnet(b"hello")
    assert clean == b"hello" and state == 0


def test_strip_telnet_removes_command():
    # IAC DO SGA embedded in data.
    raw = bytes([ord("a"), dpa.IAC, dpa.DO, dpa.OPT_SGA, ord("b")])
    clean, state = dpa.strip_telnet(raw)
    assert clean == b"ab" and state == 0


def test_strip_telnet_escaped_ff_is_data():
    raw = bytes([dpa.IAC, dpa.IAC])  # escaped literal 0xFF
    clean, state = dpa.strip_telnet(raw)
    assert clean == bytes([0xFF]) and state == 0


def test_strip_telnet_subnegotiation_dropped():
    raw = bytes([ord("x"), dpa.IAC, dpa.SB, dpa.OPT_ECHO, 1, 2, dpa.IAC, dpa.SE, ord("y")])
    clean, state = dpa.strip_telnet(raw)
    assert clean == b"xy" and state == 0


def test_strip_telnet_split_across_chunks():
    # IAC arrives at the end of one chunk, the command in the next.
    clean1, state = dpa.strip_telnet(bytes([ord("a"), dpa.IAC]))
    assert clean1 == b"a" and state == 1
    clean2, state = dpa.strip_telnet(bytes([dpa.DO, dpa.OPT_SGA, ord("b")]), state)
    assert clean2 == b"b" and state == 0


# ── connection bridge (faked serial + streams) ───────────────────────────────
class _FakeWriter:
    def __init__(self):
        self.buf = bytearray()
        self.closed = False

    def write(self, data):
        self.buf.extend(data)

    async def drain(self):
        pass

    def close(self):
        self.closed = True

    def get_extra_info(self, _):
        return ("127.0.0.1", 5555)


class _FakeReader:
    """Yields queued client chunks, then EOF (b"")."""
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, _n):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class _FakeSessions:
    """Minimal SessionManager stand-in capturing the DPA session lifecycle."""
    def __init__(self, writable=True):
        self.writable = writable
        self.opened = None
        self.writes = []
        self.closed = []
        self.sinks = {}

    def open(self, sid, port_id, dev, settings, writable):
        self.opened = (sid, port_id, dev, writable)
        return {"writer": self.writable}

    def write(self, sid, data):
        self.writes.append((sid, data))
        return True

    def close(self, sid):
        self.closed.append(sid)


def _make_manager(sessions, reader_chunks):
    sinks = {}

    def register_sink(sid, cb):
        sinks[sid] = cb

    def unregister_sink(sid):
        sinks.pop(sid, None)

    class _Store:
        def settings(self, pid):
            return {}

        def all_items(self):
            return {}

        def update(self, *a, **k):
            pass

    mgr = dpa.DpaManager(
        store=_Store(),
        enumerate_ports=lambda: [{"port_id": "p1"}],
        open_session=sessions.open,
        write_session=sessions.write,
        close_session=sessions.close,
        register_sink=register_sink,
        unregister_sink=unregister_sink,
        port_device=lambda pid: "/dev/ttyUSB0",
        port_name=lambda pid: "TESTSW",
    )
    mgr._loop = asyncio.get_event_loop()
    return mgr, sinks


def test_bridge_client_to_serial_and_serial_to_client():
    async def run():
        sessions = _FakeSessions(writable=True)
        # client types "conf" then closes; serial echoes back "OK".
        reader = _FakeReader([b"conf"])
        writer = _FakeWriter()
        mgr, sinks = _make_manager(sessions, reader)

        async def feed_serial():
            # wait for the sink to be registered, push device bytes, then EOF.
            for _ in range(50):
                if sinks:
                    break
                await asyncio.sleep(0.001)
            sid = next(iter(sinks))
            sinks[sid](b"OK")
            await asyncio.sleep(0.01)
            if sid in sinks:
                sinks[sid](b"")  # serial EOF ends the bridge (if client hasn't already)

        await asyncio.gather(mgr.bridge(reader, writer, "p1"), feed_serial())

        # client bytes were written to serial
        assert (sessions.opened[0], b"conf") in sessions.writes
        # device bytes reached the client, and the session was cleaned up
        assert b"OK" in bytes(writer.buf)
        assert sessions.closed == [sessions.opened[0]]
        assert writer.closed

    asyncio.new_event_loop().run_until_complete(run())


def test_bridge_readonly_client_cannot_write():
    async def run():
        sessions = _FakeSessions(writable=False)  # another session holds the writer
        reader = _FakeReader([b"hax"])
        writer = _FakeWriter()
        mgr, sinks = _make_manager(sessions, reader)

        async def feed_serial():
            for _ in range(50):
                if sinks:
                    break
                await asyncio.sleep(0.001)
            sid = next(iter(sinks))
            sinks[sid](b"")

        await asyncio.gather(mgr.bridge(reader, writer, "p1"), feed_serial())
        assert sessions.writes == []  # read-only: client input dropped
        assert b"read-only" in bytes(writer.buf)

    asyncio.new_event_loop().run_until_complete(run())


def test_bridge_no_device_refuses():
    async def run():
        sessions = _FakeSessions()
        mgr, _ = _make_manager(sessions, _FakeReader([]))
        mgr.port_device = lambda pid: None  # device vanished
        writer = _FakeWriter()
        await mgr.bridge(_FakeReader([]), writer, "p1")
        assert sessions.opened is None
        assert writer.closed and b"not available" in bytes(writer.buf)

    asyncio.new_event_loop().run_until_complete(run())
