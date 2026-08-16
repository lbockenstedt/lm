"""Direct Port Access (DPA) — reverse terminal-server for the console role.

Exposes each detected serial port over a per-port TCP listener so an operator can
connect straight to the console line (à la ser2net / a Cisco terminal server):
connect to the port's auto-assigned TCP port and you're attached to the serial
device. Byte flow is bridged onto the existing one-writer / many-observer
:class:`SessionManager` — the first DPA client on a port becomes the writer, the
rest are read-only observers, and the passive monitor's capture is unaffected.

Transport: Telnet (raw TCP with minimal option negotiation). Security posture —
this is a change from the "hub WebUI relay only" model, so it is **OFF by default**
and binds to **127.0.0.1** unless the operator explicitly widens it; an optional
allow-list restricts client source IPs. (Encrypted/authenticated SSH access is a
planned follow-up transport that plugs into the same bridge.)

The module has no hard dependency on pyserial/asyncio servers at import time so it
stays unit-testable: the bridge coroutine takes injected reader/writer/session
callables and the port allocator is a pure function.
"""
import asyncio
import logging
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default TCP port window for Telnet DPA listeners. The example an operator gives
# ("SSH/telnet to port 2201") lands the first port at the window base.
DEFAULT_TELNET_BASE = 2200
DEFAULT_TELNET_SPAN = 200

# Telnet protocol bytes (RFC 854/855/858).
IAC = 0xFF
DONT, DO, WONT, WILL = 0xFE, 0xFD, 0xFC, 0xFB
SB, SE = 0xFA, 0xF0
OPT_BINARY, OPT_ECHO, OPT_SGA = 0x00, 0x01, 0x03

# On connect, put the client into character-at-a-time, 8-bit-clean mode so a raw
# serial console behaves (no line buffering, no local echo mangling). We let the
# DEVICE echo, mirroring ser2net's raw pass-through.
TELNET_INIT = bytes([
    IAC, WILL, OPT_SGA, IAC, DO, OPT_SGA,
    IAC, WILL, OPT_BINARY, IAC, DO, OPT_BINARY,
    IAC, WILL, OPT_ECHO,  # server will (not) echo → client stops local echo/line mode
])


def allocate_port(existing: Dict[str, int], port_id: str,
                  base: int = DEFAULT_TELNET_BASE, span: int = DEFAULT_TELNET_SPAN) -> int:
    """Return a stable TCP port for ``port_id``.

    If ``existing`` already maps ``port_id`` → a port in ``[base, base+span)``,
    that port is kept (stable across restarts/replug). Otherwise the lowest free
    port in the window not already taken by another port_id is assigned. Raises
    ``RuntimeError`` if the window is exhausted.
    """
    cur = existing.get(port_id)
    if isinstance(cur, int) and base <= cur < base + span:
        return cur
    taken = {v for k, v in existing.items()
             if k != port_id and isinstance(v, int) and base <= v < base + span}
    for candidate in range(base, base + span):
        if candidate not in taken:
            return candidate
    raise RuntimeError(f"DPA port window {base}..{base + span - 1} exhausted")


def strip_telnet(data: bytes, in_iac: int = 0) -> "tuple[bytes, int]":
    """Remove Telnet IAC command sequences from inbound client bytes, returning
    ``(clean_payload, carry_state)``. ``in_iac`` carries partial-sequence state
    between chunks: 0 = normal, 1 = saw IAC, 2 = saw IAC+command(DO/DONT/WILL/
    WONT) awaiting the option byte, 3 = inside an IAC SB … IAC SE subnegotiation.
    """
    out = bytearray()
    state = in_iac
    for b in data:
        if state == 0:
            if b == IAC:
                state = 1
            else:
                out.append(b)
        elif state == 1:            # saw IAC
            if b == IAC:            # escaped 0xFF data byte
                out.append(IAC)
                state = 0
            elif b in (DO, DONT, WILL, WONT):
                state = 2           # option byte follows
            elif b == SB:
                state = 3           # subnegotiation until IAC SE
            else:                   # standalone 2-byte command (NOP/BRK/…)
                state = 0
        elif state == 2:            # option byte of a DO/DONT/WILL/WONT
            state = 0
        elif state == 3:            # inside subnegotiation
            if b == SE:
                state = 0           # (tolerate SE without the preceding IAC)
    return bytes(out), state


class DpaManager:
    """Runs a per-port Telnet listener and bridges each connection onto the
    shared :class:`SessionManager`. Reconcile-driven: :meth:`reconcile` starts a
    listener for every currently-present port and stops listeners for ports that
    have gone away, so hot-plugged devices get DPA automatically.

    Injected callables keep it testable without pyserial/real sockets:
      * ``open_session(sid, port_id, dev, writable) -> info``
      * ``write_session(sid, data) -> bool``
      * ``close_session(sid)``
      * ``register_sink(sid, cb)`` / ``unregister_sink(sid)`` — ``cb(bytes)`` is
        invoked (from the serial reader thread) with device→client bytes; the
        bridge marshals them onto the loop.
      * ``port_device(port_id) -> dev|None`` and ``port_name(port_id) -> str``.
    """

    def __init__(self, *, store, enumerate_ports: Callable[[], List[Dict[str, Any]]],
                 open_session: Callable[..., Dict[str, Any]],
                 write_session: Callable[[str, bytes], bool],
                 close_session: Callable[[str], None],
                 register_sink: Callable[[str, Callable[[bytes], None]], None],
                 unregister_sink: Callable[[str], None],
                 port_device: Callable[[str], Optional[str]],
                 port_name: Callable[[str], str],
                 bind: str = "127.0.0.1",
                 base: int = DEFAULT_TELNET_BASE, span: int = DEFAULT_TELNET_SPAN,
                 allow: Optional[List[str]] = None,
                 loop: Optional[asyncio.AbstractEventLoop] = None):
        self.store = store
        self.enumerate_ports = enumerate_ports
        self.open_session = open_session
        self.write_session = write_session
        self.close_session = close_session
        self.register_sink = register_sink
        self.unregister_sink = unregister_sink
        self.port_device = port_device
        self.port_name = port_name
        self.bind = bind
        self.base = base
        self.span = span
        self.allow = [a.strip() for a in (allow or []) if a.strip()]
        self._loop = loop
        self._servers: Dict[str, asyncio.AbstractServer] = {}  # port_id → server
        self._assigned: Dict[str, int] = {}                    # port_id → tcp port

    def assignment(self, port_id: str) -> Optional[int]:
        """The TCP port currently listening for ``port_id`` (None if not up)."""
        return self._assigned.get(port_id) if port_id in self._servers else None

    def _existing_assignments(self) -> Dict[str, int]:
        out = dict(self._assigned)
        for pid, rec in (self.store.all_items() if self.store else {}).items():
            p = rec.get("dpa_port")
            if isinstance(p, int) and pid not in out:
                out[pid] = p
        return out

    async def reconcile(self) -> None:
        """Ensure exactly one listener per present port; drop listeners for ports
        that vanished. Safe to call repeatedly (hot-plug driven)."""
        self._loop = self._loop or asyncio.get_running_loop()
        present = {p["port_id"] for p in self.enumerate_ports()}
        for pid in list(self._servers):          # tear down vanished ports
            if pid not in present:
                await self._stop_listener(pid)
        for pid in present:                       # bring up new ports
            if pid not in self._servers:
                await self._start_listener(pid)

    async def _start_listener(self, port_id: str) -> None:
        tcp_port = allocate_port(self._existing_assignments(), port_id, self.base, self.span)
        try:
            server = await asyncio.start_server(
                lambda r, w, pid=port_id: self._on_client(r, w, pid),
                host=self.bind, port=tcp_port)
        except Exception as e:  # noqa: BLE001 - port busy / bind denied; retry next reconcile
            logger.warning("DPA listen %s on %s:%d failed: %s", port_id, self.bind, tcp_port, e)
            return
        self._servers[port_id] = server
        self._assigned[port_id] = tcp_port
        if self.store:
            self.store.update(port_id, dpa_port=tcp_port)  # persist for stability
        logger.info("DPA listening for %s on %s:%d", port_id, self.bind, tcp_port)

    async def _stop_listener(self, port_id: str) -> None:
        server = self._servers.pop(port_id, None)
        self._assigned.pop(port_id, None)
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def stop(self) -> None:
        for pid in list(self._servers):
            await self._stop_listener(pid)

    def _peer_allowed(self, writer) -> bool:
        if not self.allow:
            return True
        try:
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else ""
        except Exception:  # noqa: BLE001
            ip = ""
        return any(ip == a or ip.startswith(a) for a in self.allow)

    async def _on_client(self, reader, writer, port_id: str) -> None:
        """asyncio.start_server callback: negotiate telnet, then bridge."""
        if not self._peer_allowed(writer):
            try:
                writer.write(b"Access denied.\r\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            _safe_close(writer)
            return
        await self.bridge(reader, writer, port_id)

    async def bridge(self, reader, writer, port_id: str) -> None:
        """Core connection bridge (transport-agnostic; unit-tested with fakes).

        Attaches a DPA session to the port's serial channel, pumps client→serial
        and serial→client until either side closes, then detaches cleanly.
        """
        loop = self._loop or asyncio.get_event_loop()
        dev = self.port_device(port_id)
        if not dev:
            _write(writer, b"\r\nDPA: serial port not available.\r\n")
            _safe_close(writer)
            return
        sid = f"dpa-{port_id}-{uuid.uuid4().hex[:8]}"
        settings = self.store.settings(port_id) if self.store else {}
        try:
            info = self.open_session(sid, port_id, dev, settings, True)
        except Exception as e:  # noqa: BLE001
            _write(writer, f"\r\nDPA: cannot open {dev}: {e}\r\n".encode())
            _safe_close(writer)
            return

        # serial → client: the sink runs on the reader THREAD, so marshal bytes
        # onto the loop via an asyncio.Queue. Empty bytes == serial EOF.
        q: "asyncio.Queue[bytes]" = asyncio.Queue()

        def _sink(data: bytes) -> None:
            try:
                loop.call_soon_threadsafe(q.put_nowait, data)
            except RuntimeError:  # loop closed
                pass

        self.register_sink(sid, _sink)

        name = self.port_name(port_id) or port_id
        writable = bool(info.get("writer"))
        role = "read-write" if writable else "read-only (another session holds the writer)"
        _write(writer, TELNET_INIT)
        _write(writer, f"\r\n*** DPA connected to {name} [{dev}] — {role} ***\r\n".encode())
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

        async def _pump_out() -> None:
            while True:
                data = await q.get()
                if not data:  # serial ended / handle died
                    _write(writer, b"\r\n*** DPA: serial connection closed ***\r\n")
                    return
                _write(writer, data)
                try:
                    await writer.drain()
                except Exception:  # noqa: BLE001
                    return

        async def _pump_in() -> None:
            state = 0
            while True:
                try:
                    chunk = await reader.read(4096)
                except Exception:  # noqa: BLE001
                    return
                if not chunk:      # client closed
                    return
                clean, state = strip_telnet(chunk, state)
                if clean and writable:
                    self.write_session(sid, clean)

        out_task = asyncio.ensure_future(_pump_out())
        in_task = asyncio.ensure_future(_pump_in())
        try:
            await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (out_task, in_task):
                t.cancel()
            self.unregister_sink(sid)
            try:
                self.close_session(sid)
            except Exception:  # noqa: BLE001
                pass
            _safe_close(writer)


def _write(writer, data: bytes) -> None:
    try:
        writer.write(data)
    except Exception:  # noqa: BLE001
        pass


def _safe_close(writer) -> None:
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
