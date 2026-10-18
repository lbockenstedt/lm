"""Direct Port Access (DPA) — reverse terminal-server for the console role.

Exposes each detected serial port over a per-port TCP listener so an operator can
connect straight to the console line (à la ser2net / a Cisco terminal server):
connect to the port's auto-assigned TCP port and you're attached to the serial
device. Byte flow is bridged onto the existing one-writer / many-observer
:class:`SessionManager` — the first DPA client on a port becomes the writer, the
rest are read-only observers, and the passive monitor's capture is unaffected.

Transports: Telnet (raw TCP with minimal option negotiation) and SSH (see
``dpa_ssh.py`` — authenticated + encrypted, plugs a custom ``listen`` callable into
this same manager/bridge). Security posture — this is a change from the "hub WebUI
relay only" model, so DPA is **OFF by default**; telnet binds **127.0.0.1** unless
the operator explicitly widens it, and an optional source-IP/CIDR allow-list
restricts clients on either transport.

The module has no hard dependency on pyserial/asyncio servers at import time so it
stays unit-testable: the bridge coroutine takes injected reader/writer/session
callables and the port allocator is a pure function.
"""
import asyncio
import ipaddress
import logging
import uuid
from typing import Any, Awaitable, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default TCP port window for Telnet DPA listeners. The example an operator gives
# ("SSH/telnet to port 2201") lands the first port at the window base.
DEFAULT_TELNET_BASE = 2200
DEFAULT_TELNET_SPAN = 200
# SSH window — mirrors the common terminal-server convention (serial 1 → 3001).
DEFAULT_SSH_BASE = 3001
DEFAULT_SSH_SPAN = 200

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


def parse_allow(entries) -> List[Any]:
    """Parse a source allow-list (list or comma/space-separated string of IPs /
    CIDRs) into ``ipaddress`` networks. Invalid entries are dropped (logged)."""
    if isinstance(entries, str):
        entries = entries.replace(",", " ").split()
    nets = []
    for e in entries or []:
        e = str(e).strip()
        if not e:
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            logger.warning("DPA allow-list: ignoring invalid entry %r", e)
    return nets


def ip_allowed(ip: str, nets: List[Any]) -> bool:
    """True when ``ip`` falls in one of ``nets`` (an empty list allows all).
    An unparsable peer address is denied whenever a list is configured."""
    if not nets:
        return True
    try:
        addr = ipaddress.ip_address((ip or "").split("%", 1)[0])
    except ValueError:
        return False
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    return any(addr.version == n.version and addr in n for n in nets)


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
                 loop: Optional[asyncio.AbstractEventLoop] = None,
                 proto: str = "telnet",
                 store_key: str = "dpa_port",
                 listen: Optional[Callable[..., Awaitable[Any]]] = None):
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
        self.allow = parse_allow(allow)
        self._loop = loop
        # proto: "telnet" (IAC negotiation on the wire) or "ssh" (raw bytes over
        # an authenticated channel). store_key: the PortStore field holding this
        # transport's stable auto-assignment; "<store_key>_override" holds an
        # operator-pinned port. listen(port_id, host, port) -> server (close() /
        # wait_closed()) replaces asyncio.start_server for non-telnet transports.
        self.proto = proto
        self.store_key = store_key
        self.override_key = f"{store_key}_override"
        self.listen = listen
        self._servers: Dict[str, asyncio.AbstractServer] = {}  # port_id → server
        self._assigned: Dict[str, int] = {}                    # port_id → tcp port
        self._pinned: set = set()                              # listening on an override
        self._stopped = False  # stop() is final: a stale caller can't resurrect listeners

    def assignment(self, port_id: str) -> Optional[int]:
        """The TCP port currently listening for ``port_id`` (None if not up)."""
        return self._assigned.get(port_id) if port_id in self._servers else None

    def _overrides(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for pid, rec in (self.store.all_items() if self.store else {}).items():
            p = rec.get(self.override_key)
            if isinstance(p, int) and p > 0:
                out[pid] = p
        return out

    def _existing_assignments(self) -> Dict[str, int]:
        out = dict(self._assigned)
        for pid, rec in (self.store.all_items() if self.store else {}).items():
            p = rec.get(self.store_key)
            if isinstance(p, int) and pid not in out:
                out[pid] = p
        return out

    def desired_port(self, port_id: str) -> int:
        """The TCP port ``port_id`` should listen on: its operator override if
        pinned, else a stable auto-assignment from the window that avoids every
        other port's override."""
        overrides = self._overrides()
        if port_id in overrides:
            return overrides[port_id]
        pinned = set(overrides.values())
        existing = {k: v for k, v in self._existing_assignments().items()
                    if k not in overrides}
        if existing.get(port_id) in pinned:
            existing.pop(port_id)  # an override now owns our old port → move
        for i, p in enumerate(sorted(pinned)):  # pinned ports are taken too
            existing[f"\0pinned{i}"] = p
        return allocate_port(existing, port_id, self.base, self.span)

    def validate_override(self, port_id: str, tcp_port: Optional[int]) -> Optional[str]:
        """Return an error string if ``tcp_port`` can't be pinned for
        ``port_id`` (out of range or owned by another port), else None."""
        if tcp_port is None:
            return None
        if not isinstance(tcp_port, int) or not (1024 <= tcp_port <= 65535):
            return "port must be an integer 1024-65535"
        for pid, p in self._overrides().items():
            if pid != port_id and p == tcp_port:
                return f"port {tcp_port} is already pinned to another serial port"
        for pid, p in self._assigned.items():
            if pid != port_id and p == tcp_port and pid in self._servers:
                return f"port {tcp_port} is in use by another serial port"
        return None

    async def reconcile(self) -> None:
        """Ensure exactly one listener per present port; drop listeners for ports
        that vanished; move a listener whose override changed. Safe to call
        repeatedly (hot-plug driven)."""
        if self._stopped:
            return
        self._loop = self._loop or asyncio.get_running_loop()
        present = {p["port_id"] for p in self.enumerate_ports()}
        for pid in list(self._servers):          # tear down vanished ports
            if pid not in present:
                await self._stop_listener(pid)
        overrides = self._overrides()
        for pid in list(self._servers):          # override set/changed/cleared → rebind
            want = overrides.get(pid)
            cur = self._assigned.get(pid)
            if (want is not None and cur != want) or (want is None and pid in self._pinned):
                await self._stop_listener(pid)
        # Free ports owned by a pinned override first so its listener can bind.
        for pid in list(self._servers):
            cur = self._assigned.get(pid)
            if pid not in overrides and cur in overrides.values():
                await self._stop_listener(pid)
        # Pinned first, then by id: set order varies per process (hash seed),
        # which would otherwise shuffle first-boot auto port numbers.
        for pid in sorted(present, key=lambda x: (x not in overrides, x)):
            if pid not in self._servers:
                await self._start_listener(pid)

    async def _start_listener(self, port_id: str) -> None:
        if self._stopped:
            return
        try:
            tcp_port = self.desired_port(port_id)
        except RuntimeError as e:
            logger.warning("DPA %s: %s", self.proto, e)
            return
        try:
            if self.listen is not None:
                server = await self.listen(port_id, self.bind, tcp_port)
            else:
                server = await asyncio.start_server(
                    lambda r, w, pid=port_id: self._on_client(r, w, pid),
                    host=self.bind, port=tcp_port)
        except Exception as e:  # noqa: BLE001 - port busy / bind denied; retry next reconcile
            logger.warning("DPA %s listen %s on %s:%d failed: %s",
                           self.proto, port_id, self.bind, tcp_port, e)
            return
        if self._stopped:  # stop() ran while we were binding — don't leak the listener
            server.close()
            return
        self._servers[port_id] = server
        self._assigned[port_id] = tcp_port
        if tcp_port == self._overrides().get(port_id):
            self._pinned.add(port_id)
        else:
            self._pinned.discard(port_id)
            if self.store:
                self.store.update(port_id, **{self.store_key: tcp_port})  # persist for stability
        logger.info("DPA %s listening for %s on %s:%d", self.proto, port_id, self.bind, tcp_port)

    async def _stop_listener(self, port_id: str) -> None:
        server = self._servers.pop(port_id, None)
        self._assigned.pop(port_id, None)
        self._pinned.discard(port_id)
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def stop(self) -> None:
        self._stopped = True
        for pid in list(self._servers):
            await self._stop_listener(pid)

    def peer_ip_allowed(self, ip: str) -> bool:
        return ip_allowed(ip, self.allow)

    def _peer_allowed(self, writer) -> bool:
        if not self.allow:
            return True
        try:
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else ""
        except Exception:  # noqa: BLE001
            ip = ""
        return ip_allowed(ip, self.allow)

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

    async def bridge(self, reader, writer, port_id: str, telnet: Optional[bool] = None,
                     on_break: Optional[Callable[[str], Any]] = None) -> None:
        """Core connection bridge (transport-agnostic; unit-tested with fakes).

        Attaches a DPA session to the port's serial channel, pumps client→serial
        and serial→client until either side closes, then detaches cleanly.
        ``telnet`` (default: ``proto == "telnet"``) enables IAC negotiation +
        stripping; SSH carries raw bytes. ``on_break(sid)`` is wired to a
        reader exposing ``set_break_handler`` (SSH ``~B`` → serial BREAK).
        """
        if telnet is None:
            telnet = self.proto == "telnet"
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
        if on_break is not None and hasattr(reader, "set_break_handler"):
            reader.set_break_handler(lambda: on_break(sid))

        name = self.port_name(port_id) or port_id
        writable = bool(info.get("writer"))
        role = "read-write" if writable else "read-only (another session holds the writer)"
        if telnet:
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
                if telnet:
                    clean, state = strip_telnet(chunk, state)
                else:
                    clean = chunk
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
