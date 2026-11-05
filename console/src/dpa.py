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
# asyncio: TCP servers, queues and tasks for the per-port bridges.
import asyncio
# ipaddress: parse and match the source-IP allow-list.
import ipaddress
# logging: report listener start/stop and refused clients.
import logging
# uuid: unique suffix for each DPA session id.
import uuid
# Type hints for the injected callables and records.
from typing import Any, Awaitable, Callable, Dict, List, Optional

# Module-level logger.
logger = logging.getLogger(__name__)

# Default TCP port window for Telnet DPA listeners. The example an operator gives
# ("SSH/telnet to port 2201") lands the first port at the window base.
DEFAULT_TELNET_BASE = 2200
DEFAULT_TELNET_SPAN = 200
# SSH window — mirrors the common terminal-server convention (serial 1 → 3001).
DEFAULT_SSH_BASE = 3001
DEFAULT_SSH_SPAN = 200

# Telnet protocol bytes (RFC 854/855/858).
# IAC ("interpret as command") starts every telnet control sequence.
IAC = 0xFF
# Option negotiation verbs.
DONT, DO, WONT, WILL = 0xFE, 0xFD, 0xFC, 0xFB
# Subnegotiation begin/end markers.
SB, SE = 0xFA, 0xF0
# Option codes we negotiate: 8-bit binary, echo, suppress-go-ahead (character mode).
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
    # A string is split on commas/whitespace into individual entries.
    if isinstance(entries, str):
        entries = entries.replace(",", " ").split()
    # Parsed networks; each entry is trimmed and blank ones skipped.
    nets = []
    for e in entries or []:
        e = str(e).strip()
        if not e:
            continue
        # strict=False accepts host bits (e.g. 10.0.0.5/24); a bare IP becomes a /32 or /128.
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        # Bad entries are skipped with a warning rather than failing the whole list.
        except ValueError:
            logger.warning("DPA allow-list: ignoring invalid entry %r", e)
    return nets


def ip_allowed(ip: str, nets: List[Any]) -> bool:
    """True when ``ip`` falls in one of ``nets`` (an empty list allows all).
    An unparsable peer address is denied whenever a list is configured."""
    # No allow-list configured: everyone is allowed.
    if not nets:
        return True
    # Drop any IPv6 zone id ("fe80::1%eth0") before parsing.
    try:
        addr = ipaddress.ip_address((ip or "").split("%", 1)[0])
    # Unparseable peer address: deny.
    except ValueError:
        return False
    # An IPv4 client seen on an IPv6 socket (::ffff:a.b.c.d) is matched as plain IPv4.
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    # Allowed if it is inside any network of the same IP version.
    return any(addr.version == n.version and addr in n for n in nets)


def allocate_port(existing: Dict[str, int], port_id: str,
                  base: int = DEFAULT_TELNET_BASE, span: int = DEFAULT_TELNET_SPAN) -> int:
    """Return a stable TCP port for ``port_id``.

    If ``existing`` already maps ``port_id`` → a port in ``[base, base+span)``,
    that port is kept (stable across restarts/replug). Otherwise the lowest free
    port in the window not already taken by another port_id is assigned. Raises
    ``RuntimeError`` if the window is exhausted.
    """
    # Keep the port's current assignment if it is still inside the window.
    cur = existing.get(port_id)
    if isinstance(cur, int) and base <= cur < base + span:
        return cur
    # Ports in the window already used by other serial ports.
    taken = {v for k, v in existing.items()
             if k != port_id and isinstance(v, int) and base <= v < base + span}
    # Hand out the lowest free port in the window.
    for candidate in range(base, base + span):
        if candidate not in taken:
            return candidate
    # Every port in the window is used.
    raise RuntimeError(f"DPA port window {base}..{base + span - 1} exhausted")


def strip_telnet(data: bytes, in_iac: int = 0) -> "tuple[bytes, int]":
    """Remove Telnet IAC command sequences from inbound client bytes, returning
    ``(clean_payload, carry_state)``. ``in_iac`` carries partial-sequence state
    between chunks: 0 = normal, 1 = saw IAC, 2 = saw IAC+command(DO/DONT/WILL/
    WONT) awaiting the option byte, 3 = inside an IAC SB … IAC SE subnegotiation.
    """
    # Output buffer of real data bytes, and the parser state carried from the last chunk.
    out = bytearray()
    state = in_iac
    # Small state machine over each incoming byte.
    for b in data:
        # Normal data: IAC starts a command, anything else is payload.
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
    # Clean payload plus the state to pass in with the next chunk.
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
        # Persistent per-port store (settings and port assignments) and the injected callables.
        self.store = store
        self.enumerate_ports = enumerate_ports
        self.open_session = open_session
        self.write_session = write_session
        self.close_session = close_session
        self.register_sink = register_sink
        self.unregister_sink = unregister_sink
        self.port_device = port_device
        self.port_name = port_name
        # Listener bind address and the TCP port window.
        self.bind = bind
        self.base = base
        self.span = span
        # Parsed source allow-list.
        self.allow = parse_allow(allow)
        # Event loop; captured lazily on first reconcile if not given.
        self._loop = loop
        # proto: "telnet" (IAC negotiation on the wire) or "ssh" (raw bytes over
        # an authenticated channel). store_key: the PortStore field holding this
        # transport's stable auto-assignment; "<store_key>_override" holds an
        # operator-pinned port. listen(port_id, host, port) -> server (close() /
        # wait_closed()) replaces asyncio.start_server for non-telnet transports.
        # Transport name, store field names, and an optional custom listen hook (SSH).
        self.proto = proto
        self.store_key = store_key
        self.override_key = f"{store_key}_override"
        self.listen = listen
        # Live listener state.
        self._servers: Dict[str, asyncio.AbstractServer] = {}  # port_id → server
        self._assigned: Dict[str, int] = {}                    # port_id → tcp port
        self._pinned: set = set()                              # listening on an override
        self._stopped = False  # stop() is final: a stale caller can't resurrect listeners

    def assignment(self, port_id: str) -> Optional[int]:
        """The TCP port currently listening for ``port_id`` (None if not up)."""
        return self._assigned.get(port_id) if port_id in self._servers else None

    def _overrides(self) -> Dict[str, int]:
        """Return {port_id: tcp_port} for every serial port with an operator-pinned TCP port."""
        # Look at every stored port record (no store means no overrides).
        out: Dict[str, int] = {}
        for pid, rec in (self.store.all_items() if self.store else {}).items():
            p = rec.get(self.override_key)
            # Only positive integers count as a pin.
            if isinstance(p, int) and p > 0:
                out[pid] = p
        return out

    def _existing_assignments(self) -> Dict[str, int]:
        """Return current and previously persisted auto-assignments, current ones winning."""
        # Start from what is live now, then add remembered assignments for other ports.
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
        # An operator pin always wins.
        overrides = self._overrides()
        if port_id in overrides:
            return overrides[port_id]
        # TCP ports pinned by any serial port; auto-assignment must avoid them.
        pinned = set(overrides.values())
        # Auto-assignments of ports without their own pin.
        existing = {k: v for k, v in self._existing_assignments().items()
                    if k not in overrides}
        if existing.get(port_id) in pinned:
            existing.pop(port_id)  # an override now owns our old port → move
        # Add pinned ports under dummy keys so allocate_port treats them as taken.
        for i, p in enumerate(sorted(pinned)):  # pinned ports are taken too
            existing[f"\0pinned{i}"] = p
        return allocate_port(existing, port_id, self.base, self.span)

    def validate_override(self, port_id: str, tcp_port: Optional[int]) -> Optional[str]:
        """Return an error string if ``tcp_port`` can't be pinned for
        ``port_id`` (out of range or owned by another port), else None."""
        # None means "clear the pin", which is always valid.
        if tcp_port is None:
            return None
        # Must be a real integer in the unprivileged range.
        if not isinstance(tcp_port, int) or not (1024 <= tcp_port <= 65535):
            return "port must be an integer 1024-65535"
        # Not pinned to a different serial port already.
        for pid, p in self._overrides().items():
            if pid != port_id and p == tcp_port:
                return f"port {tcp_port} is already pinned to another serial port"
        # Not currently being listened on by a different serial port.
        for pid, p in self._assigned.items():
            if pid != port_id and p == tcp_port and pid in self._servers:
                return f"port {tcp_port} is in use by another serial port"
        return None

    async def reconcile(self) -> None:
        """Ensure exactly one listener per present port; drop listeners for ports
        that vanished; move a listener whose override changed. Safe to call
        repeatedly (hot-plug driven)."""
        # After stop() the manager never restarts listeners.
        if self._stopped:
            return
        # Remember the running loop so serial-thread callbacks can post to it.
        self._loop = self._loop or asyncio.get_running_loop()
        # Serial ports that exist right now.
        present = {p["port_id"] for p in self.enumerate_ports()}
        for pid in list(self._servers):          # tear down vanished ports
            if pid not in present:
                await self._stop_listener(pid)
        # Current operator pins.
        overrides = self._overrides()
        for pid in list(self._servers):          # override set/changed/cleared → rebind
            # Rebind when a new pin differs from where we listen, or a pin was removed.
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
        # Do nothing once the manager is stopped.
        if self._stopped:
            return
        # Choose the TCP port; give up (with a warning) if the window is full.
        try:
            tcp_port = self.desired_port(port_id)
        except RuntimeError as e:
            logger.warning("DPA %s: %s", self.proto, e)
            return
        # Open the listener: the custom hook for SSH, or a plain asyncio TCP server for telnet.
        try:
            if self.listen is not None:
                server = await self.listen(port_id, self.bind, tcp_port)
            else:
                server = await asyncio.start_server(
                    # Default argument pid=port_id freezes this port id inside the callback.
                    lambda r, w, pid=port_id: self._on_client(r, w, pid),
                    host=self.bind, port=tcp_port)
        except Exception as e:  # noqa: BLE001 - port busy / bind denied; retry next reconcile
            logger.warning("DPA %s listen %s on %s:%d failed: %s",
                           self.proto, port_id, self.bind, tcp_port, e)
            return
        if self._stopped:  # stop() ran while we were binding — don't leak the listener
            server.close()
            return
        # Record the live listener and its TCP port.
        self._servers[port_id] = server
        self._assigned[port_id] = tcp_port
        # Listening on the pinned port: mark it pinned.
        if tcp_port == self._overrides().get(port_id):
            self._pinned.add(port_id)
        # Auto-assigned: unmark and persist the choice so it stays the same next time.
        else:
            self._pinned.discard(port_id)
            if self.store:
                self.store.update(port_id, **{self.store_key: tcp_port})  # persist for stability
        logger.info("DPA %s listening for %s on %s:%d", self.proto, port_id, self.bind, tcp_port)

    async def _stop_listener(self, port_id: str) -> None:
        """Close and forget the listener for port_id (if any)."""
        # Forget all state about this port's listener.
        server = self._servers.pop(port_id, None)
        self._assigned.pop(port_id, None)
        self._pinned.discard(port_id)
        # Close the server and wait for it to finish; shutdown errors are ignored.
        if server is not None:
            server.close()
            try:
                await server.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def stop(self) -> None:
        """Stop every listener permanently."""
        # Block future reconciles, then tear down every listener.
        self._stopped = True
        for pid in list(self._servers):
            await self._stop_listener(pid)

    def peer_ip_allowed(self, ip: str) -> bool:
        """Return True if ip may connect under the current allow-list (used by the SSH server)."""
        return ip_allowed(ip, self.allow)

    def _peer_allowed(self, writer) -> bool:
        """Return True if the client behind this asyncio writer is in the allow-list."""
        # No list: allow everyone without looking up the address.
        if not self.allow:
            return True
        # Read the peer address; any failure leaves it blank, which is denied when a list exists.
        try:
            peer = writer.get_extra_info("peername")
            ip = peer[0] if peer else ""
        except Exception:  # noqa: BLE001
            ip = ""
        return ip_allowed(ip, self.allow)

    async def _on_client(self, reader, writer, port_id: str) -> None:
        """asyncio.start_server callback: negotiate telnet, then bridge."""
        # Refused clients get a short message and are disconnected.
        if not self._peer_allowed(writer):
            try:
                writer.write(b"Access denied.\r\n")
                await writer.drain()
            except Exception:  # noqa: BLE001
                pass
            _safe_close(writer)
            return
        # Allowed: attach the client to the serial port.
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
        # Default to telnet negotiation only for the telnet transport.
        if telnet is None:
            telnet = self.proto == "telnet"
        # Loop used to post serial-thread data onto the event loop.
        loop = self._loop or asyncio.get_event_loop()
        # Resolve the serial device; tell the client and hang up if it is gone.
        dev = self.port_device(port_id)
        if not dev:
            _write(writer, b"\r\nDPA: serial port not available.\r\n")
            _safe_close(writer)
            return
        # Unique session id, e.g. "dpa-<port>-1a2b3c4d".
        sid = f"dpa-{port_id}-{uuid.uuid4().hex[:8]}"
        # Saved serial settings (baud etc.) for this port.
        settings = self.store.settings(port_id) if self.store else {}
        # Open a session asking for write access; failures are reported to the client.
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
            """Called on the serial reader thread; hand data to the event loop's queue thread-
            safely.
            """
            try:
                loop.call_soon_threadsafe(q.put_nowait, data)
            except RuntimeError:  # loop closed
                pass

        # Start receiving device output for this session.
        self.register_sink(sid, _sink)
        # SSH readers can forward a break request to the serial port.
        if on_break is not None and hasattr(reader, "set_break_handler"):
            reader.set_break_handler(lambda: on_break(sid))

        # Display name, whether we got the single writer slot, and a label for the banner.
        name = self.port_name(port_id) or port_id
        writable = bool(info.get("writer"))
        role = "read-write" if writable else "read-only (another session holds the writer)"
        # Telnet clients are switched into raw character mode first.
        if telnet:
            _write(writer, TELNET_INIT)
        # Banner telling the operator which port and access mode they have.
        _write(writer, f"\r\n*** DPA connected to {name} [{dev}] — {role} ***\r\n".encode())
        # Flush the banner; a client that already left is handled by the pumps.
        try:
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

        async def _pump_out() -> None:
            """Copy device output from the queue to the client until serial EOF or client error."""
            # Wait for the next chunk of device output.
            while True:
                data = await q.get()
                if not data:  # serial ended / handle died
                    _write(writer, b"\r\n*** DPA: serial connection closed ***\r\n")
                    return
                # Send it to the client; a failed flush means the client has gone.
                _write(writer, data)
                try:
                    await writer.drain()
                except Exception:  # noqa: BLE001
                    return

        async def _pump_in() -> None:
            """Copy client keystrokes to the serial port until the client disconnects."""
            # Telnet parser state carried between reads.
            state = 0
            while True:
                # Read up to 4 KiB from the client; a read error ends the pump.
                try:
                    chunk = await reader.read(4096)
                except Exception:  # noqa: BLE001
                    return
                if not chunk:      # client closed
                    return
                # Telnet: remove control sequences; SSH: bytes are already raw.
                if telnet:
                    clean, state = strip_telnet(chunk, state)
                else:
                    clean = chunk
                # Only the writer session may send to the device; observers' keys are discarded.
                if clean and writable:
                    self.write_session(sid, clean)

        # Run both directions at once.
        out_task = asyncio.ensure_future(_pump_out())
        in_task = asyncio.ensure_future(_pump_in())
        # Stop as soon as either direction ends.
        try:
            await asyncio.wait({out_task, in_task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            # Always clean up: stop both pumps, detach from the serial port, close the session
            # and the client connection.
            for t in (out_task, in_task):
                t.cancel()
            self.unregister_sink(sid)
            try:
                self.close_session(sid)
            except Exception:  # noqa: BLE001
                pass
            _safe_close(writer)


def _write(writer, data: bytes) -> None:
    """Write to a client connection, ignoring errors from an already-closed connection."""
    try:
        writer.write(data)
    except Exception:  # noqa: BLE001
        pass


def _safe_close(writer) -> None:
    """Close a client connection, ignoring errors."""
    try:
        writer.close()
    except Exception:  # noqa: BLE001
        pass
