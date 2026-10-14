"""End-to-end SSH Direct Port Access: a real asyncssh client ↔ the DPA SSH
listener ↔ a faked serial session. Skipped when asyncssh isn't installed."""
import asyncio
import socket

import pytest

asyncssh = pytest.importorskip("asyncssh")

import dpa  # noqa: E402
import dpa_ssh  # noqa: E402


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Sessions:
    def __init__(self):
        self.writes = []
        self.breaks = []
        self.closed = []
        self.sinks = {}

    def open(self, sid, port_id, dev, settings, writable):
        return {"writer": True}

    def write(self, sid, data):
        self.writes.append(data)
        # device echoes what it receives
        cb = self.sinks.get(sid)
        if cb:
            cb(b"ECHO:" + data)
        return True


async def _start(tmp_path, auth, allow=None):
    s = _Sessions()

    class _Store:
        def __init__(self):
            self.d = {}

        def all_items(self):
            return dict(self.d)

        def settings(self, pid):
            return {}

        def update(self, pid, **kw):
            self.d.setdefault(pid, {}).update(kw)

    port = _free_port()
    mgr = dpa.DpaManager(
        store=_Store(), enumerate_ports=lambda: [{"port_id": "p1"}],
        open_session=s.open, write_session=s.write, close_session=s.closed.append,
        register_sink=lambda sid, cb: s.sinks.__setitem__(sid, cb),
        unregister_sink=lambda sid: s.sinks.pop(sid, None),
        port_device=lambda pid: "/dev/ttyUSB0", port_name=lambda pid: "SW1",
        bind="127.0.0.1", base=port, span=1, allow=allow, proto="ssh",
        store_key="dpa_ssh_port")
    key = dpa_ssh.load_or_create_host_key(asyncssh, tmp_path / "hostkey")
    mgr.listen = dpa_ssh.make_listen(mgr, asyncssh, key, auth=lambda: auth,
                                     send_break=s.breaks.append)
    await mgr.reconcile()
    assert mgr.assignment("p1") == port
    return mgr, s, port


async def _session(port, **kw):
    conn = await asyncssh.connect("127.0.0.1", port, known_hosts=None, username="op",
                                  client_keys=kw.pop("client_keys", None), **kw)
    proc = await conn.create_process(term_type="xterm", encoding=None)
    return conn, proc


async def _read_until(proc, needle, timeout=5.0):
    buf = b""
    end = asyncio.get_event_loop().time() + timeout
    while needle not in buf:
        left = end - asyncio.get_event_loop().time()
        assert left > 0, f"timeout waiting for {needle!r}; got {buf!r}"
        buf += await asyncio.wait_for(proc.stdout.read(4096), left)
    return buf


def test_password_login_bridges_bytes_both_ways(tmp_path):
    async def run():
        mgr, s, port = await _start(tmp_path, {"password_hash": dpa_ssh.hash_password("s3cret-pass")})
        try:
            conn, proc = await _session(port, password="s3cret-pass")
            await _read_until(proc, b"DPA connected to SW1")
            proc.stdin.write(b"show ver\r")
            await _read_until(proc, b"ECHO:show ver\r")
            assert b"show ver\r" in b"".join(s.writes)
            # window resize must NOT end the session
            proc.change_terminal_size(120, 40)
            proc.stdin.write(b"x")
            await _read_until(proc, b"ECHO:x")
            # ~B / break → serial BREAK
            proc.send_break(250)
            for _ in range(100):
                if s.breaks:
                    break
                await asyncio.sleep(0.01)
            assert len(s.breaks) == 1
            conn.close()
            for _ in range(100):
                if s.closed:
                    break
                await asyncio.sleep(0.01)
            assert s.closed  # session detached on disconnect
        finally:
            await mgr.stop()

    asyncio.new_event_loop().run_until_complete(run())


def test_wrong_password_rejected(tmp_path):
    async def run():
        mgr, s, port = await _start(tmp_path, {"password_hash": dpa_ssh.hash_password("s3cret-pass")})
        try:
            with pytest.raises(asyncssh.PermissionDenied):
                await _session(port, password="nope")
            assert s.writes == []
        finally:
            await mgr.stop()

    asyncio.new_event_loop().run_until_complete(run())


def test_public_key_login(tmp_path):
    async def run():
        ck = asyncssh.generate_private_key("ssh-ed25519")
        pub = ck.export_public_key().decode()
        mgr, s, port = await _start(tmp_path, {"authorized_keys": pub})
        try:
            conn, proc = await _session(port, client_keys=[ck])
            await _read_until(proc, b"DPA connected")
            conn.close()
            # a different key is refused
            other = asyncssh.generate_private_key("ssh-ed25519")
            with pytest.raises(asyncssh.PermissionDenied):
                await _session(port, client_keys=[other])
        finally:
            await mgr.stop()

    asyncio.new_event_loop().run_until_complete(run())


def test_no_credentials_configured_means_no_login(tmp_path):
    async def run():
        mgr, s, port = await _start(tmp_path, {})
        try:
            with pytest.raises(asyncssh.PermissionDenied):
                await _session(port, password="anything")
        finally:
            await mgr.stop()

    asyncio.new_event_loop().run_until_complete(run())


def test_allow_list_blocks_before_auth(tmp_path):
    async def run():
        mgr, s, port = await _start(tmp_path, {"password_hash": dpa_ssh.hash_password("s3cret-pass")},
                                    allow=["10.0.0.0/8"])
        try:
            with pytest.raises(asyncssh.PermissionDenied):
                await _session(port, password="s3cret-pass")
        finally:
            await mgr.stop()

    asyncio.new_event_loop().run_until_complete(run())


def test_host_key_is_persistent(tmp_path):
    k1 = dpa_ssh.load_or_create_host_key(asyncssh, tmp_path / "hk")
    k2 = dpa_ssh.load_or_create_host_key(asyncssh, tmp_path / "hk")
    assert dpa_ssh.host_key_fingerprint(k1) == dpa_ssh.host_key_fingerprint(k2)
