"""SSH transport for Direct Port Access (DPA).

Each serial port gets its own SSH listener (``ssh -p 3001 user@console-host``);
the authenticated channel is bridged raw onto the port via
:meth:`dpa.DpaManager.bridge` (no telnet negotiation). Plugged into a
``DpaManager`` through its ``listen`` hook — see :func:`make_listen`.

Auth is local to the console host (no hub round-trip): an operator-set password
(stored only as a scrypt hash) and/or authorized OpenSSH public keys. With
neither configured nobody can log in. The source allow-list is enforced before
any auth method is offered. The username is not checked — the secret is the
password/key — so operators may use any name (e.g. their own for audit logs).

``asyncssh`` is an optional dependency: imported lazily so the module (and the
pure helpers) load on a node that hasn't installed it; :func:`ensure_asyncssh`
pip-installs it into the running interpreter on first use.
"""
import asyncio
import base64
import hashlib
import hmac
import importlib
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

logger = logging.getLogger(__name__)

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1
_FAIL_DELAY_S = 1.0  # slows online password guessing per attempt


# ── password hashing (pure) ──────────────────────────────────────────────────
# scrypt when the interpreter's OpenSSL provides it; PBKDF2-SHA256 otherwise
# (e.g. LibreSSL builds). The stored string names its algorithm, so either
# verifies anywhere it was produced.
_PBKDF2_ITERS = 600_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    if hasattr(hashlib, "scrypt"):
        dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                            p=_SCRYPT_P, dklen=32)
        return "scrypt${}${}${}${}${}".format(
            _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
            base64.b64encode(salt).decode(), base64.b64encode(dk).decode())
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS, dklen=32)
    return "pbkdf2_sha256${}${}${}".format(
        _PBKDF2_ITERS, base64.b64encode(salt).decode(), base64.b64encode(dk).decode())


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = (stored or "").split("$")
        pw = (password or "").encode()
        if parts[0] == "scrypt" and len(parts) == 6:
            _, n, r, p, salt_b64, dk_b64 = parts
            want = base64.b64decode(dk_b64)
            got = hashlib.scrypt(pw, salt=base64.b64decode(salt_b64),
                                 n=int(n), r=int(r), p=int(p), dklen=len(want))
        elif parts[0] == "pbkdf2_sha256" and len(parts) == 4:
            _, iters, salt_b64, dk_b64 = parts
            want = base64.b64decode(dk_b64)
            got = hashlib.pbkdf2_hmac("sha256", pw, base64.b64decode(salt_b64),
                                      int(iters), dklen=len(want))
        else:
            return False
        return hmac.compare_digest(got, want)
    except Exception:  # noqa: BLE001 - malformed hash / missing algo → deny
        return False


# ── asyncssh (optional dep) ──────────────────────────────────────────────────
def load_asyncssh():
    try:
        return importlib.import_module("asyncssh")
    except ImportError:
        return None


def ensure_asyncssh(install: bool = True) -> Tuple[Any, Optional[str]]:
    """Return ``(asyncssh_module, error)``. Blocking (may pip install) — call
    off the event loop."""
    mod = load_asyncssh()
    if mod is not None or not install:
        return mod, (None if mod else "asyncssh not installed")
    logger.info("DPA ssh: asyncssh missing — installing into %s", sys.executable)
    try:
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "asyncssh>=2.14"],
                           capture_output=True, text=True, timeout=300)
    except Exception as e:  # noqa: BLE001
        return None, f"asyncssh install failed: {e}"
    if r.returncode != 0:
        return None, "asyncssh install failed: " + (r.stderr or r.stdout or "").strip()[-300:]
    importlib.invalidate_caches()
    mod = load_asyncssh()
    return mod, (None if mod else "asyncssh still not importable after install")


def validate_authorized_keys(text: str) -> Optional[str]:
    """None if ``text`` parses as OpenSSH authorized_keys (or is blank), else an
    error message. Without asyncssh, only a light shape check is possible."""
    if not (text or "").strip():
        return None
    mod = load_asyncssh()
    if mod is None:
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and len(line.split()) < 2:
                return f"not an SSH public key: {line[:40]}"
        return None
    try:
        mod.import_authorized_keys(text)
    except Exception as e:  # noqa: BLE001
        return f"invalid authorized keys: {e}"
    return None


def load_or_create_host_key(asyncssh_mod, path: Path):
    """Persistent ed25519 host key (0600) so clients' known_hosts stay valid
    across restarts."""
    if path.exists():
        try:
            return asyncssh_mod.read_private_key(str(path))
        except Exception as e:  # noqa: BLE001
            logger.warning("DPA ssh: unreadable host key %s (%s) — regenerating", path, e)
    key = asyncssh_mod.generate_private_key("ssh-ed25519", comment="lm-console-dpa")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.export_private_key())
    os.replace(tmp, path)
    return key


# ── stream adapters: SSHServerProcess → bridge reader/writer ─────────────────
class _ProcReader:
    """``read(n)`` over an SSH process' stdin that survives out-of-band events:
    a window resize or signal is ignored and an SSH break (``~B``) is turned
    into a serial BREAK instead of ending the session."""

    def __init__(self, process, asyncssh_mod):
        self._p = process
        self._m = asyncssh_mod
        self._on_break: Optional[Callable[[], Any]] = None

    def set_break_handler(self, cb: Callable[[], Any]) -> None:
        self._on_break = cb

    async def read(self, n: int) -> bytes:
        m = self._m
        while True:
            try:
                data = await self._p.stdin.read(n)
            except m.BreakReceived:
                if self._on_break:
                    try:
                        self._on_break()
                    except Exception:  # noqa: BLE001
                        pass
                continue
            except (m.TerminalSizeChanged, m.SignalReceived):
                continue
            if isinstance(data, str):
                data = data.encode()
            return data or b""


class _ProcWriter:
    def __init__(self, process):
        self._p = process

    def write(self, data: bytes) -> None:
        self._p.stdout.write(data)

    async def drain(self) -> None:
        await self._p.stdout.drain()

    def close(self) -> None:
        try:
            self._p.exit(0)
        except Exception:  # noqa: BLE001
            pass

    def get_extra_info(self, name, default=None):
        return self._p.get_extra_info(name, default)


# ── server ───────────────────────────────────────────────────────────────────
def make_server_class(asyncssh_mod):
    class DpaSSHServer(asyncssh_mod.SSHServer):
        """Per-connection auth policy. ``auth`` is a zero-arg callable returning
        the CURRENT ``{"password_hash", "authorized_keys"}`` so a credential
        change applies to the next login without restarting listeners."""

        def __init__(self, auth: Callable[[], dict], ip_allowed: Callable[[str], bool]):
            self._auth = auth
            self._ip_allowed = ip_allowed
            self._allowed = False
            self._conn = None

        def connection_made(self, conn):
            self._conn = conn
            peer = conn.get_extra_info("peername") or ("",)
            self._allowed = bool(self._ip_allowed(peer[0] if peer else ""))
            if not self._allowed:
                logger.warning("DPA ssh: refused %s (not in allow-list)", peer[0] if peer else "?")

        def begin_auth(self, username):
            cfg = self._auth() or {}
            keys = (cfg.get("authorized_keys") or "").strip()
            if self._allowed and keys:
                try:
                    self._conn.set_authorized_keys(asyncssh_mod.import_authorized_keys(keys))
                except Exception as e:  # noqa: BLE001
                    logger.warning("DPA ssh: bad authorized keys: %s", e)
            return True  # always require auth

        def password_auth_supported(self):
            return self._allowed and bool((self._auth() or {}).get("password_hash"))

        def public_key_auth_supported(self):
            return self._allowed and bool(((self._auth() or {}).get("authorized_keys") or "").strip())

        def kbdint_auth_supported(self):
            return False

        def host_based_auth_supported(self):
            return False

        async def validate_password(self, username, password):
            ok = self._allowed and verify_password(password, (self._auth() or {}).get("password_hash") or "")
            if not ok:
                await asyncio.sleep(_FAIL_DELAY_S)
            return ok

    return DpaSSHServer


def make_listen(manager, asyncssh_mod, host_key, auth: Callable[[], dict],
                send_break: Optional[Callable[[str], Any]] = None):
    """Build the ``DpaManager.listen`` hook: one SSH server per serial port."""
    server_cls = make_server_class(asyncssh_mod)

    async def listen(port_id: str, host: str, port: int):
        async def _process(process):
            reader = _ProcReader(process, asyncssh_mod)
            writer = _ProcWriter(process)
            peer = (process.get_extra_info("peername") or ("?",))[0]
            user = process.get_extra_info("username")
            logger.info("DPA ssh: %s@%s attached to %s", user, peer, port_id)
            await manager.bridge(reader, writer, port_id, telnet=False,
                                 on_break=send_break)

        return await asyncssh_mod.create_server(
            lambda: server_cls(auth, manager.peer_ip_allowed),
            host or None, port,
            server_host_keys=[host_key],
            process_factory=_process,
            encoding=None,
            line_editor=False,
            login_timeout=30,
            keepalive_interval=60,
        )

    return listen


def host_key_fingerprint(host_key) -> Optional[str]:
    try:
        return host_key.get_fingerprint("sha256")
    except Exception:  # noqa: BLE001
        return None
