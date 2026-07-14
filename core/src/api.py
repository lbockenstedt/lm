"""LM Hub HTTP/WebSocket surface (FastAPI).

This module builds the FastAPI app that serves the Hub WebUI and integration
endpoints, and runs the uvicorn server that hosts it. It owns:

- Sessions & auth — cookie-based login/logout/setup, the in-memory ``_sessions``
  token→session map (persisted to ``sessions.json`` so a logged-in user survives
  a triggered update/restart; see ``_save_sessions``/``_load_sessions``), the
  per-request ``_session_user`` validator, and admin session listing/revocation.
- Tenant cache — per-tenant, per-module prefetched data with a background
  refresh loop and a "drop the cache when no session for a tenant is active"
  rule (``_start_cache_for_tenant``/``_stop_cache_for_tenant``).
- Simulations (cs) relay — mounts the ported Client-Sim operator UI routes
  (``register_simulations_routes``) and relays cs telemetry/events through to
  the LM cs spoke; the spoke is relay-only, so no auto-provisioning logic runs
  here (that brain lives in the pxmx agent, ``pxmx/agent/src/usb_provision.py``).
- Update trigger — ``perform_update`` orchestrates a hub self-update and, on
  success, schedules ``lm-self-restart`` (after flushing sessions to disk).

The app factory is ``create_app(hub)``; the server entrypoint is
``run_api_server``. Audience: Hub developers. For the user-facing manual see
``docs/user_manual.md``; for the REST reference see ``docs/api.md``.

Route map & auth contract
-------------------------

Routes are grouped by feature but NOT in one contiguous block — a top-down
reader encounters them in roughly this order:

  * Setup / spoke approvals / product config (``/setup/*``) — admin-only.
  * NetBox→CPPM IPAM sync (``/api/cppm/sync-endpoints`` etc.) — admin-only.
  * Firewall data + CRUD (``/api/firewall/*``).
  * Multi-instance product CRUD factory (``_instance_crud`` — NAC/IPAM/Directory).
  * CPPM / NAC devices, sessions, logs, roles (``/api/cppm/*``).
  * Device detail + aggregate + pxmx VMs (``/api/device/*``, ``/api/pxmx/*``).
  * Dashboard + global search (``/api/search`` → ``cross_system_search``).
  * Diagnostics + recovery + bug-report (``/api/diagnostics``, ``/api/bug-report``).
  * LDAP relay (``/api/ldap/*``).
  * NetBox data + CRUD (``/api/netbox/*``).
  * Tenants + users (``/setup/tenants``, ``/setup/users``).
  * Auth routes (``/auth/login``, ``/auth/me``, ``/auth/logout``, ``/auth/setup``,
    ``/auth/prefixes``) — defined LATE, near the end of ``create_app``.
  * Admin subnet-filter toggle (``/admin/subnet-filter-config``).
  * Generic Agent API (``/api/agent/*``, ``/api/generic/provision``).
  * DNS relay (``/api/dns/*``).
  * DHCP relay (``/api/dhcp/*``).
  * Cache management (``/admin/cache/*``, ``/auth/cache/*``).
  * Simulations (``/sim/api/*``) — mounted via ``register_simulations_routes``.

Auth (enforced by ``access_control_middleware``): every ``/api/``, ``/setup/``,
``/admin/``, ``/auth/``, ``/sim/api/`` path requires a valid ``lm_session`` cookie
(``_session_user``) except a small public set (``/auth/login``, ``/auth/me``,
``/auth/setup``, ``/status``, ``/sim/api/init``, ``/sim/api/health``).
``/setup/*`` and ``/admin/*`` additionally require an admin session;
``/sim/api/*`` requires the ``cs`` right OR admin. ``?tenant=`` is scoped — a
non-admin user can only request tenants they're authorised for
(``_check_tenant_access``).

The auth/tenant helper closures (``_session_user``, ``_is_admin``,
``_has_cs_access``, ``_check_tenant_access``, ``_resolve_tenant``,
``_effective_tenant*``, ``_filter_session*``) are defined LATE in ``create_app``
(search for ``def _session_user``) but used by routes ~3,500 lines earlier.
Python resolves them at call time, so this works — but a top-down reader hits the
first use long before the definition. Jump to ``def _session_user`` to find them.

Error-response conventions:
  * Spoke down / not connected → ``raise HTTPException(503, "…not connected")``.
    This is the uniform convention for relay GETs (CPPM, firewall, pxmx, NetBox,
    DNS, DHCP, LDAP) — HTTP-level monitors see the 503 directly.
  * Spoke connected but reported an error → ``raise HTTPException(502, "…")``
    (e.g. ``_cppm_unwrap`` raises 502 on a ``status: ERROR`` payload).
  * Success token: ``"ok"`` (``{"status": "ok", "message": "…", "pushed": bool}``
    for config pushes). Use ``"ok"`` for the top-level status of a simple success.
  * ``"partial_success"`` is retained for multi-target / config-push responses where
    the hub saved locally but could not reach a spoke — those also carry a
    ``"pushed": bool`` (and a count where applicable) so a monitor can distinguish
    fully-pushed from partially-pushed. Do NOT rename these to ``"ok"``.
  * Exception: the update-trigger (``/setup/update``) keeps ``"status": "success"``
    because ``webui/update_handler.js`` keys its restart-poll off that literal.
Match these conventions when adding a route; add ``logger.exception(...)`` before
a bare ``raise HTTPException(500, detail=str(e))`` so hub logs capture the trace
(a handful of older sites still lack it — add it when you touch them).
"""

import os
import re
import asyncio
import base64
import json
import time
import uuid
import logging
import hashlib
import secrets
import ipaddress
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect

# Shared logging runtime toggle (lm/core/src/logging_setup.py). Used by the
# "Enable Debug" button so the hub process itself flips to DEBUG — not just
# the broadcasted spokes/agents. Two-tier import + fallback for deploy safety.
try:
    from logging_setup import set_log_level
except ImportError:
    try:
        from core.src.logging_setup import set_log_level
    except ImportError:
        def set_log_level(enabled):  # minimal fallback (hub always has core/src)
            import logging as _logging
            lvl = _logging.DEBUG if enabled else _logging.INFO
            _logging.getLogger().setLevel(lvl)
            for _n in list(_logging.root.manager.loggerDict):
                _logging.getLogger(_n).setLevel(lvl)
            return lvl
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.websockets import WebSocketState
from typing import Any, Dict
# NOTE: any typing name used in an annotation on a nested `def` inside
# create_app() (e.g. ``Dict[str, Any]``) MUST be imported here at module scope.
# Nested-def annotations are evaluated when create_app() runs (at app build),
# NOT at module import, so a missing name raises NameError at startup — the
# .117→.121 regression. ``str | None`` (PEP 604) in nested-def return annotations
# also evaluates at def-time and needs Python 3.10+ (prod is 3.11; the dev box
# is 3.9, so prefer ``Optional[X]`` over ``X | None`` in nested defs).
import uvicorn
import websockets

logger = logging.getLogger("Hub")


class StarletteWSAdapter:
    """Expose the ``websockets``-lib server-socket API on top of a Starlette
    ``WebSocket`` so ``LabManagerHub.handle_connection`` (and ``send_to_spoke``,
    which calls ``ws.send(...)`` on stored connections) can run UNCHANGED on a
    FastAPI/uvicorn WebSocket route — the unified-443 merge.

    The spoke protocol is JSON text only (no binary, no subprotocols), so
    ``recv``/``send`` map to ``receive_text``/``send_text``. ``async for msg in
    ws:`` maps to a receive loop that stops on ``WebSocketDisconnect``.
    ``remote_address`` maps to ``websocket.client``. Sends are serialized with an
    ``asyncio.Lock`` so the many hub background loops that push to a given spoke
    can't interleave ASGI send frames on the same socket.
    """

    def __init__(self, websocket: WebSocket):
        self._ws = websocket
        self._send_lock = asyncio.Lock()
        # App-layer liveness probe wiring (see _install_active_connection's
        # half-open zombie check). uvicorn owns WS-layer keepalive pings and does
        # NOT surface pong waiters to the application, so the hub probes liveness
        # with a signed HUB_PING/HUB_PONG round-trip at the application layer.
        # ``_probe_sender`` is armed by the hub when this connection is installed
        # (it knows the spoke_id + signing key); ``ping()`` sends a probe and
        # returns a future that resolves when the matching HUB_PONG arrives (or
        # is cancelled on close). Mirrors the ``websockets``-lib ``ping()``
        # contract the test fakes already model: ``pong_waiter = await ws.ping()``.
        self._probe_sender = None  # async (nonce) -> None, set by hub._arm_liveness_probe
        self._pending_pongs: Dict[str, asyncio.Future] = {}

    @property
    def remote_address(self):
        client = self._ws.client  # (host, port) tuple or None pre-accept
        return tuple(client) if client else None

    @property
    def state(self):
        """websockets-lib ``WebSocketServerProtocol.state`` compatibility.

        The Diagnostics endpoint (``get_diagnostics``) reads ``ws.state`` off
        each stored spoke connection to surface ``connection_state``. The old
        ``websockets`` server socket exposed a ``State`` enum
        (OPEN/CLOSING/CLOSED/CONNECTING); this adapter maps Starlette's
        ``application_state`` to those name strings so the value serializes the
        same way in the diagnostics JSON (and any ``str(ws.state)`` consumer).
        """
        try:
            st = self._ws.application_state
        except Exception:
            return "CLOSED"
        if st == WebSocketState.CONNECTED:
            return "OPEN"
        if st == WebSocketState.CONNECTING:
            return "CONNECTING"
        return "CLOSED"

    async def recv(self) -> str:
        return await self._ws.receive_text()

    async def send(self, data: str) -> None:
        async with self._send_lock:
            await self._ws.send_text(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        # A close mid-probe cancels outstanding ping waiters so a liveness check
        # blocked on this socket resolves to "dead" (CancelledError → the probe's
        # except → alive=False) instead of hanging until its 2s timeout.
        for fut in list(self._pending_pongs.values()):
            if not fut.done():
                fut.cancel()
        self._pending_pongs.clear()
        try:
            async with self._send_lock:
                await self._ws.close(code=code, reason=reason)
        except Exception:
            pass

    def set_probe_sender(self, sender) -> None:
        """Arm the app-layer liveness probe. ``sender`` is an awaitable
        ``(nonce) -> None`` that signs + sends a HUB_PING to this spoke; set by
        ``LabManagerHub._arm_liveness_probe`` once the connection is installed
        and the spoke's signing key is known. Without it ``ping()`` raises
        (treated as dead) — e.g. a pending/unauthenticated connection."""
        self._probe_sender = sender

    async def ping(self):
        """Send a signed HUB_PING and return a pong-waiter future (the
        ``websockets``-lib ``ping()`` contract): the caller awaits the future
        (typically with ``asyncio.wait_for``) and it resolves when the matching
        HUB_PONG arrives, is cancelled on close, or raises if the probe could
        not be sent. Used by ``_install_active_connection`` to distinguish a
        half-open zombie (no pong) from a live-but-paused spoke (pongs)."""
        if self._probe_sender is None:
            # No signing context (pending/unauthenticated) → not probeable;
            # treat as dead so the caller falls through to evict/zombie handling.
            raise ConnectionError("liveness probe unavailable (no probe sender)")
        nonce = uuid.uuid4().hex
        fut = asyncio.get_running_loop().create_future()
        # Send BEFORE registering: a reply can't predate a successful send, and
        # a send failure (socket already gone) should raise, not strand a future.
        await self._probe_sender(nonce)
        self._pending_pongs[nonce] = fut
        return fut

    def resolve_pong(self, nonce: str) -> None:
        """Resolve the ping waiter for ``nonce`` (the hub's inbound dispatch
        calls this when a HUB_PONG / COMMAND_RESULT carrying the ping's
        message_id arrives). No-op if unknown/already resolved (late/dup pong)."""
        fut = self._pending_pongs.pop(nonce, None)
        if fut is not None and not fut.done():
            fut.set_result(None)

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        # Starlette raises WebSocketDisconnect on close; let it propagate
        # (async-for only catches StopAsyncIteration) so handle_connection's
        # ``except`` clean-close branch runs — sets telemetry DISCONNECTED and
        # records the connection_closed event, matching the websockets-lib path.
        return await self._ws.receive_text()


from messaging.protocol import Message, MessageHeader, MessagePayload
from simulations.routes import register_simulations_routes
from simulations.tenant_filter import filter_items_by_prefixes

import access
import api_tokens
import vmid_alloc
# Access-control / tenant-scoping / subnet-filter logic lives in the leaf
# module ``access`` (importable + testable, free of the create_app() nested-def
# annotation trap). api.py depends on access one-way; access never imports api.
# Re-exports keep the ~26 routes calling ``_unwrap_spoke(result)`` and the
# subnet-filter-config routes working with zero call-site churn. The closures
# ``_session_user``/``_is_admin``/``_filter_session*``/``get_netbox_spoke``/
# ``get_tenant_scoping`` are thin shims defined inside create_app() that delegate
# to access.* (search for ``def _session_user``).
_unwrap_spoke = access.unwrap_spoke
_filter_config = access.filter_config
_FILTER_MODULES = access._FILTER_MODULES
_FILTER_DEFAULTS = access._FILTER_DEFAULTS

_SESSION_TTL = 8 * 3600  # 8 hours (absolute cap)
# Per-user live-session cap (evicts oldest on login). The idle timeout is owned
# by access.session_user (reads LM_SESSION_IDLE_TIMEOUT_S there).
_MAX_SESSIONS_PER_USER = int(os.environ.get("LM_MAX_SESSIONS_PER_USER", "5"))
_sessions: dict = {}  # token → {user_id, expires, created, last_seen, sid, user}

# ── Login throttling (failed-attempt lockout + per-IP spray limiter) ─────────
# No HTTP rate-limit library is used; this is a compact in-process throttle. The
# per-username counters (lockout state) are persisted to login_attempts.json so
# a targeted brute-force survives a hub restart; the per-IP spray window is
# in-memory only (resets on restart — acceptable). Tunable via env.
_LOGIN_MAX_FAILS = int(os.environ.get("LM_LOGIN_MAX_FAILS", "5"))
_LOGIN_BASE_LOCKOUT_S = float(os.environ.get("LM_LOGIN_BASE_LOCKOUT_S", "30"))
_LOGIN_MAX_LOCKOUT_S = float(os.environ.get("LM_LOGIN_MAX_LOCKOUT_S", "3600"))
_LOGIN_IP_WINDOW_S = float(os.environ.get("LM_LOGIN_IP_WINDOW_S", "300"))
_LOGIN_IP_MAX = int(os.environ.get("LM_LOGIN_IP_MAX", "20"))
# Cap on the number of distinct source IPs tracked in the spray window. A
# spoofed-XFF rotation (or a large fleet behind one proxy) would otherwise grow
# ``_login_ip_attempts`` without limit; past this cap the oldest buckets are
# evicted. Per-username lockout remains the real defense; this is memory hygiene.
_LOGIN_IP_TRACKED_MAX = int(os.environ.get("LM_LOGIN_IP_TRACKED_MAX", "4096"))
_login_attempts: dict = {}    # {username: {count, locked_until, first_fail}}
_login_ip_attempts: dict = {}  # {ip: [ts,...]} (in-memory, not persisted)


def _load_trusted_proxies() -> tuple:
    """Parse ``LM_TRUSTED_PROXIES`` (comma/space-separated IPs/CIDRs) into a
    tuple of ``(networks, raw)``. Empty when unset.

    Behind a TLS-terminating front end (Azure App Gateway / Front Door / nginx)
    the TCP peer Starlette sees is the PROXY, not the client — so the per-IP
    login-spray limiter is useless (every login shares one proxy-IP bucket →
    20 attempts = a global self-DoS) unless the real client IP is recovered
    from ``X-Forwarded-For``. But XFF is client-settable, so trusting it
    blindly is spoofable (an attacker rotates a spoofed XFF to bypass the
    per-IP cap). ``_client_ip`` trusts XFF ONLY when the immediate TCP peer
    is in this trusted set, then walks the XFF chain right-to-left skipping
    trusted hops to the first non-trusted address = the real client. Fail-
    safe: with no trusted proxies configured, XFF is ignored and the peer IP
    is used (so a misconfigured deploy self-DoSes rather than becoming
    spoofable)."""
    raw = os.environ.get("LM_TRUSTED_PROXIES", "").strip()
    nets = []
    if raw:
        for tok in re.split(r"[,\s]+", raw):
            tok = tok.strip()
            if not tok:
                continue
            try:
                nets.append(ipaddress.ip_network(tok, strict=False))
            except ValueError:
                logger.warning("LM_TRUSTED_PROXIES: skipping unparseable entry %r", tok)
    return tuple(nets), raw


_TRUSTED_PROXY_NETS, _TRUSTED_PROXIES_RAW = _load_trusted_proxies()


def _ip_in_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in _TRUSTED_PROXY_NETS)


def _client_ip(request: Request) -> str:
    """Best-effort real client IP for security decisions (login throttling).

    When the immediate TCP peer (``request.client.host``) is a configured
    trusted proxy (``LM_TRUSTED_PROXIES``), parse ``X-Forwarded-For`` and
    return the rightmost address that is NOT itself a trusted proxy — the
    real client. When the peer is NOT a trusted proxy, return the peer IP
    directly and IGNORE XFF (an untrusted peer's XFF is spoofable). When
    there's no trusted-proxy config at all, return the peer (fail-safe: a
    misconfigured Azure deploy self-DoSes the per-IP limiter rather than
    trusting spoofable XFF)."""
    peer = (request.client.host if request.client else "") or "unknown"
    if not _TRUSTED_PROXY_NETS:
        return peer
    if not _ip_in_trusted(peer):
        return peer
    xff = request.headers.get("x-forwarded-for", "")
    if not xff:
        return peer
    chain = [h.strip() for h in xff.split(",") if h.strip()]
    # Walk right-to-left, skipping trusted-proxy hops; the first non-trusted
    # address is the real client. If every hop is trusted (odd config), fall
    # back to the leftmost (the origin the first proxy saw).
    for hop in reversed(chain):
        if not _ip_in_trusted(hop):
            return hop
    return chain[0] if chain else peer


def _sessions_file(hub) -> str:
    """Path to the persisted session store under the hub data dir."""
    return os.path.join(hub.state.data_dir, "sessions.json")


def _cookie_secure() -> bool:
    """Whether the ``lm_session`` cookie should carry the ``Secure`` flag.

    Explicit ``LM_COOKIE_SECURE`` env wins (1/true → on, 0/false → off — the
    off switch for loopback-http dev). Without it, auto: Secure when a hub TLS
    cert is configured (``LM_TLS_CERT``), off when serving plaintext. Behind a
    TLS-terminating Azure front end that doesn't forward ``X-Forwarded-Proto``,
    set ``LM_COOKIE_SECURE=1`` explicitly so the cookie isn't replayed over any
    http hop."""
    v = os.environ.get("LM_COOKIE_SECURE", "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return bool(os.environ.get("LM_TLS_CERT", "").strip())


def _record_session(hub, user_data: dict) -> str:
    """Mint a session token, enforce the per-user cap (evict oldest), persist.

    Centralizes session creation so every login path gets the same token entropy,
    ``sid`` (non-secret admin-revocation id), idle/created timestamps, and
    per-user cap enforcement. Returns the new opaque token (set as the cookie)."""
    import math as _math
    token = secrets.token_urlsafe(32)
    sid = secrets.token_hex(8)
    now = time.time()
    user_id = user_data.get("user_id")
    # Per-user cap: evict the oldest live sessions for this user beyond the cap
    # so one account can't accumulate unbounded tokens (session-fixation-style
    # amplification). ``created`` (falling back to ``expires`` for old entries)
    # is the eviction order.
    if user_id and _MAX_SESSIONS_PER_USER > 0:
        owned = [(t, s) for t, s in _sessions.items()
                 if s.get("user_id") == user_id and s.get("expires", 0) > now]
        owned.sort(key=lambda ts: ts[1].get("created", ts[1].get("expires", now)))
        while len(owned) >= _MAX_SESSIONS_PER_USER:
            old_t, _ = owned.pop(0)
            _sessions.pop(old_t, None)
    _sessions[token] = {
        "user_id":  user_id,
        "expires":  now + _SESSION_TTL,
        "created":  now,
        "last_seen": now,
        "sid":      sid,
        "user":     user_data,
    }
    _save_sessions(hub)
    return token


def _invalidate_user_sessions(hub, user_id) -> int:
    """Drop every live session for ``user_id`` and persist the revocation.

    Called on privilege/password/tenant/group change and on user deletion so a
    demoted admin's existing cookie stops granting admin (the stale-session
    window the access-control middleware would otherwise keep honoring until
    ``/auth/me`` or the 8h TTL). Returns the count dropped."""
    if not user_id:
        return 0
    drop = [t for t, s in _sessions.items() if s.get("user_id") == user_id]
    for t in drop:
        _sessions.pop(t, None)
    if drop:
        _save_sessions(hub)
        logger.info("Invalidated %d session(s) for user %s", len(drop), user_id)
    # Also drop the user's API tokens (bearer + refresh) so a demoted/deleted
    # user's tokens stop working too — mirrors the session invalidation.
    try:
        api_tokens.invalidate_user(hub, user_id)
    except Exception:  # noqa: BLE001
        pass
    return len(drop)


def _active_user_count(window_s: int = 300) -> int:
    """Distinct users with a live (non-expired), recently-seen session — i.e.
    someone actively using the WebUI right now (the WebUI polls /status every
    ~10s, refreshing last_seen). Used to defer a disruptive restart/update to a
    quiet window (see the watchdog idle-guard). Recency-based so a walked-away
    session ages out of the count on its own."""
    now = time.time()
    users = set()
    for s in _sessions.values():
        try:
            if float(s.get("expires", 0)) > now and (now - float(s.get("last_seen", 0))) <= window_s:
                users.add(s.get("user_id"))
        except (TypeError, ValueError):
            continue
    return len(users)


def write_active_users_file(hub) -> None:
    """Write the current active-user count to a file the ROOT lm-watchdog reads
    before a (non-force) restart, so it can hold off while users are logged in.
    Best-effort; never raises. Path mirrors update_pipeline's sentinel dir."""
    try:
        path = os.environ.get("LM_ACTIVE_USERS_FILE",
                              "/var/lib/lm/state/active-users")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{_active_user_count()}\n")
    except Exception as e:  # noqa: BLE001 — best-effort signalling
        logger.debug("active-users file write failed: %s", e)


def _login_attempts_file(hub) -> str:
    return os.path.join(hub.state.data_dir, "login_attempts.json")


def _save_login_attempts(hub) -> None:
    """Persist the per-username lockout counters (not the in-memory IP window)."""
    try:
        path = _login_attempts_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(_login_attempts, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("login_attempts persist failed: %s", exc)


def _load_login_attempts(hub) -> None:
    """Rehydrate persisted per-username lockout counters on startup."""
    try:
        path = _login_attempts_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            _login_attempts.update(data)
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:  # noqa: BLE001
        logger.warning("login_attempts load failed: %s", exc)


def _lockout_key(user_id: str) -> str:
    """Case-folded lockout key for a username. Pass this (not the raw username)
    to ``_login_check`` / ``_login_fail`` / ``_login_success`` so case-variant
    brute force ("admin", "Admin", "ADMIN", …) shares ONE counter and trips the
    throttle after N total tries instead of N tries × (case permutations).
    The raw username is still used for the case-sensitive user-store lookup."""
    return (user_id or "").casefold()


def _login_check(user_id: str, ip: str):
    """Return ``(allowed, retry_after_seconds)`` for a login attempt.

    Blocks (with a Retry-After) when the username is in lockout OR the source IP
    has exceeded the spray window. ``retry_after_seconds`` is 0 when allowed."""
    import math as _math
    now = time.time()
    # Per-IP spray window (credential stuffing across many usernames).
    ip_hits = [ts for ts in _login_ip_attempts.get(ip, [])
               if ts > now - _LOGIN_IP_WINDOW_S]
    if ip_hits:
        _login_ip_attempts[ip] = ip_hits
    else:
        # Drop an empty bucket so the dict doesn't retain a key per spoofed IP.
        _login_ip_attempts.pop(ip, None)
    if len(ip_hits) >= _LOGIN_IP_MAX:
        return False, max(1, int(_math.ceil((ip_hits[0] + _LOGIN_IP_WINDOW_S) - now)))
    # Bound the number of tracked IPs (memory hygiene under XFF rotation).
    if len(_login_ip_attempts) > _LOGIN_IP_TRACKED_MAX:
        _prune_ip_buckets(_LOGIN_IP_TRACKED_MAX)
    # Per-username lockout.
    rec = _login_attempts.get(user_id)
    if rec and rec.get("locked_until", 0) > now:
        return False, max(1, int(_math.ceil(rec["locked_until"] - now)))
    return True, 0


def _prune_ip_buckets(max_keep: int) -> None:
    """Evict the oldest per-IP spray buckets past ``max_keep`` (by the newest
    timestamp in each bucket) so ``_login_ip_attempts`` can't grow unbounded
    under a spoofed-XFF rotation or a large fleet behind one proxy."""
    if len(_login_ip_attempts) <= max_keep:
        return
    scored = [(max(b) if b else 0, ip) for ip, b in _login_ip_attempts.items()]
    scored.sort(reverse=True)
    for _ts, ip in scored[max_keep:]:
        _login_ip_attempts.pop(ip, None)


def _login_fail(hub, user_id: str, ip: str) -> int:
    """Record a failed attempt; engage/extend exponential lockout when over the
    threshold. Returns the remaining lockout seconds (0 if not yet locked)."""
    import math as _math
    now = time.time()
    # IP spray accounting.
    _login_ip_attempts.setdefault(ip, []).append(now)
    # Keep the per-IP list bounded (don't grow without limit between prunes).
    _login_ip_attempts[ip] = _login_ip_attempts[ip][-(_LOGIN_IP_MAX * 4):]
    # Username lockout with exponential backoff, capped.
    rec = _login_attempts.get(user_id, {"count": 0, "locked_until": 0,
                                        "first_fail": now})
    rec["count"] = int(rec.get("count", 0)) + 1
    if rec["count"] >= _LOGIN_MAX_FAILS:
        growth = min(_LOGIN_BASE_LOCKOUT_S *
                     (2 ** (rec["count"] - _LOGIN_MAX_FAILS)), _LOGIN_MAX_LOCKOUT_S)
        rec["locked_until"] = now + growth
    _login_attempts[user_id] = rec
    _save_login_attempts(hub)
    return max(0, int(_math.ceil(rec.get("locked_until", 0) - now)))


def _login_success(hub, user_id: str, ip: str = None) -> None:
    """Clear a username's lockout counters (and its per-IP spray bucket) on a
    successful login — persisted (the username record) so a restart doesn't
    re-lock an account that just succeeded. The IP bucket is in-memory only."""
    changed = False
    if user_id in _login_attempts:
        _login_attempts.pop(user_id, None)
        changed = True
    if ip and ip in _login_ip_attempts:
        _login_ip_attempts.pop(ip, None)
    if changed:
        _save_login_attempts(hub)


def _save_sessions(hub) -> None:
    """Atomically persist the live session store to disk (best-effort, never raises).

    Writes the core fields {user_id, expires, created, last_seen, sid, user} per
    token, dropping the runtime caches (prefixes/prefixes_at) that
    ``_resolve_prefixes`` adds — they re-populate on demand with their own TTL.
    Expired tokens are pruned from the written copy so the file doesn't grow
    with stale entries. Surviving a hub restart is what keeps a triggered update
    from logging everyone out: the ``lm_session`` cookie is already persistent
    for 8h, and rehydrating the same token→session mapping on startup lets
    ``/auth/me`` recognise it. A write failure logs a warning and degrades to
    today's in-memory-only behavior."""
    try:
        now = time.time()
        pruned: dict = {}
        for token, sess in _sessions.items():
            if not isinstance(sess, dict) or sess.get("expires", 0) < now:
                continue
            pruned[token] = {
                "user_id":  sess.get("user_id"),
                "expires":  sess.get("expires"),
                "created":  sess.get("created", sess.get("expires", now) - _SESSION_TTL),
                "last_seen": sess.get("last_seen", sess.get("created", now)),
                "sid":      sess.get("sid") or secrets.token_hex(8),
                "user":     sess.get("user", {}),
            }
        path = _sessions_file(hub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(pruned, f)
        os.chmod(tmp, 0o600)  # holds user identities + expiry, not passwords
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        logger.warning("session persist failed: %s", exc)


def _load_sessions(hub) -> None:
    """Rehydrate the in-memory session store from disk on startup (best-effort).

    Drops any entry whose expiry has already passed. Missing/corrupt file →
    leaves ``_sessions`` empty (today's cold-start behavior). Old entries
    persisted before ``sid``/``last_seen``/``created`` existed get them generated
    (sid) / defaulted (last_seen=created=now) so the idle timeout and admin
    revocation work for rehydrated sessions too."""
    try:
        path = _sessions_file(hub)
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        now = time.time()
        for token, sess in data.items():
            if not isinstance(token, str) or not isinstance(sess, dict):
                continue
            if sess.get("expires", 0) < now:
                continue
            _sessions[token] = {
                "user_id":  sess.get("user_id"),
                "expires":  sess.get("expires"),
                "created":  sess.get("created", now),
                "last_seen": now,  # idle window resets on restart (absolute 8h still caps)
                "sid":      sess.get("sid") or secrets.token_hex(8),
                "user":     sess.get("user", {}),
            }
        if _sessions:
            logger.info("Restored %d active session(s) from disk", len(_sessions))
    except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.warning("session load failed (%s): %s — starting empty",
                       getattr(hub.state, "data_dir", "?"), exc)

# ---------------------------------------------------------------------------
# Tenant data cache
# ---------------------------------------------------------------------------
_tenant_cache: dict = {}   # {tenant_id: {module_key: {data, fetched_at}}}
_cache_tasks: dict = {}    # {tenant_id: asyncio.Task}
_cache_status: dict = {}   # {tenant_id: {module_key: "loading"|"ready"|"error"}}
_cache_semaphore = None    # asyncio.Semaphore — gates concurrent tenant preloads

_DEFAULT_CACHE_CONFIG = {
    "rules":           {"enabled": True, "interval": 300, "label": "Firewall Rules"},
    "nat":             {"enabled": True, "interval": 300, "label": "NAT Policies"},
    "dhcp":            {"enabled": True, "interval": 300, "label": "DHCP Leases"},
    "dns":             {"enabled": True, "interval": 300, "label": "DNS Records"},
    "interfaces":      {"enabled": True, "interval": 300, "label": "Interfaces"},
    "cppm_sessions":   {"enabled": True, "interval": 300, "label": "Access Tracker"},
    "cppm_devices":    {"enabled": True, "interval": 300, "label": "Device Database"},
    "netbox_racks":    {"enabled": True, "interval": 300, "label": "Racks"},
    "netbox_devices":  {"enabled": True, "interval": 300, "label": "Devices"},
    "netbox_ips":      {"enabled": True, "interval": 300, "label": "IP Addresses"},
    "netbox_prefixes": {"enabled": True, "interval": 300, "label": "Prefixes"},
    "pxmx_vms":        {"enabled": True, "interval": 300, "label": "Virtual Machines"},
}
_FW_MODULES = {"rules", "nat", "dhcp", "dns", "interfaces"}
_FW_CMD_MAP = {
    "rules":      "OPNSENSE_GET_ALL_RULES",
    "nat":        "OPNSENSE_GET_NAT_POLICIES",
    "dhcp":       "OPNSENSE_GET_DHCP_LEASES",
    "dns":        "OPNSENSE_GET_DNS_RECORDS",
    "interfaces": "GET_INTERFACE_STATUS",
}
# Per-endpoint hub→spoke timeout (seconds) for live firewall fetches. Generous
# because spokes are distributed and may be reached over WAN (~300ms latency):
# the opnsense spoke answers each API call via a curl subprocess with
# --max-time 15, and NAT policies probe 3 endpoints sequentially (up to ~45s
# cold). The 5s request_response default timed out cold-cache NAT and returned
# an empty error dict — "NAT Policies showing nothing" (admin too, since
# filter_fw is a no-op for admins). NAT gets 60s; single-endpoint modules get
# 30s (15s curl + network slack).
_FW_FETCH_TIMEOUTS = {
    "nat": 60.0,
}
_FW_FETCH_TIMEOUT_DEFAULT = 30.0
# Firewall CRUD (add/edit/delete rule/alias/nat/dns) does an action call + an
# apply/reconfigure call sequentially (2× curl --max-time 15 → up to ~30s) →
# 45s covers it with WAN slack. The 5s default was timing out writes too.
_FW_WRITE_TIMEOUT = 45.0

# ── Tenant subnet filtering ────────────────────────────────────────────────
# Constants (_FILTER_MODULES / _DEFAULTS), _FW_FILTER_SPEC, and
# _filter_config live in access.py now; re-exported above for the routes
# that read/toggle them (Setup → Simulations). See access.py for the logic.


def _get_cache_config(hub) -> dict:
    stored = hub.state.system_state.get("cache_config", {})
    result = {}
    for key, defaults in _DEFAULT_CACHE_CONFIG.items():
        result[key] = {**defaults, **{k: v for k, v in stored.get(key, {}).items() if k in ("enabled", "interval")}}
    return result

def _get_max_concurrent(hub) -> int:
    return int(hub.state.system_state.get("cache_config", {}).get("max_concurrent_tenants", 3))

def _cache_entry(tenant_id: str, key: str):
    return _tenant_cache.get(tenant_id, {}).get(key)

def _set_cache_entry(tenant_id: str, key: str, data):
    _tenant_cache.setdefault(tenant_id, {})[key] = {"data": data, "fetched_at": time.time()}
    _set_cache_status(tenant_id, key, "ready")

def _set_cache_status(tenant_id: str, key: str, status: str):
    _cache_status.setdefault(tenant_id, {})[key] = status

def _invalidate_tenant_module(tenant_id: str, key: str):
    _tenant_cache.get(tenant_id, {}).pop(key, None)

def _invalidate_module_all_tenants(key: str):
    for t in list(_tenant_cache):
        _tenant_cache[t].pop(key, None)

def _refresh_module_all_tenants(hub, key: str):
    """Drop every tenant's cached entry for ``key`` and re-fetch in the background.

    The common post-write pattern: a spoke mutation invalidates the cached module
    data for all tenants, then kicks a background re-fetch per tenant so the next
    read sees fresh data. Previously this two-step was copy-pasted across the
    NetBox / CPPM / DNS / DHCP write handlers; route it through here instead:
    ``_refresh_module_all_tenants(hub, "netbox_devices")`` replaces
    ``_invalidate_module_all_tenants("netbox_devices")`` + the
    ``for tid in list(_tenant_cache): asyncio.create_task(_fetch_module(hub, tid, "netbox_devices"))``
    loop. (Some call sites intentionally invalidate multiple keys at once — those
    keep calling ``_invalidate_module_all_tenants`` directly.)"""
    _invalidate_module_all_tenants(key)
    for tid in list(_tenant_cache):
        asyncio.create_task(_fetch_module(hub, tid, key))

def _normalize_cached(result):
    if not isinstance(result, dict):
        return result
    if "payload" in result and isinstance(result["payload"], dict):
        return result["payload"].get("data", result)
    if "data" in result:
        return result["data"]
    return result

# _unwrap_spoke now lives in access.py (re-exported above). The previous
# in-tree body was infinite recursion (``return _unwrap_spoke(result)``) — the
# 7bc70c6 doc-pass regression — so all ~26 spoke-data unwrap call sites now
# resolve to the correct access.unwrap_spoke via the module-level alias.

def _hub_msg(spoke_id: str, msg_type: str, data) -> Message:
    """Build a hub-originated Message to a spoke.

    The standard hub→spoke construction: a fresh uuid message_id, current
    timestamp, sender_id ``"hub"``, destination_id ``spoke_id``, and a
    ``MessagePayload(type=msg_type, data=data)``. Replaces the ~11 inline
    ``Message(header=MessageHeader(...), payload=MessagePayload(...))`` blocks
    in the config-push / approval / hostname handlers. No extra header fields
    (correlation_id/priority/ttl) are set by any current call site; extend this
    factory with optional kwargs if a future one needs them."""
    return Message(
        header=MessageHeader(
            message_id=str(uuid.uuid4()),
            timestamp=time.time(),
            sender_id="hub",
            destination_id=spoke_id,
        ),
        payload=MessagePayload(type=msg_type, data=data),
    )

def _nb_slug(hub, tenant_id: str):
    try:
        return (hub.state.get_tenant(tenant_id) or {}).get("netbox_tenant_slug") or None
    except Exception:
        return None

async def _fetch_module(hub, tenant_id: str, module_key: str, fw_id: str = None) -> bool:
    """Fetch one module from its spoke and store in tenant cache."""
    cache_key = f"{module_key}:{fw_id}" if fw_id else module_key
    _set_cache_status(tenant_id, cache_key, "loading")
    try:
        result = None
        if module_key in _FW_MODULES and fw_id:
            firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
            fw = next((f for f in firewalls if f["id"] == fw_id), None)
            if not fw:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            spoke_id = fw.get("spoke_id")
            if not spoke_id or spoke_id not in hub.active_connections:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke_id, _FW_CMD_MAP[module_key], {})
        elif module_key == "cppm_sessions":
            spoke = hub.get_spoke_by_type("nac")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            # Skip the query while the spoke is connected-but-unconfigured — the
            # spoke would just return "CPPM host not configured" every cycle.
            # push_config_to_spoke sets this flag once (one WARN) when no host is
            # bound; clears it the moment a usable instance is pushed.
            if spoke in hub._nac_unconfigured_spokes:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke, "CPPM_GET_ACCESS_TRACKER", {})
        elif module_key == "cppm_devices":
            spoke = hub.get_spoke_by_type("nac")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            if spoke in hub._nac_unconfigured_spokes:
                _set_cache_status(tenant_id, cache_key, "error"); return False
            result = await hub.request_response(spoke, "LIST_ENDPOINTS", {})
        elif module_key in ("netbox_racks", "netbox_devices", "netbox_ips", "netbox_prefixes"):
            spoke = hub.get_spoke_by_type("ipam")
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            slug = _nb_slug(hub, tenant_id)
            cmd = {
                "netbox_racks":    "NETBOX_GET_RACKS",
                "netbox_devices":  "NETBOX_GET_DEVICES",
                "netbox_ips":      "NETBOX_GET_IPS",
                "netbox_prefixes": "NETBOX_GET_PREFIXES",
            }[module_key]
            # 30s, not the 5.0s default: the netbox paginated GETs
            # (NETBOX_GET_IPS/PREFIXES/DEVICES/RACKS) routinely exceed 5s on a
            # real fleet and the bare default produced recurring
            # "Request Timeout from lm-svcs-netbox after 5.0s" on cache refresh.
            # Matches dns_dhcp_sync / endpoint_sync / vm_sync's 30s budget.
            result = await hub.request_response(spoke, cmd, {"tenant": slug} if slug else {}, timeout=30.0)
        elif module_key == "pxmx_vms":
            spoke = hub.get_hypervisor_spoke()
            if not spoke: _set_cache_status(tenant_id, cache_key, "error"); return False
            cfg = hub.state.get_tenant(tenant_id) or {}
            payload = {"tag_filter": cfg["proxmox_tag"]} if cfg.get("proxmox_tag") else {}
            result = await hub.request_response(spoke, "PXMX_LIST_VMS", payload)

        if result is not None:
            _set_cache_entry(tenant_id, cache_key, _normalize_cached(result))
            return True
        _set_cache_status(tenant_id, cache_key, "error")
        return False
    except Exception as e:
        logger.warning(f"Cache fetch [{tenant_id}][{cache_key}]: {e}")
        _set_cache_status(tenant_id, cache_key, "error")
        return False

async def _preload_all_parallel(hub, tenant_id: str):
    """Parallel-fetch all enabled modules for a tenant, gated by the concurrency semaphore."""
    global _cache_semaphore
    if _cache_semaphore is None:
        _cache_semaphore = asyncio.Semaphore(_get_max_concurrent(hub))
    async with _cache_semaphore:
        config = _get_cache_config(hub)
        firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
        tasks = []
        for module_key, cfg in config.items():
            if not cfg.get("enabled", True):
                continue
            if module_key in _FW_MODULES:
                for fw in firewalls:
                    tasks.append(_fetch_module(hub, tenant_id, module_key, fw_id=fw["id"]))
            else:
                tasks.append(_fetch_module(hub, tenant_id, module_key))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

async def _cache_refresh_loop(hub, tenant_id: str):
    """Background task: initial parallel preload then periodic refresh per module interval."""
    try:
        # Brief delay so the dashboard's own data requests aren't blocked by the
        # initial burst of cache-preload spoke calls.
        await asyncio.sleep(3)
        await _preload_all_parallel(hub, tenant_id)
        while True:
            await asyncio.sleep(30)
            config = _get_cache_config(hub)
            firewalls = hub.state.system_state.get("global_config", {}).get("firewalls", [])
            tasks = []
            for module_key, cfg in config.items():
                if not cfg.get("enabled", True):
                    continue
                interval = cfg.get("interval", 300)
                if module_key in _FW_MODULES:
                    for fw in firewalls:
                        ck = f"{module_key}:{fw['id']}"
                        cached = _cache_entry(tenant_id, ck)
                        if not cached or time.time() - cached["fetched_at"] > interval:
                            tasks.append(_fetch_module(hub, tenant_id, module_key, fw_id=fw["id"]))
                else:
                    cached = _cache_entry(tenant_id, module_key)
                    if not cached or time.time() - cached["fetched_at"] > interval:
                        tasks.append(_fetch_module(hub, tenant_id, module_key))
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.warning(f"Cache refresh loop [{tenant_id}] died: {e}")

def _start_cache_for_tenant(hub, tenant_id: str):
    if not tenant_id or tenant_id == "default":
        return
    existing = _cache_tasks.get(tenant_id)
    if existing and not existing.done():
        return  # already running — second user of same tenant shares the cache
    _cache_tasks[tenant_id] = asyncio.create_task(_cache_refresh_loop(hub, tenant_id))
    logger.info(f"[Cache] task started for tenant '{tenant_id}'")

def _stop_cache_for_tenant(tenant_id: str):
    """Drop cache and cancel task only when no active sessions remain for this tenant."""
    if not tenant_id:
        return
    active = sum(
        1 for s in _sessions.values()
        if s.get("user", {}).get("tenant_id") == tenant_id
        and s.get("expires", 0) > time.time()
    )
    if active > 0:
        return
    _tenant_cache.pop(tenant_id, None)
    _cache_status.pop(tenant_id, None)
    task = _cache_tasks.pop(tenant_id, None)
    if task:
        task.cancel()
    logger.info(f"[Cache] cleared for tenant '{tenant_id}' — no active sessions")


def _spoke_payload_or_raise(data):
    """Translate a spoke relay result into the API error contract.

    Spokes return ``{status: "SUCCESS", ...}`` or ``{status: "ERROR",
    message|error}``. The hub relay passes the SUCCESS body through unchanged
    (so existing field access on the caller side is untouched) but a spoke-side
    ERROR is translated to HTTP 502 (Bad Gateway) carrying the spoke's message
    as ``detail`` — the contract every other relay group already follows. A
    non-dict result (raw list / scalar) is returned as-is. Pure → unit-testable;
    the in-``create_app`` ``_relay_spoke`` closure calls this after unwrapping.
    """
    if isinstance(data, dict) and data.get("status") == "ERROR":
        msg = data.get("message") or data.get("error") or "Spoke returned an error"
        raise HTTPException(status_code=502, detail=msg)
    return data


def _unwrap_netbox(result):
    """NetBox relay unwrap that ALSO surfaces a spoke-side status:"ERROR" as
    HTTP 502 instead of returning the error body as HTTP 200. Combines
    _unwrap_spoke + _spoke_payload_or_raise so NetBox routes follow the same
    error contract as every other relay group; each route's added
    `except HTTPException: raise` lets the 502 propagate (not become 500)."""
    return _spoke_payload_or_raise(_unwrap_spoke(result))


from types import SimpleNamespace  # ctx bundle for route modules


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return f"{salt}${dk.hex()}"

def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, dk_hex = stored.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def get_netbox_spoke(hub):
    return access.get_netbox_spoke(hub)

def get_tenant_scoping(hub, tenant_id: str = None) -> dict:
    return access.get_tenant_scoping(hub, tenant_id)


def create_app(hub):
    """Build the FastAPI app for the Hub.

    Mounts CORS, attaches the ``hub`` instance to ``app.state``, rehydrates the
    persisted login sessions from disk (``_load_sessions``), runs the
    anti-lockout admin migration, registers the access-control middleware, the
    Simulations (cs) routes, and all Hub WebUI/integration endpoints. Returns
    the configured app; host it with ``run_api_server``.
    """
    app = FastAPI(title="Lab Manager Hub API")

    # CORS. The WebUI is served from the SAME origin (unified :443 uvicorn), so a
    # credentialed cross-origin policy is NOT needed by default. Default (env
    # unset) = no credentialed cross-origin: empty origin list + credentials OFF.
    # ``LM_CORS_ORIGINS`` (comma-separated) opts IN to specific trusted origins with
    # credentials. ``["*"]`` + ``allow_credentials=True`` is spec-invalid (browsers
    # reject it) and would reflect arbitrary Origin headers — never set both.
    _cors_env = os.environ.get("LM_CORS_ORIGINS", "").strip()
    if _cors_env and _cors_env != "*":
        _cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
        # A wildcard origin with credentials is spec-invalid (browsers reject it)
        # and, if a framework fell back to reflecting Origin, would let any site
        # make credentialed requests. Reject "*" explicitly: log + fall back to the
        # no-credentialed default rather than honour it.
        if "*" in _cors_origins:
            logger.warning(
                "LM_CORS_ORIGINS contains '*' — wildcard with credentials is "
                "spec-invalid and unsafe; ignoring and falling back to the "
                "no-credentialed default. List explicit origins instead.")
            _cors_origins = []
        if _cors_origins:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=_cors_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        else:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=[],
                allow_credentials=False,
                allow_methods=["*"],
                allow_headers=["*"],
            )
    else:
        # No cross-origin opt-in: still allow same-origin (no-op) and non-credentialed
        # simple requests, but credentials are OFF and no Origin is reflected.
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[],
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Attach hub instance to app state for access in routes
    app.state.hub = hub

    # Rehydrate login sessions from disk so a user who was logged in before a
    # triggered update/restart stays logged in (the lm_session cookie already
    # persists for 8h; this restores the server-side token→session mapping).
    _load_sessions(hub)
    api_tokens.load(hub)
    _load_login_attempts(hub)

    # Anti-lockout migration: runs on every startup. Ensures the first user is
    # a fully-privileged, protected, tenant-free admin and reconciles the two
    # admin-flag forms (role + boolean) across all admin users so the WebUI
    # "System Admin" checkbox renders correctly and an edit cannot silently
    # demote an admin by dropping one of the two forms.
    if hub.state.ensure_admin_lockout():
        hub.state.save_state()

    @app.middleware("http")
    async def access_control_middleware(request, call_next):
        """Per-request access control.

        Static UI files are always public. Every ``/api/*`` (and ``/sim/api/*``)
        namespace requires a valid ``lm_session`` cookie via ``_session_user``;
        admin-scoped namespaces additionally require an admin session. Short-
        circuits to a 401/403 JSON response when the gate fails, otherwise calls
        the next handler.
        """
        path = request.url.path

        # Only API namespaces require authentication — static UI files are always public.
        # /vm/ and /cppm/ were previously OUTSIDE this list → reachable with no
        # session (e.g. GET /vm/{id}/details leaked a VM's firewall/DHCP/NAC data
        # cross-tenant to anyone). They now require an authenticated session.
        _GATED_PREFIXES = ("/api/", "/setup/", "/admin/", "/auth/", "/sim/api/", "/vm/", "/cppm/", "/tenant/")
        if not any(path.startswith(p) for p in _GATED_PREFIXES) or path == "/status":
            return await call_next(request)

        # Unauthenticated endpoints within gated namespaces
        # /auth/token (issue: does its own session-OR-password check) and
        # /auth/token/refresh (uses the refresh token itself) authenticate
        # internally, so the middleware lets them through. /auth/tokens (list)
        # and /auth/token/revoke stay session-gated (not listed here).
        _PUBLIC = {"/auth/login", "/auth/me", "/auth/setup", "/status",
                   "/auth/token", "/auth/token/refresh",
                   "/auth/oidc/login", "/auth/oidc/callback", "/auth/oidc/enabled",
                   "/sim/api/init", "/sim/api/health"}
        _PUBLIC_GET = {"/setup/appearance", "/setup/toast-config"}
        if path in _PUBLIC or (request.method == "GET" and path in _PUBLIC_GET):
            return await call_next(request)

        # Agent-facing template-repo endpoints — the owning node's agent has no
        # browser session, so these are gated by a per-op token INSIDE the route
        # (routes/templates.py), not by a session: the backup upload/progress
        # (upload token) and the refresh download/refresh-progress (refresh token).
        # Exact shape only: /api/templates/{id}/{upload,progress,download,refresh-progress}.
        # NOTE: "/refresh-progress" must be listed explicitly — it does NOT match
        # endswith("/progress") (it ends with "-progress"), so without this the
        # agent's refresh status/success reports get 401'd by this middleware and
        # the hub never learns the pull finished → the WebUI shows a generic fail
        # even when the restore actually succeeded.
        if path.startswith("/api/templates/") and (
                path.endswith("/upload") or path.endswith("/progress")
                or path.endswith("/download") or path.endswith("/refresh-progress")):
            return await call_next(request)

        sess = _session_user(request)
        if not sess:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

        # Touch the session's last_seen so the idle-timeout window (access.py)
        # resets on real activity. ``session_user`` already enforces the idle
        # cap on read, so a stale session is rejected before this runs; for a
        # live one we bump last_seen lazily (no per-request disk write — the
        # next _save_sessions, e.g. login/logout, persists it).
        if isinstance(sess, dict):
            sess["last_seen"] = time.time()

        # /setup/* and /admin/* are admin-only
        if path.startswith("/setup/") or path.startswith("/admin/"):
            if not _is_admin(sess):
                return JSONResponse(status_code=403, content={"detail": "Admin access required"})

        # /tenant/* is the tenant-admin device-management surface — a
        # session-scoped mirror of the admin-only /setup/* device CRUD. Reachable
        # by tenant-admins (and Global Admins); every other authenticated user is
        # rejected here. Per-record tenant ownership is enforced inside the
        # handlers (routes/tenant_devices.py), so there is no cross-tenant IDOR.
        if path.startswith("/tenant/"):
            if not (_is_admin(sess) or access.is_tenant_admin(sess)):
                return JSONResponse(status_code=403, content={"detail": "Tenant-admin access required"})

        # Privileged /api/* management namespaces are admin-only. Their per-route
        # siblings were already admin-gated; these were missed, so any authenticated
        # (incl. single-tenant, non-admin) user could reach them:
        #   /api/agent/*   — send-arbitrary-command, load-role (remote code on agents)
        #   /api/generic/* — provision (mints a spoke secret + hands over hub_secret)
        #   /api/ldap/*    — directory user/group/OU CRUD + reset ANY user's password
        #   /api/pxmx/agents/*/…  — revoke/rename/config/cs-command (agent mutations;
        #                            the bare GET /api/pxmx/agents list stays authed-read)
        #   /api/cppm/probe        — arbitrary path+method relay to the ClearPass API
        #                            (an authed SSRF-style relay); test-auth/refresh/health
        #                            are diagnostic spoke relays unused by the WebUI. The
        #                            real cppm *data* routes (devices/sessions/nac-status/…)
        #                            stay authed-read for tenant users.
        #   /api/help/ask     — the LLM help assistant's hub-side tools run with a
        #                        hub-wide (cross-tenant) view (search_devices hardcodes
        #                        tenant "default"; get_spokes_status returns the whole
        #                        fleet). Admin-only; /api/help/available stays authed-read.
        _ADMIN_API_PREFIXES = ("/api/agent/", "/api/generic/", "/api/pxmx/agents/",
                               "/api/cppm/probe", "/api/cppm/test-auth", "/cppm/refresh", "/cppm/health",
                               "/api/help/ask", "/api/exec")
        if any(path.startswith(p) for p in _ADMIN_API_PREFIXES):
            if not _is_admin(sess):
                return JSONResponse(status_code=403, content={"detail": "Admin access required"})

        # /sim/api/* (the Simulations module) requires the ``cs`` right OR admin.
        # The frontend hides the Simulations nav on the same right (canSeeModule);
        # this gates the API so a non-authorized user can't reach it directly.
        if path.startswith("/sim/api/"):
            if not (_is_admin(sess) or _has_cs_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Simulations module access required"})

        # /api/nw/* (Network Devices module) requires the ``nw`` right OR admin.
        # Mirrors the cs gate: frontend hides the Network nav on the same right.
        if path.startswith("/api/nw/"):
            if not (_is_admin(sess) or _has_nw_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Network Devices module access required"})

        # /api/netbox/* (IPAM module) requires the ``ipam`` right OR admin.
        # Mirrors the cs gate: frontend hides the IPAM nav on the same right.
        if path.startswith("/api/netbox/"):
            if not (_is_admin(sess) or _has_ipam_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "IPAM module access required"})

        # /api/le/* (Certificate Management module) requires the ``le`` right OR
        # admin. Mirrors the cs/nw/netbox gate; frontend hides the Certificates
        # nav on the same right.
        if path.startswith("/api/le/"):
            if not (_is_admin(sess) or _has_le_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Certificate module access required"})

        # /api/console/config/* (device config read/push) requires the higher
        # ``console_write`` right OR admin — checked BEFORE the general console gate.
        if path.startswith("/api/console/config"):
            if not (_is_admin(sess) or _has_console_write_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Console write access required"})
        # /api/console/* (Console module) requires the ``console`` right OR admin.
        # Mirrors the cs/nw/netbox/le gate; frontend hides the Console nav on the
        # same right. The /ws/console-serial relay is gated separately by ws_token.
        elif path.startswith("/api/console/"):
            if not (_is_admin(sess) or _has_console_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Console module access required"})

        # /api/firewall/* (Firewall module) requires the ``firewall`` right OR
        # admin. Mirrors the cs/nw/netbox gate; frontend hides the Firewall nav on
        # the same right. Per-firewall tenant ownership + the dedicated(full) vs
        # shared(filtered) read scope are enforced in routes/firewall.py.
        if path.startswith("/api/firewall/"):
            if not (_is_admin(sess) or _has_firewall_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Firewall module access required"})

        # /api/cppm/* + /cppm/* (Security/NAC module) require the ``nac`` right OR
        # admin. NAC is read-only (no mutation endpoints); its admin-only
        # diagnostic relays (probe/test-auth/refresh/health) are already returned
        # above by _ADMIN_API_PREFIXES, so this only gates the tenant data reads
        # (which stay subnet/tag-filtered per access.filter_session).
        if path.startswith("/api/cppm/") or path.startswith("/cppm/"):
            if not (_is_admin(sess) or _has_nac_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "NAC module access required"})

        # /api/dns/* (DNS module) requires the ``dns`` right OR admin. Writes stay
        # Global-Admin-only via _ADMIN_INFRA_WRITE_PREFIXES below (shared Unbound,
        # no per-record constrained-write model yet); GET reads are subnet-filtered.
        if path.startswith("/api/dns/"):
            if not (_is_admin(sess) or _has_dns_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "DNS module access required"})

        # /api/dhcp/* (DHCP module) requires the ``dhcp`` right OR admin. Writes
        # stay Global-Admin-only (shared Kea); GET reads are subnet-filtered.
        if path.startswith("/api/dhcp/"):
            if not (_is_admin(sess) or _has_dhcp_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "DHCP module access required"})

        # /api/pxmx/* + /vm/* (Hypervisor module) require the ``pxmx`` right OR
        # admin. VIEWING (VM lists + /vm/{id}/details) is tenant-filtered (tag +
        # subnet via access.filter_tenant), fail-closed on an unattributable VM.
        # VM CONTROL (vm-action lifecycle, create, clone, VNC console mint) is
        # gated IN-HANDLER by the write-user tier (access.has_edit_access) AND
        # per-VM ownership (access.vm_in_tenant_scope — toggle-independent,
        # fail-closed): admin any, else a write-user/tenant-admin may act only on a
        # VM in their tenant. node/pool/iso/storage enumeration is pxmx-right (feeds
        # the create UI). /api/pxmx/nodes (whole-cluster stats) + /api/pxmx/agents/*
        # stay Global-Admin-only.
        if path.startswith("/api/pxmx/") or path.startswith("/vm/"):
            if not (_is_admin(sess) or _has_pxmx_access(sess)):
                return JSONResponse(status_code=403,
                                    content={"detail": "Hypervisor module access required"})

        # /api/ldap/* (Directory module). The directory is a SHARED identity store
        # with no tenant partition, so WRITES (user/group/OU CRUD + password
        # reset) stay Global-Admin-only; READS require the ``ldap`` right OR admin
        # so a directory viewer can browse without mutate rights. Reopen writes to
        # tenant scope only once a directory-tenancy model (e.g. per-tenant OU)
        # exists. (Was entirely Global-Admin-only via _ADMIN_API_PREFIXES.)
        if path.startswith("/api/ldap/"):
            if request.method == "GET":
                if not (_is_admin(sess) or _has_ldap_access(sess)):
                    return JSONResponse(status_code=403,
                                        content={"detail": "Directory module access required"})
            # WRITES are tenant-admin tier (directory management), OU-scoped in the
            # handler (routes/ldap.py _assert_ldap_write binds a tenant-admin to
            # their own ldap_base_dn subtree; reads are filtered to it). Global
            # Admin is unconfined.
            elif not _can_edit_shared(sess):
                return JSONResponse(status_code=403,
                                    content={"detail": "Tenant-admin (or admin) required for directory changes"})

        # Shared-infrastructure WRITE paths (OPNsense firewall rules/aliases/NAT/
        # DNS, and the shared DNS/DHCP server records/reservations/syncs) mutate
        # security policy or shared infra. No module-right exists for
        # firewall/dns/dhcp (ENFORCED_RIGHTS has no fw/dns/dhcp key), so the
        # tier is the gate. Method-gated so a non-admin tenant user can still
        # VIEW their filtered firewall rules / DNS records (the GET paths apply
        # _filter_fw / subnet filtering and stay authed-read). Closes the "any
        # authenticated user can rewrite shared firewall/DNS/DHCP config" gap.
        #
        # Tier rules (Phase 3):
        #   * Global Admin  — may write for any tenant (the ?tenant= scoping
        #     below still confines a cross-tenant write to a real tenant).
        #   * tenant Admin  — may write ONLY for an explicit ?tenant= it owns.
        #     The write must target a concrete tenant (no ?tenant= is ambiguous
        #     and rejected); _check_tenant_access confirms ownership. The
        #     spoke-side push is already tenant-keyed.
        #   * anyone else   — blocked (shared infra is admin-tier work).
        # ── Write-tier gate (view / write-user / tenant-admin) ────────────────
        # Coarse method-gate; the per-object dedicated(full) vs shared(constrained)
        # vs deny decision lives in each handler via access.write_scope. GET reads
        # stay module-right-gated above.
        #
        # WRITE-TIER modules: the handler enforces per-object write_scope, so the
        # middleware only needs the write-user floor — has_edit_access (the global
        # ``edit`` right, or tenant-admin, or admin). A view user (module right but
        # no edit) is blocked here; a write user is let through and write_scope
        # then permits their OWN-tenant dedicated writes but denies shared; a
        # tenant-admin is let through and write_scope permits shared (constrained).
        # /api/netbox/* writes already enforce per-object tenant ownership in the
        # handlers (_verify_owns clamps to the caller's tenant slug + _enforce_
        # body_tenant), so the middleware only adds the write-user floor here: a
        # view user (ipam right, no edit) can read IPAM but not mutate it.
        _WRITE_TIER_PREFIXES = ("/api/firewall/", "/api/netbox/")
        # SHARED single-server CONSTRAINED writes: a tenant-admin may add/edit/
        # delete a DNS record / DHCP reservation, but the handler
        # (routes/net_services.py _constrain_shared_write) restricts it to a
        # record whose IP is in the caller's tenant subnets. Checked BEFORE the
        # admin-only prefix so record/reservation aren't swept up by /api/dns/ .
        _SHARED_CONSTRAINED_WRITE_PREFIXES = ("/api/dns/record", "/api/dhcp/reservation")
        # ADMIN-ONLY writes: these back a SINGLE shared server (one Unbound / one
        # Kea / one certbot) with no per-object constrained-write model yet, so the
        # `?tenant=` gate can prove the caller owns the query param but NOT that the
        # record/reservation/cert belongs to that tenant. Locked to Global Admin
        # until per-object subnet ownership is enforced on the bodies (dns/dhcp/le
        # phases). GET reads stay right-gated (method-gated here).
        # le + dns/dhcp SYNC (fleet-wide rebuild) have no per-object tenant model → admin-only.
        _ADMIN_INFRA_WRITE_PREFIXES = ("/api/le/", "/api/dns/", "/api/dhcp/")
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            if any(path.startswith(p) for p in _SHARED_CONSTRAINED_WRITE_PREFIXES):
                if not _can_edit_shared(sess):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Tenant-admin (or admin) required for shared DNS/DHCP writes"})
            elif any(path.startswith(p) for p in _ADMIN_INFRA_WRITE_PREFIXES):
                if not _is_admin(sess):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Admin access required for shared-infrastructure writes"})
            elif any(path.startswith(p) for p in _WRITE_TIER_PREFIXES):
                if not _has_edit_access(sess):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Edit access required (write-user, tenant-admin, or admin)"})

        # Tenant scoping: block requests for a ?tenant= the user isn't authorised for
        tenant = request.query_params.get("tenant")
        if tenant and not _check_tenant_access(sess, tenant):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Not authorized for tenant '{tenant}'"},
            )

        return await call_next(request)

    # ── Error logging (outermost middleware) ────────────────────────────────
    # Overload admission control: while the hub is in PROTECT MODE (memory
    # watermark, see run_mps_loop), shed the heavy read/polling endpoints with
    # 503 + Retry-After so the WebUI backs off instead of piling onto a saturated
    # loop. Auth/control/health paths pass through untouched. This is the "shed,
    # don't hang" guard — the ceiling stays survivable.
    # /status is deliberately NOT shed — it must stay readable in protect mode so
    # the operator + WebUI can SEE the state (it returns a lightweight body while
    # protecting; see get_system_metrics). Only the heavy fleet-shaping views shed.
    _SHED_PREFIXES = ("/setup/pending_spokes", "/setup/diagnostics",
                      "/sim", "/aggregate")

    @app.middleware("http")
    async def overload_admission_middleware(request, call_next):
        hub = getattr(app.state, "hub", None)
        if (hub is not None and getattr(hub, "_protect_mode", False)
                and request.method == "GET"
                and any(request.url.path.startswith(p) for p in _SHED_PREFIXES)):
            return JSONResponse(
                status_code=503,
                content={"detail": f"hub busy ({getattr(hub, '_protect_reason', 'overload')}) — backing off",
                         "protect": True},
                headers={"Retry-After": "30"})
        return await call_next(request)

    # Wraps every request so that *any* unhandled exception — including ones
    # raised inside access_control_middleware (e.g. session lookup) or during
    # response serialisation, which bypass the per-route try/except — is
    # logged with a full traceback to the hub log and returned as structured
    # JSON. This makes 500s diagnosable from the WebUI / browser console
    # instead of a bare "Internal Server Error" that requires CLI log-tailing.
    @app.middleware("http")
    async def error_logging_middleware(request, call_next):
        try:
            return await call_next(request)
        except Exception as exc:
            # Server-side: full traceback to the hub log (operator diagnostics).
            # Client-side: a GENERIC detail + a short reference id (also logged
            # with the trace) so the operator can correlate via the log without
            # an internet-exposed hub leaking internal paths / exception
            # fingerprints (str(exc), exc type, request path) to a caller.
            ref = secrets.token_hex(6)
            logger.exception(
                "Unhandled exception on %s %s [ref=%s]", request.method,
                request.url.path, ref
            )
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "ref": ref,
                },
            )

    # ── Security response headers (outermost: decorates last → wraps everything) ─
    # HSTS is emitted ONLY when cookies are served Secure (``_cookie_secure()``),
    # i.e. when the hub is reachable over TLS — emitting HSTS over plaintext
    # would pin an http-only client to a broken upgrade. Also stamps a couple of
    # baseline hardening headers that are harmless on both http and https.
    @app.middleware("http")
    async def security_headers_middleware(request, call_next):
        resp = await call_next(request)
        if _cookie_secure():
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp


    # ── Auth / tenant helper closures ────────────────────────────────────────
    # Thin shims over access.* — the real logic (session/auth, tenant scoping,
    # prefix resolution, subnet filtering) lives in the leaf module ``access``
    # (importable, testable, free of the nested-def annotation trap that caused
    # the .117→.121 startup regression). Kept as closures so the ~185 routes
    # keep calling the same bare names — _session_user(req), _is_admin(sess),
    # _filter_session(req, data, "nac", ["ip"]), … — with zero call-site churn.
    # They capture the live _sessions module global and the hub arg; everything
    # else flows from access. Shim signatures intentionally carry NO annotations
    # (trivial delegators) so no typing name can ever be evaluated at def-time;
    # the real type hints live in access.py under ``from __future__ import
    # annotations``. Defined late, as before, so routes above resolve them at
    # call time; register_simulations_routes below receives them as callables.
    def _session_user(request):
        # A Bearer API token (programmatic clients) takes precedence; otherwise
        # the WebUI cookie session. Both return the same session-shaped dict so
        # every access.* gate downstream is identical.
        bt = api_tokens.bearer_session(request)
        if bt is not None:
            return bt
        return access.session_user(_sessions, request)

    def _is_admin(sess):
        return access.is_admin(sess)

    def _is_tenant_admin(sess):
        return access.is_tenant_admin(sess)

    def _has_cs_access(sess):
        return access.has_cs_access(sess)

    def _has_nw_access(sess):
        return access.has_nw_access(sess)

    def _has_ipam_access(sess):
        return access.has_ipam_access(sess)

    def _has_le_access(sess):
        return access.has_le_access(sess)

    def _has_console_access(sess):
        return access.has_console_access(sess)

    def _has_console_write_access(sess):
        return access.has_console_write_access(sess)

    def _has_firewall_access(sess):
        return access.has_firewall_access(sess)

    def _has_dns_access(sess):
        return access.has_dns_access(sess)

    def _has_dhcp_access(sess):
        return access.has_dhcp_access(sess)

    def _has_nac_access(sess):
        return access.has_nac_access(sess)

    def _has_ldap_access(sess):
        return access.has_ldap_access(sess)

    def _has_pxmx_access(sess):
        return access.has_pxmx_access(sess)

    def _has_edit_access(sess):
        return access.has_edit_access(sess)

    def _can_edit_shared(sess):
        return access.can_edit_shared(sess)

    def _check_tenant_access(sess, tenant_id):
        return access.check_tenant_access(sess, tenant_id)

    def _resolve_tenant(request, explicit=None):
        return access.resolve_tenant(_sessions, request, explicit)

    async def _fetch_tenant_prefixes(hub, tenant_id):
        return await access.fetch_tenant_prefixes(hub, tenant_id)

    async def _resolve_prefixes(hub, sess):
        return await access.resolve_prefixes(hub, sess)

    def _effective_tenant(request, explicit=None):
        return access.effective_tenant(_sessions, request, explicit)

    def _effective_tenant_slug(request, explicit=None):
        return access.effective_tenant_slug(hub, _sessions, request, explicit)

    async def _resolve_prefixes_for_tenant(hub, tenant_id):
        return await access.resolve_prefixes_for_tenant(hub, tenant_id)

    def _filter_enabled(hub, module):
        return access.filter_enabled(hub, module)

    async def _filter_session(request, data, module, ip_fields):
        return await access.filter_session(hub, _sessions, request, data, module, ip_fields)

    async def _filter_fw(request, data, endpoint, firewall_id=None, explicit_tenant=None):
        return await access.filter_fw(hub, _sessions, request, data, endpoint, firewall_id, explicit_tenant)

    async def _filter_nw(request, data, endpoint, explicit_tenant=None):
        return await access.filter_nw(hub, _sessions, request, data, endpoint, explicit_tenant)

    async def _gate_record(request, record, module, ip_fields):
        return await access.gate_record(hub, _sessions, request, record, module, ip_fields)

    async def _filter_tenant(request, data, module, ip_fields, explicit_tenant=None):
        return await access.filter_tenant(hub, _sessions, request, data, module, ip_fields, explicit_tenant)

    async def _gate_record_tenant(request, record, module, ip_fields, explicit_tenant=None):
        return await access.gate_record_tenant(hub, _sessions, request, record, module, ip_fields, explicit_tenant)

    def _trigger_endpoint_sync_after_ipam_edit(hub, request: Request,
                                               data: Dict[str, Any] = None):
        """Best-effort: fire a tenant endpoint sync after an IPAM write.

        Resolves the target tenant from the request body's ``tenant`` (the
        per-tenant IPAM scope value → LM tenant id via
        hub.tenant_id_for_ipam_scope, which uses the configured source's scope
        field), falling back to the acting user's tenant. Never raises — a
        sync trigger must not break the IPAM mutation it follows.
        """
        try:
            tid = None
            scope = (data or {}).get("tenant") if isinstance(data, dict) else None
            if scope:
                tid = hub.tenant_id_for_ipam_scope(scope)
            if not tid:
                tid = _resolve_tenant(request, None)
            hub.trigger_endpoint_sync(tid)
        except Exception as e:
            logger.debug("endpoint-sync trigger after IPAM edit skipped: %s", e)

    def _trigger_vm_sync_after_pxmx_edit(hub, request: Request,
                                         data: Dict[str, Any] = None):
        """Best-effort: fire a tenant VM sync after a pxmx/hypervisor write.

        Resolves the target tenant from the acting user's session (a VM
        lifecycle action does not carry a per-tenant scope in its body, unlike
        an IPAM edit which carries ``tenant``). Never raises — a sync trigger
        must not break the VM mutation it follows. A superadmin with no tenant
        is a no-op (the scheduled loop covers unbound tenants).
        """
        try:
            tid = _resolve_tenant(request, None)
            hub.trigger_vm_sync(tid)
        except Exception as e:
            logger.debug("vm-sync trigger after pxmx edit skipped: %s", e)

    # ── Shared route context: bundle the create_app-scoped closures the
    # relocated route modules (routes/*.py) close over. Each module's
    # register(app, hub, ctx) unpacks the names it uses from ctx.
    ctx = SimpleNamespace(
        _session_user=_session_user,
        _is_admin=_is_admin,
        _is_tenant_admin=_is_tenant_admin,
        _has_cs_access=_has_cs_access,
        _has_nw_access=_has_nw_access,
        _has_ipam_access=_has_ipam_access,
        _has_le_access=_has_le_access,
        _has_console_access=_has_console_access,
        _has_console_write_access=_has_console_write_access,
        _check_tenant_access=_check_tenant_access,
        _resolve_tenant=_resolve_tenant,
        _fetch_tenant_prefixes=_fetch_tenant_prefixes,
        _resolve_prefixes=_resolve_prefixes,
        _effective_tenant=_effective_tenant,
        _effective_tenant_slug=_effective_tenant_slug,
        _resolve_prefixes_for_tenant=_resolve_prefixes_for_tenant,
        _filter_enabled=_filter_enabled,
        _filter_session=_filter_session,
        _filter_fw=_filter_fw,
        _filter_nw=_filter_nw,
        _gate_record=_gate_record,
        _filter_tenant=_filter_tenant,
        _gate_record_tenant=_gate_record_tenant,
        _trigger_endpoint_sync_after_ipam_edit=_trigger_endpoint_sync_after_ipam_edit,
        _trigger_vm_sync_after_pxmx_edit=_trigger_vm_sync_after_pxmx_edit,
    )

    # ── Simulations module (ported Client-Sim UI) ───────────────────────────
    # Registered after the auth helpers above so the /sim routes can reuse them.
    register_simulations_routes(app, app.state.hub, _session_user, _resolve_tenant,
                                _is_admin, _check_tenant_access, _sessions,
                                _has_cs_access, _is_tenant_admin)

    # ── Register relocated route groups (one module per coherent area) ──
    from routes import (
        setup, firewall, nw, cppm, pxmx, ws_transport, console, pxmx_vm, dashboard, setup_admin, ldap, netbox, tenants_users, auth, setup_misc, agents, net_services, admin_cache, help_assistant, exec as exec_routes, self_backup, tenant_devices, oidc, templates, azure_nsg, cloud_nac as cloud_nac_routes, key_vault as key_vault_routes,
    hub_watchdog as hub_watchdog_routes,
    )
    setup.register(app, hub, ctx)
    firewall.register(app, hub, ctx)
    nw.register(app, hub, ctx)
    tenant_devices.register(app, hub, ctx)
    cppm.register(app, hub, ctx)
    pxmx.register(app, hub, ctx)
    templates.register(app, hub, ctx)
    ws_transport.register(app, hub, ctx)
    console.register(app, hub, ctx)
    pxmx_vm.register(app, hub, ctx)
    dashboard.register(app, hub, ctx)
    setup_admin.register(app, hub, ctx)
    ldap.register(app, hub, ctx)
    netbox.register(app, hub, ctx)
    tenants_users.register(app, hub, ctx)
    auth.register(app, hub, ctx)
    oidc.register(app, hub, ctx)
    azure_nsg.register(app, hub, ctx)
    cloud_nac_routes.register(app, hub, ctx)
    key_vault_routes.register(app, hub, ctx)
    hub_watchdog_routes.register(app, hub, ctx)
    setup_misc.register(app, hub, ctx)
    agents.register(app, hub, ctx)
    net_services.register(app, hub, ctx)
    admin_cache.register(app, hub, ctx)
    help_assistant.register(app, hub, ctx)
    exec_routes.register(app, hub, ctx)
    self_backup.register(app, hub, ctx)

    # ── H1: scrub internal-exception detail from 5xx for non-Global callers ──
    # Routes raise ``HTTPException(500, detail=str(e))`` in their
    # except-Exception blocks (118+ sites). Without this handler a tenant_admin
    # or plain user sees the raw internal exception text — file paths, SQL /
    # NetBox / spoke error strings, stack fingerprints — an information-
    # disclosure vector (H1). A Global Admin (``is_admin``) retains the real
    # detail for ops debugging; everyone else gets a generic "Internal server
    # error" + a short ref id that is logged WITH the real detail so the
    # operator can correlate via the hub log. Unhandled (non-HTTPException)
    # exceptions are already generic via ``error_logging_middleware``; this
    # covers the RAISED-HTTPException path. Authored 4xx messages ("Missing
    # tenant_id", "Tenant admin cannot grant Global Admin", "Not authorized for
    # tenant '…'", …) pass through unchanged — only 5xx is scrubbed, so the
    # tenant-admin UX/validation feedback is preserved.
    from starlette.exceptions import HTTPException as _StarletteHTTPException

    @app.exception_handler(_StarletteHTTPException)
    async def scrub_internal_detail_handler(request: Request, exc):
        if exc.status_code >= 500:
            sess = None
            try:
                sess = _session_user(request)
            except Exception:
                sess = None
            if not _is_admin(sess):
                ref = secrets.token_hex(6)
                # Server-side: log the real detail + ref for operator correlation.
                # The ref is also returned to the (non-Global) caller so they can
                # quote it to the operator without seeing the detail itself.
                logger.warning(
                    "5xx detail scrubbed [ref=%s] %s %s -> %r",
                    ref, request.method, request.url.path, exc.detail,
                )
                return JSONResponse(
                    status_code=exc.status_code,
                    content={"detail": "Internal server error", "ref": ref},
                )
        # 4xx (authored validation messages) or a Global-admin 5xx: preserve
        # the detail + headers exactly as FastAPI's default handler would.
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None) or None,
        )

    # --- Static File Serving ---
    ui_path = os.path.join(os.path.dirname(__file__), "../../WebUI")

    if os.path.exists(ui_path):
        ui_real = os.path.realpath(ui_path)

        @app.get("/{full_path:path}")
        async def serve_ui(full_path: str):
            # SECURITY: the /{full_path:path} catch-all is PUBLIC (no session
            # gate), so a containment guard is mandatory. Without it a path
            # like 'static/../../../../etc/passwd' would let an UNAUTHENTICATED
            # caller read arbitrary files as the hub user (.env with the
            # Fernet key + secrets, sessions.json, state files). Reject '..'
            # segments outright and verify the realpath stays under ui_path
            # before serving. (Starlette decodes %2e%2e → '..' before the
            # :path converter, so encoded traversal is caught too.)
            if ".." in (full_path or "").split("/"):
                raise HTTPException(status_code=404, detail="Not found")
            file_path = os.path.join(ui_path, full_path)
            try:
                real = os.path.realpath(file_path)
            except OSError:
                raise HTTPException(status_code=404, detail="Not found")
            if real != ui_real and not real.startswith(ui_real + os.sep):
                raise HTTPException(status_code=404, detail="Not found")
            if os.path.isfile(real):
                response = FileResponse(real)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            index_html_path = os.path.join(ui_path, "index.html")
            if os.path.exists(index_html_path):
                response = FileResponse(index_html_path)
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                return response

            raise HTTPException(status_code=404, detail="UI index.html not found in WebUI folder")
    else:
        @app.get("/")
        async def root():
            return {"message": "Hub API is running. UI folder not found. Please check repository structure."}

    return app

def _uvicorn_log_config():
    """A uvicorn ``log_config`` dict that emits the canonical LM format
    ``%(asctime)s - %(name)s - %(levelname)s - %(message)s`` (dashes) — the same
    shape every spoke/agent uses via ``logging_setup.configure_logging``.

    Passing ``log_config=None`` makes uvicorn apply its DEFAULT_LOGGING
    dictConfig, which mounts uvicorn's own ``DefaultFormatter`` /
    ``AccessFormatter`` (``%(levelprefix)s %(message)s`` — no ``-`` separators,
    no consistent asctime/name/level columns) on the ``uvicorn`` /
    ``uvicorn.error`` / ``uvicorn.access`` loggers with ``propagate: False``.
    The hub's own lines then render as ``<ts> <name> <level> <msg>`` (spaces),
    visibly divergent from the spokes' canonical dashed lines. Building the
    config here lets all three uvicorn loggers share the canonical formatter so
    the hub's process logs align with the rest of the fleet.

    ``disable_existing_loggers: False`` preserves the
    ``_QuietSuccessAccessFilter`` / ``_QuietUvicornLifecycleFilter`` that
    ``configure_logging`` attached to the ``uvicorn.access`` / ``uvicorn.error``
    loggers (dictConfig only replaces a logger's ``handlers``/``propagate``/
    ``filters`` when those keys are present; here we omit ``filters``, so the
    noise-suppression filters survive). A single canonical ``StreamHandler``
    on stderr matches uvicorn's default destination (systemd captures it into
    ``/var/log/lm/hub.log``). ``uvicorn.access`` records carry their
    ``client_addr`` / ``request_line`` / ``status_code`` in ``record.args``, so
    ``record.getMessage()`` (the canonical ``%(message)s``) renders the full
    access line — no need for uvicorn's ``AccessFormatter``.
    """
    fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    datefmt = '%Y-%m-%d %H:%M:%S'
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"default": {"format": fmt, "datefmt": datefmt}},
        "handlers": {
            "default": {"class": "logging.StreamHandler",
                         "formatter": "default", "stream": "ext://sys.stderr"},
        },
        "loggers": {
            "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["default"], "level": "INFO", "propagate": False},
        },
    }


def _ws_keepalive_env(name: str, default: float) -> float:
    """Env-overridable WebSocket keepalive knob (seconds), shared by the hub's
    uvicorn server and the spoke ``websockets.connect`` call so both ends of a
    link use the same ping interval / pong timeout. Clamped to >=5s."""
    try:
        return max(5.0, float(os.environ.get(name, str(default))))
    except Exception:
        return default


def build_server(hub, host="0.0.0.0", port=443, tls_cert="", tls_key=""):
    """Build the awaitable uvicorn ``Server`` for the unified hub surface on a
    single port (443). ``Server.serve()`` is awaitable (vs blocking
    ``uvicorn.run``) so the hub ``await``s it as a task in its main asyncio loop
    — letting the ``/ws/spoke`` route, HTTP routes, and all hub background loops
    share one event loop (no cross-loop hazard). Pass ``ssl_certfile`` /
    ``ssl_keyfile`` when a cert is configured so uvicorn serves wss; without a
    cert it serves plaintext on the same port (legacy no-TLS fallback).
    """
    app = create_app(hub)
    cfg_kwargs = {"host": host, "port": port, "log_config": _uvicorn_log_config()}
    if tls_cert and tls_key:
        cfg_kwargs["ssl_certfile"] = tls_cert
        cfg_kwargs["ssl_keyfile"] = tls_key
    # WebSocket keepalive: uvicorn's defaults (ping every 20s, pong timeout 5s)
    # are too tight for spokes that do any sync I/O on their shared event loop
    # (cs telemetry relay's dhcp subprocess + config load + persist; dns
    # unbound-control; netbox pynetbox calls). A >5s stall makes the hub close
    # the spoke's WS with 1011 "keepalive ping timeout", kicking the spoke into
    # the 5→300s exponential reconnect backoff — during which every 5s
    # CS_POLL_AGENT_INBOX times out, producing the "Request Timeout from
    # cs-svr-XX-spoke after 5.0s" flood. Widen to 30s/90s (env-overridable via
    # LM_WS_PING_INTERVAL_S / LM_WS_PING_TIMEOUT_S) so a transient stall
    # recovers instead of cascading. The spoke's 30s app-level heartbeat still
    # detects a truly-dead peer via send failure, so dead-peer detection is not
    # materially delayed. Mirrored on the spoke side in control_plane.run().
    cfg_kwargs["ws_ping_interval"] = _ws_keepalive_env("LM_WS_PING_INTERVAL_S", 30.0)
    cfg_kwargs["ws_ping_timeout"] = _ws_keepalive_env("LM_WS_PING_TIMEOUT_S", 90.0)
    return uvicorn.Server(uvicorn.Config(app, **cfg_kwargs))


def run_api_server(hub, port=443):
    """Standalone BLOCKING launcher (``uvicorn.run``). The hub itself uses
    ``build_server()`` + in-loop ``Server.serve()`` so WebSocket routes share the
    hub's asyncio loop; this blocking form is kept for direct/standalone
    launches. Honors ``LM_TLS_CERT``/``LM_TLS_KEY`` for wss; otherwise plaintext.
    """
    app = create_app(hub)
    cert = os.environ.get("LM_TLS_CERT", "").strip()
    key = os.environ.get("LM_TLS_KEY", "").strip()
    # Same widened WS keepalive as build_server() (see comment there).
    _ws_kw = {
        "ws_ping_interval": _ws_keepalive_env("LM_WS_PING_INTERVAL_S", 30.0),
        "ws_ping_timeout": _ws_keepalive_env("LM_WS_PING_TIMEOUT_S", 90.0),
    }
    if cert and key:
        uvicorn.run(app, host="0.0.0.0", port=port, ssl_certfile=cert,
                    ssl_keyfile=key, log_config=_uvicorn_log_config(), **_ws_kw)
    else:
        uvicorn.run(app, host="0.0.0.0", port=port, log_config=_uvicorn_log_config(), **_ws_kw)