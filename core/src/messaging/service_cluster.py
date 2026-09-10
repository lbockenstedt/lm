"""Shared coordinator/worker transport for clustered service modules.

One hosted module spoke (the **coordinator**) drives two or more service hosts
(the **workers**) that actually run the daemon — two Unbound resolvers behind
one ``dns`` module, two Kea servers behind one ``dhcp`` module. Both sides reuse
the already-authenticated ``/ws/agent`` machinery in
:mod:`core.src.messaging.agent_hosting`:

* **Coordinator** — any :class:`AgentHostingControlPlane` (the standalone spoke's
  control plane, or the generic agent's ``RoleConnection``) already serves
  ``/ws/agent``, authenticates inbound peers against a shared PSK, HMAC-signs
  every frame, and exposes the correlated ``send_to_agent`` RPC. This module
  adds :class:`ClusterCoordinator` — a *policy* layer on top of that transport:
  a fixed command allowlist, member bookkeeping, and an all-or-report fan-out
  that reports ``PARTIAL`` rather than laundering a half-applied change into a
  success.
* **Worker** — :class:`ServiceWorkerClient` dials the coordinator's listener,
  performs the same handshake the pxmx node-agent does, heartbeats, and executes
  **only** the fixed operations its owning module registered. It is deliberately
  *not* the generic agent: there is no ``RUN_COMMAND``, no ``WRITE_FILE``, no
  caller-supplied path/URL/shell. A worker can do exactly the N things its
  module's op table names and nothing else, so compromising the coordinator
  cannot turn a resolver host into a general-purpose shell.

Why not the hub's reverse ``HUB_REQUEST``: the hub is a relay, not a brain, and
a worker is not a spoke. Tenant routing stays "one tenant → one coordinator
spoke"; the workers are bound to (and authenticated by) that coordinator only,
so they never appear in the hub's spoke registry and never widen the tenant
surface.

Ports: each module type gets its OWN listener port so a single generic agent can
host the dns AND dhcp roles at once without a bind collision — see
:data:`CLUSTER_PORTS` (8765 hub, 8766 pxmx, 8767 cs, 8768 hub-self are taken).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import ssl
import time
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import websockets

try:
    from ..security.signer import MessageSigner, encode_frame, split_frame
except ImportError:  # bare-module layout (/opt/lm/core/src on sys.path)
    from security.signer import MessageSigner, encode_frame, split_frame  # type: ignore

logger = logging.getLogger("ServiceCluster")

#: Per-module-type listener ports for the coordinator's ``/ws/agent`` socket.
#: Distinct so the dns and dhcp roles can be co-loaded on one generic agent.
CLUSTER_PORTS: Dict[str, int] = {"dns": 8769, "dhcp": 8770}

#: Wire type a worker sends for an unsolicited liveness beat (matches the
#: pxmx node-agent contract the listener already understands).
HEARTBEAT_TYPE = "AGENT_HEARTBEAT"


class InsecureCoordinatorURL(ValueError):
    """A remote coordinator was addressed over plaintext ``ws://``.

    The worker sends its shared PSK in the FIRST frame of the handshake, so a
    plaintext hop off-box hands the cluster's credential to anyone on the path.
    Loopback (the co-located all-in-one case, where TLS terminates upstream) is
    the only plaintext form allowed.
    """


def is_loopback_host(host: str) -> bool:
    host = (host or "").strip().lower()
    if host in ("localhost", "localhost.localdomain", ""):
        return host == "localhost" or host == "localhost.localdomain"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_coordinator_url(url: str, default_port: int) -> str:
    """Canonicalize an operator-supplied coordinator address.

    ``10.0.1.9`` → ``wss://10.0.1.9:<default_port>/ws/agent``. An explicit
    scheme is honored, EXCEPT that a remote ``ws://`` raises
    :class:`InsecureCoordinatorURL` rather than being silently upgraded — an
    operator who typed ``ws://`` must find out their PSK would have been sent in
    the clear, not have it quietly work.
    """
    raw = (url or "").strip()
    if not raw:
        raise ValueError("coordinator URL is required")
    if "://" not in raw:
        hostport = raw
        scheme = "wss"
        if ":" not in hostport.rsplit("]", 1)[-1]:
            hostport = f"{hostport}:{default_port}"
        raw = f"{scheme}://{hostport}"
    parts = urlsplit(raw)
    if parts.scheme not in ("ws", "wss"):
        raise ValueError(f"coordinator URL scheme must be ws/wss, got {parts.scheme!r}")
    if parts.scheme == "ws" and not is_loopback_host(parts.hostname or ""):
        raise InsecureCoordinatorURL(
            f"refusing plaintext ws:// to remote coordinator {parts.hostname!r} — "
            f"the worker PSK is sent in the handshake. Use wss:// (or a loopback "
            f"address when TLS terminates upstream).")
    path = parts.path or ""
    if not path.rstrip("/").endswith("/ws/agent"):
        path = (path.rstrip("/") + "/ws/agent") if path.rstrip("/") else "/ws/agent"
    netloc = parts.netloc
    if ":" not in netloc.rsplit("]", 1)[-1]:
        netloc = f"{netloc}:{default_port}"
    return f"{parts.scheme}://{netloc}{path}"


def cluster_client_ssl_context(ca_cert: str = "",
                               check_hostname: Optional[bool] = None
                               ) -> Optional[ssl.SSLContext]:
    """SSL context for a worker's ``wss://`` dial to its coordinator.

    **Verification is mandatory here** — unlike the hub leg, which keeps a
    verify-off lab default. A cluster worker hands over the shared PSK in its
    first frame, so an unauthenticated peer is an unacceptable MITM target and
    there is no "encrypted but unverified" mode at all.

    Trust comes from the coordinator CA the installer provisions
    (``LM_CLUSTER_CA_CERT``, written to ``/etc/lm-<mod>-worker/coordinator-ca.pem``),
    falling back to ``LM_HUB_CA_CERT`` and then the system store. A configured
    CA path that does not exist returns None so the caller aborts — never a
    silent downgrade.

    ``check_hostname`` defaults ON and is disabled only by an explicit
    ``LM_CLUSTER_TLS_CHECK_HOSTNAME=0``, for the self-signed-by-IP case the
    installer produces when the coordinator has no DNS name. The certificate is
    still verified against the pinned CA in that mode.
    """
    ca_cert = (ca_cert or os.environ.get("LM_CLUSTER_CA_CERT", "")
               or os.environ.get("LM_HUB_CA_CERT", "")).strip()
    if check_hostname is None:
        check_hostname = os.environ.get(
            "LM_CLUSTER_TLS_CHECK_HOSTNAME", "1").strip().lower() \
            not in ("0", "false", "no", "off")
    try:
        if ca_cert:
            if not os.path.isfile(ca_cert):
                logger.error("cluster wss: pinned CA %s does not exist — refusing "
                             "to connect unverified", ca_cert)
                return None
            ctx = ssl.create_default_context(cafile=ca_cert)
            logger.info("cluster wss: verifying the coordinator cert against "
                        "pinned CA %s", ca_cert)
        else:
            ctx = ssl.create_default_context()
            logger.info("cluster wss: verifying the coordinator cert against the "
                        "system trust store (no LM_CLUSTER_CA_CERT configured)")
        if not check_hostname:
            # Still CERT_REQUIRED against the pinned CA; only the SAN match is
            # relaxed (self-signed-by-IP coordinators).
            ctx.check_hostname = False
            logger.info("cluster wss: hostname check disabled "
                        "(LM_CLUSTER_TLS_CHECK_HOSTNAME=0); the cert is still "
                        "verified against the trust anchor")
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx
    except Exception as e:  # noqa: BLE001
        logger.error("Could not build cluster wss SSL context: %s", e)
        return None

#: Fan-out verdicts. ``PARTIAL`` exists so a half-applied change is never
#: reported as SUCCESS — the single most important contract in this module.
OK = "SUCCESS"
PARTIAL = "PARTIAL"
FAILED = "ERROR"


class ClusterMemberError(Exception):
    """A named cluster member is not currently connected."""


def normalize_members(raw: Iterable[Any]) -> List[Dict[str, str]]:
    """Normalize operator-supplied member config into ``[{id, host, role}]``.

    Accepts a list of plain strings (``"dns-a"``) or dicts
    (``{"id": "dns-a", "host": "10.0.1.5", "role": "primary"}``). Entries with no
    usable id are dropped and duplicates collapse to the first occurrence, so a
    typo'd config can never silently produce a one-member "cluster" that then
    reports itself fully converged.
    """
    out: List[Dict[str, str]] = []
    seen = set()
    for item in raw or []:
        if isinstance(item, str):
            member = {"id": item.strip(), "host": "", "role": ""}
        elif isinstance(item, dict):
            # Carry module-specific fields through untouched (the Kea HA pair
            # needs ha_port / ha_user / ha_password / url per node). Dropping
            # unknown keys here silently reverted every node to the defaults.
            member = {k: v for k, v in item.items()
                      if k not in ("id", "member_id", "name", "host", "address",
                                   "role")}
            member.update({
                "id": str(item.get("id") or item.get("member_id")
                          or item.get("name") or "").strip(),
                "host": str(item.get("host") or item.get("address") or "").strip(),
                "role": str(item.get("role") or "").strip().lower(),
            })
        else:
            continue
        if not member["id"] or member["id"] in seen:
            continue
        seen.add(member["id"])
        out.append(member)
    return out


class ClusterCoordinator:
    """Allowlisted fan-out over an :class:`AgentHostingControlPlane` listener.

    The owning module constructs one of these with the set of commands it is
    ever allowed to issue. ``call``/``fanout`` refuse anything outside that set
    — the allowlist is a constructor argument, never taken from a request — so a
    malformed or hostile hub payload cannot be turned into a new worker command.

    ``control_plane`` is resolved lazily via a callable because a spoke module is
    constructed BEFORE its control plane back-reference is wired
    (``RoleConnection.__init__`` sets ``role_instance.control_plane`` after
    ``register_module``).
    """

    def __init__(self, module_type: str, allowed_commands: Iterable[str],
                 control_plane_getter: Callable[[], Any],
                 members: Iterable[Any] = ()):
        self.module_type = module_type
        self._allowed = frozenset(allowed_commands)
        self._get_cp = control_plane_getter
        self.members: List[Dict[str, str]] = normalize_members(members)

    # ── Membership ──────────────────────────────────────────────────────────

    def set_members(self, members: Iterable[Any]) -> List[Dict[str, str]]:
        self.members = normalize_members(members)
        return self.members

    @property
    def enabled(self) -> bool:
        """Cluster mode is on only with 2+ declared members.

        A single declared member is NOT a cluster — the module keeps its
        original local-only behavior so existing single-host deployments are
        untouched by this feature.
        """
        return len(self.members) >= 2

    def member_ids(self) -> List[str]:
        return [m["id"] for m in self.members]

    def connected_ids(self) -> List[str]:
        cp = self._get_cp()
        connected = getattr(cp, "connected_agents", None) or {}
        return [m["id"] for m in self.members if m["id"] in connected]

    def missing_ids(self) -> List[str]:
        connected = set(self.connected_ids())
        return [m["id"] for m in self.members if m["id"] not in connected]

    def member_links(self) -> List[Dict[str, Any]]:
        """Per-member transport view: declared config + live connection facts."""
        cp = self._get_cp()
        connected = getattr(cp, "connected_agents", None) or {}
        pending = getattr(cp, "pending_agents", None) or {}
        now = time.time()
        out = []
        for m in self.members:
            rec = connected.get(m["id"])
            last_seen = rec.get("last_seen") if rec else None
            out.append({
                "id": m["id"],
                "host": m["host"],
                "role": m["role"],
                "connected": rec is not None,
                "pending_approval": m["id"] in pending,
                "last_seen": last_seen,
                "seconds_since_seen": (round(now - last_seen, 1)
                                       if last_seen else None),
                "version": (rec or {}).get("version", "unknown"),
            })
        return out

    # ── RPC ─────────────────────────────────────────────────────────────────

    def _check(self, command: str) -> None:
        if command not in self._allowed:
            raise ValueError(
                f"{self.module_type} cluster command not allowed: {command!r}")

    async def call(self, member_id: str, command: str, data: Dict[str, Any],
                   timeout: float = 20.0) -> Dict[str, Any]:
        """One allowlisted RPC to one member. Never raises for a transport
        failure — returns the ``{"status": "ERROR", "message": …}`` shape
        ``send_to_agent`` already uses so callers have exactly one contract."""
        self._check(command)
        cp = self._get_cp()
        if cp is None:
            return {"status": FAILED, "message": "no control plane attached"}
        if member_id not in (getattr(cp, "connected_agents", None) or {}):
            return {"status": FAILED,
                    "message": f"cluster member '{member_id}' not connected"}
        try:
            return await cp.send_to_agent(command, data, agent_id=member_id,
                                          timeout=timeout)
        except Exception as e:  # noqa: BLE001 — one bad member must not raise out
            logger.warning("%s cluster call %s -> %s failed: %s",
                           self.module_type, command, member_id, e)
            return {"status": FAILED, "message": str(e)}

    async def fanout(self, command: str, data: Dict[str, Any],
                     timeout: float = 20.0,
                     member_ids: Optional[Iterable[str]] = None
                     ) -> Dict[str, Any]:
        """Issue one allowlisted command to every member concurrently.

        Returns ``{"status": SUCCESS|PARTIAL|ERROR, "results": {id: reply},
        "ok": [...], "failed": [...]}``. A member that is not connected counts as
        FAILED — it did not apply the change, and pretending otherwise is how a
        cluster silently diverges.
        """
        self._check(command)
        targets = list(member_ids) if member_ids is not None else self.member_ids()
        if not targets:
            return {"status": FAILED, "results": {}, "ok": [], "failed": [],
                    "message": "no cluster members configured"}
        replies = await asyncio.gather(
            *[self.call(mid, command, data, timeout=timeout) for mid in targets])
        results = dict(zip(targets, replies))
        ok = [mid for mid, r in results.items()
              if isinstance(r, dict) and r.get("status") == OK]
        failed = [mid for mid in targets if mid not in ok]
        if not failed:
            status = OK
        elif ok:
            status = PARTIAL
        else:
            status = FAILED
        return {"status": status, "results": results, "ok": ok, "failed": failed}


class ServiceWorkerClient:
    """Reconnecting worker that executes a FIXED op table for one coordinator.

    ``ops`` maps a wire command to a handler taking the command's ``data`` dict
    and returning a result dict. Anything not in ``ops`` is refused — there is no
    escape hatch, no shell, no caller-controlled path. Handlers are run via
    ``asyncio.to_thread`` because service control (``unbound-control``, the Kea
    CA HTTP RPC, ``systemctl``) is synchronous.

    The handshake, framing and heartbeat mirror what
    ``AgentHostingControlPlane._agent_handler`` expects, so no listener change is
    needed to host workers.
    """

    def __init__(self, member_id: str, coordinator_url: str, secret: str,
                 ops: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]],
                 *, hostname: str = "", heartbeat_interval: float = 30.0,
                 on_connect: Optional[Callable[[], Awaitable[None]]] = None,
                 default_port: int = 0, ca_cert: str = ""):
        if not member_id:
            raise ValueError("member_id is required")
        if not secret:
            raise ValueError("worker secret is required")
        self.member_id = member_id
        # Raises InsecureCoordinatorURL for a remote plaintext hop — the PSK
        # rides in the first handshake frame, so this must fail at construction,
        # not connect silently.
        self.url = normalize_coordinator_url(coordinator_url, default_port or 443)
        self.secret = secret
        self.ops = dict(ops)
        self.hostname = hostname or member_id
        self.heartbeat_interval = heartbeat_interval
        self.signer = MessageSigner(secret)
        self._on_connect = on_connect
        self._ca_cert = ca_cert
        self._stop = False

    # ── Dispatch ────────────────────────────────────────────────────────────

    def dispatch(self, command: Optional[str], data: Dict[str, Any]) -> Dict[str, Any]:
        """Run one allowlisted op. Synchronous by design (called via to_thread).

        An unknown command is an ERROR, never a silent success — a coordinator
        talking to an older worker must SEE the gap rather than believe a
        change landed.
        """
        if command in ("HUB_PING", "HEARTBEAT_ACK", "GET_VERSION"):
            return {"status": OK, "member_id": self.member_id}
        handler = self.ops.get(command or "")
        if handler is None:
            return {"status": FAILED,
                    "message": f"unsupported worker operation: {command}",
                    "member_id": self.member_id}
        try:
            result = handler(data or {})
        except Exception as e:  # noqa: BLE001 — a bad op must not kill the worker
            logger.exception("worker op %s failed", command)
            return {"status": FAILED, "message": str(e),
                    "member_id": self.member_id}
        if not isinstance(result, dict):
            return {"status": FAILED, "member_id": self.member_id,
                    "message": f"op {command} returned {type(result).__name__}"}
        return {"member_id": self.member_id, **result}

    # ── Connection loop ─────────────────────────────────────────────────────

    def stop(self) -> None:
        self._stop = True

    async def run(self) -> None:
        backoff = 2
        while not self._stop:
            try:
                await self._session()
                backoff = 2
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — reconnect forever
                logger.warning("worker %s reconnect to %s in %ss: %s",
                               self.member_id, self.url, backoff, e)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 30)

    def _ssl_context(self) -> Optional[ssl.SSLContext]:
        """None for a (loopback-only) ``ws://`` dial; a context for ``wss://``.

        A failed context build is fatal — ``normalize_coordinator_url`` already
        proved this hop needs TLS, so continuing without it would send the PSK
        in the clear."""
        if not self.url.lower().startswith("wss://"):
            return None
        ctx = cluster_client_ssl_context(self._ca_cert)
        if ctx is None:
            raise RuntimeError(
                "could not build a TLS context for the coordinator connection — "
                "refusing to send the worker secret unencrypted")
        return ctx

    async def _session(self) -> None:
        ssl_ctx = self._ssl_context()
        async with websockets.connect(self.url, ping_interval=30,
                                      ping_timeout=90, ssl=ssl_ctx) as ws:
            await ws.send(json.dumps({
                "agent_id": self.member_id,
                "secret": self.secret,
                "hostname": self.hostname,
            }))
            proof = json.loads(await asyncio.wait_for(ws.recv(), timeout=10.0))
            if proof.get("status") != "HUB_VERIFIED":
                raise RuntimeError(
                    f"coordinator refused worker auth: {proof.get('status')}")
            await ws.send(json.dumps({"status": "HUB_OK"}))
            logger.info("worker %s connected to coordinator %s",
                        self.member_id, self.url)
            if self._on_connect:
                await self._on_connect()
            beat = asyncio.create_task(self._heartbeat(ws))
            try:
                async for raw in ws:
                    await self._handle_frame(ws, raw)
            finally:
                beat.cancel()

    async def _heartbeat(self, ws) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval)
            try:
                await ws.send(self._frame(HEARTBEAT_TYPE, {
                    "member_id": self.member_id, "hostname": self.hostname,
                    "timestamp": time.time(),
                }))
            except Exception:  # noqa: BLE001 — the recv loop owns reconnect
                return

    def _frame(self, msg_type: str, data: Dict[str, Any],
               correlation_id: Optional[str] = None) -> str:
        header: Dict[str, Any] = {"sender_id": self.member_id,
                                  "timestamp": time.time()}
        if correlation_id is not None:
            header["correlation_id"] = correlation_id
        return encode_frame(self.signer,
                            {"header": header,
                             "payload": {"type": msg_type, "data": data}})

    async def _handle_frame(self, ws, raw) -> None:
        try:
            text = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            sig, body = split_frame(text)
            if not sig or not self.signer.verify_bytes(body.encode(), sig):
                logger.warning("worker %s dropped unsigned/forged frame",
                               self.member_id)
                return
            msg = json.loads(body)
        except Exception:  # noqa: BLE001 — undecodable frame is a per-frame drop
            logger.warning("worker %s dropped undecodable frame", self.member_id)
            return
        corr = (msg.get("header") or {}).get("correlation_id")
        payload = msg.get("payload") or {}
        result = await asyncio.to_thread(
            self.dispatch, payload.get("type"), payload.get("data") or {})
        if corr is None:
            return
        try:
            await ws.send(self._frame("AGENT_RESPONSE", result, corr))
        except Exception as e:  # noqa: BLE001
            logger.warning("worker %s could not answer %s: %s",
                           self.member_id, corr, e)
