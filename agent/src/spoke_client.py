"""Spoke-client "device mode" for the Agent.

The dumb Agent dials its **spoke's** ``/ws/agent`` listener (never the hub) and
executes whatever the spoke tells it — generic primitives only (``RUN_COMMAND`` /
``WRITE_FILE``). All hub-bound traffic goes Agent→Spoke→Hub via the spoke's
``AGENT_RELAY_UP``; the Agent has no hub URL or hub creds.

Wire protocol (matches ``core/src/messaging/agent_hosting.py``):
  * connect wss/ws → handshake ``{agent_id, secret?}`` → ``APPROVAL_REQUIRED``
    (pend, then ``APPROVED``+secret) or ``HUB_VERIFIED`` → send ``HUB_OK``.
  * frames are ``<sig>.<body>``; body = ``{header:{correlation_id}, payload:{type,data}}``.
  * reply with ``{header:{correlation_id}, payload:{type:"AGENT_RESPONSE", data:result}}``.

Protocol-compatible with the pxmx node-agent; product-agnostic (no pvesh/qm).
"""

import asyncio
import json
import logging
import os
import queue
import sys
import time
import uuid
import ssl as _ssl

import websockets

try:
    from core.src.security.signer import MessageSigner, encode_frame, split_frame
except ImportError:  # bare-module layout (/opt/lm/core on sys.path)
    from security.signer import MessageSigner, encode_frame, split_frame

# Dep self-heal (mirror core/src/dep_guard + the netbox control-plane pattern):
# at startup the agent verifies its venv can import every declared requirement
# and runs `pip install -r requirements.txt` if not. None if dep_guard isn't
# importable in this layout (the agent still runs — just without self-heal).
try:
    from core.src.dep_guard import ensure_requirements as _ensure_requirements
except ImportError:
    try:
        from dep_guard import ensure_requirements as _ensure_requirements  # type: ignore
    except ImportError:
        _ensure_requirements = None

logger = logging.getLogger("Agent.SpokeClient")


class _DeviceAgentLogHandler(logging.Handler):
    """Capture INFO+ log records (canonical-formatted) into a queue for async
    relay to the hub as ``AGENT_LOG`` frames via the spoke WS. Mirrors the
    BaseControlPlane ``_SpokeLogRelayHandler``'s canonical format +
    drop-oldest ring-buffer so a relayed line is indistinguishable from the
    agent's local ``/var/log/lm/lm-agent.log`` line. Device mode has a single
    bucket (no multi-role prefix scoping — there is one agent, one spoke)."""

    def __init__(self, log_queue: "queue.Queue"):
        super().__init__(level=logging.DEBUG)
        self._queue = log_queue
        # Canonical LM format — matches logging_setup.DEFAULT_FORMAT so a
        # relayed line is byte-identical to the agent's local log line.
        self.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = self.format(record)
            try:
                self._queue.put_nowait(entry)
            except queue.Full:
                # Ring-buffer: on a full queue (a long spoke/hub outage), drop
                # the OLDEST line to make room for the newest — the most recent
                # lines (a crash's last words) are the ones worth keeping.
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    pass
                try:
                    self._queue.put_nowait(entry)
                except queue.Full:
                    pass
        except Exception:
            pass

_AGENT_WS_PATH = "/ws/agent"


def normalize_spoke_url(url: str) -> str:
    """Fill scheme/port/path → ``wss://host:443/ws/agent`` (or as given)."""
    u = (url or "").strip()
    if not u:
        return u
    if "://" not in u:
        u = "wss://" + u
    scheme, rest = u.split("://", 1)
    host_port, _, path = rest.partition("/")
    if ":" not in host_port:
        host_port += ":443" if scheme == "wss" else ":8767"
    path = "/" + path if path else ""
    if not path.endswith(_AGENT_WS_PATH):
        path = _AGENT_WS_PATH
    return f"{scheme}://{host_port}{path}"


class SpokeClient:
    """A generic dumb executor that dials a spoke and runs primitives."""

    def __init__(self, agent_id: str, spoke_url: str, secret: str = "",
                 secret_path: str = "", install_uuid_path: str = ""):
        self.agent_id = agent_id
        self.spoke_url = normalize_spoke_url(spoke_url)
        self.secret = secret or ""
        self.secret_path = secret_path or os.path.expanduser("~/.lm-agent-secret")
        self.install_uuid_path = install_uuid_path or os.path.expanduser(
            "~/.lm-agent-install-uuid")
        self.signer = MessageSigner(self.secret)
        self.hostname = os.uname().nodename if hasattr(os, "uname") else ""
        self.websocket = None
        self._stop = False
        # Stable per-install guid (Phase 1): lets the hub address this node
        # agent by guid, not its observable agent_id/hostname. Minted on first
        # start, persisted next to the secret (chmod 600); "" on write failure
        # (legacy — hub treats an absent guid as spoke_id-keyed, no flip).
        self.install_uuid = self._ensure_install_uuid()
        # Cert self-heal fallback: if an mTLS connect fails (the wildcard cert is
        # expired/broken so verification can't complete), the NEXT attempt drops
        # to the plain PSK-authenticated channel (encrypted, unverified) purely to
        # let the spoke re-deploy a fresh cert (_on_agent_registered custodian
        # deploy). Once connected + cert refreshed, mTLS resumes automatically.
        self._mtls_fallback = False
        # ── Device-mode scaffolding (first-class parity with hub-hosting agents) ─
        # AGENT_LOG relay: capture INFO+ log lines and flush them up the spoke WS
        # as AGENT_LOG frames. The spoke relays them to the hub via AGENT_RELAY_UP
        # (core/src/messaging/agent_hosting.py:495), which stores data.message
        # verbatim in hub.agent_logs[agent_id] — the SAME path the pxmx node-agent's
        # send_log uses. Without this a device-mode agent's connect/handshake trail
        # and crash's last words reach only local stderr, never the hub/WebUI.
        self._log_relay_queue: "queue.Queue[str]" = queue.Queue(maxsize=500)
        self._log_relay_handler = _DeviceAgentLogHandler(self._log_relay_queue)
        logging.getLogger().addHandler(self._log_relay_handler)
        # Drift / self-update bookkeeping (read by the code-drift watchdog).
        # _draining / _spoke_update_in_progress stay False until a (future)
        # spoke-driven self-update flips them; the watchdog just never skips then.
        self._draining = False
        self._spoke_update_in_progress = False
        self._loop = None
        self._drift_task = None
        self._dep_guard_done = False
        # Route uncaught SYNC exceptions through the logger (→ AGENT_LOG relay)
        # before the interpreter's default handler — a genuine crash reaches the
        # hub, not just local stderr. The asyncio-task counterpart is armed in
        # run() once the loop is running. Mirrors BaseControlPlane.
        self._install_uncaught_exception_relay()
        if not self.secret:
            self._load_secret()

    # ── secret persistence (provisioned on approval) ────────────────────────
    def _load_secret(self):
        try:
            if os.path.exists(self.secret_path):
                with open(self.secret_path) as f:
                    self.secret = f.read().strip()
                self.signer = MessageSigner(self.secret)
        except Exception as e:  # noqa: BLE001
            logger.debug("secret load skipped: %s", e)

    def _save_secret(self, secret: str):
        try:
            with open(self.secret_path, "w") as f:
                f.write(secret)
            os.chmod(self.secret_path, 0o600)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not persist provisioned secret: %s", e)

    def _ensure_install_uuid(self) -> str:
        """Stable per-install guid for a device-mode node agent — minted on
        first start and persisted next to the agent secret (chmod 600), so a
        process restart reuses the SAME guid and the hub can address it by guid
        instead of its observable agent_id/hostname. Re-imaging clears it (a
        fresh identity), mirroring spokes' INSTALL_UUID semantics. Returns ''
        on write failure so the identity never flips per boot (hub treats ''
        as legacy spoke_id-keyed)."""
        path = self.install_uuid_path
        try:
            if os.path.exists(path):
                with open(path) as f:
                    val = f.read().strip()
                if val:
                    return val
            new_uuid = str(uuid.uuid4())
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.write(new_uuid)
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except Exception:  # noqa: BLE001
                pass
            return new_uuid
        except Exception as e:  # noqa: BLE001
            logger.debug("install_uuid persist skipped: %s", e)
            return ""

    def _build_handshake(self) -> dict:
        """The /ws/agent auth frame: agent_id + optional secret/hostname +
        the per-install guid (so the hub's AGENT_RELAY_UP carries a stable,
        non-observable identity, not just the agent_id/hostname)."""
        hs = {"agent_id": self.agent_id}
        if self.secret:
            hs["secret"] = self.secret
        if self.hostname:
            hs["hostname"] = self.hostname
        if self.install_uuid:
            hs["install_uuid"] = self.install_uuid
        return hs

    def _ssl_ctx(self):
        # mTLS-aware (plumbed, default-off): today's unverified-but-encrypted
        # context unless LM_MTLS_ENABLED — then verify the spoke against the CA
        # and present the client cert. See core/src/security/mtls.py.
        is_wss = self.spoke_url.startswith("wss://")
        if not is_wss:
            return None
        # Self-heal: this attempt is a cert-refresh recovery → force the plain
        # unverified context so a broken/expired cert can't block reconnection.
        if self._mtls_fallback:
            return _ssl._create_unverified_context()
        try:
            try:
                from core.src.security.mtls import client_context
            except ImportError:
                from security.mtls import client_context
            return client_context(is_wss)
        except Exception:  # noqa: BLE001 - fall back to today's behavior
            return _ssl._create_unverified_context()

    # ── run loop ────────────────────────────────────────────────────────────
    async def run(self):
        # ── device-mode scaffolding: arm once for the process lifetime ───────
        # Route unhandled asyncio-task exceptions through the logger → AGENT_LOG
        # (the sync excepthook was installed in __init__). Set here because the
        # loop is now running. Mirrors BaseControlPlane.run().
        try:
            self._loop = asyncio.get_running_loop()
            self._loop.set_exception_handler(self._asyncio_exception_relay)
        except Exception:  # noqa: BLE001
            pass
        self._dep_guard_once()
        # Periodic code-drift self-heal: if code on disk advances ahead of the
        # running process (a manual pull / spoke-pushed update that pulled but
        # never restarted), os._exit(3) so systemd reloads current code. Opt out
        # with LM_DISABLE_DRIFT_WATCHDOG=1. Mirrors BaseControlPlane.
        if os.environ.get("LM_DISABLE_DRIFT_WATCHDOG", "0").lower() not in ("1", "true", "yes"):
            self._drift_task = asyncio.create_task(self._code_drift_watchdog())
        # AGENT_LOG relay flusher (lives across reconnects; reads self.websocket
        # fresh each cycle). Armed once here, not per-reconnect.
        asyncio.create_task(self._log_relay_task())
        backoff = 5
        while not self._stop:
            was_fallback = self._mtls_fallback
            try:
                await self._connect_once()
                self._mtls_fallback = False  # connected cleanly → resume mTLS
                backoff = 5
            except Exception as e:  # noqa: BLE001
                # If an mTLS attempt failed, the next attempt drops to the plain
                # PSK channel for a cert-refresh recovery (self-heal). If the
                # fallback attempt ALSO failed, go back to mTLS next (avoid
                # sticking in plain mode).
                try:
                    try:
                        from core.src.security.mtls import mtls_enabled as _me
                    except ImportError:
                        from security.mtls import mtls_enabled as _me
                    mtls_on = _me()
                except Exception:  # noqa: BLE001
                    mtls_on = False
                self._mtls_fallback = bool(mtls_on and not was_fallback)
                logger.warning("spoke connection to %s failed: %s — retry in %ss%s",
                               self.spoke_url, e, backoff,
                               " (cert-refresh fallback)" if self._mtls_fallback else "")
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 300)

    async def _connect_once(self):
        logger.info("Agent (device mode) → dialing spoke %s", self.spoke_url)
        async with websockets.connect(self.spoke_url, ssl=self._ssl_ctx()) as ws:
            self.websocket = ws
            await ws.send(json.dumps(self._build_handshake()))

            proof = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
            status = proof.get("status")
            if status == "APPROVAL_REQUIRED":
                logger.info("Agent '%s' pending admin approval (Setup → Spokes & "
                            "Agents).", self.agent_id)
                async for raw in ws:
                    msg = json.loads(raw if raw[:1] == "{" else split_frame(raw)[1])
                    if msg.get("status") == "APPROVED" and msg.get("secret"):
                        self.secret = msg["secret"]
                        self.signer = MessageSigner(self.secret)
                        self._save_secret(self.secret)
                        logger.info("Agent '%s' approved — reconnecting with secret.",
                                    self.agent_id)
                        return
                return
            if status != "HUB_VERIFIED":
                await ws.close(1008, "spoke identity not verified")
                raise RuntimeError(f"spoke identity proof failed: {proof}")
            await ws.send(json.dumps({"status": "HUB_OK"}))
            logger.info("Agent '%s' authenticated to spoke.", self.agent_id)

            hb = asyncio.create_task(self._heartbeat_loop())
            try:
                async for message in ws:
                    await self._handle_frame(ws, message)
            finally:
                hb.cancel()

    async def _handle_frame(self, ws, message):
        try:
            sig, body = split_frame(message)
            msg = json.loads(body)
        except Exception:  # noqa: BLE001
            return
        if sig and not self.signer.verify_bytes(body.encode(), sig):
            logger.warning("invalid signature — dropping")
            return
        payload = msg.get("payload", {})
        cmd = payload.get("type")
        data = payload.get("data", {}) or {}
        corr = msg.get("header", {}).get("correlation_id")
        result = await self._dispatch(cmd, data)
        if corr is not None:
            resp = {"header": {"correlation_id": corr, "sender_id": self.agent_id},
                    "payload": {"type": "AGENT_RESPONSE", "data": result}}
            try:
                await ws.send(encode_frame(self.signer, resp))
            except Exception as e:  # noqa: BLE001
                logger.debug("response send failed: %s", e)

    async def _dispatch(self, cmd, data):
        """Generic primitives ONLY — the spoke holds all product logic."""
        from command_runner import run_local_command, write_local_file
        if cmd in ("HUB_PING", "HEARTBEAT_ACK"):
            return {"status": "SUCCESS"}
        if cmd == "RUN_COMMAND":
            res = await asyncio.to_thread(
                run_local_command, data.get("command", ""),
                bool(data.get("allow_shell", False)),
                float(data.get("timeout", 30.0) or 30.0))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        if cmd == "WRITE_FILE":
            res = await asyncio.to_thread(
                write_local_file, data.get("path", ""), data.get("content", ""),
                b64=data.get("b64", ""), mode=int(data.get("mode", 0o600)),
                mkdirs=bool(data.get("mkdirs", True)),
                atomic=bool(data.get("atomic", True)))
            return {"status": "SUCCESS" if res.get("ok") else "ERROR",
                    "result": res, "message": res.get("error", "")}
        logger.debug("device-mode agent got non-primitive command %s (ignored)", cmd)
        return {"status": "ERROR", "message": f"unsupported in device mode: {cmd}"}

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(30)
            try:
                msg = {"header": {"sender_id": self.agent_id},
                       "payload": {"type": "HEARTBEAT",
                                   "data": {"agent_id": self.agent_id}}}
                await self.websocket.send(encode_frame(self.signer, msg))
            except Exception:  # noqa: BLE001
                return

    # ── device-mode scaffolding ──────────────────────────────────────────────
    # AGENT_LOG relay, uncaught-exception relay, and the code-drift watchdog —
    # the operational parity pieces the hub-hosting GenericAgent inherits from
    # BaseControlPlane but the dumb device-mode SpokeClient (not a subclass) did
    # not. Composition, not inheritance: BaseControlPlane is byte-untouched so
    # every spoke + the hub-hosting agent are unaffected. See agent-rework #2.

    def _dep_guard_once(self):
        """Self-heal the agent venv once at startup. Cheap if deps present
        (import checks only); runs `pip install -r requirements.txt` if a
        declared dep is missing. No-op if dep_guard isn't importable or
        LM_DEP_GUARD_DISABLE=1 is set (dep_guard enforces the latter itself)."""
        if self._dep_guard_done:
            return
        self._dep_guard_done = True
        if _ensure_requirements is None:
            return
        try:
            # agent/src/spoke_client.py → agent/requirements.txt
            agent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            req = os.path.join(agent_dir, "requirements.txt")
            _ensure_requirements(req)
            # The agent imports /opt/lm/core (BaseControlPlane, frame_crypto, …),
            # so ALSO ensure core's deps. A core change that adds a third-party
            # import (e.g. frame_crypto → cryptography) otherwise crashes an agent
            # whose venv predates it — the check above only covers the agent's own
            # requirements.txt. /opt/lm/core is co-located with the agent (same
            # clone); guard the path so a standalone agent without core degrades
            # to the agent-only check rather than raising.
            core_req = os.path.join(os.path.dirname(agent_dir), "core", "requirements.txt")
            if os.path.isfile(core_req):
                _ensure_requirements(core_req)
        except Exception as e:  # noqa: BLE001 — never block startup
            logger.debug("dep_guard skipped: %s", e)

    def _install_uncaught_exception_relay(self) -> None:
        """Route uncaught sync exceptions through the logger (→ AGENT_LOG relay)
        before the interpreter's default handler, so a genuine crash reaches the
        hub, not just local stderr. Mirrors BaseControlPlane."""
        _prev = sys.excepthook

        def _hook(exc_type, exc, tb):
            try:
                if not issubclass(exc_type, KeyboardInterrupt):
                    logger.error("Uncaught exception", exc_info=(exc_type, exc, tb))
            finally:
                _prev(exc_type, exc, tb)

        sys.excepthook = _hook

    def _asyncio_exception_relay(self, loop, context) -> None:
        """asyncio loop exception handler — logs unhandled task exceptions via
        the logger (→ AGENT_LOG) then defers to the default handler for local
        reporting. Mirrors BaseControlPlane."""
        exc = context.get("exception")
        msg = context.get("message") or "unhandled asyncio exception"
        if exc is not None:
            logger.error("Uncaught asyncio exception: %s", msg, exc_info=exc)
        else:
            logger.error("asyncio error: %s", msg)
        loop.default_exception_handler(context)

    async def _log_relay_task(self) -> None:
        """Drain the log queue and send captured log entries up the spoke as
        AGENT_LOG frames (relayed to the hub by the spoke's agent_hosting.py).
        Flushes every 5s so a short-lived or crashing process still gets its
        connect/handshake trail + final line to the hub. Best-effort: a dropped
        websocket just re-queues (the next connect resumes)."""
        while not self._stop:
            await asyncio.sleep(5)
            entries = []
            try:
                while True:
                    entries.append(self._log_relay_queue.get_nowait())
            except queue.Empty:
                pass
            if not entries:
                continue
            ws = self.websocket
            if ws is None:
                continue
            try:
                await self._send_agent_log(ws, entries)
            except Exception as e:  # noqa: BLE001
                logger.debug("AGENT_LOG relay send failed: %s", e)

    async def _send_agent_log(self, ws, entries) -> None:
        """Send one AGENT_LOG frame carrying the batched canonical log lines.
        Frame shape matches the pxmx node-agent's send_log (agent.py:1710) so
        the hub's AGENT_RELAY_UP handler stores data.message verbatim in
        agent_logs[agent_id]."""
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "sender_id": self.agent_id,
            },
            "payload": {
                "type": "AGENT_LOG",
                "data": {
                    "message": "\n".join(entries),
                    "level": "INFO",
                    "hostname": self.hostname,
                    "agent_type": "device",
                },
            },
        }
        await ws.send(encode_frame(self.signer, msg))

    async def _flush_log_relay_async(self, timeout: float = 2.0) -> None:
        """Best-effort final flush of queued log entries before a hard exit
        (the drift watchdog's os._exit(3)), so the agent's last lines reach the
        hub instead of dying in the queue."""
        entries = []
        try:
            while True:
                entries.append(self._log_relay_queue.get_nowait())
        except queue.Empty:
            pass
        if not entries:
            return
        ws = self.websocket
        if ws is None:
            return
        try:
            await asyncio.wait_for(self._send_agent_log(ws, entries), timeout=timeout)
        except Exception as e:  # noqa: BLE001
            logger.debug("pre-exit AGENT_LOG flush failed: %s", e)

    def _repo_root(self) -> str:
        """The agent's own repo checkout root (the lm repo, which vendors
        agent/ + core/). Used by the code-drift watchdog. agent/src/spoke_client.py
        → agent/src → agent → repo root."""
        return os.path.abspath(os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    def _resolve_core_root(self):
        """The shared /opt/lm/core checkout the agent imports at runtime
        (PYTHONPATH includes …/core/src). Best-effort: returns the first
        candidate that is itself a git repo, else None. The lm repo checkout
        already covers core/ when core is NOT a separate repo, so the watchdog
        watches the right thing either way."""
        for cand in (
            os.environ.get("LM_CORE_ROOT", "").strip(),
            os.path.abspath(os.path.join(self._repo_root(), "core")),
            "/opt/lm/core",
        ):
            if cand and os.path.isdir(os.path.join(cand, ".git")):
                return cand
        return None

    def _drift_watched_dirs(self) -> list:
        """Git checkouts whose on-disk HEAD advancing past the running process
        should trigger a restart: the agent's own repo + the shared core (if it
        is a separate checkout). Only real git roots are returned."""
        dirs = set()
        try:
            dirs.add(os.path.abspath(self._repo_root()))
        except Exception:  # noqa: BLE001
            pass
        try:
            core = self._resolve_core_root()
            if core:
                dirs.add(os.path.abspath(core))
        except Exception:  # noqa: BLE001
            pass
        return [d for d in dirs if os.path.isdir(os.path.join(str(d), ".git"))]

    async def _code_drift_watchdog(self, interval_s: float = 300.0):
        """Restart when code on disk drifts AHEAD of the running process — a
        manual pull / spoke-pushed update that advanced the repo but never
        restarted, so the old class stays in memory AND the next update sees
        "already up to date". Any advance → os._exit(3) so systemd
        Restart=on-failure reloads current code. Skips the exit while a
        self-update is mid-flight (that path restarts itself); a repo that
        first appears after boot is baselined, not treated as drift. Never
        crashes the agent — every failure is swallowed. Mirrors
        BaseControlPlane._code_drift_watchdog."""
        async def _head(d):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "git", "-C", str(d), "rev-parse", "HEAD",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL)
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                return out.decode().strip() if proc.returncode == 0 else ""
            except Exception:  # noqa: BLE001 — never let the watchdog crash the agent
                return ""

        baseline = {}
        for d in self._drift_watched_dirs():
            baseline[str(d)] = await _head(d)
        logger.info("code-drift watchdog armed (every %ss): %s", int(interval_s),
                    {k: v[:8] for k, v in baseline.items() if v})
        while not self._stop:
            try:
                await asyncio.sleep(interval_s)
                # A self-update in flight advances HEAD on purpose and restarts
                # itself; don't race it with a second exit.
                if self._draining or self._spoke_update_in_progress:
                    continue
                for d in self._drift_watched_dirs():
                    key, now = str(d), await _head(d)
                    if not now:
                        continue
                    if key not in baseline:  # newly-watched repo → baseline it
                        baseline[key] = now
                        continue
                    was = baseline.get(key)
                    if was and now != was:
                        logger.warning(
                            "code-drift: %s advanced %s->%s on disk but the "
                            "process never restarted -- exiting so systemd "
                            "reloads current code.", d, was[:8], now[:8])
                        try:
                            await self._flush_log_relay_async()
                        except Exception:  # noqa: BLE001
                            pass
                        os._exit(3)
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 — never fatal
                logger.debug("code-drift watchdog cycle failed: %s", e)
