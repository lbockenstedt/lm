"""Agent-hosting control plane mixin — ``AgentHostingControlPlane``.

Lifts the generic agent-listener machinery that used to live only in
``pxmx/src/control_plane.py::PxmxControlPlane`` so any spoke that needs to
host inbound agents can share one implementation. Today two spokes use it:

* **pxmx** (``hypervisor``) — the original. A Proxmox agent dials the pxmx
  spoke's ``/ws/agent`` (standalone ``wss://0.0.0.0:443`` default, or loopback
  ``127.0.0.1:8443`` on the co-located all-in-one path); the spoke relays frames
  up to the hub wrapped in ``AGENT_RELAY_UP``.
* **cs** (``simulation``) — opt-in via ``--agent-listener`` /
  ``LM_CS_AGENT_LISTENER=1``. In the split (per-module-LXC) topology a
  cs-dialed pxmx agent connects directly to the cs spoke instead of the pxmx
  spoke; the cs spoke then relays the same way. all-in-one keeps cs relay-only
  (the ``CSBridgePoller`` handles co-located cs agents), so the cs listener is
  gated and does NOT bind ``:443`` on the hub box.

Behavior is parameterized via class attrs so the lifted code is byte-identical
in behavior to the original pxmx implementation (pxmx tests are the regression
gate). Subclass hooks (``_on_agent_telemetry``, ``_on_agent_registered``) carry
the pxmx-specific telemetry caching + config re-push; the base mixin is generic.
"""

import asyncio
import json
import uuid
import time
import os
import secrets
import ssl
import hmac
import socket
import logging
import websockets
from http import HTTPStatus
from typing import Any, Dict, List, Optional

try:
    from .control_plane import BaseControlPlane, _ws_keepalive_env
    from ..security.signer import MessageSigner, split_frame
except ImportError:  # imported off a stale path (bare modules on sys.path)
    from messaging.control_plane import BaseControlPlane  # type: ignore
    from messaging.control_plane import _ws_keepalive_env  # type: ignore
    from security.signer import MessageSigner, split_frame  # type: ignore

logger = logging.getLogger("AgentHostingControlPlane")


class AgentHostingControlPlane(BaseControlPlane):
    """A spoke that also serves an inbound ``/ws/agent`` listener.

    Subclasses set the class attrs below (pxmx / cs values shown):

    * ``MODULE_TYPE``           — ``"hypervisor"`` / ``"simulation"``
    * ``AGENT_PORT_ENV``        — ``"LM_PXMX_AGENT_PORT"`` / ``"LM_CS_AGENT_PORT"``
    * ``AGENT_LOOPBACK_ENV``    — ``"LM_PXMX_AGENT_LOOPBACK"`` / ``"LM_CS_AGENT_LOOPBACK"``
    * ``AGENT_LISTENER_ENV``    — ``"LM_PXMX_AGENT_LISTENER"`` / ``"LM_CS_AGENT_LISTENER"``
    * ``AGENT_CONFIG_PATH``     — ``"/etc/lm-agent/config.json"`` / ``"/etc/lm-cs-agent/config.json"``
    * ``AGENT_LISTENER_OPT_IN`` — ``False`` (pxmx: always on) / ``True`` (cs: env-gated)
    * ``AGENT_LOOPBACK_PORT``   — ``8443`` (loopback + wss default when env unset)
    * ``AGENT_WSS_PORT``        — ``443`` (pxmx standalone) / ``443`` (cs standalone)
    * ``AGENT_FALLBACK_PORT``   — ``8766`` (pxmx legacy no-cert) / ``8767`` (cs)

    Hooks (base default is a no-op):

    * ``_on_agent_registered(agent_id)`` — pxmx re-pushes stored PVE config.
    * ``_on_agent_telemetry(agent_id, rec, data)`` — pxmx caches nodes/vms/cluster
      + persists the disk cache; cs stores minimal fields.
    """

    # ── Subclass-tunable knobs (defaults are pxmx's so a pxmx subclass that
    #    forgets to set them still behaves exactly as before) ────────────────
    MODULE_TYPE: Optional[str] = "hypervisor"
    AGENT_PORT_ENV: str = "LM_PXMX_AGENT_PORT"
    AGENT_LOOPBACK_ENV: str = "LM_PXMX_AGENT_LOOPBACK"
    AGENT_LISTENER_ENV: str = "LM_PXMX_AGENT_LISTENER"
    AGENT_CONFIG_PATH: str = "/etc/lm-agent/config.json"
    AGENT_LISTENER_OPT_IN: bool = False
    AGENT_LOOPBACK_PORT: int = 8443
    AGENT_WSS_PORT: int = 443
    AGENT_FALLBACK_PORT: int = 8766

    def __init__(self, spoke_id: str, secret: str = None, hub_secret: str = None,
                 hub_url: str = None, onboarding_psk: str = None,
                 tenant_id_hint: str = None):
        super().__init__(spoke_id, secret, hub_secret, hub_url,
                         onboarding_psk=onboarding_psk, tenant_id_hint=tenant_id_hint)
        if self.MODULE_TYPE:
            self.module_type = self.MODULE_TYPE

        # Agent onboarding secret — one value used as BOTH the auth PSK
        # (hmac.compare_digest against the agent's ``secret`` field) AND the
        # HMAC signing key for all agent↔spoke frames (``agent_signer``).
        # Generated at install time into AGENT_CONFIG_PATH so
        # ``approve_pending_agent`` can push it down to a pending agent on
        # admin approval. Absent → zero-touch only (agents approved before
        # they receive a secret).
        config_path = self.AGENT_CONFIG_PATH
        self.config: Dict[str, Any] = {}
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    self.config = json.load(f)
        except Exception as e:
            logger.error(f"Could not load agent config: {e}")

        self.agent_secret: Optional[str] = self.config.get("agent_secret")
        if not self.agent_secret:
            logger.warning("agent_secret not set — zero-touch provisioning only "
                           "(agents will be approved before receiving a secret)")
        self.agent_signer = MessageSigner(self.agent_secret or "")

        # Correlated agent command/response futures (corr_id → Future).
        self.pending_responses: Dict[str, asyncio.Future] = {}
        # corr_id → {"soft","hard","grace"} — keepalive-extendable deadlines for
        # in-flight send_to_agent waiters. A busy agent emits AGENT_PROGRESS
        # frames (correlation_id == the command's corr_id) while it works; each
        # pushes "soft" forward by another "grace" window (capped at "hard") so a
        # slow-but-alive agent isn't killed at the base timeout.
        self.pending_progress: Dict[str, Dict[str, float]] = {}
        # Hard-ceiling multiplier for the above. Env-overridable (default 6×).
        try:
            self._agent_progress_hard_mult = max(
                1.0, float(os.environ.get("LM_AGENT_PROGRESS_HARD_MULT", "6") or 6))
        except (TypeError, ValueError):
            self._agent_progress_hard_mult = 6.0
        # agent_id → {ws, hostname, cluster_name, last_seen, nodes, vms, ...}
        self.connected_agents: Dict[str, Dict[str, Any]] = {}
        # agent_id → {ws, event} for agents awaiting admin approval.
        self.pending_agents: Dict[str, Dict[str, Any]] = {}

        # Strong reference to the self-healing agent-server task so the loop
        # does not GC it mid-flight ("coroutine ignored GeneratorExit").
        self._agent_server_task: Optional[asyncio.Task] = None

    # ── Listener enablement ────────────────────────────────────────────────

    def _agent_listener_enabled(self) -> bool:
        """True when this spoke should serve ``/ws/agent``.

        pxmx (``AGENT_LISTENER_OPT_IN=False``) always serves it — backward
        compatible with existing pxmx installs that never set the env. cs
        (``AGENT_LISTENER_OPT_IN=True``) only serves it when
        ``LM_CS_AGENT_LISTENER=1`` (set by ``install_cs.sh --agent-listener``),
        so an all-in-one / relay-only cs spoke never binds ``:443``.
        """
        if not self.AGENT_LISTENER_OPT_IN:
            return True
        return os.environ.get(self.AGENT_LISTENER_ENV, "").strip() in ("1", "true", "True")

    # ── System command propagation ──────────────────────────────────────────

    async def handle_system_command(self, cmd_type: str, data: Dict[str, Any]) -> Any:
        """Handle a Hub system command; on log-level changes also broadcast to
        all connected agents so the WebUI "Enable Debug" toggle reaches them."""
        # Remote Console → a specific hosted node agent. Only an agent-hosting
        # spoke has send_to_agent, so relay RUN_COMMAND down the /ws/agent channel
        # and return the agent's runner result. The hub already gated this on
        # Global-Admin + remote_exec.enabled and audit-logged it.
        # Fleet OS updates relayed to a hosted AGENT (hub → owning spoke → agent).
        # Mirrors AGENT_RUN_COMMAND below. The apply timeout is generous because a
        # Proxmox dist-upgrade genuinely runs for many minutes; the agent bounds
        # it too, so a wedged apt can't hold the relay open forever.
        if cmd_type in ("AGENT_OS_UPDATE_CHECK", "AGENT_OS_UPDATE_APPLY"):
            _apply = cmd_type.endswith("APPLY")
            _to = 3700.0 if _apply else 240.0
            resp = await self.send_to_agent(
                "OS_UPDATE_APPLY" if _apply else "OS_UPDATE_CHECK",
                {"refresh": bool(data.get("refresh", True))},
                agent_id=data.get("agent_id"),
                timeout=_to)
            if isinstance(resp, dict):
                return resp
            return {"status": "ERROR", "message": "no response from agent"}

        if cmd_type == "AGENT_RUN_COMMAND":
            _to = float(data.get("timeout", 30.0) or 30.0)
            resp = await self.send_to_agent(
                "RUN_COMMAND",
                {"command": data.get("command", ""),
                 "allow_shell": bool(data.get("allow_shell", False)),
                 "timeout": _to},
                agent_id=data.get("agent_id"),
                timeout=_to + 10.0)
            # send_to_agent returns the agent's response data: the runner dict on
            # success, or {"status":"ERROR","message":…} if the agent is gone/timed
            # out. Normalize to a runner-shaped result for the hub.
            if isinstance(resp, dict) and resp.get("status") == "ERROR":
                res = {"ok": False, "rc": None, "stdout": "", "stderr": "",
                       "truncated": False, "error": resp.get("message", "agent error")}
            elif isinstance(resp, dict):
                res = resp
            else:
                res = {"ok": False, "rc": None, "stdout": "", "stderr": "",
                       "truncated": False, "error": "no result from agent"}
            return {"status": "SUCCESS", "result": res}
        if cmd_type == "SPOKE_UPDATE":
            # The spoke is about to pull its own repo + os._exit(3) to reload
            # (handled by the base class below). FIRST, fan the same update out
            # to every connected device-mode agent so they pull the SAME code
            # (the lm repo the agent runs) + restart on their own — closing the
            # "Update button / auto-update reaches the spoke but not its
            # device-mode agents" gap. Fire-and-forget (send_raw_to_agent): the
            # agent's AGENT_UPDATE handler os._exit(3)s on a real update, so it
            # never returns a correlated response (awaiting one would time out);
            # any pre-exit AGENT_RESPONSE is dropped by the AGENT_RESPONSE branch
            # (no pending corr_id), exactly like the VNC down-frame path. The
            # device-mode SpokeClient handles AGENT_UPDATE; a legacy node-agent
            # (BaseControlPlane) has no AGENT_UPDATE branch and ignores it
            # benignly — it's updated as an agent *spoke* via the hub mailbox, not
            # here. Forward the SAME {repo_url, core_repo_url, core_branch} the
            # hub sent: for an agent-hosting spoke these point at the lm repo
            # (update_sources.agent / .hub), which IS the device-mode agent's own
            # repo, so the agent pulls the right thing.
            await self._push_agent_update_to_devices(data)
        result = await super().handle_system_command(cmd_type, data)
        if cmd_type in ("SET_LOG_LEVEL", "SPOKE_SET_LOG_LEVEL"):
            if self.connected_agents:
                await self.broadcast_to_agents("SET_LOG_LEVEL", data)
        return result

    async def _push_agent_update_to_devices(self, update_data: Dict[str, Any]) -> None:
        """Fan an ``AGENT_UPDATE`` out to every connected device-mode agent so a
        spoke-side update (``SPOKE_UPDATE``) reaches its hosted agents too — each
        pulls its own repo + the shared /opt/lm core, arms its rollback watchdog,
        and ``os._exit(3)``s to reload, symmetric with the spoke's own
        ``SPOKE_UPDATE``. Fire-and-forget (see the SPOKE_UPDATE intercept above
        for why we don't await a response). Best-effort: a gone/erroring agent is
        skipped, never fatal — the agent's own code-drift watchdog + reconnect
        self-heal cover a missed delivery."""
        if not self.connected_agents:
            return
        payload = {
            "repo_url": update_data.get("repo_url"),
            "core_repo_url": update_data.get("core_repo_url"),
            "core_branch": update_data.get("core_branch"),
        }
        if not payload["repo_url"]:
            # Nothing to forward (hub didn't thread a repo_url) — leave the
            # agents on their current code; the next SPOKE_UPDATE carries it.
            return
        for aid in list(self.connected_agents):
            try:
                await self.send_raw_to_agent(aid, "AGENT_UPDATE", payload)
                logger.info("AGENT_UPDATE forwarded to device-mode agent '%s'", aid)
            except Exception as e:  # noqa: BLE001 — never let one agent break the fan-out
                logger.debug("AGENT_UPDATE forward to '%s' failed: %s", aid, e)

    # ── Agent WebSocket server ──────────────────────────────────────────────

    def _agent_listener_tls_paths(self):
        """Return the ``(cert, key)`` paths the ``/ws/agent`` listener should
        present. Resolution order:

        1. ``LM_TLS_CERT`` / ``LM_TLS_KEY`` env — what the installer / hub
           cert-distribution provisions on cert-capable spokes.
        2. **On-disk LE fallback** — the box's own Let's Encrypt cert, which the
           co-located ``le`` role obtains and renews in certbot's native layout
           (``$LM_LE_LIVE_DIR`` / ``/etc/letsencrypt/live/<domain>/``). The
           agent-hosting control plane is NOT in ``CERT_CAPABLE_MODULES``, so the
           WebUI cert-distribution never wires ``LM_TLS_CERT`` for it; without
           this fallback the listener drops to the plaintext (cert-less) port,
           which a locked-down NSG (443-only) blocks. See
           ``_discover_le_listener_cert``.

        Returns ``('', '')`` when neither is available → ``run_agent_server``
        falls back to plaintext (legacy/cert-less)."""
        cert = os.environ.get("LM_TLS_CERT", "").strip()
        key = os.environ.get("LM_TLS_KEY", "").strip()
        if cert and key:
            return cert, key
        return self._discover_le_listener_cert()

    def _discover_le_listener_cert(self):
        """Best-effort discovery of an on-disk Let's Encrypt cert to serve on the
        ``/ws/agent`` listener. Returns ``(fullchain, privkey)`` only when BOTH
        files exist and are readable, else ``('', '')``.

        Candidate selection (deterministic, so a renew never silently flips which
        cert is served): an explicit ``LM_AGENT_LISTENER_LE_DOMAIN`` wins; else
        rank live-cert dirs by exact-FQDN match > wildcard covering this host's
        domain > most-recently-renewed. The downstream agent→spoke leg is
        TLS-unverified (same as the spoke→hub leg), so a hostname-mismatched but
        valid cert still upgrades the listener from plaintext ``ws`` to ``wss``."""
        live_dir = os.environ.get("LM_LE_LIVE_DIR", "/etc/letsencrypt/live").strip()
        if not live_dir or not os.path.isdir(live_dir):
            return "", ""

        def _pair(name):
            d = os.path.join(live_dir, name)
            fc = os.path.join(d, "fullchain.pem")
            pk = os.path.join(d, "privkey.pem")
            if (os.path.isfile(fc) and os.path.isfile(pk)
                    and os.access(fc, os.R_OK) and os.access(pk, os.R_OK)):
                return fc, pk
            return "", ""

        override = os.environ.get("LM_AGENT_LISTENER_LE_DOMAIN", "").strip()
        if override:
            fc, pk = _pair(override)
            if fc:
                logger.info("Agent listener using LE cert for %s (LM_AGENT_LISTENER_LE_DOMAIN)", override)
            return fc, pk

        try:
            names = [n for n in os.listdir(live_dir)
                     if os.path.isdir(os.path.join(live_dir, n))]
        except OSError:
            return "", ""

        fqdn = socket.getfqdn().lower()

        def _rank(n):
            nl = n.lower()
            exact = (nl == fqdn)
            wild = nl.startswith("*.") and bool(nl[2:]) and fqdn.endswith("." + nl[2:])
            try:
                mtime = os.path.getmtime(os.path.join(live_dir, n, "fullchain.pem"))
            except OSError:
                mtime = 0.0
            return (exact, wild, mtime)

        for name in sorted(names, key=_rank, reverse=True):
            fc, pk = _pair(name)
            if fc:
                logger.info("Agent listener falling back to on-disk LE cert %s (no LM_TLS_CERT configured)", name)
                return fc, pk
        return "", ""

    def _agent_health_process_request(self, connection, request):
        """websockets ``process_request`` hook for the ``/ws/agent`` listener.

        Answers NON-WebSocket requests (health checks, TCP/port scanners, a
        browser hitting the ``wss://…:443`` port) with a plain ``200 OK`` instead
        of letting the library run its upgrade validation, which raises
        ``InvalidUpgrade`` and logs a full-traceback ``opening handshake failed``
        ERROR on EVERY probe — noise that buried real events in the
        agent-listener log.

        ``process_request`` (see ``websockets/server.py``) accepts a request only
        when it carries BOTH ``Upgrade: websocket`` AND a ``Connection`` header
        whose token list contains ``upgrade``; a request missing EITHER is
        rejected — the Connection check runs FIRST, so a benign probe with no
        Connection header ("missing Connection header") or ``Connection: close``
        ("invalid Connection header: close") trips it just as a missing Upgrade
        does. We therefore mirror the library's own acceptance test here: only a
        well-formed upgrade (both headers present) returns ``None`` so the real
        handshake runs unchanged; everything else — every shape of non-WS probe —
        gets a clean 200 and never reaches the noisy validation path. This can't
        suppress a handshake that would otherwise succeed: the library requires
        the exact same two headers, so anything we short-circuit here would have
        failed the handshake anyway."""
        try:
            upgrade = (request.headers.get("Upgrade", "") or "").strip().lower()
        except Exception:  # noqa: BLE001 — duplicate/odd headers → treat as non-WS
            upgrade = ""
        try:
            hdrs = request.headers
            conn_values = hdrs.get_all("Connection") if hasattr(hdrs, "get_all") \
                else [hdrs.get("Connection", "") or ""]
        except Exception:  # noqa: BLE001
            conn_values = []
        conn_has_upgrade = any(
            tok.strip().lower() == "upgrade"
            for value in conn_values for tok in str(value).split(","))
        if upgrade == "websocket" and conn_has_upgrade:
            return None
        return connection.respond(HTTPStatus.OK, "OK\n")

    async def run_agent_server(self):
        """Serve the agent listener. Three modes:

        * **Loopback** (``<AGENT_LOOPBACK_ENV>=1``): bind ``127.0.0.1`` only,
          plaintext, on ``<AGENT_PORT_ENV>`` (default ``AGENT_LOOPBACK_PORT``).
          TLS terminates upstream (the hub's ``/ws/agent`` byte-proxy on the
          all-in-one path); the port is NOT advertised externally.
        * **Standalone wss** — a cert is present (``_agent_listener_tls_paths``
          returns one) and loopback is OFF: ``wss`` on
          ``0.0.0.0:<AGENT_PORT_ENV>`` (default ``AGENT_WSS_PORT``); a
          standalone spoke sets it to 443 so agents dial
          ``wss://<spoke>:443/ws/agent`` directly.
        * **Standalone plaintext (legacy / cert-less)** — no cert, loopback OFF:
          ``ws`` on ``0.0.0.0:<AGENT_PORT_ENV>`` (default ``AGENT_FALLBACK_PORT``).

        Retries up to 10× on EADDRINUSE.
        """
        loopback = os.environ.get(self.AGENT_LOOPBACK_ENV, "").strip() in ("1", "true", "True")
        cert, key = self._agent_listener_tls_paths()
        cert = (cert or "").strip()
        key = (key or "").strip()
        if loopback:
            # TLS terminates upstream; the loopback hop is plaintext.
            host = "127.0.0.1"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_LOOPBACK_PORT)))
            serve_kwargs = {}
            scheme = "ws"
        elif cert and key:
            host = "0.0.0.0"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_WSS_PORT)))
            server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ctx.load_cert_chain(cert, key)
            # mTLS (plumbed, default-off): require+verify a client cert only when
            # LM_MTLS_ENABLED + a CA is configured. No-op otherwise.
            try:
                from security.mtls import apply_server_client_auth
                apply_server_client_auth(server_ctx)
            except Exception:  # noqa: BLE001
                pass
            serve_kwargs = {"ssl": server_ctx}
            scheme = "wss"
        else:
            host = "0.0.0.0"
            port = int(os.environ.get(self.AGENT_PORT_ENV, str(self.AGENT_FALLBACK_PORT)))
            serve_kwargs = {}
            scheme = "ws"
        for attempt in range(10):
            try:
                # Websocket keepalive on the /ws/agent server: use the same
                # 30s/90s (env-overridable) the hub<->spoke leg uses, NOT the
                # websockets library default 20s/20s. A long synchronous agent
                # command (qm clone, RUN_COMMAND) can block the agent's event
                # loop past 20s; the default ping_timeout would then tear down
                # the agent WS and kill every in-flight VNC console session
                # sharing that loop — the ~15s VNC stall.
                serve_kwargs["ping_interval"] = _ws_keepalive_env("LM_WS_PING_INTERVAL_S", 30.0)
                serve_kwargs["ping_timeout"] = _ws_keepalive_env("LM_WS_PING_TIMEOUT_S", 90.0)
                # Answer non-WebSocket probes (health checks, port scanners,
                # browsers) with a plain 200 instead of a logged InvalidUpgrade
                # "opening handshake failed" traceback on every hit.
                serve_kwargs["process_request"] = self._agent_health_process_request
                async with websockets.serve(
                    self._ws_dispatch, host, port, **serve_kwargs,
                ):
                    logger.info(f"Agent listener on {scheme}://{host}:{port}")
                    await asyncio.Future()
                return
            except OSError as e:
                # errno 98 = address in use (Linux), errno 48 = macOS equivalent
                if e.errno in (98, 48) and attempt < 9:
                    logger.warning(f"Port {port} in use, retrying in 3s (attempt {attempt + 1}/10)…")
                    await asyncio.sleep(3)
                else:
                    logger.error(f"Agent server failed to bind to port {port}: {e}")
                    raise
            except Exception as e:
                logger.error(f"Agent server unexpected error: {e}", exc_info=True)
                raise

    def _start_agent_server_task(self) -> None:
        """Create the self-healing agent-server task (caller invokes this from
        ``run()`` only when ``_agent_listener_enabled()`` is True). Stores a
        strong reference on ``self._agent_server_task`` so the loop does not
        garbage-collect it mid-flight."""

        async def _run_agent_server_logged():
            # Self-heal: if the agent listener ever exits (e.g. its serve task is
            # GC'd and raises "coroutine ignored GeneratorExit"), restart it after
            # a short backoff instead of leaving the port dark until a unit restart.
            while True:
                try:
                    await self.run_agent_server()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Agent server exited: {e} — restarting in 5s", exc_info=True)
                    await asyncio.sleep(5)

        self._agent_server_task = asyncio.create_task(_run_agent_server_logged())

    async def _rebind_agent_server(self) -> None:
        """Stop the current ``/ws/agent`` listener and start a fresh one so it
        picks up a newly-applied TLS cert (mirrors the cs 8080-webui
        ``_rebind_api_server``). ``run_agent_server`` reads the cert at
        serve-start, so a cert renewed mid-run isn't served until the listener
        restarts. Connected agents drop and reconnect — the spoke re-onboards
        them on reconnect (agent_id is stable), so this is safe during a cert
        renew. No-op when the listener isn't running or isn't enabled."""
        old = self._agent_server_task
        if old is not None and not old.done():
            old.cancel()
            try:
                await old
            except (asyncio.CancelledError, Exception):
                pass
            self._agent_server_task = None
        if self._agent_listener_enabled():
            logger.info("Re-binding /ws/agent listener to serve the new TLS cert")
            self._start_agent_server_task()

    # ── Pending approval / revocation ───────────────────────────────────────

    def _ensure_agent_secret(self) -> None:
        """Mint + persist an agent onboarding secret when the agent listener is
        enabled but ``AGENT_CONFIG_PATH`` provided none.

        The installer writes ``agent_secret`` at install time, but the listener
        can come up at RUNTIME without that step having run — e.g. a standalone
        cs/pxmx spoke whose ``/ws/agent`` listener now defaults ON, installed
        (or upgraded) before the secret step, or with the listener flag toggled
        on later. With no secret, ``approve_pending_agent`` has nothing to
        provision, so every hosted (zero-touch) agent gets ``{"secret": null}``,
        skips saving it, reconnects unauthenticated and flaps in
        "pending / needs admin approval" FOREVER — the classic "approve → back
        to pending" symptom. Mirrors ``HubSelfControlPlane``'s mint-on-missing.

        Persisted (0600) to ``AGENT_CONFIG_PATH`` so it is STABLE across spoke
        restarts: an in-memory-only secret would break an already-approved agent
        on the next restart (the agent saved the minted secret; a fresh mint
        would no longer match and bounce it back to pending). Best-effort — a
        persist failure still sets the in-process secret so the immediate
        approval succeeds. Idempotent: a no-op once a secret exists."""
        if self.agent_secret:
            return
        self.agent_secret = secrets.token_hex(32)
        self.agent_signer = MessageSigner(self.agent_secret)
        cfg = self.config if isinstance(getattr(self, "config", None), dict) else {}
        cfg["agent_secret"] = self.agent_secret
        self.config = cfg
        path = self.AGENT_CONFIG_PATH
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(cfg, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            logger.info(
                "agent_secret was missing — minted + persisted a new one to %s "
                "(the listener was enabled without an installer-provisioned "
                "secret; hosted agents can now be approved)", path)
        except Exception as e:  # noqa: BLE001 — in-memory secret still lets this approval succeed
            logger.error(
                "agent_secret was missing — minted one in-memory but could NOT "
                "persist it to %s (%s); it will not survive a spoke restart, so "
                "re-run the installer's agent-secret step for a stable secret",
                path, e)

    async def approve_pending_agent(self, agent_id: str):
        """Called when the LM hub approves a pending agent. Sends the
        provisioned secret (this spoke's ``agent_secret``) so the agent can
        reconnect authenticated + sign its frames."""
        logger.info(
            "approve_pending_agent: ENTER agent=%r — pending_agents=%s "
            "connected_agents=%s have_agent_secret=%s",
            agent_id, list(self.pending_agents.keys()),
            list(self.connected_agents.keys()), bool(self.agent_secret))
        pending = self.pending_agents.get(agent_id)
        if not pending:
            logger.warning(
                "Approval for unknown/already-connected agent %r — no matching "
                "pending entry. pending_agents=%s connected_agents=%s. If the "
                "relayed target name differs from a pending key, the hub sent a "
                "mismatched target_agent_id (agent registered under a different "
                "id than the hub's _agent_relay_name), so the pending agent "
                "never gets its secret and stays offline.",
                agent_id, list(self.pending_agents.keys()),
                list(self.connected_agents.keys()))
            return
        # A falsy agent_secret here is the silent "approve → straight back to
        # pending/offline" flap: the node-agent only saves a TRUTHY provisioned
        # secret (pxmx agent _save_secret), so a {"secret": null} APPROVED makes
        # it reconnect zero-touch → re-enter APPROVAL_REQUIRED forever. This
        # happens on a generic/unified agent whose agent-hosting role
        # (proxmox/simulation) has no install-written /etc/lm-agent/config.json.
        # Self-heal by provisioning one now via the role's _ensure_agent_secret
        # hook (RoleConnection); if we STILL have nothing, refuse rather than
        # ship a null secret that can only loop.
        if not self.agent_secret:
            ensure = getattr(self, "_ensure_agent_secret", None)
            logger.info(
                "approve_pending_agent(%r): no agent_secret yet — attempting "
                "self-heal via _ensure_agent_secret (callable=%s)",
                agent_id, callable(ensure))
            if callable(ensure):
                try:
                    ensure()
                    logger.info(
                        "approve_pending_agent(%r): _ensure_agent_secret ran — "
                        "agent_secret now %s", agent_id,
                        "present" if self.agent_secret else "STILL MISSING")
                except Exception as e:  # noqa: BLE001
                    logger.error(
                        f"approve_pending_agent('{agent_id}'): _ensure_agent_secret "
                        f"failed: {e}")
        if not self.agent_secret:
            logger.error(
                f"Cannot approve agent '{agent_id}': this spoke has no agent_secret "
                "to provision — the agent would reconnect unauthenticated and "
                "re-enter pending (the 'approve → offline' flap). Ensure the "
                "/ws/agent listener owns a secret (/etc/lm-agent/config.json).")
            return
        try:
            await pending["ws"].send(json.dumps({
                "status": "APPROVED",
                "secret": self.agent_secret,
            }))
            logger.info(f"Agent '{agent_id}' approved — secret provisioned")
            pending["event"].set()
        except Exception as e:
            logger.error(f"Failed to deliver approval to agent '{agent_id}': {e}")

    async def revoke_agent(self, agent_id: str):
        """Disconnect a connected or pending agent — it will auto-heal and
        re-enter pending."""
        agent = self.connected_agents.get(agent_id)
        if agent:
            try:
                await agent["ws"].close(1008, "Revoked by admin")
            except Exception:
                pass
            self.connected_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' revoked (was connected)")
            return
        pending = self.pending_agents.get(agent_id)
        if pending:
            try:
                await pending["ws"].close(1008, "Revoked by admin")
            except Exception:
                pass
            pending["event"].set()
            self.pending_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' revoked (was pending)")
            return
        logger.warning(f"Revoke requested for unknown agent '{agent_id}'")

    # ── WS path dispatch (agent listener + edge-proxy console relay) ─────────

    async def _ws_dispatch(self, websocket, path=None):
        """Route by path on the shared agent-listener server: an edge proxy dials
        ``/ws/console-relay/{session_id}`` (Phase 2), everything else is the agent
        on ``/ws/agent``. Keeps the console relay off the agent's PSK path."""
        if path is None:
            path = getattr(websocket, "path", None) or getattr(
                getattr(websocket, "request", None), "path", None)
        if path and path.startswith("/ws/console-relay/"):
            return await self._console_relay_handler(websocket, path)
        return await self._agent_handler(websocket, path)

    # ── Edge-proxy console relay (Phase 2) ──────────────────────────────────

    def _console_relay_state(self):
        """Lazily-init per-session relay registries (mixin has no __init__ hook).
        tokens: session_id → {token, agent_id, kind}; sinks: session_id → proxy ws."""
        if not hasattr(self, "_console_relay_tokens"):
            self._console_relay_tokens = {}
        if not hasattr(self, "_console_relay_sinks"):
            self._console_relay_sinks = {}
        return self._console_relay_tokens, self._console_relay_sinks

    def register_console_relay(self, session_id: str, relay_token: str,
                               agent_id: str, kind: str = "vnc",
                               down_handler=None) -> None:
        """Called by the spoke's *_START handler so an edge proxy can later attach
        a per-session relay leg (validated by relay_token).

        DOWN frames go to ``down_handler(cmd, data)`` when given (serial: the
        console spoke writes to its own /dev/tty*), else to the agent via
        ``send_raw_to_agent(agent_id, ...)`` (VNC/shell)."""
        tokens, _ = self._console_relay_state()
        tokens[str(session_id)] = {"token": str(relay_token or ""),
                                   "agent_id": str(agent_id or ""), "kind": kind,
                                   "down_handler": down_handler}

    def unregister_console_relay(self, session_id: str) -> None:
        tokens, sinks = self._console_relay_state()
        tokens.pop(str(session_id), None)
        sinks.pop(str(session_id), None)

    async def _route_console_up(self, msg_type: str, data: Dict[str, Any]) -> bool:
        """If a proxy relay leg owns this session, deliver the UP frame to it and
        return True (hub relay skipped). Otherwise return False → hub relay (the
        existing path). Inert when no sink is registered, so normal console is
        unaffected."""
        _, sinks = self._console_relay_state()
        sid = (data or {}).get("session_id")
        sink = sinks.get(str(sid)) if sid else None
        if sink is None:
            return False
        try:
            await sink.send(json.dumps({"type": msg_type, "data": data}))
            return True
        except Exception:  # noqa: BLE001 — dead proxy leg: drop it, fall back to hub
            sinks.pop(str(sid), None)
            return False

    async def _console_relay_handler(self, websocket, path):
        """Serve an edge proxy's per-session console relay leg. Auth = the
        per-session relay_token minted by the hub at *_START (NOT agent_secret).
        DOWN frames (proxy→Proxmox/PTY) are forwarded to the agent via the existing
        send_raw_to_agent; UP frames are routed here by _route_console_up."""
        session_id = path.rsplit("/", 1)[-1]
        tokens, sinks = self._console_relay_state()
        try:
            auth = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5.0))
        except Exception:  # noqa: BLE001
            await websocket.close(1008, "no auth"); return
        rec = tokens.get(session_id)
        token = (auth or {}).get("relay_token")
        if not rec or not token or not hmac.compare_digest(str(token), str(rec["token"])):
            await websocket.close(1008, "bad relay token"); return
        agent_id = rec.get("agent_id") or ""
        down_handler = rec.get("down_handler")
        await websocket.send(json.dumps({"status": "RELAY_OK"}))
        sinks[session_id] = websocket
        logger.info("Console relay leg attached for session %s (agent %s)", session_id, agent_id)
        try:
            async for raw in websocket:
                try:
                    msg = json.loads(raw if isinstance(raw, str) else raw.decode("utf-8", "replace"))
                except Exception:  # noqa: BLE001
                    continue
                cmd = msg.get("type")
                d = msg.get("data") or {}
                d["session_id"] = session_id
                # DOWN frames: serial uses a down_handler (write to /dev/tty*);
                # VNC/shell forward to the agent exactly as handle_command does.
                if cmd in ("VNC_FRAME_DOWN", "VNC_DISCONNECT",
                           "SHELL_IN", "SHELL_RESIZE", "SHELL_DISCONNECT",
                           "CONSOLE_DATA", "CONSOLE_CLOSE"):
                    if down_handler is not None:
                        try:
                            await down_handler(cmd, d)
                        except Exception as _e:  # noqa: BLE001
                            logger.warning("console relay down_handler error (%s): %s", session_id, _e)
                    elif agent_id:
                        await self.send_raw_to_agent(agent_id, cmd, d)
        except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
            pass
        except Exception as e:  # noqa: BLE001
            logger.warning("console relay leg error (session %s): %s", session_id, e)
        finally:
            if sinks.get(session_id) is websocket:
                sinks.pop(session_id, None)
            logger.info("Console relay leg detached for session %s", session_id)

    # ── Agent connection handler ────────────────────────────────────────────

    async def _agent_handler(self, websocket, path=None):
        agent_id = None
        try:
            # 0. Path enforcement — an agent dials ``/ws/agent`` (the hub proxies
            # /ws/agent to this listener on the all-in-one loopback path; a
            # standalone spoke serves /ws/agent directly on 443). Reject any
            # other path so this listener is never reached via a stray URL.
            # ``path`` is the 3rd arg on older websockets; newer versions drop it
            # from the handler sig → read ``websocket.path`` (or
            # ``websocket.request.path``).
            if path is None:
                path = getattr(websocket, "path", None) or getattr(
                    getattr(websocket, "request", None), "path", None)
            if path != "/ws/agent":
                logger.warning(f"Agent handler rejecting unexpected path: {path!r}")
                await websocket.close(1008, "unexpected path")
                return

            # 1. Auth
            auth = json.loads(await websocket.recv())
            agent_id     = auth.get("agent_id")
            agent_secret = auth.get("secret")
            # Stable install UUID + current OS hostname (sent by the agent on
            # every connect) so the hub can detect a clone-and-rename and carry
            # over per-agent config. Captured here and relayed up on every
            # AGENT_RELAY_UP frame via _relay_agent_msg_up.
            agent_install_uuid = (auth.get("install_uuid") or "").strip()
            agent_hostname     = (auth.get("hostname") or "").strip()
            # Optional zero-touch onboarding credential (pxmx install_agent.sh
            # --onboarding-psk / --tenant-hint). Only meaningful pre-approval —
            # relayed to the hub below so it can validate the PSK against the
            # hinted tenant's onboarding-key store and auto-approve without an
            # admin click. Never logged.
            onboarding_psk = auth.get("onboarding_psk") or ""
            tenant_hint    = (auth.get("tenant_hint") or "").strip()

            if not agent_id:
                await websocket.close(1008, "Missing agent_id"); return

            # ── Zero-touch / pending-approval path ───────────────────────────
            if not agent_secret:
                logger.info(
                    "Agent '%s' connected without credentials — pending approval "
                    "(pending_agents key=%r hostname=%r install_uuid=%r). The hub "
                    "must relay APPROVAL_SUCCESS with target_agent_id matching "
                    "this key to provision it.",
                    agent_id, agent_id, agent_hostname, agent_install_uuid)
                event = asyncio.Event()
                self.pending_agents[agent_id] = {"ws": websocket, "event": event}
                await websocket.send(json.dumps({"status": "APPROVAL_REQUIRED"}))
                if onboarding_psk and tenant_hint:
                    # Fire-and-forget: the hub validates + (on match) pushes
                    # APPROVAL_SUCCESS back down the normal SPOKE_RELAY path,
                    # same as an admin-triggered approval. A send failure or an
                    # invalid/missing PSK just leaves the agent pending for
                    # manual approval — never breaks the keepalive loop below.
                    try:
                        await self.send_to_hub("AGENT_ONBOARDING_PSK", {
                            "agent_id": agent_id, "psk": onboarding_psk,
                            "tenant_hint": tenant_hint,
                            "hostname": agent_hostname,
                            "install_uuid": agent_install_uuid,
                        })
                    except Exception as e:  # noqa: BLE001
                        logger.warning(
                            "Failed to relay onboarding PSK for agent '%s': %s",
                            agent_id, e)
                try:
                    # Keep connection alive (heartbeats only) until approved/disconnected
                    while not event.is_set():
                        try:
                            # Drain frames to keep the socket alive until approved.
                            # A pending agent may send signed ``<sig>.<body>``
                            # heartbeats; we don't process anything while pending,
                            # so don't parse (a decode error must NOT break the
                            # keepalive loop and bounce the pending agent).
                            await asyncio.wait_for(websocket.recv(), timeout=10.0)
                        except asyncio.TimeoutError:
                            pass
                except Exception:
                    pass
                finally:
                    self.pending_agents.pop(agent_id, None)
                    if not event.is_set():
                        logger.info(f"Pending agent '{agent_id}' disconnected before approval")
                return

            # ── Authenticated path ────────────────────────────────────────────
            if not self.agent_secret or not hmac.compare_digest(str(agent_secret), str(self.agent_secret)):
                logger.warning(f"Agent '{agent_id}' auth failed — bad secret")
                await websocket.close(1008, "Auth failed"); return

            # 2. Mutual auth
            await websocket.send(json.dumps({"status": "HUB_VERIFIED"}))
            ack = json.loads(await asyncio.wait_for(websocket.recv(), timeout=5.0))
            if ack.get("status") != "HUB_OK":
                await websocket.close(1008, "Agent failed mutual auth"); return

            logger.info(f"Agent '{agent_id}' connected")
            self.connected_agents[agent_id] = {
                "ws":           websocket,
                "hostname":     agent_hostname or agent_id,
                "cluster_name": agent_id,   # overwritten by telemetry (pxmx)
                "install_uuid": agent_install_uuid,
                "last_seen":    time.time(),
                "nodes":        [],
                "vms":          [],
                "agent_metrics": {},
                "version":      "unknown",  # overwritten by AGENT_TELEMETRY
            }

            # Post-register hook (pxmx re-pushes stored PVE credentials).
            await self._on_agent_registered(agent_id)

            # 3. Message loop
            #
            # The agent sends every post-auth frame in the ``<sig>.<body>`` wire
            # form (encode_frame): a hex HMAC over the exact body bytes, a '.',
            # then compact-JSON. A stale spoke that did a bare ``json.loads(raw)``
            # here choked on the ``<sig>.`` prefix ("Expecting value" when the sig
            # began with a-f / "Extra data" when it began with digits) and — since
            # the decode error propagated out of the ``async for`` — tore the whole
            # connection down on the FIRST frame → a tight, no-backoff reconnect
            # flap. Decode the frame the way control_plane._decode_frame and the
            # agent itself do, accept the legacy ``{...}`` dict-envelope for
            # forward/back compat, and treat any undecodable/forged/unsigned frame
            # as a per-frame drop (continue) — never a connection-fatal error.
            async for raw in websocket:
                try:
                    if isinstance(raw, (bytes, bytearray)):
                        raw = raw.decode("utf-8", "replace")
                    if raw[:1] == "{":
                        # Legacy dict-envelope: signature INSIDE the JSON.
                        msg = json.loads(raw)
                        if "signature" not in msg or not self.agent_signer.verify(msg):
                            logger.warning("Invalid agent message signature — dropping")
                            continue
                    else:
                        # Current wire form ``<sig>.<body>``: HMAC over the exact
                        # received body bytes (no re-serialization). The WS is
                        # already authenticated by the shared agent_secret; the
                        # per-frame HMAC is defense-in-depth, so an unsigned or
                        # bad-HMAC frame is dropped (mirrors the old "must be
                        # signed" posture) rather than trusted.
                        sig, body = split_frame(raw)
                        if not sig or not self.agent_signer.verify_bytes(body.encode(), sig):
                            logger.warning("Invalid/unsigned agent frame — dropping")
                            continue
                        msg = json.loads(body)
                except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
                    logger.warning(f"Undecodable agent frame dropped: {e}")
                    continue

                payload  = msg.get("payload", {})
                msg_type = payload.get("type")
                data     = payload.get("data", {})
                corr_id  = msg.get("header", {}).get("correlation_id")

                if msg_type == "AGENT_HEARTBEAT":
                    if agent_id in self.connected_agents:
                        self.connected_agents[agent_id]["last_seen"] = time.time()
                    # Relay up so the hub's HeartbeatManager tracks per-agent
                    # liveness (keyed spoke_id:agent_id) and System → Diagnostics
                    # can render a GREEN/YELLOW/RED heartbeat for the agent like
                    # it does for spokes. Best-effort (see _relay_agent_msg_up).
                    await self._relay_agent_msg_up(agent_id, "AGENT_HEARTBEAT", data)

                elif msg_type == "AGENT_TELEMETRY":
                    rec = self.connected_agents.get(agent_id)
                    if rec is not None:
                        rec["last_seen"] = time.time()
                        rec["hostname"] = data.get("hostname", agent_id)
                        rec["version"] = (data.get("agent_version") or data.get("version")
                                          or rec.get("version", "unknown"))
                    # Hook: pxmx caches nodes/vms/cluster + persists the disk
                    # cache; cs stores minimal fields. Never raises.
                    await self._on_agent_telemetry(agent_id, rec, data)

                elif msg_type == "AGENT_RESPONSE":
                    if corr_id in self.pending_responses:
                        fut = self.pending_responses.pop(corr_id)
                        if not fut.done():
                            fut.set_result(data)

                elif msg_type == "AGENT_PROGRESS":
                    # Keepalive from a busy agent: it's still working on the
                    # command correlated by corr_id. Push the send_to_agent soft
                    # deadline forward (capped at the hard ceiling) so the waiter
                    # doesn't time out on a slow-but-alive agent. Carries no
                    # result — never resolves the future.
                    _pd = self.pending_progress.get(corr_id)
                    if _pd is not None:
                        _pd["soft"] = min(time.time() + _pd["grace"], _pd["hard"])
                        logger.debug("AGENT_PROGRESS keepalive from %s (%s) — "
                                     "deadline extended", agent_id, str(corr_id)[:8])

                elif msg_type == "AGENT_LOG":
                    # Relay to hub so it appears in Setup → Agent Logs.
                    await self._relay_agent_msg_up(agent_id, "AGENT_LOG", data)

                elif msg_type and msg_type.startswith("CS_"):
                    # Relay Client-Simulation events (CS_TELEMETRY / CS_LOG /
                    # CS_WATCHDOG_EVENT / CS_HW_RESET_EVENT / CS_PROGRESS /
                    # CS_COMMAND_RESULT / CS_TOKEN_RESULT) up to the hub, which
                    # dispatches them to the cs spoke via the AGENT_RELAY_UP
                    # CS_* dispatcher. The agent's send_cs_event already injected
                    # hostname + agent_id into ``data`` so the hub can resolve
                    # tenant/host.
                    await self._relay_agent_msg_up(agent_id, msg_type, data)

                elif msg_type and msg_type.startswith("VNC_"):
                    # VNC console frames from the agent (VNC_FRAME_UP / VNC_READY
                    # / VNC_ERROR / VNC_DISCONNECT). Phase 2: if an edge proxy owns
                    # this session, deliver straight to it (hub out of the byte
                    # path); otherwise relay up to the hub's AGENT_RELAY_UP
                    # dispatcher → browser WS (the existing path).
                    if not await self._route_console_up(msg_type, data):
                        await self._relay_agent_msg_up(agent_id, msg_type, data)

                elif msg_type and msg_type.startswith("SHELL_"):
                    # Host-shell (xterm) frames — same edge-proxy short-circuit as
                    # VNC_*, else relay up to the hub → browser shell WS.
                    if not await self._route_console_up(msg_type, data):
                        await self._relay_agent_msg_up(agent_id, msg_type, data)

        except (websockets.exceptions.ConnectionClosed, asyncio.CancelledError):
            # Expected disconnect — the agent rebooted, the network blipped,
            # or the spoke restarted. The finally below removes it from
            # connected_agents + pending_agents and the agent re-registers on
            # reconnect. No traceback for the documented case (was a 60-line
            # ERROR+exc_info dump per disconnect); keep ERROR+exc_info below
            # for genuinely unexpected exceptions.
            pass
        except Exception as e:
            logger.error(f"Agent handler error: {e}", exc_info=True)
        finally:
            if agent_id:
                self.connected_agents.pop(agent_id, None)
                self.pending_agents.pop(agent_id, None)
            logger.info(f"Agent '{agent_id}' disconnected")

    # ── Hub relay ───────────────────────────────────────────────────────────

    async def _relay_agent_msg_up(self, agent_id: str, msg_type: str, data: Dict[str, Any]) -> None:
        """Wrap an agent message into an AGENT_RELAY_UP frame and forward it to
        the hub (best-effort). Shared by the AGENT_LOG / HEARTBEAT / CS_* / VNC_*
        relay branches: the hub's AGENT_RELAY_UP handler logs AGENT_LOG and
        routes CS_* payloads to the cs spoke. Never raises — relay failures
        must not tear down the agent connection."""
        hub_ws = getattr(self, "_hub_ws", None)
        if not hub_ws:
            if msg_type == "AGENT_LOG":
                level = str(data.get("level", "INFO")).upper()
                msg_text = data.get("message", "")
                # Log at the agent record's OWN level, not always WARNING. Logging
                # an agent INFO ("Auth complete", "resolved listener") at WARNING
                # made benign relayed-info show up in Setup → Errors & Warnings and
                # lit the module-status tray dot as if the module were erroring.
                _lvl = {"DEBUG": logging.DEBUG, "INFO": logging.INFO,
                        "WARNING": logging.WARNING, "WARN": logging.WARNING,
                        "ERROR": logging.ERROR, "CRITICAL": logging.CRITICAL,
                        }.get(level, logging.INFO)
                logger.log(_lvl, "[agent:%s no-hub-relay] %s: %s", agent_id, level, msg_text)
            else:
                logger.debug("[agent:%s no-hub-relay] %s dropped", agent_id, msg_type)
            return
        if not self.signer:
            logger.warning(
                "Cannot relay %s from '%s': spoke has no session signer "
                "(hub connection not yet authenticated)", msg_type, agent_id)
            return
        try:
            # Attach the agent's install_uuid + hostname to the relay envelope so
            # the hub can reconcile agent identity (clone-and-rename detection)
            # on every relayed frame, not just telemetry. Sourced from the
            # capture in _agent_handler; falls back to agent_id when absent.
            rec = self.connected_agents.get(agent_id, {})
            relay = {
                "header": {
                    "message_id": str(uuid.uuid4()),
                    "timestamp": time.time(),
                    "sender_id": self.spoke_id,
                    "destination_id": "hub",
                },
                "payload": {
                    "type": "AGENT_RELAY_UP",
                    "data": {
                        "agent_id": agent_id,
                        "install_uuid": rec.get("install_uuid", ""),
                        "hostname": rec.get("hostname", agent_id),
                        "original_payload": {"payload": {"type": msg_type, "data": data}},
                    },
                },
            }
            # Send in the ``<sig>.<body>`` wire form the hub decodes (split_frame
            # + verify the RECEIVED body bytes — main.py handle_connection). The
            # legacy dict-envelope (json.dumps with the signature INSIDE the
            # object) was mis-split by the hub's split_frame on the FIRST '.',
            # which is the header ``timestamp`` float, so json.loads(body) failed
            # and EVERY relayed agent frame (heartbeat/telemetry/CS_*/log) was
            # dropped at the hub — hosted agents stuck "offline" and CS telemetry/
            # logs absent even though the agent↔spoke link was healthy. Mirror
            # control_plane's own spoke→hub sends, which use _encode_frame.
            await hub_ws.send(self._encode_frame(relay))
        except Exception as _e:
            logger.warning("Failed to relay %s from '%s' to hub: %s", msg_type, agent_id, _e)

    # ── Agent command routing ───────────────────────────────────────────────

    async def send_to_agent(self, cmd_type: str, data: Dict[str, Any],
                            agent_id: Optional[str] = None,
                            timeout: float = 15.0) -> Dict[str, Any]:
        """Send a command to a specific agent (by agent_id) or the first
        available one. Returns the agent's response or an error dict.
        ``timeout`` bounds the wait for the agent's correlated response
        (default 15s; pass a longer window for slow ops like qm stop/snapshot).
        """
        if agent_id:
            rec = self.connected_agents.get(agent_id)
            if not rec:
                return {"status": "ERROR", "message": f"Agent '{agent_id}' not connected"}
            ws = rec["ws"]
        else:
            if not self.connected_agents:
                return {"status": "ERROR", "message": "No agents connected"}
            rec = next(iter(self.connected_agents.values()))
            ws = rec["ws"]

        corr_id = str(uuid.uuid4())
        msg = {
            "header": {
                "message_id": corr_id, "correlation_id": corr_id,
                "timestamp": time.time(),
                "sender_id": self.spoke_id, "destination_id": agent_id or "pxmx-agent",
            },
            "payload": {"type": cmd_type, "data": data},
        }
        # Wire form <sig>.<body> (encode_frame): the agent decodes with
        # split_frame + verify_bytes over the body bytes. This was previously a
        # raw ``json.dumps(msg)`` with an in-payload ``signature`` (the old signing
        # scheme) — but the agent's receive loop split_frame's on the FIRST '.',
        # which in raw JSON is the ``time.time()`` timestamp's decimal point, so
        # json.loads saw a truncated body ("Extra data: line 1 column 8 (char 7)")
        # and the agent flapped after every auth. Frame it like the hub↔spoke legs.
        wire = self.agent_signer.encode_frame(msg)

        fut = asyncio.get_running_loop().create_future()
        self.pending_responses[corr_id] = fut
        now = time.time()
        prog = {"soft": now + timeout,
                "hard": now + timeout * self._agent_progress_hard_mult,
                "grace": timeout}
        self.pending_progress[corr_id] = prog
        try:
            await ws.send(wire)
            # Extendable-deadline wait: normally resolves at `soft` (== base
            # timeout). An AGENT_PROGRESS frame for corr_id bumps `soft` forward
            # (see the AGENT_PROGRESS receive branch), so a slow-but-working
            # agent keeps the request alive up to the `hard` ceiling. With no
            # progress this is identical to the old fixed wait_for(timeout).
            while True:
                remaining = min(prog["soft"], prog["hard"]) - time.time()
                if remaining <= 0:
                    raise asyncio.TimeoutError
                try:
                    return await asyncio.wait_for(asyncio.shield(fut), timeout=remaining)
                except asyncio.TimeoutError:
                    # Slice elapsed — re-check the (possibly-extended) deadline
                    # rather than giving up, unless we've hit the hard ceiling.
                    if fut.done():
                        return fut.result()
                    if time.time() >= prog["hard"]:
                        raise
                    continue
        except asyncio.TimeoutError:
            self.pending_responses.pop(corr_id, None)
            self.pending_progress.pop(corr_id, None)
            return {"status": "ERROR", "message": "Agent response timeout"}
        except Exception as e:
            self.pending_responses.pop(corr_id, None)
            self.pending_progress.pop(corr_id, None)
            return {"status": "ERROR", "message": str(e)}
        finally:
            self.pending_progress.pop(corr_id, None)

    async def send_raw_to_agent(self, agent_id: str, cmd_type: str,
                                data: Dict[str, Any]) -> bool:
        """Fire-and-forget signed send to one agent — no response Future, no
        timeout. Used for VNC down-frames + control (VNC_START / VNC_FRAME_DOWN
        / VNC_DISCONNECT) which are high-volume or one-way; the agent's
        AGENT_RESPONSE (if any) is dropped by the ``AGENT_RESPONSE`` branch
        above (no pending corr_id). Returns True on a successful send, False if
        the agent is gone or the send failed. Caller MUST NOT await a result."""
        rec = (self.connected_agents or {}).get(agent_id)
        if not rec or not rec.get("ws"):
            return False
        msg = {
            "header": {
                "message_id": str(uuid.uuid4()), "timestamp": time.time(),
                "sender_id": self.spoke_id, "destination_id": agent_id,
            },
            "payload": {"type": cmd_type, "data": data},
        }
        # Frame form <sig>.<body> (encode_frame) — same fix as send_to_agent; a
        # raw json.dumps here made the agent's split_frame choke on the timestamp
        # float. Used for the high-volume VNC down-frames + control.
        try:
            await rec["ws"].send(self.agent_signer.encode_frame(msg))
            return True
        except Exception as e:
            logger.warning(f"send_raw_to_agent {cmd_type} -> {agent_id} failed: {e}")
            return False

    async def broadcast_to_agents(self, cmd_type: str,
                                  data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fan out a command to every connected agent; collect all results."""
        if not self.connected_agents:
            return []
        # Bound the fan-out so a large agent fleet doesn't open N simultaneous
        # sends (SET_LOG_LEVEL broadcasts to every agent on the Enable-Debug
        # toggle, key rotations broadcast to every agent, etc.).
        sem = asyncio.Semaphore(16)

        async def _one(aid):
            async with sem:
                return await self.send_to_agent(cmd_type, data, agent_id=aid)

        tasks = [_one(aid) for aid in list(self.connected_agents)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for aid, res in zip(self.connected_agents, results):
            if isinstance(res, Exception):
                out.append({"agent_id": aid, "status": "ERROR", "message": str(res)})
            else:
                out.append({"agent_id": aid, **res})
        return out

    # ── Subclass hooks (default no-ops) ──────────────────────────────────────

    async def _on_agent_registered(self, agent_id: str) -> None:
        """Called after a newly-authenticated agent is recorded in
        ``connected_agents``. pxmx overrides to re-push stored PVE credentials."""
        return None

    async def _on_agent_telemetry(self, agent_id: str, rec: Optional[Dict[str, Any]],
                                  data: Dict[str, Any]) -> None:
        """Called for each AGENT_TELEMETRY frame after the generic rec fields
        (last_seen / hostname / version) are updated. pxmx overrides to cache
        nodes/vms/cluster_name/agent_metrics + persist the disk cache + mirror
        into the module telemetry_cache; cs stores minimal fields."""
        return None