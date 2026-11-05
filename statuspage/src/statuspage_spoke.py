"""Status Page role spoke — public, read-only simulation status page for lm.

A ``BaseSpoke`` loaded IN-REPO by the generic agent (``_ROLE_MAP`` repo_url=None,
module_type "statuspage"). It is deployed and bound to ONE tenant, and serves a
public, cloud-provider-style status page (overall banner + per-component status +
90-day uptime history) plus a Clients view whose demo dropdown lets a visitor
trigger a live simulation on a client.

Data flow (hub-brokered — the agent holds NO tenant authority and NO Central
creds):
  - The HUB resolves this sub-spoke's bound tenant and pushes an already-
    tenant-scoped, REDACTED snapshot down as ``STATUS_SNAPSHOT`` (see the hub's
    status-page push loop). This spoke just caches + renders it, and appends the
    component statuses to a local 90-day uptime-history ring.
  - A public demo click POSTs to this spoke's own web server, which relays an
    unsolicited ``STATUS_RUN_DEMO {hostname, scenario}`` up via
    ``self.control_plane.send_to_hub``. The HUB forces the tenant (from the
    sub-spoke binding, never the payload), validates the client, and drives the
    existing ``CS_DEMO_SCENARIO`` machinery (ephemeral, auto-reverts in 120 min).

The web server (its own uvicorn on the spoke's event loop — mirrors the cs
lm-spoke pattern) is started lazily on the first hub frame. TLS is optional: a
cert delivered via the ``le`` role (or configured paths) enables HTTPS on :443;
without one it serves plain HTTP (dev mode).

AUTH: the read-only status page is public. The Clients view + demo endpoint
require the configured status-page clients token (``clients_token`` config or
``LM_STATUS_CLIENTS_TOKEN``).
"""
# asyncio runs the web server task and its shutdown timeout.
import asyncio
# contextlib.suppress swallows the expected CancelledError when force-stopping.
import contextlib
# Standard-library logging (logger defined below).
import logging
# os reads env settings, checks file existence and sets key file permissions.
import os
# time stamps snapshots that arrive without their own timestamp.
import time
# Path builds data and certificate file locations.
from pathlib import Path
# Type hints only; they document the shapes of payloads and results.
from typing import Any, Dict, Optional

# BaseSpoke import path differs between the agent's flat layout and the repo layout.
try:
    from base_spoke import BaseSpoke
# Repo-root layout: import it through the core package.
except ImportError:  # loaded from the repo root / as core package
    from core.src.base_spoke import BaseSpoke

# Unique module names (statuspage_*) so a multi-role agent's sys.modules cache
# can't collide these with a same-named module (`web`/`history`) from another role.
# Flat layout: import sibling modules directly.
try:
    from statuspage_history import UptimeHistory
    from statuspage_web import build_status_app
# Package layout: use relative imports instead.
except ImportError:  # loaded as a package by the agent role loader
    from .statuspage_history import UptimeHistory  # type: ignore
    from .statuspage_web import build_status_app  # type: ignore

# Named logger shared with the history and web modules.
logger = logging.getLogger("StatusPageSpoke")


class StatusPageSpoke(BaseSpoke):
    """Public simulation-status page spoke.

    Commands (hub → spoke):
      STATUS_SNAPSHOT     — redacted, tenant-scoped dashboard/checks/clients data
                            to render (and append to the 90-day uptime history).
      UPDATE_CONFIG       — web port / public hostname / TLS cert paths, tenant
                            display name. Restarts the web server if the bind or
                            cert material changed.
      INSTALL_CERT        — TLS fullchain+key material from the le cert-
                            distribution pipeline (statuspage is a CERT_CAPABLE
                            target); wired into the uvicorn TLS config + re-bind.
                            STATUS_SET_CERT is an equivalent direct alias.
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        """Read bind/TLS/token settings and prepare the snapshot cache and uptime history.

        Args:
            spoke_id: Identifier of this spoke as known to the Hub.
            config: Optional settings; each also has an LM_STATUS_* environment override.
        """
        # Let BaseSpoke store the id/config and do its common setup.
        super().__init__(spoke_id, config)
        # Set by RoleConnection after registration so the web server can push a
        # demo trigger up to the hub (mirrors the console/le pattern).
        self.control_plane = None
        # Event loop the web server runs on; recorded once the server is started.
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        # Treat a missing config as empty.
        cfg = config or {}
        # Bind config (env overrides let a standalone box configure without the
        # hub; the hub can also push these via UPDATE_CONFIG).
        # Listen address/port (default all interfaces on 443), TLS cert/key paths, and the
        # token that guards the Clients view.
        self.web_host = cfg.get("web_host") or os.environ.get("LM_STATUS_HOST", "0.0.0.0")
        self.web_port = int(cfg.get("web_port") or os.environ.get("LM_STATUS_PORT", "443"))
        self.tls_cert = cfg.get("tls_cert") or os.environ.get("LM_STATUS_TLS_CERT") or ""
        self.tls_key = cfg.get("tls_key") or os.environ.get("LM_STATUS_TLS_KEY") or ""
        self.clients_token = cfg.get("clients_token") or os.environ.get("LM_STATUS_CLIENTS_TOKEN") or ""

        # The latest redacted snapshot the hub pushed (what the page renders).
        self._snapshot: Dict[str, Any] = {
            "tenant_name": "", "overall": "unknown", "components": [],
            "clients": [], "scenarios": {}, "generated_at": 0,
        }
        # 90-day uptime history, persisted locally (survives restarts).
        # Folder for the history file; overridable for non-standard installs.
        data_dir = cfg.get("data_dir") or os.environ.get(
            "LM_STATUS_DATA_DIR", "/var/lib/lm/statuspage")
        # Load (or start) the uptime history file in that folder.
        self._history = UptimeHistory(Path(data_dir) / "uptime_history.json")

        # Lazily-started uvicorn server (needs a running loop).
        self._server = None
        self._server_task = None
        self._server_bind = None  # (host, port, cert, key) the running server used

    # ── web server lifecycle ─────────────────────────────────────────────────
    async def _stop_web_server(self) -> None:
        """Gracefully stop the running web server, force-cancelling it after 10 s."""
        # Take local references to the task and server being stopped.
        task = self._server_task
        server = self._server
        # Nothing running (or it already finished): just clear the handle.
        if task is None or task.done():
            self._server_task = None
            return
        # Ask uvicorn to exit cleanly and give it up to 10 s to do so.
        try:
            if server is not None:
                server.should_exit = True
            await asyncio.wait_for(task, timeout=10.0)
        # Shutdown took too long: cancel the task and wait for the cancellation to land.
        except asyncio.TimeoutError:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        # Any other shutdown error is logged quietly; we still clear state below.
        except Exception as e:  # noqa: BLE001
            logger.debug("status page web server shutdown failed: %s", e)
        # Always forget the old server so a fresh one can be started.
        finally:
            self._server_task = None
            self._server = None
            self._server_bind = None

    async def _ensure_web_server(self) -> None:
        """Start the public web server once we're on the event loop. Re-binds if
        the host/port/cert changed (UPDATE_CONFIG / cert delivery)."""
        # Remember the loop the server runs on.
        self._loop = asyncio.get_event_loop()
        # The settings the server should currently be using.
        bind = (self.web_host, self.web_port, self.tls_cert, self.tls_key)
        # If a server is already running, keep it when its settings match, else stop it.
        if self._server_task is not None and not self._server_task.done():
            if bind == self._server_bind:
                return  # already serving the right bind
            await self._stop_web_server()

        # uvicorn is imported lazily; without it the page simply cannot be served.
        try:
            import uvicorn
        # uvicorn not installed: log the problem and keep the spoke running without a page.
        except Exception as e:  # noqa: BLE001
            logger.error("uvicorn missing — status page cannot serve: %s", e)
            return

        # Build the FastAPI app for this spoke.
        app = build_status_app(self)
        # Use HTTPS only when both cert and key paths are set and the files exist.
        tls = {}
        if self.tls_cert and self.tls_key and os.path.exists(self.tls_cert) and os.path.exists(self.tls_key):
            tls = {"ssl_certfile": self.tls_cert, "ssl_keyfile": self.tls_key}
            scheme = "https"
        # No usable certificate: serve plain HTTP (dev mode).
        else:
            scheme = "http"
        # Start uvicorn as a background task; startup errors are logged rather than raised.
        try:
            # log_config=None keeps uvicorn from replacing our logging setup.
            config = uvicorn.Config(app, host=self.web_host, port=self.web_port,
                                    log_config=None, **tls)
            # Create the server and run it as a task on this event loop.
            self._server = uvicorn.Server(config)
            self._server_task = asyncio.create_task(self._server.serve())
            # Record the settings this server is using, then announce where it is listening.
            self._server_bind = bind
            logger.info("Status page serving on %s://%s:%d (tenant=%s)",
                        scheme, self.web_host, self.web_port,
                        self._snapshot.get("tenant_name") or "?")
        # Bad port, permission denied, invalid cert, etc.: log and keep the spoke alive.
        except Exception as e:  # noqa: BLE001
            logger.error("status page web server failed to start: %s", e)

    # ── command dispatch (hub → spoke) ───────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch one Hub command (snapshot, config or certificate delivery).

        Args:
            command_type: Command name (case-insensitive).
            data: Command payload from the Hub.

        Returns:
            A result dict with a "status" key.
        """
        # Every Hub frame doubles as the trigger to start the web server lazily.
        await self._ensure_web_server()
        # Normalise the command name and payload so None values are safe.
        cmd = (command_type or "").upper()
        data = data or {}
        # Hub pushed fresh status data to render.
        if cmd == "STATUS_SNAPSHOT":
            return self._apply_snapshot(data)
        # Hub pushed new bind/TLS/token settings.
        if cmd == "UPDATE_CONFIG":
            return await self._apply_config(data)
        # INSTALL_CERT is what the le cert-distribution pipeline pushes to every
        # cert-capable target (statuspage is registered in CERT_CAPABLE_MODULES);
        # STATUS_SET_CERT is an equivalent direct alias. Both carry
        # {fullchain, privkey} which _apply_cert wires into the uvicorn TLS bind.
        if cmd in ("INSTALL_CERT", "STATUS_SET_CERT"):
            return await self._apply_cert(data)
        # Any other command is not something this module understands.
        return {"status": "ERROR", "message": f"unknown command {command_type}"}

    def _apply_snapshot(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Cache the hub's redacted snapshot + fold component statuses into the
        90-day history. The snapshot is already tenant-scoped + redacted hub-side
        — this spoke never sees creds, spoke ids, VM ids, or raw counts."""
        # Store only the expected fields, with safe defaults for anything missing.
        self._snapshot = {
            "tenant_name": str(data.get("tenant_name") or ""),
            "overall": str(data.get("overall") or "unknown"),
            "components": data.get("components") or [],
            "clients": data.get("clients") or [],
            "scenarios": data.get("scenarios") or {},
            "generated_at": data.get("generated_at") or int(time.time()),
        }
        # Append statuses to the uptime history; a history error must not reject the snapshot.
        try:
            self._history.record(self._snapshot["components"])
        # History problems are logged quietly; the page still shows the new snapshot.
        except Exception as e:  # noqa: BLE001
            logger.debug("history record failed: %s", e)
        return {"status": "SUCCESS"}

    async def _apply_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply settings pushed by the Hub and re-bind the web server if anything changed.

        Args:
            data: Any of web_host, web_port, tls_cert, tls_key, clients_token.

        Returns:
            SUCCESS plus "rebound" telling whether the server was restarted.
        """
        # Tracks whether any setting actually changed.
        changed = False
        # Copy each supplied string setting onto the spoke, noting real changes.
        for key, attr in (("web_host", "web_host"), ("tls_cert", "tls_cert"),
                          ("tls_key", "tls_key"), ("clients_token", "clients_token")):
            if key in data and data[key] is not None and getattr(self, attr) != data[key]:
                setattr(self, attr, data[key]); changed = True
        # Port is handled separately because it must be converted to int.
        if data.get("web_port") is not None and int(data["web_port"]) != self.web_port:
            self.web_port = int(data["web_port"]); changed = True
        # Only restart the web server when something changed.
        if changed:
            await self._ensure_web_server()  # re-bind
        return {"status": "SUCCESS", "rebound": changed}

    async def _apply_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist delivered TLS material (le role) and re-bind HTTPS."""
        # Accept either le-style (fullchain/privkey) or plain (cert/key) field names.
        cert_pem = data.get("fullchain") or data.get("cert")
        key_pem = data.get("privkey") or data.get("key")
        # Both halves are required.
        if not (cert_pem and key_pem):
            return {"status": "ERROR", "message": "missing cert material"}
        # Certificates live in a tls/ folder under the data directory.
        cert_dir = Path(os.environ.get("LM_STATUS_DATA_DIR", "/var/lib/lm/statuspage")) / "tls"
        # Any file error is returned to the Hub as an ERROR result.
        try:
            # Create the folder and write both PEM files.
            cert_dir.mkdir(parents=True, exist_ok=True)
            cp, kp = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
            cp.write_text(cert_pem); kp.write_text(key_pem)
            # Make the private key readable only by the owner.
            os.chmod(kp, 0o600)
            # Point the spoke at the new files and restart the server with HTTPS.
            self.tls_cert, self.tls_key = str(cp), str(kp)
            await self._ensure_web_server()  # re-bind HTTPS
            return {"status": "SUCCESS"}
        # Disk or permission error: report it back to the Hub.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}

    # ── read accessors for the web layer ─────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        """Return the latest cached snapshot for the web layer."""
        return self._snapshot

    def uptime_bars(self) -> Dict[str, Any]:
        """Per-component 90-day daily uptime buckets for the history bars."""
        return self._history.bars()

    async def trigger_demo(self, hostname: str, scenario: str) -> Dict[str, Any]:
        """Relay a public demo click to the hub (fire-and-forget). The HUB forces
        the tenant + validates the client; this spoke supplies only hostname +
        scenario. Reconciliation is via the next STATUS_SNAPSHOT."""
        cp = self.control_plane
        # Without a Hub connection there is nowhere to send the demo request.
        if cp is None:
            return {"status": "ERROR", "message": "not connected to hub"}
        # Send an unsolicited STATUS_RUN_DEMO message to the Hub; failures become ERROR results.
        try:
            await cp.send_to_hub("STATUS_RUN_DEMO",
                                 {"hostname": hostname, "scenario": scenario})
            return {"status": "SUCCESS", "relayed": True}
        # Connection dropped or send failed: tell the web caller.
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}

    async def get_status(self) -> Dict[str, Any]:
        """Return a health summary for the Hub (role, tenant, counts, serving state, TLS)."""
        # Make sure the web server is up, then report on it and the cached snapshot.
        await self._ensure_web_server()
        snap = self._snapshot
        return {
            "role": "statuspage",
            "tenant_name": snap.get("tenant_name"),
            "overall": snap.get("overall"),
            "component_count": len(snap.get("components") or []),
            "client_count": len(snap.get("clients") or []),
            "serving": bool(self._server_task and not self._server_task.done()),
            "port": self.web_port,
            "tls": bool(self.tls_cert and self.tls_key),
            "last_snapshot": snap.get("generated_at"),
        }

    def get_version(self) -> str:
        """Return this module's version from its VERSION file, or "0.0.0" if unavailable."""
        # Read the VERSION file two directories up if it exists.
        try:
            vp = Path(__file__).resolve().parent.parent / "VERSION"
            if vp.exists():
                return vp.read_text().strip()
        # Unreadable file: fall back to the default version below.
        except Exception:  # noqa: BLE001
            pass
        # No VERSION file found.
        return "0.0.0"
