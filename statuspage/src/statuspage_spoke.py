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

AUTH: in dev mode both views are open. The Clients view + demo endpoint sit
behind a single auth SEAM (``web.require_clients_access``) that is a no-op today
so switching auth on later is a one-line change, not a re-plumb.
"""
import asyncio
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from base_spoke import BaseSpoke
except ImportError:  # loaded from the repo root / as core package
    from core.src.base_spoke import BaseSpoke

try:
    from history import UptimeHistory
    from web import build_status_app
except ImportError:  # loaded as a package by the agent role loader
    from .history import UptimeHistory  # type: ignore
    from .web import build_status_app  # type: ignore

logger = logging.getLogger("StatusPageSpoke")


class StatusPageSpoke(BaseSpoke):
    """Public simulation-status page spoke.

    Commands (hub → spoke):
      STATUS_SNAPSHOT     — redacted, tenant-scoped dashboard/checks/clients data
                            to render (and append to the 90-day uptime history).
      UPDATE_CONFIG       — web port / public hostname / TLS cert paths, tenant
                            display name. Restarts the web server if the bind or
                            cert material changed.
      STATUS_SET_CERT     — TLS fullchain+key material (le-role delivery); wired
                            into the uvicorn TLS config and the server restarted.
    """

    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        # Set by RoleConnection after registration so the web server can push a
        # demo trigger up to the hub (mirrors the console/le pattern).
        self.control_plane = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        cfg = config or {}
        # Bind config (env overrides let a standalone box configure without the
        # hub; the hub can also push these via UPDATE_CONFIG).
        self.web_host = cfg.get("web_host") or os.environ.get("LM_STATUS_HOST", "0.0.0.0")
        self.web_port = int(cfg.get("web_port") or os.environ.get("LM_STATUS_PORT", "443"))
        self.tls_cert = cfg.get("tls_cert") or os.environ.get("LM_STATUS_TLS_CERT") or ""
        self.tls_key = cfg.get("tls_key") or os.environ.get("LM_STATUS_TLS_KEY") or ""

        # The latest redacted snapshot the hub pushed (what the page renders).
        self._snapshot: Dict[str, Any] = {
            "tenant_name": "", "overall": "unknown", "components": [],
            "clients": [], "scenarios": {}, "generated_at": 0,
        }
        # 90-day uptime history, persisted locally (survives restarts).
        data_dir = cfg.get("data_dir") or os.environ.get(
            "LM_STATUS_DATA_DIR", "/var/lib/lm/statuspage")
        self._history = UptimeHistory(Path(data_dir) / "uptime_history.json")

        # Lazily-started uvicorn server (needs a running loop).
        self._server = None
        self._server_task = None
        self._server_bind = None  # (host, port, cert, key) the running server used

    # ── web server lifecycle ─────────────────────────────────────────────────
    def _ensure_web_server(self) -> None:
        """Start the public web server once we're on the event loop. Re-binds if
        the host/port/cert changed (UPDATE_CONFIG / cert delivery)."""
        self._loop = asyncio.get_event_loop()
        bind = (self.web_host, self.web_port, self.tls_cert, self.tls_key)
        if self._server_task is not None and not self._server_task.done():
            if bind == self._server_bind:
                return  # already serving the right bind
            # Bind changed — tear the old server down and re-create below.
            try:
                self._server.should_exit = True
            except Exception:  # noqa: BLE001
                pass
            self._server_task = None

        try:
            import uvicorn
        except Exception as e:  # noqa: BLE001
            logger.error("uvicorn missing — status page cannot serve: %s", e)
            return

        app = build_status_app(self)
        tls = {}
        if self.tls_cert and self.tls_key and os.path.exists(self.tls_cert) and os.path.exists(self.tls_key):
            tls = {"ssl_certfile": self.tls_cert, "ssl_keyfile": self.tls_key}
            scheme = "https"
        else:
            scheme = "http"
        try:
            config = uvicorn.Config(app, host=self.web_host, port=self.web_port,
                                    log_config=None, **tls)
            self._server = uvicorn.Server(config)
            self._server_task = asyncio.create_task(self._server.serve())
            self._server_bind = bind
            logger.info("Status page serving on %s://%s:%d (tenant=%s)",
                        scheme, self.web_host, self.web_port,
                        self._snapshot.get("tenant_name") or "?")
        except Exception as e:  # noqa: BLE001
            logger.error("status page web server failed to start: %s", e)

    # ── command dispatch (hub → spoke) ───────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_web_server()
        cmd = (command_type or "").upper()
        data = data or {}
        if cmd == "STATUS_SNAPSHOT":
            return self._apply_snapshot(data)
        if cmd == "UPDATE_CONFIG":
            return self._apply_config(data)
        if cmd == "STATUS_SET_CERT":
            return self._apply_cert(data)
        return {"status": "ERROR", "message": f"unknown command {command_type}"}

    def _apply_snapshot(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Cache the hub's redacted snapshot + fold component statuses into the
        90-day history. The snapshot is already tenant-scoped + redacted hub-side
        — this spoke never sees creds, spoke ids, VM ids, or raw counts."""
        self._snapshot = {
            "tenant_name": str(data.get("tenant_name") or ""),
            "overall": str(data.get("overall") or "unknown"),
            "components": data.get("components") or [],
            "clients": data.get("clients") or [],
            "scenarios": data.get("scenarios") or {},
            "generated_at": data.get("generated_at") or int(time.time()),
        }
        try:
            self._history.record(self._snapshot["components"])
        except Exception as e:  # noqa: BLE001
            logger.debug("history record failed: %s", e)
        return {"status": "SUCCESS"}

    def _apply_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        changed = False
        for key, attr in (("web_host", "web_host"), ("tls_cert", "tls_cert"),
                          ("tls_key", "tls_key")):
            if key in data and data[key] is not None and getattr(self, attr) != data[key]:
                setattr(self, attr, data[key]); changed = True
        if data.get("web_port") is not None and int(data["web_port"]) != self.web_port:
            self.web_port = int(data["web_port"]); changed = True
        if changed:
            self._ensure_web_server()  # re-bind
        return {"status": "SUCCESS", "rebound": changed}

    def _apply_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Persist delivered TLS material (le role) and re-bind HTTPS."""
        cert_pem = data.get("fullchain") or data.get("cert")
        key_pem = data.get("privkey") or data.get("key")
        if not (cert_pem and key_pem):
            return {"status": "ERROR", "message": "missing cert material"}
        cert_dir = Path(os.environ.get("LM_STATUS_DATA_DIR", "/var/lib/lm/statuspage")) / "tls"
        try:
            cert_dir.mkdir(parents=True, exist_ok=True)
            cp, kp = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
            cp.write_text(cert_pem); kp.write_text(key_pem)
            os.chmod(kp, 0o600)
            self.tls_cert, self.tls_key = str(cp), str(kp)
            self._ensure_web_server()  # re-bind HTTPS
            return {"status": "SUCCESS"}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}

    # ── read accessors for the web layer ─────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        return self._snapshot

    def uptime_bars(self) -> Dict[str, Any]:
        """Per-component 90-day daily uptime buckets for the history bars."""
        return self._history.bars()

    async def trigger_demo(self, hostname: str, scenario: str) -> Dict[str, Any]:
        """Relay a public demo click to the hub (fire-and-forget). The HUB forces
        the tenant + validates the client; this spoke supplies only hostname +
        scenario. Reconciliation is via the next STATUS_SNAPSHOT."""
        cp = self.control_plane
        if cp is None:
            return {"status": "ERROR", "message": "not connected to hub"}
        try:
            await cp.send_to_hub("STATUS_RUN_DEMO",
                                 {"hostname": hostname, "scenario": scenario})
            return {"status": "SUCCESS", "relayed": True}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}

    async def get_status(self) -> Dict[str, Any]:
        self._ensure_web_server()
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
        try:
            vp = Path(__file__).resolve().parent.parent / "VERSION"
            if vp.exists():
                return vp.read_text().strip()
        except Exception:  # noqa: BLE001
            pass
        return "0.0.0"
