"""Edge-proxy role spoke — per-tenant local WebUI front door.

A ``BaseSpoke`` loaded IN-REPO by the generic agent (``_ROLE_MAP`` repo_url=None,
module_type "proxy"). It serves the browser leg on :443 with a server cert from
the ``le`` role and **NO client-cert request** (CERT_NONE) — so a macOS browser
holding a client cert is never prompted — and reverse-proxies every request to the
hub over an mTLS upstream. The hub keeps ALL logic and the live ``hub`` object;
this role is a dumb forwarding front door (Option A). See docs/edge-proxy-role.md.

Data flow:
  - browser → this spoke's :443 (LE cert, no client-cert prompt)
  - → forwarded to the hub's :443 over mTLS (the proxy presents its hub-issued
    spoke client cert), with X-Forwarded-For/Proto/Host stamped so the hub's
    per-IP login lockout sees the real client.

Commands (hub → spoke):
  UPDATE_CONFIG   — web bind, public hostname, upstream hub URL, verify flag.
  INSTALL_CERT    — TLS fullchain+key from the le cert-distribution pipeline
                    (proxy is a CERT_CAPABLE target); re-binds HTTPS.

Phase 2 (console shortcut) is NOT here yet — console still relays through the hub.
"""
import asyncio
import logging
import os
import ssl
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

try:
    from base_spoke import BaseSpoke
except ImportError:  # loaded from the repo root / as core package
    from core.src.base_spoke import BaseSpoke

try:
    from proxy_app import build_proxy_app
except ImportError:  # loaded as a package by the agent role loader
    from .proxy_app import build_proxy_app  # type: ignore

logger = logging.getLogger("ProxySpoke")


def _ws_to_http(url: str) -> str:
    """Turn a hub ws(s)://host:port[/path] into the https base https://host:port."""
    if not url:
        return ""
    try:
        parts = urlsplit(url)
        scheme = {"wss": "https", "ws": "http"}.get(parts.scheme, parts.scheme or "https")
        netloc = parts.netloc or parts.path  # bare host slipped into path
        return urlunsplit((scheme, netloc, "", "", ""))
    except Exception:  # noqa: BLE001
        return ""


def _as_bool(*vals, default: bool) -> bool:
    """First of ``vals`` that is a recognizable bool wins; else ``default``.
    Accepts real bools and the usual 1/true/yes/on ↔ 0/false/no/off strings."""
    for v in vals:
        if v is None:
            continue
        if isinstance(v, bool):
            return v
        s = str(v).strip().lower()
        if s in ("1", "true", "yes", "on"):
            return True
        if s in ("0", "false", "no", "off"):
            return False
    return default


class ProxySpoke(BaseSpoke):
    def __init__(self, spoke_id: str, config: Dict[str, Any]):
        super().__init__(spoke_id, config)
        self.control_plane = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        cfg = config or {}
        self.web_host = cfg.get("web_host") or os.environ.get("LM_PROXY_HOST", "0.0.0.0")
        self.web_port = int(cfg.get("web_port") or os.environ.get("LM_PROXY_PORT", "443"))
        self.tls_cert = cfg.get("tls_cert") or os.environ.get("LM_PROXY_TLS_CERT") or ""
        self.tls_key = cfg.get("tls_key") or os.environ.get("LM_PROXY_TLS_KEY") or ""

        # Upstream = the hub's HTTPS base. Explicit config wins; else derive from
        # the hub URL the control plane already dials (HUB_URL / --hub).
        self.upstream_url = (cfg.get("upstream_url")
                             or os.environ.get("LM_PROXY_UPSTREAM")
                             or _ws_to_http(os.environ.get("HUB_URL", "")))
        # Verify the hub's SERVER cert on the upstream leg. OFF by default (matches
        # the fleet's self-signed-hub default); flip on once the hub has an LE cert.
        self.upstream_verify = str(cfg.get("upstream_verify")
                                   or os.environ.get("LM_PROXY_UPSTREAM_VERIFY", "")
                                   ).strip().lower() in ("1", "true", "yes", "on")
        # Client cert the proxy presents to the hub. This MUST be the DEDICATED
        # hub-leg cert (mtls-hub-client.*, LM_MTLS_HUB_CLIENT_CERT/KEY) — issued by
        # the local hub mTLS CA (self-managed), written by the hub's
        # _handle_set_mtls_client_cert. It must NEVER be the shared mtls-client.* /
        # LM_MTLS_CLIENT_CERT that SPOKE_SET_MTLS_MATERIALS writes for the /ws/agent
        # leg — that one is the public LE wildcard (*.orange-tme.com), which the hub
        # REJECTS here (→ upstream 502). Mirrors core/src/messaging/control_plane.py's
        # own hub dial, which likewise presents only the dedicated hub-leg cert (and
        # none if absent — the hub accepts anonymous, unlike the rejected wildcard).
        self.upstream_cert = (cfg.get("upstream_cert")
                              or os.environ.get("LM_MTLS_HUB_CLIENT_CERT") or "")
        self.upstream_key = (cfg.get("upstream_key")
                             or os.environ.get("LM_MTLS_HUB_CLIENT_KEY") or "")

        self._data_dir = cfg.get("data_dir") or os.environ.get(
            "LM_PROXY_DATA_DIR", "/var/lib/lm/proxy")

        # Rediscover a previously-installed listener cert across restarts. INSTALL_CERT
        # persists fullchain/privkey under <data_dir>/tls, but __init__ otherwise only
        # seeds tls_cert/tls_key from cfg/env — so a bare restart (self-update, crash,
        # watchdog reboot) would forget the cert and silently fall back to plaintext
        # HTTP on :443 (browsers then get a TLS handshake reset). Reload it here.
        if not (self.tls_cert and self.tls_key):
            _tls_dir = Path(self._data_dir) / "tls"
            _fc, _pk = _tls_dir / "fullchain.pem", _tls_dir / "privkey.pem"
            if _fc.exists() and _pk.exists():
                self.tls_cert, self.tls_key = str(_fc), str(_pk)

        # Phase 2 console shortcut: the co-located spoke's agent-listener base
        # (where /ws/console-relay lives), e.g. wss://<spoke-ip>:443 or
        # ws://<spoke-ip>:8443. When set, console sessions relay browser↔proxy↔
        # spoke↔agent↔Proxmox locally (hub out of the byte path); unset → the
        # Phase-1 hub proxy carries console too. Descriptor cache is filled by
        # snooping the hub's /api/pxmx/console response.
        self.relay_spoke_url = (cfg.get("relay_spoke_url")
                                or os.environ.get("LM_PROXY_RELAY_SPOKE_URL") or "")
        self._console_relay_cache = {}  # session_id → relay descriptor

        # Tenant awareness for the Phase-2 console shortcut. The hub pushes this
        # proxy's OWN assigned tenant (+ whether that tenant is shared) via
        # UPDATE_CONFIG on every (re)connect. The shortcut is taken ONLY for a
        # target whose tenant matches this proxy's non-shared tenant; a shared or
        # unassigned proxy never shortcuts (all console traffic via the hub).
        self.tenant_id = (cfg.get("tenant_id")
                          or os.environ.get("LM_PROXY_TENANT_ID") or "")
        self.tenant_shared = bool(cfg.get("tenant_shared"))

        # HTTPS-port scanner detection at this edge (see proxy_app._dispatch). ON
        # by default — it's inherently safe (report-only; the hub's auto-block is
        # itself opt-in and exempts trusted IPs). Per-node toggle so an operator
        # can silence a proxy that legitimately sees odd paths. Hub can flip it
        # live via UPDATE_CONFIG; LM_PROXY_PROBE_DETECTION env overrides the boot
        # default.
        self.probe_detection_enabled = _as_bool(
            cfg.get("probe_detection"),
            os.environ.get("LM_PROXY_PROBE_DETECTION"),
            default=True)

        self._proxy_app = None
        self._runner = None
        self._site = None
        self._bind = None  # (host, port, cert, key) the running site used

    # ── SSL contexts ─────────────────────────────────────────────────────────
    def _listener_ssl(self) -> Optional[ssl.SSLContext]:
        """Browser-facing context: server cert ONLY, no client-cert request
        (CERT_NONE) → no TLS CertificateRequest → no macOS Keychain prompt."""
        if not (self.tls_cert and self.tls_key
                and os.path.exists(self.tls_cert) and os.path.exists(self.tls_key)):
            return None  # no cert yet → plain HTTP (dev / pre-cert)
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)  # verify_mode=CERT_NONE
        ctx.load_cert_chain(self.tls_cert, self.tls_key)
        return ctx

    def upstream_ssl(self):
        """Upstream (proxy → hub) context: present our client cert for mTLS, and
        verify the hub's server cert only when explicitly enabled."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        if self.upstream_verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if (self.upstream_cert and self.upstream_key
                and os.path.exists(self.upstream_cert) and os.path.exists(self.upstream_key)):
            try:
                ctx.load_cert_chain(self.upstream_cert, self.upstream_key)
            except Exception as e:  # noqa: BLE001
                logger.warning("proxy: upstream client cert load failed: %s", e)
        return ctx

    # ── web server lifecycle ─────────────────────────────────────────────────
    async def _ensure_web_server(self) -> None:
        self._loop = asyncio.get_event_loop()
        bind = (self.web_host, self.web_port, self.tls_cert, self.tls_key)
        if self._site is not None and bind == self._bind:
            return  # already serving the right bind
        # Tear down an existing site to re-bind (config / cert change).
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:  # noqa: BLE001
                pass
            self._runner = self._site = None

        from aiohttp import web  # local import so a missing dep can't brick load
        self._proxy_app = build_proxy_app(self)
        self._runner = web.AppRunner(self._proxy_app, access_log=None)
        await self._runner.setup()
        ctx = self._listener_ssl()
        try:
            self._site = web.TCPSite(self._runner, self.web_host, self.web_port,
                                     ssl_context=ctx)
            await self._site.start()
            self._bind = bind
            logger.info("Edge proxy serving on %s://%s:%d → %s (no client-cert prompt)",
                        "https" if ctx else "http", self.web_host, self.web_port,
                        self.upstream_url or "?")
        except Exception as e:  # noqa: BLE001
            logger.error("edge proxy failed to bind %s:%d: %s",
                         self.web_host, self.web_port, e)
            self._site = None

    # ── command dispatch (hub → spoke) ───────────────────────────────────────
    async def handle_command(self, command_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        await self._ensure_web_server()
        cmd = (command_type or "").upper()
        data = data or {}
        if cmd == "UPDATE_CONFIG":
            return await self._apply_config(data)
        if cmd in ("INSTALL_CERT", "PROXY_SET_CERT"):
            return await self._apply_cert(data)
        return {"status": "ERROR", "message": f"unknown command {command_type}"}

    async def _apply_config(self, data: Dict[str, Any]) -> Dict[str, Any]:
        changed = False
        if "relay_spoke_url" in data and data["relay_spoke_url"] is not None:
            self.relay_spoke_url = data["relay_spoke_url"]  # hot — no re-bind needed
        if "tenant_id" in data and data["tenant_id"] is not None:
            self.tenant_id = str(data["tenant_id"] or "")  # hot — gates the shortcut
        if "tenant_shared" in data and data["tenant_shared"] is not None:
            self.tenant_shared = bool(data["tenant_shared"])
        if data.get("probe_detection") is not None:  # hot — no re-bind needed
            self.probe_detection_enabled = _as_bool(
                data["probe_detection"], default=self.probe_detection_enabled)
        for key in ("web_host", "tls_cert", "tls_key", "upstream_url",
                    "upstream_cert", "upstream_key"):
            if key in data and data[key] is not None and getattr(self, key) != data[key]:
                setattr(self, key, data[key])
                changed = True
        if data.get("web_port") is not None and int(data["web_port"]) != self.web_port:
            self.web_port = int(data["web_port"]); changed = True
        if data.get("upstream_verify") is not None:
            v = str(data["upstream_verify"]).strip().lower() in ("1", "true", "yes", "on")
            if v != self.upstream_verify:
                self.upstream_verify = v
        if changed:
            await self._ensure_web_server()  # re-bind
        return {"status": "SUCCESS", "rebound": changed}

    async def _apply_cert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        cert_pem = data.get("fullchain") or data.get("cert")
        key_pem = data.get("privkey") or data.get("key")
        if not (cert_pem and key_pem):
            return {"status": "ERROR", "message": "missing cert material"}
        cert_dir = Path(self._data_dir) / "tls"
        try:
            cert_dir.mkdir(parents=True, exist_ok=True)
            cp, kp = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
            cp.write_text(cert_pem)
            kp.write_text(key_pem)
            os.chmod(kp, 0o600)
            self.tls_cert, self.tls_key = str(cp), str(kp)
            await self._ensure_web_server()  # re-bind HTTPS
            return {"status": "SUCCESS"}
        except Exception as e:  # noqa: BLE001
            return {"status": "ERROR", "message": str(e)}

    # ── status / version ─────────────────────────────────────────────────────
    async def get_status(self) -> Dict[str, Any]:
        await self._ensure_web_server()
        return {
            "role": "proxy",
            "serving": bool(self._site is not None),
            "host": self.web_host,
            "port": self.web_port,
            "tls": bool(self.tls_cert and self.tls_key),
            "upstream": self.upstream_url or None,
            "upstream_verify": self.upstream_verify,
            "upstream_mtls": bool(self.upstream_cert and self.upstream_key),
            "console_relay": bool(self.relay_spoke_url),
            "tenant_id": self.tenant_id or None,
            "tenant_shared": self.tenant_shared,
            "probe_detection": self.probe_detection_enabled,
            "relay_sessions": len(self._console_relay_cache),
        }

    def get_version(self) -> str:
        try:
            vp = Path(__file__).resolve().parent.parent / "VERSION"
            if vp.exists():
                return vp.read_text().strip()
        except Exception:  # noqa: BLE001
            pass
        return "unknown"
