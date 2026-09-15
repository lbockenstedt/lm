"""Test Data Feed — publish a scrubbed fleet snapshot, or subscribe to one.

Testing a dev/qa/lrb hub means giving it a populated fleet, and standing up a
duplicate lab per branch is expensive and drifts. This module lets ONE hub
publish an anonymised snapshot of its fleet and ANOTHER replay it as synthetic
spokes, so a branch hub gets production's shape with no real hardware attached.

Both halves live here because they are two ends of one feature and an operator
sets them up from the same page — but a given hub only ever uses one:

  SOURCE (production)   ``source_enabled`` ON → serves GET /api/test-feed/snapshot,
                        already scrubbed. Nothing else changes; no new process runs.
  RECEIVER (dev/qa/lrb) holds the source URL + an API token, and runs
                        scripts/hub_feed.py as a child process that pulls on an
                        interval and replays into ITSELF over the normal spoke
                        WebSocket.

Security posture:
  * Global-Admin only on every route (also listed in api.py's
    ``_ADMIN_API_PREFIXES`` so the gate is enforced twice).
  * Publishing is OFF by default. A hub never serves fleet data — even scrubbed
    — until an operator deliberately turns it on.
  * The snapshot is scrubbed BEFORE it leaves the source (test_feed_scrub), so
    raw hostnames/addresses/user names do not cross the wire even if the
    receiver is misconfigured or compromised.
  * The receiver authenticates to the source with a normal API token (Settings →
    API Tokens on the source). No new credential type, and revoking the token
    stops the feed immediately.
  * Config changes and feed start/stop are audit-logged at WARNING.
"""
import asyncio
import os
import signal
import subprocess
import sys
import time

from api import HTTPException, Request, logger

try:
    from test_feed_scrub import scrub_snapshot, shard_by_spoke
except ImportError:  # test/bare-package path
    from core.src.test_feed_scrub import scrub_snapshot, shard_by_spoke  # type: ignore

#: Merged with global_config at READ time, so an install with no key at all
#: just gets these on its next read — no migration step.
_DEFAULTS = {
    "source_enabled": False,       # publish this hub's fleet as a feed
    "source_salt": "",             # pseudonym salt; minted on first publish
    "receiver_enabled": False,     # this hub pulls a feed
    "receiver_source_url": "",     # https://<source hub>
    "receiver_token": "",          # API token issued BY the source hub
    # No tenant field: the synthetic spokes always join THIS hub's SHARED
    # tenant, so the replayed fleet is visible to every tenant rather than
    # walled into one. Asking the operator to pick a tenant was both an extra
    # step and the wrong default — a test hub wants the data everywhere.
    # Resolved at start time via access.refresh_shared_tenant (see _shared_tenant).
    "receiver_psk": "",            # the SHARED tenant's onboarding PSK (auto-approve)
    "receiver_prefix": "feed-",    # synthetic spoke id prefix (for cleanup)
    "receiver_interval": 60,       # seconds between source polls
}

#: The running feeder child, if any. Module-level rather than hub state because
#: a process does not survive a restart — on reboot the feed is simply stopped,
#: which is the honest state rather than a stale "running" flag in config.
_proc = {"p": None, "started": 0.0, "log": ""}


def register(app, hub, ctx):
    _session_user = ctx._session_user
    _is_admin = ctx._is_admin

    def _cfg() -> dict:
        c = dict(_DEFAULTS)
        c.update((hub.state.get_global_config() or {}).get("test_feed") or {})
        return c

    def _save(patch: dict) -> dict:
        gc = hub.state.get_global_config()
        cur = dict(gc.get("test_feed", {}) or {})
        cur.update(patch)
        gc["test_feed"] = cur
        hub.state.system_state["global_config"] = gc
        hub.state._mark_dirty()
        return cur

    def _who(sess):
        return ((sess or {}).get("user_id") or (sess or {}).get("username")
                or (sess or {}).get("user") or "?")

    def _require_admin(request):
        sess = _session_user(request)
        if not _is_admin(sess):
            raise HTTPException(status_code=403, detail="Global Admin required")
        return sess

    def _redact(c: dict) -> dict:
        """Never hand a stored secret back to the browser. The UI shows whether
        one is SET, not what it is — a saved token/PSK is write-only from the
        page's point of view, so an admin session that is merely reading the
        config page cannot walk away with the source hub's credential."""
        out = dict(c)
        for k in ("receiver_token", "receiver_psk", "source_salt"):
            out[k] = bool(out.get(k))
        return out

    def _running() -> bool:
        p = _proc["p"]
        return bool(p and p.poll() is None)

    def _shared_tenant():
        """THIS hub's shared tenant — the one the replayed fleet joins.

        A spoke bound to the shared tenant is visible to every tenant (see
        access.tenant_is_shared and the registry's _spoke_effective_tenants
        union), which is what a test hub wants: one feed that everybody can
        see, not a fleet walled into whichever tenant the operator happened to
        type. Returns None when no tenant is flagged shared — the caller turns
        that into an actionable error rather than silently binding somewhere
        arbitrary or leaving the spokes unassigned (unassigned is admin-only,
        so the fleet would be invisible to exactly the people testing)."""
        try:
            from access import refresh_shared_tenant
        except ImportError:  # test/bare-package path
            from core.src.access import refresh_shared_tenant  # type: ignore
        try:
            return refresh_shared_tenant(hub)
        except Exception:  # noqa: BLE001
            logger.debug("[test-feed] shared-tenant lookup failed", exc_info=True)
            return None

    # ── SOURCE side ─────────────────────────────────────────────────────────

    @app.get("/api/test-feed/snapshot")
    async def get_feed_snapshot(request: Request):
        """Serve this hub's fleet, scrubbed and grouped per spoke.

        Gated on ``source_enabled`` — a hub that has not opted in returns 403,
        so merely deploying this code never turns a production hub into a data
        source. Reachable with a Bearer API token (that is how a receiver
        authenticates) because ``_session_user`` resolves tokens and cookies to
        the same session shape."""
        sess = _require_admin(request)
        c = _cfg()
        if not c.get("source_enabled"):
            raise HTTPException(
                status_code=403,
                detail="Test Data Feed publishing is disabled on this hub — "
                       "enable it in Setup → Test Data Feed")
        salt = c.get("source_salt") or ""
        if not salt:
            # Mint on first serve so a pseudonym is stable for the life of the
            # publish, and rotating it (Regenerate) genuinely re-randomises.
            salt = os.urandom(16).hex()
            _save({"source_salt": salt})

        raw = await asyncio.to_thread(_collect_fleet, hub)
        scrubbed = scrub_snapshot(raw, salt)
        spokes = {}
        for sid, bucket in shard_by_spoke(scrubbed).items():
            spokes[str(sid)] = {
                "clients": bucket["clients"],
                "proxmox_vms": bucket["vms"],
                "usb_devices": [],
                "vm_count": len(bucket["vms"]),
                "usb_count": 0,
            }
        logger.info("[test-feed] served snapshot to %s: %d spoke(s)",
                    _who(sess), len(spokes))
        return {"spokes": spokes, "generated_at": time.time(),
                "spoke_count": len(spokes),
                "client_count": sum(len(s["clients"]) for s in spokes.values())}

    # ── config (both sides) ─────────────────────────────────────────────────

    @app.get("/api/test-feed/config")
    async def get_feed_config(request: Request):
        _require_admin(request)
        # shared_tenant is derived, not stored — the UI shows which tenant the
        # fleet will land in (and warns when none is flagged shared) instead of
        # asking the operator to choose one.
        return {**_redact(_cfg()), "shared_tenant": _shared_tenant()}

    @app.post("/api/test-feed/config")
    async def set_feed_config(request: Request):
        sess = _require_admin(request)
        data = await request.json()
        patch = {}
        for k in ("source_enabled", "receiver_enabled"):
            if k in data:
                patch[k] = bool(data[k])
        for k in ("receiver_source_url", "receiver_prefix"):
            if k in data:
                patch[k] = str(data[k] or "").strip()
        # Secrets: an empty string means "leave what is stored alone" so the UI
        # can save the rest of the form without the operator re-typing them.
        # Clearing is explicit, via the separate clear flags below.
        for k in ("receiver_token", "receiver_psk"):
            v = str(data.get(k) or "").strip()
            if v:
                patch[k] = v
        if data.get("clear_token"):
            patch["receiver_token"] = ""
        if data.get("clear_psk"):
            patch["receiver_psk"] = ""
        if "receiver_interval" in data:
            try:
                patch["receiver_interval"] = max(15, int(data["receiver_interval"]))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="receiver_interval must be a number")
        if data.get("regenerate_salt"):
            patch["source_salt"] = os.urandom(16).hex()

        cur = _save(patch)
        logger.warning("[test-feed] config changed by %s → source_enabled=%s "
                       "receiver_enabled=%s source_url=%s",
                       _who(sess), cur.get("source_enabled"),
                       cur.get("receiver_enabled"), cur.get("receiver_source_url"))
        return {"status": "ok", **_redact(_cfg())}

    # ── RECEIVER side ───────────────────────────────────────────────────────

    @app.get("/api/test-feed/status")
    async def get_feed_status(request: Request):
        _require_admin(request)
        p = _proc["p"]
        rc = p.poll() if p else None
        return {
            "running": _running(),
            "pid": (p.pid if p and rc is None else None),
            "started": _proc["started"] or None,
            "uptime_s": (round(time.time() - _proc["started"]) if _running() else 0),
            "exit_code": rc if (p and rc is not None) else None,
            "last_output": _proc["log"][-4000:],
        }

    @app.post("/api/test-feed/start")
    async def start_feed(request: Request):
        sess = _require_admin(request)
        if _running():
            raise HTTPException(status_code=409, detail="Feed is already running")
        c = _cfg()
        missing = [k for k in ("receiver_source_url", "receiver_token",
                               "receiver_psk") if not c.get(k)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail="Not configured: " + ", ".join(
                    m.replace("receiver_", "") for m in missing))

        tenant = _shared_tenant()
        if not tenant:
            raise HTTPException(
                status_code=400,
                detail="No shared tenant on this hub. The replayed fleet joins the "
                       "shared tenant so every tenant can see it — mark one tenant "
                       "'shared' in Setup → Tenants first.")

        script = os.path.join(_repo_root(), "scripts", "hub_feed.py")
        if not os.path.isfile(script):
            raise HTTPException(status_code=500, detail=f"feeder not found at {script}")

        # The feeder replays into THIS hub over its normal spoke WebSocket. Using
        # the loopback leg rather than the public name keeps the traffic on-box
        # and sidesteps the TLS-name mismatch a self-connect would otherwise hit
        # (same-box ws://127.0.0.1 is the documented shape — see the hub/spoke
        # transport docs).
        target = "ws://127.0.0.1:443"
        argv = [sys.executable, script,
                "--source", c["receiver_source_url"],
                "--token", c["receiver_token"],
                "--target", target,
                "--tenant", tenant,
                "--psk", c["receiver_psk"],
                "--prefix", c.get("receiver_prefix") or "feed-",
                "--interval", str(c.get("receiver_interval") or 60)]

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "core", "src"), env.get("PYTHONPATH", "")])

        # AUDIT before spawning — the token is NOT logged, only its presence.
        logger.warning("[test-feed] START by %s → source=%s tenant=%s (shared) prefix=%s",
                       _who(sess), c["receiver_source_url"], tenant,
                       c.get("receiver_prefix"))
        try:
            p = await asyncio.to_thread(
                subprocess.Popen, argv,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env, cwd=_repo_root(), text=True, start_new_session=True)
        except Exception as e:  # noqa: BLE001
            logger.error("[test-feed] spawn failed: %s", e)
            raise HTTPException(status_code=500, detail=f"could not start feeder: {e}")

        _proc.update({"p": p, "started": time.time(), "log": ""})
        asyncio.create_task(_drain(p))
        _save({"receiver_enabled": True})
        return {"status": "ok", "pid": p.pid}

    @app.post("/api/test-feed/stop")
    async def stop_feed(request: Request):
        sess = _require_admin(request)
        p = _proc["p"]
        if not (p and p.poll() is None):
            _save({"receiver_enabled": False})
            return {"status": "ok", "running": False}
        logger.warning("[test-feed] STOP by %s (pid=%s)", _who(sess), p.pid)
        try:
            # Signal the whole process group: the feeder holds its own asyncio
            # tasks and synthetic spoke connections, and killing only the parent
            # would leave those sockets attached to the hub.
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            await asyncio.to_thread(p.wait, 10)
        except Exception:  # noqa: BLE001
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
            except Exception:  # noqa: BLE001
                pass
        _save({"receiver_enabled": False})
        return {"status": "ok", "running": False}

    @app.post("/api/test-feed/test")
    async def test_source(request: Request):
        """Reach the configured source and report what it would serve, WITHOUT
        starting the feed — the equivalent of the CLI's --dry-run, so an
        operator can confirm the token and the publish gate before any
        synthetic spoke connects to this hub."""
        _require_admin(request)
        c = _cfg()
        if not c.get("receiver_source_url") or not c.get("receiver_token"):
            raise HTTPException(status_code=400, detail="Source URL and token are required")
        try:
            res = await asyncio.to_thread(
                _probe_source, c["receiver_source_url"], c["receiver_token"])
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=str(e))
        return res

    async def _drain(p):
        """Pump the child's output into a small ring so the UI can show why a
        feed died. Bounded — an unbounded buffer on a long-running child is a
        slow memory leak."""
        try:
            while True:
                line = await asyncio.to_thread(p.stdout.readline)
                if not line:
                    break
                _proc["log"] = (_proc["log"] + line)[-8000:]
        except Exception:  # noqa: BLE001
            pass


def _repo_root() -> str:
    """The lm checkout root (…/core/src/routes/test_feed.py → …)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _collect_fleet(hub) -> dict:
    """This hub's fleet in the shape test_feed_scrub expects.

    Reads the simulations telemetry cache directly rather than going back out
    through the HTTP aggregate endpoints — same data, no self-request, and no
    dependency on the caller's tenant scoping (this is a Global-Admin export of
    the whole hub, deliberately)."""
    clients, vms = [], []
    try:
        # Same store SimulationsService._cache() reads (service.py:86) — the
        # per-spoke CS_TELEMETRY frames, keyed by spoke id.
        cache = getattr(hub, "simulations_cache", {}) or {}
        for sid, data in (cache.items() if hasattr(cache, "items") else []):
            data = data or {}
            for c in (data.get("clients") or []):
                row = dict(c or {})
                row.setdefault("spoke_id", sid)
                clients.append(row)
            for v in (data.get("proxmox_vms") or data.get("vms") or []):
                row = dict(v or {})
                row.setdefault("spoke_id", sid)
                vms.append(row)
    except Exception:  # noqa: BLE001 — an empty snapshot beats a 500
        logger.debug("[test-feed] fleet collection failed", exc_info=True)
    return {"clients": clients, "proxmox": vms}


def _probe_source(base_url: str, token: str) -> dict:
    """GET the source's snapshot once and summarise it. Blocking on purpose —
    every caller runs it through asyncio.to_thread."""
    import json
    import ssl
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + "/api/test-feed/snapshot"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}, method="GET")
    ctx = ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise RuntimeError("Source refused: publishing is disabled on that hub")
        if e.code == 401:
            raise RuntimeError("Source rejected the token (expired or revoked)")
        if e.code == 404:
            raise RuntimeError("Source has no test-feed endpoint (older branch)")
        raise RuntimeError(f"Source returned HTTP {e.code}")
    spokes = (data or {}).get("spokes") or {}
    sample = next(iter(spokes.values()), {}) if spokes else {}
    return {"ok": True, "spoke_count": len(spokes),
            "client_count": (data or {}).get("client_count", 0),
            "sample_clients": (sample.get("clients") or [])[:3]}
