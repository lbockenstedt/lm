"""Test Data Feed — publish a fleet snapshot, or subscribe to one.

Testing a dev/qa/lrb hub means giving it a populated fleet, and standing up a
duplicate lab per branch is expensive and drifts. This module lets ONE hub
publish a snapshot of its fleet and ANOTHER replay it as synthetic spokes, so a
test hub carries a duplicate of the production fleet with no real hardware.

Both halves live here because they are two ends of one feature and an operator
sets them up from the same page — but a given hub only ever uses one:

  SOURCE (production)   ``source_enabled`` ON → serves GET /api/test-feed/snapshot.
                        Nothing else changes; no new process runs there.
  RECEIVER (dev/qa/lrb) holds the source URL + an API token, and runs
                        scripts/hub_feed.py as a child process that pulls on an
                        interval and replays into ITSELF over the normal spoke
                        WebSocket.

Security posture:
  * Global-Admin only on every route (also listed in api.py's
    ``_ADMIN_API_PREFIXES`` so the gate is enforced twice).
  * Publishing is OFF by default. A hub never serves fleet data until an
    operator deliberately turns it on.
  * The copy is VERBATIM by default — real hostnames and addresses — because
    the feed exists to reproduce production issues against real identifiers.
    ``source_anonymise`` opts into pseudonyms instead. Either way the API
    token is a read key to a full picture of the estate.
  * Secrets are dropped on the source in BOTH modes (test_feed_scrub's
    DROP_FIELDS) — no path here forwards a password, token or key.
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
    # Verbatim by default: the point of the feed is to duplicate a production
    # fleet so an issue can be reproduced against the REAL identifiers, and
    # pseudonymised hostnames/addresses defeat that. Flip this on to publish
    # anonymised instead. Secrets are dropped either way (test_feed_scrub).
    "source_anonymise": False,
    "source_salt": "",             # pseudonym salt; only used when anonymising
    "receiver_enabled": False,     # this hub pulls a feed
    "receiver_source_url": "",     # https://<source hub>
    "receiver_token": "",          # access token issued BY the source hub
    "receiver_refresh_token": "",  # refresh half of the SAME pair (auto-rotate)
    #
    # Two things deliberately ABSENT from this dict:
    #
    #   tenant — the synthetic spokes always join THIS hub's SHARED tenant, so
    #     the replayed fleet is visible to every tenant rather than walled into
    #     one. Resolved at start via access.refresh_shared_tenant. A stored
    #     value would silently win over that resolution if the flag ever moved.
    #
    #   psk — the onboarding PSK only auto-approves the synthetic spokes on
    #     THIS hub, which is also what spawns them. Start mints an ephemeral
    #     one, registers it on the shared tenant, and revokes it on stop; a
    #     stored PSK would be a standing auto-approve credential with nothing
    #     scoping it.
    "receiver_prefix": "feed-",    # synthetic spoke id prefix (for cleanup)
    "receiver_interval": 60,       # seconds between source polls
}

#: The running feeder child, if any. Module-level rather than hub state because
#: a process does not survive a restart — on reboot the feed is simply stopped,
#: which is the honest state rather than a stale "running" flag in config.
#: ``psk``/``tenant`` record the ephemeral onboarding PSK this hub minted for
#: the running feed, so stop can revoke it. A PSK that outlived its feed would
#: be a standing auto-approve credential for the shared tenant.
_proc = {"p": None, "started": 0.0, "log": "", "psk": "", "tenant": ""}


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
        one is SET, not what it is — a saved token is write-only from the page's
        point of view, so an admin session that is merely reading the config
        page cannot walk away with the source hub's credentials."""
        out = dict(c)
        for k in ("receiver_token", "receiver_refresh_token", "source_salt"):
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
        """Serve this hub's fleet, filtered and grouped per spoke.

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
        anonymise = bool(c.get("source_anonymise"))
        salt = c.get("source_salt") or ""
        if anonymise and not salt:
            # Mint on first anonymised serve so a pseudonym is stable for the
            # life of the publish, and Regenerate genuinely re-randomises.
            salt = os.urandom(16).hex()
            _save({"source_salt": salt})

        raw = await asyncio.to_thread(_collect_fleet, hub)
        scrubbed = scrub_snapshot(raw, salt, pseudonymise=anonymise)
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
        for k in ("source_enabled", "receiver_enabled", "source_anonymise"):
            if k in data:
                patch[k] = bool(data[k])
        for k in ("receiver_source_url", "receiver_prefix"):
            if k in data:
                patch[k] = str(data[k] or "").strip()
        # Secrets: an empty string means "leave what is stored alone" so the UI
        # can save the rest of the form without the operator re-typing them.
        # Clearing is explicit, via the separate clear flags below.
        for k in ("receiver_token", "receiver_refresh_token"):
            v = str(data.get(k) or "").strip()
            if v:
                patch[k] = v
        # The two halves of one token pair — clearing takes both, so a stale
        # refresh token can never be left paired with a fresh access token.
        if data.get("clear_token"):
            patch["receiver_token"] = ""
            patch["receiver_refresh_token"] = ""
        if "receiver_interval" in data:
            try:
                patch["receiver_interval"] = max(15, int(data["receiver_interval"]))
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail="receiver_interval must be a number")
        if data.get("regenerate_salt"):
            patch["source_salt"] = os.urandom(16).hex()

        cur = _save(patch)
        # anonymise is audited explicitly: turning it off means this hub starts
        # serving real hostnames/addresses, which is exactly the kind of change
        # someone will later want to know the who and when of.
        logger.warning("[test-feed] config changed by %s → source_enabled=%s "
                       "anonymise=%s receiver_enabled=%s source_url=%s",
                       _who(sess), cur.get("source_enabled"),
                       cur.get("source_anonymise"),
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
        missing = [k for k in ("receiver_source_url", "receiver_token")
                   if not c.get(k)]
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

        # Mint the onboarding PSK here instead of asking the operator for one.
        # Its only job is to auto-approve the synthetic spokes on THIS hub, and
        # this hub is what spawns them — a human fetching a shared secret so the
        # hub can authenticate to itself bought nothing. Ephemeral and scoped to
        # this run: registered on the shared tenant now, revoked by stop.
        feed_psk = secrets.token_urlsafe(24)
        try:
            await hub.simulations_store.add_psk(tenant, feed_psk)
        except Exception as e:  # noqa: BLE001
            logger.error("[test-feed] could not register onboarding PSK: %s", e)
            raise HTTPException(
                status_code=500,
                detail=f"could not register the feed's onboarding PSK: {e}")

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
                "--psk", feed_psk,
                "--prefix", c.get("receiver_prefix") or "feed-",
                "--interval", str(c.get("receiver_interval") or 60)]
        if c.get("receiver_refresh_token"):
            # Lets the feeder rotate its own access token. Without it a long
            # feed dies when the 4h access token expires (api_tokens.issue_pair),
            # which reads as "the feed randomly stopped overnight".
            argv += ["--refresh-token", c["receiver_refresh_token"]]

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
            # Don't leave the PSK registered when the child never started — it
            # would sit on the shared tenant as a live auto-approve credential
            # with nothing using it.
            try:
                await hub.simulations_store.remove_psk(tenant, feed_psk)
            except Exception:  # noqa: BLE001
                logger.warning("[test-feed] orphaned onboarding PSK on tenant %s", tenant)
            raise HTTPException(status_code=500, detail=f"could not start feeder: {e}")

        _proc.update({"p": p, "started": time.time(), "log": "",
                      "psk": feed_psk, "tenant": tenant})
        asyncio.create_task(_drain(p))
        _save({"receiver_enabled": True})
        return {"status": "ok", "pid": p.pid}

    async def _revoke_feed_psk():
        """Revoke the ephemeral onboarding PSK this hub minted for the feed.

        Runs on every stop path, including the one where the child was already
        dead, because the PSK is registered in hub state and outlives the
        process. Leaving it behind would mean any spoke presenting it could
        auto-approve itself into the shared tenant indefinitely."""
        psk, tenant = _proc.get("psk"), _proc.get("tenant")
        if not (psk and tenant):
            return
        try:
            await hub.simulations_store.remove_psk(tenant, psk)
        except Exception:  # noqa: BLE001
            logger.warning("[test-feed] could not revoke onboarding PSK on tenant %s",
                           tenant, exc_info=True)
        finally:
            _proc["psk"] = ""
            _proc["tenant"] = ""

    @app.post("/api/test-feed/stop")
    async def stop_feed(request: Request):
        sess = _require_admin(request)
        p = _proc["p"]
        if not (p and p.poll() is None):
            await _revoke_feed_psk()
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
        await _revoke_feed_psk()
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
