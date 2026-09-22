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
import json
import os
import secrets
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
    # OPTIONAL tenant override. Blank → the shared tenant (see _shared_tenant).
    #
    # Why this exists: binding to the shared tenant makes the fleet visible in
    # Spokes & Agents, but NOT in the Simulations views —
    # SimulationsService._spokes_for_tenant matches tenant with strict equality
    # and does not union the shared tenant the way the spoke registry does. So
    # a shared-bound feed looks like "the feed is running but nothing appeared".
    # Making that lookup union shared is arguably the real fix, but it shifts
    # per-tenant client counts and sim-quota apportionment across the whole
    # product — too much blast radius to carry on this feature. Naming a real
    # tenant here sidesteps it entirely with no change to shared code.
    "receiver_tenant": "",
    #
    # PRESERVE MODE. When True the receiver ignores ``receiver_tenant`` and
    # replays each synthetic spoke into the LOCAL tenant that matches its
    # SOURCE tenant (carried per-spoke in the snapshot), so a multi-tenant
    # production fleet reproduces its tenant layout here instead of collapsing
    # into one. A source tenant with no local match — and any spoke the source
    # did not attribute — falls back to the shared tenant. Only meaningful
    # verbatim: an anonymised source omits the per-spoke tenant, so preserve
    # degrades to shared. See start_feed's preserve branch.
    "receiver_preserve_tenants": False,
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
#: the live process handle cannot be a config value. The feed itself is no longer
#: "simply stopped" on reboot: ``_resume_feed_on_startup`` re-launches it from the
#: persisted ``receiver_enabled`` intent, so a hub restart/self-update no longer
#: silently drops a feed the operator asked for.
#: ``psk``/``tenants`` record the ephemeral onboarding PSK this hub minted for
#: the running feed, so stop can revoke it. A PSK that outlived its feed would
#: be a standing auto-approve credential for the shared tenant.
_proc = {"p": None, "started": 0.0, "log": "", "psk": "", "tenants": []}

#: One stdout line the feeder prints on every token rotation, carrying the new
#: access+refresh pair so we can persist it (``_drain`` parses these out). Kept
#: byte-for-byte identical to the constant in scripts/hub_feed.py. Persisting the
#: rotated pair is what stops a hub restart from re-presenting an already-spent
#: refresh token — api_tokens.refresh() treats that reuse as theft and revokes
#: the whole family, which is why the feed used to die for good after an update.
TOKEN_ROTATION_SENTINEL = "##LM-TEST-FEED-TOKEN## "


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

    def _local_tenant_ids() -> set:
        """Every tenant id this hub knows, for preserve-mode mapping.

        A source tenant is replayed into the local tenant of the SAME id when
        one exists (the two hubs share a tenant registry lineage — NetBox ids
        are stable across them); anything else falls back to shared. Always
        includes the built-in ``default`` (ADMIN) scope, which is real even
        when the tenant_state map has no explicit row for it."""
        try:
            ids = set((hub.state.tenant_state.get("tenants", {}) or {}).keys())
        except Exception:  # noqa: BLE001
            ids = set()
        ids.add("default")
        return ids

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
                "usb_devices": bucket["usb"],
                "vm_count": len(bucket["vms"]),
                "usb_count": len(bucket["usb"]),
            }
            # Stamp the spoke's source tenant so a receiver in "preserve" mode
            # can replay the fleet into the matching local tenant instead of
            # collapsing everything into one. Only meaningful verbatim: when
            # anonymising, ``sid`` is a pseudonym that get_spoke_tenant won't
            # resolve, so the tenant is simply omitted and the receiver falls
            # back to shared — which is the honest behaviour there anyway.
            if not anonymise:
                try:
                    t = hub.state.get_spoke_tenant(str(sid))
                except Exception:  # noqa: BLE001
                    t = None
                if t:
                    spokes[str(sid)]["tenant"] = t
        # Full-fleet identity: add every connected spoke/agent (not just the
        # Client-Sim hosts that have telemetry rows) so the receiver replays the
        # WHOLE fleet with real types/names. Verbatim only — under anonymise the
        # sharded ids are pseudonyms that get_module_name/tenant can't resolve,
        # so we keep the shape-only (sim-host) behaviour there.
        if not anonymise:
            for sid, ident in _fleet_identity(hub).items():
                rec = spokes.setdefault(str(sid), {
                    "clients": [], "proxmox_vms": [], "usb_devices": [],
                    "vm_count": 0, "usb_count": 0,
                })
                if ident.get("module_type"):
                    rec["module_type"] = ident["module_type"]
                if ident.get("name"):
                    rec["name"] = ident["name"]
                if ident.get("tenant") and "tenant" not in rec:
                    rec["tenant"] = ident["tenant"]
        # The tenant REGISTRY, not just the tenants inferable from spokes. A
        # tenant whose spokes are all offline — or that has none yet — is still
        # part of the fleet's shape, and the receiver cannot discover it from
        # the payloads: its tenant picker lists LOCAL tenant records, so an
        # un-replayed tenant is simply missing from the dropdown, and preserve
        # mode silently folds its spokes into the fallback if one ever appears.
        # Verbatim only: under anonymise the tenant names/slugs are identifying
        # and the sharded ids are pseudonyms, so the receiver keeps its own.
        tenants = _tenant_registry(hub) if not anonymise else {}
        logger.info("[test-feed] served snapshot to %s: %d spoke(s), %d tenant(s)",
                    _who(sess), len(spokes), len(tenants))
        return {"spokes": spokes, "generated_at": time.time(),
                "spoke_count": len(spokes),
                "tenants": tenants,
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
        for k in ("source_enabled", "receiver_enabled", "source_anonymise",
                  "receiver_preserve_tenants"):
            if k in data:
                patch[k] = bool(data[k])
        for k in ("receiver_source_url", "receiver_prefix", "receiver_tenant"):
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
        return await _do_start_feed(_cfg(), _who(sess))

    async def _do_start_feed(c, actor):
        """Spawn the feeder from an already-validated-by-caller config.

        Shared by the operator-driven /start route and _resume_feed_on_startup,
        so a hub restart re-launches a feed the operator had enabled — with no
        HTTP request or admin session in hand. Callers own the _running() guard.
        ``actor`` is only used for the audit line (a username, or a marker such
        as "startup-resume").
        """
        missing = [k for k in ("receiver_source_url", "receiver_token")
                   if not c.get(k)]
        if missing:
            raise HTTPException(
                status_code=400,
                detail="Not configured: " + ", ".join(
                    m.replace("receiver_", "") for m in missing))

        # Refuse to subscribe to ourselves. hub_feed's own _assert_distinct
        # compares the source against the TARGET, and the target is now
        # hardcoded loopback, so it can no longer catch an operator who pasted
        # this hub's own public URL as the source. Left unguarded that is a
        # compounding loop: our feed- spokes get published, pulled back, and
        # re-prefixed on every poll.
        own = str((hub.state.get_global_config() or {}).get("hub", {}).get("url") or "")
        if own:
            import urllib.parse as _up

            def _host(u):
                return (_up.urlparse(u if "//" in u else f"//{u}").hostname or "").lower()

            if _host(own) and _host(own) == _host(c["receiver_source_url"]):
                raise HTTPException(
                    status_code=400,
                    detail="The source URL is this hub. Subscribing to yourself "
                           "replays your own feed spokes back into you, growing "
                           "on every poll — point it at the production hub.")

        # Tenant binding. Two modes:
        #   fixed    — the whole replayed fleet lands in ONE tenant: the named
        #              ``receiver_tenant`` if set, else the shared tenant.
        #   preserve — each synthetic spoke lands in the LOCAL tenant matching
        #              its SOURCE tenant, so a multi-tenant fleet keeps its
        #              shape. Unmatched/unattributed spokes use ``fallback``.
        preserve = bool(c.get("receiver_preserve_tenants"))

        # Mirror the source's tenant registry FIRST, before anything reads the
        # local tenant list. Preserve mode can only map a source tenant onto a
        # LOCAL tenant of the same id, so without this every unmatched tenant
        # collapses into the fallback — the whole replayed fleet lands in one
        # tenant, which is exactly what preserve exists to avoid. It also makes
        # tenants that own no spokes (or whose spokes are all offline) appear in
        # the receiver's tenant picker, which lists local tenant records and
        # would otherwise never learn they exist.
        #
        # Ordering matters: ``fallback`` below resolves the shared tenant, and
        # the mirror may MOVE which tenant that is. Doing this first means a run
        # binds against the shape it just applied instead of the previous one
        # (otherwise the move only takes effect on the NEXT start), and it lets
        # the feed bootstrap a receiver that has no shared tenant at all yet —
        # which would otherwise fail the "nothing to bind to" check below.
        src_tenants, src_registry = set(), {}
        if preserve:
            try:
                src_tenants, src_registry = await asyncio.to_thread(
                    _source_tenants, c["receiver_source_url"], c["receiver_token"])
            except Exception as e:  # noqa: BLE001
                raise HTTPException(
                    status_code=502,
                    detail=f"could not read the source snapshot to map tenants: {e}")
            await _ensure_local_tenants(
                hub, src_registry or {t: {} for t in src_tenants},
                _local_tenant_ids())

        fallback = (c.get("receiver_tenant") or "").strip() or _shared_tenant()
        if not fallback:
            raise HTTPException(
                status_code=400,
                detail="No tenant to bind the replayed fleet to. Name one in "
                       "Tenant below, or mark a tenant 'shared' in Setup → Tenants.")

        # source tenant id -> local tenant id (preserve only); the PSK must be
        # registered on every local tenant a synthetic spoke will claim.
        tenant_map = {}
        psk_tenants = {fallback}
        if preserve:
            local_ids = _local_tenant_ids()
            for st in src_tenants:
                local = st if st in local_ids else fallback
                tenant_map[st] = local
                psk_tenants.add(local)

        script = os.path.join(_repo_root(), "scripts", "hub_feed.py")
        if not os.path.isfile(script):
            raise HTTPException(status_code=500, detail=f"feeder not found at {script}")

        # Mint the onboarding PSK here instead of asking the operator for one.
        # Its only job is to auto-approve the synthetic spokes on THIS hub, and
        # this hub is what spawns them — a human fetching a shared secret so the
        # hub can authenticate to itself bought nothing. Ephemeral and scoped to
        # this run: registered on every target tenant now, revoked by stop. In
        # preserve mode that is one PSK spanning several tenants — the same
        # secret is fine because it is single-use per run and revoked together.
        feed_psk = secrets.token_urlsafe(24)
        registered = []
        try:
            for t in sorted(psk_tenants):
                await hub.simulations_store.add_psk(t, feed_psk)
                registered.append(t)
        except Exception as e:  # noqa: BLE001
            for t in registered:
                try:
                    await hub.simulations_store.remove_psk(t, feed_psk)
                except Exception:  # noqa: BLE001
                    logger.warning("[test-feed] orphaned onboarding PSK on tenant %s", t)
            logger.error("[test-feed] could not register onboarding PSK: %s", e)
            raise HTTPException(
                status_code=500,
                detail=f"could not register the feed's onboarding PSK: {e}")

        # The feeder replays into THIS hub over its normal spoke WebSocket.
        # Loopback rather than the public name, so the traffic stays on-box.
        #
        # It MUST be wss://, not ws://. The hub runs one uvicorn on :443 and
        # serves TLS there whenever a cert is configured, so a plaintext connect
        # gets an empty reply and the feeder would never attach. Confirmed
        # against the live hub: 443 is the only listener, and a plain HTTP
        # upgrade to it returns b''.
        target = "wss://127.0.0.1:443"
        argv = _build_feeder_argv(script, c, target, fallback, feed_psk,
                                  preserve, tenant_map)

        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            [os.path.join(_repo_root(), "core", "src"), env.get("PYTHONPATH", "")])
        # The child inherits this hub's environment, which on a TLS-verifying
        # deployment carries LM_HUB_TLS_VERIFY=1. That would make the loopback
        # leg fail hostname verification: the hub's cert is issued for its
        # public name, not 127.0.0.1. Force verification off for THIS leg only
        # — it never leaves the box, so there is no on-path position to defend
        # against, and _client_ssl_ctx still encrypts.
        env["LM_HUB_TLS_VERIFY"] = "0"
        env.pop("LM_HUB_CA_CERT", None)
        env.pop("LM_HUB_CA_BUNDLE", None)

        # AUDIT before spawning — the token is NOT logged, only its presence.
        logger.warning("[test-feed] START by %s → source=%s tenant=%s prefix=%s "
                       "preserve=%s (%d tenant[s])",
                       actor, c["receiver_source_url"], fallback,
                       c.get("receiver_prefix"), preserve, len(psk_tenants))
        try:
            p = await asyncio.to_thread(
                subprocess.Popen, argv,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env, cwd=_repo_root(), text=True, start_new_session=True)
        except Exception as e:  # noqa: BLE001
            logger.error("[test-feed] spawn failed: %s", e)
            # Don't leave the PSK registered when the child never started — it
            # would sit on each target tenant as a live auto-approve credential
            # with nothing using it.
            for t in registered:
                try:
                    await hub.simulations_store.remove_psk(t, feed_psk)
                except Exception:  # noqa: BLE001
                    logger.warning("[test-feed] orphaned onboarding PSK on tenant %s", t)
            raise HTTPException(status_code=500, detail=f"could not start feeder: {e}")

        _proc.update({"p": p, "started": time.time(), "log": "",
                      "psk": feed_psk, "tenants": list(registered)})
        asyncio.create_task(_drain(p))
        _save({"receiver_enabled": True})
        return {"status": "ok", "pid": p.pid}

    async def _revoke_feed_psk():
        """Revoke the ephemeral onboarding PSK this hub minted for the feed.

        Runs on every stop path, including the one where the child was already
        dead, because the PSK is registered in hub state and outlives the
        process. Leaving it behind would mean any spoke presenting it could
        auto-approve itself into a target tenant indefinitely. In preserve mode
        the same PSK spans several tenants — revoke it from each."""
        psk, tenants = _proc.get("psk"), _proc.get("tenants") or []
        if not (psk and tenants):
            _proc["psk"] = ""
            _proc["tenants"] = []
            return
        for tenant in list(tenants):
            try:
                await hub.simulations_store.remove_psk(tenant, psk)
            except Exception:  # noqa: BLE001
                logger.warning("[test-feed] could not revoke onboarding PSK on tenant %s",
                               tenant, exc_info=True)
        _proc["psk"] = ""
        _proc["tenants"] = []

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
        feed died, and mirror each line to the hub logger so the same detail
        survives a hub restart (the ring is in-memory only) and is greppable in
        hub.log/journald alongside the source-side ``[test-feed]`` lines."""
        try:
            while True:
                line = await asyncio.to_thread(p.stdout.readline)
                if not line:
                    break
                txt = line.rstrip("\n")
                # Token-rotation handoff. Intercept BEFORE the ring-append and
                # the logger mirror below: this line carries live access+refresh
                # tokens, and neither the UI ring nor hub.log/journald should
                # ever see them. Persisting the pair is the whole point — it is
                # what keeps the next restart from re-presenting a spent refresh
                # token and getting the token family revoked.
                if txt.startswith(TOKEN_ROTATION_SENTINEL):
                    try:
                        pair = json.loads(txt[len(TOKEN_ROTATION_SENTINEL):])
                        _save({"receiver_token": pair.get("access") or "",
                               "receiver_refresh_token": pair.get("refresh") or ""})
                        logger.info("[test-feed] persisted rotated feed token pair")
                    except Exception as e:  # noqa: BLE001
                        logger.warning(
                            "[test-feed] could not persist rotated token: %s", e)
                    continue
                _proc["log"] = (_proc["log"] + line)[-8000:]
                if txt:
                    # stderr lines from the feeder are prefixed "  ! " — surface
                    # those louder than routine poll/connect progress.
                    lvl = logger.warning if txt.lstrip().startswith("!") \
                        else logger.info
                    lvl("[test-feed:child] %s", txt)
        except Exception:  # noqa: BLE001
            pass

    async def _resume_feed_on_startup():
        """Re-launch a feed the operator had enabled, after a hub restart.

        The hub self-updates and restarts often; each restart kills the feeder
        child but leaves ``receiver_enabled`` true in config, so the operator's
        feed silently stayed dead until someone noticed and clicked Start again.
        This mirrors _resume_caches_for_active_sessions (api.py) — the same
        "the hub reboots without its loops" problem — and heals it automatically.

        Best-effort and defensive: it must never break hub startup, so every
        failure is logged and swallowed. It also never mints a token or touches
        anything unless the config already says a feed was wanted.
        """
        try:
            c = _cfg()
            if not c.get("receiver_enabled"):
                return
            if not (c.get("receiver_source_url") and c.get("receiver_token")):
                logger.warning("[test-feed] resume skipped: enabled but not "
                               "fully configured (source/token missing)")
                return
            if _running():
                return
            logger.info("[test-feed] resuming feed after restart (source=%s)",
                        c.get("receiver_source_url"))
            await _do_start_feed(c, "startup-resume")
        except Exception as e:  # noqa: BLE001
            logger.warning("[test-feed] auto-resume failed: %s", e)

    app.router.on_startup.append(_resume_feed_on_startup)


def _repo_root() -> str:
    """The lm checkout root (…/core/src/routes/test_feed.py → …)."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


def _build_feeder_argv(script, c, target, fallback, feed_psk, preserve, tenant_map):
    """Assemble the ``hub_feed.py`` command line.

    Secrets go as a single ``--flag=value`` token, never ``--flag``, ``value``.
    api_tokens mints URL-safe-base64 tokens (and the feed PSK is random base64),
    so a value can legitimately START WITH ``-``. Passed as two argv items,
    argparse reads that leading ``-`` as the NEXT option and aborts with
    "argument --refresh-token: expected one argument" — the child never starts,
    so a hub restart silently kills the feed until a human re-mints a token that
    happens not to start with ``-``. The ``=`` form binds the value to its flag
    so any token (dash-leading or not) parses. Kept module-level so this contract
    is unit-testable without spawning the feeder."""
    argv = [sys.executable, script,
            "--source", c["receiver_source_url"],
            "--token=" + c["receiver_token"],
            "--target", target,
            "--tenant", fallback,
            "--psk=" + feed_psk,
            "--prefix", c.get("receiver_prefix") or "feed-",
            "--interval", str(c.get("receiver_interval") or 60)]
    if preserve and tenant_map:
        # Per-spoke tenant routing for the feeder: it reads each payload's
        # source tenant and looks it up here, defaulting to --tenant.
        argv += ["--tenant-map", json.dumps(tenant_map)]
    if c.get("receiver_refresh_token"):
        # Lets the feeder rotate its own access token. Without it a long feed
        # dies when the 4h access token expires (api_tokens.issue_pair), which
        # reads as "the feed randomly stopped overnight".
        argv += ["--refresh-token=" + c["receiver_refresh_token"]]
        # And tell it to hand the rotated pair back to us on stdout so we persist
        # it (_drain). Otherwise the NEXT restart re-presents the spent refresh
        # token, api_tokens flags reuse, and the whole token family is revoked —
        # the feed then dies for good until a human issues a fresh token.
        argv += ["--emit-token-rotations"]
    return argv


def _collect_fleet(hub) -> dict:
    """This hub's fleet in the shape test_feed_scrub expects.

    Reads the simulations telemetry cache directly rather than going back out
    through the HTTP aggregate endpoints — same data, no self-request, and no
    dependency on the caller's tenant scoping (this is a Global-Admin export of
    the whole hub, deliberately)."""
    clients, vms, usb = [], [], []
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
            # VMs and USB devices live EITHER at the top of the frame OR, for a
            # multi-host cs/pxmx spoke, nested per host under "proxmox_hosts".
            # SimulationsService renders the per-host lists (service.py
            # _running_sim_vms, the VM Server view use proxmox_hosts when
            # present and fall back to the top level otherwise), so harvesting
            # only the top level dropped every VM and USB device on a
            # host-structured frame — which is the bulk of a real fleet. Mirror
            # that exact precedence here so the feed carries all of it.
            hosts = data.get("proxmox_hosts")
            sources = hosts if isinstance(hosts, list) and hosts else [data]
            for host in sources:
                host = host or {}
                node = host.get("hostname") or host.get("node")
                for v in (host.get("proxmox_vms") or host.get("vms") or []):
                    row = dict(v or {})
                    row.setdefault("spoke_id", sid)
                    if node:
                        row.setdefault("node", node)
                    vms.append(row)
                for u in (host.get("usb_devices") or []):
                    row = dict(u or {})
                    row.setdefault("spoke_id", sid)
                    if node:
                        row.setdefault("node", node)
                    usb.append(row)
    except Exception:  # noqa: BLE001 — an empty snapshot beats a 500
        logger.debug("[test-feed] fleet collection failed", exc_info=True)
    return {"clients": clients, "proxmox": vms, "usb": usb}


def _fleet_identity(hub) -> dict:
    """Every CURRENTLY-CONNECTED spoke → its identity (module_type, name,
    tenant), keyed by spoke id.

    ``_collect_fleet`` only knows the hosts that push Client-Sim telemetry (2
    on a typical fleet), so a snapshot built from it alone replays just those.
    This enumerates the whole live fleet from ``active_connections`` so the
    receiver can replay EVERY spoke and agent as a connected spoke of its real
    type — the test hub mirrors production, not only the sim hosts. Telemetry
    still rides ``_collect_fleet``; this adds identity for the rest, which show
    online via their heartbeat with empty deep pages."""
    out = {}
    try:
        conn = list(getattr(hub, "active_connections", {}) or {})
    except Exception:  # noqa: BLE001
        return out
    state = getattr(hub, "state", None)
    types = getattr(hub, "spoke_module_types", {}) or {}
    meta = {}
    try:
        meta = (state.system_state.get("module_metadata", {}) or {}) if state else {}
    except Exception:  # noqa: BLE001
        meta = {}
    for sid in conn:
        sid = str(sid)
        mtype = types.get(sid) or (meta.get(sid, {}) or {}).get("module_type") or ""
        try:
            name = state.get_module_name(sid) if state else sid
        except Exception:  # noqa: BLE001
            name = sid
        try:
            tenant = state.get_spoke_tenant(sid) if state else ""
        except Exception:  # noqa: BLE001
            tenant = ""
        out[sid] = {"module_type": mtype or "",
                    "name": name or sid,
                    "tenant": tenant or ""}
    return out


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


#: Tenant-registry fields the source publishes. A tenant record also carries
#: deployment wiring (ldap_base_dn, proxmox_tag) and per-tenant quotas; the feed
#: only needs enough to recreate the tenant SHELL on the receiver — its id, how
#: it is labelled in the UI, and its NetBox mapping. This is an ALLOWLIST rather
#: than a blacklist so a field added to a tenant record later is never published
#: by accident.
TENANT_FIELDS = ("name", "description", "active", "shared",
                 "netbox_tenant_slug", "netbox_id")


def _tenant_registry(hub) -> dict:
    """This hub's tenant registry reduced to the feed-safe fields, keyed by id.

    Best-effort: a hub whose tenant state is unreadable publishes no registry
    rather than failing the whole snapshot — the receiver then degrades to the
    tenants it can infer from the spokes, which is the old behaviour."""
    try:
        tenants = (getattr(hub.state, "tenant_state", None) or {}).get("tenants") or {}
    except Exception:  # noqa: BLE001
        logger.debug("[test-feed] tenant registry unavailable", exc_info=True)
        return {}
    out = {}
    for tid, row in tenants.items():
        if not isinstance(row, dict):
            continue
        out[str(tid)] = {k: row[k] for k in TENANT_FIELDS if k in row}
    return out


async def _ensure_local_tenants(hub, registry: dict, existing: set) -> list:
    """Mirror the source's tenant registry onto this hub.

    Creates a local shell for every source tenant that has no local twin, and
    reconciles which tenant is SHARED.

    Creation only ever ADDS. A tenant the operator already configured here keeps
    its own name, quotas and wiring — the feed replays a fleet, it does not get
    to reconfigure the receiver's existing tenants.

    ``shared`` is the deliberate exception, and is reconciled even on tenants
    that already exist. It is not a per-tenant preference like a quota: it is
    part of the FLEET'S SHAPE (a shared tenant's spokes are visible to every
    tenant), so a receiver replaying production must put it on the same tenant
    or the replica is visibly wrong. Applied through the same single-shared
    invariant the Setup → Tenants editor enforces: flagging the source's shared
    tenant clears the flag on every other local tenant, so exactly one survives.

    Best-effort — a tenant that cannot be created is logged and skipped rather
    than failing the whole feed start; its spokes just fall back. Returns the
    ids created, for the audit line."""
    created = []
    for tid, row in (registry or {}).items():
        clean = str(tid or "").strip()
        if not clean or clean in existing:
            continue
        # 'shared' is applied below, under the single-shared invariant, rather
        # than seeded here — seeding it directly could leave two flagged.
        seed = {k: v for k, v in (row or {}).items()
                if k in TENANT_FIELDS and k != "shared"}
        seed.setdefault("name", clean.upper())
        seed.setdefault("active", True)
        seed["description"] = (seed.get("description")
                               or "Created by the Test Data Feed.")
        try:
            hub.state.update_tenant(clean, seed)
            created.append(clean)
        except Exception:  # noqa: BLE001
            logger.warning("[test-feed] could not create local tenant %s",
                           clean, exc_info=True)

    moved = _mirror_shared_tenant(hub, registry)

    if created or moved:
        # Durable before the feeder starts: the synthetic spokes bind to these
        # ids within seconds, and a crash in between would leave spokes
        # pointing at tenants that no longer exist on disk.
        try:
            await hub.state.save_state_now()
        except Exception:  # noqa: BLE001
            logger.warning("[test-feed] tenant shells not persisted",
                           exc_info=True)
    if created:
        logger.info("[test-feed] created %d local tenant shell(s) from the "
                    "source: %s", len(created), ", ".join(sorted(created)))
    return created


def _mirror_shared_tenant(hub, registry: dict) -> bool:
    """Put the SHARED flag on the same tenant the source has it on.

    Enforces the single-shared invariant (see /setup/tenant): the source's
    shared tenant is flagged and every OTHER local tenant is cleared, so the
    receiver never ends up with two — which would make the effective shared
    tenant depend on dict insertion order.

    No-ops when the source publishes no shared tenant (an older source, an
    anonymised one, or a fleet that genuinely has none) so the operator's own
    choice is left alone. Returns True when something changed."""
    src_shared = next((str(tid) for tid, row in (registry or {}).items()
                       if isinstance(row, dict) and row.get("shared")), None)
    if not src_shared:
        return False
    try:
        tenants = (getattr(hub.state, "tenant_state", None) or {}).get("tenants") or {}
    except Exception:  # noqa: BLE001
        logger.debug("[test-feed] shared mirror: tenant state unreadable",
                     exc_info=True)
        return False
    if src_shared not in tenants:
        return False

    changed = False
    for tid, cfg in list(tenants.items()):
        if not isinstance(cfg, dict):
            continue
        want = (str(tid) == src_shared)
        if bool(cfg.get("shared")) != want:
            try:
                hub.state.update_tenant(str(tid), {"shared": want})
                changed = True
            except Exception:  # noqa: BLE001
                # A single tenant write failing must not hide the ones that
                # already landed: silently returning False here (as if
                # NOTHING changed) left the single-shared invariant broken
                # -- some tenants flipped, some not -- with no cache refresh
                # and no save_state_now() to make the partial write durable.
                # Keep going: report whatever succeeded so the caller still
                # persists and refreshes from the real (partial) state.
                logger.warning("[test-feed] could not mirror shared flag "
                               "onto tenant %s", tid, exc_info=True)

    if changed:
        # Refresh the cached id so the visibility gate is correct immediately —
        # the feeder starts binding spokes within seconds.
        try:
            try:
                from access import refresh_shared_tenant
            except ImportError:  # test/bare-package path
                from core.src.access import refresh_shared_tenant  # type: ignore
            refresh_shared_tenant(hub)
        except Exception:  # noqa: BLE001
            logger.debug("[test-feed] shared-tenant cache refresh failed",
                         exc_info=True)
        logger.info("[test-feed] shared tenant mirrored from the source: %s",
                    src_shared)
    return changed


def _source_tenants(base_url: str, token: str):
    """Source tenants for preserve mode, as ``(ids, registry)``.

    ``ids`` is every distinct tenant that actually OWNS a spoke in the snapshot
    — the PSK must be registered on each one's local twin before the feeder
    replays. ``registry`` is the source's full tenant list keyed by id, which
    also covers tenants that own NO spokes; ``ids`` structurally cannot see
    those, so before it existed such a tenant never reached the receiver at all
    (its picker lists local tenant records, not feed payloads).

    Degrades on both axes: a source predating the registry omits it, and a
    snapshot with no per-spoke tenant (an older or anonymised source) yields an
    empty set — preserve then falls back to the fallback tenant with no error.

    Blocking — the caller runs it through asyncio.to_thread."""
    import ssl
    import urllib.error
    import urllib.request

    url = base_url.rstrip("/") + "/api/test-feed/snapshot"
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}, method="GET")
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        data = json.loads(r.read().decode())
    tenants = set()
    for body in ((data or {}).get("spokes") or {}).values():
        t = (body or {}).get("tenant")
        if t:
            tenants.add(str(t))
    raw_reg = (data or {}).get("tenants")
    registry = ({str(k): (v or {}) for k, v in raw_reg.items()}
                if isinstance(raw_reg, dict) else {})
    return tenants, registry
