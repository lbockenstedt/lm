#!/usr/bin/env python3
"""Replay production fleet data into a dev/qa/lrb hub — no duplicate lab.

THE PROBLEM. Testing a branch hub means giving it a populated fleet. Standing up
a second set of spoke VMs, Proxmox nodes and client sims per branch is expensive
and drifts out of sync with production. ``loadtest_spokes.py`` already solves the
CONNECTION half — synthetic spokes driving the real ``BaseControlPlane`` — but it
invents its roster from ``random.choice``, so a branch hub gets plausible-shaped
noise rather than the fleet you are actually trying to reproduce a bug against.

WHAT THIS DOES. Pulls a live snapshot from a SOURCE hub's read-only feed API,
filters it, and replays it into a TARGET hub as synthetic spoke telemetry
using that same harness. The target sees a fleet with production's shape — spoke
count, clients per spoke, platform mix, VM counts, simulation spread — without a
single real lab box pointed at it, and re-polling on an interval keeps it live
rather than a one-shot fixture.

    prod hub ──GET /api/test-feed/snapshot──▶ hub_feed ──CS_TELEMETRY──▶ test hub
                  (read-only, gated)          (reshape)    (synthetic spokes)

SAFETY, because this straddles two hubs:

  * The source is touched with GET only. There is no code path here that writes
    to it — see ``_get_json``, the sole transport.
  * ``--target`` must NOT resolve to the same host:port as ``--source``. Feeding
    a hub its own data back would corrupt production state with synthetic
    spokes. Checked in ``_assert_distinct`` and refused.
  * Every spoke id is prefixed (``--prefix``, default ``feed-``) so the target's
    synthetic entries are bulk-deletable from Setup → Spokes & Agents, exactly
    like loadtest's.
  * Secrets (passwords, tokens, keys) are dropped and never replayed — see
    ``scrub_snapshot``. Identifiers are forwarded VERBATIM by default, since
    the point is to reproduce a production issue against the real hostnames
    and addresses; the source hub can opt into pseudonyms instead.

USAGE:

    PYTHONPATH=/opt/lm/core/src python3 scripts/hub_feed.py \\
        --source https://lm-hub.westus3.cloudapp.azure.com \\
        --token <ACCESS_TOKEN> --refresh-token <REFRESH_TOKEN> \\
        --target wss://test-hub.lab:443 \\
        --tenant <TARGET_TENANT> --psk <TARGET_TENANT_PSK> \\
        --interval 60

(Setup → Test Data Feed drives all of this from the UI, and mints the target
PSK itself; the flags are for running the feeder by hand.)

``--token`` (with ``--refresh-token``) is the preferred credential and skips the
login entirely; ``--source-pass -`` reads a password from stdin so it never
lands in shell history or the process table. ``--dry-run`` prints the snapshot
it would replay and exits without connecting to the target — always worth one
pass before pointing this at a hub.
"""
# argparse: CLI flags; asyncio: run the synthetic spokes concurrently.
import argparse
import asyncio
# getpass: prompt for the source password without echoing it.
import getpass
# hashlib: derive a random pseudonym salt.
import hashlib
# http.cookiejar: keep the source hub's lm_session login cookie.
import http.cookiejar
# json: request/response bodies and the tenant map.
import json
# os/sys: import paths, random bytes, stdout/stderr.
import os
# ssl: TLS contexts for the source hub (self-signed accepted by default).
import ssl
import sys
# time: pacing, deadlines and rate-limited error logs.
import time
# urllib: the HTTP client for the read-only source hub API.
import urllib.error
import urllib.parse
import urllib.request

# Same core-locating dance as loadtest_spokes.py — see its module docstring.
# This repo's root (one level above scripts/).
_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Prepend each existing candidate path once so both import layouts work.
for _p in ("/opt/lm", "/opt/lm/core/src", _repo, os.path.join(_repo, "core", "src")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

# The filter/reshape logic is SHARED with the hub's own routes/test_feed.py —
# see core/src/test_feed_scrub.py. It lives there, not here, because the source
# hub applies it before serving a snapshot and this feeder applies it again on
# the way in; two copies would drift, and a drift in DROP_FIELDS would mean
# secrets getting replayed.
# Import the shared scrub/reshape helpers from whichever layout is available.
try:
    from test_feed_scrub import (  # noqa: F401
        IDENTIFYING_FIELDS, IDENTIFYING_SUBSTRINGS, DROP_FIELDS,
        _pseudonym, _kind_for, _is_identifying, _is_dropped,
        scrub_snapshot, shard_by_spoke, build_payloads)
except ImportError:  # pragma: no cover - bare checkout without core/src on path
    from core.src.test_feed_scrub import (  # type: ignore  # noqa: F401
        IDENTIFYING_FIELDS, IDENTIFYING_SUBSTRINGS, DROP_FIELDS,
        _pseudonym, _kind_for, _is_identifying, _is_dropped,
        scrub_snapshot, shard_by_spoke, build_payloads)


#: Printed on its own stdout line each time the feeder rotates its API token, so
#: the parent hub can persist the NEW access+refresh pair back to config. Without
#: this the hub keeps the ORIGINAL refresh token; the next hub restart re-presents
#: an already-rotated refresh token, which api_tokens.refresh() flags as reuse and
#: punishes by revoking the whole token family — the feed then dies for good after
#: an update and every restart, until a human issues a fresh token. Must stay
#: byte-for-byte identical to the constant of the same name in
#: core/src/routes/test_feed.py, which parses these lines out of the child stream.
TOKEN_ROTATION_SENTINEL = "##LM-TEST-FEED-TOKEN## "


class SourceHub:
    """Read-only client for the source hub's aggregate API.

    GET is the only verb this class can issue. Keeping the transport in one
    method (``_get_json``) is deliberate: it makes "does this script write to
    production?" answerable by reading twenty lines rather than auditing every
    call site."""

    def __init__(self, base_url, insecure=True, token="", refresh_token="",
                 emit_rotations=False):
        """Set up the HTTP client for the source hub.

        Args:
            base_url: source hub WebUI base URL.
            insecure: accept a self-signed source certificate (default True).
            token / refresh_token: API token pair; refresh is tried on the first 401.
            emit_rotations: print a sentinel line with each newly rotated token pair.
        """
        # Base URL without a trailing slash, and the current access token.
        self.base = base_url.rstrip("/")
        self.token = (token or "").strip()
        # Access tokens are short-lived (4h — api_tokens.issue_pair). Without a
        # refresh token a long feed dies overnight and reads as "it randomly
        # stopped"; with one, _get_json rotates the pair on the first 401.
        self.refresh_token = (refresh_token or "").strip()
        # When True, every successful rotation prints a TOKEN_ROTATION_SENTINEL
        # line so the parent hub persists the new pair (see the constant's note).
        self.emit_rotations = bool(emit_rotations)
        # Cookie jar for password logins; TLS verification is off unless insecure=False.
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        # URL opener that stores cookies and uses our TLS context.
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx))

    def login(self, username, password):
        """POST /auth/login once to mint the ``lm_session`` cookie.

        The single non-GET request in this script, and it only authenticates —
        it creates a session, not fleet state."""
        # JSON login body.
        body = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.base}/auth/login", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        # Send it; turn common HTTP errors into clear fatal messages.
        try:
            with self.opener.open(req, timeout=20) as r:
                r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit("Source hub rejected the credentials (401).")
            if e.code == 429:
                raise SystemExit("Source hub is rate-limiting logins (429) — wait and retry.")
            raise SystemExit(f"Source hub login failed: HTTP {e.code}")
        # A successful login must leave an lm_session cookie in the jar.
        if not any(c.name == "lm_session" for c in self.jar):
            raise SystemExit("Login returned no lm_session cookie — is --source the hub's WebUI URL?")

    def _raw_get(self, path):
        """GET path from the source hub (Bearer token if we have one) and return parsed JSON."""
        # Send the access token as a Bearer header when one is configured.
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        req = urllib.request.Request(f"{self.base}{path}", headers=headers, method="GET")
        with self.opener.open(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def _rotate(self):
        """Exchange the refresh token for a new access+refresh pair.

        Refresh tokens are SINGLE-USE and reuse revokes the whole family, so the
        new pair must replace the old one before the next attempt — a retry that
        re-sent the spent token would lock this feed out entirely."""
        # No refresh token: cannot rotate.
        if not self.refresh_token:
            return False
        # POST the refresh token to the hub's refresh endpoint.
        body = json.dumps({"refresh_token": self.refresh_token}).encode()
        req = urllib.request.Request(
            f"{self.base}/auth/token/refresh", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        # Any failure clears the refresh token so we do not retry with a spent one.
        try:
            with self.opener.open(req, timeout=20) as r:
                d = json.loads(r.read().decode())
        except Exception as e:  # noqa: BLE001
            print(f"  ! token refresh failed: {e}", file=sys.stderr)
            self.refresh_token = ""   # spent or rejected; don't spin on it
            return False
        # Adopt the new pair (keep the old access token if none came back).
        self.token = d.get("access_token") or self.token
        self.refresh_token = d.get("refresh_token") or ""
        print("  token refreshed")
        if self.emit_rotations and self.token:
            # Hand the fresh pair to the parent hub so it replaces the spent one
            # in config. Its own line, flushed immediately, so the hub persists
            # it before this process can exit or be killed mid-rotation.
            sys.stdout.write(TOKEN_ROTATION_SENTINEL + json.dumps(
                {"access": self.token, "refresh": self.refresh_token}) + "\n")
            sys.stdout.flush()
        return True

    def _get_json(self, path):
        """GET path as JSON, rotating the token once and retrying if the hub answers 401."""
        try:
            return self._raw_get(path)
        except urllib.error.HTTPError as e:
            # One rotation attempt, then re-raise. Retrying blindly would turn an
            # actually-revoked token into an infinite loop against the source.
            if e.code != 401 or not self._rotate():
                raise
            return self._raw_get(path)

    def snapshot(self):
        """One fleet snapshot.

        Prefers ``/api/test-feed/snapshot`` — the source hub's own feed endpoint,
        which applies the operator's publish gate AND scrubs before serving, so
        raw fleet data never leaves the production box. Falls back to the three
        aggregate endpoints when the source hub predates that route (an older
        branch), in which case this process does the only scrub there is."""
        # Preferred: the source hub's own gated, pre-scrubbed feed endpoint.
        try:
            served = self._get_json("/api/test-feed/snapshot")
            # Mark it as already-scrubbed ("preserved") for build_payloads.
            if isinstance(served, dict) and "spokes" in served:
                return {"_preserved": served}
        # 403/401 are fatal with an explanation; 404 means an older hub, so fall back.
        except urllib.error.HTTPError as e:
            if e.code == 403:
                raise SystemExit(
                    "Source hub refused: the test-data feed is not published there.\n"
                    "Enable it in Setup → Test Data Feed on the SOURCE hub.")
            if e.code == 401:
                raise SystemExit("Source hub rejected the token (401) — expired or revoked?")
            if e.code != 404:
                raise SystemExit(f"Source hub snapshot failed: HTTP {e.code}")
        except Exception:  # noqa: BLE001 — fall through to the legacy path
            pass

        # Legacy path: fetch each aggregate endpoint; a failing one is just left empty.
        out = {}
        for key, path in (("clients", "/sim/api/aggregate/clients"),
                          ("proxmox", "/sim/api/aggregate/proxmox"),
                          ("simulations", "/sim/api/aggregate/simulations")):
            try:
                out[key] = self._get_json(path)
            except Exception as e:  # noqa: BLE001
                print(f"  ! {path}: {e} — continuing without it", file=sys.stderr)
                out[key] = {}
        return out


def _assert_distinct(source_url, target_url):
    """Refuse to feed a hub its own data.

    Compares host:port after normalising scheme (https/wss are the same
    endpoint on this platform — one uvicorn on :443, see the unified-443
    transport). A typo here would inject synthetic spokes into production, which
    is not something to discover afterwards."""
    def hostport(u):
        """Return (lower-case hostname, port) for a URL, defaulting the port from the scheme."""
        # Add "//" to bare host strings so urlparse treats them as a host, not a path.
        p = urllib.parse.urlparse(u if "//" in u else f"//{u}")
        port = p.port or (443 if (p.scheme or "https") in ("https", "wss") else 80)
        return ((p.hostname or "").lower(), port)

    # Same endpoint on both sides: refuse.
    s, t = hostport(source_url), hostport(target_url)
    if s == t:
        raise SystemExit(
            f"REFUSING: --source and --target are the same hub ({s[0]}:{s[1]}).\n"
            "Feeding a hub its own scrubbed data would write synthetic spokes into "
            "production state. Point --target at the dev/qa/lrb hub.")


# --------------------------------------------------------------------------
# Target side — synthetic spokes replaying the scrubbed snapshot
# --------------------------------------------------------------------------

def _load_feed_spoke():
    """Import BaseControlPlane lazily so --dry-run works off-box.

    Scrubbing and sharding are pure and unit-testable; only the replay half
    needs the lm core on disk. Importing at module scope would make the whole
    script unusable — tests included — anywhere but a spoke host."""
    # Try both package layouts for the real spoke client.
    BaseControlPlane = None
    err = None
    for mod in ("core.src.messaging.control_plane", "messaging.control_plane"):
        try:
            BaseControlPlane = __import__(mod, fromlist=["BaseControlPlane"]).BaseControlPlane
            break
        except Exception as e:  # noqa: BLE001
            err = e
    # Neither layout imports: stop with a hint.
    if BaseControlPlane is None:
        raise SystemExit(
            "Cannot import BaseControlPlane — run where the lm core is on disk "
            f"(e.g. PYTHONPATH=/opt/lm/core/src). Last error: {err}")

    class FeedSpoke(BaseControlPlane):
        """A real spoke client replaying a fixed snapshot instead of inventing one.

        Side-effects are neutralised the same way ``loadtest_spokes.LoadSpoke``
        does, and for the same reason: this is a throwaway identity that must
        never write a real ``.env``, touch healthy-marker files, or act on
        SPOKE_UPDATE (which would git-pull /opt/lm and restart the host)."""

        def __init__(self, spoke_id, payload, stats, interval=30.0,
                     module_type="simulation", display_name="", **kw):
            """Configure one replaying spoke.

            Args:
                spoke_id: synthetic id on the target hub.
                payload: this spoke's scrubbed telemetry data.
                stats: shared counters.
                interval: seconds between telemetry sends (minimum 5).
                module_type: module type to register as.
                display_name: production name to show on the target.
                **kw: passed to BaseControlPlane (hub_url, secrets, PSK, tenant hint).
            """
            super().__init__(spoke_id=spoke_id, **kw)
            # Replay each spoke as its REAL module type so the target shows the
            # whole fleet, not a wall of "simulation". Client-Sim hosts keep the
            # simulation type (→ exercises the telemetry path); everything else
            # (nw, dns, agent, …) registers as itself and shows online via its
            # heartbeat with empty deep pages.
            self.module_type = module_type or "simulation"
            if display_name:
                # Seeds the target's display_name on register (state/manager),
                # so the spoke shows its production name, not its raw id.
                self.hostname = display_name
            # Payload to replay, whether it has telemetry rows, shared stats and send interval.
            self._payload = payload
            self._has_telemetry = self._payload_has_telemetry(payload)
            self._stats = stats
            self._interval = max(5.0, float(interval))
            # Throttled diagnostics: a synthetic spoke that cannot attach (bad
            # PSK, auth reject, TLS, target down) used to bump a counter and
            # retry in silence, leaving the operator a climbing conn_err with no
            # reason. Surface the actual exception on the first failure and then
            # at most once a minute per spoke so a persistent fault stays
            # visible without flooding the captured log.
            self._first_connect_logged = False
            self._last_conn_err_log = 0.0
            self._last_send_err_log = 0.0
            # Detach the log-relay handler so synthetic spokes do not ship logs to the target hub.
            try:
                import logging
                logging.getLogger().removeHandler(self._log_relay_handler)
            except Exception:
                pass

        def set_payload(self, payload):
            """Swap in a freshly polled snapshot — this is what makes the feed
            live rather than a fixture frozen at startup."""
            self._payload = payload
            self._has_telemetry = self._payload_has_telemetry(payload)

        @staticmethod
        def _payload_has_telemetry(payload):
            """True when this spoke has Client-Sim rows to replay. Identity-only
            spokes (no clients/VMs) skip CS_TELEMETRY so they don't seed the
            target's simulations_cache with a phantom zero-client host — the
            heartbeat alone keeps them online with their real type/name."""
            # True if there are any clients or VMs (either key name) to report.
            p = payload or {}
            return bool(p.get("clients")) or bool(p.get("proxmox_vms")) or bool(p.get("vms"))

        # ── neutralise side-effects (mirrors loadtest_spokes.LoadSpoke) ──────
        def _ensure_install_uuid(self):
            """Return a stable install id derived from the spoke id (no .env writes)."""
            # STABLE per synthetic spoke. The hub keys a module by its
            # install_uuid (guid-primary in hub_identity), so a fresh random uuid
            # every run makes each feeder restart mint a BRAND-NEW module for the
            # same spoke — the target fleet accretes a ghost copy of every spoke
            # on every feed bounce (the accumulation that leaves hundreds of
            # stale offline entries). Derive it deterministically from the stable
            # spoke_id so a restart re-attaches to the SAME module instead.
            import uuid
            return uuid.uuid5(uuid.NAMESPACE_OID,
                              f"lm-feed-install:{self.spoke_id}").hex

        def _persist_session_secret(self, new_secret):
            """Do not persist rotated session secrets (throwaway spoke)."""
            pass

        def _persist_hub_secret(self, new_secret):
            """Do not persist the hub secret."""
            pass

        def _persist_recovery_psk(self, new_psk):
            """Do not persist a recovery PSK."""
            pass

        def _touch_healthy_marker(self):
            """Do not create the healthy marker file."""
            pass

        def _clear_healthy_marker(self):
            """Do not remove a healthy marker file."""
            pass

        async def handle_system_command(self, cmd_type, data):
            """Handle a hub system command, ignoring SPOKE_UPDATE so nothing is pulled or
            restarted.
            """
            if cmd_type == "SPOKE_UPDATE":
                return {"status": "SUCCESS", "message": "hub_feed: SPOKE_UPDATE ignored"}
            return await super().handle_system_command(cmd_type, data)

        def _create_spoke_tasks(self, websocket):
            """Return the per-connection tasks: the telemetry feed loop, or nothing for identity-
            only spokes.
            """
            if not self._has_telemetry:
                # No Client-Sim telemetry to emit: the heartbeat thread (started
                # in _connect_and_serve, independent of these tasks) keeps the
                # spoke ONLINE with its real type/name. Sending empty telemetry
                # would only pollute the target's simulations_cache.
                return []
            return [asyncio.create_task(self._feed_loop(websocket))]

        async def _feed_loop(self, websocket):
            """Send the current snapshot as signed CS_TELEMETRY every interval until the connection
            fails.
            """
            import uuid
            # Send until cancelled or a send fails.
            while True:
                try:
                    now = time.time()
                    # Copy the payload and stamp this spoke's id as the host.
                    data = dict(self._payload)
                    data["host"] = self.spoke_id
                    # Message envelope: header plus the CS_TELEMETRY payload.
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()),
                                   "timestamp": round(now, 6),
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "CS_TELEMETRY", "data": data},
                    }
                    # Sign, send and count it.
                    await websocket.send(self._encode_frame(msg))
                    self._stats["sent"] += 1
                # Cancellation must propagate.
                except asyncio.CancelledError:
                    raise
                # Send failed: count it, log at most once a minute, and let the reconnect loop take
                # over.
                except Exception as e:  # noqa: BLE001
                    self._stats["send_err"] += 1
                    now = time.time()
                    if now - self._last_send_err_log >= 60:
                        self._last_send_err_log = now
                        print(f"  ! {self.spoke_id}: send failed: {e!r} — "
                              f"reconnecting", file=sys.stderr)
                    return  # let the reconnect loop take over
                # Wait before the next send.
                await asyncio.sleep(self._interval)

        async def run_forever(self, stop_evt):
            """Reconnect loop without the updater worker — a synthetic spoke must
            never self-update."""
            # Resolve the target hub URL, then reconnect with back-off until stopped.
            await self._resolve_hub_url()
            delay = 1
            while not stop_evt.is_set():
                t0 = time.time()
                # Connect and serve; log the first successful attach once; reset the back-off.
                try:
                    self._stats["connects"] += 1
                    await self._connect_and_serve()
                    if not self._first_connect_logged:
                        self._first_connect_logged = True
                        print(f"  ✓ {self.spoke_id}: attached to {self.hub_url}")
                    delay = 1
                # Cancellation must propagate.
                except asyncio.CancelledError:
                    raise
                # Failure: count it, log at most once a minute, and back off (short retry after a
                # long-lived session, else doubling up to 30s).
                except Exception as e:  # noqa: BLE001
                    self._stats["conn_err"] += 1
                    now = time.time()
                    if now - self._last_conn_err_log >= 60:
                        self._last_conn_err_log = now
                        print(f"  ! {self.spoke_id}: cannot attach to "
                              f"{self.hub_url}: {e!r}", file=sys.stderr)
                    delay = 5 if (time.time() - t0) >= 30 else min(delay * 2, 30)
                # Wait before reconnecting unless the run is ending.
                if not stop_evt.is_set():
                    await asyncio.sleep(delay)

    # Return the class so the caller can instantiate it.
    return FeedSpoke


def _resolve_tenant(payload, tenant_map, default):
    """The target tenant hint for one spoke. In preserve mode the payload
    carries its SOURCE tenant; map it to a local tenant, defaulting to
    ``default`` for an unmapped or unattributed spoke. Returns None when there
    is no tenant at all, so the spoke onboards unbound rather than to ''."""
    # Map the source tenant through the tenant map when both exist.
    st = (payload or {}).get("tenant")
    if st and tenant_map:
        return tenant_map.get(str(st), default) or None
    # Otherwise use the default tenant (None if blank).
    return default or None


async def _run(args, source, salt):
    """Poll the source, start one synthetic spoke per source spoke, and keep them updated.

    Args:
        args: parsed command-line arguments.
        source: SourceHub client.
        salt: pseudonym salt for identity scrubbing.
    """
    # Build the spoke class (needs the lm core), shared counters and the stop event.
    FeedSpoke = _load_feed_spoke()
    stats = {"sent": 0, "send_err": 0, "connects": 0, "conn_err": 0, "polls": 0}
    stop_evt = asyncio.Event()

    # Source tenant -> local tenant mapping (empty when not preserving tenants).
    tenant_map = getattr(args, "_tenant_map", None) or {}

    def _tenant_for(payload):
        """Return the target tenant hint for a spoke's payload."""
        return _resolve_tenant(payload, tenant_map, args.tenant)

    def _clean(payload):
        """Drop the routing/identity-only keys so the replayed CS_TELEMETRY
        matches production shape (tenant/module_type/name are metadata, not
        fleet data — they're consumed at registration, not in telemetry)."""
        # Keys used only for registration, not part of telemetry.
        drop = ("tenant", "module_type", "name")
        if isinstance(payload, dict) and any(k in payload for k in drop):
            payload = {k: v for k, v in payload.items() if k not in drop}
        return payload

    # Absolute stop time, or None to run forever.
    deadline = time.time() + args.duration if args.duration > 0 else None
    # First poll: scrubbed per-spoke payloads keyed by synthetic spoke id.
    payloads = build_payloads(source.snapshot(), salt, args.prefix)
    stats["polls"] += 1
    if not payloads:
        # The source has no spokes YET — e.g. no active simulations are
        # producing telemetry at the moment the feed comes up. A hub restart
        # resumes the feed the instant the process is back, which can easily
        # beat the source having data. Historically this raised SystemExit, so
        # the feeder died and the feed stayed silently dead until the NEXT
        # restart. Instead, keep polling so the feed goes live on its own the
        # moment the source produces data — no operator round-trip needed.
        print("Source snapshot has no spokes yet — waiting for the source to "
              f"produce data (re-polling every {int(args.interval)}s)…",
              file=sys.stderr)
        # Keep polling until the source has data or the deadline passes.
        while not payloads:
            if deadline and time.time() >= deadline:
                raise SystemExit("Source snapshot stayed empty for the whole "
                                 "run — nothing to feed.")
            await asyncio.sleep(args.interval)
            try:
                payloads = build_payloads(source.snapshot(), salt, args.prefix)
                stats["polls"] += 1
            except Exception as e:  # noqa: BLE001
                print(f"  ! poll while waiting for data failed: {e}",
                      file=sys.stderr)
    # Announce what we are about to feed.
    if tenant_map:
        print(f"Feeding {len(payloads)} synthetic spoke(s) → {args.target} "
              f"(preserving {len(set(tenant_map.values()))} tenant[s])")
    else:
        print(f"Feeding {len(payloads)} synthetic spoke(s) → {args.target}")

    # Running spokes by id, and their tasks.
    spokes = {}
    tasks = []

    def _spawn(sid, payload):
        """Create + start one synthetic spoke and register it. Shared by the
        initial fan-out and the re-poll pickup of spokes that appear later."""
        # Register with the production name/type and the right tenant on the target.
        s = FeedSpoke(spoke_id=sid, payload=_clean(payload), stats=stats,
                      interval=args.telemetry_interval,
                      module_type=(payload or {}).get("module_type") or "simulation",
                      display_name=(payload or {}).get("name") or "",
                      hub_url=args.target, hub_secret=args.secret or None,
                      onboarding_psk=args.psk or None,
                      tenant_id_hint=_tenant_for(payload))
        # Track the spoke and start its reconnect loop.
        spokes[sid] = s
        tasks.append(asyncio.create_task(s.run_forever(stop_evt)))

    # Start every spoke, spread over the --ramp period.
    for sid, payload in payloads.items():
        _spawn(sid, payload)
        await asyncio.sleep(args.ramp / max(1, len(payloads)))

    # Main loop: re-poll the source every interval until stopped or the deadline passes.
    try:
        while not stop_evt.is_set():
            await asyncio.sleep(args.interval)
            if deadline and time.time() >= deadline:
                break
            # Re-poll: this is what keeps the target live. Spokes that appear in
            # production after the feed started are ADDED so the target keeps
            # converging on the full source fleet without an operator restart.
            # We never remove: a spoke that vanishes from the source is left in
            # place, because dropping it would orphan its registration on the
            # target and churn the view.
            try:
                # Fetch a fresh snapshot and find spokes we have not seen yet.
                fresh = build_payloads(source.snapshot(), salt, args.prefix)
                stats["polls"] += 1
                new_ids = [sid for sid in fresh if sid not in spokes]
                # Existing spokes get the new data in place.
                for sid, payload in fresh.items():
                    if sid in spokes:
                        spokes[sid].set_payload(_clean(payload))
                # New spokes are started, spread over the ramp period.
                for sid in new_ids:
                    _spawn(sid, fresh[sid])
                    await asyncio.sleep(args.ramp / max(1, len(new_ids)))
                # One summary line per poll.
                extra = f"; +{len(new_ids)} new" if new_ids else ""
                print(f"  poll {stats['polls']}: refreshed {len(fresh)} spoke(s)"
                      f"{extra}; sent={stats['sent']} conn_err={stats['conn_err']}")
            # A failed poll keeps sending the previous data.
            except Exception as e:  # noqa: BLE001
                print(f"  ! re-poll failed: {e} — keeping the previous snapshot",
                      file=sys.stderr)
    # Ctrl-C or cancellation ends the loop quietly.
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    # Always stop and wait for every spoke task.
    finally:
        stop_evt.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    # Final counters.
    print(f"Done. polls={stats['polls']} sent={stats['sent']} "
          f"send_err={stats['send_err']} conn_err={stats['conn_err']}")


def _read_password(arg):
    """Return the password: read from stdin or prompt when arg is "-", else use arg as-is."""
    # "-" means read from piped stdin, or prompt interactively when stdin is a terminal.
    if arg == "-":
        return sys.stdin.readline().rstrip("\n") if not sys.stdin.isatty() \
            else getpass.getpass("Source hub password: ")
    return arg


def build_parser():
    """The feeder's argument parser. Extracted from ``main`` so callers (and the
    test suite) can validate that a hub-built argv actually parses — in
    particular that dash-leading URL-safe-base64 tokens survive as ``--flag=value``
    rather than being misread as options."""
    # Parser with one option per CLI flag (see each help text).
    ap = argparse.ArgumentParser(
        description="Replay production fleet data into a dev/qa/lrb hub.")
    ap.add_argument("--source", required=True,
                    help="SOURCE hub WebUI base URL, read-only (https://HOST)")
    ap.add_argument("--token", default="",
                    help="source hub API access token (Bearer). Preferred over "
                         "--source-user/--source-pass; skips the login entirely.")
    ap.add_argument("--refresh-token", default="",
                    help="refresh token from the SAME pair, so a long run can "
                         "rotate its own access token instead of dying at expiry")
    ap.add_argument("--source-user", default="admin", help="source hub login")
    ap.add_argument("--source-pass", default="-",
                    help="source password; '-' reads stdin / prompts (default)")
    ap.add_argument("--target", default="",
                    help="TARGET hub WS URL (wss://HOST:PORT) — the dev/qa/lrb hub")
    ap.add_argument("--tenant", default="", help="target tenant id hint")
    ap.add_argument("--tenant-map", default="",
                    help="JSON object {source_tenant: local_tenant} for preserve "
                         "mode — each synthetic spoke is bound to the local tenant "
                         "mapped from its source tenant, defaulting to --tenant.")
    ap.add_argument("--psk", default="", help="target tenant onboarding PSK (auto-approves)")
    ap.add_argument("--secret", default="", help="pre-provisioned target spoke secret")
    ap.add_argument("--prefix", default="feed-",
                    help="synthetic spoke id prefix on the target (for cleanup)")
    ap.add_argument("--salt", default="",
                    help="pseudonym salt; default random per run. Pin it to keep "
                         "identities stable across restarts of this feeder.")
    ap.add_argument("--interval", type=float, default=60.0,
                    help="seconds between source re-polls (default 60)")
    ap.add_argument("--telemetry-interval", type=float, default=30.0,
                    help="seconds between CS_TELEMETRY sends per spoke (default 30)")
    ap.add_argument("--duration", type=int, default=0, help="stop after N seconds (0 = run forever)")
    ap.add_argument("--ramp", type=float, default=10.0,
                    help="seconds to stagger all target connects over")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the scrubbed snapshot and exit; never touches the target")
    ap.add_argument("--emit-token-rotations", action="store_true",
                    help="print a TOKEN_ROTATION_SENTINEL line on every token "
                         "rotation so a parent hub can persist the new pair. The "
                         "hub sets this; a human running the feeder by hand should "
                         "not (it would print tokens to the terminal).")
    return ap


def main():
    """Parse arguments, validate them, connect to the source, then dry-run or start the feed."""
    # Read the command line.
    ap = build_parser()
    args = ap.parse_args()

    # A target is needed unless only dry-running.
    if not args.dry_run and not args.target:
        ap.error("--target is required unless --dry-run")
    # Never allow the target to be the source hub.
    if args.target:
        _assert_distinct(args.source, args.target)

    # Parse the optional tenant map JSON, dropping empty mappings.
    args._tenant_map = {}
    if args.tenant_map:
        try:
            m = json.loads(args.tenant_map)
            if isinstance(m, dict):
                args._tenant_map = {str(k): str(v) for k, v in m.items() if v}
        except Exception as e:  # noqa: BLE001
            ap.error(f"--tenant-map is not valid JSON: {e}")

    # Use the given salt, or a random 16-hex-character one for this run.
    salt = args.salt or hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    # Read-only client for the source hub.
    source = SourceHub(args.source, token=args.token,
                       refresh_token=args.refresh_token,
                       emit_rotations=args.emit_token_rotations)
    # A token authenticates on its own — only fall back to the interactive
    # username/password login when none was supplied. Logging in anyway would
    # prompt for a password in a context (the hub's child process) that has no
    # terminal to prompt on.
    if not args.token:
        source.login(args.source_user, _read_password(args.source_pass))

    # Dry run: print the scrubbed payloads (capped at 20,000 characters) and stop.
    if args.dry_run:
        payloads = build_payloads(source.snapshot(), salt, args.prefix)
        print(json.dumps(payloads, indent=2, sort_keys=True)[:20000])
        print(f"\n-- {len(payloads)} spoke(s); salt={salt} (dry run, target untouched)")
        return

    # Run the feed until stopped.
    asyncio.run(_run(args, source, salt))


# Run main(); Ctrl-C exits quietly.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
