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
import argparse
import asyncio
import getpass
import hashlib
import http.cookiejar
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Same core-locating dance as loadtest_spokes.py — see its module docstring.
_repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in ("/opt/lm", "/opt/lm/core/src", _repo, os.path.join(_repo, "core", "src")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

# The filter/reshape logic is SHARED with the hub's own routes/test_feed.py —
# see core/src/test_feed_scrub.py. It lives there, not here, because the source
# hub applies it before serving a snapshot and this feeder applies it again on
# the way in; two copies would drift, and a drift in DROP_FIELDS would mean
# secrets getting replayed.
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


class SourceHub:
    """Read-only client for the source hub's aggregate API.

    GET is the only verb this class can issue. Keeping the transport in one
    method (``_get_json``) is deliberate: it makes "does this script write to
    production?" answerable by reading twenty lines rather than auditing every
    call site."""

    def __init__(self, base_url, insecure=True, token="", refresh_token=""):
        self.base = base_url.rstrip("/")
        self.token = (token or "").strip()
        # Access tokens are short-lived (4h — api_tokens.issue_pair). Without a
        # refresh token a long feed dies overnight and reads as "it randomly
        # stopped"; with one, _get_json rotates the pair on the first 401.
        self.refresh_token = (refresh_token or "").strip()
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            urllib.request.HTTPSHandler(context=ctx))

    def login(self, username, password):
        """POST /auth/login once to mint the ``lm_session`` cookie.

        The single non-GET request in this script, and it only authenticates —
        it creates a session, not fleet state."""
        body = json.dumps({"username": username, "password": password}).encode()
        req = urllib.request.Request(
            f"{self.base}/auth/login", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(req, timeout=20) as r:
                r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise SystemExit("Source hub rejected the credentials (401).")
            if e.code == 429:
                raise SystemExit("Source hub is rate-limiting logins (429) — wait and retry.")
            raise SystemExit(f"Source hub login failed: HTTP {e.code}")
        if not any(c.name == "lm_session" for c in self.jar):
            raise SystemExit("Login returned no lm_session cookie — is --source the hub's WebUI URL?")

    def _raw_get(self, path):
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        req = urllib.request.Request(f"{self.base}{path}", headers=headers, method="GET")
        with self.opener.open(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def _rotate(self):
        """Exchange the refresh token for a new access+refresh pair.

        Refresh tokens are SINGLE-USE and reuse revokes the whole family, so the
        new pair must replace the old one before the next attempt — a retry that
        re-sent the spent token would lock this feed out entirely."""
        if not self.refresh_token:
            return False
        body = json.dumps({"refresh_token": self.refresh_token}).encode()
        req = urllib.request.Request(
            f"{self.base}/auth/token/refresh", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(req, timeout=20) as r:
                d = json.loads(r.read().decode())
        except Exception as e:  # noqa: BLE001
            print(f"  ! token refresh failed: {e}", file=sys.stderr)
            self.refresh_token = ""   # spent or rejected; don't spin on it
            return False
        self.token = d.get("access_token") or self.token
        self.refresh_token = d.get("refresh_token") or ""
        print("  token refreshed")
        return True

    def _get_json(self, path):
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
        try:
            served = self._get_json("/api/test-feed/snapshot")
            if isinstance(served, dict) and "spokes" in served:
                return {"_preserved": served}
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
        p = urllib.parse.urlparse(u if "//" in u else f"//{u}")
        port = p.port or (443 if (p.scheme or "https") in ("https", "wss") else 80)
        return ((p.hostname or "").lower(), port)

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
    BaseControlPlane = None
    err = None
    for mod in ("core.src.messaging.control_plane", "messaging.control_plane"):
        try:
            BaseControlPlane = __import__(mod, fromlist=["BaseControlPlane"]).BaseControlPlane
            break
        except Exception as e:  # noqa: BLE001
            err = e
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

        def __init__(self, spoke_id, payload, stats, interval=30.0, **kw):
            super().__init__(spoke_id=spoke_id, **kw)
            self.module_type = "simulation"   # cs-like → exercises the telemetry path
            self._payload = payload
            self._stats = stats
            self._interval = max(5.0, float(interval))
            try:
                import logging
                logging.getLogger().removeHandler(self._log_relay_handler)
            except Exception:
                pass

        def set_payload(self, payload):
            """Swap in a freshly polled snapshot — this is what makes the feed
            live rather than a fixture frozen at startup."""
            self._payload = payload

        # ── neutralise side-effects (mirrors loadtest_spokes.LoadSpoke) ──────
        def _ensure_install_uuid(self):
            import uuid
            return uuid.uuid4().hex

        def _persist_session_secret(self, new_secret):
            pass

        def _persist_hub_secret(self, new_secret):
            pass

        def _persist_recovery_psk(self, new_psk):
            pass

        def _touch_healthy_marker(self):
            pass

        def _clear_healthy_marker(self):
            pass

        async def handle_system_command(self, cmd_type, data):
            if cmd_type == "SPOKE_UPDATE":
                return {"status": "SUCCESS", "message": "hub_feed: SPOKE_UPDATE ignored"}
            return await super().handle_system_command(cmd_type, data)

        def _create_spoke_tasks(self, websocket):
            return [asyncio.create_task(self._feed_loop(websocket))]

        async def _feed_loop(self, websocket):
            import uuid
            while True:
                try:
                    now = time.time()
                    data = dict(self._payload)
                    data["host"] = self.spoke_id
                    msg = {
                        "header": {"message_id": str(uuid.uuid4()),
                                   "timestamp": round(now, 6),
                                   "sender_id": self.spoke_id, "destination_id": "hub"},
                        "payload": {"type": "CS_TELEMETRY", "data": data},
                    }
                    await websocket.send(self._encode_frame(msg))
                    self._stats["sent"] += 1
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self._stats["send_err"] += 1
                    return  # let the reconnect loop take over
                await asyncio.sleep(self._interval)

        async def run_forever(self, stop_evt):
            """Reconnect loop without the updater worker — a synthetic spoke must
            never self-update."""
            await self._resolve_hub_url()
            delay = 1
            while not stop_evt.is_set():
                t0 = time.time()
                try:
                    self._stats["connects"] += 1
                    await self._connect_and_serve()
                    delay = 1
                except Exception:
                    self._stats["conn_err"] += 1
                    delay = 5 if (time.time() - t0) >= 30 else min(delay * 2, 30)
                if not stop_evt.is_set():
                    await asyncio.sleep(delay)

    return FeedSpoke


async def _run(args, source, salt):
    FeedSpoke = _load_feed_spoke()
    stats = {"sent": 0, "send_err": 0, "connects": 0, "conn_err": 0, "polls": 0}
    stop_evt = asyncio.Event()

    payloads = build_payloads(source.snapshot(), salt, args.prefix)
    stats["polls"] += 1
    if not payloads:
        raise SystemExit("Source snapshot produced no spokes — nothing to feed.")
    print(f"Feeding {len(payloads)} synthetic spoke(s) → {args.target}")

    spokes = {}
    tasks = []
    for sid, payload in payloads.items():
        s = FeedSpoke(spoke_id=sid, payload=payload, stats=stats,
                      interval=args.telemetry_interval,
                      hub_url=args.target, hub_secret=args.secret or None,
                      onboarding_psk=args.psk or None,
                      tenant_id_hint=args.tenant or None)
        spokes[sid] = s
        tasks.append(asyncio.create_task(s.run_forever(stop_evt)))
        await asyncio.sleep(args.ramp / max(1, len(payloads)))

    deadline = time.time() + args.duration if args.duration > 0 else None
    try:
        while not stop_evt.is_set():
            await asyncio.sleep(args.interval)
            if deadline and time.time() >= deadline:
                break
            # Re-poll: this is what keeps the target live. New spokes appearing
            # in production mid-run are ignored for this process's lifetime —
            # restarting picks them up, and churning the spoke set would leave
            # orphaned registrations on the target.
            try:
                fresh = build_payloads(source.snapshot(), salt, args.prefix)
                stats["polls"] += 1
                for sid, payload in fresh.items():
                    if sid in spokes:
                        spokes[sid].set_payload(payload)
                print(f"  poll {stats['polls']}: refreshed {len(fresh)} spoke(s); "
                      f"sent={stats['sent']} conn_err={stats['conn_err']}")
            except Exception as e:  # noqa: BLE001
                print(f"  ! re-poll failed: {e} — keeping the previous snapshot",
                      file=sys.stderr)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop_evt.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    print(f"Done. polls={stats['polls']} sent={stats['sent']} "
          f"send_err={stats['send_err']} conn_err={stats['conn_err']}")


def _read_password(arg):
    if arg == "-":
        return sys.stdin.readline().rstrip("\n") if not sys.stdin.isatty() \
            else getpass.getpass("Source hub password: ")
    return arg


def main():
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
    args = ap.parse_args()

    if not args.dry_run and not args.target:
        ap.error("--target is required unless --dry-run")
    if args.target:
        _assert_distinct(args.source, args.target)

    salt = args.salt or hashlib.sha256(os.urandom(32)).hexdigest()[:16]

    source = SourceHub(args.source, token=args.token,
                       refresh_token=args.refresh_token)
    # A token authenticates on its own — only fall back to the interactive
    # username/password login when none was supplied. Logging in anyway would
    # prompt for a password in a context (the hub's child process) that has no
    # terminal to prompt on.
    if not args.token:
        source.login(args.source_user, _read_password(args.source_pass))

    if args.dry_run:
        payloads = build_payloads(source.snapshot(), salt, args.prefix)
        print(json.dumps(payloads, indent=2, sort_keys=True)[:20000])
        print(f"\n-- {len(payloads)} spoke(s); salt={salt} (dry run, target untouched)")
        return

    asyncio.run(_run(args, source, salt))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
