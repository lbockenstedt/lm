"""security/decoy_engine.py — generic hub-side decoy (honeypot) route engine.

A request path that no legitimate client, SPA route, agent or internal code path
ever touches is high-signal by construction: there is no benign reason to ask
for it, so a single hit is evidence rather than a statistic. This module serves
such paths and reports the interaction.

Design contract (why this file contains no decoy paths)
-------------------------------------------------------
* **Generic engine only.** It ships with **zero** endpoints and is completely
  inert until a set is applied at runtime. The paths, and the bodies served, are
  supplied by the operator or a feed and are **never** hard-coded here — so the
  public source reveals no path, no bait and no signature. This is what lets an
  install serve honeypot routes without holding the private sensor code: the
  neutral mechanism is public, the sensitive content arrives as data.
* **Serve, don't slam.** A trip is answered with a plausible body, not a reset
  or a 404. Killing the connection would hand a scanner a per-path oracle: it
  could diff decoys from real 404s and map the decoy set, which both burns the
  set and tells the attacker exactly what is watched.
* **Detection is reported, not decided here.** The engine records the trip
  through a caller-supplied sink; consequences (blocking, feed publication) stay
  with the threat monitor, which already owns exemptions and rate limits.

Two failure modes drove the shape of this module
------------------------------------------------
1. **Route shadowing.** Middleware runs BEFORE routing, so a decoy always wins
   over a real endpoint of the same path. An applied set containing, say,
   ``/api/health`` would silently shadow that endpoint and answer every
   legitimate client with decoy junk — an outage caused by the defence. Shape
   validation alone (the check ``node_canary.set_config`` performs) does not
   catch this. :meth:`DecoyEngine.set_config` therefore refuses any path that
   the application can actually route, matching against each route's compiled
   regex so templated routes (``/api/spokes/{id}``) are caught too, not just
   literal ones.
2. **Untestable by construction.** The private sensor exempts loopback and
   blocks any other source, which leaves no way to exercise it end to end:
   from loopback it falls through to a real 404, from anywhere else it locks
   you out. Here loopback still **matches, serves and logs** — it is only
   exempt from being reported as an attacker. That preserves a safe local test
   path without making loopback a bypass an attacker could reach.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

logger = logging.getLogger("Security")

# Applied to every candidate path so a set pushed with trivial casing/slash
# variation matches the same way the probe/canary matchers normalise.
_MAX_BODY_BYTES = 64 * 1024


def normalize_path(path: str) -> str:
    """Normalise a request path for matching: drop the query, lowercase, strip a
    trailing slash. Mirrors ``node_canary._norm`` so a path behaves identically
    whether it is served at the edge or at the hub."""
    p = (path or "").split("?", 1)[0].strip().lower()
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    return p


def _is_loopback(host: Optional[str]) -> bool:
    """True for a loopback peer. Best-effort: an unparseable/absent host is NOT
    treated as loopback, so an odd transport can never win the exemption."""
    if not host:
        return False
    try:
        return ipaddress.ip_address(host.strip()).is_loopback
    except ValueError:
        return host.strip().lower() == "localhost"


def routable_matchers(app: Any) -> List[Any]:
    """Compiled regexes for every path the application can actually route.

    Uses each route's ``path_regex`` where Starlette provides one so templated
    routes are covered — ``/api/spokes/{id}`` must reserve ``/api/spokes/foo``,
    not merely the literal string with braces in it. Falls back to an anchored
    escape of ``path`` for anything without a compiled regex (mounts, static).
    Never raises: a route object that does not look the way we expect is skipped
    rather than taking down config application."""
    out: List[Any] = []
    for route in (getattr(app, "routes", None) or ()):
        try:
            rx = getattr(route, "path_regex", None)
            if rx is not None and hasattr(rx, "match"):
                out.append(rx)
                continue
            raw = getattr(route, "path", None) or getattr(route, "path_format", None)
            if raw:
                out.append(re.compile("^" + re.escape(str(raw)) + "/?$"))
        except Exception:  # noqa: BLE001 — one odd route must not block the set
            logger.debug("decoy_engine: skipped unreadable route", exc_info=True)
    return out


class DecoyEngine:
    """Holds one decoy set and answers path lookups against it.

    Instance-based (not a module singleton) so the hub, a test and any future
    second consumer each get an isolated set — a module global would make the
    collision rules of one process leak into another's assertions.
    """

    def __init__(self, name: str = "hub") -> None:
        self._name = name
        # normalised path -> {"status", "ctype", "body", "tier"}
        self._entries: Dict[str, Dict[str, Any]] = {}
        self._rejected: List[Tuple[str, str]] = []

    # ── configuration ────────────────────────────────────────────────────────

    def set_config(self, entries: Optional[Iterable[Dict[str, Any]]],
                   reserved: Optional[Iterable[Any]] = None) -> int:
        """Replace the active decoy set. Returns the number of decoys now live.

        ``reserved`` is the output of :func:`routable_matchers` (or any iterable
        of compiled regexes). Any candidate the application can route is
        REFUSED, because middleware precedence means it would shadow the real
        endpoint and answer legitimate clients with decoy junk.

        Never raises. A malformed or dangerous entry is dropped and recorded in
        :meth:`rejected`; one bad entry must not discard the rest of the set,
        and a bad push must never brick the request path.
        """
        built: Dict[str, Dict[str, Any]] = {}
        rejected: List[Tuple[str, str]] = []
        matchers = list(reserved or ())
        for raw in (entries or ()):
            try:
                path = normalize_path(str((raw or {}).get("path", "")))
                if not path or not path.startswith("/"):
                    rejected.append((path or "<empty>", "not an absolute path"))
                    continue
                if path in built:
                    rejected.append((path, "duplicate in set"))
                    continue
                shadowed = self._shadows_real_route(path, matchers)
                if shadowed:
                    rejected.append((path, "would shadow a real route"))
                    continue
                body = self._coerce_body(raw.get("body", ""))
                built[path] = {
                    "status": int(raw.get("status", 200) or 200),
                    "ctype": str(raw.get("ctype", "text/plain") or "text/plain"),
                    "body": body,
                    "tier": str(raw.get("tier", "decoy") or "decoy"),
                }
            except Exception:  # noqa: BLE001
                logger.debug("decoy_engine: skipped malformed entry", exc_info=True)
                rejected.append((str((raw or {}).get("path", "?")), "malformed"))
        self._entries = built
        self._rejected = rejected
        if rejected:
            # WARNING, not debug: a refused decoy is a silently reduced sensor.
            # The operator needs to know the set they pushed is not the set that
            # is live, and specifically that something collided with a real route.
            logger.warning(
                "decoy_engine[%s]: %d decoy(s) active, %d refused (%s)",
                self._name, len(built), len(rejected),
                "; ".join(f"{p}: {why}" for p, why in rejected[:10]))
        else:
            logger.info("decoy_engine[%s]: %d decoy(s) active", self._name, len(built))
        return len(built)

    @staticmethod
    def _shadows_real_route(path: str, matchers: Iterable[Any]) -> bool:
        """True when the application can route ``path`` — i.e. serving it as a
        decoy would take a working endpoint away from real clients."""
        for rx in matchers:
            try:
                if rx.match(path) or rx.match(path + "/"):
                    return True
            except Exception:  # noqa: BLE001
                continue
        return False

    @staticmethod
    def _coerce_body(body: Any) -> bytes:
        """Bodies arrive from a feed, so cap them: an oversized body would let a
        bad or hostile push turn every scan into an amplification response."""
        if isinstance(body, str):
            out = body.encode("utf-8", "replace")
        elif isinstance(body, (bytes, bytearray)):
            out = bytes(body)
        else:
            out = str(body).encode("utf-8", "replace")
        return out[:_MAX_BODY_BYTES]

    def clear(self) -> None:
        """Drop all decoys (teardown / disable). Returns the engine to inert."""
        self._entries = {}
        self._rejected = []

    # ── introspection ────────────────────────────────────────────────────────

    def is_active(self) -> bool:
        return bool(self._entries)

    def count(self) -> int:
        return len(self._entries)

    def rejected(self) -> List[Tuple[str, str]]:
        """(path, reason) for every entry refused by the last ``set_config`` —
        surfaced so a shadowing collision is diagnosable rather than mysterious."""
        return list(self._rejected)

    def paths(self) -> Set[str]:
        """The live decoy paths. For hub-side bookkeeping only — never serialise
        this to a participant or into a published feed record; the decoy set is
        the sensor, and disclosing it burns it."""
        return set(self._entries)

    def match(self, path: str) -> Optional[Dict[str, Any]]:
        """The response spec for ``path`` if it is a decoy, else ``None``.
        Cheap dict lookup; empty set → always ``None`` (inert)."""
        if not self._entries:
            return None
        return self._entries.get(normalize_path(path))


def register_decoy_middleware(app: Any, engine: DecoyEngine,
                              on_trip: Optional[Callable[..., None]] = None) -> None:
    """Install the decoy middleware on ``app``.

    Registered late so it runs OUTERMOST: Starlette inserts each middleware at
    index 0, so the last registered is the first to see a request. A decoy must
    win over the probe-signature layer, otherwise a path that is both a known
    scanner target and a decoy is consumed as a generic probe and the
    higher-confidence signal is lost.

    ``on_trip(path, peer_ip, tier, loopback)`` receives every trip. It is called
    defensively — a reporting fault must not change what the client sees, or the
    response would differ between "reported" and "not reported" and become an
    oracle.
    """
    from starlette.responses import Response  # local: keeps import cost off the
    # path for installs that never enable decoys

    @app.middleware("http")
    async def _decoy_mw(request, call_next):  # noqa: ANN001
        try:
            spec = engine.match(request.url.path)
        except Exception:  # noqa: BLE001 — never break real traffic
            spec = None
        if spec is None:
            return await call_next(request)

        peer_ip = None
        try:
            peer_ip = request.client.host if request.client else None
        except Exception:  # noqa: BLE001
            peer_ip = None
        loopback = _is_loopback(peer_ip)

        if on_trip is not None:
            try:
                on_trip(path=request.url.path, peer_ip=peer_ip,
                        tier=spec.get("tier", "decoy"), loopback=loopback)
            except Exception:  # noqa: BLE001
                logger.debug("decoy_engine: trip sink raised", exc_info=True)

        return Response(content=spec["body"], status_code=spec["status"],
                        media_type=spec["ctype"])
