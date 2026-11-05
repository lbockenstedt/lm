"""security/node_canary.py — node-side operator canary endpoints (generic engine).

A node (edge proxy / role-hosted spoke UI) can be given, at runtime, a set of
*canary endpoints* by the hub: request paths that no legitimate client, SPA
route, agent, or internal code path ever touches. When one is requested, the
node answers with the operator-supplied body and relays the interaction up the
authenticated tunnel so the hub decides what to do centrally.

Design contract (why this file is deliberately empty of specifics)
------------------------------------------------------------------
* This module is a **generic engine only**. It ships with **zero** endpoints and
  is completely inert until the hub pushes a config (``NODE_CANARY_SET``). The
  set of paths, and the bodies served, are provided by the operator at runtime
  and are **never** hard-coded here — so the public source reveals no endpoint,
  no bait, and no signature. Mirrors the ``site_ext`` loader philosophy: the
  neutral mechanism is public, the sensitive content stays operator/hub-side.
* A canary has no legitimate use, so any interaction is high-signal by
  construction — this is not signature matching against real traffic.
* Detection/response logic lives on the hub. The node only *serves* the given
  body and *relays* the interaction; it never decides consequences. A node that
  is later compromised therefore learns only the endpoints it was itself
  assigned to serve (bounded further by hub-side rotation / per-node sets).

Thread/async model: a single in-process singleton (one node = one process that
runs both the control plane, which applies config, and the request server, which
matches + serves). Config replacement is atomic (dict swap).
"""
# Allows modern type-hint syntax regardless of the running Python version.
from __future__ import annotations

# Standard-library logging for configuration and skip diagnostics.
import logging
# Type hints only; they describe the shape of canary entries.
from typing import Any, Dict, List, Optional

# Share the "Security" logger so canary events appear with other security messages.
logger = logging.getLogger("Security")

# path (normalised) -> {"status": int, "ctype": str, "body": bytes}
_ENTRIES: Dict[str, Dict[str, Any]] = {}


def _norm(path: str) -> str:
    """Normalise a request path for matching: drop the query, lowercase, strip a
    trailing slash. Mirrors the hub/proxy probe-path normalisation so a matched
    endpoint trips regardless of trivial casing/slash variation."""
    # Keep only the part before "?", trim spaces and lowercase it.
    p = (path or "").split("?", 1)[0].strip().lower()
    # Remove a trailing slash, but keep the root path "/" itself intact.
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    return p


def set_config(entries: Optional[List[Dict[str, Any]]]) -> int:
    """Replace the active canary set with ``entries`` (hub-pushed).

    Each entry is ``{"path": str, "status"?: int, "ctype"?: str, "body"?: str}``.
    An empty / missing list clears the set (fully inert). Returns the number of
    endpoints now active. Never raises — a malformed push must not brick the
    node's request path; bad entries are skipped.
    """
    # Rebind the module-level table (not mutate it) so the swap is atomic for readers.
    global _ENTRIES
    # Build the new table separately; readers keep using the old one until the swap.
    built: Dict[str, Dict[str, Any]] = {}
    # Each hub-pushed entry describes one canary path and the response to serve for it.
    for e in (entries or ()):
        try:
            # Normalise the path the same way incoming requests are, so lookups match.
            path = _norm(str(e.get("path", "")))
            # Ignore entries without a usable absolute path.
            if not path or not path.startswith("/"):
                continue
            # The body may arrive as text or bytes; always store bytes ready to send.
            body = e.get("body", "")
            if isinstance(body, str):
                body = body.encode("utf-8", "replace")
            elif not isinstance(body, (bytes, bytearray)):
                body = str(body).encode("utf-8", "replace")
            # Store the response spec, defaulting to "200 text/plain" when not given.
            built[path] = {
                "status": int(e.get("status", 200) or 200),
                "ctype": str(e.get("ctype", "text/plain") or "text/plain"),
                "body": bytes(body),
            }
        # A malformed entry is skipped (and logged quietly) so the rest still apply.
        except Exception:  # noqa: BLE001 — one bad entry must not drop the rest
            logger.debug("node_canary: skipped malformed entry", exc_info=True)
    # Atomically publish the new set and report how many endpoints are now active.
    _ENTRIES = built
    logger.info("node_canary: active endpoint set updated (%d endpoint(s))",
                len(built))
    return len(built)


def clear() -> None:
    """Drop all canary endpoints (used on teardown / disable)."""
    # Replacing with an empty dict makes the module inert again.
    global _ENTRIES
    _ENTRIES = {}


def is_active() -> bool:
    """True when at least one canary endpoint is configured."""
    # An empty table means no canaries are configured.
    return bool(_ENTRIES)


def match(path: str) -> Optional[Dict[str, Any]]:
    """Return the served response spec ``{"status","ctype","body"}`` for ``path``
    if it is a configured canary endpoint, else ``None``. Cheap dict lookup;
    empty config → always ``None`` (inert)."""
    # Fast path: with no config every path is a non-match.
    if not _ENTRIES:
        return None
    # Look up the normalised path; None when it is not a canary.
    return _ENTRIES.get(_norm(path))
