"""security/sentinel.py — in-process access sentinel (application-level tripwire).

Declares, per sensitive **resource**, the exact set of call sites that are
*allowed* to touch it, and a watcher that inspects the live Python call stack at
each guarded seam. It raises a security **anomaly** whenever:

* something **outside the contract** touches a crown-jewel (e.g. a module that is
  not on the vault's allow-list calls :func:`cred_vault.automation_get`), or
* a **canary** resource — which nothing legitimate ever reads — is touched *at
  all*.

Anomalies are forwarded to :class:`security.threat_monitor.ThreatMonitor` via a
registered reporter (wired at hub startup), so they flow through the existing,
already-relayed ``Security`` audit stream and can trigger an NSG response when an
IP is attributable.

Scope & honesty
---------------
This is the **in-process** layer of the §5J detection design. It catches the
*hub process itself* misbehaving — an unexpected caller of the vault/decrypt
seam, or an abnormal *volume* of reads. It **cannot** see a *separate* OS process
that reads the ciphertext blobs + the Fernet key and decrypts them **offline** —
that never enters the hub's Python. Catching a non-hub process requires the
host-layer telemetry in §5J (auditd / fanotify / eBPF) and is deliberately out of
scope here. Keep both layers.

Modes (per resource; default :data:`OBSERVE`)
--------------------------------------------
* ``OBSERVE``  — allow the call, but emit an anomaly on violation. Never breaks
  automation — the safe default for a live hub.
* ``ENFORCE``  — additionally raise :class:`SentinelViolation`, denying the
  access.

The policy below is the single, readable contract of *what the code should and
should not access*.
"""
# Allows modern type-hint syntax regardless of the running Python version.
from __future__ import annotations

# logging: fallback output when no reporter is registered, and guard errors.
import logging
# sys._getframe walks the call stack to find who is touching a resource.
import sys
# time.time() timestamps each access for the rate window.
import time
# deque efficiently drops old timestamps from the front of each rate window.
from collections import deque
# Lock protects the shared hit counters across threads.
from threading import Lock
# Type hints only.
from typing import Callable, Deque, Dict, Optional, Set

# Share the "Security" logger with the other security modules.
logger = logging.getLogger("Security")

# The two enforcement modes: report only, or report and deny.
OBSERVE = "observe"
ENFORCE = "enforce"


class SentinelViolation(RuntimeError):
    """Raised (only in ENFORCE mode) when an access violates the contract."""


# ── The contract ─────────────────────────────────────────────────────────────
# resource -> the set of module ``__name__`` values allowed to reach it.
# Derived from the §5I-vault audit: these are the only legitimate readers of the
# crown-jewel vault seams. Anything else touching them is, by definition, off.
_ALLOW: Dict[str, Set[str]] = {
    # Unattended (hub-mode) automation reads — background infra loops only.
    "vault.automation_get": {
        "instance_vault", "henet_sync", "le_cache",
        "routes.console", "routes.net_services",
    },
    # routes.monitoring: the Zabbix sync resolves each tenant's SNMP community.
    "vault.automation_list_by_type": {"routes.console", "routes.monitoring"},
    # Interactive PSK reveal — the human-facing cred-vault route only.
    "vault.reveal_secret": {"routes.cred_vault"},
}

# Canary resources: nothing legitimate EVER touches these. Any access is malicious
# by definition (planted decoys — see register_canary / §5J-J1).
_CANARY: Set[str] = set()

# Per-resource enforcement mode (default OBSERVE — see module docstring).
_MODE: Dict[str, str] = {}

# Per-resource volume guard: resource -> (max_hits, window_s). A burst above the
# scheduled baseline (someone dumping the vault) trips a ``sentinel_rate`` anomaly.
_RATE: Dict[str, tuple] = {
    "vault.automation_get": (60, 60.0),
    "vault.automation_list_by_type": (30, 60.0),
    "vault.reveal_secret": (30, 60.0),
}

# Frames in these modules are "plumbing" — skipped when deriving the real
# accessor so the identity is the *business* caller, not the seam itself.
_SEAM_MODULES: Set[str] = {
    __name__,               # this module
    "cred_vault",           # the vault seam
    "security.encryption",  # the decrypt primitive
}

# Recent access timestamps per resource, its lock, and the registered anomaly sink.
_hits: Dict[str, Deque[float]] = {}
_lock = Lock()
_reporter: Optional[Callable[[str, str, Optional[str], str], None]] = None


def set_reporter(fn: Optional[Callable[[str, str, Optional[str], str], None]]) -> None:
    """Register the anomaly sink. ``fn(kind, detail, ip, severity)``.

    Wired at hub startup to ``ThreatMonitor.note_anomaly``. Until set, anomalies
    fall back to the ``Security`` logger so nothing is ever silently dropped."""
    # Rebind the module-level sink so every later guard() call uses it.
    global _reporter
    _reporter = fn


def register_canary(resource: str) -> None:
    """Mark ``resource`` as a canary — ANY :func:`guard` on it is a violation."""
    # Add to the canary set; from now on any access is a violation.
    _CANARY.add(resource)


def set_mode(resource: str, mode: str) -> None:
    """Set OBSERVE (log only) or ENFORCE (also deny) for ``resource``."""
    # Reject anything other than the two known modes.
    if mode not in (OBSERVE, ENFORCE):
        raise ValueError(f"mode must be {OBSERVE!r} or {ENFORCE!r}")
    # Remember the mode for this resource.
    _MODE[resource] = mode


def is_allowed(resource: str, module: str) -> bool:
    """Pure predicate (no side effects) — used by tests and callers that want to
    ask without tripping the reporter. Canary resources allow no one."""
    # Nobody is allowed to touch a canary.
    if resource in _CANARY:
        return False
    # Look up the allow-list; resources without one are not policed.
    allow = _ALLOW.get(resource)
    if allow is None:
        return True  # unknown resource: not under contract → don't flag
    # Allowed only when the calling module is on the list.
    return module in allow


def _derive_accessor() -> tuple:
    """Return ``(module, qualname)`` of the nearest business caller — the first
    stack frame whose module is not sentinel/seam plumbing."""
    depth = 2  # skip _derive_accessor + guard
    # Walk outward through the call stack one frame at a time.
    while True:
        # Running off the top of the stack means the caller could not be identified.
        try:
            frame = sys._getframe(depth)
        except ValueError:
            return ("<unknown>", "")
        # The module name the frame's code belongs to.
        mod = frame.f_globals.get("__name__", "") or "<unknown>"
        # First frame outside the plumbing modules is the real caller; return its function name
        # (qualified name when this Python provides it).
        if mod not in _SEAM_MODULES:
            return (mod, frame.f_code.co_qualname
                    if hasattr(frame.f_code, "co_qualname") else frame.f_code.co_name)
        # Still inside plumbing: look one frame further out.
        depth += 1


def _over_rate(resource: str, now: float) -> Optional[int]:
    """Record an access to ``resource`` and return the hit count if it exceeds its limit, else None.
    """
    # Resources without a configured limit are never rate-flagged.
    limit_window = _RATE.get(resource)
    if not limit_window:
        return None
    limit, window = limit_window
    # Append this hit, discard hits older than the window, and count what remains.
    with _lock:
        dq = _hits.setdefault(resource, deque())
        dq.append(now)
        while dq and dq[0] <= now - window:
            dq.popleft()
        count = len(dq)
    # Only report the count when it is over the limit.
    return count if count > limit else None


def _emit(kind: str, detail: str, ip: Optional[str], severity: str) -> None:
    """Send an anomaly to the registered reporter, falling back to the Security logger."""
    # Prefer the registered sink (the threat monitor); stop here if it succeeded.
    if _reporter is not None:
        try:
            _reporter(kind, detail, ip, severity)
            return
        except Exception:  # a broken sink must never break the guarded call
            logger.exception("sentinel reporter failed")
    # No sink (or it failed): log critical anomalies at CRITICAL, others at WARNING.
    lvl = logging.CRITICAL if severity == "critical" else logging.WARNING
    logger.log(lvl, "SENTINEL %s [%s] — %s", kind.upper(), severity, detail)


def guard(resource: str, *, detail: str = "", ip: Optional[str] = None) -> None:
    """Check an access against the contract for ``resource``.

    Reports a ``sentinel_violation`` (contract breach / canary) and/or
    ``sentinel_rate`` (volume) anomaly. In ENFORCE mode a contract breach also
    raises :class:`SentinelViolation`. Guaranteed not to raise anything other
    than :class:`SentinelViolation` — a bug in the sentinel must never take down
    a guarded seam."""
    # Identify the business caller and the current time.
    try:
        module, qualname = _derive_accessor()
        now = time.time()

        # Flag unusually high access volume, whether or not the caller is allowed.
        over = _over_rate(resource, now)
        if over is not None:
            _emit("sentinel_rate",
                  f"{resource}: {over} accesses/window by {module} (baseline exceeded)"
                  + (f" — {detail}" if detail else ""),
                  ip, "warning")

        # An allowed caller of a non-canary resource needs nothing more.
        if is_allowed(resource, module):
            return

        # Build a message that says whether a canary or a protected resource was touched, by whom.
        is_canary = resource in _CANARY
        what = "canary tripped" if is_canary else "unauthorized access"
        msg = (f"{what}: resource '{resource}' touched by '{module}'"
               f" ({qualname})" + (f" — {detail}" if detail else ""))
        # Report the breach as critical.
        _emit("sentinel_violation", msg, ip, "critical")

        # In ENFORCE mode also deny the access by raising.
        if _MODE.get(resource, OBSERVE) == ENFORCE:
            raise SentinelViolation(msg)
    # Let the deliberate denial propagate to the caller.
    except SentinelViolation:
        raise
    # Any other error is a sentinel bug; log it and allow the call to continue.
    except Exception:
        logger.exception("sentinel guard error on resource %s", resource)
