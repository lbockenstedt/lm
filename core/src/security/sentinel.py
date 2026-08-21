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
from __future__ import annotations

import logging
import sys
import time
from collections import deque
from threading import Lock
from typing import Callable, Deque, Dict, Optional, Set

logger = logging.getLogger("Security")

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
    "vault.automation_list_by_type": {"routes.console"},
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

_hits: Dict[str, Deque[float]] = {}
_lock = Lock()
_reporter: Optional[Callable[[str, str, Optional[str], str], None]] = None


def set_reporter(fn: Optional[Callable[[str, str, Optional[str], str], None]]) -> None:
    """Register the anomaly sink. ``fn(kind, detail, ip, severity)``.

    Wired at hub startup to ``ThreatMonitor.note_anomaly``. Until set, anomalies
    fall back to the ``Security`` logger so nothing is ever silently dropped."""
    global _reporter
    _reporter = fn


def register_canary(resource: str) -> None:
    """Mark ``resource`` as a canary — ANY :func:`guard` on it is a violation."""
    _CANARY.add(resource)


def set_mode(resource: str, mode: str) -> None:
    """Set OBSERVE (log only) or ENFORCE (also deny) for ``resource``."""
    if mode not in (OBSERVE, ENFORCE):
        raise ValueError(f"mode must be {OBSERVE!r} or {ENFORCE!r}")
    _MODE[resource] = mode


def is_allowed(resource: str, module: str) -> bool:
    """Pure predicate (no side effects) — used by tests and callers that want to
    ask without tripping the reporter. Canary resources allow no one."""
    if resource in _CANARY:
        return False
    allow = _ALLOW.get(resource)
    if allow is None:
        return True  # unknown resource: not under contract → don't flag
    return module in allow


def _derive_accessor() -> tuple:
    """Return ``(module, qualname)`` of the nearest business caller — the first
    stack frame whose module is not sentinel/seam plumbing."""
    depth = 2  # skip _derive_accessor + guard
    while True:
        try:
            frame = sys._getframe(depth)
        except ValueError:
            return ("<unknown>", "")
        mod = frame.f_globals.get("__name__", "") or "<unknown>"
        if mod not in _SEAM_MODULES:
            return (mod, frame.f_code.co_qualname
                    if hasattr(frame.f_code, "co_qualname") else frame.f_code.co_name)
        depth += 1


def _over_rate(resource: str, now: float) -> Optional[int]:
    limit_window = _RATE.get(resource)
    if not limit_window:
        return None
    limit, window = limit_window
    with _lock:
        dq = _hits.setdefault(resource, deque())
        dq.append(now)
        while dq and dq[0] <= now - window:
            dq.popleft()
        count = len(dq)
    return count if count > limit else None


def _emit(kind: str, detail: str, ip: Optional[str], severity: str) -> None:
    if _reporter is not None:
        try:
            _reporter(kind, detail, ip, severity)
            return
        except Exception:  # a broken sink must never break the guarded call
            logger.exception("sentinel reporter failed")
    lvl = logging.CRITICAL if severity == "critical" else logging.WARNING
    logger.log(lvl, "SENTINEL %s [%s] — %s", kind.upper(), severity, detail)


def guard(resource: str, *, detail: str = "", ip: Optional[str] = None) -> None:
    """Check an access against the contract for ``resource``.

    Reports a ``sentinel_violation`` (contract breach / canary) and/or
    ``sentinel_rate`` (volume) anomaly. In ENFORCE mode a contract breach also
    raises :class:`SentinelViolation`. Guaranteed not to raise anything other
    than :class:`SentinelViolation` — a bug in the sentinel must never take down
    a guarded seam."""
    try:
        module, qualname = _derive_accessor()
        now = time.time()

        over = _over_rate(resource, now)
        if over is not None:
            _emit("sentinel_rate",
                  f"{resource}: {over} accesses/window by {module} (baseline exceeded)"
                  + (f" — {detail}" if detail else ""),
                  ip, "warning")

        if is_allowed(resource, module):
            return

        is_canary = resource in _CANARY
        what = "canary tripped" if is_canary else "unauthorized access"
        msg = (f"{what}: resource '{resource}' touched by '{module}'"
               f" ({qualname})" + (f" — {detail}" if detail else ""))
        _emit("sentinel_violation", msg, ip, "critical")

        if _MODE.get(resource, OBSERVE) == ENFORCE:
            raise SentinelViolation(msg)
    except SentinelViolation:
        raise
    except Exception:
        logger.exception("sentinel guard error on resource %s", resource)
