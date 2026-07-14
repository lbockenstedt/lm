"""Hub restart honors logged-in users — the autonomous (non-force) restart path
is gated by the maintenance-window/idle policy; only the manual "Update now"
button forces.

The external ``lm-watchdog`` pulls ``/opt/lm`` every 60s and restarts on version
drift. Before this change, the hub's ``check_update_health`` dropped a
``force=True`` sentinel on staleness AND ``perform_update`` forced on
``stale_reload`` — so the watchdog restarted IMMEDIATELY on every autobump,
booting logged-in operators mid-day. Now:

* ``check_update_health`` stale sentinel is NON-force (gated only: idle or
  the 2am maintenance window).
* ``perform_update``'s watchdog sentinel is ``force=bool(force)`` (no
  ``stale_reload``), and the direct self-restart ``_restart_now`` no longer
  short-circuits on ``stale_reload`` — it follows the gate like a routine
  auto-update. There is NO force-over backstop on the watchdog side: a stale
  build waits until the user logs out (RESTART_ALLOWED=1) or the 2am window
  opens (window mode returns True in-window even with a user logged in). The
  yellow footer dot is the only signal while a user stays connected.

These tests pin the force= call sites (regression guards) and the sentinel
writer's ``force `` prefix contract.
"""
import os
import sys
import tempfile

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_SRC = os.path.join(_LM_ROOT, "core", "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import update_pipeline  # noqa: E402


_SRC_FILE = os.path.join(_SRC, "update_pipeline.py")
_SRC_TEXT = open(_SRC_FILE, encoding="utf-8").read()


# ── _request_watchdog_restart sentinel prefix (behavioral) ───────────────────

def _mixin():
    """Bare UpdatePipelineMixin — _request_watchdog_restart only touches
    os.environ + logger (best-effort except). __new__ skips __init__."""
    return update_pipeline.UpdatePipelineMixin.__new__(update_pipeline.UpdatePipelineMixin)


def test_force_sentinel_writes_force_prefix():
    """A force sentinel carries the ``force `` prefix the watchdog keys off to
    bypass the gate (manual 'Update now' → restart immediately)."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "stale-sentinel")
        os.environ["LM_STALE_RESTART_SENTINEL"] = path
        try:
            _mixin()._request_watchdog_restart("stale v1->v2", force=True)
            body = open(path).read()
        finally:
            os.environ.pop("LM_STALE_RESTART_SENTINEL", None)
    assert body.startswith("force "), body
    assert "stale v1->v2" in body


def test_non_force_sentinel_has_no_force_prefix():
    """A non-force sentinel (auto-update / stale-reload) has NO ``force `` prefix
    — the watchdog gates it on RESTART_ALLOWED (idle or the 2am window)."""
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "stale-sentinel")
        os.environ["LM_STALE_RESTART_SENTINEL"] = path
        try:
            _mixin()._request_watchdog_restart("update->restart", force=False)
            body = open(path).read()
        finally:
            os.environ.pop("LM_STALE_RESTART_SENTINEL", None)
    assert not body.startswith("force "), body
    assert "update->restart" in body


# ── force= call-site invariants (regression guards) ─────────────────────────

def test_check_update_health_stale_sentinel_is_non_force():
    """check_update_health's process-vs-disk drift sentinel must be NON-force so
    the watchdog gates it (idle or the 2am window) — NO force-over backstop.
    force=True here is the mid-day-boot regression — every autobump made the
    watchdog restart a logged-in operator immediately. The call must read
    force=False (or force=bool(...)) but NOT force=True."""
    # Locate the check_update_health stale-sentinel call (the one whose reason
    # string is "stale v{run_v}->v{disk_v}") and assert it is non-force.
    needle = '_request_watchdog_restart(f"stale v{run_v}->v{disk_v}", force=False)'
    assert needle in _SRC_TEXT, (
        "check_update_health stale sentinel must be force=False (gated, idle or "
        "2am window), not force=True — force=True boots logged-in users mid-day")


def test_perform_update_sentinel_force_only_when_caller_forced():
    """perform_update's watchdog sentinel must be force=bool(force) — NOT
    force=(stale_reload or bool(force)). A stale-reload is gated now (idle or
    the 2am window — no force-over backstop); only the manual Update button
    (force=True) bypasses the gate."""
    assert "force=bool(force))" in _SRC_TEXT, (
        "perform_update sentinel must be force=bool(force)")
    assert "force=(stale_reload or bool(force))" not in _SRC_TEXT, (
        "perform_update must NOT force on stale_reload — that boots logged-in "
        "users mid-day; stale-reload is gated (idle or 2am window) now")


def test_perform_update_direct_restart_does_not_short_circuit_on_stale():
    """The direct self-restart _restart_now must follow the gate; it must NOT
    short-circuit on stale_reload (which would bypass the gate the same way the
    force sentinel did)."""
    assert "_restart_now = bool(force) or self._gate_allows_restart_now()" in _SRC_TEXT, (
        "_restart_now must be bool(force) or gate — no stale_reload short-circuit")
    assert "or stale_reload or self._gate_allows_restart_now()" not in _SRC_TEXT, (
        "_restart_now must NOT include 'or stale_reload' — that bypasses the gate")