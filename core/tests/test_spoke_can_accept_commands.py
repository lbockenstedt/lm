"""``LabManagerHub.spoke_can_accept_commands`` — fail-fast gate for command
round-trips to a connected spoke.

A protocol-incompatible legacy GenericLeafAgent connects and heartbeats but
never adopts a session key (it dispatches on top-level ``type`` instead of the
hub's ``header/payload`` envelope, so it ignores ``SPOKE_UPDATE_SESSION_KEY``).
Such a spoke is in ``active_connections`` but its ``spoke_authenticated`` flag is
never set, so ``LOAD_ROLE`` / ``GET_AVAILABLE_ROLES`` would hang to the
``request_response`` timeout. This gate lets the route return an actionable
"reinstall" 503 instead.

The fake hub forwards to the REAL ``LabManagerHub.spoke_can_accept_commands``
implementation (same pattern as ``test_parent_auto_approve``'s ``_AutoApproveHub``)
so the production decision logic — the >10s grace window included — is exercised
end-to-end.
"""

import os
import sys
import time

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402


class _CmdGateHub:
    """Minimal stand-in exposing exactly what spoke_can_accept_commands reads.
    Forwards to the real LabManagerHub implementation (bound to this fake)."""

    # The real method references these as self.* (they're class attrs on
    # LabManagerHub); mirror them so the forwarded call resolves on the fake.
    _CMD_NOT_CONNECTED = main.LabManagerHub._CMD_NOT_CONNECTED
    _CMD_UNAUTHENTICATED = main.LabManagerHub._CMD_UNAUTHENTICATED

    def __init__(self):
        self.active_connections = {}
        self.spoke_authenticated = {}
        self.spoke_telemetry = {}

    def spoke_can_accept_commands(self, spoke_id):
        return main.LabManagerHub.spoke_can_accept_commands(self, spoke_id)


def _connect(hub, spoke_id, *, age_s=0.0):
    """Record a connected spoke whose connect timestamp is age_s seconds ago."""
    hub.active_connections[spoke_id] = object()
    hub.spoke_telemetry[spoke_id] = {"last_attempt": time.time() - age_s}


# ── not connected ─────────────────────────────────────────────────────────────

def test_not_connected():
    hub = _CmdGateHub()
    ok, reason = hub.spoke_can_accept_commands("lm-opnsense")
    assert ok is False
    assert reason == hub._CMD_NOT_CONNECTED


# ── authenticated spokes are always accepted ─────────────────────────────────

def test_authenticated_at_connect_accepts():
    hub = _CmdGateHub()
    _connect(hub, "dns-spoke-1", age_s=0.0)
    hub.spoke_authenticated["dns-spoke-1"] = True
    ok, reason = hub.spoke_can_accept_commands("dns-spoke-1")
    assert ok is True
    assert reason == ""


def test_authenticated_after_first_signed_frame_accepts():
    # A zero-touch spoke connects with no secret (flag unset), receives its
    # pushed key, then verifies a signature on its first response — the flag is
    # set then. It must be accepted even right after connect.
    hub = _CmdGateHub()
    _connect(hub, "lm-opnsense", age_s=0.5)
    hub.spoke_authenticated["lm-opnsense"] = True
    ok, reason = hub.spoke_can_accept_commands("lm-opnsense")
    assert ok is True
    assert reason == ""


# ── grace window: a fresh unauthenticated spoke is given the benefit of the doubt

def test_fresh_unauthenticated_spoke_is_not_rejected():
    # A just-approved zero-touch spoke hasn't received/installed its pushed key
    # yet (<10s). Rejecting it would be a false positive; let request_response
    # handle a genuine failure instead.
    hub = _CmdGateHub()
    _connect(hub, "lm-opnsense", age_s=2.0)
    ok, reason = hub.spoke_can_accept_commands("lm-opnsense")
    assert ok is True
    assert reason == ""


# ── the legacy-leaf dead end: connected long enough, never authenticated ──────

def test_long_connected_unauthenticated_spoke_is_rejected():
    # The legacy GenericLeafAgent has been connected for 10h but never verified a
    # signature (no SPOKE_UPDATE_SESSION_KEY handler). It can never respond to a
    # command — fail fast so LOAD_ROLE doesn't hang to the 120s timeout.
    hub = _CmdGateHub()
    _connect(hub, "lm-opnsense", age_s=36000.0)
    ok, reason = hub.spoke_can_accept_commands("lm-opnsense")
    assert ok is False
    assert reason == hub._CMD_UNAUTHENTICATED


def test_reject_clears_once_authenticated():
    # Same spoke, but it later adopts its key (e.g. after a reinstall to the
    # role-capable agent-spoke) — the gate must flip to accepting.
    hub = _CmdGateHub()
    _connect(hub, "lm-opnsense", age_s=36000.0)
    assert hub.spoke_can_accept_commands("lm-opnsense") == (False, hub._CMD_UNAUTHENTICATED)
    hub.spoke_authenticated["lm-opnsense"] = True
    assert hub.spoke_can_accept_commands("lm-opnsense") == (True, "")


# ── disconnect clears the flag, so a reconnecting spoke re-earned it ──────────

def test_disconnect_clears_authenticated_flag():
    hub = _CmdGateHub()
    _connect(hub, "dns-spoke-1", age_s=0.0)
    hub.spoke_authenticated["dns-spoke-1"] = True
    assert hub.spoke_can_accept_commands("dns-spoke-1") == (True, "")
    # Disconnect: the hub's finally block pops active_connections +
    # spoke_authenticated + spoke_telemetry; mirror that, then the spoke is gone.
    hub.active_connections.pop("dns-spoke-1", None)
    hub.spoke_authenticated.pop("dns-spoke-1", None)
    hub.spoke_telemetry.pop("dns-spoke-1", None)
    ok, reason = hub.spoke_can_accept_commands("dns-spoke-1")
    assert ok is False
    assert reason == hub._CMD_NOT_CONNECTED


# ── robustness: missing/last_attempt telemetry doesn't crash ─────────────────

def test_missing_telemetry_does_not_crash():
    hub = _CmdGateHub()
    hub.active_connections["weird-spoke"] = object()
    # No spoke_telemetry entry at all (last_attempt missing).
    ok, reason = hub.spoke_can_accept_commands("weird-spoke")
    assert ok is True  # conn_age falls back to 0 -> within grace window
    assert reason == ""


def test_non_numeric_last_attempt_does_not_crash():
    hub = _CmdGateHub()
    hub.active_connections["weird-spoke"] = object()
    hub.spoke_telemetry["weird-spoke"] = {"last_attempt": "not-a-number"}
    ok, reason = hub.spoke_can_accept_commands("weird-spoke")
    assert ok is True  # conn_age falls back to 0 -> within grace window
    assert reason == ""