"""Registry-diag blind spot: an APPROVED spoke that has never been seen, holds
no session key and is not connected is stuck in the "approve → never reports
in" state, but the diagnostic used to report "no problems detected".

``_is_stuck_never_keyed`` is the pure predicate the diag row build uses to flag
these; pin its exact truth table so the finding fires for the stuck signature
and stays quiet for every legitimate state (live spoke, pending spoke, keyed
offline spoke, relayed agent with no socket of its own).
"""
from routes.setup import _is_stuck_never_keyed


def test_stuck_when_approved_never_seen_no_key_offline():
    """The cs-svr-06 signature: approved, offline, no key, never seen,
    not a relayed agent → STUCK."""
    assert _is_stuck_never_keyed(
        approved=True, connected=False, has_key=False,
        is_relayed_agent=False, seen=None) is True


def test_not_stuck_when_connected():
    """A connected spoke can still be keyed by approval / zero-touch."""
    assert _is_stuck_never_keyed(
        approved=True, connected=True, has_key=False,
        is_relayed_agent=False, seen=None) is False


def test_not_stuck_when_has_key():
    """An offline-but-keyed spoke re-keys on reconnect via the history window."""
    assert _is_stuck_never_keyed(
        approved=True, connected=False, has_key=True,
        is_relayed_agent=False, seen=None) is False


def test_not_stuck_when_seen_before():
    """A spoke that has been seen has a socket to zero-touch re-key on."""
    assert _is_stuck_never_keyed(
        approved=True, connected=False, has_key=False,
        is_relayed_agent=False, seen=123456.0) is False


def test_not_stuck_when_relayed_agent():
    """A relayed agent legitimately has no session key of its own (its parent
    spoke holds it) — that is not a fault."""
    assert _is_stuck_never_keyed(
        approved=True, connected=False, has_key=False,
        is_relayed_agent=True, seen=None) is False


def test_not_stuck_when_unapproved():
    """A never-approved pending spoke is normal — it shows an Approve action."""
    assert _is_stuck_never_keyed(
        approved=False, connected=False, has_key=False,
        is_relayed_agent=False, seen=None) is False
