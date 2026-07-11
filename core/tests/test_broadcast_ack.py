"""Fire-and-forget broadcast command ack recognition.

Pins the fix for the "Received acknowledgement for unknown message ID" WARNING
that fired on every Clear-Logs click (and every Enable-Debug toggle):
broadcast commands (``CLEAR_LOGS``, ``SET_LOG_LEVEL``) are sent via the
LOW-LEVEL ``send_to_spoke`` — NOT ``mailbox.push`` — so their message_ids are
never in ``mailbox.pending_ack``. The spoke still returns a ``COMMAND_RESULT``
for each command (every command acks), so the hub's inbound dispatch fell
through to ``mailbox.acknowledge`` → "unknown message ID" WARNING.

Fix: ``_register_broadcast_ack`` records each broadcast id in
``_pending_broadcast_ids`` (TTL-bounded); the COMMAND_RESULT dispatch checks
that set BEFORE the ``mailbox.acknowledge`` branch and logs the ack DEBUG
(expected) instead of WARNING (stray). These tests pin the registration helper
+ that both broadcast senders register every id they emit.
"""
import asyncio
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main as main_mod  # noqa: E402


class _Hub:
    """Bare stand-in for a LabManagerHub: active_connections + a capturing
    send_to_spoke. Inherits the REAL _register_broadcast_ack / broadcast_*
    methods (called unbound) so the registration logic under test is the
    production code path."""

    def __init__(self, sids):
        self.active_connections = {sid: object() for sid in sids}
        self.sent = []  # list of Message objects handed to send_to_spoke
        # Mirror the real LabManagerHub.__init__ field (the stub skips the
        # heavy __init__, but _register_broadcast_ack reads/writes this dict).
        self._pending_broadcast_ids = {}
        self._BROADCAST_ACK_TTL = 60.0

    async def send_to_spoke(self, msg, signing_secret=None):
        self.sent.append(msg)


# Attach the REAL _register_broadcast_ack so the unbound broadcast_* methods
# (called on a _Hub) exercise the production registration path, not a stub.
_Hub._register_broadcast_ack = main_mod.LabManagerHub._register_broadcast_ack


# ── _register_broadcast_ack ─────────────────────────────────────────────────

def test_register_broadcast_ack_records_id():
    hub = _Hub([])
    main_mod.LabManagerHub._register_broadcast_ack(hub, "abc-123")
    assert "abc-123" in hub._pending_broadcast_ids


def test_register_broadcast_ack_empty_is_noop():
    hub = _Hub([])
    main_mod.LabManagerHub._register_broadcast_ack(hub, "")
    assert hub._pending_broadcast_ids == {}


def test_register_broadcast_ack_prunes_expired(monkeypatch):
    # An expired entry is dropped on the next registration call so the dict
    # stays bounded across a long hub lifetime (a new broadcast per click).
    hub = _Hub([])
    # Seed an entry already in the past → must be pruned on the next register.
    hub._pending_broadcast_ids = {"old": 0.0}
    main_mod.LabManagerHub._register_broadcast_ack(hub, "new")
    assert "old" not in hub._pending_broadcast_ids
    assert "new" in hub._pending_broadcast_ids


def test_pending_broadcast_ids_init_empty():
    # LabManagerHub.__init__ must initialize _pending_broadcast_ids + the TTL
    # (the dispatch checks `corr_id in self._pending_broadcast_ids`; a missing
    # dict would KeyError on the first broadcast ack).
    import inspect
    src = inspect.getsource(main_mod.LabManagerHub.__init__)
    assert "_pending_broadcast_ids" in src
    assert "_BROADCAST_ACK_TTL" in src


# ── broadcast senders register every emitted id ─────────────────────────────

def test_broadcast_clear_logs_registers_every_id():
    hub = _Hub(["spoke-a", "spoke-b", "spoke-c"])
    asyncio.get_event_loop().run_until_complete(
        main_mod.LabManagerHub.broadcast_clear_logs(hub))
    # One CLEAR_LOGS sent per connected spoke.
    assert len(hub.sent) == 3
    for msg in hub.sent:
        assert msg.payload.type == "CLEAR_LOGS"
        # Each sent id MUST be registered so its ack is recognized (the fix).
        assert msg.header.message_id in hub._pending_broadcast_ids


def test_broadcast_log_level_registers_every_id():
    # SET_LOG_LEVEL had the SAME latent unknown-ack warning (sent via
    # send_to_spoke, not mailbox.push); registering fixes it too.
    hub = _Hub(["spoke-a", "spoke-b"])
    asyncio.get_event_loop().run_until_complete(
        main_mod.LabManagerHub.broadcast_log_level(hub, True))
    assert len(hub.sent) == 2
    for msg in hub.sent:
        assert msg.payload.type == "SET_LOG_LEVEL"
        assert msg.header.message_id in hub._pending_broadcast_ids


def test_broadcast_clear_logs_no_spokes_is_noop():
    hub = _Hub([])
    asyncio.get_event_loop().run_until_complete(
        main_mod.LabManagerHub.broadcast_clear_logs(hub))
    assert hub.sent == []
    assert hub._pending_broadcast_ids == {}


# ── dispatch recognizes a broadcast ack ──────────────────────────────────────

def test_dispatch_branch_order_broadcast_before_mailbox():
    # The COMMAND_RESULT dispatch checks _pending_broadcast_ids AFTER
    # _outstanding_requests/_recent_request_timeouts but BEFORE the
    # mailbox.acknowledge (unknown-ack WARNING) branch. Pin that the broadcast
    # branch exists in the source and is ordered before mailbox.acknowledge so
    # a broadcast ack can never reach the WARNING.
    import inspect
    src = inspect.getsource(main_mod.LabManagerHub.handle_connection)
    broadcast_check = src.find("_pending_broadcast_ids")
    mailbox_ack = src.find("self.mailbox.acknowledge(ack)")
    assert broadcast_check != -1, "broadcast-ack branch missing from dispatch"
    assert mailbox_ack != -1, "mailbox.acknowledge call missing from dispatch"
    assert broadcast_check < mailbox_ack, (
        "broadcast-ack branch must come BEFORE mailbox.acknowledge so a "
        "broadcast ack is recognized (DEBUG) instead of WARNING")