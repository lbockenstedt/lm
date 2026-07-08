"""Pins the spoke→hub log-relay format.

The relay entry MUST be the canonical ``<asctime> - <name> - <levelname> -
<message>`` record (ONE timestamp) — the hub stores relayed entries verbatim, so
a second timestamp (the prior ``time.strftime`` + ``[LEVEL] name:`` prefix)
showed up as a duplicate date/time stamp in the WebUI Logs view. The hub no
longer re-stamps on ingest; this test pins the spoke side so the single
canonical timestamp survives the round-trip.
"""

import logging
import queue
import sys
import os

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

from core.src.messaging import control_plane as cp  # noqa: E402


def test_spoke_log_relay_entry_is_canonical_single_timestamp():
    q = queue.Queue(maxsize=10)
    h = cp._SpokeLogRelayHandler(q)
    lg = logging.getLogger("PxmxAgent.test_relay")
    lg.handlers = [h]            # attach so the record reaches the handler
    lg.setLevel(logging.INFO)
    lg.propagate = False          # don't double-emit via root
    # Emit a record on a named logger and pull what the handler queued.
    lg.info("status: cs_mode=off vms=26 nodes=1")
    entry = q.get_nowait()

    # Exactly ONE timestamp (the record's asctime), canonical dashed shape.
    assert " - PxmxAgent.test_relay - INFO - status: cs_mode=off vms=26 nodes=1" in entry
    # The old double-timestamp prefix is gone:
    assert "[INFO] PxmxAgent:" not in entry
    # Count datestamp occurrences — must be exactly one (YYYY-MM-DD HH:MM:SS).
    import re
    stamps = re.findall(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", entry)
    assert len(stamps) == 1, f"expected one timestamp, got {stamps}: {entry!r}"


def test_spoke_log_relay_handler_uses_canonical_formatter():
    h = cp._SpokeLogRelayHandler(queue.Queue(maxsize=10))
    fmt = h.formatter
    assert fmt is not None
    assert "%(asctime)s" in fmt._fmt
    assert "%(name)s" in fmt._fmt
    assert "%(levelname)s" in fmt._fmt
    # Dashed separators, not spaces — matches logging_setup.DEFAULT_FORMAT.
    assert " - " in fmt._fmt