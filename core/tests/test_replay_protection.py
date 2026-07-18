"""Replay / freshness protection on inbound signed frames (item 8B).

The wire is HMAC-SIGNED, not encrypted; the signature verifies over the body
bytes, so a captured signed frame replays verbatim (same bytes → same HMAC →
accepted). TLS-verify-ON closes the capture path but not application replay.
``_check_freshness_and_replay`` is the defense-in-depth gate: a timestamp
freshness window + a bounded message_id seen-set, applied after signature
verification. These tests pin the gate's accept/drop decisions.
"""
import time
import uuid

import main  # noqa: E402  (core/src on sys.path via conftest)


def _fake_hub(window=120.0, skew=5.0, warn_interval=10.0):
    """A LabManagerHub subclass that skips the heavy real __init__ and sets only
    the replay attrs. Subclassing (not a bare object) so ``self._replay_warn``
    / ``_prune_seen_message_ids`` resolve through the MRO to the real methods."""
    class _FakeHub(main.LabManagerHub):
        def __init__(self):
            self._seen_message_ids = {}
            self._REPLAY_WINDOW_S = window
            self._REPLAY_FUTURE_SKEW_S = skew
            self._REPLAY_SEEN_TTL = window
            self._replay_warn_last = {}
            self._REPLAY_WARN_INTERVAL_S = warn_interval
            self._seen_prune_last_mono = float("-inf")  # prune time-gate (1/s)
            self.spoke_id_alias = {}  # guid-primary map (_primary_key resolves through it)
    return _FakeHub()


def _frame(ts=None, msg_id=None):
    """Build a msg_data with a header carrying timestamp + message_id."""
    if ts is None:
        ts = time.time()
    if msg_id is None:
        msg_id = str(uuid.uuid4())
    return {"header": {"message_id": msg_id, "timestamp": ts,
                       "sender_id": "s1", "destination_id": "hub"},
            "payload": {"type": "HEARTBEAT", "data": {}}}


def _check(hub, msg_data):
    return main.LabManagerHub._check_freshness_and_replay(hub, "s1", msg_data)


def test_fresh_frame_with_new_message_id_accepted_and_recorded():
    hub = _fake_hub()
    mid = "m1"
    ok = _check(hub, _frame(msg_id=mid))
    assert ok is True
    assert mid in hub._seen_message_ids  # recorded so a replay is caught


def test_exact_message_id_replay_dropped():
    hub = _fake_hub()
    mid = "m1"
    assert _check(hub, _frame(msg_id=mid)) is True       # first copy accepted
    assert _check(hub, _frame(msg_id=mid)) is False      # verbatim replay dropped


def test_stale_timestamp_beyond_window_dropped():
    hub = _fake_hub(window=120.0)
    old_ts = time.time() - 300  # 300s old >> 120s window
    assert _check(hub, _frame(ts=old_ts, msg_id="stale")) is False


def test_future_timestamp_beyond_skew_dropped():
    hub = _fake_hub(window=120.0, skew=5.0)
    fut = time.time() + 60  # 60s in the future >> 5s skew
    assert _check(hub, _frame(ts=fut, msg_id="fut")) is False


def test_future_within_skew_accepted():
    hub = _fake_hub(window=120.0, skew=5.0)
    fut = time.time() + 3  # within the 5s skew allowance
    assert _check(hub, _frame(ts=fut, msg_id="ok-fut")) is True


def test_timestamp_just_inside_window_accepted():
    hub = _fake_hub(window=120.0)
    ts = time.time() - 100  # inside the 120s window
    assert _check(hub, _frame(ts=ts, msg_id="edge")) is True


def test_missing_timestamp_skips_freshness_but_dedupes():
    """A signed frame with no timestamp (shouldn't happen — protocol stamps every
    header) is allowed through rather than bricked by v1, but message_id dedupe
    still applies."""
    hub = _fake_hub()
    msg = {"header": {"message_id": "no-ts"}, "payload": {"type": "HEARTBEAT"}}
    assert _check(hub, msg) is True
    assert _check(hub, msg) is False  # dedupe still catches the replay


def test_non_numeric_timestamp_skips_freshness():
    hub = _fake_hub()
    msg = {"header": {"message_id": "bad-ts", "timestamp": "not-a-number"},
           "payload": {"type": "HEARTBEAT"}}
    assert _check(hub, msg) is True


def test_distinct_message_ids_both_accepted():
    hub = _fake_hub()
    assert _check(hub, _frame(msg_id="a")) is True
    assert _check(hub, _frame(msg_id="b")) is True


def test_seen_set_prunes_expired_entries():
    """_prune_seen_message_ids drops entries past their expire_ts so the set
    stays bounded by the distinct-id count within the window."""
    hub = _fake_hub(window=120.0)
    # Plant an already-expired entry and a live one.
    now = time.time()
    hub._seen_message_ids = {"old": now - 1, "live": now + 100}
    main.LabManagerHub._prune_seen_message_ids(hub)
    assert "old" not in hub._seen_message_ids
    assert "live" in hub._seen_message_ids


def test_replay_warning_throttled_per_spoke(caplog):
    """A replay flood emits at most one WARNING per _REPLAY_WARN_INTERVAL_S per
    spoke so the log isn't spammed. Subsequent drops within the interval go to
    DEBUG (not captured at WARNING)."""
    import logging
    caplog.set_level(logging.WARNING, logger="Hub")
    hub = _fake_hub(warn_interval=10.0)
    # Same stale message_id replayed 5 times → only ONE WARNING (throttled).
    msg = _frame(ts=time.time() - 300, msg_id="flood")
    for _ in range(5):
        _check(hub, msg)
    warns = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warns) == 1