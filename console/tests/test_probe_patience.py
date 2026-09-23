"""The probe-patience multiplier that scales every fingerprint read window.

Serial identify is not latency-sensitive, so the defaults are deliberately
generous: a switch that pauses mid-reply must not be mistaken for a dead one.
``set_patience`` is the single place to scale that schedule for unusually slow
gear (role config ``console_probe_patience``) — or to stop the test suite
sleeping through it.
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import fingerprint as fp  # noqa: E402


@pytest.fixture
def restore_patience():
    prev = fp._PATIENCE
    yield
    fp.set_patience(prev)


def test_scales_every_window(restore_patience):
    fp.set_patience(2.0)
    assert fp._t(3.0) == 6.0
    fp.set_patience(0.5)
    assert fp._t(3.0) == 1.5


def test_returns_the_previous_value_so_callers_can_restore(restore_patience):
    fp.set_patience(1.0)
    assert fp.set_patience(4.0) == 1.0
    assert fp.set_patience(1.0) == 4.0


def test_clamped_so_bad_config_cannot_wedge_or_zero_a_probe(restore_patience):
    # A typo'd config must not hang a probe for hours...
    fp.set_patience(10_000)
    assert fp._PATIENCE == 10.0
    # ...nor collapse every window to zero, which would read nothing at all.
    fp.set_patience(0)
    assert fp._PATIENCE == 0.01
    fp.set_patience(-5)
    assert fp._PATIENCE == 0.01


@pytest.mark.parametrize("junk", ["abc", None, [], {}])
def test_non_numeric_config_is_ignored_not_fatal(restore_patience, junk):
    fp.set_patience(1.5)
    assert fp.set_patience(junk) == 1.5
    assert fp._PATIENCE == 1.5      # left alone rather than crashing the spoke


def test_read_until_honours_the_scaled_idle_gap(restore_patience):
    """The regression this exists for: the serial handle polls every 0.3s, so a
    0.4s idle gap meant ONE missed poll ended the read mid-reply."""
    assert fp._IDLE_SECS > 0.9, "idle gap must span several 0.3s poll windows"

    fp.set_patience(1.0)
    chunks = [b"first burst", b"", b"", b"second burst after a pause"]

    def read_fn():
        time.sleep(0.05)
        return chunks.pop(0) if chunks else b""

    # No pattern can match, so only the idle/timeout rules end this read.
    out = fp._read_until(read_fn, [fp._PRIV_PROMPT], timeout=3.0)
    assert "second burst" in out, "gave up during a brief pause in the reply"


def test_a_genuinely_silent_line_still_returns_promptly(restore_patience):
    """Patience must not mean hanging forever on a dead line."""
    fp.set_patience(1.0)
    started = time.monotonic()
    out = fp._read_until(lambda: b"", [fp._PRIV_PROMPT], timeout=10.0)
    elapsed = time.monotonic() - started
    assert out == ""
    # Idle break, not the 10s timeout.
    assert elapsed < fp._t(fp._IDLE_SECS) + 1.0
