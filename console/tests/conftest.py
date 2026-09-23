"""Console-spoke test isolation.

The spoke now persists port telemetry and serial-health/diagnostics history to
``_state_dir()`` so they survive a service restart. Without isolation every test
would share (and accumulate into) the real /var/lib/lm/console — or the
repo-local ``.lm-state/console`` fallback — making counter assertions depend on
test order and on leftover files from a previous run.

Point the whole module tree at a per-test tmp dir and drop the process-wide
telemetry singleton so each test starts from an empty state dir.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


@pytest.fixture(autouse=True)
def _isolated_state_dir(tmp_path, monkeypatch):
    import serial_manager as sm

    monkeypatch.setenv("LM_CONSOLE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(sm, "_TELEMETRY", None, raising=False)
    yield
    sm._TELEMETRY = None


@pytest.fixture(autouse=True)
def _impatient_probe():
    """Run the fingerprinter's read windows at 1/20th scale.

    The real defaults are deliberately generous — a serial device that pauses
    mid-reply must not be written off as unresponsive — but the tests drive
    scripted in-memory channels that answer instantly, so the full schedule
    would add minutes of pure sleeping to the suite. Scaling keeps every
    timeout's RELATIVE behaviour (and so the code paths under test) identical.
    """
    import fingerprint as fp

    prev = fp.set_patience(0.05)
    yield
    fp.set_patience(prev)
