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
