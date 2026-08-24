"""SimHealthTrend — Fleet Health's second (sim-perspective) metric.

The rule under test (from the design):
  * A FAILURE sim client is WORKING as long as its expected error was observed
    in Central AT LEAST ONCE within the trend window (default 1h). Central's
    per-cycle view is noisy, so we never judge on a single reading.
  * Only a client that goes a FULL window with no observed error is "not
    working".
  * A client first seen < 1 window ago gets grace (too new to have had a fair
    hour) and counts as working.
  * Per-tenant rollup over the CURRENT active-key set (clients that stopped
    running the sim / vanished drop out of both numerator and denominator).
  * first_seen/last_fail persist across a hub restart.
"""
import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "simulations"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from sim_health_trend import SimHealthTrend  # noqa: E402

WIN = 3600.0
T = "tenant-a"


def _t(tmp_path, window=WIN):
    return SimHealthTrend(str(tmp_path), window_s=window)


def test_seen_failing_within_window_is_working(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "clientA", True, now=now - 600)      # failed 10 min ago
    assert tr.is_working(T, "clientA", now=now) is True


def test_no_error_for_full_window_is_not_working(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    # first seen well over a window ago, last failure also older than the window
    tr.observe(T, "clientA", True, now=now - (WIN + 1200))
    tr.observe(T, "clientA", False, now=now)           # still expected, but no error
    assert tr.is_working(T, "clientA", now=now) is False


def test_new_client_inside_grace_counts_as_working(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "fresh", False, now=now - 300)        # first seen 5 min ago, no error yet
    assert tr.is_working(T, "fresh", now=now) is True   # grace: too new to judge


def test_grace_expires_after_a_full_window_with_no_error(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "c", False, now=now - (WIN + 60))     # first seen > window ago, never failed
    tr.observe(T, "c", False, now=now)
    assert tr.is_working(T, "c", now=now) is False


def test_intermittent_failure_keeps_it_working(tmp_path):
    # The core reason for a trend: Central drops the error most cycles but the
    # client DID fail once inside the window -> still working.
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "flappy", True, now=now - 3000)       # failed 50 min ago
    for i in range(10):                                  # then 10 cycles with nothing
        tr.observe(T, "flappy", False, now=now - 2400 + i * 60)
    assert tr.is_working(T, "flappy", now=now) is True


def test_unknown_key_is_not_working(tmp_path):
    tr = _t(tmp_path)
    assert tr.is_working(T, "never-seen") is False


def test_rollup_counts_and_bands(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    # 9 working (failed recently), 1 not working (silent past window) -> 90% ok
    for i in range(9):
        tr.observe(T, f"ok{i}", True, now=now - 600)
    tr.observe(T, "bad", True, now=now - (WIN + 600))
    tr.observe(T, "bad", False, now=now)
    keys = [f"ok{i}" for i in range(9)] + ["bad"]
    r = tr.rollup(T, keys, now=now)
    assert r["total"] == 10 and r["working"] == 9
    assert r["pct"] == 90.0 and r["status"] == "ok"


def test_rollup_critical_band(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "a", True, now=now - 600)
    for k in ("b", "c", "d"):
        tr.observe(T, k, True, now=now - (WIN + 600))
        tr.observe(T, k, False, now=now)
    r = tr.rollup(T, ["a", "b", "c", "d"], now=now)
    assert r["working"] == 1 and r["total"] == 4
    assert r["pct"] == 25.0 and r["status"] == "critical"


def test_rollup_only_scores_active_keys(tmp_path):
    # A client that stopped running the sim this cycle drops out of BOTH numer-
    # ator and denominator even though its history is still on disk.
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "gone", True, now=now - 600)          # was working, now inactive
    tr.observe(T, "active", True, now=now - 600)
    r = tr.rollup(T, ["active"], now=now)
    assert r["total"] == 1 and r["working"] == 1


def test_empty_active_set_is_no_data(tmp_path):
    tr = _t(tmp_path)
    r = tr.rollup(T, [], now=time.time())
    assert r["status"] == "no_data" and r["pct"] is None


def test_state_persists_across_restart(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "c", True, now=now - 600)
    tr.save()
    tr2 = _t(tmp_path)                                   # fresh instance, same dir
    assert tr2.is_working(T, "c", now=now) is True       # loaded, not reset to now


def test_prune_forgets_stale_keys(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe(T, "old", True, now=now - (3 * WIN))      # untouched > 2*window
    tr.observe(T, "recent", True, now=now - 600)
    tr.prune(now=now)
    assert "old" not in tr._state.get(T, {})
    assert "recent" in tr._state.get(T, {})


def test_tenants_are_isolated(tmp_path):
    tr = _t(tmp_path)
    now = time.time()
    tr.observe("t1", "c", True, now=now - 600)
    assert tr.is_working("t1", "c", now=now) is True
    assert tr.is_working("t2", "c", now=now) is False
