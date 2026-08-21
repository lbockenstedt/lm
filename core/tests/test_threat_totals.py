"""ThreatMonitor durable cumulative counters — the lifetime "are we seeing
anything?" tallies that survive block expiry, unblock, and the bounded events
deque rolling over.

Motivation: the Security view previously only showed *active* blocks + the last
N events, so once every block expired/was removed the operator had no way to tell
the pipeline had evaluated anything. ``snapshot()["totals"]`` now exposes
monotonic lifetime counts persisted to threat_monitor.json.
"""
import importlib.util
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


class _State:
    def __init__(self, data_dir, global_config=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": global_config or {}}

    def _mark_dirty(self):
        pass


class _Hub:
    def __init__(self, state):
        self.state = state


def _tm_for(tmp_path, entries=None):
    gc = {"azure_nsg": {"entries": entries or []}}
    return ThreatMonitor(_Hub(_State(str(tmp_path), gc)))


def test_failures_and_anomalies_tally_by_kind(tmp_path):
    tm = _tm_for(tmp_path)
    tm.record_failure("203.0.113.5", "login", username="root")
    tm.record_failure("203.0.113.5", "login", username="root")
    tm.record_failure("203.0.113.6", "api_key")
    tm.note_anomaly("sentinel_rate", "vault read burst", ip="203.0.113.20", severity="warning")
    t = tm.snapshot()["totals"]
    assert t["signals"] == 4
    assert t["failures"] == 3
    assert t["anomalies"] == 1
    assert t["by_kind"]["login"] == 2
    assert t["by_kind"]["api_key"] == 1
    assert t["by_kind"]["sentinel_rate"] == 1
    assert t["last_ts"] >= t["since"]


def test_totals_survive_expiry_unblock_and_deque_rollover(tmp_path):
    tm = _tm_for(tmp_path)
    tm.set_config({"threshold": 1, "window_s": 600})  # block on the 2nd failure
    tm.record_failure("203.0.113.9", "login")
    tm.record_failure("203.0.113.9", "login")         # crosses threshold → block
    assert "203.0.113.9" in tm._blocks
    assert tm.snapshot()["totals"]["blocks_placed"] == 1

    # Operator removes the block — the ACTIVE view empties, but the lifetime
    # tally must NOT decrement.
    tm.unblock("203.0.113.9")
    t = tm.snapshot()["totals"]
    assert t["currently_blocked"] == 0
    assert t["blocks_placed"] == 1                     # monotonic
    assert t["unblocks"] == 1
    assert t["failures"] == 2                          # both failures still counted


def test_permanent_block_counts_and_totals_persist_across_reload(tmp_path):
    tm = _tm_for(tmp_path)
    tm.block_manual("203.0.113.30", reason="perma", permanent=True)
    t = tm.snapshot()["totals"]
    assert t["blocks_placed"] == 1
    assert t["blocks_permanent"] == 1

    # A fresh instance reading the same file inherits the running tally.
    tm2 = _tm_for(tmp_path)
    t2 = tm2.snapshot()["totals"]
    assert t2["blocks_placed"] == 1
    assert t2["blocks_permanent"] == 1
    # ...and continues incrementing from there.
    tm2.record_failure("203.0.113.31", "session")
    assert tm2.snapshot()["totals"]["signals"] == 1
    assert tm2.snapshot()["totals"]["by_kind"]["session"] == 1


def test_empty_pipeline_reports_zeroed_totals(tmp_path):
    tm = _tm_for(tmp_path)
    t = tm.snapshot()["totals"]
    assert t["signals"] == 0
    assert t["failures"] == 0
    assert t["anomalies"] == 0
    assert t["blocks_placed"] == 0
    assert t["currently_blocked"] == 0
    assert t["by_kind"] == {}


def test_self_test_records_a_signal_but_never_blocks(tmp_path):
    tm = _tm_for(tmp_path)
    res = tm.self_test()
    assert res["status"] == "SUCCESS"
    assert res["totals"]["signals"] == 1
    assert res["totals"]["by_kind"]["selftest"] == 1
    assert len(tm._blocks) == 0            # benign: no IP → nothing blocked
    assert tm._events[0]["kind"] == "selftest"
    assert tm.snapshot()["totals"]["anomalies"] == 1
