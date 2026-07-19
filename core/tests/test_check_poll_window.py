"""Rolling 1-hour PASS/FAIL verdict for dashboard Checks (CheckPollWindow).

Operator rule: a dashboard check must NOT read OK if ANY poll FAILED in the last
hour — all-pass→ok, mixed→warning, all-fail→error, no samples→None (leave as-is).
Per-poll status is classified with INVERTED sim semantics (a per-poll "warning"
or "error" both count as a FAILED poll; "no_data"/other is ignored).
"""
import time

from simulations.central_hub_poller import CheckPollWindow, _classify_poll_status


# ── classify mapping ────────────────────────────────────────────────────────

def test_classify_ok_is_pass():
    assert _classify_poll_status("ok") is True


def test_classify_warning_and_error_are_fail():
    assert _classify_poll_status("warning") is False
    assert _classify_poll_status("error") is False


def test_classify_no_data_and_other_are_ignored():
    assert _classify_poll_status("no_data") is None
    assert _classify_poll_status("pending") is None
    assert _classify_poll_status("") is None
    assert _classify_poll_status(None) is None


def test_classify_is_case_insensitive():
    assert _classify_poll_status("OK") is True
    assert _classify_poll_status("  Error ") is False


# ── verdict rule ────────────────────────────────────────────────────────────

def _win(tmp_path, name="cpw.json"):
    return CheckPollWindow(str(tmp_path / name))


def test_all_pass_is_ok(tmp_path):
    w = _win(tmp_path)
    for _ in range(4):
        w.record("t", "s", "c", True)
    assert w.verdict("t", "s", "c") == "ok"


def test_mixed_is_warning(tmp_path):
    w = _win(tmp_path)
    w.record("t", "s", "c", True)
    w.record("t", "s", "c", True)
    w.record("t", "s", "c", False)
    assert w.verdict("t", "s", "c") == "warning"


def test_all_fail_is_error(tmp_path):
    w = _win(tmp_path)
    w.record("t", "s", "c", False)
    w.record("t", "s", "c", False)
    assert w.verdict("t", "s", "c") == "error"


def test_no_samples_is_none(tmp_path):
    w = _win(tmp_path)
    assert w.verdict("t", "s", "c") is None


def test_counts_reflects_passes_and_total(tmp_path):
    w = _win(tmp_path)
    w.record("t", "s", "c", True)
    w.record("t", "s", "c", True)
    w.record("t", "s", "c", False)
    assert w.counts("t", "s", "c") == (2, 3)


# ── pruning to the 1h window ────────────────────────────────────────────────

def test_prune_drops_samples_older_than_1h(tmp_path):
    w = _win(tmp_path)
    key = w._key("t", "s", "c")
    # A stale FAIL from >1h ago plus a recent PASS: the stale one is pruned, so
    # the verdict is a clean OK (not a warning).
    w._samples[key] = [(time.time() - 3601, False)]
    w.record("t", "s", "c", True)  # record() prunes on append
    assert w._samples[key] == [w._samples[key][-1]]
    assert w.verdict("t", "s", "c") == "ok"


def test_verdict_ignores_stale_samples_without_new_record(tmp_path):
    w = _win(tmp_path)
    key = w._key("t", "s", "c")
    w._samples[key] = [(time.time() - 3601, False), (time.time() - 3700, True)]
    # No new record() call — verdict() must still window out the stale samples.
    assert w.verdict("t", "s", "c") is None
    assert w.counts("t", "s", "c") == (0, 0)


# ── keying / isolation ──────────────────────────────────────────────────────

def test_checks_are_keyed_independently(tmp_path):
    w = _win(tmp_path)
    w.record("t", "s", "c1", True)
    w.record("t", "s", "c2", False)
    assert w.verdict("t", "s", "c1") == "ok"
    assert w.verdict("t", "s", "c2") == "error"


def test_forget_drops_only_that_tenant(tmp_path):
    w = _win(tmp_path)
    w.record("t1", "s", "c", True)
    w.record("t2", "s", "c", True)
    w.forget("t1")
    assert w.verdict("t1", "s", "c") is None
    assert w.verdict("t2", "s", "c") == "ok"


# ── persistence (atomic JSON, restored trimmed) ─────────────────────────────

def test_save_and_reload_restores_verdict(tmp_path):
    path = str(tmp_path / "cpw.json")
    w = CheckPollWindow(path)
    w.record("t", "s", "c", True)
    w.record("t", "s", "c", False)
    w.save_samples()
    # A fresh instance loads the persisted window and yields the same verdict.
    w2 = CheckPollWindow(path)
    assert w2.verdict("t", "s", "c") == "warning"
    assert w2.counts("t", "s", "c") == (1, 2)


def test_reload_trims_stale_samples(tmp_path):
    path = str(tmp_path / "cpw.json")
    w = CheckPollWindow(path)
    key = w._key("t", "s", "c")
    # Persist a stale FAIL directly, then reload: it must be trimmed out on load.
    w._samples[key] = [(time.time() - 3601, False)]
    w.save_samples()
    w2 = CheckPollWindow(path)
    assert w2.verdict("t", "s", "c") is None


def test_corrupt_file_starts_empty(tmp_path):
    path = tmp_path / "cpw.json"
    path.write_text("{ not json")
    w = CheckPollWindow(str(path))
    assert w.verdict("t", "s", "c") is None


def test_missing_file_starts_empty(tmp_path):
    w = CheckPollWindow(str(tmp_path / "does_not_exist.json"))
    assert w.verdict("t", "s", "c") is None
