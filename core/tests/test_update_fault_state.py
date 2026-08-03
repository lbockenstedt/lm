"""Footer version dot: amber "pending" vs RED "not progressing"
(``Hub._update_fault_state`` + ``update_recovery.update_health_summary``).

The dot was amber for both a routine pending update and a hub that could never
complete one, so an operator could press Update repeatedly and never learn it
was a no-op. Red is reserved for states that will NOT clear on their own:

* the double-failure marker (update failed AND rollback failed to boot);
* a version on the bad-versions list — the updater SKIPS those, so Update is a
  permanent no-op until the entry is cleared. This is the case that pins a hub
  on an old version indefinitely;
* drift that has persisted past LM_UPDATE_STUCK_S.

Cardinal rule inherited from the existing dot work: **never false-red**. No
drift, no markers → green, always.
"""
import os
import sys

import pytest

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main as main_mod  # noqa: E402
import update_recovery  # noqa: E402


class _Hub:
    """Bare stand-in — _update_fault_state reads only _update_drift_since.
    Called unbound off the real class, matching test_version_drift's harness."""
    pass


@pytest.fixture()
def statedir(tmp_path, monkeypatch):
    d = tmp_path / "state"
    d.mkdir()
    monkeypatch.setattr(update_recovery, "STATE_DIR", str(d), raising=False)
    monkeypatch.setenv("LM_STATE_DIR", str(d))
    # The module resolves paths through helpers that read STATE_DIR at call time.
    monkeypatch.setattr(update_recovery, "_state_dir",
                        lambda sd=None: str(d), raising=False)
    return d


def _fault(hub=None, behind=False, avail=False):
    return main_mod.LabManagerHub._update_fault_state(hub or _Hub(), behind, avail)


# ── never false-red ──────────────────────────────────────────────────────────

def test_clean_state_is_not_a_fault(statedir):
    out = _fault()
    assert out["update_failed"] is False and out["update_stuck"] is False
    assert out["bad_versions"] == []


def test_routine_pending_update_is_not_red(statedir):
    """Drift alone, freshly seen, is amber's job — not red."""
    out = _fault(behind=True, avail=True)
    assert out["update_failed"] is False and out["update_stuck"] is False


def test_unreadable_state_never_false_reds(statedir, monkeypatch):
    def _boom(*a, **kw):
        raise OSError("state unreadable")
    monkeypatch.setattr(update_recovery, "update_health_summary", _boom)
    out = _fault(behind=True)
    assert out["update_failed"] is False


# ── hard faults ──────────────────────────────────────────────────────────────

def test_double_failure_marker_is_red(statedir):
    update_recovery.write_update_failed("0.10", "/var/lib/lm/state/update-backup/x",
                                        "boot failed", state_dir=str(statedir))
    out = _fault()
    assert out["update_failed"] is True
    assert "0.10" in out["update_fault_reason"]
    assert "rollback" in out["update_fault_reason"].lower()


def test_bad_version_list_is_red_and_says_why(statedir):
    """The case that pins a hub: the updater skips these, so Update is a no-op."""
    update_recovery.add_bad_version("0.10", state_dir=str(statedir))
    out = _fault(avail=True)
    assert out["update_failed"] is True
    assert out["bad_versions"] == ["0.10"]
    assert "skips" in out["update_fault_reason"]


def test_failed_marker_outranks_bad_list_in_the_reason(statedir):
    update_recovery.add_bad_version("0.10", state_dir=str(statedir))
    update_recovery.write_update_failed("0.11", "/backup", "no boot",
                                        state_dir=str(statedir))
    out = _fault()
    assert out["update_failed"] is True
    assert "0.11" in out["update_fault_reason"]      # the harder fault wins
    assert out["bad_versions"] == ["0.10"]           # still reported


# ── stuck ────────────────────────────────────────────────────────────────────

def test_drift_becomes_stuck_after_the_threshold(statedir, monkeypatch):
    import main as _main
    monkeypatch.setattr(_main, "_UPDATE_STUCK_S", 100.0, raising=False)
    hub = _Hub()
    hub._update_drift_since = None
    out = _fault(hub, behind=True)                    # first sighting
    assert out["update_stuck"] is False
    hub._update_drift_since -= 200                    # age it past the threshold
    out = _fault(hub, behind=True)
    assert out["update_stuck"] is True
    assert out["stuck_for_s"] >= 200
    assert "not\n" in out["update_fault_reason"] or "not " in out["update_fault_reason"]


def test_drift_clearing_resets_the_stuck_clock(statedir, monkeypatch):
    import main as _main
    monkeypatch.setattr(_main, "_UPDATE_STUCK_S", 100.0, raising=False)
    hub = _Hub()
    _fault(hub, behind=True)
    hub._update_drift_since -= 200
    assert _fault(hub, behind=True)["update_stuck"] is True
    # Update lands → no drift → clock resets, so the next pending update starts
    # amber rather than inheriting the previous fault.
    assert _fault(hub)["update_stuck"] is False
    assert hub._update_drift_since is None
    out = _fault(hub, avail=True)
    assert out["update_stuck"] is False


def test_stuck_reason_not_overwritten_by_a_hard_fault(statedir, monkeypatch):
    """A hard fault's reason is more actionable; stuck must not clobber it."""
    import main as _main
    monkeypatch.setattr(_main, "_UPDATE_STUCK_S", 100.0, raising=False)
    update_recovery.add_bad_version("0.10", state_dir=str(statedir))
    hub = _Hub()
    _fault(hub, behind=True)
    hub._update_drift_since -= 200
    out = _fault(hub, behind=True)
    assert out["update_failed"] is True and out["update_stuck"] is True
    assert "skips" in out["update_fault_reason"]


# ── the summary reader ───────────────────────────────────────────────────────

def test_summary_reports_all_three_state_files(statedir):
    update_recovery.add_bad_version("0.10", state_dir=str(statedir))
    update_recovery.write_pending("/b", "0.09", "0.11", "ts", state_dir=str(statedir))
    update_recovery.write_update_failed("0.11", "/b", "no boot", state_dir=str(statedir))
    s = update_recovery.update_health_summary(state_dir=str(statedir))
    assert s["failed"] is True
    assert s["bad_versions"] == ["0.10"]
    assert (s["pending"] or {}).get("to_version") == "0.11"


def test_read_update_failed_absent_is_none(statedir):
    assert update_recovery.read_update_failed(state_dir=str(statedir)) is None


def test_read_update_failed_corrupt_is_none_not_an_exception(statedir):
    with open(update_recovery._failed_path(str(statedir)), "w") as f:
        f.write("{not json")
    assert update_recovery.read_update_failed(state_dir=str(statedir)) is None
