"""Unit tests for the 'in_progress' bug/feature status.

ab flips a report to ``in_progress`` (via MARK_BUG_IN_PROGRESS) as soon as it
starts actively working the GitHub issue, so the LM WebUI shows the user it's
being worked on — distinct from the passive ``filed`` and terminal ``fixed``.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_bug_store import HubBugStoreMixin  # noqa: E402


class _Store(HubBugStoreMixin):
    """Minimal harness owning the state LabManagerHub.__init__ normally sets."""

    def __init__(self, tmp):
        self.bug_dir = tmp
        self.bug_reports = {}
        self.bug_report_limit = 100


def _mk(tmp, **payload):
    payload.setdefault("explanation", "boom")
    return _Store(tmp), payload


def test_mark_in_progress_sets_status_and_persists(tmp_path):
    store = _Store(str(tmp_path))
    rid = store._store_bug_report({"explanation": "kaboom", "type": "bug"})
    assert store._mark_bug_in_progress(rid, "https://gh/x/1") is True

    # In-memory index reflects it.
    meta = store.bug_reports[rid]
    assert meta["status"] == "in_progress"
    assert meta["filed"] is True
    assert meta["issue_url"] == "https://gh/x/1"

    # Persisted to report.json so it survives a hub restart.
    with open(os.path.join(str(tmp_path), rid, "report.json")) as f:
        rpt = json.load(f)
    assert rpt["status"] == "in_progress"
    assert rpt["filed"] is True


def test_mark_in_progress_unknown_id_is_false(tmp_path):
    store = _Store(str(tmp_path))
    assert store._mark_bug_in_progress("nope") is False


def test_in_progress_feature_is_not_gated(tmp_path):
    """A feature request being worked must not re-gate behind admin approval."""
    store = _Store(str(tmp_path))
    rid = store._store_bug_report({"explanation": "add X", "type": "feature"})
    # A fresh, unapproved feature IS gated.
    assert store._bug_feature_gated(store.bug_reports[rid]) is True
    store._mark_bug_in_progress(rid, "https://gh/x/2")
    assert store._bug_feature_gated(store.bug_reports[rid]) is False
