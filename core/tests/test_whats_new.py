"""Unit tests for the "What's New" feed helper (``routes/setup_admin.py``).

``GET /api/whats-new`` powers the WebUI top-banner info-icon popover. It lists
recently merged **bug fixes AND features** — bug-store reports AppBuilder built
& closed (``status=="fixed"`` + a ``fixed_at`` epoch) — merged within the last
2 weeks. The selection/sort/window/cap lives in the pure ``_committed_features``
helper so it can be exercised without building the FastAPI app (``now`` is
injectable). These lock in:

* type bug OR feature is surfaced (an untyped legacy report counts as a bug);
  still-open / filed-but-not-yet-fixed reports are excluded;
* only rows ``status=="fixed"`` with a non-empty summary;
* only rows fixed within the last ``_WHATS_NEW_DAYS`` days;
* newest-first by ``fixed_at``, falling back to ``ts`` when ``fixed_at`` is 0;
* each row carries a ``type`` ("bug"/"feature") for the UI badge;
* the payload is capped at ``_WHATS_NEW_LIMIT``.
"""

from routes.setup_admin import (
    _committed_features,
    _WHATS_NEW_LIMIT,
    _WHATS_NEW_DAYS,
)

# A fixed "now" so the 2-week window is deterministic.
NOW = 1_000_000_000
DAY = 86400
RECENT = NOW - DAY  # inside the window


def test_bug_fixes_and_features_are_surfaced():
    reports = [
        {"id": "a", "type": "feature", "status": "fixed", "summary": "Dark mode", "fixed_at": RECENT},
        {"id": "b", "type": "bug", "status": "fixed", "summary": "Crash fix", "fixed_at": RECENT},
        {"id": "c", "type": "feature", "status": "filed", "summary": "Not built yet", "fixed_at": RECENT},
        {"id": "d", "type": "feature", "status": "", "summary": "Brand new", "fixed_at": RECENT},
    ]
    out = _committed_features(reports, now=NOW)
    assert sorted(f["id"] for f in out) == ["a", "b"]
    by_id = {f["id"]: f for f in out}
    assert by_id["a"]["type"] == "feature"
    assert by_id["b"]["type"] == "bug"


def test_untyped_fixed_report_counts_as_bug():
    reports = [
        {"id": "legacy", "status": "fixed", "summary": "Old fix", "fixed_at": RECENT},
    ]
    out = _committed_features(reports, now=NOW)
    assert [f["id"] for f in out] == ["legacy"]
    assert out[0]["type"] == "bug"


def test_outside_the_two_week_window_is_dropped():
    old = NOW - (_WHATS_NEW_DAYS + 1) * DAY
    reports = [
        {"id": "recent", "type": "feature", "status": "fixed", "summary": "in", "fixed_at": RECENT},
        {"id": "stale", "type": "feature", "status": "fixed", "summary": "out", "fixed_at": old},
    ]
    out = _committed_features(reports, now=NOW)
    assert [f["id"] for f in out] == ["recent"]


def test_missing_summary_is_dropped():
    reports = [
        {"id": "a", "type": "feature", "status": "fixed", "summary": "  ", "fixed_at": RECENT},
        {"id": "b", "type": "feature", "status": "fixed", "summary": "Real one", "fixed_at": RECENT - 10},
    ]
    out = _committed_features(reports, now=NOW)
    assert [f["id"] for f in out] == ["b"]


def test_newest_first_with_ts_fallback():
    reports = [
        {"id": "old", "type": "feature", "status": "fixed", "summary": "old", "fixed_at": NOW - 300},
        {"id": "new", "type": "bug", "status": "fixed", "summary": "new", "fixed_at": NOW - 100},
        {"id": "mid", "type": "feature", "status": "fixed", "summary": "mid", "fixed_at": 0, "ts": NOW - 200},
    ]
    out = _committed_features(reports, now=NOW)
    assert [f["id"] for f in out] == ["new", "mid", "old"]
    assert out[1]["fixed_at"] == NOW - 200  # ts used when fixed_at is 0


def test_capped_and_shape():
    reports = [
        {"id": str(i), "type": "feature", "status": "fixed", "summary": f"feat {i}",
         "fixed_at": NOW - i, "issue_url": f"http://x/{i}", "severity": "low"}
        for i in range(_WHATS_NEW_LIMIT + 5)
    ]
    out = _committed_features(reports, now=NOW)
    assert len(out) == _WHATS_NEW_LIMIT
    assert set(out[0].keys()) == {"id", "summary", "type", "fixed_at", "issue_url"}
    assert out[0]["id"] == "0"  # smallest offset from now -> newest -> first


def test_empty_input_returns_empty_list():
    assert _committed_features([]) == []
    assert _committed_features(None) == []
