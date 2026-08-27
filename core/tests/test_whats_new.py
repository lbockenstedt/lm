"""Unit tests for the "What's New" feed helper (``routes/setup_admin.py``).

``GET /api/whats-new`` powers the WebUI top-banner info-icon popover. It lists
recently *committed* features — bug-store reports with ``type=="feature"`` that
AppBuilder built & closed (``status=="fixed"`` + a ``fixed_at`` epoch). The
selection/sort/cap lives in the pure ``_committed_features`` helper so it can be
exercised without building the FastAPI app. These lock in:

* only ``type=="feature"`` AND ``status=="fixed"`` rows are surfaced (bugs,
  still-open features, filed-but-not-yet-fixed features are all excluded);
* rows without a summary are dropped;
* newest-first by ``fixed_at``, falling back to ``ts`` when ``fixed_at`` is 0;
* the payload is capped at ``_WHATS_NEW_LIMIT`` and carries exactly the four
  public fields (id, summary, fixed_at, issue_url).
"""

from routes.setup_admin import _committed_features, _WHATS_NEW_LIMIT


def test_only_fixed_features_are_surfaced():
    reports = [
        {"id": "a", "type": "feature", "status": "fixed", "summary": "Dark mode", "fixed_at": 100},
        {"id": "b", "type": "bug", "status": "fixed", "summary": "Crash fix", "fixed_at": 200},
        {"id": "c", "type": "feature", "status": "filed", "summary": "Not built yet", "fixed_at": 0},
        {"id": "d", "type": "feature", "status": "", "summary": "Brand new", "fixed_at": 0},
    ]
    out = _committed_features(reports)
    assert [f["id"] for f in out] == ["a"]


def test_missing_summary_is_dropped():
    reports = [
        {"id": "a", "type": "feature", "status": "fixed", "summary": "  ", "fixed_at": 100},
        {"id": "b", "type": "feature", "status": "fixed", "summary": "Real one", "fixed_at": 90},
    ]
    out = _committed_features(reports)
    assert [f["id"] for f in out] == ["b"]


def test_newest_first_with_ts_fallback():
    reports = [
        {"id": "old", "type": "feature", "status": "fixed", "summary": "old", "fixed_at": 100},
        {"id": "new", "type": "feature", "status": "fixed", "summary": "new", "fixed_at": 300},
        # fixed_at 0 → falls back to ts for ordering
        {"id": "mid", "type": "feature", "status": "fixed", "summary": "mid", "fixed_at": 0, "ts": 200},
    ]
    out = _committed_features(reports)
    assert [f["id"] for f in out] == ["new", "mid", "old"]
    assert out[1]["fixed_at"] == 200  # ts used when fixed_at is 0


def test_capped_and_shape():
    reports = [
        {"id": str(i), "type": "feature", "status": "fixed", "summary": f"feat {i}",
         "fixed_at": i, "issue_url": f"http://x/{i}", "severity": "low"}
        for i in range(_WHATS_NEW_LIMIT + 5)
    ]
    out = _committed_features(reports)
    assert len(out) == _WHATS_NEW_LIMIT
    assert set(out[0].keys()) == {"id", "summary", "fixed_at", "issue_url"}
    assert out[0]["id"] == str(_WHATS_NEW_LIMIT + 4)  # highest fixed_at first


def test_empty_input_returns_empty_list():
    assert _committed_features([]) == []
    assert _committed_features(None) == []
