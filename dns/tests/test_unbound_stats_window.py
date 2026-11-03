"""Windowed (hour/day/week/month) headline stats from counter snapshots."""
from types import SimpleNamespace

import unbound_manager
from unbound_manager import UnboundManager


def _counters(q, h, r=0, up=10_000, a=None):
    lines = [f"total.num.queries={q}", f"total.num.cachehits={h}",
             f"total.num.cachemiss={q - h}", f"total.num.recursivereplies={r}",
             "total.recursion.time.avg=0.5", f"time.up={up}"]
    if a is not None:
        lines.append(f"total.num.query.type.A={a}")
    return "\n".join(lines)


def _mgr(monkeypatch, tmp_path, history=None):
    monkeypatch.setattr(UnboundManager, "_ensure_query_logging", lambda self: {"ok": True})
    monkeypatch.setattr(UnboundManager, "_tail_query_log", lambda self: None)
    return UnboundManager(str(tmp_path / "records.conf"), stats_history_path=history)


def _run(monkeypatch, out):
    monkeypatch.setattr(unbound_manager.subprocess, "run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout=out, stderr=""))


def _at(monkeypatch, t):
    monkeypatch.setattr(unbound_manager.time, "time", lambda: t)


def test_window_is_delta_from_baseline_sample(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path)
    t0 = 1_000_000.0
    _at(monkeypatch, t0)
    _run(monkeypatch, _counters(1000, 900, r=100, a=1000))
    assert mgr.sample_stats()
    _at(monkeypatch, t0 + 3600 + 30)
    _run(monkeypatch, _counters(1200, 1050, r=150, up=13_630, a=1200))

    res = mgr.get_stats(range_seconds=3600)

    g = res["global"]
    assert g["total_queries"] == 200
    assert g["cache_hits"] == 150
    assert g["cache_hit_ratio"] == 75.0
    assert g["num_recursive"] == 50
    assert res["query_types"] == {"A": 200}
    assert res["window"] == {"seconds": 3600, "covered_seconds": 3600, "partial": False}
    assert res["lifetime"]["total_queries"] == 1200


def test_unbound_restart_inside_window_counts_post_restart_counters(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path)
    t0 = 1_000_000.0
    _at(monkeypatch, t0)
    _run(monkeypatch, _counters(1000, 900, up=50_000))
    mgr.sample_stats()
    _at(monkeypatch, t0 + 600)
    _run(monkeypatch, _counters(1100, 950, up=50_600))
    mgr.sample_stats()
    # Restart: counters and uptime reset.
    _at(monkeypatch, t0 + 1200)
    _run(monkeypatch, _counters(30, 10, up=300))

    res = mgr.get_stats(range_seconds=3600)

    # 100 seen before the restart + 30 since; history starts inside the
    # window, so the result is flagged partial rather than over-claimed.
    assert res["global"]["total_queries"] == 130
    assert res["window"]["partial"] is True


def test_short_history_is_flagged_partial(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path)
    t0 = 1_000_000.0
    _at(monkeypatch, t0)
    _run(monkeypatch, _counters(5000, 4000, up=900_000))
    mgr.sample_stats()
    _at(monkeypatch, t0 + 7200)
    _run(monkeypatch, _counters(5400, 4300, up=907_200))

    res = mgr.get_stats(range_days=7)

    assert res["global"]["total_queries"] == 400
    assert res["window"]["partial"] is True
    assert res["window"]["covered_seconds"] == 7200


def test_no_range_keeps_lifetime_totals(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path)
    _run(monkeypatch, _counters(77, 70))
    res = mgr.get_stats()
    assert res["global"]["total_queries"] == 77
    assert "window" not in res


def test_history_persists_and_old_samples_are_thinned(monkeypatch, tmp_path):
    path = str(tmp_path / "hist.json")
    mgr = _mgr(monkeypatch, tmp_path, history=path)
    t0 = 1_000_000.0
    for i in range(48 * 12):  # two days of 5-minute samples
        _at(monkeypatch, t0 + i * 300)
        _run(monkeypatch, _counters(i * 10, i * 5))
        mgr.sample_stats()
    mgr._persist_stats_history(t0 + 48 * 3600, force=True)

    hist = mgr._stats_history
    fine = [s for s in hist if hist[-1]["t"] - s["t"] <= unbound_manager.STATS_FINE_RETENTION_S]
    coarse = [s for s in hist if s not in fine]
    assert len(fine) >= 26 * 12
    assert len(coarse) <= 23  # ~one per hour beyond the fine window

    reloaded = _mgr(monkeypatch, tmp_path, history=path)
    assert len(reloaded._stats_history) == len(hist)


def test_hour_window_query_names_use_event_timestamps(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path)
    now = 2_000_000.0
    _at(monkeypatch, now)
    mgr._query_events.extend([
        (now - 7200, "10.0.0.5", "old.example", "A"),
        (now - 60, "10.0.0.5", "new.example", "A"),
        (now - 30, "10.9.0.9", "new.example", "A"),
    ])
    rows = mgr.get_query_names(range_seconds=3600, source_prefixes=["10.0.0.0/24"])
    assert rows == [{"name": "new.example", "type": "A", "count": 1,
                     "sources": [{"ip": "10.0.0.5", "count": 1}]}]
