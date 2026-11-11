"""DHCP Overview time window: Kea packet counters become the increase over
the chosen hour/day/week/month instead of totals since Kea started."""
import kea_manager
from kea_manager import KeaManager


def _raw(received, ack):
    return {"pkt4-received": [[received, "t"]], "pkt4-ack-sent": [[ack, "t"]],
            "pkt4-discover-received": [[0, "t"]]}


def _mgr(monkeypatch, tmp_path, counters):
    mgr = KeaManager(ca_url="http://127.0.0.1:8000",
                     stats_history_path=str(tmp_path / "stats_history.json"))
    monkeypatch.setattr(mgr, "_rpc", lambda *a, **k: counters["raw"])
    monkeypatch.setattr(mgr, "list_subnets", lambda: [])
    monkeypatch.setattr(mgr, "list_leases", lambda: [])
    return mgr


def _at(monkeypatch, t):
    monkeypatch.setattr(kea_manager.time, "time", lambda: t)


def test_packet_counters_are_the_window_delta(monkeypatch, tmp_path):
    counters = {"raw": _raw(1000, 400)}
    mgr = _mgr(monkeypatch, tmp_path, counters)
    t0 = 1_000_000.0
    _at(monkeypatch, t0)
    assert mgr.sample_stats()
    _at(monkeypatch, t0 + 3600 + 30)
    counters["raw"] = _raw(1250, 500)

    res = mgr.get_stats(range_seconds=3600)

    assert res["global"]["pkt4_received"] == 250
    assert res["global"]["pkt4_ack_sent"] == 100
    assert res["window"]["partial"] is False
    assert res["lifetime"]["pkt4_received"] == 1250


def test_kea_restart_is_detected_from_counters_dropping(monkeypatch, tmp_path):
    counters = {"raw": _raw(1000, 400)}
    mgr = _mgr(monkeypatch, tmp_path, counters)
    t0 = 1_000_000.0
    _at(monkeypatch, t0)
    mgr.sample_stats()
    _at(monkeypatch, t0 + 600)
    counters["raw"] = _raw(1100, 450)
    mgr.sample_stats()
    # Kea restarted: its counters start again from zero.
    _at(monkeypatch, t0 + 4200)
    counters["raw"] = _raw(30, 10)

    res = mgr.get_stats(range_seconds=7200)

    # 100 before the restart + 30 after, never a negative number.
    assert res["global"]["pkt4_received"] == 130
    assert res["global"]["pkt4_ack_sent"] == 60


def test_no_range_keeps_lifetime_totals(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path, {"raw": _raw(1000, 400)})
    _at(monkeypatch, 1_000_000.0)

    res = mgr.get_stats()

    assert res["global"]["pkt4_received"] == 1000
    assert "window" not in res


def test_history_is_saved_as_json(monkeypatch, tmp_path):
    mgr = _mgr(monkeypatch, tmp_path, {"raw": _raw(5, 1)})
    _at(monkeypatch, 1_000_000.0)
    mgr.sample_stats()
    mgr._stats.persist(1_000_000.0, force=True)

    again = KeaManager(ca_url="http://x", stats_history_path=str(tmp_path / "stats_history.json"))
    assert again._stats.samples[0]["c"]["pkt4_received"] == 5
