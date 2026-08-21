"""Drill-down evidence + event persistence for the ThreatMonitor.

Covers the Security-view drill-down feature: every recorded signal (auth
failure OR anomaly) can carry structured ``meta`` evidence, events are tagged
with an ``anomaly`` flag so the UI can filter Signals / Auth-failures /
Anomalies, and the recent-events feed (with its evidence) survives a hub
restart via threat_monitor.json.
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


def _tm_for(tmp_path):
    return ThreatMonitor(_Hub(_State(str(tmp_path), {"azure_nsg": {"entries": []}})))


def _by_ip(events, ip):
    return next(e for e in events if e["ip"] == ip)


def test_auth_failure_carries_meta_and_flag(tmp_path):
    tm = _tm_for(tmp_path)
    tm.record_failure("203.0.113.5", "login", username="root",
                      meta={"user_agent": "sqlmap/1.7", "path": "/auth/login"})
    e = _by_ip(tm.snapshot()["events"], "203.0.113.5")
    assert e["anomaly"] is False
    assert e["meta"]["user_agent"] == "sqlmap/1.7"
    assert e["meta"]["path"] == "/auth/login"


def test_anomaly_carries_meta_and_flag(tmp_path):
    tm = _tm_for(tmp_path)
    tm.note_anomaly("session_hijack", "cookie replay", ip="198.51.100.9",
                    severity="warning",
                    meta={"bound_ip": "10.0.0.1", "presented_from": "198.51.100.9"})
    e = _by_ip(tm.snapshot()["events"], "198.51.100.9")
    assert e["anomaly"] is True
    assert e["meta"]["bound_ip"] == "10.0.0.1"


def test_meta_is_bounded(tmp_path):
    tm = _tm_for(tmp_path)
    big = {f"k{i}": "x" * 5000 for i in range(100)}
    tm.note_anomaly("sentinel_rate", "vault read burst", ip="203.0.113.77",
                    severity="warning", meta=big)
    e = _by_ip(tm.snapshot()["events"], "203.0.113.77")
    assert len(e["meta"]) <= 32                       # key cap
    assert all(len(v) <= 512 for v in e["meta"].values())  # per-value cap


def test_events_survive_restart(tmp_path):
    tm = _tm_for(tmp_path)
    tm.record_failure("203.0.113.5", "http_probe", detail="GET /admin.php",
                      meta={"user_agent": "curl/8"})
    tm.note_anomaly("sentinel_rate", "contract breach", ip="203.0.113.6",
                    severity="warning", meta={"source": "sentinel"})
    tm.sweep()  # flushes the events feed to threat_monitor.json

    tm2 = _tm_for(tmp_path)   # fresh instance re-reads the same data_dir
    events = tm2.snapshot()["events"]
    probe = _by_ip(events, "203.0.113.5")
    anom = _by_ip(events, "203.0.113.6")
    assert probe["meta"]["user_agent"] == "curl/8"
    assert anom["anomaly"] is True and anom["meta"]["source"] == "sentinel"
