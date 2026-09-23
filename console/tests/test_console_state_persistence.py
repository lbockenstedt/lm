"""Restart-durability contract for the console spoke's local state.

Port liveness telemetry (``last_activity`` / cumulative ``capture_bytes``), the
per-device capture recording and the serial-health/diagnostics history all used
to live ONLY in memory, so every service restart wiped them: a long-known device
reported "never seen" with 0 bytes, the capture view went blank even though the
full on-disk recording was still there, and the diagnostics report lost the
failure history an operator needs to spot a flapping port.

These pin the replacement contract — each store round-trips through disk,
debounces its writes (the serial reader thread touches them constantly), and
tolerates a missing/corrupt file by starting empty instead of crashing.
"""

import json

import serial_manager as sm


def test_telemetry_store_roundtrips_to_disk(tmp_path):
    """Verify telemetry data persists to disk and survives a service restart."""
    store_path = tmp_path / "t.json"
    store = sm.TelemetryStore(path=store_path)
    store.record("p1", last_activity=123.5, capture_bytes=99)
    store.flush()
    fresh_store = sm.TelemetryStore(path=store_path)
    assert fresh_store.get("p1") == {"last_activity": 123.5, "capture_bytes": 99}


def test_telemetry_store_defaults_for_unknown_port(tmp_path):
    """Ensure unknown ports return zeroed defaults without crashing."""
    store = sm.TelemetryStore(path=tmp_path / "t.json")
    assert store.get("nope") == {"last_activity": 0.0, "capture_bytes": 0}


def test_telemetry_store_debounces_writes(tmp_path):
    """Confirm debouncing prevents immediate disk writes while in-memory state updates."""
    store_path = tmp_path / "t.json"
    store = sm.TelemetryStore(path=store_path)
    store.record("p1", last_activity=100.0, capture_bytes=10)
    store.record("p1", last_activity=200.0, capture_bytes=20)
    assert store.get("p1") == {"last_activity": 200.0, "capture_bytes": 20}
    assert json.loads(store_path.read_text())["p1"]["last_activity"] == 100.0
    store.flush()
    assert json.loads(store_path.read_text())["p1"]["last_activity"] == 200.0


def test_telemetry_store_survives_corrupt_file(tmp_path):
    """Validate that corrupt state files are ignored and recovery works after restart."""
    store_path = tmp_path / "t.json"
    store_path.write_text("not json")
    store = sm.TelemetryStore(path=store_path)
    assert store.get("p") == {"last_activity": 0.0, "capture_bytes": 0}
    store.record("p", last_activity=50.0, capture_bytes=5)
    store.flush()
    assert json.loads(store_path.read_text())["p"]["last_activity"] == 50.0


def test_session_manager_snapshot_uses_persisted_telemetry(tmp_path):
    """Verify snapshot retrieves telemetry from disk after a service restart."""
    sm.telemetry_store().record("ttyX", last_activity=4242.0, capture_bytes=7)
    sm.telemetry_store().flush()
    mgr = sm.SessionManager(on_data=lambda *a: None)
    snap = mgr.snapshot("ttyX")
    assert snap["capture_bytes"] == 7 and snap["last_activity"] == 4242.0
    assert snap["monitoring"] is False and snap["has_user"] is False


def test_persisted_capture_reads_log_without_a_channel(tmp_path):
    """Ensure persisted capture is readable even when no channel is open."""
    log = sm.CaptureLog("ttyX", 4096)
    log.append(b"hello console\r\n")
    mgr = sm.SessionManager(on_data=lambda *a: None)
    assert mgr.channel("ttyX") is None
    assert b"hello console" in mgr.persisted_capture("ttyX")


def test_persisted_capture_empty_when_persistence_disabled(monkeypatch):
    """Confirm persisted capture returns empty when disabled via environment."""
    monkeypatch.setenv("LM_CONSOLE_CAPTURE_BYTES", "0")
    assert sm.SessionManager(on_data=lambda *a: None).persisted_capture("ttyX") == b""


def test_health_store_roundtrips_and_clears(tmp_path):
    """Validate health store persists data to disk and clears it atomically."""
    hs = sm.HealthStore(path=tmp_path / "h.json")
    d = hs.load()
    d["p1"] = {"open_failures": 3}
    hs.flush(d)
    assert json.loads((tmp_path / "h.json").read_text())["p1"]["open_failures"] == 3
    hs2 = sm.HealthStore(path=tmp_path / "h.json")
    assert hs2.load()["p1"]["open_failures"] == 3
    hs2.clear()
    assert hs2.load() == {} and not (tmp_path / "h.json").exists()


def test_health_store_load_returns_live_dict(tmp_path):
    """Ensure load returns the same mutable dict instance for live updates."""
    hs = sm.HealthStore(path=tmp_path / "h.json")
    a = hs.load()
    b = hs.load()
    assert a is b
