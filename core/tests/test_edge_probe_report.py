"""Hub ingest of edge-reported HTTPS-port scanner probes (HTTP_PROBE_REPORT).

An edge component (reverse proxy / AppBuilder / role-hosted spoke UI) detects a
scanner on ITS OWN :443 listener and relays it up the authenticated tunnel so
the hub blocks the source centrally on the NSG — one deny protects every edge.

``LabManagerHub._handle_edge_probe_report`` is the hub-side sink. It runs only
after the frame's signature verified (authenticated spoke), but a *compromised*
edge could still forge reports to poison the blocklist. These tests pin the
three defenses: server-side path re-classification, a per-reporter rate cap, and
reuse of the threat monitor's trusted-IP exemption.
"""
import importlib.util
import os
import sys

_SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

os.environ.setdefault("LM_FERNET_KEY", __import__("cryptography.fernet",
                      fromlist=["Fernet"]).Fernet.generate_key().decode())

import main  # noqa: E402


def _load_from_src(modname, relpath):
    target = os.path.join(_SRC, relpath)
    spec = importlib.util.spec_from_file_location(modname, target)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


_load_from_src("azure_nsg", "azure_nsg.py")
_tm = _load_from_src("security.threat_monitor", os.path.join("security", "threat_monitor.py"))
ThreatMonitor = _tm.ThreatMonitor


class _State:
    def __init__(self, data_dir, gc=None):
        self.data_dir = data_dir
        self.system_state = {"global_config": gc or {}}

    def _mark_dirty(self):
        pass


class _TmHub:
    def __init__(self, state):
        self.state = state


class _FakeHub:
    """Minimal stand-in exposing only what _handle_edge_probe_report reads."""
    def __init__(self, tm, max_reports=3):
        self.threat_monitor = tm
        self._edge_probe_reports = {}
        self._EDGE_PROBE_MAX = max_reports


def _tm_for(tmp_path, entries=None, threshold=5):
    tm = ThreatMonitor(_TmHub(_State(str(tmp_path), {"azure_nsg": {"entries": entries or []}})))
    tm.set_config({"threshold": threshold, "window_s": 600})
    return tm


def _report(hub, spoke_id, remote_ip, data):
    # Call the real method unbound with our fake as self.
    return main.LabManagerHub._handle_edge_probe_report(hub, spoke_id, remote_ip, data)


def test_valid_edge_probe_is_recorded(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/wp-login.php", "method": "GET", "node": "proxy-1"})
    t = tm.snapshot()["totals"]
    assert t["by_kind"]["http_probe"] == 1
    ev = tm._events[0]
    assert ev["ip"] == "203.0.113.7"
    assert "edge proxy-1" in ev["detail"]


def test_non_probe_path_is_rejected_server_side(tmp_path):
    # A compromised edge cannot get a BENIGN path attributed to a victim: the hub
    # re-classifies and drops anything that isn't itself a scanner signature.
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/api/security/overview", "method": "GET"})
    assert tm.snapshot()["totals"]["by_kind"].get("http_probe", 0) == 0
    assert len(tm._events) == 0


def test_loopback_and_bad_source_are_dropped(tmp_path):
    tm = _tm_for(tmp_path)
    hub = _FakeHub(tm)
    for bad in ("127.0.0.1", "0.0.0.0", "not-an-ip", "", None):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": bad, "path": "/.env", "method": "GET"})
    assert len(tm._events) == 0


def test_per_reporter_rate_cap(tmp_path):
    # A single owned edge cannot flood forged reports to poison the blocklist.
    tm = _tm_for(tmp_path, threshold=100)  # high so the cap, not the block, is what limits
    hub = _FakeHub(tm, max_reports=3)
    for i in range(10):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": f"203.0.113.{i}", "path": "/xmlrpc.php", "method": "POST"})
    assert tm.snapshot()["totals"]["by_kind"]["http_probe"] == 3  # only up to the cap


def test_repeated_valid_reports_block_the_source(tmp_path):
    tm = _tm_for(tmp_path, threshold=5)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(6):  # > threshold, same source
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": "203.0.113.44", "path": "/phpmyadmin/index.php", "method": "GET"})
    assert "203.0.113.44" in tm._blocks
    assert tm._blocks["203.0.113.44"]["kind"] == "http_probe"


def test_trusted_source_is_never_blocked_via_report(tmp_path):
    tm = _tm_for(tmp_path, entries=[{"ip": "198.51.100.5/32", "description": "admin"}], threshold=2)
    hub = _FakeHub(tm, max_reports=100)
    for _ in range(10):
        _report(hub, "proxy-1", "10.0.0.9",
                {"source_ip": "198.51.100.5", "path": "/.git/config", "method": "GET"})
    assert "198.51.100.5" not in tm._blocks          # trusted → exempt
    assert tm.snapshot()["totals"]["by_kind"]["http_probe"] == 10  # still counted


def test_missing_threat_monitor_is_a_noop(tmp_path):
    hub = _FakeHub(None)
    # Must not raise even with no monitor wired.
    _report(hub, "proxy-1", "10.0.0.9",
            {"source_ip": "203.0.113.7", "path": "/.env", "method": "GET"})
