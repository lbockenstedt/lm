"""ThreatMonitor.note_anomaly — the sentinel/host-detection anomaly sink (§5J).

  1. A ``critical`` anomaly with an attributable, non-trusted IP records the
     event AND drives an NSG block (reusing the hijack response).
  2. A ``critical`` anomaly from a trusted/allow-listed IP is SPARED (never nuke
     the legit admin's own IP on an ambiguous signal).
  3. A ``warning`` anomaly (e.g. a read-volume spike) is logged but NEVER blocks.
  4. A purely local anomaly (no IP — e.g. a canary trip on the box) records the
     event for the operator/host-layer response but cannot block (nothing to).
"""
import importlib.util
import json
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


def _tm_for(tmp_path, entries=None):
    gc = {"azure_nsg": {"entries": entries or []}}
    return ThreatMonitor(_Hub(_State(str(tmp_path), gc)))


def test_critical_with_untrusted_ip_blocks(tmp_path):
    tm = _tm_for(tmp_path)
    tm.note_anomaly("spoke_session_pivot", "console session owned by A addressed by B",
                    ip="203.0.113.7", severity="critical")
    assert "203.0.113.7" in tm._blocks
    assert tm._events[0]["kind"] == "spoke_session_pivot"


def test_critical_with_trusted_ip_is_spared(tmp_path):
    tm = _tm_for(tmp_path, entries=[{"ip": "198.51.100.9/32", "description": "admin home"}])
    tm.note_anomaly("sentinel_violation", "vault touched by evil", ip="198.51.100.9",
                    severity="critical")
    assert "198.51.100.9" not in tm._blocks       # allow-listed → spared
    assert tm._events[0]["kind"] == "sentinel_violation"


def test_warning_never_blocks(tmp_path):
    tm = _tm_for(tmp_path)
    tm.note_anomaly("sentinel_rate", "vault read burst", ip="203.0.113.20", severity="warning")
    assert "203.0.113.20" not in tm._blocks
    assert tm._events[0]["severity"] == "warning"


def test_local_anomaly_no_ip_records_only(tmp_path):
    tm = _tm_for(tmp_path)
    tm.note_anomaly("sentinel_violation", "canary tripped: vault.canary", severity="critical")
    assert len(tm._blocks) == 0
    assert tm._events[0]["detail"].startswith("canary tripped")
