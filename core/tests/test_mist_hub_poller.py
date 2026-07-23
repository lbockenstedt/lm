"""Hub-side Juniper Mist poller for CENTRALIZED processing mode (Mist Phase 3).

Central and Mist are separate products; ``mist_hub_poller`` MIRRORS
``central_hub_poller`` without importing it. Covers:
  - the mirror invariant (no central_hub_poller import; mist + check_eval used),
  - the Mist-owned client-count thresholds + worst-status helper,
  - ``MistClientCountTracker`` (no_data / drop / persist round-trip),
  - ``MistCheckHealthHistory`` (record → daily summary + success_stats),
  - ``MistCheckPollWindow`` (verdict rule + tenant forget),
  - ``MistHubPoller._poll_tenant`` writes ``mist_hub_status[tenant]`` in the
    dashboard shape with INVERTED check semantics, ``mist_clients_by_site``,
    ``hardware_alerts``, and records the alert catalog tagged ``source="mist"``,
  - ``_poll_once`` prunes tenants that left centralized mode / cleared creds.
"""
import ast
import time

import simulations.mist_hub_poller as mhp
from simulations.mist_hub_poller import (
    MistCheckHealthHistory, MistCheckPollWindow, MistClientCountTracker,
    MistHubPoller, _classify_poll_status, _mist_cc_thresholds, _mist_cc_worst,
)


# ── mirror invariant (separate product, not shared) ─────────────────────────

def _imports(path):
    tree = ast.parse(open(path).read())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
        elif isinstance(node, ast.Import):
            for n in node.names:
                mods.add(n.name)
    return mods


def test_mist_hub_poller_does_not_import_central():
    import os
    here = os.path.dirname(mhp.__file__)
    mods = _imports(os.path.join(here, "mist_hub_poller.py"))
    assert not any("central_hub_poller" in m for m in mods), \
        "mist_hub_poller must mirror, not import, central_hub_poller"
    # It DOES use the Mist client + the shared generic check matcher.
    assert "mist" in mods or any(m.endswith(".mist") for m in mods)
    assert any("check_eval" in m for m in mods)


# ── thresholds + worst-status ───────────────────────────────────────────────

def test_thresholds_defaults_and_clamp():
    t = _mist_cc_thresholds({})
    assert t["warn_pct"] == 20.0 and t["error_pct"] == 50.0
    assert t["die_off_frac"] == 0.2 and t["min_peak"] == 5
    # error below warn is coerced up to warn so red never trips before amber.
    t2 = _mist_cc_thresholds({"cc_thresholds": {"warn_pct": 30, "error_pct": 10}})
    assert t2["warn_pct"] == 30.0 and t2["error_pct"] == 30.0


def test_cc_worst_severity():
    assert _mist_cc_worst("error", "warning", "ok") == "error"
    assert _mist_cc_worst("ok", "warning") == "warning"
    assert _mist_cc_worst("no_data") == "no_data"
    assert _mist_cc_worst() == "ok"


# ── MistClientCountTracker ──────────────────────────────────────────────────

def test_tracker_no_data_with_few_samples(tmp_path):
    tr = MistClientCountTracker(str(tmp_path))
    tr.record("acme", "MIA", 10)
    e = tr.entry("acme", "MIA", "Mist-MIA")
    assert e["status"] == "no_data"  # < _CC_MIN_SAMPLES(3)
    assert e["site_name"] == "Mist-MIA"


def test_tracker_drop_flags_error(tmp_path):
    tr = MistClientCountTracker(str(tmp_path))
    # Establish a healthy hourly average, then crash the count.
    for _ in range(4):
        tr.record("acme", "MIA", 100)
    tr.record("acme", "MIA", 20)  # 80% drop → error (>50%)
    e = tr.entry("acme", "MIA", "Mist-MIA")
    assert e["status"] == "error"
    assert e["drop_pct"] > 50.0


def test_tracker_persist_round_trip(tmp_path):
    tr = MistClientCountTracker(str(tmp_path))
    for _ in range(4):
        tr.record("acme", "MIA", 50)
    tr.save_samples()
    tr2 = MistClientCountTracker(str(tmp_path))
    e = tr2.entry("acme", "MIA", "Mist-MIA")
    assert e["current"] == 50 and e["status"] == "ok"


# ── MistCheckHealthHistory ──────────────────────────────────────────────────

def test_health_record_summary_and_success(tmp_path):
    h = MistCheckHealthHistory(str(tmp_path))
    h.record("acme", "MIA", "ap_offline", "ok")
    h.record("acme", "MIA", "ap_offline", "error")
    summ = h.summary("acme")
    assert "MIA" in summ and "ap_offline" in summ["MIA"]
    bucket = summ["MIA"]["ap_offline"][0]
    assert bucket["o"] == 1 and bucket["e"] == 1
    stats = h.success_stats("acme")
    # 1 ok + 1 error graded → 50% over the 24h window.
    assert stats["MIA"]["ap_offline"]["h24"] == 50.0


def test_health_forget_isolates_tenant(tmp_path):
    h = MistCheckHealthHistory(str(tmp_path))
    h.record("acme", "MIA", "c", "ok")
    h.record("beta", "MIA", "c", "ok")
    h.forget("acme")
    assert h.summary("acme") == {}
    assert "MIA" in h.summary("beta")


# ── MistCheckPollWindow (mirror of CheckPollWindow) ─────────────────────────

def test_poll_window_verdict_rule(tmp_path):
    w = MistCheckPollWindow(str(tmp_path))
    for _ in range(3):
        w.record("t", "s", "c", True)
    assert w.verdict("t", "s", "c") == "ok"
    w.record("t", "s", "c", False)
    assert w.verdict("t", "s", "c") == "warning"  # 1 fail of 4 → ≤50%
    for _ in range(4):
        w.record("t", "s", "c", False)
    assert w.verdict("t", "s", "c") == "error"  # >50% fail
    assert MistCheckPollWindow(str(tmp_path)).verdict("x", "y", "z") is None


def test_classify_inverted_semantics():
    assert _classify_poll_status("ok") is True
    assert _classify_poll_status("warning") is False  # client drop = FAILED poll
    assert _classify_poll_status("error") is False   # missing alert = FAILED poll
    assert _classify_poll_status("no_data") is None


# ── MistHubPoller._poll_tenant ──────────────────────────────────────────────

class _FakeClient:
    """Stand-in for MistClient — returns a fixed poll_site_data payload."""
    def __init__(self, cfg):
        self.cfg = cfg

    def is_configured(self):
        return bool(self.cfg.get("api_token"))

    async def poll_site_data(self, site, hw_ids):
        return {
            "client_count": 10, "wired_clients": 4, "wireless_clients": 6,
            "alert_type_counts": {"ap_offline": 2},
            "insight_cat_counts": {},
            "hw_devices": {"ap_offline": {"AP1": 1, "AP2": 1}},
        }

    async def _list_inventory(self):
        return []


class _Store:
    def __init__(self, mist_config, sites_config):
        self._mc = mist_config
        self._sc = sites_config
        self.recorded = []

    def tenant_ids(self):
        return ["acme"]

    async def get_processing_modes(self, tid):
        return {}

    def mist_api_is_centralized(self, modes):
        return True  # unset defaults to centralized

    async def get_mist_config(self, tid):
        return self._mc

    async def get_mist_sites_config(self, tid):
        return self._sc

    async def record_alert_insight_seen(self, items):
        self.recorded.extend(items or [])


class _Hub:
    def __init__(self, store, data_dir):
        self.simulations_store = store
        self.mist_hub_status = {}

        class _state:
            pass
        self.state = _state()
        self.state.data_dir = data_dir


def _build_poller(tmp_path, monkeypatch, mist_config=None, sites_config=None):
    mc = mist_config if mist_config is not None else {"api_token": "t", "org_id": "o"}
    sc = sites_config if sites_config is not None else {
        "site_mappings": {"MIA": "Mist-MIA"},
        "monitored_checks": [
            {"id": "ap_offline", "type": "alert", "name": "APs Offline"},
            {"id": "rogue_ap", "type": "alert", "name": "Rogue AP"},
        ],
        "hardware_checks": [{"id": "ap_offline", "name": "APs Offline", "device_type": "ap"}],
    }
    store = _Store(mc, sc)
    hub = _Hub(store, str(tmp_path))
    monkeypatch.setattr(mhp, "MistClient", _FakeClient)
    return MistHubPoller(hub), store, hub


def test_poll_tenant_writes_status_with_inverted_semantics(tmp_path, monkeypatch):
    poller, store, hub = _build_poller(tmp_path, monkeypatch)
    import asyncio
    asyncio.run(poller._poll_tenant("acme", {"api_token": "t", "org_id": "o"}))
    st = hub.mist_hub_status["acme"]
    checks = st["status"]["MIA"]
    # ap_offline IS present (count 2) → healthy (ok) under inverted semantics.
    assert checks["ap_offline"]["status"] == "ok"
    # rogue_ap is absent → the sim stopped producing it → error.
    assert checks["rogue_ap"]["status"] == "error"
    # client-count monitor surfaced as a check; 1 sample → no_data.
    assert "Steady Client Count 1hr Average" in checks


def test_poll_tenant_clients_hardware_and_catalog(tmp_path, monkeypatch):
    poller, store, hub = _build_poller(tmp_path, monkeypatch)
    import asyncio
    asyncio.run(poller._poll_tenant("acme", {"api_token": "t", "org_id": "o"}))
    st = hub.mist_hub_status["acme"]
    assert st["mist_clients_by_site"]["MIA"] == 10
    assert st["token_valid"] is True
    assert st["site_mappings"] == {"MIA": "Mist-MIA"}
    # hw_devices ap_offline {AP1:1, AP2:1} → total 2.
    assert any(h["id"] == "ap_offline" and h["total"] == 2 for h in st["hardware_alerts"])
    # Catalog recorded with source="mist" (Phase 1 writer).
    assert store.recorded, "alert_insight_seen should be recorded"
    assert all(it.get("source") == "mist" for it in store.recorded)
    assert any(it["id"] == "ap_offline" for it in store.recorded)


def test_poll_tenant_unconfigured_clears_status(tmp_path, monkeypatch):
    poller, store, hub = _build_poller(tmp_path, monkeypatch)
    hub.mist_hub_status["acme"] = {"status": {"MIA": {}}, "token_valid": True}
    import asyncio
    asyncio.run(poller._poll_tenant("acme", {"api_token": "", "org_id": ""}))
    assert "acme" not in hub.mist_hub_status


def test_poll_once_prunes_stale_tenants(tmp_path, monkeypatch):
    poller, store, hub = _build_poller(tmp_path, monkeypatch,
                                       mist_config={"api_token": "", "org_id": ""})
    hub.mist_hub_status["ghost"] = {"status": {}, "token_valid": True}
    import asyncio
    asyncio.run(poller._poll_once())
    # No centralized tenant with creds → ghost is pruned.
    assert "ghost" not in hub.mist_hub_status