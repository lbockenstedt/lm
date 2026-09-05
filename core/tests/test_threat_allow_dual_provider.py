"""ThreatMonitor.reconcile_allow() — dispatches the SAME shared trusted list
(global_config["azure_nsg"]["entries"] — canonical, provider-agnostic name) to
whichever cloud NSG allow rule(s) are enabled: Azure NSG and/or OCI NSG.

Root behavior this locks in:
- Neither provider enabled -> SKIPPED, no cloud calls made.
- Exactly one provider enabled -> that provider's result fields are ALSO
  surfaced at the top level (back-compat for callers that only knew Azure),
  in addition to the ``providers`` breakdown.
- Both providers enabled -> top-level ``status`` is SUCCESS only if every
  provider succeeded, PARTIAL otherwise; no top-level field merge (ambiguous
  with two providers) — callers must read ``providers``.
- OCI reconcile reuses the exact same shared entries as Azure (no separate
  OCI-only entries key).
"""
import asyncio
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
_az_mod = _load_from_src("azure_nsg", "azure_nsg.py")
_oci_mod = _load_from_src("oci_nsg", "oci_nsg.py")
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


def _tm_for(tmp_path, *, azure=None, oci=None, entries=None):
    gc = {
        "azure_nsg": {**(azure or {}), "entries": entries or []},
        "oci_nsg": dict(oci or {}),
    }
    return ThreatMonitor(_Hub(_State(str(tmp_path), gc)))


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _patch(monkeypatch, *, azure_result=None, oci_result=None, azure_raises=None, oci_raises=None):
    monkeypatch.setitem(sys.modules, "azure_nsg", _az_mod)
    monkeypatch.setitem(sys.modules, "oci_nsg", _oci_mod)
    calls = {"azure": None, "oci": None}

    async def _fake_az(cfg, azcfg, ips, http=None):
        calls["azure"] = list(ips)
        if azure_raises:
            raise azure_raises
        return azure_result or {"applied": True, "prefixes": list(ips)}
    monkeypatch.setattr(_az_mod, "reconcile_allowlist", _fake_az)

    async def _fake_oci(cfg, occfg, ips, http=None):
        calls["oci"] = list(ips)
        if oci_raises:
            raise oci_raises
        return oci_result or {"applied": True, "prefixes": list(ips), "added": len(ips), "removed": 0}
    monkeypatch.setattr(_oci_mod, "reconcile_allowlist", _fake_oci)
    return calls


def test_neither_provider_enabled_is_skipped_and_makes_no_calls(tmp_path, monkeypatch):
    calls = _patch(monkeypatch)
    tm = _tm_for(tmp_path, entries=[{"ip": "203.0.113.5/32", "description": ""}])

    res = _run(tm.reconcile_allow())

    assert res == {"status": "SKIPPED", "message": "no cloud NSG provider enabled — list saved, not applied"}
    assert calls["azure"] is None
    assert calls["oci"] is None


def test_azure_only_surfaces_fields_at_top_level_for_back_compat(tmp_path, monkeypatch):
    calls = _patch(monkeypatch)
    tm = _tm_for(
        tmp_path,
        azure={"enabled": True, "subscription_id": "s", "resource_group": "r", "nsg_name": "n"},
        entries=[{"ip": "203.0.113.5/32", "description": ""}],
    )

    res = _run(tm.reconcile_allow())

    assert res["status"] == "SUCCESS"
    assert res["count"] == 1  # top-level merge of the single provider's result
    assert res["providers"]["azure"]["status"] == "SUCCESS"
    assert "oci" not in res["providers"]
    assert calls["azure"] == ["203.0.113.5/32"]
    assert calls["oci"] is None


def test_oci_only_reuses_the_shared_azure_nsg_entries_key(tmp_path, monkeypatch):
    """OCI has no entries of its own — it must reconcile against the exact
    same shared list that lives under global_config["azure_nsg"]["entries"]."""
    calls = _patch(monkeypatch)
    tm = _tm_for(
        tmp_path,
        oci={"enabled": True, "nsg_id": "ocid1.nsg.oc1..x", "region": "us-ashburn-1"},
        entries=[{"ip": "198.51.100.9/32", "description": ""}],
    )

    res = _run(tm.reconcile_allow())

    assert res["status"] == "SUCCESS"
    assert res["count"] == 1
    assert res["added"] == 1 and res["removed"] == 0
    assert res["providers"]["oci"]["status"] == "SUCCESS"
    assert "azure" not in res["providers"]
    assert calls["oci"] == ["198.51.100.9/32"]
    assert calls["azure"] is None


def test_both_enabled_success_reports_overall_success_and_per_provider_breakdown(tmp_path, monkeypatch):
    calls = _patch(monkeypatch)
    tm = _tm_for(
        tmp_path,
        azure={"enabled": True, "subscription_id": "s", "resource_group": "r", "nsg_name": "n"},
        oci={"enabled": True, "nsg_id": "ocid1.nsg.oc1..x", "region": "us-ashburn-1"},
        entries=[{"ip": "203.0.113.5/32", "description": ""}],
    )

    res = _run(tm.reconcile_allow())

    assert res["status"] == "SUCCESS"
    assert res["providers"]["azure"]["status"] == "SUCCESS"
    assert res["providers"]["oci"]["status"] == "SUCCESS"
    assert "count" not in res  # ambiguous with two providers — no top-level merge
    # Both providers pushed the SAME shared list.
    assert calls["azure"] == ["203.0.113.5/32"]
    assert calls["oci"] == ["203.0.113.5/32"]


def test_both_enabled_one_failing_reports_partial(tmp_path, monkeypatch):
    calls = _patch(monkeypatch, oci_raises=RuntimeError("OCI 500"))
    tm = _tm_for(
        tmp_path,
        azure={"enabled": True, "subscription_id": "s", "resource_group": "r", "nsg_name": "n"},
        oci={"enabled": True, "nsg_id": "ocid1.nsg.oc1..x", "region": "us-ashburn-1"},
        entries=[{"ip": "203.0.113.5/32", "description": ""}],
    )

    res = _run(tm.reconcile_allow())

    assert res["status"] == "PARTIAL"
    assert res["providers"]["azure"]["status"] == "SUCCESS"
    assert res["providers"]["oci"]["status"] == "ERROR"
    assert "OCI 500" in res["providers"]["oci"]["message"]


def test_oci_enabled_but_not_fully_configured_is_skipped_not_errored(tmp_path, monkeypatch):
    """enabled=True but nsg_id/region missing (e.g. mid-setup) must SKIP, not
    raise or attempt a cloud call — mirrors the Azure "not configured" path."""
    calls = _patch(monkeypatch)
    tm = _tm_for(
        tmp_path,
        oci={"enabled": True},  # no nsg_id / region
        entries=[{"ip": "203.0.113.5/32", "description": ""}],
    )

    res = _run(tm.reconcile_allow())

    assert res["status"] == "SKIPPED"
    assert res["message"] == "OCI NSG not configured"
    assert calls["oci"] is None


def test_snapshot_includes_additive_oci_allow_rule_key(tmp_path, monkeypatch):
    """snapshot()'s new oci_allow_rule key must not disturb existing Azure
    fields (additive-only change)."""
    tm = _tm_for(
        tmp_path,
        azure={"enabled": True, "subscription_id": "s", "resource_group": "r", "nsg_name": "n"},
        oci={"enabled": True, "nsg_id": "ocid1.nsg.oc1..x", "region": "us-ashburn-1"},
        entries=[{"ip": "203.0.113.5/32", "description": ""}],
    )

    snap = tm.snapshot()

    assert snap["oci_allow_rule"] == {"enabled": True, "nsg_id": "ocid1.nsg.oc1..x"}
