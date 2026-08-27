"""Unit tests for tenant attribution + read-only tenant-admin scoping of
bug/feature reports.

A tenant admin gets a READ-ONLY, tenant-scoped view of Bug Reports + Feature
Requests: they see only reports filed under one of their own tenants, never
another tenant's, and never an untagged (legacy / Global-Admin-only) report.
The store must therefore capture + round-trip the ``tenant_id`` the route
resolves server-side, and the visibility rule must scope on it.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_bug_store import HubBugStoreMixin  # noqa: E402


class _Store(HubBugStoreMixin):
    def __init__(self, tmp):
        self.bug_dir = tmp
        self.bug_reports = {}
        self.bug_report_limit = 100


def test_store_captures_and_roundtrips_tenant_id(tmp_path):
    store = _Store(str(tmp_path))
    rid = store._store_bug_report(
        {"explanation": "boom", "type": "bug", "tenant_id": "lrb"}
    )
    # In-memory index carries it.
    assert store.bug_reports[rid]["tenant_id"] == "lrb"
    # Persisted to report.json.
    with open(os.path.join(str(tmp_path), rid, "report.json")) as f:
        assert json.load(f)["tenant_id"] == "lrb"
    # _get_bug_report surfaces it for the detail view.
    assert store._get_bug_report(rid)["tenant_id"] == "lrb"


def test_store_defaults_tenant_id_empty_when_absent(tmp_path):
    store = _Store(str(tmp_path))
    rid = store._store_bug_report({"explanation": "boom", "type": "bug"})
    assert store.bug_reports[rid]["tenant_id"] == ""
    assert store._get_bug_report(rid)["tenant_id"] == ""


def test_warm_load_rebuilds_tenant_id_from_disk(tmp_path):
    store = _Store(str(tmp_path))
    rid = store._store_bug_report(
        {"explanation": "boom", "type": "feature", "tenant_id": "dxp"}
    )
    # Simulate a hub restart: fresh index, rebuild from disk.
    store2 = _Store(str(tmp_path))
    store2.warm_load_bug_reports()
    assert store2.bug_reports[rid]["tenant_id"] == "dxp"


# ── Visibility rule (mirrors routes.setup_admin._bug_report_visible) ──────────
def _report_tenant(report):
    """Standalone copy of the route's tenant-resolution: top-level tenant_id,
    else the tenant in context.currentTenant ('default' sentinel → untagged)."""
    r = report or {}
    tid = str(r.get("tenant_id") or "").strip()
    if tid:
        return tid
    cmeta = r.get("context") or {}
    if isinstance(cmeta, dict):
        ctid = str(cmeta.get("currentTenant") or "").strip()
        return "" if ctid == "default" else ctid
    return ""


def _visible(is_admin, acting_tenants, report):
    """Standalone copy of the route's scoping predicate for unit testing."""
    if is_admin:
        return True
    tid = _report_tenant(report)
    return bool(tid) and tid in (acting_tenants or [])


def test_global_admin_sees_every_report():
    assert _visible(True, [], {"tenant_id": ""}) is True
    assert _visible(True, [], {"tenant_id": "other"}) is True


def test_tenant_admin_sees_only_own_tenant():
    assert _visible(False, ["lrb"], {"tenant_id": "lrb"}) is True
    assert _visible(False, ["lrb"], {"tenant_id": "dxp"}) is False


def test_tenant_admin_never_sees_untagged_legacy_report():
    assert _visible(False, ["lrb"], {"tenant_id": ""}) is False
    assert _visible(False, ["lrb"], {}) is False


def test_legacy_report_scopes_by_context_tenant():
    """A report with no top-level tenant_id still scopes by the tenant captured
    in its context (the tenant that's 'in the bug')."""
    own = {"tenant_id": "", "context": {"currentTenant": "lrb"}}
    other = {"tenant_id": "", "context": {"currentTenant": "dxp"}}
    assert _visible(False, ["lrb"], own) is True
    assert _visible(False, ["lrb"], other) is False


def test_top_level_tenant_id_wins_over_context():
    r = {"tenant_id": "lrb", "context": {"currentTenant": "dxp"}}
    assert _visible(False, ["lrb"], r) is True
    assert _visible(False, ["dxp"], r) is False


def test_default_sentinel_context_is_untagged():
    r = {"tenant_id": "", "context": {"currentTenant": "default"}}
    assert _visible(False, ["default"], r) is False
    assert _visible(False, ["lrb"], r) is False
