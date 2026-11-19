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
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hub_bug_store import HubBugStoreMixin  # noqa: E402
from routes import setup_admin  # noqa: E402


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


# ── Visibility rule (drives the real /tenant/bug-reports routes) ──────────────
def _visible(is_admin, acting_tenants, report):
    """True when the real tenant list route shows ``report`` to this caller.
    The detail route must agree: 200 when listed, 404 when hidden."""
    app = FastAPI()
    hub = SimpleNamespace(_list_bug_reports=lambda: [dict(report, id="r1")],
                          _get_bug_report=lambda rid: dict(report, id=rid))
    app.state.hub = hub
    sess = {"user": {"tenants": list(acting_tenants or [])}}
    ctx = SimpleNamespace(_is_admin=lambda s: is_admin, _session_user=lambda req: sess)
    setup_admin.register(app, hub, ctx)
    c = TestClient(app)
    listed = bool(c.get("/tenant/bug-reports").json()["reports"])
    assert c.get("/tenant/bug-reports/r1").status_code == (200 if listed else 404)
    return listed


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


def test_tenant_admin_sees_own_report_in_any_capitalisation():
    """A report filed under "ACME" belongs to a user assigned "acme" (tenant ids
    compare canonically, fleet rule 6.1), but never to another tenant."""
    assert _visible(False, ["acme"], {"tenant_id": "ACME"}) is True
    assert _visible(False, ["acme"], {"tenant_id": "", "context": {"currentTenant": "Acme"}}) is True
    assert _visible(False, ["other"], {"tenant_id": "ACME"}) is False
