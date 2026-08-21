"""Regression: api._fetch_module's cppm_sessions/cppm_devices branches must
resolve spokes via the TENANT-SCOPED hub.get_cppm_spokes_for_tenant(tenant_id)
— a tenant's own dedicated CPPM PLUS the shared-tenant CPPM if one exists —
merging both into one cached result, not the untargeted
hub.get_spoke_by_type("nac") and not a single-spoke pick that would silently
drop one of the two sources.

Before the underlying fix, the untargeted lookup ignored _fetch_module's own
tenant_id parameter entirely, so with more than one nac spoke connected (e.g.
two ClearPass appliances, each only reachable from its own spoke) this
dashboard-cache-refresh cycle could resolve to a spoke bound to a DIFFERENT
tenant, or flip between two same-tenant instances depending on connection/
reconnect order. Pinning to a single spoke fixed that but couldn't show a
tenant's own CPPM + a shared CPPM together — this merges both.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import api  # noqa: E402


class _FakeHub:
    def __init__(self, spokes_for_tenant, responses=None, unconfigured=None):
        self._spokes_for_tenant = spokes_for_tenant
        self.responses = responses or {}
        self.seen_tenant_ids = []
        self.requested = []
        self._nac_unconfigured_spokes = set(unconfigured or [])

    def get_spoke_by_type(self, module_type):
        raise AssertionError("must not use the untargeted, tenant-blind lookup")

    def get_cppm_spokes_for_tenant(self, tenant_id):
        self.seen_tenant_ids.append(tenant_id)
        return self._spokes_for_tenant

    async def request_response(self, spoke, cmd, payload, timeout=5.0):
        self.requested.append(spoke)
        return self.responses.get(spoke, {"status": "SUCCESS", "sessions": [], "devices": []})


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_cppm_sessions_resolves_via_tenant_scoped_lookup(monkeypatch):
    hub = _FakeHub(["cppm-1"])
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_sessions"))
    assert ok is True
    assert hub.seen_tenant_ids == ["tenantA"]
    assert hub.requested == ["cppm-1"]


def test_cppm_devices_resolves_via_tenant_scoped_lookup(monkeypatch):
    hub = _FakeHub(["cppm-1"])
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    ok = _run(api._fetch_module(hub, "tenantB", "cppm_devices"))
    assert ok is True
    assert hub.seen_tenant_ids == ["tenantB"]


def test_cppm_sessions_no_spoke_for_tenant_is_an_error(monkeypatch):
    hub = _FakeHub([])
    statuses = []
    monkeypatch.setattr(api, "_set_cache_status",
                        lambda tid, key, status: statuses.append((tid, key, status)))
    ok = _run(api._fetch_module(hub, "tenantC", "cppm_sessions"))
    assert ok is False
    assert ("tenantC", "cppm_sessions", "error") in statuses


# ── merge behavior: own + shared combined ───────────────────────────────────

def test_cppm_sessions_merges_own_and_shared_spokes(monkeypatch):
    hub = _FakeHub(
        ["cppm-own", "cppm-shared"],
        responses={
            "cppm-own": {"status": "SUCCESS", "sessions": [{"mac": "aa"}]},
            "cppm-shared": {"status": "SUCCESS", "sessions": [{"mac": "bb"}]},
        },
    )
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    entries = {}
    monkeypatch.setattr(api, "_set_cache_entry",
                        lambda tid, key, data: entries.__setitem__((tid, key), data))
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_sessions"))
    assert ok is True
    data = entries[("tenantA", "cppm_sessions")]
    macs = {s["mac"] for s in data["sessions"]}
    assert macs == {"aa", "bb"}
    assert data["total"] == 2


def test_cppm_devices_merge_survives_one_spoke_erroring(monkeypatch):
    """One source failing must not blank the other's data."""
    hub = _FakeHub(["cppm-own", "cppm-shared"])

    async def _flaky_request_response(spoke, cmd, payload, timeout=5.0):
        hub.requested.append(spoke)
        if spoke == "cppm-shared":
            raise TimeoutError("no route to host")
        return {"status": "SUCCESS", "devices": [{"mac": "aa"}]}

    hub.request_response = _flaky_request_response
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    entries = {}
    monkeypatch.setattr(api, "_set_cache_entry",
                        lambda tid, key, data: entries.__setitem__((tid, key), data))
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_devices"))
    assert ok is True
    data = entries[("tenantA", "cppm_devices")]
    assert [d["mac"] for d in data["devices"]] == ["aa"]


def test_cppm_sessions_skips_unconfigured_spoke_but_keeps_the_other(monkeypatch):
    hub = _FakeHub(
        ["cppm-own", "cppm-shared"],
        responses={"cppm-own": {"status": "SUCCESS", "sessions": [{"mac": "aa"}]}},
        unconfigured={"cppm-shared"},
    )
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    entries = {}
    monkeypatch.setattr(api, "_set_cache_entry",
                        lambda tid, key, data: entries.__setitem__((tid, key), data))
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_sessions"))
    assert ok is True
    assert hub.requested == ["cppm-own"]  # never queried the unconfigured one
    assert entries[("tenantA", "cppm_sessions")]["sessions"] == [{"mac": "aa"}]


def test_cppm_sessions_all_spokes_unconfigured_is_an_error(monkeypatch):
    hub = _FakeHub(["cppm-own"], unconfigured={"cppm-own"})
    statuses = []
    monkeypatch.setattr(api, "_set_cache_status",
                        lambda tid, key, status: statuses.append((tid, key, status)))
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_sessions"))
    assert ok is False
    assert ("tenantA", "cppm_sessions", "error") in statuses
    assert hub.requested == []
