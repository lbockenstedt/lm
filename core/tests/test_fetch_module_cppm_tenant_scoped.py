"""Regression: api._fetch_module's cppm_sessions/cppm_devices branches must
resolve the spoke via the TENANT-SCOPED hub.get_cppm_spoke_for_tenant(tenant_id),
not the untargeted hub.get_spoke_by_type("nac").

Before this fix, the untargeted lookup ignored _fetch_module's own tenant_id
parameter entirely, so with more than one nac spoke connected (e.g. two
ClearPass appliances, each only reachable from its own spoke) this
dashboard-cache-refresh cycle could resolve to a spoke bound to a DIFFERENT
tenant, or — for one tenant with two bound instances — flip between them
depending on connection/reconnect order (get_spoke_by_type's underlying
dict order shifts on every reconnect).
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import api  # noqa: E402


class _FakeHub:
    def __init__(self, resolved_spoke):
        self._resolved_spoke = resolved_spoke
        self.seen_tenant_ids = []
        self._nac_unconfigured_spokes = set()

    def get_spoke_by_type(self, module_type):
        raise AssertionError("must not use the untargeted, tenant-blind lookup")

    def get_cppm_spoke_for_tenant(self, tenant_id):
        self.seen_tenant_ids.append(tenant_id)
        return self._resolved_spoke

    async def request_response(self, spoke, cmd, payload, timeout=5.0):
        return {"status": "SUCCESS", "sessions": [], "devices": []}


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_cppm_sessions_resolves_via_tenant_scoped_lookup(monkeypatch):
    hub = _FakeHub("cppm-1")
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    ok = _run(api._fetch_module(hub, "tenantA", "cppm_sessions"))
    assert ok is True
    assert hub.seen_tenant_ids == ["tenantA"]


def test_cppm_devices_resolves_via_tenant_scoped_lookup(monkeypatch):
    hub = _FakeHub("cppm-1")
    monkeypatch.setattr(api, "_set_cache_status", lambda *a, **k: None)
    ok = _run(api._fetch_module(hub, "tenantB", "cppm_devices"))
    assert ok is True
    assert hub.seen_tenant_ids == ["tenantB"]


def test_cppm_sessions_no_spoke_for_tenant_is_an_error(monkeypatch):
    hub = _FakeHub(None)
    statuses = []
    monkeypatch.setattr(api, "_set_cache_status",
                        lambda tid, key, status: statuses.append((tid, key, status)))
    ok = _run(api._fetch_module(hub, "tenantC", "cppm_sessions"))
    assert ok is False
    assert ("tenantC", "cppm_sessions", "error") in statuses
