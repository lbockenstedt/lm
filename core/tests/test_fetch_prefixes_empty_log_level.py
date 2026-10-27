"""fetch_tenant_prefixes: an empty-but-successful NetBox reply is a tenant with
no prefixes (normal) and logs at INFO; an error reply still WARNs. LM-HUB
logged ~380 warnings / 6h for 'shared' and 'stme-cordelia', which have none."""
import logging

import pytest

from access import fetch_tenant_prefixes
from _fakes import FakeState


class _Hub:
    def __init__(self, reply):
        self.state = FakeState(tenants={"acme": {"name": "Acme", "netbox_tenant_slug": "acme"}})
        self._reply = reply

    def get_spoke_by_type(self, module_type):
        return "netbox-spoke-1" if module_type == "ipam" else None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        return {"payload": {"data": self._reply}}

    def warm_get(self, *a, **k):
        return None


def _levels(caplog):
    return {r.levelno for r in caplog.records if "fetch_tenant_prefixes" in r.getMessage()}


@pytest.mark.asyncio
async def test_empty_success_is_info(caplog):
    with caplog.at_level(logging.INFO):
        out = await fetch_tenant_prefixes(_Hub({"status": "SUCCESS", "prefixes": []}), "acme")
    assert out == []
    assert _levels(caplog) == {logging.INFO}


@pytest.mark.asyncio
async def test_error_reply_still_warns(caplog):
    with caplog.at_level(logging.INFO):
        out = await fetch_tenant_prefixes(_Hub({"status": "ERROR", "message": "boom"}), "acme")
    assert out == []
    assert logging.WARNING in _levels(caplog)


class _CountingHub(_Hub):
    def __init__(self, reply):
        super().__init__(reply)
        self.calls = 0

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.calls += 1
        return await super().request_response(spoke_id, command, payload, timeout)


@pytest.mark.asyncio
async def test_prefixes_cached_between_reads():
    """Every filtered list read calls this; it must not hit NetBox each time."""
    hub = _CountingHub({"status": "SUCCESS", "prefixes": [{"prefix": "10.1.0.0/24"}]})
    assert await fetch_tenant_prefixes(hub, "acme") == ["10.1.0.0/24"]
    assert await fetch_tenant_prefixes(hub, "acme") == ["10.1.0.0/24"]
    assert hub.calls == 1


@pytest.mark.asyncio
async def test_clear_prefix_cache_forces_refetch():
    from access import clear_prefix_cache
    hub = _CountingHub({"status": "SUCCESS", "prefixes": [{"prefix": "10.1.0.0/24"}]})
    await fetch_tenant_prefixes(hub, "acme")
    clear_prefix_cache(hub)
    await fetch_tenant_prefixes(hub, "acme")
    assert hub.calls == 2


@pytest.mark.asyncio
async def test_failed_lookup_retried_after_short_ttl(monkeypatch):
    import access
    hub = _CountingHub({"status": "ERROR", "message": "Timed out waiting for spoke response"})
    await fetch_tenant_prefixes(hub, "acme")
    await fetch_tenant_prefixes(hub, "acme")
    assert hub.calls == 1
    now = access.time.time()
    monkeypatch.setattr(access.time, "time", lambda: now + access._PREFIX_FAIL_TTL + 1)
    await fetch_tenant_prefixes(hub, "acme")
    assert hub.calls == 2
