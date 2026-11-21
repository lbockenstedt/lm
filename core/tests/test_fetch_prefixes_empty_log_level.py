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


@pytest.mark.asyncio
async def test_known_prefixes_match_the_fetch_without_asking_netbox(monkeypatch):
    """known_tenant_prefixes answers what fetch_tenant_prefixes would serve,
    from what the hub holds, and never asks NetBox: the last answer while
    fresh, else the NetBox feed's copy, else the expired answer."""
    import access
    from access import known_tenant_prefixes
    hub = _CountingHub({"status": "SUCCESS", "prefixes": [{"prefix": "10.1.0.0/24"}]})
    assert known_tenant_prefixes(hub, "acme") is None  # nothing held yet
    await fetch_tenant_prefixes(hub, "acme")
    assert known_tenant_prefixes(hub, "acme") == ["10.1.0.0/24"]
    # Expired with no feed copy: still the last answer, and no NetBox call.
    now = access.time.time()
    monkeypatch.setattr(access.time, "time", lambda: now + access._PREFIX_CACHE_TTL + 1)
    assert known_tenant_prefixes(hub, "acme") == ["10.1.0.0/24"]
    assert hub.calls == 1
    # Expired: a feed copy older than that answer (its refresh failed and
    # kept the old copy) loses to it.
    hub.warm_get = lambda *a, **k: {"prefixes": [{"prefix": "10.9.0.0/24"}]}
    hub.warm_last_fetched_at = lambda *a, **k: now - 60
    assert known_tenant_prefixes(hub, "acme") == ["10.1.0.0/24"]
    # A newer feed copy beats the old answer, spoke or not, because the
    # hourly map build no longer refreshes the old answer often.
    hub.warm_last_fetched_at = lambda *a, **k: now + 60
    assert known_tenant_prefixes(hub, "acme") == ["10.9.0.0/24"]
    hub.get_spoke_by_type = lambda module_type: None
    assert known_tenant_prefixes(hub, "acme") == await fetch_tenant_prefixes(hub, "acme")
    assert known_tenant_prefixes(hub, "acme") == ["10.9.0.0/24"]
    assert hub.calls == 1


@pytest.mark.asyncio
async def test_known_prefixes_take_a_vrf_move_from_the_feed(monkeypatch):
    """A prefix that moved from the global table into the tenant's own VRF
    is cut from the shared slice as soon as the feed's copy shows the move,
    not only after the next live read: the page-side topology digest is
    built from this slice."""
    import access
    from access import known_tenant_prefixes, shared_slice_prefixes
    hub = _CountingHub({"status": "SUCCESS",
                        "prefixes": [{"prefix": "10.1.0.0/24", "vrf_id": None}]})
    await fetch_tenant_prefixes(hub, "acme")
    raw = known_tenant_prefixes(hub, "acme")
    assert shared_slice_prefixes(hub, "acme", raw) == ["10.1.0.0/24"]
    now = access.time.time()
    monkeypatch.setattr(access.time, "time", lambda: now + access._PREFIX_CACHE_TTL + 1)
    feed = {"prefixes": [{"prefix": "10.1.0.0/24", "vrf_id": 7}]}
    hub.warm_get = lambda ns, key, *a, **k: (
        feed if (ns, key) == (access._PREFIX_FEED_NS, "acme") else None)
    hub.warm_last_fetched_at = lambda ns, key, *a, **k: (
        now + 60 if (ns, key) == (access._PREFIX_FEED_NS, "acme") else None)
    raw = known_tenant_prefixes(hub, "acme")
    assert raw == ["10.1.0.0/24"]
    assert shared_slice_prefixes(hub, "acme", raw) == []
    assert hub.calls == 1


@pytest.mark.asyncio
async def test_known_prefixes_after_a_restart_skip_a_feed_copy_older_than_the_last_read():
    """After a hub restart the in-memory answer is gone, but the VRFs the
    last live read saved show the feed's copy is older than what NetBox last
    said: the page read asks NetBox instead of serving that copy. Once that
    ask has failed, its fallback is served without asking again."""
    import access
    from access import known_tenant_prefixes
    hub = _CountingHub({"status": "SUCCESS", "prefixes": [{"prefix": "10.1.0.0/24"}]})
    now = access.time.time()
    stored = {
        access._PREFIX_FEED_NS: ({"prefixes": [{"prefix": "10.9.0.0/24", "vrf_id": None}]},
                                 now - 600),
        access._PREFIX_VRF_NS: ({"10.1.0.0/24": ["7"]}, now - 60),
    }
    hub.warm_get = lambda ns, key, *a, **k: (
        stored[ns][0] if ns in stored and key == "acme" else None)
    hub.warm_last_fetched_at = lambda ns, key, *a, **k: (
        stored[ns][1] if ns in stored and key == "acme" else None)
    assert known_tenant_prefixes(hub, "acme") is None
    assert hub.calls == 0
    # The ask fails: the feed's copy is the fallback, served from then on.
    hub._reply = {"status": "ERROR", "message": "NetBox down"}
    assert await fetch_tenant_prefixes(hub, "acme") == ["10.9.0.0/24"]
    access._hub_prefix_cache(hub)["acme"] = (["10.9.0.0/24"], now - 1)
    assert known_tenant_prefixes(hub, "acme") == ["10.9.0.0/24"]
    assert hub.calls == 1
