"""lm#1123: ``DNS_CLIENT_QUERIES`` must be registered as an SWR *read* command.

``_relay_spoke`` treats any command NOT in ``_SWR_READ_CMDS`` as a write, and
bumps the shared generation counter (``_swr_gen``) so any stale-while-
revalidate background refresh in flight for ANY DNS/DHCP panel is discarded
(the in-flight fetch's stashed generation no longer matches, so its result is
silently dropped instead of being written to the warm cache). Before this
fix, every click on the per-device query log page quietly busted the whole
SWR cache for every other open DNS/DHCP panel, forcing them back to a live
spoke round-trip on their next read instead of serving instantly from cache.
"""
import asyncio
import time

import httpx
from fastapi import FastAPI
from types import SimpleNamespace

from cache_core import DEFAULT_STALE_AFTER_S
from routes.net_services import register
from warm_cache import WarmCacheMixin


class FakeState:
    def __init__(self):
        self.system_state = {"global_config": {"dns_instances": [], "dhcp_instances": []},
                             "module_metadata": {}}

    def get_spoke_tenant(self, sid):
        return ""


class FakeHub(WarmCacheMixin):
    """A real WarmCacheMixin (so SWR generation/staleness logic is genuine),
    with a controllable DNS_STATUS fetch that can be held open to simulate a
    background revalidation racing a concurrent DNS_CLIENT_QUERIES call."""

    def __init__(self, tmp_path):
        self.cache_dir = str(tmp_path)
        self.warm_cache_init()
        self.active_connections = {"dns-a"}
        self.approved_modules = {"dns-a": True}
        self.state = FakeState()
        self.forwarded = []
        self.status_gate = asyncio.Event()
        self.status_call_count = 0

    def _primary_key(self, sid):
        return sid

    def get_spoke_by_type(self, module_type):
        return "dns-a" if module_type == "dns" else None

    def get_dhcp_spoke_for_tenant(self, tenant_id=None):
        return None

    def get_dhcp_spoke_for_shared(self):
        return None

    async def request_response(self, sid, cmd, payload=None, timeout=None):
        self.forwarded.append((sid, cmd, payload))
        if cmd == "DNS_STATUS":
            self.status_call_count += 1
            # Block here so the test can fire a concurrent DNS_CLIENT_QUERIES
            # call while this "slow" background refresh is still in flight —
            # exactly the real race a page full of panels creates.
            await self.status_gate.wait()
            return {"payload": {"data": {"status": "SUCCESS", "healthy": True,
                                         "call": self.status_call_count}}}
        if cmd == "DNS_CLIENT_QUERIES":
            return {"payload": {"data": {"status": "SUCCESS", "queries": [],
                                         "client": (payload or {}).get("client", "")}}}
        return {"payload": {"data": {"status": "SUCCESS"}}}


async def _apassthrough(*a, **k):
    return a[1] if len(a) > 1 else None


def _build(hub):
    app = FastAPI()
    ctx = SimpleNamespace(
        _session_user=lambda request: {"user": {"is_admin": True}},
        _is_admin=lambda s: True,
        _effective_tenant=lambda request, explicit=None: explicit,
        _filter_session=_apassthrough,
        _filter_tenant=_apassthrough,
    )
    register(app, hub, ctx)
    app.state.hub = hub
    return app


def test_client_queries_does_not_discard_an_in_flight_status_refresh(tmp_path):
    async def _scenario():
        # Hub must be constructed inside the running loop: asyncio.Event()
        # binds to the loop active at construction time in this Python
        # version, and the test's event loop is the one started below.
        hub = FakeHub(tmp_path)
        app = _build(hub)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            # Prime the DNS_STATUS warm cache with an initial (non-blocked) fetch.
            hub.status_gate.set()
            r0 = await c.get("/api/dns/status")
            assert r0.status_code == 200
            hub.status_gate.clear()

            # Force the cache stale so the next read kicks off a background
            # revalidation (the in-flight fetch this test needs to race).
            key = next(iter(hub.warm_cache.get("netsvc_dns_status", {})))
            hub.warm_cache["netsvc_dns_status"][key]["fetched_at"] = (
                time.time() - (DEFAULT_STALE_AFTER_S + 10))

            r1 = await c.get("/api/dns/status")
            assert r1.status_code == 200  # served stale immediately

            # While that background refresh is blocked mid-flight, hit the
            # per-device query log — the exact action that used to bump the
            # SWR generation and get the in-flight refresh's result thrown
            # away.
            r2 = await c.get("/api/dns/client-queries")
            assert r2.status_code == 200

            # Let the blocked DNS_STATUS fetch complete and allow its
            # background task a moment to run.
            hub.status_gate.set()
            await asyncio.sleep(0.2)

            cached = hub.warm_get("netsvc_dns_status", key)
            assert cached is not None
            assert cached.get("call") == 2, (
                "the in-flight DNS_STATUS background refresh's result was "
                "discarded -- DNS_CLIENT_QUERIES bumped the SWR generation "
                "counter as if it were a write")

    asyncio.run(_scenario())
