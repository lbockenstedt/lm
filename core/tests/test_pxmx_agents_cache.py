"""Regression tests for the ``/api/pxmx/agents`` stale-while-revalidate
cache + concurrent fan-out (``routes/pxmx.py``).

Pre-cache, the route fanned ``GET_AGENTS`` out to every agent-hosting spoke
SEQUENTIALLY with a 5s request_timeout each — so a slow/reconnecting spoke
made the Setup → Spokes & Agents page block up to N×5s on every load. The
cache serves instant reads from memory inside the stale window and
collapses concurrent first-loaders into a single concurrent
(``asyncio.gather``) fan-out. These lock in:

* a repeat read within the fresh window does NOT re-hit any spoke;
* a forced refresh fans out CONCURRENTLY (wall-clock ≈ max, not sum);
* N concurrent cold reads produce ONE fan-out, not N;
* a per-spoke failure (the pxmx agent-spoke reconnect loop) does not blank
  the tile — the other spoke's agents still come through.

The aggregation + cache live at module level (depend only on ``hub`` + the
spoke list), so these tests exercise them directly with a stub hub — no full
FastAPI app build.
"""

import asyncio
import time

from routes import pxmx


# ── Fakes ────────────────────────────────────────────────────────────────────

class _FakeStatus:
    @property
    def value(self):
        return "healthy"


class _FakeHeartbeat:
    def __init__(self):
        self.last_seen = {}
        self._status = _FakeStatus()

    def get_status(self, _key):
        return self._status


class _FakeState:
    def __init__(self):
        self.system_state = {"agent_config": {}, "agent_display_names": {}}


class _FakeHub:
    """Minimal hub: records GET_AGENTS calls per spoke with a per-spoke delay
    and returns a canned agent payload. Lets us assert concurrency + caching."""

    def __init__(self):
        self.state = _FakeState()
        self.heartbeat = _FakeHeartbeat()
        self.calls = []  # (spoke, t)
        self._delay = {}
        self._payload = {}
        self._fail = set()

    def get_all_spokes_by_type(self, t):
        # Two hypervisor spokes so we can prove concurrency + the
        # one-dead-spoke-doesn't-blank-the-tile property.
        if t == "hypervisor":
            return ["pxmx-spoke-1", "pxmx-spoke-2"]
        return []

    async def request_response(self, spoke, cmd, data, timeout=5.0, **kw):
        self.calls.append((spoke, time.time()))
        await asyncio.sleep(self._delay.get(spoke, 0))
        if spoke in self._fail:
            raise asyncio.TimeoutError("simulated slow/unreachable spoke")
        return {"payload": {"data": {"agents": self._payload.get(spoke, []),
                                       "pending_agents": []}}}

    def get_spoke_events(self, *a, **k):
        return []

    # B1/B2 guid-primary seams: aliases empty → identity (mirrors a hub with
    # no spokes/agents armed yet). The aggregate builder resolves through these.
    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_primary_key(self, agent_id):
        return agent_id

    def _agent_relay_name(self, agent_id):
        return agent_id


def _reset_cache():
    pxmx._AGENTS_CACHE["data"] = None
    pxmx._AGENTS_CACHE["ts"] = 0.0
    pxmx._AGENTS_CACHE["refreshing"] = False


SPOKES = ["pxmx-spoke-1", "pxmx-spoke-2"]


# ── Tests ────────────────────────────────────────────────────────────────────

def test_repeat_read_within_fresh_window_hits_spokes_once():
    _reset_cache()
    hub = _FakeHub()
    hub._payload["pxmx-spoke-1"] = [{"agent_id": "a1"}]
    hub._payload["pxmx-spoke-2"] = [{"agent_id": "a2"}]
    r1 = asyncio.run(pxmx._maybe_refresh_agents(hub, SPOKES, force=True))
    r2 = asyncio.run(pxmx._maybe_refresh_agents(hub, SPOKES))  # fresh → cache
    assert len(hub.calls) == 2  # one per spoke, once total
    assert {a["agent_id"] for a in r1["agents"]} == {"a1", "a2"}
    assert r2 is r1  # same cached object, no re-fan-out


def test_forced_refresh_fans_out_concurrently_not_sequentially():
    _reset_cache()
    hub = _FakeHub()
    hub._delay = {"pxmx-spoke-1": 0.2, "pxmx-spoke-2": 0.2}
    hub._payload["pxmx-spoke-1"] = [{"agent_id": "a1"}]
    hub._payload["pxmx-spoke-2"] = [{"agent_id": "a2"}]
    t0 = time.time()
    r = asyncio.run(pxmx._maybe_refresh_agents(hub, SPOKES, force=True))
    elapsed = time.time() - t0
    starts = [t for _, t in hub.calls]
    assert len(starts) == 2
    spread = max(starts) - min(starts)
    assert spread < 0.05, f"fan-out not concurrent (spread={spread:.3f}s)"
    assert elapsed < 0.35, f"refresh took {elapsed:.3f}s (sequential?)"
    assert {a["agent_id"] for a in r["agents"]} == {"a1", "a2"}


def test_concurrent_cold_reads_collapse_into_one_fanout():
    _reset_cache()
    hub = _FakeHub()
    hub._delay = {"pxmx-spoke-1": 0.1, "pxmx-spoke-2": 0.1}
    hub._payload["pxmx-spoke-1"] = [{"agent_id": "a1"}]
    hub._payload["pxmx-spoke-2"] = [{"agent_id": "a2"}]

    async def _two():
        a, b = await asyncio.gather(
            pxmx._maybe_refresh_agents(hub, SPOKES, force=True),
            pxmx._maybe_refresh_agents(hub, SPOKES, force=True),
        )
        return a, b

    a, b = asyncio.run(_two())
    # Two concurrent cold reads → ONE fan-out (2 spoke calls, not 4).
    assert len(hub.calls) == 2, f"expected 2 spoke calls, got {len(hub.calls)}"
    assert {x["agent_id"] for x in a["agents"]} == {"a1", "a2"}
    assert {x["agent_id"] for x in b["agents"]} == {"a1", "a2"}


def test_one_dead_spoke_does_not_blank_tile():
    _reset_cache()
    hub = _FakeHub()
    hub._fail = {"pxmx-spoke-2"}  # the reconnecting/slow spoke
    hub._payload["pxmx-spoke-1"] = [{"agent_id": "a1"}]
    r = asyncio.run(pxmx._maybe_refresh_agents(hub, SPOKES, force=True))
    # The healthy spoke's agent still comes through; the failed one skipped.
    assert {a["agent_id"] for a in r["agents"]} == {"a1"}


def test_stale_window_serves_cache_and_kicks_background_refresh():
    _reset_cache()
    hub = _FakeHub()
    hub._payload["pxmx-spoke-1"] = [{"agent_id": "a1"}]
    hub._payload["pxmx-spoke-2"] = [{"agent_id": "a2"}]
    # Prime the cache with a payload + an OLD ts so the route's stale-window
    # branch (age >= FRESH, < STALE) fires and spawns a background refresh.
    pxmx._AGENTS_CACHE["data"] = {"agents": [{"agent_id": "stale"}],
                                   "pending_agents": [], "spoke_connected": True}
    pxmx._AGENTS_CACHE["ts"] = time.time() - 10.0  # past FRESH(5s), inside STALE(30s)

    async def _bg():
        # Simulate the route's background-refresh spawn path.
        await pxmx._maybe_refresh_agents(hub, SPOKES)

    asyncio.run(_bg())
    # The background refresh replaced the stale payload with the live one.
    assert {a["agent_id"] for a in pxmx._AGENTS_CACHE["data"]["agents"]} == {"a1", "a2"}
    assert len(hub.calls) == 2  # one refresh fan-out