"""Regression tests for the ``/setup/pending_spokes`` stale-while-revalidate
cache (``routes/setup.py``).

The Spokes & Agents page polls /setup/pending_spokes on every load; the
handler iterates known_modules + per-spoke metadata/event reads. The SWR
cache serves instant reads from memory inside the stale window and collapses
concurrent first-loaders into a single recompute (mirroring the
``/api/pxmx/agents`` cache in ``routes/pxmx.py``). These lock in:

* a repeat read within the fresh window does NOT recompute (same object);
* a forced refresh recomputes once;
* N concurrent cold reads produce ONE recompute, not N;
* a compute failure serves the last-known payload rather than blanking;
* ``_bust_spokes_cache`` marks the cache unservable so the next read forced-
  refreshes.

The compute lives at module level (depends only on ``hub``), so these tests
exercise it directly with a stub hub — no full FastAPI app build.
"""

import asyncio
import time

from routes import setup


# ── Fakes ────────────────────────────────────────────────────────────────────

class _FakeState:
    def __init__(self, known, names=None, meta=None, tenants=None):
        self.system_state = {
            "known_modules": list(known),
            "module_names": names or {},
            "module_metadata": meta or {},
        }
        self._tenants = tenants or {}

    def get_spoke_tenant(self, sid):
        return self._tenants.get(sid)


class _FakeHub:
    """Minimal hub: counts recomputes (via get_spoke_events calls) and returns
    a canned per-spoke metadata payload."""

    def __init__(self, known=("pxmx-1", "opn-1"), names=None, meta=None,
                 tenants=None, approved=None, module_types=None):
        self.state = _FakeState(known, names, meta, tenants)
        self.approved_modules = approved or {}
        self.spoke_module_types = module_types or {}
        self._events = {}
        self.compute_count = 0

    def _primary_key(self, sid):
        return sid  # alias empty → identity (mirrors today)

    def get_spoke_events(self, sid, limit=20):
        self.compute_count += 1
        return list(self._events.get(sid, []))


def _reset_spokes_cache():
    setup._SPOKES_CACHE["data"] = None
    setup._SPOKES_CACHE["ts"] = 0.0
    setup._SPOKES_CACHE["refreshing"] = False


def _hub_with_two_spokes():
    return _FakeHub(
        known=("pxmx-1", "opn-1"),
        names={"pxmx-1": "PXMX One", "opn-1": "OPN One"},
        meta={"pxmx-1": {"hostname": "h1", "install_uuid": "guid-1", "module_type": "hypervisor"},
              "opn-1": {"hostname": "h2", "install_uuid": "guid-2", "module_type": "firewall"}},
        tenants={"pxmx-1": "tA", "opn-1": "shared"},
        approved={"pxmx-1": True, "opn-1": False},
        module_types={"pxmx-1": "hypervisor", "opn-1": "firewall"},
    )


# ── Tests ────────────────────────────────────────────────────────────────────

def test_repeat_read_within_fresh_window_recomputes_once():
    _reset_spokes_cache()
    hub = _hub_with_two_spokes()
    r1 = asyncio.run(setup._maybe_refresh_spokes(hub, force=True))
    r2 = asyncio.run(setup._maybe_refresh_spokes(hub))  # fresh → cached
    assert r2 is r1  # same cached object, no recompute
    ids = sorted(s["spoke_id"] for s in r1["spokes"])
    assert ids == ["opn-1", "pxmx-1"]
    # get_spoke_events called once per spoke per recompute → 2 for one recompute.
    assert hub.compute_count == 2


def test_concurrent_cold_reads_collapse_into_one_recompute():
    _reset_spokes_cache()
    hub = _hub_with_two_spokes()

    async def _two():
        a, b = await asyncio.gather(
            setup._maybe_refresh_spokes(hub, force=True),
            setup._maybe_refresh_spokes(hub, force=True),
        )
        return a, b

    a, b = asyncio.run(_two())
    # Two concurrent cold reads → ONE recompute (2 spoke-event reads, not 4).
    assert hub.compute_count == 2, f"expected 2, got {hub.compute_count}"
    assert a is b  # the second waiter served the result the first produced


def test_compute_failure_serves_last_known_not_blank():
    _reset_spokes_cache()
    hub = _hub_with_two_spokes()
    # Prime with a known-good payload.
    good = asyncio.run(setup._maybe_refresh_spokes(hub, force=True))
    assert good["spokes"]
    # Now make the NEXT recompute blow up (state.system_state disappears).
    hub.state.system_state = None  # .get will raise AttributeError
    # Force past the fresh window by busting the cache.
    setup._bust_spokes_cache()
    served = asyncio.run(setup._maybe_refresh_spokes(hub, force=True))
    # Stale serve of the last-known payload, not None.
    assert served is good


def test_bust_marks_cache_unservable():
    _reset_spokes_cache()
    hub = _hub_with_two_spokes()
    asyncio.run(setup._maybe_refresh_spokes(hub, force=True))
    age_before = setup._SPOKES_CACHE["ts"]
    assert age_before > 0.0
    setup._bust_spokes_cache()
    assert setup._SPOKES_CACHE["ts"] == 0.0
    # Next read forced-refreshes (recompute runs again).
    before = hub.compute_count
    asyncio.run(setup._maybe_refresh_spokes(hub, force=True))
    assert hub.compute_count > before


def test_aggregate_payload_shape():
    _reset_spokes_cache()
    hub = _hub_with_two_spokes()
    r = asyncio.run(setup._aggregate_spokes(hub))
    by = {s["spoke_id"]: s for s in r["spokes"]}
    assert by["pxmx-1"]["approved"] is True
    assert by["opn-1"]["approved"] is False
    assert by["pxmx-1"]["module_type"] == "hypervisor"
    assert by["pxmx-1"]["spoke_guid"] == "guid-1"
    assert by["pxmx-1"]["tenant_shared"] is False
    # An unassigned (None-tenant) spoke is never shared.
    assert by["opn-1"]["tenant_shared"] is False