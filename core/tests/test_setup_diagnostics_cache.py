"""Regression tests for the ``/setup/diagnostics`` stale-while-revalidate
cache (``routes/setup_admin.py``).

The Diagnostics card polls /setup/diagnostics on every load/tick; the handler
gathers system metrics + local version + per-spoke events/heartbeat/recovery/
version. The SWR cache serves instant reads from memory inside the stale
window and collapses concurrent first-loaders into a single recompute
(mirroring the ``/api/pxmx/agents`` cache in ``routes/pxmx.py``). These lock
in:

* a repeat read within the fresh window does NOT recompute (same object);
* N concurrent cold reads produce ONE recompute, not N;
* a compute failure serves the last-known payload rather than blanking;
* ``_bust_diag_cache`` marks the cache unservable so the next read forced-
  refreshes;
* the leaked relay-agent self-heal runs on a fresh recompute (cleaning a
  leaked agent id out of known_modules).

The compute lives at module level (depends only on ``hub``), so these tests
exercise it directly with a stub hub — no full FastAPI app build.
"""

import asyncio
import time

from routes import setup_admin


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
    def __init__(self, known):
        self.system_state = {
            "known_modules": list(known),
            "module_names": {},
            "module_metadata": {sid: {"module_type": "agent"} for sid in known},
            "agent_config": {},
        }

    def get_module_name(self, sid):
        return self.system_state.get("module_names", {}).get(sid, sid)

    def get_spoke_tenant(self, sid):
        return None

    def save_state(self):
        pass


class _FakeHub:
    """Minimal hub: counts recomputes via get_system_metrics and returns just
    enough per-spoke data to exercise the aggregate without crashing."""

    def __init__(self, known=("s1",)):
        self.state = _FakeState(known)
        self.known_modules = list(known)
        self.approved_modules = {}
        self.heartbeat = _FakeHeartbeat()
        self.active_connections = {}
        self.spoke_telemetry = {}
        self.spoke_recovery = {}
        self.spoke_versions = {}
        self.spoke_module_types = {}
        self.simulations_cache = {}
        self._spoke_alerts = {}
        self.metrics_calls = 0

    def _primary_key(self, sid):
        return sid

    async def get_system_metrics(self):
        self.metrics_calls += 1
        return {}

    async def get_local_version(self):
        return ".1"

    def get_spoke_events(self, sid, limit=50):
        return []

    def get_spoke_log_events(self, sid, limit=30):
        return []

    def is_spoke_in_contact(self, sid):
        return False

    def latest_version_for_module(self, mt):
        return None


def _reset_diag_cache():
    setup_admin._DIAG_CACHE["data"] = None
    setup_admin._DIAG_CACHE["ts"] = 0.0
    setup_admin._DIAG_CACHE["refreshing"] = False


# ── Tests ────────────────────────────────────────────────────────────────────

def test_repeat_read_within_fresh_window_recomputes_once():
    _reset_diag_cache()
    hub = _FakeHub()
    r1 = asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))
    r2 = asyncio.run(setup_admin._maybe_refresh_diagnostics(hub))  # fresh → cached
    assert r2 is r1  # same cached object, no recompute
    assert hub.metrics_calls == 1


def test_concurrent_cold_reads_collapse_into_one_recompute():
    _reset_diag_cache()
    hub = _FakeHub()

    async def _two():
        a, b = await asyncio.gather(
            setup_admin._maybe_refresh_diagnostics(hub, force=True),
            setup_admin._maybe_refresh_diagnostics(hub, force=True),
        )
        return a, b

    a, b = asyncio.run(_two())
    assert hub.metrics_calls == 1, f"expected 1 recompute, got {hub.metrics_calls}"
    assert a is b


def test_compute_failure_serves_last_known_not_blank():
    _reset_diag_cache()
    hub = _FakeHub()
    good = asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))
    assert good["spokes"] is not None
    # Break the next recompute.
    hub.get_system_metrics = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    setup_admin._bust_diag_cache()
    served = asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))
    assert served is good  # stale serve of last-known, not None


def test_bust_marks_cache_unservable():
    _reset_diag_cache()
    hub = _FakeHub()
    asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))
    assert setup_admin._DIAG_CACHE["ts"] > 0.0
    setup_admin._bust_diag_cache()
    assert setup_admin._DIAG_CACHE["ts"] == 0.0
    before = hub.metrics_calls
    asyncio.run(setup_admin._maybe_refresh_diagnostics(hub, force=True))
    assert hub.metrics_calls > before


def test_self_heal_removes_leaked_relay_agent_id():
    _reset_diag_cache()
    hub = _FakeHub(known=["s1", "leaked-agent"])
    # Make "leaked-agent" look like a relayed node agent: it has a composite
    # heartbeat key and an agent_config entry, so the diag self-heal should
    # evict it from known_modules/approved_modules.
    hub.heartbeat.last_seen["s1:leaked-agent"] = time.time() - 5
    hub.state.system_state["agent_config"]["leaked-agent"] = {}
    hub.approved_modules["leaked-agent"] = True
    r = asyncio.run(setup_admin._aggregate_diagnostics(hub))
    # The leaked id was removed from known_modules + approved_modules.
    assert "leaked-agent" not in hub.state.system_state["known_modules"]
    assert "leaked-agent" not in hub.approved_modules
    # And it does not appear as a spoke row in the payload.
    assert [s["spoke_id"] for s in r["spokes"]] == ["s1"]