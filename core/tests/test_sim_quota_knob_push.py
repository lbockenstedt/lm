"""Phase 2 — learned knobs → production: the sim_knob_overrides a tenant's clients
receive. The lab (Learning) tunes a sim's [simulation] intensity knobs and
publishes them; a production consumer (Adaptive) runs the lab's tuned config, not
the base simulation.conf defaults.

Drives ``hub._knob_overrides_for_tenant`` (a callable seam) against an in-memory
store. Verified cases:
  * a pure-CONSUMER tenant (no own lab) gets the APPROVED global learned knobs;
  * a LAB tenant's own live tuned values WIN for the keys it's actively testing
    (the approved baseline fills the keys no lab is tuning);
  * a tenant with neither lab nor consumer-on-a-knob-sim gets ``{}``.
"""
import asyncio

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


def _cons(site="MIA"):
    # Adaptive consumer: learning OFF, max>min, dns_fail (has knobs).
    return {"sim_id": "dns_fail", "alert_type": "alert",
            "alert_id": "CLIENT_DNS_FAILURE", "site": site,
            "count": 5, "min": 1, "max": 10, "enabled": True, "learning": False}


def _lab(site="DFW"):
    # Learning lab: learning ON, max>min, dns_fail (has knobs).
    return {"sim_id": "dns_fail", "alert_type": "alert",
            "alert_id": "CLIENT_DNS_FAILURE", "site": site,
            "count": 1, "min": 1, "max": 15, "enabled": True, "learning": True}


class _Store:
    """In-memory store: a tenant's sim_quotas + the knob/global state."""

    def __init__(self, csc, knob_state=None, global_lv=None):
        self._csc = csc
        self._knob = knob_state or {}
        self._glv = global_lv or {}

    async def get_central_sites_config(self, tenant_id):
        return dict(self._csc.get(tenant_id, {"sim_quotas": []}))

    async def get_knob_learn_state(self, tenant_id):
        return dict(self._knob)

    async def get_global_learned_values(self):
        return dict(self._glv)


class _Hub:
    def __init__(self):
        self.simulations_store = None


def _build(store):
    app = FastAPI()
    hub = _Hub()
    hub.simulations_store = store
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return hub


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


ALERT_KEY = "alert:CLIENT_DNS_FAILURE"


def test_pure_consumer_gets_approved_global_knobs():
    # A tenant with only a consumer (Adaptive) dns_fail quota — no own lab. The
    # approved global learned knobs flow to its clients, bumped by the default
    # inherit-learned-values floor (learned + 20%, capped at double) rather than
    # the bare approved value — production runs comfortably past the bare
    # minimum that fires, not right at the edge of it.
    store = _Store(
        {"t1": {"sim_quotas": [_cons()]}},
        global_lv={ALERT_KEY: {"op": 8, "knobs": {"dns_fail_rate": 600,
                                                  "dns_fail_duration": 300}}},
    )
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {"dns_fail_rate": 720, "dns_fail_duration": 360}


def test_consumer_override_wins_for_its_key_floor_fills_the_rest():
    # inherit_learned_knobs OFF with a partial override: the overridden key
    # uses the operator's exact value (even though it's below the computed
    # floor — an explicit override always wins over the recommendation), any
    # OTHER declared knob for the sim still falls back to the computed floor
    # (turning inherit off is a per-knob opt-out, not all-or-nothing).
    store = _Store(
        {"t1": {"sim_quotas": [{**_cons(), "inherit_learned_knobs": False,
                                "knob_overrides": {"dns_fail_rate": 50}}]}},
        global_lv={ALERT_KEY: {"op": 8, "knobs": {"dns_fail_rate": 600,
                                                  "dns_fail_duration": 300}}},
    )
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {"dns_fail_rate": 50, "dns_fail_duration": 360}


def test_consumer_with_no_approved_knobs_gets_empty():
    # Nothing approved yet → a pure consumer gets {} (clients fall back to base
    # simulation.conf). The knob-push only delivers the lab's tuned config once a
    # lab has published + an admin has approved.
    store = _Store({"t1": {"sim_quotas": [_cons()]}}, global_lv={})
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {}


def test_lab_live_values_win_for_keys_it_tunes():
    # A lab tenant: its own live tuned values WIN for the keys it's actively
    # testing (more current than the approved snapshot). Here the lab is sweeping
    # dns_fail_rate to 1200 (live) while the approved baseline was 600 — the lab
    # must run 1200 to test it, not the stale approved 600.
    lab_key = "alert:CLIENT_DNS_FAILURE:DFW"
    store = _Store(
        {"t1": {"sim_quotas": [_lab()]}},
        knob_state={lab_key: {"values": {"dns_fail_rate": 1200,
                                         "dns_fail_duration": 240}}},
        global_lv={ALERT_KEY: {"op": 8, "knobs": {"dns_fail_rate": 600,
                                                   "dns_fail_duration": 300}}},
    )
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {"dns_fail_rate": 1200, "dns_fail_duration": 240}


def test_consumer_and_lab_merge_precedence():
    # A tenant with BOTH a consumer (MIA) and a lab (DFW) for dns_fail on the
    # same spoke. The consumer loads the approved baseline (bumped by the
    # default inherit-learned-values floor, learned + 20%); the lab's live
    # values WIN UNCHANGED for the keys it's tuning (its own in-flight ratchet
    # search, not a "consumer floor" scenario). Here the lab is mid-sweep on
    # dns_fail_rate (1200) and hasn't touched dns_fail_duration this tick — the
    # approved baseline (300, bumped to 360) fills duration, the lab's 1200
    # wins as-is for rate. (In practice a lab's live state cold-starts every
    # knob, so the "fill" only shows for a key the lab hasn't recorded yet.)
    lab_key = "alert:CLIENT_DNS_FAILURE:DFW"
    store = _Store(
        {"t1": {"sim_quotas": [_cons(), _lab()]}},
        knob_state={lab_key: {"values": {"dns_fail_rate": 1200}}},
        global_lv={ALERT_KEY: {"op": 8, "knobs": {"dns_fail_rate": 600,
                                                   "dns_fail_duration": 300}}},
    )
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {"dns_fail_rate": 1200, "dns_fail_duration": 360}


def test_no_knob_quotas_returns_empty():
    # A tenant with no lab and no consumer-on-a-knob-sim gets {} (no knob delivery).
    store = _Store({"t1": {"sim_quotas": [
        {"sim_id": "ping_test", "alert_type": "alert", "alert_id": "P",
         "site": "MIA", "count": 5, "enabled": True}]}})
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {}


def test_disabled_or_fixed_quota_does_not_pull_knobs():
    # A disabled consumer, and a fixed (max==min, non-adaptive) dns_fail quota,
    # do NOT pull knobs — only enabled adaptive/learning rows on knob sims do.
    store = _Store({"t1": {"sim_quotas": [
        {**_cons(), "enabled": False},
        {**_cons(), "min": 5, "max": 5},  # fixed (max==min) → not adaptive
    ]}}, global_lv={ALERT_KEY: {"op": 8, "knobs": {"dns_fail_rate": 600}}})
    hub = _build(store)
    out = _run(hub._knob_overrides_for_tenant("t1"))
    assert out == {}