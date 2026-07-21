"""``_reconcile_push_tenant`` re-pushes effective sim quotas when the cs spoke's
effective set has drifted from the hub's — the actuator behind the stale-push
diagnostic (``_compute_stale_push``).

The adaptive controller only re-pushes on state change, so a spoke that missed
a push while continuously online (and whose adaptive state is stable) stays
stale forever — WPA/Max-Assoc read 0/target with no eligibility explanation.
The reconcile pass compares the spoke's reported effective counts to the hub's
and re-pushes when they diverge. These tests pin: (1) a MISSING quota triggers
a push, (2) a count mismatch triggers a push, (3) an in-sync tenant does NOT
push, (4) a tenant with no quotas does NOT forward to the spoke at all.

The harness mirrors ``test_push_config_multi_spoke``: register the routes
against a stub hub + store, then drive ``hub._reconcile_push_tenant`` (exposed
as a test seam alongside the loop).
"""
import asyncio

from fastapi import FastAPI

from simulations.routes import register_simulations_routes


# ── quota dict helper (matches test_sim_quota_stale_push's shape) ────────────
def _q(alert_id, site, count, sim_id=None):
    return {"sim_id": sim_id or alert_id, "alert_type": "alert",
            "alert_id": alert_id, "site": site, "count": count, "enabled": True}


class _Store:
    """In-memory simulations_store: holds the tenant's central_sites_config
    (sim_quotas + ignore_global_quotas) and the adaptive/knobs/global state the
    effective-merge reads. github_config returns None (best-effort in _push_config)."""

    def __init__(self, csc_by_tenant):
        self._csc = csc_by_tenant

    async def get_central_sites_config(self, tenant_id):
        return dict(self._csc.get(tenant_id, {"sim_quotas": [],
                                              "ignore_global_quotas": True}))

    async def get_sim_quota_defaults(self):
        return []  # tenant opts out of globals → not consulted, but defined

    async def get_adaptive_state(self, tenant_id):
        return {}  # no adaptive state → count stays as configured

    async def get_global_learned_values(self):
        return {}

    async def get_github_config(self, tenant_id):
        return None


class _ReconcileHub:
    """Stub hub: one bound cs spoke, a recording drain-aware push, and a
    ``request_response`` that returns a canned CS_GET_SIM_QUOTA_STATE reply
    (the spoke's ``effective`` list). ``forwarded`` records whether the spoke
    was polled so the no-quota test can assert it was NOT."""

    def __init__(self, spoke_effective):
        self._spoke_effective = spoke_effective
        self.simulations_store = None  # set by _build
        self.simulations_cache = {}
        self.active_connections = {"cs-1"}
        self.pushed = []        # (sid, cmd, payload) per CS_CONFIG_UPDATE
        self.forwarded = []     # cmd per CS_GET_SIM_QUOTA_STATE forward
        self.state = type("State", (), {"system_state": {}})()

    def get_client_sim_spokes(self, tenant_id):
        return ["cs-1"]

    def get_client_sim_spoke(self, tenant_id):
        return "cs-1"

    async def request_response(self, sid, cmd_type, payload, timeout=10.0):
        self.forwarded.append(cmd_type)
        return {"payload": {"data": {"effective": list(self._spoke_effective),
                                     "ledger": {}, "pool": {}}}}

    async def _drain_aware_config_push(self, sid, cmd_type, payload, timeout=5.0):
        self.pushed.append((sid, cmd_type, payload))
        return {"status": "ok", "queued": False, "result": {"status": "ok"}}


def _build(spoke_effective, csc):
    app = FastAPI()
    hub = _ReconcileHub(spoke_effective)
    hub.simulations_store = _Store({"10": csc})
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


def test_reconcile_pushes_when_spoke_missing_quota():
    # Hub wants WPA@5 + dns@10; the spoke's effective set is MISSING WPA
    # entirely (the push never landed) → reconcile must re-push.
    hub = _build(
        spoke_effective=[_q("dns_fail", "MIA", 10)],
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("ssidpw_fail", "MIA", 5),
                            _q("dns_fail", "MIA", 10)]})
    pushed = _run(hub._reconcile_push_tenant("10"))
    assert pushed is True
    assert len(hub.pushed) == 1
    sid, cmd, payload = hub.pushed[0]
    assert cmd == "CS_CONFIG_UPDATE"
    assert isinstance(payload.get("effective_sim_quotas"), list)
    keys = {f"alert:{q['alert_id']}:{q['site']}"
            for q in payload["effective_sim_quotas"]}
    assert "alert:ssidpw_fail:MIA" in keys  # the missing one is re-fed


def test_reconcile_pushes_on_count_mismatch():
    # Spoke has WPA@3 but hub wants 5 → flagged (not missing), re-push.
    hub = _build(
        spoke_effective=[_q("ssidpw_fail", "MIA", 3)],
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("ssidpw_fail", "MIA", 5)]})
    pushed = _run(hub._reconcile_push_tenant("10"))
    assert pushed is True
    assert len(hub.pushed) == 1


def test_reconcile_no_push_when_in_sync():
    # Spoke's effective counts match the hub's exactly → no push, no flag.
    hub = _build(
        spoke_effective=[_q("ssidpw_fail", "MIA", 5),
                         _q("dns_fail", "MIA", 10)],
        csc={"ignore_global_quotas": True,
             "sim_quotas": [_q("ssidpw_fail", "MIA", 5),
                            _q("dns_fail", "MIA", 10)]})
    pushed = _run(hub._reconcile_push_tenant("10"))
    assert pushed is False
    assert hub.pushed == []


def test_reconcile_no_forward_when_tenant_has_no_quotas():
    # Tenant has no sim_quotas → _reconcile_push_tenant returns early WITHOUT
    # forwarding CS_GET_SIM_QUOTA_STATE to the spoke (avoids a pointless poll
    # every 45s/15m for tenants with nothing configured).
    hub = _build(
        spoke_effective=[],
        csc={"ignore_global_quotas": True, "sim_quotas": []})
    pushed = _run(hub._reconcile_push_tenant("10"))
    assert pushed is False
    assert hub.pushed == []
    assert hub.forwarded == []  # the spoke was NOT polled