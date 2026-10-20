"""cs full-config sync: a cs spoke that was out of contact for a long time must
come back on the hub's CURRENT config.

Covers the routes-side pieces registered on the hub:
  * ``_cs_full_config_push`` — one CS_CONFIG_UPDATE carrying every hub-owned
    key, delivered only to the requested spoke, stamped full_config+config_hash;
  * ``_cs_expected_config_hash`` — the same hash without sending;
  * ``_cs_config_sync_once`` — drift (spoke-reported cs_config_hash != hub) and
    the hourly backstop, hash-capable spokes only.
"""

import asyncio

from fastapi import FastAPI

from simulations.routes import _cs_config_hash, register_simulations_routes


class _Store:
    def __init__(self):
        self.central = {"base_url": "https://central", "client_id": "cid", "mode": "classic"}
        self.sim_conf = "[simulation]\nx = 1\n"

    async def get_hub_config(self, tenant_id):
        return {"hub_config_enabled": True,
                "hub_config": {"image1_template_id": "9000", "usb_vidpids": "[]"}}

    async def get_sim_conf_content(self, tenant_id):
        return self.sim_conf

    async def get_user_overrides_content(self, tenant_id):
        return ""

    async def get_central_config(self, tenant_id):
        return dict(self.central)

    async def get_github_config(self, tenant_id, resolve=False):
        return {}

    async def get_source_of_truth(self, tenant_id):
        return "hub"

    async def get_global_usb_vidpids(self):
        return [{"vidpid": "0bda:8812", "type": "wireless"}]

    async def get_global_usb_ignored_vidpids(self):
        return []

    async def get_global_t1_pci_vidpids(self):
        return []

    async def get_global_t3_pci_vidpids(self):
        return []

    def __getattr__(self, name):
        # Every other store getter (quota defaults, sites configs, stacking
        # knobs, ...) reads as "nothing configured".
        if name.startswith("get_"):
            async def _empty(*a, **k):
                return None
            return _empty
        raise AttributeError(name)


class _State:
    def __init__(self, bindings):
        self.bindings = bindings
        self.system_state = {}
        self.tenant_state = {"tenants": {"t1": {}}}

    def get_spoke_tenant(self, sid):
        return self.bindings.get(sid)

    def get_global_config(self):
        return {"agent_relay_timeout_long_s": 600}


class _Hub:
    def __init__(self, spokes):
        self._spokes = list(spokes)
        self.simulations_store = _Store()
        self.state = _State({s: "t1" for s in spokes})
        self.simulations_cache = {}
        self.pushed = []
        self.draining = set()

    def get_client_sim_spokes(self, tenant_id):
        return list(self._spokes)

    def is_draining(self, sid):
        return sid in self.draining

    async def _drain_aware_config_push(self, sid, cmd, payload, timeout=5.0):
        self.pushed.append((sid, cmd, payload))
        return {"queued": False}


def _build(spokes):
    hub = _Hub(spokes)
    register_simulations_routes(
        FastAPI(), hub,
        session_user_fn=lambda req: None,
        resolve_tenant_fn=lambda req: None,
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    return hub


def test_full_push_reaches_only_requested_spoke_with_all_keys_and_hash():
    hub = _build(["s1", "s2"])
    n = asyncio.run(hub._cs_full_config_push("s1", reason="test"))
    assert n == 1
    assert [p[0] for p in hub.pushed] == ["s1"]
    _sid, cmd, payload = hub.pushed[0]
    assert cmd == "CS_CONFIG_UPDATE"
    assert payload["full_config"] is True
    assert payload["config_hash"] == _cs_config_hash(payload)
    # Keys the old reconnect push never re-delivered are now included.
    assert payload["central_config"]["client_id"] == "cid"
    assert payload["sim_conf_override"].startswith("[simulation]")
    assert payload["config_source"] == "hub"
    assert payload["image1_template_id"] == "9000"
    assert payload["agent_relay_timeout_long_s"] == 600
    assert "effective_sim_quotas" in payload
    # Effective (global + tenant) USB list replaced the placeholder.
    assert "0bda:8812" in payload["usb_vidpids"]


def test_full_push_carries_resolved_processing_modes():
    # Unset modes default to centralized (hub polls) -> spoke pollers idle.
    hub = _build(["s1"])
    asyncio.run(hub._cs_full_config_push("s1"))
    assert hub.pushed[0][2]["processing_modes"] == {
        "central_api": "centralized", "central_on_prem_api": "centralized",
        "mist_api": "centralized"}

    async def _modes(tenant_id):
        return {"central_api": "distributed"}
    hub = _build(["s1"])
    hub.simulations_store.get_processing_modes = _modes
    asyncio.run(hub._cs_full_config_push("s1"))
    pm = hub.pushed[0][2]["processing_modes"]
    assert pm["central_api"] == "distributed"
    assert pm["mist_api"] == "centralized"


def test_full_push_unbound_spoke_is_noop():
    hub = _build(["s1"])
    hub.state.bindings = {}
    assert asyncio.run(hub._cs_full_config_push("s1")) == 0
    assert hub.pushed == []


def test_expected_hash_matches_what_a_full_push_sends():
    hub = _build(["s1"])
    expected = asyncio.run(hub._cs_expected_config_hash("s1"))
    asyncio.run(hub._cs_full_config_push("s1"))
    assert expected and expected == hub.pushed[0][2]["config_hash"]


def test_sync_pushes_drifted_and_overdue_spokes_only():
    hub = _build(["in-sync", "drifted", "overdue", "legacy", "draining"])
    expected = asyncio.run(hub._cs_expected_config_hash("in-sync"))
    now = 100_000.0
    hub._cs_full_push_ts = {
        "in-sync": now - 600,          # recent + matching → skip
        "drifted": now - 600,          # recent but hash differs → push
        "overdue": now - 3601,         # matching but past the 1h backstop → push
        "legacy": 0.0,                 # no cs_config_hash in telemetry → skip
        "draining": 0.0,               # mid self-update → skip
    }
    hub.simulations_cache = {
        "in-sync": {"cs_config_hash": expected},
        "drifted": {"cs_config_hash": "stale"},
        "overdue": {"cs_config_hash": expected},
        "legacy": {"clients": []},
        "draining": {"cs_config_hash": ""},
    }
    hub.draining = {"draining"}
    pushed = asyncio.run(hub._cs_config_sync_once(now=now))
    assert pushed == 2
    assert sorted(p[0] for p in hub.pushed) == ["drifted", "overdue"]
    assert all(p[2]["full_config"] for p in hub.pushed)
    assert hub._cs_full_push_ts["drifted"] == now


def test_sync_waits_grace_after_a_recent_full_push():
    hub = _build(["s1"])
    now = 100_000.0
    hub._cs_full_push_ts = {"s1": now - 30}
    hub.simulations_cache = {"s1": {"cs_config_hash": "old"}}
    assert asyncio.run(hub._cs_config_sync_once(now=now)) == 0
    assert hub.pushed == []


def test_processing_mode_patch_pushes_resolved_modes():
    from fastapi.testclient import TestClient
    hub = _Hub(["s1"])
    saved = {}

    async def _set(tid, feature, value):
        saved[feature] = value

    async def _get(tid):
        return dict(saved)
    hub.simulations_store.set_processing_mode = _set
    hub.simulations_store.get_processing_modes = _get
    app = FastAPI()
    register_simulations_routes(
        app, hub,
        session_user_fn=lambda req: {"username": "admin"},
        resolve_tenant_fn=lambda req: "t1",
        is_admin_fn=lambda u: True,
        check_tenant_access_fn=None,
        sessions=None,
        has_cs_access_fn=lambda u: True,
    )
    r = TestClient(app).patch("/sim/api/hub/tenants/t1/processing-modes",
                              json={"mist_api": "distributed"})
    assert r.status_code == 200, r.text
    payload = hub.pushed[-1][2]
    assert payload["processing_modes"]["mist_api"] == "distributed"
    assert payload["processing_modes"]["central_api"] == "centralized"
    assert "central_api" not in payload  # legacy key only for central_api changes
