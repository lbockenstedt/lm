"""Central On-Prem poller instance tests.

CentralHubPoller is parameterized by ``instance`` ("central" default, or
"central_on_prem") so one class serves both cloud Central and an on-prem
Aruba Central appliance. These tests verify the instance wiring (config/sites
getter, status slot, source stamp, tracker classes) routes each instance to
its OWN slots — the "no stepping on each other" guarantee — and that the
default "central" instance is byte-identical to the original behavior.
"""
import asyncio
import types

import pytest

from simulations.central_hub_poller import (
    CentralHubPoller,
    ClientCountTracker,
    CheckHealthHistory,
    CheckPollWindow,
    CentralOnPremClientCountTracker,
    CentralOnPremCheckHealthHistory,
    CentralOnPremCheckPollWindow,
)


# ── stub hub + store: just enough for __init__ + _centralized_tenants + _status ─
class _StubStore:
    """Async stub store. Returns per-instance configs/sites + processing modes
    so _centralized_tenants can be exercised without a real SimulationsStore."""
    def __init__(self, tenant_ids, central_cfg, on_prem_cfg, modes):
        self._ids = list(tenant_ids)
        self._central_cfg = central_cfg
        self._on_prem_cfg = on_prem_cfg
        self._modes = modes

    def tenant_ids(self):
        return list(self._ids)

    async def get_processing_modes(self, tenant_id):
        return dict(self._modes)

    async def get_central_config(self, tenant_id):
        return dict(self._central_cfg)

    async def get_central_on_prem_config(self, tenant_id):
        return dict(self._on_prem_cfg)

    async def get_central_sites_config(self, tenant_id):
        return {}

    async def get_central_on_prem_sites_config(self, tenant_id):
        return {}

    @staticmethod
    def central_api_is_centralized(modes):
        return str((modes or {}).get("central_api") or "").strip().lower() != "distributed"

    @staticmethod
    def central_on_prem_api_is_centralized(modes):
        return str((modes or {}).get("central_on_prem_api") or "").strip().lower() != "distributed"


class _StubHub:
    """Minimal hub: a state object with a data_dir, a simulations_store, and the
    per-instance status dicts the poller reads/writes via the _status property."""
    def __init__(self, data_dir, store):
        self.state = types.SimpleNamespace(data_dir=data_dir)
        self.simulations_store = store
        self.central_hub_status = {}
        self.central_on_prem_hub_status = {}
        # _save_* attrs absent on purpose — the poller's save step is a no-op then.


# ── instance wiring ──────────────────────────────────────────────────────────
def test_default_instance_is_cloud_central_unchanged(tmp_path):
    """instance='central' (the default) must reproduce the original behavior:
    cloud status slot, 'central' source stamp, and the ORIGINAL tracker classes
    (NOT the on-prem subclasses). This is the safety anchor for the refactor."""
    hub = _StubHub(str(tmp_path), _StubStore([], {}, {}, {}))
    poller = CentralHubPoller(hub)  # default instance
    assert poller._inst_name == "central"
    assert poller._inst["status_attr"] == "central_hub_status"
    assert poller._inst["source"] == "central"
    assert poller._inst["config_getter"] == "get_central_config"
    assert poller._inst["sites_getter"] == "get_central_sites_config"
    assert poller._inst["mode_check"] == "central_api_is_centralized"
    # Original tracker classes, NOT the on-prem subclasses.
    assert isinstance(poller._cc, ClientCountTracker)
    assert not isinstance(poller._cc, CentralOnPremClientCountTracker)
    assert isinstance(poller._health, CheckHealthHistory)
    assert not isinstance(poller._health, CentralOnPremCheckHealthHistory)
    assert isinstance(poller._cpw, CheckPollWindow)
    assert not isinstance(poller._cpw, CentralOnPremCheckPollWindow)


def test_on_prem_instance_uses_on_prem_slots_and_trackers(tmp_path):
    """instance='central_on_prem' routes to the on-prem config/sites getter,
    on-prem status slot, 'central_on_prem' source stamp, and the on-prem tracker
    subclasses (separate shard filenames → isolated state)."""
    hub = _StubHub(str(tmp_path), _StubStore([], {}, {}, {}))
    poller = CentralHubPoller(hub, instance="central_on_prem")
    assert poller._inst_name == "central_on_prem"
    assert poller._inst["status_attr"] == "central_on_prem_hub_status"
    assert poller._inst["source"] == "central_on_prem"
    assert poller._inst["config_getter"] == "get_central_on_prem_config"
    assert poller._inst["sites_getter"] == "get_central_on_prem_sites_config"
    assert poller._inst["mode_check"] == "central_on_prem_api_is_centralized"
    assert isinstance(poller._cc, CentralOnPremClientCountTracker)
    assert isinstance(poller._health, CentralOnPremCheckHealthHistory)
    assert isinstance(poller._cpw, CentralOnPremCheckPollWindow)


def test_unknown_instance_rejected(tmp_path):
    hub = _StubHub(str(tmp_path), _StubStore([], {}, {}, {}))
    with pytest.raises(ValueError):
        CentralHubPoller(hub, instance="bogus")


# ── _centralized_tenants dispatch ────────────────────────────────────────────
def test_cloud_instance_polls_central_config_only(tmp_path):
    """A tenant with ONLY a cloud Central config (no on-prem config) is polled by
    the cloud instance and SKIPPED by the on-prem instance — the two instances
    poll independently from their own config slots."""
    store = _StubStore(["t1"], central_cfg={"cluster_url": "x"}, on_prem_cfg={}, modes={})
    hub = _StubHub(str(tmp_path), store)
    cloud = CentralHubPoller(hub)
    on_prem = CentralHubPoller(hub, instance="central_on_prem")
    cloud_tenants = asyncio.run(cloud._centralized_tenants())
    on_prem_tenants = asyncio.run(on_prem._centralized_tenants())
    assert [t for t, _ in cloud_tenants] == ["t1"]
    assert on_prem_tenants == []  # no on-prem config → not polled by on-prem instance


def test_on_prem_instance_polls_on_prem_config_only(tmp_path):
    """Reverse: a tenant with ONLY an on-prem config is polled by the on-prem
    instance and SKIPPED by the cloud instance — no cross-instance stepping."""
    store = _StubStore(["t1"], central_cfg={}, on_prem_cfg={"cluster_url": "y"}, modes={})
    hub = _StubHub(str(tmp_path), store)
    cloud = CentralHubPoller(hub)
    on_prem = CentralHubPoller(hub, instance="central_on_prem")
    assert asyncio.run(cloud._centralized_tenants()) == []
    assert [t for t, _ in asyncio.run(on_prem._centralized_tenants())] == ["t1"]


def test_distributed_mode_skips_instance(tmp_path):
    """A tenant with central_on_prem_api='distributed' is NOT polled hub-side by
    the on-prem instance (the spoke owns the creds) — mirroring cloud Central's
    central_api_is_centralized opt-out."""
    store = _StubStore(["t1"], central_cfg={}, on_prem_cfg={"cluster_url": "y"},
                       modes={"central_on_prem_api": "distributed"})
    hub = _StubHub(str(tmp_path), store)
    on_prem = CentralHubPoller(hub, instance="central_on_prem")
    assert asyncio.run(on_prem._centralized_tenants()) == []


# ── _status property writes the right slot ───────────────────────────────────
def test_status_property_isolates_per_instance(tmp_path):
    """The _status property reads/writes THIS instance's status dict — on-prem
    writes go to central_on_prem_hub_status, never central_hub_status, so the two
    dashboards never share status blocks (the core no-stepping guarantee)."""
    hub = _StubHub(str(tmp_path), _StubStore([], {}, {}, {}))
    cloud = CentralHubPoller(hub)
    on_prem = CentralHubPoller(hub, instance="central_on_prem")
    cloud._status["t1"] = {"status": {}, "fetched_at": 1}
    on_prem._status["t1"] = {"status": {}, "fetched_at": 2}
    assert hub.central_hub_status == {"t1": {"status": {}, "fetched_at": 1}}
    assert hub.central_on_prem_hub_status == {"t1": {"status": {}, "fetched_at": 2}}
    # Stale cleanup drops from the right slot only.
    on_prem._status.pop("t1", None)
    assert hub.central_on_prem_hub_status == {}
    assert hub.central_hub_status == {"t1": {"status": {}, "fetched_at": 1}}


def test_on_prem_tracker_subclasses_use_separate_shard_filenames():
    """The on-prem tracker subclasses override ONLY the shard filenames so their
    persisted state is separate from cloud Central's (no shared client-count
    baselines / health / poll-window files)."""
    assert CentralOnPremClientCountTracker._BASELINE == "central_on_prem_client_count_baseline.json"
    assert CentralOnPremClientCountTracker._SEVENDAY == "central_on_prem_client_count_7day.json"
    assert CentralOnPremClientCountTracker._SAMPLES == "central_on_prem_client_count_samples.json"
    assert CentralOnPremCheckHealthHistory._NAME == "central_on_prem_check_health_history.json"
    assert CentralOnPremCheckPollWindow._NAME == "central_on_prem_check_poll_window.json"
    # Parent classes unchanged (cloud Central keeps its filenames).
    assert ClientCountTracker._BASELINE == "client_count_baseline.json"
    assert CheckHealthHistory._NAME == "check_health_history.json"
    assert CheckPollWindow._NAME == "check_poll_window.json"