"""Critical path — NetBox staleness sweep (cluster-wide age-out of sync-owned
objects).

``test_staleness_sweep.py`` locks in: the config key + push command are fixed,
the interval + stale/delete-day thresholds clamp, the sweep invokes
``NETBOX_STALENESS_SWEEP`` on the IPAM spoke with the configured thresholds +
records the cluster-wide status, the [sync-error] marker fires on spoke errors,
the IPAM-offline path records an error without raising, and the disabled loop is
a no-op. Mirrors ``test_realtime_nac_sync.py`` (canned-relay hub stand-in).
"""

import asyncio
import logging

import pytest

import staleness_sweep as ss
from staleness_sweep import StalenessSweepMixin
from _fakes import FakeState


# ── config helpers ───────────────────────────────────────────────────────────

def test_cfg_key_and_push_command_are_fixed():
    assert StalenessSweepMixin._STALENESS_CFG_KEY == "staleness_sweep"
    assert StalenessSweepMixin._STALENESS_PUSH_COMMAND == "NETBOX_STALENESS_SWEEP"


def test_interval_clamps_to_60_floor():
    m = StalenessSweepMixin()
    m.state = FakeState(system_state={"global_config":
        {"staleness_sweep": {"interval_seconds": 10}}})
    assert m._staleness_interval() == 60.0   # can't hot-loop the hub
    m.state = FakeState(system_state={"global_config": {}})
    assert m._staleness_interval() == 3600.0  # default hourly


def test_thresholds_clamp_to_min_1_and_default_7_30():
    m = StalenessSweepMixin()
    m.state = FakeState(system_state={"global_config":
        {"staleness_sweep": {"stale_days": 0, "delete_days": -5}}})
    t = m._staleness_thresholds()
    assert t == {"stale_days": 1, "delete_days": 1}   # clamped to >= 1
    m.state = FakeState(system_state={"global_config": {}})
    assert m._staleness_thresholds() == {"stale_days": 7, "delete_days": 30}  # defaults


# ── canned-relay hub (async) ─────────────────────────────────────────────────

class _FakeSimulationsStore:
    def __init__(self):
        self.recorded = None

    async def set_staleness_sweep_status(self, status):
        self.recorded = status

    async def get_staleness_sweep_status(self):
        return dict(self.recorded or {})


class _SweepHub(StalenessSweepMixin):
    """Minimal hub stand-in: canned request_response + IPAM spoke routing."""

    def __init__(self, responses=None, global_config=None, ipam_spoke="netbox-1"):
        self.state = FakeState(
            system_state={"global_config": global_config or {}})
        self.simulations_store = _FakeSimulationsStore()
        self._responses = responses or {}
        self._ipam = ipam_spoke
        self.request_log = []

    def get_spoke_by_type(self, module_type):
        if module_type == "ipam":
            return self._ipam
        return None

    async def request_response(self, spoke_id, command, payload, timeout=30.0):
        self.request_log.append((spoke_id, command, payload))
        return self._responses[(spoke_id, command)]


def _sweep_ok(scanned=12, decommissioned=2, deleted=1, ip_freed=3, errors=0):
    return {"payload": {"data": {"status": "SUCCESS", "scanned": scanned,
        "decommissioned": decommissioned, "deleted": deleted,
        "ip_freed": ip_freed, "errors": errors, "message": "sweep complete",
        "per_tenant": {"lrb": {"decommissioned": 1, "deleted": 0, "errors": 0}}}}}


def _sweep_err():
    return {"payload": {"data": {"status": "ERROR", "scanned": 0,
        "decommissioned": 0, "deleted": 0, "ip_freed": 0, "errors": 5,
        "message": "NetBox 500", "per_tenant": {}}}}


# ── run_staleness_sweep_all ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sweep_invokes_command_with_thresholds_and_records_status():
    h = _SweepHub(global_config={"staleness_sweep": {"stale_days": 9,
                                                     "delete_days": 45}},
                  responses={("netbox-1", "NETBOX_STALENESS_SWEEP"): _sweep_ok()})
    res = await h.run_staleness_sweep_all()

    assert res["status"] == "success"
    assert res["scanned"] == 12
    assert res["decommissioned"] == 2
    assert res["deleted"] == 1
    assert res["ip_freed"] == 3
    # The spoke received the configured thresholds.
    sid, cmd, payload = h.request_log[0]
    assert sid == "netbox-1"
    assert cmd == "NETBOX_STALENESS_SWEEP"
    assert payload == {"stale_days": 9, "delete_days": 45}
    # Cluster-wide status persisted to the store.
    assert h.simulations_store.recorded["status"] == "success"
    assert h.simulations_store.recorded["deleted"] == 1


@pytest.mark.asyncio
async def test_sweep_uses_default_thresholds_when_unset():
    h = _SweepHub(responses={("netbox-1", "NETBOX_STALENESS_SWEEP"): _sweep_ok()})
    await h.run_staleness_sweep_all()
    _, _, payload = h.request_log[0]
    assert payload == {"stale_days": 7, "delete_days": 30}   # defaults


@pytest.mark.asyncio
async def test_sweep_error_when_ipam_offline_records_status_without_raising():
    h = _SweepHub(ipam_spoke=None)   # no IPAM spoke
    res = await h.run_staleness_sweep_all()
    assert res["status"] == "error"
    assert "not connected" in res["message"]
    assert h.simulations_store.recorded["status"] == "error"
    h.request_log == []   # no spoke call attempted


@pytest.mark.asyncio
async def test_sweep_with_errors_emits_sync_error_marker_with_message(caplog):
    h = _SweepHub(responses={("netbox-1", "NETBOX_STALENESS_SWEEP"): _sweep_err()})
    caplog.set_level(logging.WARNING, logger="Hub")
    res = await h.run_staleness_sweep_all()
    assert res["status"] == "error"          # spoke returned ERROR
    assert res["errors"] == 5
    assert any("[sync-error]" in r.message and "NetBox 500" in r.message
               for r in caplog.records)


@pytest.mark.asyncio
async def test_sweep_request_exception_records_error_without_raising():
    # The spoke request raises (e.g. timeout) → status error, no unhandled exc.
    class _BoomHub(_SweepHub):
        async def request_response(self, spoke_id, command, payload, timeout=30.0):
            raise asyncio.TimeoutError("spoke timeout")
    h = _BoomHub(responses={("netbox-1", "NETBOX_STALENESS_SWEEP"): _sweep_ok()})
    res = await h.run_staleness_sweep_all()
    assert res["status"] == "error"
    assert "spoke timeout" in res["message"]


# ── loop ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_loop_disabled_does_not_sweep(monkeypatch):
    # Disabled → the loop must NOT call run_staleness_sweep_all. Breaks after the
    # second sleep so it doesn't run forever.
    h = _SweepHub(global_config={"staleness_sweep": {"enabled": False}})

    async def _boom():
        raise AssertionError("run_staleness_sweep_all must not run when disabled")
    h.run_staleness_sweep_all = _boom

    iters = {"n": 0}

    async def fake_sleep(t):
        iters["n"] += 1
        if iters["n"] >= 2:
            raise asyncio.CancelledError()
    monkeypatch.setattr(ss.asyncio, "sleep", fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        await h.run_staleness_sweep_loop()