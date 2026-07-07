"""Agent-result → debounced per-tenant VM-cache refresh.

When an agent reports a VM-mutating CS_COMMAND_RESULT (delete_vm etc.) up
AGENT_RELAY_UP, the hub drops + re-fetches that tenant's cached pxmx_vms +
netbox_vms so the Hypervisors view doesn't stay stale up to the 300s TTL tick.
The refresh is coalesced to ≤1 / _VM_REFRESH_MIN_INTERVAL (5s) with a trailing
refresh after a burst — a 100-delete storm must NOT fire 100 refreshes. These
tests bind LabManagerHub's real methods to a fake hub and assert the coalescing.
"""
import asyncio
import time

import pytest

import main
from main import LabManagerHub


class _FakeHub:
    """Just enough state for _schedule_vm_cache_refresh / _run_vm_cache_refresh."""
    def __init__(self):
        self._vm_refresh_last = {}
        self._vm_refresh_pending = {}
        self._vm_refresh_inflight = set()
        # The real methods read these as self.<name> (class attrs on
        # LabManagerHub); mirror them on the instance so the bound methods work
        # without touching the real class.
        self._VM_MUTATING_ACTIONS = LabManagerHub._VM_MUTATING_ACTIONS
        self._VM_REFRESH_MIN_INTERVAL = 0.0  # interval-agnostic; tests assert structure


@pytest.fixture
def patched_fetch(monkeypatch):
    """Replace api._fetch_module + _invalidate_tenant_module with counters that
    record each (tenant, key) refresh. A short yield lets the loop advance so the
    debounce's asyncio.sleep/wait behaves deterministically without real 5s waits."""
    calls = {"invalidate": [], "fetch": []}

    async def _fake_fetch(hub, tenant_id, key, fw_id=None):
        calls["fetch"].append((tenant_id, key))
        await asyncio.sleep(0)  # yield
        return True

    def _fake_invalidate(tenant_id, key):
        calls["invalidate"].append((tenant_id, key))

    monkeypatch.setattr(main, "_fetch_module", _fake_fetch)
    monkeypatch.setattr(main, "_invalidate_tenant_module", _fake_invalidate)
    return calls


def _bind(hub):
    """Bind the real LabManagerHub debounce methods onto the fake hub."""
    hub._schedule_vm_cache_refresh = LabManagerHub._schedule_vm_cache_refresh.__get__(hub)
    hub._run_vm_cache_refresh = LabManagerHub._run_vm_cache_refresh.__get__(hub)
    return hub


@pytest.mark.asyncio
async def test_single_mutation_refreshes_both_modules_once(patched_fetch):
    hub = _bind(_FakeHub())
    hub._schedule_vm_cache_refresh("tenant-A")
    await asyncio.sleep(0.05)  # let the task run
    assert ("tenant-A", "pxmx_vms") in patched_fetch["fetch"]
    assert ("tenant-A", "netbox_vms") in patched_fetch["fetch"]
    assert ("tenant-A", "pxmx_vms") in patched_fetch["invalidate"]


@pytest.mark.asyncio
async def test_burst_coalesces_into_one_leading_plus_one_trailing(patched_fetch):
    """A 50-delete storm must collapse to a leading refresh + one trailing, not 50."""
    hub = _bind(_FakeHub())
    for _ in range(50):
        hub._schedule_vm_cache_refresh("tenant-A")
    # While the leading refresh is inflight, all 49 later calls just mark
    # pending (one trailing refresh) — they must NOT spawn 49 tasks.
    await asyncio.sleep(0.05)
    # Each refresh round invalidates+fetches pxmx_vms + netbox_vms (4 calls).
    # Leading (1 round) + trailing (1 round) = 8 calls; 50 rounds would be 200.
    n = len(patched_fetch["fetch"])
    assert n <= 8, f"expected ≤8 fetches (leading+trailing), got {n}"
    assert n >= 4, f"expected at least the leading round (4 fetches), got {n}"


@pytest.mark.asyncio
async def test_empty_tenant_id_is_a_noop(patched_fetch):
    hub = _bind(_FakeHub())
    hub._schedule_vm_cache_refresh("")
    await asyncio.sleep(0.02)
    assert patched_fetch["fetch"] == []
    assert patched_fetch["invalidate"] == []