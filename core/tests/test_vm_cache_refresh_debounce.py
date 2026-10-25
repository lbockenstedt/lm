"""Agent-result → debounced per-tenant VM-cache refresh.

When an agent reports a VM-mutating CS_COMMAND_RESULT (delete_vm etc.) up
AGENT_RELAY_UP, the hub refreshes that tenant's cached pxmx_vms entries (and
the admin all-tenant view) via the hub data cache's ``cache_refresh`` so the
Hypervisors view doesn't stay stale until the next refresher tick. The refresh
is coalesced to ≤1 / _VM_REFRESH_MIN_INTERVAL (5s) with a trailing refresh
after a burst — a 100-delete storm must NOT fire 100 refreshes. These tests
bind LabManagerHub's real methods to a fake hub and assert the coalescing.
"""
import asyncio

import pytest

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
        self.refresh_calls = []

    def cache_refresh(self, ns, key_prefixes=("",), exact=False):
        self.refresh_calls.append((ns, tuple(key_prefixes)))
        return 1


def _bind(hub):
    """Bind the real LabManagerHub debounce methods onto the fake hub."""
    hub._schedule_vm_cache_refresh = LabManagerHub._schedule_vm_cache_refresh.__get__(hub)
    hub._run_vm_cache_refresh = LabManagerHub._run_vm_cache_refresh.__get__(hub)
    return hub


_EXPECTED_A = ("pxmx_vms", ("tenant-A|", "_all_|"))


@pytest.mark.asyncio
async def test_single_mutation_refreshes_tenant_and_admin_views_once():
    hub = _bind(_FakeHub())
    hub._schedule_vm_cache_refresh("tenant-A")
    await asyncio.sleep(0.05)  # let the task run
    assert hub.refresh_calls == [_EXPECTED_A]
    assert hub._vm_refresh_inflight == set()


@pytest.mark.asyncio
async def test_burst_coalesces_into_one_leading_plus_one_trailing():
    """A 50-delete storm must collapse to a leading refresh + one trailing, not 50."""
    hub = _bind(_FakeHub())
    for _ in range(50):
        hub._schedule_vm_cache_refresh("tenant-A")
    # While the leading refresh is inflight, all 49 later calls just mark
    # pending (one trailing refresh) — they must NOT spawn 49 tasks.
    await asyncio.sleep(0.05)
    n = len(hub.refresh_calls)
    assert 1 <= n <= 2, f"expected leading(+trailing) refreshes only, got {n}"
    assert all(c == _EXPECTED_A for c in hub.refresh_calls)


@pytest.mark.asyncio
async def test_refresh_failure_does_not_break_loop_or_leak_inflight():
    hub = _bind(_FakeHub())

    def _boom(ns, key_prefixes=("",), exact=False):
        hub.refresh_calls.append((ns, tuple(key_prefixes)))
        raise RuntimeError("boom")

    hub.cache_refresh = _boom
    hub._schedule_vm_cache_refresh("tenant-A")
    await asyncio.sleep(0.05)
    assert hub.refresh_calls == [_EXPECTED_A]
    assert "tenant-A" not in hub._vm_refresh_inflight


@pytest.mark.asyncio
async def test_empty_tenant_id_is_a_noop():
    hub = _bind(_FakeHub())
    hub._schedule_vm_cache_refresh("")
    await asyncio.sleep(0.02)
    assert hub.refresh_calls == []
