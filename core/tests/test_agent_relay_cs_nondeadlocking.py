"""Regression: the hub's agent→cs-spoke CS_* relay must NOT block the spoke
receive loop awaiting the cs spoke's ``COMMAND_RESULT`` reply.

``_handle_agent_relay_up`` forwards a relayed ``CS_*`` agent event to the
tenant's cs spoke via ``_relay_cs_event`` → ``request_response`` (up to 30s).
A cs spoke that ALSO hosts cs-dialed pxmx agents (``LM_CS_AGENT_LISTENER=1``,
the ``install_cs.sh`` default) relays its OWN agent's ``CS_*`` events up that
SAME spoke's hub-side receive loop. ``await``-ing the relay inline blocks the
loop up to 30s waiting for the cs spoke's reply — but the very loop that must
READ that reply (and populate ``response_cache``) is the one blocked waiting
for it → a self-deadlock that surfaces as the steady ``Request Timeout:
[CS_INGEST_TELEMETRY] from <cs-spoke> after 30.0s`` at the agent telemetry
cadence (~60-67s).

Fix: ``_handle_agent_relay_up`` fires the relay as a detached
``asyncio.create_task`` so the receive loop keeps draining + can read the
reply. ``_relay_cs_event`` is split into an outer never-raises wrapper +
``_relay_cs_event_inner`` so the detached task can't leak an unhandled
exception.

These tests bind the real ``_handle_agent_relay_up`` / ``_relay_cs_event`` /
``_relay_cs_event_inner`` onto a fake hub whose ``request_response`` blocks
on a controllable event (simulating a cs spoke that never replies — the
self-deadlock case) and assert the receive loop returns immediately.
"""
import asyncio

import pytest

import main
from main import LabManagerHub


# ── fakes ──────────────────────────────────────────────────────────────────

class _FakeState:
    def __init__(self):
        self.system_state = {"agent_config": {}, "module_metadata": {}}

    def get_spoke_tenant(self, spoke_id):
        return "tenant-A"


class _FakeHub:
    """Minimal hub: real relay methods bound on, ``request_response`` blocks
    on ``relay_block`` (simulating a cs spoke that never replies — exactly the
    self-deadlock shape where the loop that would read the reply is blocked)."""

    def __init__(self):
        self.state = _FakeState()
        self.agent_info = {}
        self.approved_modules = {"cs-svr-04-spoke": True}
        self._CS_INGEST_MAP = LabManagerHub._CS_INGEST_MAP
        self._VM_MUTATING_ACTIONS = LabManagerHub._VM_MUTATING_ACTIONS
        self._VM_REFRESH_MIN_INTERVAL = 0.0
        self._vm_refresh_last = {}
        self._vm_refresh_pending = {}
        self._vm_refresh_inflight = set()
        self.relay_calls = []          # request_response invocations
        self.relay_block = asyncio.Event()
        self.relay_started = asyncio.Event()
        self.vm_refresh_calls = []

    # The slow cs-spoke round-trip the old code awaited inline.
    async def request_response(self, spoke_id, cmd, data, timeout=5.0):
        self.relay_calls.append((spoke_id, cmd, timeout))
        self.relay_started.set()
        # Block until the test releases — simulates the cs spoke not replying
        # within 30s (the self-deadlock). Capped so a buggy test fails fast
        # instead of hanging the suite.
        await asyncio.wait_for(self.relay_block.wait(), timeout=5.0)
        return {"status": "SUCCESS"}

    def get_client_sim_spoke(self, tenant_id=None):
        return "cs-svr-04-spoke"  # the tenant's cs spoke (also agent-hosting)

    def _reconcile_spoke_identity(self, *a, **kw):
        pass  # noop — identity reconciliation isn't under test

    def _schedule_vm_cache_refresh(self, tenant_id):
        self.vm_refresh_calls.append(tenant_id)

    # B1/B2 guid-primary seams: aliases empty → identity.
    def _primary_key(self, spoke_id):
        return spoke_id

    def _agent_primary_key(self, agent_id):
        return agent_id

    def _agent_relay_name(self, agent_id):
        return agent_id


def _bind(hub):
    """Bind the real LabManagerHub relay methods onto the fake hub."""
    hub._handle_agent_relay_up = LabManagerHub._handle_agent_relay_up.__get__(hub)
    hub._inherit_agent_tenant = LabManagerHub._inherit_agent_tenant.__get__(hub)
    hub._relay_cs_event = LabManagerHub._relay_cs_event.__get__(hub)
    hub._relay_cs_event_inner = LabManagerHub._relay_cs_event_inner.__get__(hub)
    return hub


def _agent_relay_up_payload(orig_type, agent_id="agent-1", hostname="host-1",
                            data=None):
    """Build an AGENT_RELAY_UP frame wrapping a CS_* agent event."""
    return {
        "type": "AGENT_RELAY_UP",
        "data": {
            "agent_id": agent_id,
            "hostname": hostname,
            "install_uuid": "uuid-1",
            "original_payload": {
                "payload": {"type": orig_type, "data": data or {"hostname": hostname}},
            },
        },
    }


# ── tests ──────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cs_relay_does_not_block_receive_loop():
    """The fix: ``_handle_agent_relay_up`` must return immediately even when the
    cs spoke's reply never comes (the self-deadlock shape). Before the fix it
    ``await``ed ``request_response`` (blocking on ``relay_block``) and the
    call would hang until the test released the event — here capped by a 1s
    timeout so the regression fails fast."""
    hub = _bind(_FakeHub())
    payload = _agent_relay_up_payload("CS_TELEMETRY")

    # Must complete well under the 30s request_response window — i.e. it did
    # NOT await the (still-blocked) cs-spoke round-trip.
    await asyncio.wait_for(
        hub._handle_agent_relay_up("pxmx-spoke-1", {}, payload),
        timeout=1.0,
    )
    # The relay was dispatched as a background task (request_response was
    # entered) but the receive loop already returned.
    assert hub.relay_started.is_set()
    assert len(hub.relay_calls) == 1
    assert hub.relay_calls[0][0] == "cs-svr-04-spoke"
    assert hub.relay_calls[0][1] == "CS_INGEST_TELEMETRY"

    # Release the blocked round-trip so the detached task completes cleanly
    # (no leaked "Task was destroyed but it is pending" warning).
    hub.relay_block.set()
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_back_to_back_cs_events_do_not_serialize():
    """Two CS_* frames must both dispatch their relay without the second
    waiting on the first's 30s round-trip. Before the fix, frame 2 sat behind
    frame 1's inline ``await request_response`` — the receive-loop stall that
    starved heartbeats + CS_COMMAND_RESULT acks and produced the steady ~67s
    timeout cadence."""
    hub = _bind(_FakeHub())
    payload1 = _agent_relay_up_payload("CS_TELEMETRY", agent_id="agent-1")
    payload2 = _agent_relay_up_payload("CS_LOG", agent_id="agent-2")

    await asyncio.wait_for(
        hub._handle_agent_relay_up("pxmx-spoke-1", {}, payload1), timeout=1.0)
    await asyncio.wait_for(
        hub._handle_agent_relay_up("pxmx-spoke-1", {}, payload2), timeout=1.0)

    # Both relays dispatched (two in-flight request_response calls) even though
    # NEITHER cs-spoke reply has arrived (relay_block still unset).
    assert hub.relay_started.is_set()
    assert len(hub.relay_calls) == 2
    types = [c[1] for c in hub.relay_calls]
    assert "CS_INGEST_TELEMETRY" in types
    assert "CS_INGEST_LOG" in types

    hub.relay_block.set()
    await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_relay_task_never_raises_on_dispatch_failure():
    """The detached ``_relay_cs_event`` wrapper must swallow any exception so a
    background relay task can't surface as an unhandled "Task exception was
    never retrieved". Force ``_relay_cs_event_inner`` to raise by making
    ``get_client_sim_spoke`` blow up; the wrapper logs + returns cleanly and
    ``_handle_agent_relay_up`` still returns True immediately."""
    hub = _bind(_FakeHub())

    def boom(*a, **kw):
        raise RuntimeError("cs spoke lookup exploded")

    hub.get_client_sim_spoke = boom
    payload = _agent_relay_up_payload("CS_TELEMETRY")

    await asyncio.wait_for(
        hub._handle_agent_relay_up("pxmx-spoke-1", {}, payload), timeout=1.0)
    # Give the detached wrapper a moment to run + swallow the exception.
    await asyncio.sleep(0.05)
    # No request_response was ever entered (lookup raised first).
    assert hub.relay_calls == []


@pytest.mark.asyncio
async def test_vm_mutating_command_result_still_triggers_refresh():
    """The fire-and-forget change must not drop the VM-cache refresh side
    effect: a CS_COMMAND_RESULT for a VM-mutating action still schedules the
    debounced refresh (it runs inside the detached relay task before the
    cs-spoke dispatch)."""
    hub = _bind(_FakeHub())
    payload = _agent_relay_up_payload(
        "CS_COMMAND_RESULT", agent_id="agent-1",
        data={"hostname": "host-1", "action": "delete_vm", "status": "completed"})

    await asyncio.wait_for(
        hub._handle_agent_relay_up("pxmx-spoke-1", {}, payload), timeout=1.0)
    await asyncio.sleep(0.05)  # let the detached task reach the refresh call
    assert "tenant-A" in hub.vm_refresh_calls

    hub.relay_block.set()
    await asyncio.sleep(0.05)