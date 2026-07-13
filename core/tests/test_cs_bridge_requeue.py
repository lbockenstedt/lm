"""CSBridgePoller relay-timeout → re-queue (retry 5 then give up).

When the hub's relay of a queued command to the agent times out (the agent is
too busy to ACCEPT within ``CS_RELAY_TIMEOUT_S`` — the symptom is a FAILED row
with message "Timed out waiting for spoke response" during a mass-delete on a
busy agent), the bridge must NOT ack the command ``failed``. It re-queues it
via ``CS_REQUEUE_COMMAND`` (the cs spoke resets status → pending + increments
``relay_attempts``), up to ``max_retries``. A genuine agent ERROR/FAILED (the
op ran and was rejected) is still acked ``failed`` immediately — retrying that
would repeat the same rejection forever.
"""
import asyncio

import gateway.cs_bridge as cs_bridge_module  # noqa: E402
from gateway.cs_bridge import CSBridgePoller


_TIMEOUT_REPLY = {"payload": {"data": {
    "status": "ERROR", "message": "Timed out waiting for spoke response"}}}


class _FakeHub:
    """Routes SPOKE_RELAY → a configurable reply; records every call so the
    test can assert re-queue vs ack-failed."""

    def __init__(self, relay_reply, agent_config, tenant_to_cs_spoke,
                 spoke_tenants):
        self._relay_reply = relay_reply
        self.calls = []
        self.state = _FakeState(agent_config, spoke_tenants)
        self._tenant_to_cs_spoke = tenant_to_cs_spoke

    def get_all_spokes_by_type(self, module_type):
        return ["host-spoke"] if module_type in ("hypervisor", "simulation") else []

    def get_client_sim_spoke(self, tenant_id=None):
        return self._tenant_to_cs_spoke.get(tenant_id)

    async def request_response(self, spoke_id, cmd_type, data, timeout=5.0):
        self.calls.append((spoke_id, cmd_type, data))
        if cmd_type == "GET_AGENTS":
            return {"payload": {"data": {"status": "SUCCESS", "agents": [
                {"agent_id": "ag-1", "hostname": "pxmx-cs-svr-04"}]}}}
        if cmd_type == "CS_POLL_AGENT_INBOX":
            return {"payload": {"data": {"status": "SUCCESS", "commands": [
                {"id": "cmd-1", "action": "delete_vm", "args": {"vmid": 90075}}]}}}
        if cmd_type == "SPOKE_RELAY":
            return self._relay_reply
        if cmd_type in ("CS_REQUEUE_COMMAND", "CS_ACK_COMMAND"):
            return {"payload": {"data": {"status": "SUCCESS", "requeued": True,
                                         "attempts": 1, "max_retries": 5}}}
        raise AssertionError(f"unexpected command {cmd_type}")


class _FakeState:
    def __init__(self, agent_config, spoke_tenants):
        self.system_state = {"agent_config": agent_config}
        self._spoke_tenants = spoke_tenants

    def get_spoke_tenant(self, spoke_id):
        return self._spoke_tenants.get(spoke_id)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def _make_poller(relay_reply):
    hub = _FakeHub(relay_reply,
                  agent_config={"ag-1": {"client_simulation": {"enabled": True}}},
                  tenant_to_cs_spoke={"default": "cs-spoke"},
                  spoke_tenants={"host-spoke": "default"})
    poller = CSBridgePoller(hub)
    poller.max_retries = 5
    return poller, hub


def test_relay_timeout_requeues_instead_of_acking_failed():
    """A relay timeout → CS_REQUEUE_COMMAND, NOT CS_ACK_COMMAND failed."""
    poller, hub = _make_poller(_TIMEOUT_REPLY)
    _run(poller._tick())
    cmd_types = [c[1] for c in hub.calls]
    assert "SPOKE_RELAY" in cmd_types
    assert "CS_REQUEUE_COMMAND" in cmd_types
    # The retry path must NOT ack failed (that would short-circuit the retry).
    ack_calls = [c for c in hub.calls if c[1] == "CS_ACK_COMMAND"]
    assert not ack_calls, "relay timeout acked failed instead of re-queuing"
    rq = next(c for c in hub.calls if c[1] == "CS_REQUEUE_COMMAND")
    assert rq[2]["max_retries"] == 5
    assert rq[2]["message"] == "Timed out waiting for spoke response"


def test_long_op_uses_long_relay_timeout():
    """delete_vm (a long op) gets relay_timeout_long, not the 16s fast window."""
    poller, hub = _make_poller(_TIMEOUT_REPLY)
    poller.relay_timeout = 16.0
    poller.relay_timeout_long = 65.0
    seen = {}

    async def _capture(spoke_id, cmd_type, data, timeout=5.0):
        if cmd_type == "SPOKE_RELAY":
            seen["timeout"] = timeout
        return _TIMEOUT_REPLY
    hub.request_response = _capture
    _run(poller._relay_one("host-spoke", "cs-spoke", "ag-1", "pxmx-cs-svr-04",
                          {"id": "cmd-x", "action": "delete_vm", "args": {}}))
    assert seen["timeout"] == 65.0


def test_fast_op_uses_fast_relay_timeout():
    """A fast op (start_vm) keeps the 16s window."""
    poller, hub = _make_poller(_TIMEOUT_REPLY)
    poller.relay_timeout = 16.0
    poller.relay_timeout_long = 65.0
    seen = {}

    async def _capture(spoke_id, cmd_type, data, timeout=5.0):
        if cmd_type == "SPOKE_RELAY":
            seen["timeout"] = timeout
        return {"payload": {"data": {"status": "SUCCESS", "message": "ok"}}}
    hub.request_response = _capture
    _run(poller._relay_one("host-spoke", "cs-spoke", "ag-1", "pxmx-cs-svr-04",
                          {"id": "cmd-y", "action": "start_vm", "args": {}}))
    assert seen["timeout"] == 16.0


def test_genuine_agent_error_acks_failed_not_requeue():
    """An agent ERROR that is NOT a relay timeout (the op ran and was rejected)
    is acked failed immediately — retrying would repeat the same rejection."""
    reply = {"payload": {"data": {"status": "ERROR",
                                   "message": "VM 90075 not found"}}}
    poller, hub = _make_poller(reply)
    _run(poller._tick())
    cmd_types = [c[1] for c in hub.calls]
    assert "CS_ACK_COMMAND" in cmd_types
    assert "CS_REQUEUE_COMMAND" not in cmd_types
    ack = next(c for c in hub.calls if c[1] == "CS_ACK_COMMAND")
    assert ack[2]["status"] == "failed"
    assert ack[2]["message"] == "VM 90075 not found"


def test_max_retries_zero_is_fail_fast():
    """max_retries<=0 preserves the old behavior: a timeout acks failed."""
    poller, hub = _make_poller(_TIMEOUT_REPLY)
    poller.max_retries = 0
    _run(poller._tick())
    cmd_types = [c[1] for c in hub.calls]
    assert "CS_ACK_COMMAND" in cmd_types
    assert "CS_REQUEUE_COMMAND" not in cmd_types
    ack = next(c for c in hub.calls if c[1] == "CS_ACK_COMMAND")
    assert ack[2]["status"] == "failed"


def test_spoke_agent_response_timeout_requeues_not_fails():
    """The spoke's send_to_agent returns ``"Agent response timeout"`` (NOT the
    hub's "Timed out waiting for spoke response" string) when a CPU-pegged
    agent can't ACK within the spoke's 60s window. This is a transient relay
    timeout, not a genuine rejection — it must requeue (retry), NOT ack failed.
    Regression for the mass-delete symptom on a saturated host (svr-02): the
    command FAILED on the first attempt with no retry even though the op often
    still ran on the agent."""
    reply = {"payload": {"data": {
        "status": "ERROR", "message": "Agent response timeout"}}}
    poller, hub = _make_poller(reply)
    _run(poller._tick())
    cmd_types = [c[1] for c in hub.calls]
    assert "SPOKE_RELAY" in cmd_types
    assert "CS_REQUEUE_COMMAND" in cmd_types
    assert "CS_ACK_COMMAND" not in cmd_types, (
        "spoke 'Agent response timeout' acked failed instead of re-queuing")
    rq = next(c for c in hub.calls if c[1] == "CS_REQUEUE_COMMAND")
    assert rq[2]["max_retries"] == 5
    assert rq[2]["message"] == "Agent response timeout"


def test_genuine_error_with_no_timeout_marker_still_fails():
    """An ERROR whose message has no timeout marker (e.g. 'no such vmid') is a
    genuine rejection — ack failed, don't retry. Guards the timeout-match
    helper against false positives."""
    reply = {"payload": {"data": {"status": "ERROR",
                                   "message": "no such vmid 90075"}}}
    poller, hub = _make_poller(reply)
    _run(poller._tick())
    cmd_types = [c[1] for c in hub.calls]
    assert "CS_ACK_COMMAND" in cmd_types
    assert "CS_REQUEUE_COMMAND" not in cmd_types
    ack = next(c for c in hub.calls if c[1] == "CS_ACK_COMMAND")
    assert ack[2]["status"] == "failed"


def test_status_snapshot_records_decision_and_counters(caplog):
    """The WebUI 'CS Bridge Status' panel reads status_snapshot(): per agent it
    shows the ACTIVE/SKIP decision + relay counters (accepted/requeued/
    gave_up/completed/failed) so an Azure-hub operator can diagnose svr-02
    (is the bridge reaching it? are commands re-queued or failing?) without SSH.
    Also asserts the requeue log line carries the agent hostname so grepping
    the agent name in WebUI Logs surfaces the outcome."""
    import logging
    poller, hub = _make_poller(_TIMEOUT_REPLY)
    with caplog.at_level(logging.INFO, logger="CSBridge"):
        _run(poller._tick())
    snap = poller.status_snapshot()
    assert snap["max_retries"] == 5
    assert snap["relay_timeout_long_s"] == 65
    # The agent ran through the relay path → it has a counter row + decision.
    rows = {r["agent_id"]: r for r in snap["agents"]}
    assert "ag-1" in rows
    row = rows["ag-1"]
    assert row["hostname"] == "pxmx-cs-svr-04"
    assert "ACTIVE" in row["decision"]
    # A relay timeout → requeued counter incremented.
    assert row["requeued"] >= 1
    assert row["last_outcome"] == "requeued"
    # The requeue INFO line names the hostname (one-grep diagnosis in WebUI Logs).
    requeue_lines = [r.getMessage() for r in caplog.records
                     if "re-queued" in r.getMessage()]
    assert requeue_lines, "no requeue INFO line emitted"
    assert any("pxmx-cs-svr-04" in ln for ln in requeue_lines), (
        "requeue log line missing the agent hostname — can't grep by agent")