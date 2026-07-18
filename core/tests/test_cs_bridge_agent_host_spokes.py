"""CSBridgePoller._tick previously only ever asked
``hub.get_spoke_by_type("hypervisor")`` for connected agents and returned
immediately if that was None — so a cs-hosted agent (the split-topology case,
where a Proxmox agent dials a cs spoke's own ``/ws/agent`` listener directly,
with no separate pxmx spoke connected at all) never had its queued VM
commands (start/stop/delete/...) relayed. They just sat in the cs spoke's
local queue until the 15-minute expiry — exactly matching "I did see the
messages in the queue a bit ago but now they are gone."

Fixed by resolving agents from every agent-hosting spoke type (hypervisor +
simulation), mirroring get_spoke_for_agent's fallback_hypervisor=False
contract. These tests exercise _tick against a fake hub with only a
"simulation" (cs) spoke connected — no hypervisor spoke at all — and confirm
a queued command still gets relayed and acked.
"""
import asyncio

import gateway.cs_bridge as cs_bridge_module  # noqa: E402  (core/src on sys.path via conftest)
from gateway.cs_bridge import CSBridgePoller


class _FakeHub:
    def __init__(self, spokes_by_type, agent_config=None, spoke_tenants=None,
                 tenant_to_cs_spoke=None):
        self._spokes_by_type = spokes_by_type
        self.calls = []
        self.state = _FakeState(agent_config or {}, spoke_tenants or {})
        self._tenant_to_cs_spoke = tenant_to_cs_spoke or {}

    def get_all_spokes_by_type(self, module_type):
        return list(self._spokes_by_type.get(module_type, []))

    def get_client_sim_spoke(self, tenant_id=None):
        return self._tenant_to_cs_spoke.get(tenant_id)

    async def request_response(self, spoke_id, cmd_type, data, timeout=5.0):
        self.calls.append((spoke_id, cmd_type, data))
        if cmd_type == "GET_AGENTS":
            return {"payload": {"data": {
                "status": "SUCCESS",
                "agents": [{"agent_id": "pxmx-cs-svr-02-agent", "hostname": "cs-svr-02"}],
            }}}
        if cmd_type == "CS_POLL_AGENT_INBOX":
            return {"payload": {"data": {
                "status": "SUCCESS",
                "commands": [{"id": "cmd-1", "action": "delete_vm", "args": {"vmid": 90001}}],
            }}}
        if cmd_type == "SPOKE_RELAY":
            return {"payload": {"data": {"status": "SUCCESS", "message": "deleted"}}}
        if cmd_type == "CS_ACK_COMMAND":
            return {"payload": {"data": {"status": "SUCCESS"}}}
        raise AssertionError(f"unexpected command {cmd_type}")


class _FakeState:
    def __init__(self, agent_config, spoke_tenants):
        self.system_state = {"agent_config": agent_config}
        self._spoke_tenants = spoke_tenants

    def get_spoke_tenant(self, spoke_id):
        return self._spoke_tenants.get(spoke_id)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_tick_relays_commands_for_cs_hosted_agent_with_no_hypervisor_spoke():
    hub = _FakeHub(
        spokes_by_type={"simulation": ["cs-svr-02-spoke"]},  # no "hypervisor" at all
        agent_config={"pxmx-cs-svr-02-agent": {"client_simulation": {"enabled": True}}},
        spoke_tenants={"cs-svr-02-spoke": "default"},
        tenant_to_cs_spoke={"default": "cs-svr-02-spoke"},
    )
    poller = CSBridgePoller(hub)

    _run(poller._tick())

    cmd_types = [c[1] for c in hub.calls]
    assert "GET_AGENTS" in cmd_types
    assert "CS_POLL_AGENT_INBOX" in cmd_types
    relay_calls = [c for c in hub.calls if c[1] == "SPOKE_RELAY"]
    assert relay_calls, "queued delete_vm command was never relayed to the agent"
    spoke_id, _, data = relay_calls[0]
    assert spoke_id == "cs-svr-02-spoke"  # relayed via the spoke that actually owns the agent
    assert data["target_agent_id"] == "pxmx-cs-svr-02-agent"
    assert data["data"]["action"] == "delete_vm"
    ack_calls = [c for c in hub.calls if c[1] == "CS_ACK_COMMAND"]
    assert ack_calls and ack_calls[0][2]["status"] == "completed"


def test_tick_is_a_noop_with_no_agent_hosting_spokes_connected():
    hub = _FakeHub(spokes_by_type={})
    poller = CSBridgePoller(hub)

    _run(poller._tick())

    assert hub.calls == []


def test_tick_dedupes_a_spoke_advertised_under_both_types():
    # Defensive: a spoke_id should never appear in both lists in practice, but
    # _tick must not double-poll it if it somehow does.
    hub = _FakeHub(
        spokes_by_type={
            "hypervisor": ["cs-svr-02-spoke"],
            "simulation": ["cs-svr-02-spoke"],
        },
        agent_config={},
        spoke_tenants={},
    )
    poller = CSBridgePoller(hub)

    _run(poller._tick())

    get_agents_calls = [c for c in hub.calls if c[1] == "GET_AGENTS"]
    assert len(get_agents_calls) == 1


# ── agent_config key tolerance + migration (hostname → runtime agent_id) ──────

class _MiniState:
    def __init__(self, agent_config):
        self.system_state = {"agent_config": agent_config}
        self.saved = 0

    def save_state(self):
        self.saved += 1

    def _mark_dirty(self):  # parity with StateManager dirty-flag persistence
        self.saved += 1     # counted as a persist request (60s loop flushes)

    async def save_state_now(self):
        self.save_state()


class _MiniHub:
    def __init__(self, agent_config):
        self.state = _MiniState(agent_config)


def test_agent_config_entry_prefers_agent_id_then_falls_back_to_hostname():
    # Stored under the hostname → looked up by runtime agent_id must still find it.
    hub = _MiniHub({"cs-svr-02": {"client_simulation": {"enabled": True}}})
    key, entry = CSBridgePoller(hub)._agent_config_entry("pxmx-cs-svr-02-agent", "cs-svr-02")
    assert key == "cs-svr-02"
    assert entry["client_simulation"]["enabled"] is True
    # Both present → the exact agent_id wins.
    hub2 = _MiniHub({"pxmx-cs-svr-02-agent": {"a": 1}, "cs-svr-02": {"b": 2}})
    key2, entry2 = CSBridgePoller(hub2)._agent_config_entry("pxmx-cs-svr-02-agent", "cs-svr-02")
    assert key2 == "pxmx-cs-svr-02-agent" and entry2 == {"a": 1}


def test_migrate_rekeys_hostname_entry_to_agent_id_and_persists():
    hub = _MiniHub({"cs-svr-02": {"display_name": "cs",
                                  "client_simulation": {"enabled": True, "tenant_id": "default"}}})
    CSBridgePoller(hub)._migrate_agent_config_key("cs-svr-02", "pxmx-cs-svr-02-agent")
    store = hub.state.system_state["agent_config"]
    assert "cs-svr-02" not in store                      # old key removed
    assert store["pxmx-cs-svr-02-agent"]["display_name"] == "cs"
    assert store["pxmx-cs-svr-02-agent"]["client_simulation"]["enabled"] is True
    assert hub.state.saved == 1                          # persist requested (dirty-flagged)


def test_migrate_keeps_operator_enable_but_preserves_existing_usb_config():
    hub = _MiniHub({
        "cs-svr-02": {"client_simulation": {"enabled": True, "tenant_id": "t1"}},
        "pxmx-cs-svr-02-agent": {"client_simulation": {"usb_config": {"vidpids": [{"vidpid": "2357:012e"}]}}},
    })
    CSBridgePoller(hub)._migrate_agent_config_key("cs-svr-02", "pxmx-cs-svr-02-agent")
    cs = hub.state.system_state["agent_config"]["pxmx-cs-svr-02-agent"]["client_simulation"]
    assert cs["enabled"] is True and cs["tenant_id"] == "t1"     # operator enable/tenant win
    assert cs["usb_config"] == {"vidpids": [{"vidpid": "2357:012e"}]}  # existing usb_config kept
    assert "cs-svr-02" not in hub.state.system_state["agent_config"]
