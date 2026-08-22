"""An OFFLINE relayed pxmx/cs agent (parent spoke down, reconstructed from
persisted state) must carry the SAME effective tenant it had while connected —
its own pinned client_simulation.tenant_id, else inherited from its parent
spoke's module_metadata binding. Without the spoke-level fallback the offline
row rendered "no tenant" while the live row + the spoke's real binding showed
one (the reported conflict). Mirrors get_pxmx_agents._agent_tid precedence.
"""
import types

from routes import pxmx  # core/src on sys.path via conftest


def _hub(*, agent_config, module_metadata, last_seen, in_contact):
    ss = {
        "agent_config": agent_config,
        "agent_display_names": {},
        "known_modules": [],
        "module_metadata": module_metadata,
    }
    state = types.SimpleNamespace(
        system_state=ss,
        is_agent_decommissioned=lambda apk: False,
    )
    heartbeat = types.SimpleNamespace(last_seen=last_seen)
    return types.SimpleNamespace(
        state=state,
        heartbeat=heartbeat,
        is_spoke_in_contact=lambda spk: in_contact,
        _agent_primary_key=lambda x: x,
    )


def test_offline_agent_inherits_spoke_tenant_when_not_pinned():
    # Agent has NO pinned tenant; its parent spoke is bound to "lrb".
    hub = _hub(
        agent_config={"agent-pk-1": {"agent_id": "agent-cs-svr-05",
                                     "hostname": "cs-svr-05",
                                     "client_simulation": {}}},
        module_metadata={"spoke-pk-1": {"hostname": "PXMX-CS-SVR-05", "tenant_id": "lrb"}},
        last_seen={"spoke-pk-1:agent-pk-1": 1000.0},
        in_contact=False,   # parent spoke offline → agent surfaces as offline
    )
    rows = pxmx._offline_relay_agents(hub, live_ids=set())
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["tenant_id"] == "lrb"
    assert row["client_simulation"]["tenant_id"] == "lrb"
    assert row["offline"] is True


def test_offline_agent_pin_wins_over_spoke_binding():
    hub = _hub(
        agent_config={"agent-pk-2": {"agent_id": "agent-cs-svr-06",
                                     "client_simulation": {"tenant_id": "acme"}}},
        module_metadata={"spoke-pk-2": {"tenant_id": "lrb"}},
        last_seen={"spoke-pk-2:agent-pk-2": 1000.0},
        in_contact=False,
    )
    rows = pxmx._offline_relay_agents(hub, live_ids=set())
    assert rows[0]["tenant_id"] == "acme"
    assert rows[0]["client_simulation"]["tenant_id"] == "acme"


def test_offline_agent_tenantless_when_neither_pinned_nor_bound():
    hub = _hub(
        agent_config={"agent-pk-3": {"agent_id": "agent-x", "client_simulation": {}}},
        module_metadata={"spoke-pk-3": {}},
        last_seen={"spoke-pk-3:agent-pk-3": 1000.0},
        in_contact=False,
    )
    rows = pxmx._offline_relay_agents(hub, live_ids=set())
    assert rows[0]["tenant_id"] == ""


def test_live_parent_spoke_hides_offline_row():
    hub = _hub(
        agent_config={"agent-pk-4": {"agent_id": "agent-y", "client_simulation": {}}},
        module_metadata={"spoke-pk-4": {"tenant_id": "lrb"}},
        last_seen={"spoke-pk-4:agent-pk-4": 1000.0},
        in_contact=True,   # parent spoke live → the live GET_AGENTS path owns it
    )
    assert pxmx._offline_relay_agents(hub, live_ids=set()) == []
