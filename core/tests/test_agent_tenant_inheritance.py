"""Agent tenant inheritance on relay-up.

A pxmx agent's owning (cs/hypervisor) spoke can be tenant-assigned while the
agent's own ``agent_config[agent_id].client_simulation.tenant_id`` is unset or
stale. ``LabManagerHub._inherit_agent_tenant`` (called from
``_handle_agent_relay_up`` right after the ``agent_info`` index write) stamps
the spoke's tenant onto the agent's ``client_simulation.tenant_id`` — always
overwrite, preserving ``enabled`` + ``usb_config``. No-op when the spoke has no
tenant (so an unassigned spoke doesn't clobber an agent's existing tenant).
"""
import os
import sys

_LM_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _LM_ROOT not in sys.path:
    sys.path.insert(0, _LM_ROOT)

import main  # noqa: E402
from state.manager import StateManager  # noqa: E402


def _fresh_state(tmp_path):
    s = StateManager()
    s.system_path = str(tmp_path / "system.json")
    s.tenants_path = str(tmp_path / "tenants.json")
    s.system_state = {
        "approved_modules": {},
        "known_modules": [],
        "module_names": {},
        "module_metadata": {},
        "agent_config": {},
        "agent_display_names": {},
    }
    return s


class _Hub:
    """Minimal stand-in: just state — _inherit_agent_tenant only touches
    self.state + the module-level logger (best-effort except branch)."""
    def __init__(self, state):
        self.state = state


def _inherit(hub, agent_id, spoke_id):
    return main.LabManagerHub._inherit_agent_tenant(hub, agent_id, spoke_id)


def test_stamps_tenant_when_spoke_assigned_and_agent_unset(tmp_path):
    state = _fresh_state(tmp_path)
    state.update_module_metadata("cs-svr-02-spoke", {"tenant_id": "lrb"})
    hub = _Hub(state)

    _inherit(hub, "pxmx-cs-svr-02-agent", "cs-svr-02-spoke")

    entry = state.system_state["agent_config"]["pxmx-cs-svr-02-agent"]
    assert entry["client_simulation"]["tenant_id"] == "lrb"


def test_always_overwrites_stale_tenant(tmp_path):
    """The agent's own tenant_id was stale (saved before the spoke was bound) —
    always overwrite to match the spoke's binding (user's choice)."""
    state = _fresh_state(tmp_path)
    state.update_module_metadata("cs-svr-02-spoke", {"tenant_id": "lrb"})
    state.system_state["agent_config"]["pxmx-cs-svr-02-agent"] = {
        "client_simulation": {"enabled": True, "tenant_id": "old-tenant",
                              "usb_config": {"vidpids": ["1234:5678"]}},
    }
    hub = _Hub(state)

    _inherit(hub, "pxmx-cs-svr-02-agent", "cs-svr-02-spoke")

    cs = state.system_state["agent_config"]["pxmx-cs-svr-02-agent"]["client_simulation"]
    assert cs["tenant_id"] == "lrb"               # overwritten
    assert cs["enabled"] is True                  # preserved
    assert cs["usb_config"] == {"vidpids": ["1234:5678"]}  # preserved


def test_no_op_when_spoke_unassigned_keeps_existing_tenant(tmp_path):
    """An unassigned spoke (no tenant_id) must NOT clobber the agent's existing
    tenant_id — only a tenant-assigned spoke is authoritative."""
    state = _fresh_state(tmp_path)
    state.system_state["agent_config"]["ag-1"] = {
        "client_simulation": {"enabled": True, "tenant_id": "keep-me"}}
    hub = _Hub(state)

    _inherit(hub, "ag-1", "unassigned-spoke")

    assert state.system_state["agent_config"]["ag-1"]["client_simulation"]["tenant_id"] == "keep-me"


def test_creates_client_simulation_subdict_when_missing(tmp_path):
    """An agent entry with no client_simulation sub-dict gets one created with
    just the tenant_id (enabled left unset — the bridge treats absent as off,
    matching its tolerant read)."""
    state = _fresh_state(tmp_path)
    state.update_module_metadata("spoke-x", {"tenant_id": "t-1"})
    state.system_state["agent_config"]["ag-2"] = {"display_name": "Agent 2"}
    hub = _Hub(state)

    _inherit(hub, "ag-2", "spoke-x")

    assert state.system_state["agent_config"]["ag-2"]["client_simulation"] == {"tenant_id": "t-1"}
    assert state.system_state["agent_config"]["ag-2"]["display_name"] == "Agent 2"


def test_creates_entry_when_agent_unknown(tmp_path):
    """A brand-new agent (no entry at all) gets one created with the tenant."""
    state = _fresh_state(tmp_path)
    state.update_module_metadata("spoke-y", {"tenant_id": "t-2"})
    hub = _Hub(state)

    _inherit(hub, "new-ag", "spoke-y")

    assert state.system_state["agent_config"]["new-ag"]["client_simulation"]["tenant_id"] == "t-2"


def test_no_op_when_agent_id_empty(tmp_path):
    state = _fresh_state(tmp_path)
    state.update_module_metadata("spoke-z", {"tenant_id": "t-3"})
    hub = _Hub(state)

    _inherit(hub, "", "spoke-z")

    assert state.system_state["agent_config"] == {}


def test_idempotent_no_save_when_already_matches(tmp_path):
    """When the agent's tenant_id already equals the spoke's, no write/save is
    needed (the guard avoids a save_state storm on every relayed frame)."""
    state = _fresh_state(tmp_path)
    state.update_module_metadata("spoke-m", {"tenant_id": "t-match"})
    state.system_state["agent_config"]["ag-3"] = {
        "client_simulation": {"enabled": True, "tenant_id": "t-match"}}
    hub = _Hub(state)
    saves = []
    state.save_state = lambda: saves.append(1)  # type: ignore

    _inherit(hub, "ag-3", "spoke-m")

    assert saves == []  # already matches → no persist
    assert state.system_state["agent_config"]["ag-3"]["client_simulation"]["tenant_id"] == "t-match"